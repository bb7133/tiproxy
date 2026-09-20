// Copyright 2026 PingCAP, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Go EC2 metadata token negotiation, role selection and credential cache policy.

use bytes::Bytes;
use http::{Request, Response};
use reqsign_aws_v4::Credential;
use reqsign_core::{Context, SigningCredential, time::Timestamp};
use serde::de::{Deserialize, Deserializer, IgnoredAny, MapAccess, Visitor};
use std::{collections::BTreeMap, fmt, time::Duration};
use tokio::sync::Mutex;

const ROLE_PATH: &str = "/latest/meta-data/iam/security-credentials/";
const TOKEN_HEADER: &str = "x-aws-ec2-metadata-token";
const TTL_HEADER: &str = "x-aws-ec2-metadata-token-ttl-seconds";

pub(crate) struct Imds {
    endpoint: String,
    disabled: bool,
    fallback: bool,
    state: Mutex<State>,
}
#[derive(Default)]
struct State {
    token: Option<(String, Timestamp)>,
    token_disabled: bool,
    credential: Option<Credential>,
}
fn env(ctx: &Context, key: &str) -> Option<String> {
    ctx.env_var(key).filter(|v| !v.is_empty())
}
fn parse_bool(value: &str) -> reqsign_core::Result<bool> {
    match value {
        "1" | "t" | "T" | "TRUE" | "true" | "True" => Ok(true),
        "0" | "f" | "F" | "FALSE" | "false" | "False" => Ok(false),
        _ => Err(failed()),
    }
}
pub(super) fn validate_env(ctx: &Context) -> reqsign_core::Result<()> {
    if let Some(value) = env(ctx, "AWS_EC2_METADATA_SERVICE_ENDPOINT_MODE")
        && !["", "ipv4", "ipv6"]
            .iter()
            .any(|v| value.trim().eq_ignore_ascii_case(v))
    {
        return Err(failed());
    }
    if let Some(value) = env(ctx, "AWS_EC2_METADATA_V1_DISABLED") {
        parse_bool(&value)?;
    }
    Ok(())
}
impl Imds {
    pub(crate) fn new(
        ctx: &Context,
        profile: &BTreeMap<String, String>,
    ) -> reqsign_core::Result<Self> {
        validate_env(ctx)?;
        let option = |environment, property| {
            env(ctx, environment)
                .or_else(|| profile.get(property).filter(|v| !v.is_empty()).cloned())
        };
        let endpoint = option(
            "AWS_EC2_METADATA_SERVICE_ENDPOINT",
            "ec2_metadata_service_endpoint",
        )
        .unwrap_or_else(|| {
            if env(ctx, "AWS_EC2_METADATA_SERVICE_ENDPOINT_MODE")
                .filter(|v| !v.trim().is_empty())
                .or_else(|| profile.get("ec2_metadata_service_endpoint_mode").cloned())
                .is_some_and(|v| v.trim().eq_ignore_ascii_case("ipv6"))
            {
                "http://[fd00:ec2::254]".into()
            } else {
                "http://169.254.169.254".into()
            }
        });
        let fallback = !option("AWS_EC2_METADATA_V1_DISABLED", "ec2_metadata_v1_disabled")
            .map(|v| parse_bool(&v))
            .transpose()?
            .unwrap_or(false);
        Ok(Self {
            endpoint,
            disabled: env(ctx, "AWS_EC2_METADATA_DISABLED")
                .is_some_and(|v| v.eq_ignore_ascii_case("true")),
            fallback,
            state: Mutex::default(),
        })
    }
    pub(crate) async fn retrieve(&self, ctx: &Context) -> reqsign_core::Result<Credential> {
        let mut state = self.state.lock().await;
        let now = Timestamp::now();
        if let Some(value) = state.credential.as_ref().filter(|v| v.is_valid_at(now)) {
            return Ok(value.clone());
        }
        let attempt = async {
            if self.disabled {
                return Err(failed());
            }
            let list = self.metadata(ctx, &mut state, ROLE_PATH).await?;
            let list = std::str::from_utf8(&list).map_err(|_| failed())?;
            let first = list.lines().next().ok_or_else(failed)?;
            // bufio.Scanner selects the first line (not the whole list); Go
            // path.Join cleans dot segments and preserves spaces in its name.
            let path = clean_path(&format!("{ROLE_PATH}{first}"), false);
            let raw = self.metadata(ctx, &mut state, &path).await?;
            let value = Output::deserialize(&mut serde_json::Deserializer::from_slice(&raw))
                .map_err(|_| failed())?;
            if !value.code.eq_ignore_ascii_case("success") {
                return Err(failed());
            }
            let expiration = value
                .expiration
                .unwrap_or("0001-01-01T00:00:00Z".parse().map_err(|_| failed())?);
            Ok(Credential {
                access_key_id: value.key,
                secret_access_key: value.secret,
                session_token: (!value.token.is_empty()).then_some(value.token),
                expires_in: Some(expiration.min(Timestamp::now() + Duration::from_secs(3600))),
            })
        }
        .await;
        let credential = match attempt {
            Ok(value) => value,
            Err(error) => {
                // ec2rolecreds explicitly retains the same previously acquired
                // identity on refresh failure, even after the old expiry.
                let Some(mut previous) = state.credential.clone() else {
                    return Err(error);
                };
                if previous.expires_in.is_none() {
                    return Err(error);
                }
                if previous
                    .expires_in
                    .is_some_and(|v| v <= Timestamp::now() + Duration::from_secs(300))
                {
                    let mut random = [0; 4];
                    getrandom::getrandom(&mut random).map_err(|_| failed())?;
                    let fraction = f64::from(u32::from_le_bytes(random)) / 4_294_967_296.0;
                    previous.expires_in =
                        Some(Timestamp::now() + Duration::from_secs_f64(300.0 + fraction * 600.0));
                }
                previous
            }
        };
        state.credential = Some(credential.clone());
        Ok(credential)
    }
    async fn metadata(
        &self,
        ctx: &Context,
        state: &mut State,
        path: &str,
    ) -> reqsign_core::Result<Bytes> {
        tokio::time::timeout(Duration::from_secs(5), async {
            let token = self.token(ctx, state).await?;
            let response = self.request(ctx, "GET", path, token.as_deref()).await?;
            if response.status() == http::StatusCode::UNAUTHORIZED {
                state.token = None;
                state.token_disabled = false;
            }
            if !response.status().is_success() {
                return Err(failed());
            }
            Ok(response.into_body())
        })
        .await
        .map_err(|_| failed())?
    }
    async fn token(
        &self,
        ctx: &Context,
        state: &mut State,
    ) -> reqsign_core::Result<Option<String>> {
        if state.token_disabled && self.fallback {
            return Ok(None);
        }
        if let Some((token, expires)) = &state.token
            && *expires > Timestamp::now()
        {
            return Ok(Some(token.clone()));
        }
        let response = self.request(ctx, "PUT", "/latest/api/token", None).await;
        match response {
            Ok(response) if response.status().is_success() => {
                let decoded = (|| {
                    let ttl = response
                        .headers()
                        .get(TTL_HEADER)?
                        .to_str()
                        .ok()?
                        .parse::<i64>()
                        .ok()?;
                    let expires =
                        Timestamp::from_second(Timestamp::now().as_second().checked_add(ttl)?)
                            .ok()?;
                    let token = std::str::from_utf8(response.body()).ok()?.to_owned();
                    Some((token, expires))
                })();
                if let Some((token, expires)) = decoded {
                    state.token = Some((token.clone(), expires));
                    return Ok(Some(token));
                }
            }
            Ok(response) => {
                if response.status() == http::StatusCode::BAD_REQUEST {
                    return Err(failed());
                }
                if matches!(response.status().as_u16(), 403..=405) && self.fallback {
                    state.token_disabled = true;
                }
            }
            Err(_) => state.token_disabled = true,
        }
        if self.fallback {
            Ok(None)
        } else {
            Err(failed())
        }
    }
    async fn request(
        &self,
        ctx: &Context,
        method: &str,
        path: &str,
        token: Option<&str>,
    ) -> reqsign_core::Result<Response<Bytes>> {
        let mut url = reqwest::Url::parse(&self.endpoint).map_err(|_| failed())?;
        let path = clean_path(path, path.ends_with('/'));
        url.set_path(&path);
        let mut request = Request::builder().method(method).uri(url.as_str());
        if method == "PUT" {
            request = request.header(TTL_HEADER, "300");
        }
        if let Some(token) = token {
            request = request.header(TOKEN_HEADER, token);
        }
        ctx.http_send(request.body(Bytes::new()).map_err(|_| failed())?)
            .await
            .map_err(|_| failed())
    }
}
fn clean_path(path: &str, trailing: bool) -> String {
    let mut parts = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            _ => parts.push(part),
        }
    }
    let mut value = format!("/{}", parts.join("/"));
    if trailing && !value.ends_with('/') {
        value.push('/');
    }
    value
}
#[derive(Default)]
struct Output {
    key: String,
    secret: String,
    token: String,
    code: String,
    expiration: Option<Timestamp>,
}
impl<'de> Deserialize<'de> for Output {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Fields;
        impl<'de> Visitor<'de> for Fields {
            type Value = Output;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("IMDS credential object")
            }
            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Output, M::Error> {
                let mut value = Output::default();
                while let Some(key) = map.next_key::<String>()? {
                    match key.to_ascii_lowercase().as_str() {
                        "accesskeyid" | "secretaccesskey" | "token" | "code" | "message" => {
                            if let Some(text) = map.next_value::<Option<String>>()? {
                                match key.to_ascii_lowercase().as_str() {
                                    "accesskeyid" => value.key = text,
                                    "secretaccesskey" => value.secret = text,
                                    "token" => value.token = text,
                                    "code" => value.code = text,
                                    _ => {}
                                }
                            }
                        }
                        "expiration" => {
                            if let Some(text) = map.next_value::<Option<String>>()? {
                                value.expiration = Some(
                                    crate::cloud_aws_process::parse_expiration(&text)
                                        .map_err(serde::de::Error::custom)?,
                                );
                            }
                        }
                        _ => {
                            let _ = map.next_value::<IgnoredAny>()?;
                        }
                    }
                }
                Ok(value)
            }
        }
        deserializer.deserialize_map(Fields)
    }
}
fn failed() -> reqsign_core::Error {
    reqsign_core::Error::credential_invalid("AWS EC2 metadata credential unavailable")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use std::{
        collections::HashMap,
        sync::{Arc, Mutex as StdMutex},
    };
    #[derive(Debug, Deserialize, PartialEq, Eq)]
    struct Observed {
        method: String,
        url: String,
        token: String,
        ttl: String,
    }
    #[derive(Deserialize)]
    struct Case {
        name: String,
        config: String,
        env: Option<HashMap<String, String>>,
        roles: String,
        response: String,
        token_status: u16,
        ttl: String,
        denied: String,
        load_error: bool,
        error: bool,
        second_error: bool,
        key: String,
        expiration: String,
        second_expiration: String,
        requests: Option<Vec<Observed>>,
    }
    #[derive(Debug, Clone)]
    struct Io {
        config: String,
        roles: String,
        response: String,
        token_status: u16,
        ttl: String,
        denied: String,
        lists: Arc<StdMutex<u32>>,
        requests: Arc<StdMutex<Vec<Observed>>>,
    }
    impl reqsign_core::FileRead for Io {
        async fn file_read(&self, path: &str) -> reqsign_core::Result<Vec<u8>> {
            if path.ends_with("/config") {
                Ok(self.config.as_bytes().to_vec())
            } else {
                Err(failed())
            }
        }
    }
    impl reqsign_core::HttpSend for Io {
        async fn http_send(
            &self,
            request: Request<Bytes>,
        ) -> reqsign_core::Result<Response<Bytes>> {
            let header = |key| {
                request
                    .headers()
                    .get(key)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or_default()
                    .to_owned()
            };
            self.requests
                .lock()
                .unwrap_or_else(|e| unreachable!("{e}"))
                .push(Observed {
                    method: request.method().to_string(),
                    url: request.uri().to_string(),
                    token: header(TOKEN_HEADER),
                    ttl: header(TTL_HEADER),
                });
            let mut response = Response::builder();
            let mut status = 200;
            let mut body = self.response.as_str();
            if request.uri().path().ends_with("/api/token") {
                body = "metadata-token";
                status = self.token_status;
                if self.ttl != "MISSING" {
                    response = response.header(TTL_HEADER, &self.ttl);
                }
            } else if request.uri().path().ends_with("/iam/security-credentials/") {
                let mut lists = self.lists.lock().unwrap_or_else(|e| unreachable!("{e}"));
                *lists += 1;
                body = &self.roles;
                if self.denied == "list" || (self.denied == "after-first" && *lists > 1) {
                    status = 403;
                    body = "denied";
                }
            } else if self.denied == "role" {
                status = 403;
                body = "denied";
            }
            response
                .status(status)
                .body(Bytes::copy_from_slice(body.as_bytes()))
                .map_err(|_| failed())
        }
    }
    fn assert_expiration(value: Option<Timestamp>, expected: &str, name: &str) {
        let value = value.unwrap_or_else(|| unreachable!("{name} lacks expiry"));
        let seconds = value.as_second() - Timestamp::now().as_second();
        match expected {
            "NOW_PLUS_3600" => assert!((3590..=3600).contains(&seconds), "{name}: {seconds}"),
            "EXTENDED_5_TO_15_MINUTES" => {
                assert!((299..900).contains(&seconds), "{name}: {seconds}");
            }
            _ => assert_eq!(value.to_string(), expected, "{name}"),
        }
    }
    #[tokio::test]
    async fn imds_token_role_requests_and_cache_match_actual_go() {
        let cases: Vec<Case> = serde_json::from_str(include_str!("../testdata/aws-imds-go.json"))
            .unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(cases.len(), 31);
        for row in cases {
            let io = Io {
                config: row.config,
                roles: row.roles,
                response: row.response,
                token_status: row.token_status,
                ttl: row.ttl,
                denied: row.denied,
                lists: Arc::default(),
                requests: Arc::default(),
            };
            let ctx = Context::new()
                .with_env(reqsign_core::StaticEnv {
                    home_dir: Some("/fixture".into()),
                    envs: row.env.unwrap_or_default(),
                })
                .with_file_read(io.clone())
                .with_http_send(io.clone());
            let signer = crate::cloud_aws::AwsSigner::new(
                &control_config::AwsMeteringConfig::default(),
                "us-east-1".into(),
                None,
                ctx,
            )
            .await;
            assert_eq!(signer.is_err(), row.load_error, "{} construction", row.name);
            if let Ok(signer) = signer {
                assert!(
                    io.requests
                        .lock()
                        .unwrap_or_else(|e| unreachable!("{e}"))
                        .is_empty()
                );
                let first = signer.credential().await;
                assert_eq!(first.is_err(), row.error, "{} retrieve", row.name);
                if let Ok(first) = first {
                    assert_eq!(first.access_key_id, row.key, "{}", row.name);
                    assert_expiration(first.expires_in, &row.expiration, &row.name);
                    let second = signer.credential().await;
                    assert_eq!(second.is_err(), row.second_error, "{} second", row.name);
                    if let Ok(second) = second {
                        assert_eq!(second.access_key_id, row.key, "{}", row.name);
                        assert_expiration(second.expires_in, &row.second_expiration, &row.name);
                    }
                }
            }
            assert_eq!(
                *io.requests.lock().unwrap_or_else(|e| unreachable!("{e}")),
                row.requests.unwrap_or_default(),
                "{} requests",
                row.name
            );
        }
    }
}
