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

//! Go container credential selection, authorization and five-minute cache window.

use bytes::Bytes;
use http::Request;
use reqsign_aws_v4::Credential;
use reqsign_core::{Context, time::Timestamp};
use serde::de::{Deserialize, Deserializer, IgnoredAny, MapAccess, Visitor};
use std::{
    fmt,
    net::{IpAddr, Ipv4Addr},
    time::Duration,
};

pub(crate) struct Container {
    endpoint: String,
    token: String,
    token_file: Option<String>,
}
impl Container {
    pub(crate) async fn new(ctx: &Context) -> reqsign_core::Result<Self> {
        let env = |key| ctx.env_var(key).filter(|v| !v.is_empty());
        let endpoint = if let Some(relative) = env("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI") {
            format!("http://169.254.170.2{relative}")
        } else {
            let full = env("AWS_CONTAINER_CREDENTIALS_FULL_URI").ok_or_else(failed)?;
            let url = reqwest::Url::parse(&full).map_err(|_| failed())?;
            let host = url
                .host_str()
                .filter(|v| !v.is_empty())
                .ok_or_else(failed)?;
            if url.scheme() == "http" {
                let host = host.trim_start_matches('[').trim_end_matches(']');
                if let Ok(ip) = host.parse::<IpAddr>() {
                    if !allowed(ip) {
                        return Err(failed());
                    }
                } else {
                    // Go resolves all addresses during construction and rejects
                    // the hostname when any resolved address is not allowed.
                    let mut addresses = tokio::time::timeout(
                        Duration::from_secs(10),
                        tokio::net::lookup_host((host, url.port_or_known_default().unwrap_or(80))),
                    )
                    .await
                    .map_err(|_| failed())?
                    .map_err(|_| failed())?;
                    if !addresses.all(|address| allowed(address.ip())) {
                        return Err(failed());
                    }
                }
            }
            full
        };
        Ok(Self {
            endpoint,
            token: env("AWS_CONTAINER_AUTHORIZATION_TOKEN").unwrap_or_default(),
            token_file: env("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE"),
        })
    }
    pub(crate) async fn retrieve(&self, ctx: &Context) -> reqsign_core::Result<Credential> {
        // A configured file always overrides the env value, including an empty
        // file. Read again on each refresh; whitespace is not trimmed.
        let token = if let Some(path) = &self.token_file {
            String::from_utf8(ctx.file_read(path).await.map_err(|_| failed())?)
                .map_err(|_| failed())?
        } else {
            self.token.clone()
        };
        if token.contains(['\r', '\n']) {
            return Err(failed());
        }
        let mut request = Request::builder()
            .method("GET")
            .uri(&self.endpoint)
            .header("accept", "application/json");
        if !token.is_empty() {
            request = request.header("authorization", token);
        }
        let request = request.body(Bytes::new()).map_err(|_| failed())?;
        let response = ctx.http_send(request).await.map_err(|_| failed())?;
        if !response.status().is_success() {
            return Err(failed());
        }
        // endpointcreds uses Decoder.Decode, accepting the first JSON value;
        // processcreds instead uses Unmarshal and rejects a trailing value.
        let mut decoder = serde_json::Deserializer::from_slice(response.body());
        let value = Output::deserialize(&mut decoder).map_err(|_| failed())?;
        let expires_in = value.expiration.map(|time| time - Duration::from_secs(300));
        Ok(Credential {
            access_key_id: value.key,
            secret_access_key: value.secret,
            session_token: (!value.token.is_empty()).then_some(value.token),
            expires_in,
        })
    }
}
fn allowed(ip: IpAddr) -> bool {
    if let IpAddr::V6(v6) = ip
        && let Some(v4) = v6.to_ipv4_mapped()
    {
        return allowed(IpAddr::V4(v4));
    }
    ip.is_loopback()
        || ip == IpAddr::V4(Ipv4Addr::new(169, 254, 170, 2))
        || ip == IpAddr::V4(Ipv4Addr::new(169, 254, 170, 23))
        || matches!(ip, IpAddr::V6(v6) if v6.segments() == [0xfd00,0x0ec2,0,0,0,0,0,0x23])
}
#[derive(Default)]
struct Output {
    key: String,
    secret: String,
    token: String,
    expiration: Option<Timestamp>,
}
impl<'de> Deserialize<'de> for Output {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Fields;
        impl<'de> Visitor<'de> for Fields {
            type Value = Output;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("container credential object")
            }
            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Output, M::Error> {
                let mut value = Output::default();
                while let Some(key) = map.next_key::<String>()? {
                    match key.to_ascii_lowercase().as_str() {
                        "accesskeyid" | "secretaccesskey" | "token" | "accountid" => {
                            if let Some(text) = map.next_value::<Option<String>>()? {
                                match key.to_ascii_lowercase().as_str() {
                                    "accesskeyid" => value.key = text,
                                    "secretaccesskey" => value.secret = text,
                                    "token" => value.token = text,
                                    _ => {}
                                }
                            }
                        }
                        "expiration" => {
                            value.expiration = map
                                .next_value::<Option<String>>()?
                                .map(|text| {
                                    crate::cloud_aws_process::parse_expiration(&text)
                                        .map_err(serde::de::Error::custom)
                                })
                                .transpose()?;
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
    reqsign_core::Error::credential_invalid("AWS container credential unavailable")
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqsign_core::ProvideCredential;
    use serde::Deserialize;
    use std::{
        collections::HashMap,
        sync::{Arc, Mutex},
    };
    #[derive(Debug, Deserialize, PartialEq, Eq)]
    struct Observed {
        method: String,
        url: String,
        token: String,
        accept: String,
    }
    #[derive(Deserialize)]
    struct Case {
        name: String,
        env: HashMap<String, String>,
        token_file: Option<String>,
        response: String,
        status: u16,
        load_error: bool,
        error: bool,
        key: String,
        token: String,
        expiration: String,
        requests: Option<Vec<Observed>>,
    }
    #[derive(Debug, Clone)]
    struct Io {
        token: Arc<Mutex<Option<String>>>,
        response: String,
        status: u16,
        requests: Arc<Mutex<Vec<Observed>>>,
    }
    impl reqsign_core::FileRead for Io {
        async fn file_read(&self, path: &str) -> reqsign_core::Result<Vec<u8>> {
            if path.ends_with("/config") {
                return Ok(b"[default]\n".to_vec());
            }
            if path == "TOKEN_FILE" {
                return self
                    .token
                    .lock()
                    .unwrap_or_else(|e| unreachable!("{e}"))
                    .as_ref()
                    .map(|v| v.as_bytes().to_vec())
                    .ok_or_else(failed);
            }
            Err(failed())
        }
    }
    impl reqsign_core::HttpSend for Io {
        async fn http_send(
            &self,
            request: Request<Bytes>,
        ) -> reqsign_core::Result<http::Response<Bytes>> {
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
                    token: header("authorization"),
                    accept: header("accept"),
                });
            http::Response::builder()
                .status(self.status)
                .body(Bytes::copy_from_slice(self.response.as_bytes()))
                .map_err(|_| failed())
        }
    }
    fn context(row: &Case) -> (Context, Io) {
        let io = Io {
            token: Arc::new(Mutex::new(row.token_file.clone())),
            response: row.response.clone(),
            status: row.status,
            requests: Arc::default(),
        };
        let ctx = Context::new()
            .with_env(reqsign_core::StaticEnv {
                home_dir: Some("/fixture".into()),
                envs: row.env.clone(),
            })
            .with_file_read(io.clone())
            .with_http_send(io.clone());
        (ctx, io)
    }
    #[tokio::test]
    async fn container_sources_requests_and_cache_match_actual_go() {
        let rows: Vec<Case> =
            serde_json::from_str(include_str!("../testdata/aws-container-go.json"))
                .unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(rows.len(), 26);
        for row in rows {
            let (ctx, io) = context(&row);
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
                let result = signer.credential().await;
                assert_eq!(result.is_err(), row.error, "{} retrieve", row.name);
                if let Ok(value) = result {
                    assert_eq!(value.access_key_id, row.key, "{}", row.name);
                    assert_eq!(
                        value.session_token.unwrap_or_default(),
                        row.token,
                        "{}",
                        row.name
                    );
                    assert_eq!(
                        value.expires_in.map(|v| v.to_string()).unwrap_or_default(),
                        row.expiration,
                        "{}",
                        row.name
                    );
                    assert!(signer.credential().await.is_ok());
                }
            }
            assert_eq!(
                *io.requests.lock().unwrap_or_else(|e| unreachable!("{e}")),
                row.requests.unwrap_or_default(),
                "{}",
                row.name
            );
        }
    }
    #[tokio::test]
    async fn container_refresh_reads_rotated_file_and_never_uses_env_fallback() {
        let row = Case {
            name: String::new(),
            env: HashMap::from([
                (
                    "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI".into(),
                    "/original".into(),
                ),
                (
                    "AWS_CONTAINER_AUTHORIZATION_TOKEN".into(),
                    "env-token".into(),
                ),
                (
                    "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE".into(),
                    "TOKEN_FILE".into(),
                ),
            ]),
            token_file: Some("first-token".into()),
            response: format!(
                r#"{{"AccessKeyId":"key","SecretAccessKey":"secret","Expiration":"{}"}}"#,
                Timestamp::now() + Duration::from_secs(60)
            ),
            status: 200,
            load_error: false,
            error: false,
            key: String::new(),
            token: String::new(),
            expiration: String::new(),
            requests: None,
        };
        let (ctx, io) = context(&row);
        let provider = crate::cloud_aws_identity::GoDefaultProvider::new("us-east-1");
        provider
            .prepare(&ctx)
            .await
            .unwrap_or_else(|e| unreachable!("{e}"));
        // Mutation after prepare cannot change the selected endpoint or token
        // file, but the contents of that already-selected file do rotate.
        let changed = ctx.with_env(reqsign_core::StaticEnv {
            home_dir: Some("/fixture".into()),
            envs: HashMap::from([
                (
                    "AWS_CONTAINER_CREDENTIALS_FULL_URI".into(),
                    "https://changed.invalid".into(),
                ),
                (
                    "AWS_CONTAINER_AUTHORIZATION_TOKEN".into(),
                    "changed-token".into(),
                ),
            ]),
        });
        assert!(provider.provide_credential(&changed).await.is_ok());
        *io.token.lock().unwrap_or_else(|e| unreachable!("{e}")) = Some("second-token".into());
        assert!(provider.provide_credential(&changed).await.is_ok());
        *io.token.lock().unwrap_or_else(|e| unreachable!("{e}")) = None;
        assert!(provider.provide_credential(&changed).await.is_err());
        let calls = io.requests.lock().unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].token, "first-token");
        assert_eq!(calls[1].token, "second-token");
        assert!(
            calls
                .iter()
                .all(|v| v.url == "http://169.254.170.2/original")
        );
    }
}
