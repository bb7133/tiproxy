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

use super::cloud_aws_retry::{Failure, Retry};
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
    retry: Retry,
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
            retry: Retry::new(ctx),
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
        self.retry
            .run(|| async {
                let response = ctx
                    .http_send(request.clone())
                    .await
                    .map_err(Failure::transport)?;
                if !response.status().is_success() {
                    // Go only exposes the status to its retryer after successful
                    // error decoding. Malformed application/json is terminal even
                    // for a normally retryable status. Content-Type is exact.
                    let code = if response
                        .headers()
                        .get("content-type")
                        .is_some_and(|v| v == "application/json")
                    {
                        ErrorBody::deserialize(&mut serde_json::Deserializer::from_slice(
                            response.body(),
                        ))
                        .map_err(|_| Failure::terminal(failed()))?
                        .0
                    } else {
                        String::new()
                    };
                    return Err(Failure::container(response.status().as_u16(), &code));
                }
                decode(response.body()).map_err(Failure::terminal)
            })
            .await
    }
}
fn decode(body: &[u8]) -> reqsign_core::Result<Credential> {
    // endpointcreds uses Decoder.Decode, accepting the first JSON value;
    // processcreds instead uses Unmarshal and rejects a trailing value.
    let mut decoder = serde_json::Deserializer::from_slice(body);
    let value = Output::deserialize(&mut decoder).map_err(|_| failed())?;
    let expires_in = value.expiration.map(|time| time - Duration::from_secs(300));
    Ok(Credential {
        access_key_id: value.key,
        secret_access_key: value.secret,
        session_token: (!value.token.is_empty()).then_some(value.token),
        expires_in,
    })
}

struct ErrorBody(String);
impl<'de> Deserialize<'de> for ErrorBody {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Fields;
        impl<'de> Visitor<'de> for Fields {
            type Value = ErrorBody;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("endpoint error object")
            }
            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
                let mut code = String::new();
                while let Some(key) = map.next_key::<String>()? {
                    if key.eq_ignore_ascii_case("code") || key.eq_ignore_ascii_case("message") {
                        if let Some(text) = map.next_value::<Option<String>>()?
                            && key.eq_ignore_ascii_case("code")
                        {
                            code = text;
                        }
                    } else {
                        let _ = map.next_value::<IgnoredAny>()?;
                    }
                }
                Ok(ErrorBody(code))
            }
        }
        deserializer.deserialize_map(Fields)
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

#[cfg(test)]
mod retry_tests {
    use super::*;
    use crate::cloud_context::HttpFailure;
    use serde::Deserialize as DeriveDeserialize;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };
    #[derive(Clone, Debug, DeriveDeserialize)]
    struct Row {
        name: String,
        new: bool,
        status: u16,
        body: String,
        content_type: String,
        transport: String,
        recover: bool,
        attempts: usize,
        error: bool,
    }
    #[derive(Clone, Debug)]
    struct Io {
        row: Row,
        count: Arc<AtomicUsize>,
        success: Arc<AtomicBool>,
    }
    impl reqsign_core::HttpSend for Io {
        async fn http_send(
            &self,
            request: Request<Bytes>,
        ) -> reqsign_core::Result<http::Response<Bytes>> {
            assert_eq!(request.method(), "GET");
            assert_eq!(request.headers()["accept"], "application/json");
            let count = self.count.fetch_add(1, Ordering::Relaxed) + 1;
            if self.success.load(Ordering::Relaxed) || (self.row.recover && count > 1) {
                return Ok(http::Response::new(Bytes::from_static(
                    br#"{"AccessKeyId":"key","SecretAccessKey":"secret"}"#,
                )));
            }
            match self.row.transport.as_str() {
                "timeout" => return Err(failed().with_source(HttpFailure::Timeout)),
                "connection-reset" | "plain" => {
                    return Err(failed().with_source(HttpFailure::Connection));
                }
                _ => {}
            }
            http::Response::builder()
                .status(self.row.status)
                .header("content-type", &self.row.content_type)
                .body(Bytes::copy_from_slice(self.row.body.as_bytes()))
                .map_err(|_| failed())
        }
    }
    fn setup(row: Row) -> (Context, Io) {
        let envs = std::collections::HashMap::from([
            (
                "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI".into(),
                "/credentials".into(),
            ),
            ("AWS_NEW_RETRIES_2026".into(), row.new.to_string()),
        ]);
        let io = Io {
            row,
            count: Arc::default(),
            success: Arc::default(),
        };
        (
            Context::new()
                .with_env(reqsign_core::StaticEnv {
                    home_dir: None,
                    envs,
                })
                .with_http_send(io.clone()),
            io,
        )
    }
    #[derive(DeriveDeserialize)]
    struct Quota {
        new: bool,
        attempts: Vec<usize>,
    }
    #[derive(DeriveDeserialize)]
    struct Fixture {
        rows: Vec<Row>,
        quotas: Vec<Quota>,
    }
    #[tokio::test(start_paused = true)]
    async fn container_retries_and_persistent_quota_match_actual_go() {
        let fixture: Fixture =
            serde_json::from_str(include_str!("../testdata/aws-container-retry-go.json"))
                .unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(fixture.rows.len(), 54);
        for row in fixture.rows {
            // Go's typed DNS NXDOMAIN is not portable through reqwest's
            // resolver errors. This transport difference is documented.
            if row.transport == "nxdomain" {
                assert_eq!(row.attempts, 1);
                continue;
            }
            let (ctx, io) = setup(row.clone());
            let provider = Container::new(&ctx)
                .await
                .unwrap_or_else(|e| unreachable!("{e}"));
            let result = provider.retrieve(&ctx).await;
            assert_eq!(result.is_err(), row.error, "{} new={}", row.name, row.new);
            assert_eq!(
                io.count.load(Ordering::Relaxed),
                row.attempts,
                "{} new={}",
                row.name,
                row.new
            );
        }
        for quota in fixture.quotas {
            let row = Row {
                name: "quota".into(),
                new: quota.new,
                status: 503,
                body: "busy".into(),
                content_type: "text/plain".into(),
                transport: String::new(),
                recover: false,
                attempts: 0,
                error: true,
            };
            let (ctx, io) = setup(row);
            let provider = Container::new(&ctx)
                .await
                .unwrap_or_else(|e| unreachable!("{e}"));
            for (i, expected) in quota.attempts.into_iter().enumerate() {
                io.success.store((52..66).contains(&i), Ordering::Relaxed);
                let before = io.count.load(Ordering::Relaxed);
                let _ = provider.retrieve(&ctx).await;
                assert_eq!(
                    io.count.load(Ordering::Relaxed) - before,
                    expected,
                    "quota operation {i} new={}",
                    quota.new
                );
            }
        }
    }
    #[tokio::test(start_paused = true)]
    async fn canceled_backoff_does_not_send_another_attempt() {
        let row = Row {
            name: "cancel".into(),
            new: false,
            status: 503,
            body: "busy".into(),
            content_type: "text/plain".into(),
            transport: String::new(),
            recover: false,
            attempts: 0,
            error: true,
        };
        let (ctx, io) = setup(row);
        let provider = Container::new(&ctx)
            .await
            .unwrap_or_else(|e| unreachable!("{e}"));
        let task = tokio::spawn(async move { provider.retrieve(&ctx).await });
        tokio::task::yield_now().await;
        assert_eq!(io.count.load(Ordering::Relaxed), 1);
        task.abort();
        assert!(task.await.is_err());
        tokio::time::advance(Duration::from_secs(10)).await;
        assert_eq!(io.count.load(Ordering::Relaxed), 1);
    }
}
