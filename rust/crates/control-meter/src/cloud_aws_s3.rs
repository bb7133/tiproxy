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

//! S3 object attempts share a client quota and retain the final observed skew.

use super::AwsSigner;
use crate::cloud_aws_clock::{Skew, sign_service_at, signing_time};
use crate::cloud_aws_retry::Failure;
use bytes::Bytes;
use http::{Method, Request, Response, StatusCode};
use reqwest::Url;
use serde::Deserialize;
use std::sync::atomic::{AtomicBool, Ordering};

#[path = "cloud_aws_s3_checksum.rs"]
mod checksum;

impl AwsSigner {
    pub(crate) async fn request(
        &self,
        method: Method,
        url: &Url,
        body: Bytes,
    ) -> reqsign_core::Result<StatusCode> {
        let clock = Skew::new(self.object_skew.load(Ordering::Relaxed));
        let missing = AtomicBool::new(false);
        let result = self
            .object_retry
            .run(|| async {
                let skew = clock.take();
                missing.store(false, Ordering::Relaxed);
                let request =
                    checksum::request(&method, url, body.clone(), self.checksum_supported)
                        .map_err(Failure::terminal)?;
                let (mut parts, body) = request.into_parts();
                let mut credential = self.credential().await.map_err(Failure::terminal)?;
                credential.expires_in = None;
                sign_service_at(
                    &mut parts,
                    &credential,
                    &self.region,
                    "s3",
                    signing_time(skew),
                )
                .map_err(Failure::terminal)?;
                let response = self
                    .context
                    .http_send(Request::from_parts(parts, body))
                    .await
                    .map_err(Failure::transport)?;
                clock.observe(&response);
                if response.status().is_success() {
                    return Ok(response.status());
                }
                let error = error_components(&response);
                if method == Method::HEAD {
                    missing.store(
                        error.as_ref().is_some_and(Components::missing),
                        Ordering::Relaxed,
                    );
                }
                Err(Failure::s3(
                    &response,
                    error.as_ref().map_or("", |e| e.code.as_str()),
                    skew,
                ))
            })
            .await;
        // S3 wires ClientSkew; only metadata from the final attempt replaces
        // it. Missing metadata resets attempts but leaves client skew intact.
        if let Some(skew) = clock.final_observed() {
            self.object_skew.store(skew, Ordering::Relaxed);
        }
        match result {
            Err(_) if missing.load(Ordering::Relaxed) => Ok(StatusCode::NOT_FOUND),
            other => other,
        }
    }
}

#[derive(Default, Deserialize)]
struct Components {
    #[serde(rename = "Code", default)]
    code: String,
    #[serde(rename = "Message", default)]
    message: String,
}
impl Components {
    fn missing(&self) -> bool {
        // metering_sdk Exists inspects the rendered SDK error, rather than
        // treating every 404 as absent. HeadObject models NotFound casefolded.
        self.code.eq_ignore_ascii_case("NotFound")
            || [&self.code, &self.message]
                .iter()
                .any(|s| s.contains("NotFound") || s.contains("NoSuchKey"))
    }
}
fn error_components(response: &Response<Bytes>) -> Option<Components> {
    let body = std::str::from_utf8(response.body()).ok()?;
    let mut components: Components = if body.trim().is_empty() {
        Components::default()
    } else {
        quick_xml::de::from_str(body).ok()?
    };
    if components.code.is_empty() && components.message.is_empty() {
        let text = response.status().canonical_reason().unwrap_or_default();
        components.code = text.replace(' ', "");
        components.message = text.into();
    }
    Some(components)
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqsign_core::{Context, StaticEnv, time::Timestamp};
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Deserialize)]
    struct Reply {
        status: u16,
        body: String,
        date: String,
        offset: i64,
        transport: bool,
    }
    #[derive(Deserialize)]
    struct Operation {
        responses: Vec<Reply>,
        calls: usize,
        error: bool,
        exists: bool,
        signed: Vec<i64>,
    }
    #[derive(Deserialize)]
    struct Row {
        name: String,
        method: String,
        new: bool,
        operations: Vec<Operation>,
    }
    #[derive(Default)]
    struct State {
        replies: Vec<Reply>,
        calls: usize,
        signed: Vec<i64>,
    }
    #[derive(Clone)]
    struct Io {
        base: Timestamp,
        method: Method,
        state: Arc<Mutex<State>>,
    }
    impl std::fmt::Debug for Io {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("S3Io").finish_non_exhaustive()
        }
    }
    impl reqsign_core::FileRead for Io {
        async fn file_read(&self, _: &str) -> reqsign_core::Result<Vec<u8>> {
            Err(super::super::failed())
        }
    }
    impl reqsign_core::HttpSend for Io {
        async fn http_send(
            &self,
            request: Request<Bytes>,
        ) -> reqsign_core::Result<Response<Bytes>> {
            let mut state = self.state.lock().unwrap_or_else(|e| unreachable!("{e}"));
            let step = state.replies[state.calls.min(state.replies.len() - 1)].clone();
            state.calls += 1;
            assert_eq!(request.method(), self.method);
            assert_eq!(request.uri().path(), "/bucket/meter.json.gz");
            assert_eq!(
                request.body().as_ref(),
                if self.method == Method::PUT {
                    &b"payload"[..]
                } else {
                    b""
                }
            );
            let date = request.headers()["x-amz-date"]
                .to_str()
                .unwrap_or_else(|e| unreachable!("{e}"));
            let at: Timestamp = format!(
                "{}-{}-{}T{}:{}:{}Z",
                &date[..4],
                &date[4..6],
                &date[6..8],
                &date[9..11],
                &date[11..13],
                &date[13..15]
            )
            .parse()
            .unwrap_or_else(|e| unreachable!("{e}"));
            state.signed.push(at.as_second() - self.base.as_second());
            if step.transport {
                return Err(super::super::failed()
                    .with_source(crate::cloud_context::HttpFailure::Connection));
            }
            let mut response = Response::builder().status(step.status);
            if step.date == "http" {
                let date = Timestamp::from_second(self.base.as_second() + step.offset)
                    .unwrap_or_else(|e| unreachable!("{e}"));
                response = response.header("date", date.format_http_date());
            } else if !step.date.is_empty() {
                response = response.header("date", step.date);
            }
            response
                .body(step.body.into())
                .map_err(|_| super::super::failed())
        }
    }
    #[tokio::test(start_paused = true)]
    async fn object_attempts_and_persistent_clock_match_actual_go_provider() {
        #[derive(Deserialize)]
        struct Fixture {
            requests: Vec<Row>,
        }
        let rows =
            serde_json::from_str::<Fixture>(include_str!("../testdata/aws-s3-retry-go.json"))
                .unwrap_or_else(|e| unreachable!("{e}"))
                .requests;
        assert_eq!(rows.len(), 80);
        for row in rows {
            let method: Method = row.method.parse().unwrap_or_else(|e| unreachable!("{e}"));
            let io = Io {
                base: Timestamp::now(),
                method: method.clone(),
                state: Arc::default(),
            };
            let ctx = Context::new()
                .with_http_send(io.clone())
                .with_file_read(io.clone())
                .with_env(StaticEnv {
                    home_dir: None,
                    envs: std::collections::HashMap::from([
                        ("AWS_NEW_RETRIES_2026".into(), row.new.to_string()),
                        (
                            // The retry fixture's CustomConfig disables optional
                            // checksums; the default production path is separately
                            // compared by the real HTTP/TLS checksum fixture.
                            "AWS_REQUEST_CHECKSUM_CALCULATION".into(),
                            "when_required".into(),
                        ),
                    ]),
                });
            let signer = AwsSigner::new(
                &control_config::AwsMeteringConfig {
                    access_key: "key".into(),
                    secret_access_key: "secret".into(),
                    ..Default::default()
                },
                "us-east-1".into(),
                None,
                ctx,
            )
            .await
            .unwrap_or_else(|e| unreachable!("{e}"));
            for (index, op) in row.operations.into_iter().enumerate() {
                *io.state.lock().unwrap_or_else(|e| unreachable!("{e}")) = State {
                    replies: op.responses,
                    ..Default::default()
                };
                let url = Url::parse("https://s3.us-east-1.amazonaws.com/bucket/meter.json.gz")
                    .unwrap_or_else(|e| unreachable!("{e}"));
                let body = if method == Method::PUT {
                    Bytes::from_static(b"payload")
                } else {
                    Bytes::new()
                };
                let result = signer.request(method.clone(), &url, body).await;
                let state = io.state.lock().unwrap_or_else(|e| unreachable!("{e}"));
                let label = format!("{} {} new={} op={index}", row.method, row.name, row.new);
                assert_eq!(result.is_err(), op.error, "{label}");
                assert_eq!(state.calls, op.calls, "{label}");
                if method == Method::HEAD {
                    assert_eq!(result.is_ok_and(|s| s.is_success()), op.exists, "{label}");
                }
                assert_eq!(state.signed.len(), op.signed.len(), "{label}");
                for (got, want) in state.signed.iter().zip(op.signed) {
                    assert!(
                        (got - want).abs() <= 1,
                        "{label}: signed {got} vs Go {want}"
                    );
                }
            }
        }
    }
    #[test]
    fn fixed_s3_signatures_match_actual_go() {
        #[derive(Deserialize)]
        struct Signature {
            method: String,
            url: String,
            time: String,
            authorization: String,
        }
        #[derive(Deserialize)]
        struct Fixture {
            signatures: Vec<Signature>,
        }
        let rows =
            serde_json::from_str::<Fixture>(include_str!("../testdata/aws-s3-retry-go.json"))
                .unwrap_or_else(|e| unreachable!("{e}"));
        for row in rows.signatures {
            let req = Request::builder()
                .method(row.method.as_str())
                .uri(row.url)
                .header("x-amz-content-sha256", "UNSIGNED-PAYLOAD")
                .body(())
                .unwrap_or_else(|e| unreachable!("{e}"));
            let (mut parts, ()) = req.into_parts();
            let d = row.time;
            let at: Timestamp = format!(
                "{}-{}-{}T{}:{}:{}Z",
                &d[..4],
                &d[4..6],
                &d[6..8],
                &d[9..11],
                &d[11..13],
                &d[13..15]
            )
            .parse()
            .unwrap_or_else(|e| unreachable!("{e}"));
            let credential = reqsign_aws_v4::Credential {
                access_key_id: "key".into(),
                secret_access_key: "secret".into(),
                session_token: Some("token".into()),
                expires_in: None,
            };
            sign_service_at(&mut parts, &credential, "us-east-1", "s3", at)
                .unwrap_or_else(|e| unreachable!("{e}"));
            assert_eq!(parts.headers["authorization"], row.authorization);
        }
    }
}
