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

//! COS uses three immediate attempts for HEAD and seekable metering uploads.
use super::CosSigner;
use bytes::Bytes;
use http::{Method, Request, StatusCode};
use reqwest::Url;

impl CosSigner {
    pub(crate) async fn request(
        &self,
        method: Method,
        url: &Url,
        body: Bytes,
    ) -> reqsign_core::Result<StatusCode> {
        // Go uses http.NoBody for an empty seekable upload, skipping CRC.
        let checksum = (method == Method::PUT && !body.is_empty())
            .then(|| crate::cloud_crc64::checksum(&body));
        for attempt in 0..3 {
            let mut request = Request::builder()
                .method(method.clone())
                .uri(url.as_str())
                .header(http::header::CONTENT_LENGTH, body.len());
            if attempt > 0 {
                request = request.header("x-cos-sdk-retry", "true");
            }
            let (mut parts, body) = request
                .body(body.clone())
                .map_err(|_| super::failed())?
                .into_parts();
            let result = async {
                self.sign(&mut parts).await?;
                self.context
                    .http_send(Request::from_parts(parts, body))
                    .await
            }
            .await;
            let response = match result {
                Ok(response) => response,
                Err(_) if attempt < 2 => continue,
                Err(_) => return Err(super::failed()),
            };
            let status = response.status();
            if status.is_success() {
                if let Some(checksum) = checksum {
                    let raw = response
                        .headers()
                        .get("x-cos-hash-crc64ecma")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or_default();
                    // Go ignores ParseUint's error and compares its numeric value;
                    // a missing/malformed value is zero, overflow saturates.
                    let returned = if !raw.is_empty() && raw.bytes().all(|b| b.is_ascii_digit()) {
                        raw.parse::<u64>().unwrap_or(u64::MAX)
                    } else {
                        0
                    };
                    if returned != checksum {
                        return Err(super::failed());
                    }
                }
                return Ok(status);
            }
            if status.as_u16() < 500 || attempt == 2 {
                return Ok(status);
            }
        }
        Err(super::failed())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use std::sync::{Arc, Mutex};
    #[derive(Clone, Deserialize)]
    struct Reply {
        status: u16,
        body: String,
        crc: String,
        transport: bool,
    }
    #[derive(Debug, Deserialize, PartialEq, Eq)]
    struct Attempt {
        retry: bool,
        body: String,
        signed: bool,
    }
    #[derive(Deserialize)]
    struct Row {
        name: String,
        method: String,
        payload: String,
        responses: Vec<Reply>,
        attempts: Vec<Attempt>,
        exists: bool,
        error: bool,
    }
    #[derive(Default)]
    struct State {
        replies: Vec<Reply>,
        attempts: Vec<Attempt>,
    }
    #[derive(Clone, Default)]
    struct Io(Arc<Mutex<State>>);
    impl std::fmt::Debug for Io {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("CosIo").finish_non_exhaustive()
        }
    }
    impl reqsign_core::HttpSend for Io {
        async fn http_send(
            &self,
            request: Request<Bytes>,
        ) -> reqsign_core::Result<http::Response<Bytes>> {
            let mut state = self.0.lock().unwrap_or_else(|e| unreachable!("{e}"));
            let reply = state.replies[state.attempts.len().min(state.replies.len() - 1)].clone();
            assert_eq!(request.uri().path(), "/object");
            state.attempts.push(Attempt {
                retry: request
                    .headers()
                    .get("x-cos-sdk-retry")
                    .is_some_and(|v| v == "true"),
                body: String::from_utf8(request.body().to_vec())
                    .unwrap_or_else(|e| unreachable!("{e}")),
                signed: request
                    .headers()
                    .get("authorization")
                    .and_then(|v| v.to_str().ok())
                    .is_some_and(|s| s.starts_with("q-sign-algorithm=sha1")),
            });
            if reply.transport {
                return Err(super::super::failed()
                    .with_source(crate::cloud_context::HttpFailure::Connection));
            }
            let mut response = http::Response::builder().status(reply.status);
            if !reply.crc.is_empty() {
                response = response.header("x-cos-hash-crc64ecma", reply.crc);
            }
            response
                .body(reply.body.into())
                .map_err(|_| super::super::failed())
        }
    }
    #[tokio::test]
    async fn seekable_object_retries_and_crc_match_actual_go_provider() {
        let rows: Vec<Row> = serde_json::from_str(include_str!("../testdata/cos-object-go.json"))
            .unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(rows.len(), 36);
        for row in rows {
            let io = Io::default();
            io.0.lock().unwrap_or_else(|e| unreachable!("{e}")).replies = row.responses;
            let ctx = reqsign_core::Context::new()
                .with_http_send(io.clone())
                .with_env(reqsign_core::StaticEnv::default());
            let signer = CosSigner::new(
                &control_config::CloudMeteringConfig {
                    access_key: "key".into(),
                    secret_access_key: "secret".into(),
                    ..Default::default()
                },
                ctx,
            );
            let method: Method = row.method.parse().unwrap_or_else(|e| unreachable!("{e}"));
            let result = signer
                .request(
                    method.clone(),
                    &Url::parse("https://bucket-123456.cos.ap-guangzhou.myqcloud.com/object")
                        .unwrap_or_else(|e| unreachable!("{e}")),
                    row.payload.into(),
                )
                .await;
            let error = result.as_ref().map_or(true, |s| {
                !(s.is_success() || method == Method::HEAD && *s == StatusCode::NOT_FOUND)
            });
            let label = format!("{} {}", row.method, row.name);
            assert_eq!(error, row.error, "{label}");
            if method == Method::HEAD {
                assert_eq!(result.is_ok_and(|s| s.is_success()), row.exists, "{label}");
            }
            assert_eq!(
                io.0.lock().unwrap_or_else(|e| unreachable!("{e}")).attempts,
                row.attempts,
                "{label}"
            );
        }
    }
}
