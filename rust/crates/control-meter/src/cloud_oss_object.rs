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

//! OSS seekable HEAD/PUT retries, response CRC64 and successful-operation clock state.
use super::OssSigner;
use bytes::Bytes;
use http::{Method, Request, Response, StatusCode};
use reqsign_core::{hash::base64_decode, time::Timestamp};
use reqwest::Url;
use std::{sync::atomic::Ordering, time::Duration};

impl OssSigner {
    pub(crate) async fn request(
        &self,
        method: Method,
        url: &Url,
        body: Bytes,
    ) -> reqsign_core::Result<StatusCode> {
        let initial_skew = self.object_skew.load(Ordering::Relaxed);
        let mut skew = initial_skew;
        let checksum =
            (method == Method::PUT).then(|| crate::cloud_crc64::checksum(&body).to_string());
        for attempt in 0..3 {
            if attempt > 0 {
                let mut random = [0_u8; 8];
                getrandom::getrandom(&mut random).map_err(|_| super::failed())?;
                // SDK RetryDelay receives the next one-based attempt (2, then 3).
                let ceiling = 200_000_000_u64 << (attempt + 1);
                tokio::time::sleep(Duration::from_nanos(u64::from_le_bytes(random) % ceiling))
                    .await;
            }
            let mut request = Request::builder()
                .method(method.clone())
                .uri(url.as_str())
                .header(http::header::CONTENT_LENGTH, body.len());
            if method == Method::PUT {
                let content_type = if url.path().to_ascii_lowercase().ends_with(".gz") {
                    &self.gzip_content_type
                } else {
                    "application/octet-stream"
                };
                request = request.header(http::header::CONTENT_TYPE, content_type);
            }
            let (mut parts, payload) = request
                .body(body.clone())
                .map_err(|_| super::failed())?
                .into_parts();
            let credential = match self.credential(false).await {
                Ok(Some(credential)) => credential,
                Err(error) if attempt < 2 && retry_transport(&error) => continue,
                _ => return Err(super::failed()),
            };
            let sign_time = crate::cloud_aws_clock::signing_time(skew);
            // Credentials are reloaded per attempt. Signing errors are terminal;
            // transport failures retain only a sanitized retry classification.
            super::signing::sign_at(
                &mut parts,
                &credential,
                &self.region,
                &self.bucket,
                sign_time,
            )?;
            let response = match self
                .context
                .http_send(Request::from_parts(parts, payload))
                .await
            {
                Ok(response) => response,
                Err(error) if attempt < 2 && retry_transport(&error) => continue,
                Err(_) => return Err(super::failed()),
            };
            let status = response.status();
            if status.is_success() {
                let crc = response
                    .headers()
                    .get("x-oss-hash-crc64ecma")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or_default();
                // Unlike COS, OSS accepts a missing CRC and retries a mismatch,
                // including empty uploads. Comparison is decimal-string exact.
                if checksum
                    .as_ref()
                    .is_some_and(|v| !crc.is_empty() && crc != v)
                {
                    if attempt < 2 {
                        continue;
                    }
                    return Err(super::failed());
                }
                if skew != initial_skew {
                    self.object_skew.store(skew, Ordering::Relaxed);
                }
                return Ok(status);
            }
            let code = service_code(&response);
            if code == "RequestTimeTooSkewed" {
                let server = response
                    .headers()
                    .get("date")
                    .and_then(|v| v.to_str().ok())
                    .and_then(parse_date)
                    .unwrap_or_else(Timestamp::now);
                // Deliberately subtract the previous corrected signing time,
                // matching SDK 1.2.3 (repeated corrections can alternate).
                skew = difference(server, sign_time);
            }
            let retry = status.as_u16() >= 500
                || matches!(status.as_u16(), 401 | 408 | 429)
                || matches!(code.as_str(), "RequestTimeTooSkewed" | "BadRequest");
            if retry && attempt < 2 {
                continue;
            }
            // Exists maps the final typed service error only, after SDK retries.
            if method == Method::HEAD && (status == StatusCode::NOT_FOUND || code == "NoSuchKey") {
                return Ok(StatusCode::NOT_FOUND);
            }
            return Err(super::failed());
        }
        Err(super::failed())
    }
}

fn retry_transport(error: &reqsign_core::Error) -> bool {
    use std::error::Error as _;
    matches!(
        error
            .source()
            .and_then(|e| e.downcast_ref::<crate::cloud_context::HttpFailure>()),
        Some(
            crate::cloud_context::HttpFailure::Timeout
                | crate::cloud_context::HttpFailure::Connection
        )
    )
}

fn difference(a: Timestamp, b: Timestamp) -> i64 {
    let nanos = (i128::from(a.as_second()) - i128::from(b.as_second())) * 1_000_000_000
        + i128::from(a.subsec_nanosecond())
        - i128::from(b.subsec_nanosecond());
    i64::try_from(nanos).unwrap_or(if nanos < 0 { i64::MIN } else { i64::MAX })
}

fn parse_date(value: &str) -> Option<Timestamp> {
    // OSS accepts only Go's http.TimeFormat, unlike Smithy's three layouts.
    let fields: Vec<_> = value.split(' ').filter(|s| !s.is_empty()).collect();
    if !matches!(fields.as_slice(),[weekday,day,_,year,_,"GMT"] if weekday.len()==4 && day.len()==2 && year.len()==4)
    {
        return None;
    }
    crate::cloud_aws_clock::parse_http_date(value)
}

fn service_code(response: &Response<Bytes>) -> String {
    let decoded;
    let mut body = response.body().as_ref();
    if body.is_empty()
        && let Some(raw) = response.headers().get("x-oss-err")
    {
        decoded = base64_decode(raw.to_str().unwrap_or_default()).unwrap_or_default();
        body = &decoded;
    }
    // Go xml.Unmarshal can retain Code even if a later XML token is malformed.
    let mut reader = quick_xml::Reader::from_reader(body);
    let mut depth = 0;
    let mut start = None;
    let mut code = "BadErrorResponse".to_owned();
    loop {
        let before = usize::try_from(reader.buffer_position()).unwrap_or(body.len());
        match reader.read_event() {
            Ok(quick_xml::events::Event::Start(e)) => {
                depth += 1;
                if depth == 1 && e.local_name().as_ref() != b"Error" {
                    break;
                }
                if depth == 2 && e.local_name().as_ref() == b"Code" {
                    start = Some(before);
                }
            }
            Ok(quick_xml::events::Event::Empty(e))
                if depth == 1 && e.local_name().as_ref() == b"Code" =>
            {
                code.clear();
            }
            Ok(quick_xml::events::Event::End(_)) => {
                if depth == 2
                    && let Some(begin) = start.take()
                    && let Ok(end) = usize::try_from(reader.buffer_position())
                    && let Some(slice) = body.get(begin..end)
                    && let Ok(xml) = std::str::from_utf8(slice)
                    && let Ok(value) = quick_xml::de::from_str::<String>(xml)
                {
                    code = value;
                }
                depth -= 1;
            }
            Ok(quick_xml::events::Event::Eof) | Err(_) => break,
            _ => (),
        }
    }
    code
}

// Metering writes .json.gz. Go mime.TypeByExtension first consults Unix host
// MIME files, then the OSS SDK fallback (.gz = application/x-gzip).
pub(super) fn gzip_content_type() -> String {
    for name in ["/usr/local/share/mime/globs2", "/usr/share/mime/globs2"] {
        if let Ok(text) = std::fs::read_to_string(name) {
            for line in text.lines() {
                let fields: Vec<_> = line.split(':').collect();
                if fields.len() >= 3 && !fields[0].starts_with('#') && fields[2] == "*.gz" {
                    return fields[1].to_owned();
                }
            }
            return "application/x-gzip".into();
        }
    }
    let mut value = "application/x-gzip".to_owned();
    for name in [
        "/etc/mime.types",
        "/etc/apache2/mime.types",
        "/etc/apache/mime.types",
        "/etc/httpd/conf/mime.types",
    ] {
        if let Ok(text) = std::fs::read_to_string(name) {
            for line in text.lines() {
                let mut fields = line.split_whitespace();
                if let Some(kind) = fields.next()
                    && !kind.starts_with('#')
                    && fields
                        .take_while(|v| !v.starts_with('#'))
                        .any(|v| v == "gz")
                {
                    kind.clone_into(&mut value);
                }
            }
        }
    }
    value
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
        transport: String,
        date: String,
        header_error: String,
    }
    #[derive(Debug, Deserialize)]
    struct Attempt {
        body: String,
        content_type: String,
        path: String,
        signed: bool,
        offset: i64,
    }
    #[derive(Deserialize)]
    struct Operation {
        responses: Vec<Reply>,
        attempts: Vec<Attempt>,
        exists: bool,
        error: bool,
    }
    #[derive(Deserialize)]
    struct Row {
        name: String,
        method: String,
        key: String,
        payload: String,
        real_http: bool,
        operations: Vec<Operation>,
    }
    #[derive(Deserialize)]
    struct Signature {
        method: String,
        key: String,
        time: String,
        content_type: String,
        authorization: String,
    }
    #[derive(Deserialize)]
    struct Fixture {
        rows: Vec<Row>,
        signatures: Vec<Signature>,
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
            f.debug_struct("OssIo").finish_non_exhaustive()
        }
    }
    impl reqsign_core::HttpSend for Io {
        async fn http_send(
            &self,
            request: Request<Bytes>,
        ) -> reqsign_core::Result<Response<Bytes>> {
            let mut state = self.0.lock().unwrap_or_else(|e| unreachable!("{e}"));
            let reply = state.replies[state.attempts.len().min(state.replies.len() - 1)].clone();
            let value = |name| {
                request
                    .headers()
                    .get(name)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or_default()
                    .to_owned()
            };
            let raw = value("x-oss-date");
            let date: Timestamp = format!(
                "{}-{}-{}T{}:{}:{}Z",
                &raw[..4],
                &raw[4..6],
                &raw[6..8],
                &raw[9..11],
                &raw[11..13],
                &raw[13..15]
            )
            .parse()
            .unwrap_or_else(|e| unreachable!("{e}"));
            state.attempts.push(Attempt {
                body: String::from_utf8(request.body().to_vec())
                    .unwrap_or_else(|e| unreachable!("{e}")),
                content_type: value("content-type"),
                path: request.uri().path().to_owned(),
                signed: value("authorization").starts_with("OSS4-HMAC-SHA256 "),
                offset: date.as_second() - Timestamp::now().as_second(),
            });
            if !reply.transport.is_empty() {
                let error = super::super::failed();
                return Err(
                    if [
                        "connection reset",
                        "connection refused",
                        "EOF",
                        "unexpected EOF",
                    ]
                    .contains(&reply.transport.as_str())
                    {
                        error.with_source(crate::cloud_context::HttpFailure::Connection)
                    } else {
                        error.with_source(crate::cloud_context::HttpFailure::OtherSend)
                    },
                );
            }
            let mut response = Response::builder().status(reply.status);
            if !reply.crc.is_empty() {
                response = response.header("x-oss-hash-crc64ecma", reply.crc);
            }
            if !reply.header_error.is_empty() {
                response = response.header("x-oss-err", reply.header_error);
            }
            if !reply.date.is_empty() {
                let date = reply.date.parse::<i64>().map_or(reply.date, |seconds| {
                    crate::cloud_aws_clock::signing_time(seconds * 1_000_000_000).format_http_date()
                });
                response = response.header("date", date);
            }
            response
                .body(reply.body.into())
                .map_err(|_| super::super::failed())
        }
    }
    fn fixture() -> Fixture {
        serde_json::from_str(include_str!("../testdata/oss-object-go.json"))
            .unwrap_or_else(|e| unreachable!("{e}"))
    }
    #[tokio::test(start_paused = true)]
    async fn seekable_attempts_crc_and_client_clock_match_actual_go_provider() {
        let rows = fixture().rows;
        assert_eq!(rows.len(), 100);
        for row in rows {
            let io = Io::default();
            let context = reqsign_core::Context::new()
                .with_env(reqsign_core::StaticEnv::default())
                .with_http_send(io.clone());
            let signer = OssSigner::new(
                &control_config::CloudMeteringConfig {
                    access_key: "key".into(),
                    secret_access_key: "secret".into(),
                    session_token: "token".into(),
                    ..Default::default()
                },
                "cn-hangzhou",
                "bucket",
                context,
            );
            let base = if row.real_http {
                "http://127.0.0.1/bucket"
            } else {
                "https://bucket.oss-cn-hangzhou.aliyuncs.com"
            };
            let url = Url::parse(&format!(
                "{base}/{}",
                row.key
                    .split('/')
                    .map(super::super::percent)
                    .collect::<Vec<_>>()
                    .join("/")
            ))
            .unwrap_or_else(|e| unreachable!("{e}"));
            let method: Method = row.method.parse().unwrap_or_else(|e| unreachable!("{e}"));
            for (index, op) in row.operations.into_iter().enumerate() {
                {
                    let mut state = io.0.lock().unwrap_or_else(|e| unreachable!("{e}"));
                    state.replies = op.responses;
                    state.attempts.clear();
                }
                let result = signer
                    .request(method.clone(), &url, row.payload.clone().into())
                    .await;
                let label = format!("{} {} op{index}", row.method, row.name);
                assert_eq!(result.is_err(), op.error, "{label}");
                if method == Method::HEAD {
                    assert_eq!(result.is_ok_and(|v| v.is_success()), op.exists, "{label}");
                }
                let state = io.0.lock().unwrap_or_else(|e| unreachable!("{e}"));
                assert_eq!(state.attempts.len(), op.attempts.len(), "{label}");
                for (got, want) in state.attempts.iter().zip(op.attempts) {
                    assert_eq!(got.body, want.body, "{label}");
                    assert_eq!(got.path, want.path, "{label}");
                    assert_eq!(got.signed, want.signed, "{label}");
                    // Fixture host MIME was recorded on macOS; Linux may use the
                    // system MIME database, as does the original Go provider.
                    let content_type = if want.content_type.is_empty() {
                        ""
                    } else {
                        &signer.gzip_content_type
                    };
                    assert_eq!(got.content_type, content_type, "{label}");
                    assert!(
                        got.offset.abs_diff(want.offset) <= 2,
                        "{label}: got {} want {}",
                        got.offset,
                        want.offset
                    );
                }
            }
        }
    }
    #[test]
    fn corrected_v4_signatures_match_actual_go_signer() {
        let rows = fixture().signatures;
        assert_eq!(rows.len(), 6);
        for row in rows {
            let mut url = Url::parse("https://bucket.oss-cn-hangzhou.aliyuncs.com")
                .unwrap_or_else(|e| unreachable!("{e}"));
            url.set_path(&format!(
                "/{}",
                row.key
                    .split('/')
                    .map(super::super::percent)
                    .collect::<Vec<_>>()
                    .join("/")
            ));
            let mut req = Request::builder()
                .method(row.method.as_str())
                .uri(url.as_str());
            if !row.content_type.is_empty() {
                req = req.header("content-type", &row.content_type);
            }
            let mut parts = req
                .body(())
                .unwrap_or_else(|e| unreachable!("{e}"))
                .into_parts()
                .0;
            let credential = reqsign_aliyun_oss::Credential {
                access_key_id: "key".into(),
                access_key_secret: "secret".into(),
                security_token: Some("token".into()),
                expires_in: None,
            };
            super::super::signing::sign_at(
                &mut parts,
                &credential,
                "cn-hangzhou",
                "bucket",
                row.time.parse().unwrap_or_else(|e| unreachable!("{e}")),
            )
            .unwrap_or_else(|e| unreachable!("{e}"));
            assert_eq!(
                parts.headers["authorization"], row.authorization,
                "{} {}",
                row.method, row.key
            );
        }
    }
}
