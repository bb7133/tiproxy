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

//! Production S3 checksum defaults for the metering SDK's seekable object body.

use bytes::Bytes;
use http::{Method, Request};
use reqsign_core::hash::{base64_encode, hex_sha256};
use reqwest::Url;

pub(super) fn request(
    method: &Method,
    url: &Url,
    body: Bytes,
    checksum_supported: bool,
) -> reqsign_core::Result<Request<Bytes>> {
    let mut request = Request::builder().method(method.clone()).uri(url.as_str());
    let https_put = method == Method::PUT && url.scheme() == "https";
    let mut hash = if https_put {
        "UNSIGNED-PAYLOAD".to_owned()
    } else {
        hex_sha256(&body)
    };
    let body = if method == Method::PUT && checksum_supported {
        let mut crc = flate2::Crc::new();
        crc.update(&body);
        let checksum = base64_encode(&crc.sum().to_be_bytes());
        if https_put && !body.is_empty() {
            // Go sees bytes.Reader's exact length and emits one unsigned chunk,
            // including for objects larger than the unknown-length 64KiB default.
            request = request
                .header("content-encoding", "aws-chunked")
                .header("x-amz-decoded-content-length", body.len())
                .header("x-amz-trailer", "x-amz-checksum-crc32");
            hash = "STREAMING-UNSIGNED-PAYLOAD-TRAILER".into();
            let mut encoded = format!("{:x}\r\n", body.len()).into_bytes();
            encoded.extend_from_slice(&body);
            encoded.extend_from_slice(
                format!("\r\n0\r\nx-amz-checksum-crc32:{checksum}\r\n\r\n").as_bytes(),
            );
            Bytes::from(encoded)
        } else {
            request = request.header("x-amz-checksum-crc32", checksum);
            body
        }
    } else {
        body
    };
    request
        .header("x-amz-content-sha256", hash)
        .header(http::header::CONTENT_LENGTH, body.len())
        .body(body)
        .map_err(|_| super::super::failed())
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::{Response, StatusCode};
    use reqsign_core::{Context, StaticEnv};
    use serde::Deserialize;
    use std::collections::{BTreeMap, HashMap};
    use std::sync::{Arc, Mutex};

    #[derive(Debug, Deserialize, PartialEq, Eq)]
    struct Wire {
        headers: BTreeMap<String, String>,
        body: String,
        length: usize,
        signed: Vec<String>,
    }
    #[derive(Deserialize)]
    #[allow(clippy::struct_excessive_bools)] // Independent Go fixture input/output flags.
    struct Row {
        name: String,
        secure: bool,
        method: String,
        env: Option<HashMap<String, String>>,
        profile: String,
        credentials: String,
        payload: Option<String>,
        retry: bool,
        load_error: bool,
        error: bool,
        requests: Option<Vec<Wire>>,
    }
    #[derive(Debug, Clone)]
    struct Io {
        files: BTreeMap<String, String>,
        requests: Arc<Mutex<Vec<Wire>>>,
        retry: bool,
    }
    impl reqsign_core::FileRead for Io {
        async fn file_read(&self, path: &str) -> reqsign_core::Result<Vec<u8>> {
            self.files
                .get(path)
                .map(|v| v.as_bytes().to_vec())
                .ok_or_else(super::super::super::failed)
        }
    }
    impl reqsign_core::HttpSend for Io {
        async fn http_send(
            &self,
            request: Request<Bytes>,
        ) -> reqsign_core::Result<Response<Bytes>> {
            let headers: BTreeMap<_, _> = [
                "content-encoding",
                "x-amz-checksum-crc32",
                "x-amz-content-sha256",
                "x-amz-decoded-content-length",
                "x-amz-trailer",
                "x-amz-sdk-checksum-algorithm",
            ]
            .into_iter()
            .filter_map(|key| {
                request.headers().get(key).map(|v| {
                    (
                        key.to_owned(),
                        v.to_str()
                            .unwrap_or_else(|e| unreachable!("{e}"))
                            .to_owned(),
                    )
                })
            })
            .collect();
            let authorization = request.headers()["authorization"]
                .to_str()
                .unwrap_or_else(|e| unreachable!("{e}"));
            let signed = authorization
                .split("SignedHeaders=")
                .nth(1)
                .unwrap_or_else(|| unreachable!())
                .split(',')
                .next()
                .unwrap_or_else(|| unreachable!())
                .split(';')
                .filter(|key| headers.contains_key(*key))
                .map(str::to_owned)
                .collect();
            let wire = Wire {
                headers,
                body: base64_encode(request.body()),
                length: request.headers()["content-length"]
                    .to_str()
                    .unwrap_or_else(|e| unreachable!("{e}"))
                    .parse()
                    .unwrap_or_else(|e| unreachable!("{e}")),
                signed,
            };
            let mut requests = self.requests.lock().unwrap_or_else(|e| unreachable!("{e}"));
            requests.push(wire);
            Response::builder()
                .status(if self.retry && requests.len() == 1 {
                    StatusCode::SERVICE_UNAVAILABLE
                } else {
                    StatusCode::OK
                })
                .body(Bytes::new())
                .map_err(|_| super::super::super::failed())
        }
    }
    #[tokio::test(start_paused = true)]
    async fn checksum_wire_matches_default_go_provider_over_real_http_and_tls() {
        let rows: Vec<Row> =
            serde_json::from_str(include_str!("../testdata/aws-s3-checksum-go.json"))
                .unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(rows.len(), 26);
        for row in rows {
            let io = Io {
                files: BTreeMap::from([
                    ("config".into(), format!("[default]\n{}\n", row.profile)),
                    (
                        "credentials".into(),
                        format!("[default]\n{}\n", row.credentials),
                    ),
                ]),
                requests: Arc::default(),
                retry: row.retry,
            };
            let mut envs = row.env.unwrap_or_default();
            envs.insert("AWS_CONFIG_FILE".into(), "config".into());
            envs.insert("AWS_SHARED_CREDENTIALS_FILE".into(), "credentials".into());
            let ctx = Context::new()
                .with_env(StaticEnv {
                    home_dir: None,
                    envs,
                })
                .with_file_read(io.clone())
                .with_http_send(io.clone());
            let signer = super::super::AwsSigner::new(
                &control_config::AwsMeteringConfig {
                    access_key: "key".into(),
                    secret_access_key: "secret".into(),
                    ..Default::default()
                },
                "us-east-1".into(),
                None,
                ctx,
            )
            .await;
            assert_eq!(signer.is_err(), row.load_error, "{} config", row.name);
            if row.load_error {
                continue;
            }
            let signer = signer.unwrap_or_else(|e| unreachable!("{e}"));
            let payload = reqsign_core::hash::base64_decode(&row.payload.unwrap_or_default())
                .unwrap_or_else(|e| unreachable!("{e}"));
            let url = Url::parse(&format!(
                "{}://example.invalid/bucket/meter.json.gz",
                if row.secure { "https" } else { "http" }
            ))
            .unwrap_or_else(|e| unreachable!("{e}"));
            let result = signer
                .request(
                    row.method.parse().unwrap_or_else(|e| unreachable!("{e}")),
                    &url,
                    Bytes::from(payload),
                )
                .await;
            assert_eq!(result.is_err(), row.error, "{} result", row.name);
            assert_eq!(
                *io.requests.lock().unwrap_or_else(|e| unreachable!("{e}")),
                row.requests.unwrap_or_default(),
                "{} secure={}",
                row.name,
                row.secure
            );
        }
    }
}
