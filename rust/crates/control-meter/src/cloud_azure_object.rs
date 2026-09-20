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

//! Azure's production `UploadStream` uses 1 MiB sequential blocks, each with retries.
use super::AzureSigner;
use crate::Error;
use bytes::Bytes;
use http::{Method, Request, Response, StatusCode};
use reqsign_core::{Context, hash::base64_encode};
use reqwest::Url;
use std::time::Duration;

#[path = "cloud_azure_date.rs"]
mod metadata_date;

const BLOCK_SIZE: usize = 1024 * 1024;
fn failed() -> Error {
    Error::Export("Azure object request failed")
}

impl AzureSigner {
    pub(crate) async fn request(
        &self,
        context: &Context,
        method: Method,
        url: &Url,
        body: Bytes,
    ) -> Result<StatusCode, Error> {
        if method != Method::PUT || body.len() < BLOCK_SIZE {
            return self.send_object(context, method, url, body, false).await;
        }
        // UploadStream defaults to concurrency one. A new UUID scopes IDs to
        // this upload, and retries preserve the same block identity and bytes.
        let mut id = [0_u8; 64];
        getrandom::getrandom(&mut id[..16]).map_err(|_| failed())?;
        id[6] = (id[6] & 0x0f) | 0x40;
        id[8] = (id[8] & 0x3f) | 0x80;
        let mut ids = Vec::new();
        for (index, start) in (0..body.len()).step_by(BLOCK_SIZE).enumerate() {
            let index = u32::try_from(index).map_err(|_| failed())?;
            id[16..20].copy_from_slice(&index.to_be_bytes());
            let block_id = base64_encode(&id);
            let mut block_url = url.clone();
            block_url
                .query_pairs_mut()
                .append_pair("comp", "block")
                .append_pair("blockid", &block_id);
            self.send_object(
                context,
                Method::PUT,
                &block_url,
                body.slice(start..body.len().min(start + BLOCK_SIZE)),
                false,
            )
            .await?;
            ids.push(block_id);
        }
        let mut xml = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<BlockList>");
        for id in ids {
            xml.push_str("<Latest>");
            xml.push_str(&id);
            xml.push_str("</Latest>");
        }
        xml.push_str("</BlockList>");
        let mut commit_url = url.clone();
        commit_url
            .query_pairs_mut()
            .append_pair("comp", "blocklist");
        self.send_object(context, Method::PUT, &commit_url, xml.into(), true)
            .await
    }

    async fn send_authorized(
        &self,
        context: &Context,
        mut request: Request<Bytes>,
    ) -> Result<reqsign_core::Result<Response<Bytes>>, Error> {
        let mut response = context.http_send(request.clone()).await;
        if let Self::Bearer(bearer) = self {
            for round in 0..2 {
                let Ok(reply) = &response else {
                    break;
                };
                if reply.status() != StatusCode::UNAUTHORIZED {
                    break;
                }
                let Some((token, cae)) = bearer.challenge(reply.headers(), round == 0).await?
                else {
                    break;
                };
                let mut authorization: http::HeaderValue =
                    format!("Bearer {token}").parse().map_err(|_| failed())?;
                authorization.set_sensitive(true);
                request
                    .headers_mut()
                    .insert(http::header::AUTHORIZATION, authorization);
                response = context.http_send(request.clone()).await;
                // A storage challenge can be followed by one CAE challenge;
                // a CAE replay is terminal for this pass through the pipeline.
                if cae {
                    break;
                }
            }
        }
        Ok(response)
    }

    async fn send_object(
        &self,
        context: &Context,
        method: Method,
        url: &Url,
        body: Bytes,
        block_list: bool,
    ) -> Result<StatusCode, Error> {
        for attempt in 0..4 {
            let mut request = Request::builder()
                .method(method.clone())
                .uri(url.as_str())
                .header("accept", "application/xml")
                .header("content-length", body.len());
            if method == Method::PUT {
                request = request.header(
                    "content-type",
                    if block_list {
                        "application/xml"
                    } else {
                        "application/octet-stream"
                    },
                );
            }
            let (mut parts, payload) = request
                .body(body.clone())
                .map_err(|_| failed())?
                .into_parts();
            self.sign(&mut parts).await?;
            let response = self
                .send_authorized(context, Request::from_parts(parts, payload))
                .await?;
            if let Ok(response) = &response {
                let status = response.status();
                if !matches!(status.as_u16(), 408 | 429 | 500 | 502 | 503 | 504) || attempt == 3 {
                    return finish(response, &method, url);
                }
            } else if attempt == 3 {
                return Err(failed());
            }
            let server_delay = response
                .as_ref()
                .ok()
                .and_then(|r| crate::cloud_azure_managed::retry_after(r.headers()));
            if server_delay.is_some_and(|d| d > Duration::from_secs(60)) {
                return response
                    .as_ref()
                    .map_err(|_| failed())
                    .and_then(|r| finish(r, &method, url));
            }
            let mut random = [0; 2];
            getrandom::getrandom(&mut random).map_err(|_| failed())?;
            let jitter = 0.8 + f64::from(u16::from_le_bytes(random)) / 131_072.0;
            let delay = (Duration::from_millis(800) * ((1_u32 << (attempt + 1)) - 1))
                .mul_f64(jitter)
                .min(Duration::from_secs(60));
            tokio::time::sleep(server_delay.unwrap_or(delay)).await;
        }
        Err(failed())
    }
}

fn finish(response: &Response<Bytes>, method: &Method, url: &Url) -> Result<StatusCode, Error> {
    let status = response.status();
    if (*method == Method::HEAD && status == StatusCode::OK)
        || (*method == Method::PUT && status == StatusCode::CREATED)
    {
        let stage = url.query_pairs().any(|(k, v)| k == "comp" && v == "block");
        validate_metadata(response.headers(), *method == Method::HEAD, stage)?;
        return Ok(status);
    }
    // Real HEAD responses have no body; azcore's error code comes from this
    // header. A failed upload never maps a not-found code to success.
    let code = response
        .headers()
        .get("x-ms-error-code")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    if *method == Method::HEAD
        && (status == StatusCode::NOT_FOUND
            || matches!(
                code,
                "BlobNotFound" | "ResourceNotFound" | "ContainerNotFound"
            ))
    {
        return Ok(StatusCode::NOT_FOUND);
    }
    Err(failed())
}

fn validate_metadata(headers: &http::HeaderMap, head: bool, stage: bool) -> Result<(), Error> {
    // Generated Go response readers use Header.Get (the first value), and
    // parse only their typed fields. Opaque ETags/metadata need no ASCII check.
    for name in headers.keys() {
        let name = name.as_str();
        let date = name == "date"
            || (!stage && name == "last-modified")
            || head
                && matches!(
                    name,
                    "x-ms-access-tier-change-time"
                        | "x-ms-copy-completion-time"
                        | "x-ms-creation-time"
                        | "x-ms-expiry-time"
                        | "x-ms-immutability-policy-until-date"
                        | "x-ms-last-access-time"
                );
        let boolean = if head {
            matches!(
                name,
                "x-ms-access-tier-inferred"
                    | "x-ms-is-current-version"
                    | "x-ms-incremental-copy"
                    | "x-ms-blob-sealed"
                    | "x-ms-server-encrypted"
                    | "x-ms-legal-hold"
            )
        } else {
            name == "x-ms-request-server-encrypted"
        };
        let encoded = name == "content-md5" || !head && name == "x-ms-content-crc64";
        let integer64 = head
            && matches!(
                name,
                "content-length" | "x-ms-blob-sequence-number" | "x-ms-tag-count"
            );
        let integer32 = head && name == "x-ms-blob-committed-block-count";
        if !date && !boolean && !encoded && !integer64 && !integer32 {
            continue;
        }
        let value = headers[name].to_str().map_err(|_| failed())?;
        if value.is_empty() {
            continue;
        }
        if date && !metadata_date::valid(value) {
            return Err(failed());
        }
        if boolean
            && !matches!(
                value,
                "1" | "t"
                    | "T"
                    | "TRUE"
                    | "true"
                    | "True"
                    | "0"
                    | "f"
                    | "F"
                    | "FALSE"
                    | "false"
                    | "False"
            )
        {
            return Err(failed());
        }
        if encoded {
            super::decode_base64(value).map_err(|_| failed())?;
        }
        if integer64 {
            value.parse::<i64>().map_err(|_| failed())?;
        }
        if integer32 {
            value.parse::<i32>().map_err(|_| failed())?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqsign_core::hash::{base64_decode, hex_sha256};
    use serde::Deserialize;
    use std::{
        collections::BTreeMap,
        sync::{Arc, Mutex},
    };
    #[derive(Clone, Default, Deserialize)]
    struct Reply {
        status: u16,
        code: String,
        body: String,
        #[serde(default)]
        headers: BTreeMap<String, String>,
        drop: bool,
    }
    #[derive(Debug, Deserialize, PartialEq, Eq)]
    struct Attempt {
        commit_body: String,
        method: String,
        path: String,
        comp: String,
        length: usize,
        sha256: String,
        blocks: Option<Vec<u32>>,
        content_type: String,
        blob_type: String,
        signed: bool,
        request_id: i32,
        sas: bool,
    }
    #[derive(Deserialize)]
    struct Row {
        name: String,
        method: String,
        size: usize,
        sas: bool,
        failure_comp: String,
        responses: Vec<Reply>,
        attempts: Vec<Attempt>,
        error: bool,
        exists: bool,
    }
    #[derive(Default)]
    struct State {
        replies: Vec<Reply>,
        attempts: Vec<Attempt>,
        failure_comp: String,
        response_index: usize,
        prefix: Option<Vec<u8>>,
    }
    #[derive(Clone, Default)]
    struct Io(Arc<Mutex<State>>);
    impl std::fmt::Debug for Io {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("AzureObjectIo").finish_non_exhaustive()
        }
    }
    fn block_number(id: &str, state: &mut State) -> (u32, String) {
        let mut bytes = base64_decode(id).unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(bytes.len(), 64);
        if let Some(prefix) = &state.prefix {
            assert_eq!(&bytes[..16], prefix);
        } else {
            state.prefix = Some(bytes[..16].to_vec());
        }
        assert_eq!(bytes[6] >> 4, 4);
        assert_eq!(bytes[8] >> 6, 2);
        assert!(bytes[20..].iter().all(|b| *b == 0));
        let n = u32::from_be_bytes(bytes[16..20].try_into().unwrap_or_else(|_| unreachable!()));
        bytes[..16].fill(0);
        (n, base64_encode(&bytes))
    }
    impl reqsign_core::HttpSend for Io {
        async fn http_send(
            &self,
            request: Request<Bytes>,
        ) -> reqsign_core::Result<Response<Bytes>> {
            let mut state = self.0.lock().unwrap_or_else(|e| unreachable!("{e}"));
            let url =
                Url::parse(&request.uri().to_string()).unwrap_or_else(|e| unreachable!("{e}"));
            let query = url.query_pairs().collect::<BTreeMap<_, _>>();
            let comp = query.get("comp").map_or("", |v| v.as_ref());
            let mut blocks = None;
            let mut commit_body = String::new();
            if comp == "block" {
                blocks = Some(vec![block_number(&query["blockid"], &mut state).0]);
            }
            let sha256 = if comp == "blocklist" {
                #[derive(Deserialize)]
                struct List {
                    #[serde(rename = "Latest")]
                    latest: Vec<String>,
                }
                let raw =
                    std::str::from_utf8(request.body()).unwrap_or_else(|e| unreachable!("{e}"));
                let list: List =
                    quick_xml::de::from_str(raw).unwrap_or_else(|e| unreachable!("{e}"));
                commit_body = raw.to_owned();
                let mut nums = Vec::new();
                for id in list.latest {
                    let (n, normal) = block_number(&id, &mut state);
                    nums.push(n);
                    commit_body = commit_body.replace(&id, &normal);
                }
                blocks = Some(nums);
                "blocklist".into()
            } else {
                hex_sha256(request.body())
            };
            let header = |name| {
                request
                    .headers()
                    .get(name)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or_default()
                    .to_owned()
            };
            state.attempts.push(Attempt {
                commit_body,
                method: request.method().to_string(),
                path: request.uri().path().to_owned(),
                comp: comp.to_owned(),
                length: request.body().len(),
                sha256,
                blocks,
                content_type: header("content-type"),
                blob_type: header("x-ms-blob-type"),
                signed: header("authorization").starts_with("SharedKey account:"),
                request_id: if header("x-ms-client-request-id").is_empty() {
                    -1
                } else {
                    0
                },
                sas: query.get("sig").is_some_and(|v| v == "fake"),
            });
            let reply = if state.failure_comp.is_empty() || state.failure_comp == comp {
                let reply =
                    state.replies[state.response_index.min(state.replies.len() - 1)].clone();
                state.response_index += 1;
                reply
            } else {
                Reply::default()
            };
            if reply.drop {
                return Err(reqsign_core::Error::unexpected(
                    "synthetic disconnected response",
                ));
            }
            let status = if reply.status == 0 {
                if request.method() == Method::HEAD {
                    200
                } else {
                    201
                }
            } else {
                reply.status
            };
            let mut response = Response::builder().status(status);
            if !reply.code.is_empty() {
                response = response.header("x-ms-error-code", reply.code);
            }
            for (k, v) in reply.headers {
                response = response.header(k, v);
            }
            response
                .body(if request.method() == Method::HEAD {
                    Bytes::new()
                } else {
                    reply.body.into()
                })
                .map_err(|_| reqsign_core::Error::unexpected("fixture response failed"))
        }
    }
    #[tokio::test(start_paused = true)]
    async fn retry_stream_blocks_and_results_match_real_go_provider() {
        let rows: Vec<Row> = serde_json::from_str(include_str!("../testdata/azure-object-go.json"))
            .unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(rows.len(), 243);
        for row in rows {
            let io = Io::default();
            {
                let mut state = io.0.lock().unwrap_or_else(|e| unreachable!("{e}"));
                state.replies = row.responses;
                state.failure_comp = row.failure_comp;
            }
            let context = Context::new().with_http_send(io.clone());
            let signer = if row.sas {
                AzureSigner::Sas
            } else {
                AzureSigner::SharedKey {
                    account: "account".into(),
                    key: b"fake-account-key".to_vec(),
                }
            };
            let mut url =
                Url::parse("http://127.0.0.1/base/bucket/prefix%20space%2F%25text%2Fkey.json.gz")
                    .unwrap_or_else(|e| unreachable!("{e}"));
            if row.sas {
                url.set_query(Some("sig=fake&sp=rw&sv=2025-11-05"));
            }
            let method: Method = row.method.parse().unwrap_or_else(|e| unreachable!("{e}"));
            let result = signer
                .request(&context, method.clone(), &url, vec![b'p'; row.size].into())
                .await;
            let label = format!("{} {}", row.method, row.name);
            assert_eq!(result.is_err(), row.error, "{label}");
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
