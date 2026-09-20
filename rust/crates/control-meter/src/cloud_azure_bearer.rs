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

//! Azure storage resource and continuous-access authentication challenges.
use crate::{
    Error,
    cloud_azure_identity::{AzureDefault, SCOPE},
};
use base64::{
    Engine as _,
    engine::{GeneralPurpose, GeneralPurposeConfig},
};
use http::HeaderMap;
use regex::Regex;
use std::{collections::BTreeMap, sync::OnceLock};
use tokio::sync::Mutex;

pub(crate) struct Bearer {
    source: AzureDefault,
    scope: Mutex<String>,
}
impl Bearer {
    pub(crate) fn new(source: AzureDefault) -> Self {
        Self {
            source,
            scope: Mutex::new(SCOPE.into()),
        }
    }
    pub(crate) async fn token(&self) -> Result<String, Error> {
        let scope = self.scope.lock().await;
        if scope.as_str() == SCOPE {
            self.source.token().await
        } else {
            self.source.token_for(&scope, Vec::new()).await
        }
    }
    pub(crate) async fn challenge(
        &self,
        headers: &HeaderMap,
        allow_resource: bool,
    ) -> Result<Option<(String, bool)>, Error> {
        let first = headers
            .get("www-authenticate")
            .and_then(|h| h.to_str().ok())
            .unwrap_or_default();
        if first.is_empty() {
            return Ok(None);
        }
        // CAE takes precedence over the storage resource challenge and may
        // appear in any WWW-Authenticate header, not just the first value.
        if let Some(claims) = parse_cae(headers)? {
            let scope = self.scope.lock().await;
            return self
                .source
                .token_for(&scope, claims)
                .await
                .map(|token| Some((token, true)));
        }
        if !allow_resource {
            return Ok(None);
        }
        // This intentionally mirrors the pinned storage SDK's permissive
        // space-delimited parser. Its extracted tenant is not used for auth.
        let text = first.replace("Bearer ", "");
        let mut resource = None;
        for part in text.split(' ') {
            let pair: Vec<_> = part.split('=').collect();
            if pair.len() == 2 && pair[0] == "resource_id" {
                let value = pair[1].replace('"', "");
                resource = Some(value.strip_suffix(',').unwrap_or(&value).to_owned());
            }
        }
        let mut resource = resource.filter(|v| !v.is_empty()).ok_or_else(failed)?;
        if !resource.ends_with("/.default") {
            resource.push_str("/.default");
        }
        let mut scope = self.scope.lock().await;
        *scope = resource;
        self.source
            .token_for(&scope, Vec::new())
            .await
            .map(|token| Some((token, false)))
    }
}
fn failed() -> Error {
    Error::Export("Azure authentication challenge failed")
}

fn parse_cae(headers: &HeaderMap) -> Result<Option<Vec<u8>>, Error> {
    static PATTERNS: OnceLock<Option<(Regex, Regex)>> = OnceLock::new();
    let (challenge, params) = PATTERNS
        .get_or_init(|| {
            Some((
                Regex::new(r#"(?:([A-Za-z0-9_]+) ((?:[A-Za-z0-9_]+="[^"]*",?[\t\n\f\r ]*)+))"#)
                    .ok()?,
                Regex::new(r#"([A-Za-z0-9_]+)="([^"]*)""#).ok()?,
            ))
        })
        .as_ref()
        .ok_or_else(failed)?;
    for header in headers.get_all("www-authenticate") {
        let Ok(header) = header.to_str() else {
            continue;
        };
        for capture in challenge.captures_iter(header) {
            if &capture[1] != "Bearer" {
                continue;
            }
            let fields: BTreeMap<_, _> = params
                .captures_iter(&capture[2])
                .map(|c| (c[1].to_owned(), c[2].to_owned()))
                .collect();
            if fields.get("error").map(String::as_str) != Some("insufficient_claims") {
                continue;
            }
            if let Some(value) = fields.get("claims").filter(|v| !v.is_empty()) {
                // Go's non-Strict StdEncoding accepts nonzero trailing bits.
                let decoder = GeneralPurpose::new(
                    &base64::alphabet::STANDARD,
                    GeneralPurposeConfig::new().with_decode_allow_trailing_bits(true),
                );
                let value = value.replace(['\r', '\n'], "");
                return decoder.decode(value).map(Some).map_err(|_| failed());
            }
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use http::{Method, Request, Response};
    use reqsign_core::{Context, StaticEnv, hash::hex_sha256};
    use serde::Deserialize;
    use std::{
        collections::HashMap,
        sync::{Arc, Mutex as StdMutex},
    };
    #[derive(Clone, Deserialize)]
    struct Reply {
        status: u16,
        challenge: Option<Vec<String>>,
    }
    #[derive(Deserialize)]
    struct Operation {
        method: String,
        replies: Vec<Reply>,
        error: bool,
        exists: bool,
    }
    #[derive(Debug, Deserialize, PartialEq, Eq)]
    struct Observed {
        kind: String,
        value: String,
        method: String,
        size: usize,
        sha256: String,
    }
    #[derive(Deserialize)]
    struct Row {
        name: String,
        ops: Vec<Operation>,
        seen: Vec<Observed>,
    }
    #[derive(Default)]
    struct State {
        replies: Vec<Reply>,
        next: usize,
        token: usize,
        seen: Vec<Observed>,
    }
    #[derive(Clone, Default)]
    struct Io(Arc<StdMutex<State>>);
    impl std::fmt::Debug for Io {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("BearerFixtureIo")
        }
    }
    impl reqsign_core::HttpSend for Io {
        async fn http_send(
            &self,
            request: Request<Bytes>,
        ) -> reqsign_core::Result<Response<Bytes>> {
            let mut state = self.0.lock().unwrap_or_else(|e| unreachable!("{e}"));
            let url = reqwest::Url::parse(&request.uri().to_string())
                .unwrap_or_else(|e| unreachable!("{e}"));
            if url.path() == "/metadata" {
                let resource = url
                    .query_pairs()
                    .find(|(k, _)| k == "resource")
                    .map(|(_, v)| v.into_owned())
                    .unwrap_or_default();
                state.token += 1;
                state.seen.push(Observed {
                    kind: "metadata".into(),
                    value: resource,
                    method: request.method().to_string(),
                    size: 0,
                    sha256: String::new(),
                });
                let body = serde_json::json!({"access_token":format!("fake-{}", state.token),"expires_on":"4070908800","token_type":"Bearer"}).to_string();
                return Response::builder()
                    .status(200)
                    .body(body.into())
                    .map_err(|_| reqsign_core::Error::unexpected("fixture response"));
            }
            state.seen.push(Observed {
                kind: "object".into(),
                value: request
                    .headers()
                    .get("authorization")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or_default()
                    .into(),
                method: request.method().to_string(),
                size: request.body().len(),
                sha256: hex_sha256(request.body()),
            });
            let reply = state.replies[state.next.min(state.replies.len() - 1)].clone();
            state.next += 1;
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
            for header in reply.challenge.unwrap_or_default() {
                response = response.header("www-authenticate", header);
            }
            response
                .body(Bytes::new())
                .map_err(|_| reqsign_core::Error::unexpected("fixture response"))
        }
    }
    #[tokio::test(start_paused = true)]
    async fn managed_bearer_challenges_match_actual_go_default_credential() {
        let rows: Vec<Row> = serde_json::from_str(include_str!("../testdata/azure-bearer-go.json"))
            .unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(rows.len(), 60);
        for row in rows {
            let io = Io::default();
            let context = Context::new()
                .with_http_send(io.clone())
                .with_env(StaticEnv {
                    envs: HashMap::from([
                        (
                            "AZURE_TOKEN_CREDENTIALS".into(),
                            "ManagedIdentityCredential".into(),
                        ),
                        ("AZURE_CLIENT_ID".into(), "fake-client".into()),
                        (
                            "IDENTITY_ENDPOINT".into(),
                            "https://fixture.invalid/metadata".into(),
                        ),
                        ("IDENTITY_HEADER".into(), "fake-header".into()),
                    ]),
                    ..Default::default()
                });
            let source = AzureDefault::new(reqwest::Client::new(), context.clone())
                .await
                .unwrap_or_else(|e| unreachable!("{e}"));
            let signer = crate::cloud_azure::AzureSigner::Bearer(Bearer::new(source));
            let url = reqwest::Url::parse("https://fixture.invalid/bucket/prefix%2Fkey.json.gz")
                .unwrap_or_else(|e| unreachable!("{e}"));
            for op in row.ops {
                {
                    let mut state = io.0.lock().unwrap_or_else(|e| unreachable!("{e}"));
                    state.replies = op.replies;
                    state.next = 0;
                }
                let method: Method = op.method.parse().unwrap_or_else(|e| unreachable!("{e}"));
                let body = if method == Method::PUT {
                    Bytes::from_static(b"payload")
                } else {
                    Bytes::new()
                };
                let result = signer.request(&context, method.clone(), &url, body).await;
                assert_eq!(result.is_err(), op.error, "{}", row.name);
                if method == Method::HEAD {
                    assert_eq!(
                        result.is_ok_and(|s| s.is_success()),
                        op.exists,
                        "{}",
                        row.name
                    );
                }
            }
            assert_eq!(
                io.0.lock().unwrap_or_else(|e| unreachable!("{e}")).seen,
                row.seen,
                "{}",
                row.name
            );
        }
    }
}
