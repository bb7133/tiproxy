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

//! Azure identity SDK composition with bounded application-owned transport.

//! Managed identity sources and failure classification from the pinned Go SDK.

use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use azure_core::credentials::{AccessToken, TokenCredential};
use azure_core::time::OffsetDateTime;
use bytes::Bytes;
use http::{Method, Request, Response, StatusCode};
use reqsign_core::Context;
use tokio::sync::Mutex;

#[cfg(test)]
const SCOPE: &str = "https://storage.azure.com/.default";
#[cfg(test)]
const RESOURCE: &str = "https://storage.azure.com";
const IMDS: &str = "http://169.254.169.254/metadata/identity/oauth2/token";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Source {
    Imds,
    AppService,
    MachineLearning,
    CloudShell,
    ServiceFabric,
    Arc,
}

/// A typed, sanitized distinction: only unavailable managed identity permits fallback.
#[derive(Debug, thiserror::Error)]
#[error("Azure managed identity unavailable")]
struct Unavailable;

pub(crate) fn unavailable(error: &azure_core::Error) -> bool {
    error.downcast_ref::<Unavailable>().is_some()
}

fn failure() -> azure_core::Error {
    azure_core::Error::with_message(
        azure_core::error::ErrorKind::Credential,
        "Azure managed identity authentication failed",
    )
}
fn missing() -> azure_core::Error {
    azure_core::Error::new(azure_core::error::ErrorKind::Credential, Unavailable)
}

struct Cached {
    token: AccessToken,
    // MSAL stores a server-supplied refresh_in. The synthetic half-life on the
    // returned AuthResult is set after cache.Write, so it is not a cache trigger.
    refresh_on: Option<OffsetDateTime>,
}

pub(crate) struct Managed {
    context: Context,
    source: Source,
    endpoint: String,
    secret: String,
    client_id: Option<String>,
    ml_default_client_id: String,
    probe: AtomicBool,
    cached: Mutex<BTreeMap<String, Cached>>,
}

impl fmt::Debug for Managed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AzureManagedIdentity")
            .field("source", &self.source)
            .finish_non_exhaustive()
    }
}

impl Managed {
    pub(crate) async fn new(context: Context) -> azure_core::Result<Self> {
        let env = |name| context.env_var(name).filter(|v| !v.is_empty());
        let identity_endpoint = env("IDENTITY_ENDPOINT");
        let identity_header = env("IDENTITY_HEADER");
        let msi_endpoint = env("MSI_ENDPOINT");
        let msi_secret = env("MSI_SECRET");
        let (source, endpoint, secret) =
            if let (Some(endpoint), Some(secret)) = (&identity_endpoint, identity_header) {
                let source = if env("IDENTITY_SERVER_THUMBPRINT").is_some() {
                    Source::ServiceFabric
                } else {
                    Source::AppService
                };
                (source, endpoint.clone(), secret)
            } else if let Some(endpoint) = msi_endpoint {
                if let Some(secret) = msi_secret {
                    (Source::MachineLearning, endpoint, secret)
                } else {
                    (Source::CloudShell, endpoint, String::new())
                }
            } else if (identity_endpoint.is_some() && env("IMDS_ENDPOINT").is_some())
                || arc_installed().await
            {
                (
                    Source::Arc,
                    identity_endpoint.unwrap_or_else(|| {
                        "http://127.0.0.1:40342/metadata/identity/oauth2/token".into()
                    }),
                    String::new(),
                )
            } else {
                (Source::Imds, IMDS.into(), String::new())
            };
        let client_id = context.env_var("AZURE_CLIENT_ID");
        if client_id.as_deref() == Some("") {
            return Err(missing());
        }
        if client_id.is_some()
            && matches!(
                source,
                Source::Arc | Source::CloudShell | Source::ServiceFabric
            )
        {
            // Go rejects this constructor; DefaultAzureCredential skips it.
            return Err(missing());
        }
        let ml_default_client_id = env("DEFAULT_IDENTITY_CLIENT_ID").unwrap_or_default();
        let probe = source == Source::Imds
            && context
                .env_var("AZURE_TOKEN_CREDENTIALS")
                .is_none_or(|value| !value.eq_ignore_ascii_case("ManagedIdentityCredential"));
        Ok(Self {
            context,
            source,
            endpoint,
            secret,
            client_id,
            ml_default_client_id,
            probe: AtomicBool::new(probe),
            cached: Mutex::new(BTreeMap::new()),
        })
    }

    fn request(&self, resource: &str, arc_key: Option<&str>) -> azure_core::Result<Request<Bytes>> {
        let mut url = reqwest::Url::parse(&self.endpoint).map_err(|_| failure())?;
        if !matches!(url.scheme(), "http" | "https")
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
        {
            return Err(failure());
        }
        let mut headers = http::HeaderMap::new();
        let mut method = Method::GET;
        let mut body = Bytes::new();
        if self.source == Source::CloudShell {
            method = Method::POST;
            headers.insert("metadata", http::HeaderValue::from_static("true"));
            headers.insert(
                http::header::CONTENT_TYPE,
                http::HeaderValue::from_static("application/x-www-form-urlencoded"),
            );
            let mut form = reqwest::Url::parse("http://form.invalid").map_err(|_| failure())?;
            form.query_pairs_mut().append_pair("resource", resource);
            body = Bytes::from(form.query().ok_or_else(failure)?.to_owned());
        } else {
            let mut query: BTreeMap<String, Vec<String>> = BTreeMap::new();
            for (key, value) in url.query_pairs() {
                query
                    .entry(key.into_owned())
                    .or_default()
                    .push(value.into_owned());
            }
            let version = match self.source {
                Source::Imds => "2018-02-01",
                Source::AppService => "2019-08-01",
                Source::MachineLearning => "2017-09-01",
                Source::ServiceFabric => "2019-07-01-preview",
                Source::Arc => "2020-06-01",
                Source::CloudShell => return Err(failure()),
            };
            query.insert("api-version".into(), vec![version.into()]);
            query.insert("resource".into(), vec![resource.into()]);
            if self.source == Source::MachineLearning {
                query.insert(
                    "clientid".into(),
                    vec![
                        self.client_id
                            .as_ref()
                            .unwrap_or(&self.ml_default_client_id)
                            .clone(),
                    ],
                );
            } else if let Some(id) = &self.client_id {
                query.insert("client_id".into(), vec![id.clone()]);
            }
            url.query_pairs_mut().clear().extend_pairs(
                query
                    .iter()
                    .flat_map(|(key, values)| values.iter().map(move |value| (key, value))),
            );
            match self.source {
                Source::Imds | Source::Arc => {
                    headers.insert("metadata", http::HeaderValue::from_static("true"));
                }
                Source::AppService => {
                    headers.insert("x-identity-header", sensitive(&self.secret)?);
                }
                Source::MachineLearning | Source::ServiceFabric => {
                    headers.insert("secret", sensitive(&self.secret)?);
                }
                Source::CloudShell => (),
            }
            if self.source == Source::ServiceFabric {
                headers.insert(
                    http::header::ACCEPT,
                    http::HeaderValue::from_static("application/json"),
                );
            }
            if let Some(key) = arc_key.filter(|key| !key.is_empty()) {
                headers.insert(
                    http::header::AUTHORIZATION,
                    sensitive(&format!("Basic {key}"))?,
                );
            }
        }
        let mut request = Request::builder()
            .method(method)
            .uri(url.as_str())
            .body(body)
            .map_err(|_| failure())?;
        *request.headers_mut() = headers;
        Ok(request)
    }

    async fn acquire(&self, resource: &str) -> azure_core::Result<Cached> {
        if self.probe.load(Ordering::Acquire) {
            // DefaultAzureCredential probes IMDS once without Metadata, with no retry.
            let request = Request::builder()
                .uri(IMDS)
                .body(Bytes::new())
                .map_err(|_| failure())?;
            tokio::time::timeout(Duration::from_secs(1), self.context.http_send(request))
                .await
                .map_err(|_| missing())?
                .map_err(|_| missing())?;
            self.probe.store(false, Ordering::Release);
        }
        let mut request = self.request(resource, None)?;
        if self.source == Source::Arc {
            let challenge = self.send(request).await?;
            if challenge.status() != StatusCode::UNAUTHORIZED {
                return Err(failure());
            }
            let root = if cfg!(target_os = "linux") {
                Some(Path::new("/var/opt/azcmagent/tokens"))
            } else {
                None
            };
            let key = arc_secret(&self.context, &challenge, root).await?;
            request = self.request(resource, Some(&key))?;
        }
        let response = self.send(request).await?;
        if !matches!(response.status(), StatusCode::OK | StatusCode::ACCEPTED) {
            if self.source == Source::Imds
                && ((response.status() == StatusCode::BAD_REQUEST && self.client_id.is_none())
                    || (response.status() == StatusCode::FORBIDDEN
                        && String::from_utf8_lossy(response.body()).contains("unreachable")))
            {
                return Err(missing());
            }
            return Err(failure());
        }
        parse_token(response.body(), OffsetDateTime::now_utc()).map_err(|_| {
            if self.source == Source::Imds {
                missing()
            } else {
                failure()
            }
        })
    }

    async fn send(&self, request: Request<Bytes>) -> azure_core::Result<Response<Bytes>> {
        let imds = self.source == Source::Imds;
        let max_retries = if imds { 6 } else { 3 };
        for attempt in 0..=max_retries {
            let result = self.context.http_send(request.clone()).await;
            if let Ok(response) = &result {
                let status = response.status().as_u16();
                let retry = if imds {
                    matches!(status, 404 | 410 | 429 | 500..=511) && status != 509
                } else {
                    matches!(status, 408 | 429 | 500 | 502 | 503 | 504)
                };
                if !retry || attempt == max_retries {
                    return result.map_err(|_| failure());
                }
            } else if attempt == max_retries {
                return Err(failure());
            }
            let maximum = Duration::from_secs(if imds { 25 } else { 60 });
            let server_delay = result.as_ref().ok().and_then(|r| retry_after(r.headers()));
            if server_delay.is_some_and(|delay| delay > maximum) {
                return result.map_err(|_| failure());
            }
            // Go uses (2^try - 1) * base with [0.8, 1.3) jitter, then caps it.
            let mut random = [0; 2];
            let jitter = if getrandom::getrandom(&mut random).is_ok() {
                0.8 + f64::from(u16::from_ne_bytes(random)) / 131_072.0
            } else {
                1.0
            };
            let factor = (1_u32 << (attempt + 1)) - 1;
            let base = Duration::from_millis(if imds { 2000 } else { 800 });
            let delay = (base * factor).mul_f64(jitter).min(maximum);
            // CloudIo and the export operation supply outer request/operation deadlines.
            tokio::time::sleep(server_delay.unwrap_or(delay)).await;
        }
        Err(failure())
    }
}

#[async_trait::async_trait]
impl TokenCredential for Managed {
    async fn get_token(
        &self,
        scopes: &[&str],
        options: Option<azure_core::credentials::TokenRequestOptions<'_>>,
    ) -> azure_core::Result<AccessToken> {
        let [scope] = scopes else {
            return Err(failure());
        };
        let resource = scope.strip_suffix("/.default").unwrap_or(scope);
        let claims = crate::cloud_azure_identity::has_claims(options.as_ref());
        let mut cached = self.cached.lock().await;
        let now = OffsetDateTime::now_utc();
        if let Some(value) = cached.get(resource)
            && !claims
            && value.token.expires_on >= now + azure_core::time::Duration::minutes(5)
        {
            if value.refresh_on.is_none_or(|refresh| refresh > now) {
                return Ok(value.token.clone());
            }
            // MSAL refresh_in failures fall back only while cache validation still succeeds.
            match self.acquire(resource).await {
                Ok(value) => {
                    let token = value.token.clone();
                    cached.insert(resource.to_owned(), value);
                    return Ok(token);
                }
                Err(_) => return Ok(value.token.clone()),
            }
        }
        let value = self.acquire(resource).await?;
        let token = value.token.clone();
        cached.insert(resource.to_owned(), value);
        Ok(token)
    }
}

pub(crate) fn retry_after(headers: &http::HeaderMap) -> Option<Duration> {
    for (name, milliseconds) in [
        ("retry-after-ms", true),
        ("x-ms-retry-after-ms", true),
        ("retry-after", false),
    ] {
        let Some(value) = headers.get(name).and_then(|v| v.to_str().ok()) else {
            continue;
        };
        if let Ok(number) = value.parse::<u64>()
            && number > 0
        {
            return Some(if milliseconds {
                Duration::from_millis(number)
            } else {
                Duration::from_secs(number)
            });
        }
        if !milliseconds && let Ok(date) = azure_core::time::parse_rfc7231(value) {
            let delta = date - OffsetDateTime::now_utc();
            if delta.is_positive() {
                return Duration::try_from(delta).ok();
            }
        }
    }
    None
}

fn sensitive(value: &str) -> azure_core::Result<http::HeaderValue> {
    let mut value = http::HeaderValue::from_str(value).map_err(|_| failure())?;
    value.set_sensitive(true);
    Ok(value)
}

async fn arc_installed() -> bool {
    cfg!(target_os = "linux")
        && tokio::fs::metadata("/opt/azcmagent/bin/himds")
            .await
            .is_ok()
}

async fn arc_secret(
    context: &Context,
    response: &Response<Bytes>,
    root: Option<&Path>,
) -> azure_core::Result<String> {
    let root = root.ok_or_else(failure)?;
    let header = response
        .headers()
        .get(http::header::WWW_AUTHENTICATE)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(failure)?;
    let path = header.split("Basic realm=").nth(1).ok_or_else(failure)?;
    let path_value = Path::new(path);
    if path_value.parent() != Some(root) || path_value.extension().is_none_or(|v| v != "key") {
        return Err(failure());
    }
    let bytes = context.file_read(path).await.map_err(|_| failure())?;
    if bytes.len() > 4096 {
        return Err(failure());
    }
    String::from_utf8(bytes).map_err(|_| failure())
}

fn parse_token(bytes: &[u8], now: OffsetDateTime) -> azure_core::Result<Cached> {
    let value: serde_json::Value = serde_json::from_slice(bytes).map_err(|_| failure())?;
    let token = value["access_token"]
        .as_str()
        .filter(|v| !v.is_empty())
        .ok_or_else(failure)?;
    let expires = match &value["expires_on"] {
        serde_json::Value::Number(v) => {
            OffsetDateTime::from_unix_timestamp(v.as_i64().ok_or_else(failure)?)
                .map_err(|_| failure())?
        }
        serde_json::Value::String(v) if !v.is_empty() => parse_expiry(v)?,
        _ => now
            .checked_add(azure_core::time::Duration::seconds(
                number(&value["expires_in"]).ok_or_else(failure)?,
            ))
            .ok_or_else(failure)?,
    };
    if expires <= now {
        return Err(failure());
    }
    let refresh_on = number(&value["refresh_in"])
        .and_then(|seconds| now.checked_add(azure_core::time::Duration::seconds(seconds)));
    Ok(Cached {
        token: AccessToken::new(token.to_owned(), expires),
        refresh_on,
    })
}
fn number(value: &serde_json::Value) -> Option<i64> {
    value
        .as_i64()
        .or_else(|| value.as_str().and_then(|v| v.parse().ok()))
}
fn parse_expiry(value: &str) -> azure_core::Result<OffsetDateTime> {
    if let Ok(timestamp) = value.parse::<i64>() {
        return OffsetDateTime::from_unix_timestamp(timestamp).map_err(|_| failure());
    }
    if let Ok(timestamp) = azure_core::time::parse_rfc3339(value) {
        return Ok(timestamp);
    }
    if let Some((date, time)) = value.split_once(' ') {
        let date = if date.contains('/') {
            let parts: Vec<_> = date.split('/').collect();
            if parts.len() != 3 {
                return Err(failure());
            }
            format!("{}-{}-{}", parts[2], parts[0], parts[1])
        } else {
            date.to_owned()
        };
        return azure_core::time::parse_rfc3339(&format!("{date}T{time}Z")).map_err(|_| failure());
    }
    Err(failure())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use reqsign_core::{FileRead, HttpSend, StaticEnv};
    use serde_json::{Value, json};
    use std::collections::{HashMap, VecDeque};
    use std::sync::{Arc, Mutex as SyncMutex};

    #[derive(Clone, Debug, Default)]
    struct Transport {
        requests: Arc<SyncMutex<Vec<Value>>>,
        replies: Arc<SyncMutex<VecDeque<(u16, String)>>>,
        fail: bool,
        retry_after_ms: Option<&'static str>,
    }
    impl HttpSend for Transport {
        async fn http_send(
            &self,
            request: Request<Bytes>,
        ) -> reqsign_core::Result<Response<Bytes>> {
            self.requests.lock().unwrap().push(json!({
                "method": request.method().as_str(), "url": request.uri().to_string(),
                "headers": request.headers().iter().map(|(name,value)| (name.as_str(), value.to_str().unwrap())).collect::<BTreeMap<_,_>>(),
                "body": std::str::from_utf8(request.body()).unwrap(),
            }));
            if self.fail {
                return Err(reqsign_core::Error::unexpected("offline"));
            }
            let (status, body) = self.replies.lock().unwrap().pop_front().unwrap_or((
                200, r#"{"access_token":"fake-managed-token","expires_on":4070908800,"token_type":"Bearer"}"#.into()));
            let mut response = Response::builder().status(status);
            if let Some(delay) = self.retry_after_ms {
                response = response.header("retry-after-ms", delay);
            }
            Ok(response.body(Bytes::from(body)).unwrap())
        }
    }
    fn context(env: HashMap<String, String>, transport: Transport) -> Context {
        Context::new()
            .with_env(StaticEnv {
                envs: env,
                ..Default::default()
            })
            .with_http_send(transport)
    }
    #[tokio::test]
    async fn all_managed_sources_match_pinned_go_sdk_requests() {
        let cases: Vec<Value> =
            serde_json::from_str(include_str!("../testdata/azure-managed-go.json")).unwrap();
        assert_eq!(cases.len(), 9);
        for case in cases {
            let mut env: HashMap<String, String> =
                serde_json::from_value(case["env"].clone()).unwrap();
            env.entry("AZURE_TOKEN_CREDENTIALS".into())
                .or_insert("ManagedIdentityCredential".into());
            let transport = Transport::default();
            if case["name"] == "azure-arc" {
                transport
                    .replies
                    .lock()
                    .unwrap()
                    .push_back((401, String::new()));
            }
            let managed = Managed::new(context(env, transport.clone())).await.unwrap();
            let result = managed.get_token(&[SCOPE], None).await;
            assert_eq!(result.is_err(), case["name"] == "azure-arc");
            assert_eq!(
                json!(*transport.requests.lock().unwrap()),
                case["requests"],
                "{}",
                case["name"]
            );
        }
    }

    #[tokio::test]
    async fn imds_unavailable_differs_from_fatal_authentication() {
        for (user, status, body, is_unavailable) in [
            (false, 400, "bad request", true),
            (true, 400, "bad request", false),
            (false, 403, "network unreachable", true),
            (false, 403, "denied", false),
            (false, 200, "not JSON", true),
            (false, 401, "denied", false),
        ] {
            let transport = Transport::default();
            transport
                .replies
                .lock()
                .unwrap()
                .push_back((status, body.into()));
            let mut env = HashMap::from([(
                "AZURE_TOKEN_CREDENTIALS".into(),
                "ManagedIdentityCredential".into(),
            )]);
            if user {
                env.insert("AZURE_CLIENT_ID".into(), "client".into());
            }
            let managed = Managed::new(context(env, transport)).await.unwrap();
            let error = managed.get_token(&[SCOPE], None).await.unwrap_err();
            assert_eq!(
                unavailable(&error),
                is_unavailable,
                "user={user}, status={status}, body={body}"
            );
        }
        let transport = Transport {
            fail: true,
            ..Default::default()
        };
        let managed = Managed::new(context(HashMap::new(), transport.clone()))
            .await
            .unwrap();
        assert!(unavailable(
            &managed.get_token(&[SCOPE], None).await.unwrap_err()
        ));
        let requests = transport.requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0]["headers"], json!({}));
    }

    #[tokio::test]
    async fn managed_cache_refresh_failure_retains_only_cache_valid_token() {
        let transport = Transport::default();
        let managed = Managed::new(context(
            HashMap::from([
                (
                    "IDENTITY_ENDPOINT".into(),
                    "http://identity.test/token".into(),
                ),
                ("IDENTITY_HEADER".into(), "fake-secret".into()),
            ]),
            transport.clone(),
        ))
        .await
        .unwrap();
        let first = managed.get_token(&[SCOPE], None).await.unwrap();
        assert_eq!(
            managed
                .get_token(&[SCOPE], None)
                .await
                .unwrap()
                .token
                .secret(),
            first.token.secret()
        );
        assert_eq!(transport.requests.lock().unwrap().len(), 1);
        managed
            .cached
            .lock()
            .await
            .get_mut(RESOURCE)
            .unwrap()
            .refresh_on = Some(OffsetDateTime::now_utc() - azure_core::time::Duration::seconds(1));
        transport
            .replies
            .lock()
            .unwrap()
            .push_back((400, "denied".into()));
        assert_eq!(
            managed
                .get_token(&[SCOPE], None)
                .await
                .unwrap()
                .token
                .secret(),
            first.token.secret()
        );
        managed
            .cached
            .lock()
            .await
            .get_mut(RESOURCE)
            .unwrap()
            .token
            .expires_on = OffsetDateTime::now_utc() + azure_core::time::Duration::minutes(1);
        transport
            .replies
            .lock()
            .unwrap()
            .push_back((400, "denied".into()));
        assert!(managed.get_token(&[SCOPE], None).await.is_err());
    }

    #[tokio::test]
    async fn retries_honor_server_delay_and_stop_above_go_cap() {
        for (delay, expected) in [("1", 2), ("61000", 1)] {
            let transport = Transport {
                retry_after_ms: Some(delay),
                ..Default::default()
            };
            transport
                .replies
                .lock()
                .unwrap()
                .push_back((503, "busy".into()));
            let managed = Managed::new(context(
                HashMap::from([
                    (
                        "IDENTITY_ENDPOINT".into(),
                        "http://identity.test/token".into(),
                    ),
                    ("IDENTITY_HEADER".into(), "fake-secret".into()),
                ]),
                transport.clone(),
            ))
            .await
            .unwrap();
            assert_eq!(
                managed.get_token(&[SCOPE], None).await.is_ok(),
                expected == 2
            );
            assert_eq!(transport.requests.lock().unwrap().len(), expected);
        }
        let mut headers = http::HeaderMap::new();
        headers.insert("retry-after", http::HeaderValue::from_static("3"));
        headers.insert("x-ms-retry-after-ms", http::HeaderValue::from_static("2"));
        headers.insert("retry-after-ms", http::HeaderValue::from_static("1"));
        assert_eq!(retry_after(&headers), Some(Duration::from_millis(1)));
        headers.insert("retry-after-ms", http::HeaderValue::from_static("0"));
        assert_eq!(retry_after(&headers), Some(Duration::from_millis(2)));
        headers.remove("x-ms-retry-after-ms");
        assert_eq!(retry_after(&headers), Some(Duration::from_secs(3)));
    }

    #[derive(Debug, Clone)]
    struct KeyFile {
        calls: Arc<SyncMutex<Vec<String>>>,
        bytes: Vec<u8>,
    }
    impl FileRead for KeyFile {
        async fn file_read(&self, path: &str) -> reqsign_core::Result<Vec<u8>> {
            self.calls.lock().unwrap().push(path.into());
            Ok(self.bytes.clone())
        }
    }
    #[tokio::test]
    async fn arc_challenge_restricts_file_and_uses_basic_secret() {
        let file = KeyFile {
            calls: Arc::default(),
            bytes: b"fake-arc-key".to_vec(),
        };
        let ctx = context(
            HashMap::from([
                (
                    "IDENTITY_ENDPOINT".into(),
                    "http://identity.test/token".into(),
                ),
                ("IMDS_ENDPOINT".into(), "configured".into()),
            ]),
            Transport::default(),
        )
        .with_file_read(file.clone());
        let root = Some(Path::new("/var/opt/azcmagent/tokens"));
        let challenge = |value: &str| {
            Response::builder()
                .status(401)
                .header("www-authenticate", value)
                .body(Bytes::new())
                .unwrap()
        };
        for value in [
            "Basic realm=/etc/secret.key",
            "Basic realm=/var/opt/azcmagent/tokens/secret.txt",
            "Basic realm=/var/opt/azcmagent/tokens/sub/secret.key",
            "Bearer realm=x",
        ] {
            assert!(arc_secret(&ctx, &challenge(value), root).await.is_err());
        }
        assert!(file.calls.lock().unwrap().is_empty());
        let valid = challenge("Basic realm=/var/opt/azcmagent/tokens/secret.key");
        assert!(arc_secret(&ctx, &valid, None).await.is_err());
        let secret = arc_secret(&ctx, &valid, root).await.unwrap();
        let managed = Managed::new(ctx.clone()).await.unwrap();
        let request = managed.request(RESOURCE, Some(&secret)).unwrap();
        assert_eq!(request.headers()["authorization"], "Basic fake-arc-key");
        assert!(request.headers()["authorization"].is_sensitive());
        let too_big = ctx.with_file_read(KeyFile {
            calls: Arc::default(),
            bytes: vec![b'x'; 4097],
        });
        assert!(arc_secret(&too_big, &valid, root).await.is_err());
    }

    #[tokio::test]
    async fn constructor_rejects_unsupported_and_empty_user_identity() {
        for pairs in [
            vec![("MSI_ENDPOINT", "http://identity.test/token")],
            vec![
                ("IDENTITY_ENDPOINT", "http://identity.test/token"),
                ("IMDS_ENDPOINT", "configured"),
            ],
            vec![
                ("IDENTITY_ENDPOINT", "http://identity.test/token"),
                ("IDENTITY_HEADER", "secret"),
                ("IDENTITY_SERVER_THUMBPRINT", "thumb"),
            ],
        ] {
            let mut env: HashMap<String, String> = pairs
                .into_iter()
                .map(|(k, v)| (k.into(), v.into()))
                .collect();
            env.insert("AZURE_CLIENT_ID".into(), "client".into());
            assert!(
                Managed::new(context(env, Transport::default()))
                    .await
                    .is_err()
            );
        }
        assert!(
            Managed::new(context(
                HashMap::from([("AZURE_CLIENT_ID".into(), String::new())]),
                Transport::default()
            ))
            .await
            .is_err()
        );
    }

    #[test]
    fn token_expiry_forms_and_server_refresh_are_preserved() {
        let now = OffsetDateTime::from_unix_timestamp(0).unwrap();
        for expires in [
            json!(4_070_908_800_i64),
            json!("4070908800"),
            json!("2099-01-01T00:00:00Z"),
            json!("2099-01-01 00:00:00"),
            json!("01/01/2099 00:00:00"),
        ] {
            let value = parse_token(
                &serde_json::to_vec(
                    &json!({"access_token":"token","expires_on":expires,"refresh_in":12}),
                )
                .unwrap(),
                now,
            )
            .unwrap();
            assert_eq!(value.token.expires_on.unix_timestamp(), 4_070_908_800);
            assert_eq!(value.refresh_on.unwrap().unix_timestamp(), 12);
        }
        let relative =
            parse_token(br#"{"access_token":"token","expires_in":"3600"}"#, now).unwrap();
        assert_eq!(relative.token.expires_on.unix_timestamp(), 3600);
        assert!(relative.refresh_on.is_none());
        for body in [
            br#"{"access_token":"token"}"#.as_slice(),
            br#"{"access_token":"token","expires_on":"bad"}"#,
            br#"{"access_token":"","expires_in":3600}"#,
        ] {
            assert!(parse_token(body, now).is_err());
        }
    }
}
