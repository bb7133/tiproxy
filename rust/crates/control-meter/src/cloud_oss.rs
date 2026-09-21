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

//! Go OSS role requests and their 15-minute refresh window.

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::fmt::{self, Write};
use std::time::Duration;

use bytes::Bytes;
use control_config::CloudMeteringConfig;
use http::Request;
use reqsign_aliyun_oss::{Credential, StaticCredentialProvider};
use reqsign_core::hash::base64_hmac_sha1;
use reqsign_core::time::Timestamp;
use reqsign_core::{Context, ProvideCredential, ProvideCredentialChain, SigningCredential};
use serde::Deserialize;
use tokio::sync::Mutex;

#[path = "cloud_oss_object.rs"]
mod object;
#[path = "cloud_oss_sign.rs"]
mod signing;

const REFRESH_WINDOW: Duration = Duration::from_secs(15 * 60);
const REFRESH_INTERVAL: Duration = Duration::from_secs(5 * 60);

pub(crate) struct OssSigner {
    context: Context,
    base: ProvideCredentialChain<Credential>,
    region: String,
    bucket: String,
    object_skew: std::sync::atomic::AtomicI64,
    gzip_content_type: String,
    role: String,
    endpoint: String,
    cached: Mutex<Option<Credential>>,
}

impl fmt::Debug for OssSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OssSigner").finish_non_exhaustive()
    }
}

impl OssSigner {
    pub(crate) fn new(
        config: &CloudMeteringConfig,
        region: &str,
        bucket: &str,
        context: Context,
    ) -> Self {
        let base = if !config.access_key.is_empty() && !config.secret_access_key.is_empty() {
            let mut provider =
                StaticCredentialProvider::new(&config.access_key, &config.secret_access_key);
            // The Go role path creates credentials-go type access_key, which
            // ignores SecurityToken. Direct OSS writes do retain that token.
            if config.assume_role_arn.is_empty() && !config.session_token.is_empty() {
                provider = provider.with_security_token(&config.session_token);
            }
            ProvideCredentialChain::new().push(provider)
        } else {
            ProvideCredentialChain::new()
                .push(crate::cloud_oss_identity::GoDefaultProvider::default())
        };
        Self {
            context,
            base,
            region: region.to_owned(),
            bucket: bucket.to_owned(),
            object_skew: std::sync::atomic::AtomicI64::new(0),
            gzip_content_type: object::gzip_content_type(),
            role: config.assume_role_arn.clone(),
            endpoint: sts_endpoint(region),
            cached: Mutex::new(None),
        }
    }

    #[cfg(test)]
    pub(crate) async fn sign(&self, parts: &mut http::request::Parts) -> reqsign_core::Result<()> {
        let credential = self.credential(false).await?.ok_or_else(failed)?;
        signing::sign_at(
            parts,
            &credential,
            &self.region,
            &self.bucket,
            Timestamp::now(),
        )
    }

    async fn credential(&self, background: bool) -> reqsign_core::Result<Option<Credential>> {
        if self.role.is_empty() {
            if background {
                return Ok(None);
            }
            let credential = self
                .base
                .provide_credential(&self.context)
                .await?
                .ok_or_else(failed)?;
            if !credential.is_valid_at(Timestamp::now()) {
                return Err(failed());
            }
            return Ok(Some(credential));
        }
        let mut cached = self.cached.lock().await;
        if background && cached.is_none() {
            return Ok(None);
        }
        let now = Timestamp::now();
        if let Some(credential) = cached.as_ref()
            && credential
                .expires_in
                .is_some_and(|expires| now + REFRESH_WINDOW <= expires)
        {
            return Ok(Some(credential.clone()));
        }
        let base = self
            .base
            .provide_credential(&self.context)
            .await?
            .ok_or_else(failed)?;
        if !base.is_valid_at(Timestamp::now()) {
            return Err(failed());
        }
        let mut nonce = [0_u8; 16];
        getrandom::getrandom(&mut nonce).map_err(|_| failed())?;
        let nonce = nonce
            .iter()
            .fold(String::with_capacity(32), |mut value, byte| {
                let _ = write!(value, "{byte:02x}");
                value
            });
        let request = role_request(&self.endpoint, &base, &self.role, now, &nonce)?;
        let response = self.context.http_send(request).await?;
        if !response.status().is_success() {
            return Err(failed());
        }
        let response: RoleResponse =
            serde_json::from_slice(response.body()).map_err(|_| failed())?;
        let value = response.credentials.ok_or_else(failed)?;
        let credential = Credential {
            access_key_id: value.access_key_id,
            access_key_secret: value.access_key_secret,
            security_token: Some(value.security_token),
            expires_in: Some(value.expiration.parse().map_err(|_| failed())?),
        };
        if !credential.is_valid_at(Timestamp::now())
            || credential
                .security_token
                .as_ref()
                .is_none_or(String::is_empty)
        {
            return Err(failed());
        }
        // A failed refresh leaves the old cache unchanged but returns the
        // error, even if it has not expired. This differs from the COS fallback.
        *cached = Some(credential.clone());
        Ok(Some(credential))
    }

    pub(crate) async fn maintain(&self) -> Infallible {
        if self.role.is_empty() {
            return std::future::pending().await;
        }
        let start = tokio::time::Instant::now() + REFRESH_INTERVAL;
        let mut interval = tokio::time::interval_at(start, REFRESH_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            // Like Go, only refresh an existing cache and ignore background
            // failures. The next foreground request still fails/retries normally.
            let _ = tokio::time::timeout(Duration::from_secs(10), self.credential(true)).await;
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct RoleResponse {
    credentials: Option<RoleCredential>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct RoleCredential {
    access_key_id: String,
    access_key_secret: String,
    security_token: String,
    expiration: String,
}

fn role_request(
    endpoint: &str,
    base: &Credential,
    role: &str,
    now: Timestamp,
    nonce: &str,
) -> reqsign_core::Result<Request<Bytes>> {
    let session = format!("oss-sdk-session-{}", now.as_second());
    let timestamp = now.format_rfc3339_zulu();
    let mut params = BTreeMap::from([
        ("Action", "AssumeRole"),
        ("DurationSeconds", "3600"),
        ("Format", "json"),
        ("AccessKeyId", base.access_key_id.as_str()),
        ("RoleArn", role),
        ("RoleSessionName", session.as_str()),
        ("SignatureMethod", "HMAC-SHA1"),
        ("SignatureNonce", nonce),
        ("SignatureVersion", "1.0"),
        ("Timestamp", timestamp.as_str()),
        ("Version", "2015-04-01"),
    ]);
    if let Some(token) = base
        .security_token
        .as_deref()
        .filter(|token| !token.is_empty())
    {
        params.insert("SecurityToken", token);
    }
    let canonical = query(&params);
    let to_sign = format!("POST&%2F&{}", percent(&canonical));
    let signature = base64_hmac_sha1(
        format!("{}&", base.access_key_secret).as_bytes(),
        to_sign.as_bytes(),
    );
    params.insert("Signature", &signature);
    Request::post(format!("https://{endpoint}/?{}", query(&params)))
        .body(Bytes::new())
        .map_err(|_| failed())
}

fn query(params: &BTreeMap<&str, &str>) -> String {
    params
        .iter()
        .map(|(key, value)| format!("{}={}", percent(key), percent(value)))
        .collect::<Vec<_>>()
        .join("&")
}

pub(crate) fn percent(value: &str) -> String {
    value
        .bytes()
        .map(|byte| {
            if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
                char::from(byte).to_string()
            } else {
                format!("%{byte:02X}")
            }
        })
        .collect()
}

// Pinned sts-20150401/v2 2.0.4 endpoint map. Storage endpoint overrides do
// not override OSS STS (unlike AWS's shared BaseEndpoint).
fn sts_endpoint(region: &str) -> String {
    match region {
        "cn-north-2-gov-1" | "cn-shenzhen-finance-1" => format!("sts-vpc.{region}.aliyuncs.com"),
        "ap-northeast-2-pop"
        | "cn-beijing-finance-1"
        | "cn-beijing-finance-pop"
        | "cn-beijing-gov-1"
        | "cn-beijing-nu16-b01"
        | "cn-edge-1"
        | "cn-fujian"
        | "cn-haidian-cm12-c01"
        | "cn-hangzhou-bj-b01"
        | "cn-hangzhou-finance"
        | "cn-hangzhou-internal-prod-1"
        | "cn-hangzhou-internal-test-1"
        | "cn-hangzhou-internal-test-2"
        | "cn-hangzhou-internal-test-3"
        | "cn-hangzhou-test-306"
        | "cn-hongkong-finance-pop"
        | "cn-huhehaote-nebula-1"
        | "cn-qingdao-nebula"
        | "cn-shanghai-et15-b01"
        | "cn-shanghai-et2-b01"
        | "cn-shanghai-inner"
        | "cn-shanghai-internal-test-1"
        | "cn-shenzhen-inner"
        | "cn-shenzhen-st4-d01"
        | "cn-shenzhen-su18-b01"
        | "cn-wuhan"
        | "cn-yushanfang"
        | "cn-zhangbei"
        | "cn-zhangbei-na61-b01"
        | "cn-zhangjiakou-na62-a01"
        | "cn-zhengzhou-nebula-1"
        | "eu-west-1-oxs"
        | "rus-west-1-pop" => "sts.aliyuncs.com".to_owned(),
        _ => format!("sts.{region}.aliyuncs.com"),
    }
}

fn failed() -> reqsign_core::Error {
    reqsign_core::Error::credential_invalid("OSS role credential unavailable")
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqsign_core::StaticEnv;
    use reqwest::Url;
    use std::sync::{
        Arc, Mutex as StdMutex,
        atomic::{AtomicBool, Ordering},
    };

    #[derive(Clone, Debug, Default)]
    struct Io {
        requests: Arc<StdMutex<Vec<Request<Bytes>>>>,
        fail: Arc<AtomicBool>,
    }
    impl reqsign_core::HttpSend for Io {
        async fn http_send(
            &self,
            request: Request<Bytes>,
        ) -> reqsign_core::Result<http::Response<Bytes>> {
            self.requests
                .lock()
                .unwrap_or_else(|e| unreachable!("{e}"))
                .push(request);
            if self.fail.load(Ordering::SeqCst) {
                return Err(failed());
            }
            Ok(http::Response::new(Bytes::from_static(br#"{"Credentials":{"AccessKeyId":"role-id","AccessKeySecret":"role-secret","SecurityToken":"role-token","Expiration":"2099-01-01T00:00:00Z"}}"#)))
        }
    }

    #[test]
    fn rpc_signature_matches_actual_go_sdk_requests() {
        let fixtures: Vec<serde_json::Value> =
            serde_json::from_str(include_str!("../testdata/assume-role-go.json"))
                .unwrap_or_else(|e| unreachable!("{e}"));
        for row in fixtures
            .iter()
            .filter(|row| row["name"].as_str().unwrap_or_default().starts_with("oss-"))
        {
            let url = Url::parse(row["url"].as_str().unwrap_or_default())
                .unwrap_or_else(|e| unreachable!("{e}"));
            let params = url.query_pairs().collect::<BTreeMap<_, _>>();
            let base = Credential {
                access_key_id: "base-id".into(),
                access_key_secret: "base-secret".into(),
                security_token: params.get("SecurityToken").map(ToString::to_string),
                expires_in: None,
            };
            let request = role_request(
                url.host_str().unwrap_or_default(),
                &base,
                &params["RoleArn"],
                params["Timestamp"]
                    .parse()
                    .unwrap_or_else(|e| unreachable!("{e}")),
                &params["SignatureNonce"],
            )
            .unwrap_or_else(|e| unreachable!("{e}"));
            assert_eq!(request.method().as_str(), row["method"]);
            assert_eq!(
                request.uri().to_string(),
                row["url"],
                "includes the actual SDK HMAC-SHA1 signature"
            );
            assert!(request.body().is_empty());
            assert!(!request.headers().contains_key(http::header::CONTENT_TYPE));
        }
        assert_eq!(sts_endpoint("cn-hangzhou"), "sts.cn-hangzhou.aliyuncs.com");
        assert_eq!(
            sts_endpoint("cn-north-2-gov-1"),
            "sts-vpc.cn-north-2-gov-1.aliyuncs.com"
        );
        assert_eq!(
            sts_endpoint("cn-shenzhen-finance-1"),
            "sts-vpc.cn-shenzhen-finance-1.aliyuncs.com"
        );
        assert_eq!(sts_endpoint("cn-hangzhou-finance"), "sts.aliyuncs.com");
    }

    #[tokio::test]
    async fn role_refresh_matches_go_threshold_error_and_static_token_rules() {
        let io = Io::default();
        let ctx = Context::new()
            .with_env(StaticEnv::default())
            .with_http_send(io.clone());
        let cfg = CloudMeteringConfig {
            access_key: "base-id".into(),
            secret_access_key: "base-secret".into(),
            session_token: "ignored-static-token".into(),
            assume_role_arn: "acs:ram::123456789012:role/metering".into(),
        };
        let signer = OssSigner::new(&cfg, "cn-hangzhou", "bucket", ctx);
        assert!(
            signer
                .credential(true)
                .await
                .unwrap_or_else(|e| unreachable!("{e}"))
                .is_none(),
            "background work must not eagerly acquire a first token"
        );
        let (one, two) = tokio::join!(signer.credential(false), signer.credential(false));
        assert!(one.is_ok() && two.is_ok());
        {
            let requests = io.requests.lock().unwrap_or_else(|e| unreachable!("{e}"));
            assert_eq!(requests.len(), 1);
            assert_eq!(
                requests[0].uri().host(),
                Some("sts.cn-hangzhou.aliyuncs.com")
            );
            assert!(
                !requests[0]
                    .uri()
                    .query()
                    .unwrap_or_default()
                    .contains("SecurityToken")
            );
        }
        signer
            .cached
            .lock()
            .await
            .as_mut()
            .unwrap_or_else(|| unreachable!())
            .expires_in = Some(Timestamp::now() + REFRESH_WINDOW + Duration::from_secs(1));
        assert!(signer.credential(false).await.is_ok());
        assert_eq!(
            io.requests
                .lock()
                .unwrap_or_else(|e| unreachable!("{e}"))
                .len(),
            1
        );
        signer
            .cached
            .lock()
            .await
            .as_mut()
            .unwrap_or_else(|| unreachable!())
            .expires_in = Some(Timestamp::now() + REFRESH_WINDOW - Duration::from_secs(1));
        io.fail.store(true, Ordering::SeqCst);
        assert!(signer.credential(true).await.is_err());
        assert!(
            signer.credential(false).await.is_err(),
            "unexpired role is not a fallback after refresh failure"
        );
        assert!(
            signer
                .cached
                .lock()
                .await
                .as_ref()
                .unwrap_or_else(|| unreachable!())
                .is_valid_at(Timestamp::now()),
            "failed refresh retains but does not return the cache"
        );
        io.fail.store(false, Ordering::SeqCst);
        assert!(signer.credential(true).await.is_ok());
        assert!(signer.credential(false).await.is_ok());
        assert_eq!(
            io.requests
                .lock()
                .unwrap_or_else(|e| unreachable!("{e}"))
                .len(),
            4
        );
    }
}
