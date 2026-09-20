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

//! Go AWS `CredentialsCache` and `AssumeRole` defaults around the shared `SigV4` SDK.

use std::fmt;

use crate::cloud_aws_retry::{Failure, Retry};
use bytes::Bytes;
use control_config::AwsMeteringConfig;
use http::{Request, request::Parts};
use reqsign_aws_core::assume_role::{AssumeRoleOperation, regional_sts_endpoint};
use reqsign_aws_v4::{AssumeRoleGrant, Credential, RequestSigner, StaticCredentialProvider};
use reqsign_core::hash::hex_sha256;
use reqsign_core::time::Timestamp;
use reqsign_core::{
    Context, ProvideCredential, ProvideCredentialChain, SignRequest, SigningCredential,
};
use reqwest::Url;
use tokio::sync::Mutex;

pub(crate) struct AwsSigner {
    context: Context,
    base: ProvideCredentialChain<Credential>,
    region: String,
    role: String,
    endpoint: Option<Url>,
    state: Mutex<State>,
    retry: Retry,
}

#[derive(Default)]
struct State {
    base: Option<Credential>,
    role: Option<Credential>,
    session: Option<String>,
}

impl fmt::Debug for AwsSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AwsSigner").finish_non_exhaustive()
    }
}

impl AwsSigner {
    pub(crate) async fn new(
        config: &AwsMeteringConfig,
        region: String,
        endpoint: Option<Url>,
        context: Context,
    ) -> reqsign_core::Result<Self> {
        let (base, settings) =
            if !config.access_key.is_empty() && !config.secret_access_key.is_empty() {
                let settings = crate::cloud_aws_identity::validate_profile(&context).await?;
                let mut provider =
                    StaticCredentialProvider::new(&config.access_key, &config.secret_access_key);
                if !config.session_token.is_empty() {
                    provider = provider.with_session_token(&config.session_token);
                }
                (ProvideCredentialChain::new().push(provider), settings)
            } else {
                let provider = crate::cloud_aws_identity::GoDefaultProvider::new(&region);
                let settings = provider.prepare(&context).await?;
                (ProvideCredentialChain::new().push(provider), settings)
            };
        Ok(Self {
            retry: Retry::configured(&context, settings),
            context,
            base,
            region,
            endpoint,
            role: config.assume_role_arn.clone(),
            state: Mutex::new(State::default()),
        })
    }

    pub(crate) async fn sign(&self, parts: &mut Parts) -> reqsign_core::Result<()> {
        let mut credential = self.credential().await?;
        // Provider-specific Go refresh windows are already reflected in the
        // cached expiration. The signer gets a clone with expiry removed so
        // reqsign does not impose an additional early-expiry window.
        credential.expires_in = None;
        RequestSigner::new("s3", &self.region)
            .sign_request(&self.context, parts, Some(&credential), None)
            .await
    }

    pub(super) async fn credential(&self) -> reqsign_core::Result<Credential> {
        let mut state = self.state.lock().await;
        let now = Timestamp::now();
        let cached = if self.role.is_empty() {
            &state.base
        } else {
            &state.role
        };
        if let Some(cached) = cached.as_ref().filter(|c| c.is_valid_at(now)) {
            return Ok(cached.clone());
        }
        if state.base.as_ref().is_none_or(|c| !c.is_valid_at(now)) {
            let base = self
                .base
                .provide_credential(&self.context)
                .await?
                .ok_or_else(failed)?;
            if base.access_key_id.is_empty() || base.secret_access_key.is_empty() {
                return Err(failed());
            }
            state.base = Some(base);
        }
        let base = state.base.as_ref().ok_or_else(failed)?.clone();
        if self.role.is_empty() {
            return Ok(base);
        }
        // stscreds generates this once, on the first Retrieve, and reuses it.
        let session = state.session.get_or_insert_with(|| {
            format!(
                "aws-go-sdk-{}{:09}",
                now.as_second(),
                now.subsec_nanosecond()
            )
        });
        let role = RoleOptions {
            arn: &self.role,
            session,
            duration: 900,
            external_id: None,
        };
        let credential = assume_role(
            &self.context,
            &self.region,
            self.endpoint.as_ref(),
            &role,
            base,
            &self.retry,
        )
        .await?;
        state.role = Some(credential.clone());
        Ok(credential)
    }
}

pub(crate) struct RoleOptions<'a> {
    pub(crate) arn: &'a str,
    pub(crate) session: &'a str,
    pub(crate) duration: u32,
    pub(crate) external_id: Option<&'a str>,
}

pub(crate) async fn assume_role(
    context: &Context,
    region: &str,
    endpoint: Option<&Url>,
    role: &RoleOptions<'_>,
    mut source: Credential,
    retry: &Retry,
) -> reqsign_core::Result<Credential> {
    let mut grant = AssumeRoleGrant::new(role.arn, role.session);
    if let Some(external_id) = role.external_id {
        grant = grant.with_external_id(external_id);
    }
    let authority = regional_sts_endpoint(region, &grant)?;
    let endpoint = match endpoint {
        Some(endpoint) => endpoint.clone(),
        None => Url::parse(&format!("https://{authority}/")).map_err(|_| failed())?,
    };
    let _operation = AssumeRoleOperation::new(authority, &grant, Some(role.duration))?;
    source.expires_in = None;
    retry
        .run(|| async {
            // Sign each attempt anew, keeping the session/body fixed per Retrieve.
            let request = role_request(&endpoint, role).map_err(Failure::terminal)?;
            let (mut parts, body) = request.into_parts();
            RequestSigner::new("sts", region)
                .sign_request(context, &mut parts, Some(&source), None)
                .await
                .map_err(Failure::terminal)?;
            let response = context
                .http_send(Request::from_parts(parts, body))
                .await
                .map_err(Failure::transport)?;
            if response.status() != http::StatusCode::OK {
                return Err(Failure::sts(&response, false));
            }
            decode_role(response.body()).map_err(Failure::terminal)
        })
        .await
}

fn decode_role(body: &[u8]) -> reqsign_core::Result<Credential> {
    #[derive(serde::Deserialize)]
    struct Envelope {
        #[serde(rename = "AssumeRoleResult")]
        result: ResultBody,
    }
    #[derive(serde::Deserialize)]
    struct ResultBody {
        #[serde(rename = "Credentials")]
        credentials: RoleCredential,
    }
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct RoleCredential {
        access_key_id: String,
        secret_access_key: String,
        session_token: String,
        expiration: String,
    }
    let body = std::str::from_utf8(body).map_err(|_| failed())?;
    let response: Envelope = quick_xml::de::from_str(body).map_err(|_| failed())?;
    let value = response.result.credentials;
    // Retain the existing reqsign adapter's success validation.
    if !(16..=128).contains(&value.access_key_id.chars().count())
        || !value
            .access_key_id
            .bytes()
            .all(|v| v.is_ascii_alphanumeric() || v == b'_')
        || value.secret_access_key.is_empty()
        || value.session_token.trim().is_empty()
        || http::HeaderValue::try_from(value.session_token.as_str()).is_err()
    {
        return Err(failed());
    }
    let credential = Credential {
        access_key_id: value.access_key_id,
        secret_access_key: value.secret_access_key,
        session_token: Some(value.session_token),
        expires_in: Some(value.expiration.parse().map_err(|_| failed())?),
    };
    if !credential.is_valid_at(Timestamp::now()) {
        return Err(failed());
    }
    Ok(credential)
}

fn role_request(endpoint: &Url, role: &RoleOptions<'_>) -> reqsign_core::Result<Request<Bytes>> {
    let duration = role.duration.to_string();
    let mut params = std::collections::BTreeMap::from([
        ("Action", "AssumeRole"),
        ("DurationSeconds", duration.as_str()),
        ("RoleArn", role.arn),
        ("RoleSessionName", role.session),
        ("Version", "2011-06-15"),
    ]);
    if let Some(external_id) = role.external_id {
        params.insert("ExternalId", external_id);
    }
    let mut encoded = Url::parse("https://unused.invalid").map_err(|_| failed())?;
    encoded.query_pairs_mut().extend_pairs(params);
    let body = encoded.query().ok_or_else(failed)?.to_owned();
    Request::post(endpoint.as_str())
        .header(
            http::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .header("x-amz-content-sha256", hex_sha256(body.as_bytes()))
        .body(Bytes::from(body))
        .map_err(|_| failed())
}

fn failed() -> reqsign_core::Error {
    reqsign_core::Error::credential_invalid("AWS credential unavailable")
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqsign_core::StaticEnv;
    use std::sync::{
        Arc, Mutex as StdMutex,
        atomic::{AtomicBool, Ordering},
    };
    use std::time::Duration;

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
            Ok(http::Response::new(Bytes::from_static(br"<AssumeRoleResponse><AssumeRoleResult><Credentials><AccessKeyId>ASIAEXAMPLE0000000000</AccessKeyId><SecretAccessKey>role-secret</SecretAccessKey><SessionToken>role-token</SessionToken><Expiration>2099-01-01T00:00:00Z</Expiration></Credentials></AssumeRoleResult></AssumeRoleResponse>")))
        }
    }

    #[test]
    fn assume_role_post_matches_actual_go_requests() {
        let fixtures: Vec<serde_json::Value> =
            serde_json::from_str(include_str!("../testdata/assume-role-go.json"))
                .unwrap_or_else(|e| unreachable!("{e}"));
        for row in fixtures
            .iter()
            .filter(|row| row["name"].as_str().unwrap_or_default().starts_with("aws-"))
        {
            let endpoint = Url::parse(row["url"].as_str().unwrap_or_default())
                .unwrap_or_else(|e| unreachable!("{e}"));
            let values = Url::parse(&format!(
                "https://unused.invalid/?{}",
                row["body"].as_str().unwrap_or_default()
            ))
            .unwrap_or_else(|e| unreachable!("{e}"));
            let values = values
                .query_pairs()
                .collect::<std::collections::BTreeMap<_, _>>();
            let request = role_request(
                &endpoint,
                &RoleOptions {
                    arn: &values["RoleArn"],
                    session: &values["RoleSessionName"],
                    duration: 900,
                    external_id: None,
                },
            )
            .unwrap_or_else(|e| unreachable!("{e}"));
            assert_eq!(request.method().as_str(), row["method"]);
            assert_eq!(request.uri().to_string(), row["url"]);
            assert_eq!(
                request.body().as_ref(),
                row["body"].as_str().unwrap_or_default().as_bytes()
            );
            assert_eq!(
                request.headers()[http::header::CONTENT_TYPE],
                row["content_type"].as_str().unwrap_or_default()
            );
            let region = if row["name"] == "aws-china" {
                "cn-north-1"
            } else {
                "us-east-1"
            };
            let authority = regional_sts_endpoint(
                region,
                &AssumeRoleGrant::new(
                    values["RoleArn"].as_ref(),
                    values["RoleSessionName"].as_ref(),
                ),
            )
            .unwrap_or_else(|e| unreachable!("{e}"));
            if row["name"] != "aws-custom" {
                assert_eq!(endpoint.host_str(), Some(authority.as_str()));
            }
        }
    }

    #[tokio::test]
    async fn role_cache_uses_actual_expiry_and_never_falls_back_to_base() {
        let io = Io::default();
        let ctx = Context::new()
            .with_env(StaticEnv::default())
            .with_http_send(io.clone());
        let cfg = AwsMeteringConfig {
            access_key: "base-id".into(),
            secret_access_key: "base-secret".into(),
            session_token: "base-token".into(),
            assume_role_arn: "arn:aws:iam::123456789012:role/metering".into(),
            ..Default::default()
        };
        let endpoint = Url::parse("http://sts.fixture.invalid:9000/prefix")
            .unwrap_or_else(|e| unreachable!("{e}"));
        let signer = AwsSigner::new(&cfg, "us-east-1".into(), Some(endpoint.clone()), ctx)
            .await
            .unwrap_or_else(|e| unreachable!("{e}"));
        let (one, two) = tokio::join!(signer.credential(), signer.credential());
        assert_eq!(
            one.unwrap_or_else(|e| unreachable!("{e}")).access_key_id,
            "ASIAEXAMPLE0000000000"
        );
        assert!(two.is_ok());
        {
            let requests = io.requests.lock().unwrap_or_else(|e| unreachable!("{e}"));
            assert_eq!(requests.len(), 1);
            assert_eq!(requests[0].uri().to_string(), endpoint.as_str());
            assert_eq!(requests[0].headers()["x-amz-security-token"], "base-token");
            assert!(
                requests[0].headers()["authorization"]
                    .to_str()
                    .unwrap_or_default()
                    .contains("Credential=base-id/")
            );
        }
        {
            let mut state = signer.state.lock().await;
            state
                .role
                .as_mut()
                .unwrap_or_else(|| unreachable!())
                .expires_in = Some(Timestamp::now() + Duration::from_secs(5));
        }
        let mut parts = Request::head("https://bucket.s3.us-east-1.amazonaws.com/key")
            .body(())
            .unwrap_or_else(|e| unreachable!("{e}"))
            .into_parts()
            .0;
        signer
            .sign(&mut parts)
            .await
            .unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(
            io.requests
                .lock()
                .unwrap_or_else(|e| unreachable!("{e}"))
                .len(),
            1,
            "no reqsign early-expiry refresh"
        );
        assert!(
            parts.headers["authorization"]
                .to_str()
                .unwrap_or_default()
                .contains("ASIAEXAMPLE0000000000")
        );
        signer
            .state
            .lock()
            .await
            .role
            .as_mut()
            .unwrap_or_else(|| unreachable!())
            .expires_in = Some(Timestamp::now() - Duration::from_secs(1));
        io.fail.store(true, Ordering::SeqCst);
        assert!(
            signer.credential().await.is_err(),
            "never use expired role or source credential for S3"
        );
        io.fail.store(false, Ordering::SeqCst);
        assert!(signer.credential().await.is_ok());
        let requests = io.requests.lock().unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(requests.len(), 3);
        assert_eq!(
            requests[0].body(),
            requests[2].body(),
            "the generated session name survives refresh"
        );
    }
}

#[cfg(test)]
mod retry_tests {
    use super::*;
    use serde::Deserialize;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    #[derive(Clone, Debug, Deserialize)]
    #[allow(clippy::struct_excessive_bools)] // Actual Go observation schema.
    struct Row {
        name: String,
        web: bool,
        new: bool,
        status: u16,
        body: String,
        after: String,
        exhaust: bool,
        calls: usize,
        error: bool,
    }
    #[derive(Clone, Debug)]
    struct Io {
        row: Row,
        calls: Arc<AtomicUsize>,
        reads: Arc<AtomicUsize>,
    }
    impl reqsign_core::FileRead for Io {
        async fn file_read(&self, path: &str) -> reqsign_core::Result<Vec<u8>> {
            if path != "/web-token" {
                return Err(failed());
            }
            self.reads.fetch_add(1, Ordering::Relaxed);
            Ok(b"web-token\n".to_vec())
        }
    }
    impl reqsign_core::HttpSend for Io {
        async fn http_send(
            &self,
            request: Request<Bytes>,
        ) -> reqsign_core::Result<http::Response<Bytes>> {
            let call = self.calls.fetch_add(1, Ordering::Relaxed) + 1;
            assert_eq!(request.method(), "POST");
            let body = std::str::from_utf8(request.body()).unwrap_or_else(|e| unreachable!("{e}"));
            assert!(body.contains("RoleSessionName=session"));
            if self.row.web {
                assert!(body.contains("Action=AssumeRoleWithWebIdentity"));
                assert!(body.contains("WebIdentityToken=web-token%0A"));
            } else {
                assert!(body.contains("Action=AssumeRole&"));
                assert!(request.headers().contains_key("authorization"));
            }
            let (status, body) = if call > 1 && !self.row.exhaust {
                let operation = if self.row.web {
                    "AssumeRoleWithWebIdentity"
                } else {
                    "AssumeRole"
                };
                (
                    200,
                    format!(
                        "<{operation}Response><{operation}Result><Credentials><AccessKeyId>ASIA1234567890123456</AccessKeyId><SecretAccessKey>secret</SecretAccessKey><SessionToken>token</SessionToken><Expiration>2099-01-01T00:00:00Z</Expiration></Credentials></{operation}Result></{operation}Response>"
                    ),
                )
            } else {
                (self.row.status, self.row.body.clone())
            };
            http::Response::builder()
                .status(status)
                .header("x-amz-retry-after", &self.row.after)
                .body(Bytes::from(body))
                .map_err(|_| failed())
        }
    }
    #[tokio::test(start_paused = true)]
    async fn assume_role_and_web_identity_retries_match_actual_go() {
        let rows: Vec<Row> =
            serde_json::from_str(include_str!("../testdata/aws-sts-retry-go.json"))
                .unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(rows.len(), 56);
        for row in rows {
            let io = Io {
                row: row.clone(),
                calls: Arc::default(),
                reads: Arc::default(),
            };
            let mut envs = std::collections::HashMap::from([
                ("AWS_NEW_RETRIES_2026".into(), row.new.to_string()),
                ("AWS_ROLE_SESSION_NAME".into(), "session".into()),
            ]);
            if row.web {
                envs.extend([
                    (
                        "AWS_ROLE_ARN".into(),
                        "arn:aws:iam::123456789012:role/test".into(),
                    ),
                    ("AWS_WEB_IDENTITY_TOKEN_FILE".into(), "/web-token".into()),
                ]);
            }
            let ctx = Context::new()
                .with_env(reqsign_core::StaticEnv {
                    home_dir: None,
                    envs,
                })
                .with_http_send(io.clone())
                .with_file_read(io.clone());
            let start = tokio::time::Instant::now();
            let error = if row.web {
                crate::cloud_aws_identity::GoDefaultProvider::new("us-east-1")
                    .provide_credential(&ctx)
                    .await
                    .is_err()
            } else {
                let retry = Retry::new(&ctx);
                assume_role(
                    &ctx,
                    "us-east-1",
                    None,
                    &RoleOptions {
                        arn: "arn:aws:iam::123456789012:role/test",
                        session: "session",
                        duration: 900,
                        external_id: None,
                    },
                    Credential {
                        access_key_id: "key".into(),
                        secret_access_key: "secret".into(),
                        session_token: None,
                        expires_in: None,
                    },
                    &retry,
                )
                .await
                .is_err()
            };
            assert_eq!(
                error, row.error,
                "{} web={} new={}",
                row.name, row.web, row.new
            );
            assert_eq!(
                io.calls.load(Ordering::Relaxed),
                row.calls,
                "{} web={} new={}",
                row.name,
                row.web,
                row.new
            );
            if row.web {
                assert_eq!(io.reads.load(Ordering::Relaxed), 1);
            }
            if row.new && row.after == "2000" && row.calls == 2 {
                assert_eq!(start.elapsed(), std::time::Duration::from_secs(2));
            }
        }
    }
}
