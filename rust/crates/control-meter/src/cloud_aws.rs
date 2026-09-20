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

use bytes::Bytes;
use control_config::AwsMeteringConfig;
use http::{Request, request::Parts};
use reqsign_aws_core::assume_role::{AssumeRoleOperation, regional_sts_endpoint};
use reqsign_aws_v4::{
    AssumeRoleGrant, Credential, DefaultCredentialProvider, RequestSigner, StaticCredentialProvider,
};
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
    pub(crate) fn new(
        config: &AwsMeteringConfig,
        region: String,
        endpoint: Option<Url>,
        context: Context,
    ) -> Self {
        let base = if !config.access_key.is_empty() && !config.secret_access_key.is_empty() {
            let mut provider =
                StaticCredentialProvider::new(&config.access_key, &config.secret_access_key);
            if !config.session_token.is_empty() {
                provider = provider.with_session_token(&config.session_token);
            }
            ProvideCredentialChain::new().push(provider)
        } else {
            ProvideCredentialChain::new().push(DefaultCredentialProvider::new())
        };
        Self {
            context,
            base,
            region,
            endpoint,
            role: config.assume_role_arn.clone(),
            state: Mutex::new(State::default()),
        }
    }

    pub(crate) async fn sign(&self, parts: &mut Parts) -> reqsign_core::Result<()> {
        let mut credential = self.credential().await?;
        // The Go CredentialsCache has no early-expiry window. This clone is
        // never put into our cache; only the signer sees expiration removed.
        credential.expires_in = None;
        RequestSigner::new("s3", &self.region)
            .sign_request(&self.context, parts, Some(&credential), None)
            .await
    }

    async fn credential(&self) -> reqsign_core::Result<Credential> {
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
            if !base.is_valid_at(Timestamp::now()) {
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
        let grant = AssumeRoleGrant::new(&self.role, session.as_str());
        let authority = regional_sts_endpoint(&self.region, &grant)?;
        let endpoint = match &self.endpoint {
            Some(endpoint) => endpoint.clone(),
            None => Url::parse(&format!("https://{authority}/")).map_err(|_| failed())?,
        };
        let operation = AssumeRoleOperation::new(authority, &grant, Some(900))?;
        // Keep the SDK's response parser and redacted errors, while using the
        // pinned Go SDK's POST body and configured BaseEndpoint for STS too.
        let mut source = base;
        source.expires_in = None;
        let request = role_request(&endpoint, &self.role, session)?;
        let (mut parts, body) = request.into_parts();
        RequestSigner::new("sts", &self.region)
            .sign_request(&self.context, &mut parts, Some(&source), None)
            .await?;
        let credential = operation
            .send(&self.context, Request::from_parts(parts, body))
            .await?;
        state.role = Some(credential.clone());
        Ok(credential)
    }
}

fn role_request(endpoint: &Url, role: &str, session: &str) -> reqsign_core::Result<Request<Bytes>> {
    let body = Url::parse_with_params(
        "https://unused.invalid",
        &[
            ("Action", "AssumeRole"),
            ("DurationSeconds", "900"),
            ("RoleArn", role),
            ("RoleSessionName", session),
            ("Version", "2011-06-15"),
        ],
    )
    .map_err(|_| failed())?
    .query()
    .ok_or_else(failed)?
    .to_owned();
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
            let request = role_request(&endpoint, &values["RoleArn"], &values["RoleSessionName"])
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
        let signer = AwsSigner::new(&cfg, "us-east-1".into(), Some(endpoint.clone()), ctx);
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
