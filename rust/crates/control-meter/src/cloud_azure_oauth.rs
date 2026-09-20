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

//! Claims-aware OAuth requests around the maintained Azure identity SDK.
use super::{ChallengeClaims, WorkloadAssertion, identity_error};
use azure_core::{
    credentials::{AccessToken, TokenCredential, TokenRequestOptions},
    http::{
        ClientOptions,
        policies::{Policy, PolicyResult},
    },
};
use std::{collections::BTreeMap, sync::Arc};
use tokio::sync::Mutex;

pub(super) enum Source {
    Secret {
        tenant: String,
        client: String,
        secret: String,
    },
    Certificate {
        tenant: String,
        client: String,
        der: String,
        password: String,
        send_chain: bool,
    },
    Workload {
        tenant: String,
        client: String,
        context: reqsign_core::Context,
        path: String,
    },
}
pub(super) struct Credential {
    source: Source,
    options: ClientOptions,
    cached: Mutex<BTreeMap<Vec<String>, AccessToken>>,
}
impl std::fmt::Debug for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AzureOAuthCredential")
    }
}
impl Credential {
    pub(super) fn new(source: Source, mut options: ClientOptions) -> azure_core::Result<Arc<Self>> {
        options.per_call_policies.push(Arc::new(ClaimsPolicy));
        let value = Arc::new(Self {
            source,
            options,
            cached: Mutex::new(BTreeMap::new()),
        });
        // Preserve constructor validation/fallback without doing credential I/O.
        value.fresh()?;
        Ok(value)
    }
    fn fresh(&self) -> azure_core::Result<Arc<dyn TokenCredential>> {
        match &self.source {
            Source::Secret {
                tenant,
                client,
                secret,
            } => azure_identity::ClientSecretCredential::new(
                tenant,
                client.clone(),
                secret.clone().into(),
                Some(azure_identity::ClientSecretCredentialOptions {
                    client_options: self.options.clone(),
                }),
            )
            .map(|v| v as Arc<dyn TokenCredential>),
            Source::Certificate {
                tenant,
                client,
                der,
                password,
                send_chain,
            } => azure_identity::ClientCertificateCredential::new(
                tenant.clone(),
                client.clone(),
                der.clone(),
                password.clone(),
                Some(azure_identity::ClientCertificateCredentialOptions {
                    client_options: self.options.clone(),
                    send_certificate_chain: *send_chain,
                }),
            )
            .map(|v| v as Arc<dyn TokenCredential>),
            Source::Workload {
                tenant,
                client,
                context,
                path,
            } => azure_identity::ClientAssertionCredential::new(
                tenant.clone(),
                client.clone(),
                WorkloadAssertion {
                    context: context.clone(),
                    path: path.clone(),
                },
                Some(azure_identity::ClientAssertionCredentialOptions {
                    client_options: self.options.clone(),
                    ..Default::default()
                }),
            )
            .map(|v| v as Arc<dyn TokenCredential>),
        }
    }
}
#[async_trait::async_trait]
impl TokenCredential for Credential {
    async fn get_token(
        &self,
        scopes: &[&str],
        options: Option<TokenRequestOptions<'_>>,
    ) -> azure_core::Result<AccessToken> {
        let claims = options
            .as_ref()
            .and_then(|o| o.method_options.context.value::<ChallengeClaims>())
            .map_or(&[][..], |c| c.0.as_slice());
        let key: Vec<_> = scopes.iter().map(|s| (*s).to_owned()).collect();
        let mut cached = self.cached.lock().await;
        if claims.is_empty()
            && let Some(token) = cached.get(&key)
            && token.expires_on
                >= azure_core::time::OffsetDateTime::now_utc()
                    + azure_core::time::Duration::minutes(5)
        {
            return Ok(token.clone());
        }
        // The pinned Rust SDK cache keys only by scope and cannot force a
        // claims refresh. A fresh SDK object handles each actual token fetch;
        // this resource cache supplies MSAL's reuse/bypass semantics.
        let token = self.fresh()?.get_token(scopes, options).await?;
        cached.insert(key, token.clone());
        Ok(token)
    }
}

pub(super) fn claims_json(claims: &[u8]) -> azure_core::Result<String> {
    let mut value = if claims.is_empty() {
        serde_json::json!({})
    } else {
        serde_json::from_slice(claims).map_err(|_| identity_error())?
    };
    merge(
        &mut value,
        &serde_json::json!({"access_token":{"xms_cc":{"values":["CP1"]}}}),
    )?;
    serde_json::to_string(&value).map_err(|_| identity_error())
}
fn merge(target: &mut serde_json::Value, defaults: &serde_json::Value) -> azure_core::Result<()> {
    let target = target.as_object_mut().ok_or_else(identity_error)?;
    for (key, value) in defaults.as_object().ok_or_else(identity_error)? {
        match target.get_mut(key) {
            None => {
                target.insert(key.clone(), value.clone());
            }
            Some(existing) if existing.is_object() && value.is_object() => merge(existing, value)?,
            Some(_) => return Err(identity_error()),
        }
    }
    Ok(())
}
pub(super) fn scope_with_oidc(scope: &str) -> String {
    let mut scopes: Vec<_> = scope.split(' ').filter(|s| !s.is_empty()).collect();
    for extra in ["openid", "offline_access", "profile"] {
        if !scopes.contains(&extra) {
            scopes.push(extra);
        }
    }
    scopes.join(" ")
}
#[derive(Debug)]
struct ClaimsPolicy;
#[async_trait::async_trait]
impl Policy for ClaimsPolicy {
    // Match the pinned SDK trait: explicitly naming Context's lifetime changes
    // async_trait's early/late lifetime binding and fails E0195.
    #[allow(elided_lifetimes_in_paths)]
    async fn send(
        &self,
        ctx: &azure_core::http::Context,
        request: &mut azure_core::http::Request,
        next: &[Arc<dyn Policy>],
    ) -> PolicyResult {
        let claims = ctx
            .value::<ChallengeClaims>()
            .map_or(&[][..], |c| c.0.as_slice());
        let claims = claims_json(claims)?;
        let azure_core::http::Body::Bytes(body) = request.body() else {
            return Err(identity_error());
        };
        let body = std::str::from_utf8(body).map_err(|_| identity_error())?;
        let mut url = reqwest::Url::parse("https://form.invalid").map_err(|_| identity_error())?;
        url.set_query(Some(body));
        let mut pairs: BTreeMap<String, String> = url
            .query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        if let Some(scope) = pairs.get_mut("scope") {
            *scope = scope_with_oidc(scope);
        }
        pairs.insert("claims".into(), claims);
        url.query_pairs_mut().clear().extend_pairs(pairs.iter());
        request.set_body(url.query().ok_or_else(identity_error)?.to_owned());
        next.first()
            .ok_or_else(identity_error)?
            .send(ctx, request, &next[1..])
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use bytes::Bytes;
    use http::{Request, Response};
    use reqsign_core::{Context, StaticEnv};
    use serde::Deserialize;
    use std::{collections::HashMap, sync::Mutex as StdMutex};
    #[derive(Deserialize)]
    struct Step {
        scope: String,
        claims: String,
        error: bool,
        token: String,
    }
    // These booleans are the independent redacted fields of the Go wire fixture.
    #[allow(clippy::struct_excessive_bools)]
    #[derive(Debug, Deserialize, PartialEq)]
    struct Observation {
        grant: String,
        scope: String,
        claims: serde_json::Value,
        client: bool,
        secret: bool,
        assertion: String,
        username: bool,
        password: bool,
    }
    #[derive(Deserialize, Clone)]
    struct ObjectStep {
        method: String,
        challenge: String,
        tokens: Vec<String>,
        error: bool,
    }
    #[derive(Default)]
    struct ObjectState {
        challenge: String,
        tokens: Vec<String>,
    }
    #[derive(Deserialize)]
    struct Row {
        source: String,
        steps: Vec<Step>,
        requests: Vec<Observation>,
        objects: Vec<ObjectStep>,
    }
    #[derive(Clone)]
    struct Io {
        client: String,
        cert: Vec<u8>,
        key: openssl::pkey::PKey<openssl::pkey::Private>,
        requests: Arc<StdMutex<Vec<Observation>>>,
        object: Arc<StdMutex<ObjectState>>,
    }
    impl std::fmt::Debug for Io {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("OAuthFixtureIo")
        }
    }
    impl reqsign_core::FileRead for Io {
        async fn file_read(&self, path: &str) -> reqsign_core::Result<Vec<u8>> {
            Ok(if path == "assertion" {
                b"fake-workload-assertion".to_vec()
            } else {
                self.cert.clone()
            })
        }
    }
    impl reqsign_core::HttpSend for Io {
        async fn http_send(
            &self,
            request: Request<Bytes>,
        ) -> reqsign_core::Result<Response<Bytes>> {
            if request.uri().path() == "/bucket/blob" {
                let mut state = self.object.lock().unwrap_or_else(|e| unreachable!("{e}"));
                let token = request
                    .headers()
                    .get("authorization")
                    .and_then(|h| h.to_str().ok())
                    .unwrap_or_default()
                    .to_owned();
                state.tokens.push(token);
                let expected: &[u8] = if request.method() == http::Method::PUT {
                    b"payload"
                } else {
                    b""
                };
                assert_eq!(request.body().as_ref(), expected);
                let challenged = state.tokens.len() == 1 && !state.challenge.is_empty();
                let status = if challenged {
                    401
                } else if request.method() == http::Method::PUT {
                    201
                } else {
                    200
                };
                let mut response = Response::builder().status(status);
                if challenged {
                    response = response.header("www-authenticate", &state.challenge);
                }
                return response
                    .body(Bytes::new())
                    .map_err(|_| reqsign_core::Error::unexpected("fixture object response"));
            }
            assert_eq!(request.method(), http::Method::POST);
            assert_eq!(
                request.uri(),
                "https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/oauth2/v2.0/token"
            );
            let mut form =
                reqwest::Url::parse("https://form.invalid").unwrap_or_else(|e| unreachable!("{e}"));
            form.set_query(Some(
                std::str::from_utf8(request.body()).unwrap_or_else(|e| unreachable!("{e}")),
            ));
            let form: BTreeMap<_, _> = form
                .query_pairs()
                .map(|(k, v)| (k.into_owned(), v.into_owned()))
                .collect();
            let get = |key| form.get(key).map_or("", String::as_str);
            let assertion = match get("client_assertion") {
                "" => "",
                "fake-workload-assertion" => "workload",
                jwt => {
                    let parts: Vec<_> = jwt.split('.').collect();
                    assert_eq!(parts.len(), 3);
                    let signature = base64::engine::general_purpose::URL_SAFE_NO_PAD
                        .decode(parts[2])
                        .unwrap_or_else(|e| unreachable!("{e}"));
                    let mut verifier = openssl::sign::Verifier::new(
                        openssl::hash::MessageDigest::sha256(),
                        &self.key,
                    )
                    .unwrap_or_else(|e| unreachable!("{e}"));
                    verifier
                        .update(format!("{}.{}", parts[0], parts[1]).as_bytes())
                        .unwrap_or_else(|e| unreachable!("{e}"));
                    assert!(
                        verifier
                            .verify(&signature)
                            .unwrap_or_else(|e| unreachable!("{e}"))
                    );
                    "certificate"
                }
            };
            let row = Observation {
                grant: get("grant_type").into(),
                scope: get("scope").into(),
                claims: serde_json::from_str(get("claims")).unwrap_or_else(|e| unreachable!("{e}")),
                client: get("client_id") == self.client,
                secret: get("client_secret") == "fake-secret",
                assertion: assertion.into(),
                username: get("username") == "fake@fixture.invalid",
                password: get("password") == "fake-password",
            };
            let mut requests = self.requests.lock().unwrap_or_else(|e| unreachable!("{e}"));
            requests.push(row);
            let body=serde_json::json!({"access_token":format!("fake-{}",requests.len()),"expires_in":3600,"token_type":"Bearer"}).to_string();
            Response::builder()
                .status(200)
                .header("content-type", "application/json")
                .body(body.into())
                .map_err(|_| reqsign_core::Error::unexpected("fixture response"))
        }
    }
    fn source_env(source: &str, client: String) -> HashMap<String, String> {
        let mut envs = HashMap::from([
            ("AZURE_CLIENT_ID".into(), client),
            (
                "AZURE_TENANT_ID".into(),
                "11111111-1111-1111-1111-111111111111".into(),
            ),
            (
                "AZURE_AUTHORITY_HOST".into(),
                "https://login.microsoftonline.com".into(),
            ),
            (
                "AZURE_TOKEN_CREDENTIALS".into(),
                "EnvironmentCredential".into(),
            ),
        ]);
        match source {
            "secret" => {
                envs.insert("AZURE_CLIENT_SECRET".into(), "fake-secret".into());
            }
            "workload" => {
                envs.insert(
                    "AZURE_TOKEN_CREDENTIALS".into(),
                    "WorkloadIdentityCredential".into(),
                );
                envs.insert("AZURE_FEDERATED_TOKEN_FILE".into(), "assertion".into());
            }
            "certificate" => {
                envs.insert("AZURE_CLIENT_CERTIFICATE_PATH".into(), "certificate".into());
            }
            "password" => {
                envs.insert("AZURE_USERNAME".into(), "fake@fixture.invalid".into());
                envs.insert("AZURE_PASSWORD".into(), "fake-password".into());
            }
            _ => unreachable!(),
        }
        envs
    }
    #[tokio::test]
    async fn oauth_claims_and_resource_caches_match_actual_go_credentials() {
        let rows: Vec<Row> = serde_json::from_str(include_str!("../testdata/azure-oauth-go.json"))
            .unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(rows.len(), 4);
        for (index, row) in rows.into_iter().enumerate() {
            let (key, cert) = super::super::tests::key_cert();
            let mut pem = cert.to_pem().unwrap_or_else(|e| unreachable!("{e}"));
            pem.extend(
                key.private_key_to_pem_pkcs8()
                    .unwrap_or_else(|e| unreachable!("{e}")),
            );
            let io = Io {
                client: format!("fake-client-{index}"),
                cert: pem,
                key,
                requests: Arc::new(StdMutex::new(Vec::new())),
                object: Arc::new(StdMutex::new(ObjectState::default())),
            };
            let envs = source_env(&row.source, io.client.clone());
            let context = Context::new()
                .with_env(StaticEnv {
                    envs,
                    ..Default::default()
                })
                .with_file_read(io.clone())
                .with_http_send(io.clone());
            let source = super::super::AzureDefault::new(reqwest::Client::new(), context.clone())
                .await
                .unwrap_or_else(|e| unreachable!("{e}"));
            assert_eq!(row.steps.len(), 13);
            for (step_index, step) in row.steps.into_iter().enumerate() {
                let result = source
                    .token_for(&step.scope, step.claims.into_bytes())
                    .await;
                assert_eq!(
                    result.is_err(),
                    step.error,
                    "{} step{step_index}",
                    row.source
                );
                if let Ok(token) = result {
                    assert_eq!(token, step.token, "{} step{step_index}", row.source);
                }
            }
            let signer = crate::cloud_azure::AzureSigner::Bearer(
                crate::cloud_azure::bearer::Bearer::new(source),
            );
            let url = reqwest::Url::parse("https://login.microsoftonline.com/bucket/blob")
                .unwrap_or_else(|e| unreachable!("{e}"));
            assert_eq!(row.objects.len(), 4);
            for (index, step) in row.objects.into_iter().enumerate() {
                {
                    let mut state = io.object.lock().unwrap_or_else(|e| unreachable!("{e}"));
                    state.challenge = step.challenge;
                    state.tokens.clear();
                }
                let method: http::Method =
                    step.method.parse().unwrap_or_else(|e| unreachable!("{e}"));
                let body = if method == http::Method::PUT {
                    Bytes::from_static(b"payload")
                } else {
                    Bytes::new()
                };
                let result = signer.request(&context, method, &url, body).await;
                assert_eq!(result.is_err(), step.error, "{} object{index}", row.source);
                assert_eq!(
                    io.object
                        .lock()
                        .unwrap_or_else(|e| unreachable!("{e}"))
                        .tokens,
                    step.tokens,
                    "{} object{index}",
                    row.source
                );
            }
            assert_eq!(
                *io.requests.lock().unwrap_or_else(|e| unreachable!("{e}")),
                row.requests,
                "{}",
                row.source
            );
        }
    }
}
