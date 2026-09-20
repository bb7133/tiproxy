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

//! Tencent SDK-compatible credential sources and STS refresh for COS.

use std::fmt;
use std::time::Duration;

use bytes::Bytes;
use control_config::CloudMeteringConfig;
use http::{Request, request::Parts};
use reqsign_core::hash::{hex_hmac_sha256, hex_sha256, hmac_sha256};
use reqsign_core::time::Timestamp;
use reqsign_core::{Context, ProvideCredential, SignRequest};
use reqsign_tencent_cos::{Credential, RequestSigner};
use serde::Deserialize;
use tokio::sync::{Mutex, OnceCell};

const ROLE_DURATION: u64 = 7200;
const CVM_ROLE: &str = "http://metadata.tencentyun.com/latest/meta-data/cam/security-credentials/";
const STS: &str = "https://sts.tencentcloudapi.com/";

pub(crate) struct CosSigner {
    context: Context,
    base: Base,
    role: String,
    state: Mutex<Option<CachedCredential>>,
}

struct CachedCredential {
    credential: Credential,
    refresh_at: Option<Timestamp>,
}

impl fmt::Debug for CosSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CosSigner").finish_non_exhaustive()
    }
}

impl CosSigner {
    pub(crate) fn new(config: &CloudMeteringConfig, context: Context) -> Self {
        let base = if !config.access_key.is_empty() && !config.secret_access_key.is_empty() {
            Base::Configured(Credential {
                secret_id: config.access_key.clone(),
                secret_key: config.secret_access_key.clone(),
                security_token: (!config.session_token.is_empty())
                    .then(|| config.session_token.clone()),
                expires_in: None,
            })
        } else {
            Base::Default(GoDefaultProvider::default())
        };
        Self {
            context,
            base,
            role: config.assume_role_arn.clone(),
            state: Mutex::new(None),
        }
    }

    pub(crate) async fn sign(&self, parts: &mut Parts) -> reqsign_core::Result<()> {
        let mut credential = self.credential().await?;
        if [&credential.secret_id, &credential.secret_key]
            .iter()
            .any(|v| v.starts_with(' ') || v.ends_with(' '))
        {
            return Err(failed());
        }
        // Go signs a one-hour header while checking the temporary credential's
        // *current* lifetime. reqsign otherwise requires a whole extra hour of
        // credential validity. Our refresh gate above owns expiry instead.
        credential.expires_in = None;
        RequestSigner::new()
            .sign_request(&self.context, parts, Some(&credential), None)
            .await
    }

    async fn credential(&self) -> reqsign_core::Result<Credential> {
        let now = Timestamp::now();
        let mut state = self.state.lock().await;
        if let Some(cached) = state.as_ref()
            && cached.refresh_at.is_none_or(|refresh| now < refresh)
        {
            return Ok(cached.credential.clone());
        }
        let refreshed = async {
            let base = self.base.credential(&self.context).await?;
            if self.role.is_empty() {
                Ok(base)
            } else {
                assume_role(&self.context, &base, &self.role, now).await
            }
        }
        .await;
        match refreshed {
            Ok(credential) => {
                if credential.secret_id.is_empty()
                    || credential.secret_key.is_empty()
                    || credential.expires_in.is_some_and(|expires| expires <= now)
                {
                    return Err(failed());
                }
                let margin = if self.role.is_empty() {
                    self.base.refresh_margin().await
                } else {
                    ROLE_DURATION / 10
                };
                let refresh_at = credential
                    .expires_in
                    .map(|expires| expires - Duration::from_secs(margin));
                *state = Some(CachedCredential {
                    credential: credential.clone(),
                    refresh_at,
                });
                Ok(credential)
            }
            Err(error) => {
                // Retain a still-valid credential when an early refresh fails,
                // matching the Go metering SDK's AssumeRole fallback policy.
                if let Some(cached) = state.as_ref()
                    && cached
                        .credential
                        .expires_in
                        .is_some_and(|expires| now < expires)
                {
                    return Ok(cached.credential.clone());
                }
                Err(error)
            }
        }
    }
}

enum Base {
    Configured(Credential),
    Default(GoDefaultProvider),
}
impl Base {
    async fn credential(&self, ctx: &Context) -> reqsign_core::Result<Credential> {
        match self {
            Self::Configured(value) => Ok(value.clone()),
            Self::Default(provider) => provider.provide_credential(ctx).await?.ok_or_else(failed),
        }
    }
    async fn refresh_margin(&self) -> u64 {
        match self {
            Self::Configured(_) => 0,
            Self::Default(provider) => match provider.selected.lock().await.as_ref() {
                Some(SelectedSource::Tke) => ROLE_DURATION / 10,
                Some(SelectedSource::Cvm) => 300,
                _ => 0,
            },
        }
    }
}

fn failed() -> reqsign_core::Error {
    reqsign_core::Error::credential_invalid("Tencent cloud credential unavailable")
}

#[derive(Debug, Default)]
struct GoDefaultProvider {
    tke_available: OnceCell<bool>,
    selected: Mutex<Option<SelectedSource>>,
}

#[derive(Debug)]
enum SelectedSource {
    Static(Credential),
    Tke,
    Cvm,
}

impl ProvideCredential for GoDefaultProvider {
    type Credential = Credential;
    async fn provide_credential(&self, ctx: &Context) -> reqsign_core::Result<Option<Credential>> {
        let mut selected = self.selected.lock().await;
        match selected.as_ref() {
            Some(SelectedSource::Static(credential)) => return Ok(Some(credential.clone())),
            Some(SelectedSource::Tke) => return TkeProvider.provide_credential(ctx).await,
            Some(SelectedSource::Cvm) => return CvmProvider.provide_credential(ctx).await,
            None => (),
        }
        // Unlike generic best-effort chains, the Go SDK stops on malformed or
        // inaccessible configured credentials. Preserve its chosen source.
        if let Some(credential) = EnvProvider.provide_credential(ctx).await? {
            *selected = Some(SelectedSource::Static(credential.clone()));
            return Ok(Some(credential));
        }
        // Metering's Go chain includes TKE only if its constructor can read
        // all inputs, including the token file. Once constructed, an STS or
        // later token-file error is terminal and never falls through.
        if *self
            .tke_available
            .get_or_init(|| TkeProvider::available(ctx))
            .await
            && let Some(credential) = TkeProvider.provide_credential(ctx).await?
        {
            *selected = Some(SelectedSource::Tke);
            return Ok(Some(credential));
        }
        if let Some(credential) = ProfileProvider.provide_credential(ctx).await? {
            *selected = Some(SelectedSource::Static(credential.clone()));
            return Ok(Some(credential));
        }
        let credential = CvmProvider.provide_credential(ctx).await?;
        if credential.is_some() {
            *selected = Some(SelectedSource::Cvm);
        }
        Ok(credential)
    }
}

#[derive(Debug)]
struct EnvProvider;
impl ProvideCredential for EnvProvider {
    type Credential = Credential;
    async fn provide_credential(&self, ctx: &Context) -> reqsign_core::Result<Option<Credential>> {
        let (Some(secret_id), Some(secret_key)) = (
            ctx.env_var("TENCENTCLOUD_SECRET_ID"),
            ctx.env_var("TENCENTCLOUD_SECRET_KEY"),
        ) else {
            return Ok(None);
        };
        if secret_id.is_empty() || secret_key.is_empty() {
            return Err(failed());
        }
        // common.DefaultEnvProvider in the pinned Go SDK ignores the token env.
        Ok(Some(Credential {
            secret_id,
            secret_key,
            security_token: None,
            expires_in: None,
        }))
    }
}

#[derive(Debug)]
struct TkeProvider;
impl TkeProvider {
    async fn available(ctx: &Context) -> bool {
        let complete = [
            "TKE_REGION",
            "TKE_PROVIDER_ID",
            "TKE_WEB_IDENTITY_TOKEN_FILE",
            "TKE_ROLE_ARN",
        ]
        .iter()
        .all(|key| ctx.env_var(key).is_some_and(|value| !value.is_empty()));
        if !complete {
            return false;
        }
        ctx.file_read(
            &ctx.env_var("TKE_WEB_IDENTITY_TOKEN_FILE")
                .unwrap_or_default(),
        )
        .await
        .is_ok()
    }
}
impl ProvideCredential for TkeProvider {
    type Credential = Credential;
    async fn provide_credential(&self, ctx: &Context) -> reqsign_core::Result<Option<Credential>> {
        let (Some(region), Some(provider), Some(file), Some(role)) = (
            ctx.env_var("TKE_REGION"),
            ctx.env_var("TKE_PROVIDER_ID"),
            ctx.env_var("TKE_WEB_IDENTITY_TOKEN_FILE"),
            ctx.env_var("TKE_ROLE_ARN"),
        ) else {
            return Ok(None);
        };
        if [&region, &provider, &file, &role]
            .iter()
            .any(|v| v.is_empty())
        {
            return Ok(None);
        }
        let token = ctx.file_read_as_string(&file).await?;
        let now = Timestamp::now();
        let body = serde_json::to_vec(&serde_json::json!({
            "ProviderId": provider, "WebIdentityToken": token, "RoleArn": role,
            "RoleSessionName": format!("tencentcloud-go-sdk-{}{:06}", now.as_second(), now.subsec_nanosecond() / 1000), "DurationSeconds": ROLE_DURATION
        })).map_err(|_| failed())?;
        let request = Request::post(STS)
            .header("content-type", "application/json")
            .header("x-tc-action", "AssumeRoleWithWebIdentity")
            .header("x-tc-version", "2018-08-13")
            // The pinned Go DefaultTkeOIDCRoleArnProvider reads TKE_REGION but
            // assigns its package-level Guangzhou constant to the actual request.
            .header("x-tc-region", "ap-guangzhou")
            .header("x-tc-timestamp", now.as_second())
            .header("authorization", "SKIP")
            .body(Bytes::from(body))?;
        let response = ctx.http_send(request).await?;
        if !response.status().is_success() {
            return Err(failed());
        }
        let response: StsResponse =
            serde_json::from_slice(response.body()).map_err(|_| failed())?;
        let value = response.response;
        Ok(Some(Credential {
            secret_id: value.credentials.tmp_secret_id,
            secret_key: value.credentials.tmp_secret_key,
            security_token: Some(value.credentials.token),
            expires_in: Some(Timestamp::from_second(value.expired_time)?),
        }))
    }
}

#[derive(Debug)]
struct ProfileProvider;

impl ProvideCredential for ProfileProvider {
    type Credential = Credential;
    async fn provide_credential(&self, ctx: &Context) -> reqsign_core::Result<Option<Credential>> {
        let configured = ctx.env_var("TENCENTCLOUD_CREDENTIALS_FILE");
        let path = configured.clone().or_else(|| {
            ctx.home_dir().map(|home| {
                home.join(".tencentcloud/credentials")
                    .to_string_lossy()
                    .into_owned()
            })
        });
        let Some(path) = path else {
            return Ok(None);
        };
        if path.is_empty() {
            return Err(failed());
        }
        let data = match ctx.file_read(&path).await {
            Ok(data) => data,
            Err(error) if configured.is_none() && crate::cloud_context::not_found(&error) => {
                return Ok(None);
            }
            Err(_) => return Err(failed()),
        };
        let data = String::from_utf8(data).map_err(|_| failed())?;
        let ini = ini::Ini::load_from_str(&data).map_err(|_| failed())?;
        let profile = ini.section(Some("default")).ok_or_else(failed)?;
        let secret_id = profile
            .get("secret_id")
            .filter(|v| !v.is_empty())
            .ok_or_else(failed)?
            .to_owned();
        let secret_key = profile
            .get("secret_key")
            .filter(|v| !v.is_empty())
            .ok_or_else(failed)?
            .to_owned();
        Ok(Some(Credential {
            secret_id,
            secret_key,
            security_token: None,
            expires_in: None,
        }))
    }
}

#[derive(Debug)]
struct CvmProvider;

impl ProvideCredential for CvmProvider {
    type Credential = Credential;
    async fn provide_credential(&self, ctx: &Context) -> reqsign_core::Result<Option<Credential>> {
        let response = ctx
            .http_send(Request::get(CVM_ROLE).body(Bytes::new())?)
            .await?;
        if !response.status().is_success() {
            return Err(failed());
        }
        let role = std::str::from_utf8(response.body()).map_err(|_| failed())?;
        if role.is_empty()
            || role
                .bytes()
                .any(|b| !b.is_ascii_alphanumeric() && b != b'_' && b != b'-')
        {
            return Err(failed());
        }
        let response = ctx
            .http_send(Request::get(format!("{CVM_ROLE}{role}")).body(Bytes::new())?)
            .await?;
        if !response.status().is_success() {
            return Err(failed());
        }
        let value: CvmResponse = serde_json::from_slice(response.body()).map_err(|_| failed())?;
        if value.code != "Success" || value.token.is_empty() {
            return Err(failed());
        }
        Ok(Some(Credential {
            secret_id: value.tmp_secret_id,
            secret_key: value.tmp_secret_key,
            security_token: Some(value.token),
            expires_in: Some(Timestamp::from_second(value.expired_time)?),
        }))
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct CvmResponse {
    #[serde(rename = "TmpSecretId")]
    tmp_secret_id: String,
    tmp_secret_key: String,
    token: String,
    expired_time: i64,
    code: String,
}

async fn assume_role(
    ctx: &Context,
    base: &Credential,
    role: &str,
    now: Timestamp,
) -> reqsign_core::Result<Credential> {
    let body = serde_json::to_vec(&serde_json::json!({
        "RoleArn": role, "RoleSessionName": "metering-writer", "DurationSeconds": ROLE_DURATION
    }))
    .map_err(|_| failed())?;
    let request = sts_request(base, now, body)?;
    let response = ctx.http_send(request).await?;
    if !response.status().is_success() {
        return Err(failed());
    }
    let value: StsResponse = serde_json::from_slice(response.body()).map_err(|_| failed())?;
    let value = value.response;
    let credentials = value.credentials;
    if credentials.tmp_secret_id.is_empty()
        || credentials.tmp_secret_key.is_empty()
        || credentials.token.is_empty()
    {
        return Err(failed());
    }
    let expires = if value.expired_time <= 0 {
        now + Duration::from_secs(ROLE_DURATION)
    } else {
        Timestamp::from_second(value.expired_time)?
    };
    Ok(Credential {
        secret_id: credentials.tmp_secret_id,
        secret_key: credentials.tmp_secret_key,
        security_token: Some(credentials.token),
        expires_in: Some(expires),
    })
}

fn sts_request(
    base: &Credential,
    now: Timestamp,
    body: Vec<u8>,
) -> reqsign_core::Result<Request<Bytes>> {
    let date = &now.format_rfc3339_zulu()[..10];
    let scope = format!("{date}/sts/tc3_request");
    let canonical = format!(
        "POST\n/\n\ncontent-type:application/json\nhost:sts.tencentcloudapi.com\n\ncontent-type;host\n{}",
        hex_sha256(&body)
    );
    let to_sign = format!(
        "TC3-HMAC-SHA256\n{}\n{scope}\n{}",
        now.as_second(),
        hex_sha256(canonical.as_bytes())
    );
    let date_key = hmac_sha256(
        format!("TC3{}", base.secret_key).as_bytes(),
        date.as_bytes(),
    );
    let service_key = hmac_sha256(&date_key, b"sts");
    let signing_key = hmac_sha256(&service_key, b"tc3_request");
    let signature = hex_hmac_sha256(&signing_key, to_sign.as_bytes());
    let auth = format!(
        "TC3-HMAC-SHA256 Credential={}/{scope}, SignedHeaders=content-type;host, Signature={signature}",
        base.secret_id
    );
    let mut request = Request::post(STS)
        .header("content-type", "application/json")
        .header("host", "sts.tencentcloudapi.com")
        .header("x-tc-action", "AssumeRole")
        .header("x-tc-version", "2018-08-13")
        .header("x-tc-region", "ap-guangzhou")
        .header("x-tc-timestamp", now.as_second())
        .header("authorization", auth);
    if let Some(token) = &base.security_token {
        request = request.header("x-tc-token", token);
    }
    let mut request = request.body(Bytes::from(body)).map_err(|_| failed())?;
    for name in ["authorization", "x-tc-token"] {
        if let Some(value) = request.headers_mut().get_mut(name) {
            value.set_sensitive(true);
        }
    }
    Ok(request)
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct StsResponse {
    response: StsResult,
}
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct StsResult {
    credentials: StsCredential,
    #[serde(default)]
    expired_time: i64,
}
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct StsCredential {
    #[serde(rename = "TmpSecretId")]
    tmp_secret_id: String,
    tmp_secret_key: String,
    token: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqsign_core::{FileRead, HttpSend, StaticEnv};
    use std::collections::{HashMap, VecDeque};
    use std::sync::{Arc, Mutex as StdMutex};

    type Replies = Arc<StdMutex<VecDeque<(u16, Vec<u8>)>>>;

    #[derive(Clone, Debug)]
    struct Fixture {
        files: HashMap<String, Vec<u8>>,
        replies: Replies,
        requests: Arc<StdMutex<Vec<Request<Bytes>>>>,
    }
    impl Fixture {
        fn new(replies: Vec<(u16, Vec<u8>)>) -> Self {
            Self {
                files: HashMap::new(),
                replies: Arc::new(StdMutex::new(replies.into())),
                requests: Arc::default(),
            }
        }
        fn context(&self, envs: HashMap<String, String>) -> Context {
            Context::new()
                .with_env(StaticEnv {
                    home_dir: None,
                    envs,
                })
                .with_file_read(self.clone())
                .with_http_send(self.clone())
        }
        fn requests(&self) -> std::sync::MutexGuard<'_, Vec<Request<Bytes>>> {
            self.requests.lock().unwrap_or_else(|e| unreachable!("{e}"))
        }
    }
    impl FileRead for Fixture {
        async fn file_read(&self, path: &str) -> reqsign_core::Result<Vec<u8>> {
            self.files.get(path).cloned().ok_or_else(|| {
                reqsign_core::Error::unexpected("fixture file missing")
                    .with_source(std::io::Error::from(std::io::ErrorKind::NotFound))
            })
        }
    }
    impl HttpSend for Fixture {
        async fn http_send(
            &self,
            request: Request<Bytes>,
        ) -> reqsign_core::Result<http::Response<Bytes>> {
            self.requests().push(request);
            let (status, body) = self
                .replies
                .lock()
                .unwrap_or_else(|e| unreachable!("{e}"))
                .pop_front()
                .ok_or_else(failed)?;
            Ok(http::Response::builder()
                .status(status)
                .body(Bytes::from(body))?)
        }
    }
    fn credential() -> Credential {
        Credential {
            secret_id: "fake-id".into(),
            secret_key: "fake-secret".into(),
            security_token: Some("fake-token".into()),
            expires_in: None,
        }
    }
    fn role_reply(now: Timestamp) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({"Response": {
            "Credentials": {"TmpSecretId":"role-id", "TmpSecretKey":"role-secret", "Token":"role-token"},
            "ExpiredTime": now.as_second() + 7200
        }})).unwrap_or_else(|e| unreachable!("{e}"))
    }

    #[test]
    fn sts_signature_matches_pinned_go_sdk_request() {
        // Regenerate from repository root: go run rust/crates/control-meter/testdata/cos-sts-go.go
        let golden: serde_json::Value =
            serde_json::from_str(include_str!("../testdata/cos-sts-go.json"))
                .unwrap_or_else(|e| unreachable!("{e}"));
        let body = golden["body"]
            .as_str()
            .unwrap_or_else(|| unreachable!())
            .as_bytes()
            .to_vec();
        let now = Timestamp::from_second(1_700_000_000).unwrap_or_else(|e| unreachable!("{e}"));
        let request = sts_request(&credential(), now, body).unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(
            request.headers()["authorization"]
                .to_str()
                .unwrap_or_else(|e| unreachable!("{e}")),
            golden["authorization"]
        );
        assert_eq!(request.headers()["x-tc-token"], "fake-token");
    }

    #[tokio::test]
    async fn role_cache_falls_back_only_while_the_old_credential_is_valid() {
        let now = Timestamp::now();
        let io = Fixture::new(vec![(200, role_reply(now)), (500, vec![]), (500, vec![])]);
        let signer = CosSigner::new(
            &CloudMeteringConfig {
                access_key: "fake-id".into(),
                secret_access_key: "fake-secret".into(),
                session_token: "fake-token".into(),
                assume_role_arn: "qcs::cam::uin/123:roleName/test".into(),
            },
            io.context(HashMap::new()),
        );
        let first = signer
            .credential()
            .await
            .unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(first.secret_id, "role-id");
        assert_eq!(
            signer
                .credential()
                .await
                .unwrap_or_else(|e| unreachable!("{e}"))
                .secret_id,
            "role-id"
        );
        assert_eq!(io.requests().len(), 1);
        {
            let mut state = signer.state.lock().await;
            let cached = state.as_mut().unwrap_or_else(|| unreachable!());
            cached.refresh_at = Some(now - Duration::from_secs(1));
            cached.credential.expires_in = Some(now + Duration::from_secs(30));
        }
        // Even <1h validity must work with Go's one-hour COS signature header.
        let mut parts = Request::get("https://bucket.cos.example/object")
            .body(())
            .unwrap_or_else(|e| unreachable!("{e}"))
            .into_parts()
            .0;
        signer
            .sign(&mut parts)
            .await
            .unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(parts.headers["x-cos-security-token"], "role-token");
        {
            let mut state = signer.state.lock().await;
            state
                .as_mut()
                .unwrap_or_else(|| unreachable!())
                .credential
                .expires_in = Some(now - Duration::from_secs(1));
        }
        assert!(signer.credential().await.is_err());
        assert_eq!(io.requests().len(), 3);
        let requests = io.requests();
        let body: serde_json::Value =
            serde_json::from_slice(requests[0].body()).unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(body["DurationSeconds"], 7200);
        assert_eq!(body["RoleSessionName"], "metering-writer");
    }

    #[tokio::test]
    async fn default_chain_preserves_go_env_and_profile_precedence() {
        let mut io = Fixture::new(vec![]);
        io.files.insert(
            "profile".into(),
            b"[default]\nsecret_id=profile-id\nsecret_key=profile-secret\n".to_vec(),
        );
        let mut env = HashMap::from([
            ("TENCENTCLOUD_SECRET_ID".into(), "env-id".into()),
            ("TENCENTCLOUD_SECRET_KEY".into(), "env-secret".into()),
            ("TENCENTCLOUD_TOKEN".into(), "ignored-token".into()),
            ("TENCENTCLOUD_CREDENTIALS_FILE".into(), "profile".into()),
        ]);
        let signer = CosSigner::new(&CloudMeteringConfig::default(), io.context(env.clone()));
        let cred = signer
            .credential()
            .await
            .unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(cred.secret_id, "env-id");
        assert!(cred.security_token.is_none());
        env.remove("TENCENTCLOUD_SECRET_KEY");
        let signer = CosSigner::new(&CloudMeteringConfig::default(), io.context(env.clone()));
        assert_eq!(
            signer
                .credential()
                .await
                .unwrap_or_else(|e| unreachable!("{e}"))
                .secret_id,
            "profile-id"
        );
        env.insert("TENCENTCLOUD_SECRET_KEY".into(), String::new());
        let signer = CosSigner::new(&CloudMeteringConfig::default(), io.context(env));
        assert!(
            signer.credential().await.is_err(),
            "explicit empty env must not fall through"
        );
        assert!(io.requests().is_empty());
    }

    #[tokio::test]
    async fn cvm_and_tke_sources_keep_temporary_identity_and_expiration() {
        let now = Timestamp::now();
        let cvm = serde_json::to_vec(&serde_json::json!({"Code":"Success", "TmpSecretId":"cvm-id", "TmpSecretKey":"cvm-secret", "Token":"cvm-token", "ExpiredTime":now.as_second()+7200})).unwrap_or_else(|e| unreachable!("{e}"));
        let io = Fixture::new(vec![(200, b"bound-role".to_vec()), (200, cvm)]);
        let signer = CosSigner::new(&CloudMeteringConfig::default(), io.context(HashMap::new()));
        let cred = signer
            .credential()
            .await
            .unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(cred.secret_id, "cvm-id");
        assert_eq!(cred.security_token.as_deref(), Some("cvm-token"));
        assert!(io.requests()[1].uri().path().ends_with("/bound-role"));
        let mut io = Fixture::new(vec![(200, role_reply(now))]);
        io.files
            .insert("token".into(), b"fake-web-identity".to_vec());
        let env = HashMap::from([
            ("TKE_REGION".into(), "ap-beijing".into()),
            ("TKE_PROVIDER_ID".into(), "provider".into()),
            ("TKE_WEB_IDENTITY_TOKEN_FILE".into(), "token".into()),
            ("TKE_ROLE_ARN".into(), "role".into()),
        ]);
        let signer = CosSigner::new(&CloudMeteringConfig::default(), io.context(env));
        let cred = signer
            .credential()
            .await
            .unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(cred.secret_id, "role-id");
        assert!(cred.expires_in.is_some());
        let requests = io.requests();
        assert_eq!(
            requests[0].headers()["x-tc-action"],
            "AssumeRoleWithWebIdentity"
        );
        let body: serde_json::Value =
            serde_json::from_slice(requests[0].body()).unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(body["DurationSeconds"], 7200);
    }
    #[tokio::test]
    async fn default_cos_upload_identity_matches_actual_go() {
        let rows: Vec<serde_json::Value> =
            serde_json::from_str(include_str!("../testdata/cos-default-go.json"))
                .unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(rows.len(), 6);
        for row in rows {
            let name = row["name"].as_str().unwrap_or_default();
            let mut io = Fixture::new(if row["denied"] == true {
                vec![(403, Vec::new())]
            } else {
                vec![(200, serde_json::to_vec(&serde_json::json!({"Response":{"Credentials":{"TmpSecretId":"tke-id","TmpSecretKey":"tke-secret","Token":"tke-token"},"ExpiredTime":4_070_908_800_i64}})).unwrap_or_else(|e| unreachable!("{e}")))]
            });
            io.files.insert(
                "/fixture/credentials".into(),
                b"[default]\nsecret_id=profile-id\nsecret_key=profile-secret\n".to_vec(),
            );
            if row["token_file"] == true {
                io.files
                    .insert("/fixture/token".into(), b"fake-token\n".to_vec());
            }
            let mut envs: HashMap<String, String> = row["env"]
                .as_object()
                .map(|o| {
                    o.iter()
                        .map(|(k, v)| (k.clone(), v.as_str().unwrap_or_default().to_owned()))
                        .collect()
                })
                .unwrap_or_default();
            envs.insert(
                "TENCENTCLOUD_CREDENTIALS_FILE".into(),
                "/fixture/credentials".into(),
            );
            if name.contains("tke") {
                envs.extend(
                    [
                        ("TKE_REGION", "ap-singapore"),
                        ("TKE_PROVIDER_ID", "provider-id"),
                        ("TKE_WEB_IDENTITY_TOKEN_FILE", "/fixture/token"),
                        ("TKE_ROLE_ARN", "qcs::cam::uin/123:roleName/test"),
                    ]
                    .map(|(k, v)| (k.into(), v.into())),
                );
            }
            let signer = CosSigner::new(&CloudMeteringConfig::default(), io.context(envs));
            let result = signer.credential().await;
            assert_eq!(
                result.is_err(),
                row["error"].as_bool().unwrap_or_default(),
                "{name}"
            );
            if let Ok(value) = result {
                assert_eq!(value.secret_id, row["credential"], "{name}");
                assert_eq!(
                    value.security_token.unwrap_or_default(),
                    row["security_token"],
                    "{name}"
                );
            }
            let requests = io.requests();
            let expected = row["sts"].as_array().cloned().unwrap_or_default();
            // The production Go Upload retries the whole operation on an
            // authentication error. This test invokes one credential fetch;
            // compare its source/request with every normalized Go attempt.
            assert!(expected.windows(2).all(|pair| pair[0] == pair[1]));
            assert_eq!(requests.len(), usize::from(!expected.is_empty()), "{name}");
            for (actual, expected) in requests.iter().zip(expected.iter().take(1)) {
                let mut body: serde_json::Value =
                    serde_json::from_slice(actual.body()).unwrap_or_else(|e| unreachable!("{e}"));
                let micros = body["RoleSessionName"]
                    .as_str()
                    .unwrap_or_default()
                    .strip_prefix("tencentcloud-go-sdk-")
                    .unwrap_or_default()
                    .parse::<i64>()
                    .unwrap_or_else(|e| unreachable!("{e}"));
                assert!((Timestamp::now().as_second() - micros / 1_000_000).abs() <= 1);
                body["RoleSessionName"] = "fixture-session".into();
                assert_eq!(body, expected["body"], "{name}");
                assert_eq!(actual.method().as_str(), expected["method"], "{name}");
                assert_eq!(actual.uri().to_string(), expected["url"], "{name}");
                assert_eq!(
                    actual.headers()["x-tc-region"],
                    expected["region"].as_str().unwrap_or_default()
                );
                assert_eq!(
                    actual.headers()["authorization"],
                    expected["authorization"].as_str().unwrap_or_default()
                );
            }
        }
    }

    #[tokio::test]
    async fn cvm_fallback_uses_its_actual_refresh_margin_despite_complete_tke_env() {
        let now = Timestamp::now();
        let io = Fixture::new(vec![(200,b"fixture-role".to_vec()),(200,serde_json::to_vec(&serde_json::json!({"Code":"Success","TmpSecretId":"cvm-id","TmpSecretKey":"cvm-secret","Token":"cvm-token","ExpiredTime":now.as_second()+7200})).unwrap_or_else(|e| unreachable!("{e}")))]);
        let envs = [
            ("TKE_REGION", "region"),
            ("TKE_PROVIDER_ID", "provider"),
            ("TKE_WEB_IDENTITY_TOKEN_FILE", "/missing"),
            ("TKE_ROLE_ARN", "role"),
        ]
        .map(|(k, v)| (k.into(), v.into()))
        .into_iter()
        .collect();
        let signer = CosSigner::new(&CloudMeteringConfig::default(), io.context(envs));
        let value = signer
            .credential()
            .await
            .unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(value.secret_id, "cvm-id");
        let state = signer.state.lock().await;
        let cached = state.as_ref().unwrap_or_else(|| unreachable!());
        assert_eq!(
            cached.refresh_at,
            value
                .expires_in
                .map(|expires| expires - Duration::from_secs(300))
        );
    }
    #[tokio::test]
    async fn constructed_tke_never_falls_through_after_token_file_disappears() {
        let mut io = Fixture::new(vec![(403, Vec::new())]);
        io.files
            .insert("/fixture/token".into(), b"fake-token".to_vec());
        io.files.insert(
            "/fixture/credentials".into(),
            b"[default]\nsecret_id=profile-id\nsecret_key=profile-secret\n".to_vec(),
        );
        let envs: HashMap<String, String> = [
            ("TKE_REGION", "region"),
            ("TKE_PROVIDER_ID", "provider"),
            ("TKE_WEB_IDENTITY_TOKEN_FILE", "/fixture/token"),
            ("TKE_ROLE_ARN", "role"),
            ("TENCENTCLOUD_CREDENTIALS_FILE", "/fixture/credentials"),
        ]
        .map(|(key, value)| (key.into(), value.into()))
        .into_iter()
        .collect();
        let provider = GoDefaultProvider::default();
        assert!(
            provider
                .provide_credential(&io.context(envs.clone()))
                .await
                .is_err()
        );
        io.files.remove("/fixture/token");
        assert!(
            provider
                .provide_credential(&io.context(envs))
                .await
                .is_err()
        );
        assert_eq!(
            io.requests().len(),
            1,
            "file error stops before any new HTTP or profile fallback"
        );
    }
}
