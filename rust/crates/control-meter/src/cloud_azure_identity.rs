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

use crate::{Error, cloud_context::CloudIo};
use azure_core::credentials::{AccessToken, TokenCredential};
use azure_core::http::{ClientOptions, Transport};
use azure_identity::{
    AzureCliCredential, AzureDeveloperCliCredential, ClientSecretCredential,
    ClientSecretCredentialOptions,
};
use reqsign_core::{Context, HttpSend};
use std::sync::Arc;
use tokio::sync::Mutex;

const SCOPE: &str = "https://storage.azure.com/.default";
type CredentialSlot = (Arc<dyn TokenCredential>, bool);

pub(crate) struct AzureDefault {
    credentials: Vec<CredentialSlot>,
    selected: Mutex<Option<usize>>,
}

impl AzureDefault {
    pub(crate) async fn new(client: reqwest::Client, ctx: Context) -> Result<Self, Error> {
        let io = CloudIo(client);
        let executor = Arc::new(AzureExecutor(ctx.clone()));
        let transport = Arc::new(AzureHttp(io));
        let options = ClientOptions {
            transport: Some(Transport::new(transport)),
            ..Default::default()
        };
        let mode = credential_mode(&ctx)?;
        let selected = |kind: &str, development: bool| {
            mode.as_deref().is_none_or(|mode| {
                mode.eq_ignore_ascii_case(kind)
                    || (mode == "dev" && development)
                    || (mode == "prod" && !development)
            })
        };
        let mut credentials: Vec<CredentialSlot> = Vec::new();
        if selected("EnvironmentCredential", false)
            && let Some(credential) = environment(&ctx, options.clone()).await
        {
            credentials.push((credential, true));
        }
        if selected("WorkloadIdentityCredential", false)
            && let (Some(tenant), Some(client), Some(path)) = (
                ctx.env_var("AZURE_TENANT_ID"),
                ctx.env_var("AZURE_CLIENT_ID"),
                ctx.env_var("AZURE_FEDERATED_TOKEN_FILE"),
            )
            && !path.is_empty()
            && let Ok(credential) = azure_identity::ClientAssertionCredential::new(
                tenant,
                client,
                WorkloadAssertion {
                    context: ctx.clone(),
                    path,
                },
                Some(azure_identity::ClientAssertionCredentialOptions {
                    client_options: options.clone(),
                    ..Default::default()
                }),
            )
        {
            credentials.push((credential, true));
        }
        if selected("ManagedIdentityCredential", false)
            && let Ok(credential) = crate::cloud_azure_managed::Managed::new(ctx.clone()).await
        {
            credentials.push((Arc::new(credential), true));
        }
        if selected("AzureCLICredential", true)
            && let Ok(credential) =
                AzureCliCredential::new(Some(azure_identity::AzureCliCredentialOptions {
                    executor: Some(executor.clone()),
                    ..Default::default()
                }))
        {
            credentials.push((credential, false));
        }
        if selected("AzureDeveloperCLICredential", true)
            && let Ok(credential) = AzureDeveloperCliCredential::new(Some(
                azure_identity::AzureDeveloperCliCredentialOptions {
                    executor: Some(executor),
                    ..Default::default()
                },
            ))
        {
            credentials.push((credential, false));
        }
        if selected("AzurePowerShellCredential", true) {
            credentials.push((
                Arc::new(AuxiliaryCredential {
                    context: ctx,
                    source: AuxiliarySource::PowerShell,
                    cached: Mutex::new(None),
                }),
                false,
            ));
        }
        Ok(Self {
            credentials,
            selected: Mutex::new(None),
        })
    }

    pub(crate) async fn token(&self) -> Result<String, Error> {
        let mut selected = self.selected.lock().await;
        if let Some(index) = *selected {
            return token(self.credentials[index].0.get_token(&[SCOPE], None).await);
        }
        for (index, (credential, fatal)) in self.credentials.iter().enumerate() {
            match credential.get_token(&[SCOPE], None).await {
                Ok(value) => {
                    let token = token(Ok(value))?;
                    *selected = Some(index);
                    return Ok(token);
                }
                Err(error) if *fatal && !crate::cloud_azure_managed::unavailable(&error) => {
                    return Err(Error::Export(
                        "Azure configured identity authentication failed",
                    ));
                }
                Err(_) => (),
            }
        }
        Err(Error::Export("Azure default identity unavailable"))
    }
}

fn credential_mode(ctx: &Context) -> Result<Option<String>, Error> {
    let mode = ctx.env_var("AZURE_TOKEN_CREDENTIALS");
    if mode.as_deref().is_some_and(|mode| {
        ![
            "EnvironmentCredential",
            "WorkloadIdentityCredential",
            "ManagedIdentityCredential",
            "AzureCLICredential",
            "AzureDeveloperCLICredential",
            "AzurePowerShellCredential",
        ]
        .iter()
        .any(|name| mode.eq_ignore_ascii_case(name))
            && !matches!(mode, "dev" | "prod")
    }) {
        return Err(Error::Invalid("invalid AZURE_TOKEN_CREDENTIALS selection"));
    }
    Ok(mode)
}

async fn environment(ctx: &Context, options: ClientOptions) -> Option<Arc<dyn TokenCredential>> {
    let tenant = ctx.env_var("AZURE_TENANT_ID")?;
    let client = ctx.env_var("AZURE_CLIENT_ID")?;
    if let Some(secret) = ctx.env_var("AZURE_CLIENT_SECRET").filter(|v| !v.is_empty()) {
        return ClientSecretCredential::new(
            &tenant,
            client,
            secret.into(),
            Some(ClientSecretCredentialOptions {
                client_options: options,
            }),
        )
        .ok()
        .map(|v| v as Arc<dyn TokenCredential>);
    }
    if let Some(path) = ctx
        .env_var("AZURE_CLIENT_CERTIFICATE_PATH")
        .filter(|v| !v.is_empty())
    {
        return certificate(ctx, &tenant, client, &path, options).await.ok();
    }
    let username = ctx.env_var("AZURE_USERNAME").filter(|v| !v.is_empty())?;
    let password = ctx.env_var("AZURE_PASSWORD").filter(|v| !v.is_empty())?;
    AuxiliaryCredential::password(ctx.clone(), &tenant, client, username, password)
        .ok()
        .map(|v| Arc::new(v) as Arc<dyn TokenCredential>)
}

fn token(result: azure_core::Result<AccessToken>) -> Result<String, Error> {
    let value = result.map_err(|_| Error::Export("Azure identity authentication failed"))?;
    if value.expires_on <= azure_core::time::OffsetDateTime::now_utc()
        || value.token.secret().is_empty()
    {
        return Err(Error::Export("Azure identity token expired or empty"));
    }
    Ok(value.token.secret().to_owned())
}

#[derive(Debug)]
struct AzureHttp(CloudIo);

#[async_trait::async_trait]
impl azure_core::http::HttpClient for AzureHttp {
    async fn execute_request(
        &self,
        request: &azure_core::http::Request,
    ) -> azure_core::Result<azure_core::http::BufResponse> {
        let error = || {
            azure_core::Error::with_message(
                azure_core::error::ErrorKind::Io,
                "Azure credential I/O failed",
            )
        };
        let mut req = http::Request::builder()
            .method(request.method().as_str())
            .uri(request.url().as_str());
        for (name, value) in request.headers().iter() {
            req = req.header(name.as_str(), value.as_str());
        }
        let azure_core::http::Body::Bytes(body) = request.body() else {
            return Err(error());
        };
        let response = self
            .0
            .http_send(req.body(body.clone()).map_err(|_| error())?)
            .await
            .map_err(|_| error())?;
        let (parts, body) = response.into_parts();
        let mut headers = azure_core::http::headers::Headers::new();
        for (name, value) in &parts.headers {
            if let Ok(value) = value.to_str() {
                headers.insert(name.as_str().to_owned(), value.to_owned());
            }
        }
        Ok(azure_core::http::BufResponse::from_bytes(
            parts.status.as_u16().into(),
            headers,
            body,
        ))
    }
}

fn identity_error() -> azure_core::Error {
    azure_core::Error::with_message(
        azure_core::error::ErrorKind::Credential,
        "Azure credential unavailable",
    )
}

struct AzureExecutor(Context);
impl std::fmt::Debug for AzureExecutor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AzureExecutor")
    }
}
#[async_trait::async_trait]
impl azure_identity::Executor for AzureExecutor {
    async fn run(
        &self,
        program: &std::ffi::OsStr,
        args: &[&std::ffi::OsStr],
    ) -> std::io::Result<std::process::Output> {
        use std::os::unix::process::ExitStatusExt as _;
        let invalid = || std::io::Error::other("Azure credential command failed");
        let program = program.to_str().ok_or_else(invalid)?;
        let args: Vec<&str> = args
            .iter()
            .map(|value| value.to_str().ok_or_else(invalid))
            .collect::<Result<_, _>>()?;
        let result = self
            .0
            .command_execute(program, &args)
            .await
            .map_err(|_| invalid())?;
        let code = if result.status < 0 { 1 } else { result.status };
        Ok(std::process::Output {
            status: std::process::ExitStatus::from_raw(code << 8),
            stdout: result.stdout,
            stderr: result.stderr,
        })
    }
}

struct WorkloadAssertion {
    context: Context,
    path: String,
}
impl std::fmt::Debug for WorkloadAssertion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AzureWorkloadAssertion")
    }
}
#[async_trait::async_trait]
impl azure_identity::ClientAssertion for WorkloadAssertion {
    async fn secret(
        &self,
        _options: Option<azure_core::http::ClientMethodOptions<'_>>,
    ) -> azure_core::Result<String> {
        let bytes = self
            .context
            .file_read(&self.path)
            .await
            .map_err(|_| identity_error())?;
        let text = String::from_utf8(bytes).map_err(|_| identity_error())?;
        if text.is_empty() {
            return Err(identity_error());
        }
        Ok(text)
    }
}

async fn certificate(
    ctx: &Context,
    tenant: &str,
    client: String,
    path: &str,
    options: ClientOptions,
) -> azure_core::Result<Arc<dyn TokenCredential>> {
    use azure_identity::{ClientCertificateCredential, ClientCertificateCredentialOptions};
    let bytes = ctx.file_read(path).await.map_err(|_| identity_error())?;
    let password = ctx
        .env_var("AZURE_CLIENT_CERTIFICATE_PASSWORD")
        .unwrap_or_default();
    let pass = password.clone();
    let der = tokio::task::spawn_blocking(move || -> Result<Vec<u8>, ()> {
        if bytes.windows(11).any(|part| part == b"-----BEGIN ") {
            let mut certs = openssl::x509::X509::stack_from_pem(&bytes).map_err(|_| ())?;
            if certs.is_empty() {
                return Err(());
            }
            let leaf = certs.remove(0);
            let key = openssl::pkey::PKey::private_key_from_pem_passphrase(&bytes, pass.as_bytes())
                .map_err(|_| ())?;
            if key.id() != openssl::pkey::Id::RSA
                || !leaf.public_key().map_err(|_| ())?.public_eq(&key)
            {
                return Err(());
            }
            let mut builder = openssl::pkcs12::Pkcs12::builder();
            builder.name("metering").pkey(&key).cert(&leaf);
            let mut ca = openssl::stack::Stack::new().map_err(|_| ())?;
            for cert in certs {
                ca.push(cert).map_err(|_| ())?;
            }
            builder.ca(ca);
            builder
                .build2(&pass)
                .and_then(|pfx| pfx.to_der())
                .map_err(|_| ())
        } else {
            let parsed = openssl::pkcs12::Pkcs12::from_der(&bytes)
                .and_then(|pfx| pfx.parse2(&pass))
                .map_err(|_| ())?;
            let key = parsed.pkey.ok_or(())?;
            let cert = parsed.cert.ok_or(())?;
            if key.id() != openssl::pkey::Id::RSA
                || !cert.public_key().map_err(|_| ())?.public_eq(&key)
            {
                return Err(());
            }
            Ok(bytes)
        }
    })
    .await
    .map_err(|_| identity_error())?
    .map_err(|()| identity_error())?;
    let send = ctx
        .env_var("AZURE_CLIENT_SEND_CERTIFICATE_CHAIN")
        .is_some_and(|v| v == "1" || v.eq_ignore_ascii_case("true"));
    ClientCertificateCredential::new(
        tenant.to_owned(),
        client,
        reqsign_core::hash::base64_encode(&der),
        password,
        Some(ClientCertificateCredentialOptions {
            client_options: options,
            send_certificate_chain: send,
        }),
    )
    .map(|credential| credential as Arc<dyn TokenCredential>)
}

enum AuxiliarySource {
    Password {
        endpoint: reqwest::Url,
        client: String,
        username: String,
        password: String,
    },
    PowerShell,
}
struct AuxiliaryCredential {
    context: Context,
    source: AuxiliarySource,
    cached: Mutex<Option<AccessToken>>,
}
impl std::fmt::Debug for AuxiliaryCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AzureAuxiliaryCredential")
    }
}
impl AuxiliaryCredential {
    fn password(
        context: Context,
        tenant: &str,
        client: String,
        username: String,
        password: String,
    ) -> azure_core::Result<Self> {
        if tenant.is_empty()
            || !tenant
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.'))
        {
            return Err(identity_error());
        }
        let authority = context
            .env_var("AZURE_AUTHORITY_HOST")
            .unwrap_or_else(|| "https://login.microsoftonline.com".into());
        let mut endpoint = reqwest::Url::parse(&authority).map_err(|_| identity_error())?;
        if endpoint.scheme() != "https"
            || endpoint.host_str().is_none()
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
        {
            return Err(identity_error());
        }
        endpoint.set_path(&format!("/{tenant}/oauth2/v2.0/token"));
        Ok(Self {
            context,
            source: AuxiliarySource::Password {
                endpoint,
                client,
                username,
                password,
            },
            cached: Mutex::new(None),
        })
    }
    async fn acquire(&self) -> azure_core::Result<AccessToken> {
        let now = azure_core::time::OffsetDateTime::now_utc();
        let (body, powershell) = match &self.source {
            AuxiliarySource::Password {
                endpoint,
                client,
                username,
                password,
            } => {
                let mut form =
                    reqwest::Url::parse("https://form.invalid").map_err(|_| identity_error())?;
                form.query_pairs_mut().extend_pairs([
                    ("grant_type", "password"),
                    ("client_id", client),
                    ("username", username),
                    ("password", password),
                    ("scope", SCOPE),
                ]);
                let body = bytes::Bytes::from(form.query().ok_or_else(identity_error)?.to_owned());
                let request = http::Request::post(endpoint.as_str())
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(body)
                    .map_err(|_| identity_error())?;
                let response = self
                    .context
                    .http_send(request)
                    .await
                    .map_err(|_| identity_error())?;
                if !response.status().is_success() {
                    return Err(identity_error());
                }
                (response.into_body().to_vec(), false)
            }
            AuxiliarySource::PowerShell => {
                let script = "$ErrorActionPreference='Stop'; Import-Module Az.Accounts; $t=Get-AzAccessToken -ResourceUrl 'https://storage.azure.com'; if ($t.Token -is [System.Security.SecureString]) { $p=[System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($t.Token); try { $v=[System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($p) } finally { [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($p) } } else { $v=$t.Token }; @{Token=$v;ExpiresOn=$t.ExpiresOn.ToUnixTimeSeconds()} | ConvertTo-Json";
                let utf16: Vec<u8> = script.encode_utf16().flat_map(u16::to_le_bytes).collect();
                let encoded = reqsign_core::hash::base64_encode(&utf16);
                let output = self
                    .context
                    .command_execute(
                        "pwsh",
                        &[
                            "-NoProfile",
                            "-NonInteractive",
                            "-OutputFormat",
                            "Text",
                            "-EncodedCommand",
                            &encoded,
                        ],
                    )
                    .await
                    .map_err(|_| identity_error())?;
                if !output.success() {
                    return Err(identity_error());
                }
                (output.stdout, true)
            }
        };
        let value: serde_json::Value =
            serde_json::from_slice(&body).map_err(|_| identity_error())?;
        let token = value[if powershell { "Token" } else { "access_token" }]
            .as_str()
            .filter(|value| !value.is_empty())
            .ok_or_else(identity_error)?;
        let expires = if powershell {
            azure_core::time::OffsetDateTime::from_unix_timestamp(
                value["ExpiresOn"].as_i64().ok_or_else(identity_error)?,
            )
            .map_err(|_| identity_error())?
        } else {
            now.checked_add(azure_core::time::Duration::seconds(
                value["expires_in"].as_i64().ok_or_else(identity_error)?,
            ))
            .ok_or_else(identity_error)?
        };
        if expires <= now {
            return Err(identity_error());
        }
        Ok(AccessToken::new(token.to_owned(), expires))
    }
}
#[async_trait::async_trait]
impl TokenCredential for AuxiliaryCredential {
    async fn get_token(
        &self,
        scopes: &[&str],
        _options: Option<azure_core::credentials::TokenRequestOptions<'_>>,
    ) -> azure_core::Result<AccessToken> {
        if scopes != [SCOPE] {
            return Err(identity_error());
        }
        let mut cached = self.cached.lock().await;
        let refresh =
            azure_core::time::OffsetDateTime::now_utc() + azure_core::time::Duration::seconds(300);
        if let Some(token) = cached.as_ref()
            && token.expires_on > refresh
        {
            return Ok(token.clone());
        }
        let token = self.acquire().await?;
        *cached = Some(token.clone());
        Ok(token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    #[derive(Debug)]
    struct Credential {
        calls: AtomicUsize,
        fail: AtomicBool,
    }
    #[async_trait::async_trait]
    impl TokenCredential for Credential {
        async fn get_token(
            &self,
            scopes: &[&str],
            _options: Option<azure_core::credentials::TokenRequestOptions<'_>>,
        ) -> azure_core::Result<AccessToken> {
            assert_eq!(scopes, [SCOPE]);
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.fail.load(Ordering::SeqCst) {
                return Err(identity_error());
            }
            Ok(AccessToken::new(
                "test-token",
                azure_core::time::OffsetDateTime::now_utc() + azure_core::time::Duration::hours(1),
            ))
        }
    }
    fn credential(fail: bool) -> Arc<Credential> {
        Arc::new(Credential {
            calls: AtomicUsize::new(0),
            fail: AtomicBool::new(fail),
        })
    }
    #[tokio::test]
    async fn default_chain_sticks_to_first_success_and_configured_failures_stop() {
        let unavailable = credential(true);
        let first = credential(false);
        let later = credential(false);
        let chain = AzureDefault {
            credentials: vec![
                (unavailable.clone(), false),
                (first.clone(), false),
                (later.clone(), false),
            ],
            selected: Mutex::new(None),
        };
        assert_eq!(
            chain.token().await.unwrap_or_else(|e| unreachable!("{e}")),
            "test-token"
        );
        first.fail.store(true, Ordering::SeqCst);
        assert!(chain.token().await.is_err());
        assert_eq!(unavailable.calls.load(Ordering::SeqCst), 1);
        assert_eq!(later.calls.load(Ordering::SeqCst), 0);
        let chain = AzureDefault {
            credentials: vec![(unavailable.clone(), true), (later.clone(), false)],
            selected: Mutex::new(None),
        };
        assert!(chain.token().await.is_err());
        assert_eq!(later.calls.load(Ordering::SeqCst), 0);
    }

    #[derive(Debug)]
    struct ManagedReply(u16);
    impl HttpSend for ManagedReply {
        async fn http_send(
            &self,
            _request: http::Request<bytes::Bytes>,
        ) -> reqsign_core::Result<http::Response<bytes::Bytes>> {
            http::Response::builder()
                .status(self.0)
                .body(bytes::Bytes::from_static(b"denied"))
                .map_err(|_| reqsign_core::Error::unexpected("test response"))
        }
    }
    #[tokio::test]
    async fn managed_chain_falls_through_only_for_unavailable_identity() {
        for (user, app_service, fallback) in [
            (false, false, true),
            (true, false, false),
            (false, true, false),
        ] {
            let mut envs = std::collections::HashMap::from([(
                "AZURE_TOKEN_CREDENTIALS".into(),
                "ManagedIdentityCredential".into(),
            )]);
            if user {
                envs.insert("AZURE_CLIENT_ID".into(), "client".into());
            }
            if app_service {
                envs.insert(
                    "IDENTITY_ENDPOINT".into(),
                    "http://identity.test/token".into(),
                );
                envs.insert("IDENTITY_HEADER".into(), "fake-secret".into());
            }
            let ctx = Context::new()
                .with_env(reqsign_core::StaticEnv {
                    envs,
                    ..Default::default()
                })
                .with_http_send(ManagedReply(400));
            let managed = crate::cloud_azure_managed::Managed::new(ctx)
                .await
                .unwrap_or_else(|e| unreachable!("{e}"));
            let later = credential(false);
            let chain = AzureDefault {
                credentials: vec![(Arc::new(managed), true), (later.clone(), false)],
                selected: Mutex::new(None),
            };
            assert_eq!(chain.token().await.is_ok(), fallback);
            assert_eq!(later.calls.load(Ordering::SeqCst), usize::from(fallback));
        }
    }

    #[derive(Debug, Clone)]
    struct Shell(Arc<AtomicUsize>);
    impl reqsign_core::CommandExecute for Shell {
        async fn command_execute(
            &self,
            program: &str,
            args: &[&str],
        ) -> reqsign_core::Result<reqsign_core::CommandOutput> {
            assert_eq!(program, "pwsh");
            assert_eq!(args[4], "-EncodedCommand");
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(reqsign_core::CommandOutput {
                status: 0,
                stderr: Vec::new(),
                stdout: br#"{"Token":"powershell-test-token","ExpiresOn":4070908800}"#.to_vec(),
            })
        }
    }
    #[tokio::test]
    async fn powershell_mode_uses_bounded_executor_and_caches() {
        let shell = Shell(Arc::new(AtomicUsize::new(0)));
        let ctx = Context::new()
            .with_env(reqsign_core::StaticEnv {
                envs: std::collections::HashMap::from([(
                    "AZURE_TOKEN_CREDENTIALS".into(),
                    "AzurePowerShellCredential".into(),
                )]),
                ..Default::default()
            })
            .with_command_execute(shell.clone());
        let chain = AzureDefault::new(reqwest::Client::new(), ctx)
            .await
            .unwrap_or_else(|e| unreachable!("{e}"));
        for _ in 0..2 {
            assert_eq!(
                chain.token().await.unwrap_or_else(|e| unreachable!("{e}")),
                "powershell-test-token"
            );
        }
        assert_eq!(shell.0.load(Ordering::SeqCst), 1);
    }
    #[derive(Clone, Debug)]
    struct CertificateFile(Vec<u8>);
    impl reqsign_core::FileRead for CertificateFile {
        async fn file_read(&self, _path: &str) -> reqsign_core::Result<Vec<u8>> {
            Ok(self.0.clone())
        }
    }
    #[tokio::test]
    async fn certificate_environment_accepts_pem_and_pfx_and_rejects_wrong_password() {
        let key = openssl::pkey::PKey::from_rsa(
            openssl::rsa::Rsa::generate(2048).unwrap_or_else(|e| unreachable!("{e}")),
        )
        .unwrap_or_else(|e| unreachable!("{e}"));
        let mut name = openssl::x509::X509Name::builder().unwrap_or_else(|e| unreachable!("{e}"));
        name.append_entry_by_text("CN", "metering-test")
            .unwrap_or_else(|e| unreachable!("{e}"));
        let name = name.build();
        let mut cert = openssl::x509::X509::builder().unwrap_or_else(|e| unreachable!("{e}"));
        cert.set_version(2).unwrap_or_else(|e| unreachable!("{e}"));
        cert.set_subject_name(&name)
            .unwrap_or_else(|e| unreachable!("{e}"));
        cert.set_issuer_name(&name)
            .unwrap_or_else(|e| unreachable!("{e}"));
        cert.set_pubkey(&key)
            .unwrap_or_else(|e| unreachable!("{e}"));
        cert.set_not_before(
            &openssl::asn1::Asn1Time::days_from_now(0).unwrap_or_else(|e| unreachable!("{e}")),
        )
        .unwrap_or_else(|e| unreachable!("{e}"));
        cert.set_not_after(
            &openssl::asn1::Asn1Time::days_from_now(1).unwrap_or_else(|e| unreachable!("{e}")),
        )
        .unwrap_or_else(|e| unreachable!("{e}"));
        cert.sign(&key, openssl::hash::MessageDigest::sha256())
            .unwrap_or_else(|e| unreachable!("{e}"));
        let cert = cert.build();
        let password = "fixture-password";
        let mut pem = b" \n".to_vec();
        pem.extend(cert.to_pem().unwrap_or_else(|e| unreachable!("{e}")));
        pem.extend(
            key.private_key_to_pem_pkcs8_passphrase(
                openssl::symm::Cipher::aes_256_cbc(),
                password.as_bytes(),
            )
            .unwrap_or_else(|e| unreachable!("{e}")),
        );
        let pfx = openssl::pkcs12::Pkcs12::builder()
            .pkey(&key)
            .cert(&cert)
            .build2(password)
            .and_then(|pfx| pfx.to_der())
            .unwrap_or_else(|e| unreachable!("{e}"));
        for file in [pem, pfx] {
            for (pass, valid) in [(password, true), ("wrong", false)] {
                let ctx = Context::new()
                    .with_env(reqsign_core::StaticEnv {
                        envs: std::collections::HashMap::from([(
                            "AZURE_CLIENT_CERTIFICATE_PASSWORD".into(),
                            pass.into(),
                        )]),
                        ..Default::default()
                    })
                    .with_file_read(CertificateFile(file.clone()));
                assert_eq!(
                    certificate(
                        &ctx,
                        "tenant",
                        "client".into(),
                        "fixture",
                        ClientOptions::default()
                    )
                    .await
                    .is_ok(),
                    valid
                );
            }
        }
    }
}
