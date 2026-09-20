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

//! Default identity selection from the pinned credentials-go providers.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Write};
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use bytes::Bytes;
use http::Request;
use reqsign_aliyun_oss::Credential;
use reqsign_core::hash::base64_hmac_sha1;
use reqsign_core::time::Timestamp;
use reqsign_core::{Context, ProvideCredential};
use serde::Deserialize;
use tokio::sync::Mutex;

use crate::cloud_oss::percent;

type Result<T> = reqsign_core::Result<T>;
type CredentialFuture<'a> = Pin<Box<dyn Future<Output = Result<Credential>> + Send + 'a>>;
const METADATA: &str = "http://100.100.100.200";
const REFRESH: Duration = Duration::from_secs(180);

#[derive(Default)]
pub(crate) struct GoDefaultProvider {
    state: Mutex<Option<Chain>>,
}
impl fmt::Debug for GoDefaultProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GoDefaultProvider").finish_non_exhaustive()
    }
}
struct Chain {
    sources: Vec<Node>,
    selected: Option<usize>,
}
impl Chain {
    fn new(ctx: &Context) -> Self {
        let mut sources = vec![Node::new("env", Kind::Environment)];
        if let Ok(node) = Profile::default().oidc(ctx) {
            sources.push(node);
        }
        if !enabled(ctx, "ALIBABA_CLOUD_CLI_PROFILE_DISABLED") {
            sources.push(Node::new(
                "cli_profile",
                Kind::Profile {
                    cli: true,
                    inner: None,
                },
            ));
        }
        sources.push(Node::new(
            "profile",
            Kind::Profile {
                cli: false,
                inner: None,
            },
        ));
        if let Ok(node) = ecs(ctx, "") {
            sources.push(node);
        }
        if let Some(uri) = env(ctx, "ALIBABA_CLOUD_CREDENTIALS_URI") {
            sources.push(Node::new("credential_uri", Kind::Uri(uri)));
        }
        Self {
            sources,
            selected: None,
        }
    }
}
impl ProvideCredential for GoDefaultProvider {
    type Credential = Credential;
    async fn provide_credential(&self, ctx: &Context) -> Result<Option<Credential>> {
        let mut state = self.state.lock().await;
        let chain = state.get_or_insert_with(|| Chain::new(ctx));
        if let Some(selected) = chain.selected {
            return chain.sources[selected].credential(ctx).await.map(Some);
        }
        // Go remembers each attempted provider BEFORE calling it. Initial
        // errors permit fallback; after success (or exhausting the chain),
        // subsequent requests retry only the remembered provider.
        for index in 0..chain.sources.len() {
            chain.selected = Some(index);
            if let Ok(value) = chain.sources[index].credential(ctx).await {
                return Ok(Some(value));
            }
        }
        Err(failed())
    }
}

struct Node {
    name: String,
    kind: Kind,
    cache: Option<Credential>,
}
enum Kind {
    Environment,
    Static(Credential),
    Profile {
        cli: bool,
        inner: Option<Box<Node>>,
    },
    Oidc {
        request: Role,
        provider: String,
        file: String,
    },
    Role {
        request: Role,
        source: Box<Node>,
    },
    Ecs {
        role: String,
        disable_v1: bool,
    },
    Uri(String),
    Sso {
        endpoint: String,
        token: String,
        account: String,
        config: String,
    },
}
struct Role {
    arn: String,
    session: String,
    duration: i64,
    policy: String,
    external: String,
    endpoint: String,
}
impl Node {
    fn new(name: &str, kind: Kind) -> Self {
        Self {
            name: name.to_owned(),
            kind,
            cache: None,
        }
    }
    fn credential<'a>(&'a mut self, ctx: &'a Context) -> CredentialFuture<'a> {
        Box::pin(async move {
            if let Some(value) = &self.cache
                && value
                    .expires_in
                    .is_some_and(|expiry| expiry > Timestamp::now() + REFRESH)
            {
                return Ok(value.clone());
            }
            let value = match &mut self.kind {
                Kind::Environment => static_keys(
                    &env(ctx, "ALIBABA_CLOUD_ACCESS_KEY_ID").ok_or_else(failed)?,
                    &env(ctx, "ALIBABA_CLOUD_ACCESS_KEY_SECRET").ok_or_else(failed)?,
                    env(ctx, "ALIBABA_CLOUD_SECURITY_TOKEN"),
                )?,
                Kind::Static(value) => value.clone(),
                Kind::Profile { cli, inner } => {
                    if inner.is_none() {
                        *inner = Some(Box::new(if *cli {
                            cli_profile(ctx).await?
                        } else {
                            ini_profile(ctx).await?
                        }));
                    }
                    let inner = inner.as_mut().ok_or_else(failed)?;
                    let value = inner.credential(ctx).await?;
                    self.name = format!(
                        "{}/{}",
                        if *cli { "cli_profile" } else { "profile" },
                        inner.name
                    );
                    return Ok(value);
                }
                Kind::Oidc {
                    request,
                    provider,
                    file,
                } => {
                    let token = ctx.file_read_as_string(file).await.map_err(|_| failed())?;
                    let body = BTreeMap::from([
                        ("OIDCProviderArn".to_owned(), provider.clone()),
                        ("OIDCToken".to_owned(), token),
                    ]);
                    sts(ctx, request, None, body).await?
                }
                Kind::Role { request, source } => {
                    let base = source.credential(ctx).await?;
                    let value =
                        sts(ctx, request, Some((&base, &source.name)), BTreeMap::new()).await?;
                    self.name = format!("ram_role_arn/{}", source.name);
                    value
                }
                Kind::Ecs { role, disable_v1 } => ecs_credential(ctx, role, *disable_v1).await?,
                Kind::Uri(uri) => {
                    let value =
                        send_json(ctx, Request::get(uri.as_str()).body(Bytes::new())?).await?;
                    decode_credential(&value)?
                }
                Kind::Sso {
                    endpoint,
                    token,
                    account,
                    config,
                } => {
                    // Keep Go's struct field order for the JSON request body.
                    #[derive(serde::Serialize)]
                    #[serde(rename_all = "PascalCase")]
                    struct Body<'b> {
                        account_id: &'b str,
                        access_configuration_id: &'b str,
                    }
                    let body = serde_json::to_vec(&Body {
                        account_id: account,
                        access_configuration_id: config,
                    })
                    .map_err(|_| failed())?;
                    let value = send_json(
                        ctx,
                        Request::post(endpoint.as_str())
                            .header("accept", "application/json")
                            .header("content-type", "application/json")
                            .header("authorization", format!("Bearer {token}"))
                            .body(Bytes::from(body))?,
                    )
                    .await?;
                    let value = decode_credential(&value["CloudCredential"])?;
                    if value.access_key_id.is_empty()
                        || value.access_key_secret.is_empty()
                        || value.security_token.as_ref().is_none_or(String::is_empty)
                    {
                        return Err(failed());
                    }
                    value
                }
            };
            if value.expires_in.is_some() {
                self.cache = Some(value.clone());
            }
            Ok(value)
        })
    }
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct Profile {
    name: String,
    mode: String,
    access_key_id: String,
    access_key_secret: String,
    sts_token: String,
    ram_role_arn: String,
    ram_session_name: String,
    expired_seconds: i64,
    sts_region: String,
    enable_vpc: bool,
    #[serde(rename = "source_profile")]
    source: String,
    ram_role_name: String,
    oidc_token_file: String,
    oidc_provider_arn: String,
    policy: String,
    external_id: String,
    cloud_sso_sign_in_url: String,
    cloud_sso_account_id: String,
    cloud_sso_access_config: String,
    access_token: String,
    cloud_sso_access_token_expire: i64,
}
impl Profile {
    fn role(&self, ctx: &Context, oidc: bool) -> Result<Role> {
        let arn = supplied(&self.ram_role_arn, ctx, "ALIBABA_CLOUD_ROLE_ARN").ok_or_else(failed)?;
        let session = if !self.ram_session_name.is_empty() {
            self.ram_session_name.clone()
        } else if !oidc && let Some(name) = env(ctx, "ALIBABA_CLOUD_ROLE_SESSION_NAME") {
            name
        } else {
            let now = Timestamp::now();
            format!(
                "credentials-go-{}{:06}",
                now.as_second(),
                now.subsec_nanosecond() / 1000
            )
        };
        let duration = if self.expired_seconds == 0 {
            3600
        } else {
            self.expired_seconds
        };
        if duration < 900 {
            return Err(failed());
        }
        let region = supplied(&self.sts_region, ctx, "ALIBABA_CLOUD_STS_REGION");
        let vpc = self.enable_vpc || enabled(ctx, "ALIBABA_CLOUD_VPC_ENDPOINT_ENABLED");
        let endpoint = region.map_or_else(
            || "sts.aliyuncs.com".to_owned(),
            |region| {
                format!(
                    "{}.{region}.aliyuncs.com",
                    if vpc { "sts-vpc" } else { "sts" }
                )
            },
        );
        Ok(Role {
            arn,
            session,
            duration,
            policy: self.policy.clone(),
            external: self.external_id.clone(),
            endpoint,
        })
    }
    fn oidc(&self, ctx: &Context) -> Result<Node> {
        let file = supplied(&self.oidc_token_file, ctx, "ALIBABA_CLOUD_OIDC_TOKEN_FILE")
            .ok_or_else(failed)?;
        let provider = supplied(
            &self.oidc_provider_arn,
            ctx,
            "ALIBABA_CLOUD_OIDC_PROVIDER_ARN",
        )
        .ok_or_else(failed)?;
        Ok(Node::new(
            "oidc_role_arn",
            Kind::Oidc {
                request: self.role(ctx, true)?,
                provider,
                file,
            },
        ))
    }
    fn static_keys(&self, ctx: &Context, token: bool) -> Result<Node> {
        if token && supplied(&self.sts_token, ctx, "ALIBABA_CLOUD_SECURITY_TOKEN").is_none() {
            return Err(failed());
        }
        Ok(Node::new(
            if token { "static_sts" } else { "static_ak" },
            Kind::Static(static_keys(
                &supplied(&self.access_key_id, ctx, "ALIBABA_CLOUD_ACCESS_KEY_ID")
                    .ok_or_else(failed)?,
                &supplied(
                    &self.access_key_secret,
                    ctx,
                    "ALIBABA_CLOUD_ACCESS_KEY_SECRET",
                )
                .ok_or_else(failed)?,
                token
                    .then(|| supplied(&self.sts_token, ctx, "ALIBABA_CLOUD_SECURITY_TOKEN"))
                    .flatten(),
            )?),
        ))
    }
}

async fn cli_profile(ctx: &Context) -> Result<Node> {
    #[derive(Deserialize)]
    #[serde(default)]
    #[derive(Default)]
    struct Configuration {
        current: String,
        profiles: Vec<Profile>,
    }
    let file = config_path(ctx, "ALIBABA_CLOUD_CONFIG_FILE", ".aliyun/config.json")?;
    let data = ctx.file_read(&file).await.map_err(|_| failed())?;
    let config: Configuration = serde_json::from_slice(&data).map_err(|_| failed())?;
    let name = env(ctx, "ALIBABA_CLOUD_PROFILE").unwrap_or(config.current);
    cli_node(ctx, &config.profiles, &name, &mut BTreeSet::new())
}
fn cli_node(
    ctx: &Context,
    profiles: &[Profile],
    name: &str,
    seen: &mut BTreeSet<String>,
) -> Result<Node> {
    if !seen.insert(name.to_owned()) {
        return Err(failed());
    }
    let p = profiles
        .iter()
        .find(|p| p.name == name)
        .ok_or_else(failed)?;
    match p.mode.as_str() {
        "AK" => p.static_keys(ctx, false),
        "StsToken" => p.static_keys(ctx, true),
        "OIDC" => p.oidc(ctx),
        "EcsRamRole" => ecs(ctx, &p.ram_role_name),
        "RamRoleArn" | "ChainableRamRoleArn" => {
            let source = if p.mode == "RamRoleArn" {
                p.static_keys(ctx, false)?
            } else {
                cli_node(ctx, profiles, &p.source, seen)?
            };
            Ok(Node::new(
                "ram_role_arn",
                Kind::Role {
                    request: p.role(ctx, false)?,
                    source: Box::new(source),
                },
            ))
        }
        "CloudSSO" => {
            if p.access_token.is_empty()
                || p.cloud_sso_access_token_expire <= Timestamp::now().as_second()
                || p.cloud_sso_account_id.is_empty()
                || p.cloud_sso_access_config.is_empty()
            {
                return Err(failed());
            }
            let uri: http::Uri = p.cloud_sso_sign_in_url.parse().map_err(|_| failed())?;
            let scheme = uri
                .scheme_str()
                .filter(|s| matches!(*s, "http" | "https"))
                .ok_or_else(failed)?;
            let host = uri.authority().ok_or_else(failed)?;
            Ok(Node::new(
                "cloud_sso",
                Kind::Sso {
                    endpoint: format!("{scheme}://{host}/cloud-credentials?"),
                    token: p.access_token.clone(),
                    account: p.cloud_sso_account_id.clone(),
                    config: p.cloud_sso_access_config.clone(),
                },
            ))
        }
        _ => Err(failed()),
    }
}
async fn ini_profile(ctx: &Context) -> Result<Node> {
    let file = config_path(
        ctx,
        "ALIBABA_CLOUD_CREDENTIALS_FILE",
        ".alibabacloud/credentials",
    )?;
    let data = ctx.file_read_as_string(&file).await.map_err(|_| failed())?;
    let ini = GoIni::parse(&data)?;
    let profile = env(ctx, "ALIBABA_CLOUD_PROFILE").unwrap_or_else(|| "default".to_owned());
    if !ini.0.contains_key(&profile) {
        return Err(failed());
    }
    let get = |key| ini.value(&profile, key).ok_or_else(failed);
    match get("type")?.as_str() {
        "access_key" => Ok(Node::new(
            "static_ak",
            Kind::Static(static_keys(
                &get("access_key_id")?,
                &get("access_key_secret")?,
                None,
            )?),
        )),
        "ecs_ram_role" => ecs(ctx, &get("role_name")?),
        "ram_role_arn" => {
            let p = Profile {
                access_key_id: get("access_key_id")?,
                access_key_secret: get("access_key_secret")?,
                ram_role_arn: get("role_arn")?,
                ram_session_name: get("role_session_name")?,
                policy: ini.value(&profile, "policy").unwrap_or_default(),
                ..Profile::default()
            };
            if p.access_key_id.is_empty()
                || p.access_key_secret.is_empty()
                || p.ram_role_arn.is_empty()
                || p.ram_session_name.is_empty()
            {
                return Err(failed());
            }
            Ok(Node::new(
                "ram_role_arn",
                Kind::Role {
                    request: p.role(ctx, false)?,
                    source: Box::new(p.static_keys(ctx, false)?),
                },
            ))
        }
        _ => Err(failed()),
    }
}
// gopkg.in/ini.v1 defaults: comment stripping precedes surrounding-quote
// removal, backslashes are literal except line continuations, and backtick /
// triple-double-quoted values can span lines. rust-ini's escaping differs.
struct GoIni(BTreeMap<String, BTreeMap<String, String>>);
impl GoIni {
    fn parse(data: &str) -> Result<Self> {
        let mut sections = BTreeMap::<String, BTreeMap<String, String>>::new();
        let mut section = "DEFAULT".to_owned();
        sections.entry(section.clone()).or_default();
        let mut lines = data.trim_start_matches('\u{feff}').split_inclusive('\n');
        while let Some(raw) = lines.next() {
            let line = raw.trim_start();
            if line.trim().is_empty() || line.starts_with(['#', ';']) {
                continue;
            }
            if line.starts_with('[') {
                let close = line.rfind(']').ok_or_else(failed)?;
                line[1..close].clone_into(&mut section);
                if section.is_empty() {
                    "DEFAULT".clone_into(&mut section);
                }
                sections.entry(section.clone()).or_default();
                continue;
            }
            let split = line.find(['=', ':']).ok_or_else(failed)?;
            let key = line[..split].trim();
            if key.is_empty() {
                return Err(failed());
            }
            let value = line[split + 1..].trim_start();
            let quote = if value.starts_with("\"\"\"") {
                Some("\"\"\"")
            } else if value.starts_with('`') {
                Some("`")
            } else {
                None
            };
            let value = if let Some(quote) = quote {
                let mut value = value[quote.len()..].to_owned();
                loop {
                    if let Some(close) = value.rfind(quote) {
                        value.truncate(close);
                        break;
                    }
                    value.push_str(lines.next().ok_or_else(failed)?);
                }
                value
            } else {
                let mut value = value.trim().to_owned();
                if value.ends_with('\\') {
                    value.pop();
                    for next in lines.by_ref() {
                        let next = next.trim();
                        if next.is_empty() {
                            break;
                        }
                        value.push_str(next);
                        if !value.ends_with('\\') {
                            break;
                        }
                        value.pop();
                    }
                } else {
                    if let Some(end) = value.find(['#', ';']) {
                        value.truncate(end);
                    }
                    value = value.trim().to_owned();
                    for quote in ['\'', '"'] {
                        if value.len() >= 2
                            && value.starts_with(quote)
                            && value.ends_with(quote)
                            && !value[1..value.len() - 1].contains(quote)
                        {
                            value = value[1..value.len() - 1].to_owned();
                            break;
                        }
                    }
                }
                value
            };
            sections
                .entry(section.clone())
                .or_default()
                .insert(key.to_owned(), value);
        }
        Ok(Self(sections))
    }
    fn raw(&self, section: &str, key: &str) -> Option<&str> {
        let mut section = section;
        loop {
            if let Some(value) = self.0.get(section).and_then(|s| s.get(key)) {
                return Some(value);
            }
            section = section.rsplit_once('.')?.0;
        }
    }
    fn value(&self, section: &str, key: &str) -> Option<String> {
        let mut value = self.raw(section, key)?.to_owned();
        for _ in 0..99 {
            let Some(start) = value.find("%(") else {
                break;
            };
            let Some(end) = value[start + 2..].find(")s").map(|n| start + 2 + n) else {
                break;
            };
            let name = &value[start + 2..end];
            let replacement = if name == key {
                None
            } else {
                self.raw(section, name)
            }
            .or_else(|| self.raw("DEFAULT", name));
            let Some(replacement) = replacement else {
                break;
            };
            value = value.replace(&value[start..end + 2], replacement);
        }
        Some(value)
    }
}

fn ecs(ctx: &Context, role: &str) -> Result<Node> {
    if enabled(ctx, "ALIBABA_CLOUD_ECS_METADATA_DISABLED") {
        return Err(failed());
    }
    Ok(Node::new(
        "ecs_ram_role",
        Kind::Ecs {
            role: supplied(role, ctx, "ALIBABA_CLOUD_ECS_METADATA").unwrap_or_default(),
            disable_v1: enabled(ctx, "ALIBABA_CLOUD_IMDSV1_DISABLED"),
        },
    ))
}
async fn ecs_get(ctx: &Context, path: &str, disable_v1: bool) -> Result<Bytes> {
    let token = tokio::time::timeout(
        Duration::from_secs(2),
        ctx.http_send(
            Request::put(format!("{METADATA}/latest/api/token?"))
                .header("x-aliyun-ecs-metadata-token-ttl-seconds", "21600")
                .body(Bytes::new())?,
        ),
    )
    .await;
    let token = match token {
        Ok(Ok(response)) if response.status() == 200 => Some(response.into_body()),
        _ if !disable_v1 => None,
        _ => return Err(failed()),
    };
    let mut request = Request::get(format!("{METADATA}{path}?"));
    if let Some(token) = token
        && !token.is_empty()
    {
        request = request.header("x-aliyun-ecs-metadata-token", token.as_ref());
    }
    let response = tokio::time::timeout(
        Duration::from_secs(2),
        ctx.http_send(request.body(Bytes::new())?),
    )
    .await
    .map_err(|_| failed())??;
    if response.status() != 200 {
        return Err(failed());
    }
    Ok(response.into_body())
}
async fn ecs_credential(ctx: &Context, role: &str, disable_v1: bool) -> Result<Credential> {
    let role = if role.is_empty() {
        String::from_utf8(
            ecs_get(
                ctx,
                "/latest/meta-data/ram/security-credentials/",
                disable_v1,
            )
            .await?
            .to_vec(),
        )
        .map_err(|_| failed())?
        .trim()
        .to_owned()
    } else {
        role.to_owned()
    };
    let body = ecs_get(
        ctx,
        &format!("/latest/meta-data/ram/security-credentials/{role}"),
        disable_v1,
    )
    .await?;
    let value: serde_json::Value = serde_json::from_slice(&body).map_err(|_| failed())?;
    if value["Code"] != "Success" {
        return Err(failed());
    }
    decode_credential(&value)
}

async fn sts(
    ctx: &Context,
    role: &Role,
    base: Option<(&Credential, &str)>,
    mut body: BTreeMap<String, String>,
) -> Result<Credential> {
    let mut query = BTreeMap::from([
        ("Version".to_owned(), "2015-04-01".to_owned()),
        (
            "Action".to_owned(),
            if base.is_some() {
                "AssumeRole"
            } else {
                "AssumeRoleWithOIDC"
            }
            .to_owned(),
        ),
        ("Format".to_owned(), "JSON".to_owned()),
        (
            "Timestamp".to_owned(),
            Timestamp::now().format_rfc3339_zulu(),
        ),
    ]);
    body.insert("RoleArn".to_owned(), role.arn.clone());
    body.insert("RoleSessionName".to_owned(), role.session.clone());
    body.insert("DurationSeconds".to_owned(), role.duration.to_string());
    if !role.policy.is_empty() {
        body.insert("Policy".to_owned(), role.policy.clone());
    }
    if base.is_some() && !role.external.is_empty() {
        body.insert("ExternalId".to_owned(), role.external.clone());
    }
    let mut request = Request::builder().method("POST");
    if let Some((base, name)) = base {
        let mut nonce = [0_u8; 16];
        getrandom::getrandom(&mut nonce).map_err(|_| failed())?;
        query.extend([
            ("AccessKeyId".to_owned(), base.access_key_id.clone()),
            ("SignatureMethod".to_owned(), "HMAC-SHA1".to_owned()),
            ("SignatureVersion".to_owned(), "1.0".to_owned()),
            (
                "SignatureNonce".to_owned(),
                nonce
                    .iter()
                    .fold(String::with_capacity(32), |mut output, byte| {
                        let _ = write!(output, "{byte:02x}");
                        output
                    }),
            ),
        ]);
        if let Some(token) = base.security_token.as_ref().filter(|s| !s.is_empty()) {
            query.insert("SecurityToken".to_owned(), token.clone());
        }
        let mut canonical = query.clone();
        canonical.extend(body.clone());
        let canonical = form(&canonical).replace('+', "%20");
        let signature = base64_hmac_sha1(
            format!("{}&", base.access_key_secret).as_bytes(),
            format!("POST&%2F&{}", percent(&canonical)).as_bytes(),
        );
        query.insert("Signature".to_owned(), signature);
        request = request.header("x-acs-credentials-provider", name);
    }
    let request = request
        .uri(format!("https://{}/?{}", role.endpoint, form(&query)))
        .header("accept-encoding", "identity")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Bytes::from(form(&body)))?;
    let value = send_json(ctx, request).await?;
    decode_credential(&value["Credentials"])
}
fn form(values: &BTreeMap<String, String>) -> String {
    values
        .iter()
        .map(|(k, v)| {
            format!(
                "{}={}",
                percent(k).replace("%20", "+"),
                percent(v).replace("%20", "+")
            )
        })
        .collect::<Vec<_>>()
        .join("&")
}
async fn send_json(ctx: &Context, request: Request<Bytes>) -> Result<serde_json::Value> {
    let response = ctx.http_send(request).await?;
    if response.status() != 200 {
        return Err(failed());
    }
    serde_json::from_slice(response.body()).map_err(|_| failed())
}
fn decode_credential(value: &serde_json::Value) -> Result<Credential> {
    let get = |key| value[key].as_str().map(str::to_owned).ok_or_else(failed);
    // The Go temporary providers distinguish missing members from present
    // empty strings. Preserve that distinction for source selection: the OSS
    // signer rejects unusable keys without switching to another identity.
    Ok(Credential {
        access_key_id: get("AccessKeyId")?,
        access_key_secret: get("AccessKeySecret")?,
        security_token: Some(get("SecurityToken")?).filter(|s| !s.is_empty()),
        expires_in: Some(get("Expiration")?.parse().map_err(|_| failed())?),
    })
}
fn static_keys(id: &str, secret: &str, token: Option<String>) -> Result<Credential> {
    if id.is_empty() || secret.is_empty() {
        return Err(failed());
    }
    Ok(Credential {
        access_key_id: id.to_owned(),
        access_key_secret: secret.to_owned(),
        security_token: token.filter(|s| !s.is_empty()),
        expires_in: None,
    })
}
fn env(ctx: &Context, key: &str) -> Option<String> {
    ctx.env_var(key).filter(|s| !s.is_empty())
}
fn supplied(value: &str, ctx: &Context, key: &str) -> Option<String> {
    if value.is_empty() {
        env(ctx, key)
    } else {
        Some(value.to_owned())
    }
}
fn enabled(ctx: &Context, key: &str) -> bool {
    env(ctx, key).is_some_and(|s| s.eq_ignore_ascii_case("true"))
}
fn config_path(ctx: &Context, key: &str, default: &str) -> Result<String> {
    env(ctx, key)
        .or_else(|| {
            ctx.home_dir()
                .map(|home| home.join(default).to_string_lossy().into_owned())
        })
        .ok_or_else(failed)
}
fn failed() -> reqsign_core::Error {
    reqsign_core::Error::credential_invalid("Alibaba cloud credential unavailable")
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use http::Response;
    use reqsign_core::{FileRead, HttpSend, StaticEnv};
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex as StdMutex};

    #[derive(Deserialize)]
    struct Case {
        name: String,
        env: Option<HashMap<String, String>>,
        files: Option<HashMap<String, String>>,
        denied: String,
        key: String,
        secret: String,
        token: String,
        error: bool,
        requests: Option<Vec<serde_json::Value>>,
    }
    #[derive(Default)]
    struct State {
        files: HashMap<String, String>,
        denied: String,
        requests: Vec<serde_json::Value>,
    }
    #[derive(Clone, Default, Debug)]
    struct Io(Arc<StdMutex<State>>);
    impl fmt::Debug for State {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("State").finish_non_exhaustive()
        }
    }
    impl FileRead for Io {
        async fn file_read(&self, path: &str) -> Result<Vec<u8>> {
            self.0
                .lock()
                .unwrap()
                .files
                .get(path)
                .map(|s| s.as_bytes().to_vec())
                .ok_or_else(failed)
        }
    }
    fn parse_form(value: &str) -> BTreeMap<String, String> {
        reqwest::Url::parse(&format!("http://fixture/?{value}"))
            .unwrap()
            .query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect()
    }
    fn signature(query: &BTreeMap<String, String>, body: &BTreeMap<String, String>) -> String {
        let mut params = query.clone();
        params.remove("Signature");
        params.extend(body.clone());
        base64_hmac_sha1(
            b"base-secret&",
            format!("POST&%2F&{}", percent(&form(&params).replace('+', "%20"))).as_bytes(),
        )
    }
    impl HttpSend for Io {
        async fn http_send(&self, request: Request<Bytes>) -> Result<Response<Bytes>> {
            let uri = request.uri();
            let mut query = parse_form(uri.query().unwrap_or_default());
            let mut body = if request
                .headers()
                .get("content-type")
                .is_some_and(|v| v == "application/json")
            {
                serde_json::from_slice(request.body()).unwrap()
            } else {
                parse_form(std::str::from_utf8(request.body()).unwrap())
            };
            if let Some(actual) = query.get("Signature") {
                assert_eq!(actual, &signature(&query, &body));
            }
            if query.contains_key("Timestamp") {
                let parsed: Timestamp = query["Timestamp"].parse().unwrap();
                assert!((Timestamp::now().as_second() - parsed.as_second()).abs() < 60);
                query.insert("Timestamp".into(), "2026-09-20T00:00:00Z".into());
            }
            if let Some(session) = body.get("RoleSessionName")
                && let Some(micros) = session.strip_prefix("credentials-go-")
            {
                let micros = micros.parse::<i64>().unwrap();
                assert!((Timestamp::now().as_second() - micros / 1_000_000).abs() < 60);
                body.insert("RoleSessionName".into(), "fixture-session".into());
            }
            if query.contains_key("SignatureNonce") {
                query.insert("SignatureNonce".into(), "fixture-nonce".into());
                query.insert("Signature".into(), signature(&query, &body));
            }
            let headers: BTreeMap<_, _> = request
                .headers()
                .iter()
                .map(|(k, v)| (k.as_str().to_owned(), v.to_str().unwrap().to_owned()))
                .collect();
            let endpoint = format!(
                "{}://{}{}",
                uri.scheme_str().unwrap(),
                uri.authority().unwrap(),
                uri.path()
            );
            let observed = serde_json::json!({"method":request.method().as_str(),"url":endpoint,"query":query,"body":body,"headers":headers});
            let mut state = self.0.lock().unwrap();
            state.requests.push(observed);
            if (state.denied == "sts" && query.contains_key("Action"))
                || (state.denied == "metadata-token" && uri.path() == "/latest/api/token")
            {
                return Ok(Response::builder().status(403).body(Bytes::new()).unwrap());
            }
            let body = if uri.path() == "/latest/api/token" {
                Bytes::from_static(b"metadata-token")
            } else if uri.path().ends_with("/security-credentials/") {
                Bytes::from_static(b"role-name\n")
            } else {
                let (id, wrapper) = match query.get("Action").map(String::as_str) {
                    Some("AssumeRoleWithOIDC") => ("oidc-id", Some("Credentials")),
                    Some("AssumeRole") => ("role-id", Some("Credentials")),
                    _ if uri.path() == "/cloud-credentials" => ("sso-id", Some("CloudCredential")),
                    _ if uri.path().contains("security-credentials") => ("ecs-id", None),
                    _ => ("uri-id", None),
                };
                let mut value = serde_json::json!({"AccessKeyId":id,"AccessKeySecret":"result-secret","SecurityToken":"result-token","Expiration":"2099-01-01T00:00:00Z","Code":"Success"});
                if state.denied == "empty-sts-key" && query.contains_key("Action") {
                    value["AccessKeyId"] = "".into();
                }
                if let Some(wrapper) = wrapper {
                    value = serde_json::json!({wrapper:value});
                }
                Bytes::from(serde_json::to_vec(&value).unwrap())
            };
            Ok(Response::new(body))
        }
    }
    fn fixtures() -> Vec<Case> {
        serde_json::from_str(include_str!("../testdata/oss-default-go.json")).unwrap()
    }
    fn context(row: &Case) -> (Context, Io) {
        let io = Io::default();
        {
            let mut state = io.0.lock().unwrap();
            state.files = row
                .files
                .clone()
                .unwrap_or_default()
                .into_iter()
                .map(|(k, v)| (format!("/fixture/{k}"), v))
                .collect();
            state.denied = row.denied.clone();
        }
        let mut envs = HashMap::from([
            ("ALIBABA_CLOUD_CONFIG_FILE".into(), "/fixture/config".into()),
            (
                "ALIBABA_CLOUD_CREDENTIALS_FILE".into(),
                "/fixture/credentials".into(),
            ),
            ("ALIBABA_CLOUD_ECS_METADATA_DISABLED".into(), "true".into()),
        ]);
        envs.extend(row.env.clone().unwrap_or_default());
        (
            Context::new()
                .with_env(StaticEnv {
                    home_dir: None,
                    envs,
                })
                .with_file_read(io.clone())
                .with_http_send(io.clone()),
            io,
        )
    }
    #[tokio::test]
    async fn default_sources_and_requests_match_actual_go() {
        let rows = fixtures();
        assert_eq!(rows.len(), 33);
        for row in rows {
            let (ctx, io) = context(&row);
            let provider = GoDefaultProvider::default();
            let result = provider.provide_credential(&ctx).await;
            assert_eq!(result.is_err(), row.error, "{}", row.name);
            if let Ok(Some(value)) = result {
                assert_eq!(value.access_key_id, row.key, "{}", row.name);
                assert_eq!(value.access_key_secret, row.secret, "{}", row.name);
                assert_eq!(
                    value.security_token.unwrap_or_default(),
                    row.token,
                    "{}",
                    row.name
                );
            }
            assert_eq!(
                io.0.lock().unwrap().requests,
                row.requests.unwrap_or_default(),
                "{}",
                row.name
            );
        }
    }
    #[tokio::test]
    async fn selection_cache_refresh_and_failure_do_not_change_identity() {
        let row = fixtures()
            .into_iter()
            .find(|r| r.name == "oidc-before-cli")
            .unwrap();
        let (ctx, io) = context(&row);
        let provider = Arc::new(GoDefaultProvider::default());
        let (a, b) = tokio::join!(
            provider.provide_credential(&ctx),
            provider.provide_credential(&ctx)
        );
        assert_eq!(a.unwrap().unwrap().access_key_id, "oidc-id");
        assert_eq!(b.unwrap().unwrap().access_key_id, "oidc-id");
        assert_eq!(io.0.lock().unwrap().requests.len(), 1);
        {
            let mut state = provider.state.lock().await;
            let chain = state.as_mut().unwrap();
            let index = chain.selected.unwrap();
            chain.sources[index].cache.as_mut().unwrap().expires_in =
                Some(Timestamp::now() + Duration::from_secs(179));
        }
        io.0.lock().unwrap().denied = "sts".into();
        assert!(
            provider.provide_credential(&ctx).await.is_err(),
            "refresh failure must not fall back to the valid CLI"
        );
        assert_eq!(io.0.lock().unwrap().requests.len(), 2);
        io.0.lock().unwrap().denied.clear();
        io.0.lock()
            .unwrap()
            .files
            .insert("/fixture/token".into(), "rotated".into());
        assert_eq!(
            provider
                .provide_credential(&ctx)
                .await
                .unwrap()
                .unwrap()
                .access_key_id,
            "oidc-id"
        );
        assert_eq!(
            io.0.lock().unwrap().requests[2]["body"]["OIDCToken"],
            "rotated"
        );
    }
    #[tokio::test]
    async fn initial_failure_falls_through_but_latches_even_the_last_failed_source() {
        let row = fixtures()
            .into_iter()
            .find(|r| r.name == "oidc-denied-falls-to-cli")
            .unwrap();
        let (ctx, io) = context(&row);
        let provider = GoDefaultProvider::default();
        assert_eq!(
            provider
                .provide_credential(&ctx)
                .await
                .unwrap()
                .unwrap()
                .access_key_id,
            "cli-id"
        );
        io.0.lock().unwrap().denied.clear();
        assert_eq!(
            provider
                .provide_credential(&ctx)
                .await
                .unwrap()
                .unwrap()
                .access_key_id,
            "cli-id"
        );
        assert_eq!(io.0.lock().unwrap().requests.len(), 1);
        let row = fixtures()
            .into_iter()
            .find(|r| r.name == "no-source")
            .unwrap();
        let (ctx, io) = context(&row);
        let provider = GoDefaultProvider::default();
        assert!(provider.provide_credential(&ctx).await.is_err());
        io.0.lock().unwrap().files.insert("/fixture/config".into(),"{\"current\":\"x\",\"profiles\":[{\"name\":\"x\",\"mode\":\"AK\",\"access_key_id\":\"late\",\"access_key_secret\":\"late\"}]}".into());
        assert!(
            provider.provide_credential(&ctx).await.is_err(),
            "last failed INI provider stays selected, despite a now-valid CLI"
        );
        io.0.lock().unwrap().files.insert(
            "/fixture/credentials".into(),
            "[default]\ntype=access_key\naccess_key_id=ini-id\naccess_key_secret=ini-secret\n"
                .into(),
        );
        assert_eq!(
            provider
                .provide_credential(&ctx)
                .await
                .unwrap()
                .unwrap()
                .access_key_id,
            "ini-id"
        );
    }
}
