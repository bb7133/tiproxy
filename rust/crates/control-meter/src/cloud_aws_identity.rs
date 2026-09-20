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

//! Default AWS identity selection follows the pinned Go config resolver.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use reqsign_aws_v4::Credential;
use reqsign_core::time::Timestamp;
use reqsign_core::{Context, ProvideCredential, SigningCredential};
use tokio::sync::{Mutex, OnceCell};

use crate::cloud_aws::{RoleOptions, assume_role};

type Properties = BTreeMap<String, String>;
type Profiles = BTreeMap<String, ProfileData>;

#[derive(Default)]
struct ProfileData {
    props: Properties,
    partial_keys: bool,
}
struct Profile {
    props: Properties,
    sso_session: Option<Properties>,
    source: Option<Box<Profile>>,
}

pub(crate) struct GoDefaultProvider {
    region: String,
    selected: OnceCell<Source>,
}

impl fmt::Debug for GoDefaultProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GoDefaultProvider").finish_non_exhaustive()
    }
}

impl GoDefaultProvider {
    pub(crate) fn new(region: &str) -> Self {
        Self {
            region: region.to_owned(),
            selected: OnceCell::new(),
        }
    }

    /// Resolve config at client construction; credential I/O stays lazy.
    pub(crate) async fn prepare(&self, ctx: &Context) -> reqsign_core::Result<()> {
        self.selected.get_or_try_init(|| self.resolve(ctx)).await?;
        Ok(())
    }

    async fn resolve(&self, ctx: &Context) -> reqsign_core::Result<Source> {
        let profile = load_profile(ctx).await?;
        // Complete environment keys, then environment web identity, then the
        // merged active profile. Authentication errors never change identity.
        if let Some(credential) = environment(ctx) {
            return Ok(Source::static_keys(credential));
        }
        if let Some(file) = env(ctx, "AWS_WEB_IDENTITY_TOKEN_FILE") {
            let arn = env(ctx, "AWS_ROLE_ARN").ok_or_else(failed)?;
            return Ok(web_identity(
                ctx,
                &self.region,
                &arn,
                &file,
                env(ctx, "AWS_ROLE_SESSION_NAME"),
            ));
        }
        self.resolve_profile(ctx, &profile).await
    }

    async fn resolve_profile(
        &self,
        ctx: &Context,
        profile: &Profile,
    ) -> reqsign_core::Result<Source> {
        let get = |key: &str| property(&profile.props, key);
        let arn = get("role_arn");
        let static_keys = match (get("aws_access_key_id"), get("aws_secret_access_key")) {
            (Some(id), Some(secret)) => Some(Credential {
                access_key_id: id.to_owned(),
                secret_access_key: secret.to_owned(),
                session_token: get("aws_session_token").map(str::to_owned),
                expires_in: None,
            }),
            _ => None,
        };
        let source = if let Some(parent) = &profile.source {
            Box::pin(self.resolve_profile(ctx, parent)).await?
        } else if let Some(keys) = static_keys {
            Source::static_keys(keys)
        } else if let Some(source) = get("credential_source") {
            match source {
                "Environment" => Source::static_keys(environment(ctx).unwrap_or(Credential {
                    access_key_id: String::new(),
                    secret_access_key: String::new(),
                    session_token: None,
                    expires_in: None,
                })),
                "Ec2InstanceMetadata" => Source::imds(ctx, &profile.props)?,
                "EcsContainer" => Source::container(ctx).await?,
                _ => return Err(failed()),
            }
        } else if let Some(file) = get("web_identity_token_file") {
            return Ok(web_identity(
                ctx,
                &self.region,
                arn.ok_or_else(failed)?,
                file,
                get("role_session_name").map(str::to_owned),
            ));
        } else if [
            "sso_session",
            "sso_region",
            "sso_start_url",
            "sso_account_id",
            "sso_role_name",
        ]
        .iter()
        .any(|key| get(key).is_some())
        {
            Source {
                kind: Kind::Sso(crate::cloud_aws_sso::Sso::new(
                    ctx,
                    &profile.props,
                    profile.sso_session.as_ref(),
                )?),
                cached: Mutex::new(None),
            }
        } else if let Some(command) = get("credential_process") {
            Source {
                kind: Kind::Process(command.to_owned()),
                cached: Mutex::new(None),
            }
        } else if env(ctx, "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI").is_some()
            || env(ctx, "AWS_CONTAINER_CREDENTIALS_FULL_URI").is_some()
        {
            Source::container(ctx).await?
        } else {
            Source::imds(ctx, &profile.props)?
        };
        if let Some(arn) = arn {
            if get("mfa_serial").is_some() {
                return Err(failed());
            }
            // Go applies the option only when integer minutes exceed 15.
            // Non-numeric, zero, negative and 901..959 retain the 900s default.
            let duration = get("duration_seconds")
                .and_then(|value| value.parse::<u32>().ok())
                .filter(|value| value / 60 > 15)
                .unwrap_or(900);
            let session = get("role_session_name").map_or_else(session_name, str::to_owned);
            Ok(Source {
                kind: Kind::Role {
                    source: Box::new(source),
                    arn: arn.to_owned(),
                    session,
                    duration,
                    external_id: get("external_id").map(str::to_owned),
                    region: self.region.clone(),
                    retry: crate::cloud_aws_retry::Retry::new(ctx),
                },
                cached: Mutex::new(None),
            })
        } else {
            Ok(source)
        }
    }
}

impl ProvideCredential for GoDefaultProvider {
    type Credential = Credential;
    async fn provide_credential(&self, ctx: &Context) -> reqsign_core::Result<Option<Credential>> {
        let source = self.selected.get_or_try_init(|| self.resolve(ctx)).await?;
        source.get(ctx).await.map(Some)
    }
}

struct Source {
    kind: Kind,
    cached: Mutex<Option<Credential>>,
}
enum Kind {
    Static(Credential),
    Process(String),
    Container(crate::cloud_aws_container::Container),
    Sso(crate::cloud_aws_sso::Sso),
    Imds(crate::cloud_aws_imds::Imds),
    Web(WebIdentity),
    Role {
        source: Box<Source>,
        arn: String,
        session: String,
        duration: u32,
        external_id: Option<String>,
        region: String,
        retry: crate::cloud_aws_retry::Retry,
    },
}
impl Source {
    async fn container(ctx: &Context) -> reqsign_core::Result<Self> {
        Ok(Self {
            kind: Kind::Container(crate::cloud_aws_container::Container::new(ctx).await?),
            cached: Mutex::new(None),
        })
    }
    fn static_keys(value: Credential) -> Self {
        Self {
            kind: Kind::Static(value),
            cached: Mutex::new(None),
        }
    }
    fn imds(ctx: &Context, props: &Properties) -> reqsign_core::Result<Self> {
        Ok(Self {
            kind: Kind::Imds(crate::cloud_aws_imds::Imds::new(ctx, props)?),
            cached: Mutex::new(None),
        })
    }
    async fn get(&self, ctx: &Context) -> reqsign_core::Result<Credential> {
        let mut cached = self.cached.lock().await;
        if let Some(value) = cached
            .as_ref()
            .filter(|value| value.is_valid_at(Timestamp::now()))
        {
            return Ok(value.clone());
        }
        let value = match &self.kind {
            Kind::Static(value) => value.clone(),
            Kind::Process(command) => crate::cloud_aws_process::retrieve(ctx, command).await?,
            Kind::Container(provider) => provider.retrieve(ctx).await?,
            Kind::Sso(provider) => provider.retrieve(ctx).await?,
            Kind::Web(web) => web.retrieve(ctx).await?,
            Kind::Imds(provider) => provider.retrieve(ctx).await?,
            Kind::Role {
                source,
                arn,
                session,
                duration,
                external_id,
                region,
                retry,
            } => {
                let source = Box::pin(source.get(ctx)).await?;
                assume_role(
                    ctx,
                    region,
                    None,
                    &RoleOptions {
                        arn,
                        session,
                        duration: *duration,
                        external_id: external_id.as_deref(),
                    },
                    source,
                    retry,
                )
                .await?
            }
        };
        if value.access_key_id.is_empty() || value.secret_access_key.is_empty() {
            return Err(failed());
        }
        *cached = Some(value.clone());
        Ok(value)
    }
}

struct WebIdentity {
    region: String,
    arn: String,
    file: String,
    session: Option<String>,
    retry: crate::cloud_aws_retry::Retry,
}

fn web_identity(
    ctx: &Context,
    region: &str,
    arn: &str,
    file: &str,
    session: Option<String>,
) -> Source {
    Source {
        kind: Kind::Web(WebIdentity {
            region: region.to_owned(),
            arn: arn.to_owned(),
            file: file.to_owned(),
            session,
            retry: crate::cloud_aws_retry::Retry::new(ctx),
        }),
        cached: Mutex::new(None),
    }
}

impl WebIdentity {
    async fn retrieve(&self, ctx: &Context) -> reqsign_core::Result<Credential> {
        let token = ctx.file_read_as_string(&self.file).await?;
        // Go passes the complete file bytes, including a trailing newline.
        // Its generated web-identity session has no prefix and is regenerated
        // per Retrieve, unlike the cached explicit AssumeRole session name.
        let now = Timestamp::now();
        let session = self
            .session
            .clone()
            .unwrap_or_else(|| format!("{}{:09}", now.as_second(), now.subsec_nanosecond()));
        let grant = reqsign_aws_v4::AssumeRoleGrant::new(&self.arn, &session);
        let authority = reqsign_aws_core::assume_role::regional_sts_endpoint(&self.region, &grant)?;
        let params = BTreeMap::from([
            ("Action", "AssumeRoleWithWebIdentity"),
            ("RoleArn", self.arn.as_str()),
            ("RoleSessionName", session.as_str()),
            ("Version", "2011-06-15"),
            ("WebIdentityToken", token.as_str()),
        ]);
        let mut encoded = reqwest::Url::parse("https://unused.invalid").map_err(|_| failed())?;
        encoded.query_pairs_mut().extend_pairs(params);
        let request = http::Request::post(format!("https://{authority}/"))
            .header(
                http::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .body(bytes::Bytes::from(
                encoded.query().ok_or_else(failed)?.to_owned(),
            ))
            .map_err(|_| failed())?;
        self.retry
            .run(|| async {
                use crate::cloud_aws_retry::Failure;
                let response = ctx
                    .http_send(request.clone())
                    .await
                    .map_err(Failure::transport)?;
                if response.status() != http::StatusCode::OK {
                    return Err(Failure::sts(&response, true));
                }
                decode_web(response.body()).map_err(Failure::terminal)
            })
            .await
    }
}

fn decode_web(raw: &[u8]) -> reqsign_core::Result<Credential> {
    let body = std::str::from_utf8(raw).map_err(|_| failed())?;
    let response: WebResponse = quick_xml::de::from_str(body).map_err(|_| failed())?;
    let value = response.result.credentials;
    let credential = Credential {
        access_key_id: value.access_key_id,
        secret_access_key: value.secret_access_key,
        session_token: Some(value.session_token),
        expires_in: Some(value.expiration.parse().map_err(|_| failed())?),
    };
    if !credential.is_valid_at(Timestamp::now())
        || credential
            .session_token
            .as_ref()
            .is_none_or(String::is_empty)
    {
        return Err(failed());
    }
    Ok(credential)
}

#[derive(serde::Deserialize)]
struct WebResponse {
    #[serde(rename = "AssumeRoleWithWebIdentityResult")]
    result: WebResult,
}
#[derive(serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
struct WebResult {
    credentials: WebCredential,
}
#[derive(serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
struct WebCredential {
    access_key_id: String,
    secret_access_key: String,
    session_token: String,
    expiration: String,
}

/// Explicit static credentials still run the Go shared-config validation,
/// but skip resolution of the profile's credential provider.
pub(crate) async fn validate_profile(ctx: &Context) -> reqsign_core::Result<()> {
    load_profile(ctx).await?;
    Ok(())
}

async fn load_profile(ctx: &Context) -> reqsign_core::Result<Profile> {
    crate::cloud_aws_imds::validate_env(ctx)?;
    let profiles = read_profiles(ctx).await?;
    let name = env(ctx, "AWS_PROFILE").or_else(|| env(ctx, "AWS_DEFAULT_PROFILE"));
    if name
        .as_ref()
        .is_some_and(|name| !profiles.contains_key(name))
    {
        return Err(failed());
    }
    normalize_profile(
        &profiles,
        name.as_deref().unwrap_or("default"),
        &mut BTreeSet::new(),
    )
}

fn environment(ctx: &Context) -> Option<Credential> {
    Some(Credential {
        access_key_id: env(ctx, "AWS_ACCESS_KEY_ID").or_else(|| env(ctx, "AWS_ACCESS_KEY"))?,
        secret_access_key: env(ctx, "AWS_SECRET_ACCESS_KEY")
            .or_else(|| env(ctx, "AWS_SECRET_KEY"))?,
        session_token: env(ctx, "AWS_SESSION_TOKEN"),
        expires_in: None,
    })
}
fn env(ctx: &Context, key: &str) -> Option<String> {
    ctx.env_var(key).filter(|value| !value.is_empty())
}
fn session_name() -> String {
    let now = Timestamp::now();
    format!(
        "aws-go-sdk-{}{:09}",
        now.as_second(),
        now.subsec_nanosecond()
    )
}

fn property<'a>(props: &'a Properties, key: &str) -> Option<&'a str> {
    props
        .get(key)
        .filter(|value| !value.is_empty())
        .map(String::as_str)
}

// Normalize source_profile links like SharedConfig.setFromIniSections: static
// credentials terminate a nested link, and revisiting a profile clears only its
// assume-role options. A cycle without a credential source fails closed.
fn normalize_profile(
    profiles: &Profiles,
    name: &str,
    seen: &mut BTreeSet<String>,
) -> reqsign_core::Result<Profile> {
    if seen.len() >= 32 {
        return Err(failed());
    }
    let mut profile = Profile {
        sso_session: None,
        props: Properties::new(),
        source: None,
    };
    if let Some(data) = profiles.get(name) {
        if data.partial_keys {
            return Err(failed());
        }
        profile.props.clone_from(&data.props);
    } else if !seen.is_empty() {
        return Err(failed());
    }
    if seen.contains(name) {
        for key in [
            "role_arn",
            "external_id",
            "mfa_serial",
            "role_session_name",
            "source_profile",
        ] {
            profile.props.remove(key);
        }
    } else if [
        "source_profile",
        "credential_source",
        "web_identity_token_file",
    ]
    .iter()
    .any(|key| property(&profile.props, key).is_some())
        && property(&profile.props, "role_arn").is_none()
    {
        return Err(failed());
    }
    if !seen.is_empty()
        && property(&profile.props, "aws_access_key_id").is_some()
        && property(&profile.props, "aws_secret_access_key").is_some()
    {
        return Ok(profile);
    }
    if !seen.insert(name.to_owned()) {
        return Err(failed());
    }
    if [
        "source_profile",
        "credential_source",
        "credential_process",
        "web_identity_token_file",
    ]
    .iter()
    .filter(|key| property(&profile.props, key).is_some())
    .count()
        > 1
    {
        return Err(failed());
    }
    if let Some(parent) = property(&profile.props, "source_profile") {
        let source = normalize_profile(profiles, parent, seen)?;
        let configured_source = [
            "source_profile",
            "credential_source",
            "credential_process",
            "web_identity_token_file",
            "sso_session",
            "sso_region",
            "sso_account_id",
            "sso_start_url",
            "sso_role_name",
        ]
        .iter()
        .any(|key| property(&source.props, key).is_some());
        let static_source = property(&source.props, "aws_access_key_id").is_some()
            && property(&source.props, "aws_secret_access_key").is_some();
        if !(configured_source || static_source) {
            return Err(failed());
        }
        profile.source = Some(Box::new(source));
    }
    if let Some(session) = property(&profile.props, "sso_session") {
        profile.sso_session = Some(
            profiles
                .get(&format!("sso-session {}", session.trim()))
                .ok_or_else(failed)?
                .props
                .clone(),
        );
    }
    Ok(profile)
}

// Credential sections use the Go SDK's literal string dialect, not Rust INI
// escape expansion. Nested maps are consumed but not credential scalar values.
fn parse_profiles(content: &str) -> BTreeMap<String, Properties> {
    let mut sections: BTreeMap<String, Properties> = BTreeMap::new();
    let mut section = String::new();
    let mut last_key = String::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with(['#', ';']) {
            continue;
        }
        let header = line.split(['#', ';']).next().unwrap_or_default().trim();
        if let Some(name) = header.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            let name = name.trim();
            let split = name.find([' ', '\t']);
            section = match split {
                Some(i) => format!(
                    "{} {}",
                    &name[..i],
                    name[i..].trim_start_matches([' ', '\t'])
                ),
                None => name.to_owned(),
            };
            sections.entry(section.clone()).or_default();
            last_key.clear();
            continue;
        }
        if section.is_empty() {
            continue;
        }
        let indented = line.starts_with([' ', '\t']);
        let text = if indented {
            line.trim_start_matches([' ', '\t'])
        } else {
            trim_comment(line).trim_end_matches([' ', '\t'])
        };
        let values = sections.entry(section.clone()).or_default();
        if let Some(index) = text.find(['=', ':']) {
            let key = text[..index].trim().to_ascii_lowercase();
            let mut value = text[index + 1..].trim();
            if value.len() >= 2
                && ((value.starts_with('"') && value.ends_with('"'))
                    || (value.starts_with('\'') && value.ends_with('\'')))
            {
                value = &value[1..value.len() - 1];
            }
            if indented
                && !last_key.is_empty()
                && values.get(&last_key).is_some_and(String::is_empty)
            {
                continue; // a sub-property of a nested map
            }
            if indented {
                value = trim_comment(value).trim();
            }
            values.insert(key.clone(), value.to_owned());
            last_key = key;
        } else if indented
            && let Some(value) = values.get_mut(&last_key)
            && !value.is_empty()
        {
            value.push('\n');
            value.push_str(text);
        }
    }
    sections
}
fn trim_comment(mut value: &str) -> &str {
    for marker in [" #", " ;", "\t#", "\t;"] {
        if let Some((prefix, _)) = value.split_once(marker) {
            value = prefix;
        }
    }
    value
}

async fn read_profiles(ctx: &Context) -> reqsign_core::Result<Profiles> {
    let mut profiles = Profiles::new();
    for (variable, fallback, config) in [
        ("AWS_CONFIG_FILE", ".aws/config", true),
        ("AWS_SHARED_CREDENTIALS_FILE", ".aws/credentials", false),
    ] {
        let path = env(ctx, variable).or_else(|| {
            ctx.home_dir()
                .map(|home| home.join(fallback).to_string_lossy().into_owned())
        });
        let Some(path) = path else {
            continue;
        };
        // Go treats every file-open/read error as an empty file, even for an
        // explicit path. Its INI tokenizer also ignores unrecognized lines.
        let Ok(content) = ctx.file_read_as_string(&path).await else {
            continue;
        };
        let ini = parse_profiles(&content);
        // In config, [profile default] replaces [default] regardless of order.
        let prefixed_default = config && ini.contains_key("profile default");
        for (section, values) in &ini {
            if (prefixed_default && section == "default")
                || (!config && section.starts_with("profile "))
            {
                continue;
            }
            let profile = if config && section != "default" && !section.starts_with("sso-session ")
            {
                let Some(profile) = section.strip_prefix("profile ") else {
                    continue;
                };
                profile
            } else {
                section.as_str()
            };
            let values = values.clone();
            let complete = values.contains_key("aws_access_key_id")
                && values.contains_key("aws_secret_access_key");
            let partial = values.contains_key("aws_access_key_id")
                != values.contains_key("aws_secret_access_key");
            let data = profiles.entry(profile.to_owned()).or_default();
            // Credentials are merged as a pair, never assembled across files.
            // A later section replaces the earlier section's error state.
            data.partial_keys = partial;
            data.props.extend(values.into_iter().filter(|(key, _)| {
                complete
                    || ![
                        "aws_access_key_id",
                        "aws_secret_access_key",
                        "aws_session_token",
                    ]
                    .contains(&key.as_str())
            }));
        }
    }
    Ok(profiles)
}

fn failed() -> reqsign_core::Error {
    reqsign_core::Error::credential_invalid("AWS default credential unavailable")
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use http::{Request, Response};
    use reqsign_core::StaticEnv;
    use serde::{Deserialize, Serialize};
    use std::sync::{Arc, Mutex as StdMutex};
    use std::time::Duration;

    #[derive(Debug, Deserialize)]
    #[allow(clippy::struct_excessive_bools)] // Mirrors independent Go fixture inputs/outcomes.
    struct Case {
        name: String,
        env: Option<BTreeMap<String, String>>,
        files: BTreeMap<String, String>,
        denied: bool,
        r#static: bool,
        load_error: bool,
        load_requests: usize,
        credential: String,
        secret: String,
        error: bool,
        requests: Option<Vec<Observed>>,
    }
    #[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
    struct Observed {
        method: String,
        url: String,
        body: String,
        signing_key: String,
        token: String,
    }
    #[derive(Debug, Default)]
    struct State {
        files: BTreeMap<String, String>,
        requests: Vec<Observed>,
        denied: bool,
        commands: usize,
    }
    #[derive(Debug, Clone, Default)]
    struct Io(Arc<StdMutex<State>>);
    impl reqsign_core::FileRead for Io {
        async fn file_read(&self, path: &str) -> reqsign_core::Result<Vec<u8>> {
            self.0
                .lock()
                .unwrap_or_else(|e| unreachable!("{e}"))
                .files
                .get(path)
                .map(|value| value.as_bytes().to_vec())
                .ok_or_else(failed)
        }
    }
    impl reqsign_core::CommandExecute for Io {
        async fn command_execute(
            &self,
            _program: &str,
            _args: &[&str],
        ) -> reqsign_core::Result<reqsign_core::CommandOutput> {
            self.0
                .lock()
                .unwrap_or_else(|e| unreachable!("{e}"))
                .commands += 1;
            Err(failed())
        }
    }
    impl reqsign_core::HttpSend for Io {
        async fn http_send(
            &self,
            request: Request<Bytes>,
        ) -> reqsign_core::Result<Response<Bytes>> {
            let header = |name| {
                request
                    .headers()
                    .get(name)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or_default()
                    .to_owned()
            };
            let body = std::str::from_utf8(request.body())
                .map_err(|_| failed())?
                .to_owned();
            let action = reqwest::Url::parse(&format!("https://unused.invalid/?{body}"))
                .map_err(|_| failed())?
                .query_pairs()
                .find_map(|(key, value)| (key == "Action").then(|| value.into_owned()))
                .ok_or_else(failed)?;
            let authorization = header("authorization");
            let signing_key = authorization
                .split_once("Credential=")
                .map(|(_, rest)| rest.split('/').next().unwrap_or_default())
                .unwrap_or_default();
            let mut state = self.0.lock().unwrap_or_else(|e| unreachable!("{e}"));
            state.requests.push(Observed {
                method: request.method().to_string(),
                url: request.uri().to_string(),
                body,
                signing_key: signing_key.to_owned(),
                token: header("x-amz-security-token"),
            });
            let id = if action == "AssumeRoleWithWebIdentity" {
                "ASIAWEBIDENTITY000000"
            } else {
                "ASIASOURCEROLE0000000"
            };
            let body = format!(
                "<{action}Response><{action}Result><Credentials><AccessKeyId>{id}</AccessKeyId><SecretAccessKey>fake-secret</SecretAccessKey><SessionToken>fake-token</SessionToken><Expiration>2099-01-01T00:00:00Z</Expiration></Credentials></{action}Result></{action}Response>"
            );
            Response::builder()
                .status(if state.denied { 403 } else { 200 })
                .body(Bytes::from(body))
                .map_err(|_| failed())
        }
    }
    fn fixtures() -> Vec<Case> {
        serde_json::from_str(include_str!("../testdata/aws-default-go.json"))
            .unwrap_or_else(|e| unreachable!("{e}"))
    }
    fn context(row: &Case) -> (Context, Io) {
        let io = Io::default();
        {
            let mut state = io.0.lock().unwrap_or_else(|e| unreachable!("{e}"));
            state.files = row
                .files
                .iter()
                .map(|(key, value)| (format!("/fixture/{key}"), value.clone()))
                .collect();
            state.denied = row.denied;
        }
        let mut envs = row.env.clone().unwrap_or_default();
        envs.insert("AWS_CONFIG_FILE".into(), "/fixture/config".into());
        envs.insert(
            "AWS_SHARED_CREDENTIALS_FILE".into(),
            "/fixture/credentials".into(),
        );
        let ctx = Context::new()
            .with_env(StaticEnv {
                home_dir: None,
                envs: envs.into_iter().collect(),
            })
            .with_file_read(io.clone())
            .with_http_send(io.clone())
            .with_command_execute(io.clone());
        (ctx, io)
    }
    #[tokio::test]
    async fn default_sources_and_sts_requests_match_actual_go() {
        let rows = fixtures();
        assert_eq!(rows.len(), 41);
        for row in rows {
            assert_eq!(row.load_requests, 0, "{}: Go constructor is lazy", row.name);
            let (ctx, io) = context(&row);
            let config = if row.r#static {
                control_config::AwsMeteringConfig {
                    access_key: "explicit-id".into(),
                    secret_access_key: "explicit-secret".into(),
                    ..Default::default()
                }
            } else {
                control_config::AwsMeteringConfig::default()
            };
            let signer =
                crate::cloud_aws::AwsSigner::new(&config, "us-east-1".into(), None, ctx).await;
            assert_eq!(
                signer.is_err(),
                row.load_error,
                "{} at construction",
                row.name
            );
            {
                let state = io.0.lock().unwrap_or_else(|e| unreachable!("{e}"));
                assert!(
                    state.requests.is_empty(),
                    "{}: no credential HTTP at construction",
                    row.name
                );
                assert_eq!(
                    state.commands, 0,
                    "{}: no credential process at construction",
                    row.name
                );
            }
            let result = match signer.as_ref() {
                Ok(signer) => signer.credential().await,
                Err(_) => Err(failed()),
            };
            assert_eq!(result.is_err(), row.error, "{}", row.name);
            if !row.error {
                let credential = result.unwrap_or_else(|e| unreachable!("{}: {e}", row.name));
                assert_eq!(credential.access_key_id, row.credential, "{}", row.name);
                assert_eq!(credential.secret_access_key, row.secret, "{}", row.name);
                assert!(
                    signer
                        .unwrap_or_else(|e| unreachable!("{e}"))
                        .credential()
                        .await
                        .is_ok()
                );
            }
            let state = io.0.lock().unwrap_or_else(|e| unreachable!("{e}"));
            assert_eq!(
                state.requests,
                row.requests.unwrap_or_default(),
                "{}",
                row.name
            );
            assert_eq!(
                state.commands,
                usize::from(row.name == "failed-process-never-falls-back")
            );
        }
    }
    #[tokio::test]
    async fn selected_web_source_and_zero_margin_cache_survive_failure_and_profile_change() {
        let row = fixtures()
            .into_iter()
            .find(|row| row.name == "web-identity-before-profile")
            .unwrap_or_else(|| unreachable!());
        let (ctx, io) = context(&row);
        let provider = GoDefaultProvider::new("us-east-1");
        provider
            .prepare(&ctx)
            .await
            .unwrap_or_else(|e| unreachable!("{e}"));
        io.0.lock()
            .unwrap_or_else(|e| unreachable!("{e}"))
            .files
            .insert(
                "/fixture/config".into(),
                "[default]\ncredential_source=Environment\n".into(),
            );
        let (one, two) = tokio::join!(
            provider.provide_credential(&ctx),
            provider.provide_credential(&ctx)
        );
        assert!(one.is_ok() && two.is_ok());
        let source = provider.selected.get().unwrap_or_else(|| unreachable!());
        source
            .cached
            .lock()
            .await
            .as_mut()
            .unwrap_or_else(|| unreachable!())
            .expires_in = Some(Timestamp::now() + Duration::from_secs(1));
        assert!(provider.provide_credential(&ctx).await.is_ok());
        assert_eq!(
            io.0.lock()
                .unwrap_or_else(|e| unreachable!("{e}"))
                .requests
                .len(),
            1
        );
        source
            .cached
            .lock()
            .await
            .as_mut()
            .unwrap_or_else(|| unreachable!())
            .expires_in = Some(Timestamp::now() - Duration::from_secs(1));
        {
            let mut state = io.0.lock().unwrap_or_else(|e| unreachable!("{e}"));
            state.files.insert(
                "/fixture/config".into(),
                "[default]\naws_access_key_id=other-id\naws_secret_access_key=other-secret\n"
                    .into(),
            );
            state.denied = true;
        }
        assert!(provider.provide_credential(&ctx).await.is_err());
        {
            let mut state = io.0.lock().unwrap_or_else(|e| unreachable!("{e}"));
            state.denied = false;
            state
                .files
                .insert("/fixture/token".into(), "rotated-token\n".into());
        }
        let value = provider
            .provide_credential(&ctx)
            .await
            .unwrap_or_else(|e| unreachable!("{e}"))
            .unwrap_or_else(|| unreachable!());
        assert_eq!(value.access_key_id, "ASIAWEBIDENTITY000000");
        let state = io.0.lock().unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(state.requests.len(), 3);
        assert!(
            state.requests[2]
                .body
                .contains("WebIdentityToken=rotated-token%0A")
        );
    }
}
