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

//! Pinned Go SSO profile validation, cache refresh, and role credentials.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use bytes::Bytes;
use http::Request;
use reqsign_aws_v4::Credential;
use reqsign_core::Context;
use reqsign_core::hash::hex_sha1;
use reqsign_core::time::Timestamp;
use serde::Deserialize;
use serde_json::{Map, Value};

pub(crate) struct Sso {
    path: Option<PathBuf>,
    key: String,
    region: String,
    account: String,
    role: String,
    refresh: bool,
}

impl Sso {
    pub(crate) fn new(
        ctx: &Context,
        profile: &BTreeMap<String, String>,
        session: Option<&BTreeMap<String, String>>,
    ) -> reqsign_core::Result<Self> {
        let get = |key: &str| {
            profile
                .get(key)
                .filter(|v| !v.is_empty())
                .map(String::as_str)
        };
        let (region, key, refresh) = if let Some(name) = get("sso_session") {
            let values = session.ok_or_else(failed)?;
            let mut selected = String::new();
            for key in ["sso_region", "sso_start_url"] {
                let value = values
                    .get(key)
                    .filter(|v| !v.is_empty())
                    .ok_or_else(failed)?;
                if get(key).is_some_and(|v| v != value) {
                    return Err(failed());
                }
                if key == "sso_region" {
                    selected.clone_from(value);
                }
            }
            (selected, name.to_owned(), true)
        } else {
            for key in [
                "sso_region",
                "sso_start_url",
                "sso_account_id",
                "sso_role_name",
            ] {
                get(key).ok_or_else(failed)?;
            }
            (
                get("sso_region").unwrap_or_default().to_owned(),
                get("sso_start_url").unwrap_or_default().to_owned(),
                false,
            )
        };
        let path = ctx.home_dir().map(|home| {
            home.join(".aws/sso/cache")
                .join(format!("{}.json", hex_sha1(key.as_bytes())))
        });
        // Session-token config computes this at construction. Legacy SSO
        // derives its cache path only when it first retrieves credentials.
        if refresh && path.is_none() {
            return Err(failed());
        }
        Ok(Self {
            path,
            key,
            region,
            account: get("sso_account_id").unwrap_or_default().to_owned(),
            role: get("sso_role_name").unwrap_or_default().to_owned(),
            refresh,
        })
    }

    fn endpoint(&self, service: &str, path: &str) -> reqsign_core::Result<reqwest::Url> {
        if self.region.is_empty()
            || !self
                .region
                .bytes()
                .all(|v| v.is_ascii_alphanumeric() || v == b'-')
        {
            return Err(failed());
        }
        let suffix = if self.region.starts_with("cn-") {
            "amazonaws.com.cn"
        } else {
            "amazonaws.com"
        };
        reqwest::Url::parse(&format!(
            "https://{service}.{}.{suffix}/{path}",
            self.region
        ))
        .map_err(|_| failed())
    }

    pub(crate) async fn retrieve(&self, ctx: &Context) -> reqsign_core::Result<Credential> {
        let path = if let Some(path) = &self.path {
            path.clone()
        } else {
            ctx.home_dir()
                .ok_or_else(failed)?
                .join(".aws/sso/cache")
                .join(format!("{}.json", hex_sha1(self.key.as_bytes())))
        };
        let path = path.to_str().ok_or_else(failed)?;
        let mut token: Map<String, Value> =
            serde_json::from_slice(&ctx.file_read(path).await?).map_err(|_| failed())?;
        // Go rejects wrong types even in refresh fields that are not needed yet.
        for key in [
            "accessToken",
            "expiresAt",
            "refreshToken",
            "clientId",
            "clientSecret",
        ] {
            if token.get(key).is_some_and(|v| !v.is_string()) {
                return Err(failed());
            }
        }
        let mut access = field(&token, "accessToken")?.to_owned();
        let expiration: Timestamp = field(&token, "expiresAt")?.parse().map_err(|_| failed())?;
        if expiration.as_second() == -62_135_596_800 {
            return Err(failed());
        } // Go time.Time's zero value.
        if Timestamp::now() > expiration {
            if !self.refresh {
                return Err(failed());
            }
            access = self.refresh_token(ctx, &mut token).await?;
        }
        let mut endpoint = self.endpoint("portal.sso", "federation/credentials")?;
        endpoint
            .query_pairs_mut()
            .append_pair("account_id", &self.account)
            .append_pair("role_name", &self.role);
        let request = Request::get(endpoint.as_str())
            .header("x-amz-sso_bearer_token", access)
            .body(Bytes::new())
            .map_err(|_| failed())?;
        let response = ctx.http_send(request).await?;
        if !response.status().is_success() {
            return Err(failed());
        }
        let body: Value = serde_json::from_slice(response.body()).map_err(|_| failed())?;
        let value = body.get("roleCredentials").ok_or_else(failed)?;
        Ok(Credential {
            access_key_id: value
                .get("accessKeyId")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            secret_access_key: value
                .get("secretAccessKey")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            session_token: value
                .get("sessionToken")
                .and_then(Value::as_str)
                .map(str::to_owned),
            expires_in: Some(Timestamp::from_millisecond(
                value
                    .get("expiration")
                    .and_then(Value::as_i64)
                    .unwrap_or_default(),
            )?),
        })
    }

    async fn refresh_token(
        &self,
        ctx: &Context,
        token: &mut Map<String, Value>,
    ) -> reqsign_core::Result<String> {
        let body = serde_json::json!({
            "clientId": field(token, "clientId")?,
            "clientSecret": field(token, "clientSecret")?,
            "grantType": "refresh_token",
            "refreshToken": field(token, "refreshToken")?,
        });
        let request = Request::post(self.endpoint("oidc", "token")?.as_str())
            .header("content-type", "application/json")
            .body(Bytes::from(
                serde_json::to_vec(&body).map_err(|_| failed())?,
            ))
            .map_err(|_| failed())?;
        let response = ctx.http_send(request).await?;
        if !response.status().is_success() {
            return Err(failed());
        }
        let value: RefreshedToken =
            serde_json::from_slice(response.body()).map_err(|_| failed())?;
        let access = value.access_token.unwrap_or_default();
        // Go clears a missing replacement refreshToken instead of retaining it.
        for (key, text) in [
            ("accessToken", access.as_str()),
            (
                "refreshToken",
                value.refresh_token.as_deref().unwrap_or_default(),
            ),
        ] {
            if text.is_empty() {
                token.remove(key);
            } else {
                token.insert(key.into(), Value::String(text.into()));
            }
        }
        let seconds = i64::from(value.expires_in.unwrap_or_default());
        let expiration = Timestamp::now()
            .as_second()
            .checked_add(seconds)
            .ok_or_else(failed)?;
        token.insert(
            "expiresAt".into(),
            Value::String(Timestamp::from_second(expiration)?.to_string()),
        );
        // Unknown fields survive the replacement, including CLI metadata.
        let mut bytes = serde_json::to_vec(token).map_err(|_| failed())?;
        bytes.push(b'\n');
        replace_cache(self.path.as_deref().ok_or_else(failed)?, &bytes).await?;
        Ok(access)
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RefreshedToken {
    access_token: Option<String>,
    refresh_token: Option<String>,
    expires_in: Option<i32>,
}

fn field<'a>(value: &'a Map<String, Value>, key: &str) -> reqsign_core::Result<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty())
        .ok_or_else(failed)
}

async fn replace_cache(path: &Path, bytes: &[u8]) -> reqsign_core::Result<()> {
    use tokio::io::AsyncWriteExt;
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let metadata = tokio::fs::metadata(path).await.map_err(|_| failed())?;
    let tmp = path.with_extension(format!(
        "json.tmp-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let mut opts = tokio::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        opts.mode(metadata.permissions().mode());
    }
    let mut file = opts.open(&tmp).await.map_err(|_| failed())?;
    let result = async {
        file.write_all(bytes).await.map_err(|_| failed())?;
        file.sync_all().await.map_err(|_| failed())?;
        drop(file);
        tokio::fs::rename(&tmp, path).await.map_err(|_| failed())
    }
    .await;
    if result.is_err() {
        let _ = tokio::fs::remove_file(&tmp).await;
    }
    result
}
fn failed() -> reqsign_core::Error {
    reqsign_core::Error::credential_invalid("AWS SSO credential unavailable")
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqsign_core::{ProvideCredential, StaticEnv};
    use serde::{Deserialize, Serialize};
    use std::sync::{Arc, Mutex};

    #[derive(Debug, Deserialize)]
    struct Case {
        name: String,
        config: String,
        cache: String,
        key: String,
        denied: String,
        load_error: bool,
        error: bool,
        credential: String,
        filename: String,
        updated: Value,
        requests: Option<Vec<Observed>>,
    }
    #[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
    struct Observed {
        method: String,
        url: String,
        body: String,
        token: String,
        content_type: String,
    }
    #[derive(Clone, Debug)]
    struct Io {
        denied: String,
        calls: Arc<Mutex<Vec<Observed>>>,
        cache: PathBuf,
    }
    impl reqsign_core::FileRead for Io {
        async fn file_read(&self, path: &str) -> reqsign_core::Result<Vec<u8>> {
            tokio::fs::read(path).await.map_err(|_| failed())
        }
    }
    impl reqsign_core::HttpSend for Io {
        async fn http_send(
            &self,
            request: Request<Bytes>,
        ) -> reqsign_core::Result<http::Response<Bytes>> {
            let header = |name| {
                request
                    .headers()
                    .get(name)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or_default()
                    .to_owned()
            };
            self.calls
                .lock()
                .unwrap_or_else(|e| unreachable!("{e}"))
                .push(Observed {
                    method: request.method().to_string(),
                    url: request.uri().to_string(),
                    body: String::from_utf8(request.body().to_vec())
                        .unwrap_or_else(|e| unreachable!("{e}")),
                    token: header("x-amz-sso_bearer_token"),
                    content_type: header("content-type"),
                });
            let (kind, body) = if request.uri().path() == "/token" {
                (
                    "token",
                    r#"{"accessToken":"new-token","refreshToken":"new-refresh","expiresIn":3600,"tokenType":"Bearer"}"#,
                )
            } else {
                (
                    "role",
                    r#"{"roleCredentials":{"accessKeyId":"sso-key","secretAccessKey":"sso-secret","sessionToken":"sso-token","expiration":4070908800000}}"#,
                )
            };
            let body = if self.denied == "bad-token-response" && kind == "token" {
                r#"{"accessToken":"new-token","expiresIn":"invalid"}"#
            } else {
                body
            };
            if self.denied == "cache-write" && kind == "token" {
                tokio::fs::rename(&self.cache, self.cache.with_extension("json.old"))
                    .await
                    .map_err(|_| failed())?;
                tokio::fs::create_dir(&self.cache)
                    .await
                    .map_err(|_| failed())?;
            }
            http::Response::builder()
                .status(if self.denied == kind { 400 } else { 200 })
                .body(Bytes::from_static(body.as_bytes()))
                .map_err(|_| failed())
        }
    }
    #[tokio::test]
    #[allow(clippy::too_many_lines)] // Full Go oracle also compares on-disk state and restart.
    async fn sso_construction_requests_and_refreshed_cache_match_actual_go() {
        let rows: Vec<Case> = serde_json::from_str(include_str!("../testdata/aws-sso-go.json"))
            .unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(rows.len(), 19);
        for (index, row) in rows.into_iter().enumerate() {
            let root =
                std::env::temp_dir().join(format!("cp-meter-sso-{}-{index}", std::process::id()));
            let cache_dir = root.join(".aws/sso/cache");
            tokio::fs::create_dir_all(&cache_dir)
                .await
                .unwrap_or_else(|e| unreachable!("{e}"));
            let cache = cache_dir.join(&row.filename);
            assert_eq!(
                row.filename,
                format!("{}.json", hex_sha1(row.key.as_bytes()))
            );
            tokio::fs::write(&cache, &row.cache)
                .await
                .unwrap_or_else(|e| unreachable!("{e}"));
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                tokio::fs::set_permissions(&cache, std::fs::Permissions::from_mode(0o600))
                    .await
                    .unwrap_or_else(|e| unreachable!("{e}"));
            }
            tokio::fs::write(root.join("config"), &row.config)
                .await
                .unwrap_or_else(|e| unreachable!("{e}"));
            let write_fails = row.denied == "cache-write";
            let io = Io {
                denied: row.denied,
                calls: Arc::new(Mutex::new(Vec::new())),
                cache: cache.clone(),
            };
            let ctx = Context::new()
                .with_env(StaticEnv {
                    home_dir: Some(root.clone()),
                    envs: [
                        (
                            "AWS_CONFIG_FILE".into(),
                            root.join("config").to_string_lossy().into_owned(),
                        ),
                        (
                            "AWS_SHARED_CREDENTIALS_FILE".into(),
                            root.join("absent").to_string_lossy().into_owned(),
                        ),
                    ]
                    .into(),
                })
                .with_file_read(io.clone())
                .with_http_send(io.clone());
            let provider = crate::cloud_aws_identity::GoDefaultProvider::new("us-east-1");
            let start = provider.prepare(&ctx).await;
            assert_eq!(start.is_err(), row.load_error, "{} constructor", row.name);
            assert!(
                io.calls
                    .lock()
                    .unwrap_or_else(|e| unreachable!("{e}"))
                    .is_empty()
            );
            let result = if start.is_ok() {
                provider.provide_credential(&ctx).await
            } else {
                Err(failed())
            };
            assert_eq!(result.is_err(), row.error, "{} retrieval", row.name);
            if !row.error {
                assert_eq!(
                    result
                        .unwrap_or_else(|e| unreachable!("{e}"))
                        .unwrap_or_else(|| unreachable!())
                        .access_key_id,
                    row.credential
                );
                assert!(provider.provide_credential(&ctx).await.is_ok());
            }
            assert_eq!(
                *io.calls.lock().unwrap_or_else(|e| unreachable!("{e}")),
                row.requests.unwrap_or_default(),
                "{} requests",
                row.name
            );
            let read_cache = if write_fails {
                cache.with_extension("json.old")
            } else {
                cache
            };
            let mut updated: Value = serde_json::from_slice(
                &tokio::fs::read(&read_cache)
                    .await
                    .unwrap_or_else(|e| unreachable!("{e}")),
            )
            .unwrap_or_else(|e| unreachable!("{e}"));
            if updated["accessToken"] == "new-token" {
                let expiration: Timestamp = updated["expiresAt"]
                    .as_str()
                    .unwrap_or_default()
                    .parse()
                    .unwrap_or_else(|e| unreachable!("{e}"));
                assert!(
                    (3590..=3600)
                        .contains(&(expiration.as_second() - Timestamp::now().as_second()))
                );
                updated["expiresAt"] = Value::String("REFRESH_PLUS_3600".into());
            }
            assert_eq!(updated, row.updated, "{} persisted cache", row.name);
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                assert_eq!(
                    tokio::fs::metadata(&read_cache)
                        .await
                        .unwrap_or_else(|e| unreachable!("{e}"))
                        .permissions()
                        .mode()
                        & 0o777,
                    0o600
                );
            }
            if row.name == "session-refresh" {
                let restarted = crate::cloud_aws_identity::GoDefaultProvider::new("us-east-1");
                restarted
                    .prepare(&ctx)
                    .await
                    .unwrap_or_else(|e| unreachable!("{e}"));
                assert!(restarted.provide_credential(&ctx).await.is_ok());
                let calls = io.calls.lock().unwrap_or_else(|e| unreachable!("{e}"));
                assert_eq!(
                    calls.len(),
                    3,
                    "restart reuses the persisted token without another refresh"
                );
                assert_eq!(calls[2].token, "new-token");
                assert_eq!(calls[2].method, "GET");
            }
            tokio::fs::remove_dir_all(root)
                .await
                .unwrap_or_else(|e| unreachable!("{e}"));
        }
    }
}
