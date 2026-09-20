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

//! Azure Blob authentication and storage endpoint assembly.

use crate::{Error, cloud_azure_identity::AzureDefault};
use control_config::MeteringConfig;
use http::{HeaderValue, Method, request::Parts};
use reqsign_core::{
    Context,
    hash::{base64_decode, base64_hmac_sha256},
    time::Timestamp,
};
use reqwest::{Client, Url};
use std::collections::BTreeMap;
use std::fmt::Write as _;

#[path = "cloud_azure_object.rs"]
mod object;

pub(crate) enum AzureSigner {
    SharedKey { account: String, key: Vec<u8> },
    Sas,
    Bearer(AzureDefault),
}

pub(crate) async fn build(
    config: &MeteringConfig,
    client: Client,
    context: Context,
) -> Result<(Url, AzureSigner), Error> {
    let cfg = config.azure.clone().unwrap_or_default();
    let raw = if config.endpoint.is_empty() {
        if cfg.account_name.is_empty() {
            return Err(Error::Invalid("Azure account or endpoint is required"));
        }
        format!("https://{}.blob.core.windows.net", cfg.account_name)
    } else {
        config.endpoint.clone()
    };
    let mut url = Url::parse(&raw).map_err(|_| Error::Invalid("invalid Azure endpoint"))?;
    if !matches!(url.scheme(), "https" | "http")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(Error::Invalid("invalid Azure endpoint"));
    }
    url.path_segments_mut()
        .map_err(|()| Error::Invalid("invalid Azure endpoint"))?
        .pop_if_empty()
        .push(&config.bucket);
    let signer = if !cfg.account_key.is_empty() {
        if cfg.account_name.is_empty() {
            return Err(Error::Invalid(
                "Azure account name is required for SharedKey",
            ));
        }
        let key = base64_decode(&cfg.account_key)
            .map_err(|_| Error::Invalid("invalid Azure account key"))?;
        AzureSigner::SharedKey {
            account: cfg.account_name,
            key,
        }
    } else if !cfg.sas_token.is_empty() {
        let token = cfg.sas_token.strip_prefix('?').unwrap_or(&cfg.sas_token);
        if !token.is_empty() {
            let query = url
                .query()
                .filter(|query| !query.is_empty())
                .map_or_else(|| token.to_owned(), |query| format!("{query}&{token}"));
            url.set_query(Some(&query));
        }
        AzureSigner::Sas
    } else {
        if url.scheme() != "https" {
            return Err(Error::Invalid("Azure bearer authentication requires HTTPS"));
        }
        AzureSigner::Bearer(AzureDefault::new(client, context).await?)
    };
    Ok((url, signer))
}

impl AzureSigner {
    pub(crate) async fn sign(&self, parts: &mut Parts) -> Result<(), Error> {
        parts
            .headers
            .insert("x-ms-version", HeaderValue::from_static("2025-11-05"));
        if parts.method == Method::PUT
            && !parts.uri.query().is_some_and(|q| {
                q.split('&')
                    .any(|v| matches!(v, "comp=block" | "comp=blocklist"))
            })
        {
            parts
                .headers
                .insert("x-ms-blob-type", HeaderValue::from_static("BlockBlob"));
        }
        let auth = match self {
            Self::SharedKey { account, key } => {
                let date = Timestamp::now()
                    .format_http_date()
                    .parse()
                    .map_err(|_| Error::Export("Azure date encoding failed"))?;
                parts.headers.entry("x-ms-date").or_insert(date);
                let text = canonical(parts, account)?;
                Some(format!(
                    "SharedKey {account}:{}",
                    base64_hmac_sha256(key, text.as_bytes())
                ))
            }
            Self::Sas => None,
            Self::Bearer(source) => Some(format!("Bearer {}", source.token().await?)),
        };
        if let Some(auth) = auth {
            let mut auth: HeaderValue = auth
                .parse()
                .map_err(|_| Error::Export("Azure authorization encoding failed"))?;
            auth.set_sensitive(true);
            parts.headers.insert(http::header::AUTHORIZATION, auth);
        }
        Ok(())
    }
}

// The Go blob client applies url.PathEscape to the entire blob name, including
// '/' separators, before joining it below the container endpoint.
pub(crate) fn escape_key(key: &str) -> String {
    let mut out = String::new();
    for b in key.bytes() {
        if b.is_ascii_alphanumeric()
            || matches!(
                b,
                b'-' | b'_' | b'.' | b'~' | b'$' | b'&' | b'+' | b':' | b'=' | b'@'
            )
        {
            out.push(char::from(b));
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

fn canonical(parts: &Parts, account: &str) -> Result<String, Error> {
    let value = |name: &str| -> Result<&str, Error> {
        parts.headers.get(name).map_or(Ok(""), |value| {
            value
                .to_str()
                .map_err(|_| Error::Export("invalid Azure request header"))
        })
    };
    let mut lines = vec![parts.method.as_str()];
    for name in [
        "content-encoding",
        "content-language",
        "content-length",
        "content-md5",
        "content-type",
        "date",
        "if-modified-since",
        "if-match",
        "if-none-match",
        "if-unmodified-since",
        "range",
    ] {
        let val = value(name)?;
        lines.push(
            if name == "date" || (name == "content-length" && val == "0") {
                ""
            } else {
                val
            },
        );
    }
    let mut headers = BTreeMap::<String, Vec<String>>::new();
    for (name, value) in &parts.headers {
        if name.as_str().starts_with("x-ms-") {
            headers.entry(name.as_str().to_owned()).or_default().push(
                value
                    .to_str()
                    .map_err(|_| Error::Export("invalid Azure request header"))?
                    .trim()
                    .to_owned(),
            );
        }
    }
    let headers = headers
        .into_iter()
        .map(|(name, values)| format!("{name}:{}", values.join(",")))
        .collect::<Vec<_>>()
        .join("\n");
    lines.push(&headers);
    let url = Url::parse(&parts.uri.to_string())
        .map_err(|_| Error::Export("invalid Azure request URI"))?;
    let mut resource = format!("/{account}{}", url.path());
    let mut query = BTreeMap::<String, Vec<String>>::new();
    for (name, value) in url.query_pairs() {
        query
            .entry(name.into_owned())
            .or_default()
            .push(value.into_owned());
    }
    for (name, mut values) in query {
        values.sort();
        write!(
            resource,
            "\n{}:{}",
            name.to_ascii_lowercase(),
            values.join(",")
        )
        .map_err(|_| Error::Export("Azure canonical resource failed"))?;
    }
    lines.push(&resource);
    Ok(lines.join("\n"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn shared_key_matches_real_go_sdk_requests() {
        let rows: Vec<serde_json::Value> =
            serde_json::from_str(include_str!("../testdata/azure-shared-key-go.json"))
                .unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(rows.len(), 5);
        for row in rows {
            let mut request = http::Request::builder()
                .method(row["method"].as_str().unwrap_or_default())
                .uri(row["url"].as_str().unwrap_or_default());
            let headers = row["headers"].as_object().unwrap_or_else(|| unreachable!());
            for (name, values) in headers {
                if name.eq_ignore_ascii_case("authorization") {
                    continue;
                }
                for value in values.as_array().unwrap_or_else(|| unreachable!()) {
                    request = request.header(name, value.as_str().unwrap_or_default());
                }
            }
            let mut parts = request
                .body(())
                .unwrap_or_else(|e| unreachable!("{e}"))
                .into_parts()
                .0;
            AzureSigner::SharedKey {
                account: "account".into(),
                key: b"fake-account-key".to_vec(),
            }
            .sign(&mut parts)
            .await
            .unwrap_or_else(|e| unreachable!("{e}"));
            assert_eq!(
                parts.headers["authorization"].to_str().unwrap_or_default(),
                row["headers"]["Authorization"][0]
                    .as_str()
                    .unwrap_or_default()
            );
        }
    }
}
