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

//! OSS V4 header signing with an explicit corrected time; reqsign's override is test-only.
use http::request::Parts;
use reqsign_aliyun_oss::Credential;
use reqsign_core::{
    hash::{hex_hmac_sha256, hex_sha256, hmac_sha256},
    time::Timestamp,
};

pub(super) fn sign_at(
    parts: &mut Parts,
    credential: &Credential,
    region: &str,
    bucket: &str,
    now: Timestamp,
) -> reqsign_core::Result<()> {
    let fail = super::failed;
    parts.headers.insert(
        "x-oss-date",
        now.format_iso8601().parse().map_err(|_| fail())?,
    );
    parts
        .headers
        .insert("date", now.format_http_date().parse().map_err(|_| fail())?);
    parts.headers.insert(
        "x-oss-content-sha256",
        http::HeaderValue::from_static("UNSIGNED-PAYLOAD"),
    );
    if let Some(token) = credential
        .security_token
        .as_deref()
        .filter(|v| !v.is_empty())
    {
        let mut value: http::HeaderValue = token.parse().map_err(|_| fail())?;
        value.set_sensitive(true);
        parts.headers.insert("x-oss-security-token", value);
    }
    let path = canonical_path(parts.uri.path());
    let path_style = parts.uri.host().is_some_and(|h| {
        h.trim_matches(['[', ']'])
            .parse::<std::net::IpAddr>()
            .is_ok()
    });
    let path = if path_style {
        path
    } else {
        format!("/{}{path}", super::percent(bucket))
    };
    // Object requests have no query or additional signed-header overrides.
    if parts.uri.query().is_some() {
        return Err(fail());
    }
    let mut names: Vec<_> = parts
        .headers
        .keys()
        .filter(|k| {
            k.as_str().starts_with("x-oss-") || matches!(k.as_str(), "content-type" | "content-md5")
        })
        .collect();
    names.sort_unstable_by_key(|k| k.as_str());
    let mut headers = String::new();
    for name in names {
        headers.push_str(name.as_str());
        headers.push(':');
        let values = parts
            .headers
            .get_all(name)
            .iter()
            .map(|v| v.to_str().map(str::trim))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| fail())?;
        headers.push_str(&values.join(","));
        headers.push('\n');
    }
    let canonical = format!("{}\n{path}\n\n{headers}\n\nUNSIGNED-PAYLOAD", parts.method);
    let date = now.format_date();
    let scope = format!("{date}/{region}/oss/aliyun_v4_request");
    let to_sign = format!(
        "OSS4-HMAC-SHA256\n{}\n{scope}\n{}",
        now.format_iso8601(),
        hex_sha256(canonical.as_bytes())
    );
    let key = hmac_sha256(
        format!("aliyun_v4{}", credential.access_key_secret).as_bytes(),
        date.as_bytes(),
    );
    let key = hmac_sha256(&key, region.as_bytes());
    let key = hmac_sha256(&key, b"oss");
    let key = hmac_sha256(&key, b"aliyun_v4_request");
    let signature = hex_hmac_sha256(&key, to_sign.as_bytes());
    let mut value: http::HeaderValue = format!(
        "OSS4-HMAC-SHA256 Credential={}/{scope},Signature={signature}",
        credential.access_key_id
    )
    .parse()
    .map_err(|_| fail())?;
    value.set_sensitive(true);
    parts.headers.insert("authorization", value);
    Ok(())
}

// URL path escapes differ from OSS's escapePath (notably '+', ':', and '@').
// Preserve already encoded bytes while escaping all other non-unreserved bytes.
fn canonical_path(path: &str) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(path.len());
    let mut bytes = path.bytes().peekable();
    while let Some(b) = bytes.next() {
        if b == b'%' {
            let a = bytes.next();
            let c = bytes.next();
            if let (Some(a), Some(c)) = (a, c)
                && a.is_ascii_hexdigit()
                && c.is_ascii_hexdigit()
            {
                out.push('%');
                out.push(char::from(a.to_ascii_uppercase()));
                out.push(char::from(c.to_ascii_uppercase()));
                continue;
            }
            // reqwest::Url produces valid escapes for metering keys.
            out.push_str("%25");
            if let Some(a) = a {
                let _ = write!(out, "%{a:02X}");
            }
            if let Some(c) = c {
                let _ = write!(out, "%{c:02X}");
            }
        } else if b.is_ascii_alphanumeric() || matches!(b, b'/' | b'-' | b'_' | b'.' | b'~') {
            out.push(char::from(b));
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}
