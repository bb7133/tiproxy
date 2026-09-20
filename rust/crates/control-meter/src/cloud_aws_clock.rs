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

//! STS v1.38.0 carries Date-derived skew between attempts, not operations.

use bytes::Bytes;
use http::{Response, request::Parts};
use reqsign_aws_core::signing::{
    canonical_request_string, canonicalize_headers, canonicalize_query,
};
use reqsign_aws_v4::Credential;
use reqsign_core::hash::{hex_hmac_sha256, hex_sha256, hmac_sha256};
use reqsign_core::{SigningRequest, time::Timestamp};
use std::sync::atomic::{AtomicI64, Ordering};

#[derive(Default)]
pub(crate) struct Skew(AtomicI64);
impl Skew {
    // Missing metadata (including a transport failure) resets the next attempt.
    pub(crate) fn take(&self) -> i64 {
        self.0.swap(0, Ordering::Relaxed)
    }
    pub(crate) fn observe(&self, response: &Response<Bytes>) {
        let skew = response
            .headers()
            .get("date")
            .and_then(|v| v.to_str().ok())
            .and_then(parse_http_date)
            .map_or(0, |server| {
                let now = Timestamp::now();
                let nanos = (i128::from(server.as_second()) - i128::from(now.as_second()))
                    * 1_000_000_000
                    + i128::from(server.subsec_nanosecond())
                    - i128::from(now.subsec_nanosecond());
                i64::try_from(nanos).unwrap_or(if nanos < 0 { i64::MIN } else { i64::MAX })
            });
        self.0.store(skew, Ordering::Relaxed);
    }
}

pub(crate) fn signing_time(skew: i64) -> Timestamp {
    let now = Timestamp::now();
    let duration = std::time::Duration::from_nanos(skew.unsigned_abs());
    if skew < 0 {
        now - duration
    } else {
        now + duration
    }
}

/// Header-only STS `SigV4` using the same public canonicalization primitives as
/// reqsign's `RequestSigner`. Its timestamp override is cfg(test)-only, so the
/// production adapter supplies the corrected timestamp explicitly here.
pub(crate) fn sign_at(
    parts: &mut Parts,
    credential: &Credential,
    region: &str,
    now: Timestamp,
) -> reqsign_core::Result<()> {
    let mut request = SigningRequest::build(parts)?;
    canonicalize_headers(&mut request, credential, None, now)?;
    let query = canonicalize_query(&request, &[]);
    let canonical = canonical_request_string(&request, &query)?;
    let date = now.format_date();
    let scope = format!("{date}/{region}/sts/aws4_request");
    let message = format!(
        "AWS4-HMAC-SHA256\n{}\n{scope}\n{}",
        now.format_iso8601(),
        hex_sha256(canonical.as_bytes())
    );
    let key = hmac_sha256(
        format!("AWS4{}", credential.secret_access_key).as_bytes(),
        date.as_bytes(),
    );
    let key = hmac_sha256(&key, region.as_bytes());
    let key = hmac_sha256(&key, b"sts");
    let key = hmac_sha256(&key, b"aws4_request");
    let signature = hex_hmac_sha256(&key, message.as_bytes());
    let mut auth = http::HeaderValue::from_str(&format!(
        "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={}, Signature={signature}",
        credential.access_key_id,
        request.header_name_to_vec_sorted().join(";")
    ))
    .map_err(|_| reqsign_core::Error::credential_invalid("AWS STS signing failed"))?;
    auth.set_sensitive(true);
    request.headers.insert(http::header::AUTHORIZATION, auth);
    request.apply(parts)
}

/// Smithy's HTTP date layouts: IMF-fixdate (one/two digit day and two/four
/// digit year), RFC850 and ANSIC. The weekday is syntactic, as in Go time.Parse.
fn parse_http_date(value: &str) -> Option<Timestamp> {
    if value.trim() != value || value.contains(['\t', '\r', '\n']) {
        return None;
    }
    let fields: Vec<_> = value.split(' ').filter(|s| !s.is_empty()).collect();
    let short = |v: &str| {
        ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
            .iter()
            .any(|name| name.eq_ignore_ascii_case(v))
    };
    let long = |v: &str| {
        [
            "Monday",
            "Tuesday",
            "Wednesday",
            "Thursday",
            "Friday",
            "Saturday",
            "Sunday",
        ]
        .iter()
        .any(|name| name.eq_ignore_ascii_case(v))
    };
    let (day, month, year, time) = match fields.as_slice() {
        [weekday, day, month, year, time, "GMT"] if short(weekday.strip_suffix(',')?) => {
            (*day, *month, *year, *time)
        }
        [weekday, date, time, zone]
            if long(weekday.strip_suffix(',')?)
                && zone.chars().all(|c| c.is_ascii_uppercase())
                && (3..=5).contains(&zone.len()) =>
        {
            let mut parts = date.split('-');
            let values = (parts.next()?, parts.next()?, parts.next()?, *time);
            if parts.next().is_some() || values.2.len() != 2 || values.0.len() != 2 {
                return None;
            }
            values
        }
        [weekday, month, day, time, year] if short(weekday) && year.len() == 4 => {
            (*day, *month, *year, *time)
        }
        _ => return None,
    };
    if !(1..=2).contains(&day.len()) || !(year.len() == 2 || year.len() == 4) {
        return None;
    }
    if !day.bytes().all(|v| v.is_ascii_digit()) || !year.bytes().all(|v| v.is_ascii_digit()) {
        return None;
    }
    let day: u8 = day.parse().ok()?;
    let month = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ]
    .iter()
    .position(|m| m.eq_ignore_ascii_case(month))?
        + 1;
    let mut number: u16 = year.parse().ok()?;
    if year.len() == 2 {
        number += if number >= 69 { 1900 } else { 2000 };
    }
    let time = time.replace(',', ".");
    let mut clock = time.split(':');
    let hour = clock.next()?;
    let minute = clock.next()?;
    let second = clock.next()?;
    if clock.next().is_some() || !(1..=2).contains(&hour.len()) || minute.len() != 2 {
        return None;
    }
    let (second, fraction) = second.split_once('.').map_or((second, ""), |(s, f)| (s, f));
    if second.len() != 2
        || [hour, minute, second, fraction]
            .iter()
            .any(|v| !v.bytes().all(|c| c.is_ascii_digit()))
    {
        return None;
    }
    let hour: u8 = hour.parse().ok()?;
    let minute: u8 = minute.parse().ok()?;
    let second: u8 = second.parse().ok()?;
    if hour > 23 || minute > 59 || second > 59 || (time.contains('.') && fraction.is_empty()) {
        return None;
    }
    let fraction = &fraction[..fraction.len().min(9)];
    let fraction = if fraction.is_empty() {
        String::new()
    } else {
        format!(".{fraction}")
    };
    format!("{number:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}{fraction}Z")
        .parse()
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    #[test]
    fn http_dates_and_fixed_time_signatures_match_actual_go() {
        #[derive(Deserialize)]
        struct Date {
            input: String,
            seconds: i64,
            nanos: i32,
            error: bool,
        }
        #[derive(Deserialize)]
        struct Signature {
            url: String,
            body: String,
            token: String,
            time: String,
            authorization: String,
        }
        #[derive(Deserialize)]
        struct Fixture {
            dates: Vec<Date>,
            signatures: Vec<Signature>,
        }
        let fixture: Fixture =
            serde_json::from_str(include_str!("../testdata/aws-sts-clock-go.json"))
                .unwrap_or_else(|e| unreachable!("{e}"));
        for date in fixture.dates {
            let parsed = parse_http_date(&date.input);
            assert_eq!(parsed.is_none(), date.error, "{}", date.input);
            if let Some(parsed) = parsed {
                assert_eq!(
                    (parsed.as_second(), parsed.subsec_nanosecond()),
                    (date.seconds, date.nanos),
                    "{}",
                    date.input
                );
            }
        }
        for row in fixture.signatures {
            let req = http::Request::post(&row.url)
                .header("content-length", row.body.len())
                .header("content-type", "application/x-www-form-urlencoded")
                .header("x-amz-content-sha256", hex_sha256(row.body.as_bytes()))
                .body(())
                .unwrap_or_else(|e| unreachable!("{e}"));
            let (mut parts, ()) = req.into_parts();
            let value = row.time;
            let at: Timestamp = format!(
                "{}-{}-{}T{}:{}:{}Z",
                &value[..4],
                &value[4..6],
                &value[6..8],
                &value[9..11],
                &value[11..13],
                &value[13..15]
            )
            .parse()
            .unwrap_or_else(|e| unreachable!("{e}"));
            sign_at(
                &mut parts,
                &Credential {
                    access_key_id: "key".into(),
                    secret_access_key: "secret".into(),
                    session_token: (!row.token.is_empty()).then_some(row.token),
                    expires_in: None,
                },
                "us-east-1",
                at,
            )
            .unwrap_or_else(|e| unreachable!("{e}"));
            assert_eq!(parts.headers["authorization"], row.authorization);
        }
    }
}
