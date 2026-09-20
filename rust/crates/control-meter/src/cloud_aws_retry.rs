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

//! AWS endpoint credential retry policy, including its provider-local quota.

use reqsign_core::Context;
use serde::Deserialize;
use std::{
    future::Future,
    sync::atomic::{AtomicU32, Ordering},
    time::Duration,
};

pub(crate) struct Retry {
    new_2026: bool,
    tokens: AtomicU32,
    imds: bool,
    max_attempts: i64,
    #[cfg(test)]
    zero_backoff: bool,
    adaptive: Option<crate::cloud_aws_adaptive::Limiter>,
}

pub(crate) struct Failure {
    error: reqsign_core::Error,
    retryable: bool,
    timeout: bool,
    throttle: bool,
    status: Option<u16>,
    retry_after: Option<Duration>,
}
impl Failure {
    pub(crate) fn terminal(error: reqsign_core::Error) -> Self {
        Self {
            error,
            retryable: false,
            timeout: false,
            throttle: false,
            status: None,
            retry_after: None,
        }
    }
    pub(crate) fn transport(error: reqsign_core::Error) -> Self {
        use std::error::Error as _;
        let kind = error
            .source()
            .and_then(|v| v.downcast_ref::<crate::cloud_context::HttpFailure>());
        let timeout = matches!(kind, Some(crate::cloud_context::HttpFailure::Timeout));
        let retryable = kind.is_some();
        Self {
            error,
            retryable,
            timeout,
            throttle: false,
            status: None,
            retry_after: None,
        }
    }
    pub(crate) fn imds(response: &http::Response<bytes::Bytes>, metadata: bool) -> Self {
        let status = response.status().as_u16();
        // Go's metadata-401 retryableError does not unwrap ResponseError;
        // only other HTTP failures expose this header to the middleware.
        let retry_after = if metadata && status == 401 {
            None
        } else {
            retry_after(response)
        };
        Self {
            error: reqsign_core::Error::credential_invalid("AWS IMDS request failed"),
            retryable: matches!(status, 500 | 502 | 503 | 504) || (metadata && status == 401),
            timeout: false,
            throttle: false,
            status: Some(status),
            retry_after,
        }
    }
    pub(crate) fn rest_json(response: &http::Response<bytes::Bytes>, sso: bool) -> Self {
        // Service clients retain HTTP status even when deserialization fails;
        // endpointcreds has a different error wrapper (see container).
        let code = rest_error_code(response, sso).unwrap_or_default();
        let mut failure = Self::container(0, &code);
        failure.status = Some(response.status().as_u16());
        failure.retryable |= matches!(response.status().as_u16(), 500 | 502 | 503 | 504);
        failure.error = reqsign_core::Error::credential_invalid("AWS SSO request failed");
        failure.retry_after = retry_after(response);
        failure
    }
    pub(crate) fn sts(response: &http::Response<bytes::Bytes>, web: bool, skew: i64) -> Self {
        #[derive(Default, Deserialize)]
        struct Envelope {
            #[serde(rename = "Error", default)]
            error: ErrorCode,
        }
        #[derive(Default, Deserialize)]
        struct ErrorCode {
            #[serde(rename = "Code", default)]
            code: String,
        }
        let code = std::str::from_utf8(response.body())
            .ok()
            .and_then(|body| quick_xml::de::from_str::<Envelope>(body).ok())
            .map(|v| v.error.code)
            .unwrap_or_default();
        let mut failure = Self::container(0, &code);
        failure.error = reqsign_core::Error::credential_invalid("AWS STS request failed");
        failure.status = Some(response.status().as_u16());
        failure.retryable |= matches!(response.status().as_u16(), 500 | 502 | 503 | 504)
            || (web && code.eq_ignore_ascii_case("InvalidIdentityToken"))
            || matches!(
                code.as_str(),
                "RequestExpired" | "RequestInTheFuture" | "RequestTimeTooSkewed"
            )
            || (skew > 240_000_000_000
                && matches!(
                    code.as_str(),
                    "InvalidSignatureException" | "SignatureDoesNotMatch" | "AuthFailure"
                ));
        failure.retry_after = retry_after(response);
        failure
    }
    pub(crate) fn status(&self) -> Option<u16> {
        self.status
    }
    pub(crate) fn is_transport(&self) -> bool {
        use std::error::Error as _;
        self.error
            .source()
            .is_some_and(<dyn std::error::Error>::is::<crate::cloud_context::HttpFailure>)
    }
    pub(crate) fn into_error(self) -> reqsign_core::Error {
        self.error
    }
    pub(crate) fn container(status: u16, code: &str) -> Self {
        let throttle = matches!(
            code,
            "Throttling"
                | "ThrottlingException"
                | "ThrottledException"
                | "RequestThrottledException"
                | "TooManyRequestsException"
                | "ProvisionedThroughputExceededException"
                | "TransactionInProgressException"
                | "RequestLimitExceeded"
                | "BandwidthLimitExceeded"
                | "LimitExceededException"
                | "RequestThrottled"
                | "SlowDown"
                | "PriorRequestNotComplete"
                | "EC2ThrottledException"
        );
        let retryable = matches!(status, 429 | 500 | 502 | 503 | 504)
            || throttle
            || matches!(code, "RequestTimeout" | "RequestTimeoutException");
        Self {
            error: reqsign_core::Error::credential_invalid("AWS container credential unavailable"),
            retryable,
            timeout: false,
            throttle,
            status: Some(status),
            retry_after: None,
        }
    }
}
impl Retry {
    pub(crate) fn new(ctx: &Context) -> Self {
        Self::configured(ctx, crate::cloud_aws_retry_config::Settings::default())
    }
    pub(crate) fn configured(
        ctx: &Context,
        settings: crate::cloud_aws_retry_config::Settings,
    ) -> Self {
        Self {
            max_attempts: settings.max_attempts,
            #[cfg(test)]
            zero_backoff: false,
            adaptive: settings
                .adaptive
                .then(crate::cloud_aws_adaptive::Limiter::new),
            new_2026: ctx.env_var("AWS_NEW_RETRIES_2026").as_deref() == Some("true"),
            tokens: AtomicU32::new(500),
            imds: false,
        }
    }
    pub(crate) fn imds(ctx: &Context) -> Self {
        Self {
            imds: true,
            ..Self::new(ctx)
        }
    }
    pub(crate) async fn json<T>(
        &self,
        ctx: &Context,
        request: http::Request<bytes::Bytes>,
        sso: bool,
        decode: impl Fn(&[u8]) -> reqsign_core::Result<T>,
    ) -> reqsign_core::Result<T> {
        self.run(|| async {
            let response = ctx
                .http_send(request.clone())
                .await
                .map_err(Failure::transport)?;
            if !response.status().is_success() {
                return Err(Failure::rest_json(&response, sso));
            }
            decode(response.body()).map_err(Failure::terminal)
        })
        .await
    }
    pub(crate) fn attempts(&self) -> Attempts<'_> {
        Attempts {
            policy: self,
            number: 1,
            previous_cost: 0,
        }
    }
    pub(crate) async fn run<T, F, Fut>(&self, operation: F) -> reqsign_core::Result<T>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = Result<T, Failure>>,
    {
        self.run_outcome(operation)
            .await
            .map_err(Failure::into_error)
    }
    pub(crate) async fn run_outcome<T, F, Fut>(&self, mut operation: F) -> Result<T, Failure>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = Result<T, Failure>>,
    {
        let mut attempts = self.attempts();
        loop {
            if let Some(limiter) = &self.adaptive {
                limiter.acquire().await;
            }
            match operation().await {
                Ok(value) => {
                    attempts.success();
                    return Ok(value);
                }
                Err(failure) => attempts.failure(failure).await?,
            }
        }
    }
    fn backoff_index(&self, attempt: u64) -> u64 {
        attempt - u64::from(self.new_2026)
    }
    fn delay(&self, attempt: u64, throttle: bool, fraction: f64) -> Duration {
        #[cfg(test)]
        if self.zero_backoff {
            return Duration::ZERO;
        }
        // SDK middleware uses zero-based backoff indices in 2026 mode.
        let index = self.backoff_index(attempt);
        if self.imds {
            // IMDS replaces the backoff with the legacy 1s-cap helper, even
            // in 2026 mode. Index0 gets jitter; indices1+ get the fixed cap.
            if index == 0 {
                Duration::from_secs_f64(fraction)
            } else {
                Duration::from_secs(1)
            }
        } else if self.new_2026 {
            let base = if throttle { 1.0 } else { 0.05 };
            Duration::from_secs_f64(
                fraction
                    * (base * 2_f64.powi(i32::try_from(index.min(32)).unwrap_or(32))).min(20.0),
            )
        } else if attempt > 4 {
            // The pinned legacy implementation caps before drawing jitter once
            // attempt exceeds floor(log2(maxBackoffSeconds)).
            Duration::from_secs(20)
        } else {
            Duration::from_secs_f64(
                fraction * 2_f64.powi(i32::try_from(index.min(32)).unwrap_or(32)),
            )
        }
    }
}

fn retry_after(response: &http::Response<bytes::Bytes>) -> Option<Duration> {
    response
        .headers()
        .get("x-amz-retry-after")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<i64>().ok())
        .filter(|v| *v >= 0)
        .map(|v| v.wrapping_mul(1_000_000))
        .and_then(|v| u64::try_from(v).ok())
        .map(Duration::from_nanos)
}

// Go REST JSON GetErrorInfo decodes the first value into a struct: folded
// fields, duplicates last-wins, null preserves strings, Code before __type.
#[derive(Default)]
struct RestError {
    code: String,
    kind: String,
}
impl<'de> Deserialize<'de> for RestError {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Fields;
        impl<'de> serde::de::Visitor<'de> for Fields {
            type Value = RestError;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("REST JSON error")
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<RestError, E> {
                Ok(RestError::default())
            }
            fn visit_map<M: serde::de::MapAccess<'de>>(
                self,
                mut map: M,
            ) -> Result<RestError, M::Error> {
                let mut value = RestError::default();
                while let Some(key) = map.next_key::<String>()? {
                    match key.to_ascii_lowercase().as_str() {
                        "code" | "__type" | "message" => {
                            if let Some(text) = map.next_value::<Option<String>>()? {
                                match key.to_ascii_lowercase().as_str() {
                                    "code" => value.code = text,
                                    "__type" => value.kind = text,
                                    _ => {}
                                }
                            }
                        }
                        _ => {
                            let _ = map.next_value::<serde::de::IgnoredAny>()?;
                        }
                    }
                }
                Ok(value)
            }
        }
        d.deserialize_any(Fields)
    }
}
fn rest_error_code(response: &http::Response<bytes::Bytes>, sso: bool) -> Option<String> {
    let body = response.body();
    let error = if body.iter().all(u8::is_ascii_whitespace) {
        RestError::default()
    } else {
        RestError::deserialize(&mut serde_json::Deserializer::from_slice(body)).ok()?
    };
    let header = response
        .headers()
        .get("x-amzn-errortype")
        .and_then(|v| v.to_str().ok())
        .filter(|v| !v.is_empty());
    let raw = header.unwrap_or(if error.code.is_empty() {
        &error.kind
    } else {
        &error.code
    });
    let code = raw.split_once(':').map_or(raw, |v| v.0);
    let code = code.split_once('#').map_or(code, |v| v.1);
    // SSO's modeled exception uses its canonical ErrorCode even if the wire
    // spelling differs in case. OIDC has no modeled TooManyRequestsException.
    Some(
        if sso && code.eq_ignore_ascii_case("TooManyRequestsException") {
            "TooManyRequestsException".into()
        } else {
            code.to_owned()
        },
    )
}

// Mutable metadata negotiation can drive attempts directly while using the
// same quota and cancellation logic as the closure-based container path.
pub(crate) struct Attempts<'a> {
    policy: &'a Retry,
    number: u64,
    previous_cost: u32,
}
impl Attempts<'_> {
    pub(crate) fn success(&self) {
        self.observe(false);
        let refund = self.previous_cost
            + u32::from(
                self.policy.adaptive.is_none() && (!self.policy.new_2026 || self.number == 1),
            );
        let _ = self
            .policy
            .tokens
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                Some(v.saturating_add(refund).min(500))
            });
    }
    fn observe(&self, throttle: bool) {
        if (!self.policy.new_2026 || self.number == 1)
            && let Some(limiter) = &self.policy.adaptive
        {
            limiter.update(throttle);
        }
    }
    pub(crate) async fn failure(&mut self, failure: Failure) -> Result<(), Failure> {
        self.observe(failure.throttle);
        if (self.policy.max_attempts > 0 && self.number >= self.policy.max_attempts.unsigned_abs())
            || !failure.retryable
        {
            return Err(failure);
        }
        let cost = if self.policy.new_2026 {
            if failure.throttle { 5 } else { 14 }
        } else if failure.timeout {
            10
        } else {
            5
        };
        if self
            .policy
            .tokens
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                v.checked_sub(cost)
            })
            .is_err()
        {
            return Err(Failure::terminal(reqsign_core::Error::credential_invalid(
                "AWS credential retry quota exhausted",
            )));
        }
        self.previous_cost = cost;
        let fraction = if self.policy.imds && (!self.policy.new_2026 || self.number > 1) {
            0.0
        } else {
            let mut random = [0; 8];
            getrandom::getrandom(&mut random).map_err(|_| {
                Failure::terminal(reqsign_core::Error::unexpected(
                    "AWS retry delay unavailable",
                ))
            })?;
            let low = u32::from_le_bytes([random[0], random[1], random[2], random[3]]);
            let high = u32::from_le_bytes([random[4], random[5], random[6], random[7]]) & 0x1f_ffff;
            (f64::from(high) * 4_294_967_296.0 + f64::from(low)) / 9_007_199_254_740_992.0
        };
        let mut delay = self.policy.delay(self.number, failure.throttle, fraction);
        if self.policy.new_2026
            && let Some(after) = failure.retry_after
        {
            delay = after.clamp(delay, delay + Duration::from_secs(5));
        }
        tokio::time::sleep(delay).await;
        self.number += 1;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn configured_attempts_adaptive_pacing_and_quota_match_actual_go_middleware() {
        #[derive(Deserialize)]
        struct Row {
            name: String,
            new: bool,
            adaptive: bool,
            max: i64,
            operations: Vec<Operation>,
        }
        #[derive(Deserialize)]
        struct Operation {
            codes: Vec<String>,
            gap_ms: u64,
            attempt_ns: Vec<u64>,
            error: bool,
            tokens: u32,
        }
        let rows: Vec<Row> = serde_json::from_str(include_str!("../testdata/aws-adaptive-go.json"))
            .unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(rows.len(), 20);
        for row in rows {
            let base = tokio::time::Instant::now();
            let retry = Retry {
                new_2026: row.new,
                tokens: AtomicU32::new(500),
                imds: false,
                max_attempts: row.max,
                zero_backoff: true,
                adaptive: row
                    .adaptive
                    .then(|| crate::cloud_aws_adaptive::Limiter::at(1_750_000_000.125)),
            };
            for (index, op) in row.operations.into_iter().enumerate() {
                tokio::time::advance(Duration::from_millis(op.gap_ms)).await;
                let mut observed = Vec::new();
                let result = retry
                    .run(|| {
                        let code = &op.codes[observed.len().min(op.codes.len() - 1)];
                        observed.push(base.elapsed());
                        std::future::ready(if code.is_empty() {
                            Ok(())
                        } else {
                            Err(Failure::container(0, code))
                        })
                    })
                    .await;
                let label = format!(
                    "{} new={} adaptive={} max={} operation={index}",
                    row.name, row.new, row.adaptive, row.max
                );
                assert_eq!(result.is_err(), op.error, "{label}");
                assert_eq!(observed.len(), op.attempt_ns.len(), "{label}");
                assert_eq!(retry.tokens.load(Ordering::Relaxed), op.tokens, "{label}");
                for (actual, expected) in observed.into_iter().zip(op.attempt_ns) {
                    let expected = Duration::from_nanos(expected);
                    let diff = actual.abs_diff(expected);
                    // Tokio timers round to milliseconds; the SDK probe advances
                    // nanoseconds. Permit scheduler quantization, not rate changes.
                    assert!(
                        diff < Duration::from_millis(100),
                        "{label}: actual {actual:?}, Go {expected:?}"
                    );
                }
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn adaptive_wait_is_cancelable_and_isolated_per_client() {
        let retry = Retry::configured(
            &Context::new(),
            crate::cloud_aws_retry_config::Settings {
                max_attempts: 1,
                adaptive: true,
            },
        );
        assert!(
            retry
                .run(|| std::future::ready(Err::<(), _>(Failure::container(0, "Throttling"))))
                .await
                .is_err()
        );
        let called = std::cell::Cell::new(false);
        assert!(
            tokio::time::timeout(
                Duration::from_millis(100),
                retry.run(|| {
                    called.set(true);
                    std::future::ready(Ok(()))
                })
            )
            .await
            .is_err()
        );
        assert!(!called.get());
        let other = Retry::configured(
            &Context::new(),
            crate::cloud_aws_retry_config::Settings {
                max_attempts: 1,
                adaptive: true,
            },
        );
        assert!(
            tokio::time::timeout(
                Duration::from_millis(1),
                other.run(|| std::future::ready(Ok(())))
            )
            .await
            .is_ok()
        );
    }

    #[test]
    fn pinned_legacy_and_2026_delay_formulas() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../testdata/aws-container-retry-go.json"))
                .unwrap_or_else(|e| unreachable!("{e}"));
        for row in fixture["backoffs"]
            .as_array()
            .unwrap_or_else(|| unreachable!())
        {
            let retry = Retry {
                new_2026: row["new"].as_bool().unwrap_or_default(),
                tokens: AtomicU32::new(500),
                imds: false,
                max_attempts: 3,
                zero_backoff: false,
                adaptive: None,
            };
            assert_eq!(
                serde_json::json!([retry.backoff_index(1), retry.backoff_index(2)]),
                row["indices"],
                "actual SDK middleware arguments"
            );
        }
        for new in [false, true] {
            let retry = Retry {
                new_2026: new,
                tokens: AtomicU32::new(500),
                imds: false,
                max_attempts: 3,
                zero_backoff: false,
                adaptive: None,
            };
            assert_eq!(
                retry.delay(1, false, 0.5),
                Duration::from_secs_f64(if new { 0.025 } else { 1.0 })
            );
            assert_eq!(
                retry.delay(2, false, 0.5),
                Duration::from_secs_f64(if new { 0.05 } else { 2.0 })
            );
            assert_eq!(
                retry.delay(1, true, 0.5),
                Duration::from_secs_f64(if new { 0.5 } else { 1.0 })
            );
            assert_eq!(
                retry.delay(5, true, 0.5),
                Duration::from_secs(if new { 8 } else { 20 })
            );
        }
    }
}
