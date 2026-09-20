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
use std::{
    future::Future,
    sync::atomic::{AtomicU32, Ordering},
    time::Duration,
};

pub(crate) struct Retry {
    new_2026: bool,
    tokens: AtomicU32,
}

pub(crate) struct Failure {
    error: reqsign_core::Error,
    retryable: bool,
    timeout: bool,
    throttle: bool,
}
impl Failure {
    pub(crate) fn terminal(error: reqsign_core::Error) -> Self {
        Self {
            error,
            retryable: false,
            timeout: false,
            throttle: false,
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
        }
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
        }
    }
}
impl Retry {
    pub(crate) fn new(ctx: &Context) -> Self {
        Self {
            new_2026: ctx.env_var("AWS_NEW_RETRIES_2026").as_deref() == Some("true"),
            tokens: AtomicU32::new(500),
        }
    }
    pub(crate) async fn run<T, F, Fut>(&self, mut operation: F) -> reqsign_core::Result<T>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = Result<T, Failure>>,
    {
        let mut previous_cost = 0;
        for attempt in 1..=3 {
            let failure = match operation().await {
                Ok(value) => {
                    // Legacy SDK refunds the successful retry's cost plus one;
                    // the 2026 policy only adds one on first-attempt success.
                    let refund = previous_cost + u32::from(!self.new_2026 || attempt == 1);
                    let _ = self
                        .tokens
                        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                            Some(v.saturating_add(refund).min(500))
                        });
                    return Ok(value);
                }
                Err(failure) => failure,
            };
            if attempt == 3 || !failure.retryable {
                return Err(failure.error);
            }
            let cost = if self.new_2026 {
                if failure.throttle { 5 } else { 14 }
            } else if failure.timeout {
                10
            } else {
                5
            };
            if self
                .tokens
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                    v.checked_sub(cost)
                })
                .is_err()
            {
                return Err(reqsign_core::Error::credential_invalid(
                    "AWS credential retry quota exhausted",
                ));
            }
            previous_cost = cost;
            let mut random = [0; 8];
            getrandom::getrandom(&mut random)
                .map_err(|_| reqsign_core::Error::unexpected("AWS retry delay unavailable"))?;
            // Same 53-bit [0,1) distribution as the Go crypto-random helper.
            let low = u32::from_le_bytes([random[0], random[1], random[2], random[3]]);
            let high = u32::from_le_bytes([random[4], random[5], random[6], random[7]]) & 0x1f_ffff;
            let fraction =
                (f64::from(high) * 4_294_967_296.0 + f64::from(low)) / 9_007_199_254_740_992.0;
            tokio::time::sleep(self.delay(attempt, failure.throttle, fraction)).await;
        }
        unreachable!("three-attempt loop always returns")
    }
    fn delay(&self, attempt: u8, throttle: bool, fraction: f64) -> Duration {
        if self.new_2026 {
            let base = if throttle { 1.0 } else { 0.05 };
            Duration::from_secs_f64(fraction * (base * 2_f64.powi(i32::from(attempt))).min(20.0))
        } else if attempt > 4 {
            // The pinned legacy implementation caps before drawing jitter once
            // attempt exceeds floor(log2(maxBackoffSeconds)).
            Duration::from_secs(20)
        } else {
            Duration::from_secs_f64(fraction * 2_f64.powi(i32::from(attempt)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pinned_legacy_and_2026_delay_formulas() {
        for new in [false, true] {
            let retry = Retry {
                new_2026: new,
                tokens: AtomicU32::new(500),
            };
            assert_eq!(
                retry.delay(1, false, 0.5),
                Duration::from_secs_f64(if new { 0.05 } else { 1.0 })
            );
            assert_eq!(
                retry.delay(2, false, 0.5),
                Duration::from_secs_f64(if new { 0.1 } else { 2.0 })
            );
            assert_eq!(retry.delay(1, true, 0.5), Duration::from_secs(1));
            assert_eq!(
                retry.delay(5, true, 0.5),
                Duration::from_secs(if new { 10 } else { 20 })
            );
        }
    }
}
