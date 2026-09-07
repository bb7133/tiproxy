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

//! Restart-pinned health-check config → validated runtime policy (CP-TOPO #213-3).
//!
//! The module is constructed with an explicit, restart-pinned
//! [`HealthCheckConfig`] and converts it here ONCE, at startup, into a validated
//! [`HealthRuntime`]. The conversion is total and fail-closed: every numeric field
//! it consumes (`interval`, `max_retries`, `retry_interval`, `dial_timeout`) is
//! range-checked in EVERY mode — a disabled runtime still needs a valid cadence
//! for its all-healthy zero-I/O rounds, and an invalid dial timeout is rejected
//! even with no cluster to build — so a malformed pinned config is a loud startup
//! rejection rather than a silent default.
//!
//! `enabled` only selects whether a per-probe [`HttpProbePolicy`] is carried (and
//! thus whether any resolver / TLS / socket is ever constructed); it never
//! suppresses validation. The health policy is a restart-pinned PROCESS input
//! owned by the module, not a configuration generation: there is no runtime
//! setter and no snapshot/update path, so it is fixed for the process lifetime by
//! this ownership seam. `metrics_*` is not consumed by #213.

use std::time::Duration;

use control_config::HealthCheckConfig;
use control_external::HttpProbePolicy;
use thiserror::Error;

use crate::health_loop::{HealthPolicy, HealthPolicyError};

/// A validated, restart-pinned health runtime.
///
/// It ALWAYS carries a valid [`HealthPolicy`] (the loop cadence and retry budget),
/// used even when disabled to drive the all-healthy zero-I/O cadence. `probe` is
/// `Some` only when health is enabled, carrying the validated per-probe policy
/// used to build each cluster's network; `None` means disabled, so no resolver,
/// TLS, or socket is ever constructed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct HealthRuntime {
    policy: HealthPolicy,
    probe: Option<HttpProbePolicy>,
}

impl HealthRuntime {
    /// Validates and converts a restart-pinned [`HealthCheckConfig`].
    ///
    /// # Errors
    ///
    /// Returns a [`HealthConfigError`] when any consumed numeric field is not a
    /// positive, in-range duration (or the retry count is above its bound). This
    /// holds in every mode: a `disabled` config with an invalid interval, retry,
    /// or dial timeout is still rejected.
    pub(crate) fn from_config(config: &HealthCheckConfig) -> Result<Self, HealthConfigError> {
        let interval =
            positive_duration(config.interval_nanos).ok_or(HealthConfigError::InvalidInterval)?;
        let retry_interval = positive_duration(config.retry_interval_nanos)
            .ok_or(HealthConfigError::InvalidRetryInterval)?;
        let policy =
            HealthPolicy::new(interval, config.max_retries, retry_interval).map_err(|error| {
                match error {
                    HealthPolicyError::InvalidInterval => HealthConfigError::InvalidInterval,
                    HealthPolicyError::InvalidRetryInterval => {
                        HealthConfigError::InvalidRetryInterval
                    }
                    HealthPolicyError::TooManyRetries => HealthConfigError::TooManyRetries,
                }
            })?;
        // The dial timeout is validated in EVERY mode (disabled or zero-cluster
        // included) through the single shared `HttpProbePolicy` validator, so there
        // is one source of truth for the attempt-timeout bound.
        let dial = positive_duration(config.dial_timeout_nanos)
            .ok_or(HealthConfigError::InvalidDialTimeout)?;
        let probe_policy =
            HttpProbePolicy::validated(dial).map_err(|_| HealthConfigError::InvalidDialTimeout)?;
        Ok(Self {
            policy,
            probe: config.enabled.then_some(probe_policy),
        })
    }

    /// The validated loop policy (cadence + retry budget), valid in every mode.
    pub(crate) fn policy(&self) -> HealthPolicy {
        self.policy
    }

    /// The per-probe policy when health is enabled, or `None` when disabled (no
    /// network is ever constructed for a disabled runtime).
    pub(crate) fn probe_policy(&self) -> Option<HttpProbePolicy> {
        self.probe
    }
}

/// Why a restart-pinned [`HealthCheckConfig`] could not be validated.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum HealthConfigError {
    /// The health-check interval is not a positive, in-range duration.
    #[error("health check interval is not a positive, in-range duration")]
    InvalidInterval,
    /// The health-check retry interval is not a positive, in-range duration.
    #[error("health check retry interval is not a positive, in-range duration")]
    InvalidRetryInterval,
    /// The health-check retry count is above its bound.
    #[error("health check retry count is above its bound")]
    TooManyRetries,
    /// The health-check dial timeout is not a positive, in-range duration.
    #[error("health check dial timeout is not a positive, in-range duration")]
    InvalidDialTimeout,
}

/// Converts a signed nanosecond count to a `Duration`, rejecting a non-positive
/// value. The upper bound is enforced by the downstream validators
/// ([`HealthPolicy::new`] and [`HttpProbePolicy::validated`]), so there is no
/// duplicated ceiling constant here.
fn positive_duration(nanos: i64) -> Option<Duration> {
    u64::try_from(nanos)
        .ok()
        .filter(|value| *value > 0)
        .map(Duration::from_nanos)
}

#[cfg(test)]
mod tests {
    use control_config::HealthCheckConfig;

    use super::{HealthConfigError, HealthRuntime};

    const SECOND: i64 = 1_000_000_000;

    /// One validation case: a field mutator and the exact error it must produce.
    type Case = (fn(&mut HealthCheckConfig), HealthConfigError);

    /// A valid, enabled restart-pinned config: 3s interval / 3 retries / 1s retry
    /// interval / 2s dial timeout — the values every consumed field is bounded by.
    fn valid() -> HealthCheckConfig {
        HealthCheckConfig {
            enabled: true,
            interval_nanos: 3 * SECOND,
            max_retries: 3,
            retry_interval_nanos: SECOND,
            dial_timeout_nanos: 2 * SECOND,
            metrics_interval_nanos: 5 * SECOND,
            metrics_timeout_nanos: 3 * SECOND,
        }
    }

    #[test]
    fn a_valid_enabled_config_carries_a_probe_policy() -> Result<(), HealthConfigError> {
        let runtime = HealthRuntime::from_config(&valid())?;
        assert!(
            runtime.probe_policy().is_some(),
            "an enabled config carries a per-probe policy (a network is constructed)"
        );
        // The loop policy is always present; reading it must not panic.
        let _ = runtime.policy();
        Ok(())
    }

    #[test]
    fn a_valid_disabled_config_has_no_probe_but_still_a_valid_policy()
    -> Result<(), HealthConfigError> {
        let mut config = valid();
        config.enabled = false;
        let runtime = HealthRuntime::from_config(&config)?;
        assert!(
            runtime.probe_policy().is_none(),
            "a disabled config carries NO probe policy (no resolver/TLS/socket ever built)"
        );
        // A disabled runtime still needs a valid cadence for its all-healthy rounds.
        let _ = runtime.policy();
        Ok(())
    }

    /// Every consumed numeric field is range-checked in EVERY mode: a disabled
    /// config with an invalid interval, retry interval, retry count, or dial
    /// timeout is STILL rejected — disabled is not a validation bypass.
    #[test]
    fn every_numeric_field_is_validated_in_both_modes() {
        let cases: [Case; 10] = [
            (|c| c.interval_nanos = 0, HealthConfigError::InvalidInterval),
            (
                |c| c.interval_nanos = -1,
                HealthConfigError::InvalidInterval,
            ),
            (
                |c| c.interval_nanos = 3601 * SECOND,
                HealthConfigError::InvalidInterval,
            ),
            (
                |c| c.retry_interval_nanos = 0,
                HealthConfigError::InvalidRetryInterval,
            ),
            (
                |c| c.retry_interval_nanos = -1,
                HealthConfigError::InvalidRetryInterval,
            ),
            (
                |c| c.retry_interval_nanos = 601 * SECOND,
                HealthConfigError::InvalidRetryInterval,
            ),
            (|c| c.max_retries = 101, HealthConfigError::TooManyRetries),
            (
                |c| c.dial_timeout_nanos = 0,
                HealthConfigError::InvalidDialTimeout,
            ),
            (
                |c| c.dial_timeout_nanos = -1,
                HealthConfigError::InvalidDialTimeout,
            ),
            (
                |c| c.dial_timeout_nanos = 301 * SECOND,
                HealthConfigError::InvalidDialTimeout,
            ),
        ];
        for (mutate, expected) in cases {
            for enabled in [true, false] {
                let mut config = valid();
                config.enabled = enabled;
                mutate(&mut config);
                assert_eq!(
                    HealthRuntime::from_config(&config),
                    Err(expected),
                    "enabled={enabled}: the malformed field must be rejected as {expected:?}"
                );
            }
        }
    }
}
