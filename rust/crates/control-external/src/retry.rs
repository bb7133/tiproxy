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

//! Owner-cancellable bounded retry policy for external calls.

use std::future::Future;
use std::time::Duration;

use control_plane::OwnerToken;
use thiserror::Error;

/// Maximum attempts accepted by one retry policy.
pub const MAX_RETRY_ATTEMPTS: u32 = 32;
const MAX_RETRY_DELAY: Duration = Duration::from_secs(30);

/// Bounded exponential retry settings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetryPolicy {
    max_attempts: u32,
    initial_delay: Duration,
    max_delay: Duration,
}

impl RetryPolicy {
    /// Creates a retry policy with a deterministic two-times backoff.
    ///
    /// # Errors
    ///
    /// Rejects zero/over-bound attempts and zero, reversed, or over-bound
    /// delays.
    pub fn new(
        max_attempts: u32,
        initial_delay: Duration,
        max_delay: Duration,
    ) -> Result<Self, RetryPolicyError> {
        if !(1..=MAX_RETRY_ATTEMPTS).contains(&max_attempts) {
            return Err(RetryPolicyError::InvalidAttempts(max_attempts));
        }
        if initial_delay.is_zero()
            || max_delay.is_zero()
            || initial_delay > max_delay
            || max_delay > MAX_RETRY_DELAY
        {
            return Err(RetryPolicyError::InvalidDelay);
        }
        Ok(Self {
            max_attempts,
            initial_delay,
            max_delay,
        })
    }

    /// Returns the maximum operation invocations, including the first.
    #[must_use]
    pub const fn max_attempts(self) -> u32 {
        self.max_attempts
    }
}

/// Invalid retry policy.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum RetryPolicyError {
    /// Attempt count is outside the bounded range.
    #[error("invalid retry attempt count {0}")]
    InvalidAttempts(u32),
    /// Backoff durations are zero, reversed, or over-bound.
    #[error("invalid retry delay policy")]
    InvalidDelay,
}

/// An operation's explicit retry classification.
#[derive(Debug)]
pub enum RetryDecision<E> {
    /// Do not retry this failure.
    Permanent(E),
    /// Retry this failure while attempts and owner lifetime remain.
    Retryable(E),
}

/// Terminal result from [`retry_bounded`].
#[derive(Debug, Error)]
pub enum RetryError<E>
where
    E: std::error::Error + 'static,
{
    /// The owner was released before or between attempts.
    #[error("stale control owner")]
    StaleOwner,
    /// A permanent failure stopped retries.
    #[error("external operation failed permanently after {attempts} attempts")]
    Permanent {
        /// Number of operation invocations.
        attempts: u32,
        /// Last typed failure.
        #[source]
        source: E,
    },
    /// The bounded attempt budget was consumed.
    #[error("external operation exhausted {attempts} attempts")]
    Exhausted {
        /// Number of operation invocations.
        attempts: u32,
        /// Last typed failure.
        #[source]
        source: E,
    },
}

/// Runs a classified external operation with owner-aware bounded backoff.
///
/// The owner is checked before every call and after every sleep. Dropping the
/// owner therefore stops a retry chain without a background task or leaked
/// timer.
///
/// # Errors
///
/// Returns a stale-owner, permanent, or exhausted typed terminal result.
pub async fn retry_bounded<T, E, F, Fut>(
    owner: &OwnerToken,
    policy: RetryPolicy,
    mut operation: F,
) -> Result<T, RetryError<E>>
where
    E: std::error::Error + 'static,
    F: FnMut(u32) -> Fut,
    Fut: Future<Output = Result<T, RetryDecision<E>>>,
{
    let mut delay = policy.initial_delay;
    for attempt in 1..=policy.max_attempts {
        if !owner.is_current() {
            return Err(RetryError::StaleOwner);
        }
        let result = operation(attempt).await;
        if !owner.is_current() {
            return Err(RetryError::StaleOwner);
        }
        match result {
            Ok(value) => return Ok(value),
            Err(RetryDecision::Permanent(source)) => {
                return Err(RetryError::Permanent {
                    attempts: attempt,
                    source,
                });
            }
            Err(RetryDecision::Retryable(source)) if attempt == policy.max_attempts => {
                return Err(RetryError::Exhausted {
                    attempts: attempt,
                    source,
                });
            }
            Err(RetryDecision::Retryable(_)) => {
                tokio::time::sleep(delay).await;
                delay = delay.saturating_mul(2).min(policy.max_delay);
            }
        }
    }
    unreachable!("validated retry policy always executes at least one attempt")
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::time::Duration;

    use control_plane::{OwnerScope, OwnershipRegistry};

    use super::{RetryDecision, RetryError, RetryPolicy, retry_bounded};

    #[tokio::test]
    async fn retry_is_bounded_and_owner_cancellable() {
        let registry = OwnershipRegistry::new();
        let lease = registry
            .claim(OwnerScope::Process, "owner-A")
            .unwrap_or_else(|error| unreachable!("claim: {error}"));
        let owner = lease.token();
        let policy = RetryPolicy::new(3, Duration::from_millis(1), Duration::from_millis(2))
            .unwrap_or_else(|error| unreachable!("policy: {error}"));
        let exhausted = retry_bounded(&owner, policy, |_| async {
            Err::<(), _>(RetryDecision::Retryable(io::Error::other("retry")))
        })
        .await;
        assert!(matches!(
            exhausted,
            Err(RetryError::Exhausted { attempts: 3, .. })
        ));

        drop(lease);
        let stale = retry_bounded(&owner, policy, |_| async {
            Ok::<_, RetryDecision<io::Error>>(())
        })
        .await;
        assert!(matches!(stale, Err(RetryError::StaleOwner)));
    }

    #[tokio::test]
    async fn successful_result_from_retired_owner_is_rejected() {
        let registry = OwnershipRegistry::new();
        let lease = registry
            .claim(OwnerScope::Process, "owner-A")
            .unwrap_or_else(|error| unreachable!("claim: {error}"));
        let owner = lease.token();
        let policy = RetryPolicy::new(1, Duration::from_millis(1), Duration::from_millis(1))
            .unwrap_or_else(|error| unreachable!("policy: {error}"));
        let mut lease = Some(lease);

        let result = retry_bounded(&owner, policy, |_| {
            let retired = lease
                .take()
                .unwrap_or_else(|| unreachable!("operation executes once"));
            async move {
                drop(retired);
                Ok::<_, RetryDecision<io::Error>>("stale-success")
            }
        })
        .await;

        assert!(matches!(result, Err(RetryError::StaleOwner)));
    }
}
