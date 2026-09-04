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

//! Owned startup rollback for the composition root.
//!
//! Process startup acquires several resources after the first control module is
//! spawned (more modules, the legacy control runtime, the metrics exporter, the
//! metering sampler, the health task). If a later acquisition or readiness check
//! fails, those already-started resources must be stopped and joined in reverse
//! order — each exactly once — rather than leaked as abruptly aborted tasks.
//!
//! This module holds the generic, testable core of that rollback: an
//! [`ArmToken`] whose drop is a bomb (an armed startup that neither committed to
//! the steady-state supervisor nor rolled back is a wiring bug), and
//! [`run_teardowns_in_reverse`], which runs registered teardown futures latest
//! first. The concrete [`crate::StartupGuard`] built from these owns the exact
//! resource handles.

use std::future::Future;
use std::pin::Pin;

/// A teardown future for one acquired resource: stops and joins it.
pub type TeardownFuture = Pin<Box<dyn Future<Output = ()> + Send>>;

/// Runs the registered teardown futures in reverse of registration order —
/// latest-acquired resource first — awaiting each exactly once.
///
/// Returns the labels in the order they were torn down, so a test can assert the
/// reverse ordering deterministically.
pub async fn run_teardowns_in_reverse(
    steps: Vec<(&'static str, TeardownFuture)>,
) -> Vec<&'static str> {
    let mut order = Vec::with_capacity(steps.len());
    for (label, teardown) in steps.into_iter().rev() {
        teardown.await;
        order.push(label);
    }
    order
}

/// Guards against a half-constructed startup being dropped without an explicit
/// outcome. It is armed on creation; the owner must call [`ArmToken::disarm`]
/// exactly once — on the commit path (handing resources to the steady-state
/// supervisor) or after a rollback. Dropping it still armed trips a debug
/// assertion, so a wiring path that forgets to commit or roll back fails loudly
/// in tests and debug builds instead of silently leaking.
#[derive(Debug)]
pub struct ArmToken {
    disposed: bool,
}

impl ArmToken {
    /// Creates an armed token.
    #[must_use]
    pub const fn armed() -> Self {
        Self { disposed: false }
    }

    /// Marks the token disposed. Must be called on every commit and rollback
    /// path exactly once.
    pub const fn disarm(&mut self) {
        self.disposed = true;
    }
}

impl Drop for ArmToken {
    fn drop(&mut self) {
        debug_assert!(
            self.disposed,
            "startup guard dropped while armed: a half-constructed startup \
             neither committed to the supervisor nor rolled back"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::{ArmToken, run_teardowns_in_reverse};
    use std::panic::AssertUnwindSafe;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A teardown that records a stop and a join into shared counters, so a test
    /// can prove each resource was stopped and joined exactly once.
    fn recording_step(
        label: &'static str,
        stop_count: &Arc<AtomicUsize>,
        join_count: &Arc<AtomicUsize>,
    ) -> (&'static str, super::TeardownFuture) {
        let stop_count = Arc::clone(stop_count);
        let join_count = Arc::clone(join_count);
        (
            label,
            Box::pin(async move {
                // A real step stops (signals) then joins (awaits) its resource.
                stop_count.fetch_add(1, Ordering::SeqCst);
                join_count.fetch_add(1, Ordering::SeqCst);
            }),
        )
    }

    // These cover the optional resources the concrete `StartupGuard` runs through
    // this ladder (the legacy runtime, metrics exporter, metering sampler, and
    // health task). The always-present module set and owner are torn down after
    // the ladder by the guard itself; that is covered by the guard's own
    // CP-CFG-ready-failure test.

    #[tokio::test]
    async fn optional_teardowns_run_latest_first_each_stopped_and_joined_once() {
        let stop_count = Arc::new(AtomicUsize::new(0));
        let join_count = Arc::new(AtomicUsize::new(0));
        // The full set of optional resources, in acquisition order — the shape of
        // a mark-ready failure.
        let steps = vec![
            recording_step("legacy_runtime", &stop_count, &join_count),
            recording_step("metrics_exporter", &stop_count, &join_count),
            recording_step("metering_sampler", &stop_count, &join_count),
            recording_step("health_task", &stop_count, &join_count),
        ];
        let order = run_teardowns_in_reverse(steps).await;
        assert_eq!(
            order,
            vec![
                "health_task",
                "metering_sampler",
                "metrics_exporter",
                "legacy_runtime",
            ]
        );
        assert_eq!(
            stop_count.load(Ordering::SeqCst),
            4,
            "each resource stopped once"
        );
        assert_eq!(
            join_count.load(Ordering::SeqCst),
            4,
            "each resource joined once"
        );
    }

    #[tokio::test]
    async fn a_health_bind_failure_tears_down_the_earlier_optionals_without_health() {
        // At a health-bind failure the health task was never spawned, so it is
        // absent; the earlier optionals retire metering, then exporter, then the
        // legacy runtime.
        let stop_count = Arc::new(AtomicUsize::new(0));
        let join_count = Arc::new(AtomicUsize::new(0));
        let steps = vec![
            recording_step("legacy_runtime", &stop_count, &join_count),
            recording_step("metrics_exporter", &stop_count, &join_count),
            recording_step("metering_sampler", &stop_count, &join_count),
        ];
        let order = run_teardowns_in_reverse(steps).await;
        assert_eq!(
            order,
            vec!["metering_sampler", "metrics_exporter", "legacy_runtime"]
        );
        assert_eq!(stop_count.load(Ordering::SeqCst), 3);
        assert_eq!(join_count.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn a_cp_cfg_ready_failure_has_no_optionals_to_tear_down() {
        // At a CP-CFG-ready failure only the module set and owner are live (both
        // torn down by the guard after this ladder), so the ladder is empty.
        let order = run_teardowns_in_reverse(Vec::new()).await;
        assert!(order.is_empty());
    }

    #[test]
    fn a_disarmed_token_drops_cleanly() {
        let mut token = ArmToken::armed();
        token.disarm();
        drop(token);
    }

    #[test]
    fn an_armed_token_dropped_without_disposal_is_a_bomb() {
        // In debug builds the drop bomb fires; catch it so the test can assert it
        // happened rather than aborting the run.
        let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
            let token = ArmToken::armed();
            drop(token);
        }));
        assert!(
            result.is_err(),
            "dropping an armed, undisposed token must trip the bomb"
        );
    }
}
