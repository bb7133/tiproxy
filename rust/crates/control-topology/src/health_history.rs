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

//! Process-level gauge values behind the three backend health families.
//!
//! Go exposes `b_status`, `ping_duration_seconds` and `health_check_seconds`
//! as package-level collectors, so every observer in the process writes into
//! one set of series. This module is that shared destination; the *events*
//! that decide what to write stay with the observer that saw them (see
//! [`crate::health_loop`]), because they are edge-triggered and a
//! process-wide snapshot cannot reconstruct an edge.
//!
//! What lives here is only the last value each series was set to, which is
//! all a gauge exposes. Two observers writing the same address overwrite each
//! other exactly as two Go observers sharing a `GaugeVec` child would.
//!
//! # Publication timing
//!
//! These are read at scrape, but that is not the same as deferring the value.
//! Each write lands at the instant Go's corresponding `Set` call would:
//! `ping_duration_seconds` the moment a dial returns (inside the retry loop,
//! failures included), `b_status` when a round's health result is applied,
//! `health_check_seconds` when a cycle ends. A scrape samples whatever the
//! gauge holds, which is what Prometheus does to Go's registry too.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use control_external::SqlDialObservation;
use tokio::time::Instant;

/// Maximum addresses retained per family.
///
/// Deliberately the same number as the router's migration retention rather
/// than a shared constant: these are different families in a different crate,
/// and sharing the value is a sizing choice, not an invariant that the sets
/// agree.
pub const MAX_RETAINED_BACKENDS: usize = 4096;

/// The latest dial a backend's SQL port reported.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PingSample {
    /// Connect duration in seconds: Go's `ping_duration_seconds` value.
    pub seconds: f64,
    /// The dial's process-monotonic sequence, used to reject an observation
    /// that completed earlier than the one already stored. Concurrent probes
    /// finish out of order, so arrival order is not completion order.
    pub sequence: u64,
}

/// A read-only copy of the three families' current values.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct HealthMetricsSnapshot {
    /// `b_status` per backend: `true` is Go's `1`, `false` its `0`.
    ///
    /// An address is absent until some observer first sees it healthy, which
    /// is why this is not simply "every backend we probed": Go only creates
    /// the child on a healthy-going transition, so a backend that has only
    /// ever been unhealthy has no series at all.
    pub status: BTreeMap<String, bool>,
    /// `ping_duration_seconds` per backend. Unlike `status` this admits every
    /// address that was dialled, healthy or not, because Go sets it from
    /// inside the dial retry loop before any verdict exists.
    pub ping: BTreeMap<String, PingSample>,
    /// `health_check_seconds`: one process-wide value, `None` before the
    /// first cycle completes.
    pub cycle_seconds: Option<f64>,
    /// Addresses refused because a retained map was full.
    pub labels_dropped: u64,
}

/// The shared destination for the backend health gauges.
#[derive(Debug, Default)]
pub struct BackendHealthHistory {
    state: Mutex<HealthMetricsSnapshot>,
}

impl BackendHealthHistory {
    /// Creates an empty history.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a completed SQL-port dial, at Go's `setPingBackendMetrics`
    /// position: immediately after `DialContext` returns, on every attempt
    /// including the failures that will be retried.
    ///
    /// An observation older than the stored one is discarded. `sequence` is
    /// assigned when the dial returns, so this compares completion order, not
    /// the order the observations happened to reach this method.
    pub fn observe_dial(&self, address: &str, dial: &SqlDialObservation) {
        let mut state = self.lock();
        let sample = PingSample {
            seconds: dial.duration.as_secs_f64(),
            sequence: dial.sequence,
        };
        if let Some(existing) = state.ping.get_mut(address) {
            if sample.sequence > existing.sequence {
                *existing = sample;
            }
            return;
        }
        if state.ping.len() >= MAX_RETAINED_BACKENDS {
            state.labels_dropped = state.labels_dropped.saturating_add(1);
            return;
        }
        state.ping.insert(address.to_owned(), sample);
    }

    /// Sets `b_status` for one address, at Go's `updateBackendStatusMetrics`
    /// position inside `updateHealthResult`.
    ///
    /// The caller has already decided that this is a transition; this method
    /// does not infer one. Creating the series is the caller's signal that the
    /// address has been healthy at least once.
    pub fn set_status(&self, address: &str, healthy: bool) {
        let mut state = self.lock();
        if let Some(existing) = state.status.get_mut(address) {
            *existing = healthy;
            return;
        }
        if state.status.len() >= MAX_RETAINED_BACKENDS {
            state.labels_dropped = state.labels_dropped.saturating_add(1);
            return;
        }
        state.status.insert(address.to_owned(), healthy);
    }

    /// Sets `health_check_seconds` at the end of a cycle.
    ///
    /// Go writes this on every iteration of the observer loop, including the
    /// ones where fetching the backend list failed and no health was applied,
    /// so a caller must not gate it on a successful round.
    pub fn set_cycle(&self, seconds: f64) {
        self.lock().cycle_seconds = Some(seconds);
    }

    /// Drops every series keyed by this address, for Go's `DelBackend`.
    ///
    /// Go deletes across all collectors at once when a backend has been down
    /// past the retention window; this covers the families owned here. The
    /// address is free to be admitted again if it comes back, exactly as a
    /// deleted `GaugeVec` child is recreated by the next `Set`.
    pub fn forget_backend(&self, address: &str) {
        let mut state = self.lock();
        state.status.remove(address);
        state.ping.remove(address);
    }

    /// A consistent copy of all three families.
    #[must_use]
    pub fn snapshot(&self) -> HealthMetricsSnapshot {
        self.lock().clone()
    }

    fn lock(&self) -> MutexGuard<'_, HealthMetricsSnapshot> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Go `backendMetricRetention`: how long a backend stays down before its
/// series are deleted.
pub const BACKEND_METRIC_RETENTION: Duration = Duration::from_secs(2 * 60 * 60);

/// One observer's edge-detection state for the backend health gauges.
///
/// The values live in the shared [`BackendHealthHistory`]; the *edges* live
/// here, per observer, because that is where Go keeps them. Two observers
/// watching one address run two independent down-timers and make their own
/// transition decisions, and either one's timer expiring deletes the shared
/// series. Collapsing this into a process-wide healthy/down snapshot would
/// lose the distinction between "just went down" and "has been down", which
/// is the only thing the retention clock is started by.
#[derive(Debug)]
pub struct ObserverHealthMetrics {
    history: Arc<BackendHealthHistory>,
    /// Go `DefaultBackendObserver.curBackends`, narrowed to the healthy bit.
    /// Replaced wholesale by each applied round, so an address missing from a
    /// result leaves this map rather than lingering as stale state.
    current: BTreeMap<String, bool>,
    /// Go `downBackends`: when *this* observer saw each address leave healthy.
    /// Written only on the healthy-to-down edge, so a backend that stays down
    /// keeps its original timestamp and one that was never healthy has no
    /// entry at all.
    down_since: BTreeMap<String, Instant>,
}

impl ObserverHealthMetrics {
    /// Starts an observer with no history of its own, publishing into
    /// `history`.
    #[must_use]
    pub fn new(history: Arc<BackendHealthHistory>) -> Self {
        Self {
            history,
            current: BTreeMap::new(),
            down_since: BTreeMap::new(),
        }
    }

    /// Go `updateHealthResult`: applies one round's whole-map verdict.
    ///
    /// Call this only for a round that produced a verdict. Go returns early
    /// from this function when fetching the backend list failed, leaving
    /// `curBackends` and every `b_status` child untouched -- a failed fetch
    /// never zeroes a backend. It does *not* skip the purge or the cycle
    /// gauge, which is why those are separate calls.
    pub fn apply_round(&mut self, healthy_by_address: &BTreeMap<String, bool>, now: Instant) {
        for (address, healthy) in healthy_by_address {
            if !*healthy {
                continue;
            }
            // Go's first loop: a backend going healthy, whether it is newly
            // seen or recovering. An already-healthy backend is not rewritten.
            if self.current.get(address) != Some(&true) {
                self.history.set_status(address, true);
                self.down_since.remove(address);
            }
        }
        for (address, was_healthy) in &self.current {
            if !*was_healthy {
                continue;
            }
            // Go's second loop: a backend that was healthy and is now either
            // unhealthy or absent from the result entirely.
            if healthy_by_address.get(address) != Some(&true) {
                self.history.set_status(address, false);
                self.down_since.insert(address.clone(), now);
            }
        }
        self.current = healthy_by_address.clone();
    }

    /// Go `purgeBackendMetrics`: retires backends down past the retention
    /// window, returning the addresses retired.
    ///
    /// Runs every cycle, including the ones where the backend list could not
    /// be fetched. A backend that was never healthy has no timer and is never
    /// purged, however long it has been failing. The returned addresses are
    /// for the caller to delete from the families this module does not own;
    /// the ones it does own are already gone.
    pub fn purge(&mut self, now: Instant) -> Vec<String> {
        let expired: Vec<String> = self
            .down_since
            .iter()
            // Go is `ts.Add(retention).Before(now)`: strictly past the window,
            // not merely at it.
            .filter(|(_, since)| **since + BACKEND_METRIC_RETENTION < now)
            .map(|(address, _)| address.clone())
            .collect();
        for address in &expired {
            self.history.forget_backend(address);
            // Go deletes the timer with the series: a backend still down when
            // the next cycle runs must not be purged again every cycle.
            self.down_since.remove(address);
        }
        expired
    }

    /// Go's `HealthCheckCycleGauge.Set` at the bottom of the observer loop.
    ///
    /// Written on every cycle, a failed backend-list fetch included, because
    /// the cycle still happened and still took this long.
    pub fn observe_cycle(&self, elapsed: Duration) {
        self.history.set_cycle(elapsed.as_secs_f64());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round(entries: &[(&str, bool)]) -> BTreeMap<String, bool> {
        entries
            .iter()
            .map(|(address, healthy)| ((*address).to_owned(), *healthy))
            .collect()
    }

    fn observer() -> (Arc<BackendHealthHistory>, ObserverHealthMetrics) {
        let history = Arc::new(BackendHealthHistory::new());
        let observer = ObserverHealthMetrics::new(Arc::clone(&history));
        (history, observer)
    }

    /// Go creates the `b_status` child only in the healthy-going branch, so a
    /// backend that has only ever failed has no series -- not a series at
    /// zero. Reporting it at zero would be indistinguishable from a backend
    /// that was healthy and went down.
    #[tokio::test]
    async fn a_backend_that_has_never_been_healthy_has_no_status_series() {
        let (history, mut observer) = observer();
        let now = Instant::now();

        observer.apply_round(&round(&[("a:4000", false)]), now);
        observer.apply_round(&round(&[("a:4000", false)]), now);

        assert!(
            history.snapshot().status.is_empty(),
            "an address that was never healthy must not appear in b_status"
        );
    }

    /// The two edges Go writes: into healthy (whether first seen or
    /// recovering) and out of healthy (whether unhealthy or gone).
    #[tokio::test]
    async fn the_status_gauge_follows_both_edges() {
        let (history, mut observer) = observer();
        let now = Instant::now();

        observer.apply_round(&round(&[("a:4000", true), ("b:4000", true)]), now);
        assert!(
            history.snapshot().status["a:4000"],
            "a healthy backend is one"
        );
        assert!(
            history.snapshot().status["b:4000"],
            "a healthy backend is one"
        );

        // `a` turns unhealthy; `b` disappears from the result entirely. Go
        // zeroes both, through the same loop.
        observer.apply_round(&round(&[("a:4000", false)]), now);
        assert!(
            !history.snapshot().status["a:4000"],
            "a backend that turned unhealthy is zeroed"
        );
        assert!(
            !history.snapshot().status["b:4000"],
            "a backend that vanished from the result is zeroed, not left at one"
        );

        // Recovery re-enters the healthy branch.
        observer.apply_round(&round(&[("a:4000", true)]), now);
        assert!(
            history.snapshot().status["a:4000"],
            "recovery re-enters the healthy branch"
        );
    }

    /// Go's `updateHealthResult` returns early when the backend list could not
    /// be fetched, so no `b_status` child is written at all. The caller
    /// expresses that by not applying a round; nothing here may decay a value
    /// on its own.
    #[tokio::test]
    async fn skipping_a_round_leaves_every_status_untouched() {
        let (history, mut observer) = observer();
        let now = Instant::now();
        observer.apply_round(&round(&[("a:4000", true)]), now);

        // The cycle still ends and the purge still runs; neither is allowed to
        // disturb a status value.
        observer.observe_cycle(Duration::from_millis(250));
        assert!(observer.purge(now).is_empty());

        assert!(
            history.snapshot().status["a:4000"],
            "a round with no verdict must not zero a healthy backend"
        );
        assert_eq!(history.snapshot().cycle_seconds, Some(0.25));
    }

    /// Go writes `downBackends[addr]` only in the loop guarded by
    /// `oldHealth.Healthy`, so the timer starts on the edge and a backend that
    /// stays down keeps its original timestamp. Refreshing it every cycle
    /// would postpone the purge forever.
    #[tokio::test]
    async fn the_down_timer_starts_on_the_edge_and_is_never_refreshed() {
        let (history, mut observer) = observer();
        let start = Instant::now();

        observer.apply_round(&round(&[("a:4000", true)]), start);
        observer.apply_round(&round(&[("a:4000", false)]), start);
        // Still down an hour later: Go's second loop skips it, because it was
        // not healthy at the start of this round.
        let hour = start + Duration::from_secs(3600);
        observer.apply_round(&round(&[("a:4000", false)]), hour);

        // Measured from the original edge, not from the most recent round.
        let just_past = start + BACKEND_METRIC_RETENTION + Duration::from_secs(1);
        assert_eq!(
            observer.purge(just_past),
            vec!["a:4000".to_owned()],
            "the retention window runs from the edge, so a backend down since the edge is \
             purged even though it was seen down again since"
        );
        assert!(history.snapshot().status.is_empty());
        assert!(history.snapshot().ping.is_empty());
    }

    /// Exactly Go's `ts.Add(retention).Before(now)`: past the window, not at
    /// it.
    #[tokio::test]
    async fn the_window_is_exclusive_and_purges_once() {
        let (_history, mut observer) = observer();
        let start = Instant::now();
        observer.apply_round(&round(&[("a:4000", true)]), start);
        observer.apply_round(&round(&[("a:4000", false)]), start);

        assert!(
            observer.purge(start + BACKEND_METRIC_RETENTION).is_empty(),
            "exactly at the window is not yet past it"
        );
        let past = start + BACKEND_METRIC_RETENTION + Duration::from_nanos(1);
        assert_eq!(observer.purge(past), vec!["a:4000".to_owned()]);
        assert!(
            observer.purge(past).is_empty(),
            "the timer is deleted with the series, so the purge does not repeat every cycle"
        );
    }

    /// A backend that comes back clears its timer, so a later spell down
    /// starts a fresh window rather than inheriting the old one.
    #[tokio::test]
    async fn recovery_clears_the_down_timer() {
        let (_history, mut observer) = observer();
        let start = Instant::now();
        observer.apply_round(&round(&[("a:4000", true)]), start);
        observer.apply_round(&round(&[("a:4000", false)]), start);
        observer.apply_round(&round(&[("a:4000", true)]), start);

        assert!(
            observer
                .purge(start + BACKEND_METRIC_RETENTION * 2)
                .is_empty(),
            "a recovered backend has no timer, however long ago it was down"
        );
    }

    /// The ping series is admitted by the dial, not by a health verdict, so an
    /// address that never became healthy still reports a ping. Only the
    /// status family is gated on having been healthy.
    #[tokio::test]
    async fn a_dial_is_reported_for_a_backend_with_no_status_series() {
        let (history, mut observer) = observer();
        let now = Instant::now();
        history.observe_dial("a:4000", &dial(0.5, 1));
        observer.apply_round(&round(&[("a:4000", false)]), now);

        let snapshot = history.snapshot();
        assert_seconds(snapshot.ping["a:4000"].seconds, 0.5);
        assert!(snapshot.status.is_empty());
    }

    /// Concurrent probes finish out of order, so an observation can arrive
    /// after a newer one. Sequence is the ordering key; arrival is not.
    #[tokio::test]
    async fn an_older_dial_never_overwrites_a_newer_one() {
        let history = BackendHealthHistory::new();
        history.observe_dial("a:4000", &dial(0.2, 7));
        history.observe_dial("a:4000", &dial(9.0, 3));

        assert_seconds(history.snapshot().ping["a:4000"].seconds, 0.2);

        history.observe_dial("a:4000", &dial(0.4, 8));
        assert_seconds(history.snapshot().ping["a:4000"].seconds, 0.4);
    }

    /// A purged address may be admitted again: Go's deleted `GaugeVec` child
    /// is recreated by the next `Set`.
    #[tokio::test]
    async fn a_forgotten_backend_can_come_back() {
        let history = BackendHealthHistory::new();
        history.observe_dial("a:4000", &dial(0.1, 1));
        history.set_status("a:4000", true);
        history.forget_backend("a:4000");
        assert!(history.snapshot().ping.is_empty());
        assert!(history.snapshot().status.is_empty());

        history.set_status("a:4000", true);
        assert!(
            history.snapshot().status["a:4000"],
            "a purged address may be admitted again"
        );
    }

    /// Each family admits independently up to the same ceiling, and every
    /// refusal is counted so the shed is visible rather than silent.
    #[tokio::test]
    async fn a_full_family_refuses_and_counts_the_refusal() {
        let history = BackendHealthHistory::new();
        for index in 0..MAX_RETAINED_BACKENDS {
            history.set_status(&format!("a{index}:4000"), true);
        }
        assert_eq!(history.snapshot().labels_dropped, 0);

        history.set_status("overflow:4000", true);
        let snapshot = history.snapshot();
        assert_eq!(snapshot.status.len(), MAX_RETAINED_BACKENDS);
        assert!(!snapshot.status.contains_key("overflow:4000"));
        assert_eq!(snapshot.labels_dropped, 1);

        // An address already admitted is still writable once the map is full.
        history.set_status("a0:4000", false);
        assert!(
            !history.snapshot().status["a0:4000"],
            "an already-admitted address stays writable when the map is full"
        );
        assert_eq!(history.snapshot().labels_dropped, 1);

        // The ping family has its own room: a full status map does not
        // refuse a dial.
        history.observe_dial("overflow:4000", &dial(0.1, 1));
        assert!(history.snapshot().ping.contains_key("overflow:4000"));
    }

    /// A `Duration` round-trip is not bit-exact for every decimal, so the
    /// gauge value is compared within a tolerance far tighter than any
    /// difference the tests distinguish.
    #[track_caller]
    fn assert_seconds(actual: f64, expected: f64) {
        assert!(
            (actual - expected).abs() < 1e-9,
            "expected {expected}s, got {actual}s"
        );
    }

    fn dial(seconds: f64, sequence: u64) -> SqlDialObservation {
        SqlDialObservation {
            duration: Duration::from_secs_f64(seconds),
            completed_at: Instant::now(),
            sequence,
        }
    }
}
