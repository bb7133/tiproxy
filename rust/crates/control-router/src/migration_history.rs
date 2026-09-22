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

//! Process-level cumulative migration history.
//!
//! Pending migrations belong to a router: when an incarnation is destroyed its
//! in-flight work genuinely no longer exists, so counting zero is right.
//! Settled ones are the opposite. `migrate_total` and
//! `migrate_duration_seconds` are cumulative, and a cumulative series must
//! never fall. Holding them on the router meant that destroying an
//! incarnation dropped its history, producing a spurious counter reset or a
//! series that disappears outright.
//!
//! So the two cumulative families live here, outside any router, written once
//! per settled terminal and never decremented.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use crate::factors::RedirectReason;

/// Go `MigrateDurationHistogram`: `ExponentialBuckets(0.0001, 2, 26)`.
///
/// Kept here because the exposition is read from this state rather than
/// accumulated from notifications, and a histogram cannot be rebuilt from a
/// count and a sum. `dataplane` asserts its own copy equals this one.
pub const MIGRATE_DURATION_BUCKETS: [f64; 26] = {
    let mut buckets = [0.0; 26];
    let mut index = 0;
    let mut value = 0.000_1;
    while index < 26 {
        buckets[index] = value;
        value *= 2.0;
        index += 1;
    }
    buckets
};

/// Ceiling on retained label sets, applied per family.
///
/// This bounds only what is *remembered for metrics*. Reaching it must never
/// refuse or delay a real migration: a settlement whose label set cannot be
/// retained is still a completed settlement.
pub const MAX_RETAINED_LABEL_SETS: usize = 4096;

/// `migrate_total` key: Go labels it `(from, to, reason, migrate_res)`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct TerminalKey {
    /// Source backend address.
    pub from: String,
    /// Destination backend address.
    pub to: String,
    /// Reason frozen when the redirect was issued.
    pub reason: RedirectReason,
    /// Whether the migration succeeded.
    pub succeeded: bool,
}

/// `migrate_duration_seconds` key: Go labels it `(from, migrate_res, to)` with
/// **no reason**, so migrations that differ only by reason merge into one
/// series here rather than producing one series per reason.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct DurationKey {
    /// Source backend address.
    pub from: String,
    /// Destination backend address.
    pub to: String,
    /// Whether the migration succeeded.
    pub succeeded: bool,
}

/// One duration series: Prometheus needs the buckets, not just a mean.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DurationSeries {
    /// Observation count.
    pub count: u64,
    /// Summed latency in nanoseconds.
    pub sum_nanos: u128,
    /// Cumulative bucket counts over [`MIGRATE_DURATION_BUCKETS`].
    pub buckets: [u64; 26],
}

/// A read-only copy of the cumulative history.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MigrationHistorySnapshot {
    /// Settled migration counts per (from, to, reason, result).
    pub terminals: BTreeMap<TerminalKey, u64>,
    /// Duration series per (from, to, result), reasons merged.
    pub durations: BTreeMap<DurationKey, DurationSeries>,
    /// Label sets ever seen, so a series that has returned to zero keeps
    /// being reported instead of vanishing between scrapes.
    pub known_pending: BTreeSet<(String, String, RedirectReason)>,
    /// Backend addresses ever seen holding a connection. Go's `Set` creates
    /// the child and it stays, so an address that drops to no connections
    /// must keep reporting zero rather than disappear from the exposition.
    pub known_backends: BTreeSet<String>,
    /// Label sets refused because a retained map was full.
    pub labels_dropped: u64,
}

/// Cumulative migration history shared by every router in the process.
#[derive(Debug, Default)]
pub struct MigrationHistory {
    state: Mutex<MigrationHistorySnapshot>,
}

impl MigrationHistory {
    /// Notes that a label set exists, so its pending series keeps reporting
    /// zero after the migration ends. Returns whether the label set is
    /// retained.
    ///
    /// This is the single admission decision for the whole metric: a caller
    /// that tracks per-label state must track exactly the sets this accepts.
    /// Two independent ceilings would each keep their own arbitrary first
    /// 4096, and a label retained here could then be refused there, losing a
    /// real pending count for a series that is still being exposed.
    pub fn remember(&self, from: &str, to: &str, reason: RedirectReason) -> bool {
        let mut state = self.lock();
        let key = (from.to_owned(), to.to_owned(), reason);
        if state.known_pending.contains(&key) {
            return true;
        }
        if state.known_pending.len() >= MAX_RETAINED_LABEL_SETS {
            state.labels_dropped = state.labels_dropped.saturating_add(1);
            return false;
        }
        state.known_pending.insert(key);
        true
    }

    /// Notes a backend address that holds a connection, so its series keeps
    /// reporting zero once the connections go away. Returns whether it is
    /// retained.
    ///
    /// This is `b_conn`'s own retained set, separate from the migration label
    /// sets: they are different families and admit independently, sharing
    /// only the same ceiling constant and the same drop counter. What must
    /// agree is every path touching *this* set -- registration, aggregation,
    /// zero retention and capacity all follow this one decision.
    pub fn remember_backend(&self, address: &str) -> bool {
        let mut state = self.lock();
        if state.known_backends.contains(address) {
            return true;
        }
        if state.known_backends.len() >= MAX_RETAINED_LABEL_SETS {
            state.labels_dropped = state.labels_dropped.saturating_add(1);
            return false;
        }
        state.known_backends.insert(address.to_owned());
        true
    }

    /// Go `metrics.DelBackend`, for the families this history owns.
    ///
    /// Go matches `backend`, `from` and `to` alike, so a retired address is
    /// dropped from `b_conn`'s retained set and from every migration label
    /// set naming it at either end -- pending sets, terminal counters and
    /// duration series.
    ///
    /// **Metric state only.** The routers' ledgers are untouched: a
    /// migration in flight between a retired address and another keeps
    /// running and keeps settling, exactly as Go's redirect does after its
    /// series are deleted. The counters simply restart from zero if the
    /// address earns a series again, which for a counter is ordinary
    /// Prometheus behaviour after a delete.
    ///
    /// A series returns only through a real write event -- a connection
    /// landing, a redirect issued or settled. A scrape must not resurrect
    /// one, which is why the read paths consult the retained sets instead of
    /// admitting on their own.
    pub fn forget_backend(&self, address: &str) {
        let mut state = self.lock();
        state.known_backends.remove(address);
        state
            .known_pending
            .retain(|(from, to, _)| from != address && to != address);
        state
            .terminals
            .retain(|key, _| key.from != address && key.to != address);
        state
            .durations
            .retain(|key, _| key.from != address && key.to != address);
    }

    /// Whether this address was admitted to the retained set.
    ///
    /// The read path consults this rather than admitting on its own: one
    /// decision was already made when the connection landed, and a refused
    /// address must stay out of the exposition instead of being reinserted by
    /// a later aggregation.
    #[must_use]
    pub fn knows_backend(&self, address: &str) -> bool {
        self.lock().known_backends.contains(address)
    }

    /// Records one settled migration. Called exactly once per `Applied`
    /// terminal; a duplicate or late settlement is `Ignored` upstream and
    /// never reaches here.
    pub fn settle(
        &self,
        from: &str,
        to: &str,
        reason: RedirectReason,
        succeeded: bool,
        elapsed: Duration,
    ) {
        let mut state = self.lock();
        let terminal = TerminalKey {
            from: from.to_owned(),
            to: to.to_owned(),
            reason,
            succeeded,
        };
        if state.terminals.contains_key(&terminal)
            || state.terminals.len() < MAX_RETAINED_LABEL_SETS
        {
            *state.terminals.entry(terminal).or_default() += 1;
        } else {
            state.labels_dropped = state.labels_dropped.saturating_add(1);
        }

        let duration = DurationKey {
            from: from.to_owned(),
            to: to.to_owned(),
            succeeded,
        };
        if !state.durations.contains_key(&duration)
            && state.durations.len() >= MAX_RETAINED_LABEL_SETS
        {
            state.labels_dropped = state.labels_dropped.saturating_add(1);
            return;
        }
        let series = state.durations.entry(duration).or_default();
        series.count = series.count.saturating_add(1);
        series.sum_nanos = series.sum_nanos.saturating_add(elapsed.as_nanos());
        let seconds = elapsed.as_secs_f64();
        for (count, bound) in series.buckets.iter_mut().zip(MIGRATE_DURATION_BUCKETS) {
            if seconds <= bound {
                *count = count.saturating_add(1);
            }
        }
    }

    /// A copy of the history, for the exposition to read.
    #[must_use]
    pub fn snapshot(&self) -> MigrationHistorySnapshot {
        self.lock().clone()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, MigrationHistorySnapshot> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// The migration families answer Go's `DelBackend` for their own series.
impl control_topology::BackendRetirementSink for MigrationHistory {
    fn retire_backend(&self, address: &str) {
        self.forget_backend(address);
    }
}

#[cfg(test)]
mod retirement_tests {
    use super::*;
    use crate::factors::Factor;

    fn conn() -> RedirectReason {
        RedirectReason::Balance(Factor::Connection)
    }

    /// Go's `DelBackend` matches `backend`, `from` and `to`, so a retired
    /// address is dropped wherever it appears -- not only where it is the
    /// subject.
    #[test]
    fn retiring_an_address_drops_every_series_naming_it_at_either_end() {
        let history = MigrationHistory::default();
        assert!(history.remember_backend("gone:4000"));
        assert!(history.remember_backend("kept:4000"));
        assert!(history.remember("gone:4000", "kept:4000", conn()));
        assert!(history.remember("kept:4000", "gone:4000", conn()));
        assert!(history.remember("kept:4000", "other:4000", conn()));
        history.settle(
            "gone:4000",
            "kept:4000",
            conn(),
            true,
            Duration::from_millis(1),
        );
        history.settle(
            "kept:4000",
            "gone:4000",
            conn(),
            false,
            Duration::from_millis(2),
        );
        history.settle(
            "kept:4000",
            "other:4000",
            conn(),
            true,
            Duration::from_millis(3),
        );

        history.forget_backend("gone:4000");

        let snapshot = history.snapshot();
        assert!(!snapshot.known_backends.contains("gone:4000"));
        assert!(
            snapshot.known_backends.contains("kept:4000"),
            "retiring one address must not disturb another"
        );
        assert!(
            snapshot
                .known_pending
                .iter()
                .all(|(from, to, _)| from != "gone:4000" && to != "gone:4000"),
            "a pending label set naming the address at either end is gone"
        );
        assert!(
            snapshot
                .terminals
                .keys()
                .all(|key| key.from != "gone:4000" && key.to != "gone:4000")
        );
        assert!(
            snapshot
                .durations
                .keys()
                .all(|key| key.from != "gone:4000" && key.to != "gone:4000")
        );
        // The untouched pair survives intact, so this is a delete and not a
        // wipe.
        assert_eq!(snapshot.known_pending.len(), 1);
        assert_eq!(snapshot.terminals.len(), 1);
        assert_eq!(snapshot.durations.len(), 1);
    }

    /// Go recreates a deleted child on the next write. A retirement must
    /// therefore not be permanent -- but only a real metric write may bring
    /// the series back, never a scrape.
    #[test]
    fn a_retired_address_returns_only_through_a_write() {
        let history = MigrationHistory::default();
        assert!(history.remember_backend("back:4000"));
        history.forget_backend("back:4000");

        assert!(
            !history.knows_backend("back:4000"),
            "the read path must not re-admit a retired address"
        );
        assert!(history.snapshot().known_backends.is_empty());

        assert!(history.remember_backend("back:4000"));
        assert!(history.knows_backend("back:4000"));
    }

    /// Retirement frees capacity, because Go's delete does.
    #[test]
    fn retirement_returns_the_capacity_it_took() {
        let history = MigrationHistory::default();
        for index in 0..MAX_RETAINED_LABEL_SETS {
            assert!(history.remember_backend(&format!("a{index}:4000")));
        }
        assert!(!history.remember_backend("overflow:4000"));
        assert_eq!(history.snapshot().labels_dropped, 1);

        history.forget_backend("a0:4000");
        assert!(
            history.remember_backend("overflow:4000"),
            "the slot a retired address held is usable again"
        );
        assert_eq!(
            history.snapshot().labels_dropped,
            1,
            "the earlier refusal stays counted; it really did happen"
        );
    }
}
