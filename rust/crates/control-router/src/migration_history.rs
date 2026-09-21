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
    /// zero after the migration ends.
    pub(crate) fn remember(&self, from: &str, to: &str, reason: RedirectReason) {
        let mut state = self.lock();
        let key = (from.to_owned(), to.to_owned(), reason);
        if state.known_pending.contains(&key) {
            return;
        }
        if state.known_pending.len() >= MAX_RETAINED_LABEL_SETS {
            state.labels_dropped = state.labels_dropped.saturating_add(1);
            return;
        }
        state.known_pending.insert(key);
    }

    /// Records one settled migration. Called exactly once per `Applied`
    /// terminal; a duplicate or late settlement is `Ignored` upstream and
    /// never reaches here.
    pub(crate) fn settle(
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
