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

//! The retained per-factor backend scores behind Go's `b_score`.
//!
//! Two Go behaviours decide the shape of this, and neither is what
//! "render the latest balance round" would produce:
//!
//! - **The family is sticky.** `BackendScoreGauge.Reset()` lives in
//!   `FactorBasedBalance.SetConfig`, not in `updateScore`, so a backend that
//!   leaves the topology keeps its `(backend, factor)` series until the
//!   configuration changes. Rendering the current round directly would drop
//!   it the moment the backend went away.
//! - **Writes are throttled.** `updateScore` only sets the gauges when
//!   `updateMetricInterval` (10s) has passed since the last time it did, so
//!   Go's value is a sample of the scores, not every round's.
//!
//! What this module owns is therefore a retained map that a caller writes
//! into on Go's cadence, wipes on a configuration change, and deletes from
//! per address when a backend is retired.

use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use crate::factors::Factor;
use crate::migration_history::MAX_RETAINED_LABEL_SETS;

/// Go `updateMetricInterval`: the shortest gap between two score writes.
pub const SCORE_METRIC_INTERVAL: Duration = Duration::from_secs(10);

/// A read-only copy of the retained scores.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ScoreSnapshot {
    /// Latest written score per `(backend address, factor)`.
    pub scores: BTreeMap<(String, Factor), u64>,
    /// Label pairs refused because the retained map was full.
    pub labels_dropped: u64,
}

/// The retained `b_score` values, shared by every router in the process.
#[derive(Debug, Default)]
pub struct ScoreHistory {
    state: Mutex<ScoreSnapshot>,
}

impl ScoreHistory {
    /// Creates an empty history.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records one throttled sample of a backend's factor scores.
    ///
    /// The caller decides when a sample is due; this does not throttle,
    /// because the cadence belongs to the balance loop that produces the
    /// scores, not to the store that holds them.
    pub fn observe(&self, address: &str, factor: Factor, score: u64) {
        let mut state = self.lock();
        let key = (address.to_owned(), factor);
        if let Some(existing) = state.scores.get_mut(&key) {
            *existing = score;
            return;
        }
        if state.scores.len() >= MAX_RETAINED_LABEL_SETS {
            state.labels_dropped = state.labels_dropped.saturating_add(1);
            return;
        }
        state.scores.insert(key, score);
    }

    /// Go `BackendScoreGauge.Reset()` in `SetConfig`: the whole family is
    /// dropped when the balance configuration changes, because the set of
    /// factors itself may have changed and a stale factor's series would
    /// otherwise persist with no producer.
    pub fn reset(&self) {
        self.lock().scores.clear();
    }

    /// Go `DelBackend`, which matches the `backend` label this family uses.
    pub fn forget_backend(&self, address: &str) {
        self.lock().scores.retain(|(kept, _), _| kept != address);
    }

    /// The retained scores.
    #[must_use]
    pub fn snapshot(&self) -> ScoreSnapshot {
        self.lock().clone()
    }

    fn lock(&self) -> MutexGuard<'_, ScoreSnapshot> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// `b_score` answers Go's `DelBackend` for its own series.
impl control_topology::BackendRetirementSink for ScoreHistory {
    fn retire_backend(&self, address: &str) {
        self.forget_backend(address);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Go resets in `SetConfig` alone, so a backend that leaves the topology
    /// keeps its series. Rendering the current balance round would instead
    /// drop it as soon as it stopped being scored.
    #[test]
    fn a_score_is_retained_until_the_configuration_changes() {
        let history = ScoreHistory::new();
        history.observe("10.0.0.1:4000", Factor::Cpu, 3);
        history.observe("10.0.0.2:4000", Factor::Cpu, 7);
        assert_eq!(history.snapshot().scores.len(), 2);

        // A later round that scores only one of them leaves the other alone.
        history.observe("10.0.0.1:4000", Factor::Cpu, 4);
        let snapshot = history.snapshot();
        assert_eq!(
            snapshot.scores[&("10.0.0.1:4000".to_owned(), Factor::Cpu)],
            4
        );
        assert_eq!(
            snapshot.scores[&("10.0.0.2:4000".to_owned(), Factor::Cpu)],
            7,
            "a backend that stopped being scored keeps its last value"
        );

        history.reset();
        assert!(
            history.snapshot().scores.is_empty(),
            "a configuration change drops the whole family, as Go's Reset does"
        );
    }

    /// The retirement deletes by address across every factor, because Go's
    /// `DelBackend` matches the `backend` label wherever it appears.
    #[test]
    fn retiring_a_backend_drops_all_of_its_factors() {
        let history = ScoreHistory::new();
        for factor in [Factor::Cpu, Factor::Memory, Factor::Connection] {
            history.observe("gone:4000", factor, 1);
            history.observe("kept:4000", factor, 2);
        }
        assert_eq!(history.snapshot().scores.len(), 6);

        history.forget_backend("gone:4000");

        let snapshot = history.snapshot();
        assert_eq!(snapshot.scores.len(), 3);
        assert!(
            snapshot
                .scores
                .keys()
                .all(|(address, _)| address == "kept:4000"),
            "every factor of the retired address is gone, and only those"
        );
    }

    /// One admission decision with the same ceiling and the same visible
    /// drop counter as the other retained label sets.
    #[test]
    fn a_full_map_refuses_new_pairs_and_counts_them() {
        let history = ScoreHistory::new();
        for index in 0..MAX_RETAINED_LABEL_SETS {
            history.observe(&format!("a{index}:4000"), Factor::Cpu, 1);
        }
        assert_eq!(history.snapshot().labels_dropped, 0);

        history.observe("overflow:4000", Factor::Cpu, 1);
        let snapshot = history.snapshot();
        assert_eq!(snapshot.scores.len(), MAX_RETAINED_LABEL_SETS);
        assert_eq!(snapshot.labels_dropped, 1);

        // An already-admitted pair stays writable when the map is full.
        history.observe("a0:4000", Factor::Cpu, 9);
        assert_eq!(
            history.snapshot().scores[&("a0:4000".to_owned(), Factor::Cpu)],
            9
        );

        // And retirement frees the slot again.
        history.forget_backend("a0:4000");
        history.observe("overflow:4000", Factor::Cpu, 1);
        assert!(
            history
                .snapshot()
                .scores
                .contains_key(&("overflow:4000".to_owned(), Factor::Cpu))
        );
    }
}
