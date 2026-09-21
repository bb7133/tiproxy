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

//! Which elections this process currently owns: Go's `server_owner`.
//!
//! Go sets the gauge to `1` on election and **deletes the child** on
//! retirement rather than setting it to `0`, with the comment that a retired
//! owner should not show on Grafana at all. A series therefore exists only
//! while this process holds that election, which makes the family a set of
//! held elections rather than a map of values -- and is why this stores a
//! set.
//!
//! The label is the etcd key with `/tiproxy/` and `/owner` trimmed off, so
//! `/tiproxy/metric_reader/z1/owner` is reported as `metric_reader/z1`.

use std::collections::BTreeSet;
use std::sync::{Mutex, MutexGuard, PoisonError};

/// Go `ownerKeyPrefix`.
const OWNER_KEY_PREFIX: &str = "/tiproxy/";
/// Go `ownerKeySuffix`.
const OWNER_KEY_SUFFIX: &str = "/owner";

/// Maximum distinct elections retained, mirroring the other families' bound.
pub const MAX_RETAINED_ELECTIONS: usize = 4096;

/// Go `election.trimedKey`: the label this process reports an election under.
#[must_use]
pub fn election_label(key: &str) -> String {
    key.strip_prefix(OWNER_KEY_PREFIX)
        .unwrap_or(key)
        .strip_suffix(OWNER_KEY_SUFFIX)
        .unwrap_or_else(|| key.strip_prefix(OWNER_KEY_PREFIX).unwrap_or(key))
        .to_owned()
}

/// A read-only copy of the currently held elections.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OwnerSnapshot {
    /// One entry per election this process owns right now. Each renders as
    /// `1`; an election not held has no series at all.
    pub owned: BTreeSet<String>,
    /// Elections refused because the retained set was full.
    pub labels_dropped: u64,
}

/// The elections this process holds.
#[derive(Debug, Default)]
pub struct ElectionOwnerHistory {
    state: Mutex<OwnerSnapshot>,
}

impl ElectionOwnerHistory {
    /// Creates an empty history.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Go `onElected`: this process won `key`.
    pub fn won(&self, key: &str) {
        let label = election_label(key);
        let mut state = self.lock();
        if state.owned.contains(&label) {
            return;
        }
        if state.owned.len() >= MAX_RETAINED_ELECTIONS {
            state.labels_dropped = state.labels_dropped.saturating_add(1);
            return;
        }
        state.owned.insert(label);
    }

    /// Go `onRetired`: the series is **deleted**, not zeroed.
    ///
    /// Reporting a retired owner as `0` would be a different statement -- "we
    /// are contesting this and losing" rather than "this is not ours to
    /// report" -- and is exactly what Go's comment says it does not want on
    /// the dashboard.
    pub fn retired(&self, key: &str) {
        self.lock().owned.remove(&election_label(key));
    }

    /// The elections held right now.
    #[must_use]
    pub fn snapshot(&self) -> OwnerSnapshot {
        self.lock().clone()
    }

    fn lock(&self) -> MutexGuard<'_, OwnerSnapshot> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Go trims a fixed prefix and suffix; it does not parse the middle.
    #[test]
    fn the_label_is_the_key_with_the_fixed_prefix_and_suffix_trimmed() {
        assert_eq!(
            election_label("/tiproxy/metric_reader/owner"),
            "metric_reader"
        );
        assert_eq!(
            election_label("/tiproxy/metric_reader/z1/owner"),
            "metric_reader/z1"
        );
        assert_eq!(
            election_label("/tiproxy/metric_reader/c1/z1/owner"),
            "metric_reader/c1/z1"
        );
        assert_eq!(election_label("/tiproxy/vip/eth0/owner"), "vip/eth0");
        // Neither affix present: Go's TrimPrefix/TrimSuffix are no-ops, and
        // the raw key is what it would label.
        assert_eq!(election_label("odd-key"), "odd-key");
    }

    /// The label must come from the very key the campaign runs on.
    ///
    /// `b_status` was shipped labelled with an internal identifier because
    /// the fixture typed the expected label by hand on both sides and never
    /// touched the function that derives it. This composes the two real
    /// functions -- the campaign's `election_name` and the metric's
    /// `election_label` -- so a change to either that breaks the pairing
    /// fails here rather than in production.
    #[test]
    fn the_label_is_derived_from_the_key_the_campaign_uses() {
        use crate::metric_owner::election_name;

        // Go's four documented shapes, from backend_reader.go:40-43.
        for (cluster, zone, expected) in [
            ("", "", "metric_reader"),
            ("default", "", "metric_reader"),
            ("", "z1", "metric_reader/z1"),
            ("c1", "", "metric_reader/c1"),
            ("c1", "z1", "metric_reader/c1/z1"),
        ] {
            let key = election_name(cluster, zone);
            assert_eq!(
                election_label(&key),
                expected,
                "cluster={cluster:?} zone={zone:?} produced key {key:?}"
            );
            assert!(
                !election_label(&key).starts_with('/'),
                "a raw etcd key must never reach a metric label"
            );
        }
    }

    /// The series exists while held and is gone once retired -- never zero.
    #[test]
    fn retiring_deletes_the_series_rather_than_zeroing_it() {
        let history = ElectionOwnerHistory::new();
        history.won("/tiproxy/metric_reader/owner");
        history.won("/tiproxy/vip/eth0/owner");
        assert_eq!(
            history.snapshot().owned,
            ["metric_reader".to_owned(), "vip/eth0".to_owned()]
                .into_iter()
                .collect()
        );

        history.retired("/tiproxy/metric_reader/owner");
        assert_eq!(
            history.snapshot().owned,
            ["vip/eth0".to_owned()].into_iter().collect(),
            "a retired election leaves no series behind, not a zero"
        );
    }

    /// Winning twice without an intervening retirement is idempotent, and
    /// retiring something never held is not an error.
    #[test]
    fn repeated_transitions_are_idempotent() {
        let history = ElectionOwnerHistory::new();
        history.won("/tiproxy/metric_reader/owner");
        history.won("/tiproxy/metric_reader/owner");
        assert_eq!(history.snapshot().owned.len(), 1);
        history.retired("/tiproxy/metric_reader/owner");
        history.retired("/tiproxy/metric_reader/owner");
        assert!(history.snapshot().owned.is_empty());
        assert_eq!(history.snapshot().labels_dropped, 0);
    }
}
