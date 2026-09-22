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

//! The raw backend observations behind Go's `backend_metric`.
//!
//! Go writes this from the resource and health factors as they take fresher
//! samples, with **no throttle** -- unlike `b_score`, which the same loop
//! rate-limits to one write per ten seconds. There is also no `Reset`: a
//! value stays until it is overwritten or the backend is retired, so the
//! family is retained for the same reason `b_score` is and cleared for
//! fewer.
//!
//! Two of the six values are derived rather than raw. `memory` is
//! `calcMemUsage`'s latest usage and `cpu` is `calcAvgUsage`'s average, both
//! computed from the sample window; the four health values are the samples
//! themselves. Publishing the raw query sample for cpu or memory would
//! report a different number under the same label.

use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard, PoisonError};

use crate::migration_history::MAX_RETAINED_LABEL_SETS;

/// The `metric` label values Go uses, one per observation it publishes.
///
/// A closed set: Go's are string literals on the factor definitions
/// (`factor_health.go:71,99`) and the two resource factors' own names, so an
/// open string here would be a way to invent a label Go cannot produce.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum BackendMetric {
    /// Go `factor_cpu.go`: `calcAvgUsage`'s average, not the latest sample.
    Cpu,
    /// Go `factor_memory.go`: `calcMemUsage`'s latest usage.
    Memory,
    /// Failed PD TSO commands, as sampled.
    FailurePd,
    /// Total PD TSO commands, as sampled.
    TotalPd,
    /// `TiKV` RPC backoffs, as sampled.
    FailureTikv,
    /// Total `TiKV` requests, as sampled.
    TotalTikv,
}

impl BackendMetric {
    /// The exact `metric` label Go writes.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Cpu => "cpu",
            Self::Memory => "memory",
            Self::FailurePd => "failure_pd",
            Self::TotalPd => "total_pd",
            Self::FailureTikv => "failure_tikv",
            Self::TotalTikv => "total_tikv",
        }
    }
}

/// The health indicators' query ids map onto their `metric` labels exactly,
/// which is what lets the publication name the label from the query it just
/// read rather than from a string written beside it.
impl From<control_topology::metrics::QueryId> for BackendMetric {
    fn from(id: control_topology::metrics::QueryId) -> Self {
        use control_topology::metrics::QueryId;
        match id {
            QueryId::Cpu => Self::Cpu,
            QueryId::Memory => Self::Memory,
            QueryId::FailurePd => Self::FailurePd,
            QueryId::TotalPd => Self::TotalPd,
            QueryId::FailureTikv => Self::FailureTikv,
            QueryId::TotalTikv => Self::TotalTikv,
        }
    }
}

/// A read-only copy of the retained observations.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct BackendMetricSnapshot {
    /// Latest published value per `(backend address, metric)`.
    pub values: BTreeMap<(String, BackendMetric), f64>,
    /// Label pairs refused because the retained map was full.
    pub labels_dropped: u64,
}

/// The retained `backend_metric` values, shared across the process.
#[derive(Debug, Default)]
pub struct BackendMetricHistory {
    state: Mutex<BackendMetricSnapshot>,
}

impl BackendMetricHistory {
    /// Creates an empty history.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records one observation, at the point the factor accepted it.
    ///
    /// The caller has already applied Go's guards -- the samples are fresher
    /// than the cached ones, the derived usage is not negative, and the
    /// health samples exist and are not expired. A value that Go skips must
    /// not reach here, because skipping leaves the previous value exposed
    /// rather than replacing it.
    pub fn observe(&self, address: &str, metric: BackendMetric, value: f64) {
        let mut state = self.lock();
        let key = (address.to_owned(), metric);
        if let Some(existing) = state.values.get_mut(&key) {
            *existing = value;
            return;
        }
        if state.values.len() >= MAX_RETAINED_LABEL_SETS {
            state.labels_dropped = state.labels_dropped.saturating_add(1);
            return;
        }
        state.values.insert(key, value);
    }

    /// Go `DelBackend`, which matches the `backend` label this family uses.
    pub fn forget_backend(&self, address: &str) {
        self.lock().values.retain(|(kept, _), _| kept != address);
    }

    /// The retained observations.
    #[must_use]
    pub fn snapshot(&self) -> BackendMetricSnapshot {
        self.lock().clone()
    }

    fn lock(&self) -> MutexGuard<'_, BackendMetricSnapshot> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// `backend_metric` answers Go's `DelBackend` for its own series.
impl control_topology::BackendRetirementSink for BackendMetricHistory {
    fn retire_backend(&self, address: &str) {
        self.forget_backend(address);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The labels are Go's exact strings; a rename here silently renames a
    /// series.
    #[test]
    fn the_labels_are_gos_literals() {
        assert_eq!(BackendMetric::Cpu.label(), "cpu");
        assert_eq!(BackendMetric::Memory.label(), "memory");
        assert_eq!(BackendMetric::FailurePd.label(), "failure_pd");
        assert_eq!(BackendMetric::TotalPd.label(), "total_pd");
        assert_eq!(BackendMetric::FailureTikv.label(), "failure_tikv");
        assert_eq!(BackendMetric::TotalTikv.label(), "total_tikv");
    }

    /// Go never resets this family, so a value stays until it is replaced or
    /// the backend is retired.
    #[test]
    fn a_value_is_retained_until_replaced_or_retired() {
        let history = BackendMetricHistory::new();
        history.observe("10.0.0.1:4000", BackendMetric::Cpu, 0.25);
        history.observe("10.0.0.1:4000", BackendMetric::Memory, 0.5);
        history.observe("10.0.0.2:4000", BackendMetric::Cpu, 0.75);

        history.observe("10.0.0.1:4000", BackendMetric::Cpu, 0.3);
        let snapshot = history.snapshot();
        assert!(
            (snapshot.values[&("10.0.0.1:4000".to_owned(), BackendMetric::Cpu)] - 0.3).abs() < 1e-9
        );
        assert!(
            (snapshot.values[&("10.0.0.2:4000".to_owned(), BackendMetric::Cpu)] - 0.75).abs()
                < 1e-9,
            "another backend's value is untouched"
        );

        history.forget_backend("10.0.0.1:4000");
        let snapshot = history.snapshot();
        assert_eq!(snapshot.values.len(), 1);
        assert!(
            snapshot
                .values
                .keys()
                .all(|(address, _)| address == "10.0.0.2:4000"),
            "retirement drops every metric of that address, and only those"
        );
    }

    /// One admission decision, the same ceiling and the same visible drop
    /// counter as every other retained label set.
    #[test]
    fn a_full_map_refuses_new_pairs_and_counts_them() {
        let history = BackendMetricHistory::new();
        for index in 0..MAX_RETAINED_LABEL_SETS {
            history.observe(&format!("a{index}:4000"), BackendMetric::Cpu, 1.0);
        }
        assert_eq!(history.snapshot().labels_dropped, 0);

        history.observe("overflow:4000", BackendMetric::Cpu, 1.0);
        let snapshot = history.snapshot();
        assert_eq!(snapshot.values.len(), MAX_RETAINED_LABEL_SETS);
        assert_eq!(snapshot.labels_dropped, 1);

        // An admitted pair stays writable when the map is full.
        history.observe("a0:4000", BackendMetric::Cpu, 9.0);
        assert!(
            (history.snapshot().values[&("a0:4000".to_owned(), BackendMetric::Cpu)] - 9.0).abs()
                < 1e-9
        );
    }
}
