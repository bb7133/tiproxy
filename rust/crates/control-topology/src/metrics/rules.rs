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

//! Fixed Go routing metric expressions and their backend history functions.

use super::{Sample, ValueKind};
use std::collections::BTreeMap;

/// One untyped exposition point (TYPE/HELP comments are filtered by Go).
#[derive(Clone, Debug, PartialEq)]
pub struct MetricPoint {
    /// Labels from the exposition point.
    pub labels: BTreeMap<String, String>,
    /// Raw point value.
    pub value: f64,
}

/// Name-indexed exposition points, retaining their original order.
pub type MetricFamily = BTreeMap<String, Vec<MetricPoint>>;

/// The six fixed queries needed by resource and location policies.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum QueryId {
    /// CPU usage history.
    Cpu,
    /// Resident-memory/quota history.
    Memory,
    /// Failed PD TSO commands.
    FailurePd,
    /// Successful PD TSO commands.
    TotalPd,
    /// `TiKV` RPC backoffs.
    FailureTikv,
    /// `TiKV` requests.
    TotalTikv,
}

/// One fixed expression and backend retention contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QuerySpec {
    /// Stable query key.
    pub id: QueryId,
    /// `PromQL` template; `{label}` is tried as job then component.
    pub promql: &'static str,
    /// Prometheus range in milliseconds (zero means instant).
    pub range_ms: i64,
    /// Backend history retention in milliseconds.
    pub retention_ms: i64,
    /// Result shape.
    pub kind: ValueKind,
    /// Required backend metric names.
    pub names: &'static [&'static str],
}

const CPU: &[&str] = &["process_cpu_seconds_total", "tidb_server_maxprocs"];
const MEMORY: &[&str] = &[
    "process_resident_memory_bytes",
    "tidb_server_memory_quota_bytes",
];
const FAILURE_PD: &[&str] = &["pd_client_cmd_handle_failed_cmds_duration_seconds_count"];
const TOTAL_PD: &[&str] = &["pd_client_cmd_handle_cmds_duration_seconds_count"];
const FAILURE_TIKV: &[&str] = &["tidb_tikvclient_backoff_seconds_count"];
const TOTAL_TIKV: &[&str] = &["tidb_tikvclient_request_seconds_count"];

/// Returns the fixed query catalog in stable order.
#[must_use]
pub fn query_catalog() -> [QuerySpec; 6] {
    [
        QuerySpec {
            id: QueryId::Cpu,
            promql: "irate(process_cpu_seconds_total{{label}=\"tidb\"}[30s])/tidb_server_maxprocs",
            range_ms: 60_000,
            retention_ms: 60_000,
            kind: ValueKind::Matrix,
            names: CPU,
        },
        QuerySpec {
            id: QueryId::Memory,
            promql: "process_resident_memory_bytes{{label}=\"tidb\"}/tidb_server_memory_quota_bytes",
            range_ms: 60_000,
            retention_ms: 60_000,
            kind: ValueKind::Matrix,
            names: MEMORY,
        },
        QuerySpec {
            id: QueryId::FailurePd,
            promql: "sum(increase(pd_client_cmd_handle_failed_cmds_duration_seconds_count{type=\"tso\"}[2m])) by (instance)",
            range_ms: 0,
            retention_ms: 120_000,
            kind: ValueKind::Vector,
            names: FAILURE_PD,
        },
        QuerySpec {
            id: QueryId::TotalPd,
            promql: "sum(increase(pd_client_cmd_handle_cmds_duration_seconds_count{type=\"tso\"}[2m])) by (instance)",
            range_ms: 0,
            retention_ms: 120_000,
            kind: ValueKind::Vector,
            names: TOTAL_PD,
        },
        QuerySpec {
            id: QueryId::FailureTikv,
            promql: "sum(increase(tidb_tikvclient_backoff_seconds_count{type=\"tikvRPC\"}[2m])) by (instance)",
            range_ms: 0,
            retention_ms: 120_000,
            kind: ValueKind::Vector,
            names: FAILURE_TIKV,
        },
        QuerySpec {
            id: QueryId::TotalTikv,
            promql: "sum(increase(tidb_tikvclient_request_seconds_count[2m])) by (instance)",
            range_ms: 0,
            retention_ms: 120_000,
            kind: ValueKind::Vector,
            names: TOTAL_TIKV,
        },
    ]
}

impl QuerySpec {
    /// Go range endpoints and 15-second step for a bounded query clock.
    /// Instant queries have no range.
    ///
    /// # Errors
    /// Rejects an end time whose subtraction cannot fit Unix milliseconds.
    pub fn window(self, end_ms: i64) -> Result<Option<(i64, i64, i64)>, super::MetricError> {
        if self.range_ms == 0 {
            return Ok(None);
        }
        let start = end_ms
            .checked_sub(self.range_ms)
            .ok_or(super::MetricError::Invalid)?;
        Ok(Some((start, end_ms, 15_000)))
    }

    /// Query spellings in Go's attempt order. The returned list is fresh on
    /// every round; a successful component query does not rewrite the catalog.
    #[must_use]
    pub fn expressions(self) -> Vec<String> {
        if self.promql.contains("{label}") {
            vec![
                self.promql.replace("{label}", "job"),
                self.promql.replace("{label}", "component"),
            ]
        } else {
            vec![self.promql.to_owned()]
        }
    }
}

impl QueryId {
    /// The existing Go registry key and shared-history JSON key.
    #[must_use]
    pub const fn key(self) -> &'static str {
        match self {
            Self::Cpu => "cpu",
            Self::Memory => "memory",
            Self::FailurePd => "failure_pd",
            Self::TotalPd => "total_pd",
            Self::FailureTikv => "failure_tikv",
            Self::TotalTikv => "total_tikv",
        }
    }

    /// Decodes a fixed registry key. Unknown shared histories are retained by
    /// History but do not become query rules.
    #[must_use]
    pub fn from_key(key: &str) -> Option<Self> {
        query_catalog()
            .iter()
            .find(|spec| spec.id.key() == key)
            .map(|spec| spec.id)
    }

    /// Gets this query's immutable expression/retention description.
    #[must_use]
    pub fn spec(self) -> QuerySpec {
        query_catalog()
            .into_iter()
            .find(|spec| spec.id == self)
            .unwrap_or_else(|| unreachable!("all QueryId variants have a spec"))
    }

    /// Applies Go's `Metric2Value`, including first-point division and integer
    /// truncation of the type-labelled error counters.
    #[must_use]
    #[allow(clippy::cast_possible_truncation, clippy::cast_precision_loss)]
    pub fn metric_value(self, metrics: &MetricFamily) -> f64 {
        let spec = self.spec();
        if spec.names.iter().any(|name| !metrics.contains_key(*name)) {
            return f64::NAN;
        }
        if matches!(self, Self::Cpu | Self::Memory) {
            let value = |name: &str| {
                metrics
                    .get(name)
                    .and_then(|values| values.first())
                    .map_or(f64::NAN, |point| point.value)
            };
            return value(spec.names[0]) / value(spec.names[1]);
        }
        let filter = match self {
            Self::FailurePd | Self::TotalPd => "tso",
            Self::FailureTikv => "tikvRPC",
            _ => "",
        };
        // Go's int conversion is defined here only for finite in-range counters;
        // unsupported non-finite/overflowing error counters do not add a sample.
        let mut total = 0i64;
        for point in &metrics[spec.names[0]] {
            if point
                .labels
                .get("type")
                .is_some_and(|kind| filter.is_empty() || kind == filter)
            {
                if !point.value.is_finite()
                    || point.value < i64::MIN as f64
                    || point.value >= -(i64::MIN as f64)
                {
                    return f64::NAN;
                }
                let Some(sum) = total.checked_add(point.value as i64) else {
                    return f64::NAN;
                };
                total = sum;
            }
        }
        total as f64
    }

    /// Applies Go's `Range2Value` (backend history, not `PromQL` extrapolation).
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn range_value(self, pairs: &[Sample]) -> f64 {
        let Some(last) = pairs.last() else {
            return f64::NAN;
        };
        if self == Self::Memory {
            return last.value;
        }
        if pairs.len() < 2 {
            return f64::NAN;
        }
        if self == Self::Cpu {
            for pair in pairs[..pairs.len() - 1].iter().rev() {
                let seconds =
                    (i128::from(last.timestamp_ms) - i128::from(pair.timestamp_ms)) as f64 / 1000.0;
                if seconds < 1.0 {
                    continue;
                }
                if pair.value > last.value {
                    return f64::NAN;
                }
                return (last.value - pair.value) / seconds;
            }
            f64::NAN
        } else {
            let diff = last.value - pairs[0].value;
            if diff < 0.0 { f64::NAN } else { diff }
        }
    }
}
