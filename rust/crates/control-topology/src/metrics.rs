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

//! Bounded query/history data core for CP-ROUTE #221.
//!
//! These values carry data, never routing or election authority. The staged
//! collector must qualify them with an applied-source capability before use.
//! No I/O, background collection, health verdict, or routing policy is enabled
//! by this module.

mod decode;
mod history;
mod rules;

pub use decode::{decode_backend, decode_owner_history, decode_prometheus};
pub use history::{BackendHistory, History, ReaderState, Source};
pub use rules::{MetricFamily, MetricPoint, QueryId, QuerySpec, query_catalog};

use std::collections::BTreeMap;

/// Maximum wire response size; matches the external HTTP boundary.
pub const MAX_BYTES: usize = 16 * 1024 * 1024;
/// Maximum distinct series or history entries in one cluster.
pub const MAX_SERIES: usize = 100_000;
/// Maximum retained sample pairs across all rules in one cluster.
pub const MAX_SAMPLES: usize = 1_000_000;
/// Maximum labels in a single series.
pub const MAX_LABELS: usize = 128;
/// Maximum bytes in a metric token or label.
pub const MAX_TOKEN: usize = 4096;

/// A payload-free decoding or capacity failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum MetricError {
    /// Input or resulting history exceeded a documented capacity.
    #[error("metric input exceeds a capacity limit")]
    Limit,
    /// The response did not match the supported wire format.
    #[error("invalid metric response")]
    Invalid,
    /// Prometheus returned an unsuccessful response.
    #[error("prometheus query failed")]
    QueryFailed,
}

/// One value with the original millisecond timestamp (not the fetch time).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Sample {
    /// Original sample timestamp in Unix milliseconds.
    pub timestamp_ms: i64,
    /// IEEE value; NaN and infinities retain their Go metric semantics.
    pub value: f64,
}

/// The two result shapes used by the six routing queries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ValueKind {
    /// One latest sample per series.
    Vector,
    /// Historical samples per series.
    Matrix,
}

/// One metric series; ordering is retained for first-match Go lookup.
#[derive(Clone, Debug, PartialEq)]
pub struct Series {
    /// Original label set, including producer-added cluster identity.
    pub labels: BTreeMap<String, String>,
    /// One sample for vectors, zero or more for matrices.
    pub samples: Vec<Sample>,
}

/// A complete query response, without any source authority.
#[derive(Clone, Debug, PartialEq)]
pub struct QueryResult {
    /// Vector or matrix shape.
    pub kind: ValueKind,
    /// Original result order (duplicate matching series use the first).
    pub series: Vec<Series>,
    /// Reader update time in Unix nanoseconds, independent of millisecond samples.
    /// `None` is Go's year-one zero time; `Some(0)` is the Unix epoch.
    /// Keep sub-millisecond changes: Go factors compare exact update times.
    pub updated_nanos: Option<i64>,
}

impl QueryResult {
    /// Go Empty checks the number of series, not whether their samples exist.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.series.is_empty()
    }

    /// Overwrites the cluster label as both Go producers do.
    pub fn attach_cluster(&mut self, cluster: &str) {
        let name = cluster_label(cluster);
        for series in &mut self.series {
            series.labels.insert("tiproxy_cluster".into(), name.clone());
        }
    }

    /// Finds the first matching series, accepting an absent cluster label.
    #[must_use]
    pub fn samples_for(&self, instance: &str, cluster: &str) -> Option<&[Sample]> {
        let cluster = cluster_label(cluster);
        self.series
            .iter()
            .find(|series| {
                series
                    .labels
                    .get("instance")
                    .is_some_and(|label| label == instance)
                    && series
                        .labels
                        .get("tiproxy_cluster")
                        .is_none_or(|label| label == &cluster)
            })
            .map(|series| series.samples.as_slice())
    }

    /// Concatenates nonempty results with Go's maximum update time.
    ///
    /// Per-sample age is deliberately unchanged. An active sibling cluster
    /// therefore keeps the global factor expiry gate open, as in Go.
    ///
    /// # Errors
    /// Returns a capacity error, or Invalid for inconsistent query shapes.
    pub fn merge(results: impl IntoIterator<Item = Self>) -> Result<Option<Self>, MetricError> {
        let mut merged: Option<Self> = None;
        let mut count = 0usize;
        for result in results.into_iter().filter(|result| !result.is_empty()) {
            count = count
                .checked_add(
                    result
                        .series
                        .iter()
                        .map(|series| series.samples.len())
                        .sum::<usize>(),
                )
                .ok_or(MetricError::Limit)?;
            if count > MAX_SAMPLES {
                return Err(MetricError::Limit);
            }
            if let Some(merged) = &mut merged {
                if merged.kind != result.kind {
                    return Err(MetricError::Invalid);
                }
                if merged.series.len() + result.series.len() > MAX_SERIES {
                    return Err(MetricError::Limit);
                }
                merged.updated_nanos = merged.updated_nanos.max(result.updated_nanos);
                merged.series.extend(result.series);
            } else {
                if result.series.len() > MAX_SERIES {
                    return Err(MetricError::Limit);
                }
                merged = Some(result);
            }
        }
        Ok(merged)
    }
}

/// Normalizes the cluster metric label exactly as Go's metrics reader.
#[must_use]
pub fn cluster_label(cluster: &str) -> String {
    match cluster.trim() {
        "" => "default".into(),
        name => name.into(),
    }
}

/// Computes the operator pod label or the exact status address label.
#[must_use]
pub fn instance_label(address: &str, ip: &str, status_port: u64) -> String {
    if operator_address(address) {
        address.split('.').next().unwrap_or(address).into()
    } else if ip.contains(':') {
        format!("[{ip}]:{status_port}")
    } else {
        format!("{ip}:{status_port}")
    }
}

pub(super) fn address_label(address: &str) -> String {
    if operator_address(address) {
        address.split('.').next().unwrap_or(address).into()
    } else {
        address.into()
    }
}

fn operator_address(mut address: &str) -> bool {
    for marker in ["-tidb-", ".", "peer", ".svc"] {
        let Some(index) = address.find(marker) else {
            return false;
        };
        address = &address[index + marker.len()..];
    }
    true
}

#[cfg(test)]
mod tests;
