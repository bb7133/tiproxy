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

//! Bounded backend histories and source selection, independent of authority.

use super::{
    MAX_SAMPLES, MAX_SERIES, MetricError, MetricFamily, QueryId, QueryResult, Sample, Series,
    ValueKind, address_label, cluster_label,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Go's shared two-step history for one query/backend label.
#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct BackendHistory {
    /// Raw metric-to-value samples.
    #[serde(rename = "Step1History")]
    pub step1: Vec<Sample>,
    /// Range-transformed samples.
    #[serde(rename = "Step2History")]
    pub step2: Vec<Sample>,
}

impl<'de> Deserialize<'de> for BackendHistory {
    fn deserialize<D: serde::Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        struct Fields;
        impl<'de> serde::de::Visitor<'de> for Fields {
            type Value = BackendHistory;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a backend history object")
            }
            fn visit_map<M: serde::de::MapAccess<'de>>(
                self,
                mut map: M,
            ) -> Result<Self::Value, M::Error> {
                let mut history = BackendHistory::default();
                while let Some(key) = map.next_key::<String>()? {
                    if key.eq_ignore_ascii_case("Step1History") {
                        history.step1 =
                            map.next_value::<Option<Vec<Sample>>>()?.unwrap_or_default();
                    } else if key.eq_ignore_ascii_case("Step2History") {
                        history.step2 =
                            map.next_value::<Option<Vec<Sample>>>()?.unwrap_or_default();
                    } else {
                        map.next_value::<serde::de::IgnoredAny>()?;
                    }
                }
                Ok(history)
            }
        }
        decoder.deserialize_map(Fields)
    }
}

/// Cluster-local backend histories. Mutation methods enforce aggregate limits.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct History {
    pub(super) entries: BTreeMap<String, BTreeMap<String, BackendHistory>>,
    series_count: usize,
    sample_count: usize,
}

impl History {
    /// Reads the immutable history map; keys unknown to this reader can arrive
    /// from a Go owner and are retained until the normal purge step.
    #[must_use]
    pub fn entries(&self) -> &BTreeMap<String, BTreeMap<String, BackendHistory>> {
        &self.entries
    }

    pub(super) fn from_entries(
        entries: BTreeMap<String, BTreeMap<String, BackendHistory>>,
    ) -> Result<Self, MetricError> {
        let mut history = Self {
            entries,
            series_count: 0,
            sample_count: 0,
        };
        history.recount()?;
        Ok(history)
    }

    fn recount(&mut self) -> Result<(), MetricError> {
        if self.entries.len() > MAX_SERIES {
            return Err(MetricError::Limit);
        }
        let mut samples = 0usize;
        let mut series = 0usize;
        for backends in self.entries.values() {
            series = series
                .checked_add(backends.len())
                .ok_or(MetricError::Limit)?;
            for history in backends.values() {
                samples = samples
                    .checked_add(history.step1.len())
                    .and_then(|n| n.checked_add(history.step2.len()))
                    .ok_or(MetricError::Limit)?;
            }
        }
        if samples > MAX_SAMPLES || series > MAX_SERIES {
            return Err(MetricError::Limit);
        }
        self.series_count = series;
        self.sample_count = samples;
        Ok(())
    }

    /// Appends one completed backend observation under the currently registered
    /// rules. Missing families and NaN transformations do not create samples.
    ///
    /// # Errors
    /// Capacity failures leave the history unchanged.
    pub fn observe(
        &mut self,
        rules: &[QueryId],
        backend: &str,
        metrics: &MetricFamily,
        now_ms: i64,
    ) -> Result<(), MetricError> {
        if backend.len() > super::MAX_TOKEN {
            return Err(MetricError::Limit);
        }
        let mut changed = Vec::new();
        for &rule in rules.iter().collect::<BTreeSet<_>>() {
            let value = rule.metric_value(metrics);
            if value.is_nan() {
                continue;
            }
            let mut history = self
                .entries
                .get(rule.key())
                .and_then(|entries| entries.get(backend))
                .cloned()
                .unwrap_or_default();
            history.step1.push(Sample {
                timestamp_ms: now_ms,
                value,
            });
            let value = rule.range_value(&history.step1);
            if !value.is_nan() {
                history.step2.push(Sample {
                    timestamp_ms: now_ms,
                    value,
                });
            }
            changed.push((rule.key().to_string(), history));
        }
        // Preflight only the touched entries; avoid cloning the entire cluster
        // for every backend observation.
        let mut added_rules = 0;
        let mut added_series = 0;
        let mut added_samples = 0;
        for (key, history) in &changed {
            added_rules += usize::from(!self.entries.contains_key(key));
            let previous = self
                .entries
                .get(key)
                .and_then(|entries| entries.get(backend));
            added_series += usize::from(previous.is_none());
            added_samples += history.step1.len() + history.step2.len()
                - previous.map_or(0, |old| old.step1.len() + old.step2.len());
        }
        if self.entries.len() + added_rules > MAX_SERIES
            || self.series_count + added_series > MAX_SERIES
            || self.sample_count + added_samples > MAX_SAMPLES
        {
            return Err(MetricError::Limit);
        }
        self.series_count += added_series;
        self.sample_count += added_samples;
        for (key, history) in changed {
            self.entries
                .entry(key)
                .or_default()
                .insert(backend.into(), history);
        }
        Ok(())
    }

    /// Merges owner history with Go's whole-step last-timestamp choice.
    /// Missing rules/backends are inserted wholesale, even outside topology.
    ///
    /// # Errors
    /// Rejects an over-capacity result without changing the previous history.
    pub fn merge(&mut self, incoming: Self) -> Result<(), MetricError> {
        let mut merged = self.clone();
        for (rule, backends) in incoming.entries {
            let local = merged.entries.entry(rule).or_default();
            for (backend, history) in backends {
                if let Some(previous) = local.get_mut(&backend) {
                    replace_step(&mut previous.step1, history.step1);
                    replace_step(&mut previous.step2, history.step2);
                } else {
                    local.insert(backend, history);
                }
            }
        }
        merged.recount()?;
        *self = merged;
        Ok(())
    }

    /// Returns addresses lacking Step2 in every active rule. Call before purge,
    /// matching Go's missing-backend fallback decision.
    #[must_use]
    pub fn missing(&self, rules: &[QueryId], addresses: &[String]) -> Vec<String> {
        addresses
            .iter()
            .filter(|address| {
                let label = address_label(address);
                !rules.iter().any(|rule| {
                    self.entries
                        .get(rule.key())
                        .and_then(|backends| backends.get(&label))
                        .is_some_and(|history| !history.step2.is_empty())
                })
            })
            .filter(|_| !rules.is_empty())
            .cloned()
            .collect()
    }

    /// Removes inactive rules and expired prefixes. Go keeps the entire suffix
    /// from the first sample with ts+retention>now, not a per-point filter.
    pub fn purge(&mut self, rules: &[QueryId], now_ms: i64) {
        self.entries.retain(|key, backends| {
            let Some(rule) = rules.iter().find(|rule| rule.key() == key) else {
                return false;
            };
            backends.retain(|_, history| {
                purge_step(&mut history.step1, rule.spec().retention_ms, now_ms);
                purge_step(&mut history.step2, rule.spec().retention_ms, now_ms);
                !history.step1.is_empty() || !history.step2.is_empty()
            });
            true
        });
        // Purge only removes entries, so it cannot exceed the previously
        // validated capacities. Count once per purge, not once per backend I/O.
        self.series_count = self.entries.values().map(BTreeMap::len).sum();
        self.sample_count = self
            .entries
            .values()
            .flat_map(BTreeMap::values)
            .map(|entry| entry.step1.len() + entry.step2.len())
            .sum();
    }

    /// Projects active query results with unchanged sample times and a new
    /// reader update time. A rule with histories but no Step2 is an empty result.
    #[must_use]
    pub fn results(
        &self,
        rules: &[QueryId],
        cluster: &str,
        updated_nanos: i64,
    ) -> BTreeMap<QueryId, QueryResult> {
        rules
            .iter()
            .filter_map(|rule| {
                let histories = self
                    .entries
                    .get(rule.key())
                    .filter(|entries| !entries.is_empty())?;
                let kind = rule.spec().kind;
                let series = histories
                    .iter()
                    .filter_map(|(backend, history)| {
                        let last = history.step2.last()?;
                        let samples = if kind == ValueKind::Vector {
                            vec![*last]
                        } else {
                            history.step2.clone()
                        };
                        Some(Series {
                            labels: BTreeMap::from([
                                ("instance".into(), backend.clone()),
                                ("tiproxy_cluster".into(), cluster_label(cluster)),
                            ]),
                            samples,
                        })
                    })
                    .collect();
                Some((
                    *rule,
                    QueryResult {
                        kind,
                        series,
                        updated_nanos: Some(updated_nanos),
                    },
                ))
            })
            .collect()
    }

    /// Serializes only histories selected for this owner's original read, in
    /// the existing Go endpoint's JSON format.
    ///
    /// # Errors
    /// Rejects a wire result above the existing response byte limit.
    pub fn owner_json(&self, selected: &[String]) -> Result<Vec<u8>, MetricError> {
        let selected: BTreeSet<&str> = selected.iter().map(String::as_str).collect();
        let filtered: BTreeMap<&str, BTreeMap<&str, &BackendHistory>> = if selected.is_empty() {
            BTreeMap::new()
        } else {
            self.entries
                .iter()
                .map(|(key, histories)| {
                    (
                        key.as_str(),
                        histories
                            .iter()
                            .filter(|(backend, _)| selected.contains(backend.as_str()))
                            .map(|(backend, history)| (backend.as_str(), history))
                            .collect(),
                    )
                })
                .collect()
        };
        let mut output = BoundedOutput(Vec::new());
        serde_json::to_writer(&mut output, &filtered).map_err(|_| MetricError::Limit)?;
        Ok(output.0)
    }
}

fn replace_step(previous: &mut Vec<Sample>, incoming: Vec<Sample>) {
    if previous.last().is_none_or(|old| {
        incoming
            .last()
            .is_some_and(|new| new.timestamp_ms > old.timestamp_ms)
    }) {
        *previous = incoming;
    }
}

fn purge_step(step: &mut Vec<Sample>, retention_ms: i64, now_ms: i64) {
    let first = step
        .iter()
        .position(|pair| {
            i128::from(pair.timestamp_ms) + i128::from(retention_ms) > i128::from(now_ms)
        })
        .unwrap_or(step.len());
    step.drain(..first);
}

/// Selected reader; backend state can change while Prom remains selected.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Source {
    /// No completed successful read yet.
    #[default]
    None,
    /// Last selected Prometheus reader.
    Prometheus,
    /// Last selected backend/history reader.
    Backend,
}

/// Source-selection and completed-result state, without runtime authority.
#[derive(Clone, Debug, Default)]
pub struct ReaderState {
    source: Source,
    prom: BTreeMap<QueryId, QueryResult>,
    backend: BTreeMap<QueryId, QueryResult>,
}

impl ReaderState {
    /// Current selected reader.
    #[must_use]
    pub const fn source(&self) -> Source {
        self.source
    }

    /// Commits a whole successful Prometheus result map, even if empty.
    pub fn complete_prom(&mut self, results: BTreeMap<QueryId, QueryResult>) {
        self.prom = results;
        self.source = Source::Prometheus;
    }

    /// Commits a completed backend result map. Go updates it before returning
    /// aggregate errors; errors retain the prior source, not the prior map.
    pub fn complete_backend(&mut self, results: BTreeMap<QueryId, QueryResult>, succeeded: bool) {
        self.backend = results;
        if succeeded {
            self.source = Source::Backend;
        }
    }

    /// Discards backend state after an observed owner identity replacement.
    /// A selected Prometheus map remains independent of unused backend owners.
    pub fn reset_backend(&mut self) {
        self.backend.clear();
        if self.source == Source::Backend {
            self.source = Source::None;
        }
    }

    /// Reads a result only from the selected source.
    #[must_use]
    pub fn get(&self, rule: QueryId) -> Option<&QueryResult> {
        match self.source {
            Source::None => None,
            Source::Prometheus => self.prom.get(&rule),
            Source::Backend => self.backend.get(&rule),
        }
    }
}

// Refuse bytes before Vec growth, including very long finite float spellings.
struct BoundedOutput(Vec<u8>);
impl std::io::Write for BoundedOutput {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > super::MAX_BYTES.saturating_sub(self.0.len()) {
            return Err(std::io::Error::other("metric response limit"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
