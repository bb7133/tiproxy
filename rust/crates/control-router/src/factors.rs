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

//! Go factor state owned by a router group, never by the metric collector.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use control_config::{RoutingBalancePolicy, RoutingConfig, RoutingSelectionPolicy};
use control_topology::metrics::{QueryId, QueryResult};

use crate::ledger::{AccountIdentity, Accounting};

mod resource;

/// One Go factor, in score-composition order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Factor {
    /// Strict business-label isolation.
    Label,
    /// Actual backend health verdict.
    Status,
    /// PD/TiKV error risk, independent of actual health.
    Health,
    /// Memory usage and OOM horizon.
    Memory,
    /// Smoothed and extrapolated CPU usage.
    Cpu,
    /// Actual health snapshot locality.
    Location,
    /// Physical plus initial pending and incoming minus outgoing redirects.
    Connection,
}
impl Factor {
    /// Number of bits used by the Go score segment.
    #[must_use]
    pub const fn bits(self) -> u32 {
        match self {
            Self::Label | Self::Status | Self::Location => 1,
            Self::Health | Self::Memory => 2,
            Self::Cpu => 5,
            Self::Connection => 16,
        }
    }
}

/// Factor advice is data; it does not authorize a route or migration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BalanceAdvice {
    /// A move would make the target too busy.
    Negative,
    /// No actionable imbalance.
    Neutral,
    /// The factor recommends moving connections.
    Positive,
}

/// Per-factor advice from this backend to the lowest-scoring backend.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct FactorAdvice {
    /// Factor that produced the advice.
    pub factor: Factor,
    /// Directional recommendation.
    pub advice: BalanceAdvice,
    /// Connections per second; Go's small-count cutoff is applied by selection.
    pub count: f64,
}

/// A diagnostic score row, with no routing authority.
#[derive(Clone, Debug, PartialEq)]
pub struct FactorScore {
    /// Opaque routing backend ID, not a metric label.
    pub backend_id: Arc<str>,
    /// Composed Go score bits.
    pub score: u64,
    /// Each segment in actual policy order, including zero contributions.
    pub parts: Vec<(Factor, u64)>,
    /// The conjunction of the factors' `CanBeRouted` results.
    pub routeable: bool,
    /// Advice to the first row, used by prefer-idle selection.
    pub advice_to_best: Vec<FactorAdvice>,
}

/// Staged factor observations; these values cannot reserve a connection.
#[derive(Clone, Debug, PartialEq)]
pub struct FactorReport {
    /// Ascending composed score, with stable opaque-ID order for exact ties.
    pub rows: Vec<FactorScore>,
    /// Eligible IDs in Go prefer-idle's ticket order (worst to best).
    pub preferred: Vec<Arc<str>>,
}
impl FactorReport {
    /// Applies Go's ticket weights. The result is data, without route authority.
    #[must_use]
    pub fn choice(&self, policy: RoutingSelectionPolicy, ticket: u128) -> Option<&str> {
        let choices: Vec<&str> = if policy == RoutingSelectionPolicy::Random {
            self.rows
                .iter()
                .filter(|row| row.routeable)
                .map(|row| row.backend_id.as_ref())
                .collect()
        } else {
            self.preferred.iter().map(AsRef::as_ref).collect()
        };
        let n = choices.len() as u128;
        if n == 0 {
            return None;
        }
        let index = if policy == RoutingSelectionPolicy::Random {
            ticket % (n * 10 + 1) % n
        } else {
            ticket % n
        };
        choices.get(usize::try_from(index).ok()?).copied()
    }
}

pub(crate) struct Input {
    pub id: Arc<str>,
    pub owner: Arc<AccountIdentity>,
    pub instance: String,
    pub cluster: String,
    pub counts: Accounting,
    pub healthy: bool,
    pub local: bool,
    pub label_matches: bool,
}

#[derive(Clone)]
struct Cache {
    owner: Arc<AccountIdentity>,
    cluster: String,
    cpu: Option<resource::Cpu>,
    memory: Option<resource::Memory>,
    health: Option<resource::Health>,
    status: Option<(i64, f64)>,
}
impl Cache {
    fn new(input: &Input) -> Self {
        Self {
            owner: Arc::clone(&input.owner),
            cluster: input.cluster.clone(),
            cpu: None,
            memory: None,
            health: None,
            status: None,
        }
    }
}

/// Cloned before evaluation; the router commits it only under current authority.
#[derive(Clone, Default)]
pub(crate) struct State {
    cache: BTreeMap<Arc<str>, Cache>,
    cpu_time: Option<i64>,
    memory_time: Option<i64>,
    health_queries: BTreeMap<QueryId, QueryResult>,
    health_dirty: BTreeSet<QueryId>,
    usage_per_conn: f64,
}

pub(crate) type Queries = BTreeMap<QueryId, QueryResult>;

fn order(policy: &RoutingConfig) -> Vec<Factor> {
    let mut factors = Vec::new();
    if !policy.label_name.is_empty() {
        factors.push(Factor::Label);
    }
    factors.push(Factor::Status);
    match policy.balance_policy {
        RoutingBalancePolicy::Connection => (),
        RoutingBalancePolicy::Resource => factors.extend([
            Factor::Health,
            Factor::Memory,
            Factor::Cpu,
            Factor::Location,
        ]),
        RoutingBalancePolicy::Location => factors.extend([
            Factor::Location,
            Factor::Health,
            Factor::Memory,
            Factor::Cpu,
        ]),
    }
    factors.push(Factor::Connection);
    factors
}

impl State {
    // Accounts outlive a temporary omission from the group, but never a retired
    // ledger owner. A same-text backend replacement must get an empty cache.
    pub(crate) fn retain_owners(&mut self, owners: &BTreeMap<Arc<str>, Arc<AccountIdentity>>) {
        let previous = self.cache.len();
        self.cache.retain(|id, cache| {
            owners
                .get(id)
                .is_some_and(|owner| Arc::ptr_eq(owner, &cache.owner))
        });
        if self.cache.len() != previous {
            self.cpu_time = None;
            self.usage_per_conn = 0.0;
        }
    }

    pub(crate) fn clear_cluster(&mut self, cluster: &str) {
        for cache in self
            .cache
            .values_mut()
            .filter(|cache| cache.cluster == cluster)
        {
            cache.cpu = None;
            cache.memory = None;
            cache.health = None;
        }
        // Force a read of the new authoritative map, even if wall time repeated.
        // Unchanged sibling caches retain their original sample times/counts.
        self.cpu_time = None;
        self.memory_time = None;
        // Cached indicators from an unchanged sibling remain reusable when a
        // current round temporarily omits that query. Remove only revoked data.
        let label = control_topology::metrics::cluster_label(cluster);
        for query in self.health_queries.values_mut() {
            query.series.retain(|series| {
                series
                    .labels
                    .get("tiproxy_cluster")
                    .is_some_and(|value| value != &label)
            });
        }
        self.health_dirty.extend([
            QueryId::FailurePd,
            QueryId::TotalPd,
            QueryId::FailureTikv,
            QueryId::TotalTikv,
        ]);
        self.usage_per_conn = 0.0;
    }

    pub(crate) fn clear_resources(&mut self) {
        for cache in self.cache.values_mut() {
            cache.cpu = None;
            cache.memory = None;
            cache.health = None;
        }
        self.cpu_time = None;
        self.memory_time = None;
        self.health_queries.clear();
        self.health_dirty.clear();
        self.usage_per_conn = 0.0;
    }

    #[allow(clippy::cast_precision_loss)]
    pub(crate) fn evaluate(
        &mut self,
        inputs: &[Input],
        policy: &RoutingConfig,
        queries: &Queries,
        now: i64,
    ) -> FactorReport {
        self.update_status(inputs, now);
        let resource = policy.balance_policy != RoutingBalancePolicy::Connection;
        let active = if resource && inputs.len() > 1 {
            self.update_resources(inputs, queries, now)
        } else {
            [false; 3]
        };
        if !resource {
            self.clear_resources();
        }
        let factors = order(policy);
        let mut sorted: Vec<_> = inputs
            .iter()
            .map(|input| {
                let mut score = 0;
                let mut routeable = true;
                let parts = factors
                    .iter()
                    .map(|&factor| {
                        let part = self.score(factor, input, active, inputs.len() > 1);
                        score = (score << factor.bits()) + part;
                        if matches!(factor, Factor::Label | Factor::Status) && part != 0 {
                            routeable = false;
                        }
                        (factor, part)
                    })
                    .collect();
                (
                    input,
                    FactorScore {
                        backend_id: Arc::clone(&input.id),
                        score,
                        parts,
                        routeable,
                        advice_to_best: Vec::new(),
                    },
                )
            })
            .collect();
        sorted.sort_by_key(|(_, row)| row.score);
        let mut preferred = Vec::new();
        if let Some(&(best, ref best_row)) = sorted.first() {
            if best_row.routeable {
                for (input, row) in sorted.iter().skip(1).rev() {
                    let mut count = 0.0;
                    for ((factor, from_score), (_, to_score)) in
                        row.parts.iter().zip(&best_row.parts)
                    {
                        if from_score > to_score {
                            let advice = self.advice(*factor, input, best, policy);
                            count = advice.count;
                            if advice.advice == BalanceAdvice::Positive && count > 0.0001 {
                                break;
                            }
                        } else if from_score < to_score {
                            break;
                        }
                    }
                    if count <= 0.0001 {
                        preferred.push(Arc::clone(&row.backend_id));
                    }
                }
                preferred.push(Arc::clone(&best.id));
            }
            for (input, row) in &mut sorted {
                row.advice_to_best = factors
                    .iter()
                    .map(|&factor| self.advice(factor, input, best, policy))
                    .collect();
            }
        }
        FactorReport {
            rows: sorted.into_iter().map(|(_, row)| row).collect(),
            preferred,
        }
    }

    #[allow(clippy::cast_precision_loss)]
    fn update_status(&mut self, inputs: &[Input], now: i64) {
        for input in inputs {
            let cache = self
                .cache
                .entry(Arc::clone(&input.id))
                .or_insert_with(|| Cache::new(input));
            if !Arc::ptr_eq(&cache.owner, &input.owner) {
                *cache = Cache::new(input);
            }
            if input.healthy {
                cache.status = None;
            } else {
                let count = cache.status.map_or(0.0, |(_, count)| count);
                cache.status = Some((
                    now,
                    if count > 0.0001 {
                        count
                    } else {
                        input.counts.connection_score() as f64 / 5.0
                    },
                ));
            }
        }
        for cache in self.cache.values_mut() {
            if cache
                .status
                .is_some_and(|(time, _)| resource::expired(time, now, 60))
            {
                cache.status = None;
            }
        }
    }

    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    fn score(&self, factor: Factor, input: &Input, active: [bool; 3], multiple: bool) -> u64 {
        let cache = &self.cache[&input.id];
        match factor {
            Factor::Label => u64::from(!input.label_matches),
            Factor::Status => u64::from(!input.healthy),
            Factor::Location => u64::from(multiple && !input.local),
            Factor::Connection => input.counts.connection_score().min(u64::from(u16::MAX)),
            Factor::Health => {
                if active[0] {
                    u64::from(cache.health.map_or(0, |value| value.risk))
                } else {
                    0
                }
            }
            Factor::Memory => {
                if active[1] {
                    u64::from(cache.memory.map_or(0, |value| value.risk))
                } else {
                    0
                }
            }
            Factor::Cpu => {
                if active[2] {
                    ((self.usage(input).1 * 100.0) as i64 / 5).clamp(0, 31) as u64
                } else {
                    0
                }
            }
        }
    }

    #[allow(clippy::cast_precision_loss)]
    fn advice(
        &self,
        factor: Factor,
        from: &Input,
        to: &Input,
        policy: &RoutingConfig,
    ) -> FactorAdvice {
        use BalanceAdvice::{Negative, Neutral, Positive};
        let a = &self.cache[&from.id];
        let b = &self.cache[&to.id];
        let configured = |rate: f64, default: f64| if rate > 0.0 { rate } else { default };
        let (advice, count) = match factor {
            Factor::Label => (Positive, 1.0),
            Factor::Status => (
                Positive,
                configured(
                    policy.status.migrations_per_second,
                    a.status.map_or(0.0, |(_, count)| count),
                ),
            ),
            Factor::Location => (
                Positive,
                configured(policy.location.migrations_per_second, 1.0),
            ),
            Factor::Health => {
                let from = a.health.unwrap_or_default();
                let to = b.health.unwrap_or_default();
                if i16::from(from.risk) - i16::from(to.risk) <= 1 {
                    (Neutral, 0.0)
                } else {
                    (
                        Positive,
                        configured(policy.health.migrations_per_second, from.balance),
                    )
                }
            }
            Factor::Memory => {
                let from = a.memory.unwrap_or_default();
                let to = b.memory.unwrap_or_default();
                if i16::from(from.risk) - i16::from(to.risk) <= 1 {
                    (Neutral, 0.0)
                } else {
                    (
                        Positive,
                        configured(policy.memory.migrations_per_second, from.balance),
                    )
                }
            }
            Factor::Cpu => {
                let (fa, fl) = self.usage(from);
                let (ta, tl) = self.usage(to);
                let per = self.usage_per_conn;
                if (1.3 - (ta + per)) * 1.1 < 1.3 - (fa - per)
                    || (1.3 - (tl + per)) * 1.1 < 1.3 - (fl - per)
                {
                    (Negative, 0.0)
                } else if 1.3 - ta < (1.3 - fa) * 1.2 || 1.3 - tl < (1.3 - fl) * 1.2 {
                    (Neutral, 0.0)
                } else {
                    (
                        Positive,
                        configured(policy.cpu.migrations_per_second, 1.0 / per / 600.0),
                    )
                }
            }
            Factor::Connection => {
                let from = from.counts.connection_score() as f64;
                let to = to.counts.connection_score() as f64;
                let ratio = if policy.connection.count_ratio_threshold > 1.0 {
                    policy.connection.count_ratio_threshold
                } else {
                    1.2
                };
                if from <= (to + 1.0) * ratio {
                    (Neutral, 0.0)
                } else {
                    (
                        Positive,
                        configured(
                            policy.connection.migrations_per_second,
                            (((from + to + 1.0) / (1.0 + ratio) - (to + 1.0)) / 120.0).max(0.0),
                        ),
                    )
                }
            }
        };
        FactorAdvice {
            factor,
            advice,
            count,
        }
    }
}

#[cfg(test)]
mod tests;
