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

use std::collections::BTreeMap;
use std::sync::Arc;

use control_config::{RoutingBalancePolicy, RoutingConfig, RoutingSelectionPolicy};
use control_topology::metrics::{QueryId, QueryResult};

use crate::ledger::{AccountIdentity, Accounting};

mod balance;
pub(crate) mod phases;
mod resource;
pub(crate) mod window;

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

/// Go's first actionable worst-to-best migration pair. Diagnostic values do
/// not grant permission to issue a redirect.
#[derive(Clone, Debug, PartialEq)]
pub struct BalancePair {
    /// Physical source backend.
    pub from: Arc<str>,
    /// Lowest-scoring routeable backend.
    pub to: Arc<str>,
    /// Connections per second.
    pub rate: f64,
    /// First actionable factor in policy priority order.
    pub reason: Factor,
}

/// Staged factor observations; these values cannot reserve a connection.
#[derive(Clone, Debug, PartialEq)]
pub struct FactorReport {
    /// Ascending composed score, with stable opaque-ID order for exact ties.
    pub rows: Vec<FactorScore>,
    /// Eligible IDs in Go prefer-idle's ticket order (worst to best).
    pub preferred: Vec<Arc<str>>,
    /// Migration pair over the supplied physical/score owners, independent of prefer-idle.
    pub balance: Option<BalancePair>,
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
        choices
            .get(phases::ticket(
                choices.len(),
                policy == RoutingSelectionPolicy::Random,
                ticket,
            )?)
            .copied()
    }
}

#[derive(Clone)]
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
struct Owner {
    identity: Arc<AccountIdentity>,
    cluster: String,
}

/// The production adapter owns account fences; the history holds values only.
#[derive(Clone)]
pub(crate) struct State {
    owners: BTreeMap<Arc<str>, Owner>,
    history: window::History<QueryResult>,
}
impl Default for State {
    fn default() -> Self {
        Self {
            owners: BTreeMap::new(),
            history: window::History::new(None),
        }
    }
}

pub(crate) type Queries = BTreeMap<QueryId, QueryResult>;

pub(crate) fn order(policy: &RoutingConfig) -> Vec<Factor> {
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
        let previous = self.owners.len();
        self.owners.retain(|id, stored| {
            owners
                .get(id)
                .is_some_and(|owner| Arc::ptr_eq(owner, &stored.identity))
        });
        self.history
            .cache
            .retain(|id, _| self.owners.contains_key(id));
        if self.owners.len() != previous {
            self.history.cpu_time = None;
            self.history.usage_per_conn = 0.0;
        }
    }

    pub(crate) fn clear_cluster(&mut self, cluster: &str) {
        for (id, owner) in &self.owners {
            if owner.cluster == cluster
                && let Some(cache) = self.history.cache.get_mut(id)
            {
                cache.cpu = None;
                cache.memory = None;
                cache.health = None;
            }
        }
        self.history.cpu_time = None;
        self.history.memory_time = None;
        let label = control_topology::metrics::cluster_label(cluster);
        for query in self.history.health_queries.values_mut() {
            query.series.retain(|series| {
                series
                    .labels
                    .get("tiproxy_cluster")
                    .is_some_and(|value| value != &label)
            });
        }
        self.history.health_dirty.extend([
            QueryId::FailurePd,
            QueryId::TotalPd,
            QueryId::FailureTikv,
            QueryId::TotalTikv,
        ]);
        self.history.usage_per_conn = 0.0;
    }

    pub(crate) fn clear_resources(&mut self) {
        self.history.clear_resources();
    }

    #[allow(clippy::cast_precision_loss)]
    pub(crate) fn evaluate(
        &mut self,
        inputs: &[Input],
        policy: &RoutingConfig,
        queries: &Queries,
        now: i64,
    ) -> FactorReport {
        let mut window = resource::RepeatedTime { queries, now };
        match self.evaluate_window(inputs, policy, &mut window) {
            Ok(report) => report,
            Err(never) => match never {},
        }
    }

    fn evaluate_window<'a, W: window::Window<'a, QueryResult>>(
        &mut self,
        inputs: &[Input],
        policy: &RoutingConfig,
        window: &mut W,
    ) -> Result<FactorReport, W::Error> {
        for input in inputs {
            if self
                .owners
                .get(&input.id)
                .is_none_or(|owner| !Arc::ptr_eq(&owner.identity, &input.owner))
            {
                self.history.cache.remove(&input.id);
                self.owners.insert(
                    Arc::clone(&input.id),
                    Owner {
                        identity: Arc::clone(&input.owner),
                        cluster: input.cluster.clone(),
                    },
                );
            }
        }
        self.history
            .status(inputs, window.clock(window::ClockSite::StatusSnapshot)?);
        let resource = policy.balance_policy != RoutingBalancePolicy::Connection;
        let active = if resource && inputs.len() > 1 {
            [
                self.history.health(inputs, window)?,
                self.history.memory(inputs, window)?,
                self.history.cpu(inputs, window)?,
            ]
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
                let parts: Vec<_> = factors
                    .iter()
                    .map(|&factor| {
                        let part = self.score(factor, input, active, inputs.len() > 1);
                        (factor, part)
                    })
                    .collect();
                let (score, routeable) = phases::compose(&parts);
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
        let preferred = phases::preferred(
            sorted.len(),
            |i| &sorted[i].1,
            |i, factor| self.advice(factor, sorted[i].0, sorted[0].0, policy),
        )
        .into_iter()
        .map(|i| Arc::clone(&sorted[i].1.backend_id))
        .collect();
        if let Some(&(best, _)) = sorted.first() {
            for (input, row) in &mut sorted {
                row.advice_to_best = factors
                    .iter()
                    .map(|&factor| self.advice(factor, input, best, policy))
                    .collect();
            }
        }
        let balance = balance::select(&sorted);
        Ok(FactorReport {
            balance,
            rows: sorted.into_iter().map(|(_, row)| row).collect(),
            preferred,
        })
    }

    fn score(&self, factor: Factor, input: &Input, active: [bool; 3], multiple: bool) -> u64 {
        let cache = &self.history.cache[&input.id];
        phases::score(
            factor,
            phases::ScoreValues {
                go_arch: self.history.go_arch,
                label_matches: input.label_matches,
                healthy: input.healthy,
                local: input.local,
                connections: input.counts.connection_score(),
                health_risk: cache.health.map_or(0, |value| value.risk),
                memory_risk: cache.memory.map_or(0, |value| value.risk),
                cpu_usage: if factor == Factor::Cpu && active[2] {
                    self.history.usage(input).1
                } else {
                    0.0
                },
            },
            active,
            multiple,
        )
    }

    #[allow(clippy::cast_precision_loss)]
    fn advice_values(&self, input: &Input) -> phases::AdviceValues {
        let cache = &self.history.cache[&input.id];
        phases::AdviceValues {
            connections: window::Count::Legacy(input.counts.connection_score()),
            status_count: cache.status.map_or(0.0, |(_, count)| count),
            health: cache
                .health
                .map_or((0, 0.0), |value| (value.risk, value.balance)),
            memory: cache
                .memory
                .map_or((0, 0.0), |value| (value.risk, value.balance)),
            cpu: self.history.usage(input),
        }
    }

    fn advice(
        &self,
        factor: Factor,
        from: &Input,
        to: &Input,
        policy: &RoutingConfig,
    ) -> FactorAdvice {
        phases::advice(
            factor,
            self.advice_values(from),
            self.advice_values(to),
            self.history.usage_per_conn,
            policy,
        )
    }
}

#[cfg(test)]
mod tests;
