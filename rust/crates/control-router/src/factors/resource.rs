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

//! Per-factor history and strict Go expiry/threshold rules.

use super::{Input, Queries, State};
use control_topology::metrics::{QueryId, QueryResult, Sample, ValueKind};

const NS: i64 = 1_000_000_000;

pub(super) fn expired(time: i64, now: i64, seconds: i64) -> bool {
    i128::from(time) + i128::from(seconds) * i128::from(NS) < i128::from(now)
}
fn sample_time(sample: &Sample) -> i64 {
    sample.timestamp_ms.saturating_mul(1_000_000)
}
fn nonempty(queries: &Queries, id: QueryId) -> Option<&QueryResult> {
    queries.get(&id).filter(|query| !query.is_empty())
}
fn pairs<'a>(query: &'a QueryResult, input: &Input) -> &'a [Sample] {
    if query.kind != ValueKind::Matrix {
        return &[];
    }
    query
        .samples_for(&input.instance, &input.cluster)
        .unwrap_or_default()
}
fn value(query: Option<&QueryResult>, input: &Input) -> Option<f64> {
    let query = query.filter(|query| query.kind == ValueKind::Vector)?;
    query
        .samples_for(&input.instance, &input.cluster)?
        .first()
        .map(|sample| sample.value)
}

#[derive(Clone, Copy)]
pub(super) struct Cpu {
    time: i64,
    avg: f64,
    latest: f64,
    connections: u64,
}
#[derive(Clone, Copy, Default)]
pub(super) struct Memory {
    time: i64,
    pub risk: u8,
    pub balance: f64,
}
#[derive(Clone, Copy, Default)]
pub(super) struct Health {
    time: i64,
    pub risk: u8,
    pub balance: f64,
}

impl State {
    pub(super) fn update_resources(
        &mut self,
        inputs: &[Input],
        queries: &Queries,
        now: i64,
    ) -> [bool; 3] {
        let health = self.update_health(inputs, queries, now);
        let memory = self.update_memory(inputs, queries, now);
        let cpu = self.update_cpu(inputs, queries, now);
        [health, memory, cpu]
    }

    fn update_cpu(&mut self, inputs: &[Input], queries: &Queries, now: i64) -> bool {
        let Some(query) = nonempty(queries, QueryId::Cpu) else {
            return false;
        };
        if self.cpu_time != Some(query.updated_nanos) {
            self.cpu_time = Some(query.updated_nanos);
            for input in inputs {
                let samples = pairs(query, input);
                let Some(last) = samples.last() else {
                    continue;
                };
                let time = sample_time(last);
                let cache = self
                    .cache
                    .entry(std::sync::Arc::clone(&input.id))
                    .or_insert_with(|| super::Cache::new(input));
                if cache.cpu.is_some_and(|old| old.time >= time) {
                    continue;
                }
                let (avg, latest) = cpu_usage(samples);
                if avg < 0.0 {
                    continue;
                }
                cache.cpu = Some(Cpu {
                    time,
                    avg,
                    latest,
                    connections: input.counts.active(),
                });
            }
            for cache in self.cache.values_mut() {
                if cache.cpu.is_some_and(|value| expired(value.time, now, 120)) {
                    cache.cpu = None;
                }
            }
            self.update_cpu_per_conn();
        }
        !expired(query.updated_nanos, now, 120)
    }

    #[allow(clippy::cast_precision_loss)]
    fn update_cpu_per_conn(&mut self) {
        let mut usage = 0.0;
        let mut connections = 0.0;
        let mut snapshots = 0;
        for value in self.cache.values().filter_map(|cache| cache.cpu) {
            snapshots += 1;
            if value.latest > 0.0 && value.connections > 0 {
                usage += value.latest;
                connections += value.connections as f64;
            }
        }
        if connections > 0.0 {
            let mut per = usage / connections;
            if per < 0.001 && usage / f64::from(snapshots) <= 0.1 {
                per = self.usage_per_conn;
            }
            self.usage_per_conn = per;
        }
        if self.usage_per_conn <= 0.0 {
            self.usage_per_conn = 0.001;
        }
    }

    #[allow(clippy::cast_precision_loss)]
    pub(super) fn usage(&self, input: &Input) -> (f64, f64) {
        let Some(cache) = self.cache[&input.id]
            .cpu
            .filter(|value| !(value.avg < 0.0 || value.latest < 0.0))
        else {
            return (1.0, 1.0);
        };
        let latest = cache.latest
            + (input.counts.connection_score() as f64 - cache.connections as f64)
                * self.usage_per_conn;
        (cache.avg, latest.clamp(0.0, 1.0))
    }

    #[allow(clippy::cast_precision_loss)]
    fn update_memory(&mut self, inputs: &[Input], queries: &Queries, now: i64) -> bool {
        let Some(query) = nonempty(queries, QueryId::Memory) else {
            return false;
        };
        if self.memory_time != Some(query.updated_nanos) {
            self.memory_time = Some(query.updated_nanos);
            for input in inputs {
                let samples = pairs(query, input);
                let Some(last) = samples.last() else {
                    continue;
                };
                let time = sample_time(last);
                let cache = self
                    .cache
                    .entry(std::sync::Arc::clone(&input.id))
                    .or_insert_with(|| super::Cache::new(input));
                if cache.memory.is_some_and(|old| old.time >= time) {
                    continue;
                }
                let (usage, horizon) = memory_usage(samples);
                if usage < 0.0 {
                    continue;
                }
                let risk = if usage > 0.75 || horizon < 45 * NS {
                    2
                } else {
                    u8::from(usage > 0.6 || horizon < 180 * NS)
                };
                let balance = if risk < 2 {
                    0.0
                } else {
                    let seconds = if horizon < 45 * NS { 10.0 } else { 60.0 };
                    (input.counts.connection_score() as f64 / seconds)
                        .max(cache.memory.map_or(0.0, |old| old.balance))
                };
                cache.memory = Some(Memory {
                    time,
                    risk,
                    balance,
                });
            }
            for cache in self.cache.values_mut() {
                if cache
                    .memory
                    .is_some_and(|value| expired(value.time, now, 60))
                {
                    cache.memory = None;
                }
            }
        }
        !expired(query.updated_nanos, now, 60)
    }

    #[allow(clippy::cast_precision_loss)]
    fn update_health(&mut self, inputs: &[Input], queries: &Queries, now: i64) -> bool {
        let indicators = [
            (QueryId::FailurePd, QueryId::TotalPd, 0.5),
            (QueryId::FailureTikv, QueryId::TotalTikv, 0.3),
        ];
        let mut latest = None;
        let mut changed = false;
        for (failure, total, _) in indicators {
            let (Some(failure_query), Some(total_query)) =
                (nonempty(queries, failure), nonempty(queries, total))
            else {
                continue;
            };
            for (id, query) in [(failure, failure_query), (total, total_query)] {
                latest = Some(latest.map_or(query.updated_nanos, |time: i64| {
                    time.max(query.updated_nanos)
                }));
                if self.health_dirty.remove(&id)
                    || self
                        .health_queries
                        .get(&id)
                        .is_none_or(|old| old.updated_nanos != query.updated_nanos)
                {
                    self.health_queries.insert(id, query.clone());
                    changed = true;
                }
            }
        }
        if latest.is_none_or(|time| expired(time, now, 60)) {
            return false;
        }
        if changed {
            for input in inputs {
                let mut updated = None;
                let mut risk = 0;
                for (failure, total, threshold) in indicators {
                    let fq = self.health_queries.get(&failure);
                    let tq = self.health_queries.get(&total);
                    let time = fq
                        .into_iter()
                        .chain(tq)
                        .map(|query| query.updated_nanos)
                        .max();
                    let Some(time) = time.filter(|&time| !expired(time, now, 60)) else {
                        continue;
                    };
                    updated = Some(updated.map_or(time, |old: i64| old.max(time)));
                    risk = risk.max(health_risk(value(fq, input), value(tq, input), threshold));
                }
                let Some(time) = updated else {
                    continue;
                };
                let cache = self
                    .cache
                    .entry(std::sync::Arc::clone(&input.id))
                    .or_insert_with(|| super::Cache::new(input));
                let old = cache.health.map_or(0.0, |value| value.balance);
                let balance = if risk < 2 {
                    0.0
                } else if old > 0.0001 {
                    old
                } else {
                    input.counts.connection_score() as f64 / 60.0
                };
                cache.health = Some(Health {
                    time,
                    risk,
                    balance,
                });
            }
            for cache in self.cache.values_mut() {
                if cache
                    .health
                    .is_some_and(|value| expired(value.time, now, 60))
                {
                    cache.health = None;
                }
            }
        }
        true
    }
}

fn cpu_usage(samples: &[Sample]) -> (f64, f64) {
    let (mut avg, mut latest) = (-1.0, -1.0);
    for sample in samples {
        if sample.value.is_nan() {
            continue;
        }
        latest = sample.value;
        avg = if avg < 0.0 {
            latest
        } else {
            avg * 0.5 + latest * 0.5
        };
    }
    if avg > 1.0 {
        avg = 1.0;
    }
    (avg, latest)
}

#[allow(clippy::cast_precision_loss, clippy::cast_possible_truncation)]
fn memory_usage(samples: &[Sample]) -> (f64, i64) {
    let (mut latest, mut latest_time, mut horizon) = (-1.0, 0, i64::MAX);
    for sample in samples.iter().rev() {
        if sample.value.is_nan() {
            continue;
        }
        let usage = if sample.value > 0.9 {
            0.9
        } else {
            sample.value
        };
        let time = sample_time(sample);
        if latest < 0.0 {
            latest = usage;
            latest_time = time;
            continue;
        }
        let delta = latest_time.saturating_sub(time);
        if delta < 10 * NS {
            continue;
        }
        if latest - usage > 1e-4 && latest > 1e-4 {
            horizon = (delta as f64 * (0.9 - latest) / (latest - usage)) as i64;
            // Preserve Go's two separate duration conversions.
            horizon = (horizon as f64 / latest * 0.6) as i64;
        }
        break;
    }
    (latest, horizon)
}

fn health_risk(failure: Option<f64>, total: Option<f64>, threshold: f64) -> u8 {
    let (Some(failure), Some(total)) = (failure, total) else {
        return 0;
    };
    if failure.is_nan() || total.is_nan() || failure == 0.0 {
        return 0;
    }
    if total == 0.0 {
        return 2;
    }
    let ratio = failure / total;
    if ratio <= 0.1 {
        0
    } else if ratio >= threshold {
        2
    } else {
        1
    }
}
