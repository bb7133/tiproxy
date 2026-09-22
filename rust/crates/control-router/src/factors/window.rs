// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Value-only factor history phases. Adapters supply each actual read window;
//! the core never reads a clock or holds a production capability.

use control_topology::metrics::{QueryId, Sample};
use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

/// Named clock reads in native policy order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClockSite {
    /// Metric emission cadence.
    MetricCadence,
    /// Status update and pruning.
    StatusSnapshot,
    /// Health expiry before a conditional snapshot.
    HealthExpiry,
    /// Health update and pruning.
    HealthSnapshot,
    /// Memory update and pruning.
    MemorySnapshot,
    /// Memory expiry after its conditional snapshot.
    MemoryExpiry,
    /// CPU update and pruning.
    CpuSnapshot,
    /// CPU expiry after its conditional snapshot.
    CpuExpiry,
    /// Random selection seed.
    RandomTicket,
    /// Prefer-idle selection seed.
    PreferIdleTicket,
}

/// Captured Go architecture, including its float64-to-int64 instruction semantics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GoArch {
    /// ARM64 FCVTZS saturates and maps NaN to zero, as does the staged Rust API.
    Arm64,
    /// AMD64 CVTTSD2SQ maps invalid/out-of-range conversions to the signed minimum.
    Amd64,
}
impl GoArch {
    #[allow(clippy::cast_possible_truncation)]
    pub(crate) fn duration(self, value: f64) -> i64 {
        const UPPER: f64 = 9_223_372_036_854_775_808.0;
        if self == Self::Amd64 && !(-UPPER..UPPER).contains(&value) {
            i64::MIN
        } else {
            value as i64
        }
    }
}

pub(crate) trait Time: Copy + Eq {
    fn before(self, other: Self) -> bool;
    fn expired(self, now: Self, seconds: i64) -> bool;
    fn stale(self, now: Self, seconds: i64) -> bool;
    fn sample(milliseconds: i64, zero: Self) -> Self;
    fn sample_delta(new: i64, old: i64) -> i64;
    fn initial_key(zero: Self) -> Option<Self>;
    fn is_zero(self) -> bool;
}
impl Time for i64 {
    fn before(self, other: Self) -> bool {
        self < other
    }
    fn expired(self, now: Self, seconds: i64) -> bool {
        i128::from(self) + i128::from(seconds) * 1_000_000_000 < i128::from(now)
    }
    fn stale(self, now: Self, seconds: i64) -> bool {
        self.expired(now, seconds)
    }
    fn sample(milliseconds: i64, _: Self) -> Self {
        milliseconds.saturating_mul(1_000_000)
    }
    fn sample_delta(new: i64, old: i64) -> i64 {
        new.saturating_mul(1_000_000)
            .saturating_sub(old.saturating_mul(1_000_000))
    }
    fn initial_key(_: Self) -> Option<Self> {
        None
    }
    fn is_zero(self) -> bool {
        false
    }
}

// Signed Go int arithmetic must happen before float conversion. The existing
// staged API retains its u64-to-float arithmetic until its caller migration.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) enum Count {
    Legacy(u64),
    Go(i64),
}
impl Count {
    #[allow(clippy::cast_precision_loss)]
    pub(crate) fn value(self) -> f64 {
        match self {
            Self::Legacy(v) => v as f64,
            Self::Go(v) => v as f64,
        }
    }
    pub(crate) fn positive(self) -> bool {
        match self {
            Self::Legacy(v) => v > 0,
            Self::Go(v) => v > 0,
        }
    }
    pub(crate) fn plus_one(self) -> f64 {
        match self {
            Self::Go(v) => Self::Go(v.wrapping_add(1)).value(),
            Self::Legacy(_) => self.value() + 1.0,
        }
    }
    pub(crate) fn sum_plus_one(self, other: Self) -> f64 {
        match (self, other) {
            (Self::Go(a), Self::Go(b)) => Self::Go(a.wrapping_add(b).wrapping_add(1)).value(),
            _ => self.value() + other.value() + 1.0,
        }
    }
    pub(crate) fn difference(self, old: Self) -> f64 {
        match (self, old) {
            (Self::Go(a), Self::Go(b)) => Self::Go(a.wrapping_sub(b)).value(),
            _ => self.value() - old.value(),
        }
    }
}

pub(crate) trait Backend {
    fn key(&self) -> &str;
    /// The backend's dial address: the `backend` label Go writes
    /// `backend_metric` with.
    ///
    /// Distinct from [`Self::key`], which is the opaque routing identity,
    /// and from [`Self::instance`], which is the Prometheus instance label
    /// derived from the address and IP. Using either of those would label
    /// the series with something Go never writes.
    fn address(&self) -> &str;
    fn touch_address(&self) {}
    fn instance(&self) -> Cow<'_, str>;
    fn cluster(&self) -> Cow<'_, str>;
    fn physical(&self) -> Count;
    fn score_count(&self) -> Count;
    fn healthy(&self) -> bool;
}
pub(crate) trait Query: Clone {
    type Time: Time;
    fn time(&self) -> Self::Time;
    fn empty(&self) -> bool;
    fn samples<'a>(&'a self, backend: &impl Backend, matrix: bool) -> &'a [Sample];
}
pub(crate) trait Window<'a, Q: Query + 'a> {
    type Error;
    fn query(&mut self, id: QueryId) -> Result<Option<&'a Q>, Self::Error>;
    fn clock(&mut self, site: ClockSite) -> Result<Q::Time, Self::Error>;
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct Cpu<T> {
    pub time: T,
    pub avg: f64,
    pub latest: f64,
    pub connections: Count,
}
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct ResourceSnapshot<T> {
    pub time: T,
    pub risk: u8,
    pub balance: f64,
}
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Snapshot<T> {
    pub cpu: Option<Cpu<T>>,
    pub memory: Option<ResourceSnapshot<T>>,
    pub health: Option<ResourceSnapshot<T>>,
    pub status: Option<(T, f64)>,
}
impl<T> Default for Snapshot<T> {
    fn default() -> Self {
        Self {
            cpu: None,
            memory: None,
            health: None,
            status: None,
        }
    }
}
#[derive(Clone)]
pub(crate) struct History<Q: Query> {
    pub cache: BTreeMap<Arc<str>, Snapshot<Q::Time>>,
    pub cpu_time: Option<Q::Time>,
    pub memory_time: Option<Q::Time>,
    pub health_queries: BTreeMap<QueryId, Q>,
    pub health_dirty: BTreeSet<QueryId>,
    pub usage_per_conn: f64,
    pub zero: Q::Time,
    pub go_arch: GoArch,
    /// Where accepted observations publish `backend_metric`, or `None` when
    /// nothing exposes them.
    ///
    /// Published from inside the factors rather than from their results,
    /// because Go writes the value it just accepted and skips the backends
    /// it rejected -- a skip leaves the previous value exposed, which a
    /// pass over the finished cache could not distinguish from a fresh one.
    pub backend_metrics: Option<Arc<crate::BackendMetricHistory>>,
    /// Observations accepted this round, not yet published.
    ///
    /// Go writes each value inline as it accepts it. We record at exactly
    /// the same points -- past exactly the same guards -- but hold the
    /// values until the caller can take the routing authority, so a round
    /// whose sources were revoked mid-evaluation publishes nothing. The
    /// buffer never outlives the round: `publish_backend_metrics` drains
    /// it, and `evaluate` clears it before filling it again.
    pending_metrics: Vec<(String, crate::BackendMetric, f64)>,
}
/// Equality over the observed state alone.
///
/// `backend_metrics` is a publication sink, not state: two histories that
/// have seen the same samples are the same history whether or not one of
/// them is wired to the exposition. Including it would make the
/// differential comparison depend on whether metrics are being served.
impl<Q: Query + PartialEq> PartialEq for History<Q> {
    fn eq(&self, other: &Self) -> bool {
        self.cache == other.cache
            && self.cpu_time == other.cpu_time
            && self.memory_time == other.memory_time
            && self.health_queries == other.health_queries
            && self.health_dirty == other.health_dirty
            && self.usage_per_conn == other.usage_per_conn
            && self.zero == other.zero
            && self.go_arch == other.go_arch
    }
}

impl<Q: Query> History<Q> {
    pub(crate) fn new(zero: Q::Time) -> Self {
        Self {
            cache: BTreeMap::new(),
            cpu_time: Q::Time::initial_key(zero),
            memory_time: Q::Time::initial_key(zero),
            health_queries: BTreeMap::new(),
            health_dirty: BTreeSet::new(),
            usage_per_conn: 0.0,
            // Preserve the preexisting staged API's saturating conversion.
            go_arch: GoArch::Arm64,
            backend_metrics: None,
            pending_metrics: Vec::new(),
            zero,
        }
    }
    /// Records an accepted observation for publication at commit time.
    ///
    /// Skipped entirely when nothing serves `backend_metric`, so an
    /// unexposed process does not accumulate a buffer it will only drop.
    fn record_metric(&mut self, address: &str, metric: crate::BackendMetric, value: f64) {
        if self.backend_metrics.is_some() {
            self.pending_metrics
                .push((address.to_owned(), metric, value));
        }
    }

    /// Discards observations recorded but never published.
    ///
    /// Called at the start of a round: a previous round that was refused
    /// the authority must not leak its values into this one.
    pub(crate) fn discard_pending_metrics(&mut self) {
        self.pending_metrics.clear();
    }

    /// Publishes this round's accepted observations.
    ///
    /// The caller runs this inside the combined commit, so the values
    /// land only while the sources that produced them are still
    /// authoritative.
    pub(crate) fn publish_backend_metrics(&mut self) {
        let Some(metrics) = self.backend_metrics.clone() else {
            self.pending_metrics.clear();
            return;
        };
        for (address, metric, value) in self.pending_metrics.drain(..) {
            metrics.observe(&address, metric, value);
        }
    }

    pub(crate) fn clear_resources(&mut self) {
        for cache in self.cache.values_mut() {
            cache.cpu = None;
            cache.memory = None;
            cache.health = None;
        }
        self.cpu_time = Q::Time::initial_key(self.zero);
        self.memory_time = Q::Time::initial_key(self.zero);
        self.health_queries.clear();
        self.health_dirty.clear();
        self.usage_per_conn = 0.0;
    }
    pub(crate) fn status(&mut self, inputs: &[impl Backend], now: Q::Time) {
        for input in inputs {
            input.touch_address();
            let cache = self.cache.entry(Arc::from(input.key())).or_default();
            if input.healthy() {
                cache.status = None;
            } else {
                let count = cache.status.map_or(0.0, |(_, count)| count);
                cache.status = Some((
                    now,
                    if count > 0.0001 {
                        count
                    } else {
                        input.score_count().value() / 5.0
                    },
                ));
            }
        }
        for cache in self.cache.values_mut() {
            if cache.status.is_some_and(|(time, _)| time.expired(now, 60)) {
                cache.status = None;
            }
        }
    }
    pub(crate) fn cpu<'a, W: Window<'a, Q>>(
        &mut self,
        inputs: &[impl Backend],
        window: &mut W,
    ) -> Result<bool, W::Error>
    where
        Q: 'a,
    {
        let Some(query) = window.query(QueryId::Cpu)?.filter(|q| !q.empty()) else {
            return Ok(false);
        };
        if self.cpu_time != Some(query.time()) {
            self.cpu_time = Some(query.time());
            let now = window.clock(ClockSite::CpuSnapshot)?;
            for input in inputs {
                input.touch_address();
                let key = input.key();
                let samples = query.samples(input, true);
                let Some(last) = samples.last() else { continue };
                let time = Q::Time::sample(last.timestamp_ms, self.zero);
                let cache = self.cache.entry(Arc::from(key)).or_default();
                let previous = cache
                    .cpu
                    .map(|old| old.time)
                    .or(Q::Time::initial_key(self.zero));
                if previous.is_some_and(|old| !old.before(time)) {
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
                    connections: input.physical(),
                });
                // Go publishes `calcAvgUsage`'s average here, past the same
                // freshness and negative-usage guards. The latest sample is
                // a different number and is not what the `cpu` label means.
                // Recorded after the cache write only to end its borrow;
                // recording buffers, so the order between the two is not
                // observable.
                self.record_metric(input.address(), crate::BackendMetric::Cpu, avg);
            }
            for cache in self.cache.values_mut() {
                if cache.cpu.is_some_and(|v| v.time.expired(now, 120)) {
                    cache.cpu = None;
                }
            }
            self.update_cpu_per_conn();
        }
        let now = window.clock(ClockSite::CpuExpiry)?;
        Ok(!query.time().stale(now, 120))
    }
    fn update_cpu_per_conn(&mut self) {
        let (mut usage, mut connections, mut signed_connections, mut snapshots) =
            (0.0, 0.0, 0_i64, 0);
        for value in self.cache.values().filter_map(|cache| cache.cpu) {
            snapshots += 1;
            if value.latest > 0.0 && value.connections.positive() {
                usage += value.latest;
                match value.connections {
                    Count::Legacy(_) => connections += value.connections.value(),
                    Count::Go(count) => {
                        signed_connections = signed_connections.wrapping_add(count);
                        connections = Count::Go(signed_connections).value();
                    }
                }
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
    pub(crate) fn usage(&self, input: &impl Backend) -> (f64, f64) {
        let Some(value) = self
            .cache
            .get(input.key())
            .and_then(|c| c.cpu)
            .filter(|v| !(v.avg < 0.0 || v.latest < 0.0))
        else {
            return (1.0, 1.0);
        };
        let latest =
            value.latest + input.score_count().difference(value.connections) * self.usage_per_conn;
        (value.avg, latest.clamp(0.0, 1.0))
    }
    pub(crate) fn memory<'a, W: Window<'a, Q>>(
        &mut self,
        inputs: &[impl Backend],
        window: &mut W,
    ) -> Result<bool, W::Error>
    where
        Q: 'a,
    {
        let Some(query) = window.query(QueryId::Memory)?.filter(|q| !q.empty()) else {
            return Ok(false);
        };
        if self.memory_time != Some(query.time()) {
            self.memory_time = Some(query.time());
            let now = window.clock(ClockSite::MemorySnapshot)?;
            for input in inputs {
                input.touch_address();
                let key = input.key();
                let samples = query.samples(input, true);
                let Some(last) = samples.last() else { continue };
                let time = Q::Time::sample(last.timestamp_ms, self.zero);
                let cache = self.cache.entry(Arc::from(key)).or_default();
                let previous = cache
                    .memory
                    .map(|old| old.time)
                    .or(Q::Time::initial_key(self.zero));
                if previous.is_some_and(|old| !old.before(time)) {
                    continue;
                }
                let (usage, horizon) = memory_usage::<Q::Time>(samples, self.go_arch);
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
                    (input.score_count().value() / seconds)
                        .max(cache.memory.map_or(0.0, |old| old.balance))
                };
                cache.memory = Some(ResourceSnapshot {
                    time,
                    risk,
                    balance,
                });
                // Go publishes `calcMemUsage`'s latest usage here, past the
                // same guards. Recorded after the cache write only to end
                // its borrow; recording buffers, so the order is not
                // observable.
                self.record_metric(input.address(), crate::BackendMetric::Memory, usage);
            }
            for cache in self.cache.values_mut() {
                if cache.memory.is_some_and(|v| v.time.expired(now, 60)) {
                    cache.memory = None;
                }
            }
        }
        let now = window.clock(ClockSite::MemoryExpiry)?;
        Ok(!query.time().stale(now, 60))
    }
    pub(crate) fn health<'a, W: Window<'a, Q>>(
        &mut self,
        inputs: &[impl Backend],
        window: &mut W,
    ) -> Result<bool, W::Error>
    where
        Q: 'a,
    {
        let indicators = [
            (QueryId::FailurePd, QueryId::TotalPd, 0.5),
            (QueryId::FailureTikv, QueryId::TotalTikv, 0.3),
        ];
        let mut latest = Q::Time::initial_key(self.zero);
        let mut changed = false;
        for (failure, total, _) in indicators {
            let Some(fq) = window.query(failure)?.filter(|q| !q.empty()) else {
                continue;
            };
            let Some(tq) = window.query(total)?.filter(|q| !q.empty()) else {
                continue;
            };
            for (id, query) in [(failure, fq), (total, tq)] {
                latest = Some(latest.map_or(query.time(), |old| {
                    if old.before(query.time()) {
                        query.time()
                    } else {
                        old
                    }
                }));
                let old = self
                    .health_queries
                    .get(&id)
                    .map(Query::time)
                    .or(Q::Time::initial_key(self.zero));
                if self.health_dirty.remove(&id) || old != Some(query.time()) {
                    self.health_queries.insert(id, query.clone());
                    changed = true;
                }
            }
        }
        let expiry = window.clock(ClockSite::HealthExpiry)?;
        if latest.is_none_or(|time| time.stale(expiry, 60)) {
            return Ok(false);
        }
        if changed {
            let now = window.clock(ClockSite::HealthSnapshot)?;
            for input in inputs {
                input.touch_address();
                let key = input.key();
                let mut updated = Q::Time::initial_key(self.zero);
                let mut risk = 0;
                for (failure, total, threshold) in indicators {
                    let fq = self.health_queries.get(&failure);
                    let tq = self.health_queries.get(&total);
                    let mut time = Q::Time::initial_key(self.zero);
                    for query in fq.into_iter().chain(tq) {
                        time = Some(time.map_or(query.time(), |old| {
                            if old.before(query.time()) {
                                query.time()
                            } else {
                                old
                            }
                        }));
                    }
                    let Some(time) = time.filter(|time| !time.expired(now, 60)) else {
                        continue;
                    };
                    updated =
                        Some(updated.map_or(time, |old| if old.before(time) { time } else { old }));
                    let (failure_value, total_value) = (value(fq, input), value(tq, input));
                    // Go writes both raw samples here, and only when both
                    // are present -- its `failureSample == nil ||
                    // totalSample == nil` skips the pair together, so one
                    // half is never published alone.
                    if let (Some(failure_value), Some(total_value)) = (failure_value, total_value) {
                        self.record_metric(input.address(), failure.into(), failure_value);
                        self.record_metric(input.address(), total.into(), total_value);
                    }
                    risk = risk.max(health_risk(failure_value, total_value, threshold));
                }
                let Some(time) = updated.filter(|time| !time.is_zero()) else {
                    continue;
                };
                let cache = self.cache.entry(Arc::from(key)).or_default();
                let old = cache.health.map_or(0.0, |value| value.balance);
                let balance = if risk < 2 {
                    0.0
                } else if old > 0.0001 {
                    old
                } else {
                    input.score_count().value() / 60.0
                };
                cache.health = Some(ResourceSnapshot {
                    time,
                    risk,
                    balance,
                });
            }
            for cache in self.cache.values_mut() {
                if cache.health.is_some_and(|v| v.time.expired(now, 60)) {
                    cache.health = None;
                }
            }
        }
        Ok(true)
    }
}
const NS: i64 = 1_000_000_000;
fn value<Q: Query>(query: Option<&Q>, input: &impl Backend) -> Option<f64> {
    query?
        .samples(input, false)
        .first()
        .map(|sample| sample.value)
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
#[allow(clippy::cast_precision_loss)]
fn memory_usage<T: Time>(samples: &[Sample], arch: GoArch) -> (f64, i64) {
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
        if latest < 0.0 {
            latest = usage;
            latest_time = sample.timestamp_ms;
            continue;
        }
        let delta = T::sample_delta(latest_time, sample.timestamp_ms);
        if delta < 10 * NS {
            continue;
        }
        if latest - usage > 1e-4 && latest > 1e-4 {
            horizon = arch.duration(delta as f64 * (0.9 - latest) / (latest - usage));
            horizon = arch.duration(horizon as f64 / latest * 0.6);
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

#[cfg(test)]
#[path = "numeric_tests.rs"]
mod numeric_tests;
