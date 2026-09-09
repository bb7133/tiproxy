// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Exact native adapters for the shared pure factor history. No authority or
//! production callback is constructed while consuming these captured values.

use super::native::{Account, ClockSite, QueryRead, Read, Shape};
use crate::factors::window::{self, Backend, Count, Query, Time, Window};
use control_routing::go_time::{GoTime, SampleTime};
use control_topology::metrics::{QueryId, Sample};
use std::{borrow::Cow, cell::Cell, cmp::Ordering};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// Reason a native evaluation cannot qualify.
pub enum Failure {
    /// Missing, reordered or excess reads.
    Reads,
    /// Invalid input values.
    Values,
    /// Discontinuous policy/config/resource history.
    Lifetime,
    /// Independently computed output differs.
    Output,
}

impl Time for GoTime {
    fn before(self, other: Self) -> bool {
        self.compare(other) == Ordering::Less
    }
    fn expired(self, now: Self, seconds: i64) -> bool {
        self.add_nanoseconds(seconds * 1_000_000_000).before(now)
    }
    fn stale(self, now: Self, seconds: i64) -> bool {
        now.sub_nanoseconds(self) > seconds * 1_000_000_000
    }
    fn sample(milliseconds: i64, zero: Self) -> Self {
        SampleTime(milliseconds).as_go_time_at(zero)
    }
    fn sample_delta(new: i64, old: i64) -> i64 {
        SampleTime(new).sub_nanoseconds(SampleTime(old))
    }
    fn initial_key(zero: Self) -> Option<Self> {
        Some(zero)
    }
    fn is_zero(self) -> bool {
        GoTime::is_zero(self)
    }
}

pub(super) struct Values<'a> {
    pub account: &'a Account,
    used: Cell<u16>,
}
impl<'a> Values<'a> {
    pub(super) fn new(account: &'a Account) -> Self {
        Self {
            account,
            used: Cell::new(0),
        }
    }
    fn use_field(&self, bit: u16) {
        self.used.set(self.used.get() | bit);
    }
    pub(super) fn complete(&self) -> bool {
        self.used.get() & !self.account.seen == 0
    }
    pub(super) fn label_matches(&self, value: &str) -> bool {
        if value.is_empty() {
            return true;
        }
        self.use_field(128);
        self.account.label_present && self.account.label == value
    }
    pub(super) fn local(&self) -> bool {
        self.use_field(32);
        self.account.local
    }
}
impl Backend for Values<'_> {
    fn key(&self) -> &str {
        self.use_field(1);
        &self.account.id
    }
    fn touch_address(&self) {
        self.use_field(2);
    }
    fn instance(&self) -> Cow<'_, str> {
        self.touch_address();
        let addr = &self.account.addr;
        let mut tail = addr.as_str();
        let operator = ["-tidb-", ".", "peer", ".svc"].into_iter().all(|part| {
            if let Some(index) = tail.find(part) {
                tail = &tail[index + part.len()..];
                true
            } else {
                false
            }
        });
        if operator {
            return Cow::Borrowed(addr.split('.').next().unwrap_or_default());
        }
        self.use_field(128);
        let host = &self.account.ip;
        // Go converts uint status ports to signed int before formatting.
        let port = i64::from_ne_bytes(self.account.status_port.to_ne_bytes());
        Cow::Owned(if host.contains(':') {
            format!("[{host}]:{port}")
        } else {
            format!("{host}:{port}")
        })
    }
    fn cluster(&self) -> Cow<'_, str> {
        self.use_field(128);
        let cluster = self.account.cluster.trim();
        Cow::Borrowed(if cluster.is_empty() {
            "default"
        } else {
            cluster
        })
    }
    fn physical(&self) -> Count {
        self.use_field(4);
        Count::Go(self.account.physical)
    }
    fn score_count(&self) -> Count {
        self.use_field(8);
        Count::Go(self.account.score_count)
    }
    fn healthy(&self) -> bool {
        self.use_field(16);
        self.account.healthy
    }
}
impl Query for QueryRead {
    type Time = GoTime;
    fn time(&self) -> GoTime {
        self.time
    }
    fn empty(&self) -> bool {
        self.typed_nil
            || matches!(self.shape, Shape::Nil | Shape::None)
            || matches!(self.shape, Shape::Matrix | Shape::Vector) && self.series.is_empty()
    }
    fn samples<'a>(&'a self, backend: &impl Backend, matrix: bool) -> &'a [Sample] {
        let shape = if matrix { Shape::Matrix } else { Shape::Vector };
        if self.typed_nil || self.shape != shape {
            return &[];
        }
        let instance = backend.instance();
        let cluster = backend.cluster();
        self.series
            .iter()
            .find(|series| {
                series.instance.as_deref() == Some(instance.as_ref())
                    && series
                        .cluster
                        .as_ref()
                        .is_none_or(|value| value == cluster.as_ref())
            })
            .map_or(&[], |series| series.samples.as_slice())
    }
}

pub(super) struct Tape<'a> {
    reads: &'a [Read],
    index: usize,
    ordinals: [u16; 10],
}
impl<'a> Tape<'a> {
    pub(super) fn new(reads: &'a [Read]) -> Self {
        Self {
            reads,
            index: 0,
            ordinals: [0; 10],
        }
    }
    pub(super) fn complete(&self) -> bool {
        self.index == self.reads.len()
    }
}
impl<'a> Window<'a, QueryRead> for Tape<'a> {
    type Error = Failure;
    fn query(&mut self, id: QueryId) -> Result<Option<&'a QueryRead>, Failure> {
        match self.reads.get(self.index) {
            Some(Read::Query(query)) if query.query == id && query.empty == Query::empty(query) => {
                self.index += 1;
                Ok(Some(query))
            }
            _ => Err(Failure::Reads),
        }
    }
    fn clock(&mut self, site: ClockSite) -> Result<GoTime, Failure> {
        match self.reads.get(self.index) {
            Some(Read::Clock {
                site: actual,
                ordinal,
                time,
            }) if *actual == site && *ordinal == self.ordinals[site as usize] => {
                self.ordinals[site as usize] += 1;
                self.index += 1;
                Ok(*time)
            }
            _ => Err(Failure::Reads),
        }
    }
}

use super::native::{Configuration, Coverage, Entry, Evaluation};
use crate::factors::{order, phases};
use crate::{BalanceAdvice, Factor, FactorAdvice, FactorScore};
use control_config::{
    EffectiveConfig, RoutingBalancePolicy, RoutingConfig, RoutingSelectionPolicy,
};
use std::sync::Arc;

struct Computed {
    returned: Vec<u8>,
    actual_advice: Vec<(u8, u8, FactorAdvice)>,
    route_seen: Vec<bool>,
    pair: Option<(usize, FactorAdvice)>,
}

/// Private diagnostic factor history. It contains no production identities.
#[derive(Clone)]
pub struct FactorState {
    history: window::History<QueryRead>,
    epoch: super::Epoch,
    group: u64,
    policy: u64,
    config: u64,
    resource: u64,
    last_resource: u64,
    evaluation: u64,
    configuration: Option<Configuration>,
    closed: bool,
    cadence: GoTime,
}
impl FactorState {
    /// Start an empty history from the accepted owner prelude.
    #[must_use]
    pub fn new(coverage: Coverage) -> Self {
        let mut history = window::History::new(coverage.zero_time);
        history.go_arch = coverage.go_arch;
        Self {
            history,
            epoch: coverage.epoch,
            group: 0,
            policy: 0,
            config: 0,
            resource: 0,
            last_resource: 0,
            evaluation: 0,
            configuration: None,
            closed: false,
            cadence: coverage.zero_time,
        }
    }
    /// Apply to a budgeted staged copy. The caller must discard that copy on any
    /// error and commit it only together with the compared owner sequence.
    ///
    /// # Errors
    /// Rejects omitted/reordered reads, missing values, lifetime discontinuity,
    /// or any differing independently computed output.
    pub fn apply(&mut self, e: &Evaluation) -> Result<(), Failure> {
        let factors = self.prepare(e)?;
        let policy = configuration(&e.configuration)?;
        if matches!(e.entry, Entry::Config | Entry::Close)
            || e.accounts.is_empty()
            || e.entry == Entry::Balance && e.accounts.len() <= 1
        {
            self.closed = e.entry == Entry::Close;
            return early(e);
        }
        let inputs: Vec<_> = e.accounts.iter().map(Values::new).collect();
        let mut tape = Tape::new(&e.reads);
        let rows = self.rows(&inputs, &e.configuration, &factors, &mut tape)?;
        for (row, actual) in rows.iter().zip(&e.accounts) {
            if row.score != actual.packed
                || row
                    .parts
                    .iter()
                    .map(|(_, score)| *score)
                    .ne(actual.parts.iter().copied())
            {
                return Err(Failure::Output);
            }
        }
        // Only after independent vectors exist may Go's equal-vector tie order
        // influence the subsequent walk. No missing, duplicate or unequal swap.
        if e.sorted.len() != rows.len() {
            return Err(Failure::Output);
        }
        let mut seen = vec![false; rows.len()];
        let mut previous = None;
        for &index in &e.sorted {
            let i = usize::from(index);
            let row = rows.get(i).ok_or(Failure::Output)?;
            if seen[i] || previous.is_some_and(|score| score > row.score) {
                return Err(Failure::Output);
            }
            seen[i] = true;
            previous = Some(row.score);
        }
        let Computed {
            returned,
            actual_advice,
            route_seen,
            pair,
        } = self.walk(e, &inputs, &rows, &policy, &mut tape)?;
        if !tape.complete() || inputs.iter().any(|input| !input.complete()) {
            return Err(Failure::Reads);
        }
        if e.returned != returned || e.advice.len() != actual_advice.len() {
            return Err(Failure::Output);
        }
        for (actual, (from, to, expected)) in e.advice.iter().zip(actual_advice) {
            let kind = match expected.advice {
                BalanceAdvice::Neutral => 0,
                BalanceAdvice::Negative => 1,
                BalanceAdvice::Positive => 2,
            };
            if (actual.from, actual.to, actual.factor, actual.advice)
                != (from, to, expected.factor, kind)
                || !number(expected.count, f64::from_bits(actual.count), true)
            {
                return Err(Failure::Output);
            }
        }
        for (i, actual) in e.accounts.iter().enumerate() {
            if actual.routeability_seen != route_seen[i]
                || actual.routeable != (route_seen[i] && rows[i].routeable)
            {
                return Err(Failure::Output);
            }
        }
        let (from, to, rate, reason) = pair.map_or((-1, -1, 0.0, None), |(i, a)| {
            (
                i16::from(e.sorted[i]),
                i16::from(e.sorted[0]),
                a.count,
                Some(a.factor),
            )
        });
        if (from, to, reason) != (e.from, e.to, e.reason)
            || !number(rate, f64::from_bits(e.balance_count), false)
        {
            return Err(Failure::Output);
        }
        Ok(())
    }
    fn walk(
        &self,
        e: &Evaluation,
        inputs: &[Values<'_>],
        rows: &[FactorScore],
        policy: &RoutingConfig,
        tape: &mut Tape<'_>,
    ) -> Result<Computed, Failure> {
        let row = |i: usize| &rows[usize::from(e.sorted[i])];
        let input = |i: usize| &inputs[usize::from(e.sorted[i])];
        let mut route_seen = vec![false; inputs.len()];
        let mut routeable = |i: usize| {
            route_seen[usize::from(e.sorted[i])] = true;
            row(i).routeable
        };
        let mut actual_advice = Vec::new();
        let mut advice = |i: usize, factor: Factor| {
            let answer = self.advice(factor, input(i), input(0), policy);
            actual_advice.push((e.sorted[i], e.sorted[0], answer));
            answer
        };
        let mut returned = Vec::new();
        let mut pair = None;
        match e.entry {
            Entry::Routeable => {
                for i in 0..rows.len() {
                    if routeable(i) {
                        returned.push(e.sorted[i]);
                    }
                }
            }
            Entry::Balance => {
                if routeable(0) {
                    pair = phases::balance(
                        rows.len(),
                        row,
                        |i| input(i).physical().positive() && input(i).score_count().positive(),
                        &mut advice,
                    );
                }
            }
            Entry::Route => {
                for input in inputs {
                    input.touch_address();
                }
                match e.configuration.routing.as_str() {
                    "idlest" => {
                        if let Some(i) = (0..rows.len()).find(|&i| routeable(i)) {
                            returned.push(e.sorted[i]);
                        }
                    }
                    "random" => {
                        let choices: Vec<_> = (0..rows.len()).filter(|&i| routeable(i)).collect();
                        if !choices.is_empty() {
                            let i = if choices.len() == 1 {
                                0
                            } else {
                                choices[ticket(tape, ClockSite::RandomTicket, choices.len(), true)?]
                            };
                            returned.push(e.sorted[i]);
                        }
                    }
                    _ => {
                        if routeable(0) {
                            let choices = phases::preferred(rows.len(), row, &mut advice);
                            let i = if choices.len() == 1 {
                                0
                            } else {
                                choices[ticket(
                                    tape,
                                    ClockSite::PreferIdleTicket,
                                    choices.len(),
                                    false,
                                )?]
                            };
                            returned.push(e.sorted[i]);
                        }
                    }
                }
            }
            _ => return Err(Failure::Values),
        }
        Ok(Computed {
            returned,
            actual_advice,
            route_seen,
            pair,
        })
    }

    fn rows(
        &mut self,
        inputs: &[Values<'_>],
        cfg: &Configuration,
        factors: &[Factor],
        tape: &mut Tape<'_>,
    ) -> Result<Vec<FactorScore>, Failure> {
        let cadence = tape.clock(ClockSite::MetricCadence)?;
        let emit = cadence.sub_nanoseconds(self.cadence) > 10_000_000_000;
        if emit {
            self.cadence = cadence;
        }
        let mut parts = vec![Vec::with_capacity(factors.len()); inputs.len()];
        for &factor in factors {
            let active = match factor {
                Factor::Status => {
                    let now = tape.clock(ClockSite::StatusSnapshot)?;
                    self.history.status(inputs, now);
                    false
                }
                Factor::Health if inputs.len() > 1 => self.history.health(inputs, tape)?,
                Factor::Memory if inputs.len() > 1 => self.history.memory(inputs, tape)?,
                Factor::Cpu if inputs.len() > 1 => self.history.cpu(inputs, tape)?,
                _ => false,
            };
            for (input, row) in inputs.iter().zip(&mut parts) {
                row.push((
                    factor,
                    self.score(factor, input, active, inputs.len() > 1, cfg),
                ));
                if emit {
                    input.touch_address();
                }
            }
        }
        let rows: Vec<_> = parts
            .into_iter()
            .zip(inputs)
            .map(|(parts, input)| {
                let (score, routeable) = phases::compose(&parts);
                FactorScore {
                    backend_id: Arc::from(input.key()),
                    score,
                    parts,
                    routeable,
                    advice_to_best: Vec::new(),
                }
            })
            .collect();
        Ok(rows)
    }

    fn prepare(&mut self, e: &Evaluation) -> Result<Vec<Factor>, Failure> {
        if self.closed
            || self.epoch != e.epoch
            || self.evaluation.checked_add(1) != Some(e.evaluation)
        {
            return Err(Failure::Lifetime);
        }
        if self.policy == 0 {
            if e.entry != Entry::Config || e.policy == 0 || e.group == 0 {
                return Err(Failure::Lifetime);
            }
            self.policy = e.policy;
            self.group = e.group;
        }
        if e.policy != self.policy || e.group != self.group {
            return Err(Failure::Lifetime);
        }
        if e.entry == Entry::Config {
            if e.config <= self.config {
                return Err(Failure::Lifetime);
            }
            let resource = e.configuration.balance != "connection";
            if resource {
                if self.resource != 0 {
                    if e.resource != self.resource {
                        return Err(Failure::Lifetime);
                    }
                } else if e.resource <= self.last_resource {
                    return Err(Failure::Lifetime);
                }
                self.last_resource = e.resource;
            } else {
                if e.resource != 0 {
                    return Err(Failure::Lifetime);
                }
                self.history.clear_resources();
            }
            self.config = e.config;
            self.resource = e.resource;
            self.configuration = Some(e.configuration.clone());
        } else if e.config != self.config
            || e.resource != self.resource
            || self.configuration.as_ref() != Some(&e.configuration)
        {
            return Err(Failure::Lifetime);
        }
        let policy = configuration(&e.configuration)?;
        let factors = order(&policy);
        if e.factors.len() != factors.len()
            || e.factors
                .iter()
                .zip(&factors)
                .any(|(&(f, bits), expected)| f != *expected || u32::from(bits) != f.bits())
        {
            return Err(Failure::Values);
        }
        self.evaluation = e.evaluation;
        Ok(factors)
    }

    fn score(
        &self,
        factor: Factor,
        input: &Values<'_>,
        active: bool,
        multiple: bool,
        cfg: &Configuration,
    ) -> u64 {
        let cache = self.history.cache.get(input.key());
        let mut value = phases::ScoreValues {
            go_arch: self.history.go_arch,
            label_matches: true,
            healthy: true,
            local: true,
            connections: 0,
            health_risk: 0,
            memory_risk: 0,
            cpu_usage: 0.0,
        };
        match factor {
            Factor::Label => value.label_matches = input.label_matches(&cfg.self_label),
            Factor::Status => value.healthy = input.healthy(),
            Factor::Location if multiple => value.local = input.local(),
            Factor::Connection => {
                value.connections = u64::try_from(input.account.score_count).unwrap_or(0);
            }
            Factor::Health if active => {
                value.health_risk = cache.and_then(|c| c.health).map_or(0, |v| v.risk);
            }
            Factor::Memory if active => {
                value.memory_risk = cache.and_then(|c| c.memory).map_or(0, |v| v.risk);
            }
            Factor::Cpu if active => value.cpu_usage = self.history.usage(input).1,
            _ => (),
        }
        if factor == Factor::Connection {
            let _ = input.score_count();
        }
        phases::score(factor, value, [active; 3], multiple)
    }
    fn advice(
        &self,
        factor: Factor,
        from: &Values<'_>,
        to: &Values<'_>,
        policy: &RoutingConfig,
    ) -> FactorAdvice {
        let values = |input: &Values<'_>| {
            let cache = self.history.cache.get(input.key());
            phases::AdviceValues {
                connections: if factor == Factor::Connection || factor == Factor::Cpu {
                    input.score_count()
                } else {
                    Count::Go(0)
                },
                status_count: cache.and_then(|c| c.status).map_or(0.0, |(_, v)| v),
                health: cache
                    .and_then(|c| c.health)
                    .map_or((0, 0.0), |v| (v.risk, v.balance)),
                memory: cache
                    .and_then(|c| c.memory)
                    .map_or((0, 0.0), |v| (v.risk, v.balance)),
                cpu: if factor == Factor::Cpu {
                    self.history.usage(input)
                } else {
                    (0.0, 0.0)
                },
            }
        };
        if factor == Factor::Label {
            from.use_field(128);
        }
        phases::advice(
            factor,
            values(from),
            values(to),
            self.history.usage_per_conn,
            policy,
        )
    }
}
fn early(e: &Evaluation) -> Result<(), Failure> {
    if !e.reads.is_empty()
        || !e.sorted.is_empty()
        || !e.advice.is_empty()
        || !e.returned.is_empty()
        || e.from != -1
        || e.to != -1
        || e.balance_count != 0
        || e.reason.is_some()
        || e.accounts.iter().any(|a| {
            a.seen != 0
                || a.packed != 0
                || a.parts.iter().any(|p| *p != 0)
                || a.routeability_seen
                || a.routeable
        })
    {
        return Err(Failure::Output);
    }
    Ok(())
}
fn configuration(cfg: &Configuration) -> Result<RoutingConfig, Failure> {
    let mut policy = EffectiveConfig::default()
        .routing()
        .map_err(|_| Failure::Values)?;
    policy.balance_policy = match cfg.balance.as_str() {
        "resource" => RoutingBalancePolicy::Resource,
        "location" => RoutingBalancePolicy::Location,
        "connection" => RoutingBalancePolicy::Connection,
        _ => return Err(Failure::Values),
    };
    policy.selection_policy = match cfg.routing.as_str() {
        "prefer-idle" | "idlest" => RoutingSelectionPolicy::PreferIdle,
        "random" => RoutingSelectionPolicy::Random,
        _ => return Err(Failure::Values),
    };
    policy.label_name = Arc::from(cfg.label.as_str());
    for (rate, bits) in [
        &mut policy.status.migrations_per_second,
        &mut policy.health.migrations_per_second,
        &mut policy.memory.migrations_per_second,
        &mut policy.cpu.migrations_per_second,
        &mut policy.location.migrations_per_second,
        &mut policy.connection.migrations_per_second,
    ]
    .into_iter()
    .zip(cfg.rates)
    {
        *rate = f64::from_bits(bits);
    }
    policy.connection.count_ratio_threshold = f64::from_bits(cfg.count_ratio);
    Ok(policy)
}
fn ticket(tape: &mut Tape<'_>, site: ClockSite, n: usize, random: bool) -> Result<usize, Failure> {
    let (seconds, nanos, _, _) = tape.clock(site)?.parts();
    let micros = seconds
        .wrapping_sub(62_135_596_800)
        .wrapping_mul(1_000_000)
        .wrapping_add(i64::from(nanos / 1000));
    phases::ticket(
        n,
        random,
        u128::try_from(micros).map_err(|_| Failure::Values)?,
    )
    .ok_or(Failure::Values)
}
#[allow(clippy::float_cmp)] // Handle exact infinity equality before applying tolerance.
fn number(actual: f64, expected: f64, advice: bool) -> bool {
    if expected.is_nan() {
        return actual.is_nan();
    }
    if actual == expected {
        return true;
    }
    if !actual.is_finite() || !expected.is_finite() {
        return false;
    }
    (actual - expected).abs()
        <= if advice {
            expected.abs().max(1.0)
        } else {
            expected.abs()
        } * 1e-10
}

impl FactorState {
    /// Conservative retained allocation charge, including spare vector storage,
    /// complete B-tree nodes and owned strings. Empty history is retained too.
    #[must_use]
    pub fn retained_bytes(&self) -> usize {
        let mut bytes = size_of::<Self>();
        bytes += self.history.cache.len() * 16 * size_of::<(Arc<str>, window::Snapshot<GoTime>)>();
        for id in self.history.cache.keys() {
            bytes += id.len() + 32;
        }
        bytes += self.history.health_queries.len() * 16 * size_of::<(QueryId, QueryRead)>();
        for query in self.history.health_queries.values() {
            bytes += query_bytes(query);
        }
        bytes += self.history.health_dirty.len() * 16 * size_of::<QueryId>();
        if let Some(cfg) = &self.configuration {
            bytes += cfg.balance.capacity()
                + cfg.routing.capacity()
                + cfg.label.capacity()
                + cfg.self_label.capacity();
        }
        bytes
    }
}
fn query_bytes(query: &QueryRead) -> usize {
    let mut bytes = query.series.capacity() * size_of::<super::native::Series>();
    for series in &query.series {
        bytes += series.instance.as_ref().map_or(0, String::capacity)
            + series.cluster.as_ref().map_or(0, String::capacity);
        bytes += series.samples.capacity() * size_of::<Sample>();
    }
    bytes
}
