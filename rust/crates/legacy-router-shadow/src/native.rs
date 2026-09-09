// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Strict v3 native values. The consumer reserves a conservative staging charge
//! before decoding and retains the resulting values only in its private budget.

use crate::Error;
use control_router::{
    Factor,
    shadow::{Epoch, native as domain},
};
use control_routing::go_time::{GoTime, Origin};
use control_topology::metrics::{QueryId, Sample};
use serde::{
    Deserialize, Deserializer,
    de::{Error as _, SeqAccess, Visitor},
};

/// Fixed native JSON body bound, independent of the older 1MiB frame ceiling.
pub const MAX_BODY: usize = 512 * 1024;
/// Conservative peak decode reservation, including wire/domain overlap and
/// vector reallocations. It is part of the consumer's total 64MiB budget.
pub const DECODE_MULTIPLIER: usize = 32;

#[derive(Clone, Copy, Deserialize)]
#[serde(try_from = "String")]
pub(crate) struct Decimal(pub(crate) u64);
impl TryFrom<String> for Decimal {
    type Error = &'static str;
    fn try_from(text: String) -> Result<Self, Self::Error> {
        let value = text.parse::<u64>().map_err(|_| "decimal")?;
        if value.to_string() != text {
            return Err("canonical decimal");
        }
        Ok(Self(value))
    }
}
#[derive(Clone, Copy, Deserialize)]
#[serde(try_from = "String")]
struct Signed(i64);
impl TryFrom<String> for Signed {
    type Error = &'static str;
    fn try_from(text: String) -> Result<Self, Self::Error> {
        let value = text.parse::<i64>().map_err(|_| "signed decimal")?;
        if value.to_string() != text {
            return Err("canonical signed decimal");
        }
        Ok(Self(value))
    }
}

struct Bounded<T, const N: usize>(Vec<T>);
impl<'de, T: Deserialize<'de>, const N: usize> Deserialize<'de> for Bounded<T, N> {
    fn deserialize<D: Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        struct Values<T, const N: usize>(std::marker::PhantomData<T>);
        impl<'de, T: Deserialize<'de>, const N: usize> Visitor<'de> for Values<T, N> {
            type Value = Bounded<T, N>;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "at most {N} values")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut access: A) -> Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(value) = access.next_element()? {
                    if values.len() == N {
                        return Err(A::Error::custom("array bound"));
                    }
                    values.push(value);
                }
                Ok(Bounded(values))
            }
        }
        decoder.deserialize_seq(Values::<T, N>(std::marker::PhantomData))
    }
}

#[derive(Deserialize)]
pub(crate) struct WireTime(String, Signed, u32, Decimal, bool, Signed);
impl WireTime {
    pub(crate) fn domain(self, origin: Origin) -> Result<GoTime, Error> {
        let Self(domain, seconds, nanos, location, monotonic, relative) = self;
        if domain != "go" || !monotonic && relative.0 != 0 {
            return Err(Error::Schema);
        }
        if monotonic {
            if relative.0 == i64::MIN || relative.0 == i64::MAX {
                return Err(Error::Schema);
            }
            GoTime::from_relative(seconds.0, nanos, location.0, origin, relative.0)
                .ok_or(Error::Schema)
        } else {
            GoTime::new(seconds.0, nanos, location.0, None).ok_or(Error::Schema)
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireOrigin {
    seconds: Signed,
    nanoseconds: u32,
    has_monotonic: bool,
    baseline_present: bool,
    baseline: Signed,
    go_version: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)] // Independent wire facts.
struct WireCoverage {
    version: u32,
    kind: String,
    process: Decimal,
    owner: Decimal,
    nonce: Decimal,
    lifecycle_only: bool,
    factors: bool,
    selection: bool,
    scheduler: bool,
    origin: WireOrigin,
    zero_time: WireTime,
    go_arch: String,
}
impl WireCoverage {
    fn domain(self) -> Result<domain::Coverage, Error> {
        if self.version != 3 {
            return Err(Error::Version);
        }
        if self.kind != "native_coverage"
            || self.lifecycle_only
            || !self.factors
            || self.selection
            || self.scheduler
            || self.origin.has_monotonic != self.origin.baseline_present
            || self.origin.nanoseconds >= 1_000_000_000
        {
            return Err(Error::Schema);
        }
        let origin = Origin::new(
            &self.origin.go_version,
            self.origin.baseline_present,
            self.origin.baseline.0,
        )
        .ok_or(Error::Schema)?;
        // Check the actual origin's wall representation as well as its baseline.
        GoTime::new(
            self.origin.seconds.0,
            self.origin.nanoseconds,
            1,
            self.origin.has_monotonic.then_some(self.origin.baseline.0),
        )
        .ok_or(Error::Schema)?;
        let zero_time = self.zero_time.domain(origin)?;
        if !zero_time.is_zero() || zero_time.parts().3.is_some() {
            return Err(Error::Schema);
        }
        Ok(domain::Coverage {
            epoch: epoch(self.process, self.owner, self.nonce)?,
            origin,
            zero_time,
            go_arch: match self.go_arch.as_str() {
                "arm64" => domain::GoArch::Arm64,
                "amd64" => domain::GoArch::Amd64,
                _ => return Err(Error::Schema),
            },
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireConfiguration {
    balance: String,
    routing: String,
    label: String,
    self_label: String,
    rates: [Decimal; 6],
    count_ratio: Decimal,
}
impl WireConfiguration {
    fn domain(self, budget: &mut ValuesBudget) -> Result<domain::Configuration, Error> {
        if !matches!(
            self.balance.as_str(),
            "resource" | "location" | "connection"
        ) || !matches!(self.routing.as_str(), "prefer-idle" | "random" | "idlest")
        {
            return Err(Error::Schema);
        }
        for value in [&self.balance, &self.routing, &self.label, &self.self_label] {
            budget.text(value)?;
        }
        Ok(domain::Configuration {
            balance: self.balance,
            routing: self.routing,
            label: self.label,
            self_label: self.self_label,
            rates: self.rates.map(|value| value.0),
            count_ratio: self.count_ratio.0,
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)] // Independent wire facts.
struct WireAccount {
    account: Decimal,
    seen: u16,
    id: String,
    addr: String,
    keyspace: String,
    ip: String,
    cluster: String,
    label: String,
    label_present: bool,
    status_port: Decimal,
    physical: Signed,
    score_count: Signed,
    healthy: bool,
    local: bool,
    parts: Bounded<Decimal, 7>,
    packed: Decimal,
    routeable: bool,
    routeability_seen: bool,
}
impl WireAccount {
    fn domain(self, budget: &mut ValuesBudget) -> Result<domain::Account, Error> {
        if self.account.0 == 0 || self.seen > 255 {
            return Err(Error::Schema);
        }
        for value in [
            &self.id,
            &self.addr,
            &self.keyspace,
            &self.ip,
            &self.cluster,
            &self.label,
        ] {
            budget.text(value)?;
        }
        Ok(domain::Account {
            account: self.account.0,
            seen: self.seen,
            id: self.id,
            addr: self.addr,
            keyspace: self.keyspace,
            ip: self.ip,
            cluster: self.cluster,
            label: self.label,
            label_present: self.label_present,
            status_port: self.status_port.0,
            physical: self.physical.0,
            score_count: self.score_count.0,
            healthy: self.healthy,
            local: self.local,
            parts: self.parts.0.into_iter().map(|value| value.0).collect(),
            packed: self.packed.0,
            routeable: self.routeable,
            routeability_seen: self.routeability_seen,
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireProvenance {
    cluster: Decimal,
    generation: Decimal,
    source: u8,
    producer: Decimal,
    registration: Decimal,
    publication: Decimal,
    read_registration: Decimal,
}
impl WireProvenance {
    fn domain(self) -> Result<domain::Provenance, Error> {
        if self.cluster.0 == 0
            || self.source > 2
            || self.source != 0 && (self.generation.0 == 0 || self.producer.0 == 0)
            || self.publication.0 != 0 && self.registration.0 == 0
            || self.source == 0
                && [
                    self.producer.0,
                    self.registration.0,
                    self.publication.0,
                    self.read_registration.0,
                ]
                .into_iter()
                .any(|value| value != 0)
        {
            return Err(Error::Schema);
        }
        Ok(domain::Provenance {
            cluster: self.cluster.0,
            generation: self.generation.0,
            source: self.source,
            producer: self.producer.0,
            registration: self.registration.0,
            publication: self.publication.0,
            read_registration: self.read_registration.0,
        })
    }
}

#[derive(Deserialize)]
struct WireSeries(bool, String, bool, String, Bounded<(Signed, Decimal), 4096>);
impl WireSeries {
    fn domain(self, budget: &mut ValuesBudget) -> Result<domain::Series, Error> {
        let Self(instance_present, instance, cluster_present, cluster, samples) = self;
        if !instance_present && !instance.is_empty() || !cluster_present && !cluster.is_empty() {
            return Err(Error::Schema);
        }
        budget.text(&instance)?;
        budget.text(&cluster)?;
        budget.samples = budget
            .samples
            .checked_add(samples.0.len())
            .ok_or(Error::Capacity)?;
        if budget.samples > 4096 {
            return Err(Error::Capacity);
        }
        let samples = samples
            .0
            .into_iter()
            .map(|(timestamp, value)| Sample {
                timestamp_ms: timestamp.0,
                value: f64::from_bits(value.0),
            })
            .collect();
        Ok(domain::Series {
            instance: instance_present.then_some(instance),
            cluster: cluster_present.then_some(cluster),
            samples,
        })
    }
}

#[derive(Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
enum WireRead {
    #[serde(rename = "clock")]
    Clock {
        site: String,
        ordinal: u16,
        time: WireTime,
    },
    #[serde(rename = "query")]
    Query {
        query: String,
        time: WireTime,
        provenance: WireProvenance,
        value_kind: String,
        typed_nil: bool,
        empty: bool,
        series: Bounded<WireSeries, { MAX_BODY / 16 }>,
    },
}
impl WireRead {
    fn domain(self, origin: Origin, budget: &mut ValuesBudget) -> Result<domain::Read, Error> {
        match self {
            Self::Clock {
                site,
                ordinal,
                time,
            } => {
                budget.clocks += 1;
                if budget.clocks > 64 {
                    return Err(Error::Capacity);
                }
                let site = clock_site(&site)?;
                Ok(domain::Read::Clock {
                    site,
                    ordinal,
                    time: time.domain(origin)?,
                })
            }
            Self::Query {
                query,
                time,
                provenance,
                value_kind,
                typed_nil,
                empty,
                series,
            } => {
                let shape = shape(&value_kind)?;
                let series = series
                    .0
                    .into_iter()
                    .map(|value| value.domain(budget))
                    .collect::<Result<Vec<_>, _>>()?;
                if typed_nil && !series.is_empty()
                    || !matches!(shape, domain::Shape::Matrix | domain::Shape::Vector)
                        && !series.is_empty()
                    || shape == domain::Shape::Nil && typed_nil
                    || shape == domain::Shape::Vector
                        && series.iter().any(|value| value.samples.len() != 1)
                {
                    return Err(Error::Schema);
                }
                let expected_empty = typed_nil
                    || matches!(shape, domain::Shape::Nil | domain::Shape::None)
                    || matches!(shape, domain::Shape::Matrix | domain::Shape::Vector)
                        && series.is_empty();
                if empty != expected_empty {
                    return Err(Error::Schema);
                }
                let provenance = provenance.domain()?;
                if provenance.source == 0 && shape != domain::Shape::Nil {
                    return Err(Error::Schema);
                }
                Ok(domain::Read::Query(domain::QueryRead {
                    query: query_id(&query)?,
                    time: time.domain(origin)?,
                    provenance,
                    shape,
                    typed_nil,
                    empty,
                    series,
                }))
            }
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireEvaluation {
    version: u32,
    kind: String,
    process: Decimal,
    owner: Decimal,
    nonce: Decimal,
    sequence: Decimal,
    group: Decimal,
    policy: Decimal,
    config: Decimal,
    resource: Decimal,
    evaluation: Decimal,
    entry: String,
    configuration: WireConfiguration,
    factors: Bounded<(String, u8), 7>,
    accounts: Bounded<WireAccount, 64>,
    reads: Bounded<WireRead, 128>,
    sorted: Bounded<u8, 64>,
    advice: Bounded<(String, u8, u8, u8, Decimal), 448>,
    returned: Bounded<u8, 64>,
    from: i16,
    to: i16,
    balance_count: Decimal,
    reason: String,
}
// Reuse the strict v3 body inside an externally tagged caller child.
#[derive(Deserialize)]
#[serde(transparent)]
pub(crate) struct NestedEvaluation(WireEvaluation);
impl NestedEvaluation {
    pub(crate) fn domain(self, origin: Origin) -> Result<domain::Evaluation, Error> {
        self.0.domain(origin)
    }
}

impl WireEvaluation {
    fn domain(self, origin: Origin) -> Result<domain::Evaluation, Error> {
        if self.version != 3 {
            return Err(Error::Version);
        }
        if self.kind != "evaluation"
            || [
                self.sequence.0,
                self.group.0,
                self.policy.0,
                self.config.0,
                self.evaluation.0,
            ]
            .contains(&0)
        {
            return Err(Error::Schema);
        }
        let mut budget = ValuesBudget::default();
        let configuration = self.configuration.domain(&mut budget)?;
        let factors = self
            .factors
            .0
            .into_iter()
            .map(|(name, width)| Ok((factor(&name)?, width)))
            .collect::<Result<Vec<_>, Error>>()?;
        let accounts = self
            .accounts
            .0
            .into_iter()
            .map(|value| value.domain(&mut budget))
            .collect::<Result<Vec<_>, _>>()?;
        let reads = self
            .reads
            .0
            .into_iter()
            .map(|value| value.domain(origin, &mut budget))
            .collect::<Result<Vec<_>, _>>()?;
        let advice = self
            .advice
            .0
            .into_iter()
            .map(|(name, from, to, advice, count)| {
                if usize::from(from) >= accounts.len()
                    || usize::from(to) >= accounts.len()
                    || advice > 2
                {
                    return Err(Error::Schema);
                }
                Ok(domain::Advice {
                    factor: factor(&name)?,
                    from,
                    to,
                    advice,
                    count: count.0,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        if self
            .sorted
            .0
            .iter()
            .chain(&self.returned.0)
            .any(|&index| usize::from(index) >= accounts.len())
            || [self.from, self.to].into_iter().any(|index| {
                index < -1 || usize::try_from(index).is_ok_and(|index| index >= accounts.len())
            })
        {
            return Err(Error::Schema);
        }
        Ok(domain::Evaluation {
            epoch: epoch(self.process, self.owner, self.nonce)?,
            sequence: self.sequence.0,
            group: self.group.0,
            policy: self.policy.0,
            config: self.config.0,
            resource: self.resource.0,
            evaluation: self.evaluation.0,
            entry: entry(&self.entry)?,
            configuration,
            factors,
            accounts,
            reads,
            sorted: self.sorted.0,
            advice,
            returned: self.returned.0,
            from: self.from,
            to: self.to,
            balance_count: self.balance_count.0,
            reason: if self.reason.is_empty() {
                None
            } else {
                Some(factor(&self.reason)?)
            },
        })
    }
}

#[derive(Default)]
struct ValuesBudget {
    strings: usize,
    samples: usize,
    clocks: usize,
}
impl ValuesBudget {
    fn text(&mut self, value: &str) -> Result<(), Error> {
        self.strings = self
            .strings
            .checked_add(value.len())
            .ok_or(Error::Capacity)?;
        if value.len() > 512 || self.strings > 64 * 1024 {
            return Err(Error::Capacity);
        }
        Ok(())
    }
}
fn epoch(process: Decimal, owner: Decimal, nonce: Decimal) -> Result<Epoch, Error> {
    if [process.0, owner.0, nonce.0].contains(&0) {
        return Err(Error::Schema);
    }
    Ok(Epoch {
        process: process.0,
        owner: owner.0,
        nonce: nonce.0,
    })
}
fn entry(value: &str) -> Result<domain::Entry, Error> {
    Ok(match value {
        "config" => domain::Entry::Config,
        "route" => domain::Entry::Route,
        "routeable" => domain::Entry::Routeable,
        "balance" => domain::Entry::Balance,
        "close" => domain::Entry::Close,
        _ => return Err(Error::Schema),
    })
}
fn factor(value: &str) -> Result<Factor, Error> {
    Ok(match value {
        "label" => Factor::Label,
        "status" => Factor::Status,
        "health" => Factor::Health,
        "memory" => Factor::Memory,
        "cpu" => Factor::Cpu,
        "location" => Factor::Location,
        "connection" => Factor::Connection,
        _ => return Err(Error::Schema),
    })
}
fn query_id(value: &str) -> Result<QueryId, Error> {
    Ok(match value {
        "failure_pd" => QueryId::FailurePd,
        "total_pd" => QueryId::TotalPd,
        "failure_tikv" => QueryId::FailureTikv,
        "total_tikv" => QueryId::TotalTikv,
        "memory" => QueryId::Memory,
        "cpu" => QueryId::Cpu,
        _ => return Err(Error::Schema),
    })
}
fn shape(value: &str) -> Result<domain::Shape, Error> {
    Ok(match value {
        "nil" => domain::Shape::Nil,
        "none" => domain::Shape::None,
        "matrix" => domain::Shape::Matrix,
        "vector" => domain::Shape::Vector,
        "scalar" => domain::Shape::Scalar,
        "string" => domain::Shape::String,
        _ => return Err(Error::Schema),
    })
}
fn clock_site(value: &str) -> Result<domain::ClockSite, Error> {
    use domain::ClockSite;
    Ok(match value {
        "metric_cadence" => ClockSite::MetricCadence,
        "status_snapshot" => ClockSite::StatusSnapshot,
        "health_expiry" => ClockSite::HealthExpiry,
        "health_snapshot" => ClockSite::HealthSnapshot,
        "memory_snapshot" => ClockSite::MemorySnapshot,
        "memory_expiry" => ClockSite::MemoryExpiry,
        "cpu_snapshot" => ClockSite::CpuSnapshot,
        "cpu_expiry" => ClockSite::CpuExpiry,
        "random_ticket" => ClockSite::RandomTicket,
        "prefer_idle_ticket" => ClockSite::PreferIdleTicket,
        _ => return Err(Error::Schema),
    })
}

/// Exactly one owner prelude or complete evaluation; v1/v2 use their own decoders.
#[derive(Clone, Debug)]
pub enum Frame {
    /// Native capabilities fixed before Begin, with the process origin.
    Coverage(domain::Coverage),
    /// Complete values; parsing grants no comparison credit.
    Evaluation(Box<domain::Evaluation>),
}

#[derive(Deserialize)]
struct Kind {
    kind: String,
}

/// Decode strict native values after the caller has reserved staging memory.
///
/// # Errors
/// Rejects framing, unknown/missing/duplicate fields, bounds, domains and
/// noncanonical scalars. An evaluation requires its already accepted origin.
pub fn decode(frame: &[u8], origin: Option<Origin>) -> Result<Frame, Error> {
    let prefix: [u8; 4] = frame
        .get(..4)
        .ok_or(Error::Framing)?
        .try_into()
        .map_err(|_| Error::Framing)?;
    let length = usize::try_from(u32::from_be_bytes(prefix)).map_err(|_| Error::Oversized)?;
    if length > MAX_BODY {
        return Err(Error::Oversized);
    }
    if length == 0 || length + 4 != frame.len() {
        return Err(Error::Framing);
    }
    let body = &frame[4..];
    let kind: Kind = serde_json::from_slice(body).map_err(|_| Error::Schema)?;
    match kind.kind.as_str() {
        "native_coverage" => serde_json::from_slice::<WireCoverage>(body)
            .map_err(|_| Error::Schema)?
            .domain()
            .map(Frame::Coverage),
        "evaluation" => serde_json::from_slice::<WireEvaluation>(body)
            .map_err(|_| Error::Schema)?
            .domain(origin.ok_or(Error::Schema)?)
            .map(|value| Frame::Evaluation(Box::new(value))),
        _ => Err(Error::Schema),
    }
}

#[derive(Deserialize)]
struct Envelope {
    version: u32,
    kind: String,
    process: Decimal,
    owner: Decimal,
    nonce: Decimal,
}
/// Identify a native frame and its owner after the caller reserves decode memory.
/// Full field/shape validation still runs in the selected version's decoder.
///
/// # Errors
/// Rejects malformed envelopes, duplicate fields, versions and zero native IDs.
pub fn envelope(frame: &[u8]) -> Result<Option<Epoch>, Error> {
    let body = frame.get(4..).ok_or(Error::Framing)?;
    let envelope: Envelope = serde_json::from_slice(body).map_err(|_| Error::Schema)?;
    match envelope.version {
        2 => Ok(None),
        3 if matches!(envelope.kind.as_str(), "native_coverage" | "evaluation") => Ok(Some(epoch(
            envelope.process,
            envelope.owner,
            envelope.nonce,
        )?)),
        _ => Err(Error::Version),
    }
}
