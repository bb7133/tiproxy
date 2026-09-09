// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Native factor observations. These are bounded, owned diagnostic values;
//! they carry no production account, source, candidate or command capability.

use super::Epoch;
pub use super::native_compute::{FactorState, Failure};
use crate::Factor;
use control_routing::go_time::{GoTime, Origin};
use control_topology::metrics::{QueryId, Sample};

/// Factory metadata before this native owner's first lifecycle event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Coverage {
    /// Complete owner identity; the origin is shared only within this process/nonce.
    pub epoch: Epoch,
    /// Validated process monotonic baseline.
    pub origin: Origin,
    /// Actual owner-local UTC identity of Go's initial zero time.
    pub zero_time: GoTime,
    /// Capturing compiler architecture, independent of the replay host.
    pub go_arch: GoArch,
}

/// The actual native method, including early exits and lifetime boundaries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Entry {
    /// Actual `Init` or `SetConfig` completion.
    Config,
    /// `BackendToRoute`.
    Route,
    /// `RouteableBackends`.
    Routeable,
    /// `BackendsToBalance`.
    Balance,
    /// Actual native policy Close.
    Close,
}

pub use crate::factors::window::{ClockSite, GoArch};

/// The actual Go result shape, including nonempty unsupported metric kinds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Shape {
    /// Nil interface.
    Nil,
    /// model.ValNone.
    None,
    /// Matrix, including zero-length or typed-nil matrix.
    Matrix,
    /// Vector, including zero-length or typed-nil vector.
    Vector,
    /// Scalar; factors do not look up samples from it.
    Scalar,
    /// String; factors do not look up samples from it.
    String,
}

/// Provenance from the same coherent source selection and getter return.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Provenance {
    /// Cluster reader incarnation.
    pub cluster: u64,
    /// Source-mode generation; initial no-source may be zero.
    pub generation: u64,
    /// None, Prometheus, or backend producer (0, 1, 2).
    pub source: u8,
    /// Actual selected producer; absent only for no-source.
    pub producer: u64,
    /// Registration that originally produced a retained result.
    pub registration: u64,
    /// Original result publication.
    pub publication: u64,
    /// Registration present at this getter, possibly zero after unregister.
    pub read_registration: u64,
}

/// The fixed two-label projection avoids an unbounded or overallocated label map.
#[derive(Clone, Debug)]
pub struct Series {
    /// Absent and present-empty instance labels remain distinct.
    pub instance: Option<String>,
    /// Absent cluster labels match any cluster, as in Go.
    pub cluster: Option<String>,
    /// Complete original sample order, including IEEE NaN values.
    pub samples: Vec<Sample>,
}

/// One copied result, with first-match order and all allowlisted sample pairs.
#[derive(Clone, Debug)]
pub struct QueryRead {
    /// One of the six native query keys.
    pub query: QueryId,
    /// Raw Go update-time identity, independent of publication identity.
    pub time: GoTime,
    /// Exact getter provenance.
    pub provenance: Provenance,
    /// Actual result kind.
    pub shape: Shape,
    /// Distinguishes a typed nil from an allocated empty value.
    pub typed_nil: bool,
    /// Go's output; the comparer must recompute it from shape and series.
    pub empty: bool,
    /// Original order; only instance/cluster labels are permitted.
    pub series: Vec<Series>,
}

/// Only clock and query items belong to this ordered tape.
#[derive(Clone, Debug)]
pub enum Read {
    /// One actual named clock read.
    Clock {
        /// Native callsite.
        site: ClockSite,
        /// Zero-based occurrence of this same site.
        ordinal: u16,
        /// Value used by Go at that callsite.
        time: GoTime,
    },
    /// Actual query return, never an end-of-evaluation snapshot.
    Query(QueryRead),
}

/// Values applied by the native factor objects at this configuration boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Configuration {
    /// Resource, Location or Connection.
    pub balance: String,
    /// Prefer-idle, random or idlest.
    pub routing: String,
    /// Actual business-label key.
    pub label: String,
    /// Actual retained self-label value of the label factor.
    pub self_label: String,
    /// IEEE bits for status, health, memory, CPU, location and connection rates.
    pub rates: [u64; 6],
    /// IEEE bits of the connection ratio used by the factor.
    pub count_ratio: u64,
}

/// One bounded backend projection, separate from the independently derived ledger.
#[derive(Clone, Debug)]
// These independent observed facts are not lifecycle states.
#[allow(clippy::struct_excessive_bools)]
pub struct Account {
    /// Diagnostic account incarnation that must already exist in the ledger.
    pub account: u64,
    /// Actual getter presence mask: ID, addr, physical, score, healthy, local,
    /// keyspace and backend info, in that order.
    pub seen: u16,
    /// Actual Go cache key.
    pub id: String,
    /// Actual address used in metric-instance lookup.
    pub addr: String,
    /// Actual authoritative keyspace getter value, if read.
    pub keyspace: String,
    /// Actual status-host IP in backend info.
    pub ip: String,
    /// Actual, unnormalized cluster name.
    pub cluster: String,
    /// Only the configured backend label.
    pub label: String,
    /// Distinguishes absent and empty configured labels.
    pub label_present: bool,
    /// Actual backend status port.
    pub status_port: u64,
    /// Actual physical count, checked against the mirror when read.
    pub physical: i64,
    /// Actual signed score count, checked against the mirror when read.
    pub score_count: i64,
    /// Actual healthy/failover verdict, if read.
    pub healthy: bool,
    /// Actual locality, if read.
    pub local: bool,
    /// Go output segments, kept separate from score inputs.
    pub parts: Vec<u64>,
    /// Go output packed score.
    pub packed: u64,
    /// Actual routeability output.
    pub routeable: bool,
    /// Whether routeability was actually called for this account.
    pub routeability_seen: bool,
}

/// Actual advice call, using input-array account indices.
#[derive(Clone, Copy, Debug)]
pub struct Advice {
    /// Factor called by the actual priority walk.
    pub factor: Factor,
    /// Source input index.
    pub from: u8,
    /// Target input index.
    pub to: u8,
    /// Go enum: neutral=0, negative=1, positive=2.
    pub advice: u8,
    /// IEEE bits of the returned rate.
    pub count: u64,
}

/// A complete native method return, with no partial comparison credit.
#[derive(Clone, Debug)]
pub struct Evaluation {
    /// Complete owner identity.
    pub epoch: Epoch,
    /// One contiguous owner sequence, assigned after native return.
    pub sequence: u64,
    /// Existing group incarnation.
    pub group: u64,
    /// Native policy incarnation, fixed before Init.
    pub policy: u64,
    /// Actual config application identity.
    pub config: u64,
    /// Private resource-factor lifetime; zero while Connection is applied.
    pub resource: u64,
    /// Checked local evaluation counter.
    pub evaluation: u64,
    /// Actual entrypoint.
    pub entry: Entry,
    /// Actual configured factor values.
    pub configuration: Configuration,
    /// Actual factor order and bit widths.
    pub factors: Vec<(Factor, u8)>,
    /// Original input order, with at most 64 accounts.
    pub accounts: Vec<Account>,
    /// At most 128 ordered query/clock items and 64 clocks.
    pub reads: Vec<Read>,
    /// Proposed tie-order witness; validate only after independent scoring.
    pub sorted: Vec<u8>,
    /// Actual advice call order, kept separate from input state.
    pub advice: Vec<Advice>,
    /// Actual returned input indices.
    pub returned: Vec<u8>,
    /// Returned migration source, or -1.
    pub from: i16,
    /// Returned migration target, or -1.
    pub to: i16,
    /// IEEE bits of the actual balance rate.
    pub balance_count: u64,
    /// Actual reason, absent when no factor selected a pair.
    pub reason: Option<Factor>,
}
