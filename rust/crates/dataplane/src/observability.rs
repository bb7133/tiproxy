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

//! Bounded Rust-dataplane observability (DPL-05).
//!
//! The SQL path only calls [`MetricsRecorder::try_record`], which uses a
//! bounded `try_send`: a full observation queue increments one local atomic
//! and never waits for either the Go process or the control socket. One
//! exporter task aggregates observations into the protocol's bulk lane.
//! Counter and histogram deltas are retained until the transport accepts a
//! batch; gauges are absolute and are sent on every interval so they
//! reconcile after a reconnect.
//!
//! `MetricDelta` has a catalog-defined meaning:
//!
//! - counters use non-negative `counter_delta`;
//! - gauges use the absolute `gauge` value;
//! - histograms use `counter_delta` as sample-count delta, `gauge` as
//!   sample-sum delta, and one cumulative delta per finite Prometheus bucket.
//!
//! Names, label keys, label sizes, series count, and bucket counts are closed
//! and bounded here and again in the Go consumer. No SQL, password, token, or
//! authentication payload can enter an observation or a log field.

use std::collections::{BTreeMap, HashMap};
use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::Duration;

use control_proto::control_transport::ControlClient;
#[cfg(test)]
use control_proto::v1::MetricDelta;
use session_core::command::Command;
pub use session_core::error_source::ErrorSource as QuitSource;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

use crate::control_dispatch::DispatchStats;
use crate::route_control::TrafficTotals;
use crate::runtime_config::DataplaneServingHandle;
use crate::server::ServerMetricsSnapshot;

/// Default SQL-path observation capacity. A full queue sheds metrics only.
pub const DEFAULT_OBSERVATION_CAPACITY: usize = 4_096;
/// Maximum entries accepted by the Go batch validator.
const MAX_METRICS_PER_BATCH: usize = 1_024;
/// Maximum dynamic series retained in one unsent batch. Reserve one entry
/// for the absolute connection gauge emitted on every interval.
const MAX_PENDING_SERIES: usize = MAX_METRICS_PER_BATCH - 1;
/// Maximum bytes in a backend label or one structured-log string field.
const MAX_LABEL_BYTES: usize = 256;

const QUERY_BUCKETS: [f64; 29] = exponential_buckets(0.0005, 2.0);
const HANDSHAKE_BUCKETS: [f64; 29] = QUERY_BUCKETS;
const QUERY_AGE_BUCKETS: [f64; 21] = exponential_buckets(1.0, 2.0);
const CONN_LIFETIME_BUCKETS: [f64; 25] = exponential_buckets(0.1, 2.0);
const GET_BACKEND_BUCKETS: [f64; 26] = exponential_buckets(0.000_001, 2.0);
/// Go `MigrateDurationHistogram`: ExponentialBuckets(0.0001, 2, 26), 0.1ms ~ 1h.
const MIGRATE_BUCKETS: [f64; 26] = exponential_buckets(0.000_1, 2.0);

const fn exponential_buckets<const N: usize>(start: f64, factor: f64) -> [f64; N] {
    let mut buckets = [0.0; N];
    let mut index = 0;
    let mut value = start;
    while index < N {
        buckets[index] = value;
        value *= factor;
        index += 1;
    }
    buckets
}

/// Maximum distinct series the process-local registry retains, matching the Go
/// consumer's `maxRustMetricSeries`. Beyond it new series are shed and counted.
const MAX_REGISTRY_SERIES: usize = 4_096;

/// Upper bound on cached per-(backend, command) key sets in the aggregator.
/// Each entry is eight small keys; the bound only limits memory, never which
/// observations are accepted.
const MAX_COMMAND_KEY_CACHE: usize = 1_024;

/// Prometheus metric kind of one catalog entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetricKind {
    /// Monotonic counter published as deltas.
    Counter,
    /// Absolute gauge published on every interval.
    Gauge,
    /// Cumulative histogram with fixed buckets.
    Histogram,
}

impl MetricKind {
    const fn exposition_type(self) -> &'static str {
        match self {
            Self::Counter => "counter",
            Self::Gauge => "gauge",
            Self::Histogram => "histogram",
        }
    }
}

/// One closed-catalog metric family. Names, help text, label keys, and
/// buckets mirror `pkg/metrics` so the native exposition is byte-compatible
/// with the Go `promhttp` output for the same series.
#[derive(Debug, Clone, Copy)]
pub struct MetricSpec {
    /// Fully qualified metric name.
    pub name: &'static str,
    /// `# HELP` text.
    pub help: &'static str,
    /// Metric kind.
    pub kind: MetricKind,
    /// Label keys in exposition order (alphabetical, matching Go).
    pub labels: &'static [&'static str],
    /// Finite histogram bucket upper bounds; empty for counters and gauges.
    pub buckets: &'static [f64],
}

/// The closed metric catalog, sorted by name (the order the Go gatherer uses).
pub const METRIC_SPECS: [MetricSpec; 32] = [
    MetricSpec {
        name: "tiproxy_backend_b_status",
        help: "Gauge of backend status.",
        kind: MetricKind::Gauge,
        labels: &["backend"],
        buckets: &[],
    },
    MetricSpec {
        name: "tiproxy_backend_backend_metric",
        help: "The backend metric.",
        kind: MetricKind::Gauge,
        labels: &["backend", "metric"],
        buckets: &[],
    },
    MetricSpec {
        name: "tiproxy_backend_dial_backend_fail",
        help: "Counter of failing to dial backends.",
        kind: MetricKind::Counter,
        labels: &["backend"],
        buckets: &[],
    },
    MetricSpec {
        name: "tiproxy_backend_get_backend",
        help: "Counter of getting backend.",
        kind: MetricKind::Counter,
        labels: &["res"],
        buckets: &[],
    },
    MetricSpec {
        name: "tiproxy_backend_get_backend_duration_seconds",
        help: "Bucketed histogram of time (s) for getting an available backend.",
        kind: MetricKind::Histogram,
        labels: &[],
        buckets: &GET_BACKEND_BUCKETS,
    },
    MetricSpec {
        name: "tiproxy_backend_health_check_seconds",
        help: "Time (s) of each health check cycle.",
        kind: MetricKind::Gauge,
        labels: &[],
        buckets: &[],
    },
    MetricSpec {
        name: "tiproxy_backend_keepalive_update_total",
        help: "Counter of health-driven backend keepalive policy updates.",
        kind: MetricKind::Counter,
        labels: &["backend", "health", "result"],
        buckets: &[],
    },
    MetricSpec {
        name: "tiproxy_backend_ping_duration_seconds",
        help: "Time (s) of pinging the SQL port of each backend.",
        kind: MetricKind::Gauge,
        labels: &["backend"],
        buckets: &[],
    },
    MetricSpec {
        name: "tiproxy_balance_b_conn",
        help: "Number of backend connections.",
        kind: MetricKind::Gauge,
        labels: &["backend"],
        buckets: &[],
    },
    MetricSpec {
        name: "tiproxy_balance_b_score",
        help: "Gauge of backend scores.",
        kind: MetricKind::Gauge,
        labels: &["backend", "factor"],
        buckets: &[],
    },
    MetricSpec {
        name: "tiproxy_balance_migrate_duration_seconds",
        help: "Bucketed histogram of migrating time (s) of sessions.",
        kind: MetricKind::Histogram,
        labels: &["from", "migrate_res", "to"],
        buckets: &MIGRATE_BUCKETS,
    },
    MetricSpec {
        name: "tiproxy_balance_migrate_total",
        help: "Number and result of session migration.",
        kind: MetricKind::Counter,
        labels: &["from", "migrate_res", "reason", "to"],
        buckets: &[],
    },
    MetricSpec {
        name: "tiproxy_balance_pending_migrate",
        help: "Number of pending session migration.",
        kind: MetricKind::Gauge,
        labels: &["from", "reason", "to"],
        buckets: &[],
    },
    MetricSpec {
        name: "tiproxy_monitor_keep_alive_total",
        help: "Counter of proxy keep alive.",
        kind: MetricKind::Counter,
        labels: &[],
        buckets: &[],
    },
    MetricSpec {
        name: "tiproxy_monitor_time_jump_back_total",
        help: "Counter of system time jumps backward.",
        kind: MetricKind::Counter,
        labels: &[],
        buckets: &[],
    },
    MetricSpec {
        name: "tiproxy_server_connections",
        help: "Number of connections.",
        kind: MetricKind::Gauge,
        labels: &[],
        buckets: &[],
    },
    MetricSpec {
        name: "tiproxy_server_create_connection_total",
        help: "Number of create connections.",
        kind: MetricKind::Counter,
        labels: &[],
        buckets: &[],
    },
    MetricSpec {
        name: "tiproxy_server_disconnection_total",
        help: "Number of disconnections.",
        kind: MetricKind::Counter,
        labels: &["type"],
        buckets: &[],
    },
    MetricSpec {
        name: "tiproxy_server_err",
        help: "Counter of server error.",
        kind: MetricKind::Counter,
        labels: &["type"],
        buckets: &[],
    },
    MetricSpec {
        name: "tiproxy_server_event",
        help: "Counter of TiProxy event.",
        kind: MetricKind::Counter,
        labels: &["type"],
        buckets: &[],
    },
    MetricSpec {
        name: "tiproxy_server_owner",
        help: "The TiProxy owner of each job type.",
        kind: MetricKind::Gauge,
        labels: &["type"],
        buckets: &[],
    },
    MetricSpec {
        name: "tiproxy_server_reject_connection_total",
        help: "Number of rejected connections.",
        kind: MetricKind::Counter,
        labels: &["type"],
        buckets: &[],
    },
    MetricSpec {
        name: "tiproxy_session_conn_lifetime_seconds",
        help: "Bucketed histogram of connection lifetime (s).",
        kind: MetricKind::Histogram,
        labels: &[],
        buckets: &CONN_LIFETIME_BUCKETS,
    },
    MetricSpec {
        name: "tiproxy_session_handshake_duration_seconds",
        help: "Bucketed histogram of processing time (s) of handshakes.",
        kind: MetricKind::Histogram,
        labels: &["backend"],
        buckets: &HANDSHAKE_BUCKETS,
    },
    MetricSpec {
        name: "tiproxy_session_query_duration_seconds",
        help: "Bucketed histogram of processing time (s) of handled queries.",
        kind: MetricKind::Histogram,
        labels: &["backend", "cmd_type"],
        buckets: &QUERY_BUCKETS,
    },
    MetricSpec {
        name: "tiproxy_session_query_time_since_conn_creation_seconds",
        help: "Bucketed histogram of query start time (s) since connection creation.",
        kind: MetricKind::Histogram,
        labels: &[],
        buckets: &QUERY_AGE_BUCKETS,
    },
    MetricSpec {
        name: "tiproxy_session_query_total",
        help: "Counter of queries.",
        kind: MetricKind::Counter,
        labels: &["backend", "cmd_type"],
        buckets: &[],
    },
    MetricSpec {
        name: "tiproxy_traffic_cross_location_bytes",
        help: "Counter of bytes between TiProxy and cross-location backends.",
        kind: MetricKind::Counter,
        labels: &[],
        buckets: &[],
    },
    MetricSpec {
        name: "tiproxy_traffic_inbound_bytes",
        help: "Counter of bytes from backends.",
        kind: MetricKind::Counter,
        labels: &["backend"],
        buckets: &[],
    },
    MetricSpec {
        name: "tiproxy_traffic_inbound_packets",
        help: "Counter of packets from backends.",
        kind: MetricKind::Counter,
        labels: &["backend"],
        buckets: &[],
    },
    MetricSpec {
        name: "tiproxy_traffic_outbound_bytes",
        help: "Counter of bytes to backends.",
        kind: MetricKind::Counter,
        labels: &["backend"],
        buckets: &[],
    },
    MetricSpec {
        name: "tiproxy_traffic_outbound_packets",
        help: "Counter of packets to backends.",
        kind: MetricKind::Counter,
        labels: &["backend"],
        buckets: &[],
    },
];

/// Formats a float exactly like Go's `strconv.FormatFloat(f, 'g', -1, 64)`,
/// which is what `expfmt` uses for sample values and `le` bucket labels: the
/// shortest round-trip digits, exponent form when the decimal exponent is
/// below -4 or at least 6, and a signed two-digit-minimum exponent.
#[must_use]
pub fn format_go_float(value: f64) -> String {
    if value.is_nan() {
        return "NaN".to_owned();
    }
    if value.is_infinite() {
        return if value > 0.0 { "+Inf" } else { "-Inf" }.to_owned();
    }
    if value == 0.0 {
        return "0".to_owned();
    }
    let scientific = format!("{value:e}");
    let (mantissa, exponent) = scientific
        .split_once('e')
        .unwrap_or((scientific.as_str(), "0"));
    let exponent: i32 = exponent.parse().unwrap_or(0);
    let negative = mantissa.starts_with('-');
    let digits: String = mantissa.chars().filter(char::is_ascii_digit).collect();
    let mut out = String::new();
    if negative {
        out.push('-');
    }
    if !(-4..6).contains(&exponent) {
        out.push_str(&digits[..1]);
        if digits.len() > 1 {
            out.push('.');
            out.push_str(&digits[1..]);
        }
        out.push('e');
        out.push(if exponent < 0 { '-' } else { '+' });
        let _ = write!(out, "{:02}", exponent.abs());
    } else if exponent < 0 {
        out.push_str("0.");
        for _ in 0..(-exponent - 1) {
            out.push('0');
        }
        out.push_str(&digits);
    } else {
        let point = usize::try_from(exponent).unwrap_or(0) + 1;
        if digits.len() <= point {
            out.push_str(&digits);
            for _ in 0..(point - digits.len()) {
                out.push('0');
            }
        } else {
            out.push_str(&digits[..point]);
            out.push('.');
            out.push_str(&digits[point..]);
        }
    }
    out
}

fn escape_help(value: &str) -> String {
    value.replace('\\', "\\\\").replace('\n', "\\n")
}

fn escape_label_value(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('\n', "\\n")
        .replace('"', "\\\"")
}

#[derive(Debug, Clone, Default)]
struct HistogramState {
    count: u64,
    sum: f64,
    cumulative_buckets: Vec<u64>,
}

#[derive(Debug, Default)]
struct RegistryState {
    counters: BTreeMap<MetricKey, u64>,
    histograms: BTreeMap<MetricKey, HistogramState>,
    gauges: BTreeMap<MetricKey, f64>,
    series_dropped: u64,
}

impl RegistryState {
    fn series_count(&self) -> usize {
        self.counters.len() + self.histograms.len() + self.gauges.len()
    }

    /// opt#7b: the steady-state path (series already present) is one map
    /// lookup and no allocation; the key is cloned only when a series is
    /// first inserted. Callers that fold several updates per observation hold
    /// the registry lock once around all of them.
    fn add_counter(&mut self, key: &MetricKey, delta: u64) {
        if let Some(value) = self.counters.get_mut(key) {
            *value = value.saturating_add(delta);
            return;
        }
        if self.series_count() >= MAX_REGISTRY_SERIES {
            self.series_dropped = self.series_dropped.saturating_add(1);
            return;
        }
        self.counters.insert(key.clone(), delta);
    }

    /// Batch twin of [`Self::observe_histogram`]: `count` observations whose
    /// cumulative bucket counts and sum were accumulated elsewhere. Sheds all
    /// of them at the series bound, counting each.
    fn observe_histogram_batch(
        &mut self,
        key: &MetricKey,
        count: u64,
        sum: f64,
        cumulative: &[u64],
    ) {
        if let Some(entry) = self.histograms.get_mut(key) {
            entry.add_batch(count, sum, cumulative);
            return;
        }
        if self.series_count() >= MAX_REGISTRY_SERIES {
            self.series_dropped = self.series_dropped.saturating_add(count);
            return;
        }
        let mut entry = HistogramState {
            cumulative_buckets: vec![0; cumulative.len()],
            ..HistogramState::default()
        };
        entry.add_batch(count, sum, cumulative);
        self.histograms.insert(key.clone(), entry);
    }

    fn observe_histogram(&mut self, key: &MetricKey, seconds: f64, buckets: &[f64]) {
        if let Some(entry) = self.histograms.get_mut(key) {
            entry.observe(seconds, buckets);
            return;
        }
        if self.series_count() >= MAX_REGISTRY_SERIES {
            self.series_dropped = self.series_dropped.saturating_add(1);
            return;
        }
        let mut entry = HistogramState {
            cumulative_buckets: vec![0; buckets.len()],
            ..HistogramState::default()
        };
        entry.observe(seconds, buckets);
        self.histograms.insert(key.clone(), entry);
    }
}

impl HistogramState {
    fn add_batch(&mut self, count: u64, sum: f64, cumulative: &[u64]) {
        self.count = self.count.saturating_add(count);
        self.sum += sum;
        for (bucket, add) in self.cumulative_buckets.iter_mut().zip(cumulative) {
            *bucket = bucket.saturating_add(*add);
        }
    }

    fn observe(&mut self, seconds: f64, buckets: &[f64]) {
        self.count = self.count.saturating_add(1);
        self.sum += seconds;
        for (upper, bucket) in buckets.iter().zip(self.cumulative_buckets.iter_mut()) {
            if seconds <= *upper {
                *bucket = bucket.saturating_add(1);
            }
        }
    }
}

/// Supplies the authoritative migration state at render time.
///
/// The three session-migration families are not accumulated from
/// notifications: a bounded queue drops observations by design, and a lost one
/// would make a delta permanently wrong. They are read from router and
/// process state instead, so a missed notification costs at most staleness.
///
/// Implementations take router locks, so this is called with **no** registry
/// lock held: the settlement path runs router lock then registry, and
/// inverting that here would deadlock against it.
pub trait MigrationStateSource: Send + Sync {
    /// In-flight counts summed over live incarnations, plus the process-level
    /// cumulative history.
    fn migration_state(&self) -> control_router::MigrationSnapshot;
}

/// Authoritative source for the three backend health families.
///
/// Separate from [`MigrationStateSource`] because the state has a different
/// owner: these values are written by the topology health child and by the
/// SQL probes, not by any router. Like the migration source it is read
/// without the registry lock, and for the same reason -- the provider takes
/// the history's own lock, and a scrape must never be able to hold a health
/// round up behind the exposition.
pub trait HealthStateSource: Send + Sync {
    /// The current value of every backend health series.
    fn health_state(&self) -> control_topology::HealthMetricsSnapshot;
}

/// The history itself is the source: it already holds exactly the values the
/// three families expose, so an adapter would only forward `snapshot`.
impl HealthStateSource for control_topology::BackendHealthHistory {
    fn health_state(&self) -> control_topology::HealthMetricsSnapshot {
        self.snapshot()
    }
}

/// Authoritative source for `backend_metric`.
pub trait BackendMetricStateSource: Send + Sync {
    /// The retained raw backend observations.
    fn backend_metric_state(&self) -> control_router::BackendMetricSnapshot;
}

/// The history itself is the source; an adapter would only forward.
impl BackendMetricStateSource for control_router::BackendMetricHistory {
    fn backend_metric_state(&self) -> control_router::BackendMetricSnapshot {
        self.snapshot()
    }
}

/// Authoritative source for `b_score`.
///
/// Held separately again because the writer is the balance round and the
/// retention rule is its own: the family survives a backend leaving the
/// topology and is cleared only by a configuration change.
pub trait ScoreStateSource: Send + Sync {
    /// The retained per-factor scores.
    fn score_state(&self) -> control_router::ScoreSnapshot;
}

/// The history itself is the source; an adapter would only forward.
impl ScoreStateSource for control_router::ScoreHistory {
    fn score_state(&self) -> control_router::ScoreSnapshot {
        self.snapshot()
    }
}

/// Authoritative source for `server_owner`.
///
/// Separate again from the health families: the writers are the election
/// workers, and the state is a set of held elections rather than a map of
/// values, because Go deletes the child on retirement instead of zeroing it.
pub trait OwnerStateSource: Send + Sync {
    /// The elections this process holds right now.
    fn owner_state(&self) -> control_topology::OwnerSnapshot;
}

/// The history itself is the source; an adapter would only forward.
impl OwnerStateSource for control_topology::ElectionOwnerHistory {
    fn owner_state(&self) -> control_topology::OwnerSnapshot {
        self.snapshot()
    }
}

/// Process-local cumulative store behind the native Prometheus exposition.
///
/// Counters and histograms reset with the process, which is ordinary
/// Prometheus counter semantics. The three session-migration families are the
/// exception: nothing about them is stored here, they are read from
/// authoritative state when the exposition renders.
#[derive(Default)]
pub struct MetricsRegistry {
    state: Mutex<RegistryState>,
    /// Deliberately not inside `state`: reading it must not need the lock
    /// that rendering takes, so the snapshot can be fetched before it.
    migrations: Mutex<Option<Arc<dyn MigrationStateSource>>>,
    /// The backend health families' source, held for the same reason.
    health: Mutex<Option<Arc<dyn HealthStateSource>>>,
    /// `server_owner`'s source, held for the same reason.
    owner: Mutex<Option<Arc<dyn OwnerStateSource>>>,
    /// `b_score`'s source, held for the same reason.
    scores: Mutex<Option<Arc<dyn ScoreStateSource>>>,
    /// `backend_metric`'s source, held for the same reason.
    backend_metrics: Mutex<Option<Arc<dyn BackendMetricStateSource>>>,
}

impl std::fmt::Debug for MetricsRegistry {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MetricsRegistry")
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

impl MetricsRegistry {
    /// Creates an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Installs the authoritative source for the migration families.
    pub fn set_migration_state_source(&self, source: Arc<dyn MigrationStateSource>) {
        *self
            .migrations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(source);
    }

    /// Installs the authoritative source for the backend health families.
    pub fn set_health_state_source(&self, source: Arc<dyn HealthStateSource>) {
        *self
            .health
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(source);
    }

    /// Reads health state while holding no registry lock, as for migrations.
    fn health_state(&self) -> control_topology::HealthMetricsSnapshot {
        let source = self
            .health
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        source
            .map(|source| source.health_state())
            .unwrap_or_default()
    }

    /// Installs the authoritative source for `backend_metric`.
    pub fn set_backend_metric_state_source(&self, source: Arc<dyn BackendMetricStateSource>) {
        *self
            .backend_metrics
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(source);
    }

    /// Reads the observations while holding no registry lock, as for the rest.
    fn backend_metric_state(&self) -> control_router::BackendMetricSnapshot {
        let source = self
            .backend_metrics
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        source
            .map(|source| source.backend_metric_state())
            .unwrap_or_default()
    }

    /// Label pairs the observation retention refused.
    #[must_use]
    pub fn backend_metric_labels_dropped(&self) -> u64 {
        self.backend_metric_state().labels_dropped
    }

    /// Installs the authoritative source for `b_score`.
    pub fn set_score_state_source(&self, source: Arc<dyn ScoreStateSource>) {
        *self
            .scores
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(source);
    }

    /// Reads score state while holding no registry lock, as for the rest.
    fn score_state(&self) -> control_router::ScoreSnapshot {
        let source = self
            .scores
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        source
            .map(|source| source.score_state())
            .unwrap_or_default()
    }

    /// Label pairs the score retention refused, folded into the same counter.
    #[must_use]
    pub fn score_labels_dropped(&self) -> u64 {
        self.score_state().labels_dropped
    }

    /// Installs the authoritative source for `server_owner`.
    pub fn set_owner_state_source(&self, source: Arc<dyn OwnerStateSource>) {
        *self
            .owner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(source);
    }

    /// Reads election state while holding no registry lock, as for the rest.
    fn owner_state(&self) -> control_topology::OwnerSnapshot {
        let source = self
            .owner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        source
            .map(|source| source.owner_state())
            .unwrap_or_default()
    }

    /// Elections the retained set refused, folded into the same counter.
    #[must_use]
    pub fn owner_labels_dropped(&self) -> u64 {
        self.owner_state().labels_dropped
    }

    /// Addresses the health retention refused, folded into the same visible
    /// dropped-observation counter as every other shed signal.
    #[must_use]
    pub fn health_labels_dropped(&self) -> u64 {
        self.health_state().labels_dropped
    }

    /// Label sets the migration retention refused, for the same visible
    /// dropped-observation counter every other shed signal reports through.
    /// A silent overflow would be worse here than before, since this path
    /// replaced one that was already counted.
    #[must_use]
    pub fn migration_labels_dropped(&self) -> u64 {
        self.migration_state().history.labels_dropped
    }

    /// Reads migration state while holding no registry lock: the source is
    /// cloned out and its guard dropped before the provider runs.
    fn migration_state(&self) -> control_router::MigrationSnapshot {
        let source = self
            .migrations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        source
            .map(|source| source.migration_state())
            .unwrap_or_default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, RegistryState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn add_counter(&self, key: &MetricKey, delta: u64) {
        RegistryState::add_counter(&mut self.lock(), key, delta);
    }

    fn set_gauge(&self, name: &'static str, value: f64) {
        self.set_labeled_gauge(&MetricKey::new(name, Vec::new()), value);
    }

    /// Sets one label combination of a gauge family. Labeled gauges (per
    /// backend, per migration pair) are unbounded in principle, so they share
    /// the counter/histogram series bound rather than growing without limit.
    fn set_labeled_gauge(&self, key: &MetricKey, value: f64) {
        let mut state = self.lock();
        if !state.gauges.contains_key(key) && state.series_count() >= MAX_REGISTRY_SERIES {
            state.series_dropped = state.series_dropped.saturating_add(1);
            return;
        }
        state.gauges.insert(key.clone(), value);
    }

    /// Number of new series shed because the registry reached its bound.
    #[must_use]
    pub fn series_dropped(&self) -> u64 {
        self.lock().series_dropped
    }

    /// Renders the Prometheus text exposition (`text/plain; version=0.0.4`)
    /// for every catalog family, in the Go gatherer's name order. Unlabeled
    /// families are always present (with zero values, like Go's plain
    /// collectors); labeled families appear once they have a series.
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn render_prometheus_text(&self) -> String {
        // Fetched first, holding nothing: the provider takes router locks and
        // the settlement path already runs router lock then registry.
        let migrations = self.migration_state();
        let health = self.health_state();
        let owner = self.owner_state();
        let scores = self.score_state();
        let observations = self.backend_metric_state();
        let state = self.lock();
        let mut out = String::new();
        for spec in &METRIC_SPECS {
            if let Some(rendered) = render_backend_metric_family(spec, &observations) {
                // Owned by the resource and health factors.
                out.push_str(&rendered);
                continue;
            }
            if let Some(rendered) = render_score_family(spec, &scores) {
                // Owned by the balance round, never accumulated here.
                out.push_str(&rendered);
                continue;
            }
            if let Some(rendered) = render_owner_family(spec, &owner) {
                // Owned by the election workers, never accumulated here.
                out.push_str(&rendered);
                continue;
            }
            if let Some(rendered) = render_health_family(spec, &health) {
                // Owned by the topology health path, never accumulated here.
                out.push_str(&rendered);
                continue;
            }
            if let Some(rendered) = render_migration_family(spec, &migrations) {
                // Served from authoritative state, never from anything this
                // registry accumulated.
                out.push_str(&rendered);
                continue;
            }
            let mut lines = String::new();
            match spec.kind {
                MetricKind::Counter => {
                    let mut any = false;
                    for (key, value) in state.counters.range(family_range(spec.name)) {
                        any = true;
                        push_sample(&mut lines, spec.name, "", &key.labels, None, *value as f64);
                    }
                    if !any && spec.labels.is_empty() {
                        push_sample(&mut lines, spec.name, "", &[], None, 0.0);
                    }
                }
                MetricKind::Gauge => {
                    let mut any = false;
                    for (key, value) in state.gauges.range(family_range(spec.name)) {
                        any = true;
                        push_sample(&mut lines, spec.name, "", &key.labels, None, *value);
                    }
                    if !any && spec.labels.is_empty() {
                        push_sample(&mut lines, spec.name, "", &[], None, 0.0);
                    }
                }
                MetricKind::Histogram => {
                    let mut any = false;
                    for (key, value) in state.histograms.range(family_range(spec.name)) {
                        any = true;
                        push_histogram(&mut lines, spec, &key.labels, value);
                    }
                    if !any && spec.labels.is_empty() {
                        let zero = HistogramState {
                            cumulative_buckets: vec![0; spec.buckets.len()],
                            ..HistogramState::default()
                        };
                        push_histogram(&mut lines, spec, &[], &zero);
                    }
                }
            }
            if lines.is_empty() {
                continue;
            }
            let _ = writeln!(out, "# HELP {} {}", spec.name, escape_help(spec.help));
            let _ = writeln!(out, "# TYPE {} {}", spec.name, spec.kind.exposition_type());
            out.push_str(&lines);
        }
        out
    }
}

/// The `BTreeMap` key range covering every label combination of one family.
fn family_range(name: &'static str) -> std::ops::RangeInclusive<MetricKey> {
    MetricKey::new(name, Vec::new())..=MetricKey::new(name, vec![("\u{10ffff}", String::new())])
}

#[allow(clippy::cast_precision_loss)]
fn push_histogram(
    out: &mut String,
    spec: &MetricSpec,
    labels: &[(&'static str, String)],
    value: &HistogramState,
) {
    for (upper, count) in spec.buckets.iter().zip(&value.cumulative_buckets) {
        push_sample(
            out,
            spec.name,
            "_bucket",
            labels,
            Some(*upper),
            *count as f64,
        );
    }
    push_sample(
        out,
        spec.name,
        "_bucket",
        labels,
        Some(f64::INFINITY),
        value.count as f64,
    );
    push_sample(out, spec.name, "_sum", labels, None, value.sum);
    push_sample(out, spec.name, "_count", labels, None, value.count as f64);
}

/// Renders one of the three session-migration families from authoritative
/// state, or `None` for any other family.
///
/// Label order matches Go's exposition, which sorts label pairs by name.
fn render_migration_family(
    spec: &MetricSpec,
    state: &control_router::MigrationSnapshot,
) -> Option<String> {
    let mut lines = String::new();
    match spec.name {
        "tiproxy_balance_b_conn" => render_backend_connections(spec, state, &mut lines),
        "tiproxy_balance_pending_migrate" => {
            // Every label set ever seen is emitted, so a series that has
            // returned to zero keeps reporting instead of disappearing.
            for (from, to, reason) in &state.history.known_pending {
                let labels = control_router::MigrationLabels {
                    from: from.clone(),
                    to: to.clone(),
                    reason: *reason,
                };
                let value = state.pending.get(&labels).copied().unwrap_or(0);
                push_sample(
                    &mut lines,
                    spec.name,
                    "",
                    &[
                        ("from", from.clone()),
                        ("reason", reason.metric_name().to_owned()),
                        ("to", to.clone()),
                    ],
                    None,
                    counter_as_f64(value),
                );
            }
        }
        "tiproxy_balance_migrate_total" => {
            for (key, count) in &state.history.terminals {
                push_sample(
                    &mut lines,
                    spec.name,
                    "",
                    &[
                        ("from", key.from.clone()),
                        ("migrate_res", migrate_result(key.succeeded).to_owned()),
                        ("reason", key.reason.metric_name().to_owned()),
                        ("to", key.to.clone()),
                    ],
                    None,
                    counter_as_f64(*count),
                );
            }
        }
        "tiproxy_balance_migrate_duration_seconds" => {
            for (key, series) in &state.history.durations {
                let labels = [
                    ("from", key.from.clone()),
                    ("migrate_res", migrate_result(key.succeeded).to_owned()),
                    ("to", key.to.clone()),
                ];
                for (count, bound) in series
                    .buckets
                    .iter()
                    .zip(control_router::MIGRATE_DURATION_BUCKETS)
                {
                    push_sample(
                        &mut lines,
                        spec.name,
                        "_bucket",
                        &labels,
                        Some(bound),
                        counter_as_f64(*count),
                    );
                }
                push_sample(
                    &mut lines,
                    spec.name,
                    "_bucket",
                    &labels,
                    Some(f64::INFINITY),
                    counter_as_f64(series.count),
                );
                #[expect(
                    clippy::cast_precision_loss,
                    reason = "a summed latency never approaches 2^53 nanoseconds"
                )]
                let sum = series.sum_nanos as f64 / 1e9;
                push_sample(&mut lines, spec.name, "_sum", &labels, None, sum);
                push_sample(
                    &mut lines,
                    spec.name,
                    "_count",
                    &labels,
                    None,
                    counter_as_f64(series.count),
                );
            }
        }
        _ => return None,
    }
    if lines.is_empty() {
        return Some(String::new());
    }
    let mut out = String::new();
    let _ = writeln!(out, "# HELP {} {}", spec.name, escape_help(spec.help));
    let _ = writeln!(out, "# TYPE {} {}", spec.name, spec.kind.exposition_type());
    out.push_str(&lines);
    Some(out)
}

/// The three families whose values the topology health path owns.
///
/// `b_status` and `ping_duration_seconds` are `GaugeVec`s in Go, so they have
/// no children until something sets one and are absent from the exposition
/// until then. `health_check_seconds` is a plain `Gauge`, registered at
/// startup, so it reports `0` before the first cycle completes rather than
/// being absent.
fn render_health_family(
    spec: &MetricSpec,
    state: &control_topology::HealthMetricsSnapshot,
) -> Option<String> {
    let mut lines = String::new();
    match spec.name {
        "tiproxy_backend_b_status" => {
            for (address, healthy) in &state.status {
                push_sample(
                    &mut lines,
                    spec.name,
                    "",
                    &[("backend", address.clone())],
                    None,
                    if *healthy { 1.0 } else { 0.0 },
                );
            }
        }
        "tiproxy_backend_ping_duration_seconds" => {
            for (address, sample) in &state.ping {
                push_sample(
                    &mut lines,
                    spec.name,
                    "",
                    &[("backend", address.clone())],
                    None,
                    sample.seconds,
                );
            }
        }
        "tiproxy_backend_health_check_seconds" => {
            push_sample(
                &mut lines,
                spec.name,
                "",
                &[],
                None,
                state.cycle_seconds.unwrap_or(0.0),
            );
        }
        _ => return None,
    }
    if lines.is_empty() {
        return Some(String::new());
    }
    let mut out = String::new();
    let _ = writeln!(out, "# HELP {} {}", spec.name, escape_help(spec.help));
    let _ = writeln!(out, "# TYPE {} {}", spec.name, spec.kind.exposition_type());
    out.push_str(&lines);
    Some(out)
}

/// `backend_metric`: one sample per retained `(backend, metric)` pair.
fn render_backend_metric_family(
    spec: &MetricSpec,
    state: &control_router::BackendMetricSnapshot,
) -> Option<String> {
    if spec.name != "tiproxy_backend_backend_metric" {
        return None;
    }
    let mut lines = String::new();
    // Ordered by the rendered label, for the same reason `b_score` is: the
    // enum's order is not the label's.
    let mut rows: Vec<(&str, &'static str, f64)> = state
        .values
        .iter()
        .map(|((address, metric), value)| (address.as_str(), metric.label(), *value))
        .collect();
    rows.sort_unstable_by_key(|(address, metric, _)| (*address, *metric));
    for (address, metric, value) in rows {
        push_sample(
            &mut lines,
            spec.name,
            "",
            &[
                ("backend", address.to_owned()),
                ("metric", metric.to_owned()),
            ],
            None,
            value,
        );
    }
    if lines.is_empty() {
        return Some(String::new());
    }
    let mut out = String::new();
    let _ = writeln!(out, "# HELP {} {}", spec.name, escape_help(spec.help));
    let _ = writeln!(out, "# TYPE {} {}", spec.name, spec.kind.exposition_type());
    out.push_str(&lines);
    Some(out)
}

/// `b_score`: one sample per retained `(backend, factor)` pair.
fn render_score_family(spec: &MetricSpec, state: &control_router::ScoreSnapshot) -> Option<String> {
    if spec.name != "tiproxy_balance_b_score" {
        return None;
    }
    let mut lines = String::new();
    // Ordered by the rendered label, not by the `Factor` discriminant: the
    // Go gatherer sorts label values, and the enum's declaration order is
    // policy priority, which puts `cpu` before `conn` where Go puts `conn`
    // first.
    let mut rows: Vec<(&str, &'static str, u64)> = state
        .scores
        .iter()
        .map(|((address, factor), score)| (address.as_str(), factor.metric_name(), *score))
        .collect();
    rows.sort_unstable_by_key(|(address, factor, _)| (*address, *factor));
    for (address, factor, score) in rows {
        push_sample(
            &mut lines,
            spec.name,
            "",
            &[
                ("backend", address.to_owned()),
                ("factor", factor.to_owned()),
            ],
            None,
            counter_as_f64(score),
        );
    }
    if lines.is_empty() {
        return Some(String::new());
    }
    let mut out = String::new();
    let _ = writeln!(out, "# HELP {} {}", spec.name, escape_help(spec.help));
    let _ = writeln!(out, "# TYPE {} {}", spec.name, spec.kind.exposition_type());
    out.push_str(&lines);
    Some(out)
}

/// `server_owner`: one sample at `1` per held election, and no series at all
/// for an election this process does not hold.
///
/// Go deletes the child on retirement rather than setting it to zero, so a
/// rendering that emitted `0` for a lost election would be making a claim Go
/// deliberately does not make on the dashboard.
fn render_owner_family(
    spec: &MetricSpec,
    state: &control_topology::OwnerSnapshot,
) -> Option<String> {
    if spec.name != "tiproxy_server_owner" {
        return None;
    }
    let mut lines = String::new();
    for job in &state.owned {
        push_sample(
            &mut lines,
            spec.name,
            "",
            &[("type", job.clone())],
            None,
            1.0,
        );
    }
    if lines.is_empty() {
        return Some(String::new());
    }
    let mut out = String::new();
    let _ = writeln!(out, "# HELP {} {}", spec.name, escape_help(spec.help));
    let _ = writeln!(out, "# TYPE {} {}", spec.name, spec.kind.exposition_type());
    out.push_str(&lines);
    Some(out)
}

/// Counters are rendered as floats, as Prometheus text exposition requires.
#[expect(
    clippy::cast_precision_loss,
    reason = "a migration counter never approaches 2^53"
)]
const fn counter_as_f64(value: u64) -> f64 {
    value as f64
}

/// Connections per backend address, summed across incarnations.
fn render_backend_connections(
    spec: &MetricSpec,
    state: &control_router::MigrationSnapshot,
    lines: &mut String,
) {
    for (address, active) in &state.backend_connections {
        push_sample(
            lines,
            spec.name,
            "",
            &[("backend", address.clone())],
            None,
            counter_as_f64(*active),
        );
    }
}

/// Go `succeedToLabel`.
const fn migrate_result(succeeded: bool) -> &'static str {
    if succeeded { "succeed" } else { "fail" }
}

fn push_sample(
    out: &mut String,
    name: &str,
    suffix: &str,
    labels: &[(&'static str, String)],
    le: Option<f64>,
    value: f64,
) {
    out.push_str(name);
    out.push_str(suffix);
    if !labels.is_empty() || le.is_some() {
        out.push('{');
        let mut first = true;
        for (key, label_value) in labels {
            if !first {
                out.push(',');
            }
            first = false;
            let _ = write!(out, "{key}=\"{}\"", escape_label_value(label_value));
        }
        if let Some(upper) = le {
            if !first {
                out.push(',');
            }
            let _ = write!(out, "le=\"{}\"", format_go_float(upper));
        }
        out.push('}');
    }
    out.push(' ');
    out.push_str(&format_go_float(value));
    out.push('\n');
}

/// Packet and byte deltas attributed to one backend-facing exchange.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BackendTraffic {
    /// Bytes read from the backend.
    pub inbound_bytes: u64,
    /// Physical `MySQL` packets read from the backend.
    pub inbound_packets: u64,
    /// Bytes written to the backend.
    pub outbound_bytes: u64,
    /// Physical `MySQL` packets written to the backend.
    pub outbound_packets: u64,
}

/// One payload-free, bounded observation from the session path.
#[derive(Debug, Clone)]
pub enum Observation {
    /// Initial route/dial acquisition completed.
    GetBackend {
        /// End-to-end acquisition duration.
        duration: Duration,
        /// Whether a backend was acquired.
        succeeded: bool,
    },
    /// One direct backend dial failed.
    DialBackendFailed {
        /// Attempted backend address.
        backend: String,
    },
    /// A live topology generation changed the current backend's health-driven
    /// keepalive policy, or a prior best-effort application was retried.
    BackendKeepaliveUpdated {
        /// Current backend address (the bounded legacy backend label).
        backend: String,
        /// Health state selected from the latest complete topology snapshot.
        healthy: bool,
        /// Whether the socket policy was applied (or no policy was configured).
        succeeded: bool,
    },
    /// Initial backend authentication completed successfully.
    HandshakeCompleted {
        /// Backend address (the legacy metric label).
        backend: String,
        /// Full connection handshake duration.
        duration: Duration,
        /// Handshake traffic since the backend was attached.
        traffic: BackendTraffic,
        /// Whether the backend is in the proxy's local location.
        local: bool,
    },
    /// opt#23: one session's accumulated command completions for one
    /// `(backend, command)` pair, folded as a batch. Produced only by the
    /// recorder's own accumulator (drained on session close); the exporter's
    /// periodic sweep folds live accumulators directly.
    CommandBatch(CommandBatch),
    /// One accepted command reached its terminal boundary.
    CommandCompleted {
        /// Backend address (the legacy metric label).
        backend: String,
        /// Stable Go command label.
        command: Command,
        /// Command duration through the terminal response boundary.
        duration: Duration,
        /// Command start time since connection admission.
        since_connection: Duration,
        /// Backend-facing traffic produced by this command.
        traffic: BackendTraffic,
        /// Whether the backend is in the proxy's local location.
        local: bool,
    },
    /// A session migration was accepted and is now in flight. Go increments
    /// `pending_migrate` at this point, only for an accepted offer.
    MigrationIssued {
        /// Source backend address.
        from: String,
        /// Destination backend address.
        to: String,
        /// Reason label frozen when the redirect was issued.
        reason: &'static str,
    },
    /// A session migration reached its terminal state. Go decrements
    /// `pending_migrate`, counts the result, and observes the elapsed time.
    MigrationSettled {
        /// Source backend address.
        from: String,
        /// Destination backend address.
        to: String,
        /// The same frozen reason the issue carried.
        reason: &'static str,
        /// Whether the migration succeeded.
        succeeded: bool,
        /// Issue-to-settlement elapsed time.
        elapsed: Duration,
    },
    /// Backend bytes written outside any command's window: a queued
    /// no-response command flushed while the client was idle, before a
    /// control command, or at session end. Folds into the per-backend
    /// traffic counters only; it is not a query.
    BackendTrafficSettled {
        /// Backend address label.
        backend: String,
        /// Raw byte delta since the last attributed boundary.
        traffic: BackendTraffic,
        /// Whether the backend shares the proxy's location.
        local: bool,
    },
    /// One admitted session closed.
    SessionClosed {
        /// Exact Go-compatible quit source.
        source: QuitSource,
        /// Full connection lifetime.
        lifetime: Duration,
        /// Terminal byte totals retained for parity tests and future sinks.
        traffic: TrafficTotals,
    },
}

impl Observation {
    fn labels_are_bounded(&self) -> bool {
        match self {
            Self::DialBackendFailed { backend }
            | Self::BackendKeepaliveUpdated { backend, .. }
            | Self::HandshakeCompleted { backend, .. }
            | Self::CommandCompleted { backend, .. }
            | Self::BackendTrafficSettled { backend, .. } => backend.len() <= MAX_LABEL_BYTES,
            Self::CommandBatch(batch) => batch.entry.backend.len() <= MAX_LABEL_BYTES,
            // Both endpoints are label values, so both are bounded.
            Self::MigrationIssued { from, to, .. } | Self::MigrationSettled { from, to, .. } => {
                from.len() <= MAX_LABEL_BYTES && to.len() <= MAX_LABEL_BYTES
            }
            Self::GetBackend { .. } | Self::SessionClosed { .. } => true,
        }
    }
}

/// Publishes router migration observations onto the metrics path.
///
/// `control-router` records migrations but owns no registry, and it cannot
/// depend on this crate, so the composition root installs this adapter. The
/// recorder is non-blocking: a full queue drops the sample rather than stalling
/// a routing settlement.
pub struct MigrationMetrics {
    recorder: MetricsRecorder,
}

impl MigrationMetrics {
    /// Wraps the process recorder as a router migration sink.
    #[must_use]
    pub const fn new(recorder: MetricsRecorder) -> Self {
        Self { recorder }
    }
}

/// Reads migration state from the route plane for the exposition.
pub struct PlaneMigrationState {
    handle: control_router::RoutePlaneHandle,
}

impl PlaneMigrationState {
    /// Wraps the route-plane handle as the exposition's state source.
    #[must_use]
    pub const fn new(handle: control_router::RoutePlaneHandle) -> Self {
        Self { handle }
    }
}

impl MigrationStateSource for PlaneMigrationState {
    fn migration_state(&self) -> control_router::MigrationSnapshot {
        self.handle.migration_snapshot()
    }
}

impl control_router::MigrationSink for MigrationMetrics {
    fn record(&self, observation: control_router::MigrationObservation) {
        let reason = observation.reason.metric_name();
        let sample = match observation.outcome {
            control_router::MigrationOutcome::Issued => Observation::MigrationIssued {
                from: observation.from,
                to: observation.to,
                reason,
            },
            control_router::MigrationOutcome::Settled { success, elapsed } => {
                Observation::MigrationSettled {
                    from: observation.from,
                    to: observation.to,
                    reason,
                    succeeded: success,
                    elapsed,
                }
            }
        };
        self.recorder.try_record(sample);
    }
}

/// opt#23: distinct `(backend, command)` pairs one session accumulates before
/// the next sweep. A session talks to one backend at a time and uses a
/// handful of command types; a redirect leaves the old backend's pairs until
/// the next sweep drains them. Reaching the bound flushes the accumulator
/// through the queue (see [`MetricsRecorder::try_record`]) before the unseen
/// pair is accumulated.
const MAX_LOCAL_COMMAND_KEYS: usize = 32;

/// One session's accumulated command completions for one
/// `(backend, command)` pair. Folding it yields the same registry, pending
/// deltas and shed counts as folding the completions one by one: histogram
/// buckets are kept cumulative like [`HistogramState`], invalid durations are
/// counted so they can be shed exactly as [`Aggregator::histogram`] sheds
/// them, and every counter remembers how many completions carried a nonzero
/// delta, because [`Aggregator::counter`] counts an update only for those.
#[derive(Debug, Clone, PartialEq)]
pub struct CommandBatch {
    entry: LocalCommandEntry,
}

#[derive(Debug, Clone, PartialEq)]
struct LocalCommandEntry {
    backend: String,
    command: Command,
    local: bool,
    /// Completions accumulated (each counts one `query_total` update).
    count: u64,
    /// Completions whose duration was not a finite non-negative number.
    duration_invalid: u64,
    duration_sum: f64,
    duration_buckets: Vec<u64>,
    /// Completions whose connection age was not a finite non-negative number.
    since_invalid: u64,
    since_sum: f64,
    since_buckets: Vec<u64>,
    traffic: BackendTraffic,
    /// Completions with a nonzero value per traffic field, in
    /// [`CommandKeys::traffic`] order.
    traffic_updates: [u64; 4],
    /// Completions with nonzero cross-location bytes.
    cross_location_updates: u64,
}

impl LocalCommandEntry {
    fn new(backend: String, command: Command, local: bool) -> Self {
        Self {
            backend,
            command,
            local,
            count: 0,
            duration_invalid: 0,
            duration_sum: 0.0,
            duration_buckets: vec![0; QUERY_BUCKETS.len()],
            since_invalid: 0,
            since_sum: 0.0,
            since_buckets: vec![0; QUERY_AGE_BUCKETS.len()],
            traffic: BackendTraffic::default(),
            traffic_updates: [0; 4],
            cross_location_updates: 0,
        }
    }

    fn accumulate(&mut self, duration: f64, since_connection: f64, traffic: BackendTraffic) {
        self.count = self.count.saturating_add(1);
        accumulate_histogram(
            duration,
            &QUERY_BUCKETS,
            &mut self.duration_invalid,
            &mut self.duration_sum,
            &mut self.duration_buckets,
        );
        accumulate_histogram(
            since_connection,
            &QUERY_AGE_BUCKETS,
            &mut self.since_invalid,
            &mut self.since_sum,
            &mut self.since_buckets,
        );
        let fields = [
            traffic.inbound_bytes,
            traffic.inbound_packets,
            traffic.outbound_bytes,
            traffic.outbound_packets,
        ];
        for (updates, value) in self.traffic_updates.iter_mut().zip(fields) {
            if value != 0 {
                *updates = updates.saturating_add(1);
            }
        }
        self.traffic.inbound_bytes = self
            .traffic
            .inbound_bytes
            .saturating_add(traffic.inbound_bytes);
        self.traffic.inbound_packets = self
            .traffic
            .inbound_packets
            .saturating_add(traffic.inbound_packets);
        self.traffic.outbound_bytes = self
            .traffic
            .outbound_bytes
            .saturating_add(traffic.outbound_bytes);
        self.traffic.outbound_packets = self
            .traffic
            .outbound_packets
            .saturating_add(traffic.outbound_packets);
        if !self.local && traffic.inbound_bytes.saturating_add(traffic.outbound_bytes) != 0 {
            self.cross_location_updates = self.cross_location_updates.saturating_add(1);
        }
    }
}

/// Mirrors [`Aggregator::histogram`]'s accept/shed split at accumulation time.
fn accumulate_histogram(
    seconds: f64,
    buckets: &[f64],
    invalid: &mut u64,
    sum: &mut f64,
    cumulative: &mut [u64],
) {
    if !seconds.is_finite() || seconds < 0.0 {
        *invalid = invalid.saturating_add(1);
        return;
    }
    *sum += seconds;
    for (upper, bucket) in buckets.iter().zip(cumulative.iter_mut()) {
        if seconds <= *upper {
            *bucket = bucket.saturating_add(1);
        }
    }
}

/// One session's command accumulator: written only by that session's task,
/// drained by the exporter's sweep and on session close.
#[derive(Debug, Default)]
struct LocalCommandStats {
    entries: Vec<LocalCommandEntry>,
}

impl LocalCommandStats {
    /// Returns false when the pair is unseen and the key bound is reached;
    /// the caller then flushes the accumulator and retries once.
    fn accumulate(
        &mut self,
        backend: &str,
        command: Command,
        local: bool,
        duration: f64,
        since_connection: f64,
        traffic: BackendTraffic,
    ) -> bool {
        let position = self
            .entries
            .iter()
            .position(|entry| entry.command == command && entry.backend == backend);
        let entry = if let Some(position) = position {
            &mut self.entries[position]
        } else {
            if self.entries.len() >= MAX_LOCAL_COMMAND_KEYS {
                return false;
            }
            self.entries
                .push(LocalCommandEntry::new(backend.to_owned(), command, local));
            let last = self.entries.len() - 1;
            &mut self.entries[last]
        };
        entry.accumulate(duration, since_connection, traffic);
        true
    }

    fn take(&mut self) -> Vec<LocalCommandEntry> {
        std::mem::take(&mut self.entries)
    }
}

/// Live accumulators the exporter sweeps once per tick.
type Accumulators = Arc<Mutex<Vec<Weak<Mutex<LocalCommandStats>>>>>;

/// Locks a session accumulator or the accumulator list; a poisoned lock is
/// recovered because the state is only counters.
fn lock_recovering<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Cloneable non-blocking SQL-path metrics surface.
///
/// opt#23: command completions are accumulated in a per-clone accumulator
/// (one per session in practice) and folded by the exporter's sweep every
/// tick and on session close, instead of crossing the queue one by one.
/// Recording never waits on I/O or on another session: the only lock a
/// completion takes is this clone's own accumulator, which the sweep holds
/// for a bounded copy. Under normal scheduling command-family series lag the
/// live state by at most one exporter tick; scheduling delay adds to that.
#[derive(Default)]
pub struct MetricsRecorder {
    tx: Option<mpsc::Sender<Observation>>,
    dropped: Arc<AtomicU64>,
    /// This clone's accumulator, created on its first command completion.
    local: OnceLock<Arc<Mutex<LocalCommandStats>>>,
    accumulators: Accumulators,
}

impl Clone for MetricsRecorder {
    /// A clone starts with an empty accumulator of its own; the queue, the
    /// drop counter and the accumulator list are shared.
    fn clone(&self) -> Self {
        Self {
            tx: self.tx.clone(),
            dropped: Arc::clone(&self.dropped),
            local: OnceLock::new(),
            accumulators: Arc::clone(&self.accumulators),
        }
    }
}

impl Drop for MetricsRecorder {
    /// Session close: whatever the sweep has not taken yet goes through the
    /// queue as batches, so nothing is lost with the accumulator.
    fn drop(&mut self) {
        let Some(local) = self.local.get() else {
            return;
        };
        let entries = lock_recovering(local).take();
        self.send_batches(entries);
    }
}

impl MetricsRecorder {
    /// Creates a bounded recorder plus the single receiver consumed by the
    /// exporter. A zero capacity is normalized to one.
    #[must_use]
    pub fn channel(capacity: usize) -> (Self, mpsc::Receiver<Observation>) {
        let (tx, rx) = mpsc::channel(capacity.max(1));
        (
            Self {
                tx: Some(tx),
                dropped: Arc::new(AtomicU64::new(0)),
                local: OnceLock::new(),
                accumulators: Arc::default(),
            },
            rx,
        )
    }

    /// Tries to record without waiting. Returns false for a full/closed queue
    /// or an overlong label; every such loss increments the local drop total.
    #[allow(clippy::must_use_candidate)]
    pub fn try_record(&self, observation: Observation) -> bool {
        let Some(tx) = &self.tx else {
            return false;
        };
        if !observation.labels_are_bounded() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        if let Observation::CommandCompleted {
            backend,
            command,
            duration,
            since_connection,
            traffic,
            local,
        } = observation
        {
            let stats = self.local_stats();
            let duration = duration.as_secs_f64();
            let since_connection = since_connection.as_secs_f64();
            let mut guard = lock_recovering(stats);
            if guard.accumulate(
                &backend,
                command,
                local,
                duration,
                since_connection,
                traffic,
            ) {
                return true;
            }
            // Pair bound reached: hand the accumulated pairs to the queue as
            // batches (a full queue sheds them, counted per completion, as
            // it always did) and accumulate the new pair in the emptied
            // accumulator. The only remaining loss condition is the queue.
            let entries = guard.take();
            drop(guard);
            self.send_batches(entries);
            let accepted = lock_recovering(stats).accumulate(
                &backend,
                command,
                local,
                duration,
                since_connection,
                traffic,
            );
            if !accepted {
                self.dropped.fetch_add(1, Ordering::Relaxed);
            }
            return accepted;
        }
        if tx.try_send(observation).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        true
    }

    /// Hands accumulated pairs to the queue as batches without waiting. A
    /// full or closed queue sheds a batch and counts every completion it
    /// represented, like the per-completion path counted a full queue.
    fn send_batches(&self, entries: Vec<LocalCommandEntry>) {
        for entry in entries {
            let count = entry.count;
            let batch = Observation::CommandBatch(CommandBatch { entry });
            if self
                .tx
                .as_ref()
                .is_none_or(|tx| tx.try_send(batch).is_err())
            {
                self.dropped.fetch_add(count, Ordering::Relaxed);
            }
        }
    }

    /// This clone's accumulator, registered for the sweep on first use.
    fn local_stats(&self) -> &Arc<Mutex<LocalCommandStats>> {
        self.local.get_or_init(|| {
            let stats = Arc::new(Mutex::new(LocalCommandStats::default()));
            lock_recovering(&self.accumulators).push(Arc::downgrade(&stats));
            stats
        })
    }

    fn accumulators(&self) -> Accumulators {
        Arc::clone(&self.accumulators)
    }

    /// Current number of intentionally shed SQL-path observations.
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    fn dropped_counter(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.dropped)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct MetricKey {
    name: &'static str,
    labels: Vec<(&'static str, String)>,
}

impl MetricKey {
    fn new(name: &'static str, labels: Vec<(&'static str, String)>) -> Self {
        Self { name, labels }
    }

    #[cfg(test)]
    fn wire_labels(&self) -> BTreeMap<String, String> {
        self.labels
            .iter()
            .map(|(key, value)| ((*key).to_owned(), value.clone()))
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq)]
enum PendingMetric {
    Counter(u64),
    Histogram {
        count: u64,
        sum: f64,
        cumulative_buckets: Vec<u64>,
    },
}

struct Aggregator {
    pending: BTreeMap<MetricKey, PendingMetric>,
    overflow_dropped: u64,
    /// opt#7: per-(backend, command) pre-built metric keys. The per-command
    /// path used to allocate ~12 label/key values per observation; the keys
    /// are content-identical, so build each set once and update by reference.
    ///
    /// Bounded by `command_key_capacity`: once full, an unseen combination
    /// builds its keys for that observation only and is not cached, so the
    /// cache cannot grow with backend churn while the series bounds shed.
    command_keys: HashMap<(String, &'static str), Arc<CommandKeys>>,
    command_key_capacity: usize,
    /// Cumulative twin of `pending`: every accepted delta is also folded into
    /// the process-local registry that backs the native `/metrics` exposition.
    registry: Arc<MetricsRegistry>,
}

/// Pre-built keys for one (backend, command) pair. Same names/labels the
/// per-observation path built inline, so exposition is unchanged.
#[derive(Debug)]
struct CommandKeys {
    query_total: MetricKey,
    query_duration: MetricKey,
    since_connection: MetricKey,
    traffic: [(MetricKey, TrafficField); 4],
    cross_location_bytes: MetricKey,
}

#[derive(Debug, Clone, Copy)]
enum TrafficField {
    InboundBytes,
    InboundPackets,
    OutboundBytes,
    OutboundPackets,
}

impl TrafficField {
    const fn pick(self, traffic: BackendTraffic) -> u64 {
        match self {
            Self::InboundBytes => traffic.inbound_bytes,
            Self::InboundPackets => traffic.inbound_packets,
            Self::OutboundBytes => traffic.outbound_bytes,
            Self::OutboundPackets => traffic.outbound_packets,
        }
    }
}

impl CommandKeys {
    fn new(backend: &str, cmd_type: &'static str) -> Self {
        let labels = vec![
            ("backend", backend.to_owned()),
            ("cmd_type", cmd_type.to_owned()),
        ];
        let traffic_key =
            |name: &'static str| MetricKey::new(name, vec![("backend", backend.to_owned())]);
        Self {
            query_total: MetricKey::new("tiproxy_session_query_total", labels.clone()),
            query_duration: MetricKey::new("tiproxy_session_query_duration_seconds", labels),
            since_connection: MetricKey::new(
                "tiproxy_session_query_time_since_conn_creation_seconds",
                vec![],
            ),
            traffic: [
                (
                    traffic_key("tiproxy_traffic_inbound_bytes"),
                    TrafficField::InboundBytes,
                ),
                (
                    traffic_key("tiproxy_traffic_inbound_packets"),
                    TrafficField::InboundPackets,
                ),
                (
                    traffic_key("tiproxy_traffic_outbound_bytes"),
                    TrafficField::OutboundBytes,
                ),
                (
                    traffic_key("tiproxy_traffic_outbound_packets"),
                    TrafficField::OutboundPackets,
                ),
            ],
            cross_location_bytes: MetricKey::new("tiproxy_traffic_cross_location_bytes", vec![]),
        }
    }
}

impl Default for Aggregator {
    fn default() -> Self {
        Self::with_registry(Arc::new(MetricsRegistry::new()))
    }
}

impl Aggregator {
    fn with_registry(registry: Arc<MetricsRegistry>) -> Self {
        Self {
            pending: BTreeMap::new(),
            overflow_dropped: 0,
            command_keys: HashMap::new(),
            command_key_capacity: MAX_COMMAND_KEY_CACHE,
            registry,
        }
    }

    /// Cached keys for one `(backend, command)` pair; past the cache bound an
    /// unseen pair gets throwaway keys so the accept/shed rules below still
    /// see every observation.
    fn command_keys_for(&mut self, backend: String, cmd_type: &'static str) -> Arc<CommandKeys> {
        if self.command_keys.len() < self.command_key_capacity {
            return Arc::clone(
                self.command_keys
                    .entry((backend, cmd_type))
                    .or_insert_with_key(|(backend, cmd_type)| {
                        Arc::new(CommandKeys::new(backend, cmd_type))
                    }),
            );
        }
        let probe = (backend, cmd_type);
        self.command_keys
            .get(&probe)
            .map_or_else(|| Arc::new(CommandKeys::new(&probe.0, probe.1)), Arc::clone)
    }

    fn get_backend(&mut self, registry: &mut RegistryState, duration: Duration, succeeded: bool) {
        self.histogram(
            registry,
            &MetricKey::new("tiproxy_backend_get_backend_duration_seconds", vec![]),
            duration.as_secs_f64(),
            &GET_BACKEND_BUCKETS,
        );
        self.counter(
            registry,
            &MetricKey::new(
                "tiproxy_backend_get_backend",
                vec![("res", if succeeded { "succeed" } else { "fail" }.to_owned())],
            ),
            1,
        );
    }

    /// opt#7b: one `pending` lookup per update (the key is cloned only when
    /// the series is first inserted into the batch) and the registry state
    /// is passed in already locked, so an observation that folds several
    /// updates takes the registry mutex once.
    ///
    /// Shed rule is unchanged: a series already in `pending` is always
    /// accepted; a new one is accepted only below `MAX_PENDING_SERIES`, and a
    /// shed update reaches neither `pending` nor the registry.
    /// Batch twin of [`Self::counter`]: `updates` completions contributed the
    /// nonzero `delta`. Shed accounting counts each of those updates, exactly
    /// as the per-completion path would have.
    fn counter_batch(
        &mut self,
        registry: &mut RegistryState,
        key: &MetricKey,
        delta: u64,
        updates: u64,
    ) {
        if delta == 0 {
            return;
        }
        match self.pending.get_mut(key) {
            Some(PendingMetric::Counter(value)) => *value = value.saturating_add(delta),
            Some(PendingMetric::Histogram { .. }) => {
                self.overflow_dropped = self.overflow_dropped.saturating_add(updates);
            }
            None => {
                if self.pending.len() >= MAX_PENDING_SERIES {
                    self.overflow_dropped = self.overflow_dropped.saturating_add(updates);
                    return;
                }
                self.pending
                    .insert(key.clone(), PendingMetric::Counter(delta));
            }
        }
        registry.add_counter(key, delta);
    }

    /// Batch twin of [`Self::histogram`]: `count` valid observations with
    /// their accumulated `sum` and cumulative bucket counts; `invalid`
    /// observations are shed one each, before any series bound, as the
    /// per-observation path sheds a non-finite or negative value.
    fn histogram_batch(
        &mut self,
        registry: &mut RegistryState,
        key: &MetricKey,
        count: u64,
        invalid: u64,
        sum: f64,
        cumulative: &[u64],
    ) {
        self.overflow_dropped = self.overflow_dropped.saturating_add(invalid);
        if count == 0 {
            return;
        }
        match self.pending.get_mut(key) {
            Some(PendingMetric::Histogram {
                count: pending_count,
                sum: pending_sum,
                cumulative_buckets,
            }) => {
                *pending_count = pending_count.saturating_add(count);
                *pending_sum += sum;
                for (bucket, add) in cumulative_buckets.iter_mut().zip(cumulative) {
                    *bucket = bucket.saturating_add(*add);
                }
            }
            Some(PendingMetric::Counter(_)) => {
                self.overflow_dropped = self.overflow_dropped.saturating_add(count);
            }
            None => {
                if self.pending.len() >= MAX_PENDING_SERIES {
                    // Two per observation, as the per-observation path.
                    self.overflow_dropped = self
                        .overflow_dropped
                        .saturating_add(count.saturating_mul(2));
                    return;
                }
                self.pending.insert(
                    key.clone(),
                    PendingMetric::Histogram {
                        count,
                        sum,
                        cumulative_buckets: cumulative.to_vec(),
                    },
                );
            }
        }
        registry.observe_histogram_batch(key, count, sum, cumulative);
    }

    /// Folds one session's accumulated completions for one pair in the same
    /// series order as `CommandCompleted`.
    fn command_batch(&mut self, registry: &mut RegistryState, entry: LocalCommandEntry) {
        let keys = self.command_keys_for(entry.backend, entry.command.name());
        self.counter_batch(registry, &keys.query_total, entry.count, entry.count);
        self.histogram_batch(
            registry,
            &keys.query_duration,
            entry.count.saturating_sub(entry.duration_invalid),
            entry.duration_invalid,
            entry.duration_sum,
            &entry.duration_buckets,
        );
        self.histogram_batch(
            registry,
            &keys.since_connection,
            entry.count.saturating_sub(entry.since_invalid),
            entry.since_invalid,
            entry.since_sum,
            &entry.since_buckets,
        );
        for ((key, field), updates) in keys.traffic.iter().zip(entry.traffic_updates) {
            self.counter_batch(registry, key, field.pick(entry.traffic), updates);
        }
        if !entry.local {
            self.counter_batch(
                registry,
                &keys.cross_location_bytes,
                entry
                    .traffic
                    .inbound_bytes
                    .saturating_add(entry.traffic.outbound_bytes),
                entry.cross_location_updates,
            );
        }
    }

    fn counter(&mut self, registry: &mut RegistryState, key: &MetricKey, delta: u64) {
        if delta == 0 {
            return;
        }
        match self.pending.get_mut(key) {
            Some(PendingMetric::Counter(value)) => *value = value.saturating_add(delta),
            Some(PendingMetric::Histogram { .. }) => {
                self.overflow_dropped = self.overflow_dropped.saturating_add(1);
            }
            None => {
                if self.pending.len() >= MAX_PENDING_SERIES {
                    self.overflow_dropped = self.overflow_dropped.saturating_add(1);
                    return;
                }
                self.pending
                    .insert(key.clone(), PendingMetric::Counter(delta));
            }
        }
        registry.add_counter(key, delta);
    }

    fn histogram(
        &mut self,
        registry: &mut RegistryState,
        key: &MetricKey,
        seconds: f64,
        buckets: &[f64],
    ) {
        if !seconds.is_finite() || seconds < 0.0 {
            self.overflow_dropped = self.overflow_dropped.saturating_add(1);
            return;
        }
        match self.pending.get_mut(key) {
            Some(PendingMetric::Histogram {
                count,
                sum,
                cumulative_buckets,
            }) => {
                *count = count.saturating_add(1);
                *sum += seconds;
                for (upper, bucket) in buckets.iter().zip(cumulative_buckets.iter_mut()) {
                    if seconds <= *upper {
                        *bucket = bucket.saturating_add(1);
                    }
                }
            }
            Some(PendingMetric::Counter(_)) => {
                self.overflow_dropped = self.overflow_dropped.saturating_add(1);
            }
            None => {
                if self.pending.len() >= MAX_PENDING_SERIES {
                    // Same count as before this path was flattened: the series
                    // bound and the histogram guard each recorded the shed.
                    self.overflow_dropped = self.overflow_dropped.saturating_add(2);
                    return;
                }
                let mut cumulative_buckets = vec![0; buckets.len()];
                for (upper, bucket) in buckets.iter().zip(cumulative_buckets.iter_mut()) {
                    if seconds <= *upper {
                        *bucket = 1;
                    }
                }
                self.pending.insert(
                    key.clone(),
                    PendingMetric::Histogram {
                        count: 1,
                        sum: seconds,
                        cumulative_buckets,
                    },
                );
            }
        }
        registry.observe_histogram(key, seconds, buckets);
    }

    /// Lock-per-call conveniences for the tick-time and test callers that
    /// fold one update at a time.
    fn counter_once(&mut self, key: &MetricKey, delta: u64) {
        let registry = Arc::clone(&self.registry);
        self.counter(&mut registry.lock(), key, delta);
    }

    /// Folds one observation, taking the registry lock exactly once for
    /// every series it updates.
    fn observe(&mut self, observation: Observation) {
        let registry = Arc::clone(&self.registry);
        let mut state = registry.lock();
        self.observe_in(&mut state, observation);
    }

    fn observe_in(&mut self, registry: &mut RegistryState, observation: Observation) {
        match observation {
            Observation::GetBackend {
                duration,
                succeeded,
            } => self.get_backend(registry, duration, succeeded),
            // The three migration families render from authoritative router
            // and process state, so accumulating them here would double
            // count. These observations remain a notification path only.
            Observation::MigrationIssued { .. } | Observation::MigrationSettled { .. } => {}
            Observation::DialBackendFailed { backend } => self.counter(
                registry,
                &MetricKey::new(
                    "tiproxy_backend_dial_backend_fail",
                    vec![("backend", backend)],
                ),
                1,
            ),
            Observation::BackendKeepaliveUpdated {
                backend,
                healthy,
                succeeded,
            } => self.backend_keepalive_updated(registry, backend, healthy, succeeded),
            Observation::HandshakeCompleted {
                backend,
                duration,
                traffic,
                local,
            } => {
                self.histogram(
                    registry,
                    &MetricKey::new(
                        "tiproxy_session_handshake_duration_seconds",
                        vec![("backend", backend.clone())],
                    ),
                    duration.as_secs_f64(),
                    &HANDSHAKE_BUCKETS,
                );
                self.traffic(registry, &backend, traffic, local);
            }
            Observation::CommandBatch(batch) => self.command_batch(registry, batch.entry),
            Observation::CommandCompleted {
                backend,
                command,
                duration,
                since_connection,
                traffic,
                local,
            } => {
                let keys = self.command_keys_for(backend, command.name());
                self.counter(registry, &keys.query_total, 1);
                self.histogram(
                    registry,
                    &keys.query_duration,
                    duration.as_secs_f64(),
                    &QUERY_BUCKETS,
                );
                self.histogram(
                    registry,
                    &keys.since_connection,
                    since_connection.as_secs_f64(),
                    &QUERY_AGE_BUCKETS,
                );
                for (key, field) in &keys.traffic {
                    self.counter(registry, key, field.pick(traffic));
                }
                if !local {
                    self.counter(
                        registry,
                        &keys.cross_location_bytes,
                        traffic.inbound_bytes.saturating_add(traffic.outbound_bytes),
                    );
                }
            }
            Observation::BackendTrafficSettled {
                backend,
                traffic,
                local,
            } => self.traffic(registry, &backend, traffic, local),
            Observation::SessionClosed {
                source,
                lifetime,
                traffic: _,
            } => {
                self.counter(
                    registry,
                    &MetricKey::new(
                        "tiproxy_server_disconnection_total",
                        vec![("type", source.metric_label().to_owned())],
                    ),
                    1,
                );
                self.histogram(
                    registry,
                    &MetricKey::new("tiproxy_session_conn_lifetime_seconds", vec![]),
                    lifetime.as_secs_f64(),
                    &CONN_LIFETIME_BUCKETS,
                );
            }
        }
    }

    fn backend_keepalive_updated(
        &mut self,
        registry: &mut RegistryState,
        backend: String,
        healthy: bool,
        succeeded: bool,
    ) {
        self.counter(
            registry,
            &MetricKey::new(
                "tiproxy_backend_keepalive_update_total",
                vec![
                    ("backend", backend),
                    (
                        "health",
                        if healthy { "healthy" } else { "unhealthy" }.to_owned(),
                    ),
                    (
                        "result",
                        if succeeded { "succeed" } else { "fail" }.to_owned(),
                    ),
                ],
            ),
            1,
        );
    }

    fn traffic(
        &mut self,
        registry: &mut RegistryState,
        backend: &str,
        traffic: BackendTraffic,
        local: bool,
    ) {
        for (name, delta) in [
            ("tiproxy_traffic_inbound_bytes", traffic.inbound_bytes),
            ("tiproxy_traffic_inbound_packets", traffic.inbound_packets),
            ("tiproxy_traffic_outbound_bytes", traffic.outbound_bytes),
            ("tiproxy_traffic_outbound_packets", traffic.outbound_packets),
        ] {
            self.counter(
                registry,
                &MetricKey::new(name, vec![("backend", backend.to_owned())]),
                delta,
            );
        }
        if !local {
            self.counter(
                registry,
                &MetricKey::new("tiproxy_traffic_cross_location_bytes", vec![]),
                traffic.inbound_bytes.saturating_add(traffic.outbound_bytes),
            );
        }
    }

    #[cfg(test)]
    fn wire_metrics(&self, gauges: &[(&'static str, f64)]) -> Vec<MetricDelta> {
        let mut metrics = Vec::with_capacity(self.pending.len() + gauges.len());
        for (key, pending) in &self.pending {
            let (counter_delta, gauge, histogram_bucket_deltas) = match pending {
                PendingMetric::Counter(delta) => {
                    (i64::try_from(*delta).unwrap_or(i64::MAX), 0.0, Vec::new())
                }
                PendingMetric::Histogram {
                    count,
                    sum,
                    cumulative_buckets,
                } => (
                    i64::try_from(*count).unwrap_or(i64::MAX),
                    *sum,
                    cumulative_buckets.clone(),
                ),
            };
            metrics.push(MetricDelta {
                name: key.name.to_owned(),
                labels: key.wire_labels(),
                counter_delta,
                gauge,
                histogram_bucket_deltas,
            });
        }
        metrics.extend(gauges.iter().map(|(name, gauge)| MetricDelta {
            name: (*name).to_owned(),
            gauge: *gauge,
            ..MetricDelta::default()
        }));
        metrics
    }

    fn clear_sent(&mut self) {
        self.pending.clear();
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct ExportTotals {
    registered: u64,
    rejected_memory: u64,
    rejected_max: u64,
    memory_probe_failures: u64,
    accept_errors: u64,
    socket_policy_failures: u64,
    registration_failures: u64,
    handler_panics: u64,
    observation_dropped: u64,
    batch_dropped: u64,
    session_scoped_dropped: u64,
    reconnect_attempts: u64,
    dispatch_unrouted: u64,
    dispatch_stale: u64,
    dispatch_send_failures: u64,
    dispatch_metering_failures: u64,
    dispatch_legacy_route_violations: u64,
}

impl ExportTotals {
    #[allow(clippy::cast_precision_loss)]
    fn sample(
        server: Option<ServerMetricsSnapshot>,
        recorder_dropped: u64,
        client: &ControlClient,
        dispatch: &DispatchStats,
    ) -> (Self, f64) {
        let server = server.unwrap_or_default();
        (
            Self {
                registered: server.registered_total,
                rejected_memory: server.rejected_memory_total,
                rejected_max: server.rejected_max_connections_total,
                memory_probe_failures: server.memory_probe_failures_total,
                accept_errors: server.accept_errors_total,
                socket_policy_failures: server.socket_policy_failures_total,
                registration_failures: server.registration_failures_total,
                handler_panics: server.handler_panics_total,
                observation_dropped: recorder_dropped,
                batch_dropped: client.metrics_dropped(),
                session_scoped_dropped: client.session_scoped_dropped(),
                reconnect_attempts: client.reconnect_attempts(),
                dispatch_unrouted: dispatch.unrouted.load(Ordering::Relaxed),
                dispatch_stale: dispatch.stale_dropped.load(Ordering::Relaxed),
                dispatch_send_failures: dispatch.send_failures.load(Ordering::Relaxed),
                dispatch_metering_failures: dispatch.metering_failures.load(Ordering::Relaxed),
                dispatch_legacy_route_violations: dispatch
                    .legacy_route_violations
                    .load(Ordering::Relaxed),
            },
            server.active_connections as f64,
        )
    }

    fn accumulate_delta(self, previous: Self, aggregator: &mut Aggregator) {
        aggregator.counter_once(
            &MetricKey::new("tiproxy_server_create_connection_total", vec![]),
            self.registered.saturating_sub(previous.registered),
        );
        for (label, current, old) in [
            ("memory", self.rejected_memory, previous.rejected_memory),
            ("max_connections", self.rejected_max, previous.rejected_max),
        ] {
            aggregator.counter_once(
                &MetricKey::new(
                    "tiproxy_server_reject_connection_total",
                    vec![("type", label.to_owned())],
                ),
                current.saturating_sub(old),
            );
        }
        for (label, current, old) in [
            (
                "rust_memory_probe_failure",
                self.memory_probe_failures,
                previous.memory_probe_failures,
            ),
            (
                "rust_accept_error",
                self.accept_errors,
                previous.accept_errors,
            ),
            (
                "rust_socket_policy_failure",
                self.socket_policy_failures,
                previous.socket_policy_failures,
            ),
            (
                "rust_registration_failure",
                self.registration_failures,
                previous.registration_failures,
            ),
            (
                "rust_handler_panic",
                self.handler_panics,
                previous.handler_panics,
            ),
            (
                "rust_metrics_observation_dropped",
                self.observation_dropped,
                previous.observation_dropped,
            ),
            (
                "rust_metrics_batch_dropped",
                self.batch_dropped,
                previous.batch_dropped,
            ),
            (
                "rust_control_session_scoped_dropped",
                self.session_scoped_dropped,
                previous.session_scoped_dropped,
            ),
            (
                "rust_control_unrouted",
                self.dispatch_unrouted,
                previous.dispatch_unrouted,
            ),
            (
                "rust_control_stale_dropped",
                self.dispatch_stale,
                previous.dispatch_stale,
            ),
            (
                "rust_control_send_failure",
                self.dispatch_send_failures,
                previous.dispatch_send_failures,
            ),
            (
                "rust_metering_failure",
                self.dispatch_metering_failures,
                previous.dispatch_metering_failures,
            ),
            (
                "rust_legacy_route_violation",
                self.dispatch_legacy_route_violations,
                previous.dispatch_legacy_route_violations,
            ),
        ] {
            aggregator.counter_once(
                &MetricKey::new("tiproxy_server_err", vec![("type", label.to_owned())]),
                current.saturating_sub(old),
            );
        }
        aggregator.counter_once(
            &MetricKey::new(
                "tiproxy_server_event",
                vec![("type", "rust_control_reconnect".to_owned())],
            ),
            self.reconnect_attempts
                .saturating_sub(previous.reconnect_attempts),
        );
    }
}

/// Folds every live session accumulator and prunes closed ones. The list
/// lock is held only to copy the live handles; a session mid-accumulation
/// (its own lock busy) is skipped until the next tick.
fn sweep_accumulators(accumulators: &Accumulators, aggregator: &mut Aggregator) {
    let live: Vec<Arc<Mutex<LocalCommandStats>>> = {
        let mut list = lock_recovering(accumulators);
        list.retain(|weak| weak.strong_count() > 0);
        list.iter().filter_map(Weak::upgrade).collect()
    };
    for stats in live {
        let entries = match stats.try_lock() {
            Ok(mut stats) => stats.take(),
            Err(std::sync::TryLockError::Poisoned(poisoned)) => poisoned.into_inner().take(),
            Err(std::sync::TryLockError::WouldBlock) => continue,
        };
        for entry in entries {
            aggregator.observe(Observation::CommandBatch(CommandBatch { entry }));
        }
    }
}

/// Running exporter task. Metrics failure never owns SQL or control-plane
/// liveness; shutdown and join are explicit so no task is detached.
pub struct MetricsExporter {
    shutdown: watch::Sender<bool>,
    task: JoinHandle<()>,
}

impl MetricsExporter {
    /// Requests exporter shutdown.
    pub fn shutdown(&self) {
        self.shutdown.send_replace(true);
    }

    /// Joins the exporter task. A panic is contained as metrics loss.
    pub async fn join(self) {
        let _ = self.task.await;
    }
}

/// Spawns the sole observation aggregator and batch exporter.
#[must_use]
pub fn spawn_metrics_exporter(
    client: Arc<ControlClient>,
    serving: DataplaneServingHandle,
    dispatch: Arc<DispatchStats>,
    recorder: &MetricsRecorder,
    observations: mpsc::Receiver<Observation>,
    interval: Duration,
    registry: Arc<MetricsRegistry>,
) -> MetricsExporter {
    let (shutdown, shutdown_rx) = watch::channel(false);
    let dropped = recorder.dropped_counter();
    let accumulators = recorder.accumulators();
    let task = tokio::spawn(run_exporter(
        client,
        serving,
        dispatch,
        observations,
        dropped,
        shutdown_rx,
        interval,
        registry,
        accumulators,
    ));
    MetricsExporter { shutdown, task }
}

#[allow(clippy::too_many_arguments)]
async fn run_exporter(
    client: Arc<ControlClient>,
    serving: DataplaneServingHandle,
    dispatch: Arc<DispatchStats>,
    mut observations: mpsc::Receiver<Observation>,
    dropped: Arc<AtomicU64>,
    mut shutdown: watch::Receiver<bool>,
    interval: Duration,
    registry: Arc<MetricsRegistry>,
    accumulators: Accumulators,
) {
    let mut ticker = tokio::time::interval(interval.max(Duration::from_millis(10)));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut aggregator = Aggregator::with_registry(Arc::clone(&registry));
    let mut previous = ExportTotals::default();
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return;
                }
            }
            observation = observations.recv() => {
                if let Some(observation) = observation {
                    aggregator.observe(observation);
                }
            }
            _ = ticker.tick() => {
                sweep_accumulators(&accumulators, &mut aggregator);
                let server = serving.metrics().await;
                // Every shed observation is one external signal: the SQL-path
                // queue, the per-batch series bound, the registry's cumulative
                // series bound, and the migration retention ceiling all count
                // as dropped observations.
                let (current, active_connections) = ExportTotals::sample(
                    server,
                    dropped
                        .load(Ordering::Relaxed)
                        .saturating_add(aggregator.overflow_dropped)
                        .saturating_add(registry.series_dropped())
                        .saturating_add(registry.migration_labels_dropped())
                        .saturating_add(registry.health_labels_dropped())
                        .saturating_add(registry.owner_labels_dropped())
                        .saturating_add(registry.score_labels_dropped())
                        .saturating_add(registry.backend_metric_labels_dropped()),
                    &client,
                    &dispatch,
                );
                current.accumulate_delta(previous, &mut aggregator);
                previous = current;
                registry.set_gauge("tiproxy_server_connections", active_connections);
                // CP-ADMIN slice 5c: the native registry is the only
                // exposition (`RUST_API_OWNER`); `MetricsBatch` is a retired
                // wire body, so the per-tick deltas are dropped once the
                // registry has absorbed them instead of being sent to Go.
                aggregator.clear_sent();
                if client.is_shutdown() {
                    return;
                }
            }
        }
    }
}

/// Go's process monitor, reproduced rule for rule (`lib/util/systimemon`).
///
/// It samples the wall clock every 100ms and counts a jump when the clock
/// reads earlier after the wait than it did before it, calls back every tenth
/// tick, and `pkg/metrics/metrics.go` raises the keepalive every fifth
/// callback. The keepalive is therefore this monitor's own heartbeat, not a
/// lease. Sampling less often, or comparing the wall delta against a
/// monotonic delta, would answer a different question, so the timer only
/// schedules: the predicate and the counting stay Go's.
pub struct SystemTimeMonitor {
    shutdown: watch::Sender<bool>,
    task: JoinHandle<()>,
}

impl SystemTimeMonitor {
    /// Signals the monitor to stop; [`Self::join`] waits for it.
    pub fn stop(&self) {
        self.shutdown.send_replace(true);
    }

    /// Waits for the stopped monitor's task.
    ///
    /// # Errors
    ///
    /// Returns the task's join error if it panicked.
    pub async fn join(self) -> Result<(), tokio::task::JoinError> {
        self.task.await
    }
}

/// Wall-clock nanoseconds since the Unix epoch, saturating before it.
fn wall_clock_nanos() -> i128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| {
            i128::try_from(since.as_nanos()).unwrap_or(i128::MAX)
        })
}

/// Spawns the monitor against a clock, so tests can move time backwards.
pub fn spawn_system_time_monitor_with_clock<F>(
    registry: Arc<MetricsRegistry>,
    now: F,
) -> SystemTimeMonitor
where
    F: Fn() -> i128 + Send + 'static,
{
    let (shutdown, mut shutdown_rx) = watch::channel(false);
    let task = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_millis(100));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        ticker.tick().await;
        let jump = MetricKey::new("tiproxy_monitor_time_jump_back_total", Vec::new());
        let alive = MetricKey::new("tiproxy_monitor_keep_alive_total", Vec::new());
        let mut ticks = 0_u32;
        let mut callbacks = 0_u32;
        loop {
            let last = now();
            tokio::select! {
                changed = shutdown_rx.changed() => {
                    if changed.is_err() || *shutdown_rx.borrow() {
                        return;
                    }
                    continue;
                }
                _ = ticker.tick() => {}
            }
            if now() < last {
                registry.add_counter(&jump, 1);
            }
            ticks += 1;
            if ticks >= 10 {
                ticks = 0;
                callbacks += 1;
                if callbacks >= 5 {
                    callbacks = 0;
                    registry.add_counter(&alive, 1);
                }
            }
        }
    });
    SystemTimeMonitor { shutdown, task }
}

/// Spawns the monitor against the system wall clock.
#[must_use]
pub fn spawn_system_time_monitor(registry: Arc<MetricsRegistry>) -> SystemTimeMonitor {
    spawn_system_time_monitor_with_clock(registry, wall_clock_nanos)
}

/// Payload-free stable fields used by the two session lifecycle logs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionLogContext {
    /// Stable connection ID.
    pub connection_id: u64,
    /// Listener address.
    pub listener: String,
    /// Actual TCP peer address.
    pub client_address: String,
    /// PROXY-protocol inner client address; falls back to the TCP peer when no
    /// inet source was decoded.
    pub proxy_client_address: String,
    /// Bounded namespace identifier.
    pub namespace: String,
    /// Captured config generation.
    pub generation: u64,
}

static SESSION_LOG_WRITER: OnceLock<fn(&str)> = OnceLock::new();

/// Installs the process log writer used by [`log_session`]. The binary
/// installs the shared rotating-file output once at startup; until then (and
/// in tests) session logs go to stderr. A second install is ignored.
pub fn install_session_log_writer(writer: fn(&str)) {
    let _ = SESSION_LOG_WRITER.set(writer);
}

/// Emits one JSON-line lifecycle log with a closed field set. All string
/// values are escaped and truncated; callers cannot attach query/auth data.
#[allow(clippy::too_many_arguments)]
pub fn log_session(
    event: &'static str,
    context: &SessionLogContext,
    backend_id: &str,
    backend_address: &str,
    cluster: &str,
    capabilities: u64,
    source: QuitSource,
) {
    let line = session_log_line(
        event,
        context,
        backend_id,
        backend_address,
        cluster,
        capabilities,
        source,
    );
    match SESSION_LOG_WRITER.get() {
        Some(writer) => writer(&line),
        None => eprintln!("{line}"),
    }
}

#[allow(clippy::too_many_arguments)]
fn session_log_line(
    event: &'static str,
    context: &SessionLogContext,
    backend_id: &str,
    backend_address: &str,
    cluster: &str,
    capabilities: u64,
    source: QuitSource,
) -> String {
    format!(
        "{{\"level\":\"info\",\"event\":\"{}\",\"connection_id\":{},\"listener\":\"{}\",\"client_addr\":\"{}\",\"proxy_client_addr\":\"{}\",\"namespace\":\"{}\",\"backend_id\":\"{}\",\"backend_addr\":\"{}\",\"cluster\":\"{}\",\"generation\":{},\"capabilities\":{},\"quit_source\":\"{}\"}}",
        event,
        context.connection_id,
        json_field(&context.listener),
        json_field(&context.client_address),
        json_field(&context.proxy_client_address),
        json_field(&context.namespace),
        json_field(backend_id),
        json_field(backend_address),
        json_field(cluster),
        context.generation,
        capabilities,
        source.metric_label(),
    )
}

fn json_field(value: &str) -> String {
    let mut end = value.len().min(MAX_LABEL_BYTES);
    while !value.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    let bounded = &value[..end];
    let mut escaped = String::with_capacity(bounded.len());
    for character in bounded.chars() {
        match character {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            character if character.is_control() => escaped.push('?'),
            character => escaped.push(character),
        }
    }
    escaped
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn queue_full_is_non_blocking_and_counted() {
        let (recorder, _rx) = MetricsRecorder::channel(1);
        assert!(recorder.try_record(Observation::GetBackend {
            duration: Duration::from_millis(1),
            succeeded: true,
        }));
        assert!(!recorder.try_record(Observation::GetBackend {
            duration: Duration::from_millis(2),
            succeeded: false,
        }));
        assert_eq!(recorder.dropped(), 1);
    }

    #[test]
    fn quit_source_labels_match_go_exactly() {
        let labels = [
            (QuitSource::None, "success"),
            (QuitSource::ClientNetwork, "client network break"),
            (QuitSource::ClientHandshake, "client handshake fail"),
            (QuitSource::ClientAuthFail, "auth fail"),
            (QuitSource::ClientSqlError, "SQL error"),
            (QuitSource::ProxyQuit, "proxy shutdown"),
            (QuitSource::ProxyMalformed, "malformed packet"),
            (QuitSource::ProxyNoBackend, "get backend fail"),
            (QuitSource::ProxyError, "proxy error"),
            (QuitSource::BackendNetwork, "backend network break"),
            (QuitSource::BackendHandshake, "backend handshake fail"),
        ];
        for (source, expected) in labels {
            assert_eq!(source.metric_label(), expected);
        }
    }

    #[test]
    fn histogram_wire_semantics_are_exact_and_cumulative() {
        let mut aggregator = Aggregator::default();
        aggregator.observe(Observation::GetBackend {
            duration: Duration::from_micros(1),
            succeeded: true,
        });
        aggregator.observe(Observation::GetBackend {
            duration: Duration::from_micros(3),
            succeeded: false,
        });
        let metrics = aggregator.wire_metrics(&[]);
        let histogram = metrics
            .iter()
            .find(|metric| metric.name == "tiproxy_backend_get_backend_duration_seconds");
        assert!(histogram.is_some());
        let Some(histogram) = histogram else {
            return;
        };
        assert_eq!(histogram.counter_delta, 2);
        assert!((histogram.gauge - 0.000_004).abs() < f64::EPSILON);
        assert_eq!(histogram.histogram_bucket_deltas[0], 1);
        assert_eq!(histogram.histogram_bucket_deltas[1], 1);
        assert_eq!(histogram.histogram_bucket_deltas[2], 2);
        assert_eq!(
            histogram.histogram_bucket_deltas.len(),
            GET_BACKEND_BUCKETS.len()
        );
    }

    #[test]
    fn backend_keepalive_updates_have_closed_bounded_labels() {
        let mut aggregator = Aggregator::default();
        aggregator.observe(Observation::BackendKeepaliveUpdated {
            backend: "127.0.0.1:4000".to_owned(),
            healthy: false,
            succeeded: true,
        });
        let metrics = aggregator.wire_metrics(&[]);
        assert!(metrics.iter().any(|metric| {
            metric.name == "tiproxy_backend_keepalive_update_total"
                && metric
                    .labels
                    .get("backend")
                    .is_some_and(|value| value == "127.0.0.1:4000")
                && metric
                    .labels
                    .get("health")
                    .is_some_and(|value| value == "unhealthy")
                && metric
                    .labels
                    .get("result")
                    .is_some_and(|value| value == "succeed")
                && metric.counter_delta == 1
        }));
    }

    #[test]
    fn pending_series_reserve_room_for_reconnect_gauge() {
        let mut aggregator = Aggregator::default();
        for index in 0..=MAX_PENDING_SERIES {
            aggregator.counter_once(
                &MetricKey::new(
                    "tiproxy_backend_dial_backend_fail",
                    vec![("backend", format!("backend-{index}"))],
                ),
                1,
            );
        }
        let metrics = aggregator.wire_metrics(&[("tiproxy_server_connections", 1.0)]);
        assert_eq!(metrics.len(), MAX_METRICS_PER_BATCH);
        assert_eq!(aggregator.overflow_dropped, 1);
    }

    #[test]
    fn log_schema_is_closed_payload_free_and_bounded() {
        let context = SessionLogContext {
            connection_id: 7,
            listener: format!("listener\n\"{}", "x".repeat(300)),
            client_address: "127.0.0.1:4000".to_owned(),
            proxy_client_address: "127.0.0.1:4000".to_owned(),
            namespace: "default".to_owned(),
            generation: 9,
        };
        let line = session_log_line(
            "connection_closed",
            &context,
            "tidb-0",
            "127.0.0.1:4000",
            "cluster-a",
            12,
            QuitSource::ClientAuthFail,
        );
        assert!(line.contains("listener\\n\\\""));
        assert!(!line.contains(&"x".repeat(MAX_LABEL_BYTES + 1)));
        assert!(line.contains("\"quit_source\":\"auth fail\""));
        for forbidden in [
            "\"sql\"",
            "\"query\"",
            "\"password\"",
            "\"token\"",
            "\"auth_response\"",
        ] {
            assert!(
                !line.contains(forbidden),
                "forbidden key {forbidden}: {line}"
            );
        }
        let multibyte = json_field(&"界".repeat(MAX_LABEL_BYTES));
        assert!(multibyte.len() <= MAX_LABEL_BYTES);
    }

    #[test]
    fn go_float_formatting_matches_strconv_g_shortest() {
        for (value, expected) in [
            (0.0005, "0.0005"),
            (0.001, "0.001"),
            (0.5, "0.5"),
            (1.0, "1"),
            (32.0, "32"),
            (100_000.0, "100000"),
            (1_000_000.0, "1e+06"),
            (2_097_152.0, "2.097152e+06"),
            (0.000_001, "1e-06"),
            (1.5, "1.5"),
            (123_456_789.0, "1.23456789e+08"),
            (0.1, "0.1"),
            (0.4, "0.4"),
            (1_677_721.6, "1.6777216e+06"),
            (838_860.8, "838860.8"),
            (33_554.432, "33554.432"),
            (1.844_674_407_370_955_2e19, "1.8446744073709552e+19"),
            (0.0, "0"),
            (f64::INFINITY, "+Inf"),
            (-2.5, "-2.5"),
        ] {
            assert_eq!(format_go_float(value), expected, "{value}");
        }
    }

    #[test]
    fn registry_is_the_cumulative_twin_of_the_bridge_deltas() {
        let mut aggregator = Aggregator::default();
        let registry = Arc::clone(&aggregator.registry);
        aggregator.observe(Observation::GetBackend {
            duration: Duration::from_micros(1),
            succeeded: true,
        });
        let _ = aggregator.wire_metrics(&[]);
        aggregator.clear_sent();
        aggregator.observe(Observation::GetBackend {
            duration: Duration::from_micros(3),
            succeeded: false,
        });
        let text = registry.render_prometheus_text();
        assert!(text.contains("tiproxy_backend_get_backend{res=\"fail\"} 1\n"));
        assert!(text.contains("tiproxy_backend_get_backend{res=\"succeed\"} 1\n"));
        assert!(text.contains("tiproxy_backend_get_backend_duration_seconds_count 2\n"));
        assert!(
            text.contains("tiproxy_backend_get_backend_duration_seconds_bucket{le=\"1e-06\"} 1\n")
        );
        assert!(
            text.contains("tiproxy_backend_get_backend_duration_seconds_bucket{le=\"+Inf\"} 2\n")
        );
        // Families are rendered in name order with HELP/TYPE headers.
        let help = text.find("# HELP tiproxy_backend_get_backend ");
        let server = text.find("# HELP tiproxy_server_connections ");
        assert!(help.is_some() && server.is_some() && help < server);
        assert!(
            !text.contains("tiproxy_backend_dial_backend_fail"),
            "a labeled family without series is absent, like a Go vec with no children"
        );
        // Unlabeled families are always present; labeled ones only once used.
        assert!(text.contains("tiproxy_server_create_connection_total 0\n"));
        assert!(!text.contains("tiproxy_session_query_total{"));
    }

    /// Fixed observations for natively served families with no recorded
    /// batch. Must equal the generator's constants.
    const FIXED_KEEP_ALIVES: u32 = 3;
    const FIXED_TIME_JUMPS: u32 = 2;
    /// `CodexM5`'s full-queue regression, restated for the pull design. Its
    /// point is unchanged: once the terminal notification is lost and no
    /// further event will arrive, the exposition must still be right.
    #[test]
    fn review_full_queue_cannot_leave_settled_migration_pending() {
        struct Settled;
        impl MigrationStateSource for Settled {
            fn migration_state(&self) -> control_router::MigrationSnapshot {
                let mut snapshot = control_router::MigrationSnapshot::default();
                // The migration finished; nothing is in flight.
                snapshot.history.known_pending.insert((
                    "127.0.0.1:4000".to_owned(),
                    "127.0.0.1:4001".to_owned(),
                    control_router::RedirectReason::Test,
                ));
                snapshot.history.terminals.insert(
                    control_router::TerminalKey {
                        from: "127.0.0.1:4000".to_owned(),
                        to: "127.0.0.1:4001".to_owned(),
                        reason: control_router::RedirectReason::Test,
                        succeeded: true,
                    },
                    1,
                );
                snapshot
            }
        }

        // Reproduce the real loss: a capacity-one queue cannot carry both
        // ends, so one of them is genuinely dropped.
        let (recorder, _receiver) = MetricsRecorder::channel(1);
        let sink = MigrationMetrics::new(recorder.clone());
        let event = |outcome| control_router::MigrationObservation {
            from: "127.0.0.1:4000".to_owned(),
            to: "127.0.0.1:4001".to_owned(),
            reason: control_router::RedirectReason::Test,
            outcome,
        };
        control_router::MigrationSink::record(
            &sink,
            event(control_router::MigrationOutcome::Issued),
        );
        control_router::MigrationSink::record(
            &sink,
            event(control_router::MigrationOutcome::Settled {
                success: true,
                elapsed: Duration::from_millis(2),
            }),
        );
        assert_eq!(
            recorder.dropped(),
            1,
            "fixture must reach real bounded queue loss"
        );

        let registry = MetricsRegistry::new();
        registry.set_migration_state_source(Arc::new(Settled));
        let rendered = registry.render_prometheus_text();
        assert!(
            rendered.contains(
                "tiproxy_balance_pending_migrate{from=\"127.0.0.1:4000\",reason=\"test\",to=\"127.0.0.1:4001\"} 0"
            ),
            "a dropped terminal must not leave a phantom pending:\n{rendered}"
        );
        assert!(
            rendered.contains("tiproxy_balance_migrate_total{") && rendered.contains("} 1"),
            "and the terminal must still be counted:\n{rendered}"
        );
    }

    /// A refused label set must reach the same visible counter as every other
    /// shed signal. It replaced a path that was already counted, so leaving it
    /// only in the snapshot would make overflow quieter than before.
    #[test]
    fn refused_label_sets_reach_the_visible_dropped_counter() {
        struct Flood;
        impl MigrationStateSource for Flood {
            fn migration_state(&self) -> control_router::MigrationSnapshot {
                let history = control_router::MigrationHistory::default();
                for index in 0..(control_router::MAX_RETAINED_LABEL_SETS + 5) {
                    history.remember(
                        &format!("10.0.0.1:{index}"),
                        "10.0.0.2:4000",
                        control_router::RedirectReason::Test,
                    );
                }
                control_router::MigrationSnapshot {
                    pending: BTreeMap::new(),
                    backend_connections: BTreeMap::new(),
                    history: history.snapshot(),
                }
            }
        }
        let registry = MetricsRegistry::new();
        assert_eq!(
            registry.migration_labels_dropped(),
            0,
            "nothing refused before a source is installed"
        );
        registry.set_migration_state_source(Arc::new(Flood));
        assert_eq!(registry.migration_labels_dropped(), 5);
    }

    /// `CodexM5`'s capacity regression, restated: the bound has to hold on the
    /// structures that actually grow, and be visible at the render entry.
    #[test]
    fn review_migration_state_is_bounded_with_registry() {
        struct Flood;
        impl MigrationStateSource for Flood {
            fn migration_state(&self) -> control_router::MigrationSnapshot {
                let history = control_router::MigrationHistory::default();
                for index in 0..(control_router::MAX_RETAINED_LABEL_SETS + 64) {
                    history.remember(
                        &format!("10.0.0.1:{index}"),
                        "10.0.0.2:4000",
                        control_router::RedirectReason::Test,
                    );
                }
                control_router::MigrationSnapshot {
                    pending: BTreeMap::new(),
                    backend_connections: BTreeMap::new(),
                    history: history.snapshot(),
                }
            }
        }

        let state = Flood.migration_state();
        assert_eq!(
            state.history.known_pending.len(),
            control_router::MAX_RETAINED_LABEL_SETS,
            "retention is bounded on the structure that grows"
        );
        assert_eq!(state.history.labels_dropped, 64);
        let registry = MetricsRegistry::new();
        registry.set_migration_state_source(Arc::new(Flood));
        let rendered = registry.render_prometheus_text();
        assert_eq!(
            rendered
                .lines()
                .filter(|line| line.starts_with("tiproxy_balance_pending_migrate{"))
                .count(),
            control_router::MAX_RETAINED_LABEL_SETS,
            "the exposition cannot emit more series than are retained"
        );
    }

    /// The duration bounds exist in two crates: the router buckets a
    /// settlement when it records it, and this catalogue declares the same
    /// bounds for the exposition. They must stay identical or the rendered
    /// histogram would not match the counts behind it.
    #[test]
    fn migrate_buckets_match_the_router_that_fills_them() {
        assert_eq!(
            MIGRATE_BUCKETS.as_slice(),
            control_router::MIGRATE_DURATION_BUCKETS.as_slice()
        );
    }

    /// Mirrors `fixedBackendMetrics` in
    /// `tests/dataplane/metrics/gen/main.go`.
    ///
    /// `10.0.0.2:4000` carries health indicators and no resource samples:
    /// Go writes only what each factor accepted, so a backend with a
    /// partial row is the ordinary case, not a fixture shortcut.
    struct FixedBackendMetrics;

    impl BackendMetricStateSource for FixedBackendMetrics {
        fn backend_metric_state(&self) -> control_router::BackendMetricSnapshot {
            use control_router::BackendMetric;
            control_router::BackendMetricSnapshot {
                values: [
                    (("10.0.0.1:4000".to_owned(), BackendMetric::Cpu), 0.25),
                    (("10.0.0.1:4000".to_owned(), BackendMetric::Memory), 0.5),
                    (("10.0.0.2:4000".to_owned(), BackendMetric::FailurePd), 2.0),
                    (("10.0.0.2:4000".to_owned(), BackendMetric::TotalPd), 100.0),
                    (
                        ("10.0.0.2:4000".to_owned(), BackendMetric::FailureTikv),
                        0.0,
                    ),
                    (("10.0.0.2:4000".to_owned(), BackendMetric::TotalTikv), 40.0),
                ]
                .into_iter()
                .collect(),
                labels_dropped: 0,
            }
        }
    }

    /// Mirrors `fixedBackendScores` in
    /// `tests/dataplane/metrics/gen/main.go`.
    ///
    /// A backend need not carry every factor: Go writes whatever the
    /// configured factor set produced, so a partial row is a real shape and
    /// not a fixture shortcut.
    struct FixedScores;

    impl ScoreStateSource for FixedScores {
        fn score_state(&self) -> control_router::ScoreSnapshot {
            use control_router::Factor;
            control_router::ScoreSnapshot {
                scores: [
                    (("10.0.0.1:4000".to_owned(), Factor::Connection), 3),
                    (("10.0.0.1:4000".to_owned(), Factor::Cpu), 1),
                    (("10.0.0.2:4000".to_owned(), Factor::Connection), 7),
                    (("10.0.0.3:4000".to_owned(), Factor::Status), 0),
                ]
                .into_iter()
                .collect(),
                labels_dropped: 0,
            }
        }
    }

    /// Mirrors `fixedOwnedElections` and `fixedRetiredElection` in
    /// `tests/dataplane/metrics/gen/main.go`.
    ///
    /// The Go fixture wins `metric_reader/z2` and then retires it, which
    /// deletes the child. Nothing here represents it, because a retired
    /// election has no series -- not a series at zero.
    struct FixedOwner;

    impl OwnerStateSource for FixedOwner {
        fn owner_state(&self) -> control_topology::OwnerSnapshot {
            control_topology::OwnerSnapshot {
                owned: ["metric_reader".to_owned(), "metric_reader/z1".to_owned()]
                    .into_iter()
                    .collect(),
                labels_dropped: 0,
            }
        }
    }

    /// Mirrors `fixedBackendHealth` and `fixedHealthCheckCycleSeconds` in
    /// `tests/dataplane/metrics/gen/main.go`.
    ///
    /// `10.0.0.3:4000` reports a ping and no status: it has been dialled but
    /// never been healthy, so Go never created its `b_status` child. A
    /// rendering that emitted it at zero would look harmless and be wrong.
    struct FixedHealth;

    impl HealthStateSource for FixedHealth {
        fn health_state(&self) -> control_topology::HealthMetricsSnapshot {
            let mut snapshot = control_topology::HealthMetricsSnapshot::default();
            snapshot.status.insert("10.0.0.1:4000".to_owned(), true);
            snapshot.status.insert("10.0.0.2:4000".to_owned(), false);
            for (address, seconds) in [
                ("10.0.0.1:4000", 0.004),
                ("10.0.0.2:4000", 0.012),
                ("10.0.0.3:4000", 0.25),
            ] {
                snapshot.ping.insert(
                    address.to_owned(),
                    control_topology::PingSample {
                        seconds,
                        sequence: 0,
                    },
                );
            }
            snapshot.cycle_seconds = Some(1.5);
            snapshot
        }
    }

    /// Mirrors `fixedMigrations` in `tests/dataplane/metrics/gen/main.go`:
    /// one succeeded and one failed migration whose pending series return to
    /// zero, and a third still in flight.
    struct FixedMigrations;

    impl MigrationStateSource for FixedMigrations {
        fn migration_state(&self) -> control_router::MigrationSnapshot {
            let (from, to) = ("10.0.0.1:4000".to_owned(), "10.0.0.2:4000".to_owned());
            let settled_reason =
                control_router::RedirectReason::Balance(control_router::Factor::Connection);
            let flight_reason =
                control_router::RedirectReason::Balance(control_router::Factor::Status);
            let flight_to = "10.0.0.3:4000".to_owned();
            let mut snapshot = control_router::MigrationSnapshot::default();
            // Mirrors `fixedBackendConns` in the Go oracle.
            snapshot
                .backend_connections
                .insert("10.0.0.1:4000".to_owned(), 2);
            snapshot
                .backend_connections
                .insert("10.0.0.2:4000".to_owned(), 1);
            snapshot.pending.insert(
                control_router::MigrationLabels {
                    from: from.clone(),
                    to: flight_to.clone(),
                    reason: flight_reason,
                },
                1,
            );
            snapshot
                .history
                .known_pending
                .insert((from.clone(), to.clone(), settled_reason));
            snapshot
                .history
                .known_pending
                .insert((from.clone(), flight_to, flight_reason));
            for (succeeded, seconds) in [(true, 0.25_f64), (false, 0.5_f64)] {
                snapshot.history.terminals.insert(
                    control_router::TerminalKey {
                        from: from.clone(),
                        to: to.clone(),
                        reason: settled_reason,
                        succeeded,
                    },
                    1,
                );
                let mut series = control_router::DurationSeries {
                    count: 1,
                    sum_nanos: Duration::from_secs_f64(seconds).as_nanos(),
                    buckets: [0; 26],
                };
                for (count, bound) in series
                    .buckets
                    .iter_mut()
                    .zip(control_router::MIGRATE_DURATION_BUCKETS)
                {
                    if seconds <= bound {
                        *count = 1;
                    }
                }
                snapshot.history.durations.insert(
                    control_router::DurationKey {
                        from: from.clone(),
                        to: to.clone(),
                        succeeded,
                    },
                    series,
                );
            }
            snapshot
        }
    }

    /// Go's monitor counts a jump only when the clock reads earlier after the
    /// wait than before it, calls back every tenth tick, and the keepalive
    /// rises every fifth callback: one heartbeat per 50 ticks (5s), while a
    /// rewind inside a single 100ms wait is still caught.
    #[tokio::test(start_paused = true)]
    async fn system_time_monitor_counts_jumps_and_heartbeats_like_go() {
        let registry = Arc::new(MetricsRegistry::new());
        let clock = Arc::new(Mutex::new(0_i128));
        let step = Arc::new(Mutex::new(100_000_000_i128));
        let reader = {
            let clock = Arc::clone(&clock);
            let step = Arc::clone(&step);
            move || {
                let mut value = clock
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let delta = *step
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                *value += delta;
                *value
            }
        };
        let monitor = spawn_system_time_monitor_with_clock(Arc::clone(&registry), reader);
        let jump = MetricKey::new("tiproxy_monitor_time_jump_back_total", Vec::new());
        let alive = MetricKey::new("tiproxy_monitor_keep_alive_total", Vec::new());
        // Let the task consume the interval's immediate first tick and reach
        // its wait, so each advance below delivers exactly one counted tick.
        tokio::task::yield_now().await;

        // Advance one tick at a time: the interval skips missed ticks, as Go's
        // ticker drops them, so a single long jump forward would deliver one.
        for _ in 0..50 {
            tokio::time::advance(Duration::from_millis(100)).await;
            tokio::task::yield_now().await;
        }
        assert_eq!(
            registry.lock().counters.get(&jump),
            None,
            "a forward clock is not a jump"
        );
        assert_eq!(
            registry.lock().counters.get(&alive),
            Some(&1),
            "one heartbeat per 50 ticks"
        );

        *step
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = -1;
        tokio::time::advance(Duration::from_millis(100)).await;
        tokio::task::yield_now().await;
        assert_eq!(
            registry.lock().counters.get(&jump),
            Some(&1),
            "a backward reading across one 100ms wait is one jump"
        );
        monitor.stop();
        monitor.join().await.unwrap_or_else(|e| unreachable!("{e}"));
    }

    #[test]
    fn registry_bounds_series_and_escapes_labels() {
        let registry = MetricsRegistry::new();
        for index in 0..MAX_REGISTRY_SERIES + 5 {
            registry.add_counter(
                &MetricKey::new(
                    "tiproxy_backend_dial_backend_fail",
                    vec![("backend", format!("b{index}"))],
                ),
                1,
            );
        }
        assert_eq!(registry.series_dropped(), 5);
        registry.add_counter(
            &MetricKey::new(
                "tiproxy_backend_dial_backend_fail",
                vec![("backend", "quote\"back\\slash\nline".to_owned())],
            ),
            1,
        );
        assert_eq!(
            registry.series_dropped(),
            6,
            "a bounded registry sheds the escaped series too"
        );
        let small = MetricsRegistry::new();
        small.add_counter(
            &MetricKey::new(
                "tiproxy_backend_dial_backend_fail",
                vec![("backend", "quote\"back\\slash\nline".to_owned())],
            ),
            1,
        );
        assert!(small.render_prometheus_text().contains(
            "tiproxy_backend_dial_backend_fail{backend=\"quote\\\"back\\\\slash\\nline\"} 1\n"
        ));
    }

    /// Labeled gauges share the counter/histogram bound. Per-backend and
    /// per-migration-pair gauges are unbounded in principle, so a family that
    /// grows without limit must shed new series instead of the registry
    /// growing forever. Rendering of labeled gauge families is covered by the
    /// first catalogued labeled gauge family; this pins the storage contract.
    #[test]
    fn labeled_gauges_are_kept_per_label_set_and_share_the_series_bound() {
        let registry = MetricsRegistry::new();
        let key = |backend: &str| {
            MetricKey::new(
                "tiproxy_server_connections",
                vec![("backend", backend.to_owned())],
            )
        };
        registry.set_labeled_gauge(&key("a"), 1.0);
        registry.set_labeled_gauge(&key("b"), 2.0);
        registry.set_labeled_gauge(&key("a"), 3.0);
        {
            let state = registry.lock();
            assert_eq!(state.gauges.len(), 2, "one series per label set");
            assert_eq!(state.gauges.get(&key("a")), Some(&3.0), "last write wins");
            assert_eq!(state.gauges.get(&key("b")), Some(&2.0));
        }

        let bounded = MetricsRegistry::new();
        for index in 0..MAX_REGISTRY_SERIES + 3 {
            bounded.set_labeled_gauge(
                &MetricKey::new(
                    "tiproxy_server_connections",
                    vec![("backend", format!("backend-{index}"))],
                ),
                1.0,
            );
        }
        assert_eq!(bounded.series_dropped(), 3);
        assert_eq!(bounded.lock().gauges.len(), MAX_REGISTRY_SERIES);
        // An already-present series is still writable once the bound is hit.
        bounded.set_labeled_gauge(
            &MetricKey::new(
                "tiproxy_server_connections",
                vec![("backend", "backend-0".to_owned())],
            ),
            9.0,
        );
        assert_eq!(
            bounded.series_dropped(),
            3,
            "updating an existing series is not a new one"
        );
    }

    /// The deterministic observation script shared with the Go parity
    /// generator (`tests/dataplane/metrics/gen`). Durations are dyadic so the
    /// histogram sums are exact regardless of summation order.
    #[allow(clippy::too_many_lines)]
    fn parity_script(aggregator: &mut Aggregator) -> Vec<Vec<MetricDelta>> {
        let backend_a = "10.0.0.1:4000".to_owned();
        let backend_b = "10.0.0.2:4000".to_owned();
        let traffic = |inbound: u64, outbound: u64| BackendTraffic {
            inbound_bytes: inbound,
            inbound_packets: inbound / 50,
            outbound_bytes: outbound,
            outbound_packets: outbound / 50,
        };
        let mut batches = Vec::new();
        aggregator.observe(Observation::GetBackend {
            duration: Duration::from_micros(1),
            succeeded: true,
        });
        aggregator.observe(Observation::GetBackend {
            duration: Duration::from_millis(250),
            succeeded: false,
        });
        aggregator.observe(Observation::DialBackendFailed {
            backend: backend_a.clone(),
        });
        aggregator.observe(Observation::BackendKeepaliveUpdated {
            backend: backend_a.clone(),
            healthy: false,
            succeeded: true,
        });
        aggregator.observe(Observation::HandshakeCompleted {
            backend: backend_a.clone(),
            duration: Duration::from_millis(500),
            traffic: traffic(100, 50),
            local: true,
        });
        aggregator.observe(Observation::CommandCompleted {
            backend: backend_a.clone(),
            command: Command::Query,
            duration: Duration::from_millis(125),
            since_connection: Duration::from_secs(3),
            traffic: traffic(1_000, 200),
            local: false,
        });
        ExportTotals {
            registered: 2,
            rejected_max: 1,
            accept_errors: 1,
            reconnect_attempts: 1,
            ..ExportTotals::default()
        }
        .accumulate_delta(ExportTotals::default(), aggregator);
        aggregator
            .registry
            .set_gauge("tiproxy_server_connections", 2.0);
        batches.push(aggregator.wire_metrics(&[("tiproxy_server_connections", 2.0)]));
        aggregator.clear_sent();

        aggregator.observe(Observation::CommandCompleted {
            backend: backend_b.clone(),
            command: Command::StmtExecute,
            duration: Duration::from_millis(62),
            since_connection: Duration::from_secs(70),
            traffic: traffic(300, 150),
            local: true,
        });
        aggregator.observe(Observation::CommandCompleted {
            backend: backend_a,
            command: Command::Query,
            duration: Duration::from_secs(2),
            since_connection: Duration::from_secs(4),
            traffic: traffic(50, 50),
            local: false,
        });
        aggregator.observe(Observation::SessionClosed {
            source: QuitSource::ClientNetwork,
            lifetime: Duration::from_millis(12_500),
            traffic: TrafficTotals::default(),
        });
        aggregator.observe(Observation::BackendKeepaliveUpdated {
            backend: backend_b,
            healthy: true,
            succeeded: false,
        });
        ExportTotals {
            registered: 3,
            rejected_max: 1,
            // ADM-001's label. Without a recorded delta here the golden only
            // ever compared `type="max_connections"`, so the memory reason
            // -- a different Go counter path -- was never rendered at all.
            rejected_memory: 1,
            accept_errors: 1,
            reconnect_attempts: 1,
            dispatch_stale: 2,
            ..ExportTotals::default()
        }
        .accumulate_delta(
            ExportTotals {
                registered: 2,
                rejected_max: 1,
                accept_errors: 1,
                reconnect_attempts: 1,
                ..ExportTotals::default()
            },
            aggregator,
        );
        aggregator
            .registry
            .set_gauge("tiproxy_server_connections", 1.0);
        batches.push(aggregator.wire_metrics(&[("tiproxy_server_connections", 1.0)]));
        aggregator.clear_sent();
        batches
    }

    fn batches_json(batches: &[Vec<MetricDelta>]) -> String {
        let mut out = String::from("[\n");
        for (index, batch) in batches.iter().enumerate() {
            let _ = write!(out, "  {{\"sequence\": {}, \"metrics\": [", index + 1);
            for (position, metric) in batch.iter().enumerate() {
                if position > 0 {
                    out.push(',');
                }
                out.push_str("\n    {\"name\": \"");
                out.push_str(&metric.name);
                out.push_str("\", \"labels\": {");
                let mut first = true;
                for (key, value) in &metric.labels {
                    if !first {
                        out.push_str(", ");
                    }
                    first = false;
                    let _ = write!(out, "\"{key}\": \"{}\"", escape_label_value(value));
                }
                let _ = write!(
                    out,
                    "}}, \"counter_delta\": {}, \"gauge\": {}, \"histogram_bucket_deltas\": [",
                    metric.counter_delta,
                    format_go_float(metric.gauge)
                );
                let buckets: Vec<String> = metric
                    .histogram_bucket_deltas
                    .iter()
                    .map(u64::to_string)
                    .collect();
                out.push_str(&buckets.join(", "));
                out.push_str("]}");
            }
            out.push_str("\n  ]}");
            if index + 1 < batches.len() {
                out.push(',');
            }
            out.push('\n');
        }
        out.push_str("]\n");
        out
    }

    /// Golden parity with the Go `promhttp` exposition of the same deltas.
    /// `tests/dataplane/metrics/parity-expected.txt` is produced by
    /// `go run ./tests/dataplane/metrics/gen` from `parity-batches.json`;
    /// setting `TIPROXY_UPDATE_METRICS_PARITY=1` rewrites the batches and the
    /// Rust rendering instead of asserting.
    #[test]
    fn native_exposition_matches_go_golden() {
        let mut aggregator = Aggregator::default();
        let batches = parity_script(&mut aggregator);
        // Families that never crossed the bridge have no recorded batch, so
        // the fixture drives them with the same fixed observations the Go
        // oracle applies. Non-zero on both sides, so an empty shell cannot
        // pass; the production rule is covered by the clock unit test.
        for _ in 0..FIXED_KEEP_ALIVES {
            aggregator.registry.add_counter(
                &MetricKey::new("tiproxy_monitor_keep_alive_total", Vec::new()),
                1,
            );
        }
        for _ in 0..FIXED_TIME_JUMPS {
            aggregator.registry.add_counter(
                &MetricKey::new("tiproxy_monitor_time_jump_back_total", Vec::new()),
                1,
            );
        }
        // The same migration fixture the Go oracle applies. These families are
        // rendered from authoritative state, so the fixture is installed as
        // that state rather than pushed through the observation path.
        aggregator
            .registry
            .set_migration_state_source(Arc::new(FixedMigrations));
        // Likewise for the backend health families, which the topology path
        // owns rather than this registry.
        aggregator
            .registry
            .set_health_state_source(Arc::new(FixedHealth));
        aggregator
            .registry
            .set_owner_state_source(Arc::new(FixedOwner));
        aggregator
            .registry
            .set_score_state_source(Arc::new(FixedScores));
        aggregator
            .registry
            .set_backend_metric_state_source(Arc::new(FixedBackendMetrics));
        let rendered = aggregator.registry.render_prometheus_text();
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../tests/dataplane/metrics");

        // The oracle selects families by this list, so a family missing from
        // either side must fail rather than quietly drop out of the compare.
        let Ok(list) = std::fs::read_to_string(root.join("native-families.json")) else {
            unreachable!("missing tests/dataplane/metrics/native-families.json")
        };
        let Ok(doc) = serde_json::from_str::<serde_json::Value>(&list) else {
            unreachable!("native-families.json is not valid JSON")
        };
        let Some(entries) = doc["families"].as_array() else {
            unreachable!("native-families.json has no families array")
        };
        let listed: BTreeSet<&str> = entries.iter().filter_map(|v| v.as_str()).collect();
        assert_eq!(
            listed.len(),
            entries.len(),
            "native-families.json lists a name twice"
        );
        let catalogued: BTreeSet<&str> = METRIC_SPECS.iter().map(|spec| spec.name).collect();
        assert_eq!(
            listed, catalogued,
            "native-families.json and METRIC_SPECS disagree; the Go oracle selects by the \
             list, so a family in only one of them would never be compared"
        );
        if std::env::var_os("TIPROXY_UPDATE_METRICS_PARITY").is_some() {
            assert!(
                std::fs::write(root.join("parity-batches.json"), batches_json(&batches)).is_ok()
            );
            assert!(std::fs::write(root.join("parity-rust.txt"), &rendered).is_ok());
            return;
        }
        let Ok(expected) = std::fs::read_to_string(root.join("parity-expected.txt")) else {
            unreachable!("missing tests/dataplane/metrics/parity-expected.txt")
        };
        assert_eq!(
            rendered, expected,
            "native exposition diverged from the Go golden; regenerate with \
             TIPROXY_UPDATE_METRICS_PARITY=1 and go run ./tests/dataplane/metrics/gen"
        );
        let Ok(recorded) = std::fs::read_to_string(root.join("parity-batches.json")) else {
            unreachable!("missing tests/dataplane/metrics/parity-batches.json")
        };
        assert_eq!(
            batches_json(&batches),
            recorded,
            "the recorded delta batches no longer match the observation script"
        );
    }

    #[test]
    fn command_key_cache_is_bounded_and_uncached_pairs_still_fold() {
        let mut aggregator = Aggregator {
            command_key_capacity: 2,
            ..Aggregator::default()
        };
        let observe = |aggregator: &mut Aggregator, backend: &str| {
            aggregator.observe(Observation::CommandCompleted {
                backend: backend.to_owned(),
                command: Command::Query,
                duration: Duration::from_millis(1),
                since_connection: Duration::from_secs(1),
                traffic: BackendTraffic {
                    inbound_bytes: 10,
                    inbound_packets: 1,
                    outbound_bytes: 5,
                    outbound_packets: 1,
                },
                local: true,
            });
        };
        observe(&mut aggregator, "backend-a");
        observe(&mut aggregator, "backend-b");
        observe(&mut aggregator, "backend-c");
        assert_eq!(aggregator.command_keys.len(), 2);
        let query_total = |backend: &str| {
            MetricKey::new(
                "tiproxy_session_query_total",
                vec![
                    ("backend", backend.to_owned()),
                    ("cmd_type", Command::Query.name().to_owned()),
                ],
            )
        };
        assert_eq!(
            aggregator.pending.get(&query_total("backend-c")),
            Some(&PendingMetric::Counter(1))
        );

        aggregator.clear_sent();
        observe(&mut aggregator, "backend-c");
        observe(&mut aggregator, "backend-a");
        assert_eq!(aggregator.command_keys.len(), 2);
        assert_eq!(
            aggregator.pending.get(&query_total("backend-c")),
            Some(&PendingMetric::Counter(1))
        );
        let state = aggregator.registry.lock();
        assert_eq!(state.counters.get(&query_total("backend-c")), Some(&2));
        assert_eq!(state.counters.get(&query_total("backend-a")), Some(&2));
    }
    fn completion(
        backend: &str,
        command: Command,
        micros: u64,
        traffic: BackendTraffic,
        local: bool,
    ) -> Observation {
        Observation::CommandCompleted {
            backend: backend.to_owned(),
            command,
            duration: Duration::from_micros(micros),
            since_connection: Duration::from_millis(micros * 7),
            traffic,
            local,
        }
    }

    fn mixed_completions() -> Vec<Observation> {
        let traffic = |inbound: u64, outbound: u64| BackendTraffic {
            inbound_bytes: inbound,
            inbound_packets: inbound / 50,
            outbound_bytes: outbound,
            outbound_packets: outbound / 50,
        };
        vec![
            completion(
                "10.0.0.1:4000",
                Command::Query,
                300,
                traffic(100, 2_000),
                true,
            ),
            completion("10.0.0.1:4000", Command::Query, 12_000, traffic(0, 0), true),
            completion(
                "10.0.0.1:4000",
                Command::StmtExecute,
                45,
                traffic(60, 0),
                true,
            ),
            completion(
                "10.0.0.2:4000",
                Command::Query,
                900,
                traffic(100, 100),
                false,
            ),
            completion("10.0.0.2:4000", Command::Query, 1, traffic(0, 40), false),
            completion("10.0.0.2:4000", Command::Ping, 3, traffic(0, 0), false),
        ]
    }

    /// opt#23: a session's accumulated batch folds to exactly what the same
    /// completions fold to one by one — registry, pending deltas and shed
    /// counts alike.
    #[test]
    fn command_batches_fold_identically_to_per_completion() {
        let mut one_by_one = Aggregator::default();
        let mut batched = Aggregator::default();
        let mut stats = LocalCommandStats::default();
        for observation in mixed_completions() {
            one_by_one.observe(observation.clone());
            let Observation::CommandCompleted {
                backend,
                command,
                duration,
                since_connection,
                traffic,
                local,
            } = observation
            else {
                unreachable!("fixture only builds completions");
            };
            assert!(stats.accumulate(
                &backend,
                command,
                local,
                duration.as_secs_f64(),
                since_connection.as_secs_f64(),
                traffic,
            ));
        }
        let entries = stats.take();
        assert_eq!(entries.len(), 4, "four (backend, command) pairs");
        for entry in entries {
            batched.observe(Observation::CommandBatch(CommandBatch { entry }));
        }
        assert_eq!(
            batched.registry.render_prometheus_text(),
            one_by_one.registry.render_prometheus_text()
        );
        assert_eq!(batched.wire_metrics(&[]), one_by_one.wire_metrics(&[]));
        assert_eq!(batched.overflow_dropped, one_by_one.overflow_dropped);
        assert!(stats.take().is_empty(), "take drains the accumulator");
    }

    /// An invalid duration is shed exactly as the per-observation histogram
    /// path sheds it: one shed count, the other series still fold.
    #[test]
    fn command_batch_sheds_invalid_durations_like_the_histogram_path() {
        let mut entry = LocalCommandEntry::new("10.0.0.1:4000".to_owned(), Command::Query, true);
        entry.accumulate(f64::NAN, 1.0, BackendTraffic::default());
        entry.accumulate(0.5, -1.0, BackendTraffic::default());
        assert_eq!(
            (entry.count, entry.duration_invalid, entry.since_invalid),
            (2, 1, 1)
        );
        let mut aggregator = Aggregator::default();
        aggregator.observe(Observation::CommandBatch(CommandBatch { entry }));
        assert_eq!(aggregator.overflow_dropped, 2);
        let text = aggregator.registry.render_prometheus_text();
        assert!(text.contains(
            "tiproxy_session_query_total{backend=\"10.0.0.1:4000\",cmd_type=\"Query\"} 2\n"
        ));
        assert!(text.contains(
            "tiproxy_session_query_duration_seconds_count{backend=\"10.0.0.1:4000\",cmd_type=\"Query\"} 1\n"
        ));
    }

    /// Completions stay in the recorder's accumulator (nothing crosses the
    /// queue) until the recorder drops, which flushes one batch per pair.
    #[test]
    fn recorder_accumulates_completions_and_flushes_batches_on_drop() {
        let (recorder, mut rx) = MetricsRecorder::channel(8);
        let session = recorder.clone();
        for observation in mixed_completions() {
            assert!(session.try_record(observation));
        }
        assert!(rx.try_recv().is_err(), "completions never cross the queue");
        assert!(session.try_record(Observation::GetBackend {
            duration: Duration::from_millis(1),
            succeeded: true,
        }));
        assert!(matches!(rx.try_recv(), Ok(Observation::GetBackend { .. })));
        drop(session);
        let mut counts = Vec::new();
        while let Ok(observation) = rx.try_recv() {
            let Observation::CommandBatch(batch) = observation else {
                unreachable!("only batches remain");
            };
            counts.push((
                batch.entry.backend.clone(),
                batch.entry.command.name(),
                batch.entry.count,
            ));
        }
        counts.sort();
        assert_eq!(
            counts,
            vec![
                ("10.0.0.1:4000".to_owned(), Command::Query.name(), 2),
                ("10.0.0.1:4000".to_owned(), Command::StmtExecute.name(), 1),
                ("10.0.0.2:4000".to_owned(), Command::Ping.name(), 1),
                ("10.0.0.2:4000".to_owned(), Command::Query.name(), 2),
            ]
        );
        assert_eq!(recorder.dropped(), 0);
        drop(recorder);
        assert!(
            rx.try_recv().is_err(),
            "a recorder that never accumulated flushes nothing"
        );
    }

    /// Past the per-session pair bound the accumulated pairs go to the queue
    /// as batches and the unseen pair is accepted; only a full queue sheds,
    /// counted per completion.
    #[test]
    fn accumulator_pair_bound_flushes_through_the_queue() {
        let (recorder, mut rx) = MetricsRecorder::channel(MAX_LOCAL_COMMAND_KEYS);
        for index in 0..MAX_LOCAL_COMMAND_KEYS {
            assert!(recorder.try_record(completion(
                &format!("10.0.0.{index}:4000"),
                Command::Query,
                1,
                BackendTraffic::default(),
                true,
            )));
        }
        assert!(rx.try_recv().is_err());
        assert!(recorder.try_record(completion(
            "10.0.1.1:4000",
            Command::Query,
            1,
            BackendTraffic::default(),
            true,
        )));
        let mut flushed = 0;
        while let Ok(observation) = rx.try_recv() {
            assert!(matches!(observation, Observation::CommandBatch(_)));
            flushed += 1;
        }
        assert_eq!(flushed, MAX_LOCAL_COMMAND_KEYS);
        assert_eq!(recorder.dropped(), 0);
        assert_eq!(
            lock_recovering(recorder.local_stats()).entries.len(),
            1,
            "the new pair is accumulated in the emptied accumulator"
        );

        // A queue too small for the flush sheds the surplus, counted per
        // completion: two completions in the shed pair.
        let (recorder, _rx) = MetricsRecorder::channel(1);
        for index in 0..MAX_LOCAL_COMMAND_KEYS {
            for _ in 0..2 {
                assert!(recorder.try_record(completion(
                    &format!("10.0.0.{index}:4000"),
                    Command::Query,
                    1,
                    BackendTraffic::default(),
                    true,
                )));
            }
        }
        assert!(recorder.try_record(completion(
            "10.0.1.1:4000",
            Command::Query,
            1,
            BackendTraffic::default(),
            true,
        )));
        assert_eq!(
            recorder.dropped(),
            2 * (MAX_LOCAL_COMMAND_KEYS as u64 - 1),
            "one batch fits the queue, the rest are shed per completion"
        );
    }

    /// The sweep folds every live accumulator and forgets closed sessions.
    #[test]
    fn sweep_folds_live_accumulators_and_prunes_closed_ones() {
        let (recorder, _rx) = MetricsRecorder::channel(8);
        let first = recorder.clone();
        let second = recorder.clone();
        let idle = recorder.clone();
        for observation in mixed_completions() {
            assert!(first.try_record(observation));
        }
        assert!(second.try_record(completion(
            "10.0.0.9:4000",
            Command::Query,
            5,
            BackendTraffic::default(),
            true,
        )));
        let accumulators = recorder.accumulators();
        assert_eq!(
            lock_recovering(&accumulators).len(),
            2,
            "idle clones never register"
        );
        let mut aggregator = Aggregator::default();
        sweep_accumulators(&accumulators, &mut aggregator);
        let text = aggregator.registry.render_prometheus_text();
        assert!(text.contains(
            "tiproxy_session_query_total{backend=\"10.0.0.1:4000\",cmd_type=\"Query\"} 2\n"
        ));
        assert!(text.contains(
            "tiproxy_session_query_total{backend=\"10.0.0.9:4000\",cmd_type=\"Query\"} 1\n"
        ));
        drop(second);
        drop(idle);
        sweep_accumulators(&accumulators, &mut aggregator);
        assert_eq!(
            lock_recovering(&accumulators).len(),
            1,
            "closed sessions are pruned"
        );
        assert_eq!(
            aggregator.registry.render_prometheus_text(),
            text,
            "a second sweep with nothing new changes nothing"
        );
        drop(first);
    }
}
