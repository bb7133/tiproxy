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

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
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
pub const METRIC_SPECS: [MetricSpec; 22] = [
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
        name: "tiproxy_backend_keepalive_update_total",
        help: "Counter of health-driven backend keepalive policy updates.",
        kind: MetricKind::Counter,
        labels: &["backend", "health", "result"],
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
}

/// Process-local cumulative store behind the native Prometheus exposition.
///
/// The exporter feeds it through the same [`Aggregator`] mapping that produces
/// the bridge deltas, so the `/metrics` text rendered here and the Go-side
/// merge of those deltas describe the same series. Counters and histograms
/// reset with the process, which is ordinary Prometheus counter semantics.
#[derive(Debug, Default)]
pub struct MetricsRegistry {
    state: Mutex<RegistryState>,
}

impl MetricsRegistry {
    /// Creates an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, RegistryState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn add_counter(&self, key: &MetricKey, delta: u64) {
        let mut state = self.lock();
        if !state.counters.contains_key(key) && state.series_count() >= MAX_REGISTRY_SERIES {
            state.series_dropped = state.series_dropped.saturating_add(1);
            return;
        }
        let value = state.counters.entry(key.clone()).or_insert(0);
        *value = value.saturating_add(delta);
    }

    fn observe_histogram(&self, key: &MetricKey, seconds: f64, buckets: &[f64]) {
        let mut state = self.lock();
        if !state.histograms.contains_key(key) && state.series_count() >= MAX_REGISTRY_SERIES {
            state.series_dropped = state.series_dropped.saturating_add(1);
            return;
        }
        let entry = state
            .histograms
            .entry(key.clone())
            .or_insert_with(|| HistogramState {
                cumulative_buckets: vec![0; buckets.len()],
                ..HistogramState::default()
            });
        entry.count = entry.count.saturating_add(1);
        entry.sum += seconds;
        for (upper, bucket) in buckets.iter().zip(entry.cumulative_buckets.iter_mut()) {
            if seconds <= *upper {
                *bucket = bucket.saturating_add(1);
            }
        }
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
        let state = self.lock();
        let mut out = String::new();
        for spec in &METRIC_SPECS {
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
            | Self::CommandCompleted { backend, .. } => backend.len() <= MAX_LABEL_BYTES,
            Self::GetBackend { .. } | Self::SessionClosed { .. } => true,
        }
    }
}

/// Cloneable non-blocking SQL-path metrics surface.
#[derive(Clone, Default)]
pub struct MetricsRecorder {
    tx: Option<mpsc::Sender<Observation>>,
    dropped: Arc<AtomicU64>,
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
        if !observation.labels_are_bounded() || tx.try_send(observation).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        true
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

#[derive(Debug, Clone)]
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
    /// Cumulative twin of `pending`: every accepted delta is also folded into
    /// the process-local registry that backs the native `/metrics` exposition.
    registry: Arc<MetricsRegistry>,
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
            registry,
        }
    }

    fn counter(&mut self, key: MetricKey, delta: u64) {
        if delta == 0 {
            return;
        }
        if !self.ensure_series(&key) {
            return;
        }
        self.registry.add_counter(&key, delta);
        match self.pending.entry(key).or_insert(PendingMetric::Counter(0)) {
            PendingMetric::Counter(value) => *value = value.saturating_add(delta),
            PendingMetric::Histogram { .. } => {
                self.overflow_dropped = self.overflow_dropped.saturating_add(1);
            }
        }
    }

    fn histogram(&mut self, key: MetricKey, seconds: f64, buckets: &[f64]) {
        if !seconds.is_finite() || seconds < 0.0 || !self.ensure_series(&key) {
            self.overflow_dropped = self.overflow_dropped.saturating_add(1);
            return;
        }
        self.registry.observe_histogram(&key, seconds, buckets);
        let entry = self
            .pending
            .entry(key)
            .or_insert_with(|| PendingMetric::Histogram {
                count: 0,
                sum: 0.0,
                cumulative_buckets: vec![0; buckets.len()],
            });
        let PendingMetric::Histogram {
            count,
            sum,
            cumulative_buckets,
        } = entry
        else {
            self.overflow_dropped = self.overflow_dropped.saturating_add(1);
            return;
        };
        *count = count.saturating_add(1);
        *sum += seconds;
        for (upper, bucket) in buckets.iter().zip(cumulative_buckets.iter_mut()) {
            if seconds <= *upper {
                *bucket = bucket.saturating_add(1);
            }
        }
    }

    fn ensure_series(&mut self, key: &MetricKey) -> bool {
        if self.pending.contains_key(key) || self.pending.len() < MAX_PENDING_SERIES {
            true
        } else {
            self.overflow_dropped = self.overflow_dropped.saturating_add(1);
            false
        }
    }

    fn observe(&mut self, observation: Observation) {
        match observation {
            Observation::GetBackend {
                duration,
                succeeded,
            } => {
                self.histogram(
                    MetricKey::new("tiproxy_backend_get_backend_duration_seconds", vec![]),
                    duration.as_secs_f64(),
                    &GET_BACKEND_BUCKETS,
                );
                self.counter(
                    MetricKey::new(
                        "tiproxy_backend_get_backend",
                        vec![("res", if succeeded { "succeed" } else { "fail" }.to_owned())],
                    ),
                    1,
                );
            }
            Observation::DialBackendFailed { backend } => self.counter(
                MetricKey::new(
                    "tiproxy_backend_dial_backend_fail",
                    vec![("backend", backend)],
                ),
                1,
            ),
            Observation::BackendKeepaliveUpdated {
                backend,
                healthy,
                succeeded,
            } => self.backend_keepalive_updated(backend, healthy, succeeded),
            Observation::HandshakeCompleted {
                backend,
                duration,
                traffic,
                local,
            } => {
                self.histogram(
                    MetricKey::new(
                        "tiproxy_session_handshake_duration_seconds",
                        vec![("backend", backend.clone())],
                    ),
                    duration.as_secs_f64(),
                    &HANDSHAKE_BUCKETS,
                );
                self.traffic(&backend, traffic, local);
            }
            Observation::CommandCompleted {
                backend,
                command,
                duration,
                since_connection,
                traffic,
                local,
            } => {
                let labels = vec![
                    ("backend", backend.clone()),
                    ("cmd_type", command.name().to_owned()),
                ];
                self.counter(
                    MetricKey::new("tiproxy_session_query_total", labels.clone()),
                    1,
                );
                self.histogram(
                    MetricKey::new("tiproxy_session_query_duration_seconds", labels),
                    duration.as_secs_f64(),
                    &QUERY_BUCKETS,
                );
                self.histogram(
                    MetricKey::new(
                        "tiproxy_session_query_time_since_conn_creation_seconds",
                        vec![],
                    ),
                    since_connection.as_secs_f64(),
                    &QUERY_AGE_BUCKETS,
                );
                self.traffic(&backend, traffic, local);
            }
            Observation::SessionClosed {
                source,
                lifetime,
                traffic: _,
            } => {
                self.counter(
                    MetricKey::new(
                        "tiproxy_server_disconnection_total",
                        vec![("type", source.metric_label().to_owned())],
                    ),
                    1,
                );
                self.histogram(
                    MetricKey::new("tiproxy_session_conn_lifetime_seconds", vec![]),
                    lifetime.as_secs_f64(),
                    &CONN_LIFETIME_BUCKETS,
                );
            }
        }
    }

    fn backend_keepalive_updated(&mut self, backend: String, healthy: bool, succeeded: bool) {
        self.counter(
            MetricKey::new(
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

    fn traffic(&mut self, backend: &str, traffic: BackendTraffic, local: bool) {
        for (name, delta) in [
            ("tiproxy_traffic_inbound_bytes", traffic.inbound_bytes),
            ("tiproxy_traffic_inbound_packets", traffic.inbound_packets),
            ("tiproxy_traffic_outbound_bytes", traffic.outbound_bytes),
            ("tiproxy_traffic_outbound_packets", traffic.outbound_packets),
        ] {
            self.counter(
                MetricKey::new(name, vec![("backend", backend.to_owned())]),
                delta,
            );
        }
        if !local {
            self.counter(
                MetricKey::new("tiproxy_traffic_cross_location_bytes", vec![]),
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
        aggregator.counter(
            MetricKey::new("tiproxy_server_create_connection_total", vec![]),
            self.registered.saturating_sub(previous.registered),
        );
        for (label, current, old) in [
            ("memory", self.rejected_memory, previous.rejected_memory),
            ("max_connections", self.rejected_max, previous.rejected_max),
        ] {
            aggregator.counter(
                MetricKey::new(
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
            aggregator.counter(
                MetricKey::new("tiproxy_server_err", vec![("type", label.to_owned())]),
                current.saturating_sub(old),
            );
        }
        aggregator.counter(
            MetricKey::new(
                "tiproxy_server_event",
                vec![("type", "rust_control_reconnect".to_owned())],
            ),
            self.reconnect_attempts
                .saturating_sub(previous.reconnect_attempts),
        );
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
    let task = tokio::spawn(run_exporter(
        client,
        serving,
        dispatch,
        observations,
        dropped,
        shutdown_rx,
        interval,
        registry,
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
                let server = serving.metrics().await;
                // Every shed observation is one external signal: the SQL-path
                // queue, the per-batch series bound, and the registry's
                // cumulative series bound all count as dropped observations.
                let (current, active_connections) = ExportTotals::sample(
                    server,
                    dropped
                        .load(Ordering::Relaxed)
                        .saturating_add(aggregator.overflow_dropped)
                        .saturating_add(registry.series_dropped()),
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

static SESSION_LOG_WRITER: std::sync::OnceLock<fn(&str)> = std::sync::OnceLock::new();

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
            aggregator.counter(
                MetricKey::new(
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
}
