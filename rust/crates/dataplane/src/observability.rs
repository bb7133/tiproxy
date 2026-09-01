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
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use control_proto::control_transport::{ControlClient, TransportError};
use control_proto::v1::control_envelope::Body;
use control_proto::v1::{ControlEnvelope, MetricDelta, MetricsBatch, Priority};
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

#[derive(Default)]
struct Aggregator {
    pending: BTreeMap<MetricKey, PendingMetric>,
    overflow_dropped: u64,
}

impl Aggregator {
    fn counter(&mut self, key: MetricKey, delta: u64) {
        if delta == 0 {
            return;
        }
        if !self.ensure_series(&key) {
            return;
        }
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
) {
    let mut ticker = tokio::time::interval(interval.max(Duration::from_millis(10)));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut aggregator = Aggregator::default();
    let mut previous = ExportTotals::default();
    let mut sequence = 1_u64;
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
                let (current, active_connections) = ExportTotals::sample(
                    server,
                    dropped.load(Ordering::Relaxed).saturating_add(aggregator.overflow_dropped),
                    &client,
                    &dispatch,
                );
                current.accumulate_delta(previous, &mut aggregator);
                previous = current;
                let metrics = aggregator.wire_metrics(&[(
                    "tiproxy_server_connections",
                    active_connections,
                )]);
                let Some(request_id) = client.allocate_request_id() else {
                    return;
                };
                let envelope = ControlEnvelope {
                    request_id,
                    priority: Priority::Bulk.into(),
                    body: Some(Body::MetricsBatch(MetricsBatch { sequence, metrics })),
                    ..ControlEnvelope::default()
                };
                match client.send(envelope).await {
                    Ok(()) => {
                        aggregator.clear_sent();
                        let Some(next) = sequence.checked_add(1) else {
                            return;
                        };
                        sequence = next;
                    }
                    Err(TransportError::MetricsDropped) => {}
                    Err(_) if client.is_shutdown() => return,
                    Err(_) => {}
                }
            }
        }
    }
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
    eprintln!(
        "{}",
        session_log_line(
            event,
            context,
            backend_id,
            backend_address,
            cluster,
            capabilities,
            source,
        )
    );
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
}
