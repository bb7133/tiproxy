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

//! Per-backend `/status` health decision (CP-TOPO #213-1, policy layer).
//!
//! This is the pure policy layer above [`ClusterHttpClient`]: it owns the retry
//! cadence, the typed JSON decode, and the exact-source authority fence, but no
//! transport. It mirrors Go `observer.DefaultHealthCheck.checkStatusPort`
//! (`pkg/balance/observer/health_check.go`):
//!
//! * a static backend (empty `ip`) is healthy this stage with no network I/O;
//! * otherwise up to `max_retries` **retries** after the initial attempt
//!   (`max_retries + 1` attempts total), a fixed `retry_interval` apart, retrying
//!   ONLY a retryable [`ClusterHttpError`] — any terminal class stops immediately
//!   as unhealthy; the retry budget is threaded in from the #213-2 policy (Go
//!   defaults: 3 retries, 1s apart);
//! * the first HTTP 200 is decoded as the typed status body (`{connections,
//!   version, git_hash}`) with Go `encoding/json` semantics (unknown ignored,
//!   missing → zero, wrong type rejects the whole record); only `version` feeds
//!   the health result, and a malformed body is terminal (the HTTP round already
//!   succeeded, so it is not retried).
//!
//! The [`GenerationGate`] alone is not identity: at each attempt admission, after
//! each backoff, and before accepting a healthy result, the probe re-validates
//! [`RoutingSnapshotHandle::still_current`] against the exact source `Arc`, so a
//! superseded or sibling source is rejected and a fence failure is terminal.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use control_external::{
    ClusterHttpClient, ClusterHttpConfigError, EtcdClientConfig, HttpProbePolicy,
};
use control_plane::OwnerToken;
use serde::Deserialize;
use serde::de::{Deserializer, IgnoredAny, MapAccess, Visitor};

use crate::merge::MergedBackend;
use crate::routing_snapshot::{RoutingSnapshot, RoutingSnapshotHandle};

/// Go `healthCheckMaxRetries`: retries AFTER the initial attempt (four attempts
/// total). The value is threaded into [`ClusterHealthNetwork::probe_backend`] by
/// the #213-2 policy; this default is retained as the tests' reference value.
#[cfg(test)]
const MAX_RETRIES: u32 = 3;
/// Go `healthCheckRetryInterval`: the fixed delay between attempts, threaded in
/// by the #213-2 policy; retained as the tests' reference value.
#[cfg(test)]
const RETRY_INTERVAL: Duration = Duration::from_secs(1);

/// The health-relevant projection of one backend, for this slice.
///
/// Only `server_version` (Go `ServerVersion`) is carried here; `connections` and
/// `git_hash` are parsed for Go typed-decode parity but do not participate in the
/// health decision and are not surfaced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackendHealth {
    /// Whether the backend passed the `/status` probe this stage.
    pub healthy: bool,
    /// The backend build version from a successful `/status` decode, if any.
    pub server_version: Option<String>,
}

impl BackendHealth {
    /// The unhealthy verdict: no version, not healthy.
    const fn unhealthy() -> Self {
        Self {
            healthy: false,
            server_version: None,
        }
    }
}

/// The typed `/status` response body. Only `version` (Go `ServerVersion`) feeds
/// the health decision; the record is decoded with a hand-written visitor that
/// reproduces Go `encoding/json` object semantics, mirroring `model.rs`.
#[derive(Default)]
struct StatusBody {
    version: String,
}

impl<'de> Deserialize<'de> for StatusBody {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct StatusBodyVisitor;

        impl<'de> Visitor<'de> for StatusBodyVisitor {
            type Value = StatusBody;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a backend /status object")
            }

            /// A top-level JSON `null` leaves the zero value, matching Go's
            /// `json.Unmarshal([]byte("null"), &struct)`.
            fn visit_unit<E>(self) -> Result<StatusBody, E>
            where
                E: serde::de::Error,
            {
                Ok(StatusBody::default())
            }

            /// Each value is read as `Option<T>` so a JSON `null` leaves the zero
            /// value (Go), a wrong type fails the whole record closed, a repeated
            /// key overwrites (last-wins), and an unknown key is ignored; tag
            /// matching is ASCII case-insensitive.
            fn visit_map<A>(self, mut map: A) -> Result<StatusBody, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut body = StatusBody::default();
                while let Some(key) = map.next_key::<String>()? {
                    if key.eq_ignore_ascii_case("version") {
                        if let Some(value) = map.next_value::<Option<String>>()? {
                            body.version = value;
                        }
                    } else if key.eq_ignore_ascii_case("connections") {
                        // Parsed only to reject a wrong-typed known member (Go).
                        let _ = map.next_value::<Option<i64>>()?;
                    } else if key.eq_ignore_ascii_case("git_hash") {
                        let _ = map.next_value::<Option<String>>()?;
                    } else {
                        let _ = map.next_value::<IgnoredAny>()?;
                    }
                }
                Ok(body)
            }
        }

        deserializer.deserialize_any(StatusBodyVisitor)
    }
}

/// Decodes the typed status body, returning the backend version. Returns `None`
/// for a malformed body or a wrong-typed known field (Go's concrete unmarshal
/// rejects the whole record), which the caller treats as terminal.
fn decode_status_version(body: &[u8]) -> Option<String> {
    let parsed: StatusBody = serde_json::from_slice(body).ok()?;
    Some(parsed.version)
}

/// One backend cluster's health-probe network: a pure policy layer wrapping the
/// cluster's owner-fenced [`ClusterHttpClient`], stamped with the discovery
/// generation and cluster it was prepared under so a probe can never use a
/// stale-epoch or sibling-cluster network's DNS/TLS material against a live
/// routing source.
pub struct ClusterHealthNetwork {
    client: ClusterHttpClient,
    /// The discovery client epoch this network's material was prepared under.
    client_epoch: u64,
    /// The backend cluster this network's DNS/TLS material belongs to.
    cluster_name: Arc<str>,
}

impl ClusterHealthNetwork {
    /// Builds the health network from one cluster's etcd client material, the
    /// process owner token, and the probe policy, stamped with the discovery
    /// `client_epoch` and `cluster_name` the material was prepared under.
    ///
    /// # Errors
    ///
    /// Returns the [`ClusterHttpConfigError`] from
    /// [`ClusterHttpClient::from_cluster_material`] (invalid policy, unbuildable
    /// resolver, or a TLS cluster whose material fails closed at construction).
    pub fn from_cluster_material(
        config: &EtcdClientConfig,
        owner: OwnerToken,
        policy: HttpProbePolicy,
        client_epoch: u64,
        cluster_name: Arc<str>,
    ) -> Result<Self, ClusterHttpConfigError> {
        Ok(Self {
            client: ClusterHttpClient::from_cluster_material(config, owner, policy)?,
            client_epoch,
            cluster_name,
        })
    }

    /// Probes one backend's `/status` port and returns its health verdict.
    ///
    /// The exact `Arc<RoutingSnapshot>` source authority is verified FIRST — before
    /// any return, including a static backend or an out-of-range port — via
    /// [`RoutingSnapshotHandle::still_current`], and the network's stamped
    /// `(client_epoch, cluster_name)` is matched against the source epoch and the
    /// `backend`'s cluster, so a superseded source, a stale-epoch network, or a
    /// sibling-cluster network is rejected before any I/O. A static backend
    /// (`ip == ""`) is then healthy with no network I/O; the `u64` status port is
    /// guarded (a value beyond `u16` is terminally unhealthy, never truncated);
    /// then up to `max_retries` retries (each `retry_interval` apart, for
    /// `max_retries + 1` attempts total) run against
    /// [`ClusterHttpClient::get_once`], retrying only a retryable
    /// [`ClusterHttpError`](control_external::ClusterHttpError). The first HTTP 200
    /// is decoded (only `version` feeds health, a malformed body terminal), with
    /// `still_current` re-checked at each attempt admission, after each backoff,
    /// and before accepting a healthy result.
    ///
    /// `max_retries` and `retry_interval` are threaded in from the #213-2
    /// [`HealthPolicy`](crate::health_loop) (Go defaults: 3 retries, 1s apart);
    /// the retry classification, the JSON decode, and the exact-source fence are
    /// unchanged by the parameterization.
    pub async fn probe_backend(
        &self,
        handle: &RoutingSnapshotHandle,
        source: &Arc<RoutingSnapshot>,
        backend: &MergedBackend,
        max_retries: u32,
        retry_interval: Duration,
    ) -> BackendHealth {
        // Exact-source authority FIRST: no return (static, mismatch, or port) may
        // precede it.
        if !handle.still_current(source) {
            return BackendHealth::unhealthy();
        }
        // Reject a network/source generation or cluster mismatch before any I/O, so
        // a stale-epoch or sibling-cluster network never probes with the wrong
        // DNS/TLS material even under a live routing source.
        if source.client_epoch != self.client_epoch
            || backend.cluster_name.as_ref() != self.cluster_name.as_ref()
        {
            return BackendHealth::unhealthy();
        }
        let ip = backend.backend.ip.as_str();
        // A static backend has no status port; it is healthy this stage.
        if ip.is_empty() {
            return BackendHealth {
                healthy: true,
                server_version: None,
            };
        }
        // Guard the u64 -> u16 port narrowing rather than silently truncating.
        let Ok(port) = u16::try_from(backend.backend.status_port) else {
            return BackendHealth::unhealthy();
        };

        let mut retries_remaining = max_retries;
        loop {
            // Exact-source authority: admit each attempt only for the live source.
            if !handle.still_current(source) {
                return BackendHealth::unhealthy();
            }
            match self.client.get_once(ip, port, source.source_gate()).await {
                Ok(body) => {
                    // The HTTP round succeeded; a decode failure is terminal.
                    let Some(version) = decode_status_version(body.as_ref()) else {
                        return BackendHealth::unhealthy();
                    };
                    // Never accept a healthy result from a superseded source.
                    if !handle.still_current(source) {
                        return BackendHealth::unhealthy();
                    }
                    return BackendHealth {
                        healthy: true,
                        server_version: Some(version),
                    };
                }
                Err(error) => {
                    // Fence-first: a stale source is terminal and wins over the
                    // I/O error class, so a retired source is never retried.
                    if !handle.still_current(source) {
                        return BackendHealth::unhealthy();
                    }
                    if error.is_retryable() && retries_remaining > 0 {
                        retries_remaining -= 1;
                        tokio::time::sleep(retry_interval).await;
                        // Re-validate the source after the backoff, before retrying.
                        if !handle.still_current(source) {
                            return BackendHealth::unhealthy();
                        }
                        continue;
                    }
                    return BackendHealth::unhealthy();
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    use control_external::{EtcdClientConfig, HttpProbePolicy};
    use control_plane::{OwnerLease, OwnerScope, OwnershipRegistry};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    use super::{
        BackendHealth, ClusterHealthNetwork, MAX_RETRIES, RETRY_INTERVAL, decode_status_version,
    };
    use crate::discovery_publish::EpochResult;
    use crate::merge::{MergedBackend, MergedTopology};
    use crate::model::BackendInfo;
    use crate::routing_snapshot::{
        RoutingSnapshot, RoutingSnapshotHandle, RoutingSnapshotPublisher,
    };

    /// The discovery epoch the published source and the happy-path network share.
    const NETWORK_EPOCH: u64 = 1;
    /// The cluster the happy-path network and its backends belong to.
    const CLUSTER: &str = "cluster-a";

    fn owner_lease() -> (OwnershipRegistry, OwnerLease) {
        let registry = OwnershipRegistry::new();
        let lease = registry
            .claim(OwnerScope::Process, "backend-health-test")
            .unwrap_or_else(|error| unreachable!("claim: {error}"));
        (registry, lease)
    }

    fn plaintext_config() -> EtcdClientConfig {
        EtcdClientConfig::new(["127.0.0.1:2379".to_owned()], None)
            .unwrap_or_else(|error| unreachable!("config: {error}"))
    }

    fn policy() -> HttpProbePolicy {
        HttpProbePolicy {
            attempt_timeout: Duration::from_secs(2),
            max_response_bytes: 64 * 1024,
        }
    }

    /// A network stamped with the happy-path epoch and cluster (both matching the
    /// `published_source` generation).
    fn network(lease: &OwnerLease) -> ClusterHealthNetwork {
        network_stamped(lease, NETWORK_EPOCH, CLUSTER)
    }

    /// A network stamped with an explicit discovery epoch and cluster.
    fn network_stamped(lease: &OwnerLease, epoch: u64, cluster: &str) -> ClusterHealthNetwork {
        ClusterHealthNetwork::from_cluster_material(
            &plaintext_config(),
            lease.token(),
            policy(),
            epoch,
            Arc::from(cluster),
        )
        .unwrap_or_else(|error| unreachable!("network: {error}"))
    }

    /// Builds one merged backend under `cluster` with the given status endpoint.
    fn merged_backend(cluster: &str, ip: &str, status_port: u64) -> MergedBackend {
        MergedBackend {
            backend_id: Arc::from(format!("{cluster}/{ip}:{status_port}").as_str()),
            cluster_name: Arc::from(cluster),
            backend: BackendInfo {
                addr: format!("{ip}:{status_port}"),
                keyspace: String::new(),
                ip: ip.to_owned(),
                status_port,
                version: String::new(),
                git_hash: String::new(),
                deploy_path: String::new(),
                start_timestamp: 0,
                labels: BTreeMap::new(),
            },
        }
    }

    /// Publishes one empty-topology generation at [`NETWORK_EPOCH`] and returns the
    /// publisher (held so its `Drop` does not revoke the gate), its handle, and the
    /// live source `Arc`.
    fn published_source() -> (
        RoutingSnapshotPublisher,
        RoutingSnapshotHandle,
        Arc<RoutingSnapshot>,
    ) {
        let (publisher, handle) = RoutingSnapshotPublisher::new();
        publisher
            .publish(EpochResult {
                client_epoch: NETWORK_EPOCH,
                value: MergedTopology::default(),
            })
            .unwrap_or_else(|_| unreachable!("first publish"));
        let source = handle
            .current()
            .unwrap_or_else(|| unreachable!("a snapshot is published"));
        (publisher, handle, source)
    }

    /// The scripted behavior of the loopback status server per connection index.
    #[derive(Clone)]
    enum Behavior {
        /// Always answer `200 OK` with the given body.
        Ok200(Vec<u8>),
        /// Always answer a bare status line.
        Status(u16),
        /// Accept then close immediately (a retryable transport failure).
        CloseImmediately,
        /// Close for the first `fail` connections, then answer `200` with `body`.
        FailThenOk { fail: usize, body: Vec<u8> },
    }

    async fn read_head(stream: &mut TcpStream) {
        let mut buffer = Vec::new();
        let mut chunk = [0u8; 256];
        loop {
            match stream.read(&mut chunk).await {
                Ok(0) | Err(_) => break,
                Ok(n) => buffer.extend_from_slice(&chunk[..n]),
            }
            if buffer.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
    }

    async fn answer(stream: &mut TcpStream, response: &[u8]) {
        read_head(stream).await;
        let _ = stream.write_all(response).await;
        let _ = stream.flush().await;
    }

    fn ok200(body: &[u8]) -> Vec<u8> {
        let mut out = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        out.extend_from_slice(body);
        out
    }

    /// Probes a `CLUSTER` backend at `ip:status_port` under the given source.
    async fn probe(
        network: &ClusterHealthNetwork,
        handle: &RoutingSnapshotHandle,
        source: &Arc<RoutingSnapshot>,
        ip: &str,
        status_port: u64,
    ) -> BackendHealth {
        network
            .probe_backend(
                handle,
                source,
                &merged_backend(CLUSTER, ip, status_port),
                MAX_RETRIES,
                RETRY_INTERVAL,
            )
            .await
    }

    // ====================================================================
    // Static backend and port guard (test 9).
    // ====================================================================

    #[tokio::test]
    async fn a_static_backend_is_healthy_without_io() {
        let (_registry, lease) = owner_lease();
        let network = network(&lease);
        let (_publisher, handle, source) = published_source();
        let health = probe(&network, &handle, &source, "", 0).await;
        assert_eq!(
            health,
            BackendHealth {
                healthy: true,
                server_version: None
            },
            "a static backend (empty ip) is healthy with no network I/O"
        );
    }

    #[tokio::test]
    async fn a_status_port_beyond_u16_is_terminally_unhealthy() {
        let (_registry, lease) = owner_lease();
        let network = network(&lease);
        let (_publisher, handle, source) = published_source();
        let health = probe(&network, &handle, &source, "127.0.0.1", 70_000).await;
        assert!(
            !health.healthy,
            "a status port beyond u16 is unhealthy, never truncated"
        );
    }

    // ====================================================================
    // Successful probe and typed decode.
    // ====================================================================

    #[tokio::test]
    async fn a_successful_probe_reports_the_backend_version() {
        let (_registry, lease) = owner_lease();
        let network = network(&lease);
        let (_publisher, handle, source) = published_source();
        let (port, _accepted) = bind_counting_server(Behavior::Ok200(
            br#"{"connections":5,"version":"v8.1.0","git_hash":"abc"}"#.to_vec(),
        ))
        .await;
        let health = probe(&network, &handle, &source, "127.0.0.1", u64::from(port)).await;
        assert_eq!(
            health,
            BackendHealth {
                healthy: true,
                server_version: Some("v8.1.0".to_owned())
            }
        );
    }

    // ====================================================================
    // Classification: terminal errors do not retry (test 7).
    // ====================================================================

    #[tokio::test]
    async fn a_non_200_status_is_terminal_and_not_retried() {
        let (_registry, lease) = owner_lease();
        let network = network(&lease);
        let (_publisher, handle, source) = published_source();
        let (port, accepted) = bind_counting_server(Behavior::Status(503)).await;
        let health = probe(&network, &handle, &source, "127.0.0.1", u64::from(port)).await;
        assert!(!health.healthy, "a non-200 status is unhealthy");
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            1,
            "a terminal non-200 is not retried"
        );
    }

    #[tokio::test]
    async fn a_malformed_body_is_terminal_and_not_retried() {
        let (_registry, lease) = owner_lease();
        let network = network(&lease);
        let (_publisher, handle, source) = published_source();
        let (port, accepted) =
            bind_counting_server(Behavior::Ok200(b"{not valid json".to_vec())).await;
        let health = probe(&network, &handle, &source, "127.0.0.1", u64::from(port)).await;
        assert!(!health.healthy, "a malformed body is unhealthy");
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            1,
            "a malformed body after a 200 is terminal (the HTTP round succeeded)"
        );
    }

    #[tokio::test]
    async fn a_wrong_typed_status_field_is_terminal() {
        let (_registry, lease) = owner_lease();
        let network = network(&lease);
        let (_publisher, handle, source) = published_source();
        // `connections` is a string: Go's typed unmarshal rejects the whole record.
        let (port, accepted) =
            bind_counting_server(Behavior::Ok200(br#"{"connections":"nope"}"#.to_vec())).await;
        let health = probe(&network, &handle, &source, "127.0.0.1", u64::from(port)).await;
        assert!(
            !health.healthy,
            "a wrong-typed known field rejects the record"
        );
        assert_eq!(accepted.load(Ordering::SeqCst), 1, "not retried");
    }

    #[tokio::test]
    async fn connection_refused_is_terminal_without_backoff() {
        let (_registry, lease) = owner_lease();
        let network = network(&lease);
        let (_publisher, handle, source) = published_source();
        // Bind then drop a port so it reliably refuses.
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|error| unreachable!("bind: {error}"));
        let port = listener
            .local_addr()
            .unwrap_or_else(|error| unreachable!("addr: {error}"))
            .port();
        drop(listener);
        let started = Instant::now();
        let health = probe(&network, &handle, &source, "127.0.0.1", u64::from(port)).await;
        let elapsed = started.elapsed();
        assert!(!health.healthy, "a refused dial is unhealthy");
        assert!(
            elapsed < Duration::from_millis(900),
            "connection-refused is terminal, so no 1s backoff ran (took {elapsed:?})"
        );
    }

    // ====================================================================
    // Retry cadence (test 7).
    // ====================================================================

    #[tokio::test]
    async fn a_retryable_failure_retries_at_most_four_attempts() {
        let (_registry, lease) = owner_lease();
        let network = network(&lease);
        let (_publisher, handle, source) = published_source();
        let (port, accepted) = bind_counting_server(Behavior::CloseImmediately).await;
        let health = probe(&network, &handle, &source, "127.0.0.1", u64::from(port)).await;
        assert!(
            !health.healthy,
            "an exhausted retryable failure is unhealthy"
        );
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            usize::try_from(MAX_RETRIES).unwrap_or(usize::MAX) + 1,
            "an always-failing retryable probe makes exactly four attempts (1 + 3 retries)"
        );
    }

    #[tokio::test]
    async fn a_retryable_failure_recovers_on_a_later_attempt() {
        let (_registry, lease) = owner_lease();
        let network = network(&lease);
        let (_publisher, handle, source) = published_source();
        // Fail the first two attempts, then answer 200 on the third.
        let (port, accepted) = bind_counting_server(Behavior::FailThenOk {
            fail: 2,
            body: br#"{"version":"v9"}"#.to_vec(),
        })
        .await;
        let health = probe(&network, &handle, &source, "127.0.0.1", u64::from(port)).await;
        assert_eq!(
            health,
            BackendHealth {
                healthy: true,
                server_version: Some("v9".to_owned())
            },
            "the probe recovers on the third attempt"
        );
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            3,
            "it stopped retrying as soon as an attempt succeeded"
        );
    }

    // ====================================================================
    // Exact-source authority (test 8).
    // ====================================================================

    #[tokio::test]
    async fn a_superseded_source_aborts_before_any_io() {
        let (_registry, lease) = owner_lease();
        let network = network(&lease);
        let (publisher, handle, source) = published_source();
        let (port, accepted) =
            bind_counting_server(Behavior::Ok200(br#"{"version":"v8"}"#.to_vec())).await;
        // Publish a newer generation: the captured source is now superseded.
        publisher
            .publish(EpochResult {
                client_epoch: 2,
                value: MergedTopology::default(),
            })
            .unwrap_or_else(|_| unreachable!("second publish"));
        let health = probe(&network, &handle, &source, "127.0.0.1", u64::from(port)).await;
        assert!(
            !health.healthy,
            "a superseded source never yields a healthy result"
        );
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            0,
            "a stale source aborts admission before any dial"
        );
    }

    #[tokio::test]
    async fn a_sibling_source_arc_is_rejected_even_with_a_live_gate() {
        let (_registry, lease) = owner_lease();
        let network = network(&lease);
        // Handle A and a sibling publisher B, both with a live snapshot.
        let (_publisher_a, handle_a, _source_a) = published_source();
        let (_publisher_b, _handle_b, source_b) = published_source();
        let (port, accepted) =
            bind_counting_server(Behavior::Ok200(br#"{"version":"v8"}"#.to_vec())).await;
        // Probe handle A with B's live-gated snapshot: identity must be rejected.
        let health = probe(&network, &handle_a, &source_b, "127.0.0.1", u64::from(port)).await;
        assert!(
            !health.healthy,
            "a sibling publisher's snapshot is not this source's authority"
        );
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            0,
            "a wrong-candidate Arc aborts before any dial, even with a live gate"
        );
    }

    // ====================================================================
    // Fix 3: Go encoding/json parity of the typed decode.
    // ====================================================================

    #[test]
    fn decode_status_version_matches_go_encoding_json() {
        // A top-level null yields the zero struct (version ""), like
        // `json.Unmarshal([]byte("null"), &struct)`.
        assert_eq!(decode_status_version(b"null"), Some(String::new()));
        // A null field leaves the zero value.
        assert_eq!(
            decode_status_version(br#"{"version":null}"#),
            Some(String::new())
        );
        // Field tags match ASCII case-insensitively.
        assert_eq!(
            decode_status_version(br#"{"VERSION":"v-case"}"#),
            Some("v-case".to_owned())
        );
        // A duplicate member keeps the last value.
        assert_eq!(
            decode_status_version(br#"{"version":"old","version":"new"}"#),
            Some("new".to_owned())
        );
        // A missing version is the zero value; an unknown field is ignored.
        assert_eq!(
            decode_status_version(br#"{"connections":5,"unknown":true}"#),
            Some(String::new())
        );

        // A wrong-typed known field rejects the whole record (terminal → None).
        assert_eq!(decode_status_version(br#"{"version":5}"#), None);
        assert_eq!(decode_status_version(br#"{"connections":"nope"}"#), None);
        // A non-object, non-null top level (number, string) is rejected.
        assert_eq!(decode_status_version(b"7"), None);
        assert_eq!(decode_status_version(br#""x""#), None);
        // Malformed JSON is rejected.
        assert_eq!(decode_status_version(b"{not json"), None);
    }

    // ====================================================================
    // Fix 4: source admission precedes the static/port shortcut.
    // ====================================================================

    #[tokio::test]
    async fn a_non_current_source_with_a_static_backend_is_unhealthy() {
        let (_registry, lease) = owner_lease();
        let network = network(&lease);
        // Two sibling publishers at the SAME epoch: handle A and B's snapshot both
        // carry NETWORK_EPOCH with a live gate, so the epoch/cluster stamp checks
        // pass and only the `still_current` identity check can reject B under A.
        let (_publisher_a, handle_a, _source_a) = published_source();
        let (_publisher_b, _handle_b, source_b) = published_source();
        // A static (empty-ip) backend would be a healthy no-I/O shortcut, but the
        // exact-source authority (`still_current`) runs FIRST, so a non-current
        // source is unhealthy — proving admission precedes the static shortcut.
        let health = probe(&network, &handle_a, &source_b, "", 0).await;
        assert!(
            !health.healthy,
            "a non-current source is unhealthy even for a static backend"
        );
    }

    // ====================================================================
    // Fix 5: epoch/cluster stamp rejects a mismatched network before any I/O.
    // ====================================================================

    #[tokio::test]
    async fn a_stale_epoch_network_rejects_before_any_io() {
        let (_registry, lease) = owner_lease();
        // The live source is at NETWORK_EPOCH; this network is stamped one epoch
        // behind, so its DNS/TLS material must never probe the live source.
        let network = network_stamped(&lease, NETWORK_EPOCH + 1, CLUSTER);
        let (_publisher, handle, source) = published_source();
        let (port, accepted) =
            bind_counting_server(Behavior::Ok200(br#"{"version":"v8"}"#.to_vec())).await;
        let health = probe(&network, &handle, &source, "127.0.0.1", u64::from(port)).await;
        assert!(
            !health.healthy,
            "a network whose epoch differs from the source epoch is unhealthy"
        );
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            0,
            "an epoch mismatch aborts before any dial"
        );
    }

    #[tokio::test]
    async fn a_sibling_cluster_backend_is_rejected_before_any_io() {
        let (_registry, lease) = owner_lease();
        let network = network(&lease); // stamped CLUSTER
        let (_publisher, handle, source) = published_source();
        let (port, accepted) =
            bind_counting_server(Behavior::Ok200(br#"{"version":"v8"}"#.to_vec())).await;
        // A backend from a DIFFERENT cluster than the network's stamp: the wrong
        // DNS/TLS material must never be used against it.
        let backend = merged_backend("cluster-b", "127.0.0.1", u64::from(port));
        let health = network
            .probe_backend(&handle, &source, &backend, MAX_RETRIES, RETRY_INTERVAL)
            .await;
        assert!(
            !health.healthy,
            "a sibling-cluster backend is rejected by the cluster stamp"
        );
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            0,
            "a cluster mismatch aborts before any dial"
        );
    }

    #[tokio::test]
    async fn a_source_superseded_mid_probe_stops_further_retries() {
        let (_registry, lease) = owner_lease();
        let network = Arc::new(network(&lease));
        let (publisher, handle, source) = published_source();
        // A server that counts accepts and signals on the first, always closing
        // immediately (a retryable failure that would otherwise be retried).
        let accepted = Arc::new(AtomicUsize::new(0));
        let first_accept = Arc::new(tokio::sync::Notify::new());
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|error| unreachable!("bind: {error}"));
        let port = listener
            .local_addr()
            .unwrap_or_else(|error| unreachable!("addr: {error}"))
            .port();
        tokio::spawn(serve_close_signalling(
            listener,
            Arc::clone(&accepted),
            Arc::clone(&first_accept),
        ));

        let net = Arc::clone(&network);
        let handle_task = handle.clone();
        let source_task = Arc::clone(&source);
        let task = tokio::spawn(async move {
            net.probe_backend(
                &handle_task,
                &source_task,
                &merged_backend(CLUSTER, "127.0.0.1", u64::from(port)),
                MAX_RETRIES,
                RETRY_INTERVAL,
            )
            .await
        });

        // After the first attempt has dialed, supersede the source; the probe's
        // fence-first / post-backoff `still_current` re-checks must abort it with
        // no further retry attempt.
        first_accept.notified().await;
        publisher
            .publish(EpochResult {
                client_epoch: NETWORK_EPOCH + 1,
                value: MergedTopology::default(),
            })
            .unwrap_or_else(|_| unreachable!("supersede publish"));

        let health = task
            .await
            .unwrap_or_else(|error| unreachable!("probe task: {error}"));
        assert!(
            !health.healthy,
            "a source superseded mid-probe never yields a healthy result"
        );
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            1,
            "the probe made exactly one attempt and did not retry after the revoke"
        );
    }

    // --- server-binding helpers used by the tests above ------------------

    /// Accepts repeatedly, counting each and signalling on the first, closing every
    /// connection immediately (a retryable transport failure).
    async fn serve_close_signalling(
        listener: TcpListener,
        accepted: Arc<AtomicUsize>,
        first_accept: Arc<tokio::sync::Notify>,
    ) {
        loop {
            let Ok((stream, _peer)) = listener.accept().await else {
                return;
            };
            if accepted.fetch_add(1, Ordering::SeqCst) == 0 {
                first_accept.notify_one();
            }
            drop(stream);
        }
    }

    /// Binds a counting status server and returns its port and accept counter.
    async fn bind_counting_server(behavior: Behavior) -> (u16, Arc<AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|error| unreachable!("bind: {error}"));
        let port = listener
            .local_addr()
            .unwrap_or_else(|error| unreachable!("addr: {error}"))
            .port();
        let accepted = Arc::new(AtomicUsize::new(0));
        let accepted_task = Arc::clone(&accepted);
        tokio::spawn(serve_counting(listener, behavior, accepted_task));
        (port, accepted)
    }

    async fn serve_counting(listener: TcpListener, behavior: Behavior, accepted: Arc<AtomicUsize>) {
        loop {
            let Ok((mut stream, _peer)) = listener.accept().await else {
                return;
            };
            let index = accepted.fetch_add(1, Ordering::SeqCst);
            let behavior = behavior.clone();
            tokio::spawn(async move {
                match behavior {
                    Behavior::Ok200(body) => answer(&mut stream, &ok200(&body)).await,
                    Behavior::Status(code) => {
                        let response = format!(
                            "HTTP/1.1 {code} STATUS\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        );
                        answer(&mut stream, response.as_bytes()).await;
                    }
                    Behavior::CloseImmediately => drop(stream),
                    Behavior::FailThenOk { fail, body } => {
                        if index < fail {
                            drop(stream);
                        } else {
                            answer(&mut stream, &ok200(&body)).await;
                        }
                    }
                }
            });
        }
    }
}
