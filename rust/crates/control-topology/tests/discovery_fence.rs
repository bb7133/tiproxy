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

//! Live gated-fence coverage for the discovery poll's two mid-poll fences.
//!
//! These drive a REAL [`control_topology::TopologyModule`] whose discovery
//! connection points at an in-process etcd v3 `KV.Range` fixture that can STALL a
//! chosen prefix read, signal the test, and count Range calls per prefix. While a
//! poll is parked inside its first Range, the test forces a material rotation (a
//! new config generation with a different client timeout), which revokes the old
//! epoch's [`control_external::GenerationGate`]. Releasing the stall then proves
//! the two fences the CP-TOPO review found were untested:
//!
//! 1. the per-connection gate fence ([`EtcdConnection::is_current`] folding the
//!    generation gate into its owner check): a revoked gate aborts the in-flight
//!    poll at its NEXT `execute`, so no further prefix Range or Prometheus retry
//!    is issued; and
//! 2. the handle's final `still_current` fence: every poll outcome under a rotated
//!    epoch surfaces as [`DiscoveryError::Stale`], never a stale value or a stale
//!    transport error.
//!
//! The fixture is the same hand-rolled single-route tonic adapter used by
//! `tests/prometheus_etcd.rs` (no `etcd-client` `build-server`); only the stall
//! and per-prefix counters are added.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use control_config::{ConfigNamespaceSource, ConfigNamespaceStore, TopologyRuntimeIdentity};
use control_external::EtcdClientConfig;
use control_plane::{
    ControlConfig, ControlModule, ControlRuntime, EventSink, LogLevel, MetricsPolicy,
    OwnershipRegistry, RuntimeEvent, TlsPolicy,
};
use control_topology::{
    DiscoveryError, StaticAdvertiseResolver, TopologyClientFactory, TopologyClusterClient,
    TopologyModule, TopologyModuleHandle, TopologyStatus,
};
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::service::TowerToHyperService;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Notify, watch};
use tonic::codegen::{BoxFuture, Context, Poll, Service, http};
use tonic::server::{Grpc, NamedService, UnaryService};
use tonic_prost::ProstCodec;

/// The etcd v3 `Range` unary gRPC method path the pinned client calls.
const RANGE_PATH: &str = "/etcdserverpb.KV/Range";
/// The gRPC service name the pinned client routes against.
const KV_SERVICE_NAME: &str = "etcdserverpb.KV";
/// The single backend cluster name shared by the config and the polls.
const CLUSTER_NAME: &str = "cluster-a";
/// The classic `TiDB` topology prefix `poll_tidb_topology` reads first.
const TIDB_PREFIX: &[u8] = b"/topology/tidb/";
/// The keyspace `TiDB` topology prefix `poll_tidb_topology` reads second.
const KEYSPACE_PREFIX: &[u8] = b"/keyspaces/tidb/";
/// The Prometheus prefix `poll_prometheus` reads.
const PROM_PREFIX: &[u8] = b"/topology/prometheus";

// ----- Wire-compatible etcd v3 messages (etcd 0.20.0 field tags) --------

#[derive(Clone, PartialEq, ::prost::Message)]
struct RangeRequest {
    #[prost(bytes = "vec", tag = "1")]
    key: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    range_end: Vec<u8>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
struct ResponseHeader {
    #[prost(uint64, tag = "1")]
    cluster_id: u64,
    #[prost(uint64, tag = "2")]
    member_id: u64,
    #[prost(int64, tag = "3")]
    revision: i64,
    #[prost(uint64, tag = "4")]
    raft_term: u64,
}

#[derive(Clone, PartialEq, ::prost::Message)]
struct KeyValue {
    #[prost(bytes = "vec", tag = "1")]
    key: Vec<u8>,
    #[prost(int64, tag = "2")]
    create_revision: i64,
    #[prost(int64, tag = "3")]
    mod_revision: i64,
    #[prost(int64, tag = "4")]
    version: i64,
    #[prost(bytes = "vec", tag = "5")]
    value: Vec<u8>,
    #[prost(int64, tag = "6")]
    lease: i64,
}

#[derive(Clone, PartialEq, ::prost::Message)]
struct RangeResponse {
    #[prost(message, optional, tag = "1")]
    header: Option<ResponseHeader>,
    #[prost(message, repeated, tag = "2")]
    kvs: Vec<KeyValue>,
    #[prost(bool, tag = "3")]
    more: bool,
    #[prost(int64, tag = "4")]
    count: i64,
}

// ----- The gated, per-prefix-counting KV.Range fixture ------------------

/// The stall coordination for one chosen prefix: it parks the FIRST matching
/// Range, signals the test it arrived, and waits for release. When
/// `error_after_release` is set it then answers a gRPC error (so, absent the
/// gate fence, the caller's retry issues another Range — the exact behaviour the
/// Prometheus fence must suppress).
#[derive(Clone)]
struct StallControl {
    prefix: Vec<u8>,
    arrived: Arc<Notify>,
    release: Arc<Notify>,
    stalled: Arc<AtomicBool>,
    error_after_release: bool,
}

/// Shared fixture state: the seeded key/value pairs, the observed Range keys (so
/// the test can count per prefix), and the optional stall control.
#[derive(Clone)]
struct KvFixture {
    seeded: Arc<Vec<(Vec<u8>, Vec<u8>)>>,
    observed: Arc<Mutex<Vec<Vec<u8>>>>,
    stall: Option<StallControl>,
}

/// Real etcd `Range` semantics: an empty `range_end` is an exact get, otherwise a
/// half-open range `key <= k < range_end`, returned ascending by key.
fn range_scan(
    seeded: &[(Vec<u8>, Vec<u8>)],
    key: &[u8],
    range_end: &[u8],
) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut hits: Vec<(Vec<u8>, Vec<u8>)> = seeded
        .iter()
        .filter(|(k, _)| {
            if range_end.is_empty() {
                k.as_slice() == key
            } else {
                k.as_slice() >= key && k.as_slice() < range_end
            }
        })
        .cloned()
        .collect();
    hits.sort_by(|(a, _), (b, _)| a.cmp(b));
    hits
}

struct RangeHandler {
    fixture: KvFixture,
}

impl UnaryService<RangeRequest> for RangeHandler {
    type Response = RangeResponse;
    type Future = BoxFuture<tonic::Response<RangeResponse>, tonic::Status>;

    fn call(&mut self, request: tonic::Request<RangeRequest>) -> Self::Future {
        let fixture = self.fixture.clone();
        Box::pin(async move {
            let message = request.into_inner();
            fixture
                .observed
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(message.key.clone());

            // Park the first Range for the chosen prefix, then (optionally) fail it
            // so a caller without the gate fence would retry.
            if let Some(stall) = &fixture.stall
                && message.key == stall.prefix
                && !stall.stalled.swap(true, Ordering::SeqCst)
            {
                stall.arrived.notify_one();
                stall.release.notified().await;
                if stall.error_after_release {
                    return Err(tonic::Status::internal("injected fence error"));
                }
            }

            let matches = range_scan(&fixture.seeded, &message.key, &message.range_end);
            let count = i64::try_from(matches.len()).unwrap_or(i64::MAX);
            let kvs = matches
                .into_iter()
                .map(|(key, value)| KeyValue {
                    key,
                    value,
                    ..KeyValue::default()
                })
                .collect();
            let header = ResponseHeader {
                cluster_id: 7,
                member_id: 11,
                revision: 42,
                raft_term: 3,
            };
            Ok(tonic::Response::new(RangeResponse {
                header: Some(header),
                kvs,
                more: false,
                count,
            }))
        })
    }
}

impl Service<http::Request<Incoming>> for KvFixture {
    type Response = http::Response<tonic::body::Body>;
    type Error = Infallible;
    type Future = BoxFuture<Self::Response, Infallible>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: http::Request<Incoming>) -> Self::Future {
        let fixture = self.clone();
        Box::pin(async move {
            let response = if request.uri().path() == RANGE_PATH {
                let mut grpc = Grpc::new(ProstCodec::<RangeResponse, RangeRequest>::default());
                grpc.unary(RangeHandler { fixture }, request).await
            } else {
                // The registrar's lease Grant/Put land here and retry harmlessly.
                unimplemented_reply()
            };
            Ok(response)
        })
    }
}

impl NamedService for KvFixture {
    const NAME: &'static str = KV_SERVICE_NAME;
}

fn unimplemented_reply() -> http::Response<tonic::body::Body> {
    let mut response = http::Response::new(tonic::body::Body::default());
    let headers = response.headers_mut();
    headers.insert(
        tonic::Status::GRPC_STATUS,
        http::HeaderValue::from_static("12"),
    );
    headers.insert(
        http::header::CONTENT_TYPE,
        tonic::metadata::GRPC_CONTENT_TYPE,
    );
    response
}

/// A running fixture: its bound address, the observed Range keys, and the stall
/// coordination handles (arrival + release) when a prefix is gated.
struct Fixture {
    addr: SocketAddr,
    observed: Arc<Mutex<Vec<Vec<u8>>>>,
    arrived: Arc<Notify>,
    release: Arc<Notify>,
}

impl Fixture {
    /// How many Range requests were observed for exactly `prefix`.
    fn range_count(&self, prefix: &[u8]) -> usize {
        self.observed
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .filter(|key| key.as_slice() == prefix)
            .count()
    }
}

/// Binds a loopback listener and serves the gated KV adapter over each accepted
/// plaintext connection. The accept loop is detached; the test process bounds its
/// lifetime.
async fn spawn_fixture(
    seeded: Vec<(Vec<u8>, Vec<u8>)>,
    stall_prefix: &[u8],
    error_after_release: bool,
) -> Option<Fixture> {
    let observed = Arc::new(Mutex::new(Vec::new()));
    let arrived = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let fixture = KvFixture {
        seeded: Arc::new(seeded),
        observed: Arc::clone(&observed),
        stall: Some(StallControl {
            prefix: stall_prefix.to_vec(),
            arrived: Arc::clone(&arrived),
            release: Arc::clone(&release),
            stalled: Arc::new(AtomicBool::new(false)),
            error_after_release,
        }),
    };
    let listener = TcpListener::bind("127.0.0.1:0").await.ok()?;
    let addr = listener.local_addr().ok()?;
    tokio::spawn(async move {
        loop {
            let Ok((stream, _peer)) = listener.accept().await else {
                return;
            };
            tokio::spawn(serve_connection(stream, fixture.clone()));
        }
    });
    Some(Fixture {
        addr,
        observed,
        arrived,
        release,
    })
}

async fn serve_connection(stream: TcpStream, fixture: KvFixture) {
    let service = TowerToHyperService::new(fixture);
    let builder = hyper::server::conn::http2::Builder::new(TokioExecutor::new());
    let _ = builder
        .serve_connection(TokioIo::new(stream), service)
        .await;
}

// ----- Module wiring ----------------------------------------------------

/// A factory that builds one plaintext cluster client pointed at the fixture,
/// with a request timeout read from a shared atomic. Flipping the atomic before a
/// new config generation changes the cluster MATERIAL, forcing a discovery
/// rotation that revokes the previous epoch's gate.
struct FixtureFactory {
    addr: SocketAddr,
    timeout_ms: Arc<AtomicU64>,
}

impl TopologyClientFactory for FixtureFactory {
    fn build(
        &self,
        snapshot: &control_config::ConfigNamespaceSnapshot,
    ) -> Result<Vec<TopologyClusterClient>, String> {
        let topology = snapshot
            .topology()
            .map_err(|_| "topology projection".to_owned())?;
        let timeout = Duration::from_millis(self.timeout_ms.load(Ordering::SeqCst));
        let mut clusters = Vec::with_capacity(topology.backend_clusters.len());
        for cluster in topology.backend_clusters.iter() {
            let client = EtcdClientConfig::new(vec![self.addr.to_string()], None)
                .and_then(|config| {
                    config.with_timeouts(
                        Duration::from_secs(1),
                        timeout,
                        Duration::from_secs(1),
                        Duration::from_millis(500),
                        Duration::from_secs(1),
                    )
                })
                .map_err(|_| "client build".to_owned())?;
            clusters.push(TopologyClusterClient {
                cluster_name: Arc::clone(&cluster.name),
                client,
            });
        }
        Ok(clusters)
    }
}

struct NullSink;
impl EventSink for NullSink {
    fn record(&self, _event: &RuntimeEvent) {}
}

fn identity() -> TopologyRuntimeIdentity {
    TopologyRuntimeIdentity {
        version: Arc::from("v-test"),
        git_hash: Arc::from("hash-test"),
        deploy_path: std::path::PathBuf::from("/deploy/test"),
        start_timestamp: 1_700_000_000,
    }
}

/// A one-cluster config whose `max-connections` is hot-reloadable, so a new
/// generation can be published without touching a reload-locked field.
fn config(max_connections: u64) -> Vec<u8> {
    format!(
        "\n[proxy]\naddr = \"0.0.0.0:6000\"\nmax-connections = {max_connections}\n\n[api]\naddr = \"0.0.0.0:10080\"\n\n[[proxy.backend-clusters]]\nname = \"{CLUSTER_NAME}\"\npd-addrs = \"pd-a:2379\"\nns-servers = []\n"
    )
    .into_bytes()
}

/// Waits until the observed generation reaches `generation`, bounded.
async fn wait_observed(status: &mut watch::Receiver<TopologyStatus>, generation: u64) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if status.borrow_and_update().observed_generation >= generation {
            return;
        }
        let remaining = deadline - tokio::time::Instant::now();
        if tokio::time::timeout(remaining, status.changed())
            .await
            .is_err()
        {
            unreachable!("the module observed generation {generation} within the deadline");
        }
    }
}

/// A live module + its handle, its config store, the shared timeout atomic, and a
/// leaked runtime kept current for the connections' lifetime.
struct Harness {
    handle: TopologyModuleHandle,
    task: tokio::task::JoinHandle<Result<(), control_plane::ModuleError>>,
    store: ConfigNamespaceStore,
    timeout_ms: Arc<AtomicU64>,
    _runtime: &'static ControlRuntime,
}

/// Builds and spawns a real `TopologyModule` (real connector + real registrar)
/// whose one cluster points at `addr`, and waits for it to become ready.
async fn spawn_module(addr: SocketAddr) -> Option<Harness> {
    let store =
        ConfigNamespaceStore::from_toml(&config(100), None, &std::env::current_dir().ok()?).ok()?;
    let timeout_ms = Arc::new(AtomicU64::new(500));
    let source: Arc<dyn ConfigNamespaceSource> = Arc::new(store.clone());
    let (module, mut handle) = TopologyModule::new(
        source,
        Box::new(FixtureFactory {
            addr,
            timeout_ms: Arc::clone(&timeout_ms),
        }),
        Arc::new(StaticAdvertiseResolver::new("10.0.0.1")),
        identity(),
    );
    let registry = Box::leak(Box::new(OwnershipRegistry::new()));
    let config = ControlConfig::new(
        1,
        Duration::from_secs(30),
        0,
        TlsPolicy::default(),
        LogLevel::Info,
        MetricsPolicy::default(),
    )
    .ok()?;
    let runtime: &'static ControlRuntime = Box::leak(Box::new(
        ControlRuntime::claim_process(registry, "cptopo-fence-test", config, Arc::new(NullSink))
            .ok()?,
    ));
    let context = runtime.handle().module_context();
    runtime.mark_ready().ok()?;
    let task = tokio::spawn(Box::new(module).run(context));
    tokio::time::timeout(Duration::from_secs(5), handle.wait_ready())
        .await
        .ok()?
        .ok()?;
    Some(Harness {
        handle,
        task,
        store,
        timeout_ms,
        _runtime: runtime,
    })
}

/// Forces a material rotation (a new client timeout in a new generation) and
/// waits for it to be applied, so the previous epoch's gate is revoked.
async fn rotate_material(harness: &Harness) {
    let mut status = harness.handle.status();
    harness.timeout_ms.store(700, Ordering::SeqCst);
    let cwd = std::env::current_dir().unwrap_or_else(|error| unreachable!("cwd: {error}"));
    harness
        .store
        .apply_toml(&config(200), None, 2, &cwd)
        .unwrap_or_else(|error| unreachable!("apply generation 2: {error}"));
    wait_observed(&mut status, 2).await;
    // The applied generation advancing to 2 means the discovery commit ran and the
    // old epoch's gate was revoked.
    assert_eq!(
        status.borrow().applied_generation,
        2,
        "the material rotation was applied (old gate revoked)"
    );
}

// ----- 1 — TiDB mid-poll gate + still_current fence ---------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tidb_poll_revoked_mid_read_aborts_before_the_second_prefix_and_is_stale() {
    let body = async {
        // One live TiDB backend under the classic prefix; the keyspace prefix has
        // nothing. The poll reads the classic prefix first (where we stall).
        let seeded = vec![
            (
                b"/topology/tidb/10.0.0.9:4000/info".to_vec(),
                br#"{"ip":"10.0.0.9","status_port":10080,"version":"v8"}"#.to_vec(),
            ),
            (b"/topology/tidb/10.0.0.9:4000/ttl".to_vec(), b"1".to_vec()),
        ];
        let Some(fixture) = spawn_fixture(seeded, TIDB_PREFIX, false).await else {
            unreachable!("the fixture binds a loopback port");
        };
        let Some(harness) = spawn_module(fixture.addr).await else {
            unreachable!("the module becomes ready against the fixture");
        };
        let discovery = harness.handle.discovery_handle();

        // Park a merged poll inside its first (classic) TiDB Range.
        let poll = tokio::spawn(async move { discovery.poll_merged_topology().await });
        fixture.arrived.notified().await;
        assert_eq!(
            fixture.range_count(TIDB_PREFIX),
            1,
            "the poll issued exactly the first (classic) TiDB Range"
        );
        assert_eq!(
            fixture.range_count(KEYSPACE_PREFIX),
            0,
            "the second prefix has not been read yet"
        );

        // Rotate the material mid-poll, revoking the parked epoch's gate, then
        // release the stall.
        rotate_material(&harness).await;
        fixture.release.notify_one();

        let Ok(joined) = tokio::time::timeout(Duration::from_secs(5), poll).await else {
            unreachable!("the parked poll resolves after release");
        };
        let result = joined.unwrap_or_else(|error| unreachable!("poll task: {error}"));

        // Fence 1 (per-connection gate): the revoked gate aborted the poll at its
        // next `execute`, so the SECOND prefix Range was never issued.
        assert_eq!(
            fixture.range_count(KEYSPACE_PREFIX),
            0,
            "the revoked gate aborted the poll before the second prefix Range"
        );
        // Fence 2 (handle still_current): a rotation mid-poll surfaces as Stale.
        assert_eq!(
            result.err(),
            Some(DiscoveryError::Stale),
            "a poll whose epoch rotated mid-read returns Stale"
        );

        harness.task.abort();
    };
    if tokio::time::timeout(Duration::from_secs(5), body)
        .await
        .is_err()
    {
        unreachable!("the TiDB fence scenario completes within the deadline");
    }
}

// ----- 2 — Prometheus mid-poll gate + still_current fence ---------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn prometheus_poll_revoked_mid_read_sends_no_retry_and_is_stale() {
    let body = async {
        // A valid Prometheus record so a NON-fenced retry would succeed; the fence
        // must stop the poll before any retry.
        let seeded = vec![(
            b"/topology/prometheus/x".to_vec(),
            br#"{"ip":"1.2.3.4","port":9090}"#.to_vec(),
        )];
        // error_after_release: the parked first attempt fails, so absent the gate
        // fence the retry policy would issue a SECOND Prometheus Range.
        let Some(fixture) = spawn_fixture(seeded, PROM_PREFIX, true).await else {
            unreachable!("the fixture binds a loopback port");
        };
        let Some(harness) = spawn_module(fixture.addr).await else {
            unreachable!("the module becomes ready against the fixture");
        };
        let discovery = harness.handle.discovery_handle();

        // Park a Prometheus poll inside its first Range attempt.
        let poll = tokio::spawn(async move { discovery.poll_prometheus(CLUSTER_NAME).await });
        fixture.arrived.notified().await;
        assert_eq!(
            fixture.range_count(PROM_PREFIX),
            1,
            "the poll issued exactly the first Prometheus Range"
        );

        // Rotate the material mid-poll, revoking the parked epoch's gate, then
        // release the stall (which then fails the first attempt).
        rotate_material(&harness).await;
        fixture.release.notify_one();

        let Ok(joined) = tokio::time::timeout(Duration::from_secs(5), poll).await else {
            unreachable!("the parked poll resolves after release");
        };
        let result = joined.unwrap_or_else(|error| unreachable!("poll task: {error}"));

        // Fence 1 (per-connection gate): the revoked gate aborts the retry loop at
        // the next attempt's `execute`, so NO second Prometheus Range is sent.
        assert_eq!(
            fixture.range_count(PROM_PREFIX),
            1,
            "the revoked gate suppressed the Prometheus retry Range"
        );
        // Fence 2 (handle still_current): the rotated epoch surfaces as Stale.
        assert_eq!(
            result.err(),
            Some(DiscoveryError::Stale),
            "a Prometheus poll whose epoch rotated mid-read returns Stale"
        );

        harness.task.abort();
    };
    if tokio::time::timeout(Duration::from_secs(5), body)
        .await
        .is_err()
    {
        unreachable!("the Prometheus fence scenario completes within the deadline");
    }
}
