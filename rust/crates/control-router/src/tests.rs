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

//! Real source/module/health composition and exact ledger boundary regressions.

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::fmt::Write as _;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll};
use std::time::Duration;

use control_config::{
    ConfigNamespaceSnapshot, ConfigNamespaceSource, ConfigNamespaceStore, HealthCheckConfig,
    NamespaceConfig, SourceRevision, TopologyRuntimeIdentity,
};
use control_external::EtcdClientConfig;
use control_plane::{
    ControlConfig, ControlModule, ControlRuntime, EventSink, LifecyclePhase, LogLevel,
    MetricsPolicy, OwnershipRegistry, RuntimeEvent, ShutdownReason, TlsPolicy,
};
use control_routing::group::ClientInfo;
use control_topology::{
    StaticAdvertiseResolver, TopologyClientFactory, TopologyClusterClient, TopologyModule,
    TopologyModuleHandle,
};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tonic::body::Body;
use tonic::codegen::{BoxFuture, Service, http};
use tonic::server::{Grpc, NamedService, UnaryService};
use tonic_prost::ProstCodec;

use crate::{Candidate, Reservation, RouteError, Router, Settlement, Unsupported};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

mod factors_live;
mod locality;
mod migration;
mod registration;
mod resource;
mod sources;
mod worker;

fn must<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
    result.unwrap_or_else(|error| unreachable!("fixture: {error:?}"))
}

#[derive(Clone, PartialEq, prost::Message)]
struct RangeRequest {
    #[prost(bytes = "vec", tag = "1")]
    key: Vec<u8>,
}
#[derive(Clone, PartialEq, prost::Message)]
struct ResponseHeader {
    #[prost(int64, tag = "3")]
    revision: i64,
}
#[derive(Clone, PartialEq, prost::Message)]
struct KeyValue {
    #[prost(bytes = "vec", tag = "1")]
    key: Vec<u8>,
    #[prost(int64, tag = "3")]
    mod_revision: i64,
    #[prost(bytes = "vec", tag = "5")]
    value: Vec<u8>,
}
#[derive(Clone, PartialEq, prost::Message)]
struct RangeResponse {
    #[prost(message, optional, tag = "1")]
    header: Option<ResponseHeader>,
    #[prost(message, repeated, tag = "2")]
    kvs: Vec<KeyValue>,
    #[prost(int64, tag = "4")]
    count: i64,
}

#[derive(Clone)]
struct KvService {
    records: Arc<Mutex<Vec<KeyValue>>>,
    registration: Option<registration::Registration>,
    release: watch::Sender<bool>,
    calls: watch::Sender<u64>,
}

impl UnaryService<RangeRequest> for KvService {
    type Response = RangeResponse;
    type Future = BoxFuture<tonic::Response<RangeResponse>, tonic::Status>;
    fn call(&mut self, request: tonic::Request<RangeRequest>) -> Self::Future {
        let fixture = self.clone();
        Box::pin(async move {
            fixture.calls.send_modify(|calls| *calls += 1);
            let mut release = fixture.release.subscribe();
            release
                .wait_for(|released| *released)
                .await
                .map_err(|_| tonic::Status::cancelled("fixture retired"))?;
            let kvs: Vec<KeyValue> = fixture
                .records
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .iter()
                .filter(|kv| kv.key.starts_with(&request.get_ref().key))
                .cloned()
                .collect();
            Ok(tonic::Response::new(RangeResponse {
                header: Some(ResponseHeader { revision: 7 }),
                count: i64::try_from(kvs.len()).unwrap_or(0),
                kvs,
            }))
        })
    }
}

impl Service<http::Request<Body>> for KvService {
    type Response = http::Response<Body>;
    type Error = Infallible;
    type Future = BoxFuture<Self::Response, Infallible>;
    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
    fn call(&mut self, request: http::Request<Body>) -> Self::Future {
        let handler = self.clone();
        Box::pin(async move {
            let response = if request.uri().path() == "/etcdserverpb.KV/Range" {
                Grpc::new(ProstCodec::<RangeResponse, RangeRequest>::default())
                    .unary(handler, request)
                    .await
            } else if request.uri().path() == "/etcdserverpb.KV/Put" {
                Grpc::new(ProstCodec::<
                    registration::PutResponse,
                    registration::PutRequest,
                >::default())
                .unary(handler, request)
                .await
            } else {
                let mut response = http::Response::new(Body::default());
                response
                    .headers_mut()
                    .insert("grpc-status", http::HeaderValue::from_static("12"));
                response.headers_mut().insert(
                    "content-type",
                    http::HeaderValue::from_static("application/grpc"),
                );
                response
            };
            Ok(response)
        })
    }
}
impl NamedService for KvService {
    const NAME: &'static str = "etcdserverpb.KV";
}

struct KvFixture {
    service: KvService,
    endpoint: String,
    server: JoinHandle<()>,
}
impl Drop for KvFixture {
    fn drop(&mut self) {
        self.server.abort();
    }
}
impl KvFixture {
    async fn new() -> TestResult<Self> {
        Self::with_registration(None).await
    }

    async fn with_registration(
        registration: Option<registration::Registration>,
    ) -> TestResult<Self> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let endpoint = listener.local_addr()?.to_string();
        let service = KvService {
            records: Arc::new(Mutex::new(Vec::new())),
            registration: registration.clone(),
            release: watch::channel(true).0,
            calls: watch::channel(0).0,
        };
        let svc = service.clone();
        let server = tokio::spawn(async move {
            let incoming = futures_util::stream::unfold(listener, |listener| async move {
                let accepted = listener.accept().await.map(|(stream, _)| stream);
                Some((accepted, listener))
            });
            let _ = tonic::transport::Server::builder()
                .add_service(svc)
                .add_optional_service(registration.map(registration::LeaseService))
                .serve_with_incoming(incoming)
                .await;
        });
        let fixture = Self {
            service,
            endpoint,
            server,
        };
        fixture.backends(&[("127.0.0.1:4000", &[])]);
        Ok(fixture)
    }

    fn backends(&self, backends: &[(&str, &[(&str, &str)])]) {
        self.backends_with_ip(backends, "127.0.0.1");
    }

    fn backends_with_ip(&self, backends: &[(&str, &[(&str, &str)])], ip: &str) {
        let mut records = Vec::new();
        for (addr, labels) in backends {
            let labels: BTreeMap<&str, &str> = labels.iter().copied().collect();
            let value = must(serde_json::to_vec(
                &serde_json::json!({"ip":ip, "labels":labels}),
            ));
            records.push(KeyValue {
                key: format!("/topology/tidb/{addr}/info").into_bytes(),
                mod_revision: 7,
                value,
            });
            records.push(KeyValue {
                key: format!("/topology/tidb/{addr}/ttl").into_bytes(),
                mod_revision: 7,
                value: b"1".to_vec(),
            });
        }
        *self
            .service
            .records
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = records;
    }
}

/// Source.current advances immediately; only the module's watch delivery is
/// held. This deterministic seam never pauses a producer or depends on sleep.
#[derive(Clone)]
struct HeldSource {
    store: ConfigNamespaceStore,
    updates: watch::Sender<Arc<ConfigNamespaceSnapshot>>,
}
impl ConfigNamespaceSource for HeldSource {
    fn current(&self) -> Arc<ConfigNamespaceSnapshot> {
        self.store.current()
    }
    fn subscribe(&self) -> watch::Receiver<Arc<ConfigNamespaceSnapshot>> {
        self.updates.subscribe()
    }
}
impl HeldSource {
    fn deliver(&self) {
        self.updates.send_replace(self.store.current());
    }
}

struct Factory {
    reject: Arc<AtomicBool>,
}
impl TopologyClientFactory for Factory {
    fn build(
        &self,
        snapshot: &ConfigNamespaceSnapshot,
    ) -> Result<Vec<TopologyClusterClient>, String> {
        if self.reject.load(Ordering::SeqCst) {
            return Err("fixture rejected material".into());
        }
        snapshot
            .topology()
            .map_err(|_| "topology".to_owned())?
            .backend_clusters
            .iter()
            .map(|cluster| {
                let client =
                    EtcdClientConfig::new(cluster.pd_addrs.iter().map(ToString::to_string), None)
                        .map_err(|_| "client".to_owned())?;
                Ok(TopologyClusterClient {
                    cluster_name: Arc::clone(&cluster.name),
                    client,
                })
            })
            .collect()
    }
}
struct NullSink;
impl EventSink for NullSink {
    fn record(&self, _: &RuntimeEvent) {}
}

struct Harness {
    _registry: OwnershipRegistry,
    runtime: ControlRuntime,
    source: HeldSource,
    topology: TopologyModuleHandle,
    module: JoinHandle<()>,
    reject: Arc<AtomicBool>,
    router: Arc<Router>,
    fixture: KvFixture,
}
impl Drop for Harness {
    fn drop(&mut self) {
        self.module.abort();
    }
}

impl Harness {
    async fn new(rule: &str, policy: &str) -> TestResult<Self> {
        Self::with_backends(rule, policy, &[("127.0.0.1:4000", &[])]).await
    }

    async fn with_backends(
        rule: &str,
        policy: &str,
        backends: &[(&str, &[(&str, &str)])],
    ) -> TestResult<Self> {
        Self::with_health(
            rule,
            policy,
            backends,
            HealthCheckConfig {
                enabled: false,
                interval_nanos: 50_000_000,
                ..HealthCheckConfig::default()
            },
            "",
        )
        .await
    }

    async fn with_health(
        rule: &str,
        policy: &str,
        backends: &[(&str, &[(&str, &str)])],
        health: HealthCheckConfig,
        proxy_zone: &str,
    ) -> TestResult<Self> {
        Self::with_fixture(
            rule,
            policy,
            backends,
            health,
            proxy_zone,
            KvFixture::new().await?,
        )
        .await
    }

    async fn with_fixture(
        rule: &str,
        policy: &str,
        backends: &[(&str, &[(&str, &str)])],
        health: HealthCheckConfig,
        proxy_zone: &str,
        fixture: KvFixture,
    ) -> TestResult<Self> {
        // Enabled rows use real SQL greeting probes. Empty IP selects the
        // production skip-HTTP path; no health verdict is fabricated here.
        fixture.backends_with_ip(backends, if health.enabled { "" } else { "127.0.0.1" });
        let mut config = format!(
            "[proxy]\npd-addrs = \"\"\n[[proxy.backend-clusters]]\nname = \"default\"\npd-addrs = \"{}\"\n[balance]\npolicy = \"{policy}\"\nrouting-rule = \"{rule}\"\n",
            fixture.endpoint
        );
        if !proxy_zone.is_empty() {
            writeln!(config, "[labels]\nzone = \"{proxy_zone}\"")?;
        }
        let store = ConfigNamespaceStore::from_toml(config.as_bytes(), None, Path::new("/tmp"))?;
        let current = store.current();
        store.apply(
            (**current.effective()).clone(),
            vec![NamespaceConfig {
                namespace: "default".into(),
                ..NamespaceConfig::default()
            }],
            SourceRevision {
                file_revision: 2,
                etcd_revision: 0,
            },
            Path::new("/tmp"),
        )?;
        let source = HeldSource {
            updates: watch::channel(store.current()).0,
            store,
        };
        let registry = OwnershipRegistry::new();
        let runtime = ControlRuntime::claim_process(
            &registry,
            "route-composition",
            ControlConfig::new(
                1,
                Duration::from_secs(30),
                0,
                TlsPolicy::default(),
                LogLevel::Info,
                MetricsPolicy::default(),
            )?,
            Arc::new(NullSink),
        )?;
        runtime.mark_ready()?;
        let reject = Arc::new(AtomicBool::new(false));
        let (module, mut topology) = TopologyModule::new(
            Arc::new(source.clone()),
            Box::new(Factory {
                reject: Arc::clone(&reject),
            }),
            Arc::new(StaticAdvertiseResolver::new("127.0.0.1")),
            TopologyRuntimeIdentity {
                version: Arc::from("test"),
                git_hash: Arc::from("test"),
                deploy_path: "/tmp".into(),
                start_timestamp: 1,
            },
            health,
        )?;
        let context = runtime.handle().module_context();
        let module = tokio::spawn(async move {
            let _ = Box::new(module).run(context).await;
        });
        tokio::time::timeout(Duration::from_secs(5), topology.wait_ready()).await??;
        let router = Arc::new(must(Router::new(
            Arc::new(source.clone()),
            &topology,
            &runtime.handle().module_context(),
            "default",
            100,
        )));
        let harness = Self {
            _registry: registry,
            runtime,
            source,
            topology,
            module,
            reject,
            router,
            fixture,
        };
        if policy == "connection" {
            let _ = harness.ready().await;
        }
        Ok(harness)
    }

    async fn ready(&self) -> Candidate {
        must(
            tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    if let Ok(candidate) = self.router.capture() {
                        break candidate;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await,
        )
    }

    async fn changed_r(&self, old: &Candidate) -> Candidate {
        must(
            tokio::time::timeout(Duration::from_secs(6), async {
                loop {
                    if let Ok(candidate) = self.router.capture()
                        && !Arc::ptr_eq(&candidate.routing, &old.routing)
                    {
                        break candidate;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await,
        )
    }

    fn patch(&self, patch: &str, revision: u64) {
        must(
            self.source
                .store
                .apply_toml(patch.as_bytes(), None, revision, Path::new("/tmp")),
        );
    }

    async fn applied(&self) {
        must(self.applied_at("FIXTURE", Duration::from_secs(5)).await);
    }

    async fn applied_at(&self, stage: &str, timeout: Duration) -> TestResult {
        let wanted = self.source.store.current().generation();
        let mut status = self.topology.status();
        tokio::time::timeout(
            timeout,
            status.wait_for(|status| status.observed_generation == wanted),
        )
        .await
        .map_err(|err| format!("CONFIG_MATERIAL_{stage}_TIMEOUT: {err}"))?
        .map_err(|err| format!("CONFIG_MATERIAL_{stage}_CLOSED: {err}"))?;
        Ok(())
    }

    fn reserve(&self, candidate: &Candidate) -> (crate::Session, Reservation) {
        must(self.reserve_at(candidate, "FIXTURE"))
    }

    fn reserve_at(
        &self,
        candidate: &Candidate,
        stage: &str,
    ) -> TestResult<(crate::Session, Reservation)> {
        let session = self
            .router
            .open()
            .map_err(|err| format!("CONFIG_MATERIAL_{stage}_OPEN: {err:?}"))?;
        let reservation = self
            .router
            .reserve(&session, candidate, ClientInfo::default(), "", &[])
            .map_err(|err| format!("CONFIG_MATERIAL_{stage}_RESERVE: {err:?}"))?;
        Ok((session, reservation))
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn independent_config_pending_rejected_and_committed_material_are_distinguished() -> TestResult
{
    // Config delivery and client-epoch changes own this test's interleaving.
    // Keep the real initial health snapshot stable between capture and reserve;
    // periodic replacement is covered by the separate health-boundary tests.
    let harness = Harness::with_health(
        "",
        "connection",
        &[("127.0.0.1:4000", &[])],
        HealthCheckConfig {
            enabled: false,
            interval_nanos: 3_600_000_000_000,
            ..HealthCheckConfig::default()
        },
        "",
    )
    .await?;
    let first = harness.ready().await;
    let (old_session, old_reservation) = harness.reserve_at(&first, "INITIAL")?;
    assert_eq!(
        harness.router.finish(&old_reservation, true),
        Settlement::Applied
    );
    let second_fixture = KvFixture::new().await?;
    second_fixture.service.release.send_replace(false);
    harness.patch(&format!("[[proxy.backend-clusters]]\nname = \"default\"\npd-addrs = \"{}\"\n[balance]\nrouting-policy = \"random\"", second_fixture.endpoint), 3);
    // The real store has C_new; the topology watch has deterministically not
    // received it. Current policy is usable with the old exact R/H.
    let pending = must(harness.router.capture());
    assert!(Arc::ptr_eq(&first.routing, &pending.routing));
    assert_eq!(
        pending.policy.selection_policy,
        control_config::RoutingSelectionPolicy::Random
    );
    let (pending_session, _) = harness.reserve_at(&pending, "PENDING")?;
    harness.router.close(&pending_session);
    assert!(matches!(
        harness
            .router
            .reserve(&old_session, &first, ClientInfo::default(), "", &[]),
        Err(RouteError::StaleCandidate)
    ));
    harness.reject.store(true, Ordering::SeqCst);
    harness.source.deliver();
    harness
        .applied_at("REJECTED", Duration::from_secs(30))
        .await?;
    assert!(harness.topology.status().borrow().last_rejection.is_some());
    let rejected = must(harness.router.capture());
    assert!(Arc::ptr_eq(&rejected.routing, &first.routing));
    let (rejected_session, _) = harness.reserve_at(&rejected, "REJECTED")?;
    harness.router.close(&rejected_session);
    harness.reject.store(false, Ordering::SeqCst);
    harness.patch("[proxy]\nmax-connections = 101", 4);
    harness.source.deliver();
    harness
        .applied_at("COMMITTED", Duration::from_secs(30))
        .await?;
    // New etcd channel committed, but its Range responses are held. Old R is
    // still published and H was synchronously revoked before epoch commit.
    let current_r = harness
        .topology
        .routing_handle()
        .current()
        .unwrap_or_else(|| unreachable!("old R remains"));
    assert!(Arc::ptr_eq(&current_r, &first.routing));
    assert!(
        harness
            .topology
            .health_overlay_handle()
            .current_for(&current_r)
            .is_none()
    );
    assert!(matches!(
        harness.router.capture(),
        Err(RouteError::ControlUnavailable)
    ));
    assert_eq!(harness.router.close(&old_session), Settlement::Applied);
    second_fixture.service.release.send_replace(true);
    let recovered = harness.ready().await;
    assert!(recovered.routing.client_epoch > first.routing.client_epoch);
    let (session, reservation) = harness.reserve_at(&recovered, "RECOVERED")?;
    assert_eq!(
        harness.router.finish(&reservation, true),
        Settlement::Applied
    );
    assert_eq!(harness.router.close(&session), Settlement::Applied);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn superseded_health_foreign_candidates_and_stale_after_lock_do_not_reserve() -> TestResult {
    let harness = Harness::new("", "connection").await?;
    let candidate = harness.ready().await;
    let session = must(harness.router.open());
    // Hold the actual ledger mutex while another thread begins reserve.
    let lock = harness.router.hold_lock_for_test();
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let started = Arc::clone(&barrier);
    let router = Arc::clone(&harness.router);
    let retained = candidate.clone();
    let owned_session = session.clone();
    let worker = std::thread::spawn(move || {
        started.wait();
        router.reserve(&owned_session, &retained, ClientInfo::default(), "", &[])
    });
    barrier.wait();
    harness.patch("[balance]\nrouting-policy = \"random\"", 3);
    drop(lock);
    assert!(matches!(
        must(worker.join()),
        Err(RouteError::StaleCandidate)
    ));
    assert!(
        harness
            .router
            .accounting("default/127.0.0.1:4000")
            .is_none()
    );
    let foreign_router = must(Router::new(
        Arc::new(harness.source.clone()),
        &harness.topology,
        &harness.runtime.handle().module_context(),
        "default",
        100,
    ));
    let foreign = must(foreign_router.capture());
    assert!(matches!(
        harness
            .router
            .reserve(&session, &foreign, ClientInfo::default(), "", &[]),
        Err(RouteError::StaleCandidate)
    ));
    let now = harness.ready().await;
    must(
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Ok(fresh) = harness.router.capture()
                    && !Arc::ptr_eq(&fresh.health, &now.health)
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await,
    );
    assert!(matches!(
        harness
            .router
            .reserve(&session, &now, ClientInfo::default(), "", &[]),
        Err(RouteError::StaleCandidate)
    ));
    harness.router.close(&session);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn namespace_revocation_and_owner_retirement_allow_only_old_settlement() -> TestResult {
    let harness = Harness::new("", "connection").await?;
    let candidate = harness.ready().await;
    let (session, reservation) = harness.reserve(&candidate);
    let current = harness.source.store.current();
    harness.source.store.apply(
        (**current.effective()).clone(),
        Vec::new(),
        SourceRevision {
            file_revision: 3,
            etcd_revision: 0,
        },
        Path::new("/tmp"),
    )?;
    assert!(matches!(
        harness.router.open(),
        Err(RouteError::NamespaceMissing)
    ));
    assert!(matches!(
        harness.router.capture(),
        Err(RouteError::NamespaceMissing)
    ));
    assert_eq!(
        harness.router.finish(&reservation, true),
        Settlement::Applied
    );
    harness.runtime.begin_shutdown(ShutdownReason::Requested)?;
    harness.runtime.advance_shutdown(LifecyclePhase::Draining)?;
    harness.runtime.advance_shutdown(LifecyclePhase::Stopping)?;
    harness.runtime.finish()?;
    assert_eq!(harness.router.close(&session), Settlement::Applied);
    assert_eq!(
        harness.router.finish(&reservation, true),
        Settlement::Ignored
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn resource_is_unsupported_and_pending_empty_clusters_keep_the_applied_source() -> TestResult
{
    let harness = Harness::new("", "resource").await?;
    assert!(matches!(
        harness.router.capture(),
        Err(RouteError::Unsupported(Unsupported::ResourcePolicy))
    ));
    harness.patch(
        "[proxy]\nbackend-clusters = []\n[balance]\npolicy = \"connection\"",
        3,
    );
    let pending = harness.ready().await;
    assert_eq!(
        pending.backend.mode(),
        control_topology::BackendSourceMode::Dynamic
    );
    harness.source.deliver();
    harness.applied().await;
    let applied = harness.ready().await;
    assert_eq!(
        applied.backend.mode(),
        control_topology::BackendSourceMode::Static
    );
    let session = must(harness.router.open());
    assert!(matches!(
        harness
            .router
            .reserve(&session, &applied, ClientInfo::default(), "", &[]),
        Err(RouteError::NoBackend)
    ));
    harness.router.close(&session);
    assert!(
        harness
            .router
            .accounting("default/127.0.0.1:4000")
            .is_none()
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn invalid_new_cidr_is_unroutable_but_invalid_refresh_keeps_old_matcher_and_owner()
-> TestResult {
    let harness = Harness::with_backends(
        "client_cidr",
        "connection",
        &[
            ("127.0.0.1:4000", &[("cidr", "192.0.2.0/24")]),
            ("127.0.0.1:4001", &[("cidr", "198.51.100.0/24,broken")]),
        ],
    )
    .await?;
    let old = harness.ready().await;
    let a = must(harness.router.open());
    let b = must(harness.router.open());
    let valid = ClientInfo {
        client_address: Some("192.0.2.7:99"),
        proxy_address: None,
    };
    let bad = ClientInfo {
        client_address: Some("198.51.100.7:99"),
        proxy_address: None,
    };
    let first = must(harness.router.reserve(&a, &old, valid, "", &[]));
    let id = first.assignment().backend_id.clone();
    harness.router.finish(&first, true);
    assert!(matches!(
        harness.router.reserve(&b, &old, bad, "", &[]),
        Err(RouteError::NoBackend)
    ));
    // The group retains old valid parsed networks when new raw values fail.
    harness
        .fixture
        .backends(&[("127.0.0.1:4000", &[("cidr", "broken")])]);
    let changed = harness.changed_r(&old).await;
    let second = must(harness.router.reserve(&b, &changed, valid, "", &[]));
    assert_eq!(second.assignment().backend_id, id);
    assert_eq!(
        harness
            .router
            .accounting(&id)
            .map(|counts| (counts.active(), counts.reserved())),
        Some((1, 1))
    );
    harness.router.close(&a);
    assert_eq!(
        harness
            .router
            .accounting(&id)
            .map(super::ledger::Accounting::connection_score),
        Some(1)
    );
    harness.router.close(&b);
    // Disappearance prunes idle owners. An old terminal cannot reach the next
    // owner when the same opaque backend ID is discovered again.
    harness.fixture.backends(&[]);
    let empty = harness.changed_r(&changed).await;
    let idle = must(harness.router.open());
    assert!(matches!(
        harness.router.reserve(&idle, &empty, valid, "", &[]),
        Err(RouteError::NoBackend)
    ));
    assert!(harness.router.accounting(&id).is_none());
    harness
        .fixture
        .backends(&[("127.0.0.1:4000", &[("cidr", "192.0.2.0/24")])]);
    let restored = harness.changed_r(&empty).await;
    let third = must(harness.router.reserve(&idle, &restored, valid, "", &[]));
    assert_eq!(harness.router.finish(&first, true), Settlement::Ignored);
    assert_eq!(harness.router.finish(&second, false), Settlement::Ignored);
    assert_eq!(
        harness
            .router
            .accounting(&id)
            .map(super::ledger::Accounting::reserved),
        Some(1)
    );
    harness.router.finish(&third, true);
    harness.router.close(&idle);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn close_and_success_race_never_leak_or_resurrect_accounting() -> TestResult {
    let harness = Harness::new("", "connection").await?;
    for _ in 0..32 {
        let candidate = harness.ready().await;
        let (session, reservation) = harness.reserve(&candidate);
        let router = Arc::clone(&harness.router);
        let result = reservation.clone();
        let start = Arc::new(std::sync::Barrier::new(2));
        let other_start = Arc::clone(&start);
        let worker = std::thread::spawn(move || {
            other_start.wait();
            router.finish(&result, true)
        });
        start.wait();
        harness.router.close(&session);
        let _ = must(worker.join());
        assert_eq!(
            harness
                .router
                .accounting(&reservation.assignment().backend_id)
                .map(super::ledger::Accounting::connection_score),
            Some(0)
        );
        assert_eq!(
            harness.router.finish(&reservation, true),
            Settlement::Ignored
        );
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn skipped_namespace_removal_and_recreation_cannot_revive_an_old_router() -> TestResult {
    let harness = Harness::new("", "connection").await?;
    let original = harness.ready().await;
    let (session, reservation) = harness.reserve(&original);
    let snapshot = harness.source.store.current();
    let publish = |namespaces, revision| {
        harness.source.store.apply(
            (**snapshot.effective()).clone(),
            namespaces,
            SourceRevision {
                file_revision: revision,
                etcd_revision: 0,
            },
            Path::new("/tmp"),
        )
    };
    publish(Vec::new(), 3)?;
    // The router deliberately never observes the intermediate removal.
    publish(snapshot.namespaces().to_vec(), 4)?;
    assert!(matches!(
        harness.router.open(),
        Err(RouteError::NamespaceReplaced)
    ));
    assert!(matches!(
        harness.router.capture(),
        Err(RouteError::NamespaceReplaced)
    ));
    // The new namespace capability cannot bind to the old producer, even
    // when both namespace contents are identical and watch delivery was held.
    assert!(matches!(
        Router::new(
            Arc::new(harness.source.clone()),
            &harness.topology,
            &harness.runtime.handle().module_context(),
            "default",
            100,
        ),
        Err(RouteError::ControlUnavailable)
    ));
    harness.source.deliver();
    harness.applied().await;
    let replacement = must(Router::new(
        Arc::new(harness.source.clone()),
        &harness.topology,
        &harness.runtime.handle().module_context(),
        "default",
        100,
    ));
    let fresh = must(replacement.capture());
    let admitted = must(replacement.open());
    let new = must(replacement.reserve(&admitted, &fresh, ClientInfo::default(), "", &[]));
    assert_eq!(replacement.finish(&reservation, true), Settlement::Ignored);
    assert_eq!(replacement.close(&session), Settlement::Ignored);
    assert_eq!(
        harness.router.finish(&reservation, true),
        Settlement::Applied
    );
    assert_eq!(harness.router.close(&session), Settlement::Applied);
    assert_eq!(
        replacement
            .accounting(&new.assignment().backend_id)
            .map(super::ledger::Accounting::reserved),
        Some(1)
    );
    replacement.close(&admitted);
    harness.runtime.begin_shutdown(ShutdownReason::Requested)?;
    assert!(matches!(
        replacement.capture(),
        Err(RouteError::ControlUnavailable)
    ));
    assert!(matches!(
        replacement.open(),
        Err(RouteError::ControlUnavailable)
    ));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn port_group_filter_and_exclusions_reserve_only_the_selected_owner() -> TestResult {
    let harness = Harness::with_backends(
        "port",
        "connection",
        &[
            (
                "127.0.0.1:4000",
                &[("tiproxy-port", " 6000 "), ("keyspace", "tenant-a")],
            ),
            ("127.0.0.1:4001", &[("tiproxy-port", "6000")]),
            ("127.0.0.1:4002", &[("tiproxy-port", "6001")]),
            ("127.0.0.1:4003", &[]),
        ],
    )
    .await?;
    let candidate = harness.ready().await;
    let session = must(harness.router.open());
    let excluded = ["default/127.0.0.1:4001"];
    let first = must(harness.router.reserve(
        &session,
        &candidate,
        ClientInfo::default(),
        "6000",
        &excluded,
    ));
    assert_eq!(first.assignment().backend_id, "default/127.0.0.1:4000");
    assert_eq!(first.assignment().cluster_name, "default");
    assert_eq!(first.assignment().backend_address, "127.0.0.1:4000");
    assert_eq!(first.assignment().keyspace, "tenant-a");
    harness.router.finish(&first, false);
    assert!(matches!(
        harness.router.reserve(
            &session,
            &candidate,
            ClientInfo::default(),
            "6000",
            &["default/127.0.0.1:4000", "default/127.0.0.1:4001"]
        ),
        Err(RouteError::NoBackend)
    ));
    let next =
        must(
            harness
                .router
                .reserve(&session, &candidate, ClientInfo::default(), "6001", &[]),
        );
    assert_eq!(next.assignment().backend_id, "default/127.0.0.1:4002");
    assert_eq!(harness.router.finish(&first, true), Settlement::Ignored);
    assert_eq!(
        harness
            .router
            .accounting("default/127.0.0.1:4000")
            .map(super::ledger::Accounting::connection_score),
        Some(0)
    );
    harness.router.close(&session);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn routing_and_health_swaps_while_the_ledger_is_locked_reject_retained_candidates()
-> TestResult {
    let harness = Harness::new("", "connection").await?;
    for change_routing in [false, true] {
        let candidate = harness.ready().await;
        let session = must(harness.router.open());
        // Intentionally hold the private synchronous ledger lock across source
        // publication: the worker must recheck inputs only after it acquires it.
        let lock = harness.router.hold_lock_for_test();
        let start = Arc::new(std::sync::Barrier::new(2));
        let worker_start = Arc::clone(&start);
        let router = Arc::clone(&harness.router);
        let retained = candidate.clone();
        let admitted = session.clone();
        let worker = std::thread::spawn(move || {
            worker_start.wait();
            router.reserve(&admitted, &retained, ClientInfo::default(), "", &[])
        });
        start.wait();
        if change_routing {
            harness.fixture.backends(&[("127.0.0.1:4001", &[])]);
            let _ = harness.changed_r(&candidate).await;
        } else {
            must(
                tokio::time::timeout(Duration::from_secs(5), async {
                    loop {
                        if let Ok(current) = harness.router.capture()
                            && !Arc::ptr_eq(&current.health, &candidate.health)
                        {
                            break;
                        }
                        tokio::task::yield_now().await;
                    }
                })
                .await,
            );
        }
        drop(lock);
        assert!(matches!(
            must(worker.join()),
            Err(RouteError::StaleCandidate)
        ));
        assert!(
            harness
                .router
                .accounting("default/127.0.0.1:4000")
                .is_none()
        );
        assert!(
            harness
                .router
                .accounting("default/127.0.0.1:4001")
                .is_none()
        );
        harness.router.close(&session);
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unsupported_factor_inputs_remain_valid_config_but_never_reserve() -> TestResult {
    let harness = Harness::new("", "connection").await?;
    harness.patch(
        "[proxy]\nfail-backend-list = []\n[balance]\npolicy = \"location\"",
        6,
    );
    assert!(matches!(
        harness.router.capture(),
        Err(RouteError::Unsupported(Unsupported::LocationPolicy))
    ));
    assert!(
        harness
            .router
            .accounting("default/127.0.0.1:4000")
            .is_none()
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn equal_listener_ports_in_different_clusters_block_reservation() -> TestResult {
    let harness = Harness::with_backends(
        "port",
        "connection",
        &[("127.0.0.1:4000", &[("tiproxy-port", "6000")])],
    )
    .await?;
    let original = harness.ready().await;
    let second = KvFixture::new().await?;
    second.backends(&[("127.0.0.1:4000", &[("tiproxy-port", "6000")])]);
    harness.patch(&format!("[[proxy.backend-clusters]]\nname = \"default\"\npd-addrs = \"{}\"\n[[proxy.backend-clusters]]\nname = \"second\"\npd-addrs = \"{}\"", harness.fixture.endpoint, second.endpoint), 3);
    harness.source.deliver();
    harness.applied().await;
    let candidate = harness.changed_r(&original).await;
    let session = must(harness.router.open());
    assert!(matches!(
        harness
            .router
            .reserve(&session, &candidate, ClientInfo::default(), "6000", &[]),
        Err(RouteError::PortConflict)
    ));
    for id in ["default/127.0.0.1:4000", "second/127.0.0.1:4000"] {
        assert_eq!(
            harness
                .router
                .accounting(id)
                .map(super::ledger::Accounting::connection_score),
            Some(0)
        );
    }
    harness.router.close(&session);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shared_go_retry_observation() -> TestResult {
    use std::fmt::Write;
    let Ok(input) = std::env::var("CPROUTE_RETRY_FIXTURE") else {
        return Ok(());
    };
    let rows: Vec<serde_json::Value> = serde_json::from_slice(&std::fs::read(input)?)?;
    let harness = Harness::with_backends(
        "port",
        "connection",
        &[("127.0.0.1:4000", &[("tiproxy-port", "6000")])],
    )
    .await?;
    let mut prior = harness.ready().await;
    let second = KvFixture::new().await?;
    second.backends(&[("127.0.0.1:4009", &[("tiproxy-port", "6000")])]);
    let mut selector = must(harness.router.selector());
    let mut output = String::new();
    for (index, row) in rows.iter().enumerate() {
        let addresses: Vec<String> = serde_json::from_value(row["backends"].clone())?;
        let labels = [("tiproxy-port", "6000")];
        let backends: Vec<(&str, &[(&str, &str)])> = addresses
            .iter()
            .map(|addr| (addr.as_str(), labels.as_slice()))
            .collect();
        harness.fixture.backends(&backends);
        let mut config = format!(
            "[[proxy.backend-clusters]]\nname=\"default\"\npd-addrs=\"{}\"\n",
            harness.fixture.endpoint
        );
        if row["conflict"].as_bool() == Some(true) {
            write!(
                config,
                "[[proxy.backend-clusters]]\nname=\"second\"\npd-addrs=\"{}\"\n",
                second.endpoint
            )?;
        }
        harness.patch(&config, index as u64 + 3);
        harness.source.deliver();
        harness.applied().await;
        prior = if index == 0 {
            harness.ready().await
        } else {
            harness.changed_r(&prior).await
        };
        let result = match selector.next_candidate(&prior, ClientInfo::default(), "6000") {
            Ok(attempt) => {
                assert_eq!(selector.finish(&attempt, false), Settlement::Applied);
                attempt.assignment().backend_id.clone()
            }
            Err(RouteError::PortConflict) => "conflict".into(),
            Err(RouteError::NoBackend) => "none".into(),
            Err(error) => unreachable!("route: {error:?}"),
        };
        writeln!(
            output,
            "{}\t{result}\t{}",
            row["name"].as_str().unwrap_or_default(),
            selector.exclusions().join(",")
        )?;
    }
    if let Ok(expected) = std::env::var("CPROUTE_RETRY_EXPECTED") {
        assert_eq!(output, std::fs::read_to_string(expected)?);
    }
    std::fs::write(std::env::var("CPROUTE_RETRY_OUTPUT")?, output)?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn label_fail_list_and_retry_preserve_exact_attempts_and_current_policy() -> TestResult {
    let harness = Harness::with_backends(
        "",
        "connection",
        &[
            ("127.0.0.1:4000", &[("tenant", "red")]),
            ("127.0.0.1:4001", &[("tenant", "blue")]),
            ("127.0.0.1:4002", &[("tenant", "red")]),
        ],
    )
    .await?;
    let original = harness.ready().await;
    harness.patch("[balance]\nlabel-name=\"tenant\"\n[labels]\ntenant=\"red\"\n[proxy]\nfail-backend-list=[\"127.0.0.1:4002\"]", 3);
    let red = must(harness.router.capture());
    assert!(Arc::ptr_eq(&original.routing, &red.routing));
    let mut selector = must(harness.router.selector());
    let first = must(selector.next_candidate(&red, ClientInfo::default(), ""));
    assert_eq!(first.assignment().backend_address, "127.0.0.1:4000");
    let repeated = must(selector.next_candidate(&red, ClientInfo::default(), ""));
    assert_eq!(first.assignment(), repeated.assignment());
    assert_eq!(selector.exclusions().len(), 1);
    assert_eq!(selector.finish(&first, false), Settlement::Applied);
    harness.patch("[proxy]\nfail-backend-list=[]", 4);
    // A stale candidate must preserve the exclusions, without resetting them.
    assert!(matches!(
        selector.next_candidate(&red, ClientInfo::default(), ""),
        Err(RouteError::StaleCandidate)
    ));
    assert_eq!(selector.exclusions().len(), 1);
    let fresh = must(harness.router.capture());
    let next = must(selector.next_candidate(&fresh, ClientInfo::default(), ""));
    assert_eq!(next.assignment().backend_address, "127.0.0.1:4002");
    assert_eq!(selector.finish(&first, true), Settlement::Ignored);
    let foreign = must(harness.router.selector());
    assert_eq!(foreign.finish(&next, false), Settlement::Ignored);
    assert_eq!(
        harness
            .router
            .accounting(&next.assignment().backend_id)
            .map(super::ledger::Accounting::reserved),
        Some(1)
    );
    assert_eq!(selector.finish(&next, true), Settlement::Applied);
    assert_eq!(selector.finish(&repeated, false), Settlement::Ignored);
    drop(selector);
    assert_eq!(
        harness
            .router
            .accounting(&next.assignment().backend_id)
            .map(super::ledger::Accounting::connection_score),
        Some(0)
    );
    assert_eq!(harness.router.finish(&next, true), Settlement::Ignored);
    Ok(())
}
