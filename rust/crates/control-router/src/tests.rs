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
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll};
use std::time::Duration;

use control_config::source::decode_proxy_online;
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

use crate::{Candidate, Reservation, RouteError, RoutePlane, Router, Settlement, Unsupported};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

mod api_differential;
mod concurrency;
mod factors_live;
mod locality;
mod migration;
mod production_dispatch;
mod registration;
mod resource;
mod resource_release;
mod sources;
mod time_boundaries;
mod worker;

fn must<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
    result.unwrap_or_else(|error| unreachable!("fixture: {error:?}"))
}

#[test]
fn route_error_categories_preserve_first_poll_source_identity() {
    assert_eq!(
        RouteError::Observer(control_topology::ObserverError::TopologyUnavailable).category(),
        "topology_unavailable"
    );
    assert_eq!(
        RouteError::Observer(control_topology::ObserverError::Cancelled).category(),
        "cancelled"
    );
    assert_eq!(
        RouteError::Observer(control_topology::ObserverError::DeadlineExceeded).category(),
        "deadline_exceeded"
    );
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
async fn route_plane_replaces_admission_but_retains_an_existing_selector() -> TestResult {
    let harness = Harness::new("", "connection").await?;
    let (plane, mut handle) = RoutePlane::new(
        Arc::new(harness.source.clone()),
        harness.topology.clone(),
        None,
    );
    let context = harness.runtime.handle().module_context();
    let plane_task = tokio::spawn(async move { Box::new(plane).run(context).await });
    tokio::time::timeout(Duration::from_secs(5), handle.wait_ready()).await??;
    assert_eq!(handle.current_incarnations(), 1);

    let mut retained = must(handle.admit(""));
    assert_eq!(retained.namespace(), "default");

    let current = harness.source.store.current();
    let mut replacement = NamespaceConfig {
        namespace: "default".to_owned(),
        ..NamespaceConfig::default()
    };
    replacement.frontend.user = "replacement".to_owned();
    harness.source.store.apply(
        (**current.effective()).clone(),
        vec![replacement],
        SourceRevision {
            file_revision: 3,
            etcd_revision: 0,
        },
        Path::new("/tmp"),
    )?;
    let waiting = handle.admit_within("replacement", Duration::from_secs(1));
    tokio::pin!(waiting);
    assert!(
        tokio::time::timeout(Duration::from_millis(10), &mut waiting)
            .await
            .is_err(),
        "the candidate snapshot is current but its exact router is not yet published"
    );
    harness.source.deliver();
    let replacement = must(tokio::time::timeout(Duration::from_secs(5), waiting).await?);
    assert!(!retained.same_router_incarnation(&replacement));
    assert_eq!(replacement.namespace(), "default");
    assert_eq!(handle.current_incarnations(), 1);
    assert_eq!(
        handle.route_ledger_evidence().router_incarnations,
        2,
        "the retired router stays observable while its admission lease is alive"
    );
    assert_eq!(handle.route_ledger_evidence().sessions, 2);

    let reservation = must(retained.selector_mut().next(ClientInfo::default(), ""));
    assert_eq!(
        reservation.assignment().backend_id,
        "default/127.0.0.1:4000"
    );
    assert_eq!(
        retained.selector().finish(&reservation, true),
        Settlement::Applied
    );
    drop(retained);
    drop(replacement);
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let evidence = handle.route_ledger_evidence();
            if evidence.router_incarnations == 1 && evidence.sessions == 0 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await?;
    plane_task.abort();
    let _ = plane_task.await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn replaced_route_plane_keeps_the_retained_incarnation_worker_alive() -> TestResult {
    let harness = Harness::with_backends(
        "",
        "connection",
        &[("127.0.0.1:4000", &[]), ("127.0.0.1:4001", &[])],
    )
    .await?;
    let (plane, mut handle) = RoutePlane::new(
        Arc::new(harness.source.clone()),
        harness.topology.clone(),
        None,
    );
    let context = harness.runtime.handle().module_context();
    let plane_task = tokio::spawn(async move { Box::new(plane).run(context).await });
    tokio::time::timeout(Duration::from_secs(5), handle.wait_ready()).await??;

    let mut retained = must(handle.admit(""));
    let reservation = must(retained.selector_mut().next(ClientInfo::default(), ""));
    let from = reservation.assignment().backend_id.clone();
    let failed_address = reservation.assignment().backend_address.clone();
    let to = if from.ends_with("4000") {
        "default/127.0.0.1:4001"
    } else {
        "default/127.0.0.1:4000"
    };
    assert_eq!(
        retained.selector().finish(&reservation, true),
        Settlement::Applied
    );
    let (registration, mut receiver) = must(retained.register_commands(12001, 4));

    let current = harness.source.store.current();
    let mut replacement = NamespaceConfig {
        namespace: "default".to_owned(),
        ..NamespaceConfig::default()
    };
    replacement.frontend.user = "replacement".to_owned();
    harness.source.store.apply(
        (**current.effective()).clone(),
        vec![replacement],
        SourceRevision {
            file_revision: 3,
            etcd_revision: 0,
        },
        Path::new("/tmp"),
    )?;
    harness.source.deliver();
    let replacement = must(
        tokio::time::timeout(
            Duration::from_secs(5),
            handle.admit_within("replacement", Duration::from_secs(4)),
        )
        .await?,
    );
    assert!(!retained.same_router_incarnation(&replacement));

    // Only after the old incarnation is withdrawn from new admission, publish
    // the failover policy. Its session-held RegisteredRouter must keep the old
    // worker and exact dispatcher alive long enough to migrate that session.
    harness.patch(
        &format!(
            "[proxy]\nfail-backend-list=[\"{failed_address}\"]\nfailover-timeout=60\n[balance.status]\nmigrations-per-second=100"
        ),
        4,
    );
    harness.source.deliver();
    let envelope = tokio::time::timeout(Duration::from_secs(5), receiver.recv())
        .await?
        .ok_or("retained worker command channel closed")?;
    let crate::MigrationCommand::Redirect(redirect) = envelope.command() else {
        return Err("retained worker emitted a close before its 60s timeout".into());
    };
    assert_eq!(redirect.from().backend_id, from);
    assert_eq!(redirect.to().backend_id, to);
    assert_eq!(envelope.finish_redirect(false), Settlement::Applied);

    drop(registration);
    drop(retained);
    drop(replacement);
    plane_task.abort();
    let _ = plane_task.await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn route_plane_restart_cleans_lost_terminal_and_starts_with_a_fresh_ledger() -> TestResult {
    let harness = Harness::with_backends(
        "",
        "connection",
        &[("127.0.0.1:4000", &[]), ("127.0.0.1:4001", &[])],
    )
    .await?;
    let (plane, mut handle) = RoutePlane::new(
        Arc::new(harness.source.clone()),
        harness.topology.clone(),
        None,
    );
    let context = harness.runtime.handle().module_context();
    let plane_task = tokio::spawn(async move { Box::new(plane).run(context).await });
    tokio::time::timeout(Duration::from_secs(5), handle.wait_ready()).await??;
    let mut admission = must(handle.admit(""));
    let old_router = admission.test_router();
    let reservation = must(admission.selector_mut().next(ClientInfo::default(), ""));
    let old_backend = reservation.assignment().backend_id.clone();
    let old_address = reservation.assignment().backend_address.clone();
    assert_eq!(
        admission.selector().finish(&reservation, true),
        Settlement::Applied
    );
    let (registration, mut receiver) = must(admission.register_commands(13001, 2));

    harness.patch(
        &format!(
            "[proxy]\nfail-backend-list=[\"{old_address}\"]\nfailover-timeout=60\n[balance.status]\nmigrations-per-second=100"
        ),
        3,
    );
    harness.source.deliver();
    let lost = tokio::time::timeout(Duration::from_secs(5), receiver.recv())
        .await?
        .ok_or("missing lost terminal fixture")?;
    assert!(matches!(
        lost.command(),
        crate::MigrationCommand::Redirect(_)
    ));

    // Model a Rust owner crash/restart: the command was removed from the FIFO
    // but never reported. Lease teardown closes the pending ledger entry; its
    // later RAII/exact terminal is ignored rather than resurrecting ownership.
    drop(receiver);
    drop(registration);
    drop(admission);
    assert_eq!(
        old_router
            .accounting(&old_backend)
            .unwrap_or_default()
            .active(),
        0
    );
    assert_eq!(lost.finish_redirect(false), Settlement::Ignored);
    plane_task.abort();
    let _ = plane_task.await;

    let (fresh_plane, mut fresh_handle) = RoutePlane::new(
        Arc::new(harness.source.clone()),
        harness.topology.clone(),
        None,
    );
    let context = harness.runtime.handle().module_context();
    let fresh_task = tokio::spawn(async move { Box::new(fresh_plane).run(context).await });
    tokio::time::timeout(Duration::from_secs(5), fresh_handle.wait_ready()).await??;
    let fresh = must(fresh_handle.admit(""));
    let fresh_router = fresh.test_router();
    assert!(
        !Arc::ptr_eq(&old_router, &fresh_router),
        "restart creates a new in-memory route ledger"
    );
    assert_eq!(
        fresh_router
            .accounting(&old_backend)
            .unwrap_or_default()
            .active(),
        0,
        "no ghost owner crosses the restart"
    );
    drop(fresh);
    fresh_task.abort();
    let _ = fresh_task.await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn route_plane_concurrent_admission_and_namespace_removal_never_stalls_or_resurrects()
-> TestResult {
    const WORKERS: usize = 8;
    const CYCLES: u64 = 50;
    let harness = Harness::new("", "connection").await?;
    let (plane, mut handle) = RoutePlane::new(
        Arc::new(harness.source.clone()),
        harness.topology.clone(),
        None,
    );
    let context = harness.runtime.handle().module_context();
    let plane_task = tokio::spawn(async move { Box::new(plane).run(context).await });
    tokio::time::timeout(Duration::from_secs(5), handle.wait_ready()).await??;
    let original = must(handle.admit(""));

    let stop = Arc::new(AtomicBool::new(false));
    let successes = Arc::new(AtomicUsize::new(0));
    let failures = Arc::new(AtomicUsize::new(0));
    let barrier = Arc::new(std::sync::Barrier::new(WORKERS + 1));
    let mut workers = Vec::with_capacity(WORKERS);
    for _ in 0..WORKERS {
        let handle = handle.clone();
        let stop = Arc::clone(&stop);
        let successes = Arc::clone(&successes);
        let failures = Arc::clone(&failures);
        let barrier = Arc::clone(&barrier);
        workers.push(std::thread::spawn(move || {
            barrier.wait();
            while !stop.load(Ordering::Acquire) {
                match handle.admit("") {
                    Ok(admission) => {
                        assert_eq!(admission.namespace(), "default");
                        successes.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(_) => {
                        failures.fetch_add(1, Ordering::Relaxed);
                    }
                }
                std::thread::yield_now();
            }
        }));
    }
    barrier.wait();
    tokio::time::sleep(Duration::from_millis(5)).await;

    let effective = (**harness.source.store.current().effective()).clone();
    for cycle in 0..CYCLES {
        let remove_revision = 3 + cycle * 2;
        harness.source.store.apply(
            effective.clone(),
            Vec::new(),
            SourceRevision {
                file_revision: remove_revision,
                etcd_revision: 0,
            },
            Path::new("/tmp"),
        )?;
        harness.source.deliver();
        tokio::time::sleep(Duration::from_millis(1)).await;

        harness.source.store.apply(
            effective.clone(),
            vec![NamespaceConfig {
                namespace: "default".to_owned(),
                ..NamespaceConfig::default()
            }],
            SourceRevision {
                file_revision: remove_revision + 1,
                etcd_revision: 0,
            },
            Path::new("/tmp"),
        )?;
        harness.source.deliver();
        tokio::time::sleep(Duration::from_millis(1)).await;
    }

    let current = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if handle.current_incarnations() == 1
                && let Ok(current) = handle.admit("")
            {
                break current;
            }
            tokio::task::yield_now().await;
        }
    })
    .await?;
    assert!(
        !original.same_router_incarnation(&current),
        "remove/recreate with identical content must mint a fresh route owner"
    );
    stop.store(true, Ordering::Release);
    for worker in workers {
        worker
            .join()
            .unwrap_or_else(|_| unreachable!("admission worker must not panic"));
    }
    assert!(successes.load(Ordering::Relaxed) > 0);
    assert!(failures.load(Ordering::Relaxed) > 0);
    assert_eq!(handle.current_incarnations(), 1);

    drop(original);
    drop(current);

    plane_task.abort();
    let _ = plane_task.await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn route_plane_applies_reloadable_capacity_without_evicting_live_leases() -> TestResult {
    let harness = Harness::new("", "connection").await?;
    let (plane, mut handle) = RoutePlane::new(
        Arc::new(harness.source.clone()),
        harness.topology.clone(),
        None,
    );
    let context = harness.runtime.handle().module_context();
    let plane_task = tokio::spawn(async move { Box::new(plane).run(context).await });
    tokio::time::timeout(Duration::from_secs(5), handle.wait_ready()).await??;

    let mut first = must(handle.admit(""));
    let mut second = must(handle.admit(""));
    let router = first.test_router();
    let backend_id = "default/127.0.0.1:4000";
    for admission in [&mut first, &mut second] {
        let reservation = must(admission.selector_mut().next(ClientInfo::default(), ""));
        assert_eq!(reservation.assignment().backend_id, backend_id);
        assert_eq!(
            admission.selector().finish(&reservation, true),
            Settlement::Applied
        );
    }
    assert_eq!(
        router
            .accounting(backend_id)
            .map(super::ledger::Accounting::active),
        Some(2),
        "both established session leases remain charged before shrink"
    );
    let current = harness.source.store.current();
    let mut effective = (**current.effective()).clone();
    effective.apply_proxy_online(decode_proxy_online(br#"{"max-connections":1}"#)?);
    harness.source.store.apply(
        effective,
        current.namespaces().to_vec(),
        SourceRevision {
            file_revision: 3,
            etcd_revision: 0,
        },
        Path::new("/tmp"),
    )?;
    harness.source.deliver();

    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if matches!(handle.admit(""), Err(RouteError::Capacity)) {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await?;
    drop(first);
    assert_eq!(
        router
            .accounting(backend_id)
            .map(super::ledger::Accounting::active),
        Some(1),
        "dropping one session lease releases exactly one active owner"
    );
    assert!(
        matches!(handle.admit(""), Err(RouteError::Capacity)),
        "shrinking never evicts the second live lease and does not admit above the new limit"
    );
    drop(second);
    assert_eq!(
        router.accounting(backend_id).unwrap_or_default().active(),
        0,
        "normal teardown returns active accounting to the empty baseline"
    );
    let after_close = must(handle.admit(""));
    assert_eq!(after_close.namespace(), "default");
    drop(after_close);

    plane_task.abort();
    let _ = plane_task.await;
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
    let ungrouped = "default/127.0.0.1:4001";
    assert!(harness.router.lookup_backend(ungrouped).is_ok());
    assert!(matches!(
        harness.router.rehydrate(&b, ungrouped),
        Err(RouteError::NoBackend)
    ));
    assert_eq!(
        harness
            .router
            .accounting(ungrouped)
            .map(|c| (c.active(), c.reserved())),
        Some((0, 0))
    );
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
async fn routing_rule_update_only_affects_new_router_incarnations() -> TestResult {
    let backends = [
        ("127.0.0.1:4000", &[("cidr", "192.0.2.0/24")][..]),
        ("127.0.0.1:4001", &[("cidr", "198.51.100.0/24")][..]),
    ];
    let h = Harness::with_backends("client_cidr", "connection", &backends).await?;
    let old = h.ready().await;
    let client = ClientInfo {
        client_address: Some("192.0.2.9:8000"),
        proxy_address: Some("198.51.100.9:8000"),
    };
    let select = |router: &Router, candidate: &Candidate| {
        let session = must(router.open());
        let reservation = must(router.reserve(&session, candidate, client, "", &[]));
        let backend = reservation.assignment().backend_id.clone();
        router.finish(&reservation, false);
        router.close(&session);
        backend
    };
    assert_eq!(select(&h.router, &old), "default/127.0.0.1:4000");
    h.patch("[balance]\nrouting-rule = 'proxy_cidr'\n", 3);
    h.source.deliver();
    h.applied().await;
    let updated = h.ready().await;
    assert_eq!(select(&h.router, &updated), "default/127.0.0.1:4000");
    // Recreating all groups inside the same router must also use its Init rule.
    h.fixture.backends(&[]);
    let empty = h.changed_r(&updated).await;
    let session = must(h.router.open());
    assert!(matches!(
        h.router.reserve(&session, &empty, client, "", &[]),
        Err(RouteError::NoBackend)
    ));
    h.router.close(&session);
    h.fixture.backends(&backends);
    let restored = h.changed_r(&empty).await;
    assert_eq!(select(&h.router, &restored), "default/127.0.0.1:4000");
    let replacement = must(Router::new(
        Arc::new(h.source.clone()),
        &h.topology,
        &h.runtime.handle().module_context(),
        "default",
        10,
    ));
    let new = must(replacement.capture());
    assert_eq!(select(&replacement, &new), "default/127.0.0.1:4001");
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

/// Pending migrations summed over every incarnation the plane still holds.
fn pending_total(handle: &crate::RoutePlaneHandle) -> u64 {
    handle.migration_snapshot().pending.values().sum()
}

/// Replaces the `default` namespace so the current incarnation is retired,
/// while any live admission lease keeps the old one alive.
fn retire_namespace(harness: &Harness, file_revision: u64) -> TestResult {
    let current = harness.source.store.current();
    let mut replacement = NamespaceConfig {
        namespace: "default".to_owned(),
        ..NamespaceConfig::default()
    };
    replacement.frontend.user = "replacement".to_owned();
    harness.source.store.apply(
        (**current.effective()).clone(),
        vec![replacement],
        SourceRevision {
            file_revision,
            etcd_revision: 0,
        },
        Path::new("/tmp"),
    )?;
    harness.source.deliver();
    Ok(())
}

/// Two incarnations migrating between the same backends for the same reason
/// share one `(from, to, reason)` label set. The exposition has to add them
/// up; a per-router write would have one silently replace the other.
///
/// The first incarnation is retired by configuration while its migration is
/// still in flight, and is kept alive only by its admission lease. That is the
/// case enumerating the plane's current routing table would miss, and it is
/// also why the migration has to be started before the retirement: a retired
/// incarnation no longer runs balance rounds, so it can hold an unsettled
/// migration but cannot begin a new one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn migration_snapshot_sums_shared_labels_across_a_retired_incarnation() -> TestResult {
    let harness = Harness::with_backends(
        "",
        "connection",
        &[("127.0.0.1:4000", &[]), ("127.0.0.1:4001", &[])],
    )
    .await?;
    let (plane, mut handle) = RoutePlane::new(
        Arc::new(harness.source.clone()),
        harness.topology.clone(),
        None,
    );
    let context = harness.runtime.handle().module_context();
    let plane_task = tokio::spawn(async move { Box::new(plane).run(context).await });
    tokio::time::timeout(Duration::from_secs(5), handle.wait_ready()).await??;

    let mut first = must(handle.admit(""));
    let reservation = must(first.selector_mut().next(ClientInfo::default(), ""));
    let old_address = reservation.assignment().backend_address.clone();
    assert_eq!(
        first.selector().finish(&reservation, true),
        Settlement::Applied
    );
    let (first_registration, mut first_commands) = must(first.register_commands(13101, 2));

    let failed = format!(
        "[proxy]\nfail-backend-list=[\"{old_address}\"]\nfailover-timeout=60\n[balance.status]\nmigrations-per-second=100"
    );
    harness.patch(&failed, 3);
    harness.source.deliver();
    let first_command = tokio::time::timeout(Duration::from_secs(5), first_commands.recv())
        .await?
        .ok_or("first incarnation issued no redirect")?;
    assert!(matches!(
        first_command.command(),
        crate::MigrationCommand::Redirect(_)
    ));
    // Deliberately unsettled: this migration must still be counted after its
    // router stops being the routed one.
    assert_eq!(pending_total(&handle), 1);

    // Fail the OTHER backend instead, so the next incarnation is forced to
    // start on the same one the first did and therefore shares its label set.
    // Which backend a reservation lands on is not fixed by the fixture, so the
    // pairing has to be forced rather than assumed.
    let other_address = if old_address == "127.0.0.1:4000" {
        "127.0.0.1:4001"
    } else {
        "127.0.0.1:4000"
    };
    let other_failed = format!(
        "[proxy]\nfail-backend-list=[\"{other_address}\"]\nfailover-timeout=60\n[balance.status]\nmigrations-per-second=100"
    );
    harness.patch(&other_failed, 4);
    harness.source.deliver();

    // Retire the first incarnation; its admission lease keeps it alive.
    retire_namespace(&harness, 5)?;
    let mut second = must(
        tokio::time::timeout(
            Duration::from_secs(5),
            handle.admit_within("replacement", Duration::from_secs(5)),
        )
        .await?,
    );
    assert!(!first.same_router_incarnation(&second));
    assert_eq!(
        pending_total(&handle),
        1,
        "a retired incarnation still holding an unsettled migration must keep counting"
    );

    let reservation = must(second.selector_mut().next(ClientInfo::default(), ""));
    assert_eq!(
        reservation.assignment().backend_address,
        old_address,
        "the replacement must start on the same backend to share the label set"
    );
    assert_eq!(
        second.selector().finish(&reservation, true),
        Settlement::Applied
    );
    let (second_registration, mut second_commands) = must(second.register_commands(13102, 2));

    harness.patch(&failed, 6);
    harness.source.deliver();
    let second_command = tokio::time::timeout(Duration::from_secs(5), second_commands.recv())
        .await?
        .ok_or("replacement incarnation issued no redirect")?;
    assert!(matches!(
        second_command.command(),
        crate::MigrationCommand::Redirect(_)
    ));

    let snapshot = handle.migration_snapshot();
    assert_eq!(
        snapshot.pending.len(),
        1,
        "one shared label set, not one series per router"
    );
    assert_eq!(
        snapshot.pending.values().sum::<u64>(),
        2,
        "both incarnations are in flight; a per-router write would report 1"
    );

    drop(first_command);
    drop(second_command);
    drop(first_registration);
    drop(second_registration);
    drop(first);
    drop(second);
    plane_task.abort();
    let _ = plane_task.await;
    Ok(())
}

/// Cumulative history must be readable when no incarnation is alive at all.
/// Reaching it through a live router made every counter vanish the moment the
/// last one was dropped -- the same disappearance the process-level store
/// exists to prevent, reintroduced one layer up.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn migration_history_survives_every_incarnation_being_dropped() -> TestResult {
    let harness = Harness::with_backends(
        "",
        "connection",
        &[("127.0.0.1:4000", &[]), ("127.0.0.1:4001", &[])],
    )
    .await?;
    let (plane, mut handle) = RoutePlane::new(
        Arc::new(harness.source.clone()),
        harness.topology.clone(),
        None,
    );
    let context = harness.runtime.handle().module_context();
    let plane_task = tokio::spawn(async move { Box::new(plane).run(context).await });
    tokio::time::timeout(Duration::from_secs(5), handle.wait_ready()).await??;

    let mut admission = must(handle.admit(""));
    let reservation = must(admission.selector_mut().next(ClientInfo::default(), ""));
    let old_address = reservation.assignment().backend_address.clone();
    assert_eq!(
        admission.selector().finish(&reservation, true),
        Settlement::Applied
    );
    let (registration, mut commands) = must(admission.register_commands(13201, 2));
    harness.patch(
        &format!(
            "[proxy]\nfail-backend-list=[\"{old_address}\"]\nfailover-timeout=60\n[balance.status]\nmigrations-per-second=100"
        ),
        3,
    );
    harness.source.deliver();
    let envelope = tokio::time::timeout(Duration::from_secs(5), commands.recv())
        .await?
        .ok_or("no redirect issued")?;
    assert_eq!(envelope.finish_redirect(true), Settlement::Applied);
    let settled: u64 = handle.migration_snapshot().history.terminals.values().sum();
    assert_eq!(settled, 1);

    // Drop everything that could hold an incarnation alive.
    drop(registration);
    drop(admission);
    drop(commands);
    plane_task.abort();
    let _ = plane_task.await;

    assert_eq!(
        handle
            .migration_snapshot()
            .history
            .terminals
            .values()
            .sum::<u64>(),
        1,
        "the cumulative series must not disappear with the last router"
    );
    Ok(())
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn review_pull_history_survives_zero_live_routers() -> TestResult {
    let harness = Harness::new("", "connection").await?;
    let (plane, mut handle) = RoutePlane::new(
        Arc::new(harness.source.clone()),
        harness.topology.clone(),
        None,
    );
    let context = harness.runtime.handle().module_context();
    let plane_task = tokio::spawn(async move { Box::new(plane).run(context).await });
    tokio::time::timeout(Duration::from_secs(5), handle.wait_ready()).await??;
    let admission = must(handle.admit(""));
    admission.test_router().review_seed_settled_migrations(0, 1);
    assert_eq!(
        handle
            .migration_snapshot()
            .history
            .terminals
            .values()
            .sum::<u64>(),
        1
    );
    drop(admission);
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
    harness.source.deliver();
    tokio::time::timeout(Duration::from_secs(5), async {
        while handle.route_ledger_evidence().router_incarnations != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    let after = handle.migration_snapshot();
    plane_task.abort();
    let _ = plane_task.await;
    assert_eq!(
        after.history.terminals.values().sum::<u64>(),
        1,
        "the actual scrape source must retain cumulative terminals with zero live routers"
    );
    assert_eq!(
        after
            .history
            .durations
            .values()
            .map(|v| v.count)
            .sum::<u64>(),
        1
    );
    assert_eq!(after.history.known_pending.len(), 1);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn review_pull_pending_union_is_globally_bounded() -> TestResult {
    let harness = Harness::new("", "connection").await?;
    let (plane, mut handle) = RoutePlane::new(
        Arc::new(harness.source.clone()),
        harness.topology.clone(),
        None,
    );
    let context = harness.runtime.handle().module_context();
    let plane_task = tokio::spawn(async move { Box::new(plane).run(context).await });
    tokio::time::timeout(Duration::from_secs(5), handle.wait_ready()).await??;
    let first = must(handle.admit(""));
    first
        .test_router()
        .review_seed_settled_migrations(0, crate::MAX_RETAINED_LABEL_SETS);
    retire_namespace(&harness, 3)?;
    let second = must(
        handle
            .admit_within("replacement", Duration::from_secs(5))
            .await,
    );
    assert!(!first.same_router_incarnation(&second));
    second
        .test_router()
        .review_seed_settled_migrations(crate::MAX_RETAINED_LABEL_SETS, 1);
    assert_eq!(handle.route_ledger_evidence().router_incarnations, 2);
    let state = handle.migration_snapshot();
    let entries = state.pending.len();
    assert_eq!(
        state.history.known_pending.len(),
        crate::MAX_RETAINED_LABEL_SETS
    );
    assert!(state.history.labels_dropped > 0);
    drop(first);
    drop(second);
    plane_task.abort();
    let _ = plane_task.await;
    assert!(
        entries <= crate::MAX_RETAINED_LABEL_SETS,
        "actual pull-side aggregate has {entries} entries, beyond global {} bound",
        crate::MAX_RETAINED_LABEL_SETS
    );
    Ok(())
}

/// The Rust side of the `b_conn` deviation recorded as MTR-007.
///
/// Two incarnations each holding one connection to the same backend address
/// report 2 here, because the address label is meant to say how many
/// connections this process holds. Go reports 1 for the same situation: it
/// writes the gauge with Set from each namespace's own router, so the last
/// writer decides. `pkg/metrics` `TestBackendConnGaugeOverwritesAcrossNamespaces`
/// pins that side. The difference is declared, so it is asserted on both
/// sides rather than left to the manifest text.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn migration_snapshot_sums_shared_backend_address() -> TestResult {
    let harness = Harness::with_backends(
        "",
        "connection",
        &[("127.0.0.1:4000", &[]), ("127.0.0.1:4001", &[])],
    )
    .await?;
    let (plane, mut handle) = RoutePlane::new(
        Arc::new(harness.source.clone()),
        harness.topology.clone(),
        None,
    );
    let context = harness.runtime.handle().module_context();
    let plane_task = tokio::spawn(async move { Box::new(plane).run(context).await });
    tokio::time::timeout(Duration::from_secs(5), handle.wait_ready()).await??;

    let mut first = must(handle.admit(""));
    let reservation = must(first.selector_mut().next(ClientInfo::default(), ""));
    let shared = reservation.assignment().backend_address.clone();
    assert_eq!(
        first.selector().finish(&reservation, true),
        Settlement::Applied
    );

    // Force the second incarnation onto the same backend by failing the other
    // one. Which backend a reservation lands on is not fixed by the fixture,
    // and the balancer will otherwise steer the second away from the one the
    // first is already using -- so the shared case has to be arranged, never
    // assumed.
    let other = if shared == "127.0.0.1:4000" {
        "127.0.0.1:4001"
    } else {
        "127.0.0.1:4000"
    };
    harness.patch(
        &format!("[proxy]\nfail-backend-list=[\"{other}\"]\nfailover-timeout=60"),
        3,
    );
    harness.source.deliver();

    // Retire the namespace; `first` keeps its incarnation alive.
    retire_namespace(&harness, 4)?;
    let mut second = must(
        tokio::time::timeout(
            Duration::from_secs(5),
            handle.admit_within("replacement", Duration::from_secs(5)),
        )
        .await?,
    );
    assert!(!first.same_router_incarnation(&second));
    let reservation = must(second.selector_mut().next(ClientInfo::default(), ""));
    assert_eq!(
        reservation.assignment().backend_address,
        shared,
        "both incarnations must hold the same address for this to be the shared case"
    );
    assert_eq!(
        second.selector().finish(&reservation, true),
        Settlement::Applied
    );

    let snapshot = handle.migration_snapshot();
    assert_eq!(
        snapshot.backend_connections.get(&shared).copied(),
        Some(2),
        "Rust reports the process total; Go would report 1 here (MTR-007)"
    );

    drop(first);
    drop(second);
    plane_task.abort();
    let _ = plane_task.await;
    Ok(())
}

#[tokio::test]
async fn review_bscore_first_real_route_scoring_publishes() -> TestResult {
    let h = Harness::with_health(
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
    let resolved = crate::ResolvedNamespace::named(h.source.current(), "default")
        .map_err(|e| format!("{e:?}"))?;
    let scores = Arc::new(crate::ScoreHistory::new());
    let router = Router::new_resolved(
        Arc::new(h.source.clone()),
        &h.topology,
        &h.runtime.handle().module_context(),
        &resolved,
        16,
        None,
        crate::selector::RouterShared {
            scores: Arc::clone(&scores),
            backend_metrics: Arc::new(crate::BackendMetricHistory::new()),
            input_diagnostics: Arc::new(crate::plane::RouteInputDiagnostics::default()),
            history: Arc::new(crate::MigrationHistory::default()),
        },
    )
    .map_err(|e| format!("{e:?}"))?;
    router.set_replay_wall(1_000_000_000_000);
    let candidate = router.capture().map_err(|e| format!("{e:?}"))?;
    let session = router.open().map_err(|e| format!("{e:?}"))?;
    let reservation = router
        .reserve_with_ticket(&session, &candidate, ClientInfo::default(), "", &[], 0)
        .map_err(|e| format!("{e:?}"))?;
    let _ = router.finish(&reservation, false);
    let _ = router.close(&session);
    let published = scores.snapshot().scores;
    println!("scores after successful real route evaluation: {published:?}");
    assert!(
        published.contains_key(&(
            "127.0.0.1:4000".to_owned(),
            crate::factors::Factor::Connection,
        )),
        "Go BackendToRoute calls updateScore; the first real route scoring must publish"
    );
    Ok(())
}

#[tokio::test]
async fn review_bscore_real_plane_config_reset_without_further_scoring() -> TestResult {
    let h = Harness::with_health(
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
    let (plane, mut handle) = RoutePlane::new(Arc::new(h.source.clone()), h.topology.clone(), None);
    let context = h.runtime.handle().module_context();
    let task = tokio::spawn(async move { Box::new(plane).run(context).await });
    let observed = async {
        tokio::time::timeout(Duration::from_secs(5), handle.wait_ready()).await??;
        let mut admission = must(handle.admit(""));
        let mut updates = admission.subscribe_updates();
        let reservation = must(admission.selector_mut().next(ClientInfo::default(), ""));
        let _ = admission.selector().finish(&reservation, false);
        drop(admission);
        let scores = handle.score_history();
        let initial = scores.snapshot().scores;
        assert!(!initial.is_empty(), "real route must have produced scores before reset");
        updates.borrow_and_update();
        let old = h.source.current().generation();
        h.patch("[balance]\npolicy=\"resource\"", 2);
        let new = h.source.current().generation();
        assert_ne!(old, new);
        h.source.deliver();
        tokio::time::timeout(Duration::from_secs(5), updates.changed()).await??;
        let after = scores.snapshot().scores;
        println!("real config reconciliation completed generation {old}->{new}, before={initial:?}, after={after:?}");
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(after)
    }.await;
    task.abort();
    let _ = task.await;
    assert!(
        observed?.is_empty(),
        "Go SetConfig resets b_score on configuration, without requiring another updateScore"
    );
    Ok(())
}

#[tokio::test]
async fn review_bscore_real_plane_reset_preserves_cadence() -> TestResult {
    let h = Harness::with_health(
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
    let (plane, mut handle) = RoutePlane::new(Arc::new(h.source.clone()), h.topology.clone(), None);
    let context = h.runtime.handle().module_context();
    let task = tokio::spawn(async move { Box::new(plane).run(context).await });
    let observed = async {
        tokio::time::timeout(Duration::from_secs(5), handle.wait_ready()).await??;
        let mut admission = must(handle.admit(""));
        let mut updates = admission.subscribe_updates();
        let router = admission.test_router();
        router.set_replay_wall(1_000_000_000_000);
        let reservation = must(admission.selector_mut().next(ClientInfo::default(), ""));
        let _ = admission.selector().finish(&reservation, false);
        drop(admission);
        let scores = handle.score_history();
        let initial = scores.snapshot().scores;
        assert!(!initial.is_empty(), "real route must have produced scores before reset");
        updates.borrow_and_update();
        let old = h.source.current().generation();
        h.patch("[balance]\npolicy=\"connection\"\nrouting-policy=\"random\"", 2);
        let new = h.source.current().generation();
        assert_ne!(old, new);
        h.source.deliver();
        tokio::time::timeout(Duration::from_secs(5), updates.changed()).await??;
        let after = scores.snapshot().scores;
        println!("real config reconciliation completed generation {old}->{new}, before={initial:?}, after={after:?}");
        assert!(after.is_empty(), "configuration reset must already be visible");
        let mut admission = must(handle.admit(""));
        router.set_replay_wall(1_000_000_000_001);
        let reservation = must(admission.selector_mut().next(ClientInfo::default(), ""));
        let _ = admission.selector().finish(&reservation, false);
        drop(admission);
        assert!(scores.snapshot().scores.is_empty(), "reset must not grant an early write");
        router.set_replay_wall(1_010_000_000_001);
        let mut admission = must(handle.admit(""));
        let reservation = must(admission.selector_mut().next(ClientInfo::default(), ""));
        let _ = admission.selector().finish(&reservation, false);
        drop(admission);
        let resumed = scores.snapshot().scores;
        println!("after reset: T+1ns remains empty; T+10s+1ns publishes {resumed:?}");
        assert!(!resumed.is_empty(), "normal original cadence must resume");
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(after)
    }.await;
    task.abort();
    let _ = task.await;
    assert!(
        observed?.is_empty(),
        "Go SetConfig resets b_score on configuration, without requiring another updateScore"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::too_many_lines)] // Two real paths end to end; splitting would hide the ordering.
async fn review_step5_real_router_revocation_refuses_both_metrics_and_throttle() -> TestResult {
    for balance in [false, true] {
        let h = Harness::with_health(
            "",
            "resource",
            &[("127.0.0.1:4000", &[]), ("127.0.0.1:4001", &[])],
            HealthCheckConfig {
                enabled: false,
                interval_nanos: 3_600_000_000_000,
                ..HealthCheckConfig::default()
            },
            "",
        )
        .await?;
        tokio::time::timeout(Duration::from_secs(5), async {
            while h.topology.routing_handle().current().is_none() {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        let mut metrics = h
            .topology
            .replay_metric_input(h.runtime.handle().module_context().owner().clone())
            .await?;
        let sample = |now: i64, value: &str| {
            serde_json::json!({
                "cpu": {"kind":"matrix", "updated_nanos":now, "series":[{
                    "labels":{"instance":"127.0.0.1:0"}, "samples":[
                        {"timestamp_ms":now/1_000_000-1000, "value":value},
                        {"timestamp_ms":now/1_000_000, "value":value}]}]},
                "memory":null,"failure_pd":null,"total_pd":null,"failure_tikv":null,"total_tikv":null
            })
        };
        let t0 = 1_000_000_000_000_i64;
        metrics.deliver(sample(t0, "0.4"))?;
        let scores = Arc::new(crate::ScoreHistory::new());
        let observations = Arc::new(crate::BackendMetricHistory::new());
        let resolved = must(crate::ResolvedNamespace::named(
            h.source.current(),
            "default",
        ));
        let router = Arc::new(must(Router::new_resolved(
            Arc::new(h.source.clone()),
            &h.topology,
            &h.runtime.handle().module_context(),
            &resolved,
            16,
            Some(metrics.handle()),
            crate::selector::RouterShared {
                scores: Arc::clone(&scores),
                backend_metrics: Arc::clone(&observations),
                input_diagnostics: Arc::new(crate::plane::RouteInputDiagnostics::default()),
                history: Arc::new(crate::MigrationHistory::default()),
            },
        )));
        let score_round = |router: &Router, candidate: &Candidate| -> Result<(), RouteError> {
            if balance {
                router
                    .prepare_balance(candidate, ClientInfo::default(), "")
                    .map(|_| ())
            } else {
                let session = router.open()?;
                let reserved = router.reserve_with_ticket(
                    &session,
                    candidate,
                    ClientInfo::default(),
                    "",
                    &[],
                    0,
                );
                if let Ok(ref reservation) = reserved {
                    router.finish(reservation, false);
                }
                router.close(&session);
                reserved.map(|_| ())
            }
        };
        router.set_replay_wall(t0);
        let first = must(router.capture());
        assert!(matches!(
            first.metrics,
            crate::authority::MetricInputs::Dynamic(Some(_))
        ));
        must(score_round(&router, &first));
        let key = ("127.0.0.1:4000".to_owned(), crate::BackendMetric::Cpu);
        assert_eq!(observations.snapshot().values.get(&key).copied(), Some(0.4));
        let before = scores.snapshot().scores;
        assert!(!before.is_empty());
        assert_eq!(router.review_last_score_metric(), Some(t0));

        let refused_time = t0 + 11_000_000_000;
        metrics.deliver(sample(refused_time, "0.9"))?;
        router.set_replay_wall(refused_time);
        let candidate = must(router.capture());
        assert!(matches!(
            candidate.metrics,
            crate::authority::MetricInputs::Dynamic(Some(_))
        ));
        let (evaluated, release) = router.review_hold_before_metric_commit();
        let worker_router = Arc::clone(&router);
        let worker = std::thread::spawn(move || {
            if balance {
                worker_router
                    .prepare_balance(&candidate, ClientInfo::default(), "")
                    .map(|_| ())
            } else {
                let session = worker_router.open()?;
                let result = worker_router.reserve_with_ticket(
                    &session,
                    &candidate,
                    ClientInfo::default(),
                    "",
                    &[],
                    0,
                );
                if let Ok(ref reservation) = result {
                    worker_router.finish(reservation, false);
                }
                worker_router.close(&session);
                result.map(|_| ())
            }
        });
        evaluated.recv_timeout(Duration::from_secs(5))?;
        // Real accepted C publication, after evaluation but before authority acquisition.
        // It preserves routing and resource inputs; no synthetic permit or fake source.
        let old = h.source.current().generation();
        h.patch("[proxy]\nfailover-timeout=61", 3);
        assert_ne!(h.source.current().generation(), old);
        release.send(())?;
        let result = worker.join().map_err(|_| "review worker panicked")?;
        assert_eq!(result, Err(RouteError::StaleCandidate));
        println!(
            "path={} real C revocation: result={result:?}, cpu={:?}, last_score={:?}",
            if balance { "balance" } else { "route" },
            observations.snapshot().values.get(&key),
            router.review_last_score_metric()
        );
        assert_eq!(
            observations.snapshot().values.get(&key).copied(),
            Some(0.4),
            "refused evaluated 0.9 must not publish"
        );
        assert_eq!(
            scores.snapshot().scores,
            before,
            "refused round must not publish scores"
        );
        assert_eq!(
            router.review_last_score_metric(),
            Some(t0),
            "refused round must not advance throttle"
        );

        let accepted_time = refused_time + 1_000_000;
        metrics.deliver(sample(accepted_time, "0.2"))?;
        router.set_replay_wall(accepted_time);
        let fresh = must(router.capture());
        assert!(matches!(
            fresh.metrics,
            crate::authority::MetricInputs::Dynamic(Some(_))
        ));
        must(score_round(&router, &fresh));
        assert_eq!(observations.snapshot().values.get(&key).copied(), Some(0.2));
        assert_eq!(
            router.review_last_score_metric(),
            Some(accepted_time),
            "accepted round 1ms later must not inherit refused throttle"
        );
        println!(
            "path={} accepted next round: cpu=0.2, last_score={accepted_time}",
            if balance { "balance" } else { "route" }
        );
    }
    Ok(())
}
