// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

//! CP-ROUTE 220-3 B2 rows on the REAL `TopologyModule` with real loopback SQL
//! greeters (real clock: the rounds are real loopback I/O).

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use control_config::{
    ConfigNamespaceSnapshot, ConfigNamespaceSource, ConfigNamespaceStore, HealthCheckConfig,
    NamespaceConfig, SourceRevision, TopologyRuntimeIdentity,
};
use control_external::GenerationGate;
use control_external::{EtcdClientConfig, EtcdConnector};
use control_plane::{
    ControlConfig, ControlModule, ControlRuntime, EventSink, LogLevel, MetricsPolicy, OwnerScope,
    OwnershipRegistry, RuntimeEvent, TlsPolicy,
};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::sync::{Notify, Semaphore, watch};

use super::{BackendSourceHandle, BackendSourceMode, BackendSourceSnapshot, ModePublisher};
use crate::discovery_publish::EpochResult;
use crate::health_overlay::HealthOverlayPublisher;
use crate::merge::MergedTopology;
use crate::module::tests::kv_fixture::{FixtureFactory, spawn_fixture};
use crate::module::{ChildRunner, TopologyClientFactory, TopologyClusterClient, TopologyModule};
use crate::resolver::StaticAdvertiseResolver;
use crate::routing_snapshot::RoutingSnapshotPublisher;
use crate::static_source::{RegisteredProducer, StaticRegistry};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct NullSink;
impl EventSink for NullSink {
    fn record(&self, _event: &RuntimeEvent) {}
}

/// What a greeter answers each accepted connection with.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Greeting {
    /// A protocol-10 greeting: healthy.
    V10,
    /// An ERR packet: unhealthy after the retry budget.
    Err,
}

/// A real loopback SQL greeter. Every accepted connection takes one permit
/// before answering, so a row can HOLD a producer's round in flight.
struct Greeter {
    address: String,
    permits: Arc<Semaphore>,
    accepted: watch::Receiver<usize>,
    greeting: Arc<Mutex<Greeting>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Greeter {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Greeter {
    async fn spawn(greeting: Greeting, held: bool) -> TestResult<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?.to_string();
        let permits = Arc::new(Semaphore::new(if held {
            0
        } else {
            Semaphore::MAX_PERMITS
        }));
        let release = Arc::clone(&permits);
        let (accepted_tx, accepted) = watch::channel(0usize);
        let greeting = Arc::new(Mutex::new(greeting));
        let current = Arc::clone(&greeting);
        let task = tokio::spawn(async move {
            // Accept never blocks on a held connection: each connection waits for
            // its own permit in its own task, so several producers can be held.
            while let Ok((mut stream, _)) = listener.accept().await {
                accepted_tx.send_modify(|count| *count += 1);
                let release = Arc::clone(&release);
                let current = Arc::clone(&current);
                tokio::spawn(async move {
                    let Ok(permit) = release.acquire().await else {
                        return;
                    };
                    permit.forget();
                    let packet: &[u8] =
                        match *current.lock().unwrap_or_else(PoisonError::into_inner) {
                            Greeting::V10 => &[3, 0, 0, 0, 0x0a, b'8', 0],
                            Greeting::Err => &[3, 0, 0, 0, 0xff, 0x15, 0x04],
                        };
                    let _ = stream.write_all(packet).await;
                });
            }
        });
        Ok(Self {
            address,
            permits,
            accepted,
            greeting,
            task,
        })
    }

    fn accepted(&self) -> usize {
        *self.accepted.borrow()
    }

    fn set(&self, greeting: Greeting) {
        *self.greeting.lock().unwrap_or_else(PoisonError::into_inner) = greeting;
    }

    fn release(&self, count: usize) {
        self.permits.add_permits(count);
    }

    async fn wait_accepted(&mut self, at_least: usize) -> TestResult {
        tokio::time::timeout(
            Duration::from_secs(10),
            self.accepted.wait_for(|count| *count >= at_least),
        )
        .await??;
        Ok(())
    }
}

/// A factory with no clusters (Static mode) or one cluster (Dynamic mode),
/// switchable per generation, and a reject switch (`ClientBuildFailed`).
struct Factory {
    reject: Arc<AtomicBool>,
}

impl TopologyClientFactory for Factory {
    fn build(
        &self,
        snapshot: &ConfigNamespaceSnapshot,
    ) -> Result<Vec<TopologyClusterClient>, String> {
        if self.reject.load(Ordering::SeqCst) {
            return Err("rejected by the row".to_owned());
        }
        let topology = snapshot.topology().map_err(|error| format!("{error:?}"))?;
        topology
            .backend_clusters
            .iter()
            .map(|cluster| {
                Ok(TopologyClusterClient {
                    cluster_name: Arc::clone(&cluster.name),
                    client: EtcdClientConfig::new(vec!["127.0.0.1:1".to_owned()], None)
                        .map_err(|error| format!("{error:?}"))?,
                })
            })
            .collect()
    }
}

fn zero_cluster_config() -> Vec<u8> {
    b"\n[proxy]\naddr = \"0.0.0.0:6000\"\npd-addrs = \"\"\n\n[api]\naddr = \"0.0.0.0:10080\"\n"
        .to_vec()
}

fn one_cluster_config() -> Vec<u8> {
    b"\n[proxy]\naddr = \"0.0.0.0:6000\"\npd-addrs = \"\"\n\n[api]\naddr = \"0.0.0.0:10080\"\n\n[[proxy.backend-clusters]]\nname = \"cluster-a\"\npd-addrs = \"pd-a:2379\"\nns-servers = []\n"
        .to_vec()
}

fn namespace(name: &str, instances: &[&str]) -> NamespaceConfig {
    let mut config = NamespaceConfig {
        namespace: name.to_owned(),
        ..NamespaceConfig::default()
    };
    config.backend.instances = instances.iter().map(|s| (*s).to_owned()).collect();
    config
}

fn store_with(config: &[u8], namespaces: Vec<NamespaceConfig>) -> TestResult<ConfigNamespaceStore> {
    let store = ConfigNamespaceStore::from_toml(config, None, Path::new("/tmp"))?;
    apply(&store, config, namespaces, 2)?;
    Ok(store)
}

/// Applies `config` (full TOML) plus `namespaces` as revision `revision`.
fn apply(
    store: &ConfigNamespaceStore,
    config: &[u8],
    namespaces: Vec<NamespaceConfig>,
    revision: u64,
) -> TestResult {
    // Parse the full TOML through a scratch store to obtain its effective view,
    // then apply that view with the namespaces atomically.
    let scratch = ConfigNamespaceStore::from_toml(config, None, Path::new("/tmp"))?;
    let effective = (**scratch.current().effective()).clone();
    store.apply(
        effective,
        namespaces,
        SourceRevision {
            file_revision: revision,
            etcd_revision: 0,
        },
        Path::new("/tmp"),
    )?;
    Ok(())
}

fn health(enabled: bool) -> HealthCheckConfig {
    HealthCheckConfig {
        enabled,
        interval_nanos: 50_000_000,
        max_retries: 0,
        retry_interval_nanos: 10_000_000,
        // Long enough that a HELD greeting keeps its round in flight for a row.
        dial_timeout_nanos: 15_000_000_000,
        ..HealthCheckConfig::default()
    }
}

struct Module {
    handle: crate::module::TopologyModuleHandle,
    task: tokio::task::JoinHandle<Result<(), control_plane::ModuleError>>,
    _runtime: ControlRuntime,
    reject: Arc<AtomicBool>,
    spawned_children: Arc<AtomicUsize>,
}

impl Drop for Module {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn spawn_module(
    store: ConfigNamespaceStore,
    health: HealthCheckConfig,
) -> TestResult<Module> {
    let reject = Arc::new(AtomicBool::new(false));
    let spawned_children = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&spawned_children);
    let runner: ChildRunner = Arc::new(move |_owner, _connector, _info, _timeout, mut shutdown| {
        counter.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            let _ = shutdown.changed().await;
            Ok(())
        })
    });
    spawn_module_with(
        store,
        health,
        Box::new(Factory {
            reject: Arc::clone(&reject),
        }),
        runner,
        reject,
        spawned_children,
    )
    .await
}

async fn spawn_module_with(
    store: ConfigNamespaceStore,
    health: HealthCheckConfig,
    factory: Box<dyn TopologyClientFactory>,
    runner: ChildRunner,
    reject: Arc<AtomicBool>,
    spawned_children: Arc<AtomicUsize>,
) -> TestResult<Module> {
    let registry = Box::leak(Box::new(OwnershipRegistry::new()));
    let runtime = ControlRuntime::claim_process(
        registry,
        "cproute-static-source",
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
    let source: Arc<dyn ConfigNamespaceSource> = Arc::new(store);
    let (module, mut handle) = TopologyModule::new_with_child_runner_and_connector(
        source,
        factory,
        Arc::new(StaticAdvertiseResolver::new("10.0.0.1")),
        TopologyRuntimeIdentity {
            version: Arc::from("v-test"),
            git_hash: Arc::from("hash-test"),
            deploy_path: PathBuf::from("/deploy/test"),
            start_timestamp: 1_700_000_000,
        },
        health,
        runner,
        Arc::new(|owner, client| {
            Box::pin(async move { EtcdConnector::new(owner, client).connect().await })
        }),
    )?;
    let context = runtime.handle().module_context();
    runtime.mark_ready()?;
    let task = tokio::spawn(Box::new(module).run(context));
    handle.wait_ready().await?;
    Ok(Module {
        handle,
        task,
        _runtime: runtime,
        reject,
        spawned_children,
    })
}

async fn wait_applied(module: &Module, generation: u64) -> TestResult {
    let mut status = module.handle.status();
    tokio::time::timeout(Duration::from_secs(10), async {
        while status.borrow_and_update().observed_generation < generation {
            if status.changed().await.is_err() {
                break;
            }
        }
    })
    .await?;
    Ok(())
}

async fn wait_handle(module: &Module, namespace: &str) -> TestResult<BackendSourceHandle> {
    Ok(tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Some(handle) = module.handle.backend_source(namespace) {
                break handle;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await?)
}

async fn wait_snapshot(
    handle: &BackendSourceHandle,
    accept: impl Fn(&BackendSourceSnapshot) -> bool,
) -> TestResult<BackendSourceSnapshot> {
    Ok(tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Some(snapshot) = handle.current()
                && accept(&snapshot)
            {
                break snapshot;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await?)
}

async fn settle(duration: Duration) {
    tokio::time::sleep(duration).await;
}

// ================================================================
// S1: a zero-cluster config serves each namespace's static list with a REAL
// greeting verdict through the default network; ids are the raw addresses.
// ================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_zero_cluster_config_serves_static_backends_with_real_greeting_health() -> TestResult {
    let live = Greeter::spawn(Greeting::V10, false).await?;
    let failing = Greeter::spawn(Greeting::Err, false).await?;
    let duplicate = live.address.clone();
    let store = store_with(
        &zero_cluster_config(),
        vec![namespace(
            "default",
            &[&live.address, &failing.address, &duplicate],
        )],
    )?;
    let module = spawn_module(store, health(true)).await?;
    let handle = wait_handle(&module, "default").await?;
    let snapshot = wait_snapshot(&handle, |s| {
        s.health().get(&live.address).healthy && !s.health().get(&failing.address).healthy
    })
    .await?;
    assert_eq!(snapshot.mode(), BackendSourceMode::Static);
    let ids: Vec<&str> = snapshot
        .routing()
        .backends
        .backends
        .iter()
        .map(|b| b.backend_id.as_ref())
        .collect();
    assert_eq!(
        ids,
        vec![live.address.as_str(), failing.address.as_str()],
        "raw-address identity, duplicates collapsed, configured order"
    );
    for backend in &snapshot.routing().backends.backends {
        assert_eq!(
            backend.cluster_name.as_ref(),
            "",
            "Go static ClusterName is empty"
        );
        assert_eq!(backend.backend.addr, backend.backend_id.as_ref());
        assert!(
            backend.backend.ip.is_empty(),
            "no status stage for a static backend"
        );
    }
    assert!(
        snapshot.health().get(&live.address).local,
        "no proxy zone: an enabled round marks the static backend local"
    );
    assert!(handle.still_current(&snapshot));
    assert!(
        live.accepted() >= 1 && failing.accepted() >= 1,
        "both were really dialed"
    );
    assert_eq!(
        module.spawned_children.load(Ordering::SeqCst),
        0,
        "no registration child in Static mode"
    );
    // Real recovery: the ERR greeter starts answering V10; a LATER round (a new
    // H, the old one de-authorized) reads it healthy. And the reverse.
    failing.set(Greeting::V10);
    let recovered = wait_snapshot(&handle, |s| s.health().get(&failing.address).healthy).await?;
    assert!(!Arc::ptr_eq(recovered.health(), snapshot.health()));
    assert!(
        !handle.still_current(&snapshot),
        "the pre-recovery round is no longer current"
    );
    live.set(Greeting::Err);
    let degraded = wait_snapshot(&handle, |s| !s.health().get(&live.address).healthy).await?;
    assert!(degraded.health().get(&failing.address).healthy);
    drop(module);
    Ok(())
}

// ================================================================
// S2: disabled health publishes all-healthy/Local=false with zero I/O.
// ================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_disabled_static_producer_reads_all_healthy_not_local_with_zero_io() -> TestResult {
    let never = Greeter::spawn(Greeting::V10, false).await?;
    let store = store_with(
        &zero_cluster_config(),
        vec![namespace("default", &[&never.address])],
    )?;
    let module = spawn_module(store, health(false)).await?;
    let handle = wait_handle(&module, "default").await?;
    let snapshot = wait_snapshot(&handle, |_| true).await?;
    let verdict = snapshot.health().get(&never.address);
    assert!(
        verdict.healthy && !verdict.local,
        "Go disabled: Healthy=true, Local=false"
    );
    settle(Duration::from_millis(200)).await;
    assert_eq!(never.accepted(), 0, "a disabled producer dials nothing");
    drop(module);
    Ok(())
}

// ================================================================
// S3: two namespaces listing the same raw address publish the SAME id in two
// sources; each producer's round is held separately and released alone.
// ================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn namespaces_sharing_an_address_are_isolated_by_source_not_by_id() -> TestResult {
    let mut greeter = Greeter::spawn(Greeting::V10, true).await?;
    let store = store_with(
        &zero_cluster_config(),
        vec![
            namespace("alpha", &[&greeter.address]),
            namespace("beta", &[&greeter.address]),
        ],
    )?;
    let module = spawn_module(store, health(true)).await?;
    let alpha = wait_handle(&module, "alpha").await?;
    let beta = wait_handle(&module, "beta").await?;
    // Both producers dial (one connection each) and are held: no H yet.
    greeter.wait_accepted(2).await?;
    assert!(alpha.current().is_none() && beta.current().is_none());
    // Release exactly one greeting: exactly one producer publishes.
    greeter.release(1);
    let published = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match (alpha.current(), beta.current()) {
                (Some(a), None) => break ("alpha", a),
                (None, Some(b)) => break ("beta", b),
                (Some(_), Some(_)) => unreachable!("one permit releases one round"),
                (None, None) => tokio::time::sleep(Duration::from_millis(5)).await,
            }
        }
    })
    .await?;
    let (name, snapshot) = published;
    assert_eq!(
        snapshot.routing().backends.backends[0].backend_id.as_ref(),
        greeter.address.as_str(),
        "the same raw address is the id in both sources"
    );
    let other = if name == "alpha" { &beta } else { &alpha };
    assert!(
        !other.still_current(&snapshot),
        "a snapshot never authorizes through the other namespace's handle"
    );
    // Release the other round: both are now published, independently.
    greeter.release(1);
    let _ = wait_snapshot(other, |_| true).await?;
    drop(module);
    Ok(())
}

// ================================================================
// S4: a namespace removed in C fails closed AT THE SOURCE immediately; an
// identical re-creation is a new incarnation with a fresh producer (ABA).
// ================================================================

// current_thread: between `apply` and the assertions below there is no await,
// so the module task provably has NOT reconciled yet — the refusal can only
// come from the source-side incarnation check.
#[tokio::test]
async fn a_removed_namespace_fails_closed_at_the_source_and_recreation_is_new() -> TestResult {
    let greeter = Greeter::spawn(Greeting::V10, false).await?;
    let store = store_with(
        &zero_cluster_config(),
        vec![namespace("default", &[&greeter.address])],
    )?;
    let observed = store.clone();
    let module = spawn_module(store, health(true)).await?;
    let handle = wait_handle(&module, "default").await?;
    let snapshot = wait_snapshot(&handle, |_| true).await?;
    // Remove the namespace: the very next check fails, before any reconcile.
    apply(&observed, &zero_cluster_config(), vec![], 3)?;
    assert!(
        !handle.still_current(&snapshot),
        "removed in C: refused at once"
    );
    assert!(handle.current().is_none());
    assert!(module.handle.backend_source("default").is_none());
    wait_applied(&module, 3).await?;
    // Re-create with identical content: a new incarnation, a new producer.
    apply(
        &observed,
        &zero_cluster_config(),
        vec![namespace("default", &[&greeter.address])],
        4,
    )?;
    wait_applied(&module, 4).await?;
    assert!(handle.current().is_none(), "the old handle stays dead");
    let fresh = wait_handle(&module, "default").await?;
    let renewed = wait_snapshot(&fresh, |_| true).await?;
    assert!(
        !Arc::ptr_eq(renewed.health(), snapshot.health())
            && !Arc::ptr_eq(renewed.routing(), snapshot.routing()),
        "a fresh producer publishes fresh R/H"
    );
    assert!(
        !fresh.still_current(&snapshot),
        "the old snapshot never authorizes"
    );
    drop(module);
    Ok(())
}

/// Installs the synchronous publish hook that records, at the very instant the
/// Dynamic epoch is published, whether the bound static overlay is still
/// authoritative (it must not be: the producer is parked before the publish).
fn pin_dynamic_publish_boundary(
    module: &Module,
    handle: &BackendSourceHandle,
) -> (Arc<AtomicBool>, Arc<AtomicBool>) {
    let hook_fired = Arc::new(AtomicBool::new(false));
    let static_live_at_publish = Arc::new(AtomicBool::new(false));
    let (static_routing, static_health) = handle.static_side().clone();
    let fired = Arc::clone(&hook_fired);
    let live = Arc::clone(&static_live_at_publish);
    *module
        .handle
        .mode_publish_hook()
        .lock()
        .unwrap_or_else(PoisonError::into_inner) = Some(Box::new(move |epoch| {
        if epoch.mode() == BackendSourceMode::Dynamic {
            fired.store(true, Ordering::SeqCst);
            if let Some(r) = static_routing.current()
                && static_health.current_for(&r).is_some()
            {
                live.store(true, Ordering::SeqCst);
            }
        }
    }));
    (hook_fired, static_live_at_publish)
}

// ================================================================
// S5: mode follows the APPLIED plan. Static→Dynamic parks the producer (no
// probing, unroutable); a probe held across the switch cannot publish;
// Dynamic→Static runs a fresh real round; old snapshots are refused.
// ================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mode_follows_the_applied_plan_and_parks_the_static_producer() -> TestResult {
    let greeter = Greeter::spawn(Greeting::V10, false).await?;
    let store = store_with(
        &zero_cluster_config(),
        vec![namespace("default", &[&greeter.address])],
    )?;
    let observed = store.clone();
    let module = spawn_module(store, health(true)).await?;
    let handle = wait_handle(&module, "default").await?;
    let before = wait_snapshot(&handle, |_| true).await?;
    assert_eq!(before.mode(), BackendSourceMode::Static);

    // A HELD greeter for the next namespace incarnation: its rounds block on
    // permits, so a probe can be held in flight across the mode switch.
    let mut gate = Greeter::spawn(Greeting::V10, true).await?;
    apply(
        &observed,
        &zero_cluster_config(),
        vec![namespace("default", &[&gate.address])],
        3,
    )?;
    wait_applied(&module, 3).await?;
    let gated = wait_handle(&module, "default").await?;
    gate.wait_accepted(1).await?; // the first round is in flight (held)
    assert!(
        gated.current().is_none(),
        "no H before the first round completes"
    );
    // Let round 1 complete so the static side has a LIVE H, then hold round 2
    // in flight across the mode switch.
    gate.release(1);
    let live_static = wait_snapshot(&gated, |_| true).await?;
    gate.wait_accepted(2).await?;

    let (hook_fired, static_live_at_publish) = pin_dynamic_publish_boundary(&module, &gated);
    apply(
        &observed,
        &one_cluster_config(),
        vec![namespace("default", &[&gate.address])],
        4,
    )?;
    wait_applied(&module, 4).await?;
    assert!(
        hook_fired.load(Ordering::SeqCst),
        "the Dynamic publish was observed"
    );
    assert!(
        !static_live_at_publish.load(Ordering::SeqCst),
        "the parked static overlay was withdrawn BEFORE the Dynamic epoch was published"
    );
    assert!(
        !handle.still_current(&before),
        "the Static epoch was revoked"
    );
    assert!(
        gated.current().is_none(),
        "Dynamic: the static side is not served"
    );
    let accepted_at_switch = gate.accepted();
    gate.release(1); // the held probe completes AFTER the switch...
    settle(Duration::from_millis(300)).await;
    assert_eq!(
        gate.accepted(),
        accepted_at_switch,
        "a parked producer constructs no new probe"
    );

    // Back to Static: a fresh real round runs and publishes a fresh H.
    apply(
        &observed,
        &zero_cluster_config(),
        vec![namespace("default", &[&gate.address])],
        5,
    )?;
    wait_applied(&module, 5).await?;
    gate.wait_accepted(accepted_at_switch + 1).await?;
    gate.release(1);
    let after = wait_snapshot(&gated, |_| true).await?;
    assert_eq!(after.mode(), BackendSourceMode::Static);
    assert!(gated.still_current(&after));
    assert!(
        !Arc::ptr_eq(after.health(), live_static.health()),
        "re-activation publishes a FRESH H, never the pre-switch one"
    );
    assert!(
        !gated.still_current(&live_static),
        "the pre-switch static snapshot stays refused"
    );
    assert!(
        !gated.still_current(&before),
        "the pre-switch snapshot stays refused"
    );
    drop(module);
    Ok(())
}

// ================================================================
// S6: a rejected cluster generation keeps the last-good mode, while the
// namespaces of that same generation are still reconciled.
// ================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_rejected_cluster_generation_keeps_the_mode_but_reconciles_namespaces() -> TestResult {
    let old = Greeter::spawn(Greeting::V10, false).await?;
    let new = Greeter::spawn(Greeting::V10, false).await?;
    let store = store_with(
        &zero_cluster_config(),
        vec![namespace("default", &[&old.address])],
    )?;
    let observed = store.clone();
    let module = spawn_module(store, health(true)).await?;
    let handle = wait_handle(&module, "default").await?;
    let before = wait_snapshot(&handle, |_| true).await?;

    module.reject.store(true, Ordering::SeqCst);
    apply(
        &observed,
        &one_cluster_config(),
        vec![namespace("default", &[&new.address])],
        3,
    )?;
    wait_applied(&module, 3).await?;
    let status = *module.handle.status().borrow();
    assert_eq!(
        status.applied_generation, 2,
        "the cluster generation was rejected"
    );
    assert!(status.last_rejection.is_some());
    assert!(
        !handle.still_current(&before),
        "the namespace was replaced in C"
    );
    let replaced = wait_handle(&module, "default").await?;
    let snapshot = wait_snapshot(&replaced, |_| true).await?;
    assert_eq!(
        snapshot.mode(),
        BackendSourceMode::Static,
        "last-good mode retained"
    );
    assert_eq!(
        snapshot.routing().backends.backends[0].backend_id.as_ref(),
        new.address.as_str(),
        "the new incarnation's producer serves the new list"
    );
    drop(module);
    Ok(())
}

// ================================================================
// S7 (isolated mode-handle regression): mode identity is the exact epoch, not
// the enum value. Static→Dynamic→Static republishing the SAME static R/H
// refuses the first-epoch snapshot; revoke-before-publish closes the window.
// ================================================================

/// A handle over injected dynamic/static sides and a test-owned mode publisher.
struct ModeHandleFixture {
    mode: ModePublisher,
    handle: BackendSourceHandle,
    owner: control_plane::OwnerToken,
    _lease: control_plane::OwnerLease,
    dyn_routing: RoutingSnapshotPublisher,
    dyn_handle: crate::routing_snapshot::RoutingSnapshotHandle,
    dyn_overlay: HealthOverlayPublisher,
    _st_routing: RoutingSnapshotPublisher,
    st_overlay: HealthOverlayPublisher,
    st_source: Arc<crate::routing_snapshot::RoutingSnapshot>,
}

impl ModeHandleFixture {
    fn build() -> TestResult<Self> {
        let store = store_with(
            &zero_cluster_config(),
            vec![namespace("default", &["10.0.0.1:4000"])],
        )?;
        let config: Arc<dyn ConfigNamespaceSource> = Arc::new(store.clone());
        let mode = ModePublisher::new();
        let (dyn_routing, dyn_handle) = RoutingSnapshotPublisher::new();
        let (dyn_overlay, dyn_health) = HealthOverlayPublisher::new();
        let (st_routing, st_handle) = RoutingSnapshotPublisher::new();
        let (st_overlay, st_health) = HealthOverlayPublisher::new();
        let _ = st_routing.publish(EpochResult {
            client_epoch: 0,
            value: MergedTopology {
                backends: super::static_backends(&["10.0.0.1:4000".to_owned()]),
            },
        });
        let st_source = st_handle.current().ok_or("static source")?;
        let registry_lease = Box::leak(Box::new(OwnershipRegistry::new()));
        let lease = registry_lease.claim(OwnerScope::Process, "mode-handle-row")?;
        let owner = lease.token();
        let registry = StaticRegistry::default();
        registry.insert(
            "default".to_owned(),
            RegisteredProducer {
                incarnation: store
                    .current()
                    .namespace_incarnation("default")
                    .ok_or("incarnation")?,
                routing: st_handle,
                health: st_health,
            },
        );
        let handle = BackendSourceHandle::bind(
            "default",
            config,
            mode.subscribe(),
            (dyn_handle.clone(), dyn_health),
            &registry,
        )
        .ok_or("bind")?;
        Ok(Self {
            mode,
            handle,
            owner,
            _lease: lease,
            dyn_routing,
            dyn_handle,
            dyn_overlay,
            _st_routing: st_routing,
            st_overlay,
            st_source,
        })
    }

    /// Publishes one all-healthy/local round on the static side.
    fn publish_static_round(&self) {
        let map = self
            .st_source
            .backends
            .backends
            .iter()
            .map(|b| {
                (
                    Arc::clone(&b.backend_id),
                    crate::backend_health::BackendHealth {
                        healthy: true,
                        server_version: None,
                        local: true,
                    },
                )
            })
            .collect();
        self.st_overlay
            .publish_round(&self.st_source, map, GenerationGate::new(), &self.owner);
    }

    /// Publishes an EMPTY dynamic R and its (empty) H.
    fn publish_empty_dynamic(&self) -> TestResult {
        let _ = self.dyn_routing.publish(EpochResult {
            client_epoch: 1,
            value: MergedTopology {
                backends: Vec::new(),
            },
        });
        let source = self.dyn_handle.current().ok_or("dynamic source")?;
        self.dyn_overlay.publish_round(
            &source,
            std::collections::HashMap::new(),
            GenerationGate::new(),
            &self.owner,
        );
        Ok(())
    }
}

#[tokio::test]
async fn mode_identity_is_the_exact_epoch_not_the_mode_value() -> TestResult {
    let fixture = ModeHandleFixture::build()?;
    fixture.publish_static_round();
    let handle = &fixture.handle;
    assert!(
        handle.current().is_none(),
        "no applied epoch yet: fail closed"
    );

    fixture.mode.publish(BackendSourceMode::Static);
    let first = handle.current().ok_or("static snapshot")?;
    assert_eq!(first.mode(), BackendSourceMode::Static);
    assert!(handle.still_current(&first));

    // Step 1 of a transition: revoke before anything new is published.
    fixture.mode.revoke();
    assert!(
        !handle.still_current(&first),
        "revoked epoch refuses at once"
    );
    assert!(
        handle.current().is_none(),
        "no live epoch: nothing is captured"
    );
    fixture.mode.publish(BackendSourceMode::Dynamic);
    assert!(handle.current().is_none(), "Dynamic side has no R/H yet");

    // Back to Static WITHOUT touching the static R/H: same Arcs, new epoch.
    fixture.mode.publish(BackendSourceMode::Static);
    let second = handle.current().ok_or("second static snapshot")?;
    assert!(Arc::ptr_eq(second.routing(), first.routing()));
    assert!(Arc::ptr_eq(second.health(), first.health()));
    assert_eq!(second.mode(), first.mode(), "same mode VALUE");
    assert!(handle.still_current(&second));
    assert!(
        !handle.still_current(&first),
        "same R/H and same mode value, different epoch: refused"
    );
    Ok(())
}

// An EMPTY dynamic R/H under Dynamic mode is served as the (empty) dynamic
// snapshot; it never falls back to the static side (Go: configured clusters
// with no discovered backend route nothing, not the static list).
#[tokio::test]
async fn an_empty_dynamic_discovery_is_served_empty_never_as_the_static_list() -> TestResult {
    let fixture = ModeHandleFixture::build()?;
    fixture.publish_static_round();
    fixture.mode.publish(BackendSourceMode::Dynamic);
    assert!(fixture.handle.current().is_none(), "no dynamic R/H yet");
    fixture.publish_empty_dynamic()?;
    let empty = fixture.handle.current().ok_or("empty dynamic snapshot")?;
    assert_eq!(empty.mode(), BackendSourceMode::Dynamic);
    assert!(
        empty.routing().backends.backends.is_empty(),
        "empty dynamic discovery is served as empty, never as the static list"
    );
    assert!(fixture.handle.still_current(&empty));
    Ok(())
}

// ================================================================
// S8 (shared Go observation): the SAME step fixture drives Go's real
// backendcluster.Manager + FallbackFetcher + StaticFetcher and the real
// TopologyModule here; compared byte-for-byte by run.sh, including the
// recorded Go/Rust divergence step.
// ================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shared_go_static_mode_observation() -> TestResult {
    let Ok(input) = std::env::var("CPROUTE_STATIC_FIXTURE") else {
        return Ok(());
    };
    let fixture: serde_json::Value = serde_json::from_slice(&std::fs::read(input)?)?;
    let text = |v: &serde_json::Value| v.as_str().unwrap_or_default().to_owned();
    let instances: Vec<String> = fixture["instances"]
        .as_array()
        .ok_or("instances")?
        .iter()
        .map(text)
        .collect();
    let steps = fixture["steps"].as_array().ok_or("steps")?.clone();
    let config_for = |clusters: &[String]| -> Vec<u8> {
        let mut toml = String::from(
            "\n[proxy]\naddr = \"0.0.0.0:6000\"\npd-addrs = \"\"\n\n[api]\naddr = \"0.0.0.0:10080\"\n",
        );
        for name in clusters {
            let cluster = format!("cluster-{}", name.trim_end_matches('2'));
            let _ = write!(
                toml,
                "\n[[proxy.backend-clusters]]\nname = \"{cluster}\"\npd-addrs = \"pd-{name}:2379\"\nns-servers = []\n"
            );
        }
        toml.into_bytes()
    };
    let refs: Vec<&str> = instances.iter().map(String::as_str).collect();
    let first: Vec<String> = steps[0]["clusters"]
        .as_array()
        .ok_or("clusters")?
        .iter()
        .map(text)
        .collect();
    let store = store_with(&config_for(&first), vec![namespace("default", &refs)])?;
    let observed = store.clone();
    // Health disabled: the fixture addresses are identity inputs, not hosts.
    let module = spawn_module(store, health(false)).await?;
    let mut output = String::new();
    for (index, step) in steps.iter().enumerate() {
        let clusters: Vec<String> = step["clusters"]
            .as_array()
            .ok_or("clusters")?
            .iter()
            .map(text)
            .collect();
        let fail = step["fail"].as_bool().unwrap_or(false);
        if index > 0 {
            module.reject.store(fail, Ordering::SeqCst);
            let revision = u64::try_from(index)? + 2;
            apply(
                &observed,
                &config_for(&clusters),
                vec![namespace("default", &refs)],
                revision,
            )?;
            wait_applied(&module, revision).await?;
        }
        let mode = module.handle.applied_mode().ok_or("applied mode")?;
        let name = text(&step["name"]);
        let divergence = text(&step["divergence"]);
        if !divergence.is_empty() {
            assert_eq!(
                mode,
                BackendSourceMode::Dynamic,
                "Rust rejects the whole generation and retains the last-good plan"
            );
            let _ = writeln!(output, "{name}\tDIVERGENCE\t{divergence}");
            continue;
        }
        match mode {
            BackendSourceMode::Static => {
                let handle = wait_handle(&module, "default").await?;
                let snapshot = wait_snapshot(&handle, |_| true).await?;
                let mut ids: Vec<&str> = snapshot
                    .routing()
                    .backends
                    .backends
                    .iter()
                    .map(|b| b.backend_id.as_ref())
                    .collect();
                ids.sort_unstable();
                let _ = writeln!(output, "{name}\tstatic\t{}", ids.join(","));
            }
            BackendSourceMode::Dynamic => {
                assert!(
                    module
                        .handle
                        .backend_source("default")
                        .is_some_and(|h| h.current().is_none()),
                    "the static side is not served in Dynamic mode"
                );
                let _ = writeln!(output, "{name}\tdynamic\t-");
            }
        }
    }
    if let Ok(expected) = std::env::var("CPROUTE_STATIC_EXPECTED") {
        assert_eq!(output, std::fs::read_to_string(expected)?);
    }
    std::fs::write(std::env::var("CPROUTE_STATIC_OUTPUT")?, output)?;
    drop(module);
    Ok(())
}

// ================================================================
// S9 (real commit window): inside `reconfigure`'s Dynamic→Static window — the
// run loop parked at `stop_children`, the only await after the outgoing epoch
// is revoked and before the new plan/commit/epoch are published — a Dynamic
// snapshot from REAL discovery is already refused and nothing is capturable.
// A consumer that captured it BEFORE waiting on a lock, and re-validates after
// the lock is granted, performs zero side effects.
// ================================================================

/// A Dynamic module over REAL discovery (one seeded backend) whose registration
/// child parks its shutdown until `release` is notified, signalling `entered`
/// first: the hook that holds `reconfigure` inside its Dynamic→Static window.
async fn dynamic_module_with_parked_child()
-> TestResult<(Module, ConfigNamespaceStore, Arc<Notify>, Arc<Notify>)> {
    let seeded = vec![
        (
            b"/topology/tidb/10.0.0.9:4000/info".to_vec(),
            br#"{"ip":"10.0.0.9","status_port":10080,"version":"v8"}"#.to_vec(),
        ),
        (b"/topology/tidb/10.0.0.9:4000/ttl".to_vec(), b"1".to_vec()),
    ];
    let addr = spawn_fixture(seeded)
        .await
        .ok_or("the fixture binds a loopback port")?;
    // The registration child parks its shutdown until the row releases it.
    let entered = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let spawned = Arc::new(AtomicUsize::new(0));
    let runner: ChildRunner = {
        let entered = Arc::clone(&entered);
        let release = Arc::clone(&release);
        let spawned = Arc::clone(&spawned);
        Arc::new(move |_owner, _connector, _info, _timeout, mut shutdown| {
            spawned.fetch_add(1, Ordering::SeqCst);
            let entered = Arc::clone(&entered);
            let release = Arc::clone(&release);
            Box::pin(async move {
                let _ = shutdown.changed().await;
                entered.notify_one();
                release.notified().await;
                Ok(())
            })
        })
    };
    let store = store_with(
        &one_cluster_config(),
        vec![namespace("default", &["10.0.0.7:4000"])],
    )?;
    let observed = store.clone();
    let module = spawn_module_with(
        store,
        health(false),
        Box::new(FixtureFactory {
            addr,
            timeout_ms: Arc::new(AtomicU64::new(500)),
        }),
        runner,
        Arc::new(AtomicBool::new(false)),
        spawned,
    )
    .await?;
    Ok((module, observed, entered, release))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_dynamic_snapshot_is_refused_inside_the_commit_window_before_static_publishes()
-> TestResult {
    let (module, observed, entered, release) = dynamic_module_with_parked_child().await?;
    let handle = wait_handle(&module, "default").await?;
    let dynamic = wait_snapshot(&handle, |s| {
        s.mode() == BackendSourceMode::Dynamic && s.routing().backends.backends.len() == 1
    })
    .await?;
    assert_eq!(
        dynamic.routing().backends.backends[0].backend_id.as_ref(),
        "cluster-a/10.0.0.9:4000",
        "a REAL discovered backend"
    );

    // The lock-holding consumer: captured `dynamic` BEFORE waiting on the lock
    // the row holds across the whole window; after the lock is granted it
    // re-validates and counts a side effect only if the capture still holds.
    let lock = Arc::new(tokio::sync::Mutex::new(()));
    let held = Arc::clone(&lock).lock_owned().await;
    let side_effects = Arc::new(AtomicUsize::new(0));
    let consumer = {
        let handle = handle.clone();
        let captured = dynamic.clone();
        let lock = Arc::clone(&lock);
        let side_effects = Arc::clone(&side_effects);
        tokio::spawn(async move {
            let _guard = lock.lock().await;
            if handle.still_current(&captured) {
                side_effects.fetch_add(1, Ordering::SeqCst);
            }
        })
    };

    // Dynamic→Static: the run loop revokes the Dynamic epoch, then parks in
    // stop_children on our child.
    apply(
        &observed,
        &zero_cluster_config(),
        vec![namespace("default", &["10.0.0.7:4000"])],
        3,
    )?;
    tokio::time::timeout(Duration::from_secs(10), entered.notified()).await?;
    assert!(
        !handle.still_current(&dynamic),
        "inside the window the outgoing Dynamic epoch is already revoked"
    );
    assert!(
        handle.current().is_none(),
        "inside the window no epoch is live: nothing can be captured"
    );
    assert!(
        module.handle.status().borrow().applied_generation < 3,
        "the static plan is not applied yet while the window is held"
    );

    // Grant the lock while the window is still held, then close the window.
    drop(held);
    tokio::time::timeout(Duration::from_secs(10), consumer).await??;
    assert_eq!(
        side_effects.load(Ordering::SeqCst),
        0,
        "a consumer re-validating after the lock performs no side effect"
    );
    release.notify_one();
    wait_applied(&module, 3).await?;
    let stationary = wait_snapshot(&handle, |s| s.mode() == BackendSourceMode::Static).await?;
    assert!(handle.still_current(&stationary));
    assert!(
        !handle.still_current(&dynamic),
        "the Dynamic snapshot stays refused"
    );
    drop(module);
    Ok(())
}
