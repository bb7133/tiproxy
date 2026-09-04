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

//! The `control_topology` self-registration module.
//!
//! [`TopologyModule`] is a [`control_plane::ControlModule`] that runs
//! self-registration. It subscribes to the injected
//! [`control_config::ConfigNamespaceStore`], and for every configuration
//! generation it fans one [`crate::registrar::run`] loop out per backend
//! cluster (Go keeps one `InfoSyncer` per cluster), each publishing the same
//! [`TopologyInfo`] under its own per-instance lease.
//!
//! This slice is a registration foundation: the binary does not yet add it to
//! its [`control_plane::ControlModuleSet`], and topology discovery is not yet
//! driven (see the scope note below). It is not a full topology mount and does
//! not on its own make topology ready for routing.
//!
//! # Generation fence
//!
//! The process [`control_plane::OwnerToken`] isolates process owners but not
//! successive configuration generations inside one process. So on every
//! generation change the module builds the new client set first, then stops and
//! **joins** every old child before starting the new ones. A late write from a
//! retired generation can therefore never overwrite a newer snapshot.
//!
//! # Scope
//!
//! This slice fans out self-registration only. The discovery poll
//! ([`crate::poll_tidb_topology`]) is not yet driven here because its snapshot
//! has no in-process consumer until routing lands; wiring a per-cluster poll
//! loop is a dependent follow-up.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use control_config::{ConfigNamespaceSnapshot, ConfigNamespaceSource, TopologyRuntimeIdentity};
use control_external::{EtcdClientConfig, EtcdConnector};
use control_plane::{
    ControlModule, LifecyclePhase, ModuleContext, ModuleError, ModuleFuture, OwnerToken,
};
use tokio::sync::watch;
use tokio::task::JoinSet;

use crate::registrar::RegistrarError;
use crate::resolver::AdvertiseEndpointResolver;

/// Grace period for a retired generation's children to deregister before they
/// are aborted, so a wedged child can never block a reconfigure or shutdown.
const CHILD_STOP_GRACE: Duration = Duration::from_secs(5);

use crate::register::TopologyInfo;

/// Stable module name used in metrics, logs, and [`ControlModule::name`].
const MODULE_NAME: &str = "control_topology";

/// The future a per-cluster registration child runs to completion.
pub(crate) type ChildFuture = Pin<Box<dyn Future<Output = Result<(), RegistrarError>> + Send>>;

/// Builds one per-cluster registration child. Production uses
/// [`crate::registrar::run`]; a test injects a deterministic child to exercise
/// unexpected-exit and wedged-shutdown handling.
pub(crate) type ChildRunner = Arc<
    dyn Fn(OwnerToken, EtcdConnector, TopologyInfo, Duration, watch::Receiver<bool>) -> ChildFuture
        + Send
        + Sync,
>;

/// The production child runner: the real self-registration loop.
fn default_child_runner() -> ChildRunner {
    Arc::new(|owner, connector, info, receive_timeout, shutdown| {
        Box::pin(crate::registrar::run(
            owner,
            connector,
            info,
            receive_timeout,
            shutdown,
        ))
    })
}

/// One backend cluster's connection material, produced by a
/// [`TopologyClientFactory`].
pub struct TopologyClusterClient {
    /// Stable cluster name, used only for deterministic ordering and diagnostics.
    pub cluster_name: Arc<str>,
    /// The validated etcd client configuration for this cluster's PD.
    pub client: EtcdClientConfig,
}

/// Builds the per-cluster etcd client set for a configuration generation.
///
/// The binary implements this by downcasting the snapshot's opaque
/// [`control_config::PreparedArtifact`] to the cluster set already prepared
/// (endpoints bound to their validated TLS material) at validation time, and
/// returning one [`EtcdClientConfig`] per backend cluster — with no PEM re-read
/// (closing the validate→apply TOCTOU). It receives the whole snapshot rather
/// than the projection so it can reach that artifact. Keeping it injectable
/// keeps PEM file access in the composition root, out of this crate, and lets
/// tests supply plain endpoints.
pub trait TopologyClientFactory: Send + Sync {
    /// Produces the cluster clients for one published generation.
    ///
    /// Implementations should return the clusters ordered by name so a
    /// generation's fan-out is deterministic.
    ///
    /// # Errors
    ///
    /// Returns a human-readable reason when the prepared material or endpoints
    /// are unusable. On the initial generation the module treats this as a
    /// fatal startup error; on a later generation it is a rejection that
    /// retains the last-good registration.
    fn build(
        &self,
        snapshot: &ConfigNamespaceSnapshot,
    ) -> Result<Vec<TopologyClusterClient>, String>;
}

/// Why a configuration generation could not be applied to registration.
///
/// Deliberately payload-free: it names the failure class for an observer
/// without carrying any configuration or credential content.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RejectionClass {
    /// The generation's topology projection could not be produced.
    TopologyProjection,
    /// No advertise host could be resolved (e.g. no usable interface).
    AdvertiseUnresolved,
    /// The factory could not build the etcd client set (e.g. bad TLS material).
    ClientBuildFailed,
    /// The built cluster set did not match the configured cluster names.
    ClusterSetMismatch,
    /// The factory returned two clients for the same cluster name.
    DuplicateClusterName,
}

/// Observable registration status.
///
/// This never carries configuration or credential payload — only generation
/// numbers and a [`RejectionClass`]. `ready` remains monotonic; this status is
/// how an observer distinguishes a healthy hot-update from a rejected one after
/// the module is already ready.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TopologyStatus {
    /// The most recent configuration generation the module observed.
    pub observed_generation: u64,
    /// The most recent generation whose registration was successfully applied
    /// (or was an unchanged no-op). Stays at the last good generation when a
    /// newer one is rejected.
    pub applied_generation: u64,
    /// The class of the most recent rejection, cleared on a successful apply or
    /// no-op.
    pub last_rejection: Option<RejectionClass>,
}

/// The self-registration control-plane module.
pub struct TopologyModule {
    source: Arc<dyn ConfigNamespaceSource>,
    factory: Box<dyn TopologyClientFactory>,
    resolver: Arc<dyn AdvertiseEndpointResolver>,
    identity: TopologyRuntimeIdentity,
    ready: watch::Sender<bool>,
    status: watch::Sender<TopologyStatus>,
    child_runner: ChildRunner,
}

/// Registration-readiness handle returned alongside a [`TopologyModule`].
///
/// The composition root waits on [`TopologyModuleHandle::wait_ready`] before
/// starting modules that depend on registration having begun. This signals only
/// that the initial generation's registration children are spawned; it does not
/// assert a published topology-discovery snapshot, which a later slice owns.
pub struct TopologyModuleHandle {
    ready: watch::Receiver<bool>,
    status: watch::Receiver<TopologyStatus>,
}

impl TopologyModuleHandle {
    /// Resolves once the module has applied its initial configuration
    /// generation and spawned the registration children.
    ///
    /// This is a local determinism guarantee that registration has begun: it
    /// does not require PD to be reachable (registration keeps retrying
    /// underneath) and does not imply a topology snapshot has been published.
    ///
    /// # Errors
    ///
    /// Returns an error only if the module was dropped before signalling ready.
    pub async fn wait_ready(&mut self) -> Result<(), watch::error::RecvError> {
        while !*self.ready.borrow_and_update() {
            self.ready.changed().await?;
        }
        Ok(())
    }

    /// Subscribes to the observable registration status.
    ///
    /// Unlike [`Self::wait_ready`] (which is monotonic), this reports every
    /// generation the module observes and applies, and the class of any
    /// rejection, so a consumer can tell a healthy hot-update from a rejected
    /// one after the module is ready.
    #[must_use]
    pub fn status(&self) -> watch::Receiver<TopologyStatus> {
        self.status.clone()
    }
}

impl TopologyModule {
    /// Builds the module and its readiness handle.
    ///
    /// `source`, `factory`, and `resolver` are all injected from the
    /// composition root: the factory reads TLS material and the resolver owns
    /// interface enumeration, keeping both out of this crate.
    #[must_use]
    pub fn new(
        source: Arc<dyn ConfigNamespaceSource>,
        factory: Box<dyn TopologyClientFactory>,
        resolver: Arc<dyn AdvertiseEndpointResolver>,
        identity: TopologyRuntimeIdentity,
    ) -> (Self, TopologyModuleHandle) {
        Self::build(source, factory, resolver, identity, default_child_runner())
    }

    /// Test-only constructor that injects a deterministic child runner, used to
    /// exercise unexpected-child-exit and wedged-shutdown handling without a
    /// live backend. Not compiled into the production crate.
    #[cfg(test)]
    fn new_with_child_runner(
        source: Arc<dyn ConfigNamespaceSource>,
        factory: Box<dyn TopologyClientFactory>,
        resolver: Arc<dyn AdvertiseEndpointResolver>,
        identity: TopologyRuntimeIdentity,
        child_runner: ChildRunner,
    ) -> (Self, TopologyModuleHandle) {
        Self::build(source, factory, resolver, identity, child_runner)
    }

    fn build(
        source: Arc<dyn ConfigNamespaceSource>,
        factory: Box<dyn TopologyClientFactory>,
        resolver: Arc<dyn AdvertiseEndpointResolver>,
        identity: TopologyRuntimeIdentity,
        child_runner: ChildRunner,
    ) -> (Self, TopologyModuleHandle) {
        let (ready_tx, ready_rx) = watch::channel(false);
        let (status_tx, status_rx) = watch::channel(TopologyStatus::default());
        (
            Self {
                source,
                factory,
                resolver,
                identity,
                ready: ready_tx,
                status: status_tx,
                child_runner,
            },
            TopologyModuleHandle {
                ready: ready_rx,
                status: status_rx,
            },
        )
    }

    async fn run_inner(self, context: ModuleContext) -> Result<(), ModuleError> {
        let owner = context.owner().clone();
        let mut lifecycle = context.lifecycle();
        let mut updates = self.source.subscribe();
        let mut children = Children::default();
        let mut active_plan: Option<RegistrationPlan> = None;

        // Apply the current generation once (including generation 1), then wait
        // for changes; borrowing after `subscribe` avoids a dropped edge.
        let initial = updates.borrow_and_update().clone();
        if !self
            .apply_and_report(&mut children, &mut active_plan, &initial, &owner)
            .await
        {
            return Err(module_error("initial_generation_rejected"));
        }
        let _ = self.ready.send_replace(true);

        loop {
            tokio::select! {
                changed = lifecycle.changed() => {
                    if changed.is_err() || shutdown_started(lifecycle.borrow().phase) {
                        stop_children(&mut children).await;
                        return Ok(());
                    }
                }
                changed = updates.changed() => {
                    if changed.is_err() {
                        stop_children(&mut children).await;
                        return Err(module_error("config_source_stopped"));
                    }
                    let snapshot = updates.borrow_and_update().clone();
                    // A rejected generation (unresolvable advertise, build
                    // failure, or a factory result that does not match the
                    // configured cluster set) retains the last-good
                    // registration rather than tearing it down; the rejection
                    // class is published on the status watch.
                    let _ = self
                        .apply_and_report(&mut children, &mut active_plan, &snapshot, &owner)
                        .await;
                }
                exited = children.tasks.join_next(), if !children.tasks.is_empty() => {
                    // A child completed while we were not tearing it down: an
                    // unexpected retirement, owner loss, or panic. Fail loud so
                    // the runtime does not treat an unregistered proxy as healthy.
                    if exited.is_some() {
                        stop_children(&mut children).await;
                        return Err(module_error("registration_child_exited"));
                    }
                }
            }
        }
    }

    /// Reconciles the per-cluster registration children for one generation.
    ///
    /// Returns `Ok(())` when registration is in a good applied state (either
    /// freshly applied or an unchanged no-op) and `Err(class)` when the
    /// generation was rejected and the previous good state was retained.
    ///
    /// The client set is built every generation, so a TLS content rotation
    /// (same paths, new PEM) is read here and produces a different plan. The
    /// [`RegistrationPlan`] holds the built [`EtcdClientConfig`] set itself
    /// (which compares endpoints and PEM bytes), so an equal plan is a genuine
    /// no-op — a namespace or log-level edit does not flap leases — while any
    /// material or endpoint change rebuilds. The factory result is closed-loop
    /// validated against the configured cluster set, and everything is checked
    /// *before* the old children are stopped, so a rejected generation never
    /// tears down a working registration and no retired write races a new one.
    async fn reconfigure(
        &self,
        children: &mut Children,
        active_plan: &mut Option<RegistrationPlan>,
        snapshot: &ConfigNamespaceSnapshot,
        owner: &OwnerToken,
    ) -> Result<(), RejectionClass> {
        let Ok(topology) = snapshot.topology() else {
            return Err(RejectionClass::TopologyProjection);
        };
        let Ok(advertise_host) = self.resolver.resolve(&topology) else {
            return Err(RejectionClass::AdvertiseUnresolved);
        };
        let info = TopologyInfo::new(
            &advertise_host,
            topology.sql_port,
            topology.status_port,
            &self.identity.version,
            &self.identity.git_hash,
            &self.identity.deploy_path.to_string_lossy(),
            self.identity.start_timestamp,
        );
        // Build every generation from the snapshot's prepared artifact, so a
        // rotation is observed here rather than swallowed by a path-only
        // comparison, and the exact material validated for this generation is
        // used without re-reading it.
        let Ok(mut clusters) = self.factory.build(snapshot) else {
            return Err(RejectionClass::ClientBuildFailed);
        };
        clusters.sort_by(|left, right| left.cluster_name.cmp(&right.cluster_name));

        // Closed-loop validation: the built set must match the configured
        // cluster names exactly, with no duplicate, missing, extra, or renamed
        // cluster. This runs before any state is mutated.
        let built: Vec<&str> = clusters.iter().map(|c| c.cluster_name.as_ref()).collect();
        if built.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(RejectionClass::DuplicateClusterName);
        }
        let mut expected: Vec<&str> = topology
            .backend_clusters
            .iter()
            .map(|cluster| cluster.name.as_ref())
            .collect();
        expected.sort_unstable();
        if built != expected {
            return Err(RejectionClass::ClusterSetMismatch);
        }

        let plan = RegistrationPlan {
            info: info.clone(),
            clusters: clusters
                .iter()
                .map(|cluster| PlannedCluster {
                    name: Arc::clone(&cluster.cluster_name),
                    client: cluster.client.clone(),
                })
                .collect(),
        };
        if active_plan.as_ref() == Some(&plan) {
            // Nothing that affects registration changed; keep the children.
            return Ok(());
        }

        // Fence: retire the previous generation before the new one publishes.
        stop_children(children).await;
        for cluster in clusters {
            let (shutdown_tx, shutdown_rx) = watch::channel(false);
            let receive_timeout = cluster.client.request_timeout();
            let connector = EtcdConnector::new(owner.clone(), cluster.client);
            children.shutdowns.push(shutdown_tx);
            children.tasks.spawn((self.child_runner)(
                owner.clone(),
                connector,
                info.clone(),
                receive_timeout,
                shutdown_rx,
            ));
        }
        *active_plan = Some(plan);
        Ok(())
    }

    /// Applies one generation and publishes the resulting observable status.
    ///
    /// Returns whether registration is in a good applied state (applied or a
    /// no-op). A no-op still counts as the generation being successfully
    /// consumed, so it advances `applied_generation` and clears any prior
    /// rejection; a rejection only advances `observed_generation`.
    async fn apply_and_report(
        &self,
        children: &mut Children,
        active_plan: &mut Option<RegistrationPlan>,
        snapshot: &ConfigNamespaceSnapshot,
        owner: &OwnerToken,
    ) -> bool {
        let generation = snapshot.generation();
        let outcome = self
            .reconfigure(children, active_plan, snapshot, owner)
            .await;
        self.status.send_modify(|status| {
            status.observed_generation = generation;
            match outcome {
                Ok(()) => {
                    status.applied_generation = generation;
                    status.last_rejection = None;
                }
                Err(class) => status.last_rejection = Some(class),
            }
        });
        outcome.is_ok()
    }
}

/// The registration-determining projection of one configuration generation:
/// the resolved published info and the built, name-sorted client set.
///
/// Equality is the no-flap decision. The built [`EtcdClientConfig`]s carry the
/// endpoints and PEM material actually in use, so an equal plan guarantees an
/// identical registration. The type deliberately has no `Debug`, so credential
/// material never reaches a log or diagnostic through it.
#[derive(PartialEq, Eq)]
struct RegistrationPlan {
    info: TopologyInfo,
    clusters: Vec<PlannedCluster>,
}

/// One planned cluster registration: its name and the exact built client.
#[derive(PartialEq, Eq)]
struct PlannedCluster {
    name: Arc<str>,
    client: EtcdClientConfig,
}

impl ControlModule for TopologyModule {
    fn name(&self) -> &'static str {
        MODULE_NAME
    }

    fn run(self: Box<Self>, context: ModuleContext) -> ModuleFuture {
        Box::pin(self.run_inner(context))
    }
}

/// The running per-cluster registration children and their stop signals.
///
/// The tasks live in a [`JoinSet`] so the module can both supervise them (an
/// unexpected exit is observable) and reliably retire them.
#[derive(Default)]
struct Children {
    shutdowns: Vec<watch::Sender<bool>>,
    tasks: JoinSet<Result<(), RegistrarError>>,
}

/// Signals every child to stop, joins them within a grace period, and aborts
/// any that do not retire in time.
///
/// Signalling first lets the children deregister concurrently; the bounded join
/// plus abort backstop guarantees this returns even if a child is wedged, so a
/// reconfigure or shutdown can never deadlock on a stuck registration.
async fn stop_children(children: &mut Children) {
    for shutdown in children.shutdowns.drain(..) {
        let _ = shutdown.send(true);
    }
    let drained = tokio::time::timeout(CHILD_STOP_GRACE, async {
        while children.tasks.join_next().await.is_some() {}
    })
    .await;
    if drained.is_err() {
        children.tasks.abort_all();
        while children.tasks.join_next().await.is_some() {}
    }
}

/// Whether a lifecycle phase means the process is shutting down.
const fn shutdown_started(phase: LifecyclePhase) -> bool {
    matches!(
        phase,
        LifecyclePhase::Quiescing
            | LifecyclePhase::Draining
            | LifecyclePhase::Stopping
            | LifecyclePhase::Stopped
            | LifecyclePhase::Failed
    )
}

const fn module_error(error_class: &'static str) -> ModuleError {
    ModuleError {
        module: MODULE_NAME,
        error_class,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ChildRunner, RegistrarError, RejectionClass, TopologyClusterClient, TopologyModule,
        TopologyStatus,
    };
    use std::future::pending;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use control_config::{ConfigNamespaceSnapshot, ConfigNamespaceStore, TopologyRuntimeIdentity};
    use control_external::{EtcdClientConfig, EtcdTlsConfig};
    use control_plane::{
        ControlConfig, ControlModule, ControlRuntime, EventSink, LifecyclePhase, LogLevel,
        MetricsPolicy, ModuleError, OwnershipRegistry, RuntimeEvent, ShutdownReason, TlsPolicy,
    };
    use tokio::sync::watch;

    use crate::TopologyClientFactory;
    use crate::resolver::StaticAdvertiseResolver;

    type TestError = Box<dyn std::error::Error>;
    type ModuleTask = tokio::task::JoinHandle<Result<(), ModuleError>>;

    struct NullSink;
    impl EventSink for NullSink {
        fn record(&self, _event: &RuntimeEvent) {}
    }

    fn identity() -> TopologyRuntimeIdentity {
        TopologyRuntimeIdentity {
            version: Arc::from("v-test"),
            git_hash: Arc::from("hash-test"),
            deploy_path: PathBuf::from("/deploy/test"),
            start_timestamp: 1_700_000_000,
        }
    }

    /// A two-cluster config; `max_connections` is hot-reloadable, so varying it
    /// publishes a new generation without touching a reload-locked field.
    fn config(max_connections: u64) -> Vec<u8> {
        format!(
            "\n[proxy]\naddr = \"0.0.0.0:6000\"\nmax-connections = {max_connections}\n\n[api]\naddr = \"0.0.0.0:10080\"\n\n[[proxy.backend-clusters]]\nname = \"cluster-a\"\npd-addrs = \"pd-a:2379\"\nns-servers = [\"dns-a:53\"]\n\n[[proxy.backend-clusters]]\nname = \"cluster-b\"\npd-addrs = \"pd-b:2379\"\nns-servers = [\"dns-b:53\"]\n"
        )
        .into_bytes()
    }

    fn client(timeout_ms: u64, ca: &[u8]) -> EtcdClientConfig {
        let tls = EtcdTlsConfig::new(ca.to_vec(), None, None, Some("cluster.local".to_owned()))
            .unwrap_or_else(|_| unreachable!("non-empty CA is valid"));
        EtcdClientConfig::new(["127.0.0.1:1".to_owned()], Some(tls))
            .unwrap_or_else(|_| unreachable!("static endpoint is valid"))
            .with_timeouts(
                Duration::from_millis(500),
                Duration::from_millis(timeout_ms),
                Duration::from_secs(1),
                Duration::from_millis(500),
                Duration::from_secs(1),
            )
            .unwrap_or_else(|_| unreachable!("timeouts are valid"))
    }

    fn cluster(name: Arc<str>, client: EtcdClientConfig) -> TopologyClusterClient {
        TopologyClusterClient {
            cluster_name: name,
            client,
        }
    }

    /// Counts child spawns and stops so a test can prove whether a generation
    /// rebuilt (spawn + stop) or was a no-op / rejection (neither).
    #[derive(Clone, Default)]
    struct Counters {
        spawns: Arc<AtomicUsize>,
        stops: Arc<AtomicUsize>,
    }

    impl Counters {
        fn spawns(&self) -> usize {
            self.spawns.load(Ordering::SeqCst)
        }
        fn stops(&self) -> usize {
            self.stops.load(Ordering::SeqCst)
        }
    }

    /// A runner that just waits for its stop signal, counting spawns and stops.
    fn counting_runner(counters: &Counters) -> ChildRunner {
        let counters = counters.clone();
        Arc::new(move |_owner, _connector, _info, _timeout, mut shutdown| {
            counters.spawns.fetch_add(1, Ordering::SeqCst);
            let stops = Arc::clone(&counters.stops);
            Box::pin(async move {
                let _ = shutdown.changed().await;
                stops.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
        })
    }

    fn runtime() -> Result<ControlRuntime, TestError> {
        let registry = Box::leak(Box::new(OwnershipRegistry::new()));
        Ok(ControlRuntime::claim_process(
            registry,
            "cptopo-module-test",
            ControlConfig::new(
                1,
                Duration::from_secs(30),
                0,
                TlsPolicy::default(),
                LogLevel::Info,
                MetricsPolicy::default(),
            )?,
            Arc::new(NullSink),
        )?)
    }

    fn spawn(
        store: ConfigNamespaceStore,
        factory: Box<dyn TopologyClientFactory>,
        runner: ChildRunner,
        runtime: &ControlRuntime,
    ) -> Result<(ModuleTask, super::TopologyModuleHandle), TestError> {
        let (module, handle) = TopologyModule::new_with_child_runner(
            Arc::new(store),
            factory,
            Arc::new(StaticAdvertiseResolver::new("10.0.0.1")),
            identity(),
            runner,
        );
        let context = runtime.handle().module_context();
        runtime.mark_ready()?;
        let task = tokio::spawn(Box::new(module).run(context));
        Ok((task, handle))
    }

    async fn wait_ready(handle: &mut super::TopologyModuleHandle) -> Result<(), TestError> {
        tokio::time::timeout(Duration::from_secs(5), handle.wait_ready()).await??;
        Ok(())
    }

    async fn wait_observed(
        status: &mut watch::Receiver<TopologyStatus>,
        generation: u64,
    ) -> Result<TopologyStatus, TestError> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            {
                let current = *status.borrow_and_update();
                if current.observed_generation >= generation {
                    return Ok(current);
                }
            }
            tokio::time::timeout(deadline - tokio::time::Instant::now(), status.changed())
                .await??;
        }
    }

    fn shutdown(runtime: &ControlRuntime) -> Result<(), TestError> {
        runtime.advance_shutdown(LifecyclePhase::Draining)?;
        runtime.advance_shutdown(LifecyclePhase::Stopping)?;
        runtime.finish()?;
        Ok(())
    }

    /// Generation-2 factory behaviour, applied after the base generation.
    #[derive(Clone, Copy)]
    enum Gen2 {
        Same,
        TransportChange,
        Missing,
        Extra,
        Renamed,
        Duplicate,
        BuildFail,
    }

    struct SwitchableFactory {
        gen2: Arc<watch::Sender<Option<Gen2>>>,
    }

    impl TopologyClientFactory for SwitchableFactory {
        fn build(
            &self,
            snapshot: &ConfigNamespaceSnapshot,
        ) -> Result<Vec<TopologyClusterClient>, String> {
            let config = snapshot
                .topology()
                .map_err(|_| "topology projection".to_owned())?;
            let names: Vec<Arc<str>> = config
                .backend_clusters
                .iter()
                .map(|c| Arc::clone(&c.name))
                .collect();
            let base = || {
                names
                    .iter()
                    .map(|name| cluster(Arc::clone(name), client(500, b"pem-a")))
                    .collect::<Vec<_>>()
            };
            match *self.gen2.borrow() {
                None | Some(Gen2::Same) => Ok(base()),
                Some(Gen2::TransportChange) => Ok(names
                    .iter()
                    .map(|name| cluster(Arc::clone(name), client(700, b"pem-a")))
                    .collect()),
                Some(Gen2::Missing) => Ok(names
                    .iter()
                    .take(1)
                    .map(|name| cluster(Arc::clone(name), client(500, b"pem-a")))
                    .collect()),
                Some(Gen2::Extra) => {
                    let mut built = base();
                    built.push(cluster(Arc::from("cluster-extra"), client(500, b"pem-a")));
                    Ok(built)
                }
                Some(Gen2::Renamed) => {
                    let mut built = vec![cluster(Arc::clone(&names[0]), client(500, b"pem-a"))];
                    built.push(cluster(Arc::from("cluster-renamed"), client(500, b"pem-a")));
                    Ok(built)
                }
                Some(Gen2::Duplicate) => Ok(vec![
                    cluster(Arc::clone(&names[0]), client(500, b"pem-a")),
                    cluster(Arc::clone(&names[0]), client(500, b"pem-a")),
                ]),
                Some(Gen2::BuildFail) => Err("factory build failed".to_owned()),
            }
        }
    }

    struct Outcome {
        status: TopologyStatus,
        spawns: usize,
        stops: usize,
    }

    async fn run_two_generations(gen2: Gen2) -> Result<Outcome, TestError> {
        let store = ConfigNamespaceStore::from_toml(&config(100), None, &std::env::current_dir()?)?;
        let (gen2_tx, _gen2_rx) = watch::channel(None);
        let gen2_tx = Arc::new(gen2_tx);
        let counters = Counters::default();
        let runtime = runtime()?;
        let (task, mut handle) = spawn(
            store.clone(),
            Box::new(SwitchableFactory {
                gen2: Arc::clone(&gen2_tx),
            }),
            counting_runner(&counters),
            &runtime,
        )?;

        wait_ready(&mut handle).await?;
        let mut status = handle.status();
        assert_eq!(status.borrow_and_update().applied_generation, 1);
        assert_eq!(counters.spawns(), 2, "two clusters spawn on generation 1");
        assert_eq!(counters.stops(), 0);

        gen2_tx.send_replace(Some(gen2));
        store.apply_toml(&config(200), None, 2, &std::env::current_dir()?)?;
        let after = wait_observed(&mut status, 2).await?;
        // Sample counters before shutdown so its stops do not mask retain-old.
        let outcome = Outcome {
            status: after,
            spawns: counters.spawns(),
            stops: counters.stops(),
        };

        runtime.begin_shutdown(ShutdownReason::Requested)?;
        tokio::time::timeout(Duration::from_secs(10), task).await???;
        shutdown(&runtime)?;
        Ok(outcome)
    }

    async fn assert_rejected(gen2: Gen2, expected: RejectionClass) -> Result<(), TestError> {
        let outcome = run_two_generations(gen2).await?;
        assert_eq!(outcome.status.observed_generation, 2);
        assert_eq!(
            outcome.status.applied_generation, 1,
            "a rejected generation retains the last-good applied generation"
        );
        assert_eq!(outcome.status.last_rejection, Some(expected));
        assert_eq!(outcome.spawns, 2, "a rejected generation does not spawn");
        assert_eq!(
            outcome.stops, 0,
            "a rejected generation does not stop old children"
        );
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn unrelated_hot_reload_is_a_noop_without_flap() -> Result<(), TestError> {
        let outcome = run_two_generations(Gen2::Same).await?;
        assert_eq!(outcome.status.applied_generation, 2);
        assert_eq!(outcome.status.last_rejection, None);
        assert_eq!(outcome.spawns, 2, "a no-op does not re-spawn");
        assert_eq!(outcome.stops, 0, "a no-op does not stop");
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn transport_plan_change_rebuilds() -> Result<(), TestError> {
        let outcome = run_two_generations(Gen2::TransportChange).await?;
        assert_eq!(outcome.status.applied_generation, 2);
        assert_eq!(outcome.status.last_rejection, None);
        assert_eq!(
            outcome.spawns, 4,
            "the changed transport re-spawns both clusters"
        );
        assert_eq!(outcome.stops, 2, "the old children were stopped");
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn missing_cluster_is_rejected_and_retains() -> Result<(), TestError> {
        assert_rejected(Gen2::Missing, RejectionClass::ClusterSetMismatch).await
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn extra_cluster_is_rejected_and_retains() -> Result<(), TestError> {
        assert_rejected(Gen2::Extra, RejectionClass::ClusterSetMismatch).await
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn renamed_cluster_is_rejected_and_retains() -> Result<(), TestError> {
        assert_rejected(Gen2::Renamed, RejectionClass::ClusterSetMismatch).await
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn duplicate_cluster_is_rejected_and_retains() -> Result<(), TestError> {
        assert_rejected(Gen2::Duplicate, RejectionClass::DuplicateClusterName).await
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn build_failure_is_rejected_and_retains() -> Result<(), TestError> {
        assert_rejected(Gen2::BuildFail, RejectionClass::ClientBuildFailed).await
    }

    /// A factory that re-reads its CA bytes from one fixed path on every build.
    /// This proves the module's own re-read-and-compare behaviour: a same-path
    /// A->B rotation is observed only because the material is re-read and the
    /// plan compares bytes. It uses a fixed factory path, not the production
    /// `TopologyConfig.cluster_tls.ca_path` mapping, which the composition round
    /// locks separately with a swap/delete test.
    struct FilePemFactory {
        path: PathBuf,
    }

    impl TopologyClientFactory for FilePemFactory {
        fn build(
            &self,
            snapshot: &ConfigNamespaceSnapshot,
        ) -> Result<Vec<TopologyClusterClient>, String> {
            let config = snapshot
                .topology()
                .map_err(|_| "topology projection".to_owned())?;
            let ca = std::fs::read(&self.path).map_err(|error| format!("read pem: {error}"))?;
            Ok(config
                .backend_clusters
                .iter()
                .map(|c| cluster(Arc::clone(&c.name), client(500, &ca)))
                .collect())
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn same_path_pem_bytes_change_rebuilds() -> Result<(), TestError> {
        let path = std::env::temp_dir().join(format!("cptopo-pem-{}.pem", std::process::id()));
        std::fs::write(&path, b"ca-bytes-a")?;
        let store = ConfigNamespaceStore::from_toml(&config(100), None, &std::env::current_dir()?)?;
        let counters = Counters::default();
        let runtime = runtime()?;
        let (task, mut handle) = spawn(
            store.clone(),
            Box::new(FilePemFactory { path: path.clone() }),
            counting_runner(&counters),
            &runtime,
        )?;
        wait_ready(&mut handle).await?;
        let mut status = handle.status();
        let _ = status.borrow_and_update();
        assert_eq!(counters.spawns(), 2);

        // Same path, new bytes: the factory re-reads and the plan differs.
        std::fs::write(&path, b"ca-bytes-b")?;
        store.apply_toml(&config(200), None, 2, &std::env::current_dir()?)?;
        wait_observed(&mut status, 2).await?;
        let spawns = counters.spawns();
        let stops = counters.stops();

        runtime.begin_shutdown(ShutdownReason::Requested)?;
        tokio::time::timeout(Duration::from_secs(10), task).await???;
        shutdown(&runtime)?;
        let _ = std::fs::remove_file(&path);

        assert_eq!(
            spawns, 4,
            "a same-path PEM bytes rotation re-spawns both clusters"
        );
        assert_eq!(stops, 2, "the old children were stopped on rotation");
        Ok(())
    }

    /// A runner where the first child fails on a trigger (a real `Err` or, when
    /// `panic` is set, a panic) and the sibling waits for its stop signal. This
    /// lets one unexpected exit fail the module while the sibling is proven to
    /// be stopped (it saw the signal) and joined (it ran to completion rather
    /// than being aborted).
    fn one_fails_runner(
        fail: watch::Receiver<bool>,
        panic: bool,
        sibling_stops: Arc<AtomicUsize>,
        sibling_completions: Arc<AtomicUsize>,
    ) -> ChildRunner {
        let call = Arc::new(AtomicUsize::new(0));
        Arc::new(move |_owner, _connector, _info, _timeout, mut shutdown| {
            let index = call.fetch_add(1, Ordering::SeqCst);
            let mut fail = fail.clone();
            let sibling_stops = Arc::clone(&sibling_stops);
            let sibling_completions = Arc::clone(&sibling_completions);
            Box::pin(async move {
                if index == 0 {
                    let _ = fail.changed().await;
                    if panic {
                        unreachable!("injected child panic")
                    }
                    Err(RegistrarError::Etcd("injected"))
                } else {
                    let _ = shutdown.changed().await;
                    sibling_stops.fetch_add(1, Ordering::SeqCst);
                    sibling_completions.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                }
            })
        })
    }

    async fn assert_child_exit_fails_loud(panic: bool) -> Result<(), TestError> {
        let store = ConfigNamespaceStore::from_toml(&config(100), None, &std::env::current_dir()?)?;
        let (fail_tx, fail_rx) = watch::channel(false);
        let sibling_stops = Arc::new(AtomicUsize::new(0));
        let sibling_completions = Arc::new(AtomicUsize::new(0));
        let runtime = runtime()?;
        let (task, mut handle) = spawn(
            store,
            Box::new(SwitchableFactory {
                gen2: Arc::new(watch::channel(None).0),
            }),
            one_fails_runner(
                fail_rx,
                panic,
                Arc::clone(&sibling_stops),
                Arc::clone(&sibling_completions),
            ),
            &runtime,
        )?;
        wait_ready(&mut handle).await?;

        fail_tx.send_replace(true);
        let result = tokio::time::timeout(Duration::from_secs(5), task).await??;
        let Err(error) = result else {
            unreachable!("an unexpected child exit must fail the module")
        };
        assert_eq!(error.module, "control_topology");
        assert_eq!(error.error_class, "registration_child_exited");
        // The module returned, so stop_children has joined the sibling: it saw
        // its stop signal exactly once and ran to completion (was not aborted).
        assert_eq!(
            sibling_stops.load(Ordering::SeqCst),
            1,
            "the sibling child was stopped exactly once"
        );
        assert_eq!(
            sibling_completions.load(Ordering::SeqCst),
            1,
            "the sibling child was joined (ran to completion) exactly once"
        );

        runtime.begin_shutdown(ShutdownReason::Requested)?;
        shutdown(&runtime)?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn unexpected_child_error_fails_the_module_loud() -> Result<(), TestError> {
        assert_child_exit_fails_loud(false).await
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn child_panic_fails_the_module_loud() -> Result<(), TestError> {
        assert_child_exit_fails_loud(true).await
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn wedged_child_is_aborted_so_shutdown_completes() -> Result<(), TestError> {
        /// Increments a counter when the wedged future is dropped, so an abort
        /// (not just a return) can be proven.
        struct DropGuard(Arc<AtomicUsize>);
        impl Drop for DropGuard {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        let store = ConfigNamespaceStore::from_toml(&config(100), None, &std::env::current_dir()?)?;
        let drops = Arc::new(AtomicUsize::new(0));
        let runner: ChildRunner = {
            let drops = Arc::clone(&drops);
            Arc::new(move |_owner, _connector, _info, _timeout, _shutdown| {
                let guard = DropGuard(Arc::clone(&drops));
                Box::pin(async move {
                    let _guard = guard;
                    pending::<()>().await;
                    Ok(())
                })
            })
        };
        let runtime = runtime()?;
        let (task, mut handle) = spawn(
            store,
            Box::new(SwitchableFactory {
                gen2: Arc::new(watch::channel(None).0),
            }),
            runner,
            &runtime,
        )?;
        wait_ready(&mut handle).await?;

        // Even a wedged child must not prevent shutdown: it is aborted only after
        // the bounded grace, so the module returns within grace plus a small
        // margin and the aborted futures are dropped.
        let grace = super::CHILD_STOP_GRACE;
        let upper = grace.saturating_add(Duration::from_secs(3));
        let lower = grace.saturating_sub(Duration::from_millis(500));
        let start = tokio::time::Instant::now();
        runtime.begin_shutdown(ShutdownReason::Requested)?;
        let result = tokio::time::timeout(upper, task).await??;
        let elapsed = start.elapsed();
        assert!(
            result.is_ok(),
            "a wedged child must not block a clean shutdown"
        );
        assert!(
            elapsed >= lower,
            "shutdown must wait the bounded grace before aborting"
        );
        assert!(
            elapsed <= upper,
            "shutdown must complete within the grace plus a small margin"
        );
        assert_eq!(
            drops.load(Ordering::SeqCst),
            2,
            "both wedged children were aborted and dropped"
        );
        shutdown(&runtime)?;
        Ok(())
    }

    #[test]
    fn unspecified_bind_with_port_range_resolves_first_port_and_global_unicast_host()
    -> Result<(), TestError> {
        use control_config::ConfigNamespaceSource;
        use std::net::IpAddr;

        use crate::register::TopologyInfo;
        use crate::resolver::{AdvertiseEndpointResolver, InterfaceAdvertiseResolver};

        // A wildcard bind host with a SQL port range: the projection's bind host
        // is unspecified and the SQL port is the range's first port.
        let toml = br#"
[proxy]
addr = "0.0.0.0:6000"
port-range = [10000, 10002]

[api]
addr = "0.0.0.0:10080"

[[proxy.backend-clusters]]
name = "cluster-a"
pd-addrs = "pd-a:2379"
ns-servers = ["dns-a:53"]
"#;
        let store = ConfigNamespaceStore::from_toml(toml, None, &std::env::current_dir()?)?;
        let topology = store.current().topology()?;
        assert_eq!(topology.bind_sql_host.as_ref(), "0.0.0.0");
        assert_eq!(
            topology.sql_port, 10000,
            "the first port of the range is used"
        );

        // The resolver replaces the wildcard bind host with a global-unicast
        // interface candidate, and the registration address pairs it with the
        // first port.
        let resolver = InterfaceAdvertiseResolver::new(Arc::new(|| {
            vec![
                "10.0.0.7"
                    .parse::<IpAddr>()
                    .unwrap_or_else(|_| unreachable!("valid ip")),
            ]
        }));
        let advertise_host = resolver.resolve(&topology)?;
        assert_eq!(advertise_host.as_ref(), "10.0.0.7");

        let id = identity();
        let info = TopologyInfo::new(
            &advertise_host,
            topology.sql_port,
            topology.status_port,
            &id.version,
            &id.git_hash,
            &id.deploy_path.to_string_lossy(),
            id.start_timestamp,
        );
        assert_eq!(info.registration_addr(), "10.0.0.7:10000");
        Ok(())
    }
}
