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

//! The `control_topology` self-registration and discovery-publication module.
//!
//! [`TopologyModule`] is a [`control_plane::ControlModule`] that runs
//! self-registration and publishes topology discovery. It subscribes to the
//! injected [`control_config::ConfigNamespaceStore`], and for every configuration
//! generation it fans one [`crate::registrar::run`] loop out per backend cluster
//! (Go keeps one `InfoSyncer` per cluster), each publishing the same
//! [`TopologyInfo`] under its own per-instance lease, and — when the cluster
//! material changes — publishes a new discovery generation for the
//! [`crate::DiscoveryHandle`] to pull.
//!
//! Becoming ready means both the initial registration children are installed and
//! the initial discovery set is published; it does not imply PD is reachable or
//! that any topology has yet been fetched.
//!
//! # Generation fence
//!
//! The process [`control_plane::OwnerToken`] isolates process owners but not
//! successive configuration generations inside one process. So on every
//! generation change the module builds the new client set first, then stops and
//! **joins** every old child before starting the new ones. A late write from a
//! retired generation can therefore never overwrite a newer snapshot.
//!
//! # Discovery publication
//!
//! Discovery rotates on its own "client epoch", which bumps only when the cluster
//! *material* (endpoints / TLS / `ns_servers`) changes — an advertise-only or
//! log-level reconfigure reuses the same long-lived channels and does not flap
//! discovery. Each generation is prepared (all cluster connections built) before
//! anything is committed, so a connect failure retains the last-good registration
//! and discovery; and on any run-loop exit the publication is RAII-revoked, so the
//! handle is left zero-I/O fail-closed. The immutable snapshot published to
//! CP-ROUTE (stamped by client epoch) is a dependent follow-up (#214).

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

use crate::discovery_publish::{
    DiscoveryConnector, DiscoveryHandle, DiscoveryPublisher, default_discovery_connector,
};
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
#[derive(Clone)]
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

/// The self-registration and discovery-publication control-plane module.
pub struct TopologyModule {
    source: Arc<dyn ConfigNamespaceSource>,
    factory: Box<dyn TopologyClientFactory>,
    resolver: Arc<dyn AdvertiseEndpointResolver>,
    identity: TopologyRuntimeIdentity,
    ready: watch::Sender<bool>,
    status: watch::Sender<TopologyStatus>,
    child_runner: ChildRunner,
    discovery: DiscoveryPublisher,
    discovery_connector: DiscoveryConnector,
}

/// Registration-readiness handle returned alongside a [`TopologyModule`].
///
/// The composition root waits on [`TopologyModuleHandle::wait_ready`] before
/// starting modules that depend on registration and discovery having begun, then
/// pulls discovery through [`TopologyModuleHandle::discovery_handle`].
pub struct TopologyModuleHandle {
    ready: watch::Receiver<bool>,
    status: watch::Receiver<TopologyStatus>,
    discovery: DiscoveryHandle,
}

impl TopologyModuleHandle {
    /// Resolves once the module has applied its initial configuration
    /// generation: the registration children are spawned and the initial
    /// discovery set is published.
    ///
    /// This is a local determinism guarantee that registration and discovery
    /// publication have begun: it does not require PD to be reachable
    /// (registration keeps retrying underneath) and does not imply any topology
    /// has yet been fetched through the discovery handle.
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

    /// A pull-on-demand discovery handle for the published topology. It is
    /// generation-fenced: a pull under a retired client epoch fails closed rather
    /// than returning stale data. Cheap to clone.
    #[must_use]
    pub fn discovery_handle(&self) -> DiscoveryHandle {
        self.discovery.clone()
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
        Self::build(
            source,
            factory,
            resolver,
            identity,
            default_child_runner(),
            default_discovery_connector(),
        )
    }

    /// Test-only constructor that injects a deterministic child runner, used to
    /// exercise unexpected-child-exit and wedged-shutdown handling without a
    /// live backend. Discovery uses a plaintext connector so the registration
    /// tests need not stand up real TLS material. Not compiled into production.
    #[cfg(test)]
    fn new_with_child_runner(
        source: Arc<dyn ConfigNamespaceSource>,
        factory: Box<dyn TopologyClientFactory>,
        resolver: Arc<dyn AdvertiseEndpointResolver>,
        identity: TopologyRuntimeIdentity,
        child_runner: ChildRunner,
    ) -> (Self, TopologyModuleHandle) {
        let connector: DiscoveryConnector = Arc::new(|owner, _client| {
            Box::pin(async move {
                let config = EtcdClientConfig::new(vec!["127.0.0.1:1".to_owned()], None)
                    .unwrap_or_else(|_| unreachable!("a plaintext endpoint is valid"));
                EtcdConnector::new(owner, config).connect().await
            })
        });
        Self::build(source, factory, resolver, identity, child_runner, connector)
    }

    /// Test-only constructor that injects both a deterministic child runner and
    /// a discovery connector, so a test can count and gate the per-cluster
    /// discovery connections a generation builds. Not compiled into production.
    #[cfg(test)]
    fn new_with_child_runner_and_connector(
        source: Arc<dyn ConfigNamespaceSource>,
        factory: Box<dyn TopologyClientFactory>,
        resolver: Arc<dyn AdvertiseEndpointResolver>,
        identity: TopologyRuntimeIdentity,
        child_runner: ChildRunner,
        discovery_connector: DiscoveryConnector,
    ) -> (Self, TopologyModuleHandle) {
        Self::build(
            source,
            factory,
            resolver,
            identity,
            child_runner,
            discovery_connector,
        )
    }

    /// Drives the discovery publisher's epoch counter to a chosen value before
    /// the module runs, so a test can exercise the checked-epoch overflow path.
    #[cfg(test)]
    fn force_next_epoch(&self, next_epoch: u64) {
        self.discovery.set_next_epoch(next_epoch);
    }

    fn build(
        source: Arc<dyn ConfigNamespaceSource>,
        factory: Box<dyn TopologyClientFactory>,
        resolver: Arc<dyn AdvertiseEndpointResolver>,
        identity: TopologyRuntimeIdentity,
        child_runner: ChildRunner,
        discovery_connector: DiscoveryConnector,
    ) -> (Self, TopologyModuleHandle) {
        let (ready_tx, ready_rx) = watch::channel(false);
        let (status_tx, status_rx) = watch::channel(TopologyStatus::default());
        let (discovery, discovery_handle) = DiscoveryPublisher::new();
        (
            Self {
                source,
                factory,
                resolver,
                identity,
                ready: ready_tx,
                status: status_tx,
                child_runner,
                discovery,
                discovery_connector,
            },
            TopologyModuleHandle {
                ready: ready_rx,
                status: status_rx,
                discovery: discovery_handle,
            },
        )
    }

    async fn run_inner(self, context: ModuleContext) -> Result<(), ModuleError> {
        let owner = context.owner().clone();
        let mut lifecycle = context.lifecycle();
        let mut updates = self.source.subscribe();
        let mut children = Children::default();
        let mut active_plan: Option<RegistrationPlan> = None;
        // RAII: on any exit — a clean retire, an error return, or the task being
        // dropped/aborted — revoke the current discovery gate and withdraw the
        // published set, so the handle is left zero-I/O fail-closed.
        let _discovery_revoke = DiscoveryRevoke(&self.discovery);

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
                    // Retire the registration only once the runtime reaches
                    // Stopping (SQL sessions have already been joined), or if the
                    // lifecycle channel closed so no later phase can arrive.
                    // Quiescing/Draining keep the registration and lease refresh
                    // alive so this instance stays discoverable during drain.
                    if changed.is_err() || retire_requested(lifecycle.borrow().phase) {
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

        // The discovery generation ("client epoch") rotates only on a change to
        // the cluster *material* — the name-sorted (name, client) set — so an
        // advertise-only or log-level reconfigure reuses the same long-lived
        // channels and does not flap discovery, even though it may re-register.
        let material: Vec<(Arc<str>, EtcdClientConfig)> = clusters
            .iter()
            .map(|cluster| (Arc::clone(&cluster.cluster_name), cluster.client.clone()))
            .collect();
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
        let registration_unchanged = active_plan.as_ref() == Some(&plan);
        let discovery_unchanged = self.discovery.material_unchanged(&material);
        if registration_unchanged && discovery_unchanged {
            // Nothing that affects registration or discovery changed.
            return Ok(());
        }

        // Prepare-then-commit: build the new discovery generation's connections
        // (lazy, no network) BEFORE mutating any live state, so a connect failure
        // leaves both the registration children and the last-good discovery set
        // untouched.
        let prepared = if discovery_unchanged {
            None
        } else {
            match self
                .discovery
                .prepare(&self.discovery_connector, owner, material)
                .await
            {
                Ok(prepared) => Some(prepared),
                Err(_) => return Err(RejectionClass::ClientBuildFailed),
            }
        };

        // Commit registration first (fence: retire the previous generation before
        // the new one publishes), then commit discovery (revoke the old gate,
        // publish the new epoch).
        if !registration_unchanged {
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
        }
        // The discovery generation was fully prepared (connections built + epoch
        // reserved) before the registration switch above, so this commit is
        // infallible and the two planes can never split.
        if let Some(prepared) = prepared {
            self.discovery.commit(prepared);
        }
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

/// Whether a lifecycle phase means the module must retire its registration.
///
/// Retirement deliberately waits for `Stopping` (or the terminal `Stopped`):
/// the process keeps its topology registration and lease refresh alive through
/// `Quiescing` and `Draining` so this instance stays discoverable while SQL
/// sessions drain, mirroring Go's `clusterManager.Close()` retiring the
/// `InfoSyncer` only after the serving layer is closed. A `Failed` runtime is
/// still advanced through `Draining` to `Stopping` before its modules join, so
/// it too retires at `Stopping`, after session join. A dropped lifecycle
/// channel is handled separately by the run loop, since no later phase can
/// arrive.
const fn retire_requested(phase: LifecyclePhase) -> bool {
    matches!(phase, LifecyclePhase::Stopping | LifecyclePhase::Stopped)
}

const fn module_error(error_class: &'static str) -> ModuleError {
    ModuleError {
        module: MODULE_NAME,
        error_class,
    }
}

/// Revokes the discovery publication when the module's run loop exits by any
/// path — a clean retire, an error return, or the task being dropped/aborted —
/// so the handle is always left zero-I/O fail-closed.
struct DiscoveryRevoke<'module>(&'module DiscoveryPublisher);

impl Drop for DiscoveryRevoke<'_> {
    fn drop(&mut self) {
        self.0.revoke();
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
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
    use std::time::Duration;

    use control_config::{ConfigNamespaceSnapshot, ConfigNamespaceStore, TopologyRuntimeIdentity};
    use control_external::{
        EtcdClientConfig, EtcdConnectError, EtcdConnector, EtcdTlsConfig, EtcdTlsPolicy,
    };
    use control_plane::{
        ControlConfig, ControlModule, ControlRuntime, EventSink, LifecyclePhase, LogLevel,
        MetricsPolicy, ModuleError, OwnershipRegistry, RuntimeEvent, ShutdownReason, TlsPolicy,
    };
    use tokio::sync::watch;

    use crate::TopologyClientFactory;
    use crate::discovery_publish::{DiscoveryConnector, DiscoveryError};
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

    /// A config with ZERO backend clusters: no `[[proxy.backend-clusters]]` and an
    /// explicitly empty top-level `pd-addrs` (which otherwise defaults to a single
    /// cluster), so the normalized topology has an empty cluster set.
    fn config_zero() -> Vec<u8> {
        b"\n[proxy]\naddr = \"0.0.0.0:6000\"\npd-addrs = \"\"\n\n[api]\naddr = \"0.0.0.0:10080\"\n"
            .to_vec()
    }

    /// A single-backend-cluster config; `max_connections` is hot-reloadable, so a
    /// new generation can be published without touching a reload-locked field.
    fn config_single(max_connections: u64) -> Vec<u8> {
        format!(
            "\n[proxy]\naddr = \"0.0.0.0:6000\"\nmax-connections = {max_connections}\n\n[api]\naddr = \"0.0.0.0:10080\"\n\n[[proxy.backend-clusters]]\nname = \"cluster-a\"\npd-addrs = \"pd-a:2379\"\nns-servers = []\n"
        )
        .into_bytes()
    }

    fn client(timeout_ms: u64, ca: &[u8]) -> EtcdClientConfig {
        let tls = EtcdTlsConfig::new(
            Some(ca.to_vec()),
            None,
            None,
            Some("cluster.local".to_owned()),
            EtcdTlsPolicy::default(),
        )
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

    /// A discovery connector that counts how many per-cluster connections it
    /// builds, returning a real plaintext (lazy, no-network) `EtcdConnection`.
    /// This lets a test prove that discovery reconnects exactly once per cluster
    /// on a material rotation and never on an unrelated or rejected generation,
    /// and that a poll forks the epoch's connection rather than reconnecting.
    fn counting_connector(count: &Arc<AtomicUsize>) -> DiscoveryConnector {
        let count = Arc::clone(count);
        Arc::new(move |owner, _client| {
            count.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move {
                let config = EtcdClientConfig::new(vec!["127.0.0.1:1".to_owned()], None)
                    .unwrap_or_else(|_| unreachable!("a plaintext endpoint is valid"));
                EtcdConnector::new(owner, config).connect().await
            })
        })
    }

    /// A discovery connector that counts attempts and connects (real
    /// `EtcdConnector::connect`) to the endpoints of the *supplied* client — so a
    /// test whose factory points the cluster at a live fixture gets a working
    /// discovery connection, and its poll can assert a real payload.
    fn counting_real_connector(count: &Arc<AtomicUsize>) -> DiscoveryConnector {
        let count = Arc::clone(count);
        Arc::new(move |owner, client| {
            count.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move { EtcdConnector::new(owner, client).connect().await })
        })
    }

    /// A discovery connector that connects (real plaintext) while `fail` is unset
    /// and returns a retired-owner connect failure once it is set, counting every
    /// attempt. This exercises prepare-then-commit: a later material rotation whose
    /// connect fails must retain both the registration children and the last-good
    /// discovery set.
    fn gated_fail_connector(
        count: &Arc<AtomicUsize>,
        fail: &Arc<AtomicBool>,
    ) -> DiscoveryConnector {
        let count = Arc::clone(count);
        let fail = Arc::clone(fail);
        Arc::new(move |owner, _client| {
            count.fetch_add(1, Ordering::SeqCst);
            let fail = fail.load(Ordering::SeqCst);
            Box::pin(async move {
                if fail {
                    return Err(EtcdConnectError::StaleOwner);
                }
                let config = EtcdClientConfig::new(vec!["127.0.0.1:1".to_owned()], None)
                    .unwrap_or_else(|_| unreachable!("a plaintext endpoint is valid"));
                EtcdConnector::new(owner, config).connect().await
            })
        })
    }

    /// Mirrors [`spawn`] but injects a supplied discovery connector so a test can
    /// count and gate the per-cluster discovery connections.
    fn spawn_with_connector(
        store: ConfigNamespaceStore,
        factory: Box<dyn TopologyClientFactory>,
        runner: ChildRunner,
        connector: DiscoveryConnector,
        runtime: &ControlRuntime,
    ) -> Result<(ModuleTask, super::TopologyModuleHandle), TestError> {
        let (module, handle) = TopologyModule::new_with_child_runner_and_connector(
            Arc::new(store),
            factory,
            Arc::new(StaticAdvertiseResolver::new("10.0.0.1")),
            identity(),
            runner,
            connector,
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

    /// Drives the runtime to `Stopping` (the phase at which the module retires
    /// its registration) without calling `finish`, so a test can then join the
    /// module task before finishing the runtime.
    fn request_stop(runtime: &ControlRuntime) -> Result<(), TestError> {
        runtime.begin_shutdown(ShutdownReason::Requested)?;
        runtime.advance_shutdown(LifecyclePhase::Draining)?;
        runtime.advance_shutdown(LifecyclePhase::Stopping)?;
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

        request_stop(&runtime)?;
        tokio::time::timeout(Duration::from_secs(10), task).await???;
        runtime.finish()?;
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

        request_stop(&runtime)?;
        tokio::time::timeout(Duration::from_secs(10), task).await???;
        runtime.finish()?;
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
        request_stop(&runtime)?;
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
        runtime.finish()?;
        Ok(())
    }

    /// A stable factory + counting runner, spawned and ready. Used by the
    /// shutdown-ordering oracles.
    async fn spawn_ready(
        counters: &Counters,
        runtime: &ControlRuntime,
    ) -> Result<ModuleTask, TestError> {
        let store = ConfigNamespaceStore::from_toml(&config(100), None, &std::env::current_dir()?)?;
        let (task, mut handle) = spawn(
            store,
            Box::new(SwitchableFactory {
                gen2: Arc::new(watch::channel(None).0),
            }),
            counting_runner(counters),
            runtime,
        )?;
        wait_ready(&mut handle).await?;
        Ok(task)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn registration_survives_drain_and_is_retired_only_at_stopping() -> Result<(), TestError>
    {
        let counters = Counters::default();
        let runtime = runtime()?;
        let task = spawn_ready(&counters, &runtime).await?;
        assert_eq!(counters.spawns(), 2);

        // Quiescing then Draining must NOT retire the registration: the instance
        // stays discoverable while SQL sessions drain.
        runtime.begin_shutdown(ShutdownReason::Requested)?;
        runtime.advance_shutdown(LifecyclePhase::Draining)?;
        tokio::time::sleep(Duration::from_millis(250)).await;
        assert_eq!(
            counters.stops(),
            0,
            "registration must survive Quiescing and Draining"
        );
        assert!(
            !task.is_finished(),
            "the module must keep running through drain"
        );

        // Stopping retires it: the child stops and the module joins.
        runtime.advance_shutdown(LifecyclePhase::Stopping)?;
        tokio::time::timeout(Duration::from_secs(10), task).await???;
        assert_eq!(
            counters.stops(),
            2,
            "both clusters' registrations are retired, at Stopping"
        );
        runtime.finish()?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_failed_runtime_still_retires_registration_only_at_stopping() -> Result<(), TestError>
    {
        let counters = Counters::default();
        let runtime = runtime()?;
        let task = spawn_ready(&counters, &runtime).await?;

        // A failure makes shutdown mandatory but still advances through Draining
        // (where SQL sessions join) before Stopping; the registration must not be
        // retired until Stopping.
        runtime.fail("test", "injected_failure");
        runtime.advance_shutdown(LifecyclePhase::Draining)?;
        tokio::time::sleep(Duration::from_millis(250)).await;
        assert_eq!(
            counters.stops(),
            0,
            "a failed runtime must not retire registration before Stopping"
        );

        runtime.advance_shutdown(LifecyclePhase::Stopping)?;
        tokio::time::timeout(Duration::from_secs(10), task).await???;
        assert_eq!(counters.stops(), 2, "both retired, at Stopping");
        runtime.finish()?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_dropped_lifecycle_channel_retires_registration() -> Result<(), TestError> {
        let counters = Counters::default();
        let runtime = runtime()?;
        let task = spawn_ready(&counters, &runtime).await?;

        // If the runtime disappears, no later phase can arrive; the module must
        // still retire its registration rather than leak the child.
        drop(runtime);
        tokio::time::timeout(Duration::from_secs(10), task).await???;
        assert_eq!(
            counters.stops(),
            2,
            "a dropped lifecycle channel retires the registration"
        );
        Ok(())
    }

    /// The connect-count discovery oracle: discovery connects exactly once per
    /// cluster at ready, a poll forks that epoch's connection (never
    /// reconnecting), an unrelated (advertise-only) generation does not flap
    /// discovery, and only a material change (a different etcd client timeout)
    /// rotates it — reconnecting both clusters. This kills a per-poll rebuild and
    /// a config-number-driven flap. Making `reconfigure` rebuild discovery on
    /// every generation (ignoring `material_unchanged`) turns the unrelated-
    /// generation assertion RED.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn discovery_reconnects_only_on_a_material_change_never_per_poll_or_unrelated()
    -> Result<(), TestError> {
        let store = ConfigNamespaceStore::from_toml(&config(100), None, &std::env::current_dir()?)?;
        let (gen2_tx, _gen2_rx) = watch::channel(None);
        let gen2_tx = Arc::new(gen2_tx);
        let counters = Counters::default();
        let connects = Arc::new(AtomicUsize::new(0));
        let runtime = runtime()?;
        let (task, mut handle) = spawn_with_connector(
            store.clone(),
            Box::new(SwitchableFactory {
                gen2: Arc::clone(&gen2_tx),
            }),
            counting_runner(&counters),
            counting_connector(&connects),
            &runtime,
        )?;
        wait_ready(&mut handle).await?;
        let mut status = handle.status();
        let _ = status.borrow_and_update();
        assert_eq!(
            connects.load(Ordering::SeqCst),
            2,
            "each of the two clusters connected exactly once at ready"
        );

        // A poll forks the epoch's connections for one pull; it must NOT
        // reconnect. The pull itself may fail (the plaintext endpoint has no
        // server) — the oracle is the connector count, not the pull result. The
        // await is bounded because it touches a real socket.
        let discovery = handle.discovery_handle();
        let _ =
            tokio::time::timeout(Duration::from_secs(5), discovery.poll_merged_topology()).await;
        let _ =
            tokio::time::timeout(Duration::from_secs(5), discovery.poll_merged_topology()).await;
        assert_eq!(
            connects.load(Ordering::SeqCst),
            2,
            "a poll forks the epoch's connection; it does not reconnect"
        );

        // An unrelated (advertise-only) generation: same clients + a hot-reloaded
        // max-connections. Neither registration nor discovery changes, so no
        // reconnect and no rotation.
        gen2_tx.send_replace(Some(Gen2::Same));
        store.apply_toml(&config(200), None, 2, &std::env::current_dir()?)?;
        wait_observed(&mut status, 2).await?;
        assert_eq!(
            connects.load(Ordering::SeqCst),
            2,
            "an unrelated generation does not flap discovery"
        );

        // A material change (a different etcd client timeout) rotates discovery:
        // both clusters reconnect, so the count reaches four.
        gen2_tx.send_replace(Some(Gen2::TransportChange));
        store.apply_toml(&config(300), None, 3, &std::env::current_dir()?)?;
        wait_observed(&mut status, 3).await?;
        assert_eq!(
            connects.load(Ordering::SeqCst),
            4,
            "a material change reconnects both clusters (the epoch rotated)"
        );

        request_stop(&runtime)?;
        tokio::time::timeout(Duration::from_secs(10), task).await???;
        runtime.finish()?;
        Ok(())
    }

    /// The RAII-revoke shutdown oracle: when the module's run loop exits, the
    /// discovery publication is withdrawn, so the handle fails closed
    /// (`Revoked`) with no I/O — for both the merged-topology and Prometheus
    /// polls. Removing the `DiscoveryRevoke` RAII guard leaves the last set
    /// published after exit and turns these assertions RED.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn shutdown_raii_revokes_the_discovery_and_fails_closed() -> Result<(), TestError> {
        let store = ConfigNamespaceStore::from_toml(&config(100), None, &std::env::current_dir()?)?;
        let counters = Counters::default();
        let connects = Arc::new(AtomicUsize::new(0));
        let runtime = runtime()?;
        let (task, mut handle) = spawn_with_connector(
            store,
            Box::new(SwitchableFactory {
                gen2: Arc::new(watch::channel(None).0),
            }),
            counting_runner(&counters),
            counting_connector(&connects),
            &runtime,
        )?;
        wait_ready(&mut handle).await?;
        // Capture the handle while the publication is live, then drive the module
        // to exit and join it so the RAII revoke has run.
        let discovery = handle.discovery_handle();
        assert_eq!(connects.load(Ordering::SeqCst), 2);

        request_stop(&runtime)?;
        tokio::time::timeout(Duration::from_secs(10), task).await???;
        runtime.finish()?;

        assert_eq!(
            discovery.poll_merged_topology().await.err(),
            Some(DiscoveryError::Revoked),
            "the publication is withdrawn on exit; the merged poll fails closed"
        );
        assert_eq!(
            discovery.poll_prometheus("cluster-a").await.err(),
            Some(DiscoveryError::Revoked),
            "the Prometheus poll also fails closed after revoke"
        );
        assert_eq!(
            connects.load(Ordering::SeqCst),
            2,
            "a fail-closed handle attempts no further connections"
        );
        Ok(())
    }

    /// The rejection-retains oracle: a rejected generation (a cluster-set
    /// mismatch) neither reconnects nor rotates discovery — the last-good epoch's
    /// connections are retained untouched. This kills "a rejection clears or
    /// rotates the discovery set".
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_rejected_generation_retains_the_last_good_discovery() -> Result<(), TestError> {
        let store = ConfigNamespaceStore::from_toml(&config(100), None, &std::env::current_dir()?)?;
        let (gen2_tx, _gen2_rx) = watch::channel(None);
        let gen2_tx = Arc::new(gen2_tx);
        let counters = Counters::default();
        let connects = Arc::new(AtomicUsize::new(0));
        let runtime = runtime()?;
        let (task, mut handle) = spawn_with_connector(
            store.clone(),
            Box::new(SwitchableFactory {
                gen2: Arc::clone(&gen2_tx),
            }),
            counting_runner(&counters),
            counting_connector(&connects),
            &runtime,
        )?;
        wait_ready(&mut handle).await?;
        let mut status = handle.status();
        let _ = status.borrow_and_update();
        assert_eq!(connects.load(Ordering::SeqCst), 2);

        // A rejected generation: the factory drops a cluster (a set mismatch).
        gen2_tx.send_replace(Some(Gen2::Missing));
        store.apply_toml(&config(200), None, 2, &std::env::current_dir()?)?;
        let after = wait_observed(&mut status, 2).await?;
        assert_eq!(
            after.last_rejection,
            Some(RejectionClass::ClusterSetMismatch),
            "the generation is rejected as a cluster-set mismatch"
        );
        assert_eq!(
            after.applied_generation, 1,
            "the last-good applied generation is retained"
        );
        assert_eq!(
            connects.load(Ordering::SeqCst),
            2,
            "a rejected generation neither reconnects nor rotates discovery"
        );

        request_stop(&runtime)?;
        tokio::time::timeout(Duration::from_secs(10), task).await???;
        runtime.finish()?;
        Ok(())
    }

    /// Prepare-then-commit atomicity (blocker 4): when a later material rotation's
    /// discovery `prepare` fails at connect, BOTH planes are retained — the
    /// registration children are not torn down (no extra stops), the status shows
    /// a `ClientBuildFailed` rejection with the last-good `applied_generation`, and
    /// the last-good discovery set is still the published, admissible generation
    /// (a poll fails on I/O against the dead endpoint, i.e. `TopologyUnavailable`,
    /// never `Revoked` or `Stale`). Moving the discovery `commit`/`prepare` ahead
    /// of the registration switch, or tearing children down before the connect
    /// succeeds, breaks this.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_failing_material_rotation_retains_both_registration_and_discovery()
    -> Result<(), TestError> {
        let store = ConfigNamespaceStore::from_toml(&config(100), None, &std::env::current_dir()?)?;
        let (gen2_tx, _gen2_rx) = watch::channel(None);
        let gen2_tx = Arc::new(gen2_tx);
        let counters = Counters::default();
        let connects = Arc::new(AtomicUsize::new(0));
        let fail = Arc::new(AtomicBool::new(false));
        let runtime = runtime()?;
        let (task, mut handle) = spawn_with_connector(
            store.clone(),
            Box::new(SwitchableFactory {
                gen2: Arc::clone(&gen2_tx),
            }),
            counting_runner(&counters),
            gated_fail_connector(&connects, &fail),
            &runtime,
        )?;
        wait_ready(&mut handle).await?;
        let mut status = handle.status();
        let _ = status.borrow_and_update();
        assert_eq!(
            connects.load(Ordering::SeqCst),
            2,
            "both clusters connected once on the initial generation"
        );
        assert_eq!(counters.spawns(), 2);
        assert_eq!(counters.stops(), 0);

        // Arm the connector to fail, then apply a material rotation. The discovery
        // prepare connects the first cluster, fails, and returns before any live
        // state is mutated.
        fail.store(true, Ordering::SeqCst);
        gen2_tx.send_replace(Some(Gen2::TransportChange));
        store.apply_toml(&config(200), None, 2, &std::env::current_dir()?)?;
        let after = wait_observed(&mut status, 2).await?;
        assert_eq!(
            after.last_rejection,
            Some(RejectionClass::ClientBuildFailed),
            "a connect failure on the rotation is a ClientBuildFailed rejection"
        );
        assert_eq!(
            after.applied_generation, 1,
            "the last-good applied generation is retained"
        );
        // Registration retained: no child was stopped (the failing prepare returns
        // before the registration switch).
        assert_eq!(
            counters.stops(),
            0,
            "a failing rotation does not tear down the registration children"
        );
        assert_eq!(counters.spawns(), 2, "no new registration child is spawned");

        // Discovery retained: the last-good epoch-0 set is still the published,
        // admissible generation, so a poll gets past admit + the final fence and
        // fails only on the dead endpoint's I/O — never Revoked or Stale.
        let discovery = handle.discovery_handle();
        let Ok(result) =
            tokio::time::timeout(Duration::from_secs(5), discovery.poll_merged_topology()).await
        else {
            unreachable!("the poll resolves within the deadline");
        };
        assert!(
            matches!(result, Err(DiscoveryError::TopologyUnavailable(_))),
            "the retained set is admitted and current; only its I/O fails: {result:?}"
        );

        request_stop(&runtime)?;
        tokio::time::timeout(Duration::from_secs(10), task).await???;
        runtime.finish()?;
        Ok(())
    }

    /// A zero-cluster initial generation still publishes a discovery set: after
    /// ready, a merged poll returns `Ok` with an empty topology at epoch 0 and the
    /// connector was never called (nothing to connect). This proves the initial
    /// generation publishes `Some(empty)` — not `None` — before ready.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_zero_cluster_initial_generation_publishes_an_empty_topology_at_epoch_zero()
    -> Result<(), TestError> {
        let store =
            ConfigNamespaceStore::from_toml(&config_zero(), None, &std::env::current_dir()?)?;
        let counters = Counters::default();
        let connects = Arc::new(AtomicUsize::new(0));
        let runtime = runtime()?;
        let (task, mut handle) = spawn_with_connector(
            store,
            Box::new(SwitchableFactory {
                gen2: Arc::new(watch::channel(None).0),
            }),
            counting_runner(&counters),
            counting_connector(&connects),
            &runtime,
        )?;
        wait_ready(&mut handle).await?;
        assert_eq!(
            connects.load(Ordering::SeqCst),
            0,
            "a zero-cluster generation connects nothing"
        );
        assert_eq!(counters.spawns(), 0, "no registration child is spawned");

        let discovery = handle.discovery_handle();
        let Ok(result) =
            tokio::time::timeout(Duration::from_secs(5), discovery.poll_merged_topology()).await
        else {
            unreachable!("the empty poll resolves within the deadline");
        };
        let merged = result.unwrap_or_else(|error| {
            unreachable!("an empty topology is a successful poll, not an error: {error:?}")
        });
        assert_eq!(
            merged.client_epoch, 0,
            "the initial (empty) generation publishes epoch 0"
        );
        assert!(
            merged.value.backends.is_empty(),
            "a zero-cluster generation yields no backends"
        );

        request_stop(&runtime)?;
        tokio::time::timeout(Duration::from_secs(10), task).await???;
        runtime.finish()?;
        Ok(())
    }

    /// A minimal in-process etcd v3 `KV.Range` fixture (hand-rolled tonic over
    /// plain hyper h2, real prefix-range filtering) serving the `TiDB` topology
    /// prefixes, plus a factory that points one cluster at it with a
    /// timeout-driven material knob. Used only by the epoch-overflow module test,
    /// which must assert a real discovery poll payload (a `127.0.0.1:1` connection
    /// returns nothing). Mirrors `tests/discovery_fence.rs`.
    mod overflow_fixture {
        use std::convert::Infallible;
        use std::net::SocketAddr;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::time::Duration;

        use control_config::ConfigNamespaceSnapshot;
        use control_external::EtcdClientConfig;
        use hyper::body::Incoming;
        use hyper_util::rt::{TokioExecutor, TokioIo};
        use hyper_util::service::TowerToHyperService;
        use tokio::net::{TcpListener, TcpStream};
        use tonic::codegen::{BoxFuture, Context, Poll, Service, http};
        use tonic::server::{Grpc, NamedService, UnaryService};
        use tonic_prost::ProstCodec;

        use crate::{TopologyClientFactory, TopologyClusterClient};

        const RANGE_PATH: &str = "/etcdserverpb.KV/Range";
        const KV_SERVICE_NAME: &str = "etcdserverpb.KV";

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

        #[derive(Clone)]
        struct KvFixture {
            seeded: Arc<Vec<(Vec<u8>, Vec<u8>)>>,
        }

        /// Real etcd `Range` semantics: an empty `range_end` is an exact get,
        /// otherwise a half-open range `key <= k < range_end`, ascending by key.
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
                        let mut grpc =
                            Grpc::new(ProstCodec::<RangeResponse, RangeRequest>::default());
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

        /// Binds a loopback listener and serves the KV adapter over each accepted
        /// plaintext connection. The accept loop is detached; the test bounds its
        /// lifetime. Returns the bound address.
        pub(super) async fn spawn_fixture(seeded: Vec<(Vec<u8>, Vec<u8>)>) -> Option<SocketAddr> {
            let fixture = KvFixture {
                seeded: Arc::new(seeded),
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
            Some(addr)
        }

        async fn serve_connection(stream: TcpStream, fixture: KvFixture) {
            let service = TowerToHyperService::new(fixture);
            let builder = hyper::server::conn::http2::Builder::new(TokioExecutor::new());
            let _ = builder
                .serve_connection(TokioIo::new(stream), service)
                .await;
        }

        /// Builds one plaintext cluster client per configured cluster, pointed at
        /// `addr` with a request timeout read from a shared atomic. Flipping the
        /// atomic across generations changes the cluster MATERIAL, forcing a
        /// discovery rotation.
        pub(super) struct FixtureFactory {
            pub(super) addr: SocketAddr,
            pub(super) timeout_ms: Arc<AtomicU64>,
        }

        impl TopologyClientFactory for FixtureFactory {
            fn build(
                &self,
                snapshot: &ConfigNamespaceSnapshot,
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
    }

    /// Blocker-1 atomicity: when the checked epoch counter overflows on a material
    /// rotation, the module rejects the generation BEFORE any registration
    /// teardown, retaining BOTH the old registration children AND the old, still
    /// usable discovery generation — proven by the old handle's REAL poll payload,
    /// not just its epoch. Tearing children down on the overflow path (a bad impl)
    /// turns the `stops == 0` assertion RED.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::too_many_lines)]
    async fn an_epoch_overflow_on_a_material_rotation_retains_the_live_generation()
    -> Result<(), TestError> {
        use overflow_fixture::{FixtureFactory, spawn_fixture};

        // One live TiDB backend under the classic prefix; the keyspace prefix has
        // nothing.
        let seeded = vec![
            (
                b"/topology/tidb/10.0.0.9:4000/info".to_vec(),
                br#"{"ip":"10.0.0.9","status_port":10080,"version":"v8"}"#.to_vec(),
            ),
            (b"/topology/tidb/10.0.0.9:4000/ttl".to_vec(), b"1".to_vec()),
        ];
        let Some(addr) = spawn_fixture(seeded).await else {
            unreachable!("the fixture binds a loopback port");
        };

        let timeout_ms = Arc::new(AtomicU64::new(500));
        let store =
            ConfigNamespaceStore::from_toml(&config_single(100), None, &std::env::current_dir()?)?;
        let counters = Counters::default();
        let connects = Arc::new(AtomicUsize::new(0));
        let runtime = runtime()?;

        // Build the module manually so the epoch counter can be driven to its
        // overflow boundary BEFORE the run loop applies the initial generation.
        let (module, mut handle) = TopologyModule::new_with_child_runner_and_connector(
            Arc::new(store.clone()),
            Box::new(FixtureFactory {
                addr,
                timeout_ms: Arc::clone(&timeout_ms),
            }),
            Arc::new(StaticAdvertiseResolver::new("10.0.0.1")),
            identity(),
            counting_runner(&counters),
            counting_real_connector(&connects),
        );
        module.force_next_epoch(u64::MAX - 1);
        let context = runtime.handle().module_context();
        runtime.mark_ready()?;
        let task = tokio::spawn(Box::new(module).run(context));

        let discovery = handle.discovery_handle();
        let body = async {
            wait_ready(&mut handle).await?;
            let mut status = handle.status();
            let _ = status.borrow_and_update();

            // The initial generation reserved epoch MAX-1 (next -> MAX).
            assert_eq!(
                connects.load(Ordering::SeqCst),
                1,
                "one cluster connected once on the initial generation"
            );
            assert_eq!(counters.spawns(), 1, "one registration child was spawned");
            let before =
                tokio::time::timeout(Duration::from_secs(5), discovery.poll_merged_topology())
                    .await?
                    .unwrap_or_else(|error| unreachable!("the initial poll succeeds: {error:?}"));
            assert_eq!(
                before.client_epoch,
                u64::MAX - 1,
                "the initial generation published epoch MAX-1"
            );
            assert_eq!(
                before.value.backends.len(),
                1,
                "the seeded backend is discovered"
            );
            assert_eq!(before.value.backends[0].backend.addr, "10.0.0.9:4000");
            assert_eq!(before.value.backends[0].cluster_name.as_ref(), "cluster-a");

            // A material rotation (a different client timeout). Its discovery
            // prepare reserves MAX, then `checked_add(1)` overflows, so reconfigure
            // rejects the generation BEFORE stopping any child.
            timeout_ms.store(700, Ordering::SeqCst);
            store.apply_toml(&config_single(200), None, 2, &std::env::current_dir()?)?;
            let after = wait_observed(&mut status, 2).await?;

            assert_eq!(
                counters.stops(),
                0,
                "the overflow generation did not tear down the registration children"
            );
            assert_eq!(
                counters.spawns(),
                1,
                "no new registration child was spawned"
            );
            assert_eq!(
                after.applied_generation, 1,
                "the last-good applied generation is retained"
            );
            assert_eq!(
                after.last_rejection,
                Some(RejectionClass::ClientBuildFailed),
                "the overflow surfaces as a ClientBuildFailed rejection"
            );
            // `prepare` connects BEFORE it reserves the epoch, so the overflow
            // generation built one throwaway connection (count 1 -> 2) — but it was
            // never committed: no NEW discovery set was published.
            assert_eq!(
                connects.load(Ordering::SeqCst),
                2,
                "the overflow generation's throwaway prepare connected once, then rejected"
            );
            assert_eq!(
                discovery.current_epoch(),
                Some(u64::MAX - 1),
                "the live discovery epoch is retained across the overflow"
            );

            // The decisive check: the OLD material is still usable — a real poll
            // still returns the same seeded backend at the same epoch.
            let retained =
                tokio::time::timeout(Duration::from_secs(5), discovery.poll_merged_topology())
                    .await?
                    .unwrap_or_else(|error| unreachable!("the retained poll succeeds: {error:?}"));
            assert_eq!(
                retained.client_epoch,
                u64::MAX - 1,
                "the retained poll still reports the last-good epoch"
            );
            assert_eq!(
                retained.value, before.value,
                "the retained poll returns the same payload"
            );
            Ok::<(), TestError>(())
        };
        tokio::time::timeout(Duration::from_secs(5), body).await??;

        request_stop(&runtime)?;
        tokio::time::timeout(Duration::from_secs(10), task).await???;
        runtime.finish()?;
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
