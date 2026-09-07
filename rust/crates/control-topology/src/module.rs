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

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use control_config::{
    ConfigNamespaceSnapshot, ConfigNamespaceSource, HealthCheckConfig, TopologyRuntimeIdentity,
};
use control_external::{ClusterHttpConfigError, EtcdClientConfig, EtcdConnector};
use control_plane::{
    ControlModule, LifecyclePhase, LifecycleSnapshot, ModuleContext, ModuleError, ModuleFuture,
    OwnerToken,
};
use tokio::sync::watch;
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::MissedTickBehavior;

use crate::backend_health::{ClusterHealthNetwork, PreparedClusterHealthNetwork};
use crate::discovery_publish::{
    DiscoveryConnector, DiscoveryHandle, DiscoveryPublisher, default_discovery_connector,
};
use crate::health_config::{HealthConfigError, HealthRuntime};
use crate::health_feed::{HealthGenerationFeed, HealthGenerationFeeder};
use crate::health_loop::{
    HEALTH_CONCURRENCY, HealthGeneration, probe_backend_in_generation, run_health_loop,
};
use crate::health_overlay::{HealthOverlayHandle, HealthOverlayPublisher};
use crate::metric_source::{MetricConfigError, MetricPublication, MetricSourceHandle};
use crate::registrar::RegistrarError;
use crate::resolver::AdvertiseEndpointResolver;
use crate::routing_snapshot::{RoutingSnapshotHandle, RoutingSnapshotPublisher};
use crate::static_source::{
    BackendSourceHandle, BackendSourceMode, ModeEpoch, ModePublisher, StaticProducers,
    StaticRegistry,
};

/// Grace period for a retired generation's children to deregister before they
/// are aborted, so a wedged child can never block a reconfigure or shutdown.
const CHILD_STOP_GRACE: Duration = Duration::from_secs(5);

/// Cadence of the routing-topology refresh loop, mirroring Go
/// `healthCheckInterval` (`lib/config/health.go`): the interval at which the
/// merged topology is re-pulled from discovery and republished for CP-ROUTE. This
/// is the topology content-refresh cadence, distinct from the lease-TTL refresh
/// in `register` and from the (future) wire-push cadence to the dataplane.
const ROUTING_REFRESH_INTERVAL: Duration = Duration::from_secs(3);

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

/// Spawns the routing-topology refresh child. Test-only: a test injects a child
/// that returns or panics (to exercise the run loop's supervision) instead of the
/// real periodic [`run_refresh`] loop.
#[cfg(test)]
type RefreshFactory =
    Arc<dyn Fn(DiscoveryHandle, Arc<RoutingSnapshotPublisher>) -> JoinHandle<()> + Send + Sync>;

/// Spawns the health-check child. Test-only: a test injects a child that returns
/// or panics (to exercise supervision) or holds a `DropGuard` (to exercise
/// teardown abort/join) instead of the real [`run_health_loop`]. It receives the
/// uniquely-owned feed and publisher (so the real ones are consumed) plus the
/// routing handle and owner.
#[cfg(test)]
type HealthFactory = Arc<
    dyn Fn(
            HealthGenerationFeed,
            HealthOverlayPublisher,
            RoutingSnapshotHandle,
            OwnerToken,
        ) -> JoinHandle<()>
        + Send
        + Sync,
>;

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
    /// A cluster's health-probe network could not be built (bad TLS material,
    /// unbuildable resolver, or invalid probe policy). Raised BEFORE any live
    /// plane is mutated and before the discovery epoch is reserved, so a health
    /// build failure never burns an epoch and retains all planes' last-good.
    HealthClientBuildFailed,
    /// Metric transports could not be prepared; no live state was mutated.
    MetricClientBuildFailed,
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
    discovery_reader: DiscoveryHandle,
    routing: Arc<RoutingSnapshotPublisher>,
    /// The validated, restart-pinned health runtime, derived once at construction
    /// from the constructor-supplied [`HealthCheckConfig`]. It is process input,
    /// not configuration generation: it lives only here, has no setter and no
    /// snapshot/update path, so "restart-pinned" is guaranteed by this ownership
    /// seam rather than by any per-generation comparison.
    health_runtime: HealthRuntime,
    /// The health feed/overlay-publisher pair, created at construction so the
    /// overlay handle can be surfaced immediately; moved into the run loop (feed +
    /// publisher into the health task, feeder into the [`ModuleRuntime`] guard) at
    /// startup. `None` only after that move.
    health: Option<HealthParts>,
    /// Unique applied metrics publisher; inactive until explicit startup opt-in.
    metrics: MetricPublication,
    /// The applied backend-source mode (CP-ROUTE 220-3 B2): Static IFF the
    /// applied registration plan has no cluster. Its epoch gate is revoked
    /// before a new plan/commit is published and a fresh epoch published after.
    mode: ModePublisher,
    /// The readers' registry of live static producers, by namespace.
    statics: Arc<StaticRegistry>,
    #[cfg(test)]
    refresh_override: Option<RefreshFactory>,
    #[cfg(test)]
    health_override: Option<HealthFactory>,
}

/// The uniquely-owned health primitives handed to the run loop: the feed and the
/// overlay publisher (into the health task) and the feeder (into the module
/// runtime guard). All three are non-`Clone`, so they are taken exactly once.
struct HealthParts {
    feeder: HealthGenerationFeeder,
    feed: HealthGenerationFeed,
    publisher: HealthOverlayPublisher,
}

/// One generation's per-cluster health networks, built (fallibly) but not yet
/// stamped with the reserved discovery epoch.
type PreparedHealthNetworks = Vec<(Arc<str>, PreparedClusterHealthNetwork)>;

/// The immutable health authority for one discovery generation.
///
/// It is the SOLE source of health material: the exact `client_epoch` reserved by
/// [`crate::discovery_publish::PreparedDiscovery`] plus the per-cluster networks
/// stamped for it (`None` when health is disabled). The module never re-reads a
/// [`RegistrationPlan`] — which carries no epoch — to build health material, so a
/// routing source can only ever be paired with networks prepared for its own
/// exact discovery generation.
struct AppliedHealthMaterial {
    client_epoch: u64,
    networks: Option<Arc<HashMap<Arc<str>, ClusterHealthNetwork>>>,
}

/// The run-loop-owned health state threaded into [`TopologyModule::reconfigure`]:
/// the unique feeder (shared by `&`), the active health artifact (mutated on a
/// rotation), and the routing observer used to re-pair the feed.
struct HealthReconcile<'a> {
    feeder: &'a HealthGenerationFeeder,
    active: &'a mut Option<AppliedHealthMaterial>,
    routing: &'a RoutingSnapshotHandle,
}

/// Re-pairs the health feed with the current routing generation.
///
/// The feed is set with a [`HealthGeneration`] IFF an artifact is active AND a
/// routing source is published whose `client_epoch` is exactly the artifact's;
/// otherwise the feed is withdrawn (fail-closed). This is the single reconcile
/// used both after a discovery commit and on every routing-observer wake, so a
/// lag or epoch mismatch is always a withdraw, never a reuse of wrong-epoch
/// material. A disabled artifact still pairs (with `networks == None`) so the
/// loop runs its all-healthy zero-I/O rounds for the exact source.
fn reconcile_health_feed(
    feeder: &HealthGenerationFeeder,
    active_health: Option<&AppliedHealthMaterial>,
    routing: &RoutingSnapshotHandle,
) {
    let Some(artifact) = active_health else {
        feeder.withdraw();
        return;
    };
    match routing.current() {
        Some(source) if source.client_epoch == artifact.client_epoch => {
            feeder.set(Arc::new(HealthGeneration {
                source,
                networks: artifact.networks.clone(),
            }));
        }
        _ => feeder.withdraw(),
    }
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
    routing: RoutingSnapshotHandle,
    health: HealthOverlayHandle,
    metrics: MetricSourceHandle,
    source: Arc<dyn ConfigNamespaceSource>,
    mode: watch::Receiver<Arc<ModeEpoch>>,
    statics: Arc<StaticRegistry>,
    #[cfg(test)]
    mode_hook: crate::static_source::PublishHook,
}

impl TopologyModuleHandle {
    /// The staged applied metrics source; empty until explicitly enabled and a
    /// matching dynamic discovery/R generation exists. No collector is started.
    #[must_use]
    pub fn metric_source(&self) -> MetricSourceHandle {
        self.metrics.clone()
    }

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

    /// A cheap-to-clone reader of the published, generation-stamped routing
    /// topology snapshot. It is fail-closed until the refresh loop publishes a
    /// first snapshot and after the module retires; a consumer must treat `None`
    /// (and a stale [`RoutingSnapshotHandle::still_current`]) as not-routable.
    #[must_use]
    pub fn routing_handle(&self) -> RoutingSnapshotHandle {
        self.routing.clone()
    }

    /// A cheap-to-clone reader of the generation-fenced backend-health overlay.
    ///
    /// A consumer reaches a verdict only through the source-paired protocol:
    /// `R = routing_handle().current()` → `H = health_overlay_handle().current_for(&R)`
    /// → `H.get(id)` → and, before any side effect, re-validate with
    /// [`HealthOverlayHandle::still_current_for`]. A missing routing source,
    /// overlay, or backend id reads as fail-closed unhealthy; there is no raw
    /// health `current()` that bypasses the routing source.
    #[must_use]
    pub fn health_overlay_handle(&self) -> HealthOverlayHandle {
        self.health.clone()
    }

    /// Test-only: the module's epoch publication hook slot (see
    /// [`crate::static_source::PublishHook`]).
    #[cfg(test)]
    pub(crate) fn mode_publish_hook(&self) -> crate::static_source::PublishHook {
        self.mode_hook.clone()
    }

    /// The live applied backend-source mode, or `None` before the first
    /// applied plan / after teardown (diagnostics and evidence only).
    #[cfg(test)]
    pub(crate) fn applied_mode(&self) -> Option<BackendSourceMode> {
        let epoch = self.mode.borrow();
        epoch.is_live().then(|| epoch.mode())
    }

    /// Binds a [`BackendSourceHandle`] to `namespace`'s CURRENT incarnation
    /// (CP-ROUTE 220-3 B2), or `None` when the namespace is absent from the
    /// committed config or its static producer is not (yet, or any longer)
    /// registered — fail-closed until the run loop has reconciled it.
    #[must_use]
    pub fn backend_source(&self, namespace: &str) -> Option<BackendSourceHandle> {
        BackendSourceHandle::bind(
            namespace,
            Arc::clone(&self.source),
            self.mode.clone(),
            (self.routing.clone(), self.health.clone()),
            &self.statics,
        )
    }
}

impl TopologyModule {
    /// Builds the module and its readiness handle.
    ///
    /// `source`, `factory`, and `resolver` are all injected from the
    /// composition root: the factory reads TLS material and the resolver owns
    /// interface enumeration, keeping both out of this crate.
    ///
    /// `health` is the restart-pinned [`HealthCheckConfig`], a process input owned
    /// by the module — not a configuration generation. `TiProxy` exposes no
    /// user-facing health-check config (Go builds it from
    /// `NewDefaultHealthCheckConfig()`), so the composition root passes the
    /// Go-compatible default and it is never read from a config snapshot. It is
    /// validated once here, so an invalid pinned policy is a loud startup
    /// rejection, and thereafter held immutably (no setter, no snapshot/update
    /// path).
    ///
    /// # Errors
    ///
    /// Returns [`HealthConfigError`] when the pinned health config is invalid
    /// (a non-positive or out-of-range interval, retry interval, or dial timeout,
    /// or a retry count above its bound) — in every mode, disabled included.
    pub fn new(
        source: Arc<dyn ConfigNamespaceSource>,
        factory: Box<dyn TopologyClientFactory>,
        resolver: Arc<dyn AdvertiseEndpointResolver>,
        identity: TopologyRuntimeIdentity,
        health: HealthCheckConfig,
    ) -> Result<(Self, TopologyModuleHandle), HealthConfigError> {
        Self::build(
            source,
            factory,
            resolver,
            identity,
            health,
            default_child_runner(),
            default_discovery_connector(),
        )
    }

    /// Enables the staged metrics material/feed using the constructor's pinned
    /// health/metrics timing. No collector, owner listener or election is started.
    /// Production composition remains a later control-plane cutover step.
    ///
    /// # Errors
    /// Returns an error for invalid metrics cadence or request timing.
    pub fn with_metrics(mut self) -> Result<Self, MetricConfigError> {
        self.metrics.enable()?;
        Ok(self)
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
        health: HealthCheckConfig,
        child_runner: ChildRunner,
    ) -> Result<(Self, TopologyModuleHandle), HealthConfigError> {
        let connector: DiscoveryConnector = Arc::new(|owner, _client| {
            Box::pin(async move {
                let config = EtcdClientConfig::new(vec!["127.0.0.1:1".to_owned()], None)
                    .unwrap_or_else(|_| unreachable!("a plaintext endpoint is valid"));
                EtcdConnector::new(owner, config).connect().await
            })
        });
        Self::build(
            source,
            factory,
            resolver,
            identity,
            health,
            child_runner,
            connector,
        )
    }

    /// Test-only constructor that injects both a deterministic child runner and
    /// a discovery connector, so a test can count and gate the per-cluster
    /// discovery connections a generation builds. Not compiled into production.
    #[cfg(test)]
    pub(crate) fn new_with_child_runner_and_connector(
        source: Arc<dyn ConfigNamespaceSource>,
        factory: Box<dyn TopologyClientFactory>,
        resolver: Arc<dyn AdvertiseEndpointResolver>,
        identity: TopologyRuntimeIdentity,
        health: HealthCheckConfig,
        child_runner: ChildRunner,
        discovery_connector: DiscoveryConnector,
    ) -> Result<(Self, TopologyModuleHandle), HealthConfigError> {
        Self::build(
            source,
            factory,
            resolver,
            identity,
            health,
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

    /// Installs a test-only refresh-child factory (used by `spawn_refresh`),
    /// letting a supervision/teardown test inject a child that returns, panics, or
    /// runs a barrier-controlled [`run_refresh`] instead of the production loop.
    #[cfg(test)]
    fn set_refresh_override(&mut self, factory: RefreshFactory) {
        self.refresh_override = Some(factory);
    }

    /// Installs a test-only health-child factory (used by `spawn_health`), letting
    /// a supervision/teardown test inject a child that returns, panics, or holds a
    /// [`tokio::sync::oneshot`]/`DropGuard` instead of the production health loop.
    #[cfg(test)]
    fn set_health_override(&mut self, factory: HealthFactory) {
        self.health_override = Some(factory);
    }

    fn build(
        source: Arc<dyn ConfigNamespaceSource>,
        factory: Box<dyn TopologyClientFactory>,
        resolver: Arc<dyn AdvertiseEndpointResolver>,
        identity: TopologyRuntimeIdentity,
        health: HealthCheckConfig,
        child_runner: ChildRunner,
        discovery_connector: DiscoveryConnector,
    ) -> Result<(Self, TopologyModuleHandle), HealthConfigError> {
        // Validate the restart-pinned health config FIRST, so an invalid policy
        // fails construction before any channel or publisher is created.
        let health_runtime = HealthRuntime::from_config(&health)?;
        let (ready_tx, ready_rx) = watch::channel(false);
        let (status_tx, status_rx) = watch::channel(TopologyStatus::default());
        let (discovery, discovery_handle) = DiscoveryPublisher::new();
        let (routing_publisher, routing_handle) = RoutingSnapshotPublisher::new();
        let routing = Arc::new(routing_publisher);
        let (feeder, feed) = HealthGenerationFeeder::new();
        let (publisher, health_overlay) = HealthOverlayPublisher::new();
        let mode = ModePublisher::new();
        let mode_reader = mode.subscribe();
        #[cfg(test)]
        let mode_hook = mode.publish_hook();
        let statics = Arc::new(StaticRegistry::default());
        let (metrics, metric_source) = MetricPublication::new(Arc::clone(&source), health);
        Ok((
            Self {
                source: Arc::clone(&source),
                factory,
                resolver,
                identity,
                ready: ready_tx,
                status: status_tx,
                child_runner,
                discovery,
                discovery_connector,
                discovery_reader: discovery_handle.clone(),
                routing,
                health_runtime,
                health: Some(HealthParts {
                    feeder,
                    feed,
                    publisher,
                }),
                mode,
                metrics,
                statics: Arc::clone(&statics),
                #[cfg(test)]
                refresh_override: None,
                #[cfg(test)]
                health_override: None,
            },
            TopologyModuleHandle {
                ready: ready_rx,
                status: status_rx,
                discovery: discovery_handle,
                routing: routing_handle,
                health: health_overlay,
                metrics: metric_source,
                source,
                mode: mode_reader,
                statics,
                #[cfg(test)]
                mode_hook,
            },
        ))
    }

    #[allow(clippy::too_many_lines)]
    async fn run_inner(mut self, context: ModuleContext) -> Result<(), ModuleError> {
        let owner = context.owner().clone();
        let mut lifecycle = context.lifecycle();
        let mut updates = self.source.subscribe();
        let mut children = Children::default();
        let mut active_plan: Option<RegistrationPlan> = None;
        // The uniquely-owned health primitives, taken once. Their absence would
        // mean the module was already run; fail closed rather than proceed with no
        // health plane.
        let Some(HealthParts {
            feeder,
            feed,
            publisher,
        }) = self.health.take()
        else {
            return Err(module_error("health_parts_missing"));
        };
        // The active health artifact (epoch + per-cluster networks) and a routing
        // reader used to re-pair the feed. A separate `routing_observer` drives the
        // main select so its `&mut` cursor never collides with these reads.
        let mut active_health: Option<AppliedHealthMaterial> = None;
        let routing_reader = self.routing.handle();
        let mut routing_observer = self.routing.handle();
        // Owns the routing-refresh child, the health child, the unique feeder, and
        // the routing + discovery withdrawal authority. Created before the first
        // apply so an early rejection (or the task being dropped/aborted) still
        // fences discovery, closes the feed, and leaves the not-yet-published
        // routing source closed. The children are attached only once an initial
        // generation is installed. On Drop it fences all three planes in the fixed
        // order without an async join, as an unbypassable backstop.
        let mut runtime = ModuleRuntime {
            routing: Arc::clone(&self.routing),
            discovery: &self.discovery,
            metrics: &self.metrics,
            feeder,
            health: None,
            refresh: None,
            mode: &self.mode,
            statics: StaticProducers::new(Arc::clone(&self.statics)),
        };

        // Apply the current generation once (including generation 1), then wait
        // for changes; borrowing after `subscribe` avoids a dropped edge.
        let initial = updates.borrow_and_update().clone();
        {
            let mut health = HealthReconcile {
                feeder: &runtime.feeder,
                active: &mut active_health,
                routing: &routing_reader,
            };
            if !self
                .apply_and_report(
                    &mut children,
                    &mut active_plan,
                    &initial,
                    &owner,
                    &mut health,
                    &mut runtime.statics,
                )
                .await
            {
                return Err(module_error("initial_generation_rejected"));
            }
        }
        let _ = self.ready.send_replace(true);
        // The initial discovery set is installed, so the refresh loop has a set to
        // pull; attach both children now. `ready` is already signalled and never
        // waits on a pull, so PD being unreachable cannot stall readiness. The
        // health loop starts parked (the feed is withdrawn until the refresh loop
        // publishes a routing source of the committed epoch).
        runtime.refresh =
            Some(self.spawn_refresh(self.discovery_reader.clone(), Arc::clone(&self.routing)));
        runtime.health =
            Some(self.spawn_health(feed, publisher, self.routing.handle(), owner.clone()));

        let outcome = loop {
            tokio::select! {
                changed = lifecycle.changed() => {
                    // Retire the registration only once the runtime reaches
                    // Stopping (SQL sessions have already been joined), or if the
                    // lifecycle channel closed so no later phase can arrive.
                    // Quiescing/Draining keep the registration and lease refresh
                    // alive so this instance stays discoverable during drain.
                    if changed.is_err() || retire_requested(lifecycle.borrow().phase) {
                        break Ok(());
                    }
                }
                changed = updates.changed() => {
                    if changed.is_err() {
                        break Err(module_error("config_source_stopped"));
                    }
                    let snapshot = updates.borrow_and_update().clone();
                    // A rejected generation (unresolvable advertise, build
                    // failure, a factory result that does not match the
                    // configured cluster set, or a health-material build failure)
                    // retains the last-good registration rather than tearing it
                    // down; the rejection class is published on the status watch.
                    let mut health = HealthReconcile {
                        feeder: &runtime.feeder,
                        active: &mut active_health,
                        routing: &routing_reader,
                    };
                    let _ = self
                        .apply_and_report(
                            &mut children,
                            &mut active_plan,
                            &snapshot,
                            &owner,
                            &mut health,
                            &mut runtime.statics,
                        )
                        .await;
                }
                changed = routing_observer.changed() => {
                    // A crate-private routing observer, used only to re-pair the
                    // health feed with each new exact routing source Arc. A closed
                    // observer must not leave the module ready and silent.
                    if changed.is_err() {
                        break Err(module_error("routing_observer_closed"));
                    }
                    reconcile_health_feed(&runtime.feeder, active_health.as_ref(), &routing_reader);
                    self.reconcile_metrics();
                }
                exited = children.tasks.join_next(), if !children.tasks.is_empty() => {
                    // A child completed while we were not tearing it down: an
                    // unexpected retirement, owner loss, or panic. Fail loud so
                    // the runtime does not treat an unregistered proxy as healthy
                    // — unless the lifecycle has already requested this teardown.
                    if exited.is_some() {
                        break child_exit_outcome(&lifecycle, "registration_child_exited");
                    }
                }
                () = supervise_child(runtime.refresh.as_mut()) => {
                    // The refresh child completed without a teardown request — an
                    // unexpected return, panic, or cancel. The await consumed the
                    // JoinHandle, so drop it and fail loud rather than leave the
                    // module ready with a permanently silent routing source.
                    runtime.refresh = None;
                    break child_exit_outcome(&lifecycle, "routing_refresh_failed");
                }
                () = supervise_child(runtime.health.as_mut()) => {
                    // The health child completed without a teardown request. The
                    // await consumed the JoinHandle, so drop it and fail loud
                    // rather than leave the module ready with a silent, never-
                    // updated health overlay.
                    runtime.health = None;
                    break child_exit_outcome(&lifecycle, "health_loop_failed");
                }
            }
        };

        // Frozen teardown order: the routing publisher is made terminal FIRST (so
        // any already-pulled result can only republish as `Retired`), then
        // discovery is revoked (fail-closing further pulls), then the feed is
        // closed (revoking any retained health overlay's feed gate) — all inside
        // `retire()`, which then aborts BOTH children together and joins each —
        // before the registration children are stopped, so both children are gone
        // before the child grace period.
        runtime.retire().await;
        stop_children(&mut children).await;
        outcome
    }

    /// Spawns the routing-refresh child. Production runs the periodic
    /// [`run_refresh`] loop with a no-op post-poll seam; a test may inject an
    /// alternative child (e.g. one that returns or panics) to exercise supervision.
    // `self` carries the test-only refresh override; production ignores it.
    #[cfg_attr(not(test), allow(clippy::unused_self))]
    fn spawn_refresh(
        &self,
        handle: DiscoveryHandle,
        routing: Arc<RoutingSnapshotPublisher>,
    ) -> JoinHandle<()> {
        #[cfg(test)]
        if let Some(factory) = &self.refresh_override {
            return factory(handle, routing);
        }
        tokio::spawn(run_refresh(
            handle,
            routing,
            ROUTING_REFRESH_INTERVAL,
            || async {},
        ))
    }

    /// Spawns the health-check child, consuming the uniquely-owned feed and
    /// overlay publisher. Production runs [`run_health_loop`] with the pinned
    /// policy, the shared concurrency cap, and the real per-generation probe; a
    /// test may inject an alternative child to exercise supervision or teardown.
    // `self` carries the test-only health override; production ignores it.
    #[cfg_attr(not(test), allow(clippy::unused_self))]
    fn spawn_health(
        &self,
        feed: HealthGenerationFeed,
        publisher: HealthOverlayPublisher,
        routing: RoutingSnapshotHandle,
        owner: OwnerToken,
    ) -> JoinHandle<()> {
        #[cfg(test)]
        if let Some(factory) = &self.health_override {
            return factory(feed, publisher, routing, owner);
        }
        tokio::spawn(run_health_loop(
            feed,
            routing,
            publisher,
            self.health_runtime.policy(),
            owner,
            HEALTH_CONCURRENCY,
            probe_backend_in_generation,
            Arc::clone(&self.source),
        ))
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
    // One cohesive validate → prepare → commit critical path whose ordering
    // (health build before epoch reserve, withdraw before commit, no await in the
    // rotation window) is load-bearing and must not be split across a seam.
    #[allow(clippy::too_many_lines)]
    async fn reconfigure(
        &self,
        children: &mut Children,
        active_plan: &mut Option<RegistrationPlan>,
        snapshot: &ConfigNamespaceSnapshot,
        owner: &OwnerToken,
        health: &mut HealthReconcile<'_>,
        statics: &mut StaticProducers,
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

        // Build every enabled cluster's health-probe transport (the only fallible
        // health step: resolver, TLS, policy) from the SAME candidate material,
        // BEFORE the discovery publisher reserves an epoch. A health build failure
        // therefore rejects the whole generation without burning an epoch and
        // retains every plane's last-good. A disabled runtime builds nothing.
        let prepared_health = if discovery_unchanged {
            None
        } else {
            match self.build_prepared_health(owner, &clusters) {
                Ok(prepared) => prepared,
                Err(_) => return Err(RejectionClass::HealthClientBuildFailed),
            }
        };

        // Metrics shares the validated candidate bytes and must also be built
        // before any discovery epoch is reserved or live authority is revoked.
        let prepared_metrics = if discovery_unchanged {
            None
        } else {
            self.metrics
                .prepare(owner, &clusters)
                .map_err(|_| RejectionClass::MetricClientBuildFailed)?
        };

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

        // Capture the reserved epoch from the prepared discovery and infallibly
        // stamp the prepared health networks onto it — BEFORE `prepared` is moved
        // into `commit`, so the health artifact and the discovery generation share
        // one exact epoch and the stamp never reaches into a committed publisher.
        let candidate_health = match &prepared {
            Some(prepared) => {
                let client_epoch = prepared.client_epoch();
                Some(AppliedHealthMaterial {
                    client_epoch,
                    networks: prepared_health.map(|networks| {
                        Arc::new(
                            networks
                                .into_iter()
                                .map(|(name, prepared)| (name, prepared.bind(client_epoch)))
                                .collect(),
                        )
                    }),
                })
            }
            None => None,
        };

        // Commit registration first (fence: retire the previous generation before
        // the new one publishes), then commit discovery (revoke the old gate,
        // publish the new epoch).
        // Mode transition, step 1 of 2: revoke the outgoing epoch BEFORE the new
        // plan, discovery commit or mode are visible to any reader.
        let next_mode = if plan.clusters.is_empty() {
            BackendSourceMode::Static
        } else {
            BackendSourceMode::Dynamic
        };
        // Metrics retirement precedes the first registration cleanup await even
        // when dynamic mode, R and H are still unchanged. Preserve the existing
        // health feed's later withdrawal contract below.
        if prepared.is_some() {
            self.metrics.withdraw_material();
        }
        let mode_changes = self.mode.applied() != Some(next_mode);
        if mode_changes {
            self.mode.revoke();
        }
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
        //
        // Rotate the health plane in lockstep, with NO await between the withdraw
        // and the reconcile: withdraw the feed FIRST (synchronously revoking the
        // retained overlay's feed gate, so a consumer loses authority before this
        // config call returns), then commit the new discovery epoch, then replace
        // the active health artifact, then re-pair the feed against the current
        // routing source — which is usually still the old epoch, so it stays
        // withdrawn until the refresh loop publishes the new source Arc.
        if let Some(prepared) = prepared {
            health.feeder.withdraw();
            let discovery = self.discovery.commit(prepared);
            self.metrics.install(prepared_metrics, discovery);
            *health.active = candidate_health;
            reconcile_health_feed(health.feeder, health.active.as_ref(), health.routing);
        }
        // Mode transition, step 2 of 2: park or activate the static producers
        // FIRST (a parked feed is withdrawn synchronously, so no old static round
        // or H is authoritative once the new epoch is visible; an activated
        // producer is fed a fresh generation), THEN publish the fresh live epoch.
        if mode_changes {
            statics.apply_mode(Some(next_mode));
            self.mode.publish(next_mode);
        }
        self.reconcile_metrics();
        Ok(())
    }

    fn reconcile_metrics(&self) {
        let mode = self.mode.subscribe().borrow().clone();
        self.metrics
            .reconcile(self.routing.handle().current(), mode);
    }

    /// Builds the fallible health-probe transport for every cluster from the
    /// candidate discovery material, or `Ok(None)` when health is disabled (no
    /// resolver, TLS, or socket is constructed).
    ///
    /// This runs BEFORE the discovery publisher reserves an epoch, so any failure
    /// rejects the whole generation without burning an epoch. The networks are
    /// left unstamped ([`PreparedClusterHealthNetwork`]); the reserved epoch is
    /// bound infallibly afterward.
    fn build_prepared_health(
        &self,
        owner: &OwnerToken,
        clusters: &[TopologyClusterClient],
    ) -> Result<Option<PreparedHealthNetworks>, ClusterHttpConfigError> {
        let Some(probe_policy) = self.health_runtime.probe_policy() else {
            return Ok(None);
        };
        let mut prepared = Vec::with_capacity(clusters.len());
        for cluster in clusters {
            let network = PreparedClusterHealthNetwork::build(
                &cluster.client,
                owner.clone(),
                probe_policy,
                Arc::clone(&cluster.cluster_name),
            )?;
            prepared.push((Arc::clone(&cluster.cluster_name), network));
        }
        Ok(Some(prepared))
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
        health: &mut HealthReconcile<'_>,
        statics: &mut StaticProducers,
    ) -> bool {
        let generation = snapshot.generation();
        // Namespaces follow the committed config (Go `CommitNamespaces`),
        // independently of whether this generation's cluster material applies.
        statics.reconcile(
            snapshot,
            owner,
            &self.health_runtime,
            &self.source,
            self.mode.applied(),
        );
        let outcome = self
            .reconfigure(children, active_plan, snapshot, owner, health, statics)
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

/// Classifies a child exit observed by a supervision arm. The lifecycle alone
/// decides: a child ending after the runtime requested retirement (`Stopping`)
/// or vanished (the channel closed, so no later phase can arrive) is the clean
/// teardown path — the lifecycle arm and the child arm are ready together then,
/// and `select!` may observe either first — while a child ending under a live
/// lifecycle that still keeps children alive is fatal under its exact class. The
/// owner is deliberately not consulted: an external owner loss with a live
/// lifecycle must still fail loud.
fn child_exit_outcome(
    lifecycle: &watch::Receiver<LifecycleSnapshot>,
    error_class: &'static str,
) -> Result<(), ModuleError> {
    if lifecycle.has_changed().is_err() || retire_requested(lifecycle.borrow().phase) {
        Ok(())
    } else {
        Err(module_error(error_class))
    }
}

const fn module_error(error_class: &'static str) -> ModuleError {
    ModuleError {
        module: MODULE_NAME,
        error_class,
    }
}

/// The routing-topology refresh loop: on each tick it pulls the merged topology
/// from discovery and republishes it, retaining the last-good snapshot on any pull
/// failure (transport error, or the epoch/gate fence returning `Stale`/`Revoked`).
///
/// The first tick fires immediately; subsequent ticks keep a fixed start-to-start
/// cadence and *skip* (never burst) if a pull runs longer than the interval, so a
/// slow PD can never make the loop catch up in a burst. Polls and publishes are
/// sequential, so at most one pull is ever in flight. `after_poll` is an injected
/// seam — empty in production — that a test uses to interpose between a successful
/// pull and its publish, to exercise teardown ordering.
async fn run_refresh<Seam, Fut>(
    handle: DiscoveryHandle,
    routing: Arc<RoutingSnapshotPublisher>,
    interval: Duration,
    mut after_poll: Seam,
) where
    Seam: FnMut() -> Fut,
    Fut: Future<Output = ()>,
{
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        ticker.tick().await;
        if let Ok(result) = handle.poll_merged_topology().await {
            after_poll().await;
            let _ = routing.publish(result);
        }
    }
}

/// Awaits the refresh child's completion for the run loop's supervision arm.
/// Resolves only when the child ends on its own (an unexpected return, panic, or
/// cancel); when no child is attached it is pending forever so the arm is inert.
async fn supervise_child(handle: Option<&mut JoinHandle<()>>) {
    match handle {
        Some(handle) => {
            let _ = handle.await;
        }
        None => std::future::pending().await,
    }
}

/// Owns the routing-refresh child, the health child, the unique health feeder,
/// and the withdrawal authority for both the routing and discovery publishers.
///
/// Teardown fences in a fixed order that does NOT depend on local
/// declaration/drop order: the routing publisher is made terminal first (via its
/// own mutex + `Retired` state, so any already-pulled result can only republish as
/// `Retired`), then discovery is revoked (fail-closing subsequent pull I/O), then
/// the feed is closed (synchronously revoking any retained health overlay's feed
/// gate, so a health consumer loses authority at once). Only then are the two
/// children aborted. [`retire`](Self::retire) aborts BOTH children before joining
/// either — never letting one run while awaiting the other — and joins each on the
/// normal path; [`Drop`] performs the same fences and aborts both without an async
/// join, as an unbypassable backstop for an aborted module task. The physical
/// overlay revoke/clear is the health task's own `HealthLoopGuard::Drop` once it is
/// aborted. Both paths are idempotent.
struct ModuleRuntime<'module> {
    routing: Arc<RoutingSnapshotPublisher>,
    discovery: &'module DiscoveryPublisher,
    metrics: &'module MetricPublication,
    feeder: HealthGenerationFeeder,
    health: Option<JoinHandle<()>>,
    refresh: Option<JoinHandle<()>>,
    mode: &'module ModePublisher,
    statics: StaticProducers,
}

impl ModuleRuntime<'_> {
    fn terminal_fence(&mut self) {
        self.mode.revoke();
        self.routing.revoke_and_clear();
        self.discovery.revoke();
        self.metrics.close();
        self.feeder.close();
        self.statics.revoke_all();
    }

    async fn retire(mut self) {
        self.terminal_fence();
        // Abort BOTH children first, then join each, so neither keeps running
        // while the other is awaited.
        if let Some(handle) = self.health.as_ref() {
            handle.abort();
        }
        if let Some(handle) = self.refresh.as_ref() {
            handle.abort();
        }
        if let Some(handle) = self.health.take() {
            let _ = handle.await;
        }
        if let Some(handle) = self.refresh.take() {
            let _ = handle.await;
        }
    }
}

impl Drop for ModuleRuntime<'_> {
    fn drop(&mut self) {
        self.terminal_fence();
        if let Some(handle) = self.health.take() {
            handle.abort();
        }
        if let Some(handle) = self.refresh.take() {
            handle.abort();
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    mod metrics;
    use super::{
        ChildRunner, HealthFactory, ModePublisher, ModuleRuntime, ROUTING_REFRESH_INTERVAL,
        RefreshFactory, RegistrarError, RejectionClass, StaticProducers, StaticRegistry,
        TopologyClusterClient, TopologyModule, TopologyStatus, run_refresh,
    };
    use std::future::pending;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
    use std::time::Duration;

    use control_config::{
        ConfigNamespaceSnapshot, ConfigNamespaceStore, HealthCheckConfig, TopologyRuntimeIdentity,
    };
    use control_external::{
        EtcdClientConfig, EtcdConnectError, EtcdConnector, EtcdTlsConfig, EtcdTlsPolicy,
    };
    use control_plane::{
        ControlConfig, ControlModule, ControlRuntime, EventSink, LifecyclePhase, LifecycleSnapshot,
        LogLevel, MetricsPolicy, ModuleError, OwnerLease, OwnerScope, OwnershipRegistry,
        RuntimeEvent, ShutdownReason, TlsPolicy,
    };
    use tokio::sync::{Notify, watch};

    use crate::discovery_publish::{
        DiscoveryConnector, DiscoveryError, DiscoveryHandle, DiscoveryPublisher, EpochResult,
    };
    use crate::health_feed::{HealthGenerationFeed, HealthGenerationFeeder};
    use crate::merge::{MergedBackend, MergedTopology};
    use crate::model::BackendInfo;
    use crate::resolver::StaticAdvertiseResolver;
    use crate::routing_snapshot::{
        RoutingSnapshot, RoutingSnapshotHandle, RoutingSnapshotPublisher,
    };
    use crate::{HealthConfigError, HealthOverlayHandle, TopologyClientFactory};

    type TestError = Box<dyn std::error::Error>;
    type ModuleTask = tokio::task::JoinHandle<Result<(), ModuleError>>;

    struct NullSink;
    impl EventSink for NullSink {
        fn record(&self, _event: &RuntimeEvent) {}
    }

    /// The health config every module test constructs with: the default
    /// (enabled: 3s interval / 3 retries / 1s retry / 2s dial), so the enabled
    /// health loop is the reachable production path exercised under test.
    fn enabled_health() -> HealthCheckConfig {
        HealthCheckConfig::default()
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
        // `skip_ca_verification` keeps the arbitrary CA bytes in the config (so a
        // same-path byte rotation still changes the plan) while letting the
        // enabled health probe build its TLS client from this material without
        // parsing the (non-PEM) CA — the health build is exercised, not the CA
        // trust chain, which `tls.rs` locks separately.
        let tls = EtcdTlsConfig::new(
            Some(ca.to_vec()),
            None,
            None,
            Some("cluster.local".to_owned()),
            EtcdTlsPolicy {
                skip_ca_verification: true,
                ..EtcdTlsPolicy::default()
            },
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
            enabled_health(),
            runner,
        )?;
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
            enabled_health(),
            runner,
            connector,
        )?;
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

    /// A health child that mirrors the real loop's clean exit: it returns once the
    /// process owner retires. It re-polls by waking itself (not `yield_now`, which
    /// defers behind the driver), so on a single-threaded runtime it is re-queued
    /// AHEAD of a module task woken by the same `drop`.
    fn owner_retire_exit_health() -> HealthFactory {
        Arc::new(|_feed, _publisher, _routing, owner: super::OwnerToken| {
            tokio::spawn(std::future::poll_fn(move |cx| {
                if owner.is_current() {
                    cx.waker().wake_by_ref();
                    std::task::Poll::Pending
                } else {
                    std::task::Poll::Ready(())
                }
            }))
        })
    }

    /// Supporting stress for the classifier (the deterministic lock is the
    /// table-driven row below): dropping the runtime retires the owner (so a
    /// health child exits cleanly) and closes the lifecycle channel in ONE
    /// synchronous step, so the module's lifecycle arm and its health-supervision
    /// arm become ready together. On a single-threaded runtime the self-waking
    /// child is re-queued ahead of the woken module task, so both are ready at
    /// the module's next `select!` poll, whose arm order is random. Whichever arm
    /// is observed, the exit is a clean teardown — never `health_loop_failed`.
    /// With the health arm made unconditional again, this row observes red.
    #[tokio::test]
    async fn a_dropped_lifecycle_with_a_cleanly_exiting_health_child_is_a_clean_teardown()
    -> Result<(), TestError> {
        for round in 0..16 {
            let runtime = runtime()?;
            let (task, mut handle) =
                spawn_module_with_health(owner_retire_exit_health(), &runtime)?;
            wait_ready(&mut handle).await?;
            drop(runtime);
            let outcome = tokio::time::timeout(Duration::from_secs(10), task).await??;
            assert_eq!(
                outcome,
                Ok(()),
                "round {round}: a child exiting during a dropped-lifecycle teardown is clean"
            );
        }
        Ok(())
    }

    /// The child-exit classifier keys on the lifecycle alone, table-driven over
    /// every phase: while the channel is live, `Starting`/`Ready`/`Quiescing`/
    /// `Draining`/`Failed` all keep children alive, so a child exit there is fatal
    /// under its exact class; `Stopping`/`Stopped` (retirement requested) and a
    /// closed channel (the runtime is gone) are the clean teardown path. Which
    /// `select!` arm observed the exit never enters the decision, so this locks
    /// the semantics deterministically; the E2E row above is supporting stress.
    #[test]
    fn a_child_exit_is_classified_by_the_lifecycle_not_by_the_select_arm() {
        const CLASSES: [&str; 3] = [
            "registration_child_exited",
            "routing_refresh_failed",
            "health_loop_failed",
        ];
        let snapshot = |phase| LifecycleSnapshot {
            phase,
            owner_id: Arc::from("owner"),
            owner_generation: 1,
            config_generation: 1,
            shutdown_reason: None,
        };
        let fatal = [
            LifecyclePhase::Starting,
            LifecyclePhase::Ready,
            LifecyclePhase::Quiescing,
            LifecyclePhase::Draining,
            LifecyclePhase::Failed,
        ];
        let clean = [LifecyclePhase::Stopping, LifecyclePhase::Stopped];
        let (tx, rx) = watch::channel(snapshot(LifecyclePhase::Starting));
        for phase in fatal {
            tx.send_replace(snapshot(phase));
            for class in CLASSES {
                assert_eq!(
                    super::child_exit_outcome(&rx, class),
                    Err(super::module_error(class)),
                    "{phase:?}: a child exit under a live lifecycle is fatal"
                );
            }
        }
        for phase in clean {
            tx.send_replace(snapshot(phase));
            for class in CLASSES {
                assert_eq!(
                    super::child_exit_outcome(&rx, class),
                    Ok(()),
                    "{phase:?}: a child exit once retirement is requested is clean"
                );
            }
        }
        // Closed with the last value unseen: still clean (closed decides first).
        tx.send_replace(snapshot(LifecyclePhase::Ready));
        drop(tx);
        for class in CLASSES {
            assert_eq!(
                super::child_exit_outcome(&rx, class),
                Ok(()),
                "a child exit after the lifecycle channel closed is clean"
            );
        }
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
    /// timeout-driven material knob. Two modes: a plain fixture (the epoch-overflow
    /// row asserts a real discovery poll payload) and a GATED fixture that can park
    /// the first Range for a chosen prefix and count Range calls per prefix (the
    /// #212 mid-poll fence rows). Mirrors `tiproxy-rs`'s proven `KvFixture`.
    pub(crate) mod kv_fixture {
        use std::convert::Infallible;
        use std::net::SocketAddr;
        use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
        use std::sync::{Arc, Mutex, PoisonError};
        use std::time::Duration;

        use control_config::ConfigNamespaceSnapshot;
        use control_external::EtcdClientConfig;
        use hyper::body::Incoming;
        use hyper_util::rt::{TokioExecutor, TokioIo};
        use hyper_util::service::TowerToHyperService;
        use tokio::net::{TcpListener, TcpStream};
        use tokio::sync::Notify;
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

        /// Parks the FIRST Range whose key equals `prefix`, signals the test, and
        /// waits for release. When `error_after_release` is set it then answers a
        /// gRPC error (so, absent the per-connection gate fence, the caller's retry
        /// issues another Range — the Prometheus fence must suppress it).
        #[derive(Clone)]
        struct StallControl {
            prefix: Vec<u8>,
            arrived: Arc<Notify>,
            release: Arc<Notify>,
            stalled: Arc<AtomicBool>,
            error_after_release: bool,
        }

        #[derive(Clone)]
        struct KvFixture {
            seeded: Arc<Vec<(Vec<u8>, Vec<u8>)>>,
            observed: Arc<Mutex<Vec<Vec<u8>>>>,
            stall: Option<StallControl>,
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
                    fixture
                        .observed
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .push(message.key.clone());

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

        /// Binds a loopback listener and serves `fixture` over each accepted
        /// plaintext connection. The accept loop is detached; the test bounds its
        /// lifetime. Returns the bound address.
        async fn bind_and_serve(fixture: KvFixture) -> Option<SocketAddr> {
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

        /// A plain (non-gated) fixture: returns the bound address.
        pub(crate) async fn spawn_fixture(seeded: Vec<(Vec<u8>, Vec<u8>)>) -> Option<SocketAddr> {
            bind_and_serve(KvFixture {
                seeded: Arc::new(seeded),
                observed: Arc::new(Mutex::new(Vec::new())),
                stall: None,
            })
            .await
        }

        /// A gated fixture: it parks the first Range for `stall_prefix` and counts
        /// Range calls per prefix. Returns the bound address plus the coordination
        /// handles.
        pub(super) async fn spawn_gated_fixture(
            seeded: Vec<(Vec<u8>, Vec<u8>)>,
            stall_prefix: &[u8],
            error_after_release: bool,
        ) -> Option<Gated> {
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
            let addr = bind_and_serve(fixture).await?;
            Some(Gated {
                addr,
                observed,
                arrived,
                release,
            })
        }

        /// The handles for a running gated fixture.
        pub(super) struct Gated {
            pub(super) addr: SocketAddr,
            observed: Arc<Mutex<Vec<Vec<u8>>>>,
            pub(super) arrived: Arc<Notify>,
            pub(super) release: Arc<Notify>,
        }

        impl Gated {
            /// How many Range requests were observed for exactly `prefix`.
            pub(super) fn range_count(&self, prefix: &[u8]) -> usize {
                self.observed
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .iter()
                    .filter(|key| key.as_slice() == prefix)
                    .count()
            }
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
        pub(crate) struct FixtureFactory {
            pub(crate) addr: SocketAddr,
            pub(crate) timeout_ms: Arc<AtomicU64>,
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
        use kv_fixture::{FixtureFactory, spawn_fixture};

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
            enabled_health(),
            counting_runner(&counters),
            counting_real_connector(&connects),
        )?;
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

    // ===================================================================
    // 214-2 — routing-topology refresh loop matrix
    // ===================================================================
    //
    // These drive `run_refresh` and the module's refresh supervision/teardown
    // directly. The discovery side is a committed ZERO-cluster generation, whose
    // `poll_merged_topology` returns `Ok(empty)` synchronously (no socket I/O), so
    // the paused-clock rows are deterministic; the mid-poll-rotation Stale path
    // itself is covered by the fixture-backed `tests/discovery_fence.rs`.

    /// A committed zero-cluster discovery generation at epoch 0. Its
    /// `poll_merged_topology` returns `Ok(EpochResult{ 0, empty })` with no I/O.
    /// The publisher is returned so a test can `revoke()` it (turning later polls
    /// into `Err(Revoked)`); the registry/lease keep the owner current.
    async fn empty_discovery() -> (
        DiscoveryPublisher,
        DiscoveryHandle,
        OwnershipRegistry,
        OwnerLease,
    ) {
        let registry = OwnershipRegistry::new();
        let lease = registry
            .claim(OwnerScope::Process, "refresh-matrix")
            .unwrap_or_else(|error| unreachable!("claim: {error}"));
        let (publisher, handle) = DiscoveryPublisher::new();
        let unused = Arc::new(AtomicUsize::new(0));
        let connector = counting_connector(&unused);
        let prepared = publisher
            .prepare(&connector, &lease.token(), Vec::new())
            .await
            .unwrap_or_else(|_| unreachable!("empty material prepares without connecting"));
        publisher.commit(prepared);
        (publisher, handle, registry, lease)
    }

    /// Yields enough times for a spawned, purely-synchronous refresh child to drain
    /// its runnable work (poll + publish) after a clock advance, so a following
    /// assertion observes a settled state. Bounded and deterministic: each tick's
    /// work never awaits real I/O, and the test task staying runnable here prevents
    /// the paused clock from auto-advancing further ticks.
    async fn settle() {
        for _ in 0..64 {
            tokio::task::yield_now().await;
        }
    }

    /// A refresh child that never polls and never completes, so the module's
    /// refresh loop cannot touch a shared fixture. Used to isolate the discovery
    /// poll under test from any background refresh poll.
    fn pending_refresh() -> RefreshFactory {
        Arc::new(|_discovery, _routing| tokio::spawn(pending::<()>()))
    }

    /// A refresh child that holds a `DropGuard` and parks forever without polling.
    /// The guard's `Drop` bumps `drops` and fires `dropped`, and the child fires
    /// `entered` once it is genuinely running (so the guard is held by the LIVE
    /// future), letting a test prove the guard is dropped exactly once — and only —
    /// through `RefreshOwner`'s abort/join (retire) and abort (Drop) backstops.
    fn guarded_pending_refresh(
        drops: &Arc<AtomicUsize>,
        dropped: &Arc<Notify>,
        entered: &Arc<Notify>,
    ) -> RefreshFactory {
        struct DropGuard {
            drops: Arc<AtomicUsize>,
            dropped: Arc<Notify>,
        }
        impl Drop for DropGuard {
            fn drop(&mut self) {
                self.drops.fetch_add(1, Ordering::SeqCst);
                self.dropped.notify_one();
            }
        }

        let drops = Arc::clone(drops);
        let dropped = Arc::clone(dropped);
        let entered = Arc::clone(entered);
        Arc::new(move |_discovery, _routing| {
            let guard = DropGuard {
                drops: Arc::clone(&drops),
                dropped: Arc::clone(&dropped),
            };
            let entered = Arc::clone(&entered);
            tokio::spawn(async move {
                let _guard = guard;
                entered.notify_one();
                pending::<()>().await;
            })
        })
    }

    /// A refresh child whose cancellation `Drop` BLOCKS on a sync `mpsc::recv`
    /// until the test releases it, so the test can hold the child mid-Drop and
    /// prove `RefreshOwner::retire` is *awaiting* `handle.await` (the JOIN) — the
    /// module task cannot finish while the child is still dropping. The guard bumps
    /// `drops` and signals `drop_entered` BEFORE it blocks; releasing (or dropping
    /// the sender on a panic) unblocks the `recv`, so a failing run never hangs.
    fn join_barrier_refresh(
        drops: &Arc<AtomicUsize>,
        entered: &Arc<Notify>,
        drop_entered: &Arc<Notify>,
        release_rx: std::sync::mpsc::Receiver<()>,
    ) -> RefreshFactory {
        struct BlockingGuard {
            drops: Arc<AtomicUsize>,
            drop_entered: Arc<Notify>,
            release: Arc<std::sync::Mutex<Option<std::sync::mpsc::Receiver<()>>>>,
        }
        impl Drop for BlockingGuard {
            fn drop(&mut self) {
                self.drops.fetch_add(1, Ordering::SeqCst);
                self.drop_entered.notify_one();
                let rx = self
                    .release
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .take();
                if let Some(rx) = rx {
                    // Sync blocking wait: returns on the test's `send`, or `Err` when
                    // the sender is dropped (panic path), so it can never hang.
                    let _ = rx.recv();
                }
            }
        }

        let drops = Arc::clone(drops);
        let entered = Arc::clone(entered);
        let drop_entered = Arc::clone(drop_entered);
        let release = Arc::new(std::sync::Mutex::new(Some(release_rx)));
        Arc::new(move |_discovery, _routing| {
            let guard = BlockingGuard {
                drops: Arc::clone(&drops),
                drop_entered: Arc::clone(&drop_entered),
                release: Arc::clone(&release),
            };
            let entered = Arc::clone(&entered);
            tokio::spawn(async move {
                let _guard = guard;
                entered.notify_one();
                pending::<()>().await;
            })
        })
    }

    // ----- Row 1: the first refresh publishes immediately at t=0 -----------

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_refresh_publishes_a_first_snapshot_immediately() -> Result<(), TestError> {
        let (_publisher, discovery, _registry, _lease) = empty_discovery().await;
        let (routing_publisher, routing_handle) = RoutingSnapshotPublisher::new();
        let routing = Arc::new(routing_publisher);
        let child = tokio::spawn(run_refresh(
            discovery,
            Arc::clone(&routing),
            ROUTING_REFRESH_INTERVAL,
            || async {},
        ));

        // The first tick fires immediately — no time advance is needed for a
        // routable snapshot to appear.
        let snapshot = tokio::time::timeout(Duration::from_secs(5), routing_handle.wait_first())
            .await?
            .unwrap_or_else(|_| unreachable!("a first routing snapshot is published at t=0"));
        assert_eq!(snapshot.generation, 1, "the first snapshot is generation 1");
        assert_eq!(snapshot.client_epoch, 0, "it carries the discovery epoch");
        assert!(
            snapshot.backends.backends.is_empty(),
            "the zero-cluster topology is empty"
        );

        child.abort();
        Ok(())
    }

    // ----- Row 2: Skip cadence, no burst catch-up --------------------------

    #[tokio::test(start_paused = true)]
    async fn a_refresh_skips_missed_ticks_and_does_not_burst() -> Result<(), TestError> {
        let (_publisher, discovery, _registry, _lease) = empty_discovery().await;
        let (routing_publisher, _routing_handle) = RoutingSnapshotPublisher::new();
        let routing = Arc::new(routing_publisher);
        let polls = Arc::new(AtomicUsize::new(0));
        let after_poll = {
            let polls = Arc::clone(&polls);
            move || {
                let polls = Arc::clone(&polls);
                async move {
                    polls.fetch_add(1, Ordering::SeqCst);
                }
            }
        };
        let child = tokio::spawn(run_refresh(
            discovery,
            Arc::clone(&routing),
            ROUTING_REFRESH_INTERVAL,
            after_poll,
        ));

        // t=0: the immediate first tick polls once.
        settle().await;
        assert_eq!(
            polls.load(Ordering::SeqCst),
            1,
            "the immediate tick polls once"
        );

        // Jump the clock across FIVE intervals at once while nothing was pending.
        // With `Skip`, the loop fires exactly ONE catch-up tick and then resumes on
        // the schedule; with `Burst` it would fire all five to catch up.
        tokio::time::advance(ROUTING_REFRESH_INTERVAL * 5).await;
        settle().await;
        assert_eq!(
            polls.load(Ordering::SeqCst),
            2,
            "Skip fires exactly one catch-up tick, not a five-tick burst"
        );

        child.abort();
        Ok(())
    }

    // ----- Row 3a: teardown makes routing terminal FIRST → Retired ---------

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_teardown_before_an_in_flight_publish_refuses_it_as_retired() -> Result<(), TestError>
    {
        let (publisher, discovery, _registry, _lease) = empty_discovery().await;
        let (routing_publisher, routing_handle) = RoutingSnapshotPublisher::new();
        let routing = Arc::new(routing_publisher);

        // The seam parks the loop AFTER a successful poll but BEFORE its publish,
        // so a teardown can land while an `Ok` result is in flight.
        let entered = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let after_poll = {
            let entered = Arc::clone(&entered);
            let release = Arc::clone(&release);
            let first = Arc::new(AtomicBool::new(true));
            move || {
                let entered = Arc::clone(&entered);
                let release = Arc::clone(&release);
                let first = Arc::clone(&first);
                async move {
                    if first.swap(false, Ordering::SeqCst) {
                        entered.notify_one();
                        release.notified().await;
                    }
                }
            }
        };
        let child = tokio::spawn(run_refresh(
            discovery,
            Arc::clone(&routing),
            ROUTING_REFRESH_INTERVAL,
            after_poll,
        ));
        tokio::time::timeout(Duration::from_secs(5), entered.notified()).await?;

        // Land the production terminal fence FIRST (routing made terminal, then
        // discovery revoked, then the feed closed), exactly as `ModuleRuntime`
        // does on teardown. A bare feeder (its feed dropped) is fine here: this
        // unit exercises only the routing-first fence ordering, not the feed.
        let mode = ModePublisher::new();
        let store =
            ConfigNamespaceStore::from_toml(&config_zero(), None, &std::env::current_dir()?)?;
        let (metrics, _) =
            crate::metric_source::MetricPublication::new(Arc::new(store), enabled_health());
        let mut owner = ModuleRuntime {
            routing: Arc::clone(&routing),
            discovery: &publisher,
            metrics: &metrics,
            feeder: HealthGenerationFeeder::new().0,
            health: None,
            refresh: None,
            mode: &mode,
            statics: StaticProducers::new(Arc::new(StaticRegistry::default())),
        };
        owner.terminal_fence();

        // Release the in-flight publish: because routing is already terminal, it is
        // refused as `Retired` and cannot resurrect a snapshot.
        release.notify_one();
        settle().await;
        assert!(
            routing_handle.current().is_none(),
            "a publish that lands after the routing-first fence is refused, not resurrected"
        );

        drop(owner);
        child.abort();
        Ok(())
    }

    // ----- Row 3b: module teardown aborts + joins / drops the refresh child --

    /// Builds a zero-cluster module wired with `refresh_override`, spawns it, and
    /// returns the module task and handle.
    fn spawn_module_with_refresh(
        refresh: RefreshFactory,
        runtime: &ControlRuntime,
    ) -> Result<(ModuleTask, super::TopologyModuleHandle), TestError> {
        let store =
            ConfigNamespaceStore::from_toml(&config_zero(), None, &std::env::current_dir()?)?;
        let connects = Arc::new(AtomicUsize::new(0));
        let counters = Counters::default();
        let (mut module, handle) = TopologyModule::new_with_child_runner_and_connector(
            Arc::new(store),
            Box::new(SwitchableFactory {
                gen2: Arc::new(watch::channel(None).0),
            }),
            Arc::new(StaticAdvertiseResolver::new("10.0.0.1")),
            identity(),
            enabled_health(),
            counting_runner(&counters),
            counting_connector(&connects),
        )?;
        module.set_refresh_override(refresh);
        let context = runtime.handle().module_context();
        runtime.mark_ready()?;
        let task = tokio::spawn(Box::new(module).run(context));
        Ok((task, handle))
    }

    /// A clean Stopping teardown must ABORT **and JOIN** the refresh child before
    /// `retire` returns — it is the JOIN, not merely the abort, that is locked here.
    ///
    /// The injected child's cancellation `Drop` bumps `drops`, signals
    /// `drop_entered`, then BLOCKS on a sync `mpsc::recv` (holding one of the two
    /// workers). While the child is thus mid-Drop, the module task can only be
    /// unfinished if `retire` is parked on `handle.await` (the join): the config
    /// has zero registration children, so `stop_children` never yields, meaning a
    /// join-less `retire` (abort kept, `handle.await` deleted) runs straight from
    /// the Stopping wake to `Ok` in a single poll — finishing the module task
    /// BEFORE the child's Drop is even scheduled. So `!task.is_finished()` at the
    /// `drop_entered` barrier holds ONLY when the join is present. Mutations
    /// "retire keeps abort but deletes the await join" and "retire fully detaches"
    /// each turn the `!task.is_finished()` assertion RED.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_stopping_teardown_aborts_and_joins_the_refresh_child() -> Result<(), TestError> {
        let drops = Arc::new(AtomicUsize::new(0));
        let entered = Arc::new(Notify::new());
        let drop_entered = Arc::new(Notify::new());
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let runtime = runtime()?;
        let (task, mut handle) = spawn_module_with_refresh(
            join_barrier_refresh(&drops, &entered, &drop_entered, release_rx),
            &runtime,
        )?;
        wait_ready(&mut handle).await?;

        // Ensure the child future is genuinely entered, holding its guard.
        tokio::time::timeout(Duration::from_secs(5), entered.notified()).await?;
        assert_eq!(
            drops.load(Ordering::SeqCst),
            0,
            "the guard is held by the live refresh child"
        );

        // Stopping teardown: `retire` aborts the child; its Drop starts, signals,
        // then blocks. Wait for the Drop to be in flight.
        request_stop(&runtime)?;
        tokio::time::timeout(Duration::from_secs(5), drop_entered.notified()).await?;
        assert_eq!(
            drops.load(Ordering::SeqCst),
            1,
            "the child's cancellation Drop ran exactly once"
        );

        // The discriminator: the module task must STILL be pending, which can only
        // be true if `retire` is awaiting `handle.await` (the join) on the child
        // that is currently blocked mid-Drop.
        assert!(
            !task.is_finished(),
            "the module task must still be pending: retire is joining the mid-Drop child"
        );

        // Release the blocked Drop; the join then completes and the module returns.
        let _ = release_tx.send(());
        let result = tokio::time::timeout(Duration::from_secs(10), task).await??;
        assert!(
            matches!(result, Ok(())),
            "a clean Stopping teardown returns Ok"
        );
        runtime.finish()?;
        Ok(())
    }

    /// A hard abort of the module task must STILL fence the refresh child: dropping
    /// the `run_inner` frame drops `RefreshOwner`, whose `Drop` aborts the child.
    /// The `dropped` `Notify` is a synchronisation point, and the timeout is a wide
    /// deadlock watchdog, not a semantic threshold: without the `Drop` abort the
    /// guard is NEVER dropped (the child leaks), so the wait always times out; with
    /// it, it fires promptly. Mutation "Drop detaches without abort" turns this row
    /// RED via the watchdog.
    #[tokio::test]
    async fn an_aborted_module_drops_the_refresh_child_via_refresh_owner_drop()
    -> Result<(), TestError> {
        let drops = Arc::new(AtomicUsize::new(0));
        let dropped = Arc::new(Notify::new());
        let entered = Arc::new(Notify::new());
        let runtime = runtime()?;
        let (task, mut handle) = spawn_module_with_refresh(
            guarded_pending_refresh(&drops, &dropped, &entered),
            &runtime,
        )?;
        wait_ready(&mut handle).await?;
        tokio::time::timeout(Duration::from_secs(5), entered.notified()).await?;

        // Hard abort: the `run_inner` frame is dropped, so `RefreshOwner::drop`
        // must abort the child (no async join available on this path). The parent
        // JoinHandle must resolve to a cancelled `JoinError`, never a normal Ok.
        task.abort();
        let joined = tokio::time::timeout(Duration::from_secs(5), task).await?;
        let Err(join_error) = joined else {
            unreachable!("an aborted module task must not complete normally");
        };
        assert!(
            join_error.is_cancelled(),
            "the aborted module task ended cancelled"
        );

        // The guard must be dropped exactly once by the child's cancellation.
        if tokio::time::timeout(Duration::from_secs(5), dropped.notified())
            .await
            .is_err()
        {
            unreachable!("RefreshOwner::drop must abort the child so its guard is dropped");
        }
        assert_eq!(
            drops.load(Ordering::SeqCst),
            1,
            "the aborted child's guard is dropped exactly once"
        );
        drop(runtime);
        Ok(())
    }

    // ----- Row 4: refresh supervision fails loud ---------------------------

    async fn assert_refresh_supervision_fails_loud(panics: bool) -> Result<(), TestError> {
        let runtime = runtime()?;
        let factory: RefreshFactory = Arc::new(move |_discovery, _routing| {
            tokio::spawn(async move {
                assert!(!panics, "injected refresh panic");
                // Otherwise return immediately: an unexpected refresh exit.
            })
        });
        let (task, mut handle) = spawn_module_with_refresh(factory, &runtime)?;
        wait_ready(&mut handle).await?;

        // The refresh child ended on its own; the supervision arm must fail the
        // module loud rather than leave it ready with a silent routing source.
        let result = tokio::time::timeout(Duration::from_secs(5), task).await??;
        let Err(error) = result else {
            unreachable!("an ended refresh child must fail the module")
        };
        assert_eq!(error.module, "control_topology");
        assert_eq!(error.error_class, "routing_refresh_failed");

        runtime.begin_shutdown(ShutdownReason::Requested)?;
        shutdown(&runtime)?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_returning_refresh_child_fails_the_module_loud() -> Result<(), TestError> {
        assert_refresh_supervision_fails_loud(false).await
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_panicking_refresh_child_fails_the_module_loud() -> Result<(), TestError> {
        assert_refresh_supervision_fails_loud(true).await
    }

    // ----- Row 5 (+6 routing side): a pull error retains the last good ------

    #[tokio::test(start_paused = true)]
    async fn a_pull_error_never_clears_or_advances_the_routing_snapshot() -> Result<(), TestError> {
        // Start with NO committed discovery set: the first poll errors.
        let registry = OwnershipRegistry::new();
        let lease = registry
            .claim(OwnerScope::Process, "refresh-retain")
            .unwrap_or_else(|error| unreachable!("claim: {error}"));
        let (publisher, discovery) = DiscoveryPublisher::new();
        let (routing_publisher, routing_handle) = RoutingSnapshotPublisher::new();
        let routing = Arc::new(routing_publisher);
        let child = tokio::spawn(run_refresh(
            discovery,
            Arc::clone(&routing),
            ROUTING_REFRESH_INTERVAL,
            || async {},
        ));

        // The immediate first poll errors (no live set): routing stays fail-closed.
        settle().await;
        assert!(
            routing_handle.current().is_none(),
            "an initial pull error leaves the routing source None"
        );

        // Commit a live set; the next tick publishes generation 1.
        let unused = Arc::new(AtomicUsize::new(0));
        let connector = counting_connector(&unused);
        let prepared = publisher
            .prepare(&connector, &lease.token(), Vec::new())
            .await
            .unwrap_or_else(|_| unreachable!("empty material prepares"));
        publisher.commit(prepared);
        tokio::time::advance(ROUTING_REFRESH_INTERVAL).await;
        settle().await;
        let good = routing_handle
            .current()
            .unwrap_or_else(|| unreachable!("a successful pull publishes generation 1"));
        assert_eq!(good.generation, 1);

        // Revoke discovery so the next pull errors (the Stale/Revoked class the
        // refresh loop must treat as retain-last-good): the routing snapshot must
        // keep the SAME Arc and generation, never clear or advance.
        publisher.revoke();
        tokio::time::advance(ROUTING_REFRESH_INTERVAL).await;
        settle().await;
        let after = routing_handle
            .current()
            .unwrap_or_else(|| unreachable!("the last-good snapshot is retained"));
        assert!(
            Arc::ptr_eq(&good, &after),
            "a post-success pull error retains the exact last-good snapshot"
        );
        assert_eq!(
            after.generation, 1,
            "a pull error never advances the generation"
        );

        child.abort();
        Ok(())
    }

    // ===================================================================
    // #212 mid-poll fence rows (moved from tests/discovery_fence.rs and
    // isolated from the background refresh so there is no wall-clock race).
    // ===================================================================
    //
    // Each drives a REAL module whose discovery connection points at a gated
    // KV.Range fixture, but with a `pending_refresh` override so the module's own
    // refresh loop never polls the fixture. The test's explicit poll is therefore
    // the ONLY caller that can consume the armed stall — with NO dependency on the
    // 3s refresh cadence.

    const CLUSTER_NAME: &str = "cluster-a";
    const TIDB_PREFIX: &[u8] = b"/topology/tidb/";
    const KEYSPACE_PREFIX: &[u8] = b"/keyspaces/tidb/";
    const PROM_PREFIX: &[u8] = b"/topology/prometheus";

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[allow(clippy::too_many_lines)]
    async fn a_tidb_poll_revoked_mid_read_aborts_before_the_second_prefix_and_is_stale()
    -> Result<(), TestError> {
        use kv_fixture::{FixtureFactory, spawn_gated_fixture};

        let body = async {
            // One live TiDB backend under the classic prefix; the keyspace prefix
            // has nothing. The poll reads the classic prefix first (where we stall).
            let seeded = vec![
                (
                    b"/topology/tidb/10.0.0.9:4000/info".to_vec(),
                    br#"{"ip":"10.0.0.9","status_port":10080,"version":"v8"}"#.to_vec(),
                ),
                (b"/topology/tidb/10.0.0.9:4000/ttl".to_vec(), b"1".to_vec()),
            ];
            let Some(fixture) = spawn_gated_fixture(seeded, TIDB_PREFIX, false).await else {
                unreachable!("the fixture binds a loopback port");
            };
            let timeout_ms = Arc::new(AtomicU64::new(500));
            let store = ConfigNamespaceStore::from_toml(
                &config_single(100),
                None,
                &std::env::current_dir()?,
            )?;
            let counters = Counters::default();
            let connects = Arc::new(AtomicUsize::new(0));
            let runtime = runtime()?;
            let (mut module, mut handle) = TopologyModule::new_with_child_runner_and_connector(
                Arc::new(store.clone()),
                Box::new(FixtureFactory {
                    addr: fixture.addr,
                    timeout_ms: Arc::clone(&timeout_ms),
                }),
                Arc::new(StaticAdvertiseResolver::new("10.0.0.1")),
                identity(),
                enabled_health(),
                counting_runner(&counters),
                counting_real_connector(&connects),
            )?;
            module.set_refresh_override(pending_refresh());
            let context = runtime.handle().module_context();
            runtime.mark_ready()?;
            let task = tokio::spawn(Box::new(module).run(context));
            wait_ready(&mut handle).await?;
            let mut status = handle.status();
            let _ = status.borrow_and_update();

            // Park a merged poll inside its first (classic) TiDB Range.
            let discovery = handle.discovery_handle();
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

            // Rotate the material mid-poll (a different client timeout), revoking
            // the parked epoch's gate, then release the stall.
            timeout_ms.store(700, Ordering::SeqCst);
            store.apply_toml(&config_single(200), None, 2, &std::env::current_dir()?)?;
            wait_observed(&mut status, 2).await?;
            fixture.release.notify_one();

            let joined = tokio::time::timeout(Duration::from_secs(5), poll).await?;
            let result = joined.unwrap_or_else(|error| unreachable!("poll task: {error}"));

            // Fence 1 (per-connection gate): the revoked gate aborted the poll at
            // its next `execute`, so the SECOND prefix Range was never issued.
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

            request_stop(&runtime)?;
            tokio::time::timeout(Duration::from_secs(10), task).await???;
            runtime.finish()?;
            Ok::<(), TestError>(())
        };
        match tokio::time::timeout(Duration::from_secs(10), body).await {
            Ok(inner) => inner,
            Err(_) => unreachable!("the TiDB fence scenario completes within the deadline"),
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[allow(clippy::too_many_lines)]
    async fn a_prometheus_poll_revoked_mid_read_sends_no_retry_and_is_stale()
    -> Result<(), TestError> {
        use kv_fixture::{FixtureFactory, spawn_gated_fixture};

        let body = async {
            // A valid Prometheus record so a NON-fenced retry would succeed; the
            // fence must stop the poll before any retry. `error_after_release`
            // fails the parked first attempt, so absent the gate fence the retry
            // policy would issue a SECOND Prometheus Range.
            let seeded = vec![(
                b"/topology/prometheus/x".to_vec(),
                br#"{"ip":"1.2.3.4","port":9090}"#.to_vec(),
            )];
            let Some(fixture) = spawn_gated_fixture(seeded, PROM_PREFIX, true).await else {
                unreachable!("the fixture binds a loopback port");
            };
            let timeout_ms = Arc::new(AtomicU64::new(500));
            let store = ConfigNamespaceStore::from_toml(
                &config_single(100),
                None,
                &std::env::current_dir()?,
            )?;
            let counters = Counters::default();
            let connects = Arc::new(AtomicUsize::new(0));
            let runtime = runtime()?;
            let (mut module, mut handle) = TopologyModule::new_with_child_runner_and_connector(
                Arc::new(store.clone()),
                Box::new(FixtureFactory {
                    addr: fixture.addr,
                    timeout_ms: Arc::clone(&timeout_ms),
                }),
                Arc::new(StaticAdvertiseResolver::new("10.0.0.1")),
                identity(),
                enabled_health(),
                counting_runner(&counters),
                counting_real_connector(&connects),
            )?;
            module.set_refresh_override(pending_refresh());
            let context = runtime.handle().module_context();
            runtime.mark_ready()?;
            let task = tokio::spawn(Box::new(module).run(context));
            wait_ready(&mut handle).await?;
            let mut status = handle.status();
            let _ = status.borrow_and_update();

            // Park a Prometheus poll inside its first Range attempt.
            let discovery = handle.discovery_handle();
            let poll = tokio::spawn(async move { discovery.poll_prometheus(CLUSTER_NAME).await });
            fixture.arrived.notified().await;
            assert_eq!(
                fixture.range_count(PROM_PREFIX),
                1,
                "the poll issued exactly the first Prometheus Range"
            );

            // Rotate the material mid-poll, revoking the parked epoch's gate, then
            // release the stall (which then fails the first attempt).
            timeout_ms.store(700, Ordering::SeqCst);
            store.apply_toml(&config_single(200), None, 2, &std::env::current_dir()?)?;
            wait_observed(&mut status, 2).await?;
            fixture.release.notify_one();

            let joined = tokio::time::timeout(Duration::from_secs(5), poll).await?;
            let result = joined.unwrap_or_else(|error| unreachable!("poll task: {error}"));

            // Fence 1 (per-connection gate): the revoked gate aborts the retry loop
            // at the next attempt's `execute`, so NO second Prometheus Range is sent.
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

            request_stop(&runtime)?;
            tokio::time::timeout(Duration::from_secs(10), task).await???;
            runtime.finish()?;
            Ok::<(), TestError>(())
        };
        match tokio::time::timeout(Duration::from_secs(10), body).await {
            Ok(inner) => inner,
            Err(_) => unreachable!("the Prometheus fence scenario completes within the deadline"),
        }
    }

    // ====================================================================
    // CP-TOPO #213-3a: health composed into the module lifecycle.
    // ====================================================================

    /// A disabled restart-pinned health config (valid cadence, no probe): the
    /// module runs its all-healthy zero-I/O rounds and NEVER constructs a network.
    fn disabled_health() -> HealthCheckConfig {
        HealthCheckConfig {
            enabled: false,
            ..HealthCheckConfig::default()
        }
    }

    /// Cluster material whose real `ClusterHttpClient` build FAILS closed: a
    /// non-`skip_ca_verification` TLS policy with non-PEM CA bytes, so
    /// `client_config()` rejects it (`EmptyCaCertificate`). The injected discovery
    /// connector ignores this material and still connects, so a health-build
    /// failure is isolated from discovery. `timeout_ms` varies the material so a
    /// later generation is a genuine rotation.
    fn bad_client(timeout_ms: u64) -> EtcdClientConfig {
        let tls = EtcdTlsConfig::new(
            Some(b"not-a-real-pem".to_vec()),
            None,
            None,
            Some("cluster.local".to_owned()),
            EtcdTlsPolicy::default(),
        )
        .unwrap_or_else(|_| unreachable!("non-empty CA is a valid config"));
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

    type MakeClient = Arc<dyn Fn() -> EtcdClientConfig + Send + Sync>;

    /// A factory whose per-cluster client is a swappable closure, so a test drives
    /// an exact material sequence (good → bad → good) across generations. The
    /// closure is read under a lock on every `build`.
    struct DynFactory {
        make: Arc<std::sync::Mutex<MakeClient>>,
    }

    impl DynFactory {
        fn new(make: MakeClient) -> (Self, Arc<std::sync::Mutex<MakeClient>>) {
            let shared = Arc::new(std::sync::Mutex::new(make));
            (
                Self {
                    make: Arc::clone(&shared),
                },
                shared,
            )
        }
    }

    fn set_make(shared: &Arc<std::sync::Mutex<MakeClient>>, make: MakeClient) {
        *shared
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = make;
    }

    impl TopologyClientFactory for DynFactory {
        fn build(
            &self,
            snapshot: &ConfigNamespaceSnapshot,
        ) -> Result<Vec<TopologyClusterClient>, String> {
            let topology = snapshot
                .topology()
                .map_err(|_| "topology projection".to_owned())?;
            let make = Arc::clone(
                &self
                    .make
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner),
            );
            Ok(topology
                .backend_clusters
                .iter()
                .map(|c| cluster(Arc::clone(&c.name), make()))
                .collect())
        }
    }

    /// One merged backend under `cluster-a` with a distinguishable address, so two
    /// same-epoch routing snapshots differ by content.
    fn merged_backend(index: usize) -> MergedBackend {
        MergedBackend {
            backend_id: Arc::from(format!("cluster-a/10.0.0.{index}:4000").as_str()),
            cluster_name: Arc::from("cluster-a"),
            backend: BackendInfo {
                addr: format!("10.0.0.{index}:4000"),
                keyspace: String::new(),
                ip: String::new(),
                status_port: 0,
                version: String::new(),
                git_hash: String::new(),
                deploy_path: String::new(),
                start_timestamp: 0,
                labels: std::collections::BTreeMap::new(),
            },
        }
    }

    fn epoch_result(client_epoch: u64, backends: usize) -> EpochResult<MergedTopology> {
        EpochResult {
            client_epoch,
            value: MergedTopology {
                backends: (0..backends).map(merged_backend).collect(),
            },
        }
    }

    /// A refresh child that publishes exactly the routing snapshots the test sends
    /// it, so a test drives the routing generation deterministically (which epoch
    /// is live, and when a same-epoch content refresh lands). Returns the factory
    /// and the command sender.
    fn commandable_refresh() -> (
        RefreshFactory,
        tokio::sync::mpsc::UnboundedSender<EpochResult<MergedTopology>>,
    ) {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<EpochResult<MergedTopology>>();
        let rx = Arc::new(std::sync::Mutex::new(Some(rx)));
        let factory: RefreshFactory = Arc::new(move |_discovery, routing| {
            let taken = rx
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take();
            tokio::spawn(async move {
                let Some(mut rx) = taken else {
                    pending::<()>().await;
                    return;
                };
                while let Some(result) = rx.recv().await {
                    let _ = routing.publish(result);
                }
            })
        });
        (factory, tx)
    }

    /// A health child that captures a clone of the feed (so a test can observe the
    /// module's feed pairing directly) and then parks. It does not publish an
    /// overlay: the feed IS the reconcile output under test.
    fn capture_feed_health(
        slot: &Arc<std::sync::Mutex<Option<HealthGenerationFeed>>>,
    ) -> HealthFactory {
        let slot = Arc::clone(slot);
        Arc::new(move |feed, _publisher, _routing, _owner| {
            *slot
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(feed.clone());
            tokio::spawn(pending::<()>())
        })
    }

    /// Resolves once the health child has stored the module's feed (spawned right
    /// after the module signals ready). Bounded and deterministic.
    async fn captured_feed(
        slot: &Arc<std::sync::Mutex<Option<HealthGenerationFeed>>>,
    ) -> Result<HealthGenerationFeed, TestError> {
        for _ in 0..2000 {
            if let Some(feed) = slot
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
            {
                return Ok(feed);
            }
            tokio::task::yield_now().await;
        }
        Err("the health child never stored the feed".into())
    }

    /// Waits until the feed's current generation reflects the given source epoch
    /// (`Some(epoch)`) or is withdrawn (`None`), awaiting the feed's own change
    /// notifier — no sleep, no busy-poll.
    async fn wait_feed_epoch(
        feed: &HealthGenerationFeed,
        want: Option<u64>,
    ) -> Result<(), TestError> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            let (generation, revision, _terminal) = feed.snapshot();
            let have = generation.as_ref().map(|g| g.source.client_epoch);
            if have == want {
                return Ok(());
            }
            tokio::time::timeout(
                deadline - tokio::time::Instant::now(),
                feed.wait_change(revision),
            )
            .await?;
        }
    }

    /// Waits until the feed is paired with a source of the given routing
    /// generation, returning that source and the feed's networks `Arc`.
    #[allow(clippy::type_complexity)]
    async fn wait_feed_source_gen(
        feed: &HealthGenerationFeed,
        want_generation: u64,
    ) -> Result<
        (
            Arc<RoutingSnapshot>,
            Option<Arc<std::collections::HashMap<Arc<str>, super::ClusterHealthNetwork>>>,
        ),
        TestError,
    > {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            let (generation, revision, _terminal) = feed.snapshot();
            if let Some(g) = &generation
                && g.source.generation == want_generation
            {
                return Ok((Arc::clone(&g.source), g.networks.clone()));
            }
            tokio::time::timeout(
                deadline - tokio::time::Instant::now(),
                feed.wait_change(revision),
            )
            .await?;
        }
    }

    // ----- B3: a disabled runtime constructs no health client ---------------

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_disabled_runtime_accepts_unbuildable_material_across_generations()
    -> Result<(), TestError> {
        // A disabled module with clusters whose material would FAIL a real
        // ClusterHttpClient build: both the initial AND a later material rotation
        // must be ACCEPTED (no HealthClientBuildFailed), proving no health client
        // is ever constructed.
        let store =
            ConfigNamespaceStore::from_toml(&config_single(100), None, &std::env::current_dir()?)?;
        let (factory, make) = DynFactory::new(Arc::new(|| bad_client(500)));
        let counters = Counters::default();
        let runtime = runtime()?;
        let (module, mut handle) = TopologyModule::new_with_child_runner(
            Arc::new(store.clone()),
            Box::new(factory),
            Arc::new(StaticAdvertiseResolver::new("10.0.0.1")),
            identity(),
            disabled_health(),
            counting_runner(&counters),
        )?;
        let context = runtime.handle().module_context();
        runtime.mark_ready()?;
        let task = tokio::spawn(Box::new(module).run(context));

        // The initial generation applied: a disabled runtime built no client from
        // the un-buildable material.
        wait_ready(&mut handle).await?;
        let mut status = handle.status();
        assert_eq!(status.borrow_and_update().applied_generation, 1);

        // A real subsequent material rotation (different un-buildable client) is
        // ALSO accepted — still no client construction.
        set_make(&make, Arc::new(|| bad_client(700)));
        store.apply_toml(&config_single(200), None, 2, &std::env::current_dir()?)?;
        let after = wait_observed(&mut status, 2).await?;
        assert_eq!(
            after.applied_generation, 2,
            "a disabled runtime accepts a rotation of un-buildable material"
        );
        assert_eq!(
            after.last_rejection, None,
            "no HealthClientBuildFailed: no health client was ever constructed"
        );

        request_stop(&runtime)?;
        tokio::time::timeout(Duration::from_secs(10), task).await???;
        runtime.finish()?;
        Ok(())
    }

    /// Waits until the published routing source carries the given client epoch,
    /// returning that exact source `Arc`.
    async fn wait_routing_epoch(
        routing: &RoutingSnapshotHandle,
        want: u64,
    ) -> Result<Arc<RoutingSnapshot>, TestError> {
        // Check, then wait on the crate-private publication watch: a version
        // published between the check and the wait is still unseen, so `changed`
        // returns at once and no edge is lost. A closed source fails closed.
        let mut routing = routing.clone();
        loop {
            if let Some(source) = routing.current()
                && source.client_epoch == want
            {
                return Ok(source);
            }
            routing
                .changed()
                .await
                .map_err(|_| "the routing source closed before the wanted epoch")?;
        }
    }

    /// Waits until the health overlay is published for the EXACT source and asserts
    /// every backend reads healthy with no version — the disabled all-healthy
    /// verdict — re-checked through the unbypassable `still_current_for`.
    async fn wait_overlay_all_healthy(
        overlay: &HealthOverlayHandle,
        routing: &RoutingSnapshotHandle,
        source: &Arc<RoutingSnapshot>,
    ) -> Result<(), TestError> {
        tokio::time::timeout(Duration::from_secs(5), async {
            let mut changes = overlay.clone();
            loop {
                if let Some(health) = overlay.current_for(source)
                    && overlay.still_current_for(&health, source, routing)
                {
                    for backend in &source.backends.backends {
                        let verdict = health.get(&backend.backend_id);
                        if !verdict.healthy || verdict.server_version.is_some() {
                            return Err("a disabled runtime must publish an all-healthy, \
                                        version-None overlay for the exact source"
                                .into());
                        }
                    }
                    return Ok(());
                }
                // The cloned receiver retains unseen publication edges, including
                // an update between the candidate check and this await.
                changes.changed().await?;
            }
        })
        .await
        .map_err(|_| -> TestError {
            "the disabled runtime never published an overlay for the exact source".into()
        })?
    }

    /// Option D's module-level disabled guarantee, on the REAL run/health loop
    /// (no injected health child): a disabled runtime not only builds no client —
    /// its `run_inner` adapter pairs a `networks = None` generation to the EXACT
    /// published routing source, and the loop publishes an all-healthy, version-None
    /// overlay for it. This holds across a real material rotation, and the
    /// superseded source is de-authorized. It kills the reconcile mutation that
    /// pairs only when `networks.is_some()` (disabled → permanent withdraw, no
    /// overlay), which the construction-only B3 row cannot see.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_disabled_runtime_publishes_an_all_healthy_overlay_across_a_rotation()
    -> Result<(), TestError> {
        let store =
            ConfigNamespaceStore::from_toml(&config_single(100), None, &std::env::current_dir()?)?;
        let (factory, make) = DynFactory::new(Arc::new(|| bad_client(500)));
        let counters = Counters::default();
        let runtime = runtime()?;
        let (module, mut handle) = TopologyModule::new_with_child_runner(
            Arc::new(store.clone()),
            Box::new(factory),
            Arc::new(StaticAdvertiseResolver::new("10.0.0.1")),
            identity(),
            disabled_health(),
            counting_runner(&counters),
        )?;
        // Drive routing deterministically; the REAL health loop runs (no override).
        let mut module = module;
        let (refresh, commands) = commandable_refresh();
        module.set_refresh_override(refresh);
        let context = runtime.handle().module_context();
        runtime.mark_ready()?;
        let task = tokio::spawn(Box::new(module).run(context));

        wait_ready(&mut handle).await?;
        let mut status = handle.status();
        let _ = status.borrow_and_update();
        let overlay = handle.health_overlay_handle();
        let routing = handle.routing_handle();

        // Publish a matching epoch-0 source: the adapter pairs a disabled
        // (networks = None) generation and the loop publishes an all-healthy overlay.
        commands.send(epoch_result(0, 1))?;
        let source0 = wait_routing_epoch(&routing, 0).await?;
        wait_overlay_all_healthy(&overlay, &routing, &source0).await?;

        // A real material rotation → discovery epoch 1, still no client construction.
        set_make(&make, Arc::new(|| bad_client(700)));
        store.apply_toml(&config_single(200), None, 2, &std::env::current_dir()?)?;
        let after = wait_observed(&mut status, 2).await?;
        assert_eq!(
            after.applied_generation, 2,
            "a disabled runtime accepts a rotation of un-buildable material"
        );
        assert_eq!(
            after.last_rejection, None,
            "no HealthClientBuildFailed: no health client was ever constructed"
        );

        // The matching epoch-1 source re-pairs and stays all-healthy; the old source
        // is de-authorized.
        commands.send(epoch_result(1, 1))?;
        let source1 = wait_routing_epoch(&routing, 1).await?;
        assert!(
            !Arc::ptr_eq(&source0, &source1),
            "the rotation published a new exact source Arc"
        );
        wait_overlay_all_healthy(&overlay, &routing, &source1).await?;
        assert!(
            overlay.current_for(&source0).is_none(),
            "the superseded epoch-0 source is fail-closed after the rotation"
        );

        request_stop(&runtime)?;
        tokio::time::timeout(Duration::from_secs(10), task).await???;
        runtime.finish()?;
        Ok(())
    }

    // ----- B4: a health-build failure burns no epoch ------------------------

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_health_build_failure_retains_last_good_and_burns_no_epoch() -> Result<(), TestError>
    {
        // ENABLED. The initial generation builds a health client from buildable
        // material; a later generation's material fails the health build while the
        // injected plaintext connector would still connect. The rejection must
        // reserve NO discovery epoch: `build_prepared_health` runs BEFORE
        // `discovery.prepare`, so the rejected generation issues no connect, and a
        // following valid generation reconnects exactly once (epoch prev+1).
        let store =
            ConfigNamespaceStore::from_toml(&config_single(100), None, &std::env::current_dir()?)?;
        let (factory, make) = DynFactory::new(Arc::new(|| client(500, b"pem-a")));
        let counters = Counters::default();
        let connects = Arc::new(AtomicUsize::new(0));
        let runtime = runtime()?;
        let (task, mut handle) = spawn_with_connector(
            store.clone(),
            Box::new(factory),
            counting_runner(&counters),
            counting_connector(&connects),
            &runtime,
        )?;
        wait_ready(&mut handle).await?;
        let mut status = handle.status();
        assert_eq!(status.borrow_and_update().applied_generation, 1);
        assert_eq!(
            connects.load(Ordering::SeqCst),
            1,
            "the initial generation reserved one discovery epoch"
        );

        // Generation 2: material that fails the health build. Rejected as
        // HealthClientBuildFailed, retaining the last-good registration — and
        // crucially issuing NO discovery connect (no epoch reserved).
        set_make(&make, Arc::new(|| bad_client(700)));
        store.apply_toml(&config_single(200), None, 2, &std::env::current_dir()?)?;
        let rejected = wait_observed(&mut status, 2).await?;
        assert_eq!(
            rejected.last_rejection,
            Some(RejectionClass::HealthClientBuildFailed),
            "the health-build failure is the rejection class"
        );
        assert_eq!(
            rejected.applied_generation, 1,
            "the last-good generation is retained"
        );
        assert_eq!(
            connects.load(Ordering::SeqCst),
            1,
            "a health-build rejection reserves no epoch: no new discovery connect"
        );

        // Generation 3: valid material again → reconnects exactly once. Had the
        // rejected generation burned an epoch, this would be the SECOND extra
        // connect; it is the first.
        set_make(&make, Arc::new(|| client(900, b"pem-a")));
        store.apply_toml(&config_single(300), None, 3, &std::env::current_dir()?)?;
        let applied = wait_observed(&mut status, 3).await?;
        assert_eq!(
            applied.applied_generation, 3,
            "the valid generation applies"
        );
        assert_eq!(applied.last_rejection, None);
        assert_eq!(
            connects.load(Ordering::SeqCst),
            2,
            "the next valid generation reserved exactly one further epoch (prev+1)"
        );

        request_stop(&runtime)?;
        tokio::time::timeout(Duration::from_secs(10), task).await???;
        runtime.finish()?;
        Ok(())
    }

    /// Builds an enabled module with BOTH a commandable refresh child and a
    /// feed-capturing health child, so a test drives routing generations by hand
    /// and reads the module's feed pairing. Returns the task, handle, the routing
    /// command sender, and the feed slot.
    #[allow(clippy::type_complexity)]
    fn spawn_module_with_controlled_planes(
        store: ConfigNamespaceStore,
        runtime: &ControlRuntime,
    ) -> Result<
        (
            ModuleTask,
            super::TopologyModuleHandle,
            tokio::sync::mpsc::UnboundedSender<EpochResult<MergedTopology>>,
            Arc<std::sync::Mutex<Option<HealthGenerationFeed>>>,
        ),
        TestError,
    > {
        let (factory, _make) = DynFactory::new(Arc::new(|| client(500, b"pem-a")));
        let counters = Counters::default();
        let connects = Arc::new(AtomicUsize::new(0));
        let (module, handle) = TopologyModule::new_with_child_runner_and_connector(
            Arc::new(store),
            Box::new(factory),
            Arc::new(StaticAdvertiseResolver::new("10.0.0.1")),
            identity(),
            enabled_health(),
            counting_runner(&counters),
            counting_connector(&connects),
        )?;
        let mut module = module;
        let (refresh, commands) = commandable_refresh();
        let slot: Arc<std::sync::Mutex<Option<HealthGenerationFeed>>> =
            Arc::new(std::sync::Mutex::new(None));
        module.set_refresh_override(refresh);
        module.set_health_override(capture_feed_health(&slot));
        let context = runtime.handle().module_context();
        runtime.mark_ready()?;
        let task = tokio::spawn(Box::new(module).run(context));
        Ok((task, handle, commands, slot))
    }

    // ----- B5: an epoch mismatch / lag withdraws the feed -------------------

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_epoch_lagged_routing_source_withdraws_the_feed() -> Result<(), TestError> {
        let store =
            ConfigNamespaceStore::from_toml(&config_single(100), None, &std::env::current_dir()?)?;
        let (factory, make) = DynFactory::new(Arc::new(|| client(500, b"pem-a")));
        let counters = Counters::default();
        let connects = Arc::new(AtomicUsize::new(0));
        let runtime = runtime()?;
        let (module, mut handle) = TopologyModule::new_with_child_runner_and_connector(
            Arc::new(store.clone()),
            Box::new(factory),
            Arc::new(StaticAdvertiseResolver::new("10.0.0.1")),
            identity(),
            enabled_health(),
            counting_runner(&counters),
            counting_connector(&connects),
        )?;
        let mut module = module;
        let (refresh, commands) = commandable_refresh();
        let slot: Arc<std::sync::Mutex<Option<HealthGenerationFeed>>> =
            Arc::new(std::sync::Mutex::new(None));
        module.set_refresh_override(refresh);
        module.set_health_override(capture_feed_health(&slot));
        let context = runtime.handle().module_context();
        runtime.mark_ready()?;
        let task = tokio::spawn(Box::new(module).run(context));

        wait_ready(&mut handle).await?;
        let mut status = handle.status();
        let _ = status.borrow_and_update();
        let feed = captured_feed(&slot).await?;

        // The initial generation reserved epoch 0. Publish a matching epoch-0
        // routing source → the observer pairs the feed to epoch 0.
        commands.send(epoch_result(0, 1))?;
        wait_feed_epoch(&feed, Some(0)).await?;

        // Rotate the cluster material → discovery advances to epoch 1. Routing is
        // still the epoch-0 source (lagging), so the exact-epoch reconcile
        // WITHDRAWS the feed rather than pairing wrong-epoch material.
        set_make(&make, Arc::new(|| client(700, b"pem-a")));
        store.apply_toml(&config_single(200), None, 2, &std::env::current_dir()?)?;
        wait_observed(&mut status, 2).await?;
        let (paired, _revision, _terminal) = feed.snapshot();
        assert!(
            paired.is_none(),
            "an epoch-lagged routing source is fail-closed: the feed is withdrawn, not mis-paired"
        );

        // Once routing publishes the epoch-1 source, the observer re-pairs the feed.
        commands.send(epoch_result(1, 1))?;
        wait_feed_epoch(&feed, Some(1)).await?;

        request_stop(&runtime)?;
        tokio::time::timeout(Duration::from_secs(10), task).await???;
        runtime.finish()?;
        Ok(())
    }

    // ----- B7: a same-epoch content refresh re-pairs and reuses the artifact -

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_same_epoch_content_refresh_repairs_with_the_reused_artifact() -> Result<(), TestError>
    {
        let store =
            ConfigNamespaceStore::from_toml(&config_single(100), None, &std::env::current_dir()?)?;
        let runtime = runtime()?;
        let (task, mut handle, commands, slot) =
            spawn_module_with_controlled_planes(store, &runtime)?;

        wait_ready(&mut handle).await?;
        let feed = captured_feed(&slot).await?;

        // Publish the first epoch-0 routing source (generation 1): the feed pairs
        // and carries the artifact's networks Arc.
        commands.send(epoch_result(0, 1))?;
        let (first_source, first_networks) = wait_feed_source_gen(&feed, 1).await?;
        assert_eq!(first_source.client_epoch, 0);
        let first_networks =
            first_networks.unwrap_or_else(|| unreachable!("enabled health carries networks"));

        // A same-epoch CONTENT refresh: a NEW Arc, SAME epoch 0, different backends
        // (generation 2). The observer re-pairs the feed to the NEW source Arc and
        // REUSES the same networks Arc (the artifact is not rebuilt).
        commands.send(epoch_result(0, 2))?;
        let (second_source, second_networks) = wait_feed_source_gen(&feed, 2).await?;
        let second_networks =
            second_networks.unwrap_or_else(|| unreachable!("enabled health carries networks"));

        assert_eq!(
            second_source.client_epoch, 0,
            "the refresh is the same discovery epoch"
        );
        assert!(
            !Arc::ptr_eq(&first_source, &second_source),
            "the feed re-paired to the NEW routing source Arc"
        );
        assert!(
            Arc::ptr_eq(&first_networks, &second_networks),
            "the SAME networks artifact Arc is reused across a same-epoch refresh"
        );
        // The feed's source is exactly the module's currently published routing Arc.
        let current = handle
            .routing_handle()
            .current()
            .unwrap_or_else(|| unreachable!("a routing source is published"));
        assert!(
            Arc::ptr_eq(&current, &second_source),
            "the feed is paired to the exact live routing source"
        );

        request_stop(&runtime)?;
        tokio::time::timeout(Duration::from_secs(10), task).await???;
        runtime.finish()?;
        Ok(())
    }

    // ----- B8: health config is pinned by construction ----------------------

    #[test]
    fn an_invalid_pinned_health_config_is_rejected_before_construction() -> Result<(), TestError> {
        // An invalid pinned config fails `new` with the exact HealthConfigError and
        // yields NO module/handle — the failure is caught before any live plane is
        // created. Validation holds in every mode (an enabled AND a disabled base).
        type HealthCase = (fn(&mut HealthCheckConfig), HealthConfigError);
        let cases: [HealthCase; 4] = [
            (|c| c.interval_nanos = 0, HealthConfigError::InvalidInterval),
            (
                |c| c.retry_interval_nanos = 0,
                HealthConfigError::InvalidRetryInterval,
            ),
            (|c| c.max_retries = 101, HealthConfigError::TooManyRetries),
            (
                |c| c.dial_timeout_nanos = 0,
                HealthConfigError::InvalidDialTimeout,
            ),
        ];
        for (mutate, expected) in cases {
            for base in [HealthCheckConfig::default(), disabled_health()] {
                let mut config = base;
                mutate(&mut config);
                let store = ConfigNamespaceStore::from_toml(
                    &config_single(100),
                    None,
                    &std::env::current_dir()?,
                )?;
                let (factory, _make) = DynFactory::new(Arc::new(|| client(500, b"pem-a")));
                let outcome = TopologyModule::new(
                    Arc::new(store),
                    Box::new(factory),
                    Arc::new(StaticAdvertiseResolver::new("10.0.0.1")),
                    identity(),
                    config,
                );
                let Err(error) = outcome else {
                    unreachable!("an invalid pinned health config must fail construction");
                };
                assert_eq!(
                    error, expected,
                    "enabled={}: the invalid field is rejected before construction",
                    config.enabled
                );
            }
        }
        Ok(())
    }

    // ----- B9: an unexpected health-child exit fails the module loud ---------

    /// Builds a zero-cluster module with an injected health child and default
    /// refresh, spawns it, and returns the module task and handle.
    fn spawn_module_with_health(
        health: HealthFactory,
        runtime: &ControlRuntime,
    ) -> Result<(ModuleTask, super::TopologyModuleHandle), TestError> {
        let store =
            ConfigNamespaceStore::from_toml(&config_zero(), None, &std::env::current_dir()?)?;
        let connects = Arc::new(AtomicUsize::new(0));
        let counters = Counters::default();
        let (mut module, handle) = TopologyModule::new_with_child_runner_and_connector(
            Arc::new(store),
            Box::new(SwitchableFactory {
                gen2: Arc::new(watch::channel(None).0),
            }),
            Arc::new(StaticAdvertiseResolver::new("10.0.0.1")),
            identity(),
            enabled_health(),
            counting_runner(&counters),
            counting_connector(&connects),
        )?;
        module.set_health_override(health);
        module.set_refresh_override(pending_refresh());
        let context = runtime.handle().module_context();
        runtime.mark_ready()?;
        let task = tokio::spawn(Box::new(module).run(context));
        Ok((task, handle))
    }

    async fn assert_health_supervision_fails_loud(panics: bool) -> Result<(), TestError> {
        let runtime = runtime()?;
        let factory: HealthFactory = Arc::new(move |_feed, _publisher, _routing, _owner| {
            tokio::spawn(async move {
                assert!(!panics, "injected health panic");
                // Otherwise return immediately: an unexpected health exit.
            })
        });
        let (task, mut handle) = spawn_module_with_health(factory, &runtime)?;
        wait_ready(&mut handle).await?;

        // The health child ended on its own; the supervision arm must fail the
        // module loud rather than leave it ready with a silent health overlay.
        let result = tokio::time::timeout(Duration::from_secs(5), task).await??;
        let Err(error) = result else {
            unreachable!("an ended health child must fail the module")
        };
        assert_eq!(error.module, "control_topology");
        assert_eq!(error.error_class, "health_loop_failed");

        runtime.begin_shutdown(ShutdownReason::Requested)?;
        shutdown(&runtime)?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_returning_health_child_fails_the_module_loud() -> Result<(), TestError> {
        assert_health_supervision_fails_loud(false).await
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_panicking_health_child_fails_the_module_loud() -> Result<(), TestError> {
        assert_health_supervision_fails_loud(true).await
    }

    // ----- B11: teardown leaks neither child --------------------------------

    /// A health child that holds a `DropGuard` and parks forever. The guard's
    /// `Drop` bumps `drops` and fires `dropped`; the child fires `entered` once it
    /// is genuinely running, so a test proves the guard is dropped exactly once and
    /// only through `ModuleRuntime`'s abort/join (retire) and abort (Drop).
    fn guarded_pending_health(
        drops: &Arc<AtomicUsize>,
        dropped: &Arc<Notify>,
        entered: &Arc<Notify>,
    ) -> HealthFactory {
        struct DropGuard {
            drops: Arc<AtomicUsize>,
            dropped: Arc<Notify>,
        }
        impl Drop for DropGuard {
            fn drop(&mut self) {
                self.drops.fetch_add(1, Ordering::SeqCst);
                self.dropped.notify_one();
            }
        }

        let drops = Arc::clone(drops);
        let dropped = Arc::clone(dropped);
        let entered = Arc::clone(entered);
        Arc::new(move |_feed, _publisher, _routing, _owner| {
            let guard = DropGuard {
                drops: Arc::clone(&drops),
                dropped: Arc::clone(&dropped),
            };
            let entered = Arc::clone(&entered);
            tokio::spawn(async move {
                let _guard = guard;
                entered.notify_one();
                pending::<()>().await;
            })
        })
    }

    /// Builds a zero-cluster module wired with BOTH a guarded refresh child and a
    /// guarded health child, spawns it, and returns the task and handle.
    #[allow(clippy::too_many_arguments)]
    fn spawn_module_with_both_children(
        refresh: RefreshFactory,
        health: HealthFactory,
        runtime: &ControlRuntime,
    ) -> Result<(ModuleTask, super::TopologyModuleHandle), TestError> {
        let store =
            ConfigNamespaceStore::from_toml(&config_zero(), None, &std::env::current_dir()?)?;
        let connects = Arc::new(AtomicUsize::new(0));
        let counters = Counters::default();
        let (mut module, handle) = TopologyModule::new_with_child_runner_and_connector(
            Arc::new(store),
            Box::new(SwitchableFactory {
                gen2: Arc::new(watch::channel(None).0),
            }),
            Arc::new(StaticAdvertiseResolver::new("10.0.0.1")),
            identity(),
            enabled_health(),
            counting_runner(&counters),
            counting_connector(&connects),
        )?;
        module.set_refresh_override(refresh);
        module.set_health_override(health);
        let context = runtime.handle().module_context();
        runtime.mark_ready()?;
        let task = tokio::spawn(Box::new(module).run(context));
        Ok((task, handle))
    }

    /// A health child whose cancellation `Drop` BLOCKS on a sync `mpsc::recv`
    /// until released, so a test can hold it mid-Drop and prove `ModuleRuntime::retire`
    /// is *awaiting* the health `handle.await` (the JOIN) — the module task cannot
    /// finish while the health child is still dropping. Mirrors `join_barrier_refresh`.
    fn join_barrier_health(
        drops: &Arc<AtomicUsize>,
        entered: &Arc<Notify>,
        drop_entered: &Arc<Notify>,
        release_rx: std::sync::mpsc::Receiver<()>,
    ) -> HealthFactory {
        struct BlockingGuard {
            drops: Arc<AtomicUsize>,
            drop_entered: Arc<Notify>,
            release: Arc<std::sync::Mutex<Option<std::sync::mpsc::Receiver<()>>>>,
        }
        impl Drop for BlockingGuard {
            fn drop(&mut self) {
                self.drops.fetch_add(1, Ordering::SeqCst);
                self.drop_entered.notify_one();
                let rx = self
                    .release
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .take();
                if let Some(rx) = rx {
                    let _ = rx.recv();
                }
            }
        }

        let drops = Arc::clone(drops);
        let entered = Arc::clone(entered);
        let drop_entered = Arc::clone(drop_entered);
        let release = Arc::new(std::sync::Mutex::new(Some(release_rx)));
        Arc::new(move |_feed, _publisher, _routing, _owner| {
            let guard = BlockingGuard {
                drops: Arc::clone(&drops),
                drop_entered: Arc::clone(&drop_entered),
                release: Arc::clone(&release),
            };
            let entered = Arc::clone(&entered);
            tokio::spawn(async move {
                let _guard = guard;
                entered.notify_one();
                pending::<()>().await;
            })
        })
    }

    /// A clean Stopping teardown must ABORT **and JOIN** the health child before
    /// `retire` returns — it is the JOIN (not merely the abort) that is locked, so
    /// this survives the `ModuleRuntime::drop` backstop. The health child's Drop
    /// bumps `drops`, signals `drop_entered`, then BLOCKS; the zero-cluster config
    /// makes `stop_children` never yield, so the module task can be unfinished at
    /// the barrier ONLY if `retire` is parked on the health `handle.await`.
    /// Mutation "retire drops the health abort+join" turns `!task.is_finished()` RED.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_stopping_teardown_aborts_and_joins_the_health_child() -> Result<(), TestError> {
        let drops = Arc::new(AtomicUsize::new(0));
        let entered = Arc::new(Notify::new());
        let drop_entered = Arc::new(Notify::new());
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let runtime = runtime()?;
        let (mut task, mut handle) = spawn_module_with_both_children(
            pending_refresh(),
            join_barrier_health(&drops, &entered, &drop_entered, release_rx),
            &runtime,
        )?;
        wait_ready(&mut handle).await?;
        tokio::time::timeout(Duration::from_secs(5), entered.notified()).await?;
        assert_eq!(
            drops.load(Ordering::SeqCst),
            0,
            "the guard is held by the live health child"
        );

        // Stopping teardown: `retire` aborts the health child; its Drop starts,
        // signals, then blocks. Wait for the Drop to be in flight.
        request_stop(&runtime)?;
        tokio::time::timeout(Duration::from_secs(5), drop_entered.notified()).await?;
        assert_eq!(
            drops.load(Ordering::SeqCst),
            1,
            "the health child's cancellation Drop ran exactly once"
        );

        // The discriminator: with the health child's Drop blocked and NEVER
        // released here, the module task cannot finish IFF `retire` is awaiting the
        // health `handle.await` (the join) — so a bounded join must TIME OUT. The
        // abort-without-join mutation lets `retire` return and the module finishes,
        // so the bounded join completes instead of timing out. `is_finished()` is
        // NOT used here: it samples an instant before the mutant's post-`retire`
        // teardown has finished and would spuriously read "pending".
        let joined = tokio::time::timeout(Duration::from_secs(2), &mut task).await;
        assert!(
            joined.is_err(),
            "the module must not finish while the health child's Drop is blocked: \
             retire must be joining it, not aborting-without-join"
        );

        // Release the blocked Drop; the join then completes and the module returns.
        let _ = release_tx.send(());
        let result = tokio::time::timeout(Duration::from_secs(10), task).await??;
        assert!(
            matches!(result, Ok(())),
            "a clean Stopping teardown returns Ok"
        );
        runtime.finish()?;
        Ok(())
    }

    #[tokio::test]
    async fn an_aborted_module_drops_both_children_via_runtime_drop() -> Result<(), TestError> {
        let refresh_drops = Arc::new(AtomicUsize::new(0));
        let refresh_dropped = Arc::new(Notify::new());
        let refresh_entered = Arc::new(Notify::new());
        let health_drops = Arc::new(AtomicUsize::new(0));
        let health_dropped = Arc::new(Notify::new());
        let health_entered = Arc::new(Notify::new());
        let runtime = runtime()?;
        let (task, mut handle) = spawn_module_with_both_children(
            guarded_pending_refresh(&refresh_drops, &refresh_dropped, &refresh_entered),
            guarded_pending_health(&health_drops, &health_dropped, &health_entered),
            &runtime,
        )?;
        wait_ready(&mut handle).await?;
        tokio::time::timeout(Duration::from_secs(5), refresh_entered.notified()).await?;
        tokio::time::timeout(Duration::from_secs(5), health_entered.notified()).await?;

        // Hard abort: the `run_inner` frame is dropped, so `ModuleRuntime::drop`
        // must abort BOTH children (no async join on this path).
        task.abort();
        let joined = tokio::time::timeout(Duration::from_secs(5), task).await?;
        let Err(join_error) = joined else {
            unreachable!("an aborted module task must not complete normally");
        };
        assert!(
            join_error.is_cancelled(),
            "the aborted module task ended cancelled"
        );

        tokio::time::timeout(Duration::from_secs(5), refresh_dropped.notified()).await?;
        tokio::time::timeout(Duration::from_secs(5), health_dropped.notified()).await?;
        assert_eq!(
            refresh_drops.load(Ordering::SeqCst),
            1,
            "ModuleRuntime::drop aborts the refresh child"
        );
        assert_eq!(
            health_drops.load(Ordering::SeqCst),
            1,
            "ModuleRuntime::drop aborts the health child"
        );
        drop(runtime);
        Ok(())
    }
}
