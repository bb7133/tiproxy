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
/// The binary implements this: it reads the TLS PEM material referenced by the
/// [`control_config::TopologyConfig`] paths and produces one
/// [`EtcdClientConfig`] per backend cluster. Keeping it injectable keeps PEM
/// file access in the composition root, out of this crate, and lets tests
/// supply plain endpoints.
pub trait TopologyClientFactory: Send + Sync {
    /// Produces the cluster clients for one topology configuration.
    ///
    /// Implementations should return the clusters ordered by name so a
    /// generation's fan-out is deterministic.
    ///
    /// # Errors
    ///
    /// Returns a human-readable reason when the TLS material or endpoints are
    /// unusable. On the initial generation the module treats this as a fatal
    /// startup error; on a later generation it is a rejection that retains the
    /// last-good registration.
    fn build(
        &self,
        config: &control_config::TopologyConfig,
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
        // Build every generation: this reads the PEM material, so a rotation is
        // observed here rather than swallowed by a path-only comparison.
        let Ok(mut clusters) = self.factory.build(&topology) else {
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
            let child_owner = owner.clone();
            let child_info = info.clone();
            children.shutdowns.push(shutdown_tx);
            children.tasks.spawn(async move {
                Box::pin(crate::registrar::run(
                    child_owner,
                    connector,
                    child_info,
                    receive_timeout,
                    shutdown_rx,
                ))
                .await
            });
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
