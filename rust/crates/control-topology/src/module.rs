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

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use control_config::{
    BackendClusterConfig, ClientTlsConfig, ConfigNamespaceSnapshot, ConfigNamespaceSource,
    TopologyRuntimeIdentity,
};
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
    /// unusable; the module treats this as a terminal misconfiguration.
    fn build(
        &self,
        config: &control_config::TopologyConfig,
    ) -> Result<Vec<TopologyClusterClient>, String>;
}

/// The self-registration control-plane module.
pub struct TopologyModule {
    source: Arc<dyn ConfigNamespaceSource>,
    factory: Box<dyn TopologyClientFactory>,
    resolver: Arc<dyn AdvertiseEndpointResolver>,
    identity: TopologyRuntimeIdentity,
    ready: watch::Sender<bool>,
}

/// Registration-readiness handle returned alongside a [`TopologyModule`].
///
/// The composition root waits on [`TopologyModuleHandle::wait_ready`] before
/// starting modules that depend on registration having begun. This signals only
/// that the initial generation's registration children are spawned; it does not
/// assert a published topology-discovery snapshot, which a later slice owns.
pub struct TopologyModuleHandle {
    ready: watch::Receiver<bool>,
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
        (
            Self {
                source,
                factory,
                resolver,
                identity,
                ready: ready_tx,
            },
            TopologyModuleHandle { ready: ready_rx },
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
        self.reconfigure(&mut children, &mut active_plan, &initial, &owner)
            .await?;
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
                    if let Err(error) = self
                        .reconfigure(&mut children, &mut active_plan, &snapshot, &owner)
                        .await
                    {
                        stop_children(&mut children).await;
                        return Err(error);
                    }
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
    /// A [`RegistrationPlan`] is derived first; if it equals the active plan the
    /// call is a no-op, so a config generation that does not change registration
    /// (e.g. a namespace or log-level edit) causes no lease flap. Otherwise the
    /// new client set is built and validated *before* the old children are
    /// stopped and joined, so no retired-generation write can race a new one.
    async fn reconfigure(
        &self,
        children: &mut Children,
        active_plan: &mut Option<RegistrationPlan>,
        snapshot: &ConfigNamespaceSnapshot,
        owner: &OwnerToken,
    ) -> Result<(), ModuleError> {
        let topology = snapshot
            .topology()
            .map_err(|_| module_error("topology_config"))?;
        let advertise_host = self
            .resolver
            .resolve(&topology)
            .map_err(|_| module_error("advertise_resolve"))?;
        let info = TopologyInfo::new(
            &advertise_host,
            topology.sql_port,
            topology.status_port,
            &self.identity.version,
            &self.identity.git_hash,
            &self.identity.deploy_path.to_string_lossy(),
            self.identity.start_timestamp,
        );
        let plan = RegistrationPlan {
            info: info.clone(),
            backend_clusters: Arc::clone(&topology.backend_clusters),
            cluster_tls: topology.cluster_tls.clone(),
        };
        if active_plan.as_ref() == Some(&plan) {
            // Nothing that affects registration changed; keep the children.
            return Ok(());
        }

        // Build and validate the new client set before retiring the old one
        // (prospective validation: a bad transport fails here, not mid-swap).
        let clusters = self
            .factory
            .build(&topology)
            .map_err(|_| module_error("topology_client_build"))?;
        let mut names = BTreeSet::new();
        for cluster in &clusters {
            if !names.insert(Arc::clone(&cluster.cluster_name)) {
                return Err(module_error("duplicate_cluster_name"));
            }
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
}

/// The registration-affecting projection of one configuration generation.
///
/// Two generations with an equal plan produce identical registrations, so the
/// module can skip a rebuild (and its lease flap) when only unrelated
/// configuration changed.
#[derive(Clone, PartialEq, Eq)]
struct RegistrationPlan {
    info: TopologyInfo,
    backend_clusters: Arc<[BackendClusterConfig]>,
    cluster_tls: ClientTlsConfig,
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
