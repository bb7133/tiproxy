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

//! Namespace-scoped static backend source (CP-ROUTE 220-3 B2).
//!
//! Go routes a namespace through `FallbackFetcher`: the static instance list
//! (`cfg.Backend.Instances`) is the backend source IFF the APPLIED backend
//! cluster map is empty (`backendcluster.Manager.HasBackendClusters`), and the
//! same real health observer probes those addresses through the empty-cluster
//! default network (system resolver, plain TCP, SQL greeting only). Every
//! namespace owns its own observer; a replaced namespace is a new one.
//!
//! Here the mode is the topology module's applied [`RegistrationPlan`]
//! (`crate::module`) — never the pending config nor an empty/failed discovery —
//! published as a [`ModeEpoch`] whose gate is revoked BEFORE a new plan, commit
//! or epoch is published. One [`StaticBackendProducer`] per namespace
//! incarnation composes the existing routing publisher, health feed/overlay and
//! health loop over the static list; it probes only while the mode is Static
//! (parked otherwise) and is revoked synchronously when its namespace is
//! replaced or removed. Consumers hold an opaque [`BackendSourceHandle`] and
//! capture a [`BackendSourceSnapshot`] that carries the exact mode epoch, the
//! routing source and the exact health round, and re-check all of them (plus the
//! namespace incarnation at the config source) at their side-effect boundary.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, Mutex, PoisonError};

use control_config::{ConfigNamespaceSnapshot, ConfigNamespaceSource, NamespaceIncarnation};
use control_external::{ClusterHttpConfigError, GenerationGate};
use control_plane::OwnerToken;
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::backend_health::{ClusterHealthNetwork, PreparedClusterHealthNetwork};
use crate::discovery_publish::EpochResult;
use crate::health_config::HealthRuntime;
use crate::health_feed::HealthGenerationFeeder;
use crate::health_loop::{
    HEALTH_CONCURRENCY, HealthGeneration, probe_backend_in_generation, run_health_loop,
};
use crate::health_overlay::{HealthOverlayHandle, HealthOverlayPublisher, HealthSnapshot};
use crate::merge::{MergedBackend, MergedTopology};
use crate::model::BackendInfo;
use crate::routing_snapshot::{RoutingSnapshot, RoutingSnapshotHandle, RoutingSnapshotPublisher};

/// Go `StaticFetcher` backends carry no cluster name; the empty name selects the
/// default network in `probe_backend_in_generation`.
const STATIC_CLUSTER_NAME: &str = "";

/// A static source never rotates material, so its routing `client_epoch` is a
/// fixed diagnostic value; it authorizes nothing (the gates and identities do).
const STATIC_CLIENT_EPOCH: u64 = 0;

/// Which backend source a namespace routes through, as decided by the applied
/// cluster runtime (Go `HasBackendClusters`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackendSourceMode {
    /// Backend clusters are applied: the shared dynamic discovery R/H.
    Dynamic,
    /// No backend cluster is applied: each namespace's static instance list.
    Static,
}

/// One published mode incarnation: the mode value plus a gate that is revoked
/// the instant the module decides to leave it.
#[derive(Debug)]
pub struct ModeEpoch {
    mode: BackendSourceMode,
    gate: GenerationGate,
}

impl ModeEpoch {
    /// The mode this epoch was published for.
    #[must_use]
    pub const fn mode(&self) -> BackendSourceMode {
        self.mode
    }

    /// Whether this exact epoch is still the live one.
    #[must_use]
    pub fn is_live(&self) -> bool {
        self.gate.is_live()
    }
}

/// The module-owned mode publisher. Starts revoked (no mode has been applied
/// yet), so every consumer fails closed until the first applied plan.
pub(crate) struct ModePublisher {
    current: watch::Sender<Arc<ModeEpoch>>,
    /// Test-only synchronous hook run right after a new epoch is published
    /// (inside the publication step, before `publish` returns), so a row can
    /// pin the publication boundary without relying on thread scheduling.
    #[cfg(test)]
    on_publish: PublishHook,
}

/// A shared, test-installed observer of epoch publications.
#[cfg(test)]
pub(crate) type PublishHook = Arc<Mutex<Option<Box<dyn Fn(&ModeEpoch) + Send + Sync>>>>;

impl ModePublisher {
    pub(crate) fn new() -> Self {
        let gate = GenerationGate::new();
        gate.revoke();
        Self {
            current: watch::channel(Arc::new(ModeEpoch {
                mode: BackendSourceMode::Dynamic,
                gate,
            }))
            .0,
            #[cfg(test)]
            on_publish: Arc::new(Mutex::new(None)),
        }
    }

    /// Test-only: the shared hook slot a row installs its observer into.
    #[cfg(test)]
    pub(crate) fn publish_hook(&self) -> PublishHook {
        Arc::clone(&self.on_publish)
    }

    pub(crate) fn subscribe(&self) -> watch::Receiver<Arc<ModeEpoch>> {
        self.current.subscribe()
    }

    /// The live mode, or `None` while no applied epoch is published.
    pub(crate) fn applied(&self) -> Option<BackendSourceMode> {
        let epoch = self.current.borrow();
        epoch.is_live().then_some(epoch.mode)
    }

    /// Revokes the current epoch's gate WITHOUT publishing a successor: the
    /// first step of a mode transition, taken before the new plan/commit.
    pub(crate) fn revoke(&self) {
        self.current.borrow().gate.revoke();
    }

    /// Publishes a fresh live epoch for `mode`: the last step of a transition.
    pub(crate) fn publish(&self, mode: BackendSourceMode) {
        self.current.borrow().gate.revoke();
        let epoch = Arc::new(ModeEpoch {
            mode,
            gate: GenerationGate::new(),
        });
        self.current.send_replace(Arc::clone(&epoch));
        #[cfg(test)]
        if let Some(hook) = self
            .on_publish
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
        {
            hook(&epoch);
        }
    }
}

/// The reader-visible handles of one live static producer, keyed by namespace.
struct RegisteredProducer {
    incarnation: NamespaceIncarnation,
    routing: RoutingSnapshotHandle,
    health: HealthOverlayHandle,
}

/// The registry the module handle consults to bind a [`BackendSourceHandle`] to
/// the producer of a namespace's CURRENT incarnation.
#[derive(Default)]
pub(crate) struct StaticRegistry {
    producers: Mutex<HashMap<String, RegisteredProducer>>,
}

impl StaticRegistry {
    fn lookup(
        &self,
        namespace: &str,
        incarnation: &NamespaceIncarnation,
    ) -> Option<(RoutingSnapshotHandle, HealthOverlayHandle)> {
        let producers = self
            .producers
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let entry = producers.get(namespace)?;
        entry
            .incarnation
            .same_as(incarnation)
            .then(|| (entry.routing.clone(), entry.health.clone()))
    }

    fn insert(&self, namespace: String, entry: RegisteredProducer) {
        self.producers
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(namespace, entry);
    }

    fn remove(&self, namespace: &str) {
        self.producers
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(namespace);
    }

    fn clear(&self) {
        self.producers
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
    }
}

/// Go `backendListToMap`: one backend per raw address (map identity, no
/// trimming), `BackendInfo{Addr}` only. Configured order is kept for the first
/// occurrence.
fn static_backends(instances: &[String]) -> Vec<MergedBackend> {
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    let mut backends = Vec::with_capacity(instances.len());
    for address in instances {
        if !seen.insert(address.as_str()) {
            continue;
        }
        backends.push(MergedBackend {
            backend_id: Arc::from(address.as_str()),
            cluster_name: Arc::from(STATIC_CLUSTER_NAME),
            backend: BackendInfo {
                addr: address.clone(),
                keyspace: String::new(),
                ip: String::new(),
                status_port: 0,
                version: String::new(),
                git_hash: String::new(),
                deploy_path: String::new(),
                start_timestamp: 0,
                labels: BTreeMap::new(),
            },
        });
    }
    backends
}

/// The static source and health producer of one namespace incarnation.
///
/// Composes the existing primitives: its own routing publisher (one generation
/// for the incarnation), its own health feed/overlay and one `run_health_loop`
/// over the empty-cluster default network. It probes only while activated.
pub(crate) struct StaticBackendProducer {
    incarnation: NamespaceIncarnation,
    routing: Arc<RoutingSnapshotPublisher>,
    routing_handle: RoutingSnapshotHandle,
    health: HealthOverlayHandle,
    feeder: HealthGenerationFeeder,
    source: Arc<RoutingSnapshot>,
    networks: Option<Arc<HashMap<Arc<str>, ClusterHealthNetwork>>>,
    active: bool,
    task: JoinHandle<()>,
}

impl StaticBackendProducer {
    /// Spawns the producer for `instances` under `incarnation`. `activate`
    /// feeds the first health generation immediately (Static mode); otherwise
    /// the loop stays parked until [`Self::activate`].
    ///
    /// # Errors
    ///
    /// Returns the default network's build failure (an invalid probe timeout).
    pub(crate) fn spawn(
        instances: &[String],
        incarnation: NamespaceIncarnation,
        owner: OwnerToken,
        runtime: &HealthRuntime,
        zone: Arc<dyn ConfigNamespaceSource>,
        activate: bool,
    ) -> Result<Self, ClusterHttpConfigError> {
        let networks = match runtime.probe_policy() {
            Some(policy) => {
                let network = PreparedClusterHealthNetwork::system_default(owner.clone(), policy)?
                    .bind(STATIC_CLIENT_EPOCH);
                let mut map = HashMap::with_capacity(1);
                map.insert(Arc::<str>::from(STATIC_CLUSTER_NAME), network);
                Some(Arc::new(map))
            }
            None => None,
        };
        let (publisher, routing_handle) = RoutingSnapshotPublisher::new();
        let routing = Arc::new(publisher);
        // The first publish of a fresh publisher cannot overflow or be stale.
        let _ = routing.publish(EpochResult {
            client_epoch: STATIC_CLIENT_EPOCH,
            value: MergedTopology {
                backends: static_backends(instances),
            },
        });
        let source = routing_handle
            .current()
            .unwrap_or_else(|| unreachable!("a fresh static publisher publishes its first source"));
        let (feeder, feed) = HealthGenerationFeeder::new();
        let (overlay, health) = HealthOverlayPublisher::new();
        let task = tokio::spawn(run_health_loop(
            feed,
            routing_handle.clone(),
            overlay,
            runtime.policy(),
            owner,
            HEALTH_CONCURRENCY,
            probe_backend_in_generation,
            zone,
        ));
        let mut producer = Self {
            incarnation,
            routing,
            routing_handle,
            health,
            feeder,
            source,
            networks,
            active: false,
            task,
        };
        if activate {
            producer.activate();
        }
        Ok(producer)
    }

    pub(crate) fn incarnation(&self) -> &NamespaceIncarnation {
        &self.incarnation
    }

    fn registered(&self) -> RegisteredProducer {
        RegisteredProducer {
            incarnation: self.incarnation.clone(),
            routing: self.routing_handle.clone(),
            health: self.health.clone(),
        }
    }

    /// Starts real probing: a FRESH health generation (a new `Arc`, so no round
    /// or result of a previous activation can publish into this one).
    pub(crate) fn activate(&mut self) {
        if self.active {
            return;
        }
        self.active = true;
        self.feeder.set(Arc::new(HealthGeneration {
            source: Arc::clone(&self.source),
            networks: self.networks.clone(),
        }));
    }

    /// Stops probing (Dynamic mode): the feed is withdrawn, the loop parks, its
    /// in-flight probes are aborted and its overlay is cleared, fail-closed.
    pub(crate) fn park(&mut self) {
        if !self.active {
            return;
        }
        self.active = false;
        self.feeder.withdraw();
    }

    /// Revokes every reader gate synchronously, then aborts the loop.
    pub(crate) fn revoke(self) {
        self.routing.revoke_and_clear();
        self.feeder.close();
        self.task.abort();
    }
}

/// The run-loop-owned set of static producers plus the registry readers use.
pub(crate) struct StaticProducers {
    producers: HashMap<String, StaticBackendProducer>,
    registry: Arc<StaticRegistry>,
}

impl StaticProducers {
    pub(crate) fn new(registry: Arc<StaticRegistry>) -> Self {
        Self {
            producers: HashMap::new(),
            registry,
        }
    }

    /// Reconciles the producers with the namespaces of `snapshot` (Go
    /// `CommitNamespaces`): keep the same incarnation untouched, replace a changed
    /// one, create a new one, revoke a removed one. Independent of whether the
    /// generation's cluster material is applied.
    pub(crate) fn reconcile(
        &mut self,
        snapshot: &ConfigNamespaceSnapshot,
        owner: &OwnerToken,
        runtime: &HealthRuntime,
        zone: &Arc<dyn ConfigNamespaceSource>,
        mode: Option<BackendSourceMode>,
    ) {
        let activate = mode == Some(BackendSourceMode::Static);
        let mut retain: Vec<&str> = Vec::with_capacity(snapshot.namespaces().len());
        for namespace in snapshot.namespaces() {
            let name = namespace.namespace.as_str();
            retain.push(name);
            let Some(incarnation) = snapshot.namespace_incarnation(name) else {
                continue;
            };
            if self
                .producers
                .get(name)
                .is_some_and(|producer| producer.incarnation().same_as(&incarnation))
            {
                continue;
            }
            if let Some(old) = self.producers.remove(name) {
                self.registry.remove(name);
                old.revoke();
            }
            // The only build failure is a probe timeout the health runtime already
            // validated at construction; a namespace without a producer simply has
            // no static source (fail-closed for readers).
            if let Ok(producer) = StaticBackendProducer::spawn(
                &namespace.backend.instances,
                incarnation,
                owner.clone(),
                runtime,
                Arc::clone(zone),
                activate,
            ) {
                self.registry.insert(name.to_owned(), producer.registered());
                self.producers.insert(name.to_owned(), producer);
            }
        }
        let removed: Vec<String> = self
            .producers
            .keys()
            .filter(|name| !retain.contains(&name.as_str()))
            .cloned()
            .collect();
        for name in removed {
            if let Some(old) = self.producers.remove(&name) {
                self.registry.remove(&name);
                old.revoke();
            }
        }
    }

    /// Activates every producer in Static mode, parks every producer otherwise.
    pub(crate) fn apply_mode(&mut self, mode: Option<BackendSourceMode>) {
        for producer in self.producers.values_mut() {
            if mode == Some(BackendSourceMode::Static) {
                producer.activate();
            } else {
                producer.park();
            }
        }
    }

    /// Revokes every producer (terminal fence).
    pub(crate) fn revoke_all(&mut self) {
        self.registry.clear();
        for (_, producer) in self.producers.drain() {
            producer.revoke();
        }
    }
}

/// An opaque capture of one namespace's backend source: the exact mode epoch,
/// the routing source and the exact health round it was taken under.
///
/// It is a candidate, never authority: a consumer must re-check it with
/// [`BackendSourceHandle::still_current`] at its side-effect boundary.
#[derive(Clone)]
pub struct BackendSourceSnapshot {
    bundle: Arc<()>,
    epoch: Arc<ModeEpoch>,
    routing: Arc<RoutingSnapshot>,
    health: Arc<HealthSnapshot>,
}

impl BackendSourceSnapshot {
    /// The mode this snapshot was captured under.
    #[must_use]
    pub fn mode(&self) -> BackendSourceMode {
        self.epoch.mode
    }

    /// The routing source of the selected side.
    #[must_use]
    pub const fn routing(&self) -> &Arc<RoutingSnapshot> {
        &self.routing
    }

    /// The exact health round published for [`Self::routing`].
    #[must_use]
    pub const fn health(&self) -> &Arc<HealthSnapshot> {
        &self.health
    }
}

/// The capability a consumer holds for one namespace's backend source.
///
/// Private fields only; not serializable. Bound to the namespace incarnation
/// current when it was created and to the producer registered for it.
#[derive(Clone)]
pub struct BackendSourceHandle {
    bundle: Arc<()>,
    namespace: Arc<str>,
    origin: Arc<ConfigNamespaceSnapshot>,
    config: Arc<dyn ConfigNamespaceSource>,
    mode: watch::Receiver<Arc<ModeEpoch>>,
    dynamic: (RoutingSnapshotHandle, HealthOverlayHandle),
    stationary: (RoutingSnapshotHandle, HealthOverlayHandle),
}

impl BackendSourceHandle {
    pub(crate) fn bind(
        namespace: &str,
        config: Arc<dyn ConfigNamespaceSource>,
        mode: watch::Receiver<Arc<ModeEpoch>>,
        dynamic: (RoutingSnapshotHandle, HealthOverlayHandle),
        registry: &StaticRegistry,
    ) -> Option<Self> {
        let origin = config.current();
        let incarnation = origin.namespace_incarnation(namespace)?;
        let stationary = registry.lookup(namespace, &incarnation)?;
        Some(Self {
            bundle: Arc::new(()),
            namespace: Arc::from(namespace),
            origin,
            config,
            mode,
            dynamic,
            stationary,
        })
    }

    /// The namespace this handle is bound to.
    #[must_use]
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    /// Test-only: the bound static producer's routing/overlay handles, so a row
    /// can assert the publication boundary (a parked static H is withdrawn
    /// before the Dynamic epoch is visible).
    #[cfg(test)]
    pub(crate) const fn static_side(&self) -> &(RoutingSnapshotHandle, HealthOverlayHandle) {
        &self.stationary
    }

    /// Whether the bound namespace incarnation is still the config source's
    /// current one. Checked at the SOURCE on every call, so a namespace removed
    /// or replaced in the committed config fails closed at once, in every mode,
    /// regardless of the topology run loop's progress.
    fn namespace_current(&self) -> bool {
        self.origin
            .same_namespace_incarnation(&self.config.current(), &self.namespace)
    }

    const fn side(&self, epoch: &ModeEpoch) -> &(RoutingSnapshotHandle, HealthOverlayHandle) {
        match epoch.mode {
            BackendSourceMode::Dynamic => &self.dynamic,
            BackendSourceMode::Static => &self.stationary,
        }
    }

    /// Captures the current source under the current mode epoch, or `None`
    /// when the namespace, the epoch, the routing source or an exact health
    /// round for it is unavailable. The capture is re-checked with
    /// [`Self::still_current`] before it is returned.
    #[must_use]
    pub fn current(&self) -> Option<BackendSourceSnapshot> {
        if !self.namespace_current() {
            return None;
        }
        let epoch = Arc::clone(&self.mode.borrow());
        if !epoch.is_live() {
            return None;
        }
        let (routing, health) = self.side(&epoch);
        let r = routing.current()?;
        let h = health.current_for(&r)?;
        let snapshot = BackendSourceSnapshot {
            bundle: Arc::clone(&self.bundle),
            epoch,
            routing: r,
            health: h,
        };
        self.still_current(&snapshot).then_some(snapshot)
    }

    /// Whether `snapshot` is still authoritative through THIS handle: same
    /// handle, namespace incarnation still current at the source, the very same
    /// mode epoch still live and current (a mode value equal to the current one
    /// is never enough), and the selected side's exact routing/health pair still
    /// published and gated.
    #[must_use]
    pub fn still_current(&self, snapshot: &BackendSourceSnapshot) -> bool {
        if !Arc::ptr_eq(&snapshot.bundle, &self.bundle) || !self.namespace_current() {
            return false;
        }
        let current = self.mode.borrow();
        if !Arc::ptr_eq(&snapshot.epoch, &current) || !snapshot.epoch.is_live() {
            return false;
        }
        let (routing, health) = self.side(&snapshot.epoch);
        health.still_current_for(&snapshot.health, &snapshot.routing, routing)
    }
}

#[cfg(test)]
#[path = "static_source_tests.rs"]
mod tests;
