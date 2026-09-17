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

//! Process-local namespace-router incarnation registry and readiness boundary.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError, Weak};
use std::time::Duration;

use control_config::{ConfigNamespaceSnapshot, ConfigNamespaceSource, NamespaceIncarnation};
use control_plane::{ControlModule, LifecyclePhase, ModuleContext, ModuleError, ModuleFuture};
use control_topology::{MetricOverlayHandle, TopologyModuleHandle};
use tokio::sync::{oneshot, watch};
use tokio::task::JoinSet;

use crate::scheduler::{RouteCommandDispatcher, RouteCommandReceiver, RouteCommandRegistration};
use crate::{
    ResolvedNamespace, RouteError, RouteLedgerEvidence, Router, Selector, UserNamespaceResolver,
};

const MODULE_NAME: &str = "control_router";

struct RegisteredRouter {
    namespace: Arc<str>,
    incarnation: NamespaceIncarnation,
    router: Arc<Router>,
    dispatcher: Arc<RouteCommandDispatcher>,
    stop_worker: watch::Sender<bool>,
}

impl Drop for RegisteredRouter {
    fn drop(&mut self) {
        self.stop_worker.send_replace(true);
    }
}

#[derive(Default)]
struct RegistryState {
    current: BTreeMap<String, Arc<RegisteredRouter>>,
    terminal: bool,
}

/// Payload-free proof that production route selection consumed live health and
/// metric inputs. These counters are diagnostic only and grant no authority.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RouteInputEvidence {
    /// Successful dynamic-input observations made by a production router.
    pub observations: u64,
    /// Backends represented in the exact health-qualified route input set.
    pub health_input_backends: u64,
    /// Healthy backends in that set.
    pub healthy_backends: u64,
    /// CPU series in the current producer-qualified metric snapshot.
    pub cpu_series: u64,
    /// Memory series in the current producer-qualified metric snapshot.
    pub memory_series: u64,
}

#[derive(Default)]
pub(crate) struct RouteInputDiagnostics(Mutex<RouteInputEvidence>);

impl RouteInputDiagnostics {
    pub(crate) fn record(
        &self,
        health_input_backends: usize,
        healthy_backends: usize,
        cpu_series: usize,
        memory_series: usize,
    ) {
        let mut evidence = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        evidence.observations = evidence.observations.saturating_add(1);
        evidence.health_input_backends = usize_to_u64(health_input_backends);
        evidence.healthy_backends = usize_to_u64(healthy_backends);
        evidence.cpu_series = usize_to_u64(cpu_series);
        evidence.memory_series = usize_to_u64(memory_series);
    }

    fn snapshot(&self) -> RouteInputEvidence {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

fn usize_to_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

#[derive(Default)]
struct RouteLedgerDiagnostics(Mutex<Vec<Weak<Router>>>);

impl RouteLedgerDiagnostics {
    fn register(&self, router: &Arc<Router>) {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(Arc::downgrade(router));
    }

    fn snapshot(&self) -> RouteLedgerEvidence {
        // Upgrade and prune while holding only the weak-list lock. Router locks
        // are acquired afterwards, so diagnostics cannot invert registry or
        // route-ledger lock order.
        let routers = {
            let mut registered = self.0.lock().unwrap_or_else(PoisonError::into_inner);
            let mut live = Vec::with_capacity(registered.len());
            registered.retain(|weak| {
                if let Some(router) = weak.upgrade() {
                    live.push(router);
                    true
                } else {
                    false
                }
            });
            live
        };
        let mut evidence = RouteLedgerEvidence::default();
        for router in routers {
            evidence.add(router.ledger_evidence());
        }
        evidence
    }
}

/// A newly admitted connection bound to one exact router incarnation.
///
/// Its selector holds the router (and therefore its retained topology-source
/// lease) for the entire route-session lifetime. Replacing the namespace removes
/// this incarnation from new admission without rebinding or invalidating this
/// already-open selector.
pub struct RouteAdmission {
    entry: Arc<RegisteredRouter>,
    selector: Selector,
    updates: watch::Receiver<u64>,
}

impl RouteAdmission {
    /// The namespace selected for this connection.
    #[must_use]
    pub fn namespace(&self) -> &str {
        &self.entry.namespace
    }

    /// The connection-scoped selector bound to this incarnation.
    #[must_use]
    pub const fn selector(&self) -> &Selector {
        &self.selector
    }

    /// The mutable connection-scoped selector used for retrying initial dials.
    #[must_use]
    pub const fn selector_mut(&mut self) -> &mut Selector {
        &mut self.selector
    }

    /// Subscribes to completed registry reconciliations for this route plane.
    ///
    /// Selection can deliberately reject a candidate when config or topology
    /// changes between capture and the reserve lock.  The session owner uses
    /// this signal to retry that transient boundary without spinning or
    /// treating a current backend as a terminal control failure.
    #[must_use]
    pub fn subscribe_updates(&self) -> watch::Receiver<u64> {
        self.updates.clone()
    }

    /// Whether two admissions belong to the same router incarnation.
    #[must_use]
    pub fn same_router_incarnation(&self, other: &Self) -> bool {
        self.entry.incarnation.same_as(&other.entry.incarnation)
    }

    /// Registers this exact opaque route session with its incarnation's local
    /// production command dispatcher.  The returned registration must live
    /// until session teardown; dropping it unregisters and drains before the
    /// selector closes its router ledger entry.
    ///
    /// # Errors
    ///
    /// Returns `AlreadyActive` if this exact session was registered twice.
    pub fn register_commands(
        &self,
        public_connection_id: u64,
        capacity: usize,
    ) -> Result<(RouteCommandRegistration, RouteCommandReceiver), RouteError> {
        self.entry.dispatcher.register(
            self.selector.route_session(),
            public_connection_id,
            capacity,
        )
    }

    #[cfg(test)]
    pub(crate) fn test_router(&self) -> Arc<Router> {
        Arc::clone(&self.entry.router)
    }
}

/// Readiness and admission handle for the process-local route plane.
#[derive(Clone)]
pub struct RoutePlaneHandle {
    ready: watch::Receiver<bool>,
    updates: watch::Receiver<u64>,
    source: Arc<dyn ConfigNamespaceSource>,
    resolver: UserNamespaceResolver,
    registry: Arc<Mutex<RegistryState>>,
    input_diagnostics: Arc<RouteInputDiagnostics>,
    ledger_diagnostics: Arc<RouteLedgerDiagnostics>,
}

impl RoutePlaneHandle {
    /// Resolves once every namespace in the initial committed configuration has
    /// an exact router and retained topology-source lease in the registry.
    ///
    /// # Errors
    ///
    /// Returns an error if the route module exits before reaching readiness.
    pub async fn wait_ready(&mut self) -> Result<(), watch::error::RecvError> {
        while !*self.ready.borrow_and_update() {
            self.ready.changed().await?;
        }
        Ok(())
    }

    /// Resolves `user`, opens a selector under that exact current router, and
    /// returns a session-long incarnation binding.
    ///
    /// Resolution and registry lookup never fall back to a different
    /// incarnation. A concurrent replacement is caught again by
    /// [`Router::selector`] before the session is admitted.
    ///
    /// # Errors
    ///
    /// Returns the resolver, readiness, namespace-incarnation, source, or
    /// bounded-ledger admission error without opening a session on failure.
    pub fn admit(&self, user: &str) -> Result<RouteAdmission, RouteError> {
        if !*self.ready.borrow() {
            return Err(RouteError::ControlUnavailable);
        }
        let resolved = self.resolver.resolve(user)?;
        if !resolved.is_current(self.source.as_ref()) {
            return Err(RouteError::StaleCandidate);
        }
        let entry = {
            let registry = self.registry.lock().unwrap_or_else(PoisonError::into_inner);
            if registry.terminal {
                return Err(RouteError::ControlUnavailable);
            }
            let entry = registry
                .current
                .get(resolved.namespace())
                .ok_or(RouteError::ControlUnavailable)?;
            if !entry.incarnation.same_as(resolved.incarnation()) {
                return Err(RouteError::ControlUnavailable);
            }
            Arc::clone(entry)
        };
        let selector = entry.router.selector()?;
        let mut updates = self.updates.clone();
        // Only reconciliations after this exact admission can unblock a
        // transient Selector::next boundary.  Do not let an old, unread plane
        // revision manufacture an immediate retry.
        updates.borrow_and_update();
        Ok(RouteAdmission {
            entry,
            selector,
            updates,
        })
    }

    /// Waits across the narrow config-publication/registry-reconcile window.
    /// Semantic rejections (missing namespace, invalid config, capacity) return
    /// immediately; only transient authority drift is retried under `timeout`.
    ///
    /// # Errors
    ///
    /// Returns the semantic admission error, or the last transient error when
    /// the bounded wait expires or the route plane terminates.
    pub async fn admit_within(
        &self,
        user: &str,
        timeout: Duration,
    ) -> Result<RouteAdmission, RouteError> {
        let deadline = tokio::time::Instant::now() + timeout;
        let mut updates = self.updates.clone();
        updates.borrow_and_update();
        loop {
            let error = match self.admit(user) {
                Ok(admission) => return Ok(admission),
                Err(error @ (RouteError::ControlUnavailable | RouteError::StaleCandidate)) => error,
                Err(error) => return Err(error),
            };
            match tokio::time::timeout_at(deadline, updates.changed()).await {
                Ok(Ok(())) => {
                    updates.borrow_and_update();
                }
                Ok(Err(_)) | Err(_) => return Err(error),
            }
        }
    }

    /// Returns the latest nonempty backend version retained by the current
    /// `default` router. The caller supplies the process protocol fallback when
    /// no default namespace/version exists.
    #[must_use]
    pub fn default_server_version(&self) -> Option<String> {
        let entry = {
            let registry = self.registry.lock().unwrap_or_else(PoisonError::into_inner);
            if registry.terminal {
                return None;
            }
            registry.current.get("default").cloned()
        };
        // Never acquire a router lock while holding the registry lock.
        entry
            .map(|entry| entry.router.server_version())
            .filter(|version| !version.is_empty())
    }

    /// Returns payload-free evidence from the latest production selection that
    /// consumed a current dynamic metric snapshot.
    #[must_use]
    pub fn route_input_evidence(&self) -> RouteInputEvidence {
        self.input_diagnostics.snapshot()
    }

    /// Returns payload-free totals across current and retained router
    /// incarnations. Retained old namespaces remain visible until their final
    /// session lease drops, so replacement cannot hide unsettled accounting.
    #[must_use]
    pub fn route_ledger_evidence(&self) -> RouteLedgerEvidence {
        self.ledger_diagnostics.snapshot()
    }

    #[cfg(test)]
    pub(crate) fn current_incarnations(&self) -> usize {
        self.registry
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .current
            .len()
    }
}

/// Control module that owns the current namespace-to-router registry.
pub struct RoutePlane {
    source: Arc<dyn ConfigNamespaceSource>,
    topology: TopologyModuleHandle,
    metrics: Option<MetricOverlayHandle>,
    ready: watch::Sender<bool>,
    updates: watch::Sender<u64>,
    registry: Arc<Mutex<RegistryState>>,
    input_diagnostics: Arc<RouteInputDiagnostics>,
    ledger_diagnostics: Arc<RouteLedgerDiagnostics>,
    workers: JoinSet<Result<(), RouteError>>,
}

impl RoutePlane {
    /// Creates the route-plane module and its readiness/admission handle.
    #[must_use]
    pub fn new(
        source: Arc<dyn ConfigNamespaceSource>,
        topology: TopologyModuleHandle,
        metrics: Option<MetricOverlayHandle>,
    ) -> (Self, RoutePlaneHandle) {
        let (ready, ready_rx) = watch::channel(false);
        let (updates, updates_rx) = watch::channel(0);
        let registry = Arc::new(Mutex::new(RegistryState::default()));
        let input_diagnostics = Arc::new(RouteInputDiagnostics::default());
        let ledger_diagnostics = Arc::new(RouteLedgerDiagnostics::default());
        let resolver = UserNamespaceResolver::new(Arc::clone(&source));
        (
            Self {
                source: Arc::clone(&source),
                topology,
                metrics,
                ready,
                updates,
                registry: Arc::clone(&registry),
                input_diagnostics: Arc::clone(&input_diagnostics),
                ledger_diagnostics: Arc::clone(&ledger_diagnostics),
                workers: JoinSet::new(),
            },
            RoutePlaneHandle {
                ready: ready_rx,
                updates: updates_rx,
                source,
                resolver,
                registry,
                input_diagnostics,
                ledger_diagnostics,
            },
        )
    }

    async fn reconcile(
        &mut self,
        snapshot: &Arc<ConfigNamespaceSnapshot>,
        context: &ModuleContext,
    ) -> Result<(), RouteError> {
        let configured_max_sessions = snapshot
            .effective()
            .serving()
            .map_err(|_| RouteError::InvalidConfig)?
            .max_connections;
        let max_sessions = if configured_max_sessions == 0 {
            usize::MAX
        } else {
            usize::try_from(configured_max_sessions).unwrap_or(usize::MAX)
        };
        let previous = self
            .registry
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .current
            .clone();
        let mut next = BTreeMap::new();
        for namespace in snapshot.namespaces() {
            let incarnation = snapshot
                .namespace_incarnation(&namespace.namespace)
                .ok_or(RouteError::NamespaceMissing)?;
            if let Some(entry) = previous
                .get(&namespace.namespace)
                .filter(|entry| entry.incarnation.same_as(&incarnation))
            {
                entry.router.set_max_sessions(max_sessions);
                next.insert(namespace.namespace.clone(), Arc::clone(entry));
                continue;
            }
            let resolved = ResolvedNamespace::named(Arc::clone(snapshot), &namespace.namespace)?;
            let router = Arc::new(Router::new_resolved(
                Arc::clone(&self.source),
                &self.topology,
                context,
                &resolved,
                max_sessions,
                self.metrics.clone(),
                Arc::clone(&self.input_diagnostics),
            )?);
            self.ledger_diagnostics.register(&router);
            let dispatcher = RouteCommandDispatcher::new(Arc::clone(&router));
            let (stop_worker, stop) = watch::channel(false);
            let (started, started_rx) = oneshot::channel();
            self.workers.spawn(run_route_worker(
                Arc::clone(&router),
                Arc::clone(&dispatcher),
                stop,
                started,
            ));
            started_rx
                .await
                .map_err(|_| RouteError::ControlUnavailable)?;
            next.insert(
                namespace.namespace.clone(),
                Arc::new(RegisteredRouter {
                    namespace: Arc::from(namespace.namespace.as_str()),
                    incarnation,
                    router,
                    dispatcher,
                    stop_worker,
                }),
            );
        }
        if !Arc::ptr_eq(snapshot, &self.source.current()) {
            return Err(RouteError::StaleCandidate);
        }
        let retired = {
            let mut registry = self.registry.lock().unwrap_or_else(PoisonError::into_inner);
            if registry.terminal {
                return Err(RouteError::ControlUnavailable);
            }
            std::mem::replace(&mut registry.current, next)
        };
        // Router/source leases must never be dropped under the registry lock.
        drop(retired);
        self.updates.send_modify(|revision| {
            *revision = revision.saturating_add(1);
        });
        Ok(())
    }

    fn retire_registry(&self) {
        let retired = {
            let mut registry = self.registry.lock().unwrap_or_else(PoisonError::into_inner);
            registry.terminal = true;
            std::mem::take(&mut registry.current)
        };
        self.ready.send_replace(false);
        drop(retired);
        self.updates.send_modify(|revision| {
            *revision = revision.saturating_add(1);
        });
    }

    async fn run_inner(mut self: Box<Self>, context: ModuleContext) -> Result<(), ModuleError> {
        let mut config_updates = self.source.subscribe();
        let mut topology_updates = self.topology.backend_source_updates();
        let mut lifecycle = context.lifecycle();

        loop {
            match self.reconcile(&self.source.current(), &context).await {
                Ok(()) => break,
                Err(RouteError::ControlUnavailable | RouteError::StaleCandidate) => {}
                Err(error) => {
                    self.retire_registry();
                    return Err(module_error(error));
                }
            }
            tokio::select! {
                changed = config_updates.changed() => {
                    if changed.is_err() {
                        self.retire_registry();
                        return Err(module_error(RouteError::ControlUnavailable));
                    }
                }
                changed = topology_updates.changed() => {
                    if changed.is_err() {
                        self.retire_registry();
                        return Err(module_error(RouteError::ControlUnavailable));
                    }
                }
                changed = lifecycle.changed() => {
                    if changed.is_err() || stopping(lifecycle.borrow().phase) {
                        self.retire_registry();
                        while self.workers.join_next().await.is_some() {}
                        return Ok(());
                    }
                }
                worker = self.workers.join_next(), if !self.workers.is_empty() => {
                    match worker {
                        Some(Ok(Ok(()))) | None => {}
                        Some(Ok(Err(error))) => {
                            self.retire_registry();
                            return Err(worker_module_error(error));
                        }
                        Some(Err(error)) => {
                            self.retire_registry();
                            return Err(worker_module_error(error));
                        }
                    }
                }
            }
        }
        self.ready.send_replace(true);

        loop {
            tokio::select! {
                changed = config_updates.changed() => {
                    if changed.is_err() {
                        self.retire_registry();
                        return Err(module_error(RouteError::ControlUnavailable));
                    }
                }
                changed = topology_updates.changed() => {
                    if changed.is_err() {
                        self.retire_registry();
                        return Err(module_error(RouteError::ControlUnavailable));
                    }
                }
                changed = lifecycle.changed() => {
                    if changed.is_err() || stopping(lifecycle.borrow().phase) {
                        self.retire_registry();
                        while self.workers.join_next().await.is_some() {}
                        return Ok(());
                    }
                    continue;
                }
                worker = self.workers.join_next(), if !self.workers.is_empty() => {
                    match worker {
                        Some(Ok(Ok(()))) | None => {}
                        Some(Ok(Err(error))) => {
                            self.retire_registry();
                            return Err(worker_module_error(error));
                        }
                        Some(Err(error)) => {
                            self.retire_registry();
                            return Err(worker_module_error(error));
                        }
                    }
                    continue;
                }
            }
            match self.reconcile(&self.source.current(), &context).await {
                Ok(()) | Err(RouteError::ControlUnavailable | RouteError::StaleCandidate) => {}
                Err(error) => {
                    self.retire_registry();
                    return Err(module_error(error));
                }
            }
        }
    }
}

async fn run_route_worker(
    router: Arc<Router>,
    dispatcher: Arc<RouteCommandDispatcher>,
    mut stop: watch::Receiver<bool>,
    started: oneshot::Sender<()>,
) -> Result<(), RouteError> {
    let (mut config, mut backend, mut lifecycle) = router.migration_updates();
    let mut ticker = tokio::time::interval_at(
        tokio::time::Instant::now() + crate::scheduler::TICK,
        crate::scheduler::TICK,
    );
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    if lifecycle.borrow().phase == LifecyclePhase::Ready {
        refresh_worker_state(&router)?;
    }
    let _ = started.send(());
    loop {
        if worker_stopped(&stop) || stopping(lifecycle.borrow().phase) {
            return Ok(());
        }
        let tick = tokio::select! {
            biased;
            _ = stop.changed() => false,
            changed = lifecycle.changed() => {
                if changed.is_err() { return Ok(()); }
                false
            },
            changed = config.changed() => {
                changed.map_err(|_| RouteError::ControlUnavailable)?;
                false
            },
            changed = backend.changed() => {
                changed.map_err(|_| RouteError::ControlUnavailable)?;
                false
            },
            _ = ticker.tick() => true,
        };
        if worker_stopped(&stop) || stopping(lifecycle.borrow().phase) {
            return Ok(());
        }
        if lifecycle.borrow().phase != LifecyclePhase::Ready {
            continue;
        }
        let candidate = match router.capture_retained() {
            Ok(candidate) => candidate,
            Err(RouteError::StaleCandidate | RouteError::ControlUnavailable) => continue,
            Err(error) => return Err(error),
        };
        let now = tokio::time::Instant::now().into_std();
        let result = if tick {
            router.migration_round(
                &candidate,
                dispatcher.as_ref(),
                true,
                &stop,
                &crate::scheduler::RoundClock::default(),
            )
        } else {
            router.refresh_failover(&candidate, now)
        };
        match result {
            Ok(()) | Err(RouteError::StaleCandidate | RouteError::ControlUnavailable) => (),
            Err(error) => return Err(error),
        }
    }
}

fn worker_stopped(stop: &watch::Receiver<bool>) -> bool {
    stop.has_changed().is_err() || *stop.borrow()
}

fn refresh_worker_state(router: &Router) -> Result<(), RouteError> {
    match router.capture_retained() {
        Ok(candidate) => {
            match router.refresh_failover(&candidate, tokio::time::Instant::now().into_std()) {
                Ok(()) | Err(RouteError::StaleCandidate | RouteError::ControlUnavailable) => Ok(()),
                Err(error) => Err(error),
            }
        }
        Err(RouteError::StaleCandidate | RouteError::ControlUnavailable) => Ok(()),
        Err(error) => Err(error),
    }
}

impl ControlModule for RoutePlane {
    fn name(&self) -> &'static str {
        MODULE_NAME
    }

    fn run(self: Box<Self>, context: ModuleContext) -> ModuleFuture {
        Box::pin(self.run_inner(context))
    }
}

impl Drop for RoutePlane {
    fn drop(&mut self) {
        self.retire_registry();
    }
}

fn stopping(phase: LifecyclePhase) -> bool {
    matches!(
        phase,
        LifecyclePhase::Stopping | LifecyclePhase::Stopped | LifecyclePhase::Failed
    )
}

fn module_error(error: RouteError) -> ModuleError {
    let error_class = match error {
        RouteError::InvalidConfig => "invalid_config",
        RouteError::NamespaceMissing | RouteError::NamespaceReplaced => "namespace_invalid",
        RouteError::ControlUnavailable | RouteError::StaleCandidate => "source_unavailable",
        _ => "router_registry_failed",
    };
    ModuleError {
        module: MODULE_NAME,
        error_class,
    }
}

fn worker_module_error(error: impl std::fmt::Debug) -> ModuleError {
    let _ = error;
    ModuleError {
        module: MODULE_NAME,
        error_class: "migration_worker_failed",
    }
}
