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
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use control_config::{ConfigNamespaceSnapshot, ConfigNamespaceSource, NamespaceIncarnation};
use control_plane::{ControlModule, LifecyclePhase, ModuleContext, ModuleError, ModuleFuture};
use control_topology::{MetricOverlayHandle, TopologyModuleHandle};
use tokio::sync::watch;

use crate::{ResolvedNamespace, RouteError, Router, Selector, UserNamespaceResolver};

const MODULE_NAME: &str = "control_router";

struct RegisteredRouter {
    namespace: Arc<str>,
    incarnation: NamespaceIncarnation,
    router: Arc<Router>,
}

#[derive(Default)]
struct RegistryState {
    current: BTreeMap<String, Arc<RegisteredRouter>>,
    terminal: bool,
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

    /// Whether two admissions belong to the same router incarnation.
    #[must_use]
    pub fn same_router_incarnation(&self, other: &Self) -> bool {
        self.entry.incarnation.same_as(&other.entry.incarnation)
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
        Ok(RouteAdmission { entry, selector })
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
        let resolver = UserNamespaceResolver::new(Arc::clone(&source));
        (
            Self {
                source: Arc::clone(&source),
                topology,
                metrics,
                ready,
                updates,
                registry: Arc::clone(&registry),
            },
            RoutePlaneHandle {
                ready: ready_rx,
                updates: updates_rx,
                source,
                resolver,
                registry,
            },
        )
    }

    fn reconcile(
        &self,
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
            )?);
            next.insert(
                namespace.namespace.clone(),
                Arc::new(RegisteredRouter {
                    namespace: Arc::from(namespace.namespace.as_str()),
                    incarnation,
                    router,
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

    async fn run_inner(self: Box<Self>, context: ModuleContext) -> Result<(), ModuleError> {
        let mut config_updates = self.source.subscribe();
        let mut topology_updates = self.topology.backend_source_updates();
        let mut lifecycle = context.lifecycle();

        loop {
            match self.reconcile(&self.source.current(), &context) {
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
                        return Ok(());
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
                        return Ok(());
                    }
                    continue;
                }
            }
            match self.reconcile(&self.source.current(), &context) {
                Ok(()) | Err(RouteError::ControlUnavailable | RouteError::StaleCandidate) => {}
                Err(error) => {
                    self.retire_registry();
                    return Err(module_error(error));
                }
            }
        }
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
