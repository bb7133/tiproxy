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

//! Independent config and namespace backend-source authority at reserve.

use std::sync::Arc;

use control_config::{
    ConfigNamespaceSnapshot, ConfigNamespaceSource, RoutingBalancePolicy, RoutingConfig,
    RoutingNamespace,
};
use control_plane::{LifecyclePhase, LifecycleSnapshot, ModuleContext, OwnerToken};
use control_topology::{
    BackendSourceHandle, BackendSourceSnapshot, HealthSnapshot, RoutingSnapshot,
    TopologyModuleHandle,
};
use tokio::sync::watch;

use crate::ledger::LedgerError;

/// Routing capability intentionally unavailable before the final selector head.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unsupported {
    /// Resource metrics/factors are not yet composed into this selector.
    ResourcePolicy,
    /// Locality-first factors are not yet composed into this selector.
    LocationPolicy,
}

/// Typed, payload-free route failure before an assignment is reserved.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouteError {
    /// The current accepted configuration cannot be projected.
    InvalidConfig,
    /// A simulation already has an owned worker running.
    WorkerRunning,
    /// The named namespace does not exist in the current source.
    NamespaceMissing,
    /// This namespace router has been replaced and cannot admit new work.
    NamespaceReplaced,
    /// The process owner, lifecycle, or a topology/health source is unavailable.
    ControlUnavailable,
    /// A retained candidate lost authority or belongs to a different router.
    StaleCandidate,
    /// No eligible healthy backend remains in the client's group.
    NoBackend,
    /// Multiple clusters claim the same listener port.
    PortConflict,
    /// A temporary unsupported capability is required, with no silent fallback.
    Unsupported(Unsupported),
    /// The caller's session was not minted by this router or has closed.
    InvalidSession,
    /// An initial assignment is already active on this session.
    AlreadyActive,
    /// A bounded live-session table is full.
    Capacity,
    /// A never-reused identity or connection counter cannot advance.
    Exhausted,
    /// Redirects require an established physical session.
    NotActive,
    /// This session already has one accepted redirect awaiting a result.
    RedirectPending,
    /// A failed or rejected redirect is inside Go's three-second cooldown.
    CoolingDown,
    /// This session already has an admitted close awaiting observation.
    ForceClosing,
    /// Redirect source and target are the same retained owner.
    SameBackend,
    /// Migration may never cross keyspace scopes, including empty/nonempty.
    CrossKeyspace,
}

impl From<LedgerError> for RouteError {
    fn from(error: LedgerError) -> Self {
        match error {
            LedgerError::ForeignSession
            | LedgerError::ClosedSession
            | LedgerError::ForeignAccount => Self::InvalidSession,
            LedgerError::AlreadyActive => Self::AlreadyActive,
            LedgerError::Exhausted => Self::Exhausted,
            LedgerError::Capacity => Self::Capacity,
            LedgerError::NotActive => Self::NotActive,
            LedgerError::RedirectPending => Self::RedirectPending,
            LedgerError::CoolingDown => Self::CoolingDown,
            LedgerError::ForceClosing => Self::ForceClosing,
            LedgerError::SameAccount => Self::SameBackend,
            LedgerError::CrossKeyspace => Self::CrossKeyspace,
        }
    }
}

pub(crate) enum MetricInputs {
    // This variant is minted only from the actual Static backend snapshot.
    StaticEmpty,
    Dynamic(Option<Arc<control_topology::MetricSnapshot>>),
}
impl Clone for MetricInputs {
    fn clone(&self) -> Self {
        match self {
            Self::StaticEmpty => Self::StaticEmpty,
            Self::Dynamic(snapshot) => Self::Dynamic(snapshot.clone()),
        }
    }
}

/// An opaque candidate, valid only when rechecked by its producing router.
///
/// Retaining this value never retains routing authority. Config, routing and
/// health remain separate immutable sources. Their applied source mode and
/// namespace authority are also checked at reserve.
#[derive(Clone)]
pub struct Candidate {
    pub(crate) bundle: Arc<()>,
    pub(crate) config: Arc<ConfigNamespaceSnapshot>,
    pub(crate) backend: BackendSourceSnapshot,
    pub(crate) routing: Arc<RoutingSnapshot>,
    pub(crate) health: Arc<HealthSnapshot>,
    pub(crate) policy: RoutingConfig,
    pub(crate) metrics: MetricInputs,
}

pub(crate) struct Sources {
    identity: Arc<()>,
    source: Arc<dyn ConfigNamespaceSource>,
    backend: BackendSourceHandle,
    owner: OwnerToken,
    lifecycle: watch::Receiver<LifecycleSnapshot>,
    namespace: RoutingNamespace,
    namespace_origin: Arc<ConfigNamespaceSnapshot>,
}

impl Sources {
    pub(crate) fn new(
        source: Arc<dyn ConfigNamespaceSource>,
        topology: &TopologyModuleHandle,
        context: &ModuleContext,
        namespace: &str,
    ) -> Result<Self, RouteError> {
        let current = source.current();
        let namespace = current
            .namespaces()
            .iter()
            .find(|ns| ns.namespace == namespace)
            .ok_or(RouteError::NamespaceMissing)?
            .routing();
        Ok(Self {
            identity: Arc::new(()),
            source,
            backend: topology
                .backend_source(namespace.name.as_ref())
                .ok_or(RouteError::ControlUnavailable)?,
            owner: context.owner().clone(),
            lifecycle: context.lifecycle(),
            namespace,
            namespace_origin: current,
        })
    }

    pub(crate) fn updates(
        &self,
    ) -> (
        watch::Receiver<Arc<ConfigNamespaceSnapshot>>,
        BackendSourceHandle,
        watch::Receiver<LifecycleSnapshot>,
    ) {
        (
            self.source.subscribe(),
            self.backend.clone(),
            self.lifecycle.clone(),
        )
    }

    pub(crate) fn admit(&self) -> Result<Arc<ConfigNamespaceSnapshot>, RouteError> {
        self.live()?;
        let config = self.source.current();
        self.namespace_current(&config)?;
        Ok(config)
    }

    fn live(&self) -> Result<(), RouteError> {
        if self.owner.is_current()
            && self.lifecycle.has_changed().is_ok()
            && self.lifecycle.borrow().phase == LifecyclePhase::Ready
        {
            Ok(())
        } else {
            Err(RouteError::ControlUnavailable)
        }
    }

    fn namespace_current(&self, config: &ConfigNamespaceSnapshot) -> Result<(), RouteError> {
        let namespace = config
            .namespaces()
            .iter()
            .find(|ns| ns.namespace == self.namespace.name.as_ref())
            .ok_or(RouteError::NamespaceMissing)?;
        if namespace.routing() != self.namespace
            || !self
                .namespace_origin
                .same_namespace_incarnation(config, self.namespace.name.as_ref())
        {
            return Err(RouteError::NamespaceReplaced);
        }
        Ok(())
    }

    pub(crate) fn capture(&self) -> Result<Candidate, RouteError> {
        self.capture_inputs(false)
    }

    pub(crate) fn capture_composed(
        &self,
        overlay: Option<&control_topology::MetricOverlayHandle>,
    ) -> Result<Candidate, RouteError> {
        let mut candidate = self.capture_inputs(true)?;
        candidate.metrics =
            if candidate.backend.mode() == control_topology::BackendSourceMode::Static {
                MetricInputs::StaticEmpty
            } else {
                MetricInputs::Dynamic(overlay.and_then(|overlay| {
                    overlay
                        .routing_current_for(
                            &candidate.routing,
                            &candidate.config.resource_incarnation(),
                        )
                        .map(Arc::new)
                }))
            };
        self.validate(&candidate)?;
        Ok(candidate)
    }

    pub(crate) fn capture_factors(&self) -> Result<Candidate, RouteError> {
        self.capture_inputs(true)
    }

    fn capture_inputs(&self, factors_only: bool) -> Result<Candidate, RouteError> {
        let config = self.admit()?;
        let policy = config
            .effective()
            .routing()
            .map_err(|_| RouteError::InvalidConfig)?;
        if !factors_only {
            supported(&policy)?;
        }
        let backend = self
            .backend
            .current()
            .ok_or(RouteError::ControlUnavailable)?;
        let candidate = Candidate {
            bundle: Arc::clone(&self.identity),
            config,
            routing: Arc::clone(backend.routing()),
            health: Arc::clone(backend.health()),
            backend,
            policy,
            metrics: MetricInputs::Dynamic(None),
        };
        self.validate(&candidate)?;
        Ok(candidate)
    }

    pub(crate) fn validate(&self, candidate: &Candidate) -> Result<(), RouteError> {
        self.live()?;
        // C is independent of topology's accepted material. Comparing C's
        // generation/epoch to R would wrongly block new policy on old backends.
        if !Arc::ptr_eq(&candidate.bundle, &self.identity)
            || !Arc::ptr_eq(&candidate.config, &self.source.current())
            || !self.backend.still_current(&candidate.backend)
        {
            return Err(RouteError::StaleCandidate);
        }
        self.namespace_current(&candidate.config)
    }

    pub(crate) fn current_config(&self, config: &Arc<ConfigNamespaceSnapshot>) -> bool {
        self.live().is_ok()
            && Arc::ptr_eq(config, &self.source.current())
            && self.namespace_current(config).is_ok()
    }
}

fn supported(policy: &RoutingConfig) -> Result<(), RouteError> {
    match policy.balance_policy {
        RoutingBalancePolicy::Connection => (),
        RoutingBalancePolicy::Resource => {
            return Err(RouteError::Unsupported(Unsupported::ResourcePolicy));
        }
        RoutingBalancePolicy::Location => {
            return Err(RouteError::Unsupported(Unsupported::LocationPolicy));
        }
    }
    Ok(())
}
