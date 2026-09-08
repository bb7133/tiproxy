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

//! Namespace-scoped synchronous selection and stable backend ownership.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use control_config::{ConfigNamespaceSource, RoutingConfig, RoutingRule, RoutingSelectionPolicy};
use control_plane::ModuleContext;
use control_routing::group::{ClientInfo, GroupMatcher, MatchType, PortRoutes};
use control_routing::{RouteAssignment, RouteCode};
use control_topology::{HealthSnapshot, MergedBackend, RoutingSnapshot, TopologyModuleHandle};

use crate::authority::{Candidate, RouteError, Sources};
use crate::ledger::{
    AccountIdentity, Accounting, Ledger, Redirect, Reservation, Session, Settlement,
};
use crate::policy::{RoutingIdentity, label_matches};

struct Backend {
    source: MergedBackend,
    routing_identity: RoutingIdentity,
    account: Arc<AccountIdentity>,
    healthy: bool,
    group: Option<u64>,
}

#[derive(Clone, Default)]
struct GroupFactors {
    incarnation: Option<control_config::ResourceIncarnation>,
    core: crate::factors::State,
    lineages: BTreeMap<String, control_topology::MetricCacheLineage>,
}

struct State {
    ledger: Ledger,
    factors: BTreeMap<u64, GroupFactors>,
    backends: BTreeMap<Arc<str>, Backend>,
    groups: BTreeMap<u64, GroupMatcher>,
    ports: PortRoutes<u64>,
    next_group: u64,
    observed: Option<(Arc<RoutingSnapshot>, Arc<HealthSnapshot>)>,
}

#[cfg(test)]
type MetricUseBarrier = (
    std::sync::mpsc::Sender<usize>,
    std::sync::mpsc::Receiver<()>,
);

#[cfg(test)]
type RedirectOfferBarrier = (std::sync::mpsc::Sender<()>, std::sync::mpsc::Receiver<()>);

/// One namespace router incarnation, with a single lock for selection/accounting.
///
/// This staged API is intentionally not wired to the production dataplane.
/// `new` retains the staged Connection-only API; `new_with_factors` explicitly
/// composes Resource/Location inputs with the same reservation ledger.
/// Replacing/removing this router's namespace rejects new work; already minted
/// reservations can still settle their original accounting owner.
pub struct Router {
    factors_enabled: bool,
    metrics: Option<control_topology::MetricOverlayHandle>,
    sources: Sources,
    state: Mutex<State>,
    #[cfg(test)]
    next_lock: Mutex<Option<std::sync::mpsc::Sender<()>>>,
    #[cfg(test)]
    next_metric_use: Mutex<Option<MetricUseBarrier>>,
    #[cfg(test)]
    next_redirect_offer: Mutex<Option<RedirectOfferBarrier>>,
}

impl Router {
    /// Builds one router from handles supplied by the same composition owner.
    /// `max_sessions` bounds live session state, including sessions awaiting a
    /// backend. A removed namespace requires a new router incarnation.
    ///
    /// # Errors
    /// Returns [`RouteError::NamespaceMissing`] if the namespace is absent, or
    /// [`RouteError::ControlUnavailable`] until its backend producer is registered.
    pub fn new(
        source: Arc<dyn ConfigNamespaceSource>,
        topology: &TopologyModuleHandle,
        context: &ModuleContext,
        namespace: &str,
        max_sessions: usize,
    ) -> Result<Self, RouteError> {
        Ok(Self {
            factors_enabled: false,
            metrics: None,
            sources: Sources::new(source, topology, context, namespace)?,
            #[cfg(test)]
            next_lock: Mutex::new(None),
            #[cfg(test)]
            next_metric_use: Mutex::new(None),
            #[cfg(test)]
            next_redirect_offer: Mutex::new(None),
            state: Mutex::new(State {
                ledger: Ledger::new(max_sessions),
                factors: BTreeMap::new(),
                backends: BTreeMap::new(),
                groups: BTreeMap::new(),
                ports: PortRoutes::default(),
                next_group: 1,
                observed: None,
            }),
        })
    }

    /// Explicitly enables Resource/Location selection using the existing
    /// ledger. Dynamic metrics are optional inputs from a routing-bound
    /// collector; static empty inputs come from the actual backend source.
    /// This constructor does not enable the production dataplane composition.
    /// # Errors
    /// Returns the same namespace/backend registration errors as `new`.
    pub fn new_with_factors(
        source: Arc<dyn ConfigNamespaceSource>,
        topology: &TopologyModuleHandle,
        context: &ModuleContext,
        namespace: &str,
        max_sessions: usize,
        metrics: Option<control_topology::MetricOverlayHandle>,
    ) -> Result<Self, RouteError> {
        let mut router = Self::new(source, topology, context, namespace, max_sessions)?;
        router.factors_enabled = true;
        router.metrics = metrics;
        Ok(router)
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        // Pin the actual lock attempt, so a regression moving validation ahead
        // of the lock cannot pass a barrier test by arriving after publication.
        #[cfg(test)]
        if let Some(signal) = self
            .next_lock
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
        {
            let _ = signal.send(());
        }
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    #[cfg(test)]
    pub(crate) fn hold_lock_for_test(&self) -> impl Drop + '_ {
        self.lock()
    }

    #[cfg(test)]
    pub(crate) fn observe_next_lock_for_test(&self) -> std::sync::mpsc::Receiver<()> {
        let (signal, attempted) = std::sync::mpsc::channel();
        *self
            .next_lock
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(signal);
        attempted
    }

    #[cfg(test)]
    pub(crate) fn hold_next_redirect_offer_for_test(
        &self,
    ) -> (std::sync::mpsc::Receiver<()>, std::sync::mpsc::Sender<()>) {
        let (signal, offered) = std::sync::mpsc::channel();
        let (release, wait) = std::sync::mpsc::channel();
        *self
            .next_redirect_offer
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some((signal, wait));
        (offered, release)
    }

    #[cfg(test)]
    pub(crate) fn observe_next_metric_use_for_test(
        &self,
    ) -> (
        std::sync::mpsc::Receiver<usize>,
        std::sync::mpsc::Sender<()>,
    ) {
        let (signal, observed) = std::sync::mpsc::channel();
        let (release, wait) = std::sync::mpsc::channel();
        *self
            .next_metric_use
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some((signal, wait));
        (observed, release)
    }

    /// Admits a new session under the current namespace incarnation.
    ///
    /// # Errors
    /// Rejects retired ownership, missing/replaced namespaces, table capacity,
    /// or identity exhaustion. Backend availability is checked at reserve.
    pub fn open(&self) -> Result<Session, RouteError> {
        let config = self.sources.admit()?;
        let mut state = self.lock();
        if !self.sources.current_config(&config) {
            return Err(RouteError::StaleCandidate);
        }
        state.ledger.open().map_err(Into::into)
    }

    /// Captures candidate C/R/H inputs without retaining authority.
    ///
    /// # Errors
    /// Returns a typed unsupported policy, absent source, lifecycle or namespace
    /// error. Every candidate is checked again after acquiring the reserve lock.
    pub fn capture(&self) -> Result<Candidate, RouteError> {
        if self.factors_enabled {
            self.sources.capture_composed(self.metrics.as_ref())
        } else {
            self.sources.capture()
        }
    }

    /// Selects and reserves using a previously captured candidate.
    ///
    /// The wall-clock ticket follows Go's `UnixMicro` modulo rule; it is not a
    /// cryptographic random source. Exclusions refer to opaque backend IDs. This
    /// is one selection attempt; [`crate::Selector`] owns a retry cycle.
    ///
    /// # Errors
    /// Stale/foreign sources, retired admission, unsupported policy, invalid
    /// sessions, port conflicts and an empty candidate group reserve nothing.
    pub fn reserve(
        &self,
        session: &Session,
        candidate: &Candidate,
        client: ClientInfo<'_>,
        listener_port: &str,
        excluded: &[&str],
    ) -> Result<Reservation, RouteError> {
        let ticket = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| RouteError::ControlUnavailable)?
            .as_micros();
        self.reserve_with_ticket(session, candidate, client, listener_port, excluded, ticket)
    }

    pub(crate) fn reserve_with_ticket(
        &self,
        session: &Session,
        candidate: &Candidate,
        client: ClientInfo<'_>,
        listener_port: &str,
        excluded: &[&str],
        ticket: u128,
    ) -> Result<Reservation, RouteError> {
        let mut state = self.lock();
        self.sources.validate(candidate)?;
        if let Some(pending) = state.ledger.pending(session)? {
            return Ok(pending);
        }
        state.refresh(candidate)?;
        let group = state.factor_group(candidate, client, listener_port)?;
        if self.factors_enabled && candidate.config.resource_incarnation().enabled() {
            return self.reserve_factors(&mut state, session, candidate, group, excluded, ticket);
        }
        let mut choices = state.routeable(group, &candidate.policy, excluded);
        // Go leaves exact ordering of ties unspecified. This owner chooses a
        // stable opaque-ID order; the score clamp and ticket weights are exact.
        choices.sort_by_key(|(_, score)| (*score).min(u64::from(u16::MAX)));
        let index = choose(
            &choices.iter().map(|(_, score)| *score).collect::<Vec<_>>(),
            &candidate.policy,
            ticket,
        )
        .ok_or(RouteError::NoBackend)?;
        let backend = choices[index].0;
        let identity = Arc::clone(&backend.account);
        let local = candidate.health.get(&backend.source.backend_id).local;
        let assignment = assignment(&backend.source, local);
        self.sources.validate(candidate)?;
        state
            .ledger
            .reserve(session, &identity, assignment)
            .map_err(Into::into)
    }

    #[allow(clippy::too_many_arguments)]
    fn reserve_factors(
        &self,
        state: &mut State,
        session: &Session,
        candidate: &Candidate,
        group: u64,
        excluded: &[&str],
        ticket: u128,
    ) -> Result<Reservation, RouteError> {
        let metrics = match &candidate.metrics {
            crate::authority::MetricInputs::StaticEmpty => None,
            crate::authority::MetricInputs::Dynamic(snapshot) => snapshot.as_deref(),
        };
        let now = now_nanos()?;
        let mut select = |metrics: Option<&control_topology::MetricSnapshot>,
                          queries: &crate::factors::Queries| {
            self.sources.validate(candidate)?;
            let inputs = state.resource_inputs(group, candidate, excluded);
            let mut factors = state.prepare_factors(
                group,
                metrics,
                &inputs,
                &candidate.config.resource_incarnation(),
            );
            let report = factors
                .core
                .evaluate(&inputs, &candidate.policy, queries, now);
            let id = report
                .choice(candidate.policy.selection_policy, ticket)
                .ok_or(RouteError::NoBackend)?;
            let backend = state.backends.get(id).ok_or(RouteError::NoBackend)?;
            let identity = Arc::clone(&backend.account);
            let assignment = assignment(&backend.source, candidate.health.get(id).local);
            // Metrics qualify input data only. C/R/H and the ledger authorize
            // the effect, under this same lock and (when present) metric fence.
            self.sources.validate(candidate)?;
            let reserved = state.ledger.reserve(session, &identity, assignment)?;
            state.factors.insert(group, factors);
            Ok(reserved)
        };
        // Keep the test barrier after reading data and before its final fence.
        #[allow(clippy::collapsible_if)]
        if let Some(metrics) =
            metrics.filter(|metrics| Arc::ptr_eq(&candidate.routing, metrics.source().routing()))
            && let Ok(queries) = read_queries(metrics)
        {
            #[cfg(test)]
            if let Some((signal, wait)) = self
                .next_metric_use
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take()
            {
                let _ = signal.send(queries.len());
                let _ = wait.recv();
            }
            if let Some(result) = metrics.with_current(|| select(Some(metrics), &queries)) {
                return result;
            }
        }
        // A material change or a delayed collector must never create an
        // availability window. Discard stale values AND their cache lineage.
        select(None, &crate::factors::Queries::new())
    }

    /// Evaluates staged Resource/Location factors using this router's actual
    /// ledger counts and a producer-issued metric snapshot. Returns diagnostic
    /// data only; this method never reserves connections.
    ///
    /// # Errors
    /// Rejects mismatched/stale C/R/H/metric authority, missing groups, and
    /// bounded metric merge errors. No counts are reserved by this operation.
    pub fn factor_report(
        &self,
        metrics: &control_topology::MetricSnapshot,
        client: ClientInfo<'_>,
        listener_port: &str,
    ) -> Result<crate::FactorReport, RouteError> {
        let candidate = self.sources.capture_factors()?;
        if !Arc::ptr_eq(&candidate.routing, metrics.source().routing()) {
            return Err(RouteError::StaleCandidate);
        }
        let mut queries = crate::factors::Queries::new();
        for spec in control_topology::metrics::query_catalog() {
            if let Some(query) = metrics
                .query_result(spec.id)
                .map_err(|_| RouteError::ControlUnavailable)?
            {
                queries.insert(spec.id, query);
            }
        }
        let now = i64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| RouteError::ControlUnavailable)?
                .as_nanos(),
        )
        .map_err(|_| RouteError::ControlUnavailable)?;
        let mut state = self.lock();
        self.sources.validate(&candidate)?;
        metrics
            .with_current(|| {
                self.sources.validate(&candidate)?;
                state.refresh(&candidate)?;
                let group = state.factor_group(&candidate, client, listener_port)?;
                let inputs = state.factor_inputs(group, &candidate);
                let mut factors = state.prepare_factors(
                    group,
                    Some(metrics),
                    &inputs,
                    &candidate.config.resource_incarnation(),
                );
                let report = factors
                    .core
                    .evaluate(&inputs, &candidate.policy, &queries, now);
                self.sources.validate(&candidate)?;
                state.factors.insert(group, factors);
                Ok(report)
            })
            .ok_or(RouteError::StaleCandidate)?
    }

    pub(crate) fn prepare_redirect(
        &self,
        session: &Session,
        candidate: &Candidate,
        target_id: &str,
    ) -> Result<crate::PreparedRedirect, RouteError> {
        let mut state = self.lock();
        self.sources.validate(candidate)?;
        state.refresh(candidate)?;
        let source = Arc::clone(state.ledger.active_owner(session)?);
        let target = state.redirect_target(&source, candidate, target_id)?;
        self.sources.validate(candidate)?;
        Ok(crate::PreparedRedirect {
            session: session.clone(),
            candidate: candidate.clone(),
            source,
            target: Arc::clone(&target.account),
            target_id: Arc::clone(&target.source.backend_id),
        })
    }

    pub(crate) fn offer_redirect(
        &self,
        prepared: &crate::PreparedRedirect,
        sender: &std::sync::mpsc::SyncSender<Redirect>,
        now: Instant,
    ) -> Result<bool, RouteError> {
        let mut state = self.lock();
        self.sources.validate(&prepared.candidate)?;
        if !Arc::ptr_eq(
            state.ledger.active_owner(&prepared.session)?,
            &prepared.source,
        ) {
            return Err(RouteError::StaleCandidate);
        }
        state.refresh(&prepared.candidate)?;
        let target =
            state.redirect_target(&prepared.source, &prepared.candidate, &prepared.target_id)?;
        if !Arc::ptr_eq(&target.account, &prepared.target) {
            return Err(RouteError::StaleCandidate);
        }
        let assignment = assignment(
            &target.source,
            prepared.candidate.health.get(&prepared.target_id).local,
        );
        let redirect =
            state
                .ledger
                .prepare_redirect(&prepared.session, &prepared.target, assignment, now)?;
        self.sources.validate(&prepared.candidate)?;
        // No callback, blocking send or fallible state transition after this
        // offer. An immediate terminal has to acquire this same router lock.
        let accepted = sender.try_send(redirect.clone()).is_ok();
        #[cfg(test)]
        if let Some((signal, wait)) = self
            .next_redirect_offer
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
        {
            let _ = signal.send(());
            let _ = wait.recv_timeout(std::time::Duration::from_secs(5));
        }
        state.ledger.admit_redirect(redirect, accepted, now);
        Ok(accepted)
    }

    pub(crate) fn finish_redirect(
        &self,
        redirect: &Redirect,
        success: bool,
        now: Instant,
    ) -> Settlement {
        self.lock().ledger.finish_redirect(redirect, success, now)
    }

    /// Settles an exact pending attempt, even after its C/R/H inputs retire.
    /// Duplicate, foreign and late results have no effect.
    pub fn finish(&self, reservation: &Reservation, connected: bool) -> Settlement {
        self.lock().ledger.finish(reservation, connected)
    }

    /// Closes the exact session incarnation and returns any remaining accounting.
    /// Closing twice or closing a foreign session has no effect.
    pub fn close(&self, session: &Session) -> Settlement {
        self.lock().ledger.close(session)
    }

    /// Observes accounting for the currently retained owner of an opaque ID.
    /// This is diagnostic only; a backend ID never authorizes settlement.
    #[must_use]
    pub fn accounting(&self, backend_id: &str) -> Option<Accounting> {
        let state = self.lock();
        state
            .backends
            .get(backend_id)
            .and_then(|backend| state.ledger.counts(&backend.account))
    }
}

fn now_nanos() -> Result<i64, RouteError> {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| RouteError::ControlUnavailable)?
            .as_nanos(),
    )
    .map_err(|_| RouteError::ControlUnavailable)
}

fn read_queries(
    metrics: &control_topology::MetricSnapshot,
) -> Result<crate::factors::Queries, RouteError> {
    let mut queries = crate::factors::Queries::new();
    for spec in control_topology::metrics::query_catalog() {
        if let Some(query) = metrics
            .query_result(spec.id)
            .map_err(|_| RouteError::ControlUnavailable)?
        {
            queries.insert(spec.id, query);
        }
    }
    Ok(queries)
}

fn match_type(rule: RoutingRule) -> MatchType {
    match rule {
        RoutingRule::MatchAll => MatchType::All,
        RoutingRule::ClientCidr => MatchType::ClientCidr,
        RoutingRule::ProxyCidr => MatchType::ProxyCidr,
        RoutingRule::ListenerPort => MatchType::Port,
    }
}

fn cidrs(backend: &MergedBackend) -> Vec<String> {
    backend
        .backend
        .labels
        .get("cidr")
        .map_or_else(Vec::new, |value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
                .collect()
        })
}

fn group_values(backend: &MergedBackend, rule: MatchType) -> Vec<String> {
    match rule {
        MatchType::All => Vec::new(),
        MatchType::ClientCidr | MatchType::ProxyCidr => cidrs(backend),
        MatchType::Port => backend
            .backend
            .labels
            .get("tiproxy-port")
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
            .map(|port| {
                if backend.cluster_name.is_empty() {
                    port.into()
                } else {
                    format!("{}:{port}", backend.cluster_name)
                }
            })
            .into_iter()
            .collect(),
    }
}

impl State {
    fn redirect_target(
        &self,
        source: &Arc<AccountIdentity>,
        candidate: &Candidate,
        target_id: &str,
    ) -> Result<&Backend, RouteError> {
        let physical = self
            .backends
            .values()
            .find(|backend| Arc::ptr_eq(&backend.account, source))
            .ok_or(RouteError::StaleCandidate)?;
        let group = physical.group.ok_or(RouteError::NoBackend)?;
        let target = self
            .routeable(group, &candidate.policy, &[])
            .into_iter()
            .find(|(backend, _)| backend.source.backend_id.as_ref() == target_id)
            .map(|(backend, _)| backend)
            .ok_or(RouteError::NoBackend)?;
        if Arc::ptr_eq(&target.account, source) {
            return Err(RouteError::SameBackend);
        }
        if assignment(&physical.source, false).keyspace
            != assignment(&target.source, false).keyspace
        {
            return Err(RouteError::CrossKeyspace);
        }
        Ok(target)
    }

    fn factor_group(
        &self,
        candidate: &Candidate,
        client: ClientInfo<'_>,
        listener_port: &str,
    ) -> Result<u64, RouteError> {
        let group = if candidate.policy.routing_rule == RoutingRule::ListenerPort {
            self.ports
                .group_for(listener_port)
                .map_err(|_| RouteError::PortConflict)?
                .copied()
        } else {
            self.groups
                .iter()
                .find(|(_, matcher)| matcher.matches(client))
                .map(|(id, _)| *id)
        };
        group.ok_or(RouteError::NoBackend)
    }

    fn factor_inputs(&self, group: u64, candidate: &Candidate) -> Vec<crate::factors::Input> {
        self.backends
            .values()
            .filter(|backend| backend.group == Some(group))
            .filter_map(|backend| {
                self.ledger
                    .counts(&backend.account)
                    .map(|counts| crate::factors::Input {
                        id: Arc::clone(&backend.source.backend_id),
                        owner: Arc::clone(&backend.account),
                        instance: control_topology::metrics::instance_label(
                            &backend.source.backend.addr,
                            &backend.source.backend.ip,
                            backend.source.backend.status_port,
                        ),
                        cluster: backend.source.cluster_name.to_string(),
                        counts,
                        healthy: backend.healthy,
                        local: candidate.health.get(&backend.source.backend_id).local,
                        label_matches: label_matches(
                            &candidate.policy,
                            &backend.source.backend.labels,
                        ),
                    })
            })
            .collect()
    }

    fn prepare_factors(
        &self,
        group: u64,
        metrics: Option<&control_topology::MetricSnapshot>,
        inputs: &[crate::factors::Input],
        incarnation: &control_config::ResourceIncarnation,
    ) -> GroupFactors {
        let owners = self
            .backends
            .iter()
            .map(|(id, backend)| (Arc::clone(id), Arc::clone(&backend.account)))
            .collect();
        let mut factors = self.factors.get(&group).cloned().unwrap_or_default();
        if factors
            .incarnation
            .as_ref()
            .is_none_or(|old| !old.same_as(incarnation))
        {
            factors.core.clear_resources();
            factors.lineages.clear();
        }
        factors.incarnation = Some(incarnation.clone());
        factors.core.retain_owners(&owners);
        let clusters: BTreeSet<String> = inputs
            .iter()
            .map(|input| input.cluster.clone())
            .chain(factors.lineages.keys().cloned())
            .collect();
        for cluster in clusters {
            let next = metrics.and_then(|metrics| metrics.cache_lineage(&cluster));
            let previous = factors.lineages.get(&cluster);
            if !matches!((&next, previous), (Some(next), Some(old)) if next.same_history(old)) {
                factors.core.clear_cluster(&cluster);
            }
            if let Some(next) = next {
                factors.lineages.insert(cluster, next);
            } else {
                factors.lineages.remove(&cluster);
            }
        }
        factors
    }
    fn resource_inputs(
        &self,
        group: u64,
        candidate: &Candidate,
        excluded: &[&str],
    ) -> Vec<crate::factors::Input> {
        let inputs = self.factor_inputs(group, candidate);
        let ignore_failed = inputs
            .iter()
            .filter(|input| input.healthy && input.label_matches)
            .all(|input| {
                self.backends[&input.id]
                    .routing_identity
                    .failed(&candidate.policy)
            });
        // Group.Route filters health/failover/retries BEFORE factors. Label
        // isolation stays in FactorLabel so CPU sees the same candidate pool.
        inputs
            .into_iter()
            .filter(|input| {
                input.healthy
                    && !excluded.contains(&input.id.as_ref())
                    && (ignore_failed
                        || !self.backends[&input.id]
                            .routing_identity
                            .failed(&candidate.policy))
            })
            .collect()
    }

    fn routeable(
        &self,
        group: u64,
        policy: &RoutingConfig,
        excluded: &[&str],
    ) -> Vec<(&Backend, u64)> {
        let mut choices: Vec<(&Backend, u64)> = self
            .backends
            .values()
            .filter(|backend| {
                backend.group == Some(group)
                    && backend.healthy
                    && label_matches(policy, &backend.source.backend.labels)
            })
            .filter_map(|backend| {
                self.ledger
                    .counts(&backend.account)
                    .map(|counts| (backend, counts.connection_score()))
            })
            .collect();
        // The fail-list safeguard counts otherwise routeable observed members
        // in this group. Retry exclusions must not change that denominator.
        let ignore_failed = choices
            .iter()
            .all(|(backend, _)| backend.routing_identity.failed(policy));
        choices.retain(|(backend, _)| {
            (ignore_failed || !backend.routing_identity.failed(policy))
                && !excluded.contains(&backend.source.backend_id.as_ref())
        });
        choices
    }

    fn refresh(&mut self, candidate: &Candidate) -> Result<(), RouteError> {
        if self.observed.as_ref().is_some_and(|(r, h)| {
            Arc::ptr_eq(r, &candidate.routing) && Arc::ptr_eq(h, &candidate.health)
        }) {
            return Ok(());
        }
        for backend in self.backends.values_mut() {
            backend.healthy = false;
        }
        for source in &candidate.routing.backends.backends {
            let healthy = candidate.health.get(&source.backend_id).healthy;
            if let Some(backend) = self.backends.get_mut(&source.backend_id) {
                backend.source = source.clone();
                backend.healthy = healthy;
            } else if healthy {
                let account = self.ledger.add_account()?;
                self.backends.insert(
                    Arc::clone(&source.backend_id),
                    Backend {
                        source: source.clone(),
                        routing_identity: RoutingIdentity::new(&source.backend.addr),
                        account,
                        healthy,
                        group: None,
                    },
                );
            }
        }
        // An outstanding reservation retains its original owner even if the
        // backend disappears, changes material epoch, or becomes unhealthy.
        self.backends
            .retain(|_, backend| backend.healthy || !self.ledger.prune(&backend.account));
        let occupied: BTreeSet<u64> = self
            .backends
            .values()
            .filter_map(|backend| backend.group)
            .collect();
        self.groups.retain(|id, _| occupied.contains(id));
        self.factors.retain(|id, _| occupied.contains(id));
        let rule = match_type(candidate.policy.routing_rule);
        for backend in self
            .backends
            .values_mut()
            .filter(|backend| backend.group.is_none())
        {
            let values = group_values(&backend.source, rule);
            if rule != MatchType::All && values.is_empty() {
                continue;
            }
            let existing = self
                .groups
                .iter()
                .find(|(_, matcher)| rule == MatchType::All || matcher.intersects(&values))
                .map(|(id, _)| *id);
            let group = if let Some(group) = existing {
                group
            } else {
                let Ok(matcher) = GroupMatcher::new(rule, values) else {
                    continue;
                };
                let next = self
                    .next_group
                    .checked_add(1)
                    .ok_or(RouteError::Exhausted)?;
                let group = self.next_group;
                self.next_group = next;
                self.groups.insert(group, matcher);
                group
            };
            backend.group = Some(group);
        }
        if matches!(rule, MatchType::ClientCidr | MatchType::ProxyCidr) {
            for (id, matcher) in &mut self.groups {
                let values: BTreeSet<String> = self
                    .backends
                    .values()
                    .filter(|backend| backend.group == Some(*id))
                    .flat_map(|backend| cidrs(&backend.source))
                    .collect();
                // An invalid refresh retains the old parsed network list, as
                // Go Group.parseValues does; raw grouping values still change.
                let _ = matcher.refresh_values(values.into_iter().collect());
            }
        }
        self.ports = PortRoutes::default();
        if rule == MatchType::Port {
            for (id, matcher) in &self.groups {
                for value in matcher.values() {
                    let (cluster, port) = value.split_once(':').unwrap_or(("", value));
                    self.ports.bind(port, cluster, *id);
                }
            }
        }
        self.observed = Some((
            Arc::clone(&candidate.routing),
            Arc::clone(&candidate.health),
        ));
        Ok(())
    }
}

// Inputs are sorted by the clamped connection factor. Go's raw connection
// count is nevertheless used when asking whether migration would be advised.
#[allow(clippy::cast_precision_loss)]
fn choose(scores: &[u64], policy: &RoutingConfig, ticket: u128) -> Option<usize> {
    let &first = scores.first()?;
    let n = scores.len();
    if n == 1 {
        return Some(0);
    }
    if policy.selection_policy == RoutingSelectionPolicy::Random {
        let modulus = n as u128 * 10 + 1;
        return usize::try_from(ticket % modulus % n as u128).ok();
    }
    let ratio = if policy.connection.count_ratio_threshold > 1.0 {
        policy.connection.count_ratio_threshold
    } else {
        1.2
    };
    let mut choices = Vec::with_capacity(n);
    for index in (1..n).rev() {
        let from = scores[index];
        let mut count = 0.0;
        if from.min(u64::from(u16::MAX)) > first.min(u64::from(u16::MAX))
            && from as f64 > (first as f64 + 1.0) * ratio
        {
            count = if policy.connection.migrations_per_second > 0.0 {
                policy.connection.migrations_per_second
            } else {
                ((from as f64 + first as f64 + 1.0) / (1.0 + ratio) - (first as f64 + 1.0)) / 120.0
            };
        }
        if count <= 0.0001 {
            choices.push(index);
        }
    }
    choices.push(0);
    usize::try_from(ticket % choices.len() as u128)
        .ok()
        .map(|index| choices[index])
}

fn assignment(source: &MergedBackend, local: bool) -> RouteAssignment {
    // Locality belongs to the same exact H that admitted this reservation.
    // Current routing config can be newer than the config observed by that H.
    RouteAssignment {
        backend_id: source.backend_id.to_string(),
        backend_address: source.backend.addr.clone(),
        cluster_name: source.cluster_name.to_string(),
        keyspace: if source.backend.keyspace.is_empty() {
            source
                .backend
                .labels
                .get("keyspace")
                .cloned()
                .unwrap_or_default()
        } else {
            source.backend.keyspace.clone()
        },
        healthy: true,
        local,
        code: RouteCode::Ok,
        ..RouteAssignment::default()
    }
}

#[cfg(test)]
mod tests {
    use super::choose;
    use control_config::{ConfigNamespaceSource, ConfigNamespaceStore, RoutingSelectionPolicy};
    use std::fmt::Write;

    fn must<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
        result.unwrap_or_else(|error| unreachable!("fixture: {error:?}"))
    }

    #[test]
    fn shared_go_choice_observation() {
        let Ok(input) = std::env::var("CPROUTE_CHOICE_FIXTURE") else {
            return;
        };
        let rows = must(std::fs::read_to_string(input));
        let mut output = String::new();
        for row in rows
            .lines()
            .filter(|row| !row.is_empty() && !row.starts_with('#'))
        {
            let fields: Vec<&str> = row.split('\t').collect();
            assert_eq!(fields.len(), 6);
            let scores: Vec<u64> = fields[2]
                .split(',')
                .map(|score| must(score.parse()))
                .collect();
            let mut policy = must(
                must(ConfigNamespaceStore::from_toml(
                    b"",
                    None,
                    std::path::Path::new("/tmp"),
                ))
                .current()
                .effective()
                .routing(),
            );
            policy.selection_policy = if fields[1] == "random" {
                RoutingSelectionPolicy::Random
            } else {
                RoutingSelectionPolicy::PreferIdle
            };
            policy.connection.count_ratio_threshold = must(fields[3].parse());
            policy.connection.migrations_per_second = must(fields[4].parse());
            let period = must(fields[5].parse::<u128>());
            let mut weights = vec![0_u64; scores.len()];
            for ticket in 0..period {
                let index =
                    choose(&scores, &policy, ticket).unwrap_or_else(|| unreachable!("candidate"));
                weights[index] += 1;
            }
            must(writeln!(
                output,
                "{}\t{}",
                fields[0],
                weights
                    .iter()
                    .map(u64::to_string)
                    .collect::<Vec<_>>()
                    .join(",")
            ));
        }
        must(std::fs::write(
            must(std::env::var("CPROUTE_CHOICE_OUTPUT")),
            output,
        ));
    }
}

#[cfg(test)]
#[path = "composition_tests.rs"]
mod composition_tests;
