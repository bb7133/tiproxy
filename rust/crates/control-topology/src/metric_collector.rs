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

//! Staged in-process metrics collection and owner history service.

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use control_external::GenerationGate;
use control_plane::{ControlModule, LifecyclePhase, ModuleContext, ModuleError, ModuleFuture};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinSet;

use crate::metrics::{MetricError, QueryId, QueryResult, ReaderState, Source};
use crate::{MetricCapture, MetricSourceHandle};

#[cfg(feature = "api-replay")]
pub(crate) mod api_replay;
mod collect;
mod owner;
mod service;

#[cfg(test)]
pub(crate) mod test_http;
#[cfg(test)]
mod tests;

const MODULE: &str = "metrics";
const MAX_CLUSTERS: usize = 128;

/// Failure to bind or configure the staged owner service.
#[derive(Debug, thiserror::Error)]
pub enum MetricCollectorError {
    /// The requested in-process listener could not be bound.
    #[error("metric owner listener could not bind")]
    Bind(#[source] std::io::Error),
}

#[derive(Clone)]
struct QueryLifetime {
    source: MetricSourceHandle,
    incarnation: control_config::ResourceIncarnation,
}
impl QueryLifetime {
    fn is_live(&self) -> bool {
        self.incarnation
            .same_as(&self.source.resource_incarnation())
    }
}

struct ClusterResult {
    queries: Option<QueryLifetime>,
    lineage: Arc<()>,
    gate: GenerationGate,
    reader: ReaderState,
    backend_proofs: Vec<owner::Proof>,
    owner: Option<Arc<owner::LocalOwner>>,
    export: Arc<[u8]>,
}
impl ClusterResult {
    fn queries_current(&self) -> bool {
        self.queries.as_ref().is_none_or(QueryLifetime::is_live)
    }
    fn selected_proofs(&self) -> &[owner::Proof] {
        if self.reader.source() == Source::Backend {
            &self.backend_proofs
        } else {
            &[]
        }
    }
}

#[derive(Default)]
struct Published {
    #[cfg(feature = "api-replay")]
    external: Option<Arc<api_replay::ExternalResult>>,
    capture: Option<MetricCapture>,
    clusters: BTreeMap<String, Arc<ClusterResult>>,
}
impl Published {
    fn clear(&mut self) {
        #[cfg(feature = "api-replay")]
        if let Some(external) = self.external.take() {
            external.gate.revoke();
        }
        for result in self.clusters.values() {
            result.gate.revoke();
        }
        self.clusters.clear();
        self.capture = None;
    }
}

struct Shared {
    source: MetricSourceHandle,
    serving: Arc<service::Binding>,
    queries: Mutex<BTreeSet<QueryId>>,
    routing_queries: bool,
    published: Mutex<Published>,
}
impl Shared {
    fn lock(&self) -> MutexGuard<'_, Published> {
        self.published
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }
    fn query_lifetime(&self) -> Option<QueryLifetime> {
        self.routing_queries.then(|| QueryLifetime {
            source: self.source.clone(),
            incarnation: self.source.resource_incarnation(),
        })
    }
    fn queries(&self, lifetime: Option<&QueryLifetime>) -> Vec<QueryId> {
        if let Some(lifetime) = lifetime {
            return crate::metrics::query_catalog()
                .iter()
                .filter(|_| lifetime.incarnation.enabled())
                .map(|spec| spec.id)
                .collect();
        }
        self.queries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .copied()
            .collect()
    }
    fn publish(
        &self,
        capture: &MetricCapture,
        cluster: &str,
        result: ClusterResult,
        work: Option<&control_etcd::ElectionWorkPermit>,
    ) -> bool {
        let proofs = result.selected_proofs().to_vec();
        // The work permit already locks its local authority. Lock all other
        // provenance first, and never re-enter that authority through Proof.
        let proofs: Vec<_> = proofs
            .iter()
            .filter(|proof| work.is_none() || !matches!(proof, owner::Proof::Local(_)))
            .collect();
        let put = || {
            let mut published = self.lock();
            if !result.queries_current() {
                return false;
            }
            if !published
                .capture
                .as_ref()
                .is_some_and(|active| active.same_generation(capture))
            {
                return false;
            }
            let result = Arc::new(result);
            if let Some(previous) = published.clusters.insert(cluster.into(), result) {
                previous.gate.revoke();
            }
            true
        };
        self.serving
            .with_live(|| {
                capture
                    .with_current(|| {
                        owner::with_retained(&proofs, || {
                            if let Some(work) = work {
                                work.with_current(put).unwrap_or(false)
                            } else {
                                put()
                            }
                        })
                        .unwrap_or(false)
                    })
                    .unwrap_or(false)
            })
            .unwrap_or(false)
    }
}

/// Opaque continuity of one cluster's selected metric history.
/// This is a cache key, never an authorization to use data without a current
/// snapshot. Only the collector can issue it, and equality is object identity.
#[derive(Clone)]
pub struct MetricCacheLineage(Arc<()>);
impl MetricCacheLineage {
    /// Whether two captures belong to the exact same selected history lifetime.
    #[must_use]
    pub fn same_history(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

/// An immutable metric result carrying its actual source and owner provenance.
/// Query values remain data; retain this snapshot and use `with_current` at the
/// routing publication boundary after reading a value.
pub struct MetricSnapshot {
    #[cfg(feature = "api-replay")]
    external: Option<Arc<api_replay::ExternalResult>>,
    capture: MetricCapture,
    serving: Arc<service::Binding>,
    clusters: BTreeMap<String, Arc<ClusterResult>>,
}
impl MetricSnapshot {
    /// Cache continuity for a cluster with a completed selected result. Retain
    /// only alongside ledger-owned factor state; final use requires `with_current`.
    #[must_use]
    pub fn cache_lineage(&self, cluster: &str) -> Option<MetricCacheLineage> {
        #[cfg(feature = "api-replay")]
        if let Some(external) = &self.external {
            return Some(MetricCacheLineage(Arc::clone(&external.lineage)));
        }
        self.clusters
            .get(cluster)
            .map(|result| MetricCacheLineage(Arc::clone(&result.lineage)))
    }

    /// Checks source, serving lifetime, result replacement and selected owners.
    #[must_use]
    pub fn still_current(&self) -> bool {
        self.input_current()
            && self.capture.still_current()
            && self.serving.is_live()
            && self.clusters.values().all(|result| {
                result.queries_current()
                    && result.gate.is_live()
                    && result.selected_proofs().iter().all(owner::Proof::is_live)
            })
    }
    fn input_current(&self) -> bool {
        #[cfg(feature = "api-replay")]
        if self
            .external
            .as_ref()
            .is_some_and(|result| !result.current())
        {
            return false;
        }
        true
    }
    /// The original topology capture for final pairing with a routing decision.
    #[must_use]
    pub fn source(&self) -> &MetricCapture {
        &self.capture
    }
    /// Merges current cluster results with the data core's exact update times.
    /// # Errors
    /// Returns the data core's bounded merge error.
    pub fn query_result(&self, rule: QueryId) -> Result<Option<QueryResult>, MetricError> {
        if !self.still_current() {
            return Ok(None);
        }
        #[cfg(feature = "api-replay")]
        if let Some(external) = &self.external {
            // This input is already merged. A second merge would reorder first
            // matches and rewrite timestamps from an unrelated cluster.
            let result = external.queries.get(&rule).cloned();
            return Ok(self.still_current().then_some(result).flatten());
        }
        let result = QueryResult::merge(
            self.clusters
                .values()
                .filter_map(|cluster| cluster.reader.get(rule).cloned()),
        )?;
        if self.still_current() {
            Ok(result)
        } else {
            Ok(None)
        }
    }
    /// Serializes a short synchronous use against feed and retained-owner fences.
    /// The closure must not re-enter this snapshot or the underlying authorities.
    pub fn with_current<T>(&self, use_result: impl FnOnce() -> T) -> Option<T> {
        self.serving
            .with_live(|| {
                self.capture
                    .with_current(|| {
                        let proofs: Vec<_> = self
                            .clusters
                            .values()
                            .flat_map(|result| result.selected_proofs())
                            .collect();
                        owner::with_retained(&proofs, || {
                            if self.serving.is_live()
                                && self.capture.still_current()
                                && self.input_current()
                                && self
                                    .clusters
                                    .values()
                                    .all(|result| result.gate.is_live() && result.queries_current())
                            {
                                Some(use_result())
                            } else {
                                None
                            }
                        })
                        .flatten()
                    })
                    .flatten()
            })
            .flatten()
    }
}

/// Read-only result captures plus the bounded fixed-query registration surface.
#[derive(Clone)]
pub struct MetricOverlayHandle {
    shared: Arc<Shared>,
}
impl MetricOverlayHandle {
    /// Registers an expression for a manually bound collector. Routing-bound
    /// collectors own their query set and ignore manual registration.
    pub fn add_query(&self, query: QueryId) {
        self.shared
            .queries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(query);
    }
    /// Removes a manual expression; backend history is purged in the next round.
    pub fn remove_query(&self, query: QueryId) {
        self.shared
            .queries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&query);
    }
    /// Captures routing inputs from the automatic collector only, paired with
    /// the actual routing snapshot and policy lifetime. None means unavailable
    /// metrics, never unavailable routing authority.
    #[must_use]
    pub fn routing_current_for(
        &self,
        routing: &Arc<crate::RoutingSnapshot>,
        incarnation: &control_config::ResourceIncarnation,
    ) -> Option<MetricSnapshot> {
        if !self.shared.routing_queries
            || !incarnation.enabled()
            || !incarnation.same_as(&self.shared.source.resource_incarnation())
        {
            return None;
        }
        let capture = self.shared.source.capture()?;
        if !Arc::ptr_eq(routing, capture.routing()) {
            return None;
        }
        self.current_for(&capture)
    }
    /// Captures current results only for this exact retained material/source.
    #[must_use]
    pub fn current_for(&self, capture: &MetricCapture) -> Option<MetricSnapshot> {
        if !capture.still_current() || !self.shared.serving.is_live() {
            return None;
        }
        let published = self.shared.lock();
        if !published
            .capture
            .as_ref()
            .is_some_and(|active| active.same_generation(capture))
        {
            return None;
        }
        let snapshot = MetricSnapshot {
            #[cfg(feature = "api-replay")]
            external: published.external.clone(),
            capture: capture.clone(),
            serving: Arc::clone(&self.shared.serving),
            clusters: published.clusters.clone(),
        };
        drop(published);
        snapshot.still_current().then_some(snapshot)
    }
}

/// Opt-in collector owning one real in-process owner HTTP binding.
/// Binding is completed before any election can advertise its address. This
/// module is not installed in the production composition by this API.
pub struct MetricCollector {
    listener: Option<TcpListener>,
    shared: Arc<Shared>,
}
impl MetricCollector {
    /// Binds the actual owner endpoint; configured queries start empty, as in Go.
    /// The resulting control module must run before collection/serving begins.
    /// # Errors
    /// Returns a listener bind failure without starting any campaign or worker.
    pub async fn bind(
        source: MetricSourceHandle,
        address: SocketAddr,
    ) -> Result<(Self, MetricOverlayHandle), MetricCollectorError> {
        Self::bind_queries(source, address, false).await
    }
    /// Binds an opt-in routing collector. The accepted config owns all six
    /// expressions while Resource/Location factors exist; Connection removes
    /// them. Every transition is retained even if watch notifications coalesce.
    /// # Errors
    /// Returns a listener bind failure before any worker starts.
    pub async fn bind_for_routing(
        source: MetricSourceHandle,
        address: SocketAddr,
    ) -> Result<(Self, MetricOverlayHandle), MetricCollectorError> {
        Self::bind_queries(source, address, true).await
    }
    async fn bind_queries(
        source: MetricSourceHandle,
        address: SocketAddr,
        routing_queries: bool,
    ) -> Result<(Self, MetricOverlayHandle), MetricCollectorError> {
        let listener = TcpListener::bind(address)
            .await
            .map_err(MetricCollectorError::Bind)?;
        let address = listener.local_addr().map_err(MetricCollectorError::Bind)?;
        let shared = Arc::new(Shared {
            source,
            serving: Arc::new(service::Binding::new(address)),
            queries: Mutex::new(BTreeSet::new()),
            routing_queries,
            published: Mutex::new(Published::default()),
        });
        Ok((
            Self {
                listener: Some(listener),
                shared: Arc::clone(&shared),
            },
            MetricOverlayHandle { shared },
        ))
    }
    /// The address of the real bound listener, fixed for this service lifetime.
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.shared.serving.address
    }

    async fn run_inner(mut self: Box<Self>, context: ModuleContext) -> Result<(), ModuleError> {
        self.shared.serving.activate(context.owner().clone());
        let listener = self.listener.take().ok_or(ModuleError {
            module: MODULE,
            error_class: "listener_missing",
        })?;
        let mut service_task = JoinSet::new();
        service_task.spawn(service::serve(listener, Arc::clone(&self.shared)));
        let mut lifecycle = context.lifecycle();
        let mut children = JoinSet::new();
        let (mut shutdown, _) = watch::channel(false);
        let mut seen = None;
        let mut failure = None;
        loop {
            if !self.shared.serving.is_live()
                || !matches!(
                    lifecycle.borrow().phase,
                    LifecyclePhase::Starting | LifecyclePhase::Ready
                )
            {
                break;
            }
            let (capture, revision, closed) = self.shared.source.snapshot();
            if closed {
                break;
            }
            if seen != Some(revision) {
                shutdown.send_replace(true);
                self.shared.lock().clear();
                stop_clusters(&mut children).await;
                let (next_shutdown, receiver) = watch::channel(false);
                shutdown = next_shutdown;
                if let Some(capture) = capture {
                    let names: Vec<_> = capture.cluster_names().map(str::to_owned).collect();
                    if names.len() > MAX_CLUSTERS {
                        failure = Some("cluster_limit");
                        break;
                    }
                    let installed = capture
                        .with_current(|| {
                            self.shared.lock().capture = Some(capture.clone());
                        })
                        .is_some();
                    if installed {
                        for cluster in names {
                            children.spawn(collect::run_cluster(
                                Arc::clone(&self.shared),
                                capture.clone(),
                                cluster,
                                receiver.clone(),
                            ));
                        }
                    }
                }
                seen = Some(revision);
            }
            tokio::select! {
                biased;
                result = lifecycle.changed() => { if result.is_err() { break; } }
                () = self.shared.source.wait_change(revision) => {}
                _ = service_task.join_next() => { failure = Some("listener_stopped"); break; }
                result = children.join_next(), if !children.is_empty() => {
                    if result.is_some() { failure = Some("collector_stopped"); break; }
                }
            }
        }
        self.shared.serving.close();
        self.shared.lock().clear();
        shutdown.send_replace(true);
        stop_clusters(&mut children).await;
        service_task.abort_all();
        while service_task.join_next().await.is_some() {}
        failure.map_or(Ok(()), |error_class| {
            Err(ModuleError {
                module: MODULE,
                error_class,
            })
        })
    }
}
impl Drop for MetricCollector {
    fn drop(&mut self) {
        self.shared.serving.close();
    }
}
impl ControlModule for MetricCollector {
    fn name(&self) -> &'static str {
        MODULE
    }
    fn run(self: Box<Self>, context: ModuleContext) -> ModuleFuture {
        Box::pin(self.run_inner(context))
    }
}
async fn stop_clusters(children: &mut JoinSet<()>) {
    if tokio::time::timeout(Duration::from_secs(30), async {
        while children.join_next().await.is_some() {}
    })
    .await
    .is_err()
    {
        children.abort_all();
        while children.join_next().await.is_some() {}
    }
}
