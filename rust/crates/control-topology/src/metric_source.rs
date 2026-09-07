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

//! Applied metric material and a uniquely owned, synchronized generation feed.

#[cfg(test)]
#[path = "metric_source_tests.rs"]
mod tests;

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use control_config::{ConfigNamespaceSource, HealthCheckConfig};
use control_external::{
    ClusterHttpClient, ClusterHttpConfigError, ClusterHttpError, CombinedFence, GenerationGate,
    HttpProbePolicy, HttpTarget, IoFence,
};
use control_plane::OwnerToken;
use thiserror::Error;
use tokio::sync::Notify;

use crate::health_loop::{HealthPolicy, ProxyZoneSource};
use crate::{
    BackendSourceMode, DiscoveryCapture, DiscoveryError, MergedTopology, ModeEpoch, PrometheusInfo,
    RoutingSnapshot, TopologyClusterClient,
};

/// Invalid restart-pinned metrics input, rejected before runtime activation.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum MetricConfigError {
    /// Invalid metrics interval or inherited backend retry policy.
    #[error("invalid metrics cadence or retry policy")]
    InvalidCadence,
    /// Invalid backend dial timeout or Prometheus request timeout.
    #[error("invalid metrics request timeout")]
    InvalidTimeout,
}

/// Restart-pinned timing for the later metrics collector.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MetricRuntimePolicy {
    interval: Duration,
    retry_interval: Duration,
    max_retries: u32,
    backend_timeout: Duration,
    prom_timeout: Duration,
}

impl MetricRuntimePolicy {
    fn new(config: HealthCheckConfig) -> Result<Self, MetricConfigError> {
        let positive = |nanos| {
            u64::try_from(nanos)
                .ok()
                .filter(|n| *n > 0)
                .map(Duration::from_nanos)
        };
        let interval =
            positive(config.metrics_interval_nanos).ok_or(MetricConfigError::InvalidCadence)?;
        let retry_interval =
            positive(config.retry_interval_nanos).ok_or(MetricConfigError::InvalidCadence)?;
        HealthPolicy::new(interval, config.max_retries, retry_interval)
            .map_err(|_| MetricConfigError::InvalidCadence)?;
        let backend_timeout =
            positive(config.dial_timeout_nanos).ok_or(MetricConfigError::InvalidTimeout)?;
        let prom_timeout =
            positive(config.metrics_timeout_nanos).ok_or(MetricConfigError::InvalidTimeout)?;
        for timeout in [backend_timeout, prom_timeout] {
            HttpProbePolicy::validated(timeout).map_err(|_| MetricConfigError::InvalidTimeout)?;
        }
        Ok(Self {
            interval,
            retry_interval,
            max_retries: config.max_retries,
            backend_timeout,
            prom_timeout,
        })
    }

    /// Start-to-start round interval; Go defaults to five seconds.
    #[must_use]
    pub const fn interval(self) -> Duration {
        self.interval
    }
    /// Fixed delay between backend retries.
    #[must_use]
    pub const fn retry_interval(self) -> Duration {
        self.retry_interval
    }
    /// Backend retry count after the first attempt.
    #[must_use]
    pub const fn max_retries(self) -> u32 {
        self.max_retries
    }
    /// Total Prometheus query budget (including its retries).
    #[must_use]
    pub const fn prom_timeout(self) -> Duration {
        self.prom_timeout
    }
}

pub(crate) struct PreparedMetricNetworks {
    policy: MetricRuntimePolicy,
    clusters: HashMap<Arc<str>, ClusterHttpClient>,
    election_material: HashMap<Arc<str>, control_external::EtcdClientConfig>,
    owner: OwnerToken,
    prom: ClusterHttpClient,
}

impl PreparedMetricNetworks {
    fn build(
        owner: &OwnerToken,
        clusters: &[TopologyClusterClient],
        policy: MetricRuntimePolicy,
    ) -> Result<Self, ClusterHttpConfigError> {
        let http_policy = |attempt_timeout| HttpProbePolicy {
            attempt_timeout,
            max_response_bytes: control_external::http::MAX_HTTP_RESPONSE_BYTES,
        };
        let mut networks = HashMap::with_capacity(clusters.len());
        let mut election_material = HashMap::with_capacity(clusters.len());
        for cluster in clusters {
            let network = ClusterHttpClient::from_cluster_material(
                &cluster.client,
                owner.clone(),
                http_policy(policy.backend_timeout),
            )?;
            networks.insert(Arc::clone(&cluster.cluster_name), network);
            election_material.insert(Arc::clone(&cluster.cluster_name), cluster.client.clone());
        }
        let prom = ClusterHttpClient::system_http(owner.clone(), http_policy(policy.prom_timeout))?;
        Ok(Self {
            policy,
            clusters: networks,
            election_material,
            owner: owner.clone(),
            prom,
        })
    }

    // The actual capture comes from the infallible discovery commit. No caller
    // can reconstruct this authority from a client epoch or re-read PEM paths.
    fn bind(self, discovery: DiscoveryCapture) -> AppliedMetricMaterial {
        AppliedMetricMaterial {
            discovery,
            gate: GenerationGate::new(),
            networks: self,
        }
    }
}

struct AppliedMetricMaterial {
    discovery: DiscoveryCapture,
    gate: GenerationGate,
    networks: PreparedMetricNetworks,
}

struct MetricGeneration {
    source: Arc<RoutingSnapshot>,
    material: Arc<AppliedMetricMaterial>,
    mode: Arc<ModeEpoch>,
}

impl MetricGeneration {
    fn is_live(&self) -> bool {
        self.source.source_gate().is_live()
            && self.material.gate.is_live()
            && self.material.discovery.still_current()
            && self.mode.is_live()
            && self.mode.mode() == BackendSourceMode::Dynamic
    }
}

struct FeedSlot {
    material: Option<Arc<AppliedMetricMaterial>>,
    generation: Option<Arc<MetricGeneration>>,
    gate: Option<GenerationGate>,
    revision: u64,
    closed: bool,
    overflowed: bool,
}
impl FeedSlot {
    fn terminal(&self) -> bool {
        self.closed || self.overflowed
    }
    fn revoke(&mut self) {
        if let Some(gate) = self.gate.take() {
            gate.revoke();
        }
        self.generation = None;
    }
    fn advance(&mut self) {
        if let Some(revision) = self.revision.checked_add(1) {
            self.revision = revision;
        } else {
            self.overflowed = true;
            self.revoke();
        }
    }
}
struct FeedShared {
    slot: Mutex<FeedSlot>,
    changed: Notify,
}
impl FeedShared {
    fn lock(&self) -> MutexGuard<'_, FeedSlot> {
        self.slot.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// The module's UNIQUE feed writer and applied material owner. Drop closes it.
/// Only this owner can prepare/bind/reconcile a metric source; a public consumer
/// receives opaque captures and cannot publish a guessed numeric generation.
pub(crate) struct MetricPublication {
    shared: Arc<FeedShared>,
    pinned: HealthCheckConfig,
    policy: Option<MetricRuntimePolicy>,
}

impl MetricPublication {
    pub(crate) fn new(
        source: Arc<dyn ConfigNamespaceSource>,
        pinned: HealthCheckConfig,
    ) -> (Self, MetricSourceHandle) {
        let shared = Arc::new(FeedShared {
            slot: Mutex::new(FeedSlot {
                material: None,
                generation: None,
                gate: None,
                revision: 0,
                closed: false,
                overflowed: false,
            }),
            changed: Notify::new(),
        });
        (
            Self {
                shared: Arc::clone(&shared),
                pinned,
                policy: None,
            },
            MetricSourceHandle { shared, source },
        )
    }

    pub(crate) fn enable(&mut self) -> Result<(), MetricConfigError> {
        self.policy = Some(MetricRuntimePolicy::new(self.pinned)?);
        Ok(())
    }

    pub(crate) fn prepare(
        &self,
        owner: &OwnerToken,
        clusters: &[TopologyClusterClient],
    ) -> Result<Option<PreparedMetricNetworks>, ClusterHttpConfigError> {
        self.policy
            .map(|policy| PreparedMetricNetworks::build(owner, clusters, policy))
            .transpose()
    }

    // Called after all fallible preparation and BEFORE stop_children's await.
    pub(crate) fn withdraw_material(&self) {
        let mut slot = self.shared.lock();
        if slot.terminal() {
            return;
        }
        slot.revoke();
        if let Some(material) = slot.material.take() {
            material.gate.revoke();
        }
        slot.advance();
        self.shared.changed.notify_waiters();
    }

    pub(crate) fn install(
        &self,
        prepared: Option<PreparedMetricNetworks>,
        discovery: DiscoveryCapture,
    ) {
        let mut slot = self.shared.lock();
        if slot.terminal() {
            return;
        }
        slot.material = prepared.map(|prepared| Arc::new(prepared.bind(discovery)));
    }

    pub(crate) fn reconcile(&self, source: Option<Arc<RoutingSnapshot>>, mode: Arc<ModeEpoch>) {
        let mut slot = self.shared.lock();
        if slot.terminal() {
            return;
        }
        let pair = source
            .zip(slot.material.clone())
            .filter(|(source, material)| {
                // The numeric comparison pairs private, same-module producer output.
                // Every retained consumer also owns and validates all actual gates,
                // source/material identities and the original discovery capability.
                source.client_epoch == material.discovery.client_epoch()
                    && source.source_gate().is_live()
                    && material.gate.is_live()
                    && material.discovery.still_current()
                    && mode.is_live()
                    && mode.mode() == BackendSourceMode::Dynamic
            });
        let Some((source, material)) = pair else {
            if slot.generation.is_some() {
                slot.revoke();
                slot.advance();
                self.shared.changed.notify_waiters();
            }
            return;
        };
        if slot.generation.as_ref().is_some_and(|generation| {
            Arc::ptr_eq(&source, &generation.source)
                && Arc::ptr_eq(&material, &generation.material)
                && Arc::ptr_eq(&mode, &generation.mode)
        }) {
            return;
        }
        slot.revoke();
        slot.generation = Some(Arc::new(MetricGeneration {
            source,
            material,
            mode,
        }));
        slot.gate = Some(GenerationGate::new());
        slot.advance();
        self.shared.changed.notify_waiters();
    }

    pub(crate) fn close(&self) {
        let mut slot = self.shared.lock();
        if slot.closed {
            return;
        }
        slot.revoke();
        if let Some(material) = slot.material.take() {
            material.gate.revoke();
        }
        slot.closed = true;
        slot.advance();
        self.shared.changed.notify_waiters();
    }
}
impl Drop for MetricPublication {
    fn drop(&mut self) {
        self.close();
    }
}

/// Live read side of the module's applied dynamic metrics source.
/// Static mode has no applied cluster reader; it does not manufacture one.
#[derive(Clone)]
pub struct MetricSourceHandle {
    shared: Arc<FeedShared>,
    source: Arc<dyn ConfigNamespaceSource>,
}

impl MetricSourceHandle {
    /// Captures the exact current material/source/mode incarnation, if live.
    #[must_use]
    pub fn capture(&self) -> Option<MetricCapture> {
        self.snapshot().0
    }

    /// Returns the current capture, change revision, and terminal flag atomically.
    /// The revision is for waiting; it cannot authorize any operation.
    #[must_use]
    pub fn snapshot(&self) -> (Option<MetricCapture>, u64, bool) {
        let slot = self.shared.lock();
        let capture = if slot.terminal() {
            None
        } else {
            slot.generation
                .as_ref()
                .zip(slot.gate.as_ref())
                .filter(|(generation, gate)| generation.is_live() && gate.is_live())
                .map(|(generation, gate)| MetricCapture {
                    generation: Arc::clone(generation),
                    gate: gate.clone(),
                    shared: Arc::clone(&self.shared),
                })
        };
        (capture, slot.revision, slot.terminal())
    }

    /// Waits for a different revision or terminal close, without losing an edge.
    pub async fn wait_change(&self, seen: u64) {
        loop {
            let notified = self.shared.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            {
                let slot = self.shared.lock();
                if slot.terminal() || slot.revision != seen {
                    return;
                }
            }
            notified.await;
        }
    }

    /// Reads the CURRENT committed proxy zone independently of applied material.
    /// The backend collector captures it once at round entry, including after a
    /// rejected cluster update. It is not an election identity or a work permit.
    #[must_use]
    pub fn proxy_zone(&self) -> Option<Arc<str>> {
        self.source.proxy_zone()
    }
}

/// One actual feed/material/discovery/R/mode capability. Fields are private.
#[derive(Clone)]
pub struct MetricCapture {
    generation: Arc<MetricGeneration>,
    gate: GenerationGate,
    shared: Arc<FeedShared>,
}
impl IoFence for MetricCapture {
    fn is_live(&self) -> bool {
        self.still_current()
    }
}

/// A bounded discovery/HTTP read failure; stale authority takes precedence.
#[derive(Debug, Error)]
pub enum MetricReadError {
    /// A retained local capability was revoked.
    #[error("metric read source is stale")]
    Stale,
    /// The cluster is absent from the actual captured material.
    #[error("unknown metric cluster")]
    UnknownCluster,
    /// Topology/Prometheus discovery failed under the current capture.
    #[error("metric discovery failed")]
    Discovery(DiscoveryError),
    /// The current bounded HTTP attempt failed.
    #[error("metric HTTP request failed")]
    Http(#[from] ClusterHttpError),
}

impl MetricCapture {
    /// Checks the actual retained identities and gates, without polling a watch.
    #[must_use]
    pub fn still_current(&self) -> bool {
        self.gate.is_live() && self.generation.is_live()
    }

    /// The captured full R, including backends excluded by health H.
    #[must_use]
    pub fn routing(&self) -> &Arc<RoutingSnapshot> {
        &self.generation.source
    }

    /// Restart-pinned collector timing associated with this material.
    #[must_use]
    pub fn policy(&self) -> MetricRuntimePolicy {
        self.generation.material.networks.policy
    }

    /// Names of the clusters in this actual applied material.
    pub fn cluster_names(&self) -> impl Iterator<Item = &str> {
        self.generation.material.discovery.cluster_names()
    }

    /// Serializes final publication against feed replacement/withdrawal/Drop.
    ///
    /// The closure must be short, synchronous and must not re-enter the feed.
    /// Owner-selected publication nests its actual work permit's `with_current`
    /// inside this closure: lock order feed → authority → overlay. Published
    /// results retain this capture and any required retained election authority.
    pub fn with_current<T>(&self, publish: impl FnOnce() -> T) -> Option<T> {
        let slot = self.shared.lock();
        if slot.terminal()
            || !self.still_current()
            || !slot
                .generation
                .as_ref()
                .is_some_and(|current| Arc::ptr_eq(current, &self.generation))
        {
            return None;
        }
        Some(publish())
    }

    pub(crate) fn same_generation(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.generation, &other.generation) && Arc::ptr_eq(&self.shared, &other.shared)
    }

    // Kept inside the crate: callers never receive client config or raw clients.
    pub(crate) async fn campaign_metric_owner(
        &self,
        cluster: &str,
        election: control_etcd::ElectionConfig,
        scope: Arc<dyn IoFence>,
    ) -> Result<control_etcd::ElectionSession, control_etcd::ElectionError> {
        if !self.still_current() || !scope.is_live() {
            return Err(control_etcd::ElectionError::StaleScope);
        }
        let networks = &self.generation.material.networks;
        let material = networks.election_material.get(cluster).ok_or(
            control_etcd::ElectionError::InvalidResponse {
                class: "unknown_metric_cluster",
            },
        )?;
        control_etcd::ElectionSession::campaign_with_scope(
            networks.owner.clone(),
            material.clone(),
            election,
            Arc::new(MetricCampaignFence {
                capture: self.clone(),
                extra: scope,
            }),
        )
        .await
    }

    pub(crate) async fn poll_metric_owners(
        &self,
        cluster: &str,
        prefix: &str,
    ) -> Result<Vec<crate::metric_owner::OwnerRecord>, MetricReadError> {
        self.check()?;
        let result = self
            .generation
            .material
            .discovery
            .poll_metric_owners_fenced(cluster, prefix, Arc::new(self.clone()))
            .await;
        self.check()?;
        result.map_err(MetricReadError::Discovery)
    }

    fn check(&self) -> Result<(), MetricReadError> {
        if self.still_current() {
            Ok(())
        } else {
            Err(MetricReadError::Stale)
        }
    }

    /// Reads full cluster topology through the retained discovery capability.
    /// # Errors
    /// Returns stale authority, unknown-cluster or a bounded discovery failure.
    pub async fn poll_cluster_topology(
        &self,
        cluster: &str,
    ) -> Result<MergedTopology, MetricReadError> {
        self.check()?;
        let result = self
            .generation
            .material
            .discovery
            .poll_cluster_topology_fenced(cluster, Arc::new(self.clone()))
            .await;
        self.check()?;
        result.map_err(MetricReadError::Discovery)
    }

    /// Refreshes Prometheus discovery through this actual applied set.
    /// # Errors
    /// Returns stale authority, current absence or a bounded discovery failure.
    pub async fn poll_prometheus(&self, cluster: &str) -> Result<PrometheusInfo, MetricReadError> {
        self.check()?;
        let result = self
            .generation
            .material
            .discovery
            .poll_prometheus_fenced(cluster, Arc::new(self.clone()))
            .await;
        self.check()?;
        result.map_err(MetricReadError::Discovery)
    }

    /// One cluster HTTP attempt with this material/source AND the caller's actual
    /// work or observed-peer capability checked at every effect boundary. A retry
    /// calls this method again; no previous admission is reused.
    /// # Errors
    /// Returns stale authority, unknown-cluster or a bounded HTTP failure.
    pub async fn get_cluster_once(
        &self,
        cluster: &str,
        host: &str,
        port: u16,
        target: &HttpTarget,
        work: &dyn IoFence,
    ) -> Result<Vec<u8>, MetricReadError> {
        let fence = CombinedFence::new(self, work);
        if !fence.is_live() {
            return Err(MetricReadError::Stale);
        }
        let Some(client) = self.generation.material.networks.clusters.get(cluster) else {
            if !fence.is_live() {
                return Err(MetricReadError::Stale);
            }
            return Err(MetricReadError::UnknownCluster);
        };
        let result = client.get_target_once(host, port, target, &fence).await;
        if !fence.is_live() {
            return Err(MetricReadError::Stale);
        }
        result
            .map(|bytes| bytes.to_vec())
            .map_err(MetricReadError::Http)
    }

    /// One plain HTTP/system-DNS Prometheus attempt. Prom-selected data depends
    /// on material/source authority, independently of backend owner election.
    /// # Errors
    /// Returns stale authority or a bounded HTTP failure.
    pub async fn get_prom_once(
        &self,
        host: &str,
        port: u16,
        target: &HttpTarget,
    ) -> Result<Vec<u8>, MetricReadError> {
        self.check()?;
        let result = self
            .generation
            .material
            .networks
            .prom
            .get_target_once(host, port, target, self)
            .await;
        self.check()?;
        result
            .map(|bytes| bytes.to_vec())
            .map_err(MetricReadError::Http)
    }
}

struct MetricCampaignFence {
    capture: MetricCapture,
    extra: Arc<dyn IoFence>,
}
impl IoFence for MetricCampaignFence {
    fn is_live(&self) -> bool {
        self.capture.still_current() && self.extra.is_live()
    }
}
