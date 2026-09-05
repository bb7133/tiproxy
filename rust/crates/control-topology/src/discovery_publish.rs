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

//! Pull-based discovery publication and the generation-fenced handle.
//!
//! The [`TopologyModule`](crate::TopologyModule) publishes one immutable
//! [`DiscoverySet`] per *client epoch* — a discovery-plan generation that bumps
//! only when a backend cluster's material (endpoints / TLS / `ns_servers`)
//! changes, not on an advertise-only or log-level reconfigure. Each set carries
//! its long-lived, channel-backed [`EtcdConnection`]s and a revocable
//! [`GenerationGate`].
//!
//! [`DiscoveryHandle`] reads the latest set from a `watch`, forks the
//! connections under the set's gate for one pull, runs the merge, and — before
//! returning — re-validates that the same epoch is still published and its gate
//! still live, so a result captured by a retired epoch never escapes. The gate is
//! folded into each connection's own ownership check, so a revoked epoch also
//! stops an in-flight poll from issuing its next prefix read or retry. The result
//! of a successful pull carries its source `client_epoch` so a consumer (#214)
//! can stamp it and never mix two epochs' data.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use control_external::{
    EtcdClientConfig, EtcdConnectError, EtcdConnection, EtcdConnector, GenerationGate,
};
use control_plane::OwnerToken;
use tokio::sync::watch;

use crate::discovery::{poll_prometheus, poll_tidb_topology};
use crate::merge::{
    ClusterTopologyFetch, MergedTopology, TopologyUnavailable, merge_tidb_topology,
};
use crate::model::{PrometheusInfo, TopologySnapshot};

/// The per-cluster topology-read budget, mirroring Go `topologyFetchTimeout`.
const PER_CLUSTER_BUDGET: Duration = Duration::from_secs(2);

/// A successful discovery pull tagged with the client epoch it was read from, so
/// a consumer can stamp it and never mix two epochs' data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochResult<T> {
    /// The discovery-plan generation the value was read from.
    pub client_epoch: u64,
    /// The pulled value.
    pub value: T,
}

/// Why a discovery pull did not return a value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DiscoveryError {
    /// No discovery set is published, or the captured set's gate was already
    /// revoked at admission: the handle is fail-closed (no I/O attempted).
    Revoked,
    /// The published epoch changed (rotated or revoked) while the pull was in
    /// flight, so the captured result is discarded rather than returned stale.
    Stale,
    /// The named cluster is not part of the currently published set.
    UnknownCluster {
        /// The requested cluster name.
        cluster: Arc<str>,
    },
    /// No Prometheus endpoint is registered for the cluster in this epoch. It
    /// carries the captured epoch so a consumer can attribute the absence to the
    /// exact source generation.
    NoPrometheus {
        /// The cluster with no Prometheus record.
        cluster: Arc<str>,
        /// The source epoch the absence was observed in.
        client_epoch: u64,
    },
    /// Every cluster's topology fetch failed (Go `empty && any_error`).
    TopologyUnavailable(TopologyUnavailable),
    /// The Prometheus read failed (transport, timeout, or a malformed record).
    /// A read failure that is actually a retired epoch surfaces as [`Stale`]
    /// instead, via the post-pull re-validation.
    ///
    /// [`Stale`]: DiscoveryError::Stale
    PrometheusUnavailable,
}

/// One backend cluster's production topology fetch: a forked, gate-fenced
/// connection sharing the epoch's long-lived channel.
struct ConnectionTopologyFetch {
    cluster_name: Arc<str>,
    connection: EtcdConnection,
}

impl ClusterTopologyFetch for ConnectionTopologyFetch {
    fn cluster_name(&self) -> Arc<str> {
        Arc::clone(&self.cluster_name)
    }

    async fn fetch(mut self) -> Result<TopologySnapshot, control_external::EtcdOperationError> {
        poll_tidb_topology(&mut self.connection).await
    }
}

/// One published discovery generation: its epoch, its revocable gate, and the
/// long-lived per-cluster connections. Private — never leaked from the handle.
struct DiscoverySet {
    client_epoch: u64,
    gate: GenerationGate,
    clusters: Vec<(Arc<str>, EtcdConnection)>,
}

impl DiscoverySet {
    /// Whether this set is still the admissible current generation.
    fn is_admissible(&self, published: Option<&Arc<DiscoverySet>>) -> bool {
        self.gate.is_live()
            && published.is_some_and(|current| current.client_epoch == self.client_epoch)
    }
}

/// A pull-on-demand, generation-fenced view of the published topology discovery.
///
/// Cheap to clone; it holds only a `watch` receiver. Every pull captures the
/// current set, fences it (gate + epoch) before I/O and again before returning.
#[derive(Clone)]
pub struct DiscoveryHandle {
    published: watch::Receiver<Option<Arc<DiscoverySet>>>,
}

impl DiscoveryHandle {
    /// Captures the currently published set, failing closed when none is live.
    fn admit(&self) -> Result<Arc<DiscoverySet>, DiscoveryError> {
        let set = self
            .published
            .borrow()
            .as_ref()
            .filter(|set| set.gate.is_live())
            .map(Arc::clone);
        set.ok_or(DiscoveryError::Revoked)
    }

    /// Re-validates that `epoch` is still the live published generation after a
    /// pull's I/O.
    fn still_current(&self, set: &DiscoverySet) -> Result<(), DiscoveryError> {
        let published = self.published.borrow();
        if set.is_admissible(published.as_ref()) {
            Ok(())
        } else {
            Err(DiscoveryError::Stale)
        }
    }

    /// Locates a cluster within a captured set. A not-found is fenced: if the
    /// captured set has since rotated away, a missing cluster surfaces as `Stale`,
    /// never a stale `UnknownCluster` answered from a retired generation.
    fn locate<'set>(
        &self,
        set: &'set DiscoverySet,
        cluster: &str,
    ) -> Result<(Arc<str>, &'set EtcdConnection), DiscoveryError> {
        if let Some((name, connection)) = set
            .clusters
            .iter()
            .find(|(name, _)| name.as_ref() == cluster)
        {
            return Ok((Arc::clone(name), connection));
        }
        self.still_current(set)?;
        Err(DiscoveryError::UnknownCluster {
            cluster: Arc::from(cluster),
        })
    }

    /// The epoch of the currently published set, or `None` when nothing live is
    /// published. Test-only: lets a module test observe that a rejected
    /// generation retained the last-good discovery epoch.
    #[cfg(test)]
    pub(crate) fn current_epoch(&self) -> Option<u64> {
        self.published
            .borrow()
            .as_ref()
            .filter(|set| set.gate.is_live())
            .map(|set| set.client_epoch)
    }

    /// Pulls and merges every cluster's live `TiDB` topology for the current
    /// epoch.
    ///
    /// # Errors
    ///
    /// Returns [`DiscoveryError::Revoked`] when no set is live, [`Stale`] when the
    /// epoch rotates mid-pull, or [`TopologyUnavailable`] when no cluster
    /// produced a backend and at least one fetch failed.
    ///
    /// [`Stale`]: DiscoveryError::Stale
    /// [`TopologyUnavailable`]: DiscoveryError::TopologyUnavailable
    pub async fn poll_merged_topology(
        &self,
    ) -> Result<EpochResult<MergedTopology>, DiscoveryError> {
        let set = self.admit()?;
        let fetchers: Vec<ConnectionTopologyFetch> = set
            .clusters
            .iter()
            .map(|(name, connection)| ConnectionTopologyFetch {
                cluster_name: Arc::clone(name),
                connection: connection.fork_with_gate(set.gate.clone()),
            })
            .collect();
        let merged = merge_tidb_topology(fetchers, PER_CLUSTER_BUDGET).await;
        // The final generation fence covers EVERY outcome (including a fully
        // failed or hung merge): a rotation or revoke during the poll surfaces as
        // Stale, never a stale `TopologyUnavailable`.
        self.still_current(&set)?;
        let merged = merged.map_err(DiscoveryError::TopologyUnavailable)?;
        Ok(EpochResult {
            client_epoch: set.client_epoch,
            value: merged,
        })
    }

    /// Pulls one cluster's Prometheus endpoint for the current epoch.
    ///
    /// # Errors
    ///
    /// Returns [`DiscoveryError::Revoked`]/[`Stale`] under a retired epoch,
    /// [`UnknownCluster`] when the cluster is not in the set, [`NoPrometheus`]
    /// (carrying the epoch) when the cluster has no Prometheus record, or
    /// [`PrometheusUnavailable`] on a read failure.
    ///
    /// [`Stale`]: DiscoveryError::Stale
    /// [`UnknownCluster`]: DiscoveryError::UnknownCluster
    /// [`NoPrometheus`]: DiscoveryError::NoPrometheus
    /// [`PrometheusUnavailable`]: DiscoveryError::PrometheusUnavailable
    pub async fn poll_prometheus(
        &self,
        cluster: &str,
    ) -> Result<EpochResult<PrometheusInfo>, DiscoveryError> {
        let set = self.admit()?;
        let (name, connection) = self.locate(&set, cluster)?;
        let mut forked = connection.fork_with_gate(set.gate.clone());
        let result = poll_prometheus(&mut forked).await;
        self.still_current(&set)?;
        match result {
            Ok(Some(info)) => Ok(EpochResult {
                client_epoch: set.client_epoch,
                value: info,
            }),
            Ok(None) => Err(DiscoveryError::NoPrometheus {
                cluster: name,
                client_epoch: set.client_epoch,
            }),
            Err(_) => Err(DiscoveryError::PrometheusUnavailable),
        }
    }
}

/// The material fingerprint of one discovery generation: the name-sorted cluster
/// set with its exact etcd client material. Discovery rotates only when this
/// changes.
type Material = Vec<(Arc<str>, EtcdClientConfig)>;

/// Builds one cluster's long-lived, channel-backed connection. Production uses
/// [`EtcdConnector::connect`]; a test injects a connector so the module's
/// registration tests need not stand up real TLS material.
pub(crate) type DiscoveryConnector = Arc<
    dyn Fn(
            OwnerToken,
            EtcdClientConfig,
        )
            -> Pin<Box<dyn Future<Output = Result<EtcdConnection, EtcdConnectError>> + Send>>
        + Send
        + Sync,
>;

/// The production connector: one owner-fenced, lazy `connect()` per cluster.
pub(crate) fn default_discovery_connector() -> DiscoveryConnector {
    Arc::new(|owner, client| {
        Box::pin(async move { EtcdConnector::new(owner, client).connect().await })
    })
}

/// A prepared-but-not-committed discovery generation: every per-cluster
/// `connect()` (lazy, no network) has already succeeded AND the client epoch has
/// already been reserved (overflow-checked), so [`DiscoveryPublisher::commit`]
/// is infallible — a caller can mutate registration first, knowing the discovery
/// commit that follows cannot fail and split the two planes.
pub(crate) struct PreparedDiscovery {
    client_epoch: u64,
    material: Material,
    connections: Vec<(Arc<str>, EtcdConnection)>,
}

/// Why a discovery generation could not be prepared. Both are raised BEFORE any
/// state is mutated, so the caller retains the last-good registration and
/// discovery.
#[derive(Debug)]
pub(crate) enum PrepareError {
    /// A cluster's `connect()` failed (retired owner or dependency).
    Connect(#[allow(dead_code)] EtcdConnectError),
    /// The monotonic client-epoch counter would wrap; the publisher fails closed
    /// rather than reusing an epoch (no ABA).
    EpochOverflow,
}

/// The publisher's mutable bookkeeping, behind a `Mutex` so the whole publisher
/// works through `&self` (letting the module hold it as a field and drive it from
/// its `&self` reconfigure without a mutable-borrow refactor).
struct PublisherState {
    current_gate: Option<GenerationGate>,
    current_material: Option<Material>,
    next_epoch: u64,
}

/// Owns the discovery publication for a [`TopologyModule`]: the `watch` sender,
/// the current gate, the current material, and the monotonic epoch counter.
pub(crate) struct DiscoveryPublisher {
    published: watch::Sender<Option<Arc<DiscoverySet>>>,
    state: Mutex<PublisherState>,
}

impl DiscoveryPublisher {
    /// Builds a publisher (no set published yet) and the handle that reads it.
    pub(crate) fn new() -> (Self, DiscoveryHandle) {
        let (published, receiver) = watch::channel(None);
        (
            Self {
                published,
                state: Mutex::new(PublisherState {
                    current_gate: None,
                    current_material: None,
                    next_epoch: 0,
                }),
            },
            DiscoveryHandle {
                published: receiver,
            },
        )
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, PublisherState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Sets the next epoch the publisher will reserve. Test-only: lets a test
    /// drive the checked epoch counter to its overflow boundary.
    #[cfg(test)]
    pub(crate) fn set_next_epoch(&self, next_epoch: u64) {
        self.lock().next_epoch = next_epoch;
    }

    /// Whether `material` already matches the currently published generation, so
    /// no rotation (and no reconnect) is needed.
    pub(crate) fn material_unchanged(&self, material: &Material) -> bool {
        self.lock().current_material.as_ref() == Some(material)
    }

    /// Prepares a new generation: connects every cluster (lazy, no network) and
    /// reserves the next overflow-checked client epoch. It is the ONLY fallible
    /// step, and it runs before any registration or discovery state is mutated,
    /// so a failure retains the last-good registration and discovery. The reserved
    /// epoch is consumed only on a successful connect, so a connect failure never
    /// burns an epoch.
    ///
    /// # Errors
    ///
    /// Returns [`PrepareError::Connect`] for the first cluster whose `connect()`
    /// fails, or [`PrepareError::EpochOverflow`] if the epoch counter would wrap.
    pub(crate) async fn prepare(
        &self,
        connector: &DiscoveryConnector,
        owner: &OwnerToken,
        material: Material,
    ) -> Result<PreparedDiscovery, PrepareError> {
        let mut connections = Vec::with_capacity(material.len());
        for (name, client) in &material {
            let connection = connector(owner.clone(), client.clone())
                .await
                .map_err(PrepareError::Connect)?;
            connections.push((Arc::clone(name), connection));
        }
        // Reserve the epoch last (after connect succeeds), overflow-checked, so
        // the subsequent commit is infallible.
        let client_epoch = {
            let mut state = self.lock();
            let reserved = state.next_epoch;
            state.next_epoch = reserved.checked_add(1).ok_or(PrepareError::EpochOverflow)?;
            reserved
        };
        Ok(PreparedDiscovery {
            client_epoch,
            material,
            connections,
        })
    }

    /// Commits a prepared generation: revokes the old gate and publishes the new
    /// immutable set under the epoch already reserved by [`Self::prepare`]. This
    /// is infallible, so committing after a registration switch can never fail and
    /// leave the two planes split.
    pub(crate) fn commit(&self, prepared: PreparedDiscovery) {
        let mut state = self.lock();
        if let Some(previous) = &state.current_gate {
            previous.revoke();
        }
        let gate = GenerationGate::new();
        state.current_gate = Some(gate.clone());
        state.current_material = Some(prepared.material);
        self.published.send_replace(Some(Arc::new(DiscoverySet {
            client_epoch: prepared.client_epoch,
            gate,
            clusters: prepared.connections,
        })));
    }

    /// Retires the publication: revokes the current gate first, then withdraws
    /// the published set so the handle is zero-I/O fail-closed. Idempotent, used
    /// by the module's RAII revoke on any exit.
    pub(crate) fn revoke(&self) {
        let mut state = self.lock();
        if let Some(gate) = state.current_gate.take() {
            gate.revoke();
        }
        state.current_material = None;
        self.published.send_replace(None);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use control_external::EtcdConnector;
    use control_plane::{OwnerLease, OwnerScope, OwnershipRegistry};

    use super::{
        DiscoveryConnector, DiscoveryError, DiscoveryPublisher, EtcdClientConfig, Material,
        PrepareError, PreparedDiscovery,
    };
    use std::sync::Arc;

    fn owner() -> (OwnershipRegistry, OwnerLease) {
        let registry = OwnershipRegistry::new();
        let lease = registry
            .claim(OwnerScope::Process, "discovery-publish-test")
            .unwrap_or_else(|error| unreachable!("claim: {error}"));
        (registry, lease)
    }

    fn plaintext() -> EtcdClientConfig {
        EtcdClientConfig::new(vec!["127.0.0.1:1".to_owned()], None)
            .unwrap_or_else(|_| unreachable!("a plaintext endpoint is valid"))
    }

    fn material(name: &str) -> Material {
        vec![(Arc::from(name), plaintext())]
    }

    /// A connector that counts how many connections it builds; the connection is
    /// a real plaintext (lazy, no-network) `EtcdConnection`.
    fn counting_connector(count: &Arc<AtomicUsize>) -> DiscoveryConnector {
        let count = Arc::clone(count);
        Arc::new(move |owner, _client| {
            count.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move { EtcdConnector::new(owner, plaintext()).connect().await })
        })
    }

    async fn prepare(
        publisher: &DiscoveryPublisher,
        connector: &DiscoveryConnector,
        lease: &OwnerLease,
        name: &str,
    ) -> PreparedDiscovery {
        publisher
            .prepare(connector, &lease.token(), material(name))
            .await
            .unwrap_or_else(|_| unreachable!("a lazy plaintext connect prepares"))
    }

    #[tokio::test]
    async fn commit_increments_epoch_and_revokes_the_previous_gate() {
        let (_registry, lease) = owner();
        let count = Arc::new(AtomicUsize::new(0));
        let connector = counting_connector(&count);
        let (publisher, handle) = DiscoveryPublisher::new();

        let prepared = prepare(&publisher, &connector, &lease, "a").await;
        publisher.commit(prepared);
        let first = handle
            .admit()
            .unwrap_or_else(|_| unreachable!("the first set is admissible"));
        assert_eq!(first.client_epoch, 0);
        assert!(first.gate.is_live());

        let prepared = prepare(&publisher, &connector, &lease, "b").await;
        publisher.commit(prepared);
        assert!(
            !first.gate.is_live(),
            "committing a new generation revokes the previous gate"
        );
        let second = handle
            .admit()
            .unwrap_or_else(|_| unreachable!("the second set is admissible"));
        assert_eq!(second.client_epoch, 1, "the epoch increments monotonically");
        // Each generation connected once per cluster.
        assert_eq!(count.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn revoke_leaves_the_handle_fail_closed() {
        let (_registry, lease) = owner();
        let count = Arc::new(AtomicUsize::new(0));
        let connector = counting_connector(&count);
        let (publisher, handle) = DiscoveryPublisher::new();

        let prepared = prepare(&publisher, &connector, &lease, "a").await;
        publisher.commit(prepared);
        assert!(handle.admit().is_ok());

        publisher.revoke();
        assert_eq!(handle.admit().err(), Some(DiscoveryError::Revoked));
    }

    #[tokio::test]
    async fn material_unchanged_reflects_the_committed_material() {
        let (_registry, lease) = owner();
        let count = Arc::new(AtomicUsize::new(0));
        let connector = counting_connector(&count);
        let (publisher, _handle) = DiscoveryPublisher::new();

        assert!(!publisher.material_unchanged(&material("a")));
        let prepared = prepare(&publisher, &connector, &lease, "a").await;
        publisher.commit(prepared);
        assert!(publisher.material_unchanged(&material("a")));
        assert!(!publisher.material_unchanged(&material("b")));
    }

    #[tokio::test]
    async fn a_rotation_makes_an_older_captured_set_stale() {
        let (_registry, lease) = owner();
        let count = Arc::new(AtomicUsize::new(0));
        let connector = counting_connector(&count);
        let (publisher, handle) = DiscoveryPublisher::new();

        let prepared = prepare(&publisher, &connector, &lease, "a").await;
        publisher.commit(prepared);
        let captured = handle
            .admit()
            .unwrap_or_else(|_| unreachable!("admissible"));
        assert!(handle.still_current(&captured).is_ok());

        let prepared = prepare(&publisher, &connector, &lease, "b").await;
        publisher.commit(prepared);
        assert_eq!(
            handle.still_current(&captured).err(),
            Some(DiscoveryError::Stale),
            "a result captured under the old epoch is stale after rotation"
        );
    }

    #[tokio::test]
    async fn a_missing_cluster_on_a_rotated_set_is_stale_not_unknown() {
        let (_registry, lease) = owner();
        let count = Arc::new(AtomicUsize::new(0));
        let connector = counting_connector(&count);
        let (publisher, handle) = DiscoveryPublisher::new();
        let prepared = prepare(&publisher, &connector, &lease, "a").await;
        publisher.commit(prepared);
        let old_set = handle
            .admit()
            .unwrap_or_else(|_| unreachable!("admissible"));

        // Rotate: the captured set is now a retired generation.
        let prepared = prepare(&publisher, &connector, &lease, "b").await;
        publisher.commit(prepared);

        // A missing cluster resolved against the retired set is Stale, never a
        // stale UnknownCluster answered from a rotated-away generation.
        assert_eq!(
            handle.locate(&old_set, "missing").err(),
            Some(DiscoveryError::Stale),
        );
    }

    #[tokio::test]
    async fn a_missing_cluster_on_the_current_set_is_unknown() {
        let (_registry, lease) = owner();
        let count = Arc::new(AtomicUsize::new(0));
        let connector = counting_connector(&count);
        let (publisher, handle) = DiscoveryPublisher::new();
        let prepared = prepare(&publisher, &connector, &lease, "a").await;
        publisher.commit(prepared);
        let set = handle
            .admit()
            .unwrap_or_else(|_| unreachable!("admissible"));

        assert_eq!(
            handle.locate(&set, "missing").err(),
            Some(DiscoveryError::UnknownCluster {
                cluster: Arc::from("missing"),
            }),
        );
    }

    #[tokio::test]
    async fn a_checked_epoch_overflow_fails_closed_in_prepare() {
        let (_registry, lease) = owner();
        let count = Arc::new(AtomicUsize::new(0));
        let connector = counting_connector(&count);
        let (publisher, handle) = DiscoveryPublisher::new();
        publisher.lock().next_epoch = u64::MAX;

        // Overflow is caught in prepare, BEFORE any state mutation, so nothing is
        // published and a caller can still retain its last-good state.
        let prepared = publisher
            .prepare(&connector, &lease.token(), material("a"))
            .await;
        assert!(
            matches!(prepared, Err(PrepareError::EpochOverflow)),
            "the monotonic epoch counter never wraps"
        );
        assert_eq!(
            handle.admit().err(),
            Some(DiscoveryError::Revoked),
            "an overflowed prepare publishes nothing"
        );
    }

    #[tokio::test]
    async fn an_overflow_on_the_next_prepare_retains_the_committed_live_set() {
        // Blocker-3 atomicity: a module already has a live discovery set, and the
        // NEXT prepare overflows. Because prepare reserves the epoch (overflow
        // checked) BEFORE it mutates any published state, the overflow leaves the
        // previously committed generation — its epoch, gate, material, and
        // published set — entirely intact.
        let (_registry, lease) = owner();
        let count = Arc::new(AtomicUsize::new(0));
        let connector = counting_connector(&count);
        let (publisher, handle) = DiscoveryPublisher::new();

        // Commit a first live set at epoch 0.
        let prepared = prepare(&publisher, &connector, &lease, "a").await;
        publisher.commit(prepared);
        let live = handle
            .admit()
            .unwrap_or_else(|_| unreachable!("the first set is admissible"));
        assert_eq!(live.client_epoch, 0);
        assert!(live.gate.is_live());
        let connects_after_commit = count.load(Ordering::SeqCst);

        // Drive the counter to the brink; the next prepare must overflow.
        publisher.lock().next_epoch = u64::MAX;
        let overflow = publisher
            .prepare(&connector, &lease.token(), material("b"))
            .await;
        assert!(
            matches!(overflow, Err(PrepareError::EpochOverflow)),
            "the monotonic epoch counter never wraps on the next prepare"
        );

        // The committed generation is unchanged: same epoch, still-live gate,
        // still the admissible current generation, still the committed material.
        let retained = handle
            .admit()
            .unwrap_or_else(|_| unreachable!("the committed set is retained"));
        assert_eq!(
            retained.client_epoch, 0,
            "the committed epoch is retained across an overflow"
        );
        assert!(
            retained.gate.is_live(),
            "the committed gate stays live across an overflow"
        );
        assert!(
            handle.still_current(&retained).is_ok(),
            "the committed set is still the current generation after an overflow"
        );
        assert!(
            publisher.material_unchanged(&material("a")),
            "the committed material is retained across an overflow"
        );
        // The overflow is detected only AFTER the (lazy, no-network) connect, so
        // the failed prepare did connect its cluster once but published nothing.
        assert_eq!(
            count.load(Ordering::SeqCst),
            connects_after_commit + 1,
            "the failed prepare connected before detecting the overflow, yet committed nothing"
        );
    }
}
