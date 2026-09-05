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

//! Concurrent multi-cluster `TiDB` topology merge.
//!
//! [`merge_tidb_topology`] mirrors Go
//! `backendcluster.Manager::GetTiDBTopology` (`pkg/manager/backendcluster/`):
//! it fetches each backend cluster's topology concurrently, each under a single
//! per-cluster budget, and merges the results into one deterministic view keyed
//! by the opaque `backendID = "<cluster>/<addr>"`. The same address in two
//! clusters is two distinct backends. A duplicate `backendID` keeps the first by
//! the caller's frozen input order (never by concurrent completion order); the
//! duplicate can only occur within one cluster's own snapshot, which the parser
//! already de-duplicates, so this is a defensive tie-break.
//!
//! Error semantics are Go-exact (`manager.go`): the merge fails **only** when it
//! produced no backends AND at least one cluster fetch failed. A cluster that
//! succeeds with an empty topology does not suppress the error, and any cluster
//! returning at least one backend makes the whole merge succeed.

use std::collections::HashSet;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use control_external::EtcdOperationError;
use tokio::task::JoinSet;
use tokio::time::timeout;

use crate::model::{BackendInfo, TopologySnapshot};

/// One cluster's fetch outcome tagged with its name: `Ok` on a successful read,
/// `Err(())` on a transport failure or a per-cluster timeout.
type ClusterOutcome = (Arc<str>, Result<TopologySnapshot, ()>);

/// One discovered backend tagged with its cluster identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MergedBackend {
    /// The opaque merge identity `"<cluster_name>/<addr>"`. It is an in-memory
    /// key only and must not be parsed or used as a network address.
    pub backend_id: Arc<str>,
    /// The backend's backend-cluster name.
    pub cluster_name: Arc<str>,
    /// The discovered backend.
    pub backend: BackendInfo,
}

/// The merged multi-cluster topology, ordered deterministically by
/// `(cluster_name, addr)`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MergedTopology {
    /// The merged backends, sorted by `(cluster_name, addr)`.
    pub backends: Vec<MergedBackend>,
}

/// The merge produced no backends and at least one cluster fetch failed
/// (Go: `len(merged) == 0 && len(errs) > 0`). This is deliberately payload-free
/// (only counts): an empty result with no failures is `Ok(empty)`, not this
/// error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TopologyUnavailable {
    /// The number of clusters whose fetch failed (transport error or timeout).
    pub failed_clusters: usize,
    /// The total number of clusters attempted.
    pub total_clusters: usize,
}

/// One backend cluster's topology fetch, run concurrently by
/// [`merge_tidb_topology`]. It is consumed by the fetch so the future owns its
/// connection and can be spawned. Injectable so the concurrency, ordering, and
/// error predicate are unit-tested without a fleet of real etcd servers.
pub trait ClusterTopologyFetch: Send + 'static {
    /// The backend-cluster name, read before the fetch consumes `self`.
    fn cluster_name(&self) -> Arc<str>;

    /// Fetches this cluster's live topology (both `TiDB` prefixes).
    fn fetch(self) -> impl Future<Output = Result<TopologySnapshot, EtcdOperationError>> + Send;
}

/// Fetches every cluster concurrently — each under its own `per_cluster` budget
/// covering that cluster's whole topology read — and merges the results.
///
/// `clusters` are supplied in the caller's frozen order (Go's cluster set is
/// name-sorted upstream); the merge iterates that order so the first-wins
/// tie-break on a duplicate `backendID` is deterministic regardless of which
/// concurrent fetch finished first. The output is sorted by `(cluster_name,
/// addr)`.
///
/// # Errors
///
/// Returns [`TopologyUnavailable`] only when no cluster produced a backend and at
/// least one fetch failed (a transport error, a timeout, or a spawned task that
/// did not report). An all-empty (no-failure) result is `Ok` with an empty
/// topology.
pub async fn merge_tidb_topology<F: ClusterTopologyFetch>(
    clusters: Vec<F>,
    per_cluster: Duration,
) -> Result<MergedTopology, TopologyUnavailable> {
    let total_clusters = clusters.len();
    let mut set: JoinSet<(usize, ClusterOutcome)> = JoinSet::new();
    for (index, fetcher) in clusters.into_iter().enumerate() {
        set.spawn(async move {
            let cluster_name = fetcher.cluster_name();
            // One budget per cluster, covering its whole topology read. A
            // transport failure and a timeout are both "this cluster failed".
            let fetched = match timeout(per_cluster, fetcher.fetch()).await {
                Ok(Ok(snapshot)) => Ok(snapshot),
                Ok(Err(_)) | Err(_) => Err(()),
            };
            (index, (cluster_name, fetched))
        });
    }

    // Collect concurrent results back into the caller's frozen input order; a
    // slot left empty (a task that panicked/aborted) is treated as a failure.
    let mut slots: Vec<Option<ClusterOutcome>> = std::iter::repeat_with(|| None)
        .take(total_clusters)
        .collect();
    while let Some(joined) = set.join_next().await {
        if let Ok((index, outcome)) = joined
            && let Some(slot) = slots.get_mut(index)
        {
            *slot = Some(outcome);
        }
    }

    let mut seen: HashSet<Arc<str>> = HashSet::new();
    let mut backends: Vec<MergedBackend> = Vec::new();
    let mut failed_clusters = 0usize;
    for slot in slots {
        match slot {
            Some((cluster_name, Ok(snapshot))) => {
                for backend in snapshot.backends {
                    let backend_id: Arc<str> = format!("{cluster_name}/{}", backend.addr).into();
                    if seen.insert(Arc::clone(&backend_id)) {
                        backends.push(MergedBackend {
                            backend_id,
                            cluster_name: Arc::clone(&cluster_name),
                            backend,
                        });
                    }
                }
            }
            Some((_, Err(()))) | None => failed_clusters += 1,
        }
    }

    if backends.is_empty() && failed_clusters > 0 {
        return Err(TopologyUnavailable {
            failed_clusters,
            total_clusters,
        });
    }
    backends.sort_by(|left, right| {
        (left.cluster_name.as_ref(), left.backend.addr.as_str())
            .cmp(&(right.cluster_name.as_ref(), right.backend.addr.as_str()))
    });
    Ok(MergedTopology { backends })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use control_external::EtcdOperationError;
    use tokio::sync::{Barrier, Notify};

    use super::{ClusterTopologyFetch, MergedTopology, TopologyUnavailable, merge_tidb_topology};
    use crate::model::{BackendInfo, TopologySnapshot};

    const BUDGET: Duration = Duration::from_secs(2);
    /// A generous deadlock guard for the rendezvous test: it bounds the test, not
    /// a fetch's latency, so a correct concurrent merge never approaches it.
    const GUARD: Duration = Duration::from_secs(5);

    fn backend(addr: &str) -> BackendInfo {
        backend_with_version(addr, "")
    }

    fn backend_with_version(addr: &str, version: &str) -> BackendInfo {
        BackendInfo {
            addr: addr.to_owned(),
            keyspace: String::new(),
            ip: addr.split(':').next().unwrap_or_default().to_owned(),
            status_port: 0,
            version: version.to_owned(),
            git_hash: String::new(),
            deploy_path: String::new(),
            start_timestamp: 0,
            labels: std::collections::BTreeMap::new(),
        }
    }

    fn snapshot(addrs: &[&str]) -> TopologySnapshot {
        TopologySnapshot {
            backends: addrs.iter().map(|addr| backend(addr)).collect(),
        }
    }

    enum Outcome {
        Topology(TopologySnapshot),
        Failure,
        Hang(Duration),
        /// Waits at a shared rendezvous barrier before returning: every cluster
        /// must reach it, so a serialised merge (which cannot start the second
        /// fetch until the first returns) deadlocks instead of releasing.
        Rendezvous(Arc<Barrier>, TopologySnapshot),
        /// Waits for the notify before returning (completes second).
        AwaitNotify(Arc<Notify>, TopologySnapshot),
        /// Fires the notify, then returns (completes first).
        SignalNotify(Arc<Notify>, TopologySnapshot),
    }

    struct FakeCluster {
        name: Arc<str>,
        outcome: Outcome,
    }

    impl FakeCluster {
        fn new(name: &str, outcome: Outcome) -> Self {
            Self {
                name: Arc::from(name),
                outcome,
            }
        }
    }

    impl ClusterTopologyFetch for FakeCluster {
        fn cluster_name(&self) -> Arc<str> {
            Arc::clone(&self.name)
        }

        async fn fetch(self) -> Result<TopologySnapshot, EtcdOperationError> {
            match self.outcome {
                Outcome::Topology(snapshot) => Ok(snapshot),
                Outcome::Failure => Err(EtcdOperationError::Dependency(
                    etcd_client::Error::InvalidArgs("injected".to_owned()),
                )),
                Outcome::Hang(delay) => {
                    tokio::time::sleep(delay).await;
                    Ok(TopologySnapshot::default())
                }
                Outcome::Rendezvous(barrier, snapshot) => {
                    barrier.wait().await;
                    Ok(snapshot)
                }
                Outcome::AwaitNotify(notify, snapshot) => {
                    notify.notified().await;
                    Ok(snapshot)
                }
                Outcome::SignalNotify(notify, snapshot) => {
                    notify.notify_one();
                    Ok(snapshot)
                }
            }
        }
    }

    fn ids(merged: &MergedTopology) -> Vec<String> {
        merged
            .backends
            .iter()
            .map(|entry| entry.backend_id.to_string())
            .collect()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn merges_clusters_and_keeps_same_addr_across_clusters() {
        // The same addr in two clusters yields two distinct backend_ids; the
        // output is sorted by (cluster_name, addr). Dropping the cluster from the
        // key collapses the two into one.
        let clusters = vec![
            FakeCluster::new("cluster-b", Outcome::Topology(snapshot(&["10.0.0.1:4000"]))),
            FakeCluster::new(
                "cluster-a",
                Outcome::Topology(snapshot(&["10.0.0.1:4000", "10.0.0.2:4000"])),
            ),
        ];
        let merged = merge_tidb_topology(clusters, BUDGET)
            .await
            .unwrap_or_else(|_| unreachable!("a successful merge"));
        assert_eq!(
            ids(&merged),
            vec![
                "cluster-a/10.0.0.1:4000".to_owned(),
                "cluster-a/10.0.0.2:4000".to_owned(),
                "cluster-b/10.0.0.1:4000".to_owned(),
            ],
            "same addr across clusters is kept, sorted by (cluster, addr)"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fetches_run_concurrently() {
        // Deterministic rendezvous, not wall-clock timing: both fetches must
        // reach a shared 2-party barrier before either returns. A concurrent
        // merge starts both, so the barrier releases and the merge completes; a
        // serialised merge cannot start the second fetch until the first returns,
        // so the first blocks at the barrier forever and the merge deadlocks —
        // caught by the outer guard.
        let body = async {
            let barrier = Arc::new(Barrier::new(2));
            let clusters = vec![
                FakeCluster::new(
                    "a",
                    Outcome::Rendezvous(Arc::clone(&barrier), snapshot(&["1.1.1.1:1"])),
                ),
                FakeCluster::new(
                    "b",
                    Outcome::Rendezvous(Arc::clone(&barrier), snapshot(&["2.2.2.2:2"])),
                ),
            ];
            let merged = merge_tidb_topology(clusters, BUDGET)
                .await
                .unwrap_or_else(|_| unreachable!("a successful merge"));
            assert_eq!(merged.backends.len(), 2);
        };
        if tokio::time::timeout(GUARD, body).await.is_err() {
            unreachable!("concurrent fetches must rendezvous, not serialize");
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_per_cluster_hang_is_that_cluster_failing() {
        // One cluster hangs past the budget (a failure); the other returns a
        // backend, so the merge succeeds with only the live backend.
        let clusters = vec![
            FakeCluster::new("slow", Outcome::Hang(Duration::from_millis(400))),
            FakeCluster::new("live", Outcome::Topology(snapshot(&["9.9.9.9:9"]))),
        ];
        let merged = merge_tidb_topology(clusters, Duration::from_millis(100))
            .await
            .unwrap_or_else(|_| unreachable!("one live cluster makes the merge succeed"));
        assert_eq!(ids(&merged), vec!["live/9.9.9.9:9".to_owned()]);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn any_backend_suppresses_a_sibling_failure() {
        let clusters = vec![
            FakeCluster::new("bad", Outcome::Failure),
            FakeCluster::new("good", Outcome::Topology(snapshot(&["3.3.3.3:3"]))),
        ];
        let merged = merge_tidb_topology(clusters, BUDGET)
            .await
            .unwrap_or_else(|_| unreachable!("a live sibling suppresses the failure"));
        assert_eq!(ids(&merged), vec!["good/3.3.3.3:3".to_owned()]);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_failure_plus_an_empty_success_is_an_error() {
        // The Go predicate is `empty && any_error`, NOT `all failed`: a cluster
        // that succeeds but returns nothing does not suppress the error.
        let clusters = vec![
            FakeCluster::new("bad", Outcome::Failure),
            FakeCluster::new("empty", Outcome::Topology(TopologySnapshot::default())),
        ];
        let error = match merge_tidb_topology(clusters, BUDGET).await {
            Err(error) => error,
            Ok(merged) => unreachable!("an empty result with a failure is an error: {merged:?}"),
        };
        assert_eq!(
            error,
            TopologyUnavailable {
                failed_clusters: 1,
                total_clusters: 2,
            }
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn all_empty_without_failure_is_ok_empty() {
        let clusters = vec![
            FakeCluster::new("a", Outcome::Topology(TopologySnapshot::default())),
            FakeCluster::new("b", Outcome::Topology(TopologySnapshot::default())),
        ];
        let merged = merge_tidb_topology(clusters, BUDGET)
            .await
            .unwrap_or_else(|_| unreachable!("all-empty with no failure is Ok(empty)"));
        assert!(merged.backends.is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn all_clusters_failing_is_an_error() {
        let clusters = vec![
            FakeCluster::new("a", Outcome::Failure),
            FakeCluster::new("b", Outcome::Failure),
        ];
        let error = match merge_tidb_topology(clusters, BUDGET).await {
            Err(error) => error,
            Ok(merged) => unreachable!("all failing is an error: {merged:?}"),
        };
        assert_eq!(error.failed_clusters, 2);
        assert_eq!(error.total_clusters, 2);
    }

    // A current-thread runtime makes the completion order deterministic: input 1
    // fires the notify and returns before the executor resumes the parked input
    // 0, so `JoinSet::join_next` yields input 1 first. The frozen input-order
    // merge still keeps input 0; a completion-order merge would keep input 1.
    #[tokio::test]
    async fn duplicate_backend_id_keeps_the_input_order_winner() {
        // Two fetchers with the SAME backend_id (same cluster_name + addr) but a
        // distinguishable payload. Input 0 is gated to finish AFTER input 1 (it
        // awaits a notify that input 1 fires), so completion order is the reverse
        // of input order. The frozen rule keeps the INPUT-order winner (input 0),
        // so merging by completion order instead would keep input 1 — RED.
        let body = async {
            let notify = Arc::new(Notify::new());
            let clusters = vec![
                FakeCluster::new(
                    "dup",
                    Outcome::AwaitNotify(
                        Arc::clone(&notify),
                        TopologySnapshot {
                            backends: vec![backend_with_version("1.1.1.1:1", "input-zero")],
                        },
                    ),
                ),
                FakeCluster::new(
                    "dup",
                    Outcome::SignalNotify(
                        Arc::clone(&notify),
                        TopologySnapshot {
                            backends: vec![backend_with_version("1.1.1.1:1", "input-one")],
                        },
                    ),
                ),
            ];
            let merged = merge_tidb_topology(clusters, BUDGET)
                .await
                .unwrap_or_else(|_| unreachable!("a successful merge"));
            assert_eq!(merged.backends.len(), 1, "the duplicate backend_id dedups");
            assert_eq!(
                merged.backends[0].backend.version, "input-zero",
                "the input-order winner survives, not the completion-order one"
            );
        };
        if tokio::time::timeout(GUARD, body).await.is_err() {
            unreachable!("the notify rendezvous must complete");
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn zero_clusters_is_ok_empty() {
        let merged = merge_tidb_topology(Vec::<FakeCluster>::new(), BUDGET)
            .await
            .unwrap_or_else(|_| unreachable!("no clusters is Ok(empty), never an error"));
        assert!(merged.backends.is_empty());
    }
}
