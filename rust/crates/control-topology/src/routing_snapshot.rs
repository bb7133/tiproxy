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

//! Generation-stamped immutable routing topology snapshots for CP-ROUTE.
//!
//! [`RoutingSnapshotPublisher`] turns the discovery layer's pull-on-demand merged
//! topology into an immutable, whole-view snapshot that a routing consumer reads
//! without ever observing a torn or partial generation. Each published
//! [`RoutingSnapshot`] is an `Arc` swapped atomically into a `watch`, mirroring Go
//! `SnapshotPublisher` (`pkg/controlbridge`): a monotonic `generation` minted `1`
//! for the first snapshot and advanced only on a real change, with the previous
//! generation's authority revoked at each swap.
//!
//! "Real change" is the `(client_epoch, backends)` tuple, not the backends alone:
//! a discovery-plan epoch change must advance the generation even when the backend
//! bytes are identical, so a consumer never routes on a snapshot whose stated
//! provenance is stale. Two successive polls of the same epoch that return the same
//! backends are a true no-op — nothing is swapped and the generation holds.
//!
//! Old generations are fenced by *authority*, not merely by `Arc` immutability:
//! every snapshot carries its own private revocable [`GenerationGate`], and a
//! consumer holding a retained `Arc` re-validates with
//! [`RoutingSnapshotHandle::still_current`] (published-`Arc` identity **and** a live
//! gate, checked in that order so a revoke-in-progress fails closed) before acting
//! on it. The `generation` field is a diagnostic stamp only — it is never used as
//! cross-publisher authority, since two independent publishers both start at `1`.
//!
//! Withdrawal is terminal and unbypassable: [`RoutingSnapshotPublisher::revoke_and_clear`]
//! retires the publisher so any later `publish` is refused, and the publisher's
//! `Drop` revokes the live gate and clears the watch, so neither a late result nor a
//! dropped publisher can leave a consumer holding live authority.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use control_external::GenerationGate;
use tokio::sync::watch;

use crate::discovery_publish::EpochResult;
use crate::merge::MergedTopology;

/// One immutable, generation-stamped routing view of the merged multi-cluster
/// topology, published for CP-ROUTE to consume.
#[derive(Debug)]
pub struct RoutingSnapshot {
    /// The monotonic routing generation: `1` for the first published snapshot,
    /// advanced by one every time the published `(client_epoch, backends)` tuple
    /// changes. It is a diagnostic stamp; it is **not** cross-publisher authority.
    pub generation: u64,
    /// The discovery-plan epoch these backends were read from, carried as
    /// provenance so a consumer can attribute the view to its source generation.
    pub client_epoch: u64,
    /// The merged backends for this generation.
    pub backends: MergedTopology,
    /// This generation's revocable authority, revoked when a newer generation is
    /// published or the source is withdrawn.
    gate: GenerationGate,
}

/// The outcome of a [`RoutingSnapshotPublisher::publish`] call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PublishOutcome {
    /// A new generation was minted and swapped in atomically.
    Published {
        /// The generation just published.
        generation: u64,
    },
    /// The result matched the live snapshot's `(client_epoch, backends)`; nothing
    /// was swapped and the generation held.
    Unchanged,
    /// The result's `client_epoch` predates the live snapshot's, so it was refused
    /// as stale; nothing was swapped. Discovery normally fences a retired epoch as
    /// `Stale` upstream, but the publisher does not trust callers to serialise.
    RejectedStale,
    /// The publisher has been withdrawn ([`RoutingSnapshotPublisher::revoke_and_clear`]);
    /// the result is refused and the source stays fail-closed.
    Retired,
}

/// The routing generation counter is exhausted: the last published generation was
/// already [`u64::MAX`], so no further generation can be minted. The publish is
/// refused **before** any gate revoke or swap, so the last-good snapshot (at
/// generation [`u64::MAX`]) is fully retained; the counter never wraps and no
/// generation is ever reused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GenerationOverflow;

/// The routing source closed without ever publishing a routable snapshot — the
/// publisher was dropped before a live generation existed. A consumer waiting for
/// readiness must fail closed rather than treat the closure as success.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RoutingSourceClosed;

/// The publisher's serialised mutable state.
struct PublisherState {
    /// The last generation actually published, or `None` before the first publish.
    /// The next generation is this value's checked increment (or `1` when `None`),
    /// so generation [`u64::MAX`] is itself publishable and exhaustion is only the
    /// request that would follow it.
    last_generation: Option<u64>,
    /// Set once the publisher is withdrawn; every later `publish` is refused.
    retired: bool,
}

/// The single-writer publisher of [`RoutingSnapshot`]s.
///
/// It is created with no snapshot published (the handle is fail-closed until the
/// first success), every mutation is serialised so at most one generation is
/// installed at a time, and its `Drop` withdraws the publication so authority never
/// outlives the owner.
pub struct RoutingSnapshotPublisher {
    published: watch::Sender<Option<Arc<RoutingSnapshot>>>,
    state: Mutex<PublisherState>,
}

impl Drop for RoutingSnapshotPublisher {
    fn drop(&mut self) {
        // Never let a dropped publisher leave a consumer holding live authority:
        // revoke the current gate and clear the watch before the channel closes.
        self.revoke_and_clear();
    }
}

impl RoutingSnapshotPublisher {
    /// Builds a publisher (no snapshot published yet) and the first handle reading
    /// it.
    #[must_use]
    pub fn new() -> (Self, RoutingSnapshotHandle) {
        let (published, receiver) = watch::channel(None);
        (
            Self {
                published,
                state: Mutex::new(PublisherState {
                    last_generation: None,
                    retired: false,
                }),
            },
            RoutingSnapshotHandle {
                published: receiver,
            },
        )
    }

    /// A fresh handle onto this publisher, for an additional consumer.
    #[must_use]
    pub fn handle(&self) -> RoutingSnapshotHandle {
        RoutingSnapshotHandle {
            published: self.published.subscribe(),
        }
    }

    fn lock(&self) -> MutexGuard<'_, PublisherState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Sets the last generation the publisher believes it has issued. Test-only:
    /// lets a test drive the checked generation counter to its exhaustion boundary.
    #[cfg(test)]
    pub(crate) fn set_last_generation(&self, last_generation: Option<u64>) {
        self.lock().last_generation = last_generation;
    }

    /// Revokes the currently published snapshot's gate without clearing the watch.
    /// Test-only: reproduces the transient revoke-before-swap window (a `Some`
    /// whose gate is already dead) that a concurrent publish opens.
    #[cfg(test)]
    pub(crate) fn revoke_published_gate(&self) {
        if let Some(current) = self.published.borrow().as_ref() {
            current.gate.revoke();
        }
    }

    /// Publishes a freshly pulled merged topology, minting a new generation only on
    /// a real change.
    ///
    /// A withdrawn publisher refuses every result ([`PublishOutcome::Retired`]). A
    /// result whose `client_epoch` predates the live snapshot is refused
    /// ([`PublishOutcome::RejectedStale`]); a result matching the live
    /// `(client_epoch, backends)` tuple is a no-op ([`PublishOutcome::Unchanged`]);
    /// otherwise a new generation is reserved, built with its own gate, the old
    /// gate is revoked, and the new snapshot is swapped in atomically
    /// ([`PublishOutcome::Published`]). An authoritative empty topology is a normal
    /// publishable value.
    ///
    /// # Errors
    ///
    /// Returns [`GenerationOverflow`] if the last published generation was already
    /// [`u64::MAX`]. The increment is checked before any gate is revoked or swap
    /// performed, so on exhaustion the last-good snapshot is retained untouched.
    pub fn publish(
        &self,
        result: EpochResult<MergedTopology>,
    ) -> Result<PublishOutcome, GenerationOverflow> {
        let mut state = self.lock();
        if state.retired {
            return Ok(PublishOutcome::Retired);
        }
        let current = self.published.borrow().clone();
        if let Some(current) = &current {
            if result.client_epoch < current.client_epoch {
                return Ok(PublishOutcome::RejectedStale);
            }
            if result.client_epoch == current.client_epoch && result.value == current.backends {
                return Ok(PublishOutcome::Unchanged);
            }
        }
        // Reserve the generation first: building the snapshot cannot fail, so an
        // exhausted counter is refused here before any gate is revoked or swap
        // performed, leaving the last-good snapshot fully intact. The last-issued
        // value is incremented (not a pre-reserved next), so u64::MAX is itself
        // publishable and only the request after it fails.
        let generation = match state.last_generation {
            None => 1,
            Some(last) => last.checked_add(1).ok_or(GenerationOverflow)?,
        };
        let gate = GenerationGate::new();
        if let Some(current) = &current {
            current.gate.revoke();
        }
        self.published.send_replace(Some(Arc::new(RoutingSnapshot {
            generation,
            client_epoch: result.client_epoch,
            backends: result.value,
            gate,
        })));
        state.last_generation = Some(generation);
        Ok(PublishOutcome::Published { generation })
    }

    /// Withdraws the publication: marks the publisher terminal so any later publish
    /// is refused, revokes the current gate, then publishes `None` so every handle
    /// is fail-closed. Idempotent; also invoked by `Drop`.
    pub fn revoke_and_clear(&self) {
        let mut state = self.lock();
        state.retired = true;
        if let Some(current) = self.published.borrow().clone() {
            current.gate.revoke();
        }
        self.published.send_replace(None);
    }
}

/// A cheap-to-clone, generation-fenced reader of the published routing topology.
///
/// A consumer takes a snapshot with [`current`](Self::current), routes on it, and —
/// before committing a routing decision built from a retained `Arc` — re-validates
/// with [`still_current`](Self::still_current) so a retired generation never wins.
#[derive(Clone)]
pub struct RoutingSnapshotHandle {
    published: watch::Receiver<Option<Arc<RoutingSnapshot>>>,
}

impl RoutingSnapshotHandle {
    /// The currently published snapshot, or `None` when the source is fail-closed
    /// (nothing published yet, or withdrawn).
    #[must_use]
    pub fn current(&self) -> Option<Arc<RoutingSnapshot>> {
        self.published
            .borrow()
            .as_ref()
            .filter(|snapshot| snapshot.gate.is_live())
            .map(Arc::clone)
    }

    /// Whether `candidate` is still the live published generation.
    ///
    /// Authority is the published-`Arc` **identity** plus a live gate, never the
    /// `generation` number: a snapshot from a different publisher that happens to
    /// share a generation is rejected. The identity is confirmed first and the
    /// candidate's gate is read **last**, so a publisher that revokes the old gate
    /// before swapping in the new snapshot cannot be observed as still-current
    /// through the retired `Arc`. A consumer must re-check at its own side-effect
    /// boundary, since the answer can be invalidated the instant after it returns.
    #[must_use]
    pub fn still_current(&self, candidate: &Arc<RoutingSnapshot>) -> bool {
        self.still_current_between(candidate, || {})
    }

    /// The ordering-critical core of [`still_current`]: the published-`Arc`
    /// identity is resolved to a `bool` **first** (and its watch borrow released),
    /// then `between` runs, then the candidate's gate is read **last**. Production
    /// passes an empty `between`; a test injects a concurrent revoke there to prove
    /// the gate is read strictly after the identity, so a revoke landing in the
    /// revoke-before-swap window fails closed instead of leaking a stale `true`
    /// through the retired `Arc`.
    fn still_current_between(
        &self,
        candidate: &Arc<RoutingSnapshot>,
        between: impl FnOnce(),
    ) -> bool {
        let identity = self
            .published
            .borrow()
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, candidate));
        between();
        identity && candidate.gate.is_live()
    }

    /// Resolves once a routable (live-gated) snapshot has been published, returning
    /// it. Distinct from the module's `wait_ready`, which only signals discovery
    /// installation and does not wait on any actual topology pull.
    ///
    /// # Errors
    ///
    /// Returns [`RoutingSourceClosed`] if the publisher is dropped before any
    /// routable snapshot exists, so a waiter fails closed instead of treating the
    /// closure as readiness.
    pub async fn wait_first(&self) -> Result<Arc<RoutingSnapshot>, RoutingSourceClosed> {
        let mut receiver = self.published.clone();
        loop {
            let ready = receiver
                .borrow()
                .as_ref()
                .filter(|snapshot| snapshot.gate.is_live())
                .map(Arc::clone);
            if let Some(snapshot) = ready {
                return Ok(snapshot);
            }
            if receiver.changed().await.is_err() {
                return Err(RoutingSourceClosed);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use std::collections::BTreeMap;

    use super::{
        EpochResult, GenerationOverflow, MergedTopology, PublishOutcome, RoutingSnapshotPublisher,
        RoutingSourceClosed,
    };
    use crate::merge::MergedBackend;
    use crate::model::BackendInfo;

    /// A merged topology with one backend whose address distinguishes contents.
    fn topology(addr: &str) -> MergedTopology {
        MergedTopology {
            backends: vec![MergedBackend {
                backend_id: Arc::from(format!("cluster-a/{addr}")),
                cluster_name: Arc::from("cluster-a"),
                backend: BackendInfo {
                    addr: addr.to_owned(),
                    keyspace: String::new(),
                    ip: String::new(),
                    status_port: 0,
                    version: String::new(),
                    git_hash: String::new(),
                    deploy_path: String::new(),
                    start_timestamp: 0,
                    labels: BTreeMap::new(),
                },
            }],
        }
    }

    fn result(client_epoch: u64, value: MergedTopology) -> EpochResult<MergedTopology> {
        EpochResult {
            client_epoch,
            value,
        }
    }

    fn publish_ok(
        publisher: &RoutingSnapshotPublisher,
        client_epoch: u64,
        value: MergedTopology,
    ) -> PublishOutcome {
        publisher
            .publish(result(client_epoch, value))
            .unwrap_or_else(|GenerationOverflow| unreachable!("no overflow expected"))
    }

    #[test]
    fn a_fresh_publisher_is_fail_closed_with_no_snapshot() {
        let (_publisher, handle) = RoutingSnapshotPublisher::new();
        assert!(handle.current().is_none());
    }

    #[test]
    fn the_first_publish_of_an_empty_topology_is_generation_one() {
        let (publisher, handle) = RoutingSnapshotPublisher::new();
        let outcome = publish_ok(&publisher, 0, MergedTopology::default());
        assert_eq!(outcome, PublishOutcome::Published { generation: 1 });
        let current = handle
            .current()
            .unwrap_or_else(|| unreachable!("a snapshot is published"));
        assert_eq!(current.generation, 1);
        assert_eq!(current.client_epoch, 0);
        assert!(current.backends.backends.is_empty());
    }

    #[test]
    fn the_same_epoch_and_content_is_a_no_op() {
        let (publisher, handle) = RoutingSnapshotPublisher::new();
        publish_ok(&publisher, 4, topology("10.0.0.1:4000"));
        let before = handle
            .current()
            .unwrap_or_else(|| unreachable!("a snapshot is published"));

        let outcome = publish_ok(&publisher, 4, topology("10.0.0.1:4000"));
        assert_eq!(outcome, PublishOutcome::Unchanged);

        let after = handle
            .current()
            .unwrap_or_else(|| unreachable!("a snapshot is published"));
        assert_eq!(after.generation, 1);
        assert!(
            Arc::ptr_eq(&before, &after),
            "a no-op must not swap the Arc"
        );
    }

    #[test]
    fn the_same_epoch_with_changed_content_advances_the_generation() {
        let (publisher, handle) = RoutingSnapshotPublisher::new();
        publish_ok(&publisher, 4, topology("10.0.0.1:4000"));

        let outcome = publish_ok(&publisher, 4, topology("10.0.0.2:4000"));
        assert_eq!(outcome, PublishOutcome::Published { generation: 2 });
        let current = handle
            .current()
            .unwrap_or_else(|| unreachable!("a snapshot is published"));
        assert_eq!(current.generation, 2);
        assert_eq!(current.client_epoch, 4);
    }

    #[test]
    fn a_new_epoch_with_identical_content_advances_the_generation_and_revokes_the_old() {
        let (publisher, handle) = RoutingSnapshotPublisher::new();
        publish_ok(&publisher, 4, topology("10.0.0.1:4000"));
        let old = handle
            .current()
            .unwrap_or_else(|| unreachable!("a snapshot is published"));

        // Byte-identical backends, but a newer plan epoch: must mint + swap so the
        // published provenance is never stale.
        let outcome = publish_ok(&publisher, 5, topology("10.0.0.1:4000"));
        assert_eq!(outcome, PublishOutcome::Published { generation: 2 });

        let current = handle
            .current()
            .unwrap_or_else(|| unreachable!("a snapshot is published"));
        assert_eq!(current.generation, 2);
        assert_eq!(current.client_epoch, 5);
        assert!(!old.gate.is_live(), "the superseded gate must be revoked");
        assert!(
            !handle.still_current(&old),
            "the old Arc is no longer current"
        );
        assert!(handle.still_current(&current));
    }

    #[test]
    fn an_older_source_epoch_is_rejected() {
        let (publisher, handle) = RoutingSnapshotPublisher::new();
        publish_ok(&publisher, 5, topology("10.0.0.1:4000"));
        let current = handle
            .current()
            .unwrap_or_else(|| unreachable!("a snapshot is published"));

        let outcome = publish_ok(&publisher, 4, topology("10.0.0.9:4000"));
        assert_eq!(outcome, PublishOutcome::RejectedStale);

        let after = handle
            .current()
            .unwrap_or_else(|| unreachable!("a snapshot is published"));
        assert!(
            Arc::ptr_eq(&current, &after),
            "a rejected result must not swap the Arc"
        );
        assert_eq!(after.client_epoch, 5);
    }

    #[test]
    fn the_max_generation_is_itself_publishable() {
        let (publisher, handle) = RoutingSnapshotPublisher::new();
        publish_ok(&publisher, 4, topology("10.0.0.1:4000"));
        publisher.set_last_generation(Some(u64::MAX - 1));

        let outcome = publish_ok(&publisher, 4, topology("10.0.0.2:4000"));
        assert_eq!(
            outcome,
            PublishOutcome::Published {
                generation: u64::MAX
            }
        );
        let current = handle
            .current()
            .unwrap_or_else(|| unreachable!("a snapshot is published"));
        assert_eq!(current.generation, u64::MAX);
    }

    #[test]
    fn a_request_after_the_max_generation_is_refused_and_retains_the_live_snapshot() {
        let (publisher, handle) = RoutingSnapshotPublisher::new();
        publish_ok(&publisher, 4, topology("10.0.0.1:4000"));
        publisher.set_last_generation(Some(u64::MAX));
        let live = handle
            .current()
            .unwrap_or_else(|| unreachable!("a snapshot is published"));

        let overflow = publisher.publish(result(4, topology("10.0.0.2:4000")));
        assert_eq!(overflow, Err(GenerationOverflow));

        let after = handle
            .current()
            .unwrap_or_else(|| unreachable!("the live snapshot is retained"));
        assert!(
            Arc::ptr_eq(&live, &after),
            "an exhausted counter must not swap the Arc"
        );
        assert!(live.gate.is_live(), "the live gate must not be revoked");
    }

    #[test]
    fn a_sibling_publishers_snapshot_of_the_same_generation_is_not_current() {
        let (publisher_a, handle_a) = RoutingSnapshotPublisher::new();
        let (publisher_b, _handle_b) = RoutingSnapshotPublisher::new();
        publish_ok(&publisher_a, 0, topology("10.0.0.1:4000"));
        publish_ok(&publisher_b, 0, topology("10.0.0.1:4000"));

        let sibling = publisher_b
            .handle()
            .current()
            .unwrap_or_else(|| unreachable!("b published a snapshot"));
        assert_eq!(sibling.generation, 1);
        assert!(sibling.gate.is_live());
        assert!(
            !handle_a.still_current(&sibling),
            "a same-generation snapshot from another publisher must be rejected"
        );
    }

    #[test]
    fn a_published_snapshot_with_a_revoked_gate_is_not_current() {
        // The identity-match/gate-dead state a concurrent revoke-before-swap opens:
        // still_current must reject it (gate checked after identity).
        let (publisher, handle) = RoutingSnapshotPublisher::new();
        publish_ok(&publisher, 4, topology("10.0.0.1:4000"));
        let snapshot = handle
            .current()
            .unwrap_or_else(|| unreachable!("a snapshot is published"));

        publisher.revoke_published_gate();
        assert!(
            !handle.still_current(&snapshot),
            "a revoked gate must fail the identity-matched Arc closed"
        );
    }

    #[test]
    fn still_current_reads_the_gate_strictly_after_the_identity() {
        // Model the revoke-before-swap window: a writer revokes the gate BETWEEN the
        // identity read and the gate read, while the watch still points at the old
        // Arc. An identity-first / gate-last order sees the fresh revoke and fails
        // closed; a gate-first order would have latched `live == true` and leaked a
        // stale `true` through the retired Arc.
        let (publisher, handle) = RoutingSnapshotPublisher::new();
        publish_ok(&publisher, 4, topology("10.0.0.1:4000"));
        let snapshot = handle
            .current()
            .unwrap_or_else(|| unreachable!("a snapshot is published"));

        let observed =
            handle.still_current_between(&snapshot, || publisher.revoke_published_gate());
        assert!(
            !observed,
            "a revoke between the identity and gate reads must fail closed"
        );
    }

    #[test]
    fn revoke_and_clear_fails_closed_and_revokes_the_gate() {
        let (publisher, handle) = RoutingSnapshotPublisher::new();
        publish_ok(&publisher, 4, topology("10.0.0.1:4000"));
        let live = handle
            .current()
            .unwrap_or_else(|| unreachable!("a snapshot is published"));

        publisher.revoke_and_clear();
        assert!(handle.current().is_none(), "the handle is fail-closed");
        assert!(!live.gate.is_live(), "the withdrawn gate must be revoked");
        assert!(!handle.still_current(&live));
    }

    #[test]
    fn a_publish_after_withdrawal_is_refused_and_stays_fail_closed() {
        let (publisher, handle) = RoutingSnapshotPublisher::new();
        publish_ok(&publisher, 4, topology("10.0.0.1:4000"));
        let old = handle
            .current()
            .unwrap_or_else(|| unreachable!("a snapshot is published"));
        publisher.revoke_and_clear();

        // A late result must not resurrect a withdrawn source.
        let outcome = publish_ok(&publisher, 9, topology("10.0.0.2:4000"));
        assert_eq!(outcome, PublishOutcome::Retired);
        assert!(handle.current().is_none(), "the source stays withdrawn");
        assert!(!old.gate.is_live());
    }

    #[test]
    fn dropping_the_publisher_withdraws_authority() {
        let (publisher, handle) = RoutingSnapshotPublisher::new();
        publish_ok(&publisher, 4, topology("10.0.0.1:4000"));
        let retained = handle
            .current()
            .unwrap_or_else(|| unreachable!("a snapshot is published"));

        drop(publisher);
        assert!(
            handle.current().is_none(),
            "a dropped publisher leaves the handle fail-closed"
        );
        assert!(
            !retained.gate.is_live(),
            "a retained Arc's gate must die with the publisher"
        );
    }

    #[tokio::test]
    async fn wait_first_resolves_with_the_live_snapshot() {
        let (publisher, handle) = RoutingSnapshotPublisher::new();
        let waiter = tokio::spawn(async move { handle.wait_first().await });
        publish_ok(&publisher, 7, topology("10.0.0.1:4000"));
        let snapshot = tokio::time::timeout(Duration::from_secs(5), waiter)
            .await
            .unwrap_or_else(|_| unreachable!("wait_first must resolve after a publish"))
            .unwrap_or_else(|error| unreachable!("waiter task panicked: {error}"))
            .unwrap_or_else(|RoutingSourceClosed| unreachable!("a live snapshot was published"));
        assert_eq!(snapshot.client_epoch, 7);
    }

    #[tokio::test]
    async fn wait_first_skips_a_revoked_some_and_resolves_on_the_next_live_snapshot() {
        let (publisher, handle) = RoutingSnapshotPublisher::new();
        publish_ok(&publisher, 4, topology("10.0.0.1:4000"));
        publisher.revoke_published_gate(); // a Some whose gate is already dead

        let waiter = tokio::spawn(async move { handle.wait_first().await });
        // Let the waiter observe the revoked Some and park on `changed()` before the
        // next publish; on the current-thread runtime this ordering is deterministic.
        tokio::task::yield_now().await;
        publish_ok(&publisher, 5, topology("10.0.0.2:4000")); // a live snapshot

        // It must resolve with the LIVE generation (epoch 5), never the revoked Some
        // (epoch 4) it saw first.
        let snapshot = tokio::time::timeout(Duration::from_secs(5), waiter)
            .await
            .unwrap_or_else(|_| unreachable!("wait_first must resolve after a live publish"))
            .unwrap_or_else(|error| unreachable!("waiter task panicked: {error}"))
            .unwrap_or_else(|RoutingSourceClosed| unreachable!("a live snapshot was published"));
        assert_eq!(
            snapshot.client_epoch, 5,
            "a revoked Some must not be reported as ready"
        );
    }

    #[tokio::test]
    async fn wait_first_fails_closed_when_the_source_closes_unpublished() {
        let (publisher, handle) = RoutingSnapshotPublisher::new();
        let waiter = tokio::spawn(async move { handle.wait_first().await });
        // Never published: dropping the publisher must surface as a closed source,
        // not a spurious success.
        drop(publisher);
        let result = tokio::time::timeout(Duration::from_secs(5), waiter)
            .await
            .unwrap_or_else(|_| unreachable!("wait_first must resolve on source close"))
            .unwrap_or_else(|error| unreachable!("waiter task panicked: {error}"));
        assert!(
            matches!(result, Err(RoutingSourceClosed)),
            "an unpublished close must fail closed"
        );
    }
}
