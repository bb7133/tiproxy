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

//! Generation-fenced backend-health overlay for CP-TOPO #213-2.
//!
//! A [`HealthSnapshot`] is one whole-map health verdict for the backends of one
//! exact [`RoutingSnapshot`] generation. It is immutable and `Arc`-shared, and it
//! is paired to its routing source by `Arc` identity — never by a generation
//! number — so a verdict computed for one routing generation can never be read as
//! authority for another.
//!
//! Authority is layered exactly like [`RoutingSnapshotHandle`]: the overlay
//! carries its own revocable [`GenerationGate`], revoked the instant a newer
//! round is published or the source is cleared, and a consumer must re-validate
//! at its own side-effect boundary with
//! [`HealthOverlayHandle::still_current_for`], which re-checks the *currently
//! published* overlay identity (not merely the routing source). A raw `current()`
//! that bypasses the source is deliberately never exposed: a candidate obtained
//! from [`HealthOverlayHandle::current_for`] only becomes authority after the
//! unbypassable [`still_current_for`](HealthOverlayHandle::still_current_for)
//! recheck.
//!
//! A backend id absent from a snapshot's map is treated by consumers as
//! **fail-closed unhealthy** — [`HealthSnapshot::get`] returns an unhealthy
//! verdict for an unknown id — so a partial or mis-keyed map can never surface a
//! backend as healthy by omission.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use control_external::GenerationGate;
use control_plane::OwnerToken;

use crate::backend_health::BackendHealth;
use crate::routing_snapshot::{RoutingSnapshot, RoutingSnapshotHandle};

/// One immutable, generation-fenced health verdict for the backends of one exact
/// [`RoutingSnapshot`] generation.
///
/// It is paired to its routing source by `Arc` identity: the private `source`
/// `Arc` is the only thing that makes this snapshot authoritative for a routing
/// generation, and the private [`GenerationGate`] is revoked when a newer round
/// supersedes it. Neither is exposed; a consumer reaches a verdict only through
/// [`HealthOverlayHandle`], which enforces the source pairing.
pub struct HealthSnapshot {
    /// The exact routing generation this verdict was computed for. Private: the
    /// pairing is enforced through [`HealthOverlayHandle`], never by a caller
    /// reading the source directly.
    source: Arc<RoutingSnapshot>,
    /// This round's revocable authority, revoked when a newer round is published
    /// or the overlay is cleared. Private, like [`RoutingSnapshot`]'s gate.
    gate: GenerationGate,
    /// The feed generation's gate, cloned in at publish time. A feed transition
    /// (set/withdraw/close) revokes it synchronously, so this overlay loses
    /// authority the instant the transition returns — before the loop physically
    /// clears the overlay.
    feed_gate: GenerationGate,
    /// The process owner this verdict was produced under. An owner (lease) release
    /// makes this overlay lose authority synchronously — without waiting for the
    /// loop to poll — because it is re-checked at the end of every authority path.
    owner: OwnerToken,
    /// The whole-map verdict, keyed by `backend_id`. A missing id is fail-closed
    /// unhealthy at [`Self::get`].
    health: HashMap<Arc<str>, BackendHealth>,
}

impl HealthSnapshot {
    /// The health verdict for `backend_id`, **fail-closed** unhealthy when the id
    /// is absent from this round's map.
    ///
    /// An absent id is never healthy-by-omission: a backend that was not probed,
    /// or a map that does not key this backend, reads as `healthy = false` with no
    /// version, so a consumer can only ever act on an explicit healthy verdict.
    #[must_use]
    pub fn get(&self, backend_id: &str) -> BackendHealth {
        self.health
            .get(backend_id)
            .cloned()
            .unwrap_or(BackendHealth {
                healthy: false,
                server_version: None,
                local: false,
            })
    }
}

/// The outcome of a [`HealthOverlayPublisher::publish_round`] call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HealthPublishOutcome {
    /// A new round was minted, the previous round's gate revoked, and the new
    /// snapshot swapped in atomically.
    Published,
    /// The publisher has been terminally withdrawn
    /// ([`HealthOverlayPublisher::revoke_and_clear`]); the round is refused and no
    /// snapshot is revived.
    Retired,
}

/// A cheap-to-clone, generation-fenced reader of the published health overlay.
///
/// A consumer takes a *candidate* with [`current_for`](Self::current_for), and —
/// before any side effect built from it — re-validates with
/// [`still_current_for`](Self::still_current_for), which is the only path to
/// authority. There is deliberately no raw `current()`: a verdict is meaningless
/// without the routing source it was computed for.
#[derive(Clone)]
pub struct HealthOverlayHandle {
    published: tokio::sync::watch::Receiver<Option<Arc<HealthSnapshot>>>,
}

impl HealthOverlayHandle {
    /// Test waits observe actual publication instead of counting scheduler yields.
    #[cfg(test)]
    pub(crate) async fn changed(&mut self) -> Result<(), tokio::sync::watch::error::RecvError> {
        self.published.changed().await
    }

    /// The currently published overlay **candidate** for routing source `r`, or
    /// `None`.
    ///
    /// A candidate is yielded IFF a snapshot is published whose `source` is
    /// `Arc`-identical to `r`, whose own round gate is live, whose feed gate is
    /// live (a feed transition revokes it synchronously), whose producing process
    /// owner is still current (a lease release fails it closed synchronously), and
    /// whose paired routing source `r` is itself still live. This is only a
    /// candidate: the caller must
    /// still pass it (with `r`) through
    /// [`still_current_for`](Self::still_current_for) at its side-effect boundary,
    /// since the answer can be invalidated the instant after it returns.
    #[must_use]
    pub fn current_for(&self, r: &Arc<RoutingSnapshot>) -> Option<Arc<HealthSnapshot>> {
        if !r.source_gate().is_live() {
            return None;
        }
        self.published
            .borrow()
            .as_ref()
            .filter(|health| {
                Arc::ptr_eq(&health.source, r)
                    && health.gate.is_live()
                    && health.feed_gate.is_live()
                    && health.owner.is_current()
            })
            .map(Arc::clone)
    }

    /// The unbypassable pre-side-effect authority check: whether `h` is still the
    /// live overlay for routing source `r`.
    ///
    /// True IFF the **currently published** overlay is `Arc`-identical to `h`
    /// (never a foreign or superseded snapshot that merely shares a source or a
    /// generation number), `h`'s `source` is `Arc`-identical to `r`, the paired
    /// routing generation is still current
    /// ([`RoutingSnapshotHandle::still_current`]), `h`'s own round gate is live,
    /// `h`'s feed gate is live (revoked synchronously by a feed transition), and
    /// `h`'s producing process owner is still current (a lease release fails it
    /// closed synchronously). The published-identity is resolved first and the
    /// gates read last, mirroring
    /// [`RoutingSnapshotHandle::still_current`], so a revoke landing in the
    /// revoke-before-swap window fails closed. This deliberately does **not**
    /// re-check only the routing source: a retained `h` superseded by a newer
    /// same-source round, or invalidated by a feed transition, is rejected here
    /// even while `r` is still current.
    #[must_use]
    pub fn still_current_for(
        &self,
        h: &Arc<HealthSnapshot>,
        r: &Arc<RoutingSnapshot>,
        routing: &RoutingSnapshotHandle,
    ) -> bool {
        let identity = self
            .published
            .borrow()
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, h));
        identity
            && Arc::ptr_eq(&h.source, r)
            && routing.still_current(r)
            && h.gate.is_live()
            && h.feed_gate.is_live()
            && h.owner.is_current()
    }
}

/// The publisher's serialised terminal state.
struct OverlayState {
    /// Set once the overlay is terminally withdrawn; every later round is refused
    /// and no snapshot is revived.
    retired: bool,
}

/// The single-writer publisher of [`HealthSnapshot`]s.
///
/// It publishes one whole-map snapshot per completed round, revoking the previous
/// round's gate at each swap so a retained overlay loses authority immediately.
/// Its `Drop` is a same-order terminal backstop, so authority never outlives the
/// owner.
pub(crate) struct HealthOverlayPublisher {
    published: tokio::sync::watch::Sender<Option<Arc<HealthSnapshot>>>,
    state: Mutex<OverlayState>,
}

impl Drop for HealthOverlayPublisher {
    fn drop(&mut self) {
        // Same-order terminal backstop: never leave a consumer holding live
        // authority once the publisher is gone.
        self.revoke_and_clear();
    }
}

impl HealthOverlayPublisher {
    /// Builds a publisher (no round published yet) and the first handle reading
    /// it.
    pub(crate) fn new() -> (Self, HealthOverlayHandle) {
        let (published, receiver) = tokio::sync::watch::channel(None);
        (
            Self {
                published,
                state: Mutex::new(OverlayState { retired: false }),
            },
            HealthOverlayHandle {
                published: receiver,
            },
        )
    }

    /// A fresh handle onto this publisher, for an additional consumer. Test-only:
    /// production surfaces the single handle minted alongside the publisher.
    #[cfg(test)]
    pub(crate) fn handle(&self) -> HealthOverlayHandle {
        HealthOverlayHandle {
            published: self.published.subscribe(),
        }
    }

    fn lock(&self) -> MutexGuard<'_, OverlayState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Publishes one completed round's whole verdict map for the exact routing
    /// `source`.
    ///
    /// A withdrawn publisher refuses the round ([`HealthPublishOutcome::Retired`])
    /// and revives nothing. Otherwise a new snapshot is built with its own live
    /// round gate and the caller's `feed_gate` (the feed generation's gate, so a
    /// later feed transition invalidates this overlay synchronously), the previous
    /// published round's gate is revoked, and the new snapshot is swapped in with a
    /// single `send_replace` — one whole-map publish per round.
    pub(crate) fn publish_round(
        &self,
        source: &Arc<RoutingSnapshot>,
        health: HashMap<Arc<str>, BackendHealth>,
        feed_gate: GenerationGate,
        owner: &OwnerToken,
    ) -> HealthPublishOutcome {
        let state = self.lock();
        if state.retired {
            return HealthPublishOutcome::Retired;
        }
        let new = Arc::new(HealthSnapshot {
            source: Arc::clone(source),
            gate: GenerationGate::new(),
            feed_gate,
            owner: owner.clone(),
            health,
        });
        // Revoke the PREVIOUS published round's gate so a retained overlay loses
        // authority immediately, then swap the new snapshot in atomically.
        let previous = self.published.borrow().clone();
        if let Some(previous) = &previous {
            previous.gate.revoke();
        }
        self.published.send_replace(Some(new));
        HealthPublishOutcome::Published
    }

    /// Clears the overlay to `None`, revoking the current round's gate, but stays
    /// **non-terminal**: a later [`publish_round`](Self::publish_round) still
    /// works. Used on a rotation or withdrawal where a fresh round is expected to
    /// republish, so a retained overlay loses authority the instant the source is
    /// superseded.
    pub(crate) fn transient_clear(&self) {
        let _state = self.lock();
        let previous = self.published.borrow().clone();
        if let Some(previous) = &previous {
            previous.gate.revoke();
        }
        self.published.send_replace(None);
    }

    /// Terminally withdraws the overlay: marks it retired so any later round is
    /// refused, revokes the current gate, then clears the watch to `None`.
    /// Idempotent; also invoked by `Drop`.
    pub(crate) fn revoke_and_clear(&self) {
        let mut state = self.lock();
        state.retired = true;
        let previous = self.published.borrow().clone();
        if let Some(previous) = &previous {
            previous.gate.revoke();
        }
        self.published.send_replace(None);
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, HashMap};
    use std::sync::Arc;

    use control_external::GenerationGate;
    use control_plane::{OwnerLease, OwnerScope, OwnerToken, OwnershipRegistry};

    use super::{HealthOverlayPublisher, HealthPublishOutcome};
    use crate::backend_health::BackendHealth;
    use crate::discovery_publish::EpochResult;
    use crate::merge::{MergedBackend, MergedTopology};
    use crate::model::BackendInfo;
    use crate::routing_snapshot::{
        RoutingSnapshot, RoutingSnapshotHandle, RoutingSnapshotPublisher,
    };

    /// A claimed process-owner lease and its registry, both held so `token()`
    /// stays current; a test drops the lease to model an owner release.
    fn owner_lease() -> (OwnershipRegistry, OwnerLease) {
        let registry = OwnershipRegistry::new();
        let lease = registry
            .claim(OwnerScope::Process, "overlay-test")
            .unwrap_or_else(|error| unreachable!("claim: {error}"));
        (registry, lease)
    }

    /// A process owner that stays current for the whole test binary (registry and
    /// lease leaked), so a happy-path publish/authority assertion runs under a live
    /// owner without the test threading a lease.
    fn live_owner() -> OwnerToken {
        let registry = Box::leak(Box::new(OwnershipRegistry::new()));
        let lease = registry
            .claim(OwnerScope::Process, "overlay-live-owner")
            .unwrap_or_else(|error| unreachable!("claim: {error}"));
        let owner = lease.token();
        let _leaked: &'static OwnerLease = Box::leak(Box::new(lease));
        owner
    }

    /// One merged backend under `cluster-a` with a distinguishable address.
    fn merged_backend(addr: &str) -> MergedBackend {
        MergedBackend {
            backend_id: Arc::from(format!("cluster-a/{addr}").as_str()),
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
        }
    }

    /// Publishes one single-backend generation and returns the publisher (held so
    /// its `Drop` does not revoke the gate), its handle, the live source, and a
    /// leaked live process owner (so a happy-path publish is authoritative).
    fn published_source(
        client_epoch: u64,
        addr: &str,
    ) -> (
        RoutingSnapshotPublisher,
        RoutingSnapshotHandle,
        Arc<RoutingSnapshot>,
        OwnerToken,
    ) {
        let (publisher, handle) = RoutingSnapshotPublisher::new();
        publisher
            .publish(EpochResult {
                client_epoch,
                value: MergedTopology {
                    backends: vec![merged_backend(addr)],
                },
            })
            .unwrap_or_else(|_| unreachable!("first publish"));
        let source = handle
            .current()
            .unwrap_or_else(|| unreachable!("a snapshot is published"));
        (publisher, handle, source, live_owner())
    }

    fn healthy_map(source: &Arc<RoutingSnapshot>) -> HashMap<Arc<str>, BackendHealth> {
        source
            .backends
            .backends
            .iter()
            .map(|backend| {
                (
                    Arc::clone(&backend.backend_id),
                    BackendHealth {
                        healthy: true,
                        server_version: Some("v8".to_owned()),
                        local: false,
                    },
                )
            })
            .collect()
    }

    // ================================================================
    // Snapshot getter: fail-closed on an unknown backend id.
    // ================================================================

    #[test]
    fn an_unknown_backend_id_is_fail_closed_unhealthy() {
        let (_publisher, _handle, source, owner) = published_source(1, "10.0.0.1:4000");
        let (overlay, overlay_handle) = HealthOverlayPublisher::new();
        overlay.publish_round(&source, healthy_map(&source), GenerationGate::new(), &owner);
        let published = overlay_handle
            .current_for(&source)
            .unwrap_or_else(|| unreachable!("a round is published for the source"));
        let known = published.get("cluster-a/10.0.0.1:4000");
        assert!(known.healthy, "the probed backend is healthy");
        let unknown = published.get("cluster-a/does-not-exist:4000");
        assert!(
            !unknown.healthy && unknown.server_version.is_none(),
            "an unknown id is fail-closed unhealthy, never healthy by omission"
        );
    }

    // ================================================================
    // A1: a foreign publisher's snapshot (different Arc) is rejected.
    // ================================================================

    #[test]
    fn a_foreign_overlay_snapshot_is_rejected_by_authority() {
        let (_publisher, routing, source, owner) = published_source(1, "10.0.0.1:4000");
        let (overlay_a, handle_a) = HealthOverlayPublisher::new();
        let (overlay_b, _handle_b) = HealthOverlayPublisher::new();

        overlay_a.publish_round(&source, healthy_map(&source), GenerationGate::new(), &owner);
        // A foreign publisher B publishes for the SAME routing source: a distinct
        // Arc that shares the source and is live.
        overlay_b.publish_round(&source, healthy_map(&source), GenerationGate::new(), &owner);
        let foreign = overlay_b
            .handle()
            .current_for(&source)
            .unwrap_or_else(|| unreachable!("b published a round"));

        // A's own candidate is A's snapshot, not the foreign one.
        let mine = handle_a
            .current_for(&source)
            .unwrap_or_else(|| unreachable!("a published a round"));
        assert!(
            !Arc::ptr_eq(&mine, &foreign),
            "the two publishers minted distinct snapshots"
        );
        // The foreign snapshot is never this handle's authority, even though it
        // shares the source and is live.
        assert!(
            !handle_a.still_current_for(&foreign, &source, &routing),
            "a foreign publisher's snapshot is rejected by published-Arc identity"
        );
    }

    // ================================================================
    // A2: the previous round's gate is revoked on the next publish.
    // ================================================================

    #[test]
    fn the_previous_round_gate_is_revoked_on_the_next_round() {
        let (_publisher, routing, source, owner) = published_source(1, "10.0.0.1:4000");
        let (overlay, handle) = HealthOverlayPublisher::new();

        overlay.publish_round(&source, healthy_map(&source), GenerationGate::new(), &owner);
        let first = handle
            .current_for(&source)
            .unwrap_or_else(|| unreachable!("the first round is published"));
        assert!(
            first.gate.is_live(),
            "the first round is live once published"
        );

        // A second same-source round must revoke the retained first round's gate,
        // so a consumer holding the first snapshot loses authority at once.
        overlay.publish_round(&source, healthy_map(&source), GenerationGate::new(), &owner);
        assert!(
            !first.gate.is_live(),
            "the previous round's gate is revoked by the next publish"
        );
        assert!(
            !handle.still_current_for(&first, &source, &routing),
            "the retained first snapshot is no longer authority"
        );
    }

    // ================================================================
    // A5: still_current_for re-checks the published overlay, not only routing.
    // ================================================================

    #[test]
    fn still_current_for_rechecks_the_published_overlay_not_only_routing() {
        let (_publisher, routing, source, owner) = published_source(1, "10.0.0.1:4000");
        let (overlay, handle) = HealthOverlayPublisher::new();

        overlay.publish_round(&source, healthy_map(&source), GenerationGate::new(), &owner);
        let captured = handle
            .current_for(&source)
            .unwrap_or_else(|| unreachable!("the first round is a candidate"));

        // A newer SAME-source round supersedes the captured one; the routing
        // source is untouched, so `routing.still_current(&source)` is still true.
        overlay.publish_round(&source, healthy_map(&source), GenerationGate::new(), &owner);
        assert!(
            routing.still_current(&source),
            "the routing source is unchanged by an overlay round"
        );
        // A routing-only recheck would wrongly accept the captured snapshot; the
        // real check rejects it because the published overlay is a different Arc.
        assert!(
            !handle.still_current_for(&captured, &source, &routing),
            "a superseded same-source overlay is rejected even with a live routing source"
        );
    }

    // ================================================================
    // A4: a late publish after revoke_and_clear is Retired and never revives.
    // ================================================================

    #[test]
    fn a_late_round_after_revoke_and_clear_is_retired() {
        let (_publisher, routing, source, owner) = published_source(1, "10.0.0.1:4000");
        let (overlay, handle) = HealthOverlayPublisher::new();

        overlay.publish_round(&source, healthy_map(&source), GenerationGate::new(), &owner);
        let live = handle
            .current_for(&source)
            .unwrap_or_else(|| unreachable!("the first round is published"));

        overlay.revoke_and_clear();
        assert!(
            !handle.still_current_for(&live, &source, &routing),
            "the withdrawn overlay is no longer authority"
        );
        assert!(
            handle.current_for(&source).is_none(),
            "the overlay is cleared"
        );

        // A late round must not resurrect a terminally-withdrawn overlay.
        let outcome =
            overlay.publish_round(&source, healthy_map(&source), GenerationGate::new(), &owner);
        assert_eq!(outcome, HealthPublishOutcome::Retired);
        assert!(
            handle.current_for(&source).is_none(),
            "a retired publisher stays fail-closed after a late round"
        );
    }

    // ================================================================
    // transient_clear is non-terminal: a later round republishes.
    // ================================================================

    #[test]
    fn transient_clear_is_non_terminal_and_a_later_round_republishes() {
        let (_publisher, _routing, source, owner) = published_source(1, "10.0.0.1:4000");
        let (overlay, handle) = HealthOverlayPublisher::new();

        overlay.publish_round(&source, healthy_map(&source), GenerationGate::new(), &owner);
        let first = handle
            .current_for(&source)
            .unwrap_or_else(|| unreachable!("the first round is published"));

        overlay.transient_clear();
        assert!(
            !first.gate.is_live(),
            "transient_clear revokes the current gate"
        );
        assert!(
            handle.current_for(&source).is_none(),
            "the overlay is cleared"
        );

        // Non-terminal: a fresh round republishes a live overlay.
        let outcome =
            overlay.publish_round(&source, healthy_map(&source), GenerationGate::new(), &owner);
        assert_eq!(outcome, HealthPublishOutcome::Published);
        assert!(
            handle.current_for(&source).is_some(),
            "a round after a transient clear republishes"
        );
    }

    // ================================================================
    // current_for requires a live routing source and an exact-source pairing.
    // ================================================================

    #[test]
    fn current_for_requires_a_live_paired_routing_source() {
        let (publisher, _routing, source, owner) = published_source(1, "10.0.0.1:4000");
        let (overlay, handle) = HealthOverlayPublisher::new();
        overlay.publish_round(&source, healthy_map(&source), GenerationGate::new(), &owner);
        assert!(handle.current_for(&source).is_some(), "paired and live");

        // A sibling source (different Arc) is never this overlay's pairing.
        let (_publisher_b, _routing_b, sibling, _owner_b) = published_source(1, "10.0.0.1:4000");
        assert!(
            handle.current_for(&sibling).is_none(),
            "a sibling routing Arc is not the overlay's paired source"
        );

        // Revoking the routing source's own gate fails the candidate closed.
        publisher.revoke_and_clear();
        assert!(
            handle.current_for(&source).is_none(),
            "a revoked routing source yields no candidate"
        );
    }

    // ================================================================
    // Feed gate: a feed transition revokes overlay authority synchronously.
    // ================================================================

    #[test]
    fn a_revoked_feed_gate_invalidates_the_overlay() {
        let (_publisher, routing, source, owner) = published_source(1, "10.0.0.1:4000");
        let (overlay, handle) = HealthOverlayPublisher::new();

        // Publish under an explicit feed gate (as the feed loop does with the
        // generation's slot gate).
        let feed_gate = GenerationGate::new();
        overlay.publish_round(&source, healthy_map(&source), feed_gate.clone(), &owner);
        let h = handle
            .current_for(&source)
            .unwrap_or_else(|| unreachable!("the round is published"));
        assert!(
            handle.still_current_for(&h, &source, &routing),
            "authority holds while every gate is live"
        );

        // A feed transition revokes the feed gate: authority dies SYNCHRONOUSLY,
        // even though the round gate, source identity, and routing are all live.
        feed_gate.revoke();
        assert!(
            handle.current_for(&source).is_none(),
            "current_for rejects a revoked feed gate"
        );
        assert!(
            !handle.still_current_for(&h, &source, &routing),
            "still_current_for rejects a revoked feed gate"
        );
    }

    // ================================================================
    // Owner authority: an owner (lease) release invalidates the overlay
    // synchronously, with no clock advance and no feed change.
    // ================================================================

    #[test]
    fn a_released_owner_lease_makes_current_for_none() {
        let (_publisher, _routing, source, _leaked) = published_source(1, "10.0.0.1:4000");
        let (_registry, lease) = owner_lease();
        let owner = lease.token();
        let (overlay, handle) = HealthOverlayPublisher::new();

        overlay.publish_round(&source, healthy_map(&source), GenerationGate::new(), &owner);
        assert!(
            handle.current_for(&source).is_some(),
            "published under a live owner"
        );

        // Release the owner lease: authority dies SYNCHRONOUSLY.
        drop(lease);
        assert!(
            handle.current_for(&source).is_none(),
            "current_for rejects a released owner"
        );
    }

    #[test]
    fn a_released_owner_lease_makes_still_current_for_false() {
        let (_publisher, routing, source, _leaked) = published_source(1, "10.0.0.1:4000");
        let (_registry, lease) = owner_lease();
        let owner = lease.token();
        let (overlay, handle) = HealthOverlayPublisher::new();

        overlay.publish_round(&source, healthy_map(&source), GenerationGate::new(), &owner);
        let h = handle
            .current_for(&source)
            .unwrap_or_else(|| unreachable!("published under a live owner"));
        assert!(handle.still_current_for(&h, &source, &routing));

        // Release the owner lease: authority dies SYNCHRONOUSLY.
        drop(lease);
        assert!(
            !handle.still_current_for(&h, &source, &routing),
            "still_current_for rejects a released owner"
        );
    }

    // ================================================================
    // dev2 layered closure: a stale swap under an already-revoked feed gate is
    // never current authority (an honest outcome lock, not a lock-hold mutation).
    // ================================================================

    #[test]
    fn a_stale_swap_under_a_revoked_feed_gate_is_never_current() {
        let (_publisher, routing, source, owner) = published_source(1, "10.0.0.1:4000");
        let (overlay, handle) = HealthOverlayPublisher::new();

        // A first live round, captured as a retained consumer handle.
        overlay.publish_round(&source, healthy_map(&source), GenerationGate::new(), &owner);
        let live = handle
            .current_for(&source)
            .unwrap_or_else(|| unreachable!("the live round is published"));
        assert!(handle.still_current_for(&live, &source, &routing));

        // A stale swap: publish under a feed gate that was ALREADY revoked (the feed
        // transitioned before this swap landed).
        let dead_feed_gate = GenerationGate::new();
        dead_feed_gate.revoke();
        overlay.publish_round(&source, healthy_map(&source), dead_feed_gate, &owner);

        // The stale swap is never current authority.
        assert!(
            handle.current_for(&source).is_none(),
            "a swap under an already-revoked feed gate is never current"
        );
        // And the prior live round it superseded is also no longer current.
        assert!(
            !handle.still_current_for(&live, &source, &routing),
            "the superseded prior round is no longer current"
        );
    }
}
