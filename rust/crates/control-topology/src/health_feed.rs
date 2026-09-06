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

//! Lock-guarded health-generation feed (CP-TOPO #213-2).
//!
//! This replaces a raw `watch` generation channel so the health loop's
//! final-publish authority check and the overlay swap are ONE critical section
//! shared with the generation transition. A raw `watch::Ref` cannot serialise the
//! last-`Sender` *Drop* (close), so a terminal close could land between reading
//! the open state and publishing, and republish a stale map after teardown.
//!
//! The feed is a single [`Mutex`]-guarded [`FeedSlot`] plus a change [`Notify`].
//! The UNIQUE, non-`Clone` [`HealthGenerationFeeder`] owns the write side; every
//! `set`/`withdraw`/`close` **synchronously revokes the current slot gate** first,
//! so a retained published overlay (which carries a clone of that gate) loses
//! authority the instant the transition returns — before the loop physically
//! clears it. [`HealthGenerationFeed`] is the shareable read/loop side, and
//! [`HealthGenerationFeed::publish_current`] performs the atomic exact-generation
//! check and overlay publish while STILL holding the slot lock (lock order
//! feed → overlay, never the reverse).

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use control_external::GenerationGate;
use tokio::sync::Notify;

use crate::health_loop::HealthGeneration;

/// The feed's serialised slot: the current generation, its revocable feed gate, a
/// monotonic revision, and the terminal flags.
struct FeedSlot {
    /// The current generation, or `None` when withdrawn/closed.
    generation: Option<Arc<HealthGeneration>>,
    /// The current generation's revocable feed gate. A published overlay embeds a
    /// clone of it, so revoking it kills that overlay's authority synchronously.
    gate: Option<GenerationGate>,
    /// A monotonic change counter; a reader waits on `revision != seen`.
    revision: u64,
    /// Set once terminally closed (the last feeder dropped). Never reopens.
    closed: bool,
    /// Set once the revision counter overflowed; terminal fail-closed, treated
    /// exactly like `closed`.
    overflowed: bool,
}

impl FeedSlot {
    /// Whether the feed is terminally fail-closed (closed or overflowed). Both are
    /// permanent.
    fn is_terminal(&self) -> bool {
        self.closed || self.overflowed
    }
}

/// The shared feed state: the locked slot plus a change notifier.
struct FeedShared {
    slot: Mutex<FeedSlot>,
    changed: Notify,
}

/// The UNIQUE write side of the feed. Deliberately NOT `Clone`; its `Drop` closes
/// the feed so a dropped owner never leaves the loop reading a stale generation.
pub(crate) struct HealthGenerationFeeder {
    shared: Arc<FeedShared>,
}

impl HealthGenerationFeeder {
    /// Builds a feeder and its shareable read/loop feed.
    pub(crate) fn new() -> (Self, HealthGenerationFeed) {
        let shared = Arc::new(FeedShared {
            slot: Mutex::new(FeedSlot {
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
            },
            HealthGenerationFeed { shared },
        )
    }

    fn lock(&self) -> MutexGuard<'_, FeedSlot> {
        self.shared
            .slot
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Publishes a new current generation. A no-op once the feed is terminal
    /// (closed or overflowed).
    pub(crate) fn set(&self, generation: Arc<HealthGeneration>) {
        let mut slot = self.lock();
        if slot.is_terminal() {
            return;
        }
        // Revoke the outgoing slot gate FIRST, so any overlay published under it
        // loses authority synchronously before the new generation is installed.
        revoke_current(&slot);
        slot.generation = Some(generation);
        slot.gate = Some(GenerationGate::new());
        advance(&mut slot);
        self.shared.changed.notify_waiters();
    }

    /// Withdraws the current generation (no generation, no gate) without closing
    /// the feed. A no-op once terminal.
    pub(crate) fn withdraw(&self) {
        let mut slot = self.lock();
        if slot.is_terminal() {
            return;
        }
        revoke_current(&slot);
        slot.generation = None;
        slot.gate = None;
        advance(&mut slot);
        self.shared.changed.notify_waiters();
    }

    /// Terminally closes the feed. Idempotent; also invoked by `Drop`.
    fn close(&self) {
        let mut slot = self.lock();
        if slot.closed {
            return;
        }
        revoke_current(&slot);
        slot.generation = None;
        slot.gate = None;
        slot.closed = true;
        advance(&mut slot);
        self.shared.changed.notify_waiters();
    }

    /// Test-only: drives the revision counter to a chosen value so a test can
    /// exercise the overflow boundary.
    #[cfg(test)]
    pub(crate) fn force_revision(&self, revision: u64) {
        self.lock().revision = revision;
    }
}

impl Drop for HealthGenerationFeeder {
    fn drop(&mut self) {
        self.close();
    }
}

/// Revokes the slot's current feed gate, if any.
fn revoke_current(slot: &FeedSlot) {
    if let Some(gate) = &slot.gate {
        gate.revoke();
    }
}

/// Advances the revision, latching `overflowed` (terminal) on wrap rather than
/// reusing a revision.
fn advance(slot: &mut FeedSlot) {
    match slot.revision.checked_add(1) {
        Some(next) => slot.revision = next,
        None => slot.overflowed = true,
    }
}

/// The shareable read/loop side of the feed. Cheap to clone.
#[derive(Clone)]
pub(crate) struct HealthGenerationFeed {
    shared: Arc<FeedShared>,
}

impl HealthGenerationFeed {
    fn lock(&self) -> MutexGuard<'_, FeedSlot> {
        self.shared
            .slot
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Reads `(current generation, revision, terminal)` under the lock.
    pub(crate) fn snapshot(&self) -> (Option<Arc<HealthGeneration>>, u64, bool) {
        let slot = self.lock();
        (slot.generation.clone(), slot.revision, slot.is_terminal())
    }

    /// Resolves once the feed's revision differs from `seen_revision` or the feed
    /// is terminal.
    ///
    /// The change waiter is registered (`enable`d) BEFORE the revision is
    /// re-read under the lock, so a transition landing between the read and the
    /// await cannot be lost.
    pub(crate) async fn wait_change(&self, seen_revision: u64) {
        loop {
            let notified = self.shared.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            {
                let slot = self.lock();
                if slot.is_terminal() || slot.revision != seen_revision {
                    return;
                }
            }
            notified.await;
        }
    }

    /// The atomic publish critical section.
    ///
    /// Under the feed lock, IFF the feed is live AND `generation` is still the
    /// exact current generation AND its slot gate is live, invokes `publish` with a
    /// CLONE of that live slot gate and returns `true`; otherwise returns `false`
    /// without calling `publish`. `publish` runs WHILE the feed lock is held (lock
    /// order feed → overlay, never the reverse), so the exact-generation check, the
    /// gate read, and the overlay swap form one critical section shared with the
    /// generation transition — a same-source replacement, a withdraw, or a close
    /// landing at the boundary either loses the lock race (and this returns
    /// `false`) or wins it after the publish (and synchronously revoked the gate).
    pub(crate) fn publish_current(
        &self,
        generation: &Arc<HealthGeneration>,
        publish: impl FnOnce(GenerationGate),
    ) -> bool {
        let slot = self.lock();
        if slot.is_terminal() {
            return false;
        }
        if !slot
            .generation
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, generation))
        {
            return false;
        }
        let Some(gate) = slot.gate.as_ref() else {
            return false;
        };
        if !gate.is_live() {
            return false;
        }
        publish(gate.clone());
        true
    }
}
