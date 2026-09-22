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

//! Authority that can be revoked without racing the effects made under it.
//!
//! A [`CommitPermit`] answers one question — is this authority still valid —
//! and offers one way to act on the answer that a revocation cannot slip
//! past. The distinction matters and is the reason this type exists:
//!
//! ```text
//! if permit.is_valid() { write(); }   // the revocation can land between
//! permit.commit(|| write());          // it cannot
//! ```
//!
//! Reading validity and then acting leaves a window no amount of locking
//! *elsewhere* removes. Ordering the effect against other effects is not
//! ordering it against the state change; only a lock both the revoker and
//! the committer take can do that, and it has to live with the authority
//! whose lifetime it guards.
//!
//! This lives in `control-plane` because it is the root of the internal
//! crate graph: ownership, configuration, topology and routing all depend
//! on it already, so each can revoke its own authority through the same
//! primitive without any of them depending on each other.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

/// One revocable authority, clonable so holders and the revoker share it.
#[derive(Clone, Debug)]
pub struct CommitPermit {
    state: Arc<PermitState>,
}

#[derive(Debug)]
struct PermitState {
    valid: AtomicBool,
    /// Held across a revocation and across each commit, so the two cannot
    /// overlap. Nothing else may be done under it.
    commit: Mutex<()>,
}

impl Default for CommitPermit {
    fn default() -> Self {
        Self::new()
    }
}

impl CommitPermit {
    /// Creates a valid permit.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: Arc::new(PermitState {
                valid: AtomicBool::new(true),
                commit: Mutex::new(()),
            }),
        }
    }

    /// Revokes the authority.
    ///
    /// Takes the commit lock first, so a commit already running finishes
    /// before this returns and a later one is refused. A commit is never
    /// half-applied across a revocation.
    pub fn revoke(&self) {
        let _commit = self.lock();
        self.state.valid.store(false, Ordering::SeqCst);
    }

    /// Revokes, reporting whether this call was the one that did it.
    ///
    /// For a revoker that must also perform a one-time teardown -- freeing
    /// a registry entry, say -- and would otherwise need a second flag to
    /// tell a repeat call from the first. The decision is made under the
    /// commit lock, so exactly one caller sees `true` however many race.
    #[must_use]
    pub fn revoke_once(&self) -> bool {
        let _commit = self.lock();
        self.state.valid.swap(false, Ordering::SeqCst)
    }

    /// Runs `effect` if and only if the authority is still valid, with
    /// revocation excluded for its duration. Returns `None` if refused.
    ///
    /// # Panics-free contract
    ///
    /// `effect` must be short and synchronous. It must not await, perform
    /// I/O, or reach for a lock that a revoker holds before this one --
    /// nothing that could make a revocation wait on the effect's own
    /// dependencies.
    pub fn commit<T>(&self, effect: impl FnOnce() -> T) -> Option<T> {
        let _guard = self.lock();
        if !self.state.valid.load(Ordering::SeqCst) {
            return None;
        }
        Some(effect())
    }

    /// Runs `effect` only if **every** permit is still valid, holding all
    /// of their commit locks for its duration.
    ///
    /// For an authority that is a conjunction of several independent ones,
    /// where committing under a subset would leave the rest free to be
    /// revoked mid-effect. The permits are ordered by address and
    /// deduplicated before locking, so any two callers passing overlapping
    /// sets take them in the same order and a permit named twice within
    /// one call is not self-deadlocked.
    ///
    /// # Contract
    ///
    /// `effect` inherits [`Self::commit`]'s: short, synchronous, no await,
    /// no I/O, and no lock a revoker takes first.
    ///
    /// It must also **not re-enter any permit held by this call or by an
    /// enclosing one** — neither [`Self::commit`] nor `commit_all` is
    /// reentrant, and a nested call naming a permit already held blocks
    /// forever on it.
    ///
    /// The address ordering fixes only the locks taken *within a single
    /// call*. It does nothing for a caller that already holds some permits
    /// and then calls this with others: that outer scope has fixed its own
    /// order, this one cannot see it, and the two can disagree. Acquire
    /// every permit an effect needs in one call.
    #[must_use]
    pub fn commit_all<T>(permits: &[&Self], effect: impl FnOnce() -> T) -> Option<T> {
        let mut ordered: Vec<&Self> = permits.to_vec();
        ordered.sort_unstable_by_key(|permit| Arc::as_ptr(&permit.state).cast::<()>());
        ordered.dedup_by_key(|permit| Arc::as_ptr(&permit.state).cast::<()>());
        let mut guards = Vec::with_capacity(ordered.len());
        for permit in &ordered {
            guards.push(permit.lock());
        }
        if ordered.iter().any(|permit| !permit.is_valid()) {
            return None;
        }
        let value = effect();
        drop(guards);
        Some(value)
    }

    /// Whether the authority is still valid.
    ///
    /// A lock-free read for ordinary fencing. It describes the past the
    /// instant it returns; anything that must not outlive the authority
    /// belongs in [`Self::commit`].
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.state.valid.load(Ordering::SeqCst)
    }

    fn lock(&self) -> MutexGuard<'_, ()> {
        self.state
            .commit
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use super::CommitPermit;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc;

    #[test]
    fn a_revocation_ordered_first_refuses_the_commit() {
        let permit = CommitPermit::new();
        permit.revoke();
        assert_eq!(permit.commit(|| 1), None);
    }

    /// The other order, pinned by a barrier: the revoking thread starts
    /// only once the commit is demonstrably inside, so a permit without the
    /// lock would let the flip land mid-commit.
    #[test]
    fn a_commit_ordered_first_completes_before_the_revocation() {
        let permit = CommitPermit::new();
        let finished = Arc::new(AtomicBool::new(false));
        let (entered, started) = mpsc::channel();

        let revoker = {
            let permit = permit.clone();
            let finished = Arc::clone(&finished);
            std::thread::spawn(move || {
                started
                    .recv()
                    .unwrap_or_else(|error| unreachable!("commit never entered: {error}"));
                permit.revoke();
                assert!(
                    finished.load(Ordering::SeqCst),
                    "revocation overtook a commit that had already begun"
                );
            })
        };

        let committed = permit.commit(|| {
            let _ = entered.send(());
            std::thread::sleep(std::time::Duration::from_millis(50));
            finished.store(true, Ordering::SeqCst);
            7
        });

        revoker
            .join()
            .unwrap_or_else(|_| unreachable!("revoking thread panicked"));
        assert_eq!(committed, Some(7));
        assert!(!permit.is_valid());
    }

    /// A conjunction is only as valid as its weakest member.
    #[test]
    fn commit_all_refuses_when_any_permit_is_revoked() {
        let first = CommitPermit::new();
        let second = CommitPermit::new();
        let third = CommitPermit::new();
        assert_eq!(
            CommitPermit::commit_all(&[&first, &second, &third], || 1),
            Some(1)
        );

        second.revoke();
        assert_eq!(
            CommitPermit::commit_all(&[&first, &second, &third], || 1),
            None,
            "one revoked member refuses the whole commit"
        );
        assert!(
            first.is_valid() && third.is_valid(),
            "refusing does not revoke the others"
        );
    }

    /// Naming one permit twice must not deadlock against itself, and two
    /// callers with overlapping sets must take them in the same order.
    #[test]
    fn commit_all_deduplicates_and_orders() {
        let first = CommitPermit::new();
        let second = CommitPermit::new();
        assert_eq!(
            CommitPermit::commit_all(&[&first, &first, &second], || 2),
            Some(2),
            "a repeated permit is locked once"
        );

        // Both orderings reach the same lock order, so neither blocks.
        let forward = CommitPermit::commit_all(&[&first, &second], || 3);
        let reverse = CommitPermit::commit_all(&[&second, &first], || 4);
        assert_eq!((forward, reverse), (Some(3), Some(4)));
    }

    /// An empty conjunction commits: there is nothing to invalidate it.
    #[test]
    fn commit_all_of_nothing_runs() {
        assert_eq!(CommitPermit::commit_all(&[], || 5), Some(5));
    }

    /// Exactly one caller sees the transition, however many race for it.
    #[test]
    fn revoke_once_reports_the_transition_to_a_single_caller() {
        let permit = CommitPermit::new();
        assert!(permit.revoke_once(), "the first call performed it");
        assert!(!permit.revoke_once(), "a repeat call did not");
        assert!(!permit.is_valid());

        let permit = CommitPermit::new();
        let winners: Vec<bool> = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..8)
                .map(|_| {
                    let permit = permit.clone();
                    scope.spawn(move || permit.revoke_once())
                })
                .collect();
            handles
                .into_iter()
                .map(|handle| {
                    handle
                        .join()
                        .unwrap_or_else(|_| unreachable!("revoking thread panicked"))
                })
                .collect()
        });
        assert_eq!(
            winners.iter().filter(|won| **won).count(),
            1,
            "eight racing revokers, one transition"
        );
    }
}
