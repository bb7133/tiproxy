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

//! Retained session authority and permits for one confirmed leadership interval.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use control_external::GenerationGate;
use control_plane::OwnerToken;

use crate::ElectionState;

struct Interval {
    gate: GenerationGate,
}

struct State {
    phase: ElectionState,
    interval: Option<Arc<Interval>>,
}

struct Shared {
    owner: OwnerToken,
    retirement: GenerationGate,
    state: Mutex<State>,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn is_live(&self) -> bool {
        self.owner.is_current() && self.retirement.is_live()
    }
}

/// A live view of one session's last-known ownership, minted only by that session.
///
/// Clones retain the original process owner and shared retirement state. An
/// `Uncertain` session retains already-published results, but cannot issue work
/// permits. Definitive retirement, shutdown and session drop revoke every clone.
/// This is local observed authority, not proof of an unobserved remote lease.
#[derive(Clone)]
pub struct ElectionAuthority {
    shared: Arc<Shared>,
}

impl ElectionAuthority {
    pub(crate) fn new(owner: OwnerToken) -> Self {
        Self {
            shared: Arc::new(Shared {
                owner,
                retirement: GenerationGate::new(),
                state: Mutex::new(State {
                    phase: ElectionState::Campaigning,
                    interval: None,
                }),
            }),
        }
    }

    /// Whether a previously committed result still has last-known local ownership.
    /// Unlike a copied snapshot, this checks the live session and original owner.
    #[must_use]
    pub fn retains_local_ownership(&self) -> bool {
        let state = self.shared.lock();
        self.shared.is_live()
            && matches!(
                state.phase,
                ElectionState::Leader | ElectionState::Uncertain
            )
    }

    /// Captures permission to finish new owner work in this confirmed interval.
    /// An uncertain or retired session, or a stale process, issues no permit.
    #[must_use]
    pub fn capture_work(&self) -> Option<ElectionWorkPermit> {
        let state = self.shared.lock();
        if !self.shared.is_live() || state.phase != ElectionState::Leader {
            return None;
        }
        Some(ElectionWorkPermit {
            shared: Arc::clone(&self.shared),
            interval: Arc::clone(state.interval.as_ref()?),
        })
    }

    // Called before the diagnostic watch is notified. Terminal authority never
    // reopens; successful recovery starts a fresh interval, not a revived permit.
    pub(crate) fn transition(&self, phase: ElectionState) {
        let mut state = self.shared.lock();
        if !self.shared.retirement.is_live() {
            return;
        }
        if phase != ElectionState::Leader {
            revoke_interval(&mut state);
        } else if state.phase != ElectionState::Leader {
            state.interval = Some(Arc::new(Interval {
                gate: GenerationGate::new(),
            }));
        }
        if matches!(phase, ElectionState::Retired | ElectionState::Stopped) {
            self.shared.retirement.revoke();
        }
        state.phase = phase;
    }

    pub(crate) fn retire(&self) {
        self.transition(ElectionState::Retired);
    }
}

fn revoke_interval(state: &mut State) {
    if let Some(interval) = state.interval.take() {
        interval.gate.revoke();
    }
}

/// An unforgeable permit for one confirmed leadership interval in one session.
///
/// Entering uncertainty permanently invalidates existing permits. Recovery of
/// the same lease creates a new interval: old asynchronous results cannot regain
/// permission. Published results retain [`ElectionAuthority`] instead, so normal
/// uncertainty does not invalidate already-established local service.
#[derive(Clone)]
pub struct ElectionWorkPermit {
    shared: Arc<Shared>,
    interval: Arc<Interval>,
}

impl control_external::IoFence for ElectionWorkPermit {
    fn is_live(&self) -> bool {
        self.still_current()
    }
}

impl ElectionWorkPermit {
    /// Checks permission at admission or after an asynchronous operation.
    /// Use [`Self::with_current`] for the final synchronous publication boundary.
    #[must_use]
    pub fn still_current(&self) -> bool {
        self.shared.is_live() && self.interval.gate.is_live()
    }

    /// Runs a short synchronous publication only while this interval is current.
    ///
    /// The closure is serialized against session uncertainty/retirement. It must
    /// not block, await, or re-enter this authority (including through a clone).
    /// Collector lock order is feed → authority → overlay. A later retirement
    /// still invalidates the retained authority embedded in a published result.
    /// This does not replace an etcd transaction's distributed ownership fence.
    pub fn with_current<T>(&self, publish: impl FnOnce() -> T) -> Option<T> {
        let state = self.shared.lock();
        if !self.still_current()
            || state.phase != ElectionState::Leader
            || !state
                .interval
                .as_ref()
                .is_some_and(|interval| Arc::ptr_eq(interval, &self.interval))
        {
            return None;
        }
        Some(publish())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use control_plane::OwnershipRegistry;
    use control_plane::{OwnerLease, OwnerScope};

    fn leader() -> (OwnershipRegistry, OwnerLease, ElectionAuthority) {
        let registry = OwnershipRegistry::new();
        let owner = registry
            .claim(OwnerScope::Process, "authority-test")
            .unwrap_or_else(|error| unreachable!("owner: {error}"));
        let authority = ElectionAuthority::new(owner.token());
        authority.transition(ElectionState::Leader);
        (registry, owner, authority)
    }

    #[test]
    fn uncertainty_retains_results_but_never_revives_old_work() {
        let (_registry, _owner, authority) = leader();
        let old = authority.capture_work().unwrap_or_else(|| unreachable!());
        assert_eq!(old.with_current(|| 7), Some(7));
        authority.transition(ElectionState::Uncertain);
        assert!(authority.retains_local_ownership());
        assert!(authority.capture_work().is_none());
        assert!(!old.still_current());
        assert_eq!(old.with_current(|| 8), None);
        authority.transition(ElectionState::Leader);
        assert!(authority.retains_local_ownership());
        assert!(!old.still_current());
        assert_eq!(old.with_current(|| 9), None);
        assert!(authority.capture_work().is_some());
        authority.retire();
        authority.transition(ElectionState::Leader);
        assert!(!authority.retains_local_ownership());
        assert!(authority.capture_work().is_none());
    }

    #[test]
    fn publication_is_serialized_against_retirement() {
        use std::sync::mpsc;
        use std::time::Duration;
        let (_registry, _owner, authority) = leader();
        let permit = authority.capture_work().unwrap_or_else(|| unreachable!());
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let publishing = permit.clone();
        let writer = std::thread::spawn(move || {
            publishing.with_current(|| {
                entered_tx
                    .send(())
                    .unwrap_or_else(|error| unreachable!("{error}"));
                release_rx
                    .recv_timeout(Duration::from_secs(2))
                    .unwrap_or_else(|error| unreachable!("{error}"));
                7
            })
        });
        entered_rx
            .recv_timeout(Duration::from_secs(2))
            .unwrap_or_else(|error| unreachable!("{error}"));
        // The real publication closure owns the same mutex needed by retirement.
        assert!(authority.shared.state.try_lock().is_err());
        let (retired_tx, retired_rx) = mpsc::channel();
        let retiring = authority.clone();
        let retirement = std::thread::spawn(move || {
            retiring.retire();
            retired_tx
                .send(())
                .unwrap_or_else(|error| unreachable!("{error}"));
        });
        assert!(retired_rx.try_recv().is_err());
        release_tx
            .send(())
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(writer.join().unwrap_or_else(|_| unreachable!()), Some(7));
        retired_rx
            .recv_timeout(Duration::from_secs(2))
            .unwrap_or_else(|error| unreachable!("{error}"));
        retirement.join().unwrap_or_else(|_| unreachable!());
        assert!(!authority.retains_local_ownership());
        assert_eq!(permit.with_current(|| 8), None);
    }

    #[test]
    fn original_process_owner_is_checked_without_a_session_wakeup() {
        let (_registry, owner, authority) = leader();
        let permit = authority.capture_work().unwrap_or_else(|| unreachable!());
        drop(owner);
        assert!(!authority.retains_local_ownership());
        assert!(authority.capture_work().is_none());
        assert!(!permit.still_current());
        assert_eq!(permit.with_current(|| 1), None);
    }
}
