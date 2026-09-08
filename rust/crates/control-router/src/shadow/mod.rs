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

//! Bounded observation-only routing state. This module has no production handles.

mod ledger;
/// Actual-capture batches and independent output-witness comparison.
pub mod live;

use std::collections::BTreeMap;

use ledger::Mirror;
pub use ledger::{AccountView, Counts, Event, LedgerView, Policy, Transition};

/// Immutable identity supplied on every observation frame; never an authority handle.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Epoch {
    /// Authoritative Go process incarnation.
    pub process: u64,
    /// Namespace/router owner incarnation inside that process.
    pub owner: u64,
    /// Observation start nonce, bound to the first Begin record.
    pub nonce: u64,
}

/// One contiguous owner observation, already decoded by the legacy adapter.
#[derive(Clone, Debug)]
pub struct Observation {
    /// Owner identity; every record repeats the complete identity.
    pub epoch: Epoch,
    /// One-based owner-local sequence.
    pub sequence: u64,
    /// Observed authoritative event.
    pub event: Event,
}

/// Why an observation interval cannot qualify as comparison evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InvalidReason {
    /// Capture did not begin before the owner was initialized.
    MissingBegin,
    /// A known owner/nonce was replayed or replaced without owner recreation.
    ReplayedBegin,
    /// A sequence was duplicated, skipped, reordered or exhausted.
    Sequence,
    /// A zero or otherwise malformed identity was supplied.
    Identity,
    /// Bounded retained state was exhausted.
    Capacity,
    /// The observed transition cannot follow the independently maintained state.
    Lifecycle,
    /// An observation transport was lost or malformed.
    Transport,
    /// No recent observation watermark is available.
    Stale,
    /// Go output differs from the independently applied lifecycle transition.
    Witness,
}

/// Qualification state of one owner interval.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    /// Observation was not enabled.
    Disabled,
    /// Valid contiguous observations are being compared.
    Comparing,
    /// The owner retired and its complete retained tail was observed closed.
    CleanEnded,
    /// This interval is permanently disqualified.
    Invalid(InvalidReason),
}

/// Explicit memory/population limits; exhaustion invalidates instead of evicting history.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Total owner intervals retained, including invalid and ended intervals.
    pub owners: usize,
    /// Total account identities retained per owner, including removed accounts.
    pub accounts: usize,
    /// Total session incarnations retained per owner, including closed sessions.
    pub sessions: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            owners: 128,
            accounts: 4096,
            sessions: 65_536,
        }
    }
}

/// A bounded result contains no session, reservation or command authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Progress {
    /// Whether the interval remains qualified.
    pub status: Status,
    /// Last successfully compared sequence; invalid input never advances it.
    pub compared_sequence: u64,
    /// Whether the authoritative lifecycle event changed accounting.
    pub transition: Option<Transition>,
}

struct Owner {
    epoch: Epoch,
    local_identity: u64,
    sequence: u64,
    status: Status,
    ledger: Mirror,
}

/// Isolated diagnostic registry and value ledger. No production store is consulted.
///
/// Removed/ended owners remain registered so a serialized Begin cannot resurrect
/// them. Reaching a limit disqualifies the stream rather than discarding tombstones.
pub struct ShadowState {
    enabled: bool,
    fatal: Option<InvalidReason>,
    limits: Limits,
    next_identity: u64,
    owners: BTreeMap<(u64, u64), Owner>,
}
impl ShadowState {
    /// Create a disabled observer with no captured state.
    #[must_use]
    pub fn disabled() -> Self {
        let mut state = Self::new(Limits::default());
        state.enabled = false;
        state
    }

    /// Create a bounded empty registry; only Begin can establish an owner.
    #[must_use]
    pub fn new(limits: Limits) -> Self {
        Self {
            enabled: true,
            fatal: None,
            limits,
            next_identity: 1,
            owners: BTreeMap::new(),
        }
    }

    /// Consume a value record, independently maintaining accepted lifecycle state.
    pub fn observe(&mut self, observation: &Observation) -> Progress {
        if !self.enabled {
            return Progress {
                status: Status::Disabled,
                compared_sequence: 0,
                transition: None,
            };
        }
        if let Some(reason) = self.fatal {
            return Progress {
                status: Status::Invalid(reason),
                compared_sequence: self
                    .owners
                    .get(&(observation.epoch.process, observation.epoch.owner))
                    .filter(|owner| owner.epoch == observation.epoch)
                    .map_or(0, |owner| owner.sequence),
                transition: None,
            };
        }
        let key = (observation.epoch.process, observation.epoch.owner);
        if !self.owners.contains_key(&key) {
            if self.owners.len() >= self.limits.owners {
                return self.fail_all(InvalidReason::Capacity);
            }
            let Some(next) = self.next_identity.checked_add(1) else {
                return self.fail_all(InvalidReason::Capacity);
            };
            let reason = if observation.epoch.process == 0
                || observation.epoch.owner == 0
                || observation.epoch.nonce == 0
            {
                Some(InvalidReason::Identity)
            } else if observation.sequence != 1 || observation.event != Event::Begin {
                Some(InvalidReason::MissingBegin)
            } else {
                None
            };
            self.owners.insert(
                key,
                Owner {
                    epoch: observation.epoch,
                    local_identity: self.next_identity,
                    sequence: u64::from(reason.is_none()),
                    status: reason.map_or(Status::Comparing, Status::Invalid),
                    ledger: Mirror::new(self.limits),
                },
            );
            self.next_identity = next;
            return self.progress(observation.epoch, None);
        }
        let Some(owner) = self.owners.get_mut(&key) else {
            return self.fail_all(InvalidReason::Identity);
        };
        if matches!(owner.status, Status::Invalid(_)) {
            return self.progress(observation.epoch, None);
        }
        let reason = if owner.epoch != observation.epoch || observation.event == Event::Begin {
            Some(InvalidReason::ReplayedBegin)
        } else if owner.status == Status::CleanEnded
            || owner.sequence.checked_add(1) != Some(observation.sequence)
        {
            Some(InvalidReason::Sequence)
        } else {
            None
        };
        if let Some(reason) = reason {
            owner.status = Status::Invalid(reason);
            return self.progress(observation.epoch, None);
        }
        let transition = match owner.ledger.apply(&observation.event) {
            Ok(transition) => {
                owner.sequence = observation.sequence;
                if observation.event == Event::End {
                    owner.status = Status::CleanEnded;
                }
                Some(transition)
            }
            Err(reason) => {
                owner.status = Status::Invalid(reason);
                None
            }
        };
        self.progress(observation.epoch, transition)
    }

    fn progress(&self, epoch: Epoch, transition: Option<Transition>) -> Progress {
        self.owners.get(&(epoch.process, epoch.owner)).map_or(
            Progress {
                status: Status::Invalid(InvalidReason::MissingBegin),
                compared_sequence: 0,
                transition: None,
            },
            |owner| Progress {
                status: owner.status,
                compared_sequence: owner.sequence,
                transition,
            },
        )
    }

    fn fail_all(&mut self, reason: InvalidReason) -> Progress {
        self.fatal = Some(reason);
        for owner in self.owners.values_mut() {
            if owner.status == Status::Comparing {
                owner.status = Status::Invalid(reason);
            }
        }
        Progress {
            status: Status::Invalid(reason),
            compared_sequence: 0,
            transition: None,
        }
    }

    /// Whether every retained lifecycle interval has an explicit complete end.
    /// This is a lifecycle-corpus diagnostic, never full routing qualification.
    #[must_use]
    pub fn lifecycle_trace_complete(&self) -> bool {
        self.enabled
            && self.fatal.is_none()
            && !self.owners.is_empty()
            && self
                .owners
                .values()
                .all(|owner| owner.status == Status::CleanEnded)
    }

    /// Disqualify all incomplete intervals after transport loss, without a synthetic end.
    pub fn transport_lost(&mut self) {
        for owner in self.owners.values_mut() {
            if owner.status == Status::Comparing {
                owner.status = Status::Invalid(InvalidReason::Transport);
            }
        }
    }

    /// Disqualify one owner after an absent watermark or observed disappearance.
    pub fn invalidate(&mut self, epoch: Epoch, reason: InvalidReason) -> Progress {
        let Some(owner) = self.owners.get_mut(&(epoch.process, epoch.owner)) else {
            return self.progress(epoch, None);
        };
        if owner.epoch != epoch {
            return Progress {
                status: Status::Invalid(InvalidReason::Identity),
                compared_sequence: 0,
                transition: None,
            };
        }
        if owner.status == Status::Comparing {
            owner.status = Status::Invalid(reason);
        }
        self.progress(epoch, None)
    }

    /// Read a bounded diagnostic snapshot, never a production authority or effect.
    #[must_use]
    pub fn view(&self, epoch: Epoch) -> Option<LedgerView> {
        let owner = self.owners.get(&(epoch.process, epoch.owner))?;
        (owner.epoch == epoch).then(|| {
            owner
                .ledger
                .view(owner.local_identity, owner.status, owner.sequence)
        })
    }
}

#[cfg(test)]
mod tests;
