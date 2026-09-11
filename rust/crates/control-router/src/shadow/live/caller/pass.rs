// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Router pass order, independent of individual Group transactions. The actual
//! Go loop balances every group first, then closes every group. Production
//! integration must feed only committed Group callers into this tracker.
use crate::shadow::{Epoch, InvalidReason};

/// Frozen caller metadata group bound.
pub const MAX_GROUPS: usize = 64;

/// Bounded ordered group inventory. Construction does not create domain groups.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Groups {
    ids: [u64; MAX_GROUPS],
    len: usize,
}
impl Groups {
    /// Copy an already-derived inventory or a wire witness, keeping their roles
    /// separate at the comparison call site.
    ///
    /// # Errors
    /// Rejects zero, duplicate and excessive group identities.
    pub fn new(ids: &[u64]) -> Result<Self, InvalidReason> {
        if ids.len() > MAX_GROUPS {
            return Err(InvalidReason::Capacity);
        }
        for (i, id) in ids.iter().enumerate() {
            if *id == 0 || ids[..i].contains(id) {
                return Err(InvalidReason::Identity);
            }
        }
        let mut value = Self {
            ids: [0; MAX_GROUPS],
            len: ids.len(),
        };
        value.ids[..ids.len()].copy_from_slice(ids);
        Ok(value)
    }
    /// Actual iteration order, without unused storage.
    #[must_use]
    pub fn as_slice(&self) -> &[u64] {
        &self.ids[..self.len]
    }
}

/// Header captured once while holding the existing router lock.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Begin {
    /// Monotonic nonzero pass incarnation for this owner.
    pub pass: u64,
    /// Actual gate read, checked against retained configuration.
    pub support_redirection: bool,
    /// Actual order witness, checked against retained metadata order.
    pub groups: Groups,
}
/// Tail witnesses count completed Group calls, including calls doing no work.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct End {
    /// The open pass incarnation.
    pub pass: u64,
    /// Completed balance calls, zero when redirection is disabled.
    pub balanced: u16,
    /// Completed close calls, independent of the redirection gate.
    pub closed: u16,
}
/// Typed pass boundary. Neither variant carries children or creates groups.
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)] // Fixed charged storage avoids a separate heap allocation.
pub enum Event {
    /// Open the router pass before the first Group call.
    Begin(Begin),
    /// Close only after all expected Group callers committed.
    End(End),
}
/// One sequence point between, rather than across, Group transactions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Boundary {
    /// Full captured namespace identity.
    pub epoch: Epoch,
    /// Exactly one contiguous sequence point; span is always one.
    pub sequence: u64,
    /// Independently checked header or tail.
    pub event: Event,
}
/// Caller kind observed only after its atomic final comparison succeeded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    /// A complete Group Balance, including a zero-rate early return.
    Balance,
    /// A complete Group Close, including no timed-out sessions.
    Close,
}
struct Open {
    begin: Begin,
    completed: usize,
}

/// Fixed retention per owner. No eviction, queued callbacks or heap history.
/// The integration must add this full charge to R before creating the owner.
/// This pure component is not yet installed in a shadow factory.
#[derive(Default)]
pub struct Tracker {
    last_pass: u64,
    open: Option<Open>,
    failed: Option<InvalidReason>,
}
impl Tracker {
    /// Full fixed retained footprint, including an open 64-group pass.
    pub const CHARGE: usize = size_of::<Self>();

    /// Compare a header against independently derived router metadata/config.
    /// The observed header must never be used as `known_groups` or to initialize
    /// that inventory. Only one pass may remain open per owner.
    ///
    /// # Errors
    /// Sticky identity, order, replay or open-pass violations.
    pub fn begin(
        &mut self,
        begin: &Begin,
        known_groups: &Groups,
        known_redirection: bool,
    ) -> Result<(), InvalidReason> {
        let result = self.check().and_then(|()| {
            if self.open.is_some() {
                return Err(InvalidReason::Lifecycle);
            }
            if self.last_pass.checked_add(1) != Some(begin.pass) {
                return Err(InvalidReason::Sequence);
            }
            if &begin.groups != known_groups || begin.support_redirection != known_redirection {
                return Err(InvalidReason::Witness);
            }
            Ok(())
        });
        self.remember(result)?;
        self.open = Some(Open {
            begin: begin.clone(),
            completed: 0,
        });
        Ok(())
    }
    /// Record one already-committed Group caller. Unrelated lifecycle callbacks
    /// may interleave and do not call this method. All Balance calls precede all
    /// Close calls; disabled redirection skips only the former loop.
    ///
    /// # Errors
    /// Sticky missing, repeated, foreign or reordered Group completion.
    pub fn group(&mut self, pass: u64, phase: Phase, group: u64) -> Result<(), InvalidReason> {
        let result = self.check().and_then(|()| {
            let open = self.open.as_ref().ok_or(InvalidReason::Lifecycle)?;
            if pass != open.begin.pass {
                return Err(InvalidReason::Identity);
            }
            let groups = open.begin.groups.as_slice();
            let balances = if open.begin.support_redirection {
                groups.len()
            } else {
                0
            };
            let (expected_phase, index) = if open.completed < balances {
                (Phase::Balance, open.completed)
            } else {
                (Phase::Close, open.completed - balances)
            };
            if phase != expected_phase || groups.get(index) != Some(&group) {
                return Err(InvalidReason::Witness);
            }
            Ok(())
        });
        self.remember(result)?;
        if let Some(open) = self.open.as_mut() {
            open.completed += 1;
        }
        Ok(())
    }
    /// Compare a complete tail. No observed count can repair an omitted caller.
    ///
    /// # Errors
    /// Sticky mismatched incarnation, counts or missing Group callers.
    pub fn end(&mut self, end: End) -> Result<(), InvalidReason> {
        let result = self.check().and_then(|()| {
            let open = self.open.as_ref().ok_or(InvalidReason::Lifecycle)?;
            let closes = open.begin.groups.as_slice().len();
            let balances = if open.begin.support_redirection {
                closes
            } else {
                0
            };
            if end.pass != open.begin.pass {
                return Err(InvalidReason::Identity);
            }
            if open.completed != balances + closes
                || usize::from(end.balanced) != balances
                || usize::from(end.closed) != closes
            {
                return Err(InvalidReason::Witness);
            }
            Ok(())
        });
        self.remember(result)?;
        self.last_pass = end.pass;
        self.open = None;
        Ok(())
    }
    /// A final qualification tail cannot leave a pass open.
    ///
    /// # Errors
    /// Rejects an earlier failure or an unpaired header; does not mutate history.
    pub fn tail(&self) -> Result<(), InvalidReason> {
        self.check()?;
        if self.open.is_some() {
            Err(InvalidReason::Lifecycle)
        } else {
            Ok(())
        }
    }
    fn check(&self) -> Result<(), InvalidReason> {
        self.failed.map_or(Ok(()), Err)
    }
    fn remember(&mut self, result: Result<(), InvalidReason>) -> Result<(), InvalidReason> {
        if let Err(reason) = result {
            self.failed.get_or_insert(reason);
        }
        result
    }
}

#[cfg(test)]
mod tests;
