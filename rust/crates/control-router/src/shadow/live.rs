// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Independent comparison of bounded batches captured at actual Go mutations.
//! Witnesses are outputs only; they never initialize or repair the mirror.

pub mod native;

use super::{Epoch, Event, InvalidReason, Limits, Observation, Progress, ShadowState, Status};
use std::collections::{BTreeMap, BTreeSet};

/// Hard maximum of transitions in one atomic Go mutation.
pub const MAX_EVENTS: usize = 4;
/// Hard maximum of affected account witnesses in one mutation.
pub const MAX_ACCOUNTS: usize = 2;

/// A fixed projection of independently represented connection state.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)] // Independent fixed Go witness dimensions.
pub struct ConnectionState {
    /// A physical Go connection wrapper has existed for this session.
    pub present: bool,
    /// Actual retained physical account, or zero after close.
    pub physical: u64,
    /// Independent score owner, or zero after close.
    pub score_owner: u64,
    /// Accepted migration or administrative reconnect awaits a terminal.
    pub redirect_pending: bool,
    /// Force-close was accepted, but physical close has not completed.
    pub closing: bool,
    /// Actual terminal close has occurred.
    pub closed: bool,
}

/// Constant-size account output; physical order itself stays in the mirror.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AccountWitness {
    /// Diagnostic account incarnation.
    pub id: u64,
    /// Independently derived score count.
    pub score: i64,
    /// Independently derived physical count.
    pub physical: u64,
    /// First physical arrival, or zero if empty.
    pub head: u64,
    /// Last physical arrival, or zero if empty.
    pub tail: u64,
}

/// Fixed-size Go output witness, compared after applying the whole batch.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Witness {
    /// At most two changed or explicitly examined retained accounts.
    pub accounts: Vec<AccountWitness>,
    /// Affected session, including an unbound selection incarnation.
    pub session: u64,
    /// Actual predecessor only when this batch physically appends the session.
    pub predecessor: u64,
    /// State before the actual atomic Go mutation.
    pub before: ConnectionState,
    /// State after the actual atomic Go mutation.
    pub after: ConnectionState,
}

/// Actual captured event. Metadata is group scoped and cannot imply factor parity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LiveEvent {
    /// Existing lifecycle transition with explicit observed endpoint identities.
    Lifecycle {
        /// Pure lifecycle input; Policy is forbidden in this live slice.
        event: Event,
        /// Actual source endpoint, when the operation has an explicit source.
        source: u64,
        /// Actual target endpoint, when it was examined by the Go operation.
        target: u64,
    },
    /// Group created before its actual policy Init.
    GroupCreated(u64),
    /// Actual removal of an empty group, retaining the diagnostic tombstone.
    GroupRemoved(u64),
    /// Selection ended after its actual failed creation settled its reservation.
    SelectionDone(u64),
    /// A route attempt returned no backend and acquired no reservation.
    RouteRejected {
        /// Selector diagnostic identity, not a guessed connection identity.
        session: u64,
        /// Examined group, or zero when router matching failed first.
        group: u64,
    },
    /// Administrative same-backend reconnect marks pending even on refusal.
    Reconnect {
        /// Existing physical session.
        session: u64,
        /// Captured operation incarnation.
        operation: u64,
        /// Existing physical account, unchanged as score owner.
        account: u64,
        /// Actual callback return; false does not undo Go's pending marker.
        accepted: bool,
    },
}
impl LiveEvent {
    fn session(&self) -> Option<u64> {
        match self {
            Self::Lifecycle {
                event:
                    Event::Open(s)
                    | Event::Closed(s)
                    | Event::Reserve { session: s, .. }
                    | Event::Created { session: s, .. }
                    | Event::Redirect { session: s, .. }
                    | Event::Redirected { session: s, .. }
                    | Event::Closing { session: s, .. }
                    | Event::Rehydrate { session: s, .. }
                    | Event::Rejected { session: s },
                ..
            }
            | Self::SelectionDone(s)
            | Self::Reconnect { session: s, .. } => Some(*s),
            _ => None,
        }
    }
    fn appends(&self) -> bool {
        matches!(
            self,
            Self::Lifecycle {
                event: Event::Rehydrate { .. }
                    | Event::Created { success: true, .. }
                    | Event::Redirected { success: true, .. },
                ..
            }
        )
    }
}

/// One atomic capture. The adapter rejects lengths before constructing this value.
#[derive(Clone, Debug)]
pub struct Batch {
    /// Complete immutable owner identity, repeated on every envelope.
    pub epoch: Epoch,
    /// First contiguous event sequence in this batch.
    pub sequence: u64,
    /// One to four lifecycle or explicit coverage events.
    pub events: Vec<LiveEvent>,
    /// Go output to compare, never a state seed.
    pub witness: Witness,
}

/// Live observation domain. It reuses the existing isolated lifecycle mirror and
/// adds only bounded group history and strict witness qualification.
pub struct LiveState {
    core: ShadowState,
    groups: BTreeMap<(u64, u64), BTreeMap<u64, bool>>,
    limits: Limits,
    native: BTreeMap<Epoch, native::NativeOwner>,
    native_bytes: usize,
    native_peak: usize,
}
impl LiveState {
    /// Empty observer; production state cannot be attached or reconstructed.
    #[must_use]
    pub fn new(limits: Limits) -> Self {
        Self {
            core: ShadowState::new(limits),
            groups: BTreeMap::new(),
            limits,
            native: BTreeMap::new(),
            native_bytes: 0,
            native_peak: 0,
        }
    }

    /// Last qualified comparison sequence. Invalid summaries never advance it.
    #[must_use]
    pub fn progress(&self, epoch: Epoch) -> Progress {
        let mut progress = self.core.progress(epoch, None);
        if self
            .core
            .owners
            .get(&(epoch.process, epoch.owner))
            .is_some_and(|owner| owner.epoch != epoch)
        {
            // Diagnostic queries cannot qualify another nonce's interval.
            // Retain the compared boundary without mutating the real owner.
            progress.status = Status::Invalid(InvalidReason::Identity);
            progress.transition = None;
        }
        progress
    }

    /// Read an explicit diagnostic snapshot, outside capture or comparison loops.
    #[must_use]
    pub fn view(&self, epoch: Epoch) -> Option<super::LedgerView> {
        self.core.view(epoch)
    }

    /// Read independently derived score/physical totals without copying lists.
    #[must_use]
    pub fn totals(&self, epoch: Epoch) -> Option<(u64, u64)> {
        let owner = self.core.owners.get(&(epoch.process, epoch.owner))?;
        (owner.epoch == epoch).then(|| owner.ledger.totals())
    }

    /// Keep invalid history after a transport interval is lost.
    pub fn transport_lost(&mut self) {
        self.core.transport_lost();
    }

    /// Persist an out-of-band invalid notice, including for an unseen owner.
    /// `last_admitted` is deliberately not a parameter: it is not comparison proof.
    pub fn invalidate(&mut self, epoch: Epoch, reason: InvalidReason) -> Progress {
        let key = (epoch.process, epoch.owner);
        if !self.core.owners.contains_key(&key) {
            self.core.observe(&Observation {
                epoch,
                sequence: 0,
                event: Event::Watermark,
            });
        }
        if let Some(owner) = self.core.owners.get_mut(&key) {
            if owner.epoch != epoch {
                owner.status = Status::Invalid(InvalidReason::Identity);
            } else if !matches!(owner.status, Status::Invalid(_)) {
                owner.status = Status::Invalid(reason);
            }
        }
        self.progress(epoch)
    }

    /// Apply the entire independent transition before comparing Go outputs.
    /// A bad batch permanently invalidates and cannot advance `compared_sequence`,
    /// even if an earlier event in that same batch had been locally applied.
    pub fn observe(&mut self, batch: &Batch) -> Progress {
        let previous = self.progress(batch.epoch).compared_sequence;
        if let Err(reason) = self.apply_and_compare(batch) {
            self.invalidate(batch.epoch, reason);
            if let Some(owner) = self
                .core
                .owners
                .get_mut(&(batch.epoch.process, batch.epoch.owner))
            {
                owner.sequence = previous;
            }
        }
        self.progress(batch.epoch)
    }

    fn apply_and_compare(&mut self, batch: &Batch) -> Result<(), InvalidReason> {
        if batch.events.is_empty()
            || batch.events.len() > MAX_EVENTS
            || batch.witness.accounts.len() > MAX_ACCOUNTS
        {
            return Err(InvalidReason::Capacity);
        }
        let key = (batch.epoch.process, batch.epoch.owner);
        if let Some(owner) = self.core.owners.get(&key) {
            if matches!(owner.status, Status::Invalid(_)) {
                return Ok(());
            }
            if owner.epoch != batch.epoch {
                return Err(InvalidReason::Identity);
            }
        }
        let mut session = 0;
        for event in &batch.events {
            if let Some(id) = event.session() {
                if id == 0 || (session != 0 && session != id) {
                    return Err(InvalidReason::Identity);
                }
                session = id;
            }
        }
        let before = self
            .core
            .owners
            .get(&key)
            .map_or(ConnectionState::default(), |o| o.ledger.connection(session));
        let mut required = BTreeSet::new();
        for id in [before.physical, before.score_owner] {
            if id != 0 {
                required.insert(id);
            }
        }
        let mut appended = false;
        for (index, event) in batch.events.iter().enumerate() {
            self.required_accounts(key, event, &mut required)?;
            let sequence = batch
                .sequence
                .checked_add(index as u64)
                .ok_or(InvalidReason::Sequence)?;
            let progress = self.apply_event(batch.epoch, sequence, event)?;
            if let Status::Invalid(reason) = progress.status {
                return Err(reason);
            }
            // A terminal arriving after actual close is a no-op, not an append.
            appended |= event.appends() && !before.closed;
        }
        let owner = self
            .core
            .owners
            .get(&key)
            .ok_or(InvalidReason::MissingBegin)?;
        let after = owner.ledger.connection(session);
        for id in [after.physical, after.score_owner] {
            if id != 0 {
                required.insert(id);
            }
        }
        let observed: BTreeSet<_> = batch.witness.accounts.iter().map(|a| a.id).collect();
        if required.len() > MAX_ACCOUNTS
            || required != observed
            || observed.len() != batch.witness.accounts.len()
            || batch.witness.session != session
            || batch.witness.before != before
            || batch.witness.after != after
            || batch.witness.predecessor
                != if appended {
                    owner.ledger.predecessor(session)
                } else {
                    0
                }
        {
            return Err(InvalidReason::Witness);
        }
        for witness in &batch.witness.accounts {
            if owner.ledger.compact_account(witness.id) != Some(*witness) {
                return Err(InvalidReason::Witness);
            }
        }
        Ok(())
    }

    fn required_accounts(
        &self,
        key: (u64, u64),
        event: &LiveEvent,
        required: &mut BTreeSet<u64>,
    ) -> Result<(), InvalidReason> {
        match event {
            LiveEvent::Lifecycle {
                event,
                source,
                target,
            } => {
                for id in [*source, *target] {
                    if id != 0 {
                        required.insert(id);
                    }
                }
                match *event {
                    Event::Account { id, .. }
                    | Event::RemoveAccount(id)
                    | Event::Reserve { account: id, .. }
                    | Event::Rehydrate { account: id, .. }
                    | Event::Redirect { target: id, .. } => {
                        required.insert(id);
                    }
                    Event::Created { session, .. } => {
                        if let Some(id) = self
                            .core
                            .owners
                            .get(&key)
                            .and_then(|o| o.ledger.pending_account(session))
                        {
                            required.insert(id);
                        }
                    }
                    Event::Policy(_) => return Err(InvalidReason::Lifecycle),
                    _ => {}
                }
            }
            LiveEvent::Reconnect { account, .. } => {
                required.insert(*account);
            }
            _ => {}
        }
        Ok(())
    }

    fn apply_event(
        &mut self,
        epoch: Epoch,
        sequence: u64,
        event: &LiveEvent,
    ) -> Result<Progress, InvalidReason> {
        let key = (epoch.process, epoch.owner);
        if let LiveEvent::Lifecycle { event, .. } = event {
            if let Event::Account { group, .. } = event
                && self.groups.get(&key).and_then(|groups| groups.get(group)) != Some(&true)
            {
                return Err(InvalidReason::Identity);
            }
            return Ok(self.core.observe(&Observation {
                epoch,
                sequence,
                event: event.clone(),
            }));
        }
        // Metadata also consumes a contiguous event sequence, after the same
        // epoch/sequence checks. Any failure invalidates this entire batch.
        let progress = self.core.observe(&Observation {
            epoch,
            sequence,
            event: Event::Watermark,
        });
        if progress.status != Status::Comparing {
            return Ok(progress);
        }
        let owner = self
            .core
            .owners
            .get_mut(&key)
            .ok_or(InvalidReason::MissingBegin)?;
        match *event {
            LiveEvent::GroupCreated(id) => {
                let groups = self.groups.entry(key).or_default();
                if groups.len() >= self.limits.accounts {
                    return Err(InvalidReason::Capacity);
                }
                if id == 0 || groups.contains_key(&id) {
                    return Err(InvalidReason::Identity);
                }
                groups.insert(id, true);
            }
            LiveEvent::GroupRemoved(id) => {
                let group = self
                    .groups
                    .get_mut(&key)
                    .and_then(|groups| groups.get_mut(&id))
                    .ok_or(InvalidReason::Identity)?;
                if !*group || !owner.ledger.group_empty(id) {
                    return Err(InvalidReason::Lifecycle);
                }
                *group = false;
            }
            LiveEvent::SelectionDone(id) => owner.ledger.selection_done(id)?,
            LiveEvent::RouteRejected { session, group } => {
                if session == 0
                    || (group != 0
                        && self.groups.get(&key).and_then(|g| g.get(&group)) != Some(&true))
                {
                    return Err(InvalidReason::Identity);
                }
            }
            LiveEvent::Reconnect {
                session,
                operation,
                account,
                ..
            } => owner.ledger.reconnect(session, operation, account)?,
            LiveEvent::Lifecycle { .. } => return Err(InvalidReason::Lifecycle),
        }
        Ok(progress)
    }
}

#[cfg(test)]
mod tests;
