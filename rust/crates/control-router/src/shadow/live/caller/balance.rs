// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Group-local Balance comparison. Values come from a future typed caller
//! codec; actual Go hooks, router-pass binding and transport remain uninstalled.
//! Physical order comes from the lifecycle ledger, rates from native comparison,
//! and attempt times from earlier successful caller commits, never Go outputs.

use super::arithmetic::{self, AfterClock, Start};
use super::{
    Batch, Budget, Epoch, Event, InvalidReason, LiveEvent, LiveState, Progress, Scope, Stage,
};
use crate::shadow::native::{Entry, Evaluation};
use control_routing::go_time::GoTime;
use std::collections::BTreeMap;

const FAILURE_COOLDOWN: i64 = 3_000_000_000;
const ATTEMPT_CHARGE: usize = 16 * size_of::<(u64, Attempt)>();

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Attempt {
    time: GoTime,
    // Latest accepted operation, equal to the independent lifecycle watermark.
    operation: u64,
    pending: bool,
    failed: bool,
}

// Stored beside factor state so the existing affected Group clone/commit and
// retained/clone charges include every byte of scheduling history. Tombstones
// remain retained; a new config does not reset the actual Group watermark.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Timing {
    last_accepted: Option<GoTime>,
    attempts: BTreeMap<u64, Attempt>,
}
impl Timing {
    pub(crate) fn entry_charge(&self) -> usize {
        self.attempts.len() * ATTEMPT_CHARGE
    }
}

/// The single actual balance clock followed by the whole-pair keyspace reads.
#[derive(Clone, Debug)]
pub struct Clock {
    /// Already read at the production balance clock site.
    pub now: GoTime,
    /// First whole-pair keyspace read.
    pub from_keyspace: String,
    /// Second whole-pair keyspace read.
    pub to_keyspace: String,
}

/// One actual invocation of the direct redirect backstop and its lifecycle child.
#[derive(Clone, Debug)]
pub struct Redirect {
    /// Fresh source keyspace read at the direct callback boundary.
    pub from_keyspace: String,
    /// Fresh destination keyspace read at the direct callback boundary.
    pub to_keyspace: String,
    /// Absent exactly when the direct keyspace backstop prevents the callback.
    pub callback: Option<bool>,
    /// Complete actual accepted/rejected child, retaining original identities.
    pub batch: Batch,
}

/// A visited physical element, including connections skipped before redirect.
#[derive(Clone, Debug)]
pub struct Visit {
    /// Actual visited identity, checked against the independent physical prefix.
    pub session: u64,
    /// Present only if closing/pending/cooldown checks allow redirectConn.
    pub redirect: Option<Redirect>,
}

/// One complete Group critical section, with one native Balance evaluation.
#[derive(Clone, Debug)]
pub struct Envelope {
    /// Complete owner incarnation, shared by every child.
    pub epoch: Epoch,
    /// First sequence belongs to the native evaluation.
    pub sequence: u64,
    /// Native evaluation, lifecycle events and exactly one final caller check.
    pub span: u64,
    /// Nonzero actual call identity, scoped by the contiguous owner sequence.
    pub caller: u64,
    /// Independently retained Group incarnation.
    pub group: u64,
    /// Full actual Go map iteration order; checked as a retained-set permutation.
    pub members: Vec<u64>,
    /// Actual native inputs and witnesses; its independently returned rate wins.
    pub evaluation: Box<Evaluation>,
    /// Absent exactly for the native zero-rate early return.
    pub clock: Option<Clock>,
    /// Actual ctx.Err results in execution order; true means cancellation.
    pub contexts: Vec<bool>,
    /// At most 64 actually visited physical elements, including skipped ones.
    pub visits: Vec<Visit>,
    /// Actual successful callback count, compared only after the whole scan.
    pub accepted: u16,
}

impl Envelope {
    /// Validate bounded populations and complete child identity/sequence layout.
    ///
    /// # Errors
    /// Rejects malformed captures before creating the affected Group clone.
    pub fn validate(&self) -> Result<(), InvalidReason> {
        if [
            self.epoch.process,
            self.epoch.owner,
            self.epoch.nonce,
            self.sequence,
            self.caller,
            self.group,
        ]
        .contains(&0)
            || self.evaluation.epoch != self.epoch
            || self.evaluation.group != self.group
        {
            return Err(InvalidReason::Identity);
        }
        if self.evaluation.sequence != self.sequence {
            return Err(InvalidReason::Sequence);
        }
        if self.evaluation.entry != Entry::Balance {
            return Err(InvalidReason::Witness);
        }
        if self.members.len() > 64
            || self.visits.len() > 64
            || self.contexts.len() > 65
            || self.accepted > 64
        {
            return Err(InvalidReason::Capacity);
        }
        for (i, id) in self.members.iter().enumerate() {
            if *id == 0 || self.members[..i].contains(id) {
                return Err(InvalidReason::Identity);
            }
        }
        let mut next = self
            .sequence
            .checked_add(1)
            .ok_or(InvalidReason::Sequence)?;
        let mut strings = 0;
        let mut reads = self.contexts.len();
        if let Some(clock) = &self.clock {
            check_strings(&clock.from_keyspace, &clock.to_keyspace, &mut strings)?;
            reads += 2;
        }
        for (i, visit) in self.visits.iter().enumerate() {
            if visit.session == 0 || self.visits[..i].iter().any(|v| v.session == visit.session) {
                return Err(InvalidReason::Identity);
            }
            if let Some(redirect) = &visit.redirect {
                check_strings(&redirect.from_keyspace, &redirect.to_keyspace, &mut strings)?;
                reads += 2 + usize::from(redirect.callback.is_some());
                let batch = &redirect.batch;
                if batch.epoch != self.epoch {
                    return Err(InvalidReason::Identity);
                }
                if batch.sequence != next {
                    return Err(InvalidReason::Sequence);
                }
                if batch.events.len() != 1 || batch.witness.accounts.len() > 2 {
                    return Err(InvalidReason::Witness);
                }
                next = next.checked_add(1).ok_or(InvalidReason::Sequence)?;
            }
        }
        if reads > 128 {
            return Err(InvalidReason::Capacity);
        }
        if next - self.sequence + 1 != self.span {
            return Err(InvalidReason::Sequence);
        }
        Ok(())
    }
}

fn check_strings(from: &str, to: &str, total: &mut usize) -> Result<(), InvalidReason> {
    if from.len() > 512 || to.len() > 512 {
        return Err(InvalidReason::Capacity);
    }
    *total += from.len() + to.len();
    if *total > 65536 {
        return Err(InvalidReason::Capacity);
    }
    Ok(())
}

impl LiveState {
    /// Independently compare the full Group Balance and atomically commit its
    /// factor, lifecycle and timing history. This is a preparatory domain API;
    /// it grants no installed scheduling or transport capability.
    #[must_use]
    pub fn observe_group_balance(&mut self, envelope: &Envelope, frame_bytes: usize) -> Progress {
        if let Err(reason) = envelope.validate() {
            self.invalidate(envelope.epoch, reason);
            return self.progress(envelope.epoch);
        }
        let mut sessions = [0; 64];
        for (slot, visit) in sessions.iter_mut().zip(&envelope.visits) {
            *slot = visit.session;
        }
        let previous = self.progress(envelope.epoch).compared_sequence;
        let result = self.begin_caller(Scope {
            epoch: envelope.epoch,
            group: envelope.group,
            sequence: envelope.sequence,
            span: envelope.span,
            sessions: &sessions[..envelope.visits.len()],
            frame_bytes,
        });
        match result {
            Ok(mut stage) => {
                let comparison = stage.compare_balance(envelope);
                stage.finish(comparison)
            }
            Err(reason) => Progress {
                status: super::Status::Invalid(reason),
                compared_sequence: previous,
                transition: None,
            },
        }
    }

    // A callback completion changes failure phase but never the original attempt
    // clock or Group watermark. Run only after the entire lifecycle witness
    // compares, including when the callback interleaves with another Group pass.
    pub(crate) fn update_balance_terminals(&mut self, batch: &Batch) {
        if batch.witness.before.closed {
            return;
        }
        let Some(native) = self.native.get_mut(&batch.epoch) else {
            return;
        };
        for event in &batch.events {
            if let LiveEvent::Lifecycle {
                event: Event::Closed(session),
                ..
            } = event
            {
                for stored in native.groups.values_mut() {
                    if let Some(attempt) = stored.timing.attempts.get_mut(session) {
                        // Close retires the pending attempt; its original time
                        // remains a tombstone and late terminals cannot reset it.
                        attempt.pending = false;
                    }
                }
                continue;
            }
            let LiveEvent::Lifecycle {
                event:
                    Event::Redirected {
                        session,
                        operation,
                        success,
                    },
                ..
            } = event
            else {
                continue;
            };
            for stored in native.groups.values_mut() {
                if let Some(attempt) = stored.timing.attempts.get_mut(session)
                    && attempt.pending
                    && attempt.operation == *operation
                    && batch.witness.before.redirect_pending
                    && !batch.witness.after.redirect_pending
                {
                    attempt.pending = false;
                    attempt.failed = !success;
                }
            }
        }
    }
}

impl Stage<'_> {
    fn timing(&self) -> Result<&Timing, InvalidReason> {
        self.staged.native[&self.epoch]
            .groups
            .get(&self.group)
            .map(|stored| &stored.timing)
            .ok_or(InvalidReason::Lifecycle)
    }

    fn compare_balance(&mut self, e: &Envelope) -> Result<(), InvalidReason> {
        let key = (self.epoch.process, self.epoch.owner);
        let ledger = &self.staged.core.owners[&key].ledger;
        let inventory = ledger.caller_account_ids(e.group);
        let mut count = 0;
        for id in inventory {
            count += 1;
            if !e.members.contains(&id) {
                return Err(InvalidReason::Witness);
            }
        }
        if count != e.members.len()
            || e.evaluation.accounts.len() != e.members.len()
            || e.evaluation
                .accounts
                .iter()
                .zip(&e.members)
                .any(|(a, id)| a.account != *id)
        {
            return Err(InvalidReason::Witness);
        }
        let decision = self.evaluation(&e.evaluation)?;
        let coverage = self.staged.native[&e.epoch].coverage;
        let rate = decision.balance_rate().ok_or(InvalidReason::Witness)?;
        let Start::ReadClock(rate) = arithmetic::start(rate, coverage.go_arch) else {
            if e.clock.is_some() {
                return Err(InvalidReason::Witness);
            }
            return finish_scan(e, 0, 0, 0);
        };
        let clock = e.clock.as_ref().ok_or(InvalidReason::Witness)?;
        let (from, to, _) = decision.pair();
        let from = usize::try_from(from)
            .ok()
            .and_then(|i| e.members.get(i))
            .copied()
            .ok_or(InvalidReason::Witness)?;
        let to = usize::try_from(to)
            .ok()
            .and_then(|i| e.members.get(i))
            .copied()
            .ok_or(InvalidReason::Witness)?;
        if from == to {
            return Err(InvalidReason::Witness);
        }
        let last = self.timing()?.last_accepted.unwrap_or(coverage.zero_time);
        match rate.after_clock(clock.from_keyspace == clock.to_keyspace, clock.now, last) {
            AfterClock::CrossKeyspace | AfterClock::Wait { .. } => finish_scan(e, 0, 0, 0),
            AfterClock::DivideByZero => Err(InvalidReason::Lifecycle),
            AfterClock::Scan { quota, .. } => self.scan_balance(e, from, to, clock.now, quota),
        }
    }

    fn scan_balance(
        &mut self,
        e: &Envelope,
        from: u64,
        to: u64,
        now: GoTime,
        quota: i64,
    ) -> Result<(), InvalidReason> {
        let key = (self.epoch.process, self.epoch.owner);
        let (mut position, mut contexts, mut accepted) = (0, 0, 0_u16);
        loop {
            // The independent list may exceed the admitted visited subset. It
            // remains borrowed from the already charged affected ledger clone.
            let physical = self.staged.core.owners[&key]
                .ledger
                .caller_physical(from)
                .ok_or(InvalidReason::Identity)?;
            let Some(&session) = physical.get(position) else {
                break;
            };
            let cancelled = *e.contexts.get(contexts).ok_or(InvalidReason::Witness)?;
            contexts += 1;
            if cancelled || i64::from(accepted) >= quota {
                break;
            }
            if position >= 64 {
                return Err(InvalidReason::Capacity);
            }
            let visit = e.visits.get(position).ok_or(InvalidReason::Witness)?;
            if visit.session != session {
                return Err(InvalidReason::Witness);
            }
            let ledger = &self.staged.core.owners[&key].ledger;
            let state = ledger.connection(session);
            if !state.present || state.closed || state.physical != from {
                return Err(InvalidReason::Lifecycle);
            }
            let previous = self.timing()?.attempts.get(&session).copied();
            let skip = if state.closing || state.redirect_pending {
                true
            } else {
                let watermark = ledger
                    .caller_redirect_watermark(session)
                    .ok_or(InvalidReason::Identity)?;
                if previous.map_or(0, |old| old.operation) != watermark {
                    // A prior untyped redirect cannot fabricate a known clock.
                    return Err(InvalidReason::Lifecycle);
                }
                previous.is_some_and(|old| {
                    old.failed
                        && old
                            .time
                            .add_nanoseconds(FAILURE_COOLDOWN)
                            .compare(now)
                            .is_gt()
                })
            };
            if skip {
                if visit.redirect.is_some() {
                    return Err(InvalidReason::Witness);
                }
            } else {
                let redirect = visit.redirect.as_ref().ok_or(InvalidReason::Witness)?;
                let issued = self.compare_redirect(session, from, to, now, redirect)?;
                if issued {
                    accepted += 1;
                }
            }
            position += 1;
        }
        // Deliberately late: no child or timing update survives a final mismatch.
        finish_scan(e, position, contexts, accepted)
    }

    fn compare_redirect(
        &mut self,
        session: u64,
        from: u64,
        to: u64,
        now: GoTime,
        redirect: &Redirect,
    ) -> Result<bool, InvalidReason> {
        let accepted = if redirect.from_keyspace == redirect.to_keyspace {
            redirect.callback.ok_or(InvalidReason::Witness)?
        } else {
            if redirect.callback.is_some() {
                return Err(InvalidReason::Witness);
            }
            false
        };
        let [
            LiveEvent::Lifecycle {
                event,
                source,
                target,
            },
        ] = redirect.batch.events.as_slice()
        else {
            return Err(InvalidReason::Witness);
        };
        if *source != from || *target != to {
            return Err(InvalidReason::Witness);
        }
        let paired = match event {
            Event::Redirect {
                session: id,
                operation,
                target,
            } => accepted && *id == session && *operation != 0 && *target == to,
            Event::Rejected { session: id } => !accepted && *id == session,
            _ => false,
        };
        if !paired {
            return Err(InvalidReason::Witness);
        }
        self.batch(&redirect.batch)?;
        let key = (self.epoch.process, self.epoch.owner);
        let operation = self.staged.core.owners[&key]
            .ledger
            .caller_redirect_watermark(session)
            .ok_or(InvalidReason::Identity)?;
        self.record_attempt(
            session,
            Attempt {
                time: now,
                operation,
                pending: accepted,
                failed: !accepted,
            },
            accepted,
        )?;
        Ok(accepted)
    }

    fn record_attempt(
        &mut self,
        session: u64,
        attempt: Attempt,
        accepted: bool,
    ) -> Result<(), InvalidReason> {
        let timing = self.timing()?;
        let growth = if timing.attempts.contains_key(&session) {
            0
        } else {
            ATTEMPT_CHARGE
        };
        if growth != 0 && timing.attempts.len() >= self.staged.limits.sessions {
            return Err(InvalidReason::Capacity);
        }
        let clones = self
            .ledger_clone
            .checked_add(self.factor_charge())
            .and_then(|n| n.checked_add(growth))
            .ok_or(InvalidReason::Capacity)?;
        let budget = Budget::new(self.frame_bytes, self.retained, clones)?;
        self.original.record_caller_budget(budget);
        let stored = self
            .staged
            .native
            .get_mut(&self.epoch)
            .and_then(|owner| owner.groups.get_mut(&self.group))
            .ok_or(InvalidReason::Lifecycle)?;
        // Admission precedes the first possible B-tree allocation. Its 16x
        // entry charge also pays for nodes allocated at a split boundary.
        stored.timing.attempts.insert(session, attempt);
        if accepted {
            stored.timing.last_accepted = Some(attempt.time);
        }
        stored.charge += growth;
        self.staged.native_bytes += growth;
        Ok(())
    }
}

fn finish_scan(
    e: &Envelope,
    visits: usize,
    contexts: usize,
    accepted: u16,
) -> Result<(), InvalidReason> {
    if visits != e.visits.len() || contexts != e.contexts.len() || accepted != e.accepted {
        return Err(InvalidReason::Witness);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
