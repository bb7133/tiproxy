// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Affected-view transactions; no caller transport or installed capability yet.
//! The forthcoming typed caller comparator must supply its independent final
//! result. Successfully comparing children alone does not verify a caller.

/// Go-compatible caller arithmetic, independent of production effects.
pub mod arithmetic;

use super::native::{HISTORY_LIMIT, NativeOwner, STAGE_OVERHEAD, Stored};
use super::{Batch, Epoch, Event, InvalidReason, LiveEvent, LiveState, Progress, Status};
use crate::shadow::native::{Decision, Evaluation};
use std::collections::BTreeMap;

/// Complete caller frame limit, including its four-byte prefix.
pub const MAX_CALLER_FRAME: usize = 1024 * 1024;
/// Admission covers simultaneous raw bytes, nested decoding and domain values.
pub const DECODE_MULTIPLIER: usize = 32;

/// One captured critical section, not a whole router traversal.
#[derive(Clone, Copy)]
pub struct Scope<'a> {
    /// Immutable native owner identity.
    pub epoch: Epoch,
    /// Existing Group, or zero for an attempt before entering any Group.
    pub group: u64,
    /// First child sequence, or final caller sequence for a childless scope.
    pub sequence: u64,
    /// All child events/evaluations plus exactly one final caller check.
    pub span: u64,
    /// Bounded session keys the caller will examine, including new identities.
    pub sessions: &'a [u64],
    /// Actual prefix plus body length, supplied by the bounded transport.
    pub frame_bytes: usize,
}

/// A simultaneous admitted memory witness, not a sum of independent maxima.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Budget {
    /// Complete incoming encoded frame, including prefix (F).
    pub frame: usize,
    /// Nested decoder reservation, 32F (D).
    pub decode: usize,
    /// Existing retained native/caller history (R).
    pub retained: usize,
    /// All concurrently retained affected-view copies (C).
    pub clones: usize,
    /// Fixed temporary/new-key allowance (S).
    pub fixed: usize,
    /// Admitted D + R + C + S.
    pub peak: usize,
}
impl Budget {
    fn new(frame: usize, retained: usize, clones: usize) -> Result<Self, InvalidReason> {
        if !(5..=MAX_CALLER_FRAME).contains(&frame) {
            return Err(InvalidReason::Capacity);
        }
        let decode = frame
            .checked_mul(DECODE_MULTIPLIER)
            .ok_or(InvalidReason::Capacity)?;
        let peak = decode
            .checked_add(retained)
            .and_then(|n| n.checked_add(clones))
            .and_then(|n| n.checked_add(STAGE_OVERHEAD))
            .filter(|n| *n <= HISTORY_LIMIT)
            .ok_or(InvalidReason::Capacity)?;
        Ok(Self {
            frame,
            decode,
            retained,
            clones,
            fixed: STAGE_OVERHEAD,
            peak,
        })
    }
}

/// One privately staged Group and bounded session/account subset. Dropping an
/// unfinished transaction invalidates the owner, while preserving its original
/// history and compared prefix. It holds no production lock or effect handle.
pub struct Stage<'a> {
    original: &'a mut LiveState,
    staged: LiveState,
    epoch: Epoch,
    group: u64,
    last_sequence: u64,
    sessions: [u64; 64],
    session_count: usize,
    evaluations: usize,
    batches: usize,
    frame_bytes: usize,
    retained: usize,
    ledger_clone: usize,
    original_factor: usize,
    failed: Option<InvalidReason>,
    finished: bool,
}

impl LiveState {
    /// Highest admitted caller D/R/C/S tuple, recorded at one actual boundary.
    #[must_use]
    pub const fn caller_peak_budget(&self) -> Option<Budget> {
        self.caller_peak
    }

    fn record_caller_budget(&mut self, budget: Budget) {
        self.native_peak = self.native_peak.max(budget.peak);
        if self.caller_peak.is_none_or(|old| budget.peak > old.peak) {
            self.caller_peak = Some(budget);
        }
    }

    /// Reserve affected-view copies before allocating them. No child can commit
    /// to the original state before the caller comparator finishes this stage.
    /// This preparation API does not install selection/scheduler observation.
    ///
    /// # Errors
    /// Invalidates on identity, sequence, population or shared-budget failure.
    pub fn begin_caller(&mut self, scope: Scope<'_>) -> Result<Stage<'_>, InvalidReason> {
        let plan = self.caller_plan(scope);
        let (ledger_clone, original_factor, last_sequence, budget) = match plan {
            Ok(plan) => plan,
            Err(reason) => {
                self.invalidate(scope.epoch, reason);
                return Err(reason);
            }
        };
        self.record_caller_budget(budget);
        let key = (scope.epoch.process, scope.epoch.owner);
        let owner = &self.core.owners[&key];
        let mut staged = Self::new(self.limits);
        staged.core.owners.insert(
            key,
            crate::shadow::Owner {
                epoch: owner.epoch,
                local_identity: owner.local_identity,
                sequence: owner.sequence,
                status: owner.status,
                ledger: owner.ledger.fork_caller(scope.group, scope.sessions),
            },
        );
        if scope.group != 0 {
            staged
                .groups
                .insert(key, BTreeMap::from([(scope.group, true)]));
        }
        let native = &self.native[&scope.epoch];
        let mut groups = BTreeMap::new();
        if let Some(old) = native.groups.get(&scope.group) {
            groups.insert(
                scope.group,
                Stored {
                    state: old.state.clone(),
                    charge: old.charge,
                },
            );
        }
        staged.native.insert(
            scope.epoch,
            NativeOwner {
                coverage: native.coverage,
                groups,
            },
        );
        // Original history remains alive. The staged factor group is an extra
        // copy, not a replacement, until the final caller check commits.
        staged.native_bytes = budget.retained + ledger_clone + original_factor;
        let mut sessions = [0; 64];
        sessions[..scope.sessions.len()].copy_from_slice(scope.sessions);
        Ok(Stage {
            retained: budget.retained,
            original: self,
            staged,
            epoch: scope.epoch,
            group: scope.group,
            last_sequence,
            sessions,
            session_count: scope.sessions.len(),
            evaluations: 0,
            batches: 0,
            frame_bytes: scope.frame_bytes,
            ledger_clone,
            original_factor,
            failed: None,
            finished: false,
        })
    }

    fn caller_plan(&self, scope: Scope<'_>) -> Result<(usize, usize, u64, Budget), InvalidReason> {
        let key = (scope.epoch.process, scope.epoch.owner);
        let owner = self
            .core
            .owners
            .get(&key)
            .ok_or(InvalidReason::MissingBegin)?;
        if owner.epoch != scope.epoch || self.core.fatal.is_some() {
            return Err(InvalidReason::Identity);
        }
        if owner.status != Status::Comparing {
            return Err(InvalidReason::Lifecycle);
        }
        if owner.sequence.checked_add(1) != Some(scope.sequence)
            || scope.span == 0
            || scope.span > 261
        {
            return Err(InvalidReason::Sequence);
        }
        let last = scope
            .sequence
            .checked_add(scope.span - 1)
            .ok_or(InvalidReason::Sequence)?;
        if scope.group != 0
            && self.groups.get(&key).and_then(|g| g.get(&scope.group)) != Some(&true)
        {
            return Err(InvalidReason::Identity);
        }
        let native = self
            .native
            .get(&scope.epoch)
            .ok_or(InvalidReason::MissingBegin)?;
        let factor = native.groups.get(&scope.group).map_or(0, |old| old.charge);
        let ledger = owner
            .ledger
            .caller_clone_charge(scope.group, scope.sessions)?;
        let clones = ledger.checked_add(factor).ok_or(InvalidReason::Capacity)?;
        let budget = Budget::new(scope.frame_bytes, self.native_bytes, clones)?;
        Ok((ledger, factor, last, budget))
    }
}

impl Stage<'_> {
    fn check(&self) -> Result<(), InvalidReason> {
        self.failed.map_or(Ok(()), Err)
    }

    fn remember<T>(&mut self, result: Result<T, InvalidReason>) -> Result<T, InvalidReason> {
        if let Err(reason) = result {
            self.failed.get_or_insert(reason);
        }
        result
    }

    fn factor_charge(&self) -> usize {
        self.staged.native[&self.epoch]
            .groups
            .get(&self.group)
            .map_or(0, |old| old.charge)
    }

    /// Independently compare a child against this private ledger/factor stage.
    /// Extra per-child factor cloning is charged simultaneously with the parent
    /// stage and original history; it cannot borrow the parent's charge twice.
    ///
    /// # Errors
    /// A failed child permanently poisons the entire transaction.
    pub fn evaluation(&mut self, evaluation: &Evaluation) -> Result<Decision, InvalidReason> {
        self.check()?;
        let result = self.evaluation_inner(evaluation);
        self.remember(result)
    }

    fn evaluation_inner(&mut self, e: &Evaluation) -> Result<Decision, InvalidReason> {
        if self.evaluations >= 4 {
            return Err(InvalidReason::Capacity);
        }
        if e.epoch != self.epoch || self.group == 0 || e.group != self.group {
            return Err(InvalidReason::Identity);
        }
        let factor = self.factor_charge();
        let clones = factor
            .checked_mul(2)
            .and_then(|n| n.checked_add(self.ledger_clone))
            .ok_or(InvalidReason::Capacity)?;
        let budget = Budget::new(self.frame_bytes, self.retained, clones)?;
        self.original.record_caller_budget(budget);
        let (progress, decision) = self.staged.observe_native_decision(e, budget.decode);
        checked_progress(progress)?;
        self.evaluations += 1;
        decision.ok_or(InvalidReason::Witness)
    }

    /// Apply a complete compound lifecycle child in its actual mutation order.
    /// Only declared sessions and the independently known Group accounts exist
    /// in the fork. Owner/account incarnation and router metadata events remain
    /// outside this per-Group transaction preparation API.
    ///
    /// # Errors
    /// Rejects escaping scope, malformed witnesses, population loss or >64 batches.
    pub fn batch(&mut self, batch: &Batch) -> Result<(), InvalidReason> {
        self.check()?;
        let result = self.batch_inner(batch);
        self.remember(result)
    }

    fn batch_inner(&mut self, batch: &Batch) -> Result<(), InvalidReason> {
        if self.batches >= 64 {
            return Err(InvalidReason::Capacity);
        }
        if batch.epoch != self.epoch {
            return Err(InvalidReason::Identity);
        }
        for event in &batch.events {
            if let Some(id) = event.session()
                && !self.sessions[..self.session_count].contains(&id)
            {
                return Err(InvalidReason::Identity);
            }
            match event {
                LiveEvent::Lifecycle {
                    event:
                        Event::Begin
                        | Event::End
                        | Event::Retire
                        | Event::Policy(_)
                        | Event::Account { .. }
                        | Event::RemoveAccount(_),
                    ..
                }
                | LiveEvent::GroupCreated(_)
                | LiveEvent::GroupRemoved(_) => return Err(InvalidReason::Lifecycle),
                LiveEvent::RouteRejected { session, group }
                    if *group != self.group
                        || !self.sessions[..self.session_count].contains(session) =>
                {
                    return Err(InvalidReason::Identity);
                }
                _ => (),
            }
        }
        checked_progress(self.staged.observe(batch))?;
        self.batches += 1;
        Ok(())
    }

    /// Commit only after the typed caller comparator supplies its independent
    /// result. Passing child checks alone is insufficient. Until that comparator
    /// and actual hooks are installed, this API grants no caller capability.
    #[must_use]
    pub fn finish(mut self, caller_result: Result<(), InvalidReason>) -> Progress {
        let result = self.check().and(caller_result).and_then(|()| self.commit());
        self.finished = true;
        if let Err(reason) = result {
            self.original.invalidate(self.epoch, reason);
        }
        self.original.progress(self.epoch)
    }

    fn commit(&mut self) -> Result<(), InvalidReason> {
        let key = (self.epoch.process, self.epoch.owner);
        let staged_owner = self
            .staged
            .core
            .owners
            .get(&key)
            .ok_or(InvalidReason::Identity)?;
        if staged_owner.sequence.checked_add(1) != Some(self.last_sequence) {
            return Err(InvalidReason::Sequence);
        }
        let current_factor = self.factor_charge();
        let retained = self
            .retained
            .checked_sub(self.original_factor)
            .and_then(|n| n.checked_add(current_factor))
            .ok_or(InvalidReason::Capacity)?;
        // Validate both destinations before the first mutation of original state.
        if !self.original.core.owners.contains_key(&key)
            || !self.original.native.contains_key(&self.epoch)
        {
            return Err(InvalidReason::Identity);
        }
        let owner = self
            .staged
            .core
            .owners
            .remove(&key)
            .ok_or(InvalidReason::Identity)?;
        let factor = self
            .staged
            .native
            .get_mut(&self.epoch)
            .and_then(|n| n.groups.remove(&self.group));
        if let (Some(original), Some(native)) = (
            self.original.core.owners.get_mut(&key),
            self.original.native.get_mut(&self.epoch),
        ) {
            original.ledger.commit_caller(owner.ledger);
            if let Some(factor) = factor {
                native.groups.insert(self.group, factor);
            }
            original.sequence = self.last_sequence;
            self.original.native_bytes = retained;
            Ok(())
        } else {
            Err(InvalidReason::Identity)
        }
    }
}

impl Drop for Stage<'_> {
    fn drop(&mut self) {
        if !self.finished {
            self.original
                .invalidate(self.epoch, self.failed.unwrap_or(InvalidReason::Lifecycle));
        }
    }
}

fn checked_progress(progress: Progress) -> Result<(), InvalidReason> {
    match progress.status {
        Status::Comparing => Ok(()),
        Status::Invalid(reason) => Err(reason),
        _ => Err(InvalidReason::Lifecycle),
    }
}

#[cfg(test)]
mod tests;
