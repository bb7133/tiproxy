// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Native factor comparison shares the lifecycle owner's contiguous prefix.
use super::super::native::{Coverage, Evaluation, FactorState};
use super::{Epoch, InvalidReason, LiveState, Progress, Status};
use std::collections::BTreeMap;

/// Total private factor history plus incoming decode, derivation and clone budget.
pub const HISTORY_LIMIT: usize = 64 * 1024 * 1024;
/// Covers new 64-account B-tree nodes, key storage and temporary score rows.
/// Query/frame copies are charged separately by the transport's decode bound.
pub const STAGE_OVERHEAD: usize = 1024 * 1024;
const OWNER_CHARGE: usize = 16 * size_of::<(Epoch, NativeOwner)>();
const GROUP_CHARGE: usize = 16 * size_of::<(u64, Stored)>();
pub(super) struct NativeOwner {
    coverage: Coverage,
    groups: BTreeMap<u64, Stored>,
}
struct Stored {
    state: FactorState,
    charge: usize,
}
impl LiveState {
    /// The producer capability must arrive before the owner's first Begin.
    ///
    /// # Errors
    /// Refuses duplicate/late preludes, conflicting process origins and bounds.
    pub fn install_native(&mut self, coverage: Coverage) -> Result<(), InvalidReason> {
        let result = self.install_native_inner(coverage);
        if let Err(reason) = result {
            self.invalidate(coverage.epoch, reason);
        }
        result
    }
    fn install_native_inner(&mut self, coverage: Coverage) -> Result<(), InvalidReason> {
        let epoch = coverage.epoch;
        if self.native.contains_key(&epoch)
            || self.core.owners.contains_key(&(epoch.process, epoch.owner))
        {
            return Err(InvalidReason::Identity);
        }
        if self.native.len() >= self.limits.owners || !self.native_can_stage(OWNER_CHARGE) {
            return Err(InvalidReason::Capacity);
        }
        if self.native.values().any(|old| {
            old.coverage.epoch.process == epoch.process
                && old.coverage.epoch.nonce == epoch.nonce
                && (old.coverage.origin != coverage.origin
                    || old.coverage.go_arch != coverage.go_arch)
        }) {
            return Err(InvalidReason::Identity);
        }
        self.native.insert(
            epoch,
            NativeOwner {
                coverage,
                groups: BTreeMap::new(),
            },
        );
        self.native_bytes += OWNER_CHARGE;
        Ok(())
    }
    /// Accepted origin for strict transport decoding, without creating authority.
    #[must_use]
    pub fn native_coverage(&self, epoch: Epoch) -> Option<Coverage> {
        self.native.get(&epoch).map(|owner| owner.coverage)
    }
    /// Check before allocating any incoming body or staging a group clone.
    #[must_use]
    pub fn native_can_stage(&self, charge: usize) -> bool {
        charge <= HISTORY_LIMIT.saturating_sub(self.native_bytes)
    }
    /// Highest admitted private retained plus staged charge.
    #[must_use]
    pub fn native_peak_bytes(&self) -> usize {
        self.native_peak
    }
    /// Admit incoming decode storage and record its diagnostic high water.
    pub fn native_admit_stage(&mut self, charge: usize) -> bool {
        if !self.native_can_stage(charge) {
            return false;
        }
        self.native_peak = self.native_peak.max(self.native_bytes + charge);
        true
    }
    /// Retained private history charge; includes invalid and retired owners.
    #[must_use]
    pub fn native_retained_bytes(&self) -> usize {
        self.native_bytes
    }
    /// Compare one complete evaluation and atomically advance history and prefix.
    /// `staging` includes the transport-owned frame and its decoder/derivation peak.
    pub fn observe_native(&mut self, e: &Evaluation, staging: usize) -> Progress {
        let key = (e.epoch.process, e.epoch.owner);
        match self.core.owners.get(&key) {
            None => {
                self.invalidate(e.epoch, InvalidReason::MissingBegin);
            }
            Some(owner) if owner.epoch != e.epoch => {
                self.invalidate(e.epoch, InvalidReason::Identity);
            }
            Some(owner) if owner.status == Status::Comparing => {
                if let Err(reason) = self.compare_native(e, staging) {
                    self.invalidate(e.epoch, reason);
                }
            }
            Some(owner) if matches!(owner.status, Status::Invalid(_)) => (),
            Some(_) => {
                self.invalidate(e.epoch, InvalidReason::Lifecycle);
            }
        }
        self.progress(e.epoch)
    }
    fn compare_native(&mut self, e: &Evaluation, staging: usize) -> Result<(), InvalidReason> {
        let key = (e.epoch.process, e.epoch.owner);
        let owner = self
            .core
            .owners
            .get(&key)
            .ok_or(InvalidReason::MissingBegin)?;
        if owner.epoch != e.epoch {
            return Err(InvalidReason::Identity);
        }
        if owner.sequence.checked_add(1) != Some(e.sequence) {
            return Err(InvalidReason::Sequence);
        }
        if self
            .groups
            .get(&key)
            .and_then(|groups| groups.get(&e.group))
            != Some(&true)
        {
            return Err(InvalidReason::Identity);
        }
        if e.accounts.len() > 64 || e.reads.len() > 128 {
            return Err(InvalidReason::Capacity);
        }
        for account in &e.accounts {
            if owner.ledger.account_group(account.account) != Some(e.group) {
                return Err(InvalidReason::Identity);
            }
            let counts = owner
                .ledger
                .compact_account(account.account)
                .ok_or(InvalidReason::Identity)?;
            if account.seen & 8 != 0 && account.score_count != counts.score
                || account.seen & 4 != 0
                    && u64::try_from(account.physical).ok() != Some(counts.physical)
            {
                return Err(InvalidReason::Witness);
            }
        }
        let native = self
            .native
            .get(&e.epoch)
            .ok_or(InvalidReason::MissingBegin)?;
        let old = native.groups.get(&e.group);
        let old_charge = old.map_or(0, |stored| stored.charge);
        let peak = staging
            .checked_add(old_charge)
            .and_then(|v| v.checked_add(STAGE_OVERHEAD))
            .ok_or(InvalidReason::Capacity)?;
        if !self.native_can_stage(peak) {
            return Err(InvalidReason::Capacity);
        }
        self.native_peak = self.native_peak.max(self.native_bytes + peak);
        // Admission precedes cloning any retained query or factor snapshot.
        let mut staged = old.map_or_else(
            || FactorState::new(native.coverage),
            |stored| stored.state.clone(),
        );
        staged.apply(e).map_err(|_| InvalidReason::Witness)?;
        let charge = staged.retained_bytes() + GROUP_CHARGE;
        if charge > old_charge + staging + STAGE_OVERHEAD {
            return Err(InvalidReason::Capacity);
        }
        self.native_bytes = self.native_bytes - old_charge + charge;
        let native = self
            .native
            .get_mut(&e.epoch)
            .ok_or(InvalidReason::Identity)?;
        native.groups.insert(
            e.group,
            Stored {
                state: staged,
                charge,
            },
        );
        // The only sequence write is after the entire independent comparison.
        self.core
            .owners
            .get_mut(&key)
            .ok_or(InvalidReason::Identity)?
            .sequence = e.sequence;
        Ok(())
    }
}

#[cfg(test)]
#[path = "native_tests.rs"]
mod tests;
