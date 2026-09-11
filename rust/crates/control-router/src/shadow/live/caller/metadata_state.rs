// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::metadata::{Boundary, Event, StoredMetadata, Tracker};
use super::{
    Batch, Budget, Entry, Evaluation, InvalidReason, LiveEvent, LiveState, Progress, Scope, Stage,
    Status,
};

impl LiveState {
    /// Independently compare a metadata frame using the retained owner tracker.
    /// Its affected snapshot, growth and decoder coexist under D+R+C+S; only a
    /// successful final caller check transfers it into retained history.
    #[must_use]
    pub fn observe_router_metadata(&mut self, boundary: &Boundary, frame_bytes: usize) -> Progress {
        let previous = self.progress(boundary.epoch).compared_sequence;
        let result = self.begin_caller(Scope {
            epoch: boundary.epoch,
            group: 0,
            sequence: boundary.sequence,
            span: 1,
            sessions: &[],
            frame_bytes,
        });
        match result {
            Ok(mut stage) => {
                let comparison = stage.compare_metadata(boundary);
                stage.finish(comparison)
            }
            Err(reason) => Progress {
                status: Status::Invalid(reason),
                compared_sequence: previous,
                transition: None,
            },
        }
    }

    /// Borrow independently retained metadata without allocating a diagnostic
    /// ledger view or a matcher clone. No production capability is installed.
    #[must_use]
    pub fn router_metadata(&self, epoch: super::Epoch) -> Option<&Tracker> {
        self.metadata
            .get(&epoch)
            .map(|stored| stored.tracker.as_ref())
    }

    fn prepare_metadata_prefix(
        &mut self,
        epoch: super::Epoch,
        frame_bytes: usize,
    ) -> Result<Option<StoredMetadata>, InvalidReason> {
        let Some(old) = self.metadata.get(&epoch) else {
            return Ok(None);
        };
        if self.progress(epoch).status != Status::Comparing {
            return Err(InvalidReason::Lifecycle);
        }
        let charge = StoredMetadata::fork_charge(Some(old));
        let budget = Budget::new(frame_bytes, self.native_bytes, charge)?;
        self.record_caller_budget(budget);
        Ok(Some(StoredMetadata::fork(self.metadata.get(&epoch))))
    }

    fn commit_metadata_prefix(&mut self, epoch: super::Epoch, stored: StoredMetadata) {
        let old = self
            .metadata
            .get(&epoch)
            .map_or(0, StoredMetadata::retained_charge);
        self.native_bytes = self.native_bytes - old + stored.retained_charge();
        self.metadata.insert(epoch, stored);
    }

    /// Compare Group lifecycle records with both the metadata generation and
    /// the original ledger witness. Failed children preserve metadata's prior
    /// accepted prefix; the original ledger invalidation semantics still apply.
    #[must_use]
    pub fn observe_router_metadata_batch(&mut self, batch: &Batch, frame_bytes: usize) -> Progress {
        let relevant = batch.events.iter().any(|event| {
            matches!(
                event,
                LiveEvent::GroupCreated(_) | LiveEvent::GroupRemoved(_)
            )
        });
        if !relevant {
            return self.observe(batch);
        }
        let prepared = self
            .prepare_metadata_prefix(batch.epoch, frame_bytes)
            .and_then(|mut stored| {
                if let Some(stored) = stored.as_mut() {
                    for event in &batch.events {
                        stored.tracker.group_event(event)?;
                    }
                }
                Ok(stored)
            });
        let stored = match prepared {
            Ok(stored) => stored,
            Err(reason) => return self.invalidate(batch.epoch, reason),
        };
        let progress = self.observe(batch);
        if progress.status == Status::Comparing
            && let Some(stored) = stored
        {
            self.commit_metadata_prefix(batch.epoch, stored);
        }
        progress
    }

    /// Bind native Init/SetConfig only when its complete factor comparison also
    /// succeeds. The metadata snapshot remains charged during factor staging.
    #[must_use]
    pub fn observe_router_metadata_native(
        &mut self,
        evaluation: &Evaluation,
        frame_bytes: usize,
    ) -> Progress {
        let epoch = evaluation.epoch;
        let prepared = if evaluation.entry == Entry::Config {
            self.prepare_metadata_prefix(epoch, frame_bytes)
                .and_then(|mut stored| {
                    if let Some(stored) = stored.as_mut() {
                        stored.tracker.native_init(evaluation.group)?;
                    }
                    Ok(stored)
                })
        } else {
            Ok(None)
        };
        let stored = match prepared {
            Ok(stored) => stored,
            Err(reason) => return self.invalidate(epoch, reason),
        };
        let extra = stored.as_ref().map_or(0, StoredMetadata::retained_charge);
        let Some(staging) = frame_bytes
            .checked_mul(super::DECODE_MULTIPLIER)
            .and_then(|n| n.checked_add(extra))
        else {
            return self.invalidate(epoch, InvalidReason::Capacity);
        };
        let progress = self.observe_native(evaluation, staging);
        if progress.status == Status::Comparing
            && let Some(stored) = stored
        {
            self.commit_metadata_prefix(epoch, stored);
        }
        progress
    }
}

impl Stage<'_> {
    fn compare_metadata(&mut self, boundary: &Boundary) -> Result<(), InvalidReason> {
        let old = self.original.metadata.get(&self.epoch);
        if old.is_none() && !matches!(&boundary.event, Event::Begin(begin) if begin.generation == 1)
        {
            return Err(InvalidReason::MissingBegin);
        }
        if old.is_none()
            && self
                .original
                .groups
                .get(&(self.epoch.process, self.epoch.owner))
                .is_some_and(|groups| !groups.is_empty())
        {
            return Err(InvalidReason::Lifecycle);
        }
        let extra = StoredMetadata::fork_charge(old);
        let initial = Budget::new(self.frame_bytes, self.retained, self.ledger_clone + extra)?;
        self.original.record_caller_budget(initial);
        let mut stored = StoredMetadata::fork(self.original.metadata.get(&self.epoch));
        let overhead = stored.retained_charge() - stored.tracker.retained_charge();
        let mut peak = initial;
        let mut admit = |charge: usize| {
            let budget = Budget::new(
                self.frame_bytes,
                self.retained,
                self.ledger_clone + overhead + charge,
            )?;
            if budget.peak > peak.peak {
                peak = budget;
            }
            Ok(())
        };
        let key = (self.epoch.process, self.epoch.owner);
        let owner = &self.original.core.owners[&key];
        let result = match &boundary.event {
            Event::Begin(begin) => stored.tracker.begin(begin.clone(), &mut admit),
            Event::Assign(assign) => stored.tracker.assign(
                assign,
                |account| {
                    owner
                        .ledger
                        .compact_account(account)
                        .is_none_or(|counts| counts.physical == 0 && counts.score == 0)
                },
                &mut admit,
            ),
            Event::Refresh(refresh) => stored.tracker.refresh(refresh, &mut admit),
            Event::End(end) => stored.tracker.end(*end, &mut admit),
        };
        self.original.record_caller_budget(peak);
        result?;
        self.metadata = Some(stored);
        Ok(())
    }

    pub(super) fn metadata_commit_charge(&self, retained: usize) -> Result<usize, InvalidReason> {
        let Some(stored) = self.metadata.as_ref() else {
            return Ok(retained);
        };
        let old = self
            .original
            .metadata
            .get(&self.epoch)
            .map_or(0, StoredMetadata::retained_charge);
        retained
            .checked_sub(old)
            .and_then(|n| n.checked_add(stored.retained_charge()))
            .filter(|n| *n <= super::HISTORY_LIMIT)
            .ok_or(InvalidReason::Capacity)
    }
}

#[cfg(test)]
mod tests;
