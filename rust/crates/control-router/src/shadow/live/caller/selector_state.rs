// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::selection::{Boundary, BoundaryEvent, DerivedResult, StoredSelection};
use super::{Budget, InvalidReason, LiveState, Progress, Scope, Stage, route};

impl LiveState {
    /// Compare a real selector entry/return/end with the independently retained
    /// attempt state. No production routing capability is installed by this API.
    #[must_use]
    pub fn observe_selector_boundary(
        &mut self,
        boundary: &Boundary,
        frame_bytes: usize,
    ) -> Progress {
        if let Err(reason) = boundary.validate() {
            self.invalidate(boundary.epoch, reason);
            return self.progress(boundary.epoch);
        }
        let previous = self.progress(boundary.epoch).compared_sequence;
        let result = self.begin_caller(Scope {
            epoch: boundary.epoch,
            group: 0,
            sequence: boundary.sequence,
            span: 1,
            sessions: &[boundary.session],
            frame_bytes,
        });
        match result {
            Ok(mut stage) => {
                let comparison = stage.selector_boundary(boundary);
                stage.finish(comparison)
            }
            Err(reason) => Progress {
                status: super::Status::Invalid(reason),
                compared_sequence: previous,
                transition: None,
            },
        }
    }

    /// Atomically bind an independently compared Group Route to its selector
    /// attempt. Router metadata classification remains a separate required
    /// input to the eventual installed caller dispatcher.
    #[must_use]
    pub fn observe_selector_group_route_result(
        &mut self,
        envelope: &route::Envelope,
        next: u64,
        ordinal: u8,
        excluded: &[u64],
        frame_bytes: usize,
    ) -> (Progress, Option<DerivedResult>) {
        if let Err(reason) = envelope.validate() {
            self.invalidate(envelope.epoch, reason);
            return (self.progress(envelope.epoch), None);
        }
        let previous = self.progress(envelope.epoch).compared_sequence;
        let result = self.begin_caller(Scope {
            epoch: envelope.epoch,
            group: envelope.route.group,
            sequence: envelope.sequence,
            span: envelope.span,
            sessions: &[envelope.route.session],
            frame_bytes,
        });
        match result {
            Ok(mut stage) => {
                let comparison = stage.compare_route(envelope).and_then(|derived| {
                    if excluded.len() != usize::from(envelope.route.excluded_count) {
                        return Err(InvalidReason::Witness);
                    }
                    stage
                        .selector_attempt(envelope.route.session, next, ordinal, excluded, derived)
                        .map(|()| derived)
                });
                let progress = stage.finish(comparison.map(|_| ()));
                let derived = if progress.status == super::Status::Comparing {
                    comparison.ok()
                } else {
                    None
                };
                (progress, derived)
            }
            Err(reason) => (
                Progress {
                    status: super::Status::Invalid(reason),
                    compared_sequence: previous,
                    transition: None,
                },
                None,
            ),
        }
    }

    /// Whether every observed selector of this owner has explicitly closed.
    /// A settled ledger alone cannot prove that Next or selector capture ended.
    #[must_use]
    pub fn selectors_settled(&self, epoch: super::Epoch) -> bool {
        self.selectors
            .iter()
            .filter(|((owner, _), _)| *owner == epoch)
            .all(|(_, stored)| stored.closed && stored.tracker.tail().is_ok())
    }
}

impl Stage<'_> {
    fn selector_boundary(&mut self, boundary: &Boundary) -> Result<(), InvalidReason> {
        let key = (self.epoch, boundary.session);
        if !self.staged.selectors.contains_key(&key) {
            let may_create = matches!(
                boundary.event,
                BoundaryEvent::Begin { next: 1, .. } | BoundaryEvent::Close { next: 0, .. }
            );
            if !may_create {
                return Err(InvalidReason::Lifecycle);
            }
            let count = self
                .original
                .selectors
                .keys()
                .filter(|(epoch, _)| *epoch == self.epoch)
                .count();
            if count >= self.original.limits.sessions {
                return Err(InvalidReason::Capacity);
            }
            let clones = self
                .ledger_clone
                .checked_add(self.original_factor)
                .and_then(|n| n.checked_add(StoredSelection::CHARGE))
                .ok_or(InvalidReason::Capacity)?;
            let budget = Budget::new(self.frame_bytes, self.retained, clones)?;
            self.original.record_caller_budget(budget);
            // Admission precedes the Box allocation and map insertion. Keep the
            // new state in C until commit transfers its fixed charge into R.
            self.staged
                .selectors
                .insert(key, StoredSelection::default());
            self.ledger_clone += StoredSelection::CHARGE;
            self.staged.native_bytes += StoredSelection::CHARGE;
        }
        let stored = self
            .staged
            .selectors
            .get_mut(&key)
            .ok_or(InvalidReason::Identity)?;
        if stored.closed {
            return Err(InvalidReason::Lifecycle);
        }
        match &boundary.event {
            BoundaryEvent::Begin {
                next,
                current,
                excluded,
            } => stored.tracker.begin(*next, *current, excluded),
            BoundaryEvent::End {
                next,
                current,
                excluded,
                backend,
                error,
            } => stored
                .tracker
                .end(*next, *backend, *error, *current, excluded),
            BoundaryEvent::Close {
                next,
                current,
                excluded,
            } => {
                stored.tracker.close_witness(*next, *current, excluded)?;
                stored.closed = true;
                Ok(())
            }
        }
    }

    pub(super) fn selector_attempt(
        &mut self,
        session: u64,
        next: u64,
        ordinal: u8,
        excluded: &[u64],
        derived: DerivedResult,
    ) -> Result<(), InvalidReason> {
        if !self.sessions[..self.session_count].contains(&session) {
            return Err(InvalidReason::Identity);
        }
        let stored = self
            .staged
            .selectors
            .get_mut(&(self.epoch, session))
            .ok_or(InvalidReason::Lifecycle)?;
        if stored.closed {
            return Err(InvalidReason::Lifecycle);
        }
        stored
            .tracker
            .attempt(next, ordinal, excluded, derived)
            .map(|_| ())
    }
}

#[cfg(test)]
#[path = "selector_state_tests.rs"]
mod tests;
