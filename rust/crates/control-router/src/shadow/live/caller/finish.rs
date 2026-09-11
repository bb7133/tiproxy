// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::{
    Batch, Epoch, Event, InvalidReason, LiveEvent, LiveState, Progress, Scope, Stage, Status,
};

/// Actual Group Finish arguments and the complete Created child. Captured
/// arguments are witnesses; the retained selector and ledger supply authority.
#[derive(Clone, Debug)]
pub struct Envelope {
    /// Owner incarnation shared with the child.
    pub epoch: Epoch,
    /// Created sequence, followed by the caller comparison.
    pub sequence: u64,
    /// Exactly one Created plus one final comparison.
    pub span: u64,
    /// Nonzero actual caller identity.
    pub caller: u64,
    /// Actual Group being entered.
    pub group: u64,
    /// Original selector session.
    pub session: u64,
    /// Actual backend passed to Finish, without rereading a getter.
    pub backend: u64,
    /// Original reservation operation captured before Created changes state.
    pub operation: u64,
    /// Actual connection creation outcome.
    pub success: bool,
    /// Complete existing lifecycle body, including before/after witnesses.
    pub created: Batch,
}
impl Envelope {
    /// Validate fixed envelope shape before opening the affected-view stage.
    ///
    /// # Errors
    /// Rejects foreign, non-contiguous or non-Created children and invalid IDs.
    pub fn validate(&self) -> Result<(), InvalidReason> {
        if [
            self.epoch.process,
            self.epoch.owner,
            self.epoch.nonce,
            self.sequence,
            self.caller,
            self.group,
            self.session,
            self.backend,
            self.operation,
        ]
        .contains(&0)
            || self.created.epoch != self.epoch
            || self.created.sequence != self.sequence
        {
            return Err(InvalidReason::Identity);
        }
        if self.span != 2
            || self.sequence.checked_add(1).is_none()
            || self.created.witness.accounts.len() != 1
            || !matches!(
                self.created.events.as_slice(),
                [LiveEvent::Lifecycle {
                    event: Event::Created { .. },
                    ..
                }]
            )
        {
            return Err(InvalidReason::Witness);
        }
        Ok(())
    }
}
impl LiveState {
    /// Compare and commit Finish, selector binding and Created atomically.
    /// No lifecycle child can escape a rejected final caller comparison.
    #[must_use]
    pub fn observe_selector_finish(&mut self, envelope: &Envelope, frame_bytes: usize) -> Progress {
        if let Err(reason) = envelope.validate() {
            self.invalidate(envelope.epoch, reason);
            return self.progress(envelope.epoch);
        }
        let previous = self.progress(envelope.epoch).compared_sequence;
        match self.begin_caller(Scope {
            epoch: envelope.epoch,
            group: envelope.group,
            sequence: envelope.sequence,
            span: envelope.span,
            sessions: &[envelope.session],
            frame_bytes,
        }) {
            Ok(mut stage) => {
                let comparison = stage.compare_finish(envelope);
                stage.finish(comparison)
            }
            Err(reason) => Progress {
                status: Status::Invalid(reason),
                compared_sequence: previous,
                transition: None,
            },
        }
    }
}
impl Stage<'_> {
    fn compare_finish(&mut self, envelope: &Envelope) -> Result<(), InvalidReason> {
        let stored = self
            .staged
            .selectors
            .get_mut(&(self.epoch, envelope.session))
            .filter(|stored| !stored.closed)
            .ok_or(InvalidReason::Lifecycle)?;
        let binding = stored.tracker.finish_binding(envelope.backend)?;
        self.batch(&envelope.created)?;
        // Check caller identity bindings after the real child comparison: a
        // failure here must discard the staged refund/attachment and sequence.
        if binding.group != envelope.group
            || binding.operation != envelope.operation
            || binding.account != envelope.created.witness.accounts[0].id
            || !matches!(envelope.created.events.as_slice(), [LiveEvent::Lifecycle {
                event: Event::Created { session, operation, success }, ..
            }] if *session == envelope.session && *operation == envelope.operation && *success == envelope.success)
        {
            return Err(InvalidReason::Witness);
        }
        Ok(())
    }
}
