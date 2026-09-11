// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Group-local Route comparison. Router match/metadata and selector retry
//! binding are separate forthcoming callers; this grants no installed coverage.
use super::selection::{Binding, DerivedResult, ErrorClass};
use super::{Batch, Epoch, Event, InvalidReason, LiveEvent, LiveState, Progress, Scope, Stage};
use crate::shadow::native::{Entry, Evaluation};

/// Already-read getter values in actual call order, with child completion positions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Read {
    /// Group's health getter (not a second factor getter).
    Healthy {
        /// Number of children completed at the actual read site.
        completed: u8,
        /// Admitted backend account being read.
        account: u64,
        /// Already evaluated getter result.
        value: bool,
    },
    /// Backend ID at each actually executed equality comparison.
    BackendId {
        /// Number of children completed at the actual read site.
        completed: u8,
        /// Admitted backend account being read.
        account: u64,
        /// Copied UTF-8 getter result, at most 512 bytes.
        value: String,
    },
    /// Excluded backend ID, preserving the Go loop's short circuit.
    ExcludedId {
        /// Number of children completed at the actual read site.
        completed: u8,
        /// Original exclusion slice index.
        index: u16,
        /// Copied UTF-8 getter result, at most 512 bytes.
        value: String,
    },
}
/// One complete native evaluation or compound lifecycle mutation.
#[derive(Clone, Debug)]
pub enum Child {
    /// Body retains its own epoch, sequence, Group, inputs and witnesses.
    Evaluation(Box<Evaluation>),
    /// Body retains all events and complete before/after witnesses.
    Batch(Batch),
}
/// Actual Group return value and its position after child completions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResultValue {
    /// Selected account, zero exactly for `ErrNoBackend`.
    pub account: u64,
    /// Actual reservation identity, zero exactly for `ErrNoBackend`.
    pub operation: u64,
    /// Number of complete children at return.
    pub completed: u8,
}
/// Bounded value capture, not a source of inventory or routing authority.
#[derive(Clone, Debug)]
pub struct Route {
    /// Nonzero call identity, scoped by the owner and contiguous sequence.
    pub caller: u64,
    /// Group already admitted to the independent ledger.
    pub group: u64,
    /// Selection identity; the ledger owns its lifecycle and operation watermark.
    pub session: u64,
    /// Actual Go exclusion slice length.
    pub excluded_count: u16,
    /// Full Group iteration order; independently checked against retained inventory.
    pub members: Vec<u64>,
    /// Actual caller getter tape, at most 128 entries and 64KiB of strings.
    pub reads: Vec<Read>,
    /// Captured result to compare after independent selection.
    pub result: ResultValue,
}
/// One Group critical section with complete unescaped child bodies.
#[derive(Clone, Debug)]
pub struct Envelope {
    /// Owner incarnation shared by every child.
    pub epoch: Epoch,
    /// First child sequence (or final comparison for a childless caller).
    pub sequence: u64,
    /// Evaluations plus lifecycle events plus one final caller check.
    pub span: u64,
    /// Typed actual caller reads and return value.
    pub route: Route,
    /// Actual completion/mutation order, bounded by four evaluations and 64 batches.
    pub children: Vec<Child>,
}
impl Envelope {
    /// Validate bounded domain values, also for callers that bypass the wire codec.
    ///
    /// # Errors
    /// Rejects invalid identities, size/count limits or non-contiguous child spans.
    pub fn validate(&self) -> Result<(), InvalidReason> {
        let r = &self.route;
        if [
            self.epoch.process,
            self.epoch.owner,
            self.epoch.nonce,
            self.sequence,
            r.caller,
            r.group,
            r.session,
        ]
        .contains(&0)
            || (r.result.account == 0) != (r.result.operation == 0)
        {
            return Err(InvalidReason::Identity);
        }
        if r.members.len() > 64
            || r.excluded_count > 64
            || r.reads.len() > 128
            || self.children.len() > 68
        {
            return Err(InvalidReason::Capacity);
        }
        for (i, id) in r.members.iter().enumerate() {
            if *id == 0 || r.members[..i].contains(id) {
                return Err(InvalidReason::Identity);
            }
        }
        let mut strings = 0;
        for read in &r.reads {
            let (completed, valid, text) = match read {
                Read::Healthy {
                    completed, account, ..
                } => (*completed, *account != 0, ""),
                Read::BackendId {
                    completed,
                    account,
                    value,
                } => (*completed, *account != 0, value.as_str()),
                Read::ExcludedId {
                    completed,
                    index,
                    value,
                } => (*completed, *index < r.excluded_count, value.as_str()),
            };
            if !valid || usize::from(completed) > self.children.len() {
                return Err(InvalidReason::Witness);
            }
            strings += text.len();
            if text.len() > 512 || strings > 65536 {
                return Err(InvalidReason::Capacity);
            }
        }
        let mut next = self.sequence;
        let (mut evaluations, mut batches) = (0, 0);
        for child in &self.children {
            let (epoch, sequence, span) = match child {
                Child::Evaluation(e) => {
                    evaluations += 1;
                    if e.group != r.group {
                        return Err(InvalidReason::Identity);
                    }
                    (e.epoch, e.sequence, 1)
                }
                Child::Batch(b) => {
                    batches += 1;
                    if b.events.is_empty() || b.events.len() > 4 || b.witness.accounts.len() > 2 {
                        return Err(InvalidReason::Capacity);
                    }
                    (b.epoch, b.sequence, b.events.len() as u64)
                }
            };
            if epoch != self.epoch {
                return Err(InvalidReason::Identity);
            }
            if sequence != next {
                return Err(InvalidReason::Sequence);
            }
            next = next.checked_add(span).ok_or(InvalidReason::Sequence)?;
        }
        if evaluations > 4 || batches > 64 {
            return Err(InvalidReason::Capacity);
        }
        if next - self.sequence + 1 != self.span {
            return Err(InvalidReason::Sequence);
        }
        Ok(())
    }
}
impl LiveState {
    /// Compare a complete Group Route, then commit all factor and lifecycle changes
    /// together. No successful child or observed output grants its own commit.
    #[must_use]
    pub fn observe_group_route(&mut self, envelope: &Envelope, frame_bytes: usize) -> Progress {
        self.observe_group_route_result(envelope, frame_bytes).0
    }

    /// Return the independently selected account and validated reservation only
    /// after the entire Group caller commits. Failed or replayed callers expose
    /// no result. This does not validate the router's choice of Group or install
    /// selector history; those remain separate caller integration boundaries.
    #[must_use]
    pub fn observe_group_route_result(
        &mut self,
        envelope: &Envelope,
        frame_bytes: usize,
    ) -> (Progress, Option<DerivedResult>) {
        if let Err(reason) = envelope.validate() {
            self.invalidate(envelope.epoch, reason);
            return (self.progress(envelope.epoch), None);
        }
        let sessions = [envelope.route.session];
        let previous = self.progress(envelope.epoch).compared_sequence;
        let result = self.begin_caller(Scope {
            epoch: envelope.epoch,
            group: envelope.route.group,
            sequence: envelope.sequence,
            span: envelope.span,
            sessions: &sessions,
            frame_bytes,
        });
        match result {
            Ok(mut stage) => {
                let comparison = stage.compare_route(envelope);
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
}
impl Route {
    fn eligible(&self) -> Result<([u64; 64], usize), InvalidReason> {
        let mut eligible = [0; 64];
        let mut length = 0;
        let mut reads = self.reads.iter();
        for &account in &self.members {
            let healthy = match reads.next() {
                Some(Read::Healthy {
                    completed: 0,
                    account: got,
                    value,
                }) if *got == account => *value,
                _ => return Err(InvalidReason::Witness),
            };
            if !healthy {
                continue;
            }
            let mut excluded = false;
            for index in 0..self.excluded_count {
                let id = match reads.next() {
                    Some(Read::BackendId {
                        completed: 0,
                        account: got,
                        value,
                    }) if *got == account => value,
                    _ => return Err(InvalidReason::Witness),
                };
                let exclude = match reads.next() {
                    Some(Read::ExcludedId {
                        completed: 0,
                        index: got,
                        value,
                    }) if *got == index => value,
                    _ => return Err(InvalidReason::Witness),
                };
                if id == exclude {
                    excluded = true;
                    break;
                }
            }
            if !excluded {
                eligible[length] = account;
                length += 1;
            }
        }
        if reads.next().is_some() {
            return Err(InvalidReason::Witness);
        }
        Ok((eligible, length))
    }
}
impl Stage<'_> {
    pub(super) fn compare_route(&mut self, e: &Envelope) -> Result<DerivedResult, InvalidReason> {
        let r = &e.route;
        let key = (e.epoch.process, e.epoch.owner);
        let ledger = &self.staged.core.owners[&key].ledger;
        let mut count = 0;
        for id in ledger.caller_account_ids(r.group) {
            count += 1;
            if !r.members.contains(&id) {
                return Err(InvalidReason::Witness);
            }
        }
        if count != r.members.len() {
            return Err(InvalidReason::Witness);
        }
        let (eligible, length) = r.eligible()?;
        let mut children = e.children.iter();
        let selected = if r.members.is_empty() {
            0
        } else {
            let Some(Child::Evaluation(native)) = children.next() else {
                return Err(InvalidReason::Witness);
            };
            if native.entry != Entry::Route
                || native.accounts.len() != length
                || native
                    .accounts
                    .iter()
                    .zip(&eligible[..length])
                    .any(|(a, id)| a.account != *id)
            {
                return Err(InvalidReason::Witness);
            }
            let decision = self.evaluation(native)?;
            match decision.returned() {
                [] => 0,
                [index] => native.accounts[usize::from(*index)].account,
                _ => return Err(InvalidReason::Witness),
            }
        };
        let Some(Child::Batch(batch)) = children.next() else {
            return Err(InvalidReason::Witness);
        };
        // The reservation child supplies its operation; the caller's return is
        // only a witness. The ledger below validates this operation's lifetime.
        let operation = match batch.events.last() {
            Some(LiveEvent::Lifecycle {
                event: Event::Reserve { operation, .. },
                ..
            }) => *operation,
            _ => 0,
        };
        let expected = LiveEvent::Lifecycle {
            event: Event::Reserve {
                session: r.session,
                operation,
                account: selected,
            },
            source: 0,
            target: 0,
        };
        let paired = if selected == 0 {
            batch.events
                == [LiveEvent::RouteRejected {
                    session: r.session,
                    group: r.group,
                }]
        } else {
            batch.events == [expected.clone()]
                || batch.events
                    == [
                        LiveEvent::Lifecycle {
                            event: Event::Open(r.session),
                            source: 0,
                            target: 0,
                        },
                        expected,
                    ]
        };
        if !paired || selected != r.result.account || operation != r.result.operation {
            return Err(InvalidReason::Witness);
        }
        self.batch(batch)?;
        // Deliberately final: even a fully valid child pair cannot commit if the
        // enclosing caller omitted/added a child or returned at another position.
        if children.next().is_some() || usize::from(r.result.completed) != e.children.len() {
            return Err(InvalidReason::Witness);
        }
        Ok(DerivedResult {
            backend: selected,
            error: if selected == 0 {
                ErrorClass::NoBackend
            } else {
                ErrorClass::None
            },
            binding: (selected != 0).then_some(Binding {
                account: selected,
                group: r.group,
                operation,
            }),
        })
    }
}

#[cfg(test)]
mod tests;
