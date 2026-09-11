// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Fixture-only composition of real Go routeOnce captures with selector state.
//! Router metadata, runtime dispatch and shared selector retention are not installed.
use control_router::shadow::{
    Epoch, Event, Limits, Status,
    live::{
        LiveEvent, LiveState,
        caller::{
            finish,
            selection::{Binding, ErrorClass, Tracker},
        },
    },
};
use legacy_router_shadow::{caller, live};
use serde::Deserialize;
use std::{fs, io};
#[path = "support/route_prefix.rs"]
mod prefix;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Error {
    None,
    Sentinel,
    Other,
}
impl From<Error> for ErrorClass {
    fn from(error: Error) -> Self {
        match error {
            Error::None => Self::None,
            Error::Sentinel => Self::NoBackend,
            Error::Other => Self::Other,
        }
    }
}
#[derive(Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase", deny_unknown_fields)]
enum Record {
    Frame {
        bytes: Vec<u8>,
    },
    Begin {
        next: u64,
        current: u64,
        excluded: Vec<u64>,
    },
    Attempt {
        next: u64,
        ordinal: u8,
        excluded: Vec<u64>,
        backend: u64,
        error: Error,
        bytes: Vec<u8>,
    },
    End {
        next: u64,
        backend: u64,
        error: Error,
        current: u64,
        excluded: Vec<u64>,
    },
    Finish {
        backend: u64,
        #[serde(default)]
        success: bool,
    },
    Tail {
        next: u64,
        attempts: usize,
        successes: usize,
        rejected: usize,
    },
}

fn check<T>(value: std::result::Result<T, control_router::shadow::InvalidReason>) -> Result<T> {
    value.map_err(|e| io::Error::other(format!("SELECTOR_ROUTE_TRANSITION {e:?}")).into())
}

#[derive(Default)]
struct Replay {
    tracker: Tracker,
    captured_boundaries: usize,
    captured_finishes: usize,
    finish_successes: usize,
    finish_success: bool,
    session: Option<u64>,
    pending: Option<Binding>,
    next: u64,
    attempts: usize,
    successes: usize,
    rejected: usize,
    switches: usize,
    previous_group: Option<u64>,
    tail: bool,
}
impl Replay {
    fn attempt(
        &mut self,
        state: &mut LiveState,
        origin: Option<control_routing::go_time::Origin>,
        record: &Record,
    ) -> Result<()> {
        let Record::Attempt {
            next,
            ordinal,
            excluded,
            backend,
            error,
            bytes,
        } = record
        else {
            return Err("attempt variant".into());
        };
        let caller::Frame::GroupRoute(e) =
            caller::decode_caller(bytes, origin, state.native_retained_bytes())?
        else {
            return Err("SELECTOR_ROUTE_FAMILY".into());
        };
        if self
            .session
            .is_some_and(|session| session != e.route.session)
            || usize::from(e.route.excluded_count) != excluded.len()
        {
            return Err("SELECTOR_ROUTE_SCOPE".into());
        }
        self.session = Some(e.route.session);
        let (progress, derived) = if self.captured_boundaries == 0 {
            state.observe_group_route_result(&e, bytes.len())
        } else {
            state.observe_selector_group_route_result(&e, *next, *ordinal, excluded, bytes.len())
        };
        if progress.status != Status::Comparing
            || progress.compared_sequence != e.sequence + e.span - 1
        {
            return Err("SELECTOR_ROUTE_GROUP_COMPARISON".into());
        }
        let derived = derived.ok_or("SELECTOR_ROUTE_COMMITTED_RESULT")?;
        if (derived.backend, derived.error) != (*backend, (*error).into()) {
            return Err("SELECTOR_ROUTE_RETURN_WITNESS".into());
        }
        // No field of the Go return witness is an input to Tracker::attempt.
        // Only the independently calculated factor result and validated Reserve
        // binding may enter the selector transition calculation.
        check(self.tracker.attempt(*next, *ordinal, excluded, derived))?;
        if self
            .previous_group
            .is_some_and(|group| group != e.route.group)
        {
            self.switches += 1;
        }
        self.previous_group = Some(e.route.group);
        self.attempts += 1;
        Ok(())
    }

    fn finish(
        &mut self,
        state: &mut LiveState,
        envelope: &finish::Envelope,
        frame_bytes: usize,
    ) -> Result<()> {
        let binding = self.pending.ok_or("SELECTOR_ROUTE_FINISH_BATCH")?;
        if Some(envelope.session) != self.session
            || envelope.group != binding.group
            || envelope.backend != binding.account
            || envelope.operation != binding.operation
            || envelope.success != self.finish_success
        {
            return Err("SELECTOR_ROUTE_FINISH_BINDING".into());
        }
        let progress = state.observe_selector_finish(envelope, frame_bytes);
        if progress.status != Status::Comparing
            || progress.compared_sequence != envelope.sequence + 1
        {
            return Err("SELECTOR_ROUTE_FINISH_ATOMIC".into());
        }
        self.pending = None;
        self.captured_finishes += 1;
        self.finish_successes += usize::from(envelope.success);
        Ok(())
    }

    fn lifecycle(&mut self, bytes: &[u8]) -> Result<()> {
        let Some(binding) = self.pending else {
            return Ok(());
        };
        let live::Frame::Batch(batch) = live::decode(bytes)? else {
            return Err("SELECTOR_ROUTE_FINISH_BATCH".into());
        };
        if !matches!(batch.events.as_slice(), [LiveEvent::Lifecycle {
            event: Event::Created { session, operation, success }, ..
        }] if Some(*session) == self.session && *operation == binding.operation && *success == self.finish_success)
            || batch.witness.accounts.len() != 1
            || batch.witness.accounts[0].id != binding.account
        {
            return Err("SELECTOR_ROUTE_FINISH_BINDING".into());
        }
        self.pending = None;
        Ok(())
    }

    fn boundary(&mut self, record: &Record, state: &LiveState, owner: Option<Epoch>) -> Result<()> {
        match record {
            Record::Begin {
                next,
                current,
                excluded,
            } => {
                check(self.tracker.begin(*next, *current, excluded))?;
                self.next = *next;
            }
            Record::End {
                next,
                backend,
                error,
                current,
                excluded,
            } => {
                check(
                    self.tracker
                        .end(*next, *backend, (*error).into(), *current, excluded),
                )?;
                if matches!(error, Error::None) {
                    self.successes += 1;
                } else {
                    self.rejected += 1;
                }
            }
            Record::Finish { backend, success } => {
                self.finish_success = *success;
                if self.pending.is_some() {
                    return Err("SELECTOR_ROUTE_DUPLICATE_FINISH".into());
                }
                self.pending = Some(check(self.tracker.finish_binding(*backend))?);
            }
            Record::Tail {
                next,
                attempts,
                successes,
                rejected,
            } => {
                check(self.tracker.tail())?;
                if (*next, *attempts, *successes, *rejected) != (6, 9, 4, 2)
                    || (self.next, self.attempts, self.successes, self.rejected) != (6, 9, 4, 2)
                    || self.switches != 2
                    || self.pending.is_some()
                    || state.totals(owner.ok_or("owner")?) != Some((0, 0))
                {
                    return Err("SELECTOR_ROUTE_POPULATION_AND_SETTLED_TAIL".into());
                }
                if self.captured_boundaries != 0 {
                    if self.captured_boundaries != 13
                        || self.captured_finishes != 4
                        || self.finish_successes != 1
                        || !state.selectors_settled(owner.ok_or("owner")?)
                    {
                        return Err("SELECTOR_STATE_UNSETTLED".into());
                    }
                    let budget = state.caller_peak_budget().ok_or("selector budget")?;
                    println!(
                        "SELECTOR_STATE_RETAINED boundaries=13 F={} D={} R={} C={} S={} P={}",
                        budget.frame,
                        budget.decode,
                        budget.retained,
                        budget.clones,
                        budget.fixed,
                        budget.peak
                    );
                }
                self.tail = true;
            }
            _ => return Err("unexpected boundary".into()),
        }
        Ok(())
    }
}

fn replay(records: &[Record]) -> Result<()> {
    let mut state = LiveState::new(Limits::default());
    let (mut origin, mut owner) = (None, None);
    let mut replay = Replay::default();
    for record in records {
        if replay.tail {
            return Err("SELECTOR_ROUTE_DATA_AFTER_TAIL".into());
        }
        match record {
            Record::Frame { bytes } => {
                if let Ok(caller::Frame::Selector(boundary)) =
                    caller::decode_caller(bytes, origin, state.native_retained_bytes())
                {
                    let progress = state.observe_selector_boundary(&boundary, bytes.len());
                    if progress.status != Status::Comparing
                        || progress.compared_sequence != boundary.sequence
                    {
                        return Err("SELECTOR_STATE_BOUNDARY".into());
                    }
                    replay.captured_boundaries += 1;
                    continue;
                }
                if let Ok(caller::Frame::Finish(envelope)) =
                    caller::decode_caller(bytes, origin, state.native_retained_bytes())
                {
                    replay.finish(&mut state, &envelope, bytes.len())?;
                    continue;
                }
                replay.lifecycle(bytes)?;
                prefix::observe_prefix(&mut state, bytes, &mut origin, &mut owner)?;
            }
            Record::Attempt { .. } => replay.attempt(&mut state, origin, record)?,
            _ => replay.boundary(record, &state, owner)?,
        }
    }
    if !replay.tail {
        return Err("SELECTOR_ROUTE_MISSING_TAIL".into());
    }
    Ok(())
}

fn corrupt(record: &mut Record, fault: u8) -> bool {
    match (fault, record) {
        (
            0,
            Record::Attempt {
                next: 3,
                ordinal: 2,
                backend,
                ..
            },
        )
        | (3, Record::Finish { backend, .. }) => *backend = 0,
        (
            1,
            Record::Attempt {
                next: 3,
                ordinal: 2,
                excluded,
                ..
            },
        ) => excluded.push(999),
        (
            2,
            Record::End {
                next: 3, current, ..
            },
        ) => *current = 0,
        _ => return false,
    }
    true
}

fn main() -> Result<()> {
    let text = fs::read_to_string(std::env::args().nth(1).ok_or("fixture path")?)?;
    let records = text
        .lines()
        .map(serde_json::from_str)
        .collect::<std::result::Result<Vec<Record>, _>>()?;
    replay(&records)?;
    println!(
        "SELECTOR_ROUTE_INDEPENDENT next=6 attempts=9 successes=4 rejected=2 group_switches=2 settled=true"
    );
    // Actual captured returns and selector state are witnesses, never expected
    // route decisions. Each corruption must fail at its intended comparison.
    for (fault, marker) in [
        (0, "SELECTOR_ROUTE_RETURN_WITNESS"),
        (1, "SELECTOR_ROUTE_TRANSITION"),
        (2, "SELECTOR_ROUTE_TRANSITION"),
        (3, "SELECTOR_ROUTE_TRANSITION"),
    ] {
        let mut changed = records.clone();
        let injected = changed.iter_mut().any(|record| corrupt(record, fault));
        // An exclusion length corruption is rejected before transition input.
        let expected = if fault == 1 {
            "SELECTOR_ROUTE_SCOPE"
        } else {
            marker
        };
        let rejected = replay(&changed)
            .err()
            .ok_or("SELECTOR_ROUTE_FAULT_SURVIVED")?;
        if !injected || !rejected.to_string().contains(expected) {
            return Err(io::Error::other(format!(
                "SELECTOR_ROUTE_WRONG_FAILURE fault={fault} error={rejected}"
            ))
            .into());
        }
        println!("SELECTOR_ROUTE_CORRUPTION fault={fault} marker={expected} detected=true");
    }
    Ok(())
}
