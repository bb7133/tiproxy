// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::shadow::live::{ConnectionState, Witness};
use crate::shadow::native::Advice;
use crate::shadow::{Limits, Status};

fn must<T, E: std::fmt::Debug>(value: Result<T, E>) -> T {
    value.unwrap_or_else(|error| unreachable!("fixture: {error:?}"))
}
fn some<T>(value: Option<T>) -> T {
    value.unwrap_or_else(|| unreachable!("fixture"))
}
fn now(nanos: i64) -> GoTime {
    some(GoTime::new(63_000_000_000, 0, 1, Some(nanos)))
}
fn life(event: Event, source: u64, target: u64) -> LiveEvent {
    LiveEvent::Lifecycle {
        event,
        source,
        target,
    }
}
fn fixture(order: &[u64]) -> (LiveState, Envelope) {
    let (mut state, mut configuration) = super::super::tests::setup(Limits::default());
    let epoch = configuration.epoch;
    let ledger = &mut state
        .core
        .owners
        .get_mut(&(epoch.process, epoch.owner))
        .unwrap_or_else(|| unreachable!("owner"))
        .ledger;
    must(ledger.apply(&Event::Account { id: 19, group: 2 }));
    for &session in order {
        must(ledger.apply(&Event::Rehydrate {
            session,
            account: 9,
        }));
    }
    let mut evaluation = configuration.clone();
    configuration.config += 1;
    configuration.configuration.rates[0] = 1_f64.to_bits();
    configuration.configuration.rates[5] = 50_f64.to_bits();
    configuration.entry = Entry::Config;
    configuration.accounts.clear();
    configuration.reads.clear();
    configuration.sorted.clear();
    configuration.returned.clear();
    assert_eq!(
        state.observe_native(&configuration, 4096).status,
        Status::Comparing
    );
    evaluation.config = configuration.config;
    evaluation.configuration = configuration.configuration;
    evaluation.sequence = 6;
    evaluation.evaluation = 3;
    evaluation.entry = Entry::Balance;
    let mut destination = evaluation.accounts[0].clone();
    destination.account = 19;
    destination.id = "destination".into();
    destination.addr = "destination:4000".into();
    evaluation.accounts[0].physical = must(i64::try_from(order.len()));
    evaluation.accounts[0].score_count = must(i64::try_from(order.len()));
    evaluation.accounts[0].parts[1] = must(u64::try_from(order.len()));
    evaluation.accounts[0].packed = must(u64::try_from(order.len()));
    evaluation.accounts[0].routeability_seen = false;
    evaluation.accounts[0].routeable = false;
    evaluation.accounts.push(destination);
    evaluation.sorted = vec![1, 0];
    evaluation.returned.clear();
    evaluation.from = 0;
    evaluation.to = 1;
    evaluation.reason = Some(crate::Factor::Connection);
    evaluation.balance_count = 50_f64.to_bits();
    evaluation.advice = vec![
        Advice {
            from: 0,
            to: 1,
            factor: crate::Factor::Status,
            advice: 2,
            count: 1_f64.to_bits(),
        },
        Advice {
            from: 0,
            to: 1,
            factor: crate::Factor::Connection,
            advice: 2,
            count: 50_f64.to_bits(),
        },
    ];
    (
        state,
        Envelope {
            epoch,
            sequence: 6,
            span: 2,
            caller: 70,
            group: 2,
            members: vec![9, 19],
            evaluation: Box::new(evaluation),
            clock: Some(Clock {
                now: now(10_000_000_000),
                from_keyspace: String::new(),
                to_keyspace: String::new(),
            }),
            contexts: vec![],
            visits: vec![],
            accepted: 0,
        },
    )
}

// Fixture witnesses are generated from a separate lifecycle mirror and are
// never used to initialize the observer under test.
fn redirects(state: &LiveState, e: &mut Envelope, rows: &[(u64, Option<bool>)]) {
    let sessions: Vec<_> = rows.iter().map(|r| r.0).collect();
    let key = (e.epoch.process, e.epoch.owner);
    let mut ledger = state.core.owners[&key]
        .ledger
        .fork_caller(e.group, &sessions);
    let mut sequence = e.sequence + 1;
    e.visits.clear();
    e.accepted = 0;
    for &(session, callback) in rows {
        let redirect = callback.map(|accepted| {
            let before = ledger.connection(session);
            let event = if accepted {
                e.accepted += 1;
                Event::Redirect {
                    session,
                    operation: sequence + 100,
                    target: 19,
                }
            } else {
                Event::Rejected { session }
            };
            must(ledger.apply(&event));
            let batch = Batch {
                epoch: e.epoch,
                sequence,
                events: vec![life(event, 9, 19)],
                witness: Witness {
                    accounts: vec![
                        some(ledger.compact_account(9)),
                        some(ledger.compact_account(19)),
                    ],
                    session,
                    before,
                    after: ledger.connection(session),
                    predecessor: 0,
                },
            };
            sequence += 1;
            Redirect {
                from_keyspace: String::new(),
                to_keyspace: String::new(),
                callback: Some(accepted),
                batch,
            }
        });
        e.visits.push(Visit { session, redirect });
    }
    e.span = sequence - e.sequence + 1;
}
fn timing(state: &LiveState, e: &Envelope) -> Timing {
    state.native[&e.epoch].groups[&e.group].timing.clone()
}
fn next(state: &LiveState, e: &Envelope, nanos: i64) -> Envelope {
    let mut next = e.clone();
    next.sequence = state.progress(e.epoch).compared_sequence + 1;
    next.evaluation.sequence = next.sequence;
    next.evaluation.evaluation += 1;
    next.caller += 1;
    next.span = 2;
    next.visits.clear();
    next.contexts.clear();
    next.accepted = 0;
    next.clock
        .as_mut()
        .unwrap_or_else(|| unreachable!("clock"))
        .now = now(nanos);
    next
}

#[test]
fn physical_prefix_skips_and_refusals_do_not_consume_quota() {
    let (mut state, mut e) = fixture(&[12, 10, 11]);
    must(
        state
            .core
            .owners
            .get_mut(&(41, 1))
            .unwrap_or_else(|| unreachable!("owner"))
            .ledger
            .apply(&Event::Closing {
                session: 12,
                operation: 1,
            }),
    );
    redirects(
        &state,
        &mut e,
        &[(12, None), (10, Some(false)), (11, Some(true))],
    );
    e.contexts = vec![false; 3];
    assert_eq!(
        state.observe_group_balance(&e, 8192).status,
        Status::Comparing,
        "BALANCE_PHYSICAL_SKIP_REFUSAL_QUOTA"
    );
    let history = timing(&state, &e);
    assert_eq!(
        history.last_accepted,
        Some(now(10_000_000_000)),
        "BALANCE_ACCEPTED_WATERMARK"
    );
    assert!(
        !history.attempts.contains_key(&12),
        "BALANCE_SKIP_NO_ATTEMPT_CLOCK"
    );
    assert!(history.attempts[&10].failed && !history.attempts[&10].pending);
    assert!(!history.attempts[&11].failed && history.attempts[&11].pending);
}

#[test]
fn context_is_read_before_quota_stop_but_never_after_list_exhaustion() {
    for remaining in [false, true] {
        for forged in [false, true] {
            let (mut state, mut e) = fixture(&[12, 10, 11]);
            if remaining {
                redirects(&state, &mut e, &[(12, Some(true))]);
            } else {
                for session in [12, 10] {
                    must(
                        state
                            .core
                            .owners
                            .get_mut(&(41, 1))
                            .unwrap_or_else(|| unreachable!("owner"))
                            .ledger
                            .apply(&Event::Closing {
                                session,
                                operation: 1,
                            }),
                    );
                }
                redirects(&state, &mut e, &[(12, None), (10, None), (11, Some(true))]);
            }
            e.contexts = vec![false; if remaining { 2 } else { 3 }];
            if forged {
                if remaining {
                    e.contexts.pop();
                } else {
                    e.contexts.push(false);
                }
            }
            let got = state.observe_group_balance(&e, 8192);
            assert_eq!(
                got.status,
                if forged {
                    Status::Invalid(InvalidReason::Witness)
                } else {
                    Status::Comparing
                },
                "BALANCE_CONTEXT_NIL_QUOTA_ORDER remaining={remaining} forged={forged}"
            );
        }
    }
}

#[test]
fn cancellation_stops_before_visit_and_cannot_hide_an_extra_read() {
    for extra in [false, true] {
        let (mut state, mut e) = fixture(&[12, 10, 11]);
        e.contexts = if extra { vec![true, false] } else { vec![true] };
        let got = state.observe_group_balance(&e, 8192);
        assert_eq!(
            got.status,
            if extra {
                Status::Invalid(InvalidReason::Witness)
            } else {
                Status::Comparing
            },
            "BALANCE_CONTEXT_CANCEL_EXACT"
        );
        assert!(timing(&state, &e).attempts.is_empty());
    }
}

#[test]
fn cooldown_uses_attempt_time_and_strict_monotonic_expiry() {
    for offset in [-1_i64, 0, 1] {
        let (mut state, mut e) = fixture(&[12, 10, 11]);
        redirects(
            &state,
            &mut e,
            &[(12, Some(false)), (10, Some(false)), (11, Some(false))],
        );
        e.contexts = vec![false; 3];
        assert_eq!(
            state.observe_group_balance(&e, 8192).status,
            Status::Comparing
        );
        assert_eq!(
            timing(&state, &e).last_accepted,
            None,
            "BALANCE_REFUSAL_NO_GROUP_WATERMARK"
        );
        let before = timing(&state, &e);
        let mut later = next(&state, &e, 13_000_000_000 + offset);
        let result = (offset >= 0).then_some(false);
        redirects(
            &state,
            &mut later,
            &[(12, result), (10, result), (11, result)],
        );
        later.contexts = vec![false; 3];
        assert_eq!(
            state.observe_group_balance(&later, 8192).status,
            Status::Comparing,
            "BALANCE_COOLDOWN_EQUAL_ELIGIBLE"
        );
        if offset < 0 {
            assert_eq!(
                timing(&state, &e),
                before,
                "BALANCE_COOLDOWN_SKIP_PRESERVES_HISTORY"
            );
        } else {
            assert_eq!(
                timing(&state, &e).attempts[&12].time,
                now(13_000_000_000 + offset)
            );
        }
    }
}

#[test]
fn whole_pair_and_direct_backstop_have_distinct_reads_and_history() {
    for direct in [false, true] {
        for extra_callback in [false, true] {
            let (mut state, mut e) = fixture(&[12, 10, 11]);
            if direct {
                redirects(
                    &state,
                    &mut e,
                    &[(12, Some(false)), (10, Some(false)), (11, Some(false))],
                );
                e.contexts = vec![false; 3];
                for visit in &mut e.visits {
                    let redirect = visit
                        .redirect
                        .as_mut()
                        .unwrap_or_else(|| unreachable!("redirect"));
                    redirect.to_keyspace = "other".into();
                    redirect.callback = extra_callback.then_some(false);
                }
            } else {
                e.clock
                    .as_mut()
                    .unwrap_or_else(|| unreachable!("clock"))
                    .to_keyspace = "other".into();
                if extra_callback {
                    e.contexts.push(false);
                }
            }
            assert_eq!(
                state.observe_group_balance(&e, 8192).status,
                if extra_callback {
                    Status::Invalid(InvalidReason::Witness)
                } else {
                    Status::Comparing
                },
                "BALANCE_DIRECT_KEYSPACE_BACKSTOP"
            );
            if !extra_callback {
                let history = timing(&state, &e);
                assert_eq!(history.attempts.len(), if direct { 3 } else { 0 });
                assert_eq!(history.last_accepted, None);
            }
        }
    }
}

#[test]
fn final_mismatch_rolls_back_factor_lifecycle_and_timing_together() {
    let (mut state, mut e) = fixture(&[12, 10, 11]);
    let before = some(state.view(e.epoch));
    let history = timing(&state, &e);
    let retained = state.native_retained_bytes();
    redirects(&state, &mut e, &[(12, Some(true))]);
    e.contexts = vec![false, false];
    e.accepted = 0;
    let result = state.observe_group_balance(&e, 8192);
    assert_eq!(timing(&state, &e), history, "BALANCE_FINAL_ROLLBACK_TIMING");
    assert_eq!(
        (result.status, result.compared_sequence),
        (Status::Invalid(InvalidReason::Witness), 5),
        "BALANCE_FINAL_ROLLBACK_PREFIX"
    );
    assert_eq!(
        some(state.view(e.epoch)).accounts,
        before.accounts,
        "BALANCE_FINAL_ROLLBACK_LEDGER"
    );
    assert_eq!(timing(&state, &e), history, "BALANCE_FINAL_ROLLBACK_TIMING");
    assert_eq!(
        state.native_retained_bytes(),
        retained,
        "BALANCE_FINAL_ROLLBACK_CHARGE"
    );
    let mut factor = state.native[&e.epoch].groups[&e.group].state.clone();
    assert!(
        factor.apply(&e.evaluation).is_ok(),
        "BALANCE_FINAL_ROLLBACK_FACTOR"
    );
}

#[test]
fn physical_order_and_complete_native_inventory_are_independent() {
    for fault in 0..4 {
        let (mut state, mut e) = fixture(&[12, 10, 11]);
        redirects(&state, &mut e, &[(12, Some(true))]);
        e.contexts = vec![false, false];
        match fault {
            0 => redirects(&state, &mut e, &[(10, Some(true))]),
            1 => {
                e.members.remove(0);
            }
            2 => e.members.swap(0, 1),
            _ => e.members[1] = 99,
        }
        assert_eq!(
            state.observe_group_balance(&e, 8192).status,
            Status::Invalid(InvalidReason::Witness),
            "BALANCE_INDEPENDENT_PHYSICAL_AND_INVENTORY"
        );
        assert_eq!(state.progress(e.epoch).compared_sequence, 5);
    }
}

fn terminal(state: &LiveState, e: &Envelope, session: u64, success: bool) -> Batch {
    let key = (e.epoch.process, e.epoch.owner);
    let mut ledger = state.core.owners[&key]
        .ledger
        .fork_caller(e.group, &[session]);
    let before = ledger.connection(session);
    let operation = some(ledger.caller_redirect_watermark(session));
    let event = Event::Redirected {
        session,
        operation,
        success,
    };
    must(ledger.apply(&event));
    Batch {
        epoch: e.epoch,
        sequence: state.progress(e.epoch).compared_sequence + 1,
        events: vec![life(event, 9, 19)],
        witness: Witness {
            accounts: vec![
                some(ledger.compact_account(9)),
                some(ledger.compact_account(19)),
            ],
            session,
            before,
            after: ledger.connection(session),
            predecessor: if success {
                ledger.predecessor(session)
            } else {
                0
            },
        },
    }
}

#[test]
fn failed_terminal_retains_original_attempt_clock_and_group_watermark() {
    let (mut state, mut e) = fixture(&[12, 10, 11]);
    redirects(&state, &mut e, &[(12, Some(true))]);
    e.contexts = vec![false, false];
    assert_eq!(
        state.observe_group_balance(&e, 8192).status,
        Status::Comparing
    );
    let batch = terminal(&state, &e, 12, false);
    assert_eq!(state.observe(&batch).status, Status::Comparing);
    let history = timing(&state, &e);
    assert!(
        history.attempts[&12].failed && !history.attempts[&12].pending,
        "BALANCE_TERMINAL_FAILURE_PHASE"
    );
    assert_eq!(
        history.attempts[&12].time,
        now(10_000_000_000),
        "BALANCE_TERMINAL_PRESERVES_ATTEMPT_CLOCK"
    );
    assert_eq!(
        history.last_accepted,
        Some(now(10_000_000_000)),
        "BALANCE_TERMINAL_PRESERVES_GROUP_CLOCK"
    );
    let mut later = next(&state, &e, 12_999_999_999);
    redirects(
        &state,
        &mut later,
        &[(12, None), (10, Some(false)), (11, Some(false))],
    );
    later.contexts = vec![false; 3];
    assert_eq!(
        state.observe_group_balance(&later, 8192).status,
        Status::Comparing,
        "BALANCE_FAILED_TERMINAL_NEXT_SCAN"
    );
    let mut replay = batch.clone();
    replay.sequence = state.progress(e.epoch).compared_sequence + 1;
    replay.witness.before = ConnectionState {
        present: true,
        physical: 9,
        score_owner: 9,
        ..ConnectionState::default()
    };
    replay.witness.after = replay.witness.before;
    replay.witness.accounts = vec![
        some(state.core.owners[&(41, 1)].ledger.compact_account(9)),
        some(state.core.owners[&(41, 1)].ledger.compact_account(19)),
    ];
    assert_eq!(state.observe(&replay).status, Status::Comparing);
    assert_eq!(
        timing(&state, &e).attempts[&12],
        history.attempts[&12],
        "BALANCE_LATE_TERMINAL_NO_REWRITE"
    );
}

#[test]
fn config_update_preserves_committed_time_history() {
    let (mut state, mut e) = fixture(&[12, 10, 11]);
    redirects(
        &state,
        &mut e,
        &[(12, Some(false)), (10, Some(false)), (11, Some(false))],
    );
    e.contexts = vec![false; 3];
    assert_eq!(
        state.observe_group_balance(&e, 8192).status,
        Status::Comparing
    );
    let history = timing(&state, &e);
    let mut config = e.evaluation.as_ref().clone();
    config.sequence = state.progress(e.epoch).compared_sequence + 1;
    config.evaluation += 1;
    config.config += 1;
    config.entry = Entry::Config;
    config.accounts.clear();
    config.reads.clear();
    config.sorted.clear();
    config.advice.clear();
    config.returned.clear();
    config.from = -1;
    config.to = -1;
    config.reason = None;
    config.balance_count = 0;
    assert_eq!(
        state.observe_native(&config, 4096).status,
        Status::Comparing
    );
    assert_eq!(
        timing(&state, &e),
        history,
        "BALANCE_CONFIG_RETAINS_GROUP_HISTORY"
    );
}

#[test]
fn timing_retained_and_clone_charge_survive_sibling_group_commit() {
    let (mut state, mut e) = fixture(&[12, 10, 11]);
    redirects(
        &state,
        &mut e,
        &[(12, Some(false)), (10, Some(false)), (11, Some(false))],
    );
    e.contexts = vec![false; 3];
    let (mut reference, mut no_attempts) = fixture(&[12, 10, 11]);
    no_attempts.contexts = vec![true];
    assert_eq!(
        reference.observe_group_balance(&no_attempts, 8192).status,
        Status::Comparing
    );
    let before = reference.native_retained_bytes();
    assert_eq!(
        state.observe_group_balance(&e, 8192).status,
        Status::Comparing
    );
    assert_eq!(
        state.native_retained_bytes(),
        before + 3 * ATTEMPT_CHARGE,
        "BALANCE_TIMING_RETAINED_CHARGED"
    );
    let history = timing(&state, &e);
    let retained = state.native_retained_bytes();
    let sequence = state.progress(e.epoch).compared_sequence + 1;
    // A router-only final check cannot replace an unrelated Group's timing.
    let transaction = must(state.begin_caller(Scope {
        epoch: e.epoch,
        group: 0,
        sequence,
        span: 1,
        sessions: &[],
        frame_bytes: 8192,
    }));
    assert_eq!(transaction.finish(Ok(())).status, Status::Comparing);
    assert_eq!(
        timing(&state, &e),
        history,
        "BALANCE_UNVISITED_GROUP_TIME_PRESERVED"
    );
    assert_eq!(state.native_retained_bytes(), retained);
    let sequence = state.progress(e.epoch).compared_sequence + 1;
    let clone = state.native[&e.epoch].groups[&2].charge;
    let ledger = must(
        state.core.owners[&(41, 1)]
            .ledger
            .caller_clone_charge(2, &[12]),
    );
    let transaction = must(state.begin_caller(Scope {
        epoch: e.epoch,
        group: 2,
        sequence,
        span: 1,
        sessions: &[12],
        frame_bytes: 8192,
    }));
    assert_eq!(transaction.finish(Ok(())).status, Status::Comparing);
    assert_eq!(
        timing(&state, &e),
        history,
        "BALANCE_TIMING_CLONE_COPIES_HISTORY"
    );
    assert!(
        some(state.caller_peak_budget()).clones >= ledger + clone,
        "BALANCE_TIMING_CLONE_CHARGED"
    );
}

#[test]
fn timing_growth_is_admitted_at_exact_shared_budget_and_rejected_at_plus_one() {
    let order: Vec<_> = (10..41).collect();
    let (mut probe, mut sample) = fixture(&order);
    let ledger_charge = must(
        probe.core.owners[&(41, 1)]
            .ledger
            .caller_clone_charge(2, &order),
    );
    let rows: Vec<_> = order.iter().map(|id| (*id, Some(false))).collect();
    redirects(&probe, &mut sample, &rows);
    sample.contexts = vec![false; order.len()];
    assert_eq!(
        probe.observe_group_balance(&sample, 8192).status,
        Status::Comparing
    );
    assert_eq!(
        some(probe.caller_peak_budget()).clones,
        ledger_charge + probe.native[&sample.epoch].groups[&2].charge,
        "BALANCE_TIMING_GROWTH_CHARGED"
    );
    let headroom =
        super::super::super::native::HISTORY_LIMIT - some(probe.caller_peak_budget()).peak;
    for extra in [0, 1] {
        let (mut state, mut e) = fixture(&order);
        redirects(&state, &mut e, &rows);
        e.contexts = vec![false; order.len()];
        state.native_bytes += headroom + extra;
        let retained = state.native_retained_bytes();
        let got = state.observe_group_balance(&e, 8192);
        if extra == 0 {
            assert_eq!(got.status, Status::Comparing, "BALANCE_TIMING_BUDGET_EQUAL");
            assert_eq!(
                some(state.caller_peak_budget()).peak,
                super::super::super::native::HISTORY_LIMIT
            );
        } else {
            assert_eq!(
                (got.status, got.compared_sequence),
                (Status::Invalid(InvalidReason::Capacity), 5),
                "BALANCE_TIMING_BUDGET_PLUS_ONE"
            );
            assert!(
                timing(&state, &e).attempts.is_empty(),
                "BALANCE_CAPACITY_ROLLS_BACK_TIMING"
            );
            assert_eq!(state.native_retained_bytes(), retained);
        }
    }
}

#[test]
fn caller_read_and_visit_caps_include_skipped_connections() {
    for extra in [0, 1] {
        let order: Vec<_> = (10..43 + extra).collect();
        let (mut state, mut e) = fixture(&order);
        let skipped = must(usize::try_from(2 + extra));
        for &session in order.iter().take(skipped) {
            must(
                state
                    .core
                    .owners
                    .get_mut(&(41, 1))
                    .unwrap_or_else(|| unreachable!("owner"))
                    .ledger
                    .apply(&Event::Closing {
                        session,
                        operation: 1,
                    }),
            );
        }
        let rows: Vec<_> = order
            .iter()
            .enumerate()
            .map(|(i, id)| (*id, (i >= skipped).then_some(false)))
            .collect();
        redirects(&state, &mut e, &rows);
        e.contexts = vec![false; order.len()];
        assert_eq!(
            state.observe_group_balance(&e, 8192).status,
            if extra == 0 {
                Status::Comparing
            } else {
                Status::Invalid(InvalidReason::Capacity)
            },
            "BALANCE_READ_CAP_EQUAL_PLUS_ONE"
        );
    }
    for extra in [0, 1] {
        let order: Vec<_> = (10..74 + extra).collect();
        let (mut state, mut e) = fixture(&order);
        for &session in &order {
            must(
                state
                    .core
                    .owners
                    .get_mut(&(41, 1))
                    .unwrap_or_else(|| unreachable!("owner"))
                    .ledger
                    .apply(&Event::Closing {
                        session,
                        operation: 1,
                    }),
            );
        }
        // No separate fixture fork: the producer's attempted 65th visit is
        // intentionally malformed and must fail before begin_caller cloning.
        e.visits = order
            .iter()
            .map(|id| Visit {
                session: *id,
                redirect: None,
            })
            .collect();
        e.contexts = vec![false; order.len()];
        assert_eq!(
            state.observe_group_balance(&e, 8192).status,
            if extra == 0 {
                Status::Comparing
            } else {
                Status::Invalid(InvalidReason::Capacity)
            },
            "BALANCE_VISIT_CAP_EQUAL_PLUS_ONE"
        );
    }
}

#[test]
fn pending_skips_and_independent_recent_group_watermark_control_next_round() {
    let (mut state, mut e) = fixture(&[12, 10, 11]);
    redirects(&state, &mut e, &[(12, Some(true))]);
    e.contexts = vec![false, false];
    assert_eq!(
        state.observe_group_balance(&e, 8192).status,
        Status::Comparing
    );
    let batch = terminal(&state, &e, 12, false);
    assert_eq!(state.observe(&batch).status, Status::Comparing);
    let history = timing(&state, &e);
    let mut later = next(&state, &e, 10_000_000_000);
    // Native comparison accepts the legacy scalar tolerance; the enclosing
    // caller must still use the independently computed exact50/s slow branch.
    later.evaluation.balance_count = 50_f64.to_bits() + 1;
    later.evaluation.advice[1].count = later.evaluation.balance_count;
    redirects(&state, &mut later, &[(12, None), (10, Some(true))]);
    later.contexts = vec![false; 3];
    assert_eq!(
        state.observe_group_balance(&later, 8192).status,
        Status::Invalid(InvalidReason::Witness),
        "BALANCE_COMPUTED_RATE_AND_RETAINED_WATERMARK"
    );
    assert_eq!(timing(&state, &e), history);
}

#[test]
fn exact_zero_rate_rejects_every_extra_caller_read() {
    for extra in [false, true] {
        let (mut state, mut e) = fixture(&[12, 10, 11]);
        must(
            state
                .core
                .owners
                .get_mut(&(41, 1))
                .unwrap_or_else(|| unreachable!("owner"))
                .ledger
                .apply(&Event::RemoveAccount(19)),
        );
        e.members.pop();
        e.evaluation.accounts.pop();
        e.evaluation.accounts[0].seen = 0;
        e.evaluation.accounts[0].parts.clear();
        e.evaluation.accounts[0].packed = 0;
        e.evaluation.sorted.clear();
        e.evaluation.reads.clear();
        e.evaluation.advice.clear();
        e.evaluation.from = -1;
        e.evaluation.to = -1;
        e.evaluation.reason = None;
        e.evaluation.balance_count = 0;
        if !extra {
            e.clock = None;
        }
        assert_eq!(
            state.observe_group_balance(&e, 8192).status,
            if extra {
                Status::Invalid(InvalidReason::Witness)
            } else {
                Status::Comparing
            },
            "BALANCE_ZERO_RATE_NO_CLOCK_OR_READS"
        );
    }
}

#[test]
fn pending_session_is_skipped_without_changing_its_attempt_history() {
    let (mut state, mut e) = fixture(&[12, 10, 11, 13, 14]);
    must(
        state
            .core
            .owners
            .get_mut(&(41, 1))
            .unwrap_or_else(|| unreachable!("owner"))
            .ledger
            .apply(&Event::Redirect {
                session: 12,
                operation: 1,
                target: 19,
            }),
    );
    e.evaluation.accounts[0].score_count = 4;
    e.evaluation.accounts[0].parts[1] = 4;
    e.evaluation.accounts[0].packed = 4;
    e.evaluation.accounts[1].score_count = 1;
    e.evaluation.accounts[1].parts[1] = 1;
    e.evaluation.accounts[1].packed = 1;
    redirects(&state, &mut e, &[(12, None), (10, Some(true))]);
    e.contexts = vec![false; 3];
    assert_eq!(
        state.observe_group_balance(&e, 8192).status,
        Status::Comparing,
        "BALANCE_PENDING_SKIP_NO_QUOTA"
    );
    assert!(
        !timing(&state, &e).attempts.contains_key(&12),
        "BALANCE_PENDING_SKIP_NO_CLOCK"
    );
    let batch = terminal(&state, &e, 12, false);
    assert_eq!(state.observe(&batch).status, Status::Comparing);
    let mut later = next(&state, &e, 20_000_000_000);
    // Account counts remain 4/1: one earlier pending redirect failed and the
    // newly accepted session10 is now pending. Session12's original attempt
    // clock was never captured, so its failed phase cannot be qualified.
    redirects(
        &state,
        &mut later,
        &[
            (12, Some(false)),
            (10, None),
            (11, Some(false)),
            (13, Some(false)),
            (14, Some(false)),
        ],
    );
    later.contexts = vec![false; 5];
    assert_eq!(
        state.observe_group_balance(&later, 8192).status,
        Status::Invalid(InvalidReason::Lifecycle),
        "BALANCE_MISSING_ATTEMPT_HISTORY_REJECTED"
    );
}

#[test]
fn dropped_and_late_failed_children_preserve_original_timing() {
    for dropped in [false, true] {
        let (mut state, mut e) = fixture(&[12, 10, 11]);
        redirects(
            &state,
            &mut e,
            &[(12, Some(false)), (10, Some(false)), (11, Some(false))],
        );
        e.contexts = vec![false; 3];
        let before = timing(&state, &e);
        if dropped {
            let mut transaction = must(state.begin_caller(Scope {
                epoch: e.epoch,
                group: e.group,
                sequence: e.sequence,
                span: e.span,
                sessions: &[12, 10, 11],
                frame_bytes: 8192,
            }));
            must(transaction.compare_balance(&e));
            assert_eq!(must(transaction.timing()).attempts.len(), 3);
            drop(transaction);
        } else {
            e.visits[1]
                .redirect
                .as_mut()
                .unwrap_or_else(|| unreachable!("redirect"))
                .batch
                .witness
                .accounts[0]
                .score = 999;
            assert_eq!(
                state.observe_group_balance(&e, 8192).status,
                Status::Invalid(InvalidReason::Witness)
            );
        }
        assert_eq!(
            timing(&state, &e),
            before,
            "BALANCE_UNFINISHED_TIMING_ROLLBACK"
        );
        assert_eq!(state.progress(e.epoch).compared_sequence, 5);
    }
}

#[test]
fn sibling_group_factor_commit_does_not_replace_timing() {
    let (mut state, mut e) = fixture(&[12, 10, 11]);
    redirects(
        &state,
        &mut e,
        &[(12, Some(false)), (10, Some(false)), (11, Some(false))],
    );
    e.contexts = vec![false; 3];
    assert_eq!(
        state.observe_group_balance(&e, 8192).status,
        Status::Comparing
    );
    let before = timing(&state, &e);
    let sequence = state.progress(e.epoch).compared_sequence + 1;
    assert_eq!(
        state
            .observe(&Batch {
                epoch: e.epoch,
                sequence,
                events: vec![LiveEvent::GroupCreated(6)],
                witness: Witness::default()
            })
            .status,
        Status::Comparing
    );
    let mut config = e.evaluation.as_ref().clone();
    config.group = 6;
    config.sequence = sequence + 1;
    config.evaluation = 1;
    config.entry = Entry::Config;
    config.accounts.clear();
    config.reads.clear();
    config.sorted.clear();
    config.advice.clear();
    config.returned.clear();
    config.from = -1;
    config.to = -1;
    config.reason = None;
    config.balance_count = 0;
    let mut transaction = must(state.begin_caller(Scope {
        epoch: e.epoch,
        group: 6,
        sequence: config.sequence,
        span: 2,
        sessions: &[],
        frame_bytes: 8192,
    }));
    must(transaction.evaluation(&config));
    assert_eq!(transaction.finish(Ok(())).status, Status::Comparing);
    assert!(
        state.native[&e.epoch].groups.contains_key(&2),
        "BALANCE_SIBLING_COMMIT_PRESERVES_TIMING"
    );
    assert_eq!(
        timing(&state, &e),
        before,
        "BALANCE_SIBLING_COMMIT_PRESERVES_TIMING"
    );
    assert_eq!(state.native[&e.epoch].groups[&6].timing, Timing::default());
}

#[test]
fn actual_close_retires_pending_time_and_late_terminal_preserves_it() {
    let (mut state, mut e) = fixture(&[12, 10, 11]);
    redirects(&state, &mut e, &[(12, Some(true))]);
    e.contexts = vec![false, false];
    assert_eq!(
        state.observe_group_balance(&e, 8192).status,
        Status::Comparing
    );
    let before = timing(&state, &e);
    let mut mirror = state.core.owners[&(41, 1)].ledger.fork_caller(2, &[12]);
    let before_close = mirror.connection(12);
    must(mirror.apply(&Event::Closed(12)));
    let close = Batch {
        epoch: e.epoch,
        sequence: state.progress(e.epoch).compared_sequence + 1,
        events: vec![life(Event::Closed(12), 9, 19)],
        witness: Witness {
            accounts: vec![
                some(mirror.compact_account(9)),
                some(mirror.compact_account(19)),
            ],
            session: 12,
            before: before_close,
            after: mirror.connection(12),
            predecessor: 0,
        },
    };
    assert_eq!(state.observe(&close).status, Status::Comparing);
    assert!(
        !timing(&state, &e).attempts[&12].pending,
        "BALANCE_CLOSE_RETIRES_PENDING_TIME"
    );
    let closed = timing(&state, &e);
    assert_eq!(closed.attempts[&12].time, before.attempts[&12].time);
    assert_eq!(closed.last_accepted, before.last_accepted);
    let late = terminal(&state, &e, 12, false);
    assert_eq!(state.observe(&late).status, Status::Comparing);
    assert_eq!(
        timing(&state, &e),
        closed,
        "BALANCE_LATE_CLOSED_TERMINAL_PRESERVES_TIME"
    );
}
