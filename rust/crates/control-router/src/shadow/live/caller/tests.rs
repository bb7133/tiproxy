// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::shadow::live::{AccountWitness, ConnectionState, Witness};
use crate::shadow::{
    Limits,
    native::{Account, ClockSite, Configuration, Coverage, Entry, GoArch, Read},
};
use control_routing::go_time::{GoTime, Origin, SUPPORTED_GO_VERSION};

fn must<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
    result.unwrap_or_else(|error| unreachable!("fixture: {error:?}"))
}
fn some<T>(value: Option<T>) -> T {
    value.unwrap_or_else(|| unreachable!("fixture"))
}
fn life(event: Event) -> LiveEvent {
    LiveEvent::Lifecycle {
        event,
        source: 0,
        target: 0,
    }
}
fn batch(epoch: Epoch, sequence: u64, events: Vec<LiveEvent>, witness: Witness) -> Batch {
    Batch {
        epoch,
        sequence,
        events,
        witness,
    }
}
fn account(score: i64, physical: bool) -> AccountWitness {
    AccountWitness {
        id: 9,
        score,
        physical: u64::from(physical),
        head: if physical { 10 } else { 0 },
        tail: if physical { 10 } else { 0 },
    }
}
pub(super) fn setup(limits: Limits) -> (LiveState, Evaluation) {
    let epoch = Epoch {
        process: 41,
        owner: 1,
        nonce: 43,
    };
    let zero = some(GoTime::new(0, 0, 1, None));
    let mut state = LiveState::new(limits);
    must(state.install_native(Coverage {
        epoch,
        origin: some(Origin::new(SUPPORTED_GO_VERSION, false, 0)),
        zero_time: zero,
        go_arch: GoArch::Arm64,
    }));
    for (sequence, event) in [(1, life(Event::Begin)), (2, LiveEvent::GroupCreated(2))] {
        assert_eq!(
            state
                .observe(&batch(epoch, sequence, vec![event], Witness::default()))
                .status,
            Status::Comparing
        );
    }
    let mut e = Evaluation {
        epoch,
        sequence: 3,
        group: 2,
        policy: 3,
        config: 4,
        resource: 0,
        evaluation: 1,
        entry: Entry::Config,
        configuration: Configuration {
            balance: "connection".into(),
            routing: "idlest".into(),
            label: String::new(),
            self_label: String::new(),
            rates: [0; 6],
            count_ratio: 1.2_f64.to_bits(),
        },
        factors: vec![(crate::Factor::Status, 1), (crate::Factor::Connection, 16)],
        accounts: Vec::new(),
        reads: Vec::new(),
        sorted: Vec::new(),
        advice: Vec::new(),
        returned: Vec::new(),
        from: -1,
        to: -1,
        balance_count: 0,
        reason: None,
    };
    assert_eq!(state.observe_native(&e, 4096).compared_sequence, 3);
    assert_eq!(
        state
            .observe(&batch(
                epoch,
                4,
                vec![life(Event::Account { id: 9, group: 2 })],
                Witness {
                    accounts: vec![account(0, false)],
                    ..Witness::default()
                }
            ))
            .status,
        Status::Comparing
    );
    e.sequence = 5;
    e.evaluation = 2;
    e.entry = Entry::Routeable;
    e.accounts.push(Account {
        account: 9,
        seen: 31,
        id: "backend".into(),
        addr: "backend:4000".into(),
        keyspace: String::new(),
        ip: String::new(),
        cluster: String::new(),
        label: String::new(),
        label_present: false,
        status_port: 0,
        physical: 0,
        score_count: 0,
        healthy: true,
        local: false,
        parts: vec![0, 0],
        packed: 0,
        routeable: true,
        routeability_seen: true,
    });
    e.sorted = vec![0];
    e.returned = vec![0];
    for site in [ClockSite::MetricCadence, ClockSite::StatusSnapshot] {
        e.reads.push(Read::Clock {
            site,
            ordinal: 0,
            time: zero,
        });
    }
    (state, e)
}
fn scope<'a>(e: &Evaluation, span: u64, sessions: &'a [u64]) -> Scope<'a> {
    Scope {
        epoch: e.epoch,
        group: e.group,
        sequence: e.sequence,
        span,
        sessions,
        frame_bytes: 4096,
    }
}
fn reserve(e: &Evaluation, sequence: u64) -> Batch {
    batch(
        e.epoch,
        sequence,
        vec![
            life(Event::Open(10)),
            life(Event::Reserve {
                session: 10,
                operation: 1,
                account: 9,
            }),
        ],
        Witness {
            accounts: vec![account(1, false)],
            session: 10,
            ..Witness::default()
        },
    )
}
fn created(e: &Evaluation, sequence: u64) -> Batch {
    batch(
        e.epoch,
        sequence,
        vec![life(Event::Created {
            session: 10,
            operation: 1,
            success: true,
        })],
        Witness {
            accounts: vec![account(1, true)],
            session: 10,
            after: ConnectionState {
                present: true,
                physical: 9,
                score_owner: 9,
                ..ConnectionState::default()
            },
            ..Witness::default()
        },
    )
}
fn later(e: &Evaluation) -> Evaluation {
    let mut next = e.clone();
    next.sequence += 4;
    next.evaluation += 1;
    next.accounts[0].score_count = 1;
    next.accounts[0].physical = 1;
    next.accounts[0].parts[1] = 1;
    next.accounts[0].packed = 1;
    next
}

#[test]
fn final_caller_failure_rolls_back_all_successful_children() {
    for good in [false, true] {
        let (mut state, e) = setup(Limits::default());
        let before = some(state.view(e.epoch));
        let retained = state.native_retained_bytes();
        let next = later(&e);
        let mut transaction = must(state.begin_caller(scope(&e, 6, &[10])));
        must(transaction.evaluation(&e));
        must(transaction.batch(&reserve(&e, 6)));
        must(transaction.batch(&created(&e, 8)));
        must(transaction.evaluation(&next));
        assert_eq!(transaction.staged.totals(e.epoch), Some((1, 1)));
        let mut consumed = transaction.staged.native[&e.epoch].groups[&2].state.clone();
        assert!(
            consumed.apply(&e).is_err(),
            "fixture must advance factor history twice"
        );
        let progress = transaction.finish(if good {
            Ok(())
        } else {
            Err(InvalidReason::Witness)
        });
        let after = some(state.view(e.epoch));
        if good {
            assert_eq!(progress.status, Status::Comparing);
            assert_eq!(
                progress.compared_sequence, 10,
                "CALLER_STAGE_COMMIT_FINAL_PREFIX"
            );
            assert_eq!(
                state.totals(e.epoch),
                Some((1, 1)),
                "CALLER_STAGE_COMMIT_CHILDREN"
            );
            let mut consumed = state.native[&e.epoch].groups[&2].state.clone();
            assert!(
                consumed.apply(&e).is_err(),
                "CALLER_STAGE_COMMIT_FACTOR_HISTORY"
            );
        } else {
            assert_eq!(
                (progress.status, progress.compared_sequence),
                (Status::Invalid(InvalidReason::Witness), 4),
                "CALLER_STAGE_ROLLBACK_ALL_CHILDREN"
            );
            assert_eq!(
                after.accounts, before.accounts,
                "CALLER_STAGE_ROLLBACK_ALL_CHILDREN"
            );
            assert_eq!(
                state.native_retained_bytes(),
                retained,
                "CALLER_STAGE_ROLLBACK_ALL_CHILDREN"
            );
            let owner = &mut state
                .core
                .owners
                .get_mut(&(e.epoch.process, e.epoch.owner))
                .unwrap_or_else(|| unreachable!("owner"))
                .ledger;
            assert!(
                owner.apply(&Event::Open(10)).is_ok(),
                "CALLER_STAGE_ROLLBACK_ALL_CHILDREN"
            );
            let mut history = state.native[&e.epoch].groups[&2].state.clone();
            assert_eq!(
                history.apply(&e),
                Ok(()),
                "CALLER_STAGE_ROLLBACK_ALL_CHILDREN"
            );
            assert_eq!(
                history.apply(&next),
                Ok(()),
                "CALLER_STAGE_ROLLBACK_ALL_CHILDREN"
            );
        }
    }
}

#[test]
fn late_child_failure_and_dropped_stage_preserve_original_history() {
    for fault in 0..3 {
        let (mut state, e) = setup(Limits::default());
        let before = some(state.view(e.epoch)).accounts;
        let mut transaction = must(state.begin_caller(scope(&e, 6, &[10])));
        must(transaction.evaluation(&e));
        must(transaction.batch(&reserve(&e, 6)));
        if fault == 0 {
            let mut bad = created(&e, 8);
            bad.witness.accounts[0].score = 999;
            assert_eq!(transaction.batch(&bad), Err(InvalidReason::Witness));
            assert_eq!(
                transaction.batch(&created(&e, 8)),
                Err(InvalidReason::Witness),
                "CALLER_STAGE_CHILD_FAILURE_STICKY"
            );
        } else if fault == 1 {
            must(transaction.batch(&created(&e, 8)));
            let mut bad = later(&e);
            bad.accounts[0].packed = 999;
            assert_eq!(transaction.evaluation(&bad), Err(InvalidReason::Witness));
        }
        if fault == 2 {
            drop(transaction);
        } else {
            assert_eq!(
                transaction.finish(Ok(())).status,
                Status::Invalid(InvalidReason::Witness),
                "CALLER_STAGE_FAILURE_NOT_REPAIRED_BY_FINISH"
            );
        }
        assert_eq!(
            some(state.view(e.epoch)).accounts,
            before,
            "CALLER_STAGE_FAILED_CHILD_ROLLBACK"
        );
        assert_eq!(state.progress(e.epoch).compared_sequence, 4);
        let mut history = state.native[&e.epoch].groups[&2].state.clone();
        assert_eq!(
            history.apply(&e),
            Ok(()),
            "CALLER_STAGE_FAILED_CHILD_FACTOR_ROLLBACK"
        );
    }
}

fn add_omitted(state: &mut LiveState, e: &Evaluation) {
    let extra = AccountWitness {
        id: 19,
        score: 0,
        physical: 0,
        head: 0,
        tail: 0,
    };
    for (sequence, event, witness) in [
        (5, LiveEvent::GroupCreated(6), Witness::default()),
        (
            6,
            life(Event::Account { id: 19, group: 6 }),
            Witness {
                accounts: vec![extra],
                ..Witness::default()
            },
        ),
        (
            7,
            life(Event::Open(90)),
            Witness {
                session: 90,
                ..Witness::default()
            },
        ),
        (
            8,
            LiveEvent::SelectionDone(90),
            Witness {
                session: 90,
                ..Witness::default()
            },
        ),
    ] {
        assert_eq!(
            state
                .observe(&batch(e.epoch, sequence, vec![event], witness))
                .status,
            Status::Comparing
        );
    }
}
#[test]
fn partial_fork_keeps_original_population_and_session_tombstones() {
    for event in [
        Event::Open(10),
        Event::Rehydrate {
            session: 10,
            account: 9,
        },
    ] {
        let (mut state, mut e) = setup(Limits {
            sessions: 1,
            accounts: 2,
            ..Limits::default()
        });
        add_omitted(&mut state, &e);
        e.sequence = 9;
        let witness = if matches!(event, Event::Rehydrate { .. }) {
            Witness {
                session: 10,
                accounts: vec![account(1, true)],
                after: ConnectionState {
                    present: true,
                    physical: 9,
                    score_owner: 9,
                    ..ConnectionState::default()
                },
                ..Witness::default()
            }
        } else {
            Witness {
                session: 10,
                ..Witness::default()
            }
        };
        let mut transaction = must(state.begin_caller(scope(&e, 2, &[10])));
        assert_eq!(
            transaction.batch(&batch(e.epoch, 9, vec![life(event)], witness)),
            Err(InvalidReason::Capacity),
            "CALLER_STAGE_POPULATION_ORIGINAL_TOTALS"
        );
        assert_eq!(transaction.finish(Ok(())).compared_sequence, 8);
    }
    // At equality a new session succeeds; its append must retain the original
    // per-account vector bound, even though most session identities are omitted.
    let (mut state, mut e) = setup(Limits {
        sessions: 2,
        accounts: 2,
        ..Limits::default()
    });
    add_omitted(&mut state, &e);
    e.sequence = 9;
    let before = some(state.view(e.epoch)).accounts;
    let mut transaction = must(state.begin_caller(scope(&e, 4, &[10])));
    must(transaction.batch(&reserve(&e, 9)));
    must(transaction.batch(&created(&e, 11)));
    assert_eq!(
        transaction.finish(Ok(())).status,
        Status::Comparing,
        "CALLER_STAGE_POPULATION_EQUAL"
    );
    let after = some(state.view(e.epoch)).accounts;
    assert_eq!(
        before[1], after[1],
        "CALLER_STAGE_OMITTED_ACCOUNT_PRESERVED"
    );
    e.sequence = 13;
    let mut transaction = must(state.begin_caller(scope(&e, 2, &[90])));
    assert_eq!(
        transaction.batch(&batch(
            e.epoch,
            13,
            vec![life(Event::Open(90))],
            Witness::default()
        )),
        Err(InvalidReason::Identity),
        "CALLER_STAGE_TOMBSTONE_NOT_NEW"
    );
    drop(transaction);
}

#[test]
fn parent_budget_counts_both_factor_copies_at_exact_limit() {
    for extra in [0, 1] {
        let (mut state, e) = setup(Limits::default());
        let mut request = scope(&e, 2, &[]);
        request.frame_bytes = MAX_CALLER_FRAME;
        let ledger = must(
            state.core.owners[&(41, 1)]
                .ledger
                .caller_clone_charge(2, &[]),
        );
        let factor = state.native[&e.epoch].groups[&2].charge;
        state.native_bytes = HISTORY_LIMIT
            - DECODE_MULTIPLIER * MAX_CALLER_FRAME
            - ledger
            - 2 * factor
            - STAGE_OVERHEAD
            + extra;
        let before = state.native_retained_bytes();
        let mut transaction = must(state.begin_caller(request));
        if extra == 0 {
            must(transaction.evaluation(&e));
            assert_eq!(
                transaction.finish(Ok(())).status,
                Status::Comparing,
                "CALLER_STAGE_BUDGET_EQUAL"
            );
            let budget = some(state.caller_peak_budget());
            assert_eq!(
                budget.peak, HISTORY_LIMIT,
                "CALLER_STAGE_NESTED_CLONE_CHARGED"
            );
            assert_eq!(budget.clones, ledger + 2 * factor);
            assert_eq!(
                budget.decode + budget.retained + budget.clones + budget.fixed,
                budget.peak
            );
        } else {
            assert_eq!(
                transaction.evaluation(&e),
                Err(InvalidReason::Capacity),
                "CALLER_STAGE_BUDGET_PLUS_ONE"
            );
            assert_eq!(transaction.finish(Ok(())).compared_sequence, 4);
            assert_eq!(state.native_retained_bytes(), before);
        }
    }
    assert!(Budget::new(MAX_CALLER_FRAME, 0, 0).is_ok());
    for frame in [0, 4, MAX_CALLER_FRAME + 1, usize::MAX] {
        assert_eq!(
            Budget::new(frame, 0, 0),
            Err(InvalidReason::Capacity),
            "CALLER_STAGE_PREFIX_INCLUSIVE_BOUND"
        );
    }
    assert_eq!(Budget::new(5, usize::MAX, 1), Err(InvalidReason::Capacity));
}

#[test]
fn scope_identity_sequence_population_and_escaping_events_fail_closed() {
    for fault in 0..7 {
        let (mut state, e) = setup(Limits::default());
        let many = [1; 65];
        let mut s = scope(&e, 1, &[]);
        let expected = match fault {
            0 => {
                s.sequence += 1;
                InvalidReason::Sequence
            }
            1 => {
                s.span = 0;
                InvalidReason::Sequence
            }
            2 => {
                s.span = 262;
                InvalidReason::Sequence
            }
            3 => {
                s.group = 99;
                InvalidReason::Identity
            }
            4 => {
                s.sessions = &[0];
                InvalidReason::Identity
            }
            5 => {
                s.sessions = &[1, 1];
                InvalidReason::Identity
            }
            _ => {
                s.sessions = &many;
                InvalidReason::Capacity
            }
        };
        assert!(
            matches!(state.begin_caller(s), Err(reason) if reason == expected),
            "CALLER_STAGE_SCOPE_REJECTED"
        );
        assert_eq!(state.progress(e.epoch).compared_sequence, 4);
    }
    let (mut state, e) = setup(Limits::default());
    let transaction = must(state.begin_caller(scope(&e, 2, &[])));
    assert_eq!(
        transaction.finish(Ok(())).status,
        Status::Invalid(InvalidReason::Sequence),
        "CALLER_STAGE_MISSING_CHILD_SPAN"
    );
    for fault in 0..3 {
        let (mut state, e) = setup(Limits::default());
        let mut transaction = must(state.begin_caller(scope(&e, 2, &[])));
        let event = match fault {
            0 => life(Event::Open(10)),
            1 => life(Event::Account { id: 19, group: 2 }),
            _ => LiveEvent::GroupCreated(99),
        };
        assert!(
            transaction
                .batch(&batch(e.epoch, 5, vec![event], Witness::default()))
                .is_err(),
            "CALLER_STAGE_ESCAPING_EVENT"
        );
    }
}

#[test]
fn router_only_stage_does_not_create_group_or_native_state() {
    let (mut state, e) = setup(Limits::default());
    let groups = state.groups.clone();
    let retained = state.native_retained_bytes();
    let mut s = scope(&e, 1, &[]);
    s.group = 0;
    let transaction = must(state.begin_caller(s));
    assert_eq!(transaction.finish(Ok(())).compared_sequence, 5);
    assert_eq!(state.groups, groups);
    assert_eq!(state.native_retained_bytes(), retained);
    assert!(
        !state.native[&e.epoch].groups.contains_key(&0),
        "CALLER_STAGE_NO_FAKE_GROUP"
    );
}

#[test]
fn complete_child_cross_product_has_one_final_sequence_and_strict_limits() {
    for fault in 0..3 {
        let (mut state, mut e) = setup(Limits::default());
        let mut transaction = must(state.begin_caller(scope(&e, 261, &[])));
        for _ in 0..4 {
            must(transaction.evaluation(&e));
            e.sequence += 1;
            e.evaluation += 1;
        }
        if fault == 1 {
            assert_eq!(
                transaction.evaluation(&e),
                Err(InvalidReason::Capacity),
                "CALLER_STAGE_NATIVE_CHILD_PLUS_ONE"
            );
            assert_eq!(transaction.finish(Ok(())).compared_sequence, 4);
            continue;
        }
        for _ in 0..64 {
            must(transaction.batch(&batch(
                e.epoch,
                e.sequence,
                vec![life(Event::Watermark); 4],
                Witness::default(),
            )));
            e.sequence += 4;
        }
        if fault == 2 {
            assert_eq!(
                transaction.batch(&batch(
                    e.epoch,
                    e.sequence,
                    vec![life(Event::Watermark)],
                    Witness::default()
                )),
                Err(InvalidReason::Capacity),
                "CALLER_STAGE_LIFECYCLE_CHILD_PLUS_ONE"
            );
            assert_eq!(transaction.finish(Ok(())).compared_sequence, 4);
        } else {
            let progress = transaction.finish(Ok(()));
            assert_eq!(
                (progress.status, progress.compared_sequence),
                (Status::Comparing, 265),
                "CALLER_STAGE_FULL_SPAN_261"
            );
        }
    }
}

#[test]
fn omitted_live_sessions_still_allow_append_to_original_physical_list_limit() {
    let (mut state, mut e) = setup(Limits {
        sessions: 3,
        accounts: 2,
        ..Limits::default()
    });
    add_omitted(&mut state, &e);
    assert_eq!(state.observe(&reserve(&e, 9)).status, Status::Comparing);
    assert_eq!(state.observe(&created(&e, 11)).status, Status::Comparing);
    e.sequence = 12;
    let mut transaction = must(state.begin_caller(scope(&e, 2, &[11])));
    must(transaction.batch(&batch(
        e.epoch,
        12,
        vec![life(Event::Rehydrate {
            session: 11,
            account: 9,
        })],
        Witness {
            accounts: vec![AccountWitness {
                id: 9,
                score: 2,
                physical: 2,
                head: 10,
                tail: 11,
            }],
            session: 11,
            predecessor: 10,
            after: ConnectionState {
                present: true,
                physical: 9,
                score_owner: 9,
                ..ConnectionState::default()
            },
            ..Witness::default()
        },
    )));
    assert_eq!(
        transaction.finish(Ok(())).status,
        Status::Comparing,
        "CALLER_STAGE_PHYSICAL_ORIGINAL_LIMIT"
    );
    let owner = &state.core.owners[&(41, 1)];
    assert_eq!(
        owner.ledger.connection(10).physical,
        9,
        "CALLER_STAGE_OMITTED_LIVE_SESSION_PRESERVED"
    );
    assert_eq!(
        some(state.view(e.epoch)).accounts[0].physical_order,
        [10, 11]
    );
}

#[test]
fn affected_account_population_is_bounded_before_any_clone() {
    for extra in [0, 1] {
        let (mut state, e) = setup(Limits::default());
        let owner = state
            .core
            .owners
            .get_mut(&(41, 1))
            .unwrap_or_else(|| unreachable!("owner"));
        for id in 100..163 + extra {
            must(owner.ledger.apply(&Event::Account { id, group: 2 }));
        }
        let result = state.begin_caller(scope(&e, 1, &[]));
        if extra == 0 {
            assert_eq!(
                must(result).finish(Ok(())).status,
                Status::Comparing,
                "CALLER_STAGE_ACCOUNTS_EQUAL"
            );
        } else {
            assert!(
                matches!(result, Err(InvalidReason::Capacity)),
                "CALLER_STAGE_ACCOUNTS_PLUS_ONE"
            );
        }
    }
}
