// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0
use super::*;
use crate::shadow::{
    Limits, Status,
    live::{AccountWitness, Witness},
};

fn must<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
    result.unwrap_or_else(|e| unreachable!("fixture {e:?}"))
}
fn life(event: Event) -> LiveEvent {
    LiveEvent::Lifecycle {
        event,
        source: 0,
        target: 0,
    }
}
fn fixture() -> (LiveState, Envelope) {
    let (state, mut e) = super::super::tests::setup(Limits::default());
    e.entry = Entry::Route;
    let envelope = Envelope {
        epoch: e.epoch,
        sequence: 5,
        span: 4,
        route: Route {
            caller: 1,
            group: 2,
            session: 10,
            excluded_count: 0,
            members: vec![9],
            reads: vec![Read::Healthy {
                completed: 0,
                account: 9,
                value: true,
            }],
            result: ResultValue {
                account: 9,
                operation: 1,
                completed: 2,
            },
        },
        children: vec![
            Child::Evaluation(Box::new(e.clone())),
            Child::Batch(Batch {
                epoch: e.epoch,
                sequence: 6,
                events: vec![
                    life(Event::Open(10)),
                    life(Event::Reserve {
                        session: 10,
                        operation: 1,
                        account: 9,
                    }),
                ],
                witness: Witness {
                    accounts: vec![AccountWitness {
                        id: 9,
                        score: 1,
                        physical: 0,
                        head: 0,
                        tail: 0,
                    }],
                    session: 10,
                    ..Witness::default()
                },
            }),
        ],
    };
    (state, envelope)
}
fn empty_result(e: &mut Envelope) {
    let Child::Evaluation(native) = &mut e.children[0] else {
        unreachable!("fixture")
    };
    native.accounts.clear();
    native.reads.clear();
    native.sorted.clear();
    native.returned.clear();
    e.children[1] = Child::Batch(Batch {
        epoch: e.epoch,
        sequence: 6,
        events: vec![LiveEvent::RouteRejected {
            session: 10,
            group: 2,
        }],
        witness: Witness::default(),
    });
    e.route.result.account = 0;
    e.route.result.operation = 0;
    e.span = 3;
}
#[test]
fn independent_route_result_and_reservation_commit_together() {
    let (mut state, e) = fixture();
    let (progress, derived) = state.observe_group_route_result(&e, 4096);
    assert_eq!(
        derived,
        Some(DerivedResult {
            backend: 9,
            error: ErrorClass::None,
            binding: Some(Binding {
                account: 9,
                group: 2,
                operation: 1,
            }),
        }),
        "ROUTE_DERIVED_COMMITTED_BINDING"
    );
    assert_eq!(
        (progress.status, progress.compared_sequence),
        (Status::Comparing, 8),
        "ROUTE_COMMIT_FINAL_PREFIX"
    );
    assert_eq!(
        state.totals(e.epoch),
        Some((1, 0)),
        "ROUTE_COMMIT_RESERVATION"
    );
    let (replayed, derived) = state.observe_group_route_result(&e, 4096);
    assert_eq!(replayed.compared_sequence, 8, "ROUTE_REPLAY_NO_PREFIX");
    assert_eq!(derived, None, "ROUTE_REPLAY_NO_BINDING");
}
#[test]
fn late_result_failure_rolls_back_native_and_ledger() {
    for fault in 0..5 {
        let (mut state, mut e) = fixture();
        let native = if let Child::Evaluation(n) = &e.children[0] {
            n.clone()
        } else {
            unreachable!("fixture")
        };
        let retained = state.native_retained_bytes();
        match fault {
            0 => e.route.result.completed = 1,
            1 => e.route.result.account = 19,
            2 => {
                if let Child::Batch(b) = &mut e.children[1] {
                    b.witness.accounts[0].score = 2;
                }
            }
            3 => {
                if let Child::Batch(b) = &mut e.children[1] {
                    b.events[1] = life(Event::Reserve {
                        session: 10,
                        operation: 2,
                        account: 9,
                    });
                }
            }
            _ => {
                e.children.push(Child::Batch(Batch {
                    epoch: e.epoch,
                    sequence: 8,
                    events: vec![life(Event::Watermark)],
                    witness: Witness::default(),
                }));
                e.span += 1;
                e.route.result.completed = 3;
            }
        }
        let (p, derived) = state.observe_group_route_result(&e, 4096);
        assert_eq!(derived, None, "ROUTE_FAILED_NO_BINDING");
        assert_eq!(
            (p.status, p.compared_sequence),
            (Status::Invalid(InvalidReason::Witness), 4),
            "ROUTE_LATE_FAILURE_ROLLBACK"
        );
        assert_eq!(
            state.totals(e.epoch),
            Some((0, 0)),
            "ROUTE_ROLLBACK_RESERVATION"
        );
        assert_eq!(
            state.native_retained_bytes(),
            retained,
            "ROUTE_ROLLBACK_HISTORY_CHARGE"
        );
        let mut history = state.native[&e.epoch].groups[&2].state.clone();
        assert_eq!(
            history.apply(&native),
            Ok(()),
            "ROUTE_ROLLBACK_FACTOR_CONTENT"
        );
        let owner = state
            .core
            .owners
            .get_mut(&(41, 1))
            .unwrap_or_else(|| unreachable!("owner"));
        assert!(
            owner.ledger.apply(&Event::Open(10)).is_ok(),
            "ROUTE_ROLLBACK_SESSION_OPEN"
        );
    }
}
#[test]
fn filtering_consumes_exact_short_circuit_tape() {
    for fault in 0..5 {
        let (mut state, mut e) = fixture();
        empty_result(&mut e);
        e.route.excluded_count = 2;
        e.route.reads.extend([
            Read::BackendId {
                completed: 0,
                account: 9,
                value: "same".into(),
            },
            Read::ExcludedId {
                completed: 0,
                index: 0,
                value: "same".into(),
            },
        ]);
        match fault {
            0 => (),
            1 => e.route.reads.push(Read::BackendId {
                completed: 0,
                account: 9,
                value: "extra".into(),
            }),
            2 => e.route.reads.swap(1, 2),
            3 => {
                e.route.reads[0] = Read::Healthy {
                    completed: 1,
                    account: 9,
                    value: true,
                }
            }
            _ => {
                e.route.reads[2] = Read::ExcludedId {
                    completed: 0,
                    index: 1,
                    value: "same".into(),
                }
            }
        }
        let p = state.observe_group_route(&e, 4096);
        assert_eq!(
            p.status == Status::Comparing,
            fault == 0,
            "ROUTE_EXCLUSION_SHORT_CIRCUIT"
        );
        assert_eq!(p.compared_sequence, if fault == 0 { 7 } else { 4 });
    }
    let (mut state, mut e) = fixture();
    empty_result(&mut e);
    e.route.excluded_count = 64;
    e.route.reads[0] = Read::Healthy {
        completed: 0,
        account: 9,
        value: false,
    };
    assert_eq!(
        state.observe_group_route(&e, 4096).status,
        Status::Comparing,
        "ROUTE_UNHEALTHY_NO_ID_READ"
    );
}
#[test]
fn empty_group_differs_from_filtered_empty_and_inventory_is_complete() {
    for fault in 0..4 {
        let (mut state, mut e) = fixture();
        empty_result(&mut e);
        e.route.reads[0] = Read::Healthy {
            completed: 0,
            account: 9,
            value: false,
        };
        match fault {
            0 => (),
            1 => {
                e.children.remove(0);
                if let Child::Batch(b) = &mut e.children[0] {
                    b.sequence = 5;
                }
                e.span = 2;
                e.route.result.completed = 1;
            }
            2 => {
                e.route.members.clear();
                e.route.reads.clear();
            }
            _ => {
                e.route.members[0] = 19;
                e.route.reads[0] = Read::Healthy {
                    completed: 0,
                    account: 19,
                    value: false,
                };
            }
        }
        assert_eq!(
            state.observe_group_route(&e, 4096).status == Status::Comparing,
            fault == 0,
            "ROUTE_FILTERED_EMPTY_STILL_FACTOR"
        );
    }
    let (mut state, mut e) = fixture();
    empty_result(&mut e);
    let owner = state
        .core
        .owners
        .get_mut(&(41, 1))
        .unwrap_or_else(|| unreachable!("owner"));
    must(owner.ledger.apply(&Event::RemoveAccount(9)));
    e.route.members.clear();
    e.route.reads.clear();
    e.children.remove(0);
    if let Child::Batch(b) = &mut e.children[0] {
        b.sequence = 5;
    }
    e.span = 2;
    e.route.result.completed = 1;
    assert_eq!(
        state.observe_group_route(&e, 4096).status,
        Status::Comparing,
        "ROUTE_EMPTY_GROUP_NO_FACTOR"
    );
}
#[test]
fn nested_identity_order_span_and_limits_cannot_commit() {
    for fault in 0..8 {
        let (mut state, mut e) = fixture();
        match fault {
            0 => {
                // Structurally contiguous nested envelope, but not the retained
                // owner's next boundary: exercise begin_caller failure too.
                e.sequence = 40;
                if let Child::Evaluation(n) = &mut e.children[0] {
                    n.sequence = 40;
                }
                if let Child::Batch(b) = &mut e.children[1] {
                    b.sequence = 41;
                }
            }
            1 => e.span += 1,
            2 => {
                if let Child::Batch(b) = &mut e.children[1] {
                    b.epoch.owner += 1;
                }
            }
            3 => {
                if let Child::Evaluation(n) = &mut e.children[0] {
                    n.group += 1;
                }
            }
            4 => e.children.swap(0, 1),
            5 => e.route.members = vec![9, 9],
            6 => e.route.reads = vec![e.route.reads[0].clone(); 129],
            _ => e.route.reads.push(Read::BackendId {
                completed: 0,
                account: 9,
                value: "x".repeat(513),
            }),
        }
        let p = state.observe_group_route(&e, 4096);
        assert!(
            matches!(p.status, Status::Invalid(_)),
            "ROUTE_NESTED_REJECT"
        );
        assert_eq!(
            p.compared_sequence, 4,
            "ROUTE_INVALID_PRESERVES_ACTUAL_PREFIX"
        );
        assert_eq!(state.totals(e.epoch), Some((0, 0)));
    }
}

#[test]
fn retry_reservation_uses_existing_session_and_new_operation() {
    for replay in [false, true] {
        let (mut state, mut e) = fixture();
        assert_eq!(
            state.observe_group_route(&e, 4096).status,
            Status::Comparing
        );
        let failed = Batch {
            epoch: e.epoch,
            sequence: 9,
            events: vec![life(Event::Created {
                session: 10,
                operation: 1,
                success: false,
            })],
            witness: Witness {
                session: 10,
                accounts: vec![AccountWitness {
                    id: 9,
                    score: 0,
                    physical: 0,
                    head: 0,
                    tail: 0,
                }],
                ..Witness::default()
            },
        };
        assert_eq!(state.observe(&failed).status, Status::Comparing);
        e.sequence = 10;
        e.span = 3;
        e.route.caller = 2;
        e.route.result.operation = if replay { 1 } else { 2 };
        if let Child::Evaluation(n) = &mut e.children[0] {
            n.sequence = 10;
            n.evaluation = 3;
        }
        if let Child::Batch(b) = &mut e.children[1] {
            b.sequence = 11;
            b.events = vec![life(Event::Reserve {
                session: 10,
                operation: e.route.result.operation,
                account: 9,
            })];
        }
        let p = state.observe_group_route(&e, 4096);
        assert_eq!(
            p.status == Status::Comparing,
            !replay,
            "ROUTE_RETRY_OPERATION_WATERMARK"
        );
        assert_eq!(
            p.compared_sequence,
            if replay { 9 } else { 12 },
            "ROUTE_RETRY_ATOMIC_PREFIX"
        );
        assert_eq!(state.totals(e.epoch), Some((u64::from(!replay), 0)));
    }
}

#[test]
fn late_selector_attempt_failure_rolls_back_group_factor_and_reservation() {
    use super::super::selection::{Boundary, BoundaryEvent};
    for ordinal in [1, 2] {
        let (mut state, mut envelope) = fixture();
        assert_eq!(
            state
                .observe_selector_boundary(
                    &Boundary {
                        epoch: envelope.epoch,
                        sequence: 5,
                        session: 10,
                        event: BoundaryEvent::Begin {
                            next: 1,
                            current: 0,
                            excluded: vec![]
                        }
                    },
                    128
                )
                .status,
            Status::Comparing
        );
        envelope.sequence += 1;
        for child in &mut envelope.children {
            match child {
                Child::Evaluation(e) => e.sequence += 1,
                Child::Batch(b) => b.sequence += 1,
            }
        }
        let before = state.native_retained_bytes();
        let (progress, derived) =
            state.observe_selector_group_route_result(&envelope, 1, ordinal, &[], 4096);
        if ordinal == 1 {
            assert_eq!(progress.status, Status::Comparing);
            assert!(derived.is_some());
            assert_eq!(state.totals(envelope.epoch), Some((1, 0)));
        } else {
            assert_eq!(
                progress.status,
                Status::Invalid(InvalidReason::Sequence),
                "SELECTOR_GROUP_LATE_FAILURE"
            );
            assert_eq!(progress.compared_sequence, 5);
            assert!(derived.is_none());
            assert_eq!(
                state.totals(envelope.epoch),
                Some((0, 0)),
                "SELECTOR_GROUP_NO_RESERVATION_ESCAPE"
            );
            assert_eq!(
                state.native_retained_bytes(),
                before,
                "SELECTOR_GROUP_NO_FACTOR_ESCAPE"
            );
        }
    }
}

fn finish_fixture(wrong_operation: bool) -> (LiveState, super::super::finish::Envelope) {
    use super::super::{
        finish,
        selection::{Boundary, BoundaryEvent},
    };
    let (mut state, mut route) = fixture();
    let epoch = route.epoch;
    let begin = Boundary {
        epoch,
        sequence: 5,
        session: 10,
        event: BoundaryEvent::Begin {
            next: 1,
            current: 0,
            excluded: vec![],
        },
    };
    assert_eq!(
        state.observe_selector_boundary(&begin, 128).status,
        Status::Comparing
    );
    route.sequence += 1;
    for child in &mut route.children {
        match child {
            Child::Evaluation(e) => e.sequence += 1,
            Child::Batch(b) => b.sequence += 1,
        }
    }
    assert_eq!(
        state
            .observe_selector_group_route_result(&route, 1, 1, &[], 4096)
            .0
            .status,
        Status::Comparing
    );
    let end = Boundary {
        epoch,
        sequence: 10,
        session: 10,
        event: BoundaryEvent::End {
            next: 1,
            current: 9,
            excluded: vec![9],
            backend: 9,
            error: ErrorClass::None,
        },
    };
    assert_eq!(
        state.observe_selector_boundary(&end, 128).status,
        Status::Comparing
    );
    let envelope = finish::Envelope {
        epoch,
        sequence: 11,
        span: 2,
        caller: 3,
        group: 2,
        session: 10,
        backend: 9,
        operation: if wrong_operation { 2 } else { 1 },
        success: false,
        created: Batch {
            epoch,
            sequence: 11,
            events: vec![life(Event::Created {
                session: 10,
                operation: 1,
                success: false,
            })],
            witness: Witness {
                accounts: vec![AccountWitness {
                    id: 9,
                    score: 0,
                    physical: 0,
                    head: 0,
                    tail: 0,
                }],
                session: 10,
                ..Witness::default()
            },
        },
    };
    (state, envelope)
}

#[test]
fn finish_late_binding_failure_cannot_refund_or_advance() {
    for wrong_operation in [false, true] {
        let (mut state, envelope) = finish_fixture(wrong_operation);
        let epoch = envelope.epoch;
        let retained = state.native_retained_bytes();
        let progress = state.observe_selector_finish(&envelope, 1024);
        if wrong_operation {
            assert_eq!(
                progress.status,
                Status::Invalid(InvalidReason::Witness),
                "FINISH_LATE_OPERATION_WITNESS"
            );
            assert_eq!(progress.compared_sequence, 10, "FINISH_NO_PREFIX_ESCAPE");
            assert_eq!(state.totals(epoch), Some((1, 0)), "FINISH_NO_REFUND_ESCAPE");
            assert_eq!(
                state.native_retained_bytes(),
                retained,
                "FINISH_NO_RETAINED_ESCAPE"
            );
        } else {
            assert_eq!(
                progress.status,
                Status::Comparing,
                "FINISH_ACTUAL_REFUND_COMMIT"
            );
            assert_eq!(progress.compared_sequence, 12);
            assert_eq!(state.totals(epoch), Some((0, 0)));
            let mut duplicate = envelope;
            duplicate.sequence = 13;
            duplicate.created.sequence = 13;
            assert!(
                matches!(
                    state.observe_selector_finish(&duplicate, 1024).status,
                    Status::Invalid(_)
                ),
                "FINISH_NO_DUPLICATE_REFUND"
            );
            assert_eq!(state.progress(epoch).compared_sequence, 12);
        }
    }
}

#[test]
fn finish_after_actual_selection_done_and_close_is_rejected() {
    use super::super::selection::{Boundary, BoundaryEvent};
    let (mut state, mut envelope) = finish_fixture(false);
    let epoch = envelope.epoch;
    assert_eq!(
        state.observe_selector_finish(&envelope, 1024).status,
        Status::Comparing
    );
    let done = Batch {
        epoch,
        sequence: 13,
        events: vec![LiveEvent::SelectionDone(10)],
        witness: Witness {
            session: 10,
            ..Witness::default()
        },
    };
    assert_eq!(state.observe(&done).status, Status::Comparing);
    let close = Boundary {
        epoch,
        sequence: 14,
        session: 10,
        event: BoundaryEvent::Close {
            next: 1,
            current: 9,
            excluded: vec![9],
        },
    };
    assert_eq!(
        state.observe_selector_boundary(&close, 128).status,
        Status::Comparing
    );
    assert!(state.selectors_settled(epoch));
    let retained = state.native_retained_bytes();
    envelope.sequence = 15;
    envelope.created.sequence = 15;
    let progress = state.observe_selector_finish(&envelope, 1024);
    assert_eq!(
        progress.status,
        Status::Invalid(InvalidReason::Lifecycle),
        "FINISH_CLOSED_SELECTOR_REJECTED"
    );
    assert_eq!(
        progress.compared_sequence, 14,
        "FINISH_CLOSED_PREFIX_UNCHANGED"
    );
    assert_eq!(state.totals(epoch), Some((0, 0)), "FINISH_CLOSED_NO_REFUND");
    assert_eq!(state.native_retained_bytes(), retained);
}
