// Copyright 2026 PingCAP, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use super::*;

const EPOCH: Epoch = Epoch {
    process: 10,
    owner: 20,
    nonce: 30,
};
fn send(state: &mut ShadowState, sequence: u64, event: Event) -> Progress {
    state.observe(&Observation {
        epoch: EPOCH,
        sequence,
        event,
    })
}
fn setup() -> ShadowState {
    let mut state = ShadowState::new(Limits::default());
    assert_eq!(send(&mut state, 1, Event::Begin).status, Status::Comparing);
    assert_eq!(
        send(&mut state, 2, Event::Account { id: 1, group: 1 }).status,
        Status::Comparing
    );
    assert_eq!(
        send(&mut state, 3, Event::Account { id: 2, group: 1 }).status,
        Status::Comparing
    );
    assert_eq!(
        send(
            &mut state,
            4,
            Event::Rehydrate {
                session: 1,
                account: 1
            }
        )
        .status,
        Status::Comparing
    );
    state
}
fn view(state: &ShadowState) -> LedgerView {
    match state.view(EPOCH) {
        Some(view) => view,
        None => unreachable!(),
    }
}

#[test]
fn shadow_score_physical_and_both_close_result_orders() {
    for close_first in [false, true] {
        let mut state = setup();
        assert_eq!(
            send(
                &mut state,
                5,
                Event::Redirect {
                    session: 1,
                    operation: 1,
                    target: 2
                }
            )
            .status,
            Status::Comparing
        );
        let pending = view(&state);
        assert_eq!(
            pending.accounts[0].counts.active(),
            1,
            "SHADOW_SCORE_PHYSICAL"
        );
        assert_eq!(
            pending.accounts[0].counts.score(),
            0,
            "SHADOW_SCORE_PHYSICAL"
        );
        assert_eq!(
            pending.accounts[1].counts.active(),
            0,
            "SHADOW_SCORE_PHYSICAL"
        );
        assert_eq!(
            pending.accounts[1].counts.score(),
            1,
            "SHADOW_SCORE_PHYSICAL"
        );
        assert_eq!(
            send(
                &mut state,
                6,
                Event::Closing {
                    session: 1,
                    operation: 1
                }
            )
            .status,
            Status::Comparing
        );
        assert_eq!(
            view(&state).accounts,
            pending.accounts,
            "SHADOW_CLOSE_ADMISSION"
        );
        let closed = Event::Closed(1);
        let result = Event::Redirected {
            session: 1,
            operation: 1,
            success: true,
        };
        let (first, second) = if close_first {
            (closed, result)
        } else {
            (result, closed)
        };
        assert_eq!(send(&mut state, 7, first).status, Status::Comparing);
        assert_eq!(send(&mut state, 8, second).status, Status::Comparing);
        assert!(
            view(&state)
                .accounts
                .iter()
                .all(|a| a.counts == Counts::default() && a.physical_order.is_empty()),
            "SHADOW_CLOSE_RESULT_ORDER"
        );
        assert_eq!(
            send(&mut state, 9, Event::Closed(1)).transition,
            Some(Transition::Ignored),
            "SHADOW_TERMINAL_DUPLICATE"
        );
    }
}

#[test]
fn shadow_failed_redirect_retains_arrival_and_old_result_cannot_settle_new() {
    let mut state = setup();
    send(
        &mut state,
        5,
        Event::Rehydrate {
            session: 2,
            account: 1,
        },
    );
    send(
        &mut state,
        6,
        Event::Redirect {
            session: 1,
            operation: 4,
            target: 2,
        },
    );
    send(
        &mut state,
        7,
        Event::Redirected {
            session: 1,
            operation: 4,
            success: false,
        },
    );
    assert_eq!(
        view(&state).accounts[0].physical_order,
        vec![1, 2],
        "SHADOW_FAILED_ORDER"
    );
    send(
        &mut state,
        8,
        Event::Redirect {
            session: 1,
            operation: 5,
            target: 2,
        },
    );
    let before = view(&state).accounts;
    assert_eq!(
        send(
            &mut state,
            9,
            Event::Redirected {
                session: 1,
                operation: 4,
                success: true
            }
        )
        .transition,
        Some(Transition::Ignored),
        "SHADOW_OPERATION_IDENTITY"
    );
    assert_eq!(view(&state).accounts, before, "SHADOW_OPERATION_IDENTITY");
    send(
        &mut state,
        10,
        Event::Redirected {
            session: 1,
            operation: 5,
            success: true,
        },
    );
    assert_eq!(
        view(&state).accounts[0].physical_order,
        vec![2],
        "SHADOW_ARRIVAL_ORDER"
    );
    assert_eq!(view(&state).accounts[1].physical_order, vec![1]);
}

#[test]
fn shadow_route_failure_retry_and_close_settle_only_original_reservation() {
    let mut state = setup();
    send(&mut state, 5, Event::Open(2));
    send(
        &mut state,
        6,
        Event::Reserve {
            session: 2,
            operation: 1,
            account: 1,
        },
    );
    assert_eq!(view(&state).accounts[0].counts.reserved(), 1);
    send(
        &mut state,
        7,
        Event::Created {
            session: 2,
            operation: 1,
            success: false,
        },
    );
    send(
        &mut state,
        8,
        Event::Reserve {
            session: 2,
            operation: 2,
            account: 2,
        },
    );
    assert_eq!(
        send(
            &mut state,
            9,
            Event::Created {
                session: 2,
                operation: 1,
                success: true
            }
        )
        .transition,
        Some(Transition::Ignored)
    );
    assert_eq!(
        view(&state).accounts[1].counts.reserved(),
        1,
        "SHADOW_ROUTE_RETRY"
    );
    send(&mut state, 10, Event::Closed(2));
    assert_eq!(
        send(
            &mut state,
            11,
            Event::Created {
                session: 2,
                operation: 2,
                success: true
            }
        )
        .transition,
        Some(Transition::Ignored)
    );
    assert_eq!(
        view(&state).accounts[1].counts,
        Counts::default(),
        "SHADOW_ROUTE_CLOSE"
    );
}

#[test]
fn shadow_epoch_gap_duplicate_and_begin_replay_are_sticky() {
    for observation in [
        Observation {
            epoch: EPOCH,
            sequence: 6,
            event: Event::Watermark,
        },
        Observation {
            epoch: EPOCH,
            sequence: 4,
            event: Event::Watermark,
        },
        Observation {
            epoch: EPOCH,
            sequence: 5,
            event: Event::Begin,
        },
        Observation {
            epoch: Epoch { nonce: 31, ..EPOCH },
            sequence: 1,
            event: Event::Begin,
        },
    ] {
        let mut state = setup();
        let result = state.observe(&observation);
        assert!(
            matches!(result.status, Status::Invalid(_)),
            "SHADOW_SEQUENCE_BEGIN"
        );
        assert_eq!(result.compared_sequence, 4);
        assert_eq!(
            send(&mut state, 5, Event::Closed(1)).status,
            result.status,
            "SHADOW_INVALID_STICKY"
        );
        assert_eq!(
            view(&state).accounts[0].counts.active(),
            1,
            "SHADOW_INVALID_STICKY"
        );
    }
    let mut state = ShadowState::new(Limits::default());
    assert_eq!(
        send(
            &mut state,
            1,
            Event::Rehydrate {
                session: 1,
                account: 1
            }
        )
        .status,
        Status::Invalid(InvalidReason::MissingBegin),
        "SHADOW_LATE_ATTACH"
    );
    assert_eq!(
        send(&mut state, 1, Event::Begin).status,
        Status::Invalid(InvalidReason::MissingBegin),
        "SHADOW_LATE_ATTACH"
    );
}

#[test]
fn shadow_process_restart_keeps_invalid_old_interval_and_rehydrates_fresh_owner() {
    let mut state = setup();
    let first = view(&state).local_owner;
    state.transport_lost();
    assert_eq!(
        view(&state).status,
        Status::Invalid(InvalidReason::Transport)
    );
    assert_eq!(
        send(&mut state, 5, Event::Watermark).status,
        Status::Invalid(InvalidReason::Transport)
    );
    let fresh = Epoch {
        process: 11,
        ..EPOCH
    };
    for (index, event) in [
        Event::Begin,
        Event::Account { id: 1, group: 1 },
        Event::Rehydrate {
            session: 1,
            account: 1,
        },
    ]
    .into_iter()
    .enumerate()
    {
        let sequence = u64::try_from(index).unwrap_or(0) + 1;
        assert_eq!(
            state
                .observe(&Observation {
                    epoch: fresh,
                    sequence,
                    event
                })
                .status,
            Status::Comparing,
            "SHADOW_NEW_PROCESS"
        );
    }
    let Some(new) = state.view(fresh) else {
        unreachable!()
    };
    assert_ne!(new.local_owner, first, "SHADOW_LOCAL_IDENTITY");
    assert_eq!(new.accounts[0].counts.active(), 1);
    assert_eq!(
        view(&state).status,
        Status::Invalid(InvalidReason::Transport)
    );
}

#[test]
fn shadow_factor_lifetime_is_separate_and_connection_transition_is_not_coalesced() {
    let mut state = setup();
    let owner = view(&state).local_owner;
    send(&mut state, 5, Event::Policy(Policy::Resource));
    let first = view(&state).factor_lifetime;
    assert!(first.is_some());
    send(&mut state, 6, Event::Policy(Policy::Location));
    assert_eq!(
        view(&state).factor_lifetime,
        first,
        "SHADOW_RESOURCE_LOCATION_LIFETIME"
    );
    send(&mut state, 7, Event::Policy(Policy::Connection));
    assert_eq!(view(&state).factor_lifetime, None);
    send(&mut state, 8, Event::Policy(Policy::Resource));
    assert_ne!(
        view(&state).factor_lifetime,
        first,
        "SHADOW_RESOURCE_REENTRY"
    );
    assert_eq!(view(&state).local_owner, owner);
}

#[test]
fn shadow_retirement_keeps_tail_and_requires_explicit_complete_end() {
    let mut state = setup();
    send(
        &mut state,
        5,
        Event::Redirect {
            session: 1,
            operation: 1,
            target: 2,
        },
    );
    send(&mut state, 6, Event::Retire);
    send(
        &mut state,
        7,
        Event::Redirected {
            session: 1,
            operation: 1,
            success: true,
        },
    );
    assert_eq!(
        view(&state).accounts[1].counts.active(),
        1,
        "SHADOW_RETIRED_TAIL"
    );
    send(&mut state, 8, Event::Closed(1));
    assert_eq!(send(&mut state, 9, Event::End).status, Status::CleanEnded);
    let mut premature = setup();
    send(&mut premature, 5, Event::Retire);
    assert_eq!(
        send(&mut premature, 6, Event::End).status,
        Status::Invalid(InvalidReason::Lifecycle),
        "SHADOW_PREMATURE_END"
    );
}

#[test]
fn shadow_capacity_and_removed_identity_never_evict_history() {
    let mut state = ShadowState::new(Limits {
        owners: 1,
        accounts: 1,
        sessions: 1,
    });
    send(&mut state, 1, Event::Begin);
    send(&mut state, 2, Event::Account { id: 1, group: 1 });
    send(&mut state, 3, Event::RemoveAccount(1));
    assert_eq!(
        send(&mut state, 4, Event::Account { id: 1, group: 1 }).status,
        Status::Invalid(InvalidReason::Identity),
        "SHADOW_ACCOUNT_TOMBSTONE"
    );
    let mut state = ShadowState::new(Limits {
        owners: 1,
        accounts: 1,
        sessions: 1,
    });
    send(&mut state, 1, Event::Begin);
    send(&mut state, 2, Event::Account { id: 1, group: 1 });
    send(
        &mut state,
        3,
        Event::Rehydrate {
            session: 1,
            account: 1,
        },
    );
    send(&mut state, 4, Event::Closed(1));
    assert_eq!(
        send(&mut state, 5, Event::Open(2)).status,
        Status::Invalid(InvalidReason::Capacity),
        "SHADOW_SESSION_BOUND"
    );
    assert_eq!(view(&state).accounts[0].counts, Counts::default());
}

#[test]
fn shadow_unknown_terminal_is_missing_history_not_a_duplicate() {
    for event in [
        Event::Closed(999),
        Event::Created {
            session: 999,
            operation: 1,
            success: true,
        },
        Event::Redirected {
            session: 999,
            operation: 1,
            success: true,
        },
    ] {
        let mut state = setup();
        let before = view(&state).accounts;
        let progress = send(&mut state, 5, event);
        assert_eq!(
            progress.status,
            Status::Invalid(InvalidReason::Identity),
            "SHADOW_UNKNOWN_IDENTITY"
        );
        assert_eq!(progress.compared_sequence, 4);
        assert_eq!(view(&state).accounts, before);
        assert!(view(&state).lifecycle_only, "SHADOW_COVERAGE_SCOPE");
    }
}

#[test]
fn shadow_foreign_nonce_and_owner_capacity_fail_without_reusing_registry() {
    let mut state = setup();
    let progress = state.observe(&Observation {
        epoch: Epoch { nonce: 99, ..EPOCH },
        sequence: 5,
        event: Event::Watermark,
    });
    assert_eq!(
        progress.status,
        Status::Invalid(InvalidReason::ReplayedBegin),
        "SHADOW_FOREIGN_NONCE"
    );
    let mut state = ShadowState::new(Limits {
        owners: 1,
        ..Limits::default()
    });
    assert_eq!(send(&mut state, 1, Event::Begin).status, Status::Comparing);
    let next = Epoch { owner: 21, ..EPOCH };
    assert_eq!(
        state
            .observe(&Observation {
                epoch: next,
                sequence: 1,
                event: Event::Begin
            })
            .status,
        Status::Invalid(InvalidReason::Capacity),
        "SHADOW_OWNER_BOUND"
    );
    assert_eq!(
        view(&state).status,
        Status::Invalid(InvalidReason::Capacity)
    );
}

#[test]
fn shadow_global_capacity_preserves_each_exact_owners_compared_sequence() {
    let mut state = ShadowState::new(Limits {
        owners: 2,
        ..Limits::default()
    });
    send(&mut state, 1, Event::Begin);
    send(&mut state, 2, Event::Account { id: 1, group: 1 });
    send(&mut state, 3, Event::Open(1));
    let second = Epoch { owner: 21, ..EPOCH };
    state.observe(&Observation {
        epoch: second,
        sequence: 1,
        event: Event::Begin,
    });
    let overflow = Epoch { owner: 22, ..EPOCH };
    assert_eq!(
        state.observe(&Observation {
            epoch: overflow,
            sequence: 1,
            event: Event::Begin,
        }),
        Progress {
            status: Status::Invalid(InvalidReason::Capacity),
            compared_sequence: 0,
            transition: None,
        }
    );
    for (epoch, sequence) in [
        (EPOCH, 3),
        (second, 1),
        (overflow, 0),
        (Epoch { nonce: 99, ..EPOCH }, 0),
    ] {
        for event in [Event::Watermark, Event::Open(99)] {
            assert_eq!(
                state.observe(&Observation {
                    epoch,
                    sequence: 100,
                    event,
                }),
                Progress {
                    status: Status::Invalid(InvalidReason::Capacity),
                    compared_sequence: sequence,
                    transition: None,
                },
                "SHADOW_CAPACITY_PROGRESS"
            );
        }
    }
    assert_eq!(view(&state).compared_sequence, 3);
    assert_eq!(view(&state).accounts[0].counts, Counts::default());
    assert!(state.view(overflow).is_none());
    assert!(state.view(Epoch { nonce: 99, ..EPOCH }).is_none());
}

#[test]
fn shadow_account_limit_and_rejected_admission_preserve_state() {
    let mut state = ShadowState::new(Limits {
        accounts: 1,
        ..Limits::default()
    });
    send(&mut state, 1, Event::Begin);
    send(&mut state, 2, Event::Account { id: 1, group: 1 });
    let before = view(&state).accounts;
    assert_eq!(
        send(&mut state, 3, Event::Account { id: 2, group: 1 }).status,
        Status::Invalid(InvalidReason::Capacity),
        "SHADOW_ACCOUNT_BOUND"
    );
    assert_eq!(view(&state).accounts, before);
    let mut state = setup();
    let before = view(&state);
    assert_eq!(
        send(&mut state, 5, Event::Rejected { session: 1 }).transition,
        Some(Transition::Ignored),
        "SHADOW_REJECTED"
    );
    assert_eq!(view(&state).accounts, before.accounts, "SHADOW_REJECTED");
    assert_eq!(
        view(&state).pending_redirects,
        before.pending_redirects,
        "SHADOW_REJECTED"
    );
}

#[test]
fn shadow_unsealed_eof_is_not_a_complete_lifecycle_trace() {
    let empty = ShadowState::new(Limits::default());
    assert!(!empty.lifecycle_trace_complete(), "SHADOW_UNSEALED_EOF");
    let mut state = setup();
    assert!(!state.lifecycle_trace_complete(), "SHADOW_UNSEALED_EOF");
    send(&mut state, 5, Event::Closed(1));
    send(&mut state, 6, Event::Retire);
    assert!(!state.lifecycle_trace_complete(), "SHADOW_UNSEALED_EOF");
    send(&mut state, 7, Event::End);
    assert!(state.lifecycle_trace_complete(), "SHADOW_CLEAN_END");
    let other = Epoch { owner: 21, ..EPOCH };
    state.observe(&Observation {
        epoch: other,
        sequence: 1,
        event: Event::Begin,
    });
    assert!(!state.lifecycle_trace_complete(), "SHADOW_UNSEALED_EOF");
    state.transport_lost();
    assert!(!state.lifecycle_trace_complete(), "SHADOW_UNSEALED_EOF");
}

#[test]
fn shadow_foreign_invalidation_cannot_report_another_epoch_qualified() {
    let mut state = setup();
    let foreign = Epoch { nonce: 99, ..EPOCH };
    let progress = state.invalidate(foreign, InvalidReason::Stale);
    assert_eq!(
        progress.status,
        Status::Invalid(InvalidReason::Identity),
        "SHADOW_INVALIDATION_SCOPE"
    );
    assert_eq!(progress.compared_sequence, 0);
    assert!(state.view(foreign).is_none());
    assert_eq!(view(&state).status, Status::Comparing);
}
