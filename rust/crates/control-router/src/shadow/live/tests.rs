// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0
use super::*;

fn epoch(owner: u64) -> Epoch {
    Epoch {
        process: 41,
        owner,
        nonce: 43,
    }
}
fn life(event: Event) -> LiveEvent {
    LiveEvent::Lifecycle {
        event,
        source: 0,
        target: 0,
    }
}
fn batch(sequence: u64, events: Vec<LiveEvent>, witness: Witness) -> Batch {
    Batch {
        epoch: epoch(1),
        sequence,
        events,
        witness,
    }
}
fn account(score: i64, order: &[u64]) -> AccountWitness {
    AccountWitness {
        id: 2,
        score,
        physical: u64::try_from(order.len()).unwrap_or(u64::MAX),
        head: order.first().copied().unwrap_or(0),
        tail: order.last().copied().unwrap_or(0),
    }
}
fn connection() -> ConnectionState {
    ConnectionState {
        present: true,
        physical: 2,
        score_owner: 2,
        ..ConnectionState::default()
    }
}
fn setup() -> LiveState {
    let mut state = LiveState::new(Limits::default());
    for b in [
        batch(1, vec![life(Event::Begin)], Witness::default()),
        batch(2, vec![LiveEvent::GroupCreated(1)], Witness::default()),
        batch(
            3,
            vec![life(Event::Account { id: 2, group: 1 })],
            Witness {
                accounts: vec![account(0, &[])],
                ..Witness::default()
            },
        ),
    ] {
        assert_eq!(state.observe(&b).status, Status::Comparing);
    }
    state
}
#[test]
fn batch_witness_is_output_and_failure_keeps_previous_compared_sequence() {
    let reserve = batch(
        4,
        vec![
            life(Event::Open(3)),
            life(Event::Reserve {
                session: 3,
                operation: 1,
                account: 2,
            }),
        ],
        Witness {
            accounts: vec![account(1, &[])],
            session: 3,
            ..Witness::default()
        },
    );
    for fault in 0..3 {
        let mut state = setup();
        let mut changed = reserve.clone();
        match fault {
            0 => changed.witness.accounts[0].score = 0,
            1 => changed.witness.accounts.clear(),
            _ => changed.witness.after = connection(),
        }
        let progress = state.observe(&changed);
        assert_eq!(
            progress.status,
            Status::Invalid(InvalidReason::Witness),
            "LIVE_WITNESS"
        );
        assert_eq!(progress.compared_sequence, 3, "LIVE_BATCH_ATOMIC");
        assert_eq!(
            state
                .view(epoch(1))
                .unwrap_or_else(|| unreachable!("owner"))
                .accounts[0]
                .counts
                .score(),
            1,
            "witness must not repair the independent state"
        );
        assert_eq!(
            state.observe(&reserve).compared_sequence,
            3,
            "late valid data must not restore qualification"
        );
    }
    let mut state = setup();
    assert_eq!(state.observe(&reserve).compared_sequence, 5);
    let failed = batch(
        6,
        vec![life(Event::Created {
            session: 3,
            operation: 1,
            success: false,
        })],
        Witness {
            accounts: vec![account(0, &[])],
            session: 3,
            ..Witness::default()
        },
    );
    assert_eq!(state.observe(&failed).status, Status::Comparing);
    let done = batch(
        7,
        vec![LiveEvent::SelectionDone(3)],
        Witness {
            session: 3,
            ..Witness::default()
        },
    );
    assert_eq!(state.observe(&done).status, Status::Comparing);
    assert_eq!(
        state
            .view(epoch(1))
            .unwrap_or_else(|| unreachable!("owner"))
            .accounts[0]
            .counts
            .score(),
        0
    );
}
#[test]
fn unpaired_selection_cannot_refund_and_invalid_owner_never_recovers() {
    let mut state = setup();
    let reserve = batch(
        4,
        vec![
            life(Event::Open(3)),
            life(Event::Reserve {
                session: 3,
                operation: 1,
                account: 2,
            }),
        ],
        Witness {
            accounts: vec![account(1, &[])],
            session: 3,
            ..Witness::default()
        },
    );
    assert_eq!(state.observe(&reserve).status, Status::Comparing);
    assert_eq!(
        state
            .observe(&batch(
                6,
                vec![LiveEvent::SelectionDone(3)],
                Witness {
                    session: 3,
                    ..Witness::default()
                }
            ))
            .status,
        Status::Invalid(InvalidReason::Lifecycle),
        "LIVE_SELECTION_DISCARD"
    );
    assert_eq!(
        state
            .view(epoch(1))
            .unwrap_or_else(|| unreachable!("owner"))
            .accounts[0]
            .counts
            .score(),
        1
    );
    for event in [
        Event::Retire,
        Event::End,
        Event::Created {
            session: 3,
            operation: 1,
            success: false,
        },
    ] {
        assert!(matches!(
            state
                .observe(&batch(6, vec![life(event)], Witness::default()))
                .status,
            Status::Invalid(_)
        ));
    }
    assert_eq!(
        state
            .view(epoch(1))
            .unwrap_or_else(|| unreachable!("owner"))
            .accounts[0]
            .counts
            .score(),
        1
    );
    let mut fresh = batch(1, vec![life(Event::Begin)], Witness::default());
    fresh.epoch = epoch(2);
    assert_eq!(state.observe(&fresh).status, Status::Comparing);
    state.invalidate(epoch(1), InvalidReason::Transport);
    assert_eq!(state.progress(epoch(2)).status, Status::Comparing);
}
#[test]
fn reconnect_marker_never_changes_redirect_accounting_or_v1_pending_set() {
    let mut state = setup();
    for (sequence, session, order, pred) in [(4, 3, vec![3], 0), (5, 4, vec![3, 4], 3)] {
        assert_eq!(
            state
                .observe(&batch(
                    sequence,
                    vec![life(Event::Rehydrate {
                        session,
                        account: 2
                    })],
                    Witness {
                        accounts: vec![account(
                            i64::try_from(order.len()).unwrap_or(i64::MAX),
                            &order
                        )],
                        session,
                        predecessor: pred,
                        after: connection(),
                        ..Witness::default()
                    }
                ))
                .status,
            Status::Comparing
        );
    }
    let pending = ConnectionState {
        redirect_pending: true,
        ..connection()
    };
    assert_eq!(
        state
            .observe(&batch(
                6,
                vec![LiveEvent::Reconnect {
                    session: 3,
                    operation: 1,
                    account: 2,
                    accepted: false
                }],
                Witness {
                    accounts: vec![account(2, &[3, 4])],
                    session: 3,
                    before: connection(),
                    after: pending,
                    ..Witness::default()
                }
            ))
            .status,
        Status::Comparing
    );
    let view = state
        .view(epoch(1))
        .unwrap_or_else(|| unreachable!("owner"));
    assert!(
        view.pending_redirects.is_empty(),
        "LIVE_RECONNECT_NOT_REDIRECT"
    );
    assert_eq!(view.accounts[0].counts.incoming(), 0);
    assert_eq!(view.accounts[0].counts.outgoing(), 0);
    assert_eq!(
        state
            .observe(&batch(
                7,
                vec![LiveEvent::Lifecycle {
                    event: Event::Redirected {
                        session: 3,
                        operation: 1,
                        success: true
                    },
                    source: 2,
                    target: 2
                }],
                Witness {
                    accounts: vec![account(2, &[4, 3])],
                    session: 3,
                    predecessor: 4,
                    before: pending,
                    after: connection()
                }
            ))
            .status,
        Status::Comparing
    );
}
#[test]
fn omitted_group_history_replayed_nonce_and_batch_overflow_invalidate() {
    let mut state = setup();
    let mut wrong = batch(4, vec![life(Event::Watermark)], Witness::default());
    wrong.epoch.nonce = 44;
    assert_eq!(
        state.progress(wrong.epoch).status,
        Status::Invalid(InvalidReason::Identity),
        "LIVE_PROGRESS_IDENTITY"
    );
    assert_eq!(state.progress(wrong.epoch).compared_sequence, 3);
    assert_eq!(state.progress(epoch(1)).status, Status::Comparing);
    assert_eq!(
        state.observe(&wrong).status,
        Status::Invalid(InvalidReason::Identity)
    );
    let mut state = LiveState::new(Limits::default());
    assert_eq!(
        state
            .observe(&batch(1, vec![life(Event::Begin)], Witness::default()))
            .status,
        Status::Comparing
    );
    assert_eq!(
        state
            .observe(&batch(
                2,
                vec![life(Event::Account { id: 2, group: 1 })],
                Witness {
                    accounts: vec![account(0, &[])],
                    ..Witness::default()
                }
            ))
            .status,
        Status::Invalid(InvalidReason::Identity)
    );
    let mut state = setup();
    let b = batch(4, vec![life(Event::Watermark); 5], Witness::default());
    assert_eq!(
        state.observe(&b).status,
        Status::Invalid(InvalidReason::Capacity),
        "LIVE_BATCH_BOUND"
    );
    assert_eq!(state.progress(epoch(1)).compared_sequence, 3);
}
