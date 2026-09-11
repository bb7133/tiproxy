// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0
use super::super::{
    selection::{Binding, ErrorClass},
    tests::setup,
};
use super::*;
use crate::shadow::{Limits, Status};

fn begin(epoch: super::super::Epoch, sequence: u64) -> Boundary {
    Boundary {
        epoch,
        sequence,
        session: 10,
        event: BoundaryEvent::Begin {
            next: 1,
            current: 0,
            excluded: vec![],
        },
    }
}

#[test]
fn selector_retained_charge_and_late_failure_are_atomic() {
    let (mut state, e) = setup(Limits::default());
    let before = state.native_retained_bytes();
    assert_eq!(
        state
            .observe_selector_boundary(&begin(e.epoch, 5), 128)
            .status,
        Status::Comparing
    );
    assert_eq!(
        state.native_retained_bytes() - before,
        StoredSelection::CHARGE,
        "SELECTOR_STATE_RETAINED_CHARGE"
    );
    assert!(!state.selectors_settled(e.epoch));
    let retained = state.native_retained_bytes();
    let mut transaction = state
        .begin_caller(Scope {
            epoch: e.epoch,
            group: 2,
            sequence: 6,
            span: 1,
            sessions: &[10],
            frame_bytes: 128,
        })
        .unwrap_or_else(|e| unreachable!("stage {e:?}"));
    let derived = DerivedResult {
        backend: 9,
        error: ErrorClass::None,
        binding: Some(Binding {
            account: 9,
            group: 2,
            operation: 20,
        }),
    };
    assert!(transaction.selector_attempt(10, 1, 1, &[], derived).is_ok());
    assert_eq!(
        transaction
            .finish(Err(InvalidReason::Witness))
            .compared_sequence,
        5,
        "SELECTOR_STATE_LATE_ROLLBACK"
    );
    assert_eq!(state.native_retained_bytes(), retained);
    // Original open Next still has no attempt. A successful private update
    // must not escape simply because the failure occurred after it.
    let stored = state
        .selectors
        .get_mut(&(e.epoch, 10))
        .unwrap_or_else(|| unreachable!("selector"));
    assert!(
        stored.tracker.attempt(1, 1, &[], derived).is_ok(),
        "SELECTOR_STATE_PRIVATE_ATTEMPT"
    );
}

#[test]
fn selector_admission_counts_new_and_cloned_history_at_equality() {
    for extra in [0, 1] {
        let (mut state, e) = setup(Limits::default());
        let ledger = state.core.owners[&(41, 1)]
            .ledger
            .caller_clone_charge(0, &[10])
            .unwrap_or_else(|e| unreachable!("ledger {e:?}"));
        state.native_bytes = super::super::HISTORY_LIMIT
            - 32 * 128
            - ledger
            - StoredSelection::CHARGE
            - super::super::STAGE_OVERHEAD
            + extra;
        let before = state.native_retained_bytes();
        let progress = state.observe_selector_boundary(&begin(e.epoch, 5), 128);
        if extra == 0 {
            assert_eq!(
                progress.status,
                Status::Comparing,
                "SELECTOR_STATE_BUDGET_EQUAL"
            );
            let budget = state
                .caller_peak_budget()
                .unwrap_or_else(|| unreachable!("budget"));
            assert_eq!(budget.peak, super::super::HISTORY_LIMIT);
            assert_eq!(budget.clones, ledger + StoredSelection::CHARGE);
        } else {
            assert_eq!(
                progress.status,
                Status::Invalid(InvalidReason::Capacity),
                "SELECTOR_STATE_BUDGET_PLUS_ONE"
            );
            assert_eq!(progress.compared_sequence, 4);
            assert!(state.selectors.is_empty());
            assert_eq!(state.native_retained_bytes(), before);
        }
    }
}

#[test]
fn closed_empty_selector_is_retained_and_cannot_reopen() {
    let (mut state, e) = setup(Limits::default());
    let close = Boundary {
        epoch: e.epoch,
        sequence: 5,
        session: 10,
        event: BoundaryEvent::Close {
            next: 0,
            current: 0,
            excluded: vec![],
        },
    };
    assert_eq!(
        state.observe_selector_boundary(&close, 128).status,
        Status::Comparing
    );
    assert!(state.selectors_settled(e.epoch));
    assert_eq!(
        state
            .observe_selector_boundary(&begin(e.epoch, 6), 128)
            .status,
        Status::Invalid(InvalidReason::Lifecycle),
        "SELECTOR_STATE_CLOSED_REUSE"
    );
}
