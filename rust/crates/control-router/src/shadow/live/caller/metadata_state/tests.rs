// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::super::metadata::{Begin, End, Rule};
use super::super::selection::ErrorClass;
use super::*;
use crate::shadow::live::{LiveEvent, Witness};
use crate::shadow::native::{Coverage, GoArch};
use crate::shadow::{Epoch, Event as Life, Limits};
use control_routing::go_time::{GoTime, Origin, SUPPORTED_GO_VERSION};

fn initial() -> (LiveState, Epoch) {
    let epoch = Epoch {
        process: 41,
        owner: 1,
        nonce: 43,
    };
    let mut state = LiveState::new(Limits::default());
    assert!(
        state
            .install_native(Coverage {
                epoch,
                origin: Origin::new(SUPPORTED_GO_VERSION, false, 0)
                    .unwrap_or_else(|| unreachable!("origin")),
                zero_time: GoTime::new(0, 0, 1, None).unwrap_or_else(|| unreachable!("time")),
                go_arch: GoArch::Arm64,
            })
            .is_ok()
    );
    let batch = Batch {
        epoch,
        sequence: 1,
        events: vec![LiveEvent::Lifecycle {
            event: Life::Begin,
            source: 0,
            target: 0,
        }],
        witness: Witness::default(),
    };
    assert_eq!(state.observe(&batch).status, Status::Comparing);
    (state, epoch)
}

fn begin(epoch: Epoch) -> Boundary {
    Boundary {
        epoch,
        sequence: 2,
        event: Event::Begin(Begin {
            generation: 1,
            observer_error: ErrorClass::None,
            rule: Rule::All,
            inputs: vec![],
        }),
    }
}

fn end(epoch: Epoch) -> Boundary {
    Boundary {
        epoch,
        sequence: 3,
        event: Event::End(End {
            generation: 1,
            support_redirection: true,
            groups: 0,
            created: 0,
            removed: 0,
            refresh_failed: 0,
            conflicts: 0,
        }),
    }
}

#[test]
fn metadata_retention_is_shared_and_late_rejection_keeps_generation() {
    let (mut state, epoch) = initial();
    let before = state.native_retained_bytes();
    assert_eq!(
        state.observe_router_metadata(&begin(epoch), 128).status,
        Status::Comparing
    );
    let retained = state.native_retained_bytes();
    assert!(retained > before, "METADATA_LIVE_SHARED_RETENTION");
    assert_eq!(retained - before, state.metadata[&epoch].retained_charge());
    let boundary = end(epoch);
    let mut transaction = state
        .begin_caller(Scope {
            epoch,
            group: 0,
            sequence: 3,
            span: 1,
            sessions: &[],
            frame_bytes: 128,
        })
        .unwrap_or_else(|e| unreachable!("stage {e:?}"));
    assert!(transaction.compare_metadata(&boundary).is_ok());
    assert_eq!(
        transaction
            .metadata
            .as_ref()
            .map(|m| m.tracker.generation()),
        Some(1)
    );
    assert_eq!(
        transaction
            .finish(Err(InvalidReason::Witness))
            .compared_sequence,
        2,
        "METADATA_LIVE_LATE_PREFIX"
    );
    assert_eq!(
        state.router_metadata(epoch).map(Tracker::generation),
        Some(0),
        "METADATA_LIVE_LATE_STATE"
    );
    assert_eq!(
        state.native_retained_bytes(),
        retained,
        "METADATA_LIVE_LATE_CHARGE"
    );
}

#[test]
fn metadata_budget_equality_and_one_byte_overflow() {
    let (mut probe, epoch) = initial();
    let old = probe.native_retained_bytes();
    assert_eq!(
        probe.observe_router_metadata(&begin(epoch), 128).status,
        Status::Comparing
    );
    let needed = probe
        .caller_peak_budget()
        .unwrap_or_else(|| unreachable!("budget"))
        .peak
        - old;
    for extra in [0, 1] {
        let (mut state, epoch) = initial();
        state.native_bytes = super::super::HISTORY_LIMIT - needed + extra;
        let before = state.native_retained_bytes();
        let progress = state.observe_router_metadata(&begin(epoch), 128);
        if extra == 0 {
            assert_eq!(
                progress.status,
                Status::Comparing,
                "METADATA_LIVE_BUDGET_EQUAL"
            );
            assert_eq!(
                state.caller_peak_budget().map(|b| b.peak),
                Some(super::super::HISTORY_LIMIT)
            );
        } else {
            assert_eq!(
                progress.status,
                Status::Invalid(InvalidReason::Capacity),
                "METADATA_LIVE_BUDGET_PLUS_ONE"
            );
            assert_eq!(progress.compared_sequence, 1);
            assert!(state.router_metadata(epoch).is_none());
            assert_eq!(state.native_retained_bytes(), before);
        }
    }
}

#[test]
fn metadata_group_event_rejects_late_lifecycle_witness_without_retaining_it() {
    let (mut state, epoch) = initial();
    assert_eq!(
        state.observe_router_metadata(&begin(epoch), 128).status,
        Status::Comparing
    );
    let retained = state.native_retained_bytes();
    let batch = Batch {
        epoch,
        sequence: 3,
        events: vec![LiveEvent::GroupCreated(7)],
        witness: Witness {
            session: 99,
            ..Witness::default()
        },
    };
    let progress = state.observe_router_metadata_batch(&batch, 128);
    assert_eq!(progress.status, Status::Invalid(InvalidReason::Witness));
    assert_eq!(progress.compared_sequence, 2);
    assert_eq!(state.native_retained_bytes(), retained);
    assert!(
        state
            .metadata
            .get_mut(&epoch)
            .unwrap_or_else(|| unreachable!("metadata"))
            .tracker
            .native_init(7)
            .is_err(),
        "METADATA_LIVE_NO_CREATED_ESCAPE"
    );
}

#[test]
fn metadata_prefix_commit_checks_retained_limit_before_publication() {
    for excess in [0, 1, usize::MAX] {
        let (mut state, epoch) = initial();
        let stored = StoredMetadata::fork(None);
        let charge = stored.retained_charge();
        state.native_bytes = if excess == usize::MAX {
            usize::MAX
        } else {
            super::super::HISTORY_LIMIT - charge + excess
        };
        let before = state.native_bytes;
        let result = state.commit_metadata_prefix(epoch, stored);
        if excess == 0 {
            assert_eq!(result, Ok(()));
            assert_eq!(state.native_bytes, super::super::HISTORY_LIMIT);
            assert!(state.router_metadata(epoch).is_some());
        } else {
            assert_eq!(result, Err(InvalidReason::Capacity));
            assert_eq!(state.native_bytes, before);
            assert!(state.router_metadata(epoch).is_none());
        }
        assert_eq!(state.progress(epoch).compared_sequence, 1);
    }
}
