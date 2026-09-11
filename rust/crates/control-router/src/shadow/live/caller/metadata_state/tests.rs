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

fn startup(epoch: Epoch, raw: &str, rule: Rule) -> Boundary {
    Boundary {
        epoch,
        sequence: 2,
        event: Event::Init(super::super::metadata::Init {
            raw_rule: raw.into(),
            rule,
        }),
    }
}

#[test]
fn startup_rule_sequence_and_atomic_rejection() {
    for (raw, rule) in [
        ("", Rule::All),
        ("CLIENT_CIDR", Rule::ClientCidr),
        ("CLİENT_CİDR", Rule::ClientCidr),
        ("proxy_cidr", Rule::ProxyCidr),
        ("PORT", Rule::Port),
        (" port", Rule::All),
        ("port ", Rule::All),
        ("unknown", Rule::All),
    ] {
        let (mut state, epoch) = initial();
        assert_eq!(
            state
                .observe_router_metadata(&startup(epoch, raw, rule), 512)
                .status,
            Status::Comparing
        );
        let metadata = state
            .router_metadata(epoch)
            .unwrap_or_else(|| unreachable!("startup"));
        assert_eq!(
            metadata.route_header(0),
            Ok((rule, ErrorClass::None)),
            "STARTUP_RULE_DERIVATION"
        );
        assert!(!metadata.detector_present());
    }
    let (mut state, epoch) = initial();
    let retained = state.native_retained_bytes();
    let old = state.progress(epoch).compared_sequence;
    let bad = startup(epoch, "port", Rule::All);
    assert_eq!(
        state.observe_router_metadata(&bad, 512).status,
        Status::Invalid(InvalidReason::Witness),
        "STARTUP_INIT_WITNESS"
    );
    assert_eq!(state.progress(epoch).compared_sequence, old);
    assert_eq!(
        state.native_retained_bytes(),
        retained,
        "STARTUP_INIT_ATOMIC_BYTES"
    );
    assert!(
        state.router_metadata(epoch).is_none(),
        "STARTUP_INIT_ATOMIC_STATE"
    );
    let (mut state, epoch) = initial();
    let mut late = startup(epoch, "port", Rule::Port);
    late.sequence = 3;
    assert!(
        matches!(
            state.observe_router_metadata(&late, 512).status,
            Status::Invalid(_)
        ),
        "STARTUP_INIT_SEQUENCE_TWO"
    );
}

#[test]
fn startup_missing_duplicate_and_snapshot() {
    let mut tracker = Tracker::native();
    assert_eq!(
        tracker.route_header(0),
        Err(InvalidReason::MissingBegin),
        "STARTUP_REQUIRES_INIT"
    );
    let init = super::super::metadata::Init {
        raw_rule: "port".into(),
        rule: Rule::Port,
    };
    assert!(tracker.initialize(&init).is_ok());
    assert_eq!(
        tracker.initialize(&init),
        Err(InvalidReason::Lifecycle),
        "STARTUP_DUPLICATE_INIT"
    );
    let stored = StoredMetadata {
        tracker: Box::new(tracker),
    };
    let copied = StoredMetadata::fork(Some(&stored));
    assert_eq!(
        copied.tracker.route_header(0),
        Ok((Rule::Port, ErrorClass::None)),
        "STARTUP_SNAPSHOT_INITIALIZED"
    );
    assert_eq!(
        StoredMetadata::fork_charge(Some(&stored)),
        copied.retained_charge(),
        "STARTUP_SNAPSHOT_EXACT_CHARGE"
    );
}

#[test]
fn startup_health_fence_and_detector_history() {
    let mut tracker = Tracker::native();
    assert!(
        tracker
            .initialize(&super::super::metadata::Init {
                raw_rule: "port".into(),
                rule: Rule::Port
            })
            .is_ok()
    );
    for (generation, error) in [
        (1, ErrorClass::Other),
        (2, ErrorClass::None),
        (3, ErrorClass::Other),
    ] {
        let before = tracker.detector_present();
        assert!(
            tracker
                .begin(
                    Begin {
                        generation,
                        observer_error: error,
                        rule: Rule::Port,
                        inputs: vec![]
                    },
                    &mut |_| Ok(())
                )
                .is_ok()
        );
        assert_eq!(
            tracker.route_header(0),
            Err(InvalidReason::Sequence),
            "STARTUP_GEN0_AFTER_BEGIN"
        );
        assert!(
            tracker
                .end(
                    End {
                        generation,
                        support_redirection: generation >= 2,
                        groups: 0,
                        created: 0,
                        removed: 0,
                        refresh_failed: 0,
                        conflicts: 0
                    },
                    &mut |_| Ok(())
                )
                .is_ok()
        );
        let expected = if error == ErrorClass::None {
            true
        } else {
            before
        };
        assert_eq!(
            tracker.detector_present(),
            expected,
            "STARTUP_ERROR_DETECTOR_HISTORY"
        );
        let stored = StoredMetadata {
            tracker: Box::new(tracker),
        };
        let copy = StoredMetadata::fork(Some(&stored));
        assert_eq!(
            copy.tracker.detector_present(),
            expected,
            "STARTUP_SNAPSHOT_DETECTOR"
        );
        assert_eq!(
            copy.retained_charge(),
            StoredMetadata::fork_charge(Some(&stored))
        );
        tracker = *stored.tracker;
    }
}

#[test]
fn startup_budget_bounds_use_current_layout() {
    let (mut state, epoch) = initial();
    let before = state.native_retained_bytes();
    let scope = Scope {
        epoch,
        group: 0,
        sequence: 2,
        span: 1,
        sessions: &[],
        frame_bytes: 512,
    };
    let mut transaction = state
        .begin_caller(scope)
        .unwrap_or_else(|e| unreachable!("transaction {e:?}"));
    assert!(
        transaction
            .compare_metadata(&startup(epoch, "port", Rule::Port))
            .is_ok()
    );
    let charge = transaction
        .metadata
        .as_ref()
        .map_or(0, StoredMetadata::retained_charge);
    assert!(charge > size_of::<Tracker>());
    assert_eq!(
        transaction.metadata_commit_charge(super::super::HISTORY_LIMIT - charge),
        Ok(super::super::HISTORY_LIMIT),
        "STARTUP_HISTORY_EQUALITY"
    );
    assert_eq!(
        transaction.metadata_commit_charge(super::super::HISTORY_LIMIT - charge + 1),
        Err(InvalidReason::Capacity),
        "STARTUP_HISTORY_PLUS_ONE"
    );
    let progress = transaction.finish(Err(InvalidReason::Witness));
    assert_eq!(progress.compared_sequence, 1);
    assert_eq!(
        state.native_retained_bytes(),
        before,
        "STARTUP_STAGE_ROLLBACK_CHARGE"
    );
    assert!(state.router_metadata(epoch).is_none());
}
