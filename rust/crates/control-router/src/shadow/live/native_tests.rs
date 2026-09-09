// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::super::{AccountWitness, Batch, LiveEvent, Witness};
use super::*;
use crate::shadow::{
    Event, Limits,
    native::{Account, ClockSite, Configuration, Entry, Read},
};
use control_routing::go_time::{GoTime, Origin, SUPPORTED_GO_VERSION};
fn must<T>(value: Option<T>) -> T {
    value.unwrap_or_else(|| unreachable!("fixture"))
}
fn initial() -> (LiveState, Evaluation) {
    let epoch = Epoch {
        process: 41,
        owner: 1,
        nonce: 43,
    };
    let zero = must(GoTime::new(0, 0, 1, None));
    let coverage = Coverage {
        epoch,
        origin: must(Origin::new(SUPPORTED_GO_VERSION, false, 0)),
        zero_time: zero,
        go_arch: crate::shadow::native::GoArch::Arm64,
    };
    let mut state = LiveState::new(Limits::default());
    assert_eq!(state.install_native(coverage), Ok(()));
    for (sequence, event) in [
        (
            1,
            LiveEvent::Lifecycle {
                event: Event::Begin,
                source: 0,
                target: 0,
            },
        ),
        (2, LiveEvent::GroupCreated(2)),
    ] {
        assert_eq!(
            state
                .observe(&Batch {
                    epoch,
                    sequence,
                    events: vec![event],
                    witness: Witness::default()
                })
                .status,
            Status::Comparing
        );
    }
    let e = Evaluation {
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
    (state, e)
}
#[test]
fn bad_native_output_does_not_commit_history_or_prefix() {
    let (mut state, mut e) = initial();
    assert_eq!(state.observe_native(&e, 4096).compared_sequence, 3);
    let charge = state.native_retained_bytes();
    e.sequence = 4;
    e.evaluation = 2;
    e.entry = Entry::Route;
    e.reads.push(Read::Clock {
        site: ClockSite::CpuExpiry,
        ordinal: 0,
        time: must(GoTime::new(0, 0, 1, None)),
    });
    let bad = state.observe_native(&e, 4096);
    assert_eq!(
        bad.status,
        Status::Invalid(InvalidReason::Witness),
        "NATIVE_ATOMIC_INVALID"
    );
    assert_eq!(bad.compared_sequence, 3, "NATIVE_ATOMIC_PREFIX");
    assert_eq!(
        state.native_retained_bytes(),
        charge,
        "NATIVE_ATOMIC_HISTORY"
    );
    e.reads.clear();
    let mut history = state.native[&e.epoch].groups[&2].state.clone();
    assert_eq!(history.apply(&e), Ok(()), "NATIVE_ATOMIC_CONTENT");
    assert_eq!(state.observe_native(&e, 4096), bad, "NATIVE_NO_REPAIR");
}
#[test]
fn native_budget_includes_old_history_clone_and_stage_at_equality() {
    for extra in [1, 0] {
        let (mut state, mut e) = initial();
        assert_eq!(state.observe_native(&e, 4096).compared_sequence, 3);
        let retained = state.native[&e.epoch].groups[&2].charge;
        let incoming = 4096;
        state.native_bytes = HISTORY_LIMIT - retained - STAGE_OVERHEAD - incoming + extra;
        let before = state.native_bytes;
        e.sequence = 4;
        e.evaluation = 2;
        e.entry = Entry::Route;
        let progress = state.observe_native(&e, incoming);
        if extra == 0 {
            assert_eq!(progress.status, Status::Comparing, "NATIVE_HISTORY_EQUAL");
            assert_eq!(progress.compared_sequence, 4);
            assert_eq!(
                state.native_peak_bytes(),
                HISTORY_LIMIT,
                "NATIVE_PEAK_INCLUDES_CLONE"
            );
        } else {
            assert_eq!(
                progress.status,
                Status::Invalid(InvalidReason::Capacity),
                "NATIVE_HISTORY_PLUS_ONE"
            );
            assert_eq!(progress.compared_sequence, 3, "NATIVE_BUDGET_NO_PREFIX");
            assert_eq!(state.native_bytes, before, "NATIVE_BUDGET_NO_CLONE_COMMIT");
        }
    }
    let (state, _) = initial();
    let left = HISTORY_LIMIT - state.native_bytes;
    assert!(state.native_can_stage(left), "NATIVE_DECODE_EQUAL");
    assert!(!state.native_can_stage(left + 1), "NATIVE_DECODE_PLUS_ONE");
}
#[test]
fn missing_begin_cannot_be_repaired_by_late_native_prelude() {
    let (_, e) = initial();
    let mut state = LiveState::new(Limits::default());
    assert_eq!(
        state.observe_native(&e, 4096).status,
        Status::Invalid(InvalidReason::MissingBegin)
    );
    let p = state.observe(&Batch {
        epoch: e.epoch,
        sequence: 1,
        events: vec![LiveEvent::Lifecycle {
            event: Event::Begin,
            source: 0,
            target: 0,
        }],
        witness: Witness::default(),
    });
    assert!(
        matches!(p.status, Status::Invalid(_)),
        "NATIVE_LATE_BEGIN_NO_REPAIR"
    );
    assert_eq!(p.compared_sequence, 0);
}

#[test]
fn conflicting_native_preludes_are_sticky() {
    let (mut state, e) = initial();
    let mut coverage = must(state.native_coverage(e.epoch));
    coverage.epoch.owner = 2;
    coverage.go_arch = crate::shadow::native::GoArch::Amd64;
    assert_eq!(
        state.install_native(coverage),
        Err(InvalidReason::Identity),
        "NATIVE_ARCH_PROCESS_CONFLICT"
    );
    coverage.go_arch = crate::shadow::native::GoArch::Arm64;
    assert_eq!(
        state.install_native(coverage),
        Err(InvalidReason::Identity),
        "NATIVE_PRELUDE_NO_REPAIR"
    );
    assert!(matches!(
        state.progress(coverage.epoch).status,
        Status::Invalid(_)
    ));
    assert_eq!(
        state.install_native(must(state.native_coverage(e.epoch))),
        Err(InvalidReason::Identity),
        "NATIVE_DUPLICATE_PRELUDE"
    );
    assert_eq!(state.progress(e.epoch).compared_sequence, 2);
}

fn with_account() -> (LiveState, Evaluation) {
    let (mut state, mut e) = initial();
    assert_eq!(state.observe_native(&e, 4096).compared_sequence, 3);
    let p = state.observe(&Batch {
        epoch: e.epoch,
        sequence: 4,
        events: vec![LiveEvent::Lifecycle {
            event: Event::Account { id: 9, group: 2 },
            source: 0,
            target: 0,
        }],
        witness: Witness {
            accounts: vec![AccountWitness {
                id: 9,
                score: 0,
                physical: 0,
                head: 0,
                tail: 0,
            }],
            ..Witness::default()
        },
    });
    assert_eq!(p.status, Status::Comparing);
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
            time: must(GoTime::new(0, 0, 1, None)),
        });
    }
    (state, e)
}

#[test]
fn native_counts_and_membership_are_independent_of_consistent_factor_output() {
    let (mut state, e) = with_account();
    assert_eq!(
        state.observe_native(&e, 4096).compared_sequence,
        5,
        "NATIVE_LEDGER_BASELINE"
    );
    for fault in 0..3 {
        let (mut state, mut e) = with_account();
        match fault {
            0 => {
                e.accounts[0].score_count = 1;
                e.accounts[0].parts[1] = 1;
                e.accounts[0].packed = 1;
            }
            1 => e.accounts[0].physical = 1,
            _ => e.accounts[0].account = 99,
        }
        // The outputs remain internally consistent with the forged inputs.
        // Only the lifecycle ledger can disprove those inputs.
        let mut factors = state.native[&e.epoch].groups[&2].state.clone();
        assert_eq!(factors.apply(&e), Ok(()), "NATIVE_FORGED_FACTOR_CONSISTENT");
        let before = state.native_retained_bytes();
        let p = state.observe_native(&e, 4096);
        assert_eq!(
            p.status,
            Status::Invalid(if fault == 2 {
                InvalidReason::Identity
            } else {
                InvalidReason::Witness
            }),
            "NATIVE_LEDGER_INDEPENDENT"
        );
        assert_eq!(p.compared_sequence, 4, "NATIVE_LEDGER_PREFIX");
        assert_eq!(
            state.native_retained_bytes(),
            before,
            "NATIVE_LEDGER_HISTORY"
        );
    }
}

#[test]
fn native_score_cannot_hide_its_getter_presence_to_bypass_ledger() {
    let (mut state, mut e) = with_account();
    e.accounts[0].seen &= !8;
    e.accounts[0].score_count = 1;
    e.accounts[0].parts[1] = 1;
    e.accounts[0].packed = 1;
    let p = state.observe_native(&e, 4096);
    assert_eq!(
        p.status,
        Status::Invalid(InvalidReason::Witness),
        "NATIVE_SCORE_PRESENCE_REQUIRED"
    );
    assert_eq!(p.compared_sequence, 4);
}
