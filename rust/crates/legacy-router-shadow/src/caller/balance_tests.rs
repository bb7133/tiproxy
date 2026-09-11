// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::{
    tests::{frame, origin},
    *,
};
use control_router::shadow::{
    Event, InvalidReason, Status,
    live::{AccountWitness, Batch, ConnectionState, LiveEvent, LiveState, Witness},
    native::{Coverage, Entry, GoArch},
};

const BALANCE: &str =
    include_str!("../../../../../tests/controlplane/cproute/shadow/v4-group-balance.json");
fn envelope(body: &str) -> balance::Envelope {
    match decode_caller(&frame(body), Some(origin()), 0)
        .unwrap_or_else(|e| unreachable!("fixture {e:?}"))
    {
        Frame::GroupBalance(e) => e,
        _ => unreachable!("balance fixture"),
    }
}
fn account(id: u64, count: u64, tail: u64) -> AccountWitness {
    AccountWitness {
        id,
        score: i64::try_from(count).unwrap_or_else(|_| unreachable!("small fixture")),
        physical: count,
        head: if count == 0 { 0 } else { 12 },
        tail,
    }
}
fn connection() -> ConnectionState {
    ConnectionState {
        present: true,
        physical: 9,
        score_owner: 9,
        ..ConnectionState::default()
    }
}
fn state(e: &balance::Envelope) -> LiveState {
    state_with_order(e, &[12, 10, 11, 13, 14])
}
fn state_with_order(e: &balance::Envelope, order: &[u64]) -> LiveState {
    let mut s = LiveState::new(control_router::shadow::Limits::default());
    s.install_native(Coverage {
        epoch: e.epoch,
        origin: origin(),
        go_arch: GoArch::Arm64,
        zero_time: control_routing::go_time::GoTime::new(0, 0, 1, None)
            .unwrap_or_else(|| unreachable!("zero")),
    })
    .unwrap_or_else(|_| unreachable!("coverage"));
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
            s.observe(&Batch {
                epoch: e.epoch,
                sequence,
                events: vec![event],
                witness: Witness::default()
            })
            .status,
            Status::Comparing,
            "BALANCE_CODEC_PREFIX"
        );
    }
    let mut config = e.evaluation.as_ref().clone();
    config.sequence = 3;
    config.evaluation = 1;
    config.entry = Entry::Config;
    config.accounts.clear();
    config.reads.clear();
    config.sorted.clear();
    config.returned.clear();
    config.advice.clear();
    config.from = -1;
    config.to = -1;
    config.reason = None;
    config.balance_count = 0;
    assert_eq!(
        s.observe_native(&config, 4096).status,
        Status::Comparing,
        "BALANCE_CODEC_CONFIG"
    );
    for (sequence, id) in [(4, 9), (5, 19)] {
        assert_eq!(
            s.observe(&Batch {
                epoch: e.epoch,
                sequence,
                events: vec![LiveEvent::Lifecycle {
                    event: Event::Account { id, group: 2 },
                    source: 0,
                    target: 0
                }],
                witness: Witness {
                    accounts: vec![account(id, 0, 0)],
                    ..Witness::default()
                }
            })
            .status,
            Status::Comparing,
            "BALANCE_CODEC_ACCOUNT"
        );
    }
    physical_prefix(&mut s, e, order);
    s
}

fn physical_prefix(s: &mut LiveState, e: &balance::Envelope, order: &[u64]) {
    for (i, &session) in order.iter().enumerate() {
        assert_eq!(
            s.observe(&Batch {
                epoch: e.epoch,
                sequence: 6 + i as u64,
                events: vec![LiveEvent::Lifecycle {
                    event: Event::Rehydrate {
                        session,
                        account: 9
                    },
                    source: 0,
                    target: 0
                }],
                witness: Witness {
                    session,
                    accounts: vec![account(9, i as u64 + 1, session)],
                    before: ConnectionState::default(),
                    after: connection(),
                    predecessor: if i == 0 { 0 } else { order[i - 1] }
                }
            })
            .status,
            Status::Comparing,
            "BALANCE_CODEC_PHYSICAL_PREFIX"
        );
    }
    assert_eq!(
        s.observe(&Batch {
            epoch: e.epoch,
            sequence: 6 + order.len() as u64,
            events: vec![LiveEvent::Lifecycle {
                event: Event::Closing {
                    session: 12,
                    operation: 1
                },
                source: 0,
                target: 0
            }],
            witness: Witness {
                session: 12,
                accounts: vec![account(
                    9,
                    order.len() as u64,
                    *order.last().unwrap_or_else(|| unreachable!("order"))
                )],
                before: connection(),
                after: ConnectionState {
                    closing: true,
                    ..connection()
                },
                predecessor: 0
            }
        })
        .status,
        Status::Comparing,
        "BALANCE_CODEC_SKIP_PREFIX"
    );
}

#[test]
fn go_balance_fixture_commits_native_ledger_and_final_sequence() {
    let e = envelope(BALANCE);
    let mut s = state(&e);
    let before = s.view(e.epoch);
    let p = s.observe_group_balance(&e, frame(BALANCE).len());
    assert_eq!(
        (p.status, p.compared_sequence),
        (Status::Comparing, 16),
        "BALANCE_GO_WIRE_DOMAIN_COMMIT"
    );
    assert_eq!(
        (e.sequence, e.span, e.visits.len(), e.contexts.len()),
        (12, 5, 4, 5),
        "BALANCE_CODEC_IDENTITY_AND_ORDER"
    );
    assert!(e.visits[0].redirect.is_none());
    assert_eq!(
        e.visits[1].redirect.as_ref().and_then(|r| r.callback),
        Some(false)
    );
    assert_eq!(e.visits[2].redirect.as_ref().and_then(|r| r.callback), None);
    assert_ne!(s.view(e.epoch), before, "BALANCE_CODEC_LEDGER_CHANGED");
    assert_eq!(s.totals(e.epoch), Some((5, 5)));
    let mut late = e.clone();
    late.accepted = 2;
    let mut s = state(&e);
    let before = s.view(e.epoch);
    let p = s.observe_group_balance(&late, frame(BALANCE).len());
    assert_eq!(
        (p.status, p.compared_sequence),
        (Status::Invalid(InvalidReason::Witness), 11),
        "BALANCE_CODEC_LATE_FAILURE_ATOMIC"
    );
    let mut expected = before.unwrap_or_else(|| unreachable!("ledger"));
    expected.status = Status::Invalid(InvalidReason::Witness);
    assert_eq!(
        s.view(e.epoch),
        Some(expected),
        "BALANCE_CODEC_LATE_LEDGER_ROLLBACK"
    );
    assert!(
        decode_caller(&frame(BALANCE), None, 0).is_err(),
        "BALANCE_CODEC_ORIGIN_REQUIRED"
    );
    assert!(
        decode(&frame(BALANCE), 0).is_err(),
        "BALANCE_CODEC_NOT_PASS"
    );
}

#[test]
fn balance_skip_and_quota_tapes_are_compared() {
    let base = envelope(BALANCE);
    for fault in ["skip-visit", "quota-overrun", "missing-quota-context"] {
        let mut e = base.clone();
        match fault {
            "skip-visit" => {
                e.visits.remove(0);
            }
            "quota-overrun" => e.visits.push(balance::Visit {
                session: 14,
                redirect: None,
            }),
            _ => {
                e.contexts.pop();
            }
        }
        let mut s = state(&base);
        let p = s.observe_group_balance(&e, frame(BALANCE).len());
        assert_eq!(
            p.status,
            Status::Invalid(InvalidReason::Witness),
            "BALANCE_CODEC_SCAN_TAPE {fault}"
        );
        assert_eq!(p.compared_sequence, 11, "BALANCE_CODEC_SCAN_ROLLBACK");
    }
}

#[test]
fn balance_nil_exit_has_no_extra_context_read() {
    let mut e = envelope(BALANCE);
    // Same Go wire values, with the original physical tail (session14) absent.
    // Reconstruct the shorter independent prefix and adjust its exact sequences.
    e.sequence -= 1;
    e.evaluation.sequence -= 1;
    e.evaluation.accounts[0].physical = 4;
    e.evaluation.accounts[0].score_count = 4;
    e.evaluation.accounts[0].parts[1] = 4;
    e.evaluation.accounts[0].packed = 4;
    e.contexts.pop();
    for visit in &mut e.visits {
        if let Some(r) = &mut visit.redirect {
            r.batch.sequence -= 1;
            r.batch.witness.accounts[0].physical = 4;
            r.batch.witness.accounts[0].tail = 13;
            r.batch.witness.accounts[0].score -= 1;
        }
    }
    let mut s = state_with_order(&e, &[12, 10, 11, 13]);
    assert_eq!(
        s.observe_group_balance(&e, frame(BALANCE).len()).status,
        Status::Comparing,
        "BALANCE_CODEC_NIL_CONTROL"
    );
    e.contexts.push(false);
    let mut s = state_with_order(&e, &[12, 10, 11, 13]);
    let p = s.observe_group_balance(&e, frame(BALANCE).len());
    assert_eq!(
        (p.status, p.compared_sequence),
        (Status::Invalid(InvalidReason::Witness), 10),
        "BALANCE_CODEC_NIL_NO_EXTRA_CONTEXT"
    );
}

#[test]
fn balance_nested_schema_rejects_foreign_bounds_and_missing_nullable_values() {
    let original: serde_json::Value =
        serde_json::from_str(BALANCE).unwrap_or_else(|_| unreachable!("json"));
    for fault in 0..24 {
        let mut v = original.clone();
        let b = &mut v["payload"]["group_balance"];
        match fault {
            0 => b["evaluation"]["owner"] = "99".into(),
            1 => b["evaluation"]["group"] = "99".into(),
            2 => b["evaluation"]["entry"] = "route".into(),
            3 => b["evaluation"]["sequence"] = "13".into(),
            4 => b["evaluation"]["extra"] = true.into(),
            5 => b["visits"][1]["redirect"]["batch"]["sequence"] = "12".into(),
            6 => b["visits"][1]["redirect"]["batch"]["owner"] = "99".into(),
            7 => b["visits"][1]["redirect"]["batch"]["factors"] = true.into(),
            8 => b["clock"]["now"][0] = "sample".into(),
            9 => b["clock"]["now"][2] = 1_000_000_000_u32.into(),
            10 => b["clock"]["from_keyspace"] = "x".repeat(513).into(),
            11 => b["contexts"] = vec![false; 66].into(),
            12 => b["visits"] = vec![b["visits"][0].clone(); 65].into(),
            13 => b["accepted"] = 65.into(),
            14 => b["members"] = serde_json::json!(["9", "9"]),
            15 => b["visits"][1]["session"] = "12".into(),
            16 => {
                b.as_object_mut()
                    .unwrap_or_else(|| unreachable!("object"))
                    .remove("clock");
            }
            17 => {
                b["visits"][0]
                    .as_object_mut()
                    .unwrap_or_else(|| unreachable!("object"))
                    .remove("redirect");
            }
            18 => {
                b["visits"][1]["redirect"]
                    .as_object_mut()
                    .unwrap_or_else(|| unreachable!("object"))
                    .remove("callback");
            }
            19 => b["visits"][1]["redirect"]["callback"] = 0.into(),
            20 => b["visits"][1]["redirect"]["extra"] = true.into(),
            21 => b["caller"] = "0".into(),
            22 => b["clock"]["now"][5] = "1".into(),
            _ => v["span"] = "6".into(),
        }
        assert!(
            decode_caller(&frame(&v.to_string()), Some(origin()), 0).is_err(),
            "BALANCE_CODEC_STRICT_SCHEMA {fault}"
        );
    }
    for (from, to) in [
        (r#""accepted":1"#, r#""accepted":1,"accepted":1"#),
        (
            r#""callback":false"#,
            r#""callback":false,"callback":false"#,
        ),
        (r#""redirect":null"#, r#""redirect":null,"redirect":null"#),
    ] {
        let bad = BALANCE.replace(from, to);
        assert_ne!(bad, BALANCE);
        assert!(
            decode_caller(&frame(&bad), Some(origin()), 0).is_err(),
            "BALANCE_CODEC_DUPLICATE_KEYS"
        );
    }
}

#[test]
fn balance_prefix_and_joint_read_limits_are_preserved() {
    let mut body = BALANCE.to_owned();
    body.extend(std::iter::repeat_n(' ', MAX_CALLER_FRAME - 4 - body.len()));
    assert!(
        decode_caller(&frame(&body), Some(origin()), 0).is_ok(),
        "BALANCE_CODEC_PREFIX_EQUAL"
    );
    body.push(' ');
    assert!(
        matches!(
            decode_caller(&frame(&body), Some(origin()), 0),
            Err(Error::Oversized)
        ),
        "BALANCE_CODEC_PREFIX_PLUS_ONE"
    );
    let original: serde_json::Value =
        serde_json::from_str(BALANCE).unwrap_or_else(|_| unreachable!("json"));
    for (contexts, valid) in [(33, true), (34, false)] {
        let mut v = original.clone();
        let b = &mut v["payload"]["group_balance"];
        let mut visits = Vec::new();
        for i in 0..31 {
            let mut visit = b["visits"][1].clone();
            visit["session"] = (100 + i).to_string().into();
            visit["redirect"]["batch"]["sequence"] = (13 + i).to_string().into();
            visits.push(visit);
        }
        b["visits"] = visits.into();
        b["contexts"] = vec![false; contexts].into();
        v["span"] = "33".into();
        assert_eq!(
            decode_caller(&frame(&v.to_string()), Some(origin()), 0).is_ok(),
            valid,
            "BALANCE_CODEC_READ_EQUAL_PLUS_ONE"
        );
    }
}

#[test]
fn zero_rate_go_fixture_rejects_an_extra_clock_after_decode() {
    const ZERO: &str =
        include_str!("../../../../../tests/controlplane/cproute/shadow/v4-group-balance-zero.json");
    for extra in [false, true] {
        let mut e = envelope(ZERO);
        let mut s = state(&e);
        assert_eq!(
            s.observe(&Batch {
                epoch: e.epoch,
                sequence: 12,
                events: vec![LiveEvent::Lifecycle {
                    event: Event::RemoveAccount(19),
                    source: 0,
                    target: 0
                }],
                witness: Witness {
                    accounts: vec![account(19, 0, 0)],
                    ..Witness::default()
                },
            })
            .status,
            Status::Comparing,
            "BALANCE_CODEC_ZERO_PREFIX"
        );
        if extra {
            e.clock = envelope(BALANCE).clock;
        }
        assert_eq!(
            s.observe_group_balance(&e, frame(ZERO).len()).status,
            if extra {
                Status::Invalid(InvalidReason::Witness)
            } else {
                Status::Comparing
            },
            "BALANCE_CODEC_ZERO_CLOCK"
        );
    }
}
