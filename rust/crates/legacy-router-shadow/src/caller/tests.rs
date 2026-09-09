// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0
use super::*;
use control_router::shadow::live::native::{HISTORY_LIMIT, STAGE_OVERHEAD};

const BEGIN: &str =
    include_str!("../../../../../tests/controlplane/cproute/shadow/v4-pass-begin.json");
const END: &str = include_str!("../../../../../tests/controlplane/cproute/shadow/v4-pass-end.json");
pub(super) fn frame(body: &str) -> Vec<u8> {
    let mut value = u32::try_from(body.len())
        .unwrap_or_else(|_| unreachable!("valid fixture"))
        .to_be_bytes()
        .to_vec();
    value.extend_from_slice(body.as_bytes());
    value
}
#[test]
fn go_fixture_and_fixed_layout() {
    let decoded = decode(&frame(BEGIN), pass::Tracker::CHARGE)
        .unwrap_or_else(|_| unreachable!("valid fixture"));
    assert_eq!(
        decoded.epoch,
        Epoch {
            process: 1,
            owner: 1,
            nonce: 2
        }
    );
    assert_eq!(decoded.sequence, 2);
    assert_eq!(
        decoded.event,
        pass::Event::Begin(pass::Begin {
            pass: 1,
            support_redirection: false,
            groups: pass::Groups::new(&[9, 3]).unwrap_or_else(|_| unreachable!("valid fixture"))
        }),
        "PASS_GO_RUST_WIRE_FIXTURE"
    );
    assert_eq!(
        decode(&frame(END), 0)
            .unwrap_or_else(|_| unreachable!("valid fixture"))
            .event,
        pass::Event::End(pass::End {
            pass: 1,
            balanced: 0,
            closed: 2
        })
    );
    let small = frame(END).len().min(frame(BEGIN).len());
    // Both selected variants are fixed size. Decimal parsing temporaries fit
    // within 32F; all wire/domain/fixed-array overlap is below fixed S.
    assert!(
        size_of::<Wire>() + size_of::<pass::Boundary>() + 2 * size_of::<Groups>() < STAGE_OVERHEAD,
        "PASS_FIXED_DECODE_LAYOUT"
    );
    assert!(size_of::<Wire>() < 32 * small);
    eprintln!(
        "wire={} boundary={} groups={} retained={} min_frame={small}",
        size_of::<Wire>(),
        size_of::<pass::Boundary>(),
        size_of::<Groups>(),
        pass::Tracker::CHARGE
    );
}
#[test]
fn strict_keys_identity_and_canonical_scalars() {
    let bad = [
        BEGIN.replace(r#""version":4"#, r#""version":3"#),
        BEGIN.replace(r#""kind":"caller""#, r#""kind":"evaluation""#),
        BEGIN.replace(r#""owner":"1""#, r#""owner":"0""#),
        BEGIN.replace(r#""owner":"1""#, r#""owner":"01""#),
        BEGIN.replace(r#""sequence":"2""#, r#""sequence":2"#),
        BEGIN.replace(r#""span":"1""#, r#""span":"2""#),
        BEGIN.replace(r#""span":"1","#, ""),
        BEGIN.replace(r#""span":"1""#, r#""span":"1","span":"1""#),
        BEGIN.replace(r#""groups":["9","3"]"#, r#""groups":["9","3"],"closed":0"#),
        BEGIN.replace(r#""support_redirection":false,"#, ""),
        BEGIN.replace(
            r#""support_redirection":false"#,
            r#""support_redirection":false,"support_redirection":false"#,
        ),
        BEGIN.replace(r#""pass":"1""#, r#""pass":"0""#),
        BEGIN.replace(r#""pass_begin""#, r#""other""#),
        BEGIN.replace(r#""groups":["9","3"]"#, r#""groups":["9","9"]"#),
        BEGIN.replace(r#""groups":["9","3"]"#, r#""groups":["9","0"]"#),
        BEGIN.replace(r#""groups":["9","3"]"#, r#""groups":["9","03"]"#),
        END.replace(r#""closed":2"#, r#""closed":65"#),
        END.replace(r#""closed":2"#, r#""closed":2.0"#),
        END.replace(r#""closed":2"#, r#""closed":2,"groups":[]"#),
        END.replace(r#""closed":2"#, r#""closed":2,"closed":2"#),
        END.replace(r#""balanced":0,"#, ""),
        END.replace(r#""span":"1""#, r#""span":"1","children":[]"#),
        format!("{BEGIN}{END}"),
    ];
    for body in bad {
        assert!(
            decode(&frame(&body), 0).is_err(),
            "PASS_STRICT_SCHEMA: {body}"
        );
    }
    let double = BEGIN.replace(
        r#""groups":["9","3"]}}"#,
        r#""groups":["9","3"]},"pass_end":{"pass":"1","balanced":0,"closed":2}}"#,
    );
    assert!(
        decode(&frame(&double), 0).is_err(),
        "PASS_EXACTLY_ONE_VARIANT"
    );
}
#[test]
fn groups_and_counts_equal_plus_one() {
    for n in [64, 65] {
        let groups = (1..=n)
            .map(|n| format!("\"{n}\""))
            .collect::<Vec<_>>()
            .join(",");
        let body = BEGIN.replace(r#"["9","3"]"#, &format!("[{groups}]"));
        assert_eq!(
            decode(&frame(&body), 0).is_ok(),
            n == 64,
            "PASS_GROUP_BOUND"
        );
    }
    assert!(
        decode(&frame(&END.replace(r#""closed":2"#, r#""closed":64"#)), 0).is_ok(),
        "PASS_COUNT_EQUAL"
    );
}
#[test]
fn prefix_inclusive_size_and_admission_before_decode() {
    let mut body = BEGIN.to_owned();
    body.extend(std::iter::repeat_n(' ', MAX_CALLER_FRAME - 4 - body.len()));
    let equal = frame(&body);
    assert!(decode(&equal, 0).is_ok(), "PASS_PREFIX_EQUAL");
    body.push(' ');
    assert_eq!(
        decode(&frame(&body), 0),
        Err(Error::Oversized),
        "PASS_PREFIX_PLUS_ONE"
    );
    let mut truncated = equal.clone();
    truncated.pop();
    assert_eq!(decode(&truncated, 0), Err(Error::Framing));
    let mut forged = frame(BEGIN);
    forged[..4].copy_from_slice(
        &u32::try_from(MAX_CALLER_FRAME)
            .unwrap_or_else(|_| unreachable!("valid fixture"))
            .to_be_bytes(),
    );
    assert_eq!(decode(&forged, 0), Err(Error::Oversized));
    let retained = HISTORY_LIMIT - 32 * MAX_CALLER_FRAME - STAGE_OVERHEAD;
    assert_eq!(
        admission(MAX_CALLER_FRAME, retained)
            .unwrap_or_else(|_| unreachable!("valid fixture"))
            .peak,
        HISTORY_LIMIT,
        "PASS_COMBINED_BUDGET_EQUAL"
    );
    assert_eq!(
        admission(MAX_CALLER_FRAME, retained + 1),
        Err(Error::Capacity),
        "PASS_COMBINED_BUDGET_PLUS_ONE"
    );
    assert_eq!(
        decode(&frame("not json"), HISTORY_LIMIT),
        Err(Error::Capacity),
        "PASS_ADMISSION_BEFORE_PARSE"
    );
}

const ROUTE: &str =
    include_str!("../../../../../tests/controlplane/cproute/shadow/v4-group-route.json");
pub(super) fn origin() -> Origin {
    Origin::new(control_routing::go_time::SUPPORTED_GO_VERSION, false, 0)
        .unwrap_or_else(|| unreachable!("origin"))
}
fn route_frame(body: &str) -> route::Envelope {
    match decode_caller(&frame(body), Some(origin()), 0)
        .unwrap_or_else(|e| unreachable!("fixture {e:?}"))
    {
        Frame::GroupRoute(e) => e,
        Frame::Pass(_) | Frame::GroupBalance(_) => unreachable!("route fixture"),
    }
}
fn route_state(e: &route::Envelope) -> control_router::shadow::live::LiveState {
    use control_router::shadow::{
        Event, Status,
        live::{AccountWitness, Batch, LiveEvent, LiveState, Witness},
        native::{Coverage, Entry, GoArch},
    };
    let mut state = LiveState::new(control_router::shadow::Limits::default());
    state
        .install_native(Coverage {
            epoch: e.epoch,
            origin: origin(),
            go_arch: GoArch::Arm64,
            zero_time: control_routing::go_time::GoTime::new(0, 0, 1, None)
                .unwrap_or_else(|| unreachable!("time")),
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
            state
                .observe(&Batch {
                    epoch: e.epoch,
                    sequence,
                    events: vec![event],
                    witness: Witness::default()
                })
                .status,
            Status::Comparing
        );
    }
    let route::Child::Evaluation(native) = &e.children[0] else {
        unreachable!("native")
    };
    let mut config = native.as_ref().clone();
    config.sequence = 3;
    config.evaluation = 1;
    config.entry = Entry::Config;
    config.accounts.clear();
    config.reads.clear();
    config.sorted.clear();
    config.returned.clear();
    assert_eq!(
        state.observe_native(&config, 4096).status,
        Status::Comparing
    );
    assert_eq!(
        state
            .observe(&Batch {
                epoch: e.epoch,
                sequence: 4,
                events: vec![LiveEvent::Lifecycle {
                    event: Event::Account { id: 9, group: 2 },
                    source: 0,
                    target: 0
                }],
                witness: Witness {
                    accounts: vec![AccountWitness {
                        id: 9,
                        score: 0,
                        physical: 0,
                        head: 0,
                        tail: 0
                    }],
                    ..Witness::default()
                }
            })
            .status,
        Status::Comparing
    );
    state
}
#[test]
fn complete_go_nested_fixture_drives_atomic_domain_comparator() {
    use control_router::shadow::Status;
    let e = route_frame(ROUTE);
    assert_eq!(
        (e.sequence, e.span, e.route.members.as_slice()),
        (5, 4, &[9][..]),
        "ROUTE_WIRE_IDENTITY_SPAN"
    );
    let mut state = route_state(&e);
    let p = state.observe_group_route(&e, frame(ROUTE).len());
    assert_eq!(
        (p.status, p.compared_sequence),
        (Status::Comparing, 8),
        "ROUTE_GO_WIRE_DOMAIN_COMMIT"
    );
    assert_eq!(
        state.totals(e.epoch),
        Some((1, 0)),
        "ROUTE_GO_WIRE_RESERVATION"
    );
    assert!(
        decode_caller(&frame(ROUTE), None, 0).is_err(),
        "ROUTE_NESTED_ORIGIN_REQUIRED"
    );
    assert!(decode(&frame(ROUTE), 0).is_err(), "ROUTE_NOT_PASS_DIALECT");
    let mut late = e.clone();
    late.route.result.completed = 1;
    let mut state = route_state(&e);
    assert_eq!(
        state
            .observe_group_route(&late, frame(ROUTE).len())
            .compared_sequence,
        4,
        "ROUTE_GO_WIRE_LATE_FAILURE_ATOMIC"
    );
    assert_eq!(state.totals(e.epoch), Some((0, 0)));
}
#[test]
fn caller_nested_bodies_preserve_strict_v2_v3_allowlists() {
    let source: serde_json::Value =
        serde_json::from_str(ROUTE).unwrap_or_else(|_| unreachable!("json"));
    for fault in 0..20 {
        let mut value = source.clone();
        let r = &mut value["payload"]["group_route"];
        let children = &mut r["children"];
        match fault {
            0 => children[0]["evaluation"]["version"] = 2.into(),
            1 => children[0]["evaluation"]["owner"] = "99".into(),
            2 => children[0]["evaluation"]["sequence"] = "05".into(),
            3 => children[0]["evaluation"]["group"] = "99".into(),
            4 => children[0]["evaluation"]["extra"] = true.into(),
            5 => children[1]["batch"]["factors"] = true.into(),
            6 => children[1]["batch"]["events"][0]["target"] = "9".into(),
            7 => children[1]["batch"]["witness"]["accounts"][0]["score"] = "01".into(),
            8 => {
                children[1]["batch"]["witness"]
                    .as_object_mut()
                    .unwrap_or_else(|| unreachable!("object"))
                    .remove("before");
            }
            9 => children[1]["batch"]["sequence"] = "5".into(),
            10 => children[1]["batch"]["kind"] = "invalid".into(),
            11 => value["span"] = "5".into(),
            12 => r["members"] = serde_json::json!(["9", "9"]),
            13 => r["reads"][0]["healthy"]["completed"] = 256.into(),
            14 => r["reads"][0]["healthy"]["extra"] = false.into(),
            15 => r["reads"][0]["healthy"]["account"] = "0".into(),
            16 => {
                r["reads"] = serde_json::json!([{"backend_id":{"completed":0,"account":"9","value":"x".repeat(513)}}]);
            }
            17 => {
                let old = r["reads"][0].clone();
                r["reads"] = vec![old; 129].into();
            }
            18 => {
                let old = children[0].clone();
                children
                    .as_array_mut()
                    .unwrap_or_else(|| unreachable!("array"))
                    .push(old);
            }
            _ => r["excluded_count"] = 65.into(),
        }
        assert!(
            decode_caller(&frame(&value.to_string()), Some(origin()), 0).is_err(),
            "ROUTE_STRICT_NESTED_SCHEMA {fault}"
        );
    }
    for (from, to) in [
        (
            r#""excluded_count":0"#,
            r#""excluded_count":0,"excluded_count":0"#,
        ),
        (r#""entry":"route""#, r#""entry":"route","entry":"route""#),
        (
            r#""lifecycle_only":true"#,
            r#""lifecycle_only":true,"lifecycle_only":true"#,
        ),
        (
            r#""healthy":{"completed":0"#,
            r#""healthy":{"completed":0,"completed":0"#,
        ),
    ] {
        let bad = ROUTE.replace(from, to);
        assert_ne!(bad, ROUTE);
        assert!(
            decode_caller(&frame(&bad), Some(origin()), 0).is_err(),
            "ROUTE_DUPLICATE_KEYS {from}"
        );
    }
}

#[test]
fn nested_child_cross_product_and_decode_layout_are_bounded() {
    let base: serde_json::Value =
        serde_json::from_str(ROUTE).unwrap_or_else(|_| unreachable!("json"));
    for (evaluations, batches, valid) in [(4, 64, true), (5, 64, false), (4, 65, false)] {
        let mut value = base.clone();
        let r = &mut value["payload"]["group_route"];
        let native = r["children"][0].clone();
        let batch = r["children"][1].clone();
        let mut children = Vec::new();
        let mut next = 5;
        for _ in 0..evaluations {
            let mut n = native.clone();
            n["evaluation"]["sequence"] = next.to_string().into();
            children.push(n);
            next += 1;
        }
        for _ in 0..batches {
            let mut b = batch.clone();
            b["batch"]["sequence"] = next.to_string().into();
            let mut event = b["batch"]["events"][0].clone();
            event["kind"] = "watermark".into();
            event["session"] = "0".into();
            b["batch"]["events"] = vec![event; 4].into();
            children.push(b);
            next += 4;
        }
        r["children"] = children.into();
        r["result"]["completed"] = (evaluations + batches).into();
        value["span"] = (next - 5 + 1).to_string().into();
        let wire = frame(&value.to_string());
        assert_eq!(
            decode_caller(&wire, Some(origin()), 0).is_ok(),
            valid,
            "ROUTE_NESTED_CHILD_BOUNDS"
        );
        if valid {
            let Frame::GroupRoute(e) =
                decode_caller(&wire, Some(origin()), 0).unwrap_or_else(|_| unreachable!("bounded"))
            else {
                unreachable!("group")
            };
            assert_eq!(e.span, 261, "ROUTE_NESTED_FULL_SPAN");
            // Only a codec/ownership stress body: not a legal semantic Group.Route.
            assert!(
                size_of::<Wire>()
                    + size_of::<route::Envelope>()
                    + 68 * size_of::<route::Child>()
                    + 256 * size_of::<route::Read>()
                    + 2 * 64 * size_of::<u64>()
                    < STAGE_OVERHEAD,
                "ROUTE_FIXED_DECODE_TEMPORARIES"
            );
            eprintln!(
                "route_wire={} envelope={} child={} read={} full_child_frame={} decode32F={}",
                size_of::<Wire>(),
                size_of::<route::Envelope>(),
                size_of::<route::Child>(),
                size_of::<route::Read>(),
                wire.len(),
                32 * wire.len()
            );
        }
    }
    let mut body = ROUTE.to_owned();
    body.extend(std::iter::repeat_n(' ', MAX_CALLER_FRAME - 4 - body.len()));
    assert!(
        decode_caller(&frame(&body), Some(origin()), 0).is_ok(),
        "ROUTE_PREFIX_EQUAL"
    );
    body.push(' ');
    assert!(
        matches!(
            decode_caller(&frame(&body), Some(origin()), 0),
            Err(Error::Oversized)
        ),
        "ROUTE_PREFIX_PLUS_ONE"
    );
}
