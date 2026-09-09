// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0
use super::*;
use control_router::shadow::live::native::{HISTORY_LIMIT, STAGE_OVERHEAD};

const BEGIN: &str =
    include_str!("../../../../../tests/controlplane/cproute/shadow/v4-pass-begin.json");
const END: &str = include_str!("../../../../../tests/controlplane/cproute/shadow/v4-pass-end.json");
fn frame(body: &str) -> Vec<u8> {
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
