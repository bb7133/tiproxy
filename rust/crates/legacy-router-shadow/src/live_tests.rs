// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::live::{self, Frame};
use crate::Error;
const GOLDEN: &str = include_str!("../../../../tests/controlplane/cproute/shadow/v2-begin.json");
fn framed(body: &str) -> Vec<u8> {
    let mut frame = u32::try_from(body.len())
        .unwrap_or(u32::MAX)
        .to_be_bytes()
        .to_vec();
    frame.extend(body.as_bytes());
    frame
}
#[test]
fn live_go_golden_and_strict_schema() {
    let Frame::Batch(batch) =
        live::decode(&framed(GOLDEN)).unwrap_or_else(|error| unreachable!("{error}"))
    else {
        unreachable!("batch")
    };
    assert_eq!(batch.epoch.owner, 1);
    assert_eq!(batch.sequence, 1);
    for (from, to) in [
        ("\"factors\":false,", "\"extra\":0,\"factors\":false,"),
        ("\"kind\":\"begin\"", "\"kind\":\"begin\",\"extra\":0"),
        ("\"owner\":\"1\"", "\"owner\":\"1\",\"owner\":\"1\""),
        ("\"owner\":\"1\"", "\"owner\":1"),
        ("\"sequence\":\"1\"", "\"sequence\":\"01\""),
        ("\"factors\":false,", ""),
        ("\"factors\":false,", "\"unknown\":false,"),
        ("\"selection\":false", "\"selection\":true"),
        ("\"kind\":\"begin\"", "\"kind\":\"policy\""),
        ("\"accounts\":[]", "\"accounts\":null"),
        ("\"target\":\"0\"", "\"target\":\"1\""),
        ("\"present\":false", "\"present\":false,\"present\":false"),
    ] {
        assert!(
            live::decode(&framed(&GOLDEN.replacen(from, to, 1))).is_err(),
            "LIVE_STRICT_SCHEMA: {from} -> {to}"
        );
    }
    assert!(matches!(
        live::decode(&framed(&GOLDEN.replace("\"version\":2", "\"version\":1"))),
        Err(Error::Version)
    ));
    let mut frame = framed(GOLDEN);
    frame.pop();
    assert!(matches!(live::decode(&frame), Err(Error::Framing)));
    assert!(matches!(
        live::decode(&1_048_577_u32.to_be_bytes()),
        Err(Error::Oversized)
    ));
    let mut value: serde_json::Value =
        serde_json::from_str(GOLDEN).unwrap_or_else(|error| unreachable!("{error}"));
    let event = value["events"][0].clone();
    value["events"] = serde_json::json!([event, event, event, event, event]);
    assert!(live::decode(&framed(&value.to_string())).is_err());
}
