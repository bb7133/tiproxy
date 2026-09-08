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
use control_router::shadow::{Epoch, Event};

fn record() -> Observation {
    Observation {
        epoch: Epoch {
            process: u64::MAX,
            owner: 2,
            nonce: 3,
        },
        sequence: 1,
        event: Event::Begin,
    }
}
fn framed(body: &[u8]) -> Vec<u8> {
    let length = u32::try_from(body.len()).unwrap_or(u32::MAX);
    let mut frame = length.to_be_bytes().to_vec();
    frame.extend_from_slice(body);
    frame
}
fn padded(bytes: usize) -> Vec<u8> {
    let mut frame = encode(&record()).unwrap_or_default();
    frame.resize(bytes + 4, b' ');
    frame[..4].copy_from_slice(&u32::try_from(bytes).unwrap_or(u32::MAX).to_be_bytes());
    frame
}

#[test]
fn frame_hard_limit_and_truncation_are_checked_before_decode() {
    assert!(
        decode(&padded(MAX_FRAME_BYTES)).is_ok(),
        "SHADOW_FRAME_LIMIT"
    );
    assert!(
        matches!(decode(&padded(MAX_FRAME_BYTES + 1)), Err(Error::Oversized)),
        "SHADOW_FRAME_LIMIT"
    );
    assert!(matches!(
        decode(&u32::MAX.to_be_bytes()),
        Err(Error::Oversized)
    ));
    let mut frame = encode(&record()).unwrap_or_default();
    frame.pop();
    assert!(
        matches!(decode(&frame), Err(Error::Framing)),
        "SHADOW_FRAME_TRUNCATED"
    );
    assert!(matches!(decode(&[0, 0, 0]), Err(Error::Framing)));
}

#[test]
fn strict_schema_rejects_duplicates_unknown_fields_and_noncanonical_ids() {
    let base = r#"{"version":1,"process":"18446744073709551615","owner":"2","nonce":"3","sequence":"1","event":{"kind":"begin"}}"#;
    assert!(decode(&framed(base.as_bytes())).is_ok());
    for changed in [
        base.replace("\"version\":1", "\"version\":1,\"version\":1"),
        base.replace(
            "\"kind\":\"begin\"",
            "\"kind\":\"begin\",\"kind\":\"begin\"",
        ),
        base.replace("\"kind\":\"begin\"", "\"kind\":\"begin\",\"secret\":\"no\""),
        base.replace("\"owner\":\"2\"", "\"owner\":2"),
        base.replace("\"owner\":\"2\"", "\"owner\":\"02\""),
        base.replace("\"owner\":\"2\"", "\"owner\":\"+2\""),
        base.replace("18446744073709551615", "18446744073709551616"),
        base.replace("\"kind\":\"begin\"", "\"kind\":\"production_redirect\""),
    ] {
        assert_ne!(changed, base);
        assert!(
            matches!(decode(&framed(changed.as_bytes())), Err(Error::Schema)),
            "SHADOW_STRICT_SCHEMA: {changed}"
        );
    }
    let changed = base.replace("\"version\":1", "\"version\":2");
    assert!(matches!(
        decode(&framed(changed.as_bytes())),
        Err(Error::Version)
    ));
}

#[test]
fn record_budget_limit_plus_one_preserves_fifo_and_charge() {
    let mut inbox = Inbox::default();
    let frame = encode(&record()).unwrap_or_default();
    for _ in 0..MAX_QUEUED_RECORDS {
        assert_eq!(inbox.push(&frame), Ok(()), "SHADOW_BYTE_BOUND");
    }
    assert_eq!(inbox.len(), MAX_QUEUED_RECORDS);
    assert_eq!(
        inbox.push(&frame),
        Err(Error::Capacity),
        "SHADOW_RECORD_BOUND"
    );
    assert_eq!(inbox.queued_bytes(), frame.len() * MAX_QUEUED_RECORDS);
    for _ in 0..MAX_QUEUED_RECORDS {
        assert_eq!(inbox.pop().map(|o| o.epoch), Some(record().epoch));
    }
    assert!(inbox.is_empty());
    assert_eq!(inbox.queued_bytes(), 0);
    assert_eq!(inbox.push(&frame), Ok(()), "SHADOW_BYTE_BOUND");
}

#[test]
fn byte_budget_limit_plus_one_is_independent_of_record_budget() {
    let frame = padded(MAX_FRAME_BYTES - 4);
    assert_eq!(frame.len(), MAX_FRAME_BYTES);
    let mut inbox = Inbox::default();
    for _ in 0..64 {
        assert_eq!(inbox.push(&frame), Ok(()), "SHADOW_BYTE_BOUND");
    }
    assert_eq!(inbox.queued_bytes(), MAX_QUEUED_BYTES, "SHADOW_BYTE_BOUND");
    assert_eq!(
        inbox.push(&frame),
        Err(Error::Capacity),
        "SHADOW_BYTE_BOUND"
    );
    assert_eq!(inbox.len(), 64);
    assert!(inbox.pop().is_some());
    assert_eq!(inbox.push(&frame), Ok(()), "SHADOW_BYTE_BOUND");
    assert_eq!(inbox.queued_bytes(), MAX_QUEUED_BYTES);
}

#[test]
fn byte_budget_exactly_one_byte_over_limit_is_rejected() {
    let small = encode(&record()).unwrap_or_default();
    let full = padded(MAX_FRAME_BYTES - 4);
    let mut inbox = Inbox::default();
    for _ in 0..63 {
        assert_eq!(inbox.push(&full), Ok(()));
    }
    let last = padded(MAX_FRAME_BYTES - small.len() + 1 - 4);
    assert_eq!(inbox.push(&last), Ok(()));
    assert_eq!(inbox.queued_bytes() + small.len(), MAX_QUEUED_BYTES + 1);
    assert_eq!(
        inbox.push(&small),
        Err(Error::Capacity),
        "SHADOW_BYTE_LIMIT_PLUS_ONE"
    );
}
