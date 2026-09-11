// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0
use super::tests::frame;
use super::*;
use control_router::shadow::live::caller::selection::ErrorClass;

const BEGIN: &str =
    include_str!("../../../../../tests/controlplane/cproute/shadow/v4-metadata-begin.json");
const BEGIN_ERROR: &str =
    include_str!("../../../../../tests/controlplane/cproute/shadow/v4-metadata-begin-error.json");
const ASSIGN: &str =
    include_str!("../../../../../tests/controlplane/cproute/shadow/v4-metadata-assign.json");
const ASSIGN_REMOVED: &str = include_str!(
    "../../../../../tests/controlplane/cproute/shadow/v4-metadata-assign-removed.json"
);
const REFRESH: &str =
    include_str!("../../../../../tests/controlplane/cproute/shadow/v4-metadata-refresh.json");
const REFRESH_PORT: &str =
    include_str!("../../../../../tests/controlplane/cproute/shadow/v4-metadata-refresh-port.json");
const END: &str =
    include_str!("../../../../../tests/controlplane/cproute/shadow/v4-metadata-end.json");

fn decode_metadata(body: &str) -> Result<metadata::Boundary, Error> {
    match decode_caller(&frame(body), None, 0)? {
        Frame::Metadata(boundary) => Ok(boundary),
        _ => Err(Error::Schema),
    }
}

#[test]
fn metadata_go_fixtures_decode_to_typed_boundaries() {
    let begin = decode_metadata(BEGIN).unwrap_or_else(|_| unreachable!("valid fixture"));
    assert_eq!(
        begin.epoch,
        Epoch {
            process: 1,
            owner: 1,
            nonce: 2
        }
    );
    assert_eq!(begin.sequence, 2);
    let metadata::Event::Begin(b) = begin.event else {
        unreachable!("begin fixture")
    };
    assert_eq!(b.generation, 3);
    assert_eq!(b.observer_error, ErrorClass::None);
    assert_eq!(b.rule, metadata::Rule::ClientCidr);
    assert_eq!(b.inputs.len(), 4, "METADATA_GO_RUST_WIRE_FIXTURE");
    assert_eq!(b.inputs[0].account, 7);
    assert!(b.inputs[0].held() && b.inputs[0].healthy && b.inputs[0].present);
    assert!(b.inputs[1].held() && !b.inputs[1].present && !b.inputs[1].healthy);
    assert!(
        !b.inputs[2].held() && b.inputs[2].account == 0,
        "METADATA_UNHELD_INPUT"
    );
    assert!(!b.inputs[3].support_redirection);

    let error = decode_metadata(BEGIN_ERROR).unwrap_or_else(|_| unreachable!("valid fixture"));
    let metadata::Event::Begin(b) = error.event else {
        unreachable!("begin-error fixture")
    };
    assert_eq!(
        b.observer_error,
        ErrorClass::NoBackend,
        "METADATA_EXACT_SENTINEL_CLASS"
    );
    assert_eq!(b.rule, metadata::Rule::Port);
    assert!(b.inputs.is_empty());

    let assign = decode_metadata(ASSIGN).unwrap_or_else(|_| unreachable!("valid fixture"));
    assert_eq!(
        assign.event,
        metadata::Event::Assign(metadata::Assign {
            generation: 3,
            index: 1,
            account: 9,
            group: 12,
            removed: false,
            created: true,
            values_read: true,
            values: vec!["10.0.0.0/8".to_string(), "192.168.1.0/24".to_string()],
        })
    );
    let removed = decode_metadata(ASSIGN_REMOVED).unwrap_or_else(|_| unreachable!("valid fixture"));
    assert_eq!(
        removed.event,
        metadata::Event::Assign(metadata::Assign {
            generation: 3,
            index: 2,
            account: 8,
            group: 0,
            removed: true,
            created: false,
            values_read: false,
            values: Vec::new(),
        })
    );
}

#[test]
fn metadata_refresh_and_end_fixtures_decode_to_typed_boundaries() {
    let refresh = decode_metadata(REFRESH).unwrap_or_else(|_| unreachable!("valid fixture"));
    assert_eq!(
        refresh.event,
        metadata::Event::Refresh(metadata::Refresh {
            generation: 3,
            group: 12,
            values_read: true,
            members: vec![
                metadata::Member {
                    account: 9,
                    values: vec!["10.0.0.0/8".to_string(), "192.168.1.0/24".to_string()],
                },
                metadata::Member {
                    account: 7,
                    values: vec!["10.0.0.0/8".to_string(), "bad-cidr".to_string()],
                },
            ],
            values: vec![
                "192.168.1.0/24".to_string(),
                "10.0.0.0/8".to_string(),
                "bad-cidr".to_string()
            ],
            parsed: false,
        })
    );
    let port = decode_metadata(REFRESH_PORT).unwrap_or_else(|_| unreachable!("valid fixture"));
    assert_eq!(
        port.event,
        metadata::Event::Refresh(metadata::Refresh {
            generation: 3,
            group: 12,
            values_read: false,
            members: Vec::new(),
            values: Vec::new(),
            parsed: true,
        })
    );

    let end = decode_metadata(END).unwrap_or_else(|_| unreachable!("valid fixture"));
    assert_eq!(
        end.event,
        metadata::Event::End(metadata::End {
            generation: 3,
            support_redirection: true,
            groups: 2,
            created: 1,
            removed: 0,
            refresh_failed: 1,
            conflicts: 0
        })
    );
}

#[test]
fn metadata_strict_schema_rejects_bad_shapes() {
    let reject = |body: String, marker: &str| {
        assert!(decode_metadata(&body).is_err(), "{marker}");
    };
    reject(
        BEGIN.replace(r#""generation":"3""#, r#""generation":"0""#),
        "METADATA_ZERO_GENERATION",
    );
    reject(
        BEGIN.replace(r#""observer_error":1"#, r#""observer_error":2"#),
        "METADATA_ERROR_WITH_INPUTS",
    );
    reject(
        BEGIN.replace(r#""observer_error":1"#, r#""observer_error":4"#),
        "METADATA_UNKNOWN_ERROR_CLASS",
    );
    reject(
        BEGIN.replace(r#""rule":2"#, r#""rule":5"#),
        "METADATA_UNKNOWN_RULE",
    );
    reject(
        BEGIN.replace(r#""account":"8""#, r#""account":"7""#),
        "METADATA_DUPLICATE_ACCOUNT",
    );
    reject(
        BEGIN.replace(
            r#""account":"0","healthy":false"#,
            r#""account":"0","healthy":true"#,
        ),
        "METADATA_UNHELD_HEALTHY",
    );
    reject(
        BEGIN.replace(
            r#""account":"8","healthy":false,"support_redirection":true,"present":false"#,
            r#""account":"8","healthy":true,"support_redirection":true,"present":false"#,
        ),
        "METADATA_DROPPED_HEALTHY",
    );
    reject(
        BEGIN.replace(r#""present":true}"#, r#""present":true,"extra":1}"#),
        "METADATA_UNKNOWN_FIELD",
    );
    reject(
        ASSIGN.replace(r#""removed":false"#, r#""removed":true"#),
        "METADATA_REMOVED_WITH_GROUP",
    );
    reject(
        ASSIGN.replace(r#""group":"12""#, r#""group":"0""#),
        "METADATA_CREATED_WITHOUT_GROUP",
    );
    reject(
        ASSIGN.replace(r#""values_read":true"#, r#""values_read":false"#),
        "METADATA_UNREAD_VALUES",
    );
    reject(
        ASSIGN_REMOVED.replace(r#""values_read":false"#, r#""values_read":true"#),
        "METADATA_REMOVED_READS_VALUES",
    );
    reject(
        ASSIGN.replace(r#""10.0.0.0/8""#, &format!("\"{}\"", "a".repeat(513))),
        "METADATA_VALUE_BYTES_PLUS_ONE",
    );
    reject(
        REFRESH_PORT.replace(r#""parsed":true"#, r#""parsed":false"#),
        "METADATA_UNREAD_REFRESH_FAILS",
    );
    reject(
        REFRESH.replace(r#""group":"12""#, r#""group":"0""#),
        "METADATA_REFRESH_WITHOUT_GROUP",
    );
    reject(
        REFRESH.replace(r#""account":"7""#, r#""account":"9""#),
        "METADATA_DUPLICATE_MEMBER",
    );
    reject(
        REFRESH.replace(r#""account":"7""#, r#""account":"0""#),
        "METADATA_ZERO_MEMBER",
    );
    reject(
        REFRESH_PORT.replace(
            r#""members":[]"#,
            r#""members":[{"account":"1","values":[]}]"#,
        ),
        "METADATA_UNREAD_REFRESH_MEMBER",
    );
    reject(
        END.replace(r#""groups":2"#, r#""groups":65"#),
        "METADATA_GROUPS_PLUS_ONE",
    );
    reject(
        BEGIN.replace(r#""span":"1""#, r#""span":"2""#),
        "METADATA_SPAN_ONE",
    );
    // The pass-only decoder must not accept metadata frames.
    assert!(decode(&frame(BEGIN), 0).is_err(), "METADATA_NOT_A_PASS");
}
