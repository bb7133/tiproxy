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

//! Cross-language golden and boundary coverage for control protocol v1.

use std::fs;
use std::path::PathBuf;

use control_proto::v1::control_envelope::Body;
use control_proto::v1::{ControlEnvelope, Hello, Priority, ProtocolError};
use control_proto::{
    DEFAULT_MAX_FRAME_BYTES, FrameError, decode_frame, encode_frame, negotiate_hello,
};
use prost::Message;

fn fixture(name: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let repository = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..");
    Ok(fs::read(
        repository.join("proto/dataplane/v1/testdata").join(name),
    )?)
}

#[test]
fn rust_decodes_go_golden_and_reencodes_identically() -> Result<(), Box<dyn std::error::Error>> {
    let golden = fixture("go-hello.frame")?;
    let envelope = decode_frame(&golden, DEFAULT_MAX_FRAME_BYTES)?;
    assert_eq!(envelope.control_epoch, 41);
    let Some(Body::Hello(hello)) = &envelope.body else {
        return Err("Go golden did not contain Hello".into());
    };
    assert_eq!(hello.process_id, "go-control-golden");
    let encoded = encode_frame(&envelope, DEFAULT_MAX_FRAME_BYTES)?;
    assert_eq!(encoded, golden);
    Ok(())
}

#[test]
fn frame_limits_empty_fields_unknown_data_and_max_enum_are_safe()
-> Result<(), Box<dyn std::error::Error>> {
    let envelope = ControlEnvelope {
        protocol_version: 1,
        priority: i32::MAX,
        body: Some(Body::Error(ProtocolError {
            code: 22,
            offending_request_id: 0,
            retryable: false,
            detail: "x".repeat(64 * 1024),
        })),
        ..Default::default()
    };
    let body_len = envelope.encoded_len();
    let body_limit = u32::try_from(body_len)?;
    let frame = encode_frame(&envelope, body_limit)?;
    assert!(matches!(
        encode_frame(&envelope, u32::try_from(body_len - 1)?),
        Err(FrameError::Oversized { .. })
    ));
    let decoded = decode_frame(&frame, body_limit)?;
    assert_eq!(decoded.priority, i32::MAX);

    let empty_fields = ControlEnvelope {
        protocol_version: 1,
        ..Default::default()
    };
    let empty_frame = encode_frame(&empty_fields, DEFAULT_MAX_FRAME_BYTES)?;
    assert!(decode_frame(&empty_frame, DEFAULT_MAX_FRAME_BYTES).is_ok());

    let mut unknown = fixture("go-hello.frame")?;
    let mut body = unknown[4..].to_vec();
    body.extend_from_slice(&[0xd8, 0x07, 0x4d]);
    let length = u32::try_from(body.len())?;
    unknown[..4].copy_from_slice(&length.to_be_bytes());
    unknown.truncate(4);
    unknown.extend_from_slice(&body);
    assert!(decode_frame(&unknown, DEFAULT_MAX_FRAME_BYTES).is_ok());

    let oversized = (DEFAULT_MAX_FRAME_BYTES + 1).to_be_bytes();
    assert!(matches!(
        decode_frame(&oversized, DEFAULT_MAX_FRAME_BYTES),
        Err(FrameError::Oversized { .. })
    ));
    Ok(())
}

#[test]
fn required_capability_and_version_negotiation_fail_closed()
-> Result<(), Box<dyn std::error::Error>> {
    let local = Hello {
        supported_versions: vec![1],
        capabilities: vec![1, 3],
        max_frame_bytes: DEFAULT_MAX_FRAME_BYTES,
        ..Default::default()
    };
    let remote = Hello {
        supported_versions: vec![1],
        capabilities: vec![3, 5],
        max_frame_bytes: 64 * 1024,
        ..Default::default()
    };
    let ack = negotiate_hello(&local, &remote, &[3], 9)?;
    assert_eq!(ack.negotiated_capabilities, vec![3]);
    assert_eq!(ack.max_frame_bytes, 64 * 1024);
    assert!(matches!(
        negotiate_hello(&local, &remote, &[7], 9),
        Err(FrameError::MissingCapability(7))
    ));
    let incompatible = Hello {
        supported_versions: vec![2],
        ..Default::default()
    };
    assert!(matches!(
        negotiate_hello(&local, &incompatible, &[], 9),
        Err(FrameError::UnsupportedVersion)
    ));
    Ok(())
}

#[test]
fn rust_golden_is_self_consistent() -> Result<(), Box<dyn std::error::Error>> {
    let golden = fixture("rust-snapshot.frame")?;
    let envelope = decode_frame(&golden, DEFAULT_MAX_FRAME_BYTES)?;
    assert_eq!(envelope.generation, 11);
    assert_eq!(envelope.priority, Priority::Control as i32);
    let encoded = encode_frame(&envelope, DEFAULT_MAX_FRAME_BYTES)?;
    assert_eq!(encoded, golden);
    Ok(())
}
