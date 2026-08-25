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

use std::collections::BTreeSet;
use std::fmt;

use prost::Message;

use crate::CONTROL_PROTOCOL_V1;
use crate::v1::{ControlEnvelope, ErrorCode, Hello, HelloAck};

/// Default and hard v1 frame limit.
pub const DEFAULT_MAX_FRAME_BYTES: u32 = 1024 * 1024;

/// Codec or Hello negotiation failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameError {
    /// The record has no complete four-byte length prefix.
    TruncatedPrefix,
    /// The declared body is empty.
    EmptyFrame,
    /// The body exceeds the negotiated frame limit.
    Oversized {
        /// Declared or encoded body length.
        length: usize,
        /// Negotiated body limit.
        limit: u32,
    },
    /// The record length does not match its prefix.
    LengthMismatch {
        /// Declared body length.
        declared: usize,
        /// Available body length.
        actual: usize,
    },
    /// The protobuf body is malformed.
    Malformed(String),
    /// The peers have no protocol version in common.
    UnsupportedVersion,
    /// A required capability is missing at the peer.
    MissingCapability(u64),
}

impl fmt::Display for FrameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TruncatedPrefix => formatter.write_str("truncated frame prefix"),
            Self::EmptyFrame => formatter.write_str("empty control frame"),
            Self::Oversized { length, limit } => {
                write!(
                    formatter,
                    "control frame size {length} exceeds limit {limit}"
                )
            }
            Self::LengthMismatch { declared, actual } => write!(
                formatter,
                "control frame declares {declared} bytes but contains {actual}"
            ),
            Self::Malformed(error) => write!(formatter, "malformed control protobuf: {error}"),
            Self::UnsupportedVersion => formatter.write_str("no common control protocol version"),
            Self::MissingCapability(capability) => {
                write!(
                    formatter,
                    "peer is missing required capability {capability}"
                )
            }
        }
    }
}

impl std::error::Error for FrameError {}

/// Deterministically encodes an envelope with its big-endian length prefix.
///
/// # Errors
///
/// Returns [`FrameError::EmptyFrame`] for an empty protobuf or
/// [`FrameError::Oversized`] when the encoded body exceeds the negotiated
/// limit.
pub fn encode_frame(envelope: &ControlEnvelope, limit: u32) -> Result<Vec<u8>, FrameError> {
    let body = envelope.encode_to_vec();
    if body.is_empty() {
        return Err(FrameError::EmptyFrame);
    }
    let limit = normalized_limit(limit);
    if body.len() > limit as usize {
        return Err(FrameError::Oversized {
            length: body.len(),
            limit,
        });
    }
    let length = u32::try_from(body.len()).map_err(|_| FrameError::Oversized {
        length: body.len(),
        limit,
    })?;
    let mut frame = Vec::with_capacity(4 + body.len());
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(&body);
    Ok(frame)
}

/// Decodes exactly one length-prefixed envelope.
///
/// # Errors
///
/// Returns a [`FrameError`] when the prefix, size, exact record length, or
/// protobuf body is invalid.
pub fn decode_frame(frame: &[u8], limit: u32) -> Result<ControlEnvelope, FrameError> {
    let prefix: [u8; 4] = frame
        .get(..4)
        .ok_or(FrameError::TruncatedPrefix)?
        .try_into()
        .map_err(|_| FrameError::TruncatedPrefix)?;
    let declared = u32::from_be_bytes(prefix) as usize;
    if declared == 0 {
        return Err(FrameError::EmptyFrame);
    }
    let limit = normalized_limit(limit);
    if declared > limit as usize {
        return Err(FrameError::Oversized {
            length: declared,
            limit,
        });
    }
    let body = &frame[4..];
    if body.len() != declared {
        return Err(FrameError::LengthMismatch {
            declared,
            actual: body.len(),
        });
    }
    ControlEnvelope::decode(body).map_err(|error| FrameError::Malformed(error.to_string()))
}

/// Negotiates protocol v1 and the sorted intersection of peer capabilities.
///
/// # Errors
///
/// Returns [`FrameError::UnsupportedVersion`] when either peer lacks v1, or
/// [`FrameError::MissingCapability`] when the remote peer lacks a required
/// capability.
pub fn negotiate_hello(
    local: &Hello,
    remote: &Hello,
    required_remote_capabilities: &[u64],
    control_epoch: u64,
) -> Result<HelloAck, FrameError> {
    if !local
        .supported_versions
        .contains(&u32::from(CONTROL_PROTOCOL_V1))
        || !remote
            .supported_versions
            .contains(&u32::from(CONTROL_PROTOCOL_V1))
    {
        return Err(FrameError::UnsupportedVersion);
    }

    let remote_capabilities: BTreeSet<u64> = remote.capabilities.iter().copied().collect();
    for capability in required_remote_capabilities {
        if !remote_capabilities.contains(capability) {
            return Err(FrameError::MissingCapability(*capability));
        }
    }

    let local_capabilities: BTreeSet<u64> = local.capabilities.iter().copied().collect();
    let negotiated_capabilities = local_capabilities
        .intersection(&remote_capabilities)
        .copied()
        .collect();
    let local_limit = normalized_limit(local.max_frame_bytes);
    let remote_limit = normalized_limit(remote.max_frame_bytes);

    Ok(HelloAck {
        selected_version: u32::from(CONTROL_PROTOCOL_V1),
        negotiated_capabilities,
        max_frame_bytes: local_limit.min(remote_limit),
        control_epoch,
        rejection_code: ErrorCode::Ok.into(),
        rejection_detail: String::new(),
    })
}

fn normalized_limit(limit: u32) -> u32 {
    if limit == 0 {
        DEFAULT_MAX_FRAME_BYTES
    } else {
        limit.min(DEFAULT_MAX_FRAME_BYTES)
    }
}
