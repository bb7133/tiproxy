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

use std::fmt;

/// A typed failure while decoding untrusted `MySQL` wire bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// A fixed or declared field extends beyond the supplied bytes.
    UnexpectedEof {
        /// Field being decoded.
        field: &'static str,
        /// Byte offset where the field starts.
        offset: usize,
        /// Bytes required at that offset.
        needed: usize,
        /// Bytes still available.
        remaining: usize,
    },
    /// A NUL-terminated field has no terminator.
    MissingNul {
        /// Field being decoded.
        field: &'static str,
        /// Byte offset where the field starts.
        offset: usize,
    },
    /// A marker or fixed field contains an unsupported value.
    InvalidValue {
        /// Field being decoded.
        field: &'static str,
        /// Byte offset of the invalid value.
        offset: usize,
        /// Invalid byte value.
        value: u8,
    },
    /// A length-encoded integer uses a longer-than-needed representation.
    NonCanonicalLength {
        /// Byte offset of the length marker.
        offset: usize,
        /// Length marker (`0xfc`, `0xfd`, or `0xfe`).
        marker: u8,
        /// Decoded value.
        value: u64,
    },
    /// A wire length cannot be represented by the local address space.
    LengthOverflow {
        /// Field whose length overflowed.
        field: &'static str,
        /// Byte offset of the declared length.
        offset: usize,
        /// Declared wire value.
        value: u64,
    },
    /// A declared variable-length field is longer than the remaining input.
    LengthExceedsInput {
        /// Field whose payload is incomplete.
        field: &'static str,
        /// Byte offset of the field payload.
        offset: usize,
        /// Declared payload length.
        declared: usize,
        /// Available payload length.
        remaining: usize,
    },
    /// A length-encoded `NULL` appears where a concrete value is mandatory.
    UnexpectedNull {
        /// Field being decoded.
        field: &'static str,
        /// Byte offset of the NULL marker.
        offset: usize,
    },
    /// A packet carries a different command than the codec requires.
    UnexpectedCommand {
        /// Required command byte.
        expected: u8,
        /// Received command byte, or `None` for an empty command packet.
        actual: Option<u8>,
    },
    /// A command packet has a legal empty `MySQL` payload but no command byte.
    EmptyCommandPacket,
    /// A fixed-size structure contains extra bytes.
    TrailingBytes {
        /// Structure being decoded.
        field: &'static str,
        /// Offset where trailing bytes begin.
        offset: usize,
        /// Number of trailing bytes.
        remaining: usize,
    },
}

impl fmt::Display for DecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedEof {
                field,
                offset,
                needed,
                remaining,
            } => write!(
                formatter,
                "truncated {field} at offset {offset}: need {needed} bytes, have {remaining}"
            ),
            Self::MissingNul { field, offset } => {
                write!(
                    formatter,
                    "missing NUL terminator for {field} at offset {offset}"
                )
            }
            Self::InvalidValue {
                field,
                offset,
                value,
            } => write!(
                formatter,
                "invalid {field} value 0x{value:02x} at offset {offset}"
            ),
            Self::NonCanonicalLength {
                offset,
                marker,
                value,
            } => write!(
                formatter,
                "non-canonical length value {value} with marker 0x{marker:02x} at offset {offset}"
            ),
            Self::LengthOverflow {
                field,
                offset,
                value,
            } => write!(
                formatter,
                "{field} length {value} at offset {offset} does not fit this platform"
            ),
            Self::LengthExceedsInput {
                field,
                offset,
                declared,
                remaining,
            } => write!(
                formatter,
                "{field} at offset {offset} declares {declared} bytes, only {remaining} remain"
            ),
            Self::UnexpectedNull { field, offset } => {
                write!(formatter, "unexpected NULL {field} at offset {offset}")
            }
            Self::UnexpectedCommand { expected, actual } => match actual {
                Some(actual) => write!(
                    formatter,
                    "expected command 0x{expected:02x}, received 0x{actual:02x}"
                ),
                None => write!(
                    formatter,
                    "expected command 0x{expected:02x}, received an empty packet"
                ),
            },
            Self::EmptyCommandPacket => formatter.write_str("empty MySQL command packet"),
            Self::TrailingBytes {
                field,
                offset,
                remaining,
            } => write!(
                formatter,
                "{field} has {remaining} trailing bytes at offset {offset}"
            ),
        }
    }
}

impl std::error::Error for DecodeError {}

/// A typed failure while encoding `MySQL` wire bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncodeError {
    /// A numeric value exceeds the protocol field width.
    ValueOutOfRange {
        /// Field being encoded.
        field: &'static str,
        /// Supplied value.
        value: u64,
        /// Largest representable value.
        max: u64,
    },
    /// A host-size length cannot be represented in the protocol.
    LengthOverflow {
        /// Field being encoded.
        field: &'static str,
        /// Supplied host length.
        length: usize,
    },
    /// A NUL-terminated field contains an interior NUL byte.
    InteriorNul {
        /// Field being encoded.
        field: &'static str,
        /// Index of the first NUL byte.
        index: usize,
    },
    /// A fixed-size field has the wrong length.
    InvalidFieldLength {
        /// Field being encoded.
        field: &'static str,
        /// Supplied length.
        length: usize,
        /// Required length.
        expected: usize,
    },
    /// A required capability is absent for a requested optional field.
    MissingCapability {
        /// Field that requires the capability.
        field: &'static str,
        /// Required capability bit.
        capability: u32,
    },
}

impl fmt::Display for EncodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ValueOutOfRange { field, value, max } => {
                write!(formatter, "{field} value {value} exceeds maximum {max}")
            }
            Self::LengthOverflow { field, length } => {
                write!(formatter, "{field} length {length} cannot be encoded")
            }
            Self::InteriorNul { field, index } => {
                write!(formatter, "{field} contains NUL at index {index}")
            }
            Self::InvalidFieldLength {
                field,
                length,
                expected,
            } => write!(
                formatter,
                "{field} has length {length}, expected exactly {expected}"
            ),
            Self::MissingCapability { field, capability } => write!(
                formatter,
                "{field} requires capability bit 0x{capability:08x}"
            ),
        }
    }
}

impl std::error::Error for EncodeError {}
