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

use crate::{DecodeError, EncodeError};

/// Largest payload representable by a three-byte `MySQL` physical-packet length.
pub const MAX_PAYLOAD_LEN: u32 = (1 << 24) - 1;

/// A decoded `MySQL` length-encoded integer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LengthEncodedInt {
    /// The dedicated `0xfb` NULL marker.
    Null,
    /// A concrete unsigned value.
    Value(u64),
}

/// A checked cursor over an immutable caller-owned byte slice.
///
/// Returned subslices retain lifetime `'a` and point into the original input.
/// Advancing the cursor never allocates, copies, or indexes without a prior
/// bounds check.
#[derive(Debug, Clone)]
pub struct Cursor<'a> {
    input: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    /// Creates a cursor at byte zero.
    #[must_use]
    pub const fn new(input: &'a [u8]) -> Self {
        Self { input, position: 0 }
    }

    /// Returns the current byte offset.
    #[must_use]
    pub const fn position(&self) -> usize {
        self.position
    }

    /// Returns the number of unconsumed bytes.
    #[must_use]
    pub const fn remaining(&self) -> usize {
        self.input.len() - self.position
    }

    /// Returns whether the cursor consumed the entire input.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    /// Returns all unconsumed bytes without advancing.
    #[must_use]
    pub const fn remaining_bytes(&self) -> &'a [u8] {
        self.input.split_at(self.position).1
    }

    /// Borrows and advances over exactly `length` bytes.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::UnexpectedEof`] when fewer bytes remain.
    pub fn take(&mut self, length: usize, field: &'static str) -> Result<&'a [u8], DecodeError> {
        let remaining = self.remaining();
        if length > remaining {
            return Err(DecodeError::UnexpectedEof {
                field,
                offset: self.position,
                needed: length,
                remaining,
            });
        }
        let start = self.position;
        self.position += length;
        Ok(&self.input[start..self.position])
    }

    /// Decodes one byte.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::UnexpectedEof`] when no byte remains.
    pub fn read_u8(&mut self, field: &'static str) -> Result<u8, DecodeError> {
        Ok(self.take(1, field)?[0])
    }

    /// Decodes a little-endian 16-bit integer.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::UnexpectedEof`] when fewer than two bytes remain.
    pub fn read_u16_le(&mut self, field: &'static str) -> Result<u16, DecodeError> {
        let bytes = self.take(2, field)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    /// Decodes a little-endian unsigned three-byte integer.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::UnexpectedEof`] when fewer than three bytes remain.
    pub fn read_u24_le(&mut self, field: &'static str) -> Result<u32, DecodeError> {
        let bytes = self.take(3, field)?;
        Ok(u32::from(bytes[0]) | (u32::from(bytes[1]) << 8) | (u32::from(bytes[2]) << 16))
    }

    /// Decodes a little-endian 32-bit integer.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::UnexpectedEof`] when fewer than four bytes remain.
    pub fn read_u32_le(&mut self, field: &'static str) -> Result<u32, DecodeError> {
        let bytes = self.take(4, field)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    /// Decodes a little-endian 64-bit integer.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::UnexpectedEof`] when fewer than eight bytes remain.
    pub fn read_u64_le(&mut self, field: &'static str) -> Result<u64, DecodeError> {
        let bytes = self.take(8, field)?;
        Ok(u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    /// Borrows a NUL-terminated field without copying the bytes.
    ///
    /// The returned slice excludes the terminator.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::MissingNul`] when no terminator remains.
    pub fn read_nul_terminated(&mut self, field: &'static str) -> Result<&'a [u8], DecodeError> {
        let start = self.position;
        let Some(relative) = self.remaining_bytes().iter().position(|byte| *byte == 0) else {
            return Err(DecodeError::MissingNul {
                field,
                offset: start,
            });
        };
        let value = &self.input[start..start + relative];
        self.position = start + relative + 1;
        Ok(value)
    }

    /// Decodes a strict, canonical `MySQL` length-encoded integer.
    ///
    /// Unlike the legacy Go helper, this method rejects truncation, `0xff`, and
    /// longer-than-needed encodings with typed errors instead of indexing past
    /// the input or accepting ambiguous representations.
    ///
    /// # Errors
    ///
    /// Returns a [`DecodeError`] for truncated, undefined, or non-canonical input.
    pub fn read_length_encoded_int(&mut self) -> Result<LengthEncodedInt, DecodeError> {
        let marker_offset = self.position;
        let marker = self.read_u8("length-encoded integer marker")?;
        match marker {
            0xfb => Ok(LengthEncodedInt::Null),
            0xfc => {
                let value = u64::from(self.read_u16_le("length-encoded u16")?);
                if value <= 250 {
                    return Err(DecodeError::NonCanonicalLength {
                        offset: marker_offset,
                        marker,
                        value,
                    });
                }
                Ok(LengthEncodedInt::Value(value))
            }
            0xfd => {
                let value = u64::from(self.read_u24_le("length-encoded u24")?);
                if u16::try_from(value).is_ok() {
                    return Err(DecodeError::NonCanonicalLength {
                        offset: marker_offset,
                        marker,
                        value,
                    });
                }
                Ok(LengthEncodedInt::Value(value))
            }
            0xfe => {
                let value = self.read_u64_le("length-encoded u64")?;
                if value <= u64::from(MAX_PAYLOAD_LEN) {
                    return Err(DecodeError::NonCanonicalLength {
                        offset: marker_offset,
                        marker,
                        value,
                    });
                }
                Ok(LengthEncodedInt::Value(value))
            }
            0xff => Err(DecodeError::InvalidValue {
                field: "length-encoded integer marker",
                offset: marker_offset,
                value: marker,
            }),
            value => Ok(LengthEncodedInt::Value(u64::from(value))),
        }
    }

    /// Decodes a length-encoded byte string and borrows its payload.
    ///
    /// `Ok(None)` preserves the distinction between the `0xfb` NULL marker and
    /// a present zero-length string.
    ///
    /// # Errors
    ///
    /// Returns a [`DecodeError`] for an invalid length or incomplete payload.
    pub fn read_length_encoded_bytes(
        &mut self,
        field: &'static str,
    ) -> Result<Option<&'a [u8]>, DecodeError> {
        let length_offset = self.position;
        let length = match self.read_length_encoded_int()? {
            LengthEncodedInt::Null => return Ok(None),
            LengthEncodedInt::Value(value) => {
                usize::try_from(value).map_err(|_| DecodeError::LengthOverflow {
                    field,
                    offset: length_offset,
                    value,
                })?
            }
        };
        let remaining = self.remaining();
        if length > remaining {
            return Err(DecodeError::LengthExceedsInput {
                field,
                offset: self.position,
                declared: length,
                remaining,
            });
        }
        self.take(length, field).map(Some)
    }
}

/// Decodes one strict length-encoded integer and returns bytes consumed.
///
/// # Errors
///
/// Returns a [`DecodeError`] for truncated, undefined, or non-canonical input.
pub fn decode_length_encoded_int(input: &[u8]) -> Result<(LengthEncodedInt, usize), DecodeError> {
    let mut cursor = Cursor::new(input);
    let value = cursor.read_length_encoded_int()?;
    Ok((value, cursor.position()))
}

/// Decodes one length-encoded byte string and returns bytes consumed.
///
/// The returned payload borrows directly from `input`.
///
/// # Errors
///
/// Returns a [`DecodeError`] for an invalid length or incomplete payload.
pub fn decode_length_encoded_bytes(input: &[u8]) -> Result<(Option<&[u8]>, usize), DecodeError> {
    let mut cursor = Cursor::new(input);
    let value = cursor.read_length_encoded_bytes("length-encoded bytes")?;
    Ok((value, cursor.position()))
}

/// Encodes a value as a three-byte little-endian integer.
///
/// # Errors
///
/// Returns [`EncodeError::ValueOutOfRange`] above [`MAX_PAYLOAD_LEN`].
pub fn encode_u24_le(value: u32) -> Result<[u8; 3], EncodeError> {
    if value > MAX_PAYLOAD_LEN {
        return Err(EncodeError::ValueOutOfRange {
            field: "three-byte integer",
            value: u64::from(value),
            max: u64::from(MAX_PAYLOAD_LEN),
        });
    }
    let bytes = value.to_le_bytes();
    Ok([bytes[0], bytes[1], bytes[2]])
}

/// Returns the canonical encoded size of a concrete length-encoded integer.
#[must_use]
pub const fn length_encoded_int_size(value: u64) -> usize {
    match value {
        0..=250 => 1,
        251..=0xffff => 3,
        0x1_0000..=0xff_ffff => 4,
        _ => 9,
    }
}

/// Appends a canonical `MySQL` length-encoded integer.
pub fn encode_length_encoded_int(value: u64, output: &mut Vec<u8>) {
    match value {
        0..=250 => output.push(value.to_le_bytes()[0]),
        251..=0xffff => {
            output.push(0xfc);
            output.extend_from_slice(&value.to_le_bytes()[..2]);
        }
        0x1_0000..=0xff_ffff => {
            output.push(0xfd);
            output.extend_from_slice(&value.to_le_bytes()[..3]);
        }
        _ => {
            output.push(0xfe);
            output.extend_from_slice(&value.to_le_bytes());
        }
    }
}

/// Appends a canonical length-encoded byte string or NULL marker.
///
/// # Errors
///
/// Returns [`EncodeError::LengthOverflow`] if a host slice length does not fit
/// the protocol's 64-bit length field.
pub fn encode_length_encoded_bytes(
    value: Option<&[u8]>,
    output: &mut Vec<u8>,
) -> Result<(), EncodeError> {
    let Some(value) = value else {
        output.push(0xfb);
        return Ok(());
    };
    let length = u64::try_from(value.len()).map_err(|_| EncodeError::LengthOverflow {
        field: "length-encoded bytes",
        length: value.len(),
    })?;
    encode_length_encoded_int(length, output);
    output.extend_from_slice(value);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn length_encoded_boundaries_round_trip() {
        let values = [
            0,
            1,
            250,
            251,
            u64::from(u16::MAX),
            u64::from(u16::MAX) + 1,
            u64::from(MAX_PAYLOAD_LEN),
            u64::from(MAX_PAYLOAD_LEN) + 1,
            u64::MAX,
        ];
        for value in values {
            let mut encoded = Vec::new();
            encode_length_encoded_int(value, &mut encoded);
            let decoded = decode_length_encoded_int(&encoded);
            assert_eq!(decoded, Ok((LengthEncodedInt::Value(value), encoded.len())));
            assert_eq!(encoded.len(), length_encoded_int_size(value));
        }
    }

    #[test]
    fn property_length_encoded_round_trip() {
        let mut state = 0x4d59_5351_4c57_4952_u64;
        for _ in 0..20_000 {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let mut encoded = Vec::new();
            encode_length_encoded_int(state, &mut encoded);
            assert_eq!(
                decode_length_encoded_int(&encoded),
                Ok((LengthEncodedInt::Value(state), encoded.len()))
            );
        }
    }

    #[test]
    fn rejects_truncated_and_noncanonical_lengths() {
        for input in [
            &[0xfc][..],
            &[0xfc, 1][..],
            &[0xfd, 1, 2][..],
            &[0xfe, 0, 0, 0, 0, 0, 0, 0][..],
        ] {
            assert!(matches!(
                decode_length_encoded_int(input),
                Err(DecodeError::UnexpectedEof { .. })
            ));
        }
        for input in [
            &[0xfc, 250, 0][..],
            &[0xfd, 0xff, 0xff, 0][..],
            &[0xfe, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0][..],
        ] {
            assert!(matches!(
                decode_length_encoded_int(input),
                Err(DecodeError::NonCanonicalLength { .. })
            ));
        }
        assert!(matches!(
            decode_length_encoded_int(&[0xff]),
            Err(DecodeError::InvalidValue { .. })
        ));
    }

    #[test]
    fn bytes_preserve_null_empty_and_borrowing() -> Result<(), DecodeError> {
        assert_eq!(decode_length_encoded_bytes(&[0xfb]), Ok((None, 1)));
        assert_eq!(decode_length_encoded_bytes(&[0]), Ok((Some(&[][..]), 1)));

        let input = [3, b'a', b'b', b'c'];
        let (decoded, consumed) = decode_length_encoded_bytes(&input)?;
        assert_eq!(decoded, Some(&input[1..]));
        assert_eq!(consumed, input.len());
        Ok(())
    }

    #[test]
    fn three_byte_integer_bounds() {
        assert_eq!(encode_u24_le(0x00ab_cdef), Ok([0xef, 0xcd, 0xab]));
        assert!(matches!(
            encode_u24_le(MAX_PAYLOAD_LEN + 1),
            Err(EncodeError::ValueOutOfRange { .. })
        ));
    }
}
