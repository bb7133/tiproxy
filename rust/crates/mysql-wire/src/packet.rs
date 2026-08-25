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

use crate::{CommandCode, Cursor, DecodeError, EncodeError, MAX_PAYLOAD_LEN, encode_u24_le};

/// Size of a `MySQL` physical-packet header.
pub const PHYSICAL_PACKET_HEADER_LEN: usize = 4;

/// Returns the number of physical packets required for one logical payload.
///
/// The count always includes a final packet shorter than [`MAX_PAYLOAD_LEN`].
/// Consequently an empty logical payload is one empty physical packet, and an
/// exact multiple of the maximum ends with an additional empty packet.
#[must_use]
pub const fn physical_packet_count(logical_payload_length: u64) -> u64 {
    logical_payload_length / MAX_PAYLOAD_LEN as u64 + 1
}

/// Allocation-free physical-fragment plan for one logical `MySQL` payload.
///
/// This iterator yields only payload lengths. Sequence assignment belongs to
/// the directional reader or writer because source and destination sequences
/// are independent while a proxy forwards a message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogicalPacketFragments {
    remaining: u64,
    emit_terminator: bool,
    finished: bool,
}

impl LogicalPacketFragments {
    /// Creates a fragment plan for `logical_payload_length` bytes.
    #[must_use]
    pub const fn new(logical_payload_length: u64) -> Self {
        Self {
            remaining: logical_payload_length,
            emit_terminator: logical_payload_length % MAX_PAYLOAD_LEN as u64 == 0,
            finished: false,
        }
    }

    /// Returns the logical payload bytes not yet assigned to a fragment.
    #[must_use]
    pub const fn remaining_payload(&self) -> u64 {
        self.remaining
    }
}

impl Iterator for LogicalPacketFragments {
    type Item = u32;

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }
        if self.remaining > 0 {
            let length = if self.remaining >= u64::from(MAX_PAYLOAD_LEN) {
                MAX_PAYLOAD_LEN
            } else {
                // This branch is strictly below the 24-bit packet maximum.
                u32::try_from(self.remaining).unwrap_or(MAX_PAYLOAD_LEN)
            };
            self.remaining -= u64::from(length);
            if self.remaining == 0 && length < MAX_PAYLOAD_LEN {
                self.finished = true;
            }
            return Some(length);
        }
        if self.emit_terminator {
            self.emit_terminator = false;
            self.finished = true;
            return Some(0);
        }
        self.finished = true;
        None
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining_fragments = if self.finished {
            0
        } else {
            physical_packet_count(self.remaining)
        };
        match usize::try_from(remaining_fragments) {
            Ok(remaining_fragments) => (remaining_fragments, Some(remaining_fragments)),
            Err(_) => (usize::MAX, None),
        }
    }
}

/// The three-byte payload length and one-byte sequence of a physical packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketHeader {
    payload_length: u32,
    sequence_id: u8,
}

impl PacketHeader {
    /// Creates a validated packet header.
    ///
    /// # Errors
    ///
    /// Returns [`EncodeError::ValueOutOfRange`] if `payload_length` exceeds
    /// the protocol's 24-bit maximum.
    pub fn new(payload_length: u32, sequence_id: u8) -> Result<Self, EncodeError> {
        if payload_length > MAX_PAYLOAD_LEN {
            return Err(EncodeError::ValueOutOfRange {
                field: "physical packet payload",
                value: u64::from(payload_length),
                max: u64::from(MAX_PAYLOAD_LEN),
            });
        }
        Ok(Self {
            payload_length,
            sequence_id,
        })
    }

    /// Decodes the first four bytes of `input` as a header.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::UnexpectedEof`] for an incomplete header.
    pub fn decode(input: &[u8]) -> Result<Self, DecodeError> {
        let mut cursor = Cursor::new(input);
        let payload_length = cursor.read_u24_le("physical packet payload length")?;
        let sequence_id = cursor.read_u8("physical packet sequence")?;
        Ok(Self {
            payload_length,
            sequence_id,
        })
    }

    /// Encodes the four-byte header.
    #[must_use]
    pub fn encode(self) -> [u8; PHYSICAL_PACKET_HEADER_LEN] {
        let length = self.payload_length.to_le_bytes();
        [length[0], length[1], length[2], self.sequence_id]
    }

    /// Returns the decoded payload length.
    #[must_use]
    pub const fn payload_length(self) -> u32 {
        self.payload_length
    }

    /// Returns the physical-packet sequence byte.
    #[must_use]
    pub const fn sequence_id(self) -> u8 {
        self.sequence_id
    }
}

/// A validated physical packet borrowing both its raw frame and payload.
///
/// `raw()` points at the exact header-plus-payload bytes supplied by the caller;
/// `payload()` is a subslice of the same allocation. The decoder never copies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PhysicalPacket<'a> {
    header: PacketHeader,
    raw: &'a [u8],
    payload: &'a [u8],
}

impl<'a> PhysicalPacket<'a> {
    /// Decodes the first complete physical packet and returns any following bytes.
    ///
    /// # Errors
    ///
    /// Returns a typed truncation or declared-length error instead of indexing
    /// beyond hostile input.
    pub fn decode(input: &'a [u8]) -> Result<(Self, &'a [u8]), DecodeError> {
        let header = PacketHeader::decode(input)?;
        let declared =
            usize::try_from(header.payload_length).map_err(|_| DecodeError::LengthOverflow {
                field: "physical packet payload",
                offset: 0,
                value: u64::from(header.payload_length),
            })?;
        let payload_offset = PHYSICAL_PACKET_HEADER_LEN;
        let available = input.len().saturating_sub(payload_offset);
        if declared > available {
            return Err(DecodeError::LengthExceedsInput {
                field: "physical packet payload",
                offset: payload_offset,
                declared,
                remaining: available,
            });
        }
        let frame_length = payload_offset + declared;
        let raw = &input[..frame_length];
        let payload = &input[payload_offset..frame_length];
        Ok((
            Self {
                header,
                raw,
                payload,
            },
            &input[frame_length..],
        ))
    }

    /// Returns the decoded header.
    #[must_use]
    pub const fn header(self) -> PacketHeader {
        self.header
    }

    /// Returns the exact header-plus-payload input bytes.
    #[must_use]
    pub const fn raw(self) -> &'a [u8] {
        self.raw
    }

    /// Returns the borrowed packet payload.
    #[must_use]
    pub const fn payload(self) -> &'a [u8] {
        self.payload
    }
}

/// Appends one complete physical packet to `output`.
///
/// # Errors
///
/// Returns a typed length error instead of truncating payloads above 24 bits.
pub fn encode_physical_packet(
    payload: &[u8],
    sequence_id: u8,
    output: &mut Vec<u8>,
) -> Result<(), EncodeError> {
    let payload_length = u32::try_from(payload.len()).map_err(|_| EncodeError::LengthOverflow {
        field: "physical packet payload",
        length: payload.len(),
    })?;
    let length = encode_u24_le(payload_length)?;
    output.extend_from_slice(&length);
    output.push(sequence_id);
    output.extend_from_slice(payload);
    Ok(())
}

/// A command payload borrowing the command-specific bytes after byte zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommandPacket<'a> {
    /// Raw command byte wrapped without discarding unknown extensions.
    pub command: CommandCode,
    /// Command-specific bytes after the command byte.
    pub data: &'a [u8],
    /// Exact command payload supplied by the caller.
    pub raw: &'a [u8],
}

impl<'a> CommandPacket<'a> {
    /// Decodes a command payload without allocating.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::EmptyCommandPacket`] when a legal empty physical
    /// packet is used where a command byte is required.
    pub fn decode(payload: &'a [u8]) -> Result<Self, DecodeError> {
        let Some((&command, data)) = payload.split_first() else {
            return Err(DecodeError::EmptyCommandPacket);
        };
        Ok(Self {
            command: CommandCode::from_byte(command),
            data,
            raw: payload,
        })
    }
}

/// Encodes a command byte followed by command-specific bytes.
#[must_use]
pub fn encode_command_packet(command: CommandCode, data: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(1_usize.saturating_add(data.len()));
    output.push(command.as_byte());
    output.extend_from_slice(data);
    output
}

/// The result of observing an incoming physical-packet sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SequenceObservation {
    /// Sequence expected before the packet arrived.
    pub expected: u8,
    /// Sequence received from the peer.
    pub received: u8,
    /// Sequence expected after accepting this packet.
    pub next: u8,
}

impl SequenceObservation {
    /// Returns whether the peer's sequence differed from the local expectation.
    #[must_use]
    pub const fn mismatched(self) -> bool {
        self.expected != self.received
    }
}

/// Per-direction `MySQL` physical-packet sequence tracking.
///
/// Incoming mismatches intentionally match the current Go `TiProxy` behavior:
/// the caller receives an observable mismatch, while the tracker accepts the
/// packet and resynchronizes to `received + 1`. Logging remains an owner-layer
/// responsibility so this runtime-independent crate does not choose a logger.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SequenceTracker {
    expected: u8,
}

impl SequenceTracker {
    /// Creates a tracker with the supplied next expected sequence.
    #[must_use]
    pub const fn new(expected: u8) -> Self {
        Self { expected }
    }

    /// Returns the next expected sequence.
    #[must_use]
    pub const fn expected(self) -> u8 {
        self.expected
    }

    /// Observes an incoming sequence and resynchronizes with wrapping arithmetic.
    pub fn observe(&mut self, received: u8) -> SequenceObservation {
        let observation = SequenceObservation {
            expected: self.expected,
            received,
            next: received.wrapping_add(1),
        };
        self.expected = observation.next;
        observation
    }

    /// Returns the sequence for the next outgoing packet and advances it.
    pub fn take_next(&mut self) -> u8 {
        let current = self.expected;
        self.expected = self.expected.wrapping_add(1);
        current
    }

    /// Resets the next expected sequence, normally to zero at a command boundary.
    pub const fn reset(&mut self, expected: u8) {
        self.expected = expected;
    }
}

#[cfg(test)]
mod tests {
    use std::mem::size_of;

    use super::*;

    #[test]
    fn property_packet_header_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        let mut state = 0x5041_434b_4554_u64;
        for _ in 0..20_000 {
            state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            let state_bytes = state.to_le_bytes();
            let length = u32::from_le_bytes([
                state_bytes[0],
                state_bytes[1],
                state_bytes[2],
                state_bytes[3],
            ]) & MAX_PAYLOAD_LEN;
            let sequence = state_bytes[4];
            let header = PacketHeader::new(length, sequence)?;
            assert_eq!(PacketHeader::decode(&header.encode())?, header);
        }
        Ok(())
    }

    #[test]
    fn logical_fragment_boundaries_include_exact_multiple_terminator() {
        let maximum = u64::from(MAX_PAYLOAD_LEN);
        let cases: &[(u64, &[u32])] = &[
            (0, &[0]),
            (1, &[1]),
            (maximum - 1, &[MAX_PAYLOAD_LEN - 1]),
            (maximum, &[MAX_PAYLOAD_LEN, 0]),
            (maximum + 1, &[MAX_PAYLOAD_LEN, 1]),
            (maximum * 2, &[MAX_PAYLOAD_LEN, MAX_PAYLOAD_LEN, 0]),
        ];
        for (logical_length, expected) in cases {
            assert_eq!(
                LogicalPacketFragments::new(*logical_length).collect::<Vec<_>>(),
                *expected
            );
            assert_eq!(
                physical_packet_count(*logical_length),
                u64::try_from(expected.len()).unwrap_or(u64::MAX)
            );
        }
    }

    #[test]
    fn synthetic_gib_fragment_plan_is_constant_space() {
        let logical_length = 1_u64 << 30;
        let fragments = LogicalPacketFragments::new(logical_length);
        assert_eq!(
            fragments.clone().map(u64::from).sum::<u64>(),
            logical_length
        );
        assert_eq!(
            u64::try_from(fragments.count()).unwrap_or(u64::MAX),
            physical_packet_count(logical_length)
        );
        assert!(size_of::<LogicalPacketFragments>() <= 32);
    }

    #[test]
    fn physical_packet_borrows_and_returns_tail() -> Result<(), DecodeError> {
        let input = [3, 0, 0, 9, b'a', b'b', b'c', 0xee];
        let (packet, tail) = PhysicalPacket::decode(&input)?;
        assert_eq!(packet.payload(), &input[4..7]);
        assert_eq!(packet.raw(), &input[..7]);
        assert_eq!(tail, &input[7..]);
        assert_eq!(packet.header().sequence_id(), 9);
        Ok(())
    }

    #[test]
    fn empty_payload_is_valid() -> Result<(), DecodeError> {
        let input = [0, 0, 0, 3];
        let (packet, tail) = PhysicalPacket::decode(&input)?;
        assert!(packet.payload().is_empty());
        assert!(tail.is_empty());
        Ok(())
    }

    #[test]
    fn truncated_header_and_payload_are_typed() {
        for length in 0..PHYSICAL_PACKET_HEADER_LEN {
            assert!(matches!(
                PhysicalPacket::decode(&[0, 0, 0, 0][..length]),
                Err(DecodeError::UnexpectedEof { .. })
            ));
        }
        assert!(matches!(
            PhysicalPacket::decode(&[4, 0, 0, 0, 1, 2]),
            Err(DecodeError::LengthExceedsInput { .. })
        ));
    }

    #[test]
    fn sequence_mismatch_resynchronizes_and_wraps() {
        let mut tracker = SequenceTracker::new(0);
        let mismatch = tracker.observe(7);
        assert!(mismatch.mismatched());
        assert_eq!(mismatch.next, 8);
        assert_eq!(tracker.expected(), 8);

        tracker.reset(u8::MAX);
        assert_eq!(tracker.take_next(), u8::MAX);
        assert_eq!(tracker.expected(), 0);
        assert!(!tracker.observe(0).mismatched());
    }

    #[test]
    fn command_packet_preserves_unknown_codes_and_rejects_empty() {
        let payload = [0x80, 1, 2, 3];
        let decoded = CommandPacket::decode(&payload);
        assert_eq!(
            decoded,
            Ok(CommandPacket {
                command: CommandCode::from_byte(0x80),
                data: &payload[1..],
                raw: &payload,
            })
        );
        assert_eq!(
            encode_command_packet(CommandCode::QUERY, b"SELECT 1"),
            b"\x03SELECT 1"
        );
        assert_eq!(
            CommandPacket::decode(&[]),
            Err(DecodeError::EmptyCommandPacket)
        );
    }
}
