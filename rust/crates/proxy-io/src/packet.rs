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

use std::io;
use std::num::NonZeroUsize;

use mysql_wire::{
    EncodeError, LogicalPacketFragments, MAX_PAYLOAD_LEN, PHYSICAL_PACKET_HEADER_LEN, PacketHeader,
    SequenceObservation, SequenceTracker,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{IoSide, PacketIoError};

const PEEK_BYTES: usize = PHYSICAL_PACKET_HEADER_LEN + 1;

/// Default payload-copy buffer used by streaming packet operations.
pub const DEFAULT_STREAM_BUFFER_SIZE: usize = 32 * 1024;

/// Non-consuming view of the next physical packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketPreview {
    /// First payload byte, or `None` for an empty physical packet.
    pub first_byte: Option<u8>,
    /// Payload length from the next physical header.
    pub first_packet_length: u32,
    /// Sequence from the next physical header.
    pub sequence_id: u8,
}

/// Bounded capture and accounting state for one logical packet forward.
///
/// A cancellable forward may return at a physical-packet boundary with this
/// value still incomplete. Pass the same value back to resume so accounting
/// and prefix capture continue without duplicating bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardProgress {
    capture_limit: usize,
    captured_prefix: Vec<u8>,
    logical_payload_bytes: u64,
    physical_packets: u64,
    first_packet_length: Option<u32>,
    first_byte: Option<u8>,
    sequence_mismatches: u64,
    first_sequence_mismatch: Option<SequenceObservation>,
    complete: bool,
}

impl ForwardProgress {
    /// Creates empty progress with at most `capture_limit` retained payload bytes.
    #[must_use]
    pub const fn new(capture_limit: usize) -> Self {
        Self {
            capture_limit,
            captured_prefix: Vec::new(),
            logical_payload_bytes: 0,
            physical_packets: 0,
            first_packet_length: None,
            first_byte: None,
            sequence_mismatches: 0,
            first_sequence_mismatch: None,
            complete: false,
        }
    }

    /// Returns the configured prefix-capture limit.
    #[must_use]
    pub const fn capture_limit(&self) -> usize {
        self.capture_limit
    }

    /// Returns the retained logical-payload prefix.
    #[must_use]
    pub fn captured_prefix(&self) -> &[u8] {
        &self.captured_prefix
    }

    /// Returns whether payload bytes beyond a nonzero capture limit were omitted.
    #[must_use]
    pub fn capture_truncated(&self) -> bool {
        self.capture_limit > 0
            && self.logical_payload_bytes
                > u64::try_from(self.captured_prefix.len()).unwrap_or(u64::MAX)
    }

    /// Returns total logical payload bytes forwarded so far.
    #[must_use]
    pub const fn logical_payload_bytes(&self) -> u64 {
        self.logical_payload_bytes
    }

    /// Returns complete physical packets forwarded so far.
    #[must_use]
    pub const fn physical_packets(&self) -> u64 {
        self.physical_packets
    }

    /// Returns the first physical payload length once its header was consumed.
    #[must_use]
    pub const fn first_packet_length(&self) -> Option<u32> {
        self.first_packet_length
    }

    /// Returns the logical payload's first byte, or `None` for an empty payload.
    #[must_use]
    pub const fn first_byte(&self) -> Option<u8> {
        self.first_byte
    }

    /// Returns the number of source sequence mismatches observed.
    #[must_use]
    pub const fn sequence_mismatches(&self) -> u64 {
        self.sequence_mismatches
    }

    /// Returns the first source sequence mismatch for bounded diagnostics.
    #[must_use]
    pub const fn first_sequence_mismatch(&self) -> Option<SequenceObservation> {
        self.first_sequence_mismatch
    }

    /// Returns whether the terminating short physical packet was forwarded.
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.complete
    }

    fn observe_header(
        &mut self,
        header: PacketHeader,
        sequence: SequenceObservation,
    ) -> Result<(), PacketIoError> {
        if self.first_packet_length.is_none() {
            self.first_packet_length = Some(header.payload_length());
        }
        if sequence.mismatched() {
            self.sequence_mismatches =
                self.sequence_mismatches
                    .checked_add(1)
                    .ok_or(PacketIoError::CounterOverflow {
                        field: "source sequence mismatch",
                    })?;
            if self.first_sequence_mismatch.is_none() {
                self.first_sequence_mismatch = Some(sequence);
            }
        }
        Ok(())
    }

    fn observe_payload(&mut self, payload: &[u8]) -> Result<(), PacketIoError> {
        if self.first_byte.is_none() {
            self.first_byte = payload.first().copied();
        }
        self.logical_payload_bytes = self
            .logical_payload_bytes
            .checked_add(u64::try_from(payload.len()).map_err(|_| {
                PacketIoError::CounterOverflow {
                    field: "logical payload bytes",
                }
            })?)
            .ok_or(PacketIoError::CounterOverflow {
                field: "logical payload bytes",
            })?;
        let remaining_capture = self
            .capture_limit
            .saturating_sub(self.captured_prefix.len());
        let capture_length = remaining_capture.min(payload.len());
        self.captured_prefix
            .extend_from_slice(&payload[..capture_length]);
        Ok(())
    }

    fn finish_physical_packet(&mut self, payload_length: u32) -> Result<(), PacketIoError> {
        self.physical_packets =
            self.physical_packets
                .checked_add(1)
                .ok_or(PacketIoError::CounterOverflow {
                    field: "forwarded physical packets",
                })?;
        self.complete = payload_length < MAX_PAYLOAD_LEN;
        Ok(())
    }
}

/// Result of a cancellation-aware logical-packet forward attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForwardStatus {
    /// The terminating physical packet was forwarded.
    Complete,
    /// Cancellation was requested before the next physical header was consumed.
    CancelledAtPacketBoundary,
}

/// Decision made from a non-consuming packet preview in [`PacketReader::forward_until`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForwardUntilDecision {
    /// Forward this logical packet and inspect the next one.
    Continue,
    /// Forward this logical packet, capture at most the supplied prefix, and stop.
    Stop {
        /// Maximum payload prefix retained from the terminating logical packet.
        capture_limit: usize,
    },
}

/// Completed result from forwarding logical packets until a caller-selected end.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardUntilResult {
    /// Number of complete logical packets forwarded, including the final packet.
    pub logical_packets: u64,
    /// Capture and sequence observations for the final logical packet.
    pub final_packet: ForwardProgress,
}

/// Result of cancellation-aware forwarding across logical packets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForwardUntilStatus {
    /// The predicate selected and forwarded a final logical packet.
    Complete(ForwardUntilResult),
    /// Cancellation was observed between logical packets.
    CancelledAtLogicalBoundary {
        /// Complete logical packets forwarded before cancellation.
        logical_packets: u64,
    },
}

/// A bounded materialized logical packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogicalPacket {
    /// Complete logical payload without physical headers.
    pub payload: Vec<u8>,
    /// Physical framing and sequence observations.
    pub progress: ForwardProgress,
}

/// Inner-independent read state: sequence tracking, prefetch buffer, accounting.
///
/// All physical/logical read logic lives here as methods that borrow the
/// transport for the duration of a call, so the same state drives both the
/// read-only [`PacketReader`] and the duplex [`PacketIo`]. The state owns only
/// the fixed prefetch window; streaming methods allocate one bounded copy
/// buffer and never scale memory with the logical message length.
#[derive(Debug)]
struct ReaderState {
    sequence: SequenceTracker,
    prefetched: [u8; PEEK_BYTES],
    prefetch_start: usize,
    prefetch_end: usize,
    stream_buffer_size: NonZeroUsize,
    in_bytes: u64,
    in_packets: u64,
}

impl ReaderState {
    fn new() -> Self {
        Self {
            sequence: SequenceTracker::default(),
            prefetched: [0; PEEK_BYTES],
            prefetch_start: 0,
            prefetch_end: 0,
            stream_buffer_size: NonZeroUsize::new(DEFAULT_STREAM_BUFFER_SIZE)
                .unwrap_or(NonZeroUsize::MIN),
            in_bytes: 0,
            in_packets: 0,
        }
    }

    fn with_stream_buffer_size(stream_buffer_size: NonZeroUsize) -> Self {
        Self {
            stream_buffer_size,
            ..Self::new()
        }
    }

    async fn peek_packet(
        &mut self,
        inner: &mut (impl AsyncRead + Unpin),
    ) -> Result<PacketPreview, PacketIoError> {
        self.ensure_prefetched(inner, PHYSICAL_PACKET_HEADER_LEN)
            .await?;
        let header = PacketHeader::decode(&self.prefetched_slice()[..PHYSICAL_PACKET_HEADER_LEN])?;
        let first_byte = if header.payload_length() == 0 {
            None
        } else {
            self.ensure_prefetched(inner, PEEK_BYTES).await?;
            self.prefetched_slice()
                .get(PHYSICAL_PACKET_HEADER_LEN)
                .copied()
        };
        Ok(PacketPreview {
            first_byte,
            first_packet_length: header.payload_length(),
            sequence_id: header.sequence_id(),
        })
    }

    async fn read_logical(
        &mut self,
        inner: &mut (impl AsyncRead + Unpin),
        payload_limit: usize,
    ) -> Result<LogicalPacket, PacketIoError> {
        let mut progress = ForwardProgress::new(payload_limit);
        let mut scratch = vec![0_u8; self.stream_buffer_size.get()];
        loop {
            let (header, sequence) = self.read_header(inner).await?;
            progress.observe_header(header, sequence)?;
            self.read_payload_into_progress(
                inner,
                header.payload_length(),
                &mut scratch,
                &mut progress,
            )
            .await?;
            self.finish_physical_packet()?;
            progress.finish_physical_packet(header.payload_length())?;
            if progress.is_complete() {
                break;
            }
        }
        if progress.logical_payload_bytes() > u64::try_from(payload_limit).unwrap_or(u64::MAX) {
            return Err(PacketIoError::LogicalPayloadTooLarge {
                limit: payload_limit,
                observed: progress.logical_payload_bytes(),
            });
        }
        Ok(LogicalPacket {
            payload: progress.captured_prefix.clone(),
            progress,
        })
    }

    async fn read_payload_into_progress(
        &mut self,
        inner: &mut (impl AsyncRead + Unpin),
        payload_length: u32,
        scratch: &mut [u8],
        progress: &mut ForwardProgress,
    ) -> Result<(), PacketIoError> {
        let mut remaining =
            usize::try_from(payload_length).map_err(|_| PacketIoError::CounterOverflow {
                field: "physical payload length",
            })?;
        while remaining > 0 {
            let chunk_length = remaining.min(scratch.len());
            self.read_exact(
                inner,
                &mut scratch[..chunk_length],
                "physical packet payload",
            )
            .await?;
            progress.observe_payload(&scratch[..chunk_length])?;
            remaining -= chunk_length;
        }
        Ok(())
    }

    async fn read_header(
        &mut self,
        inner: &mut (impl AsyncRead + Unpin),
    ) -> Result<(PacketHeader, SequenceObservation), PacketIoError> {
        let mut bytes = [0_u8; PHYSICAL_PACKET_HEADER_LEN];
        self.read_exact(inner, &mut bytes, "physical packet header")
            .await?;
        let header = PacketHeader::decode(&bytes)?;
        let sequence = self.sequence.observe(header.sequence_id());
        Ok((header, sequence))
    }

    async fn ensure_prefetched(
        &mut self,
        inner: &mut (impl AsyncRead + Unpin),
        needed: usize,
    ) -> Result<(), PacketIoError> {
        while self.prefetched_len() < needed {
            if self.prefetch_start > 0 {
                self.prefetched
                    .copy_within(self.prefetch_start..self.prefetch_end, 0);
                self.prefetch_end -= self.prefetch_start;
                self.prefetch_start = 0;
            }
            let read = inner
                .read(&mut self.prefetched[self.prefetch_end..])
                .await
                .map_err(|error| PacketIoError::io(IoSide::Source, "prefetching packet", error))?;
            if read == 0 {
                return Err(PacketIoError::io(
                    IoSide::Source,
                    "prefetching packet",
                    io::Error::new(io::ErrorKind::UnexpectedEof, "incomplete packet preview"),
                ));
            }
            self.prefetch_end += read;
        }
        Ok(())
    }

    async fn read_exact(
        &mut self,
        inner: &mut (impl AsyncRead + Unpin),
        output: &mut [u8],
        operation: &'static str,
    ) -> Result<(), PacketIoError> {
        let prefetched = self.prefetched_len().min(output.len());
        if prefetched > 0 {
            output[..prefetched].copy_from_slice(&self.prefetched_slice()[..prefetched]);
            self.prefetch_start += prefetched;
            self.add_in_bytes(prefetched)?;
            if self.prefetch_start == self.prefetch_end {
                self.prefetch_start = 0;
                self.prefetch_end = 0;
            }
        }
        let mut position = prefetched;
        while position < output.len() {
            let read = inner
                .read(&mut output[position..])
                .await
                .map_err(|error| PacketIoError::io(IoSide::Source, operation, error))?;
            if read == 0 {
                return Err(PacketIoError::io(
                    IoSide::Source,
                    operation,
                    io::Error::new(io::ErrorKind::UnexpectedEof, "incomplete packet"),
                ));
            }
            position += read;
            self.add_in_bytes(read)?;
        }
        Ok(())
    }

    fn prefetched_slice(&self) -> &[u8] {
        &self.prefetched[self.prefetch_start..self.prefetch_end]
    }

    const fn prefetched_len(&self) -> usize {
        self.prefetch_end - self.prefetch_start
    }

    fn add_in_bytes(&mut self, bytes: usize) -> Result<(), PacketIoError> {
        self.in_bytes = self
            .in_bytes
            .checked_add(
                u64::try_from(bytes).map_err(|_| PacketIoError::CounterOverflow {
                    field: "input wire bytes",
                })?,
            )
            .ok_or(PacketIoError::CounterOverflow {
                field: "input wire bytes",
            })?;
        Ok(())
    }

    fn finish_physical_packet(&mut self) -> Result<(), PacketIoError> {
        self.in_packets = self
            .in_packets
            .checked_add(1)
            .ok_or(PacketIoError::CounterOverflow {
                field: "input physical packets",
            })?;
        Ok(())
    }
}

/// Inner-independent write state: sequence tracking and accounting.
///
/// All physical/logical write logic lives here as methods that borrow the
/// destination transport, so the same state drives both the write-only
/// [`PacketWriter`] and the duplex [`PacketIo`].
#[derive(Debug)]
struct WriterState {
    sequence: SequenceTracker,
    stream_buffer_size: NonZeroUsize,
    out_bytes: u64,
    out_packets: u64,
}

impl WriterState {
    fn new() -> Self {
        Self {
            sequence: SequenceTracker::default(),
            stream_buffer_size: NonZeroUsize::new(DEFAULT_STREAM_BUFFER_SIZE)
                .unwrap_or(NonZeroUsize::MIN),
            out_bytes: 0,
            out_packets: 0,
        }
    }

    fn with_stream_buffer_size(stream_buffer_size: NonZeroUsize) -> Self {
        Self {
            stream_buffer_size,
            ..Self::new()
        }
    }

    async fn write_physical(
        &mut self,
        inner: &mut (impl AsyncWrite + Unpin),
        payload: &[u8],
    ) -> Result<(), PacketIoError> {
        let payload_length =
            u32::try_from(payload.len()).map_err(|_| EncodeError::LengthOverflow {
                field: "physical packet payload",
                length: payload.len(),
            })?;
        self.start_physical_packet(inner, payload_length).await?;
        self.write_payload(inner, payload).await?;
        self.finish_physical_packet()
    }

    async fn write_logical(
        &mut self,
        inner: &mut (impl AsyncWrite + Unpin),
        payload: &[u8],
        flush: bool,
    ) -> Result<(), PacketIoError> {
        let logical_length =
            u64::try_from(payload.len()).map_err(|_| EncodeError::LengthOverflow {
                field: "logical packet payload",
                length: payload.len(),
            })?;
        let mut position = 0_usize;
        for fragment_length in LogicalPacketFragments::new(logical_length) {
            self.start_physical_packet(inner, fragment_length).await?;
            let fragment_length =
                usize::try_from(fragment_length).map_err(|_| PacketIoError::CounterOverflow {
                    field: "physical payload length",
                })?;
            let end =
                position
                    .checked_add(fragment_length)
                    .ok_or(PacketIoError::CounterOverflow {
                        field: "logical payload offset",
                    })?;
            self.write_payload(inner, &payload[position..end]).await?;
            self.finish_physical_packet()?;
            position = end;
        }
        if flush {
            self.flush(inner).await?;
        }
        Ok(())
    }

    async fn write_logical_from<S>(
        &mut self,
        inner: &mut (impl AsyncWrite + Unpin),
        source: &mut S,
        logical_length: u64,
        flush: bool,
    ) -> Result<(), PacketIoError>
    where
        S: AsyncRead + Unpin,
    {
        let mut scratch = vec![0_u8; self.stream_buffer_size.get()];
        for fragment_length in LogicalPacketFragments::new(logical_length) {
            self.start_physical_packet(inner, fragment_length).await?;
            let mut remaining =
                usize::try_from(fragment_length).map_err(|_| PacketIoError::CounterOverflow {
                    field: "physical payload length",
                })?;
            while remaining > 0 {
                let chunk_length = remaining.min(scratch.len());
                read_source_exact(source, &mut scratch[..chunk_length]).await?;
                self.write_payload(inner, &scratch[..chunk_length]).await?;
                remaining -= chunk_length;
            }
            self.finish_physical_packet()?;
        }
        if flush {
            self.flush(inner).await?;
        }
        Ok(())
    }

    async fn flush(&mut self, inner: &mut (impl AsyncWrite + Unpin)) -> Result<(), PacketIoError> {
        inner
            .flush()
            .await
            .map_err(|error| PacketIoError::io(IoSide::Destination, "flushing packets", error))
    }

    async fn start_physical_packet(
        &mut self,
        inner: &mut (impl AsyncWrite + Unpin),
        payload_length: u32,
    ) -> Result<(), PacketIoError> {
        let sequence = self.sequence.take_next();
        let header = PacketHeader::new(payload_length, sequence)?.encode();
        self.write_all(inner, &header, "writing physical packet header")
            .await
    }

    async fn write_payload(
        &mut self,
        inner: &mut (impl AsyncWrite + Unpin),
        payload: &[u8],
    ) -> Result<(), PacketIoError> {
        self.write_all(inner, payload, "writing physical packet payload")
            .await
    }

    async fn write_all(
        &mut self,
        inner: &mut (impl AsyncWrite + Unpin),
        input: &[u8],
        operation: &'static str,
    ) -> Result<(), PacketIoError> {
        let mut position = 0_usize;
        while position < input.len() {
            let written = inner
                .write(&input[position..])
                .await
                .map_err(|error| PacketIoError::io(IoSide::Destination, operation, error))?;
            if written == 0 {
                return Err(PacketIoError::io(
                    IoSide::Destination,
                    operation,
                    io::Error::new(io::ErrorKind::WriteZero, "failed to write packet bytes"),
                ));
            }
            position += written;
            self.out_bytes = self
                .out_bytes
                .checked_add(u64::try_from(written).map_err(|_| {
                    PacketIoError::CounterOverflow {
                        field: "output wire bytes",
                    }
                })?)
                .ok_or(PacketIoError::CounterOverflow {
                    field: "output wire bytes",
                })?;
        }
        Ok(())
    }

    fn finish_physical_packet(&mut self) -> Result<(), PacketIoError> {
        self.out_packets =
            self.out_packets
                .checked_add(1)
                .ok_or(PacketIoError::CounterOverflow {
                    field: "output physical packets",
                })?;
        Ok(())
    }
}

/// Core single-logical-packet forward across independent read and write halves.
///
/// The read half (`src_state`/`src_inner`) and write half
/// (`dst_state`/`dst_inner`) are borrowed disjointly, so the same routine drives
/// both the read/write-object pair ([`PacketReader`]/[`PacketWriter`]) and the
/// two-endpoint duplex ([`PacketIo`]) case.
///
/// Cancellation contract: `is_cancelled` is consulted only at a physical-packet
/// boundary, immediately before the next header is consumed, and never while a
/// header or payload is partially transferred. When `allow_cancel` is observed
/// after a maximum-size fragment, the same `progress` resumes at the next
/// physical header without duplicating bytes. The regenerated wire output is
/// byte-identical to sequential per-object framing.
#[allow(clippy::too_many_arguments)]
async fn forward_inner(
    src_state: &mut ReaderState,
    src_inner: &mut (impl AsyncRead + Unpin),
    dst_state: &mut WriterState,
    dst_inner: &mut (impl AsyncWrite + Unpin),
    progress: &mut ForwardProgress,
    allow_cancel: bool,
    is_cancelled: &mut impl FnMut() -> bool,
    flush_on_complete: bool,
) -> Result<ForwardStatus, PacketIoError> {
    if progress.is_complete() {
        return Err(PacketIoError::ForwardAlreadyComplete);
    }
    let mut scratch = vec![0_u8; src_state.stream_buffer_size.get()];
    loop {
        if allow_cancel && is_cancelled() {
            return Ok(ForwardStatus::CancelledAtPacketBoundary);
        }
        let (header, sequence) = src_state.read_header(src_inner).await?;
        progress.observe_header(header, sequence)?;
        dst_state
            .start_physical_packet(dst_inner, header.payload_length())
            .await?;

        let mut remaining = usize::try_from(header.payload_length()).map_err(|_| {
            PacketIoError::CounterOverflow {
                field: "physical payload length",
            }
        })?;
        while remaining > 0 {
            let chunk_length = remaining.min(scratch.len());
            src_state
                .read_exact(
                    src_inner,
                    &mut scratch[..chunk_length],
                    "physical packet payload",
                )
                .await?;
            progress.observe_payload(&scratch[..chunk_length])?;
            dst_state
                .write_payload(dst_inner, &scratch[..chunk_length])
                .await?;
            remaining -= chunk_length;
        }
        src_state.finish_physical_packet()?;
        dst_state.finish_physical_packet()?;
        progress.finish_physical_packet(header.payload_length())?;
        if progress.is_complete() {
            if flush_on_complete {
                dst_state.flush(dst_inner).await?;
            }
            return Ok(ForwardStatus::Complete);
        }
    }
}

async fn read_source_exact<S>(source: &mut S, output: &mut [u8]) -> Result<(), PacketIoError>
where
    S: AsyncRead + Unpin,
{
    let mut position = 0_usize;
    while position < output.len() {
        let read = source
            .read(&mut output[position..])
            .await
            .map_err(|error| PacketIoError::io(IoSide::Source, "reading logical payload", error))?;
        if read == 0 {
            return Err(PacketIoError::io(
                IoSide::Source,
                "reading logical payload",
                io::Error::new(io::ErrorKind::UnexpectedEof, "incomplete logical payload"),
            ));
        }
        position += read;
    }
    Ok(())
}

/// Async physical/logical packet reader over an arbitrary transport layer.
///
/// The reader owns only five prefetch bytes. Streaming methods allocate one
/// fixed-size copy buffer and an explicitly bounded capture prefix; memory does
/// not scale with the logical message length.
#[derive(Debug)]
pub struct PacketReader<R> {
    inner: R,
    state: ReaderState,
}

impl<R> PacketReader<R> {
    /// Creates a reader with sequence zero and a 32-KiB streaming buffer.
    #[must_use]
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            state: ReaderState::new(),
        }
    }

    /// Creates a reader with a caller-selected nonzero streaming buffer size.
    #[must_use]
    pub fn with_stream_buffer_size(inner: R, stream_buffer_size: NonZeroUsize) -> Self {
        Self {
            inner,
            state: ReaderState::with_stream_buffer_size(stream_buffer_size),
        }
    }

    /// Returns a shared reference to the underlying transport.
    #[must_use]
    pub const fn get_ref(&self) -> &R {
        &self.inner
    }

    /// Returns a mutable reference to the underlying transport.
    #[must_use]
    pub fn get_mut(&mut self) -> &mut R {
        &mut self.inner
    }

    /// Consumes the packet reader and returns the underlying transport.
    #[must_use]
    pub fn into_inner(self) -> R {
        self.inner
    }

    /// Returns the next expected incoming physical sequence.
    #[must_use]
    pub const fn expected_sequence(&self) -> u8 {
        self.state.sequence.expected()
    }

    /// Resets the expected incoming sequence, normally at a command boundary.
    pub const fn reset_sequence(&mut self, expected: u8) {
        self.state.sequence.reset(expected);
    }

    /// Returns consumed physical wire bytes, including headers.
    #[must_use]
    pub const fn in_bytes(&self) -> u64 {
        self.state.in_bytes
    }

    /// Returns completely consumed physical packets.
    #[must_use]
    pub const fn in_packets(&self) -> u64 {
        self.state.in_packets
    }

    /// Returns the fixed payload-copy buffer size used by streaming methods.
    #[must_use]
    pub const fn stream_buffer_size(&self) -> usize {
        self.state.stream_buffer_size.get()
    }
}

impl<R> PacketReader<R>
where
    R: AsyncRead + Unpin,
{
    /// Peeks at the next physical header and optional first payload byte.
    ///
    /// The method consumes neither sequence state nor accounting counters.
    ///
    /// # Errors
    ///
    /// Returns a source I/O or header decode error for incomplete input.
    pub async fn peek_packet(&mut self) -> Result<PacketPreview, PacketIoError> {
        self.state.peek_packet(&mut self.inner).await
    }

    /// Reads and materializes one logical packet up to `payload_limit` bytes.
    ///
    /// An oversized logical packet is fully drained with constant scratch space
    /// before [`PacketIoError::LogicalPayloadTooLarge`] is returned, leaving the
    /// reader at the next logical-packet boundary.
    ///
    /// # Errors
    ///
    /// Returns a typed framing/I/O error, or a size error after draining an
    /// oversized message.
    pub async fn read_logical(
        &mut self,
        payload_limit: usize,
    ) -> Result<LogicalPacket, PacketIoError> {
        self.state
            .read_logical(&mut self.inner, payload_limit)
            .await
    }

    /// Streams one logical packet to `destination` and flushes it.
    ///
    /// Source headers are decoded and destination headers are regenerated with
    /// the destination's independent sequence. At most `capture_limit` payload
    /// bytes are retained.
    ///
    /// # Errors
    ///
    /// Returns a typed source/destination I/O, framing, or accounting error.
    pub async fn forward_packet_to<W>(
        &mut self,
        destination: &mut PacketWriter<W>,
        capture_limit: usize,
    ) -> Result<ForwardProgress, PacketIoError>
    where
        W: AsyncWrite + Unpin,
    {
        let mut progress = ForwardProgress::new(capture_limit);
        forward_inner(
            &mut self.state,
            &mut self.inner,
            &mut destination.state,
            &mut destination.inner,
            &mut progress,
            false,
            &mut || false,
            true,
        )
        .await?;
        Ok(progress)
    }

    /// Advances a resumable logical-packet forward until completion or a safe boundary.
    ///
    /// `is_cancelled` is checked only before a physical header is consumed. It
    /// is never checked while a header or payload is partially transferred.
    /// Callers must request cancellation through this probe rather than dropping
    /// the future mid-I/O. When cancelled after a maximum-size fragment, pass the
    /// same `progress` back to resume at the next physical header.
    ///
    /// # Errors
    ///
    /// Returns a typed source/destination I/O, framing, or accounting error.
    pub async fn forward_packet_to_cancellable<W, C>(
        &mut self,
        destination: &mut PacketWriter<W>,
        progress: &mut ForwardProgress,
        mut is_cancelled: C,
    ) -> Result<ForwardStatus, PacketIoError>
    where
        W: AsyncWrite + Unpin,
        C: FnMut() -> bool,
    {
        forward_inner(
            &mut self.state,
            &mut self.inner,
            &mut destination.state,
            &mut destination.inner,
            progress,
            true,
            &mut is_cancelled,
            true,
        )
        .await
    }

    /// Forwards logical packets until `decide` selects a terminating packet.
    ///
    /// The first byte and physical length are peeked without consumption.
    /// Intermediate packets are not captured, and the destination is flushed
    /// once after the terminating logical packet.
    ///
    /// # Errors
    ///
    /// Returns a typed source/destination I/O, framing, or accounting error.
    pub async fn forward_until<W, F>(
        &mut self,
        destination: &mut PacketWriter<W>,
        mut decide: F,
    ) -> Result<ForwardUntilResult, PacketIoError>
    where
        W: AsyncWrite + Unpin,
        F: FnMut(PacketPreview) -> ForwardUntilDecision,
    {
        let mut logical_packets = 0_u64;
        loop {
            let preview = self.peek_packet().await?;
            let decision = decide(preview);
            let (stop, capture_limit) = match decision {
                ForwardUntilDecision::Continue => (false, 0),
                ForwardUntilDecision::Stop { capture_limit } => (true, capture_limit),
            };
            let mut progress = ForwardProgress::new(capture_limit);
            forward_inner(
                &mut self.state,
                &mut self.inner,
                &mut destination.state,
                &mut destination.inner,
                &mut progress,
                false,
                &mut || false,
                false,
            )
            .await?;
            logical_packets =
                logical_packets
                    .checked_add(1)
                    .ok_or(PacketIoError::CounterOverflow {
                        field: "forwarded logical packets",
                    })?;
            if stop {
                destination.flush().await?;
                return Ok(ForwardUntilResult {
                    logical_packets,
                    final_packet: progress,
                });
            }
        }
    }

    /// Cancellation-aware [`Self::forward_until`] checked at logical boundaries.
    ///
    /// A cancellation return flushes all preceding complete logical packets.
    /// No partial logical packet is started after the probe reports cancellation.
    ///
    /// # Errors
    ///
    /// Returns a typed source/destination I/O, framing, or accounting error.
    pub async fn forward_until_cancellable<W, F, C>(
        &mut self,
        destination: &mut PacketWriter<W>,
        mut decide: F,
        mut is_cancelled: C,
    ) -> Result<ForwardUntilStatus, PacketIoError>
    where
        W: AsyncWrite + Unpin,
        F: FnMut(PacketPreview) -> ForwardUntilDecision,
        C: FnMut() -> bool,
    {
        let mut logical_packets = 0_u64;
        loop {
            if is_cancelled() {
                destination.flush().await?;
                return Ok(ForwardUntilStatus::CancelledAtLogicalBoundary { logical_packets });
            }
            let preview = self.peek_packet().await?;
            let decision = decide(preview);
            let (stop, capture_limit) = match decision {
                ForwardUntilDecision::Continue => (false, 0),
                ForwardUntilDecision::Stop { capture_limit } => (true, capture_limit),
            };
            let mut progress = ForwardProgress::new(capture_limit);
            forward_inner(
                &mut self.state,
                &mut self.inner,
                &mut destination.state,
                &mut destination.inner,
                &mut progress,
                false,
                &mut || false,
                false,
            )
            .await?;
            logical_packets =
                logical_packets
                    .checked_add(1)
                    .ok_or(PacketIoError::CounterOverflow {
                        field: "forwarded logical packets",
                    })?;
            if stop {
                destination.flush().await?;
                return Ok(ForwardUntilStatus::Complete(ForwardUntilResult {
                    logical_packets,
                    final_packet: progress,
                }));
            }
        }
    }
}

/// Async physical/logical packet writer over an arbitrary transport layer.
#[derive(Debug)]
pub struct PacketWriter<W> {
    inner: W,
    state: WriterState,
}

impl<W> PacketWriter<W> {
    /// Creates a writer with sequence zero and a 32-KiB streaming buffer.
    #[must_use]
    pub fn new(inner: W) -> Self {
        Self {
            inner,
            state: WriterState::new(),
        }
    }

    /// Creates a writer with a caller-selected nonzero streaming buffer size.
    #[must_use]
    pub fn with_stream_buffer_size(inner: W, stream_buffer_size: NonZeroUsize) -> Self {
        Self {
            inner,
            state: WriterState::with_stream_buffer_size(stream_buffer_size),
        }
    }

    /// Returns a shared reference to the underlying transport.
    #[must_use]
    pub const fn get_ref(&self) -> &W {
        &self.inner
    }

    /// Returns a mutable reference to the underlying transport.
    #[must_use]
    pub fn get_mut(&mut self) -> &mut W {
        &mut self.inner
    }

    /// Consumes the packet writer and returns the underlying transport.
    #[must_use]
    pub fn into_inner(self) -> W {
        self.inner
    }

    /// Returns the next outgoing physical sequence.
    #[must_use]
    pub const fn next_sequence(&self) -> u8 {
        self.state.sequence.expected()
    }

    /// Resets the outgoing sequence, normally at a command boundary.
    pub const fn reset_sequence(&mut self, sequence: u8) {
        self.state.sequence.reset(sequence);
    }

    /// Returns physical wire bytes accepted by the destination transport.
    #[must_use]
    pub const fn out_bytes(&self) -> u64 {
        self.state.out_bytes
    }

    /// Returns completely emitted physical packets.
    #[must_use]
    pub const fn out_packets(&self) -> u64 {
        self.state.out_packets
    }

    /// Returns the fixed payload-copy buffer size used by streaming writes.
    #[must_use]
    pub const fn stream_buffer_size(&self) -> usize {
        self.state.stream_buffer_size.get()
    }
}

impl<W> PacketWriter<W>
where
    W: AsyncWrite + Unpin,
{
    /// Writes one complete physical packet without flushing.
    ///
    /// # Errors
    ///
    /// Returns a typed header encode or destination I/O error.
    pub async fn write_physical(&mut self, payload: &[u8]) -> Result<(), PacketIoError> {
        self.state.write_physical(&mut self.inner, payload).await
    }

    /// Writes one logical packet from a caller-owned payload slice.
    ///
    /// # Errors
    ///
    /// Returns a typed length, framing, or destination I/O error.
    pub async fn write_logical(
        &mut self,
        payload: &[u8],
        flush: bool,
    ) -> Result<(), PacketIoError> {
        self.state
            .write_logical(&mut self.inner, payload, flush)
            .await
    }

    /// Streams exactly `logical_length` payload bytes into one logical packet.
    ///
    /// The source and destination are copied through one fixed-size buffer; the
    /// payload is never materialized as a whole.
    ///
    /// # Errors
    ///
    /// Returns a source I/O error if fewer bytes are available, or a typed
    /// framing/destination error after any bytes already emitted.
    pub async fn write_logical_from<S>(
        &mut self,
        source: &mut S,
        logical_length: u64,
        flush: bool,
    ) -> Result<(), PacketIoError>
    where
        S: AsyncRead + Unpin,
    {
        self.state
            .write_logical_from(&mut self.inner, source, logical_length, flush)
            .await
    }

    /// Flushes the underlying destination transport.
    ///
    /// # Errors
    ///
    /// Returns a destination I/O error.
    pub async fn flush(&mut self) -> Result<(), PacketIoError> {
        self.state.flush(&mut self.inner).await
    }
}

/// Single-owner duplex packet endpoint over one bidirectional transport.
///
/// `PacketIo` co-locates the independent [`ReaderState`] and [`WriterState`]
/// halves alongside one owned transport, giving the session engine a single
/// object per connection whose read and write sequences advance independently.
/// The read and write state fields are disjoint from `inner`, so cross-object
/// forwarding can borrow one endpoint's read half and another endpoint's write
/// half simultaneously.
///
/// Compression splice point (slice C): TODO — a future change will interpose a
/// compression codec between `read`/`write` and `inner` here. The
/// state-versus-transport separation established above is the seam that change
/// will use; no compression behavior is introduced in this change.
#[derive(Debug)]
pub struct PacketIo<T> {
    inner: T,
    read: ReaderState,
    write: WriterState,
}

/// Opaque carrier for a [`PacketIo`]'s read/write state across a transport swap.
///
/// Produced by [`PacketIo::into_upgrade_parts`] and consumed by
/// [`PacketIo::from_upgrade_parts`], this token moves both sequence trackers,
/// wire/packet counters, and stream-buffer sizes between transports without
/// exposing or perturbing any internal invariant. Its fields are private: the
/// carried prefetch window is always empty (any unread prefetched bytes are
/// handed back separately as a replayable prefix), so reattaching the state onto
/// a new transport never duplicates bytes and never resets sequences.
#[derive(Debug)]
pub struct PacketIoUpgradeState {
    read: ReaderState,
    write: WriterState,
}

impl<T> PacketIo<T> {
    /// Creates a duplex endpoint with zeroed sequences and 32-KiB buffers.
    #[must_use]
    pub fn new(inner: T) -> Self {
        Self {
            inner,
            read: ReaderState::new(),
            write: WriterState::new(),
        }
    }

    /// Creates a duplex endpoint with a caller-selected nonzero buffer size.
    #[must_use]
    pub fn with_stream_buffer_size(inner: T, stream_buffer_size: NonZeroUsize) -> Self {
        Self {
            inner,
            read: ReaderState::with_stream_buffer_size(stream_buffer_size),
            write: WriterState::with_stream_buffer_size(stream_buffer_size),
        }
    }

    /// Returns a shared reference to the underlying transport.
    #[must_use]
    pub const fn get_ref(&self) -> &T {
        &self.inner
    }

    /// Returns a mutable reference to the underlying transport.
    #[must_use]
    pub fn get_mut(&mut self) -> &mut T {
        &mut self.inner
    }

    /// Consumes the endpoint and returns the underlying transport.
    #[must_use]
    pub fn into_inner(self) -> T {
        self.inner
    }

    /// Returns the next expected incoming physical sequence.
    #[must_use]
    pub const fn expected_read_sequence(&self) -> u8 {
        self.read.sequence.expected()
    }

    /// Resets the expected incoming sequence, normally at a command boundary.
    pub const fn reset_read_sequence(&mut self, expected: u8) {
        self.read.sequence.reset(expected);
    }

    /// Returns consumed physical wire bytes, including headers.
    #[must_use]
    pub const fn in_bytes(&self) -> u64 {
        self.read.in_bytes
    }

    /// Returns completely consumed physical packets.
    #[must_use]
    pub const fn in_packets(&self) -> u64 {
        self.read.in_packets
    }

    /// Returns the next outgoing physical sequence.
    #[must_use]
    pub const fn next_write_sequence(&self) -> u8 {
        self.write.sequence.expected()
    }

    /// Resets the outgoing sequence, normally at a command boundary.
    pub const fn reset_write_sequence(&mut self, sequence: u8) {
        self.write.sequence.reset(sequence);
    }

    /// Returns physical wire bytes accepted by the destination transport.
    #[must_use]
    pub const fn out_bytes(&self) -> u64 {
        self.write.out_bytes
    }

    /// Returns completely emitted physical packets.
    #[must_use]
    pub const fn out_packets(&self) -> u64 {
        self.write.out_packets
    }

    /// Splits the endpoint into its transport, an opaque state token, and the
    /// currently-prefetched-but-unread bytes, for a state-preserving transport
    /// upgrade (e.g. wrapping the raw transport in TLS).
    ///
    /// The returned `Vec<u8>` is a copy of the reader's unconsumed prefetch
    /// window. That window is cleared inside the returned
    /// [`PacketIoUpgradeState`] so the bytes exist in exactly one place: the
    /// caller must replay the returned prefix ahead of the upgraded transport's
    /// stream. Every other piece of state — both sequence trackers,
    /// `in_bytes`/`in_packets`/`out_bytes`/`out_packets`, and both stream-buffer
    /// sizes — is moved into the token unchanged. Reattach with
    /// [`PacketIo::from_upgrade_parts`].
    #[must_use]
    pub fn into_upgrade_parts(self) -> (T, PacketIoUpgradeState, Vec<u8>) {
        let Self {
            inner,
            mut read,
            write,
        } = self;
        let unread_prefix = read.prefetched_slice().to_vec();
        // Exactly-once: the prefix now lives solely in `unread_prefix`. Clear the
        // reader's prefetch window so the token retains no second copy.
        read.prefetch_start = 0;
        read.prefetch_end = 0;
        (inner, PacketIoUpgradeState { read, write }, unread_prefix)
    }

    /// Reattaches carried read/write state onto a new transport after an upgrade.
    ///
    /// The token's prefetch window is already empty (cleared by
    /// [`PacketIo::into_upgrade_parts`]), so the new endpoint starts with no
    /// prefetched bytes while preserving both sequence trackers, all wire/packet
    /// counters, and both stream-buffer sizes. No sequence or counter is reset;
    /// the caller is responsible for having replayed the unread prefix ahead of
    /// `inner`'s stream.
    ///
    /// The new transport type is inferred from `inner`, so it may differ from the
    /// type the state was split out of (e.g. a TLS-wrapped stream).
    #[must_use]
    pub fn from_upgrade_parts(inner: T, state: PacketIoUpgradeState) -> Self {
        Self {
            inner,
            read: state.read,
            write: state.write,
        }
    }
}

impl<T> PacketIo<T>
where
    T: AsyncRead + Unpin,
{
    /// Peeks at the next physical header and optional first payload byte.
    ///
    /// The method consumes neither sequence state nor accounting counters.
    ///
    /// # Errors
    ///
    /// Returns a source I/O or header decode error for incomplete input.
    pub async fn peek_packet(&mut self) -> Result<PacketPreview, PacketIoError> {
        self.read.peek_packet(&mut self.inner).await
    }

    /// Reads and materializes one logical packet up to `payload_limit` bytes.
    ///
    /// # Errors
    ///
    /// Returns a typed framing/I/O error, or a size error after draining an
    /// oversized message.
    pub async fn read_logical(
        &mut self,
        payload_limit: usize,
    ) -> Result<LogicalPacket, PacketIoError> {
        self.read.read_logical(&mut self.inner, payload_limit).await
    }

    /// Streams one logical packet from `src` into `dst` and flushes it.
    ///
    /// The source read half and destination write half are borrowed disjointly.
    /// Destination headers are regenerated with the destination's independent
    /// sequence; at most `capture_limit` payload bytes are retained.
    ///
    /// # Errors
    ///
    /// Returns a typed source/destination I/O, framing, or accounting error.
    pub async fn forward_packet_to<B>(
        src: &mut Self,
        dst: &mut PacketIo<B>,
        capture_limit: usize,
    ) -> Result<ForwardProgress, PacketIoError>
    where
        B: AsyncWrite + Unpin,
    {
        let mut progress = ForwardProgress::new(capture_limit);
        forward_inner(
            &mut src.read,
            &mut src.inner,
            &mut dst.write,
            &mut dst.inner,
            &mut progress,
            false,
            &mut || false,
            true,
        )
        .await?;
        Ok(progress)
    }

    /// Cross-object resumable forward checked only at physical boundaries.
    ///
    /// `is_cancelled` is consulted only before a physical header is consumed,
    /// never mid-header/payload. When cancelled after a maximum-size fragment,
    /// pass the same `progress` back to resume at the next physical header.
    ///
    /// # Errors
    ///
    /// Returns a typed source/destination I/O, framing, or accounting error.
    pub async fn forward_packet_to_cancellable<B, C>(
        src: &mut Self,
        dst: &mut PacketIo<B>,
        progress: &mut ForwardProgress,
        mut is_cancelled: C,
    ) -> Result<ForwardStatus, PacketIoError>
    where
        B: AsyncWrite + Unpin,
        C: FnMut() -> bool,
    {
        forward_inner(
            &mut src.read,
            &mut src.inner,
            &mut dst.write,
            &mut dst.inner,
            progress,
            true,
            &mut is_cancelled,
            true,
        )
        .await
    }

    /// Cross-object forward of logical packets until `decide` selects an end.
    ///
    /// The first byte and physical length are peeked without consumption.
    /// Intermediate packets are not captured, and the destination is flushed
    /// once after the terminating logical packet.
    ///
    /// # Errors
    ///
    /// Returns a typed source/destination I/O, framing, or accounting error.
    pub async fn forward_until<B, F>(
        src: &mut Self,
        dst: &mut PacketIo<B>,
        mut decide: F,
    ) -> Result<ForwardUntilResult, PacketIoError>
    where
        B: AsyncWrite + Unpin,
        F: FnMut(PacketPreview) -> ForwardUntilDecision,
    {
        let mut logical_packets = 0_u64;
        loop {
            let preview = src.read.peek_packet(&mut src.inner).await?;
            let decision = decide(preview);
            let (stop, capture_limit) = match decision {
                ForwardUntilDecision::Continue => (false, 0),
                ForwardUntilDecision::Stop { capture_limit } => (true, capture_limit),
            };
            let mut progress = ForwardProgress::new(capture_limit);
            forward_inner(
                &mut src.read,
                &mut src.inner,
                &mut dst.write,
                &mut dst.inner,
                &mut progress,
                false,
                &mut || false,
                false,
            )
            .await?;
            logical_packets =
                logical_packets
                    .checked_add(1)
                    .ok_or(PacketIoError::CounterOverflow {
                        field: "forwarded logical packets",
                    })?;
            if stop {
                dst.write.flush(&mut dst.inner).await?;
                return Ok(ForwardUntilResult {
                    logical_packets,
                    final_packet: progress,
                });
            }
        }
    }
}

impl<T> PacketIo<T>
where
    T: AsyncWrite + Unpin,
{
    /// Writes one complete physical packet without flushing.
    ///
    /// # Errors
    ///
    /// Returns a typed header encode or destination I/O error.
    pub async fn write_physical(&mut self, payload: &[u8]) -> Result<(), PacketIoError> {
        self.write.write_physical(&mut self.inner, payload).await
    }

    /// Writes one logical packet from a caller-owned payload slice.
    ///
    /// # Errors
    ///
    /// Returns a typed length, framing, or destination I/O error.
    pub async fn write_logical(
        &mut self,
        payload: &[u8],
        flush: bool,
    ) -> Result<(), PacketIoError> {
        self.write
            .write_logical(&mut self.inner, payload, flush)
            .await
    }

    /// Streams exactly `logical_length` payload bytes into one logical packet.
    ///
    /// # Errors
    ///
    /// Returns a source I/O error if fewer bytes are available, or a typed
    /// framing/destination error after any bytes already emitted.
    pub async fn write_logical_from<S>(
        &mut self,
        source: &mut S,
        logical_length: u64,
        flush: bool,
    ) -> Result<(), PacketIoError>
    where
        S: AsyncRead + Unpin,
    {
        self.write
            .write_logical_from(&mut self.inner, source, logical_length, flush)
            .await
    }

    /// Flushes the underlying destination transport.
    ///
    /// # Errors
    ///
    /// Returns a destination I/O error.
    pub async fn flush(&mut self) -> Result<(), PacketIoError> {
        self.write.flush(&mut self.inner).await
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::io;
    use std::io::Cursor;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use mysql_wire::{PacketHeader, encode_physical_packet, physical_packet_count};
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    use super::*;

    #[derive(Debug)]
    struct SyntheticPayload {
        remaining: u64,
    }

    impl SyntheticPayload {
        const fn new(remaining: u64) -> Self {
            Self { remaining }
        }
    }

    impl AsyncRead for SyntheticPayload {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            output: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let available = usize::try_from(self.remaining).unwrap_or(usize::MAX);
            let read = output.remaining().min(available);
            output.advance(read);
            self.remaining -= u64::try_from(read).unwrap_or(u64::MAX);
            Poll::Ready(Ok(()))
        }
    }

    #[derive(Debug)]
    struct GeneratedWire {
        fragments: LogicalPacketFragments,
        header: [u8; PHYSICAL_PACKET_HEADER_LEN],
        header_position: usize,
        payload_remaining: usize,
        next_sequence: u8,
        complete: bool,
    }

    impl GeneratedWire {
        const fn new(logical_length: u64) -> Self {
            Self::with_sequence(logical_length, 0)
        }

        const fn with_sequence(logical_length: u64, sequence: u8) -> Self {
            Self {
                fragments: LogicalPacketFragments::new(logical_length),
                header: [0; PHYSICAL_PACKET_HEADER_LEN],
                header_position: PHYSICAL_PACKET_HEADER_LEN,
                payload_remaining: 0,
                next_sequence: sequence,
                complete: false,
            }
        }

        fn prepare_fragment(&mut self) {
            let Some(payload_length) = self.fragments.next() else {
                self.complete = true;
                return;
            };
            let length_bytes = payload_length.to_le_bytes();
            self.header = [
                length_bytes[0],
                length_bytes[1],
                length_bytes[2],
                self.next_sequence,
            ];
            self.header_position = 0;
            self.payload_remaining = usize::try_from(payload_length).unwrap_or(usize::MAX);
            self.next_sequence = self.next_sequence.wrapping_add(1);
        }
    }

    impl AsyncRead for GeneratedWire {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            output: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            while output.remaining() > 0 && !self.complete {
                if self.header_position == PHYSICAL_PACKET_HEADER_LEN && self.payload_remaining == 0
                {
                    self.prepare_fragment();
                    continue;
                }
                if self.header_position < PHYSICAL_PACKET_HEADER_LEN {
                    let copy_length = output
                        .remaining()
                        .min(PHYSICAL_PACKET_HEADER_LEN - self.header_position);
                    let end = self.header_position + copy_length;
                    output.put_slice(&self.header[self.header_position..end]);
                    self.header_position = end;
                    continue;
                }
                let read = output.remaining().min(self.payload_remaining);
                output.advance(read);
                self.payload_remaining -= read;
            }
            Poll::Ready(Ok(()))
        }
    }

    #[derive(Debug, Default)]
    struct CountingWriter {
        bytes: u64,
        writes: u64,
        flushes: u64,
        maximum_write: usize,
        fail: bool,
    }

    impl CountingWriter {
        const fn failing() -> Self {
            Self {
                bytes: 0,
                writes: 0,
                flushes: 0,
                maximum_write: 0,
                fail: true,
            }
        }
    }

    impl AsyncWrite for CountingWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            input: &[u8],
        ) -> Poll<io::Result<usize>> {
            if self.fail {
                return Poll::Ready(Err(io::Error::other("synthetic destination failure")));
            }
            self.bytes += u64::try_from(input.len()).unwrap_or(u64::MAX);
            self.writes += 1;
            self.maximum_write = self.maximum_write.max(input.len());
            Poll::Ready(Ok(input.len()))
        }

        fn poll_flush(
            mut self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<io::Result<()>> {
            self.flushes += 1;
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[derive(Debug)]
    struct FailingReader;

    impl AsyncRead for FailingReader {
        fn poll_read(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            _output: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Err(io::Error::other("synthetic source failure")))
        }
    }

    fn validate_logical_wire(wire: &[u8], logical_length: u64) -> Result<(), Box<dyn Error>> {
        let mut position = 0_usize;
        let mut sequence = 0_u8;
        for fragment_length in LogicalPacketFragments::new(logical_length) {
            let header_end = position + PHYSICAL_PACKET_HEADER_LEN;
            let header = PacketHeader::decode(&wire[position..header_end])?;
            assert_eq!(header.payload_length(), fragment_length);
            assert_eq!(header.sequence_id(), sequence);
            position = header_end + usize::try_from(fragment_length)?;
            sequence = sequence.wrapping_add(1);
        }
        assert_eq!(position, wire.len());
        Ok(())
    }

    fn encoded_physical_packet(payload: &[u8], sequence: u8) -> Result<Vec<u8>, EncodeError> {
        let mut wire = Vec::new();
        encode_physical_packet(payload, sequence, &mut wire)?;
        Ok(wire)
    }

    #[tokio::test]
    async fn logical_writer_covers_boundaries_and_empty_terminator() -> Result<(), Box<dyn Error>> {
        let maximum = u64::from(MAX_PAYLOAD_LEN);
        for logical_length in [0, 1, maximum - 1, maximum, maximum + 1] {
            let mut source = SyntheticPayload::new(logical_length);
            let mut writer = PacketWriter::new(Vec::new());
            writer
                .write_logical_from(&mut source, logical_length, true)
                .await?;
            assert_eq!(writer.out_packets(), physical_packet_count(logical_length));
            validate_logical_wire(&writer.into_inner(), logical_length)?;
        }
        Ok(())
    }

    #[tokio::test]
    async fn peek_is_non_consuming_and_forward_sequences_are_independent()
    -> Result<(), Box<dyn Error>> {
        let wire = encoded_physical_packet(b"abc", 9)?;
        let mut reader = PacketReader::new(wire.as_slice());
        let preview = reader.peek_packet().await?;
        assert_eq!(
            preview,
            PacketPreview {
                first_byte: Some(b'a'),
                first_packet_length: 3,
                sequence_id: 9,
            }
        );
        assert_eq!(reader.in_bytes(), 0);
        assert_eq!(reader.expected_sequence(), 0);

        let mut writer = PacketWriter::new(Vec::new());
        writer.reset_sequence(3);
        let progress = reader.forward_packet_to(&mut writer, 2).await?;
        assert_eq!(progress.captured_prefix(), b"ab");
        assert!(progress.capture_truncated());
        assert_eq!(progress.first_packet_length(), Some(3));
        assert_eq!(progress.first_byte(), Some(b'a'));
        assert_eq!(progress.sequence_mismatches(), 1);
        assert_eq!(
            progress.first_sequence_mismatch(),
            Some(SequenceObservation {
                expected: 0,
                received: 9,
                next: 10,
            })
        );
        assert_eq!(reader.expected_sequence(), 10);
        assert_eq!(writer.next_sequence(), 4);
        let destination_wire = writer.into_inner();
        let header = PacketHeader::decode(&destination_wire)?;
        assert_eq!(header.sequence_id(), 3);
        assert_eq!(&destination_wire[PHYSICAL_PACKET_HEADER_LEN..], b"abc");
        Ok(())
    }

    #[tokio::test]
    async fn bounded_read_drains_oversize_and_accepts_empty_at_zero_limit()
    -> Result<(), Box<dyn Error>> {
        let mut wire = encoded_physical_packet(&[], 0)?;
        encode_physical_packet(b"abc", 1, &mut wire)?;
        encode_physical_packet(b"z", 2, &mut wire)?;
        let mut reader = PacketReader::new(wire.as_slice());

        assert_eq!(
            reader.peek_packet().await?,
            PacketPreview {
                first_byte: None,
                first_packet_length: 0,
                sequence_id: 0,
            }
        );
        assert_eq!(reader.in_bytes(), 0);
        let empty = reader.read_logical(0).await?;
        assert!(empty.payload.is_empty());
        let error = reader
            .read_logical(2)
            .await
            .err()
            .ok_or_else(|| io::Error::other("oversized packet unexpectedly succeeded"))?;
        assert!(matches!(
            error,
            PacketIoError::LogicalPayloadTooLarge {
                limit: 2,
                observed: 3
            }
        ));
        let final_packet = reader.read_logical(1).await?;
        assert_eq!(final_packet.payload, b"z");
        assert_eq!(reader.in_packets(), 3);
        Ok(())
    }

    #[tokio::test]
    async fn cancellable_forward_resumes_only_at_physical_boundary() -> Result<(), Box<dyn Error>> {
        let logical_length = u64::from(MAX_PAYLOAD_LEN) + 1;
        let mut reader = PacketReader::new(GeneratedWire::new(logical_length));
        let mut writer = PacketWriter::new(CountingWriter::default());
        let mut progress = ForwardProgress::new(1_024);
        let mut probes = 0_u8;
        let status = reader
            .forward_packet_to_cancellable(&mut writer, &mut progress, || {
                probes = probes.saturating_add(1);
                probes == 2
            })
            .await?;
        assert_eq!(status, ForwardStatus::CancelledAtPacketBoundary);
        assert_eq!(progress.logical_payload_bytes(), u64::from(MAX_PAYLOAD_LEN));
        assert_eq!(progress.physical_packets(), 1);
        assert!(!progress.is_complete());
        assert_eq!(reader.in_packets(), 1);
        assert_eq!(writer.out_packets(), 1);

        let status = reader
            .forward_packet_to_cancellable(&mut writer, &mut progress, || false)
            .await?;
        assert_eq!(status, ForwardStatus::Complete);
        assert_eq!(progress.logical_payload_bytes(), logical_length);
        assert_eq!(progress.physical_packets(), 2);
        assert!(progress.is_complete());
        assert_eq!(progress.captured_prefix().len(), 1_024);
        assert_eq!(writer.get_ref().flushes, 1);
        Ok(())
    }

    #[tokio::test]
    async fn sequence_wrap_and_command_reset_are_explicit() -> Result<(), Box<dyn Error>> {
        let mut writer = PacketWriter::new(Vec::new());
        writer.reset_sequence(u8::MAX);
        writer.write_logical(b"a", false).await?;
        writer.write_logical(b"b", false).await?;
        assert_eq!(writer.next_sequence(), 1);
        let wire = writer.get_ref();
        assert_eq!(PacketHeader::decode(wire)?.sequence_id(), u8::MAX);
        assert_eq!(
            PacketHeader::decode(&wire[PHYSICAL_PACKET_HEADER_LEN + 1..])?.sequence_id(),
            0
        );
        writer.reset_sequence(7);
        assert_eq!(writer.next_sequence(), 7);
        Ok(())
    }

    #[tokio::test]
    async fn forward_until_regenerates_destination_sequence_and_captures_final()
    -> Result<(), Box<dyn Error>> {
        let mut wire = encoded_physical_packet(&[1], 0)?;
        encode_physical_packet(&[0xfe, 0], 1, &mut wire)?;
        let mut reader = PacketReader::new(wire.as_slice());
        let mut writer = PacketWriter::new(Vec::new());
        writer.reset_sequence(7);
        let result = reader
            .forward_until(&mut writer, |preview| {
                if preview.first_byte == Some(0xfe) {
                    ForwardUntilDecision::Stop { capture_limit: 2 }
                } else {
                    ForwardUntilDecision::Continue
                }
            })
            .await?;
        assert_eq!(result.logical_packets, 2);
        assert_eq!(result.final_packet.captured_prefix(), &[0xfe, 0]);
        let destination = writer.into_inner();
        assert_eq!(PacketHeader::decode(&destination)?.sequence_id(), 7);
        assert_eq!(PacketHeader::decode(&destination[5..])?.sequence_id(), 8);
        Ok(())
    }

    #[tokio::test]
    async fn endpoint_failures_retain_source_or_destination_attribution()
    -> Result<(), Box<dyn Error>> {
        let mut source_reader = PacketReader::new(FailingReader);
        let source_error = source_reader
            .peek_packet()
            .await
            .err()
            .ok_or_else(|| io::Error::other("source failure unexpectedly succeeded"))?;
        assert!(matches!(
            source_error,
            PacketIoError::Io {
                side: IoSide::Source,
                ..
            }
        ));

        let wire = encoded_physical_packet(b"x", 0)?;
        let mut reader = PacketReader::new(wire.as_slice());
        let mut writer = PacketWriter::new(CountingWriter::failing());
        let destination_error = reader
            .forward_packet_to(&mut writer, 0)
            .await
            .err()
            .ok_or_else(|| io::Error::other("destination failure unexpectedly succeeded"))?;
        assert!(matches!(
            destination_error,
            PacketIoError::Io {
                side: IoSide::Destination,
                ..
            }
        ));
        Ok(())
    }

    #[tokio::test]
    async fn synthetic_gib_forward_keeps_buffers_constant() -> Result<(), Box<dyn Error>> {
        let logical_length = 1_u64 << 30;
        let mut reader = PacketReader::new(GeneratedWire::new(logical_length));
        let mut writer = PacketWriter::new(CountingWriter::default());
        let progress = reader.forward_packet_to(&mut writer, 1_024).await?;

        let physical_packets = physical_packet_count(logical_length);
        assert_eq!(progress.logical_payload_bytes(), logical_length);
        assert_eq!(progress.physical_packets(), physical_packets);
        assert_eq!(progress.captured_prefix().len(), 1_024);
        assert_eq!(reader.stream_buffer_size(), DEFAULT_STREAM_BUFFER_SIZE);
        assert_eq!(writer.stream_buffer_size(), DEFAULT_STREAM_BUFFER_SIZE);
        assert!(writer.get_ref().maximum_write <= DEFAULT_STREAM_BUFFER_SIZE);
        assert_eq!(writer.out_packets(), physical_packets);
        assert_eq!(
            writer.out_bytes(),
            logical_length + physical_packets * PHYSICAL_PACKET_HEADER_LEN as u64
        );
        Ok(())
    }

    #[tokio::test]
    async fn packet_io_write_matches_packet_writer_for_small_logical() -> Result<(), Box<dyn Error>>
    {
        let payload = b"hello packetio";

        let mut writer = PacketWriter::new(Vec::new());
        writer.write_logical(payload, true).await?;
        let expected = writer.into_inner();

        // `Cursor<Vec<u8>>` is an in-memory duplex transport: both AsyncRead and
        // AsyncWrite, so one `PacketIo` covers the write and read halves.
        let mut io = PacketIo::new(Cursor::new(Vec::new()));
        io.write_logical(payload, true).await?;
        let out_packets = io.out_packets();
        let produced = io.into_inner().into_inner();
        assert_eq!(produced, expected);
        assert_eq!(out_packets, 1);

        let mut reader = PacketReader::new(expected.as_slice());
        let via_reader = reader.read_logical(payload.len()).await?;
        let mut io_reader = PacketIo::new(Cursor::new(expected.clone()));
        let via_io = io_reader.read_logical(payload.len()).await?;
        assert_eq!(via_io.payload, via_reader.payload);
        assert_eq!(via_io.payload, payload);
        assert_eq!(io_reader.in_packets(), reader.in_packets());
        Ok(())
    }

    #[tokio::test]
    async fn packet_io_write_matches_packet_writer_across_fragment_boundary()
    -> Result<(), Box<dyn Error>> {
        let logical_length = u64::from(MAX_PAYLOAD_LEN) + 1;

        let mut writer = PacketWriter::new(Vec::new());
        writer
            .write_logical_from(
                &mut SyntheticPayload::new(logical_length),
                logical_length,
                true,
            )
            .await?;
        let expected = writer.into_inner();

        let mut io = PacketIo::new(Cursor::new(Vec::new()));
        io.write_logical_from(
            &mut SyntheticPayload::new(logical_length),
            logical_length,
            true,
        )
        .await?;
        let out_packets = io.out_packets();
        let produced = io.into_inner().into_inner();

        assert_eq!(produced, expected);
        assert_eq!(out_packets, physical_packet_count(logical_length));
        validate_logical_wire(&produced, logical_length)?;
        Ok(())
    }

    #[tokio::test]
    async fn packet_io_peek_is_non_consuming() -> Result<(), Box<dyn Error>> {
        let wire = encoded_physical_packet(b"abc", 9)?;
        let mut io = PacketIo::new(Cursor::new(wire));
        let preview = io.peek_packet().await?;
        assert_eq!(
            preview,
            PacketPreview {
                first_byte: Some(b'a'),
                first_packet_length: 3,
                sequence_id: 9,
            }
        );
        assert_eq!(io.in_bytes(), 0);
        assert_eq!(io.expected_read_sequence(), 0);
        let logical = io.read_logical(3).await?;
        assert_eq!(logical.payload, b"abc");
        assert_eq!(io.in_packets(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn packet_io_forward_matches_reader_writer_pair() -> Result<(), Box<dyn Error>> {
        let wire = encoded_physical_packet(b"abc", 9)?;

        let mut reference_reader = PacketReader::new(wire.as_slice());
        let mut reference_writer = PacketWriter::new(Vec::new());
        reference_writer.reset_sequence(3);
        let reference_progress = reference_reader
            .forward_packet_to(&mut reference_writer, 2)
            .await?;
        let reference_out_packets = reference_writer.out_packets();
        let reference_wire = reference_writer.into_inner();

        // Two `PacketIo` endpoints over in-memory duplex transports.
        let mut src = PacketIo::new(Cursor::new(wire.clone()));
        let mut dst = PacketIo::new(Cursor::new(Vec::new()));
        dst.reset_write_sequence(3);
        let progress = PacketIo::forward_packet_to(&mut src, &mut dst, 2).await?;
        let dst_out_packets = dst.out_packets();
        let produced_wire = dst.into_inner().into_inner();

        assert_eq!(produced_wire, reference_wire);
        assert_eq!(
            progress.captured_prefix(),
            reference_progress.captured_prefix()
        );
        assert_eq!(
            progress.first_packet_length(),
            reference_progress.first_packet_length()
        );
        assert_eq!(
            progress.sequence_mismatches(),
            reference_progress.sequence_mismatches()
        );
        assert_eq!(src.in_packets(), reference_reader.in_packets());
        assert_eq!(dst_out_packets, reference_out_packets);
        Ok(())
    }

    #[tokio::test]
    async fn upgrade_prefix_equals_prefetched_unread_bytes() -> Result<(), Box<dyn Error>> {
        let wire = encoded_physical_packet(b"abc", 0)?;
        let mut io = PacketIo::new(Cursor::new(wire.clone()));
        // `peek_packet` prefetches exactly the header plus the first payload byte.
        io.peek_packet().await?;
        assert_eq!(io.get_ref().position(), u64::try_from(PEEK_BYTES)?);

        let (_inner, _state, unread_prefix) = io.into_upgrade_parts();
        assert_eq!(unread_prefix.as_slice(), &wire[..PEEK_BYTES]);
        Ok(())
    }

    #[tokio::test]
    async fn upgrade_token_carries_no_prefetch_after_split() -> Result<(), Box<dyn Error>> {
        let wire = encoded_physical_packet(b"abc", 0)?;
        let mut io = PacketIo::new(Cursor::new(wire.clone()));
        io.peek_packet().await?;
        let (_inner, state, unread_prefix) = io.into_upgrade_parts();

        // Replay the returned prefix ahead of the not-yet-prefetched continuation;
        // together they reconstruct the original stream exactly once.
        let mut replayed = unread_prefix.clone();
        replayed.extend_from_slice(&wire[unread_prefix.len()..]);
        assert_eq!(replayed, wire);

        let mut reattached = PacketIo::from_upgrade_parts(Cursor::new(replayed), state);
        let logical = reattached.read_logical(3).await?;
        // No duplicated prefix: the packet materializes exactly once.
        assert_eq!(logical.payload, b"abc");
        assert_eq!(reattached.in_packets(), 1);
        assert_eq!(reattached.expected_read_sequence(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn upgrade_round_trip_conserves_sequences_and_counters() -> Result<(), Box<dyn Error>> {
        let buffer_size =
            NonZeroUsize::new(4_096).ok_or_else(|| io::Error::other("buffer size"))?;
        let mut io = PacketIo::with_stream_buffer_size(Cursor::new(Vec::new()), buffer_size);
        // Advance the write half: three physical packets, sequences 0, 1, 2.
        io.write_logical(b"p0", false).await?;
        io.write_logical(b"p1", false).await?;
        io.write_logical(b"next-payload", false).await?;
        // Rewind and advance the read half over the first two packets.
        io.get_mut().set_position(0);
        assert_eq!(io.read_logical(2).await?.payload, b"p0");
        assert_eq!(io.read_logical(2).await?.payload, b"p1");
        // Force a prefetch of the third packet without consuming it.
        io.peek_packet().await?;

        let read_sequence = io.expected_read_sequence();
        let write_sequence = io.next_write_sequence();
        let in_bytes = io.in_bytes();
        let out_bytes = io.out_bytes();
        let in_packets = io.in_packets();
        let out_packets = io.out_packets();
        let read_buffer = io.read.stream_buffer_size;
        let write_buffer = io.write.stream_buffer_size;

        let (_inner, state, _prefix) = io.into_upgrade_parts();
        let reattached = PacketIo::from_upgrade_parts(Cursor::new(Vec::<u8>::new()), state);

        assert_eq!(reattached.expected_read_sequence(), read_sequence);
        assert_eq!(reattached.next_write_sequence(), write_sequence);
        assert_eq!(reattached.in_bytes(), in_bytes);
        assert_eq!(reattached.out_bytes(), out_bytes);
        assert_eq!(reattached.in_packets(), in_packets);
        assert_eq!(reattached.out_packets(), out_packets);
        assert_eq!(reattached.read.stream_buffer_size, read_buffer);
        assert_eq!(reattached.write.stream_buffer_size, write_buffer);

        // The round trip carried real, non-zero, non-reset state.
        assert_eq!(read_sequence, 2);
        assert_eq!(write_sequence, 3);
        assert!(in_bytes > 0 && out_bytes > 0);
        assert_eq!(in_packets, 2);
        assert_eq!(out_packets, 3);
        Ok(())
    }

    #[tokio::test]
    async fn upgrade_replays_prefix_and_continues_next_packet() -> Result<(), Box<dyn Error>> {
        let mut io = PacketIo::new(Cursor::new(Vec::new()));
        // Advance both halves so sequences are non-zero before the upgrade.
        io.write_logical(b"c0", false).await?;
        io.write_logical(b"c1", false).await?;
        // The third packet (sequence 2) is the "next" packet resumed after upgrade.
        io.write_logical(b"resumed-next", false).await?;
        io.get_mut().set_position(0);
        let _ = io.read_logical(8).await?;
        let _ = io.read_logical(8).await?;
        assert_eq!(io.expected_read_sequence(), 2);
        // Force a prefetch straddling the next packet's header and first byte.
        io.peek_packet().await?;

        // Raw wire of the un-consumed next packet, starting after the two read ones.
        let full_wire = io.get_ref().get_ref().clone();
        let next_packet_wire = full_wire[12..].to_vec();

        let (_inner, state, unread_prefix) = io.into_upgrade_parts();
        assert_eq!(unread_prefix.as_slice(), &next_packet_wire[..PEEK_BYTES]);

        // Fresh transport preloaded with unread_prefix ++ continuation bytes.
        let mut replayed = unread_prefix.clone();
        replayed.extend_from_slice(&next_packet_wire[unread_prefix.len()..]);
        assert_eq!(replayed, next_packet_wire);

        let mut upgraded = PacketIo::from_upgrade_parts(Cursor::new(replayed), state);
        let resumed = upgraded.read_logical(64).await?;
        assert_eq!(resumed.payload, b"resumed-next");
        // Sequence continued from 2 to 3 (not reset); no duplicated prefix bytes.
        assert_eq!(upgraded.expected_read_sequence(), 3);
        Ok(())
    }
}
