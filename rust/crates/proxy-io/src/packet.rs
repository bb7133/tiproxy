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

/// Async physical/logical packet reader over an arbitrary transport layer.
///
/// The reader owns only five prefetch bytes. Streaming methods allocate one
/// fixed-size copy buffer and an explicitly bounded capture prefix; memory does
/// not scale with the logical message length.
#[derive(Debug)]
pub struct PacketReader<R> {
    inner: R,
    sequence: SequenceTracker,
    prefetched: [u8; PEEK_BYTES],
    prefetch_start: usize,
    prefetch_end: usize,
    stream_buffer_size: NonZeroUsize,
    in_bytes: u64,
    in_packets: u64,
}

impl<R> PacketReader<R> {
    /// Creates a reader with sequence zero and a 32-KiB streaming buffer.
    #[must_use]
    pub fn new(inner: R) -> Self {
        Self {
            inner,
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

    /// Creates a reader with a caller-selected nonzero streaming buffer size.
    #[must_use]
    pub fn with_stream_buffer_size(inner: R, stream_buffer_size: NonZeroUsize) -> Self {
        Self {
            stream_buffer_size,
            ..Self::new(inner)
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
        self.sequence.expected()
    }

    /// Resets the expected incoming sequence, normally at a command boundary.
    pub const fn reset_sequence(&mut self, expected: u8) {
        self.sequence.reset(expected);
    }

    /// Returns consumed physical wire bytes, including headers.
    #[must_use]
    pub const fn in_bytes(&self) -> u64 {
        self.in_bytes
    }

    /// Returns completely consumed physical packets.
    #[must_use]
    pub const fn in_packets(&self) -> u64 {
        self.in_packets
    }

    /// Returns the fixed payload-copy buffer size used by streaming methods.
    #[must_use]
    pub const fn stream_buffer_size(&self) -> usize {
        self.stream_buffer_size.get()
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
        self.ensure_prefetched(PHYSICAL_PACKET_HEADER_LEN).await?;
        let header = PacketHeader::decode(&self.prefetched_slice()[..PHYSICAL_PACKET_HEADER_LEN])?;
        let first_byte = if header.payload_length() == 0 {
            None
        } else {
            self.ensure_prefetched(PEEK_BYTES).await?;
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
        let mut progress = ForwardProgress::new(payload_limit);
        let mut scratch = vec![0_u8; self.stream_buffer_size.get()];
        loop {
            let (header, sequence) = self.read_header().await?;
            progress.observe_header(header, sequence)?;
            self.read_payload_into_progress(header.payload_length(), &mut scratch, &mut progress)
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
        self.forward_inner(destination, &mut progress, false, &mut || false, true)
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
        self.forward_inner(destination, progress, true, &mut is_cancelled, true)
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
            self.forward_inner(destination, &mut progress, false, &mut || false, false)
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
            self.forward_inner(destination, &mut progress, false, &mut || false, false)
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

    async fn forward_inner<W, C>(
        &mut self,
        destination: &mut PacketWriter<W>,
        progress: &mut ForwardProgress,
        allow_cancel: bool,
        is_cancelled: &mut C,
        flush_on_complete: bool,
    ) -> Result<ForwardStatus, PacketIoError>
    where
        W: AsyncWrite + Unpin,
        C: FnMut() -> bool,
    {
        if progress.is_complete() {
            return Err(PacketIoError::ForwardAlreadyComplete);
        }
        let mut scratch = vec![0_u8; self.stream_buffer_size.get()];
        loop {
            if allow_cancel && is_cancelled() {
                return Ok(ForwardStatus::CancelledAtPacketBoundary);
            }
            let (header, sequence) = self.read_header().await?;
            progress.observe_header(header, sequence)?;
            destination
                .start_physical_packet(header.payload_length())
                .await?;

            let mut remaining = usize::try_from(header.payload_length()).map_err(|_| {
                PacketIoError::CounterOverflow {
                    field: "physical payload length",
                }
            })?;
            while remaining > 0 {
                let chunk_length = remaining.min(scratch.len());
                self.read_exact(&mut scratch[..chunk_length], "physical packet payload")
                    .await?;
                progress.observe_payload(&scratch[..chunk_length])?;
                destination.write_payload(&scratch[..chunk_length]).await?;
                remaining -= chunk_length;
            }
            self.finish_physical_packet()?;
            destination.finish_physical_packet()?;
            progress.finish_physical_packet(header.payload_length())?;
            if progress.is_complete() {
                if flush_on_complete {
                    destination.flush().await?;
                }
                return Ok(ForwardStatus::Complete);
            }
        }
    }

    async fn read_payload_into_progress(
        &mut self,
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
            self.read_exact(&mut scratch[..chunk_length], "physical packet payload")
                .await?;
            progress.observe_payload(&scratch[..chunk_length])?;
            remaining -= chunk_length;
        }
        Ok(())
    }

    async fn read_header(&mut self) -> Result<(PacketHeader, SequenceObservation), PacketIoError> {
        let mut bytes = [0_u8; PHYSICAL_PACKET_HEADER_LEN];
        self.read_exact(&mut bytes, "physical packet header")
            .await?;
        let header = PacketHeader::decode(&bytes)?;
        let sequence = self.sequence.observe(header.sequence_id());
        Ok((header, sequence))
    }

    async fn ensure_prefetched(&mut self, needed: usize) -> Result<(), PacketIoError> {
        while self.prefetched_len() < needed {
            if self.prefetch_start > 0 {
                self.prefetched
                    .copy_within(self.prefetch_start..self.prefetch_end, 0);
                self.prefetch_end -= self.prefetch_start;
                self.prefetch_start = 0;
            }
            let read = self
                .inner
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
            let read = self
                .inner
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

/// Async physical/logical packet writer over an arbitrary transport layer.
#[derive(Debug)]
pub struct PacketWriter<W> {
    inner: W,
    sequence: SequenceTracker,
    stream_buffer_size: NonZeroUsize,
    out_bytes: u64,
    out_packets: u64,
}

impl<W> PacketWriter<W> {
    /// Creates a writer with sequence zero and a 32-KiB streaming buffer.
    #[must_use]
    pub fn new(inner: W) -> Self {
        Self {
            inner,
            sequence: SequenceTracker::default(),
            stream_buffer_size: NonZeroUsize::new(DEFAULT_STREAM_BUFFER_SIZE)
                .unwrap_or(NonZeroUsize::MIN),
            out_bytes: 0,
            out_packets: 0,
        }
    }

    /// Creates a writer with a caller-selected nonzero streaming buffer size.
    #[must_use]
    pub fn with_stream_buffer_size(inner: W, stream_buffer_size: NonZeroUsize) -> Self {
        Self {
            stream_buffer_size,
            ..Self::new(inner)
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
        self.sequence.expected()
    }

    /// Resets the outgoing sequence, normally at a command boundary.
    pub const fn reset_sequence(&mut self, sequence: u8) {
        self.sequence.reset(sequence);
    }

    /// Returns physical wire bytes accepted by the destination transport.
    #[must_use]
    pub const fn out_bytes(&self) -> u64 {
        self.out_bytes
    }

    /// Returns completely emitted physical packets.
    #[must_use]
    pub const fn out_packets(&self) -> u64 {
        self.out_packets
    }

    /// Returns the fixed payload-copy buffer size used by streaming writes.
    #[must_use]
    pub const fn stream_buffer_size(&self) -> usize {
        self.stream_buffer_size.get()
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
        let payload_length =
            u32::try_from(payload.len()).map_err(|_| EncodeError::LengthOverflow {
                field: "physical packet payload",
                length: payload.len(),
            })?;
        self.start_physical_packet(payload_length).await?;
        self.write_payload(payload).await?;
        self.finish_physical_packet()
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
        let logical_length =
            u64::try_from(payload.len()).map_err(|_| EncodeError::LengthOverflow {
                field: "logical packet payload",
                length: payload.len(),
            })?;
        let mut position = 0_usize;
        for fragment_length in LogicalPacketFragments::new(logical_length) {
            self.start_physical_packet(fragment_length).await?;
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
            self.write_payload(&payload[position..end]).await?;
            self.finish_physical_packet()?;
            position = end;
        }
        if flush {
            self.flush().await?;
        }
        Ok(())
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
        let mut scratch = vec![0_u8; self.stream_buffer_size.get()];
        for fragment_length in LogicalPacketFragments::new(logical_length) {
            self.start_physical_packet(fragment_length).await?;
            let mut remaining =
                usize::try_from(fragment_length).map_err(|_| PacketIoError::CounterOverflow {
                    field: "physical payload length",
                })?;
            while remaining > 0 {
                let chunk_length = remaining.min(scratch.len());
                read_source_exact(source, &mut scratch[..chunk_length]).await?;
                self.write_payload(&scratch[..chunk_length]).await?;
                remaining -= chunk_length;
            }
            self.finish_physical_packet()?;
        }
        if flush {
            self.flush().await?;
        }
        Ok(())
    }

    /// Flushes the underlying destination transport.
    ///
    /// # Errors
    ///
    /// Returns a destination I/O error.
    pub async fn flush(&mut self) -> Result<(), PacketIoError> {
        self.inner
            .flush()
            .await
            .map_err(|error| PacketIoError::io(IoSide::Destination, "flushing packets", error))
    }

    async fn start_physical_packet(&mut self, payload_length: u32) -> Result<(), PacketIoError> {
        let sequence = self.sequence.take_next();
        let header = PacketHeader::new(payload_length, sequence)?.encode();
        self.write_all(&header, "writing physical packet header")
            .await
    }

    async fn write_payload(&mut self, payload: &[u8]) -> Result<(), PacketIoError> {
        self.write_all(payload, "writing physical packet payload")
            .await
    }

    async fn write_all(
        &mut self,
        input: &[u8],
        operation: &'static str,
    ) -> Result<(), PacketIoError> {
        let mut position = 0_usize;
        while position < input.len() {
            let written = self
                .inner
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

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::io;
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
    async fn forward_until_peeks_and_captures_only_final_packet() -> Result<(), Box<dyn Error>> {
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
}
