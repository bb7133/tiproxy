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

//! Bounded `MySQL` compressed-protocol framing.
//!
//! The compressed sequence is shared by reads and writes, just like Go
//! `TiProxy`'s `compressedReadWriter`. Call [`CompressedIo::begin_read`] or
//! [`CompressedIo::begin_write`] before handing the transport to a packet
//! reader/writer. A direction change returns the compressed sequence that the
//! packet layer must adopt for its uncompressed sequence.
//!
//! Unlike Go's permissive `BeginRW`, the async adapter rejects a direction
//! change that would strand buffered output or unread decoded bytes. Session
//! owners must flush a request and consume its response before switching; this
//! is an intentional local ownership invariant, not a wire-visible difference.

use std::fmt;
use std::io::{self, Read, Write};
use std::pin::Pin;
use std::task::{Context, Poll};

use flate2::Compression;
use flate2::bufread::ZlibDecoder;
use flate2::write::ZlibEncoder;
use mysql_wire::{CapabilityFlags, MAX_PAYLOAD_LEN};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use zstd_pure_rs::prelude::{ZSTD_compress, ZSTD_compressBound, ZSTD_getErrorName, ZSTD_isError};
use zstd_zero::{
    DecodeStep as ZstdDecodeStep, Decoder as ZstdDecoder, DecoderBuffers as ZstdDecoderBuffers,
    FrameKind as ZstdFrameKind, HeaderStatus as ZstdHeaderStatus, MAX_BLOCK_SIZE,
    StreamHeader as ZstdStreamHeader, inspect_frame as inspect_zstd_frame,
};

/// Bytes in a `MySQL` compressed-protocol header.
pub const COMPRESSED_HEADER_LEN: usize = 7;

/// Maximum payload representable by either 24-bit compressed length field.
pub const MAX_COMPRESSED_FRAME_LEN: usize = MAX_PAYLOAD_LEN as usize;

/// Minimum buffered size at which Go `TiProxy` attempts compression.
pub const MIN_COMPRESS_LEN: usize = 50;

/// `MySQL`-compatible zlib compression level used by Go `TiProxy`.
pub const ZLIB_COMPRESSION_LEVEL: u32 = 6;

/// Default maximum declared decompression expansion.
///
/// This admits the high-ratio 16-MiB repeated-byte vectors produced by the Go
/// zstd encoder while still making the CPU/memory work proportional to a
/// declared, reviewable bound.
pub const DEFAULT_MAX_EXPANSION_RATIO: u32 = 65_536;

const RETAINED_BUFFER_CAPACITY: usize = 32 * 1024;

/// Compression selected independently for one client or backend transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionAlgorithm {
    /// `MySQL` classic zlib compression at level six.
    Zlib,
    /// `MySQL` zstd compression at the negotiated level.
    Zstd {
        /// Negotiated zstd level in the MySQL-supported range `1..=22`.
        level: i32,
    },
}

impl CompressionAlgorithm {
    fn validate(self) -> Result<Self, CompressionError> {
        if let Self::Zstd { level } = self
            && !(1..=22).contains(&level)
        {
            return Err(CompressionError::InvalidZstdLevel { level });
        }
        Ok(self)
    }
}

impl fmt::Display for CompressionAlgorithm {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Zlib => formatter.write_str("zlib"),
            Self::Zstd { .. } => formatter.write_str("zstd"),
        }
    }
}

/// Selects the codec for one independently negotiated transport.
///
/// Classic zlib wins when both capability bits are present, matching Go
/// `TiProxy`'s `setCompress`. Call this separately for the client capability
/// set and the client/backend capability intersection; the two legs need not
/// select the same algorithm.
///
/// # Errors
///
/// Returns a typed error when zstd is selected without a handshake level or
/// when that level is outside `MySQL`'s supported `1..=22` range.
pub fn negotiate_compression(
    capabilities: CapabilityFlags,
    zstd_level: Option<u8>,
) -> Result<Option<CompressionAlgorithm>, CompressionError> {
    if capabilities.contains(CapabilityFlags::COMPRESS) {
        return Ok(Some(CompressionAlgorithm::Zlib));
    }
    if capabilities.contains(CapabilityFlags::ZSTD_COMPRESSION_ALGORITHM) {
        let level = zstd_level.ok_or(CompressionError::MissingZstdLevel)?;
        return Ok(Some(
            CompressionAlgorithm::Zstd {
                level: i32::from(level),
            }
            .validate()?,
        ));
    }
    Ok(None)
}

/// Current uncompressed packet-I/O direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionDirection {
    /// Bytes are being read from the peer.
    Read,
    /// Bytes are being written to the peer.
    Write,
}

impl fmt::Display for CompressionDirection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read => formatter.write_str("read"),
            Self::Write => formatter.write_str("write"),
        }
    }
}

/// Allocation and expansion limits for one compressed transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompressionLimits {
    max_uncompressed_frame_len: usize,
    max_expansion_ratio: u32,
}

impl CompressionLimits {
    /// Creates validated frame and expansion limits.
    ///
    /// # Errors
    ///
    /// Returns a typed configuration error when either value is zero or the
    /// frame length does not fit the protocol's 24-bit field.
    pub fn new(
        max_uncompressed_frame_len: usize,
        max_expansion_ratio: u32,
    ) -> Result<Self, CompressionError> {
        if max_uncompressed_frame_len == 0 || max_uncompressed_frame_len > MAX_COMPRESSED_FRAME_LEN
        {
            return Err(CompressionError::InvalidFrameLimit {
                value: max_uncompressed_frame_len,
                max: MAX_COMPRESSED_FRAME_LEN,
            });
        }
        if max_expansion_ratio == 0 {
            return Err(CompressionError::InvalidExpansionRatio);
        }
        Ok(Self {
            max_uncompressed_frame_len,
            max_expansion_ratio,
        })
    }

    /// Returns the maximum materialized uncompressed bytes per frame.
    #[must_use]
    pub const fn max_uncompressed_frame_len(self) -> usize {
        self.max_uncompressed_frame_len
    }

    /// Returns the maximum declared uncompressed/compressed ratio.
    #[must_use]
    pub const fn max_expansion_ratio(self) -> u32 {
        self.max_expansion_ratio
    }
}

impl Default for CompressionLimits {
    fn default() -> Self {
        Self {
            max_uncompressed_frame_len: MAX_COMPRESSED_FRAME_LEN,
            max_expansion_ratio: DEFAULT_MAX_EXPANSION_RATIO,
        }
    }
}

/// Decoded seven-byte `MySQL` compressed-protocol header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompressedFrameHeader {
    compressed_len: usize,
    sequence: u8,
    uncompressed_len: usize,
}

impl CompressedFrameHeader {
    /// Decodes a complete compressed-protocol header.
    ///
    /// # Errors
    ///
    /// Returns [`CompressionError::TruncatedHeader`] when fewer than seven
    /// bytes are available.
    pub fn decode(input: &[u8]) -> Result<Self, CompressionError> {
        if input.len() < COMPRESSED_HEADER_LEN {
            return Err(CompressionError::TruncatedHeader {
                available: input.len(),
            });
        }
        Ok(Self {
            compressed_len: decode_u24(&input[..3]),
            sequence: input[3],
            uncompressed_len: decode_u24(&input[4..7]),
        })
    }

    /// Encodes a validated compressed-protocol header.
    ///
    /// # Errors
    ///
    /// Returns a typed length error when a value exceeds the 24-bit wire field.
    pub fn new(
        compressed_len: usize,
        sequence: u8,
        uncompressed_len: usize,
    ) -> Result<Self, CompressionError> {
        if compressed_len > MAX_COMPRESSED_FRAME_LEN {
            return Err(CompressionError::FrameLengthTooLarge {
                field: "compressed",
                value: compressed_len,
                max: MAX_COMPRESSED_FRAME_LEN,
            });
        }
        if uncompressed_len > MAX_COMPRESSED_FRAME_LEN {
            return Err(CompressionError::FrameLengthTooLarge {
                field: "uncompressed",
                value: uncompressed_len,
                max: MAX_COMPRESSED_FRAME_LEN,
            });
        }
        Ok(Self {
            compressed_len,
            sequence,
            uncompressed_len,
        })
    }

    /// Returns the body length following the compressed header.
    #[must_use]
    pub const fn compressed_len(self) -> usize {
        self.compressed_len
    }

    /// Returns the independent compressed sequence byte.
    #[must_use]
    pub const fn sequence(self) -> u8 {
        self.sequence
    }

    /// Returns the declared decoded size, or zero for an uncompressed frame.
    #[must_use]
    pub const fn uncompressed_len(self) -> usize {
        self.uncompressed_len
    }

    /// Returns whether this frame carries its body without compression.
    #[must_use]
    pub const fn is_uncompressed(self) -> bool {
        self.uncompressed_len == 0
    }

    /// Encodes this header into its seven-byte wire representation.
    #[must_use]
    pub fn encode(self) -> [u8; COMPRESSED_HEADER_LEN] {
        // `new` and `decode` are the only constructors, so both values are
        // guaranteed to fit the protocol's 24-bit fields.
        let compressed = self.compressed_len.to_le_bytes();
        let uncompressed = self.uncompressed_len.to_le_bytes();
        [
            compressed[0],
            compressed[1],
            compressed[2],
            self.sequence,
            uncompressed[0],
            uncompressed[1],
            uncompressed[2],
        ]
    }
}

/// Failure while configuring, encoding, or decoding compressed frames.
#[derive(Debug, Error)]
pub enum CompressionError {
    /// Zstd was negotiated but the handshake response omitted its level byte.
    #[error("zstd compression capability requires a negotiated level")]
    MissingZstdLevel,
    /// The negotiated zstd level is outside `MySQL`'s supported range.
    #[error("invalid zstd compression level {level}; expected 1..=22")]
    InvalidZstdLevel {
        /// Rejected level.
        level: i32,
    },
    /// The configured frame limit is zero or does not fit the wire field.
    #[error("invalid uncompressed frame limit {value}; expected 1..={max}")]
    InvalidFrameLimit {
        /// Rejected limit.
        value: usize,
        /// Protocol maximum.
        max: usize,
    },
    /// The configured expansion ratio is zero.
    #[error("maximum decompression expansion ratio must be nonzero")]
    InvalidExpansionRatio,
    /// A compressed header is incomplete.
    #[error("truncated compressed header: have {available} bytes, need 7")]
    TruncatedHeader {
        /// Bytes available to the decoder.
        available: usize,
    },
    /// A 24-bit compressed header field cannot represent a value.
    #[error("{field} frame length {value} exceeds {max}")]
    FrameLengthTooLarge {
        /// Stable field name.
        field: &'static str,
        /// Rejected length.
        value: usize,
        /// Effective maximum.
        max: usize,
    },
    /// A frame did not contain exactly the declared body length.
    #[error("compressed body length mismatch: declared {declared}, actual {actual}")]
    BodyLengthMismatch {
        /// Header declaration.
        declared: usize,
        /// Supplied body bytes.
        actual: usize,
    },
    /// The peer's compressed sequence is not the expected shared sequence.
    #[error("compressed sequence mismatch: expected {expected}, actual {actual}")]
    SequenceMismatch {
        /// Locally expected sequence.
        expected: u8,
        /// Sequence received from the peer.
        actual: u8,
    },
    /// A compressed frame exceeds the configured materialization limit.
    #[error("uncompressed frame length {actual} exceeds configured limit {limit}")]
    UncompressedFrameTooLarge {
        /// Configured limit.
        limit: usize,
        /// Declared or raw frame length.
        actual: usize,
    },
    /// A declared expansion exceeds the configured ratio.
    #[error("declared decompression expansion {uncompressed}/{compressed} exceeds ratio {limit}")]
    ExpansionRatioExceeded {
        /// Compressed body bytes.
        compressed: usize,
        /// Declared decoded bytes.
        uncompressed: usize,
        /// Configured maximum ratio.
        limit: u32,
    },
    /// A codec failed to encode or decode a frame.
    #[error("{algorithm} {operation} failed: {detail}")]
    Codec {
        /// Selected codec.
        algorithm: CompressionAlgorithm,
        /// Stable operation name.
        operation: &'static str,
        /// Bounded library error description.
        detail: String,
    },
    /// A zstd frame declares a history window above the configured bound.
    #[error("zstd history window {actual} exceeds configured limit {limit}")]
    ZstdWindowTooLarge {
        /// Configured maximum window allocation.
        limit: usize,
        /// Declared window bytes.
        actual: u64,
    },
    /// zlib returned an I/O-shaped codec error.
    #[error("zlib {operation} failed: {source}")]
    Zlib {
        /// Stable operation name.
        operation: &'static str,
        /// Codec error.
        #[source]
        source: io::Error,
    },
    /// Decoded bytes differ from the compressed header declaration.
    #[error("decoded length mismatch: declared {declared}, actual {actual}")]
    DecodedLengthMismatch {
        /// Header declaration.
        declared: usize,
        /// Bytes produced by the codec.
        actual: usize,
    },
    /// A direction-specific operation was attempted without its `BeginRW` hook.
    #[error("compressed transport {attempted} attempted before begin_{attempted}")]
    DirectionNotBegun {
        /// Attempted direction.
        attempted: CompressionDirection,
    },
    /// A write-to-read transition would strand buffered output.
    #[error("cannot begin compressed read with {buffered} buffered output bytes")]
    PendingWriteOnReadTransition {
        /// Bytes not yet handed completely to the underlying transport.
        buffered: usize,
    },
    /// A read-to-write transition would discard decompressed response bytes.
    #[error("cannot begin compressed write with {buffered} unread decoded bytes")]
    PendingReadOnWriteTransition {
        /// Decoded bytes not consumed by the packet layer.
        buffered: usize,
    },
}

/// Sans-I/O frame codec and shared read/write compressed sequence.
#[derive(Debug)]
pub struct CompressionCodec {
    algorithm: CompressionAlgorithm,
    limits: CompressionLimits,
    sequence: u8,
    direction: Option<CompressionDirection>,
}

impl CompressionCodec {
    /// Creates a codec with compressed sequence zero.
    ///
    /// # Errors
    ///
    /// Returns a typed error for an invalid zstd level.
    pub fn new(
        algorithm: CompressionAlgorithm,
        limits: CompressionLimits,
    ) -> Result<Self, CompressionError> {
        Ok(Self {
            algorithm: algorithm.validate()?,
            limits,
            sequence: 0,
            direction: None,
        })
    }

    /// Returns the selected compression algorithm.
    #[must_use]
    pub const fn algorithm(&self) -> CompressionAlgorithm {
        self.algorithm
    }

    /// Returns the active limits.
    #[must_use]
    pub const fn limits(&self) -> CompressionLimits {
        self.limits
    }

    /// Returns the next shared compressed sequence.
    #[must_use]
    pub const fn sequence(&self) -> u8 {
        self.sequence
    }

    /// Returns the current packet-I/O direction, if begun.
    #[must_use]
    pub const fn direction(&self) -> Option<CompressionDirection> {
        self.direction
    }

    /// Resets compressed sequence and `BeginRW` direction at a command boundary.
    ///
    /// The caller must first finish the current packet operation and drain any
    /// async adapter buffers. Resetting a partially read or buffered frame is
    /// not a recovery mechanism; framing errors make that connection unusable.
    pub const fn reset_sequence(&mut self) {
        self.sequence = 0;
        self.direction = None;
    }

    /// Begins a packet-I/O direction.
    ///
    /// On a direction change, returns the compressed sequence that the
    /// uncompressed packet reader/writer must adopt. Repeating the same
    /// direction returns `None`, preserving that packet layer's own progress.
    pub fn begin(&mut self, direction: CompressionDirection) -> Option<u8> {
        if self.direction == Some(direction) {
            return None;
        }
        self.direction = Some(direction);
        Some(self.sequence)
    }

    /// Encodes one body and advances the shared compressed sequence.
    ///
    /// Inputs below 50 bytes are emitted raw. Larger bodies are compressed even
    /// when the result is not smaller, matching Go `TiProxy`. The sole fallback
    /// is a compressed result that no longer fits 24 bits; the original body is
    /// then emitted raw so the header cannot truncate.
    ///
    /// # Errors
    ///
    /// Returns a typed size or codec error.
    pub fn encode_frame(&mut self, data: &[u8]) -> Result<Vec<u8>, CompressionError> {
        if data.len() > self.limits.max_uncompressed_frame_len {
            return Err(CompressionError::UncompressedFrameTooLarge {
                limit: self.limits.max_uncompressed_frame_len,
                actual: data.len(),
            });
        }

        let compressed = if data.len() >= MIN_COMPRESS_LEN {
            Some(self.compress(data)?)
        } else {
            None
        };
        let (body, uncompressed_len) = match compressed {
            Some(body) if body.len() <= MAX_COMPRESSED_FRAME_LEN => (body, data.len()),
            Some(_) | None => (data.to_vec(), 0),
        };
        let header = CompressedFrameHeader::new(body.len(), self.sequence, uncompressed_len)?;
        let mut frame = Vec::with_capacity(COMPRESSED_HEADER_LEN + body.len());
        frame.extend_from_slice(&header.encode());
        frame.extend_from_slice(&body);
        self.sequence = self.sequence.wrapping_add(1);
        Ok(frame)
    }

    /// Decodes exactly one header-plus-body frame and advances the sequence.
    ///
    /// # Errors
    ///
    /// Returns typed sequence, length, bound, or codec errors. After a valid
    /// sequence byte is accepted, the sequence advances even if the body later
    /// proves malformed, matching Go `TiProxy`'s observable state transition.
    pub fn decode_frame(&mut self, frame: &[u8]) -> Result<Vec<u8>, CompressionError> {
        let header = CompressedFrameHeader::decode(frame)?;
        self.accept_header(header)?;
        let body = frame
            .get(COMPRESSED_HEADER_LEN..)
            .ok_or(CompressionError::TruncatedHeader {
                available: frame.len(),
            })?;
        if body.len() != header.compressed_len {
            return Err(CompressionError::BodyLengthMismatch {
                declared: header.compressed_len,
                actual: body.len(),
            });
        }
        self.decode_body(header, body)
    }

    fn accept_header(&mut self, header: CompressedFrameHeader) -> Result<(), CompressionError> {
        if header.sequence != self.sequence {
            return Err(CompressionError::SequenceMismatch {
                expected: self.sequence,
                actual: header.sequence,
            });
        }
        self.sequence = self.sequence.wrapping_add(1);

        let materialized = if header.is_uncompressed() {
            header.compressed_len
        } else {
            header.uncompressed_len
        };
        if materialized > self.limits.max_uncompressed_frame_len {
            return Err(CompressionError::UncompressedFrameTooLarge {
                limit: self.limits.max_uncompressed_frame_len,
                actual: materialized,
            });
        }
        if !header.is_uncompressed()
            && header.uncompressed_len
                > header
                    .compressed_len
                    .saturating_mul(self.limits.max_expansion_ratio as usize)
        {
            return Err(CompressionError::ExpansionRatioExceeded {
                compressed: header.compressed_len,
                uncompressed: header.uncompressed_len,
                limit: self.limits.max_expansion_ratio,
            });
        }
        Ok(())
    }

    fn decode_body(
        &self,
        header: CompressedFrameHeader,
        body: &[u8],
    ) -> Result<Vec<u8>, CompressionError> {
        if header.is_uncompressed() {
            return Ok(body.to_vec());
        }
        let decoded = match self.algorithm {
            CompressionAlgorithm::Zlib => decode_zlib(body, header.uncompressed_len)?,
            CompressionAlgorithm::Zstd { .. } => decode_zstd(
                body,
                header.uncompressed_len,
                self.limits.max_uncompressed_frame_len,
                self.algorithm,
            )?,
        };
        if decoded.len() != header.uncompressed_len {
            return Err(CompressionError::DecodedLengthMismatch {
                declared: header.uncompressed_len,
                actual: decoded.len(),
            });
        }
        Ok(decoded)
    }

    fn compress(&self, data: &[u8]) -> Result<Vec<u8>, CompressionError> {
        match self.algorithm {
            CompressionAlgorithm::Zlib => encode_zlib(data),
            CompressionAlgorithm::Zstd { level } => encode_zstd(data, level),
        }
    }

    fn require_direction(&self, attempted: CompressionDirection) -> Result<(), CompressionError> {
        if self.direction != Some(attempted) {
            return Err(CompressionError::DirectionNotBegun { attempted });
        }
        Ok(())
    }
}

/// Async compressed transport over a single client or backend byte stream.
///
/// Reads and writes share the compressed sequence. The type intentionally does
/// not expose its buffered wire bytes through `Debug`.
pub struct CompressedIo<T> {
    inner: T,
    codec: CompressionCodec,
    read_header: [u8; COMPRESSED_HEADER_LEN],
    read_header_filled: usize,
    read_frame_header: Option<CompressedFrameHeader>,
    read_body: Vec<u8>,
    read_body_filled: usize,
    read_decoded: Vec<u8>,
    read_decoded_offset: usize,
    read_eof: bool,
    read_failed: bool,
    write_buffer: Vec<u8>,
    pending_write: Vec<u8>,
    pending_write_offset: usize,
}

impl<T> CompressedIo<T> {
    /// Wraps a transport in bounded compressed framing.
    ///
    /// # Errors
    ///
    /// Returns a typed error for an invalid compression configuration.
    pub fn new(
        inner: T,
        algorithm: CompressionAlgorithm,
        limits: CompressionLimits,
    ) -> Result<Self, CompressionError> {
        Ok(Self {
            inner,
            codec: CompressionCodec::new(algorithm, limits)?,
            read_header: [0; COMPRESSED_HEADER_LEN],
            read_header_filled: 0,
            read_frame_header: None,
            read_body: Vec::new(),
            read_body_filled: 0,
            read_decoded: Vec::new(),
            read_decoded_offset: 0,
            read_eof: false,
            read_failed: false,
            write_buffer: Vec::new(),
            pending_write: Vec::new(),
            pending_write_offset: 0,
        })
    }

    /// Returns the underlying transport.
    ///
    /// The caller must first consume all decoded bytes and flush all buffered
    /// output. This ownership escape intentionally does not synthesize I/O.
    #[must_use]
    pub fn into_inner(self) -> T {
        self.inner
    }

    /// Returns a shared reference to the underlying transport.
    #[must_use]
    pub const fn get_ref(&self) -> &T {
        &self.inner
    }

    /// Returns a mutable reference to the underlying transport.
    ///
    /// Callers must not bypass framing while compressed bytes are buffered.
    #[must_use]
    pub fn get_mut(&mut self) -> &mut T {
        &mut self.inner
    }

    /// Returns the sans-I/O codec and sequence state.
    #[must_use]
    pub const fn codec(&self) -> &CompressionCodec {
        &self.codec
    }

    /// Begins reading and returns a packet-sequence reset on direction change.
    ///
    /// # Errors
    ///
    /// Rejects a transition that would strand buffered compressed output.
    pub fn begin_read(&mut self) -> Result<Option<u8>, CompressionError> {
        if self.codec.direction() == Some(CompressionDirection::Write) {
            let buffered = self.write_buffer.len().saturating_add(
                self.pending_write
                    .len()
                    .saturating_sub(self.pending_write_offset),
            );
            if buffered > 0 {
                return Err(CompressionError::PendingWriteOnReadTransition { buffered });
            }
        }
        Ok(self.codec.begin(CompressionDirection::Read))
    }

    /// Begins writing and returns a packet-sequence reset on direction change.
    ///
    /// # Errors
    ///
    /// Rejects a transition that would discard unread decompressed bytes.
    pub fn begin_write(&mut self) -> Result<Option<u8>, CompressionError> {
        if self.codec.direction() == Some(CompressionDirection::Read) {
            let buffered = self
                .read_decoded
                .len()
                .saturating_sub(self.read_decoded_offset);
            if buffered > 0 {
                return Err(CompressionError::PendingReadOnWriteTransition { buffered });
            }
        }
        Ok(self.codec.begin(CompressionDirection::Write))
    }

    /// Resets compressed sequence and direction at a clean command boundary.
    ///
    /// Call this only after the packet layer consumed the response and flushed
    /// the request; it does not discard or reinterpret buffered frame bytes.
    pub const fn reset_sequence(&mut self) {
        self.codec.reset_sequence();
    }

    /// Returns currently buffered uncompressed output bytes.
    #[must_use]
    pub fn buffered_write_len(&self) -> usize {
        self.write_buffer.len().saturating_add(
            self.pending_write
                .len()
                .saturating_sub(self.pending_write_offset),
        )
    }

    /// Returns currently readable decompressed bytes.
    #[must_use]
    pub fn buffered_read_len(&self) -> usize {
        self.read_decoded
            .len()
            .saturating_sub(self.read_decoded_offset)
    }

    fn reset_decoded_buffer(&mut self) {
        if self.read_decoded.capacity() > RETAINED_BUFFER_CAPACITY {
            self.read_decoded = Vec::new();
        } else {
            self.read_decoded.clear();
        }
        self.read_decoded_offset = 0;
    }

    fn poll_fill_decoded(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<bool>>
    where
        T: AsyncRead + Unpin,
    {
        if self.read_failed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "compressed reader is unusable after a framing error",
            )));
        }
        if let Err(error) = self.codec.require_direction(CompressionDirection::Read) {
            return Poll::Ready(Err(invalid_data(error)));
        }

        loop {
            if self.read_decoded_offset < self.read_decoded.len() {
                return Poll::Ready(Ok(true));
            }
            if !self.read_decoded.is_empty() {
                self.reset_decoded_buffer();
            }
            if self.read_eof {
                return Poll::Ready(Ok(false));
            }

            if self.read_header_filled < COMPRESSED_HEADER_LEN {
                let before = self.read_header_filled;
                let mut buffer = ReadBuf::new(&mut self.read_header[before..]);
                match Pin::new(&mut self.inner).poll_read(cx, &mut buffer) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Ready(Ok(())) => {
                        let read = buffer.filled().len();
                        if read == 0 {
                            if before == 0 {
                                self.read_eof = true;
                                return Poll::Ready(Ok(false));
                            }
                            self.read_failed = true;
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "truncated compressed header",
                            )));
                        }
                        self.read_header_filled += read;
                        continue;
                    }
                }
            }

            if self.read_frame_header.is_none() {
                let header =
                    match CompressedFrameHeader::decode(&self.read_header).and_then(|header| {
                        self.codec.accept_header(header)?;
                        Ok(header)
                    }) {
                        Ok(header) => header,
                        Err(error) => {
                            self.read_failed = true;
                            return Poll::Ready(Err(invalid_data(error)));
                        }
                    };
                self.read_body = vec![0; header.compressed_len];
                self.read_body_filled = 0;
                self.read_frame_header = Some(header);
            }

            if self.read_body_filled < self.read_body.len() {
                let before = self.read_body_filled;
                let mut buffer = ReadBuf::new(&mut self.read_body[before..]);
                match Pin::new(&mut self.inner).poll_read(cx, &mut buffer) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Ready(Ok(())) => {
                        let read = buffer.filled().len();
                        if read == 0 {
                            self.read_failed = true;
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "truncated compressed body",
                            )));
                        }
                        self.read_body_filled += read;
                        continue;
                    }
                }
            }

            let Some(header) = self.read_frame_header.take() else {
                self.read_failed = true;
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "missing decoded compressed header",
                )));
            };
            let body = std::mem::take(&mut self.read_body);
            self.read_body_filled = 0;
            self.read_header_filled = 0;
            match self.codec.decode_body(header, &body) {
                Ok(decoded) => self.read_decoded = decoded,
                Err(error) => {
                    self.read_failed = true;
                    return Poll::Ready(Err(invalid_data(error)));
                }
            }
        }
    }

    fn build_pending_write(&mut self) -> io::Result<()> {
        if self.write_buffer.is_empty() {
            return Ok(());
        }
        let data = std::mem::take(&mut self.write_buffer);
        self.pending_write = self.codec.encode_frame(&data).map_err(invalid_data)?;
        self.pending_write_offset = 0;
        Ok(())
    }

    fn finish_pending_write(&mut self) {
        if self.pending_write.capacity() > RETAINED_BUFFER_CAPACITY {
            self.pending_write = Vec::new();
        } else {
            self.pending_write.clear();
        }
        self.pending_write_offset = 0;
    }

    fn poll_drain_pending(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>>
    where
        T: AsyncWrite + Unpin,
    {
        while self.pending_write_offset < self.pending_write.len() {
            let bytes = &self.pending_write[self.pending_write_offset..];
            match Pin::new(&mut self.inner).poll_write(cx, bytes) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "underlying transport accepted no compressed bytes",
                    )));
                }
                Poll::Ready(Ok(written)) => self.pending_write_offset += written,
            }
        }
        if !self.pending_write.is_empty() {
            self.finish_pending_write();
        }
        Poll::Ready(Ok(()))
    }
}

impl<T> fmt::Debug for CompressedIo<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompressedIo")
            .field("algorithm", &self.codec.algorithm())
            .field("limits", &self.codec.limits())
            .field("sequence", &self.codec.sequence())
            .field("direction", &self.codec.direction())
            .field("buffered_read_len", &self.buffered_read_len())
            .field("buffered_write_len", &self.buffered_write_len())
            .field("read_eof", &self.read_eof)
            .field("read_failed", &self.read_failed)
            .finish_non_exhaustive()
    }
}

impl<T> AsyncRead for CompressedIo<T>
where
    T: AsyncRead + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        destination: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if destination.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        match this.poll_fill_decoded(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Ready(Ok(false)) => Poll::Ready(Ok(())),
            Poll::Ready(Ok(true)) => {
                let available = &this.read_decoded[this.read_decoded_offset..];
                let copied = available.len().min(destination.remaining());
                destination.put_slice(&available[..copied]);
                this.read_decoded_offset += copied;
                Poll::Ready(Ok(()))
            }
        }
    }
}

impl<T> AsyncWrite for CompressedIo<T>
where
    T: AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        source: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if let Err(error) = this.codec.require_direction(CompressionDirection::Write) {
            return Poll::Ready(Err(invalid_data(error)));
        }
        match this.poll_drain_pending(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => {}
        }
        if source.is_empty() {
            return Poll::Ready(Ok(0));
        }

        if this.write_buffer.len() == this.codec.limits.max_uncompressed_frame_len {
            if let Err(error) = this.build_pending_write() {
                return Poll::Ready(Err(error));
            }
            return match this.poll_drain_pending(cx) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) => Self::poll_write(Pin::new(this), cx, source),
            };
        }

        let remaining = this
            .codec
            .limits
            .max_uncompressed_frame_len
            .saturating_sub(this.write_buffer.len());
        let accepted = remaining.min(source.len());
        this.write_buffer.extend_from_slice(&source[..accepted]);
        if this.write_buffer.len() == this.codec.limits.max_uncompressed_frame_len
            && let Err(error) = this.build_pending_write()
        {
            return Poll::Ready(Err(error));
        }
        Poll::Ready(Ok(accepted))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Err(error) = this.codec.require_direction(CompressionDirection::Write) {
            return Poll::Ready(Err(invalid_data(error)));
        }
        loop {
            match this.poll_drain_pending(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) => {}
            }
            if this.write_buffer.is_empty() {
                return Pin::new(&mut this.inner).poll_flush(cx);
            }
            if let Err(error) = this.build_pending_write() {
                return Poll::Ready(Err(error));
            }
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match AsyncWrite::poll_flush(self.as_mut(), cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => Pin::new(&mut self.get_mut().inner).poll_shutdown(cx),
        }
    }
}

fn encode_zlib(data: &[u8]) -> Result<Vec<u8>, CompressionError> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::new(ZLIB_COMPRESSION_LEVEL));
    encoder
        .write_all(data)
        .map_err(|source| CompressionError::Zlib {
            operation: "compression",
            source,
        })?;
    encoder.finish().map_err(|source| CompressionError::Zlib {
        operation: "compression finalization",
        source,
    })
}

fn decode_zlib(data: &[u8], expected: usize) -> Result<Vec<u8>, CompressionError> {
    let mut decoder = ZlibDecoder::new(data);
    let mut output = Vec::with_capacity(expected.saturating_add(1));
    decoder
        .by_ref()
        .take(
            u64::try_from(expected)
                .unwrap_or(u64::MAX)
                .saturating_add(1),
        )
        .read_to_end(&mut output)
        .map_err(|source| CompressionError::Zlib {
            operation: "decompression",
            source,
        })?;
    let consumed = usize::try_from(decoder.total_in()).unwrap_or(usize::MAX);
    if consumed != data.len() {
        return Err(CompressionError::BodyLengthMismatch {
            declared: consumed,
            actual: data.len(),
        });
    }
    Ok(output)
}

fn encode_zstd(data: &[u8], level: i32) -> Result<Vec<u8>, CompressionError> {
    let algorithm = CompressionAlgorithm::Zstd { level };
    let bound = ZSTD_compressBound(data.len());
    if ZSTD_isError(bound) {
        return Err(zstd_error("compression bound", bound, algorithm));
    }
    let mut encoded = vec![0; bound];
    let size = ZSTD_compress(&mut encoded, data, level);
    if ZSTD_isError(size) {
        return Err(zstd_error("compression", size, algorithm));
    }
    encoded.truncate(size);
    Ok(encoded)
}

fn decode_zstd(
    data: &[u8],
    expected: usize,
    max_window: usize,
    algorithm: CompressionAlgorithm,
) -> Result<Vec<u8>, CompressionError> {
    let history_len = validate_zstd_header(data, expected, max_window, algorithm)?;

    // The network-facing decoder is deliberately separate from the encoder:
    // zstd-zero forbids unsafe code and cannot allocate. The configured frame
    // limit bounds its history allocation, the two scratch buffers are fixed,
    // and the output Vec never grows beyond the MySQL header declaration.
    let mut history = vec![0; history_len];
    let mut block = vec![0; MAX_BLOCK_SIZE];
    let mut literals = vec![0; MAX_BLOCK_SIZE];
    let mut decoder = ZstdDecoder::new(ZstdDecoderBuffers {
        history: &mut history,
        block: &mut block,
        literals: &mut literals,
    });
    drive_zstd_decoder(&mut decoder, data, expected, algorithm)
}

fn validate_zstd_header(
    data: &[u8],
    expected: usize,
    max_window: usize,
    algorithm: CompressionAlgorithm,
) -> Result<usize, CompressionError> {
    let header =
        match inspect_zstd_frame(data).map_err(|error| zstd_decode_error(error, algorithm))? {
            ZstdHeaderStatus::Complete {
                header: ZstdStreamHeader::Zstandard(header),
                ..
            } => header,
            ZstdHeaderStatus::Complete {
                header: ZstdStreamHeader::Skippable { .. },
                ..
            } => {
                return Err(CompressionError::Codec {
                    algorithm,
                    operation: "frame validation",
                    detail: "skippable zstd frames are not MySQL payload frames".to_owned(),
                });
            }
            ZstdHeaderStatus::NeedMore { .. } => {
                return Err(CompressionError::Codec {
                    algorithm,
                    operation: "frame validation",
                    detail: "truncated zstd frame header".to_owned(),
                });
            }
        };
    if header.dictionary_id != 0 {
        return Err(CompressionError::Codec {
            algorithm,
            operation: "frame validation",
            detail: "zstd dictionaries are not negotiated by MySQL".to_owned(),
        });
    }
    if let Some(content_size) = header.content_size {
        let declared = usize::try_from(content_size).unwrap_or(usize::MAX);
        if declared != expected {
            return Err(CompressionError::DecodedLengthMismatch {
                declared: expected,
                actual: declared,
            });
        }
    }
    if header.window_size > max_window as u64 {
        return Err(CompressionError::ZstdWindowTooLarge {
            limit: max_window,
            actual: header.window_size,
        });
    }
    Ok(usize::try_from(header.window_size)
        .unwrap_or(usize::MAX)
        .max(1))
}

fn drive_zstd_decoder(
    decoder: &mut ZstdDecoder<'_>,
    data: &[u8],
    expected: usize,
    algorithm: CompressionAlgorithm,
) -> Result<Vec<u8>, CompressionError> {
    let mut output = Vec::with_capacity(expected);
    let mut remaining = data;
    let mut frames_started = 0_u8;
    let mut frames_finished = 0_u8;
    let mut idle_steps = 0_u8;

    while !remaining.is_empty() {
        let step = decoder
            .decode(remaining)
            .map_err(|error| zstd_decode_error(error, algorithm))?;
        let consumed = step.consumed();
        if consumed > remaining.len() {
            return Err(zstd_stalled_error(algorithm));
        }
        let produced = handle_zstd_step(
            &step,
            expected,
            &mut output,
            &mut frames_started,
            &mut frames_finished,
            algorithm,
        )?;
        remaining = &remaining[consumed..];
        if consumed != 0 || produced {
            idle_steps = 0;
        } else {
            idle_steps = idle_steps.saturating_add(1);
            if idle_steps > 16 {
                return Err(zstd_stalled_error(algorithm));
            }
        }
    }

    loop {
        let step = decoder
            .decode(&[])
            .map_err(|error| zstd_decode_error(error, algorithm))?;
        if matches!(step, ZstdDecodeStep::NeedInput { .. }) {
            break;
        }
        let produced = handle_zstd_step(
            &step,
            expected,
            &mut output,
            &mut frames_started,
            &mut frames_finished,
            algorithm,
        )?;
        if produced {
            idle_steps = 0;
        } else {
            idle_steps = idle_steps.saturating_add(1);
            if idle_steps > 16 {
                return Err(zstd_stalled_error(algorithm));
            }
        }
    }
    decoder
        .finish()
        .map_err(|error| zstd_decode_error(error, algorithm))?;
    if frames_started != 1 || frames_finished != 1 {
        return Err(CompressionError::Codec {
            algorithm,
            operation: "frame validation",
            detail: "expected exactly one complete zstd frame".to_owned(),
        });
    }
    Ok(output)
}

fn handle_zstd_step(
    step: &ZstdDecodeStep<'_>,
    expected: usize,
    decoded: &mut Vec<u8>,
    frames_started: &mut u8,
    frames_finished: &mut u8,
    algorithm: CompressionAlgorithm,
) -> Result<bool, CompressionError> {
    match step {
        ZstdDecodeStep::FrameStarted {
            header: ZstdStreamHeader::Zstandard(_),
            ..
        } => {
            *frames_started = frames_started.saturating_add(1);
            if *frames_started != 1 {
                return Err(CompressionError::Codec {
                    algorithm,
                    operation: "frame validation",
                    detail: "multiple zstd frames in one MySQL compressed body".to_owned(),
                });
            }
            Ok(false)
        }
        ZstdDecodeStep::FrameStarted {
            header: ZstdStreamHeader::Skippable { .. },
            ..
        }
        | ZstdDecodeStep::FrameFinished {
            kind: ZstdFrameKind::Skippable { .. },
            ..
        } => Err(CompressionError::Codec {
            algorithm,
            operation: "frame validation",
            detail: "skippable zstd frames are not MySQL payload frames".to_owned(),
        }),
        ZstdDecodeStep::Output { bytes, .. } => {
            let actual = decoded.len().saturating_add(bytes.len());
            if actual > expected {
                return Err(CompressionError::DecodedLengthMismatch {
                    declared: expected,
                    actual,
                });
            }
            decoded.extend_from_slice(bytes);
            Ok(!bytes.is_empty())
        }
        ZstdDecodeStep::FrameFinished {
            kind: ZstdFrameKind::Zstandard,
            ..
        } => {
            *frames_finished = frames_finished.saturating_add(1);
            if *frames_finished != 1 {
                return Err(CompressionError::Codec {
                    algorithm,
                    operation: "frame validation",
                    detail: "multiple zstd frames in one MySQL compressed body".to_owned(),
                });
            }
            Ok(false)
        }
        ZstdDecodeStep::NeedInput { .. } => Ok(false),
    }
}

fn zstd_decode_error(
    error: zstd_zero::DecodeError,
    algorithm: CompressionAlgorithm,
) -> CompressionError {
    CompressionError::Codec {
        algorithm,
        operation: "decompression",
        detail: error.to_string(),
    }
}

fn zstd_stalled_error(algorithm: CompressionAlgorithm) -> CompressionError {
    CompressionError::Codec {
        algorithm,
        operation: "decompression",
        detail: "safe decoder stopped making progress".to_owned(),
    }
}

fn zstd_error(
    operation: &'static str,
    code: usize,
    algorithm: CompressionAlgorithm,
) -> CompressionError {
    CompressionError::Codec {
        algorithm,
        operation,
        detail: ZSTD_getErrorName(code).to_owned(),
    }
}

fn decode_u24(input: &[u8]) -> usize {
    usize::from(input[0]) | (usize::from(input[1]) << 8) | (usize::from(input[2]) << 16)
}

fn invalid_data(error: CompressionError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}
