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

//! WIRE-C compression sequence-bridge regressions at the `PacketIo<compressed>`
//! and `CompressedIo` codec level.
//!
//! These lock the four sequence-bridge fixes deterministically, without racing
//! the real engine `select`:
//!
//! * A command-boundary reset FAILS CLOSED while a frame is in flight (a
//!   partially read header/body, unread decoded bytes, or pending output),
//!   instead of silently rewinding the shared compressed sequence.
//! * The guarded control-interleave path (the engine's `just_served_control`
//!   flag) does NOT reset a next command whose compressed frame a `peek_packet`
//!   already decoded and staged: the response is emitted at compressed sequence
//!   1, not 0.
//! * An empty flush after a read (or at shutdown) is a no-op that returns `Ok`.
//!
//! `PacketIo<T>` requires `T: DirectionSync`, but `CompressedIo`'s inherent
//! `begin_read`/`begin_write` SHADOW (rather than implement) that trait, so a
//! bare `PacketIo<CompressedIo<_>>` cannot compile. [`CompressedTransport`] is a
//! test-only newtype that impls `DirectionSync` by delegating to the SAME
//! inherent `CompressedIo` hooks the production `dataplane::transport` variants
//! delegate to (mapping `CompressionError` -> `io::Error`).

use std::error::Error;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, Waker};

use proxy_io::PacketIo;
use proxy_io::compression::{
    CompressedFrameHeader, CompressedIo, CompressionAlgorithm, CompressionCodec, CompressionError,
    CompressionLimits,
};
use proxy_io::direction::DirectionSync;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

type TestResult = Result<(), Box<dyn Error>>;

/// Maps a codec error into a transport `io::Error`, mirroring the production
/// `dataplane::transport` helper so the packet layer's hooks can fail closed.
fn compression_io_error(error: CompressionError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

/// Whether an `io::Error` wraps [`CompressionError::ResetWithBufferedData`].
fn is_reset_with_buffered(error: &io::Error) -> bool {
    error
        .get_ref()
        .and_then(|source| source.downcast_ref::<CompressionError>())
        .is_some_and(|source| matches!(source, CompressionError::ResetWithBufferedData { .. }))
}

/// One `MySQL` physical packet carrying `payload` at physical sequence `seq`.
fn mysql_packet(payload: &[u8], seq: u8) -> Vec<u8> {
    let length = u32::try_from(payload.len()).unwrap_or(0).to_le_bytes();
    let mut packet = Vec::with_capacity(4 + payload.len());
    packet.extend_from_slice(&length[..3]);
    packet.push(seq);
    packet.extend_from_slice(payload);
    packet
}

/// One `MySQL` physical packet wrapped in one compressed frame at compressed
/// sequence zero — the wire a client's next command presents on a compressed leg.
fn command_frame(
    algorithm: CompressionAlgorithm,
    payload: &[u8],
) -> Result<Vec<u8>, CompressionError> {
    let mut codec = CompressionCodec::new(algorithm, CompressionLimits::default())?;
    codec.encode_frame(&mysql_packet(payload, 0))
}

// ---------------------------------------------------------------------
// Test transports
// ---------------------------------------------------------------------

/// An in-memory duplex byte transport: reads drain `input`, writes append to
/// `output`. Serves the `PacketIo<compressed>` read-then-write flow with a
/// single shared `CompressedIo` sequence.
struct DuplexBytes {
    input: Vec<u8>,
    input_pos: usize,
    output: Vec<u8>,
}

impl DuplexBytes {
    fn new(input: Vec<u8>) -> Self {
        Self {
            input,
            input_pos: 0,
            output: Vec::new(),
        }
    }
}

impl AsyncRead for DuplexBytes {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let available = self.input.len().saturating_sub(self.input_pos);
        let take = available.min(buf.remaining());
        let end = self.input_pos + take;
        let chunk = self.input[self.input_pos..end].to_vec();
        buf.put_slice(&chunk);
        self.input_pos = end;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for DuplexBytes {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.output.extend_from_slice(data);
        Poll::Ready(Ok(data.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// A read-only transport that only releases `released` bytes of `data`; a read
/// beyond that stalls with `Poll::Pending`. This deterministically stages a
/// partially read compressed header or body inside `CompressedIo` so the
/// fail-closed reset branches can be observed without racing.
struct GatedReader {
    data: Vec<u8>,
    pos: usize,
    released: usize,
}

impl AsyncRead for GatedReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let available = self.released.saturating_sub(self.pos);
        if available == 0 {
            if self.pos >= self.data.len() {
                return Poll::Ready(Ok(()));
            }
            return Poll::Pending;
        }
        let take = available.min(buf.remaining());
        let end = self.pos + take;
        let chunk = self.data[self.pos..end].to_vec();
        buf.put_slice(&chunk);
        self.pos = end;
        Poll::Ready(Ok(()))
    }
}

/// Test-only `DirectionSync` newtype over `CompressedIo<DuplexBytes>`, forwarding
/// to the same inherent codec hooks the production transport variants drive.
struct CompressedTransport {
    inner: CompressedIo<DuplexBytes>,
}

impl AsyncRead for CompressedTransport {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(context, buf)
    }
}

impl AsyncWrite for CompressedTransport {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(context, data)
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(context)
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(context)
    }
}

impl DirectionSync for CompressedTransport {
    fn begin_read(&mut self) -> io::Result<Option<u8>> {
        self.inner.begin_read().map_err(compression_io_error)
    }

    fn begin_write(&mut self) -> io::Result<Option<u8>> {
        self.inner.begin_write().map_err(compression_io_error)
    }

    fn reset_layer_sequence(&mut self) -> io::Result<()> {
        self.inner.reset_sequence().map_err(compression_io_error)
    }
}

fn compressed_packet_io(input: Vec<u8>, algorithm: CompressionAlgorithm) -> TestResult2 {
    let compressed = CompressedIo::new(
        DuplexBytes::new(input),
        algorithm,
        CompressionLimits::default(),
    )?;
    Ok(PacketIo::new(CompressedTransport { inner: compressed }))
}

type TestResult2 = Result<PacketIo<CompressedTransport>, CompressionError>;

// ---------------------------------------------------------------------
// A. Reset fails closed on in-flight data; succeeds on a clean boundary.
// ---------------------------------------------------------------------

/// A command-boundary reset must fail closed on any in-flight frame state and
/// only succeed once the boundary is clean — never a silent rewind of the
/// shared compressed sequence over live command bytes.
#[tokio::test]
async fn reset_fails_closed_on_in_flight_and_succeeds_on_clean_boundary() -> TestResult {
    let algorithm = CompressionAlgorithm::Zlib;
    let limits = CompressionLimits::default();

    // (1) Staged decoded bytes after a `peek_packet`: the codec advanced to
    // sequence 1 and the decoded command is buffered, so the reset fails closed.
    let mut peeked = compressed_packet_io(command_frame(algorithm, b"\x03SELECT 1")?, algorithm)?;
    let preview = peeked.peek_packet().await?;
    assert_eq!(preview.first_byte, Some(0x03));
    let reset = peeked.get_mut().reset_layer_sequence();
    let error = reset
        .err()
        .ok_or("reset must fail closed on staged decoded bytes")?;
    assert!(is_reset_with_buffered(&error));

    // (2) Pending write output: buffered-but-unflushed bytes fail closed too.
    let mut writer = CompressedIo::new(Vec::new(), algorithm, limits)?;
    writer.begin_write()?;
    writer.write_all(b"a partial buffered command body").await?;
    assert!(writer.buffered_write_len() > 0);
    assert!(matches!(
        writer.reset_sequence(),
        Err(CompressionError::ResetWithBufferedData { .. })
    ));

    // (3) A fully consumed read is a clean boundary: reset succeeds and rewinds
    // to sequence 0 for the next command.
    let frame = command_frame(algorithm, b"\x03SELECT 1")?;
    let decoded_len = {
        let mut codec = CompressionCodec::new(algorithm, limits)?;
        codec.decode_frame(&frame)?.len()
    };
    let mut reader = CompressedIo::new(frame.as_slice(), algorithm, limits)?;
    reader.begin_read()?;
    let mut sink = vec![0_u8; decoded_len];
    reader.read_exact(&mut sink).await?;
    assert_eq!(reader.buffered_read_len(), 0);
    assert_eq!(reader.codec().sequence(), 1);
    reader.reset_sequence()?;
    assert_eq!(reader.codec().sequence(), 0);

    // (4) A flushed write is a clean boundary as well.
    let mut clean_writer = CompressedIo::new(Vec::new(), algorithm, limits)?;
    clean_writer.begin_write()?;
    clean_writer.write_all(b"\x03SELECT 2").await?;
    clean_writer.flush().await?;
    assert_eq!(clean_writer.buffered_write_len(), 0);
    clean_writer.reset_sequence()?;
    assert_eq!(clean_writer.codec().sequence(), 0);

    // (5) A fresh transport resets trivially.
    let mut fresh = CompressedIo::new(Vec::<u8>::new(), algorithm, limits)?;
    fresh.reset_sequence()?;
    Ok(())
}

// ---------------------------------------------------------------------
// B. No rewind across a control interleave; unguarded reset fails closed.
//    Covers CodexM5 case (a): a fully staged ("ready-peek") next command.
// ---------------------------------------------------------------------

/// The exact scenario `CodexM5` reproduced: a next command's compressed frame is
/// decoded and staged by `peek_packet` (codec sequence -> 1). The engine's
/// `just_served_control` guard SKIPS the reset (an unguarded reset here now
/// fails closed), so the subsequent read + response `write_logical` emit the
/// response at compressed sequence 1, not 0.
#[tokio::test]
async fn ready_peek_interleave_does_not_rewind_and_unguarded_reset_fails_closed() -> TestResult {
    let algorithm = CompressionAlgorithm::Zlib;
    let mut io = compressed_packet_io(command_frame(algorithm, b"\x03SELECT 1")?, algorithm)?;

    // The idle `peek` decoded and staged the next command, advancing the shared
    // compressed sequence to 1.
    let preview = io.peek_packet().await?;
    assert_eq!(preview.first_byte, Some(0x03));

    // The unguarded reset (what a naive re-entry after control activity would
    // do) now fails closed instead of rewinding the staged command to 0. This
    // exercises the PRODUCTION `PacketIo::reset_layer_sequence` the engine calls
    // (not the transport-level `get_mut().reset_layer_sequence()`): it sees the
    // staged command — here in the packet prefetch AND in the compression layer's
    // decoded remainder — and refuses to rewind over live command bytes.
    let reset = io.reset_layer_sequence();
    let error = reset.err().ok_or("the unguarded reset must fail closed")?;
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);

    // The guarded path takes over: read the staged command, then answer.
    let command = io.read_logical(64 * 1024).await?;
    assert_eq!(command.payload, b"\x03SELECT 1");
    io.write_logical(b"\x00\x00\x00\x02\x00\x00\x00", true)
        .await?;

    // The response left the wire as a compressed frame at sequence 1 — proof the
    // shared sequence was not rewound.
    let wire = io.into_inner().inner.into_inner().output;
    let header = CompressedFrameHeader::decode(&wire)?;
    assert_eq!(
        header.sequence(),
        1,
        "the guarded response is emitted at compressed sequence 1, not 0"
    );
    Ok(())
}

/// The prefetch blind spot the `PacketIo`-level reset closes. `COM_PING` has a
/// 1-byte payload, so its whole 5-byte `MySQL` packet (`[0x01,0x00,0x00,0x00,
/// 0x0e]`) is exactly the packet prefetch window: after `peek_packet` ALL five
/// bytes sit in `PacketIo`'s prefetch and `CompressedIo`'s own read buffer is
/// empty. The transport-level reset only inspects the codec's buffer, so it
/// WRONGLY reports a clean boundary — the blind spot — while the production
/// `PacketIo::reset_layer_sequence` also inspects the prefetch and fails closed.
///
/// Unlike `ready_peek_interleave_...` (a multi-byte command that leaves a decoded
/// remainder INSIDE `CompressedIo`, so even the transport reset fails), here the
/// codec buffer is genuinely empty; only the `PacketIo`-level check catches it.
#[tokio::test]
async fn small_command_in_prefetch_only_packet_level_reset_fails_closed() -> TestResult {
    let algorithm = CompressionAlgorithm::Zlib;
    let mut io = compressed_packet_io(command_frame(algorithm, &[0x0e])?, algorithm)?;

    // The idle peek drains the whole COM_PING frame into the packet prefetch; the
    // compression layer's read buffer is now empty.
    let preview = io.peek_packet().await?;
    assert_eq!(preview.first_byte, Some(0x0e));

    // The transport-level reset sees only the (empty) codec buffer, so it wrongly
    // returns Ok — the silent rewind the PacketIo-level check exists to prevent.
    io.get_mut()
        .reset_layer_sequence()
        .map_err(|_| "the transport-level reset sees a clean codec here (the blind spot)")?;

    // The production PacketIo-level reset also inspects the packet prefetch, sees
    // the staged COM_PING, and fails closed.
    let reset = io.reset_layer_sequence();
    let error = reset
        .err()
        .ok_or("the PacketIo-level reset must fail closed on the staged prefetch")?;
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    Ok(())
}

/// `CodexM5` cases (b) partial header staged and (c) partial body staged: a frame
/// that a `peek` could not fully decode still leaves in-flight state that fails
/// a reset closed, and the guarded path (no reset) completes the frame and
/// answers at compressed sequence 1 — never a rewind.
#[test]
fn partial_header_and_body_stage_fail_closed_and_do_not_rewind() -> TestResult {
    let algorithm = CompressionAlgorithm::Zlib;
    let limits = CompressionLimits::default();
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);

    // Each entry is (released prefix bytes, whether the partial header stage is
    // reached before the body). 3 bytes stages a partial 7-byte header; 9 bytes
    // stages a full header plus a partial body.
    for released in [3_usize, 9_usize] {
        let frame = command_frame(algorithm, b"\x03SELECT 1")?;
        let mut io = CompressedIo::new(
            GatedReader {
                data: frame.clone(),
                pos: 0,
                released,
            },
            algorithm,
            limits,
        )?;
        assert_eq!(io.begin_read()?, Some(0));

        // First poll stalls mid-frame with only `released` bytes available.
        let mut store = [0_u8; 64];
        let mut buf = ReadBuf::new(&mut store);
        assert!(
            matches!(
                Pin::new(&mut io).poll_read(&mut context, &mut buf),
                Poll::Pending
            ),
            "a partial frame ({released} bytes) stalls the read"
        );

        // The in-flight partial header/body fails the reset closed.
        assert!(
            matches!(
                io.reset_sequence(),
                Err(CompressionError::ResetWithBufferedData { .. })
            ),
            "a partial frame ({released} bytes) fails the reset closed"
        );

        // The guarded path (no reset) completes the frame once the rest arrives.
        io.get_mut().released = frame.len();
        let mut store = [0_u8; 64];
        let mut buf = ReadBuf::new(&mut store);
        let Poll::Ready(Ok(())) = Pin::new(&mut io).poll_read(&mut context, &mut buf) else {
            unreachable!("the completed frame decodes once fully released ({released} bytes)")
        };
        assert_eq!(buf.filled(), mysql_packet(b"\x03SELECT 1", 0).as_slice());
        assert_eq!(io.buffered_read_len(), 0);

        // The shared sequence advanced to 1 with no rewind, so the response
        // write would begin at compressed sequence 1.
        assert_eq!(io.codec().sequence(), 1);
        assert_eq!(
            io.begin_write()?,
            Some(1),
            "the guarded path answers at compressed sequence 1 ({released} bytes)"
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------
// C. Empty flush after a read is a no-op that returns Ok.
// ---------------------------------------------------------------------

/// After reading a compressed frame (direction = Read), a `PacketIo::flush`
/// carries no buffered output and must return `Ok(())` — the same no-op path the
/// shutdown flush takes — rather than erroring on the absent write direction.
#[tokio::test]
async fn empty_flush_after_read_over_compression_is_ok() -> TestResult {
    let algorithm = CompressionAlgorithm::Zlib;
    let mut io = compressed_packet_io(command_frame(algorithm, b"\x03SELECT 1")?, algorithm)?;

    let command = io.read_logical(64 * 1024).await?;
    assert_eq!(command.payload, b"\x03SELECT 1");

    // The read left no buffered write output; the flush is a straight-through
    // no-op on the inner transport.
    io.flush().await?;

    // A second flush (still empty) remains Ok, matching the shutdown path.
    io.flush().await?;
    Ok(())
}
