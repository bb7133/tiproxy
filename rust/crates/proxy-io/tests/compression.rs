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

//! `MySQL` compression framing, bounds, sequence, and packet-layer tests.

use std::error::Error;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use mysql_wire::CapabilityFlags;
use proxy_io::compression::{
    COMPRESSED_HEADER_LEN, CompressedFrameHeader, CompressedIo, CompressionAlgorithm,
    CompressionCodec, CompressionDirection, CompressionError, CompressionLimits,
    DEFAULT_MAX_EXPANSION_RATIO, MAX_COMPRESSED_FRAME_LEN, MIN_COMPRESS_LEN, negotiate_compression,
};
use proxy_io::{PacketReader, PacketWriter};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, ReadBuf};

type TestResult = Result<(), Box<dyn Error>>;

#[derive(Debug)]
struct ChunkedReader {
    bytes: Vec<u8>,
    offset: usize,
    chunk_size: usize,
}

impl ChunkedReader {
    fn new(bytes: Vec<u8>, chunk_size: usize) -> Self {
        Self {
            bytes,
            offset: 0,
            chunk_size,
        }
    }
}

impl AsyncRead for ChunkedReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        destination: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let available = self.bytes.len().saturating_sub(self.offset);
        let copied = available.min(self.chunk_size).min(destination.remaining());
        if copied > 0 {
            let end = self.offset + copied;
            destination.put_slice(&self.bytes[self.offset..end]);
            self.offset = end;
        }
        Poll::Ready(Ok(()))
    }
}

fn split_frames(mut wire: &[u8]) -> Result<Vec<&[u8]>, CompressionError> {
    let mut frames = Vec::new();
    while !wire.is_empty() {
        let header = CompressedFrameHeader::decode(wire)?;
        let length = COMPRESSED_HEADER_LEN + header.compressed_len();
        let frame = wire
            .get(..length)
            .ok_or(CompressionError::BodyLengthMismatch {
                declared: header.compressed_len(),
                actual: wire.len().saturating_sub(COMPRESSED_HEADER_LEN),
            })?;
        frames.push(frame);
        wire = &wire[length..];
    }
    Ok(frames)
}

#[test]
fn header_and_configuration_bounds_are_explicit() -> TestResult {
    let header = CompressedFrameHeader::new(0x12_3456, 0xa5, 0x65_4321)?;
    assert_eq!(header.encode(), [0x56, 0x34, 0x12, 0xa5, 0x21, 0x43, 0x65]);
    assert_eq!(CompressedFrameHeader::decode(&header.encode())?, header);
    assert!(matches!(
        CompressedFrameHeader::decode(&[0; 6]),
        Err(CompressionError::TruncatedHeader { available: 6 })
    ));
    assert!(matches!(
        CompressionLimits::new(0, 1),
        Err(CompressionError::InvalidFrameLimit { .. })
    ));
    assert!(matches!(
        CompressionLimits::new(MAX_COMPRESSED_FRAME_LEN, 0),
        Err(CompressionError::InvalidExpansionRatio)
    ));
    assert!(matches!(
        CompressionCodec::new(
            CompressionAlgorithm::Zstd { level: 0 },
            CompressionLimits::default()
        ),
        Err(CompressionError::InvalidZstdLevel { level: 0 })
    ));
    Ok(())
}

#[test]
fn threshold_raw_and_compressed_frames_round_trip() -> TestResult {
    for algorithm in [
        CompressionAlgorithm::Zlib,
        CompressionAlgorithm::Zstd { level: 3 },
    ] {
        let mut writer = CompressionCodec::new(algorithm, CompressionLimits::default())?;
        let raw = vec![b'a'; MIN_COMPRESS_LEN - 1];
        let raw_frame = writer.encode_frame(&raw)?;
        let raw_header = CompressedFrameHeader::decode(&raw_frame)?;
        assert!(raw_header.is_uncompressed());
        assert_eq!(raw_header.compressed_len(), raw.len());

        let compressed = vec![b'b'; MIN_COMPRESS_LEN];
        let compressed_frame = writer.encode_frame(&compressed)?;
        let compressed_header = CompressedFrameHeader::decode(&compressed_frame)?;
        assert!(!compressed_header.is_uncompressed());
        assert_eq!(compressed_header.uncompressed_len(), compressed.len());
        assert_eq!(compressed_header.sequence(), 1);

        let mut reader = CompressionCodec::new(algorithm, CompressionLimits::default())?;
        assert_eq!(reader.decode_frame(&raw_frame)?, raw);
        assert_eq!(reader.decode_frame(&compressed_frame)?, compressed);
        assert_eq!(reader.sequence(), 2);
    }
    Ok(())
}

#[test]
fn zstd_negotiated_levels_are_interoperable() -> TestResult {
    let mut state = 0x243f_6a88_85a3_08d3_u64;
    let mut block = Vec::with_capacity(64 * 1024);
    for _ in 0..64 * 1024 {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        block.push(state.to_le_bytes()[0]);
    }
    let mut payload = block.clone();
    payload.extend_from_slice(b"PARITY-CMP-002 zstd negotiated level");
    payload.extend_from_slice(&block);
    let mut encoded_frames = Vec::new();
    for level in [1, 3, 9, 22] {
        let algorithm = CompressionAlgorithm::Zstd { level };
        let mut writer = CompressionCodec::new(algorithm, CompressionLimits::default())?;
        let frame = writer.encode_frame(&payload)?;
        let mut reader = CompressionCodec::new(algorithm, CompressionLimits::default())?;
        assert_eq!(reader.decode_frame(&frame)?, payload);
        encoded_frames.push(frame);
    }
    assert!(
        encoded_frames.windows(2).any(|pair| pair[0] != pair[1]),
        "negotiated zstd levels must reach the encoder instead of being ignored"
    );
    Ok(())
}

#[test]
fn client_and_backend_transports_select_algorithms_independently() -> TestResult {
    let limits = CompressionLimits::default();
    let payload = b"independent client/backend compression".repeat(64);
    let client_capabilities =
        CapabilityFlags::COMPRESS | CapabilityFlags::ZSTD_COMPRESSION_ALGORITHM;
    let backend_capabilities = CapabilityFlags::ZSTD_COMPRESSION_ALGORITHM;
    let client_algorithm = negotiate_compression(client_capabilities, Some(9))?
        .ok_or("expected client compression")?;
    let backend_algorithm =
        negotiate_compression(client_capabilities & backend_capabilities, Some(9))?
            .ok_or("expected backend compression")?;
    assert_eq!(client_algorithm, CompressionAlgorithm::Zlib);
    assert_eq!(backend_algorithm, CompressionAlgorithm::Zstd { level: 9 });

    let mut client_encoder = CompressionCodec::new(client_algorithm, limits)?;
    let mut backend_encoder = CompressionCodec::new(backend_algorithm, limits)?;

    let client_frame = client_encoder.encode_frame(&payload)?;
    let backend_frame = backend_encoder.encode_frame(&payload)?;
    assert_ne!(client_frame, backend_frame);
    assert_eq!(client_encoder.sequence(), 1);
    assert_eq!(backend_encoder.sequence(), 1);

    let mut client_decoder = CompressionCodec::new(client_algorithm, limits)?;
    let mut backend_decoder = CompressionCodec::new(backend_algorithm, limits)?;
    assert_eq!(client_decoder.decode_frame(&client_frame)?, payload);
    assert_eq!(backend_decoder.decode_frame(&backend_frame)?, payload);
    assert_eq!(client_decoder.algorithm(), CompressionAlgorithm::Zlib);
    assert_eq!(
        backend_decoder.algorithm(),
        CompressionAlgorithm::Zstd { level: 9 }
    );
    assert_eq!(
        negotiate_compression(CapabilityFlags::default(), None)?,
        None
    );
    assert!(matches!(
        negotiate_compression(CapabilityFlags::ZSTD_COMPRESSION_ALGORITHM, None),
        Err(CompressionError::MissingZstdLevel)
    ));
    assert!(matches!(
        negotiate_compression(CapabilityFlags::ZSTD_COMPRESSION_ALGORITHM, Some(23)),
        Err(CompressionError::InvalidZstdLevel { level: 23 })
    ));
    Ok(())
}

#[test]
fn shared_sequence_follows_begin_rw_and_command_reset() -> TestResult {
    let limits = CompressionLimits::default();
    let mut peer = CompressionCodec::new(CompressionAlgorithm::Zlib, limits)?;
    let inbound = peer.encode_frame(&[b'r'; 128])?;

    let mut codec = CompressionCodec::new(CompressionAlgorithm::Zlib, limits)?;
    assert_eq!(codec.begin(CompressionDirection::Read), Some(0));
    assert_eq!(codec.begin(CompressionDirection::Read), None);
    assert_eq!(codec.decode_frame(&inbound)?.len(), 128);
    assert_eq!(codec.sequence(), 1);
    assert_eq!(codec.begin(CompressionDirection::Write), Some(1));
    let outbound = codec.encode_frame(&[b'w'; 128])?;
    assert_eq!(CompressedFrameHeader::decode(&outbound)?.sequence(), 1);
    assert_eq!(codec.begin(CompressionDirection::Write), None);
    codec.reset_sequence();
    assert_eq!(codec.sequence(), 0);
    assert_eq!(codec.direction(), None);
    Ok(())
}

#[test]
fn sequence_mismatch_is_strict_and_valid_sequence_advances_before_body_error() -> TestResult {
    let limits = CompressionLimits::default();
    let mut codec = CompressionCodec::new(CompressionAlgorithm::Zlib, limits)?;
    let wrong = CompressedFrameHeader::new(1, 7, 0)?.encode();
    let mut wrong_frame = wrong.to_vec();
    wrong_frame.push(1);
    assert!(matches!(
        codec.decode_frame(&wrong_frame),
        Err(CompressionError::SequenceMismatch {
            expected: 0,
            actual: 7
        })
    ));
    assert_eq!(codec.sequence(), 0);

    let truncated = CompressedFrameHeader::new(2, 0, 0)?.encode();
    let mut truncated_frame = truncated.to_vec();
    truncated_frame.push(1);
    assert!(matches!(
        codec.decode_frame(&truncated_frame),
        Err(CompressionError::BodyLengthMismatch { .. })
    ));
    assert_eq!(codec.sequence(), 1);
    Ok(())
}

#[test]
fn expansion_and_absolute_limits_reject_before_decompression() -> TestResult {
    let limits = CompressionLimits::new(1024, 8)?;
    let mut codec = CompressionCodec::new(CompressionAlgorithm::Zlib, limits)?;
    let header = CompressedFrameHeader::new(1, 0, 9)?.encode();
    let mut frame = header.to_vec();
    frame.push(0);
    assert!(matches!(
        codec.decode_frame(&frame),
        Err(CompressionError::ExpansionRatioExceeded {
            compressed: 1,
            uncompressed: 9,
            limit: 8
        })
    ));

    codec.reset_sequence();
    let header = CompressedFrameHeader::new(1025, 0, 0)?.encode();
    let mut frame = header.to_vec();
    frame.resize(COMPRESSED_HEADER_LEN + 1025, 0);
    assert!(matches!(
        codec.decode_frame(&frame),
        Err(CompressionError::UncompressedFrameTooLarge {
            limit: 1024,
            actual: 1025
        })
    ));

    let payload = vec![b'b'; 4096];
    let mut encoder =
        CompressionCodec::new(CompressionAlgorithm::Zlib, CompressionLimits::default())?;
    let valid_bomb = encoder.encode_frame(&payload)?;
    let mut bounded =
        CompressionCodec::new(CompressionAlgorithm::Zlib, CompressionLimits::new(4096, 2)?)?;
    assert!(matches!(
        bounded.decode_frame(&valid_bomb),
        Err(CompressionError::ExpansionRatioExceeded { .. })
    ));
    Ok(())
}

#[test]
fn trailing_codec_data_and_declared_output_mismatch_are_rejected() -> TestResult {
    let payload = b"exact compressed body consumption".repeat(128);
    for algorithm in [
        CompressionAlgorithm::Zlib,
        CompressionAlgorithm::Zstd { level: 3 },
    ] {
        let mut encoder = CompressionCodec::new(algorithm, CompressionLimits::default())?;
        let frame = encoder.encode_frame(&payload)?;
        let header = CompressedFrameHeader::decode(&frame)?;

        let trailing_header = CompressedFrameHeader::new(
            header.compressed_len() + 1,
            header.sequence(),
            header.uncompressed_len(),
        )?;
        let mut trailing = trailing_header.encode().to_vec();
        trailing.extend_from_slice(&frame[COMPRESSED_HEADER_LEN..]);
        trailing.push(0);
        let mut decoder = CompressionCodec::new(algorithm, CompressionLimits::default())?;
        let error = decoder
            .decode_frame(&trailing)
            .err()
            .ok_or("expected trailing codec data to fail")?;
        match algorithm {
            CompressionAlgorithm::Zlib => {
                assert!(matches!(error, CompressionError::BodyLengthMismatch { .. }));
            }
            CompressionAlgorithm::Zstd { .. } => {
                assert!(matches!(error, CompressionError::Codec { .. }));
            }
        }

        let wrong_output_header = CompressedFrameHeader::new(
            header.compressed_len(),
            header.sequence(),
            header.uncompressed_len() + 1,
        )?;
        let mut wrong_output = wrong_output_header.encode().to_vec();
        wrong_output.extend_from_slice(&frame[COMPRESSED_HEADER_LEN..]);
        let mut decoder = CompressionCodec::new(algorithm, CompressionLimits::default())?;
        assert!(matches!(
            decoder.decode_frame(&wrong_output),
            Err(CompressionError::DecodedLengthMismatch { .. })
        ));

        if matches!(algorithm, CompressionAlgorithm::Zstd { .. }) {
            let body = &frame[COMPRESSED_HEADER_LEN..];
            let concatenated_header = CompressedFrameHeader::new(
                body.len() * 2,
                header.sequence(),
                header.uncompressed_len(),
            )?;
            let mut concatenated = concatenated_header.encode().to_vec();
            concatenated.extend_from_slice(body);
            concatenated.extend_from_slice(body);
            let mut decoder = CompressionCodec::new(algorithm, CompressionLimits::default())?;
            assert!(matches!(
                decoder.decode_frame(&concatenated),
                Err(CompressionError::Codec { .. })
            ));
        }
    }
    Ok(())
}

#[test]
fn zstd_declared_window_is_bounded_before_allocation() -> TestResult {
    // Standard magic, non-single-segment header with a 2-GiB window, then one
    // empty last raw block. The MySQL output declaration is tiny, so only the
    // independent history-window check can stop the oversized allocation.
    let zstd = [0x28, 0xb5, 0x2f, 0xfd, 0x00, 0xa8, 0x01, 0x00, 0x00];
    let header = CompressedFrameHeader::new(zstd.len(), 0, 1)?;
    let mut frame = header.encode().to_vec();
    frame.extend_from_slice(&zstd);
    let mut decoder = CompressionCodec::new(
        CompressionAlgorithm::Zstd { level: 3 },
        CompressionLimits::default(),
    )?;
    assert!(matches!(
        decoder.decode_frame(&frame),
        Err(CompressionError::ZstdWindowTooLarge {
            limit: MAX_COMPRESSED_FRAME_LEN,
            actual: 2_147_483_648
        })
    ));
    Ok(())
}

#[test]
fn maximum_incompressible_zlib_frame_falls_back_to_raw() -> TestResult {
    let mut state = 0xa076_1d64_78bd_642f_u64;
    let mut payload = Vec::with_capacity(MAX_COMPRESSED_FRAME_LEN);
    for _ in 0..MAX_COMPRESSED_FRAME_LEN {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        payload.push(state.to_le_bytes()[0]);
    }
    let mut encoder =
        CompressionCodec::new(CompressionAlgorithm::Zlib, CompressionLimits::default())?;
    let frame = encoder.encode_frame(&payload)?;
    let header = CompressedFrameHeader::decode(&frame)?;
    assert!(header.is_uncompressed());
    assert_eq!(header.compressed_len(), MAX_COMPRESSED_FRAME_LEN);
    assert_eq!(&frame[COMPRESSED_HEADER_LEN..], payload);
    Ok(())
}

#[tokio::test]
async fn async_adapter_coalesces_and_splits_at_the_configured_frame_bound() -> TestResult {
    let limits = CompressionLimits::new(1024, DEFAULT_MAX_EXPANSION_RATIO)?;
    let mut writer = CompressedIo::new(Vec::new(), CompressionAlgorithm::Zlib, limits)?;
    assert_eq!(writer.begin_write()?, Some(0));
    let payload = (0..2500_usize)
        .map(|index| u8::try_from(index % 251).unwrap_or(0))
        .collect::<Vec<_>>();
    writer.write_all(&payload[..300]).await?;
    assert_eq!(writer.buffered_write_len(), 300);
    writer.write_all(&payload[300..]).await?;
    writer.flush().await?;
    let wire = writer.into_inner();
    let frames = split_frames(&wire)?;
    assert_eq!(frames.len(), 3);
    assert_eq!(
        frames
            .iter()
            .map(|frame| {
                CompressedFrameHeader::decode(frame).map(CompressedFrameHeader::sequence)
            })
            .collect::<Result<Vec<_>, _>>()?,
        vec![0, 1, 2]
    );

    let mut decoder = CompressionCodec::new(CompressionAlgorithm::Zlib, limits)?;
    let mut output = Vec::new();
    for frame in frames {
        output.extend_from_slice(&decoder.decode_frame(frame)?);
    }
    assert_eq!(output, payload);
    Ok(())
}

#[tokio::test]
async fn default_adapter_splits_after_the_24_bit_maximum() -> TestResult {
    let mut writer = CompressedIo::new(
        Vec::new(),
        CompressionAlgorithm::Zlib,
        CompressionLimits::default(),
    )?;
    assert_eq!(writer.begin_write()?, Some(0));
    let payload = vec![b'x'; MAX_COMPRESSED_FRAME_LEN + 1];
    writer.write_all(&payload).await?;
    writer.flush().await?;
    let wire = writer.into_inner();
    let frames = split_frames(&wire)?;
    assert_eq!(frames.len(), 2);
    assert_eq!(
        CompressedFrameHeader::decode(frames[0])?.uncompressed_len(),
        MAX_COMPRESSED_FRAME_LEN
    );
    let tail = CompressedFrameHeader::decode(frames[1])?;
    assert!(tail.is_uncompressed());
    assert_eq!(tail.compressed_len(), 1);
    Ok(())
}

#[tokio::test]
async fn async_reader_handles_one_byte_transport_chunks_and_multiple_frames() -> TestResult {
    let algorithm = CompressionAlgorithm::Zstd { level: 3 };
    let limits = CompressionLimits::default();
    let first = b"first compressed response ".repeat(20);
    let second = b"second compressed response ".repeat(20);
    let mut encoder = CompressionCodec::new(algorithm, limits)?;
    let mut wire = encoder.encode_frame(&first)?;
    wire.extend_from_slice(&encoder.encode_frame(&second)?);

    let mut reader = CompressedIo::new(ChunkedReader::new(wire, 1), algorithm, limits)?;
    assert_eq!(reader.begin_read()?, Some(0));
    let mut output = Vec::new();
    reader.read_to_end(&mut output).await?;
    let mut expected = first;
    expected.extend_from_slice(&second);
    assert_eq!(output, expected);
    assert_eq!(reader.codec().sequence(), 2);
    Ok(())
}

#[tokio::test]
async fn packet_layer_peek_read_and_flush_work_over_compression() -> TestResult {
    let algorithm = CompressionAlgorithm::Zlib;
    let limits = CompressionLimits::default();
    let payload = b"SELECT PARITY-CMP-003".repeat(32);

    let compressed = CompressedIo::new(Vec::new(), algorithm, limits)?;
    let mut packet_writer = PacketWriter::new(compressed);
    let sequence = packet_writer
        .get_mut()
        .begin_write()?
        .ok_or("expected write direction change")?;
    packet_writer.reset_sequence(sequence);
    packet_writer.write_logical(&payload, true).await?;
    let wire = packet_writer.into_inner().into_inner();

    let compressed = CompressedIo::new(wire.as_slice(), algorithm, limits)?;
    let mut packet_reader = PacketReader::new(compressed);
    let sequence = packet_reader
        .get_mut()
        .begin_read()?
        .ok_or("expected read direction change")?;
    packet_reader.reset_sequence(sequence);
    let preview = packet_reader.peek_packet().await?;
    assert_eq!(preview.first_byte, Some(b'S'));
    let logical = packet_reader.read_logical(payload.len()).await?;
    assert_eq!(logical.payload, payload);
    Ok(())
}

#[tokio::test]
async fn truncated_async_headers_and_bodies_are_rejected() -> TestResult {
    let limits = CompressionLimits::default();
    let mut header_reader =
        CompressedIo::new([1_u8, 0].as_slice(), CompressionAlgorithm::Zlib, limits)?;
    header_reader.begin_read()?;
    let mut byte = [0_u8; 1];
    let error = header_reader
        .read_exact(&mut byte)
        .await
        .err()
        .ok_or("expected error")?;
    assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);

    let mut body = CompressedFrameHeader::new(2, 0, 0)?.encode().to_vec();
    body.push(1);
    let mut body_reader = CompressedIo::new(body.as_slice(), CompressionAlgorithm::Zlib, limits)?;
    body_reader.begin_read()?;
    let error = body_reader
        .read_exact(&mut byte)
        .await
        .err()
        .ok_or("expected error")?;
    assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
    Ok(())
}

#[tokio::test]
async fn direction_switch_guards_buffered_data_and_debug_is_redacted() -> TestResult {
    let limits = CompressionLimits::default();
    let mut writer = CompressedIo::new(Vec::new(), CompressionAlgorithm::Zlib, limits)?;
    writer.begin_write()?;
    writer.write_all(b"wire-secret").await?;
    assert!(matches!(
        writer.begin_read(),
        Err(CompressionError::PendingWriteOnReadTransition { buffered: 11 })
    ));
    let debug = format!("{writer:?}");
    assert!(!debug.contains("wire-secret"));
    assert!(debug.contains("buffered_write_len"));

    let mut peer = CompressionCodec::new(CompressionAlgorithm::Zlib, limits)?;
    let wire = peer.encode_frame(b"decoded-secret")?;
    let mut reader = CompressedIo::new(wire.as_slice(), CompressionAlgorithm::Zlib, limits)?;
    reader.begin_read()?;
    let mut prefix = [0_u8; 1];
    reader.read_exact(&mut prefix).await?;
    assert!(matches!(
        reader.begin_write(),
        Err(CompressionError::PendingReadOnWriteTransition { .. })
    ));
    let debug = format!("{reader:?}");
    assert!(!debug.contains("decoded-secret"));
    Ok(())
}

#[test]
fn deterministic_property_round_trip_covers_boundaries_and_sequence_wrap() -> TestResult {
    let limits = CompressionLimits::new(128 * 1024, DEFAULT_MAX_EXPANSION_RATIO)?;
    for algorithm in [
        CompressionAlgorithm::Zlib,
        CompressionAlgorithm::Zstd { level: 3 },
    ] {
        let mut encoder = CompressionCodec::new(algorithm, limits)?;
        let mut decoder = CompressionCodec::new(algorithm, limits)?;
        let mut state = 0x9e37_79b9_7f4a_7c15_u64;
        for iteration in 0..300_usize {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let boundary_lengths = [
                0,
                1,
                MIN_COMPRESS_LEN - 1,
                MIN_COMPRESS_LEN,
                MIN_COMPRESS_LEN + 1,
                1024,
                32 * 1024,
                128 * 1024,
            ];
            let length = if iteration < boundary_lengths.len() {
                boundary_lengths[iteration]
            } else {
                usize::try_from(state % (128 * 1024 + 1) as u64)?
            };
            let mut payload = Vec::with_capacity(length);
            for index in 0..length {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                let byte = if iteration % 3 == 0 {
                    u8::try_from(index % 7)?
                } else {
                    state.to_le_bytes()[0]
                };
                payload.push(byte);
            }
            let frame = encoder.encode_frame(&payload)?;
            assert_eq!(decoder.decode_frame(&frame)?, payload);
        }
        assert_eq!(encoder.sequence(), 44);
        assert_eq!(decoder.sequence(), 44);
    }
    Ok(())
}

#[test]
fn deterministic_malformed_frames_never_escape_configured_bounds() -> TestResult {
    let limits = CompressionLimits::new(4096, 32)?;
    let mut state = 0xd1b5_4a32_d192_ed03_u64;
    for algorithm in [
        CompressionAlgorithm::Zlib,
        CompressionAlgorithm::Zstd { level: 3 },
    ] {
        for length in 0..=256_usize {
            let mut frame = Vec::with_capacity(length);
            for _ in 0..length {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                frame.push(state.to_le_bytes()[0]);
            }
            if frame.len() >= COMPRESSED_HEADER_LEN {
                frame[3] = 0;
            }
            let mut decoder = CompressionCodec::new(algorithm, limits)?;
            let _ = decoder.decode_frame(&frame);
        }
    }
    Ok(())
}

#[test]
fn mutated_zstd_frames_exercise_safe_decoder_without_panics_or_growth() -> TestResult {
    let expected = 4096;
    let limits = CompressionLimits::new(expected, DEFAULT_MAX_EXPANSION_RATIO)?;
    let algorithm = CompressionAlgorithm::Zstd { level: 3 };
    let mut encoder = CompressionCodec::new(algorithm, limits)?;
    let valid = encoder.encode_frame(&vec![b'z'; expected])?;
    let valid_body = &valid[COMPRESSED_HEADER_LEN..];

    let exercise = |body: &[u8]| -> Result<(), CompressionError> {
        let header = CompressedFrameHeader::new(body.len(), 0, expected)?;
        let mut frame = header.encode().to_vec();
        frame.extend_from_slice(body);
        let mut decoder = CompressionCodec::new(algorithm, limits)?;
        if let Ok(output) = decoder.decode_frame(&frame) {
            assert_eq!(output.len(), expected);
        }
        Ok(())
    };

    for length in 0..valid_body.len() {
        exercise(&valid_body[..length])?;
    }
    for index in 0..valid_body.len() {
        for bit in 0..8 {
            let mut mutated = valid_body.to_vec();
            mutated[index] ^= 1 << bit;
            exercise(&mutated)?;
        }
    }

    let mut state = 0x1319_8a2e_0370_7344_u64;
    for length in 4..=512_usize {
        let mut candidate = Vec::with_capacity(length);
        candidate.extend_from_slice(&[0x28, 0xb5, 0x2f, 0xfd]);
        while candidate.len() < length {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            candidate.push(state.to_le_bytes()[0]);
        }
        exercise(&candidate)?;
    }
    Ok(())
}
