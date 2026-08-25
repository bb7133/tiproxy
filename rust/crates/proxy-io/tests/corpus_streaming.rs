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

//! Streaming-adapter checks against deterministic Go packet traces.

use std::error::Error;
use std::fs::File;
use std::io::{Error as IoError, ErrorKind, Read};
use std::path::PathBuf;

use flate2::read::GzDecoder;
use mysql_wire::MAX_PAYLOAD_LEN;
use proxy_io::{PacketReader, PacketWriter};

const TRACE_MAGIC: &[u8; 8] = b"TPXCRP1\n";

fn load_single_wire(case_id: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../tests/dataplane/corpus/v1/cases")
        .join(format!("{case_id}.trace.gz"));
    let mut decoder = GzDecoder::new(File::open(path)?);
    let mut trace = Vec::new();
    decoder.read_to_end(&mut trace)?;

    if trace.get(..TRACE_MAGIC.len()) != Some(TRACE_MAGIC) {
        return Err(IoError::new(ErrorKind::InvalidData, "invalid trace magic").into());
    }
    let count_start = TRACE_MAGIC.len();
    let count_end = count_start + 4;
    let count_bytes: [u8; 4] = trace
        .get(count_start..count_end)
        .ok_or_else(|| IoError::new(ErrorKind::UnexpectedEof, "missing record count"))?
        .try_into()?;
    if u32::from_le_bytes(count_bytes) != 1 {
        return Err(IoError::new(ErrorKind::InvalidData, "expected one trace record").into());
    }
    let direction = *trace
        .get(count_end)
        .ok_or_else(|| IoError::new(ErrorKind::UnexpectedEof, "missing direction"))?;
    if direction != 1 {
        return Err(IoError::new(ErrorKind::InvalidData, "expected client direction").into());
    }
    let length_start = count_end + 1;
    let length_end = length_start + 8;
    let length_bytes: [u8; 8] = trace
        .get(length_start..length_end)
        .ok_or_else(|| IoError::new(ErrorKind::UnexpectedEof, "missing record length"))?
        .try_into()?;
    let wire_length = usize::try_from(u64::from_le_bytes(length_bytes))?;
    let wire_end = length_end
        .checked_add(wire_length)
        .ok_or_else(|| IoError::new(ErrorKind::InvalidData, "record length overflow"))?;
    let wire = trace
        .get(length_end..wire_end)
        .ok_or_else(|| IoError::new(ErrorKind::UnexpectedEof, "truncated record"))?;
    if wire_end != trace.len() {
        return Err(IoError::new(ErrorKind::InvalidData, "trailing trace bytes").into());
    }
    Ok(wire.to_vec())
}

#[tokio::test]
async fn parity_pkt_002_pkt_003_large_messages_stream_byte_exactly() -> Result<(), Box<dyn Error>> {
    let maximum = u64::from(MAX_PAYLOAD_LEN);
    for (case_id, logical_length, physical_packets) in [
        ("packet-exact-max-tail", maximum, 2_u64),
        ("packet-large-query", maximum + 33, 2_u64),
    ] {
        let wire = load_single_wire(case_id)?;
        let mut reader = PacketReader::new(wire.as_slice());
        let mut writer = PacketWriter::new(Vec::new());
        let progress = reader.forward_packet_to(&mut writer, 1_024).await?;
        assert_eq!(progress.logical_payload_bytes(), logical_length);
        assert_eq!(progress.physical_packets(), physical_packets);
        assert_eq!(progress.captured_prefix().len(), 1_024);
        assert!(progress.capture_truncated());
        assert_eq!(writer.into_inner(), wire);
    }
    Ok(())
}

#[tokio::test]
async fn parity_pkt_004_mismatch_is_observed_and_resynchronized() -> Result<(), Box<dyn Error>> {
    let wire = load_single_wire("packet-sequence-mismatch")?;
    let mut reader = PacketReader::new(wire.as_slice());
    let mut writer = PacketWriter::new(Vec::new());
    writer.reset_sequence(7);
    let progress = reader.forward_packet_to(&mut writer, 1).await?;
    assert_eq!(progress.sequence_mismatches(), 1);
    assert_eq!(reader.expected_sequence(), 8);
    assert_eq!(writer.into_inner(), wire);
    Ok(())
}

#[tokio::test]
async fn parity_pkt_005_empty_logical_packet_round_trips() -> Result<(), Box<dyn Error>> {
    let wire = load_single_wire("packet-empty-payload")?;
    let mut reader = PacketReader::new(wire.as_slice());
    let mut writer = PacketWriter::new(Vec::new());
    let progress = reader.forward_packet_to(&mut writer, 1).await?;
    assert_eq!(progress.logical_payload_bytes(), 0);
    assert_eq!(progress.physical_packets(), 1);
    assert!(progress.is_complete());
    assert!(progress.captured_prefix().is_empty());
    assert_eq!(writer.into_inner(), wire);
    Ok(())
}
