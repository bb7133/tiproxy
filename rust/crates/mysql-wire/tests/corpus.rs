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

//! Differential wire-level checks against the deterministic Go oracle corpus.

use std::error::Error;
use std::fs::File;
use std::io::{Error as IoError, ErrorKind, Read};
use std::path::PathBuf;

use flate2::read::GzDecoder;
use mysql_wire::{
    CapabilityFlags, CommandCode, CommandPacket, DecodeError, MAX_PAYLOAD_LEN, PhysicalPacket,
    ResponseKind, SequenceTracker, StatusFlags, classify_response, parse_change_user,
    parse_error_packet, parse_handshake_response, parse_initial_handshake, parse_ok_packet,
};

const TRACE_MAGIC: &[u8; 8] = b"TPXCRP1\n";
const CLIENT_CAPS: CapabilityFlags = CapabilityFlags::PROTOCOL_41
    .union(CapabilityFlags::SECURE_CONNECTION)
    .union(CapabilityFlags::PLUGIN_AUTH)
    .union(CapabilityFlags::CONNECT_ATTRS)
    .union(CapabilityFlags::MULTI_STATEMENTS)
    .union(CapabilityFlags::MULTI_RESULTS)
    .union(CapabilityFlags::PS_MULTI_RESULTS)
    .union(CapabilityFlags::LOCAL_FILES)
    .union(CapabilityFlags::CONNECT_WITH_DB);

#[derive(Debug)]
struct TraceRecord {
    direction: u8,
    wire: Vec<u8>,
}

fn load_trace(case_id: &str) -> Result<Vec<TraceRecord>, Box<dyn Error>> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../tests/dataplane/corpus/v1/cases")
        .join(format!("{case_id}.trace.gz"));
    let mut decoder = GzDecoder::new(File::open(path)?);
    let mut trace_bytes = Vec::new();
    decoder.read_to_end(&mut trace_bytes)?;

    let mut position = 0_usize;
    let magic = take(
        &trace_bytes,
        &mut position,
        TRACE_MAGIC.len(),
        "trace magic",
    )?;
    if magic != TRACE_MAGIC {
        return Err(IoError::new(ErrorKind::InvalidData, "invalid trace magic").into());
    }
    let count_bytes: [u8; 4] = take(&trace_bytes, &mut position, 4, "record count")?.try_into()?;
    let count = u32::from_le_bytes(count_bytes) as usize;
    let mut records = Vec::with_capacity(count);
    for _ in 0..count {
        let direction = take(&trace_bytes, &mut position, 1, "record direction")?[0];
        let length_bytes: [u8; 8] =
            take(&trace_bytes, &mut position, 8, "record length")?.try_into()?;
        let wire_length = usize::try_from(u64::from_le_bytes(length_bytes))
            .map_err(|_| IoError::new(ErrorKind::InvalidData, "record length exceeds host size"))?;
        let wire = take(
            &trace_bytes,
            &mut position,
            wire_length,
            "record wire bytes",
        )?
        .to_vec();
        records.push(TraceRecord { direction, wire });
    }
    if position != trace_bytes.len() {
        return Err(IoError::new(ErrorKind::InvalidData, "trailing trace bytes").into());
    }
    Ok(records)
}

fn take<'a>(
    input: &'a [u8],
    position: &mut usize,
    length: usize,
    field: &'static str,
) -> Result<&'a [u8], IoError> {
    let remaining = input.len().saturating_sub(*position);
    if length > remaining {
        return Err(IoError::new(
            ErrorKind::UnexpectedEof,
            format!("truncated {field}: need {length}, have {remaining}"),
        ));
    }
    let start = *position;
    *position += length;
    Ok(&input[start..*position])
}

fn packets(wire: &[u8]) -> Result<Vec<PhysicalPacket<'_>>, DecodeError> {
    let mut remaining = wire;
    let mut packets = Vec::new();
    while !remaining.is_empty() {
        let (packet, tail) = PhysicalPacket::decode(remaining)?;
        packets.push(packet);
        remaining = tail;
    }
    Ok(packets)
}

fn only_payload(record: &TraceRecord) -> Result<&[u8], Box<dyn Error>> {
    let decoded = packets(&record.wire)?;
    if decoded.len() != 1 {
        return Err(IoError::new(ErrorKind::InvalidData, "expected one physical packet").into());
    }
    Ok(decoded[0].payload())
}

#[test]
fn parity_pkt_001_three_byte_header_and_sequence() -> Result<(), Box<dyn Error>> {
    let trace = load_trace("packet-fragmented-query")?;
    assert_eq!(trace.len(), 1, "PARITY-PKT-001 record count");
    assert_eq!(trace[0].direction, 1, "PARITY-PKT-001 direction");
    let decoded = packets(&trace[0].wire)?;
    assert_eq!(decoded.len(), 1, "PARITY-PKT-001 physical count");
    assert_eq!(decoded[0].header().sequence_id(), 0);
    assert_eq!(decoded[0].payload()[0], CommandCode::QUERY.as_byte());
    assert_eq!(&decoded[0].payload()[1..], b"SELECT 1");
    Ok(())
}

#[test]
fn parity_pkt_002_max_payload_and_empty_tail() -> Result<(), Box<dyn Error>> {
    let exact = load_trace("packet-exact-max-tail")?;
    let decoded = packets(&exact[0].wire)?;
    assert_eq!(decoded.len(), 2, "PARITY-PKT-002 exact-multiple count");
    assert_eq!(decoded[0].header().payload_length(), MAX_PAYLOAD_LEN);
    assert_eq!(decoded[0].header().sequence_id(), 0);
    assert!(decoded[1].payload().is_empty());
    assert_eq!(decoded[1].header().sequence_id(), 1);

    let large = load_trace("packet-large-query")?;
    let decoded = packets(&large[0].wire)?;
    assert_eq!(decoded.len(), 2, "PARITY-PKT-002 split count");
    assert_eq!(decoded[0].header().payload_length(), MAX_PAYLOAD_LEN);
    assert_eq!(decoded[1].header().payload_length(), 33);
    Ok(())
}

#[test]
fn parity_pkt_004_sequence_mismatch_resync() -> Result<(), Box<dyn Error>> {
    let trace = load_trace("packet-sequence-mismatch")?;
    let packet = PhysicalPacket::decode(&trace[0].wire)?.0;
    let mut sequence = SequenceTracker::new(0);
    let observation = sequence.observe(packet.header().sequence_id());
    assert!(observation.mismatched(), "PARITY-PKT-004 warning condition");
    assert_eq!(observation.received, 7);
    assert_eq!(sequence.expected(), 8, "PARITY-PKT-004 resync");
    Ok(())
}

#[test]
fn parity_pkt_005_empty_payload_is_valid() -> Result<(), Box<dyn Error>> {
    let trace = load_trace("packet-empty-payload")?;
    let packet = PhysicalPacket::decode(&trace[0].wire)?.0;
    assert!(packet.payload().is_empty(), "PARITY-PKT-005");
    assert_eq!(
        CommandPacket::decode(packet.payload()),
        Err(DecodeError::EmptyCommandPacket)
    );
    Ok(())
}

#[test]
fn parity_pkt_007_truncated_header_is_typed() -> Result<(), Box<dyn Error>> {
    let trace = load_trace("packet-truncated-header")?;
    assert!(matches!(
        PhysicalPacket::decode(&trace[0].wire),
        Err(DecodeError::UnexpectedEof { .. })
    ));
    Ok(())
}

#[test]
fn parity_hs_001_initial_handshake() -> Result<(), Box<dyn Error>> {
    let trace = load_trace("handshake-initial-native")?;
    let payload = only_payload(&trace[0])?;
    let greeting = parse_initial_handshake(payload)?;
    assert_eq!(greeting.server_version, b"8.0.11-TiDB", "PARITY-HS-001");
    assert_eq!(greeting.connection_id, 42);
    assert_eq!(greeting.auth_plugin_data_part_1, b"12345678");
    assert_eq!(greeting.auth_plugin_data_part_2, b"90abcdefghij");
    assert_eq!(
        greeting.auth_plugin_name,
        Some(&b"mysql_native_password"[..])
    );
    Ok(())
}

#[test]
fn parity_hs_003_hs_006_handshake_fields_and_attributes() -> Result<(), Box<dyn Error>> {
    let native = load_trace("handshake-response-native")?;
    let response = parse_handshake_response(only_payload(&native[0])?)?;
    assert_eq!(response.username, b"corpus_user", "PARITY-HS-003");
    assert_eq!(response.database, Some(&b"corpus_db"[..]));
    assert_eq!(response.auth_response, &[1, 2, 3, 4]);

    let modern = load_trace("handshake-response-modern")?;
    let response = parse_handshake_response(only_payload(&modern[0])?)?;
    assert_eq!(response.zstd_level, Some(3), "PARITY-HS-006");
    let attributes = response
        .attributes
        .ok_or_else(|| IoError::new(ErrorKind::InvalidData, "missing corpus attributes"))?;
    let decoded: Result<Vec<_>, _> = attributes.iter().collect();
    let decoded = decoded?;
    assert_eq!(decoded.len(), 1);
    assert_eq!(decoded[0].key, b"_client_name");
    assert_eq!(decoded[0].value, b"tiproxy-corpus");
    Ok(())
}

#[test]
fn parity_hs_011_malformed_greeting_prefixes_are_safe() -> Result<(), Box<dyn Error>> {
    let trace = load_trace("handshake-initial-native")?;
    let payload = only_payload(&trace[0])?;
    for length in 0..payload.len() {
        // The protocol permits a legacy greeting to end exactly after the
        // lower capability word; every other prefix is either a typed error or
        // that valid legacy form, and none may panic.
        let result = parse_initial_handshake(&payload[..length]);
        if result.is_ok() {
            assert_eq!(length, 28, "only the legacy boundary may decode");
        }
    }
    assert!(parse_initial_handshake(payload).is_ok(), "PARITY-HS-011");
    Ok(())
}

#[test]
fn parity_rsp_001_error_packet() -> Result<(), Box<dyn Error>> {
    let trace = load_trace("query-error")?;
    assert_eq!(trace.len(), 2);
    let payload = only_payload(&trace[1])?;
    assert_eq!(classify_response(payload)?, ResponseKind::Error);
    let error = parse_error_packet(payload, CapabilityFlags::PROTOCOL_41)?;
    assert_eq!(error.code, 1064, "PARITY-RSP-001");
    assert_eq!(error.sql_state, Some(*b"42000"));
    assert_eq!(error.message, b"synthetic parse error");
    Ok(())
}

#[test]
fn parity_rsp_002_rsp_003_eof_classification_and_status() -> Result<(), Box<dyn Error>> {
    let legacy = load_trace("resultset-legacy-eof")?;
    let legacy_packets = packets(&legacy[0].wire)?;
    assert_eq!(
        classify_response(legacy_packets[2].payload())?,
        ResponseKind::Eof
    );
    assert_eq!(
        classify_response(legacy_packets[4].payload())?,
        ResponseKind::Eof
    );

    let modern = load_trace("resultset-deprecate-eof")?;
    let modern_packets = packets(&modern[0].wire)?;
    let terminator = modern_packets[3].payload();
    assert_eq!(classify_response(terminator)?, ResponseKind::ResultsetOk);
    let ok = parse_ok_packet(terminator, CapabilityFlags::PROTOCOL_41)?;
    assert!(
        ok.status.contains(StatusFlags::AUTOCOMMIT),
        "PARITY-RSP-003"
    );
    Ok(())
}

#[test]
fn parity_cmd_017_change_user_and_malformed() -> Result<(), Box<dyn Error>> {
    let trace = load_trace("change-user")?;
    let request = parse_change_user(only_payload(&trace[0])?, CLIENT_CAPS)?;
    assert_eq!(request.username, b"next_user", "PARITY-CMD-017");
    assert_eq!(request.database, b"next_db");
    assert_eq!(request.character_set, Some(45));
    assert_eq!(request.auth_response, &[1, 3, 3, 7]);

    let malformed = load_trace("change-user-malformed")?;
    let payload = only_payload(&malformed[0])?;
    assert!(matches!(
        parse_change_user(payload, CLIENT_CAPS),
        Err(DecodeError::LengthExceedsInput { .. })
    ));
    Ok(())
}
