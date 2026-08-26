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

//! SES-04 response-boundary checks over exact generated Go corpus bytes.

use std::error::Error;
use std::fs::File;
use std::io::{Error as IoError, ErrorKind, Read};
use std::num::NonZeroU64;
use std::path::PathBuf;

use flate2::read::GzDecoder;
use mysql_wire::{CapabilityFlags, MAX_PAYLOAD_LEN, PhysicalPacket, StatusFlags};
use session_core::command::ExpectedResponse;
use session_core::response::{
    FlushAction, PacketRole, RESPONSE_OBSERVER_PREFIX_LIMIT, ResponseDisposition, ResponseObserver,
    ResponsePacket,
};

const TRACE_MAGIC: &[u8; 8] = b"TPXCRP1\n";
const LEGACY_CAPS: CapabilityFlags = CapabilityFlags::PROTOCOL_41;
const MODERN_CAPS: CapabilityFlags =
    CapabilityFlags::PROTOCOL_41.union(CapabilityFlags::DEPRECATE_EOF);

#[derive(Debug)]
struct TraceRecord {
    direction: u8,
    wire: Vec<u8>,
}

#[derive(Debug)]
struct LogicalPacket {
    payload: Vec<u8>,
    first_physical_payload_bytes: u32,
    physical_packets: u64,
}

#[derive(Debug, Clone, Copy)]
struct CorpusExpectation {
    case_id: &'static str,
    response: ExpectedResponse,
    capabilities: CapabilityFlags,
    roles: &'static [PacketRole],
    final_disposition: ResponseDisposition,
    final_status: Option<StatusFlags>,
    boundary_packets: &'static [usize],
}

const CASES: &[CorpusExpectation] = &[
    CorpusExpectation {
        case_id: "query-ok",
        response: ExpectedResponse::Query,
        capabilities: LEGACY_CAPS,
        roles: &[PacketRole::Ok],
        final_disposition: ResponseDisposition::CompleteSuccess,
        final_status: Some(StatusFlags::AUTOCOMMIT),
        boundary_packets: &[0],
    },
    CorpusExpectation {
        case_id: "query-error",
        response: ExpectedResponse::Query,
        capabilities: LEGACY_CAPS,
        roles: &[PacketRole::Error],
        final_disposition: ResponseDisposition::CompleteError { code: 1064 },
        final_status: None,
        boundary_packets: &[0],
    },
    CorpusExpectation {
        case_id: "resultset-legacy-eof",
        response: ExpectedResponse::Query,
        capabilities: LEGACY_CAPS,
        roles: &[
            PacketRole::ResultsetHeader,
            PacketRole::ColumnDefinition,
            PacketRole::Terminator,
            PacketRole::Row,
            PacketRole::Terminator,
        ],
        final_disposition: ResponseDisposition::CompleteSuccess,
        final_status: Some(StatusFlags::AUTOCOMMIT),
        boundary_packets: &[4],
    },
    CorpusExpectation {
        case_id: "resultset-deprecate-eof",
        response: ExpectedResponse::Query,
        capabilities: MODERN_CAPS,
        roles: &[
            PacketRole::ResultsetHeader,
            PacketRole::ResultsetData,
            PacketRole::ResultsetData,
            PacketRole::Terminator,
        ],
        final_disposition: ResponseDisposition::CompleteSuccess,
        final_status: Some(StatusFlags::AUTOCOMMIT),
        boundary_packets: &[3],
    },
    CorpusExpectation {
        case_id: "query-multi-results",
        response: ExpectedResponse::Query,
        capabilities: MODERN_CAPS,
        roles: &[PacketRole::Ok, PacketRole::Ok],
        final_disposition: ResponseDisposition::CompleteSuccess,
        final_status: Some(StatusFlags::AUTOCOMMIT),
        boundary_packets: &[0, 1],
    },
    CorpusExpectation {
        case_id: "local-infile",
        response: ExpectedResponse::Query,
        capabilities: LEGACY_CAPS,
        roles: &[PacketRole::LocalInfileRequest, PacketRole::Ok],
        final_disposition: ResponseDisposition::CompleteSuccess,
        final_status: Some(StatusFlags::AUTOCOMMIT),
        boundary_packets: &[0, 1],
    },
    CorpusExpectation {
        case_id: "stmt-execute-cursor",
        response: ExpectedResponse::Query,
        capabilities: LEGACY_CAPS,
        roles: &[
            PacketRole::ResultsetHeader,
            PacketRole::ColumnDefinition,
            PacketRole::Terminator,
        ],
        final_disposition: ResponseDisposition::CompleteSuccess,
        final_status: Some(StatusFlags::AUTOCOMMIT.union(StatusFlags::CURSOR_EXISTS)),
        boundary_packets: &[2],
    },
    CorpusExpectation {
        case_id: "stmt-fetch",
        response: ExpectedResponse::Fetch,
        capabilities: LEGACY_CAPS,
        roles: &[PacketRole::Row, PacketRole::Terminator],
        final_disposition: ResponseDisposition::CompleteSuccess,
        final_status: Some(StatusFlags::AUTOCOMMIT.union(StatusFlags::LAST_ROW_SENT)),
        boundary_packets: &[1],
    },
    CorpusExpectation {
        case_id: "statistics",
        response: ExpectedResponse::Statistics,
        capabilities: LEGACY_CAPS,
        roles: &[PacketRole::Raw],
        final_disposition: ResponseDisposition::CompleteRaw,
        final_status: None,
        boundary_packets: &[0],
    },
    CorpusExpectation {
        case_id: "field-list",
        response: ExpectedResponse::FieldList,
        capabilities: LEGACY_CAPS,
        roles: &[PacketRole::ColumnDefinition, PacketRole::Terminator],
        final_disposition: ResponseDisposition::CompleteSuccess,
        final_status: Some(StatusFlags::AUTOCOMMIT),
        boundary_packets: &[1],
    },
    CorpusExpectation {
        case_id: "process-info",
        response: ExpectedResponse::Query,
        capabilities: LEGACY_CAPS,
        roles: &[
            PacketRole::ResultsetHeader,
            PacketRole::ColumnDefinition,
            PacketRole::Terminator,
            PacketRole::Row,
            PacketRole::Terminator,
        ],
        final_disposition: ResponseDisposition::CompleteSuccess,
        final_status: Some(StatusFlags::AUTOCOMMIT),
        boundary_packets: &[4],
    },
    CorpusExpectation {
        case_id: "set-option",
        response: ExpectedResponse::OnePacket,
        capabilities: LEGACY_CAPS,
        roles: &[PacketRole::Terminator],
        final_disposition: ResponseDisposition::CompleteSuccess,
        final_status: Some(StatusFlags::AUTOCOMMIT),
        boundary_packets: &[0],
    },
    CorpusExpectation {
        case_id: "ping",
        response: ExpectedResponse::OnePacket,
        capabilities: LEGACY_CAPS,
        roles: &[PacketRole::Ok],
        final_disposition: ResponseDisposition::CompleteSuccess,
        final_status: Some(StatusFlags::AUTOCOMMIT),
        boundary_packets: &[0],
    },
    CorpusExpectation {
        case_id: "command-sleep",
        response: ExpectedResponse::OnePacket,
        capabilities: LEGACY_CAPS,
        roles: &[PacketRole::Error],
        final_disposition: ResponseDisposition::CompleteError { code: 1064 },
        final_status: None,
        boundary_packets: &[0],
    },
];

fn corpus_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../tests/dataplane/corpus/v1")
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

fn load_trace(case_id: &str) -> Result<Vec<TraceRecord>, Box<dyn Error>> {
    let path = corpus_root()
        .join("cases")
        .join(format!("{case_id}.trace.gz"));
    let mut decoder = GzDecoder::new(File::open(path)?);
    let mut bytes = Vec::new();
    decoder.read_to_end(&mut bytes)?;

    let mut position = 0_usize;
    if take(&bytes, &mut position, TRACE_MAGIC.len(), "trace magic")? != TRACE_MAGIC {
        return Err(IoError::new(ErrorKind::InvalidData, "invalid trace magic").into());
    }
    let count = u32::from_le_bytes(take(&bytes, &mut position, 4, "record count")?.try_into()?);
    let mut records = Vec::with_capacity(usize::try_from(count)?);
    for _ in 0..count {
        let direction = take(&bytes, &mut position, 1, "record direction")?[0];
        let wire_len =
            u64::from_le_bytes(take(&bytes, &mut position, 8, "record length")?.try_into()?);
        let wire_len = usize::try_from(wire_len)
            .map_err(|_| IoError::new(ErrorKind::InvalidData, "record length exceeds host"))?;
        let wire = take(&bytes, &mut position, wire_len, "record wire")?.to_vec();
        records.push(TraceRecord { direction, wire });
    }
    if position != bytes.len() {
        return Err(IoError::new(ErrorKind::InvalidData, "trailing trace bytes").into());
    }
    Ok(records)
}

fn backend_logical_packets(records: &[TraceRecord]) -> Result<Vec<LogicalPacket>, Box<dyn Error>> {
    let mut packets = Vec::new();
    for record in records.iter().filter(|record| record.direction == 3) {
        let mut remaining = record.wire.as_slice();
        let mut payload = Vec::new();
        let mut first_physical_payload_bytes = None;
        let mut physical_packets = 0_u64;
        while !remaining.is_empty() {
            let (physical, tail) = PhysicalPacket::decode(remaining)?;
            let payload_length = physical.header().payload_length();
            first_physical_payload_bytes.get_or_insert(payload_length);
            payload.extend_from_slice(physical.payload());
            physical_packets = physical_packets
                .checked_add(1)
                .ok_or_else(|| IoError::new(ErrorKind::InvalidData, "physical packet overflow"))?;
            remaining = tail;
            if payload_length < MAX_PAYLOAD_LEN {
                packets.push(LogicalPacket {
                    payload: std::mem::take(&mut payload),
                    first_physical_payload_bytes: first_physical_payload_bytes.take().ok_or_else(
                        || IoError::new(ErrorKind::InvalidData, "missing first physical packet"),
                    )?,
                    physical_packets,
                });
                physical_packets = 0;
            }
        }
        if first_physical_payload_bytes.is_some() || !payload.is_empty() {
            return Err(IoError::new(
                ErrorKind::InvalidData,
                "backend record ends inside a logical packet",
            )
            .into());
        }
    }
    Ok(packets)
}

#[test]
fn parity_rsp_001_through_005_and_008_match_go_corpus() -> Result<(), Box<dyn Error>> {
    for expectation in CASES {
        let records = load_trace(expectation.case_id)?;
        let packets = backend_logical_packets(&records)?;
        assert_eq!(
            packets.len(),
            expectation.roles.len(),
            "{}",
            expectation.case_id
        );
        let mut observer = ResponseObserver::new(
            expectation.response,
            expectation.capabilities,
            false,
            NonZeroU64::MAX,
        )?;
        let mut final_effect = None;
        for (index, logical) in packets.iter().enumerate() {
            let logical_payload_bytes = u64::try_from(logical.payload.len())?;
            let prefix_length = logical.payload.len().min(RESPONSE_OBSERVER_PREFIX_LIMIT);
            let packet = ResponsePacket::from_forwarded(
                &logical.payload[..prefix_length],
                logical_payload_bytes,
                logical.first_physical_payload_bytes,
                logical.physical_packets,
            )?;
            let effect = observer.observe_backend(packet)?;
            assert_eq!(
                effect.role, expectation.roles[index],
                "{} packet {index}",
                expectation.case_id
            );
            assert_eq!(
                effect.flush == FlushAction::ProtocolBoundary,
                expectation.boundary_packets.contains(&index),
                "{} packet {index}",
                expectation.case_id
            );
            final_effect = Some(effect);
        }
        let final_effect = final_effect.ok_or_else(|| {
            IoError::new(
                ErrorKind::InvalidData,
                format!("{} has no backend packets", expectation.case_id),
            )
        })?;
        assert_eq!(
            final_effect.disposition, expectation.final_disposition,
            "{}",
            expectation.case_id
        );
        assert_eq!(
            final_effect.status, expectation.final_status,
            "{}",
            expectation.case_id
        );
        assert!(observer.is_complete(), "{}", expectation.case_id);
        assert_eq!(observer.retained_payload_bytes(), 0);
    }
    Ok(())
}

#[test]
fn corpus_manifest_links_every_ses_04_parity_item() -> Result<(), Box<dyn Error>> {
    let manifest = std::fs::read_to_string(corpus_root().join("manifest.json"))?;
    for parity_id in [
        "RSP-001", "RSP-002", "RSP-003", "RSP-004", "RSP-005", "RSP-008",
    ] {
        assert!(
            manifest.contains(&format!("\"{parity_id}\"")),
            "{parity_id}"
        );
    }
    Ok(())
}
