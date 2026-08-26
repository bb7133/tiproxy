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

//! SES-05 lifecycle checks over exact generated Go corpus bytes.

use std::error::Error;
use std::fs::{File, read_to_string};
use std::io::{Error as IoError, ErrorKind, Read};
use std::num::NonZeroU64;
use std::path::PathBuf;

use flate2::read::GzDecoder;
use mysql_wire::{
    CapabilityFlags, ColumnType, CommandCode, CommandPacket, MAX_PAYLOAD_LEN, ParameterType,
    ParameterValue, PhysicalPacket,
};
use session_core::command::{Command, ExpectedResponse, dispatch};
use session_core::fsm::{SessionEvent, SessionFsm, SessionState};
use session_core::prepared::{
    PrepareDisposition, PrepareMetadata, PrepareObserver, PreparedGuard, PreparedRegistry,
    PreparedStatementState,
};
use session_core::response::{
    FlushAction, RESPONSE_OBSERVER_PREFIX_LIMIT, ResponseDisposition, ResponseEffect,
    ResponseObserver, ResponsePacket,
};

const TRACE_MAGIC: &[u8; 8] = b"TPXCRP1\n";
const LEGACY_CAPS: CapabilityFlags = CapabilityFlags::PROTOCOL_41;

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

fn logical_packets(record: &TraceRecord) -> Result<Vec<LogicalPacket>, Box<dyn Error>> {
    let mut packets = Vec::new();
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
            "record ends inside a logical packet",
        )
        .into());
    }
    Ok(packets)
}

fn response_packet(logical: &LogicalPacket) -> Result<ResponsePacket<'_>, Box<dyn Error>> {
    let prefix_length = logical.payload.len().min(RESPONSE_OBSERVER_PREFIX_LIMIT);
    Ok(ResponsePacket::from_forwarded(
        &logical.payload[..prefix_length],
        u64::try_from(logical.payload.len())?,
        logical.first_physical_payload_bytes,
        logical.physical_packets,
    )?)
}

fn only_client_payload(record: &TraceRecord) -> Result<Vec<u8>, Box<dyn Error>> {
    if record.direction != 1 {
        return Err(IoError::new(ErrorKind::InvalidData, "record is not client traffic").into());
    }
    let mut packets = logical_packets(record)?;
    if packets.len() != 1 {
        return Err(IoError::new(
            ErrorKind::InvalidData,
            "client command record is not one logical packet",
        )
        .into());
    }
    Ok(packets.remove(0).payload)
}

fn ready_fsm() -> Result<SessionFsm, Box<dyn Error>> {
    let mut fsm = SessionFsm::new();
    for event in [
        SessionEvent::ConnectionAccepted,
        SessionEvent::ClientHandshakeResponse,
        SessionEvent::BackendGreetingReceived,
        SessionEvent::BackendAuthOk,
    ] {
        fsm.on_event(event)?;
    }
    assert_eq!(fsm.state(), SessionState::Ready);
    Ok(fsm)
}

fn observe_record(
    record: &TraceRecord,
    response: ExpectedResponse,
) -> Result<Vec<ResponseEffect>, Box<dyn Error>> {
    if record.direction != 3 {
        return Err(IoError::new(ErrorKind::InvalidData, "record is not backend traffic").into());
    }
    let mut observer = ResponseObserver::new(response, LEGACY_CAPS, false, NonZeroU64::MAX)?;
    let packets = logical_packets(record)?;
    let mut effects = Vec::with_capacity(packets.len());
    for logical in &packets {
        effects.push(observer.observe_backend(response_packet(logical)?)?);
    }
    assert!(observer.is_complete());
    assert_eq!(observer.retained_payload_bytes(), 0);
    Ok(effects)
}

fn lifecycle_registry() -> PreparedRegistry {
    let mut registry = PreparedRegistry::new();
    for statement_id in [7, 8] {
        registry.register(PrepareMetadata {
            statement_id,
            parameter_count: 0,
            column_count: u16::from(statement_id == 8),
            warnings: 0,
        });
    }
    registry
}

#[test]
fn parity_rsp_006_prepare_metadata_modes_match_go_corpus() -> Result<(), Box<dyn Error>> {
    for (case_id, capabilities, expected) in [
        (
            "stmt-prepare-metadata",
            LEGACY_CAPS,
            PrepareMetadata {
                statement_id: 7,
                parameter_count: 1,
                column_count: 1,
                warnings: 0,
            },
        ),
        (
            "stmt-prepare-metadata-deprecate-eof",
            LEGACY_CAPS | CapabilityFlags::DEPRECATE_EOF,
            PrepareMetadata {
                statement_id: 9,
                parameter_count: 1,
                column_count: 1,
                warnings: 0,
            },
        ),
    ] {
        let records = load_trace(case_id)?;
        let backend = records
            .iter()
            .find(|record| record.direction == 3)
            .ok_or_else(|| IoError::new(ErrorKind::InvalidData, "missing prepare response"))?;
        let mut observer = PrepareObserver::new(capabilities);
        let mut flushes = 0_usize;
        let mut final_disposition = None;
        for logical in &logical_packets(backend)? {
            let effect = observer.observe(response_packet(logical)?)?;
            flushes += usize::from(effect.flush != FlushAction::None);
            final_disposition = Some(effect.disposition);
        }
        assert_eq!(
            final_disposition,
            Some(PrepareDisposition::CompleteSuccess(expected)),
            "{case_id}"
        );
        assert_eq!(flushes, 1, "{case_id}");
        assert!(observer.is_complete(), "{case_id}");
    }
    Ok(())
}

#[test]
fn parity_ps_004_execute_types_and_reuse_match_go_corpus() -> Result<(), Box<dyn Error>> {
    let records = load_trace("stmt-execute-types-reuse")?;
    let client_records: Vec<_> = records
        .iter()
        .filter(|record| record.direction == 1)
        .collect();
    assert_eq!(client_records.len(), 2);

    let mut registry = PreparedRegistry::new();
    registry.register(PrepareMetadata {
        statement_id: 42,
        parameter_count: 4,
        column_count: 0,
        warnings: 0,
    });
    let first_payload = only_client_payload(client_records[0])?;
    let first = registry.decode_execute(&first_payload)?;
    assert!(first.new_params_bound);
    assert_eq!(first.parameters[0].value, ParameterValue::Int64(-7));
    assert_eq!(first.parameters[1].value, ParameterValue::UInt64(u64::MAX));
    assert_eq!(first.parameters[2].value, ParameterValue::Bytes(b"blob"));
    assert_eq!(first.parameters[3].value, ParameterValue::Null);
    assert_eq!(
        registry
            .get(42)
            .map(PreparedStatementState::parameter_types),
        Some(
            [
                ParameterType {
                    column_type: ColumnType::LongLong,
                    flags: 0,
                },
                ParameterType {
                    column_type: ColumnType::LongLong,
                    flags: 0x80,
                },
                ParameterType {
                    column_type: ColumnType::String,
                    flags: 0,
                },
                ParameterType {
                    column_type: ColumnType::Null,
                    flags: 0,
                },
            ]
            .as_slice()
        )
    );

    let reuse_payload = only_client_payload(client_records[1])?;
    let reuse = registry.decode_execute(&reuse_payload)?;
    assert!(!reuse.new_params_bound);
    assert_eq!(reuse.parameters, first.parameters);
    Ok(())
}

#[test]
fn parity_ps_001_002_003_005_006_lifecycle_matches_go_corpus() -> Result<(), Box<dyn Error>> {
    let records = load_trace("stmt-lifecycle-independent")?;
    let mut registry = lifecycle_registry();
    let mut fsm = ready_fsm()?;
    let mut current = None;
    let mut pending_after_command = Vec::new();

    for record in &records {
        match record.direction {
            1 => {
                assert!(
                    current.is_none(),
                    "previous command still awaits a response"
                );
                assert_eq!(fsm.state(), SessionState::Ready);
                let payload = only_client_payload(record)?;
                let packet = CommandPacket::decode(&payload)?;
                let plan = dispatch(packet)?;
                let statement_id = match plan.command {
                    Command::StmtExecute
                    | Command::StmtSendLongData
                    | Command::StmtClose
                    | Command::StmtReset
                    | Command::StmtFetch => Some(PreparedRegistry::statement_id(
                        &payload,
                        CommandCode::from_byte(plan.command.as_byte()),
                    )?),
                    _ => None,
                };
                fsm.on_event(SessionEvent::ClientCommand)?;
                if let Some(mutation) = plan.after_forward.prepared {
                    registry.apply_mutation(mutation);
                }
                fsm.on_event(registry.session_event())?;
                if plan.response == ExpectedResponse::None {
                    fsm.on_event(SessionEvent::NoResponseCommandComplete)?;
                    pending_after_command.push(registry.has_pending());
                } else {
                    current = Some((
                        plan.command,
                        plan.response,
                        plan.after_success.prepared,
                        statement_id,
                    ));
                }
            }
            3 => {
                let (command, response, after_success, statement_id) =
                    current.take().ok_or_else(|| {
                        IoError::new(ErrorKind::InvalidData, "orphan backend response")
                    })?;
                for effect in observe_record(record, response)? {
                    let success = effect.disposition == ResponseDisposition::CompleteSuccess;
                    if success && let Some(mutation) = after_success {
                        registry.apply_mutation(mutation);
                    }
                    if let Some(statement_id) = statement_id {
                        registry.observe_response(command, statement_id, effect);
                    }
                    if !matches!(
                        effect.disposition,
                        ResponseDisposition::Continue | ResponseDisposition::MoreResults
                    ) {
                        fsm.on_event(registry.session_event())?;
                    }
                    fsm.on_event(effect.session_event())?;
                }
                assert_eq!(fsm.state(), SessionState::Ready);
                pending_after_command.push(registry.has_pending());
            }
            other => {
                return Err(IoError::new(
                    ErrorKind::InvalidData,
                    format!("unexpected trace direction {other}"),
                )
                .into());
            }
        }
    }

    assert!(current.is_none());
    assert_eq!(
        pending_after_command,
        [true, true, true, true, true, false, false]
    );
    assert_eq!(
        registry.get(7).map(PreparedStatementState::guard),
        Some(PreparedGuard::Idle)
    );
    assert!(registry.get(8).is_none());
    assert!(!fsm.flags().prepared_pending);
    assert_eq!(fsm.state(), SessionState::Ready);
    Ok(())
}

#[test]
fn corpus_manifest_links_every_ses_05_parity_item() -> Result<(), Box<dyn Error>> {
    let manifest = read_to_string(corpus_root().join("manifest.json"))?;
    for parity_id in [
        "RSP-006", "PS-001", "PS-002", "PS-003", "PS-004", "PS-005", "PS-006",
    ] {
        assert!(
            manifest.contains(&format!("\"{parity_id}\"")),
            "missing {parity_id}"
        );
    }
    Ok(())
}
