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

//! SES-03 dispatch checks over the exact generated Go corpus bytes.

use std::error::Error;
use std::fs::{File, read_to_string};
use std::io::{Error as IoError, ErrorKind, Read};
use std::path::PathBuf;

use flate2::read::GzDecoder;
use mysql_wire::{CommandPacket, PhysicalPacket};
use session_core::command::{
    Command, CommandDispatchError, ExpectedResponse, PreparedMutation, SessionMutation, dispatch,
};

const TRACE_MAGIC: &[u8; 8] = b"TPXCRP1\n";

#[derive(Debug)]
struct TraceRecord {
    direction: u8,
    wire: Vec<u8>,
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

fn client_command(records: &[TraceRecord]) -> Result<CommandPacket<'_>, Box<dyn Error>> {
    let record = records
        .iter()
        .find(|record| record.direction == 1)
        .ok_or_else(|| IoError::new(ErrorKind::InvalidData, "missing client command"))?;
    let (packet, tail) = PhysicalPacket::decode(&record.wire)?;
    if !tail.is_empty() {
        return Err(IoError::new(
            ErrorKind::InvalidData,
            "command corpus record contains multiple physical packets",
        )
        .into());
    }
    Ok(CommandPacket::decode(packet.payload())?)
}

fn first_backend_payload(records: &[TraceRecord]) -> Result<Option<&[u8]>, Box<dyn Error>> {
    let Some(record) = records.iter().find(|record| record.direction == 3) else {
        return Ok(None);
    };
    let (packet, _) = PhysicalPacket::decode(&record.wire)?;
    Ok(Some(packet.payload()))
}

const DISPATCH_CASES: [(&str, Command, ExpectedResponse); 32] = [
    ("command-sleep", Command::Sleep, ExpectedResponse::OnePacket),
    ("quit", Command::Quit, ExpectedResponse::None),
    ("init-db", Command::InitDb, ExpectedResponse::OnePacket),
    ("query-ok", Command::Query, ExpectedResponse::Query),
    (
        "field-list",
        Command::FieldList,
        ExpectedResponse::FieldList,
    ),
    (
        "command-create-db",
        Command::CreateDb,
        ExpectedResponse::OnePacket,
    ),
    (
        "command-drop-db",
        Command::DropDb,
        ExpectedResponse::OnePacket,
    ),
    (
        "command-refresh",
        Command::Refresh,
        ExpectedResponse::OnePacket,
    ),
    (
        "command-deprecated-shutdown",
        Command::DeprecatedShutdown,
        ExpectedResponse::OnePacket,
    ),
    (
        "statistics",
        Command::Statistics,
        ExpectedResponse::Statistics,
    ),
    (
        "process-info",
        Command::ProcessInfo,
        ExpectedResponse::Query,
    ),
    (
        "command-connect",
        Command::Connect,
        ExpectedResponse::OnePacket,
    ),
    (
        "command-process-kill",
        Command::ProcessKill,
        ExpectedResponse::OnePacket,
    ),
    ("command-debug", Command::Debug, ExpectedResponse::OnePacket),
    ("ping", Command::Ping, ExpectedResponse::OnePacket),
    ("command-time", Command::Time, ExpectedResponse::OnePacket),
    (
        "command-delayed-insert",
        Command::DelayedInsert,
        ExpectedResponse::OnePacket,
    ),
    (
        "change-user",
        Command::ChangeUser,
        ExpectedResponse::ChangeUser,
    ),
    (
        "command-binlog-dump",
        Command::BinlogDump,
        ExpectedResponse::OnePacket,
    ),
    (
        "command-table-dump",
        Command::TableDump,
        ExpectedResponse::OnePacket,
    ),
    (
        "command-connect-out",
        Command::ConnectOut,
        ExpectedResponse::OnePacket,
    ),
    (
        "command-register-slave",
        Command::RegisterSlave,
        ExpectedResponse::OnePacket,
    ),
    (
        "stmt-prepare-metadata",
        Command::StmtPrepare,
        ExpectedResponse::Prepare,
    ),
    (
        "stmt-execute-cursor",
        Command::StmtExecute,
        ExpectedResponse::Query,
    ),
    (
        "stmt-long-data",
        Command::StmtSendLongData,
        ExpectedResponse::None,
    ),
    ("stmt-close", Command::StmtClose, ExpectedResponse::None),
    (
        "stmt-reset",
        Command::StmtReset,
        ExpectedResponse::OnePacket,
    ),
    (
        "set-option",
        Command::SetOption,
        ExpectedResponse::OnePacket,
    ),
    ("stmt-fetch", Command::StmtFetch, ExpectedResponse::Fetch),
    (
        "command-daemon",
        Command::Daemon,
        ExpectedResponse::OnePacket,
    ),
    (
        "command-binlog-dump-gtid",
        Command::BinlogDumpGtid,
        ExpectedResponse::OnePacket,
    ),
    (
        "reset-connection",
        Command::ResetConnection,
        ExpectedResponse::OnePacket,
    ),
];

#[test]
fn parity_cmd_000_through_031_dispatch_from_go_corpus() -> Result<(), Box<dyn Error>> {
    for (index, (case_id, expected_command, expected_response)) in
        DISPATCH_CASES.into_iter().enumerate()
    {
        let trace = load_trace(case_id)?;
        let plan = dispatch(client_command(&trace)?)?;
        assert_eq!(plan.command, expected_command, "PARITY-CMD-{index:03}");
        assert_eq!(plan.command.as_byte(), u8::try_from(index)?);
        assert_eq!(plan.response, expected_response, "case {case_id}");
        match expected_response {
            ExpectedResponse::None => {
                assert!(first_backend_payload(&trace)?.is_none(), "case {case_id}");
            }
            ExpectedResponse::OnePacket => {
                let payload = first_backend_payload(&trace)?.ok_or_else(|| {
                    IoError::new(
                        ErrorKind::InvalidData,
                        format!("case {case_id} has no backend response"),
                    )
                })?;
                assert!(
                    matches!(payload.first(), Some(0x00 | 0xfe | 0xff)),
                    "case {case_id} has a non-generic response header"
                );
            }
            ExpectedResponse::Query
            | ExpectedResponse::FieldList
            | ExpectedResponse::Statistics
            | ExpectedResponse::ChangeUser
            | ExpectedResponse::Prepare
            | ExpectedResponse::Fetch => {}
        }
    }
    Ok(())
}

#[test]
fn corpus_drives_command_state_effects() -> Result<(), Box<dyn Error>> {
    let init = load_trace("init-db")?;
    assert_eq!(
        dispatch(client_command(&init)?)?.after_success.session,
        Some(SessionMutation::SetCurrentDatabase(b"next_db"))
    );

    for (case_id, enabled) in [("set-option", true), ("set-option-disable", false)] {
        let trace = load_trace(case_id)?;
        assert_eq!(
            dispatch(client_command(&trace)?)?.after_success.session,
            Some(SessionMutation::SetMultiStatements(enabled))
        );
    }

    let reset = load_trace("reset-connection")?;
    let plan = dispatch(client_command(&reset)?)?;
    assert_eq!(
        plan.after_success.session,
        Some(SessionMutation::ResetConnection)
    );
    assert_eq!(
        plan.after_success.prepared,
        Some(PreparedMutation::ClearAll)
    );
    Ok(())
}

#[test]
fn parity_cmd_032_and_unknown_policy_are_safe() -> Result<(), Box<dyn Error>> {
    for (case_id, byte) in [("command-end-sentinel", 0x20), ("command-unknown", 0xff)] {
        let trace = load_trace(case_id)?;
        assert_eq!(
            dispatch(client_command(&trace)?),
            Err(CommandDispatchError::UnknownCommand { byte }),
            "PARITY-CMD-032 case {case_id}"
        );
    }

    let malformed = load_trace("set-option-malformed")?;
    assert_eq!(
        dispatch(client_command(&malformed)?),
        Err(CommandDispatchError::InvalidSetOption { value: 2 })
    );
    Ok(())
}

#[test]
fn manifest_mentions_every_stable_command_id() -> Result<(), Box<dyn Error>> {
    let manifest = read_to_string(corpus_root().join("manifest.json"))?;
    for index in 0..=32 {
        let id = format!("CMD-{index:03}");
        assert!(manifest.contains(&format!("\"{id}\"")), "missing {id}");
    }
    Ok(())
}
