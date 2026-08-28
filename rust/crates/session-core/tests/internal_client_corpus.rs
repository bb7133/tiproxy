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

//! SES-08 checks over the exact Go-generated `migration-session-state`
//! corpus bytes (`PARITY-RSP-007` / `PARITY-MIG-002`).

use std::error::Error;
use std::fs::File;
use std::io::{Error as IoError, ErrorKind, Read};
use std::path::PathBuf;

use flate2::read::GzDecoder;
use mysql_wire::{CapabilityFlags, MAX_PAYLOAD_LEN, PhysicalPacket};
use session_core::internal_client::{
    InternalLimits, InternalParserState, InternalProgress, InternalQuery, InternalResult,
};

const TRACE_MAGIC: &[u8; 8] = b"TPXCRP1\n";
const BACKEND_TO_PROXY: u8 = 3;
const PROXY_TO_BACKEND: u8 = 4;
const MODERN_CAPS: CapabilityFlags =
    CapabilityFlags::PROTOCOL_41.union(CapabilityFlags::DEPRECATE_EOF);

#[derive(Debug)]
struct TraceRecord {
    direction: u8,
    wire: Vec<u8>,
}

fn corpus_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../tests/dataplane/corpus/v1")
}

fn corpus_trace() -> PathBuf {
    corpus_root().join("cases/migration-session-state.trace.gz")
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

fn load_trace() -> Result<Vec<TraceRecord>, Box<dyn Error>> {
    let mut decoder = GzDecoder::new(File::open(corpus_trace())?);
    let mut bytes = Vec::new();
    decoder.read_to_end(&mut bytes)?;

    let mut position = 0;
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
        records.push(TraceRecord {
            direction,
            wire: take(&bytes, &mut position, wire_len, "record wire")?.to_vec(),
        });
    }
    if position != bytes.len() {
        return Err(IoError::new(ErrorKind::InvalidData, "trailing trace bytes").into());
    }
    Ok(records)
}

fn logical_payloads(
    records: &[TraceRecord],
    direction: u8,
) -> Result<Vec<Vec<u8>>, Box<dyn Error>> {
    let mut logical = Vec::new();
    for record in records
        .iter()
        .filter(|record| record.direction == direction)
    {
        let mut remaining = record.wire.as_slice();
        let mut payload = Vec::new();
        while !remaining.is_empty() {
            let (physical, tail) = PhysicalPacket::decode(remaining)?;
            let payload_length = physical.header().payload_length();
            payload.extend_from_slice(physical.payload());
            remaining = tail;
            if payload_length < MAX_PAYLOAD_LEN {
                logical.push(std::mem::take(&mut payload));
            }
        }
        if !payload.is_empty() {
            return Err(
                IoError::new(ErrorKind::InvalidData, "trace ends inside a logical packet").into(),
            );
        }
    }
    Ok(logical)
}

#[test]
fn migration_query_and_result_match_go_corpus() -> Result<(), Box<dyn Error>> {
    let records = load_trace()?;
    assert_eq!(
        logical_payloads(&records, PROXY_TO_BACKEND)?,
        vec![InternalQuery::ShowSessionStates.encode(InternalLimits::default())?]
    );

    let mut parser =
        InternalQuery::ShowSessionStates.parser(MODERN_CAPS, InternalLimits::default())?;
    let mut result = None;
    for payload in logical_payloads(&records, BACKEND_TO_PROXY)? {
        match parser.consume(&payload)? {
            InternalProgress::Continue => {}
            InternalProgress::Complete(completed) => result = Some(completed),
        }
    }
    let Some(InternalResult::SessionStates(snapshot)) = result else {
        return Err(IoError::new(
            ErrorKind::InvalidData,
            "corpus did not produce session state",
        )
        .into());
    };
    assert_eq!(snapshot.session_states(), r#"{"current-db":"corpus_db"}"#);
    assert_eq!(snapshot.session_token(), "synthetic-token-1");
    assert_eq!(snapshot.current_database(), Some("corpus_db"));
    assert_eq!(parser.state(), InternalParserState::Complete);
    Ok(())
}

#[test]
fn ordinary_response_source_has_no_internal_client_dependency() {
    const USER_RESPONSE_SOURCE: &str = include_str!("../src/response.rs");
    assert!(USER_RESPONSE_SOURCE.contains("RESPONSE_OBSERVER_PREFIX_LIMIT: usize = 23"));
    assert!(
        !USER_RESPONSE_SOURCE.contains("internal_client"),
        "ordinary response forwarding must not import or call the full row parser"
    );
}

#[test]
fn corpus_manifest_links_ses_08_parity_contracts() -> Result<(), Box<dyn Error>> {
    let manifest = std::fs::read_to_string(corpus_root().join("manifest.json"))?;
    for required in [
        r#""id": "migration-session-state""#,
        r#""RSP-007""#,
        r#""MIG-002""#,
    ] {
        assert!(manifest.contains(required), "missing {required}");
    }
    Ok(())
}
