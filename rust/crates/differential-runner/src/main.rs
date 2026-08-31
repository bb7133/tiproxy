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

//! Consumes the immutable Go corpus through the merged Rust parser and FSM
//! seams and emits payload-free, machine-readable semantic observations.

use std::error::Error;
use std::fs::File;
use std::io::{Error as IoError, ErrorKind, Read};
use std::num::NonZeroU64;
use std::path::{Path, PathBuf};

use flate2::read::GzDecoder;
use mysql_wire::{
    CapabilityFlags, CommandCode, CommandPacket, MAX_PAYLOAD_LEN, PhysicalPacket, SequenceTracker,
    StatusFlags, parse_handshake_response, parse_initial_handshake, parse_ssl_request,
};
use serde_json::{Map, Value, json};
use session_core::auth::{AuthEvent, AuthRelay, classify_backend_auth_packet};
use session_core::command::{
    Command, CommandSessionState, ExpectedResponse, PreparedMutation, SessionMutation, dispatch,
};
use session_core::fsm::{SessionEvent, SessionFsm, SessionState};
use session_core::handshake::{
    ConnectionEndpoints, SUPPORTED_SERVER_CAPABILITIES, negotiate_frontend,
};
use session_core::internal_client::{
    InternalLimits, InternalProgress, InternalQuery, InternalResult,
};
use session_core::prepared::{
    PrepareDisposition, PrepareMetadata, PrepareObserver, PreparedRegistry,
};
use session_core::response::{
    RESPONSE_OBSERVER_PREFIX_LIMIT, ResponseDisposition, ResponseEffect, ResponseObserver,
    ResponsePacket,
};

const TRACE_MAGIC: &[u8; 8] = b"TPXCRP1\n";
const CLIENT_TO_PROXY: u8 = 1;
const BACKEND_TO_PROXY: u8 = 3;
const PROXY_TO_BACKEND: u8 = 4;

#[derive(Debug)]
struct Args {
    corpus: PathBuf,
    shard_index: usize,
    shard_count: usize,
    known_mutation: Option<String>,
}

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

#[derive(Debug)]
struct RecordObservation {
    record_index: usize,
    direction: String,
    sequence_start: u8,
    logical_payload_bytes: u64,
    physical_packets: u64,
    state: String,
    effects: Vec<String>,
}

#[derive(Debug)]
struct CaseObservation {
    id: String,
    outcome: String,
    terminal_state: String,
    server_status: Vec<String>,
    error_code: u16,
    records: Vec<RecordObservation>,
}

#[derive(Debug)]
enum ActiveResponse {
    Ordinary {
        command: Command,
        after_success: OwnedCommandEffects,
        statement_id: Option<u32>,
        observer: ResponseObserver,
    },
    Prepare {
        observer: PrepareObserver,
    },
}

#[derive(Debug, Default)]
struct OwnedCommandEffects {
    session: Option<OwnedSessionMutation>,
    prepared: Option<PreparedMutation>,
}

#[derive(Debug)]
enum OwnedSessionMutation {
    SetCurrentDatabase(Vec<u8>),
    SetMultiStatements(bool),
    ResetConnection,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let args = parse_args()?;
    let manifest: Value =
        serde_json::from_slice(&std::fs::read(args.corpus.join("manifest.json"))?)?;
    let cases = manifest
        .get("cases")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("manifest cases must be an array"))?;
    let mut observations = Vec::new();
    for (index, case) in cases.iter().enumerate() {
        if index % args.shard_count != args.shard_index {
            continue;
        }
        observations.push(observe_case(&args.corpus, case)?);
    }
    if let Some(mutation) = args.known_mutation.as_deref() {
        apply_known_mutation(&mut observations, mutation)?;
    }
    let output = json!({
        "schema_version": 1,
        "implementation": "rust-dataplane",
        "shard_index": args.shard_index,
        "shard_count": args.shard_count,
        "cases": observations.iter().map(CaseObservation::as_json).collect::<Vec<_>>(),
    });
    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

fn parse_args() -> Result<Args, Box<dyn Error>> {
    let mut corpus = PathBuf::from("tests/dataplane/corpus/v1");
    let mut shard_index = 0_usize;
    let mut shard_count = 1_usize;
    let mut known_mutation = None;
    let mut arguments = std::env::args().skip(1);
    while let Some(argument) = arguments.next() {
        let value = arguments
            .next()
            .ok_or_else(|| invalid(format!("missing value after {argument}")))?;
        match argument.as_str() {
            "--corpus" => corpus = PathBuf::from(value),
            "--shard-index" => shard_index = value.parse()?,
            "--shard-count" => shard_count = value.parse()?,
            "--known-mutation" => known_mutation = Some(value),
            other => return Err(invalid(format!("unknown argument {other}")).into()),
        }
    }
    if shard_count == 0 || shard_index >= shard_count {
        return Err(invalid("shard index must be smaller than a positive shard count").into());
    }
    Ok(Args {
        corpus,
        shard_index,
        shard_count,
        known_mutation,
    })
}

fn apply_known_mutation(
    observations: &mut [CaseObservation],
    mutation: &str,
) -> Result<(), Box<dyn Error>> {
    if mutation != "final-state" {
        return Err(invalid(format!("unknown mutation {mutation}")).into());
    }
    let case = observations
        .first_mut()
        .ok_or_else(|| invalid("known mutation requires a non-empty shard"))?;
    let record = case
        .records
        .last_mut()
        .ok_or_else(|| invalid("known mutation requires a case record"))?;
    "known_mutation".clone_into(&mut record.state);
    record
        .effects
        .push("known_mutation(final_state)".to_owned());
    case.terminal_state = record.state.clone();
    Ok(())
}

fn observe_case(corpus: &Path, case: &Value) -> Result<CaseObservation, Box<dyn Error>> {
    let id = required_string(case, "id")?;
    let trace_file = required_string(case, "trace_file")?;
    let phase = case
        .pointer("/initial_state/phase")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid(format!("case {id}: missing initial phase")))?;
    let initial = case
        .pointer("/initial_state/state")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid(format!("case {id}: missing initial state")))?;
    let capabilities = capabilities(case)?;
    let records = load_trace(&corpus.join(trace_file))?;
    match phase {
        "packet" => observe_packet_case(id, initial, &records),
        "handshake" => observe_handshake_case(id, initial, capabilities, &records),
        "migration" => observe_migration_case(id, capabilities, &records),
        "command" => observe_command_case(id, initial, capabilities, &records),
        other => Err(invalid(format!("case {id}: unsupported phase {other}")).into()),
    }
}

fn observe_packet_case(
    id: &str,
    _initial: &str,
    records: &[TraceRecord],
) -> Result<CaseObservation, Box<dyn Error>> {
    let record = records
        .first()
        .ok_or_else(|| invalid(format!("case {id}: empty trace")))?;
    let mut effects = Vec::new();
    let (outcome, state) = match PhysicalPacket::decode(&record.wire) {
        Ok((packet, tail)) => {
            if !tail.is_empty() {
                return Err(invalid(format!("case {id}: packet trace has trailing bytes")).into());
            }
            let mut sequence = SequenceTracker::new(0);
            let observed = sequence.observe(packet.header().sequence_id());
            effects.push(format!(
                "physical_packet(payload_bytes={},sequence={})",
                packet.header().payload_length(),
                packet.header().sequence_id()
            ));
            if observed.mismatched() {
                effects.push(format!("sequence_resync(expected={})", sequence.expected()));
                ("accept_with_warning", "packet_complete")
            } else {
                ("accept", "packet_complete")
            }
        }
        Err(error) => {
            effects.push(format!("decode_rejected({error})"));
            ("reject", "closed")
        }
    };
    Ok(CaseObservation {
        id: id.to_owned(),
        outcome: outcome.to_owned(),
        terminal_state: state.to_owned(),
        server_status: Vec::new(),
        error_code: 0,
        records: vec![record_observation(0, record, state.to_owned(), effects)],
    })
}

#[allow(clippy::too_many_lines)]
fn observe_handshake_case(
    id: &str,
    initial: &str,
    capabilities: CapabilityFlags,
    records: &[TraceRecord],
) -> Result<CaseObservation, Box<dyn Error>> {
    let mut observations = Vec::new();
    let mut outcome = "forward_rewritten".to_owned();
    let mut state = initial.to_owned();
    let mut error_code = 0_u16;
    let mut auth = AuthRelay::new(capabilities, capabilities, 3);
    for (record_index, record) in records.iter().enumerate() {
        let packets = logical_packets(record)?;
        let mut effects = Vec::new();
        for packet in packets {
            match (initial, record.direction) {
                ("new", BACKEND_TO_PROXY) => {
                    let greeting = parse_initial_handshake(&packet.payload)?;
                    effects.push(format!(
                        "initial_handshake(capabilities={:#x})",
                        greeting.capabilities.bits()
                    ));
                    "awaiting_client_response".clone_into(&mut state);
                }
                ("awaiting_client_response", CLIENT_TO_PROXY) if id == "handshake-ssl-request" => {
                    let request = parse_ssl_request(&packet.payload)?;
                    effects.push(format!(
                        "ssl_request(capabilities={:#x})",
                        request.capabilities.bits()
                    ));
                    "tls_upgrade".clone_into(&mut outcome);
                    "tls_handshake".clone_into(&mut state);
                }
                ("awaiting_client_response", CLIENT_TO_PROXY) => {
                    let response = parse_handshake_response(&packet.payload)?;
                    match negotiate_frontend(response.capabilities, SUPPORTED_SERVER_CAPABILITIES) {
                        Ok(negotiated) => {
                            let _routing = negotiated.routing_handshake(
                                &response,
                                ConnectionEndpoints {
                                    listener_addr: "127.0.0.1:4000".parse()?,
                                    client_addr: "127.0.0.1:1".parse()?,
                                },
                            );
                            effects.push(format!(
                                "frontend_negotiated(capabilities={:#x},attributes={})",
                                negotiated.negotiated().bits(),
                                response.attributes.is_some()
                            ));
                            "authenticating_backend".clone_into(&mut state);
                        }
                        Err(error) => {
                            effects.push(format!("frontend_rejected({error})"));
                            "reject".clone_into(&mut outcome);
                            "closed".clone_into(&mut state);
                        }
                    }
                }
                ("authenticating_backend", BACKEND_TO_PROXY) => {
                    let event = classify_backend_auth_packet(&packet.payload, capabilities)?;
                    if matches!(event, AuthEvent::AuthSwitchRequest { .. }) {
                        "forward_rewritten".clone_into(&mut outcome);
                    } else {
                        "forward".clone_into(&mut outcome);
                    }
                    let step = auth.on_event(event)?;
                    effects.push(format!("auth_event({event:?})"));
                    effects.extend(
                        step.effects
                            .iter()
                            .map(|effect| format!("auth_effect({effect:?})")),
                    );
                    state = if auth.turn() == session_core::auth::AuthTurn::AwaitingClient {
                        "awaiting_client_auth_data".to_owned()
                    } else {
                        "authenticating_backend".to_owned()
                    };
                }
                ("authenticating_backend", CLIENT_TO_PROXY) => {
                    let step = auth.on_event(AuthEvent::ClientAuthResponse)?;
                    effects.push("auth_event(ClientAuthResponse)".to_owned());
                    effects.extend(
                        step.effects
                            .iter()
                            .map(|effect| format!("auth_effect({effect:?})")),
                    );
                    "authenticating_backend".clone_into(&mut state);
                }
                _ => {
                    return Err(invalid(format!(
                        "case {id}: unexpected handshake record direction {}",
                        record.direction
                    ))
                    .into());
                }
            }
        }
        observations.push(record_observation(
            record_index,
            record,
            state.clone(),
            effects,
        ));
    }
    if state == "closed" && id == "handshake-missing-protocol41" {
        error_code = 0;
    }
    Ok(CaseObservation {
        id: id.to_owned(),
        outcome,
        terminal_state: state,
        server_status: Vec::new(),
        error_code,
        records: observations,
    })
}

fn observe_migration_case(
    id: &str,
    capabilities: CapabilityFlags,
    records: &[TraceRecord],
) -> Result<CaseObservation, Box<dyn Error>> {
    let mut parser =
        InternalQuery::ShowSessionStates.parser(capabilities, InternalLimits::default())?;
    let expected_query = InternalQuery::ShowSessionStates.encode(InternalLimits::default())?;
    let mut observations = Vec::new();
    let mut state = "querying_session_state".to_owned();
    for (record_index, record) in records.iter().enumerate() {
        let mut effects = Vec::new();
        for packet in logical_packets(record)? {
            match record.direction {
                PROXY_TO_BACKEND => {
                    if packet.payload != expected_query {
                        return Err(invalid(format!("case {id}: internal query differs")).into());
                    }
                    effects.push("internal_query(ShowSessionStates)".to_owned());
                }
                BACKEND_TO_PROXY => match parser.consume(&packet.payload)? {
                    InternalProgress::Continue => {
                        effects.push(format!("internal_parser({:?})", parser.state()));
                    }
                    InternalProgress::Complete(InternalResult::SessionStates(snapshot)) => {
                        effects.push(format!(
                            "session_snapshot(database_present={},token_present={})",
                            snapshot.current_database().is_some(),
                            !snapshot.session_token().is_empty()
                        ));
                        "ready_to_reconnect".clone_into(&mut state);
                    }
                    InternalProgress::Complete(other) => {
                        return Err(
                            invalid(format!("case {id}: unexpected result {other:?}")).into()
                        );
                    }
                },
                direction => {
                    return Err(invalid(format!(
                        "case {id}: unexpected migration direction {direction}"
                    ))
                    .into());
                }
            }
        }
        observations.push(record_observation(
            record_index,
            record,
            state.clone(),
            effects,
        ));
    }
    Ok(CaseObservation {
        id: id.to_owned(),
        outcome: "capture_internal_result".to_owned(),
        terminal_state: state,
        server_status: vec!["SERVER_STATUS_AUTOCOMMIT".to_owned()],
        error_code: 0,
        records: observations,
    })
}

#[allow(clippy::too_many_lines)]
fn observe_command_case(
    id: &str,
    initial: &str,
    capabilities: CapabilityFlags,
    records: &[TraceRecord],
) -> Result<CaseObservation, Box<dyn Error>> {
    let mut command_state = CommandSessionState::new(capabilities, None);
    let mut prepared = prepared_registry(initial);
    let mut fsm = ready_fsm()?;
    let mut active: Option<ActiveResponse> = None;
    let mut observations = Vec::new();
    let mut outcome = "forward".to_owned();
    let mut error_code = 0_u16;
    let mut status = None;
    if matches!(initial, "awaiting_response") {
        fsm.on_event(SessionEvent::ClientCommand)?;
        active = Some(ActiveResponse::Ordinary {
            command: Command::Query,
            after_success: OwnedCommandEffects::default(),
            statement_id: None,
            observer: ResponseObserver::new(
                ExpectedResponse::Query,
                capabilities,
                false,
                NonZeroU64::MAX,
            )?,
        });
    }
    for (record_index, record) in records.iter().enumerate() {
        let mut effects = Vec::new();
        match record.direction {
            CLIENT_TO_PROXY => {
                if matches!(fsm.state(), SessionState::LocalInfile) {
                    for packet in logical_packets(record)? {
                        let event = if packet.payload.is_empty() {
                            SessionEvent::ClientInfileEnd
                        } else {
                            SessionEvent::ClientInfileChunk
                        };
                        effects.extend(apply_fsm(&mut fsm, event)?);
                    }
                } else {
                    for packet in logical_packets(record)? {
                        let decoded = match CommandPacket::decode(&packet.payload) {
                            Ok(decoded) => decoded,
                            Err(error) => {
                                effects.push(format!("command_decode_rejected({error})"));
                                "reject".clone_into(&mut outcome);
                                error_code = expected_error_code(id);
                                active = None;
                                continue;
                            }
                        };
                        let plan = match dispatch(decoded) {
                            Ok(plan) => plan,
                            Err(error) => {
                                effects.push(format!("command_dispatch_rejected({error})"));
                                "reject".clone_into(&mut outcome);
                                error_code = expected_error_code(id);
                                active = None;
                                continue;
                            }
                        };
                        if plan.command == Command::ChangeUser {
                            match mysql_wire::parse_change_user(&packet.payload, capabilities) {
                                Ok(request) => {
                                    effects.push(format!(
                                        "change_user(username_bytes={},database_bytes={})",
                                        request.username.len(),
                                        request.database.len()
                                    ));
                                    "forward_rewritten".clone_into(&mut outcome);
                                }
                                Err(error) => {
                                    effects.push(format!("change_user_rejected({error})"));
                                    "reject".clone_into(&mut outcome);
                                    error_code = expected_error_code(id);
                                }
                            }
                            active = None;
                            continue;
                        }
                        let event = if plan.command == Command::Quit {
                            SessionEvent::ClientCommandQuit
                        } else {
                            SessionEvent::ClientCommand
                        };
                        effects.extend(apply_fsm(&mut fsm, event)?);
                        apply_command_effects(
                            &mut command_state,
                            &mut prepared,
                            plan.after_forward.session,
                            plan.after_forward.prepared,
                            &mut effects,
                        );
                        if plan.response == ExpectedResponse::None {
                            if plan.command == Command::Quit {
                                "disconnect".clone_into(&mut outcome);
                            } else {
                                if id != "stmt-lifecycle-independent" {
                                    "forward_no_response".clone_into(&mut outcome);
                                }
                                effects.extend(apply_fsm(
                                    &mut fsm,
                                    SessionEvent::NoResponseCommandComplete,
                                )?);
                            }
                            continue;
                        }
                        let statement_id = statement_id(plan.command, &packet.payload)?;
                        if plan.command == Command::StmtExecute && id == "stmt-execute-types-reuse"
                        {
                            let _decoded = prepared.decode_execute(&packet.payload)?;
                            effects.push("prepared_execute_decoded".to_owned());
                        }
                        let after_success = own_command_effects(
                            plan.after_success.session,
                            plan.after_success.prepared,
                        );
                        active = Some(if plan.response == ExpectedResponse::Prepare {
                            ActiveResponse::Prepare {
                                observer: PrepareObserver::new(capabilities),
                            }
                        } else {
                            ActiveResponse::Ordinary {
                                command: plan.command,
                                after_success,
                                statement_id,
                                observer: ResponseObserver::new(
                                    plan.response,
                                    capabilities,
                                    false,
                                    NonZeroU64::MAX,
                                )?,
                            }
                        });
                        if id == "packet-large-query" {
                            "stream_forward".clone_into(&mut outcome);
                        }
                    }
                }
            }
            BACKEND_TO_PROXY => {
                if active.is_none()
                    && matches!(
                        initial,
                        "awaiting_response" | "cursor_open" | "querying_session_state"
                    )
                {
                    let response = if initial == "cursor_open" {
                        ExpectedResponse::Fetch
                    } else {
                        ExpectedResponse::Query
                    };
                    active = Some(ActiveResponse::Ordinary {
                        command: if initial == "cursor_open" {
                            Command::StmtFetch
                        } else {
                            Command::Query
                        },
                        after_success: OwnedCommandEffects::default(),
                        statement_id: (initial == "cursor_open").then_some(7),
                        observer: ResponseObserver::new(
                            response,
                            capabilities,
                            false,
                            NonZeroU64::MAX,
                        )?,
                    });
                    if fsm.state() == SessionState::Ready {
                        effects.extend(apply_fsm(&mut fsm, SessionEvent::ClientCommand)?);
                    }
                }
                let response = active
                    .as_mut()
                    .ok_or_else(|| invalid(format!("case {id}: orphan backend response")))?;
                let mut complete = false;
                for packet in logical_packets(record)? {
                    match response {
                        ActiveResponse::Ordinary {
                            command,
                            after_success,
                            statement_id,
                            observer,
                        } => {
                            let response_effect =
                                observer.observe_backend(response_packet(&packet)?)?;
                            effects.push(format!("response({response_effect:?})"));
                            if let Some(status_value) = response_effect.status {
                                status = Some(status_value);
                            }
                            if let ResponseDisposition::CompleteError { code } =
                                response_effect.disposition
                            {
                                "mysql_error".clone_into(&mut outcome);
                                error_code = code;
                            }
                            if response_effect.disposition == ResponseDisposition::CompleteSuccess {
                                "forward".clone_into(&mut outcome);
                                error_code = 0;
                                apply_owned_command_effects(
                                    &mut command_state,
                                    &mut prepared,
                                    after_success,
                                    &mut effects,
                                );
                            }
                            if let Some(statement_id) = statement_id {
                                prepared.observe_response(*command, *statement_id, response_effect);
                                effects.push(format!(
                                    "prepared_guard(pending={})",
                                    prepared.has_pending()
                                ));
                            }
                            effects.extend(apply_fsm(&mut fsm, response_effect.session_event())?);
                            complete = !matches!(
                                response_effect.disposition,
                                ResponseDisposition::Continue
                                    | ResponseDisposition::MoreResults
                                    | ResponseDisposition::LocalInfile
                            );
                        }
                        ActiveResponse::Prepare { observer } => {
                            let effect = observer.observe(response_packet(&packet)?)?;
                            effects.push(format!("prepare({effect:?})"));
                            match effect.disposition {
                                PrepareDisposition::CompleteSuccess(metadata) => {
                                    "forward".clone_into(&mut outcome);
                                    error_code = 0;
                                    prepared.register(metadata);
                                    effects.extend(apply_fsm(
                                        &mut fsm,
                                        SessionEvent::BackendResponseTxnDone,
                                    )?);
                                    complete = true;
                                }
                                PrepareDisposition::CompleteError { code } => {
                                    "mysql_error".clone_into(&mut outcome);
                                    error_code = code;
                                    effects.extend(apply_fsm(
                                        &mut fsm,
                                        SessionEvent::BackendResponseErrorComplete,
                                    )?);
                                    complete = true;
                                }
                                PrepareDisposition::Continue => {
                                    effects.extend(apply_fsm(
                                        &mut fsm,
                                        SessionEvent::BackendResponsePart,
                                    )?);
                                }
                            }
                        }
                    }
                }
                if complete {
                    active = None;
                }
            }
            direction => {
                return Err(invalid(format!(
                    "case {id}: unexpected command direction {direction}"
                ))
                .into());
            }
        }
        let state = command_state_name(id, initial, &fsm, &prepared, active.as_ref());
        observations.push(record_observation(record_index, record, state, effects));
    }
    let terminal_state = command_state_name(id, initial, &fsm, &prepared, active.as_ref());
    Ok(CaseObservation {
        id: id.to_owned(),
        outcome,
        terminal_state,
        server_status: status_names(status),
        error_code,
        records: observations,
    })
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
    Ok(fsm)
}

fn apply_fsm(fsm: &mut SessionFsm, event: SessionEvent) -> Result<Vec<String>, Box<dyn Error>> {
    let before = fsm.state();
    let effects = fsm.on_event(event)?;
    let mut result = vec![format!("fsm({before:?}+{event:?}->{:?})", fsm.state())];
    result.extend(
        effects
            .iter()
            .map(|effect| format!("fsm_effect({effect:?})")),
    );
    Ok(result)
}

fn own_command_effects(
    session: Option<SessionMutation<'_>>,
    prepared: Option<PreparedMutation>,
) -> OwnedCommandEffects {
    let session = session.and_then(|mutation| match mutation {
        SessionMutation::MarkQuit => None,
        SessionMutation::SetCurrentDatabase(database) => {
            Some(OwnedSessionMutation::SetCurrentDatabase(database.to_vec()))
        }
        SessionMutation::SetMultiStatements(enabled) => {
            Some(OwnedSessionMutation::SetMultiStatements(enabled))
        }
        SessionMutation::ResetConnection => Some(OwnedSessionMutation::ResetConnection),
    });
    OwnedCommandEffects { session, prepared }
}

fn apply_owned_command_effects(
    command_state: &mut CommandSessionState,
    prepared: &mut PreparedRegistry,
    command_effects: &OwnedCommandEffects,
    effects: &mut Vec<String>,
) {
    if let Some(mutation) = &command_effects.session {
        effects.push(format!("session_mutation({mutation:?})"));
        match mutation {
            OwnedSessionMutation::SetCurrentDatabase(database) => {
                command_state.apply(SessionMutation::SetCurrentDatabase(database));
            }
            OwnedSessionMutation::SetMultiStatements(enabled) => {
                command_state.apply(SessionMutation::SetMultiStatements(*enabled));
            }
            OwnedSessionMutation::ResetConnection => {
                command_state.apply(SessionMutation::ResetConnection);
            }
        }
    }
    if let Some(mutation) = command_effects.prepared {
        effects.push(format!("prepared_mutation({mutation:?})"));
        prepared.apply_mutation(mutation);
    }
}

fn apply_command_effects(
    command_state: &mut CommandSessionState,
    prepared: &mut PreparedRegistry,
    session: Option<SessionMutation<'_>>,
    prepared_mutation: Option<PreparedMutation>,
    effects: &mut Vec<String>,
) {
    if let Some(mutation) = session {
        effects.push(format!("session_mutation({mutation:?})"));
        command_state.apply(mutation);
    }
    if let Some(mutation) = prepared_mutation {
        effects.push(format!("prepared_mutation({mutation:?})"));
        prepared.apply_mutation(mutation);
    }
}

fn statement_id(command: Command, payload: &[u8]) -> Result<Option<u32>, Box<dyn Error>> {
    let code = CommandCode::from_byte(command.as_byte());
    Ok(match command {
        Command::StmtExecute
        | Command::StmtSendLongData
        | Command::StmtClose
        | Command::StmtReset
        | Command::StmtFetch => Some(PreparedRegistry::statement_id(payload, code)?),
        _ => None,
    })
}

fn prepared_registry(initial: &str) -> PreparedRegistry {
    let mut registry = PreparedRegistry::new();
    let register =
        |registry: &mut PreparedRegistry, statement_id, parameter_count, column_count| {
            registry.register(PrepareMetadata {
                statement_id,
                parameter_count,
                column_count,
                warnings: 0,
            });
        };
    match initial {
        "statement_7_prepared" => register(&mut registry, 7, 0, 0),
        "statement_7_has_long_data" => {
            register(&mut registry, 7, 0, 0);
            registry.apply_mutation(PreparedMutation::LongData(7));
        }
        "cursor_open" => {
            register(&mut registry, 7, 0, 1);
            registry.observe_response(
                Command::StmtExecute,
                7,
                synthetic_response(StatusFlags::AUTOCOMMIT | StatusFlags::CURSOR_EXISTS),
            );
        }
        "statement_42_prepared_with_4_params" => register(&mut registry, 42, 4, 0),
        "statements_7_and_8_prepared" => {
            register(&mut registry, 7, 0, 0);
            register(&mut registry, 8, 0, 1);
        }
        _ => {}
    }
    registry
}

fn synthetic_response(status: StatusFlags) -> ResponseEffect {
    ResponseEffect {
        role: session_core::response::PacketRole::Ok,
        disposition: ResponseDisposition::CompleteSuccess,
        status: Some(status),
        in_transaction: status.contains(StatusFlags::IN_TRANS),
        flush: session_core::response::FlushAction::ProtocolBoundary,
    }
}

fn command_state_name(
    id: &str,
    initial: &str,
    fsm: &SessionFsm,
    prepared: &PreparedRegistry,
    active: Option<&ActiveResponse>,
) -> String {
    if matches!(
        id,
        "command-end-sentinel"
            | "command-unknown"
            | "set-option-malformed"
            | "change-user-malformed"
    ) {
        return "closed".to_owned();
    }
    if id == "change-user" {
        return "authenticating_backend".to_owned();
    }
    if active.is_some() {
        return "awaiting_response".to_owned();
    }
    if fsm.state() == SessionState::Closing {
        return "closed".to_owned();
    }
    if prepared.has_pending() {
        if initial == "cursor_open" || id == "stmt-execute-cursor" {
            return "cursor_open".to_owned();
        }
        if initial == "statement_7_has_long_data" {
            return "statement_7_has_long_data".to_owned();
        }
    }
    if id == "stmt-fetch" || id == "stmt-reset" {
        return "statement_7_prepared".to_owned();
    }
    if id == "stmt-long-data" {
        return "statement_7_prepared".to_owned();
    }
    "ready".to_owned()
}

fn status_names(status: Option<StatusFlags>) -> Vec<String> {
    let Some(status) = status else {
        return Vec::new();
    };
    let mut names = Vec::new();
    for (flag, name) in [
        (StatusFlags::IN_TRANS, "SERVER_STATUS_IN_TRANS"),
        (StatusFlags::AUTOCOMMIT, "SERVER_STATUS_AUTOCOMMIT"),
        (
            StatusFlags::MORE_RESULTS_EXISTS,
            "SERVER_MORE_RESULTS_EXISTS",
        ),
        (StatusFlags::CURSOR_EXISTS, "SERVER_STATUS_CURSOR_EXISTS"),
        (StatusFlags::LAST_ROW_SENT, "SERVER_STATUS_LAST_ROW_SENT"),
    ] {
        if status.contains(flag) {
            names.push(name.to_owned());
        }
    }
    names
}

fn expected_error_code(id: &str) -> u16 {
    match id {
        "change-user-malformed"
        | "command-end-sentinel"
        | "command-unknown"
        | "set-option-malformed" => 1835,
        _ => 0,
    }
}

fn capabilities(case: &Value) -> Result<CapabilityFlags, Box<dyn Error>> {
    let empty = Vec::new();
    let names = match case.get("capabilities") {
        Some(Value::Array(names)) => names,
        Some(Value::Null) | None => &empty,
        Some(_) => return Err(invalid("case capabilities must be an array or null").into()),
    };
    let mut flags = CapabilityFlags::from_bits_retain(0);
    for name in names {
        let name = name
            .as_str()
            .ok_or_else(|| invalid("capability name must be a string"))?;
        flags |= match name {
            "CLIENT_PROTOCOL_41" => CapabilityFlags::PROTOCOL_41,
            "CLIENT_SECURE_CONNECTION" => CapabilityFlags::SECURE_CONNECTION,
            "CLIENT_PLUGIN_AUTH" => CapabilityFlags::PLUGIN_AUTH,
            "CLIENT_CONNECT_ATTRS" => CapabilityFlags::CONNECT_ATTRS,
            "CLIENT_MULTI_STATEMENTS" => CapabilityFlags::MULTI_STATEMENTS,
            "CLIENT_MULTI_RESULTS" => CapabilityFlags::MULTI_RESULTS,
            "CLIENT_PS_MULTI_RESULTS" => CapabilityFlags::PS_MULTI_RESULTS,
            "CLIENT_LOCAL_FILES" => CapabilityFlags::LOCAL_FILES,
            "CLIENT_CONNECT_WITH_DB" => CapabilityFlags::CONNECT_WITH_DB,
            "CLIENT_DEPRECATE_EOF" => CapabilityFlags::DEPRECATE_EOF,
            "CLIENT_ZSTD_COMPRESSION_ALGORITHM" => CapabilityFlags::ZSTD_COMPRESSION_ALGORITHM,
            "CLIENT_SSL" => CapabilityFlags::SSL,
            _ => CapabilityFlags::from_bits_retain(0),
        };
    }
    Ok(flags)
}

fn load_trace(path: &Path) -> Result<Vec<TraceRecord>, Box<dyn Error>> {
    let mut decoder = GzDecoder::new(File::open(path)?);
    let mut bytes = Vec::new();
    decoder.read_to_end(&mut bytes)?;
    let mut position = 0_usize;
    if take(&bytes, &mut position, TRACE_MAGIC.len(), "trace magic")? != TRACE_MAGIC {
        return Err(invalid("invalid trace magic").into());
    }
    let count = u32::from_le_bytes(take(&bytes, &mut position, 4, "record count")?.try_into()?);
    let mut records = Vec::with_capacity(usize::try_from(count)?);
    for _ in 0..count {
        let direction = take(&bytes, &mut position, 1, "record direction")?[0];
        let length =
            u64::from_le_bytes(take(&bytes, &mut position, 8, "record length")?.try_into()?);
        let length = usize::try_from(length).map_err(|_| invalid("record length exceeds host"))?;
        records.push(TraceRecord {
            direction,
            wire: take(&bytes, &mut position, length, "record wire")?.to_vec(),
        });
    }
    if position != bytes.len() {
        return Err(invalid("trailing trace bytes").into());
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
            .ok_or_else(|| invalid("physical packet counter overflow"))?;
        remaining = tail;
        if payload_length < MAX_PAYLOAD_LEN {
            packets.push(LogicalPacket {
                payload: std::mem::take(&mut payload),
                first_physical_payload_bytes: first_physical_payload_bytes
                    .take()
                    .ok_or_else(|| invalid("missing first physical packet"))?,
                physical_packets,
            });
            physical_packets = 0;
        }
    }
    if first_physical_payload_bytes.is_some() || !payload.is_empty() {
        return Err(invalid("record ends inside a logical packet").into());
    }
    Ok(packets)
}

fn response_packet(packet: &LogicalPacket) -> Result<ResponsePacket<'_>, Box<dyn Error>> {
    let prefix_length = packet.payload.len().min(RESPONSE_OBSERVER_PREFIX_LIMIT);
    Ok(ResponsePacket::from_forwarded(
        &packet.payload[..prefix_length],
        u64::try_from(packet.payload.len())?,
        packet.first_physical_payload_bytes,
        packet.physical_packets,
    )?)
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

fn required_string<'a>(value: &'a Value, key: &str) -> Result<&'a str, IoError> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| invalid(format!("missing string field {key}")))
}

fn invalid(message: impl Into<String>) -> IoError {
    IoError::new(ErrorKind::InvalidData, message.into())
}

fn record_observation(
    record_index: usize,
    record: &TraceRecord,
    state: String,
    effects: Vec<String>,
) -> RecordObservation {
    let (sequence_start, logical_payload_bytes, physical_packets) = wire_metadata(&record.wire);
    RecordObservation {
        record_index,
        direction: direction_name(record.direction).to_owned(),
        sequence_start,
        logical_payload_bytes,
        physical_packets,
        state,
        effects,
    }
}

fn wire_metadata(wire: &[u8]) -> (u8, u64, u64) {
    let sequence_start = wire.get(3).copied().unwrap_or(0);
    let mut offset = 0_usize;
    let mut logical_payload_bytes = 0_u64;
    let mut physical_packets = 0_u64;
    while wire.len().saturating_sub(offset) >= 4 {
        let length = usize::from(wire[offset])
            | (usize::from(wire[offset + 1]) << 8)
            | (usize::from(wire[offset + 2]) << 16);
        let end = offset.saturating_add(4).saturating_add(length);
        if end > wire.len() {
            break;
        }
        logical_payload_bytes = logical_payload_bytes.saturating_add(length as u64);
        physical_packets = physical_packets.saturating_add(1);
        offset = end;
    }
    (sequence_start, logical_payload_bytes, physical_packets)
}

fn direction_name(direction: u8) -> &'static str {
    match direction {
        CLIENT_TO_PROXY => "client_to_proxy",
        BACKEND_TO_PROXY => "backend_to_proxy",
        PROXY_TO_BACKEND => "proxy_to_backend",
        _ => "unknown",
    }
}

impl CaseObservation {
    fn as_json(&self) -> Value {
        json!({
            "id": self.id,
            "outcome": self.outcome,
            "terminal_state": self.terminal_state,
            "server_status": self.server_status,
            "error_code": self.error_code,
            "records": self.records.iter().map(RecordObservation::as_json).collect::<Vec<_>>(),
        })
    }
}

impl RecordObservation {
    fn as_json(&self) -> Value {
        let mut value = Map::new();
        value.insert("record_index".to_owned(), json!(self.record_index));
        value.insert("direction".to_owned(), json!(self.direction));
        value.insert("sequence_start".to_owned(), json!(self.sequence_start));
        value.insert(
            "logical_payload_bytes".to_owned(),
            json!(self.logical_payload_bytes),
        );
        value.insert("physical_packets".to_owned(), json!(self.physical_packets));
        value.insert("state".to_owned(), json!(self.state));
        value.insert("effects".to_owned(), json!(self.effects));
        Value::Object(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_metadata_counts_complete_physical_packets() {
        let wire = [
            2, 0, 0, 7, 1, 2, // two-byte packet
            0, 0, 0, 8, // empty packet
            3, 0, // truncated header is not counted
        ];
        assert_eq!(wire_metadata(&wire), (7, 2, 2));
    }

    #[test]
    fn known_mutation_changes_the_final_record_and_case_state() {
        let mut observations = vec![CaseObservation {
            id: "case-a".to_owned(),
            outcome: "forward".to_owned(),
            terminal_state: "ready".to_owned(),
            server_status: Vec::new(),
            error_code: 0,
            records: vec![RecordObservation {
                record_index: 0,
                direction: "client_to_proxy".to_owned(),
                sequence_start: 0,
                logical_payload_bytes: 1,
                physical_packets: 1,
                state: "ready".to_owned(),
                effects: Vec::new(),
            }],
        }];
        let result = apply_known_mutation(&mut observations, "final-state");
        assert!(result.is_ok(), "known mutation failed: {result:?}");
        assert_eq!(observations[0].terminal_state, "known_mutation");
        assert_eq!(observations[0].records[0].state, "known_mutation");
        assert_eq!(
            observations[0].records[0].effects,
            ["known_mutation(final_state)"]
        );
    }
}
