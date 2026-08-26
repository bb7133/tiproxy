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

//! SES-05 prepared lifecycle integration and parity tests.

use mysql_wire::{
    CapabilityFlags, ColumnType, CommandCode, CommandPacket, ExecuteParameter, MAX_PAYLOAD_LEN,
    ParameterType, ParameterValue, PrepareOkParams, StatusFlags, StmtExecuteParams,
    encode_eof_packet, encode_error_packet, encode_prepare_ok, encode_stmt_execute,
};
use session_core::command::{Command, PreparedMutation, dispatch};
use session_core::prepared::{
    PrepareDisposition, PrepareMetadata, PrepareObserver, PrepareObserverState, PreparedGuard,
    PreparedRegistry, PreparedStatementState,
};
use session_core::response::{
    FlushAction, PacketRole, ResponseDisposition, ResponseEffect, ResponsePacket,
};
use session_core::special::{ChangeUserEffect, ChangeUserEvent, ChangeUserRelay};

fn packet(
    payload: &[u8],
) -> Result<ResponsePacket<'_>, session_core::response::ResponseObserverError> {
    ResponsePacket::from_payload(payload)
}

fn effect(disposition: ResponseDisposition, status: Option<StatusFlags>) -> ResponseEffect {
    ResponseEffect {
        role: PacketRole::Terminator,
        disposition,
        status,
        in_transaction: false,
        flush: FlushAction::ProtocolBoundary,
    }
}

fn metadata(statement_id: u32, parameter_count: u16) -> PrepareMetadata {
    PrepareMetadata {
        statement_id,
        parameter_count,
        column_count: 1,
        warnings: 0,
    }
}

/// Classic prepare metadata consumes exact parameter/column definitions and
/// both EOF packets, with one flush and one atomic registration boundary.
#[test]
fn classic_prepare_observer_counts_metadata_and_flushes_once()
-> Result<(), Box<dyn std::error::Error>> {
    let capabilities = CapabilityFlags::PROTOCOL_41;
    let mut observer = PrepareObserver::new(capabilities);
    let header = encode_prepare_ok(PrepareOkParams {
        statement_id: 71,
        column_count: 1,
        parameter_count: 2,
        warnings: 3,
    });
    let mut flushes = 0;
    let first = observer.observe(packet(&header)?)?;
    assert_eq!(first.disposition, PrepareDisposition::Continue);
    assert_eq!(
        observer.state(),
        PrepareObserverState::Parameters { remaining: 2 }
    );
    for payload in [b"parameter-1".as_slice(), b"parameter-2".as_slice()] {
        let step = observer.observe(packet(payload)?)?;
        flushes += usize::from(step.flush != FlushAction::None);
    }
    assert_eq!(observer.state(), PrepareObserverState::ParameterEof);
    let eof = encode_eof_packet(0, StatusFlags::AUTOCOMMIT);
    let step = observer.observe(packet(&eof)?)?;
    flushes += usize::from(step.flush != FlushAction::None);
    assert_eq!(
        observer.state(),
        PrepareObserverState::Columns { remaining: 1 }
    );
    let step = observer.observe(packet(b"column-1")?)?;
    flushes += usize::from(step.flush != FlushAction::None);
    assert_eq!(observer.state(), PrepareObserverState::ColumnEof);
    let step = observer.observe(packet(&eof)?)?;
    flushes += usize::from(step.flush != FlushAction::None);
    assert_eq!(
        step.disposition,
        PrepareDisposition::CompleteSuccess(PrepareMetadata {
            statement_id: 71,
            parameter_count: 2,
            column_count: 1,
            warnings: 3,
        })
    );
    assert_eq!(flushes, 1);
    assert!(observer.is_complete());
    Ok(())
}

/// Deprecated-EOF mode omits both EOF packets, while a first-packet ERR is a
/// complete nonfatal response and malformed headers are inert.
#[test]
fn deprecate_eof_error_and_malformed_prepare_paths_are_bounded()
-> Result<(), Box<dyn std::error::Error>> {
    let capabilities = CapabilityFlags::PROTOCOL_41 | CapabilityFlags::DEPRECATE_EOF;
    let mut observer = PrepareObserver::new(capabilities);
    let header = encode_prepare_ok(PrepareOkParams {
        statement_id: 72,
        column_count: 1,
        parameter_count: 1,
        warnings: 0,
    });
    observer.observe(packet(&header)?)?;
    observer.observe(packet(b"parameter")?)?;
    let final_effect = observer.observe(packet(b"column")?)?;
    assert_eq!(
        final_effect.disposition,
        PrepareDisposition::CompleteSuccess(PrepareMetadata {
            statement_id: 72,
            parameter_count: 1,
            column_count: 1,
            warnings: 0,
        })
    );

    let mut error_observer = PrepareObserver::new(capabilities);
    let error = encode_error_packet(1045, Some(*b"28000"), b"denied", capabilities)?;
    assert_eq!(
        error_observer.observe(packet(&error)?)?.disposition,
        PrepareDisposition::CompleteError { code: 1045 }
    );

    let mut malformed = PrepareObserver::new(capabilities);
    let before = malformed.clone();
    assert!(malformed.observe(packet(&[0x00, 1, 2])?).is_err());
    assert_eq!(malformed, before, "malformed prepare header is inert");
    Ok(())
}

/// Each statement ID has an independent long-data/cursor guard. ERR never
/// clears it; status-bearing execute/fetch boundaries update only that ID.
#[test]
fn independent_guards_preserve_execute_and_fetch_errors() {
    let mut registry = PreparedRegistry::new();
    registry.register(metadata(1, 0));
    registry.register(metadata(2, 0));
    registry.apply_mutation(PreparedMutation::LongData(1));
    registry.observe_response(
        Command::StmtExecute,
        2,
        effect(
            ResponseDisposition::CompleteSuccess,
            Some(StatusFlags::AUTOCOMMIT | StatusFlags::CURSOR_EXISTS),
        ),
    );
    assert_eq!(
        registry.get(1).map(PreparedStatementState::guard),
        Some(PreparedGuard::LongDataPending)
    );
    assert_eq!(
        registry.get(2).map(PreparedStatementState::guard),
        Some(PreparedGuard::CursorOpen)
    );
    assert!(registry.has_pending());

    registry.observe_response(
        Command::StmtExecute,
        1,
        effect(ResponseDisposition::CompleteError { code: 1210 }, None),
    );
    registry.observe_response(
        Command::StmtFetch,
        2,
        effect(ResponseDisposition::CompleteError { code: 1317 }, None),
    );
    assert_eq!(
        registry.get(1).map(PreparedStatementState::guard),
        Some(PreparedGuard::LongDataPending)
    );
    assert_eq!(
        registry.get(2).map(PreparedStatementState::guard),
        Some(PreparedGuard::CursorOpen)
    );

    registry.observe_response(
        Command::StmtExecute,
        1,
        effect(
            ResponseDisposition::CompleteSuccess,
            Some(StatusFlags::AUTOCOMMIT),
        ),
    );
    assert_eq!(
        registry.get(1).map(PreparedStatementState::guard),
        Some(PreparedGuard::Idle)
    );
    assert!(registry.has_pending(), "statement 2 remains independent");

    registry.observe_response(
        Command::StmtFetch,
        2,
        effect(
            ResponseDisposition::CompleteSuccess,
            Some(StatusFlags::AUTOCOMMIT | StatusFlags::LAST_ROW_SENT),
        ),
    );
    assert!(!registry.has_pending());
}

/// RESET/CLOSE and successful session-wide clears follow their exact scope;
/// hostile long data on an unknown ID still blocks like Go's status map.
#[test]
fn reset_close_and_clear_all_have_exact_scope() {
    let mut registry = PreparedRegistry::new();
    registry.register(metadata(1, 1));
    registry.register(metadata(2, 1));
    registry.apply_mutation(PreparedMutation::LongData(1));
    registry.apply_mutation(PreparedMutation::LongData(2));
    registry.apply_mutation(PreparedMutation::Reset(1));
    assert_eq!(
        registry.get(1).map(PreparedStatementState::guard),
        Some(PreparedGuard::Idle)
    );
    assert_eq!(
        registry.get(2).map(PreparedStatementState::guard),
        Some(PreparedGuard::LongDataPending)
    );
    registry.apply_mutation(PreparedMutation::Close(2));
    assert!(registry.get(2).is_none());

    registry.apply_mutation(PreparedMutation::LongData(999));
    assert_eq!(
        registry.get(999).map(PreparedStatementState::metadata),
        Some(None)
    );
    assert!(registry.has_pending());
    registry.apply_mutation(PreparedMutation::Reset(999));
    assert!(registry.get(999).is_none(), "Go deletes the unknown guard");
    assert!(!registry.has_pending());

    registry.apply_mutation(PreparedMutation::ClearAll);
    assert!(registry.is_empty());
}

/// SES-06's terminal result and SES-03's success-only dispatch mutation join
/// at one boundary: rejected change-user preserves prepared guards, while OK
/// clears the entire registry before SES-00 observes command completion.
#[test]
fn change_user_clears_all_only_after_relay_success() -> Result<(), Box<dyn std::error::Error>> {
    let command = [CommandCode::CHANGE_USER.as_byte()];
    let plan = dispatch(CommandPacket::decode(&command)?)?;
    assert_eq!(
        plan.after_success.prepared,
        Some(PreparedMutation::ClearAll)
    );

    let mut registry = PreparedRegistry::new();
    registry.register(metadata(1, 0));
    registry.apply_mutation(PreparedMutation::LongData(1));
    let failed =
        ChangeUserRelay::new(false).on_event(ChangeUserEvent::BackendError { code: 1045 })?;
    assert!(
        failed
            .effects
            .contains(&ChangeUserEffect::DiscardPendingIdentity)
    );
    assert!(
        registry.has_pending(),
        "failure must not apply after_success"
    );

    let succeeded = ChangeUserRelay::new(false).on_event(ChangeUserEvent::BackendOk {
        in_transaction: false,
    })?;
    assert!(
        succeeded
            .effects
            .contains(&ChangeUserEffect::CommitPendingIdentity)
    );
    registry.apply_mutation(
        plan.after_success
            .prepared
            .ok_or("missing clear-all mutation")?,
    );
    assert!(registry.is_empty());
    Ok(())
}

/// Full execute decoding covers null bitmap, exact signed/unsigned flag,
/// type reuse, and `TiDB` vector values without retaining packet bytes.
#[test]
fn execute_codec_types_and_reuse_are_retained_per_statement()
-> Result<(), Box<dyn std::error::Error>> {
    let mut registry = PreparedRegistry::new();
    registry.register(PrepareMetadata {
        statement_id: 88,
        parameter_count: 3,
        column_count: 0,
        warnings: 0,
    });
    let parameters = [
        ExecuteParameter {
            parameter_type: ParameterType {
                column_type: ColumnType::LongLong,
                flags: 0x80,
            },
            value: ParameterValue::UInt64(u64::MAX),
        },
        ExecuteParameter {
            parameter_type: ParameterType {
                column_type: ColumnType::Vector,
                flags: 0,
            },
            value: ParameterValue::Bytes(b"vector"),
        },
        ExecuteParameter {
            parameter_type: ParameterType {
                column_type: ColumnType::String,
                flags: 0,
            },
            value: ParameterValue::Null,
        },
    ];
    let first = encode_stmt_execute(StmtExecuteParams {
        statement_id: 88,
        flags: 0,
        iteration_count: 1,
        new_params_bound: true,
        parameters: &parameters,
    })?;
    assert_eq!(registry.decode_execute(&first)?.parameters, parameters);
    assert_eq!(
        registry.get(88).map(|state| state.parameter_types().len()),
        Some(3)
    );

    let reuse = encode_stmt_execute(StmtExecuteParams {
        statement_id: 88,
        flags: 0,
        iteration_count: 1,
        new_params_bound: false,
        parameters: &parameters,
    })?;
    assert_eq!(registry.decode_execute(&reuse)?.parameters, parameters);
    Ok(())
}

/// The transparent path extracts only the five-byte command/ID prefix even
/// when the logical execute spans physical packets.
#[test]
fn large_execute_statement_id_uses_only_the_bounded_prefix()
-> Result<(), Box<dyn std::error::Error>> {
    let mut execute = vec![0_u8; usize::try_from(MAX_PAYLOAD_LEN)? + 64];
    execute[0] = CommandCode::STMT_EXECUTE.as_byte();
    execute[1..5].copy_from_slice(&0xfeed_beef_u32.to_le_bytes());
    assert_eq!(
        PreparedRegistry::statement_id(&execute[..5], CommandCode::STMT_EXECUTE),
        Ok(0xfeed_beef)
    );
    assert_eq!(
        PreparedRegistry::statement_id(&execute, CommandCode::STMT_EXECUTE),
        Ok(0xfeed_beef)
    );
    Ok(())
}
