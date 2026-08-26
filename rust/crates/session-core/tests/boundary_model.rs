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

//! SES-07 differential/integration model: the safety authority driven by
//! the real SES-04 observer statuses and SES-05 registry, and the held
//! `BEGIN` composed with the SES-00 FSM across a full migration.

use std::num::NonZeroU64;

use mysql_wire::{CapabilityFlags, CommandPacket, StatusFlags};
use session_core::boundary::{
    HeldBegin, HeldBeginPhase, HoldEffect, SessionSafety, need_hold_request,
};
use session_core::command::{Command, PreparedMutation, dispatch};
use session_core::fsm::{SessionEvent, SessionFsm, SessionState};
use session_core::prepared::{PrepareMetadata, PreparedRegistry};
use session_core::response::{ResponseObserver, ResponsePacket};

fn caps() -> CapabilityFlags {
    CapabilityFlags::from_bits_retain(
        CapabilityFlags::PROTOCOL_41.bits() | CapabilityFlags::DEPRECATE_EOF.bits(),
    )
}

fn flush_threshold() -> NonZeroU64 {
    match NonZeroU64::new(1 << 20) {
        Some(threshold) => threshold,
        None => unreachable!("nonzero literal"),
    }
}

fn ok_packet(status: StatusFlags) -> Vec<u8> {
    let mut payload = vec![0x00, 0x00, 0x00];
    payload.extend_from_slice(&status.bits().to_le_bytes());
    payload.extend_from_slice(&[0x00, 0x00]);
    payload
}

fn authenticated_fsm() -> SessionFsm {
    let mut fsm = SessionFsm::new();
    for event in [
        SessionEvent::ConnectionAccepted,
        SessionEvent::ClientHandshakeResponse,
        SessionEvent::BackendGreetingReceived,
        SessionEvent::BackendAuthOk,
    ] {
        match fsm.on_event(event) {
            Ok(_) => {}
            Err(error) => unreachable!("setup failed: {error}"),
        }
    }
    fsm
}

/// Migration never occurs during a transaction, multi-result, LOCAL INFILE,
/// cursor, or long-data state: the authority is driven by real observer
/// statuses and registry guards through each blocking condition.
#[test]
fn authority_blocks_every_unsafe_state() -> Result<(), Box<dyn std::error::Error>> {
    let mut safety = SessionSafety::new();
    let mut registry = PreparedRegistry::new();
    assert!(safety.is_safe_boundary());

    // 1. Open transaction via a real OK status from the observer.
    let query = [Command::Query.as_byte(), b'B'];
    let plan = dispatch(CommandPacket::decode(&query)?)?;
    let mut observer = ResponseObserver::new(plan.response, caps(), false, flush_threshold())?;
    let effect = observer.observe_backend(ResponsePacket::from_payload(&ok_packet(
        StatusFlags::IN_TRANS,
    ))?)?;
    let Some(status) = effect.status else {
        unreachable!("OK carries a status")
    };
    safety.observe_status(status.contains(StatusFlags::IN_TRANS));
    assert!(!safety.is_safe_boundary(), "transaction blocks migration");

    // 2. Multi-result: the command has not completed, so the runtime never
    //    consults the authority mid-stream; the status that ends the first
    //    result still says MORE_RESULTS and the txn state persists.
    let mut observer = ResponseObserver::new(
        dispatch(CommandPacket::decode(&query)?)?.response,
        caps(),
        true,
        flush_threshold(),
    )?;
    let effect = observer.observe_backend(ResponsePacket::from_payload(&ok_packet(
        StatusFlags::IN_TRANS.union(StatusFlags::MORE_RESULTS_EXISTS),
    ))?)?;
    assert!(!observer.is_complete(), "MORE_RESULTS is not a completion");
    let Some(status) = effect.status else {
        unreachable!("OK carries a status")
    };
    safety.observe_status(status.contains(StatusFlags::IN_TRANS));
    assert!(!safety.is_safe_boundary());

    // 3. LOCAL INFILE in flight: no completion, no authority consult; a
    //    disruption (client abort) must leave the state unsafe.
    safety.observe_disruption();
    assert!(!safety.is_safe_boundary(), "unknown after abort is unsafe");
    safety.observe_status(false);

    // 4. Cursor open via the registry (real execute status path).
    registry.register(PrepareMetadata {
        statement_id: 7,
        parameter_count: 0,
        column_count: 1,
        warnings: 0,
    });
    let execute = [
        &[Command::StmtExecute.as_byte()][..],
        &7_u32.to_le_bytes()[..],
    ]
    .concat();
    let plan = dispatch(CommandPacket::decode(&execute)?)?;
    let mut observer = ResponseObserver::new(plan.response, caps(), false, flush_threshold())?;
    let effect = observer.observe_backend(ResponsePacket::from_payload(&ok_packet(
        StatusFlags::CURSOR_EXISTS,
    ))?)?;
    registry.observe_response(Command::StmtExecute, 7, effect);
    safety.set_prepared_pending(registry.has_pending());
    assert!(!safety.is_safe_boundary(), "open cursor blocks migration");

    // 5. Long data pending blocks too; clearing everything restores safety.
    registry.apply_mutation(PreparedMutation::LongData(9));
    safety.set_prepared_pending(registry.has_pending());
    assert!(!safety.is_safe_boundary(), "long data blocks migration");
    registry.apply_mutation(PreparedMutation::ClearAll);
    safety.set_prepared_pending(registry.has_pending());
    assert!(safety.is_safe_boundary(), "cleared state is safe again");
    Ok(())
}

/// The full held-BEGIN walk across the SES-00 FSM: a pending redirect inside
/// a transaction, `BEGIN` arrives, the internal COMMIT closes the
/// transaction, migration fires at the boundary, and the held request is
/// replayed exactly once on the new backend.
#[test]
fn held_begin_walk_across_migration() {
    let mut fsm = authenticated_fsm();
    // Open a transaction, then queue a redirect (it must wait).
    for event in [
        SessionEvent::ClientCommand,
        SessionEvent::BackendResponseTxnOpen,
        SessionEvent::ControlRedirect,
    ] {
        match fsm.on_event(event) {
            Ok(_) => {}
            Err(error) => unreachable!("setup failed: {error}"),
        }
    }
    assert_eq!(fsm.state(), SessionState::Ready);
    assert!(fsm.flags().redirect_pending);

    let mut safety = SessionSafety::new();
    safety.observe_status(true);
    assert!(!safety.is_safe_boundary());

    // The client sends BEGIN: the hold decision fires.
    assert!(need_hold_request(Command::Query, b"BEGIN", true, false));
    let (mut hold, effect) = HeldBegin::start();
    assert_eq!(effect, HoldEffect::SendInternalCommit);

    // The FSM still enters Command for the in-flight (internal) exchange;
    // the runtime substitutes the COMMIT for the held BEGIN.
    match fsm.on_event(SessionEvent::ClientCommand) {
        Ok(_) => assert_eq!(fsm.state(), SessionState::Command),
        Err(error) => unreachable!("command failed: {error}"),
    }

    // The internal COMMIT succeeds: transaction closed, boundary safe.
    match hold.on_commit_ok() {
        Ok(()) => {}
        Err(error) => unreachable!("commit ok failed: {error}"),
    }
    safety.observe_status(false);
    assert!(safety.is_safe_boundary());

    // The commit's TxnDone boundary lets the queued redirect fire.
    match fsm.on_event(SessionEvent::BackendResponseTxnDone) {
        Ok(_) => assert_eq!(fsm.state(), SessionState::RedirectPending),
        Err(error) => unreachable!("boundary failed: {error}"),
    }
    match fsm.on_event(SessionEvent::RedirectBackendReady) {
        Ok(_) => assert_eq!(fsm.state(), SessionState::Ready),
        Err(error) => unreachable!("migration failed: {error}"),
    }

    // The held BEGIN replays exactly once on the new backend.
    assert_eq!(hold.take_for_replay(), Ok(HoldEffect::ReplayHeldRequest));
    match fsm.on_event(SessionEvent::ClientCommand) {
        Ok(_) => assert_eq!(fsm.state(), SessionState::Command),
        Err(error) => unreachable!("replay failed: {error}"),
    }
    assert_eq!(hold.phase(), HeldBeginPhase::Replayed);
    assert!(hold.take_for_replay().is_err(), "never duplicated");
}

/// A failed migration still replays the held BEGIN on the old backend
/// (Go executes it regardless of the redirect result), and a graceful
/// close instead drops it.
#[test]
fn held_begin_failure_and_close_paths() {
    // Failed migration: replay happens on the retained backend.
    let (mut hold, _) = HeldBegin::start();
    match hold.on_commit_ok() {
        Ok(()) => {}
        Err(error) => unreachable!("commit ok failed: {error}"),
    }
    let mut fsm = authenticated_fsm();
    for event in [
        SessionEvent::ControlRedirect,
        SessionEvent::RedirectBackendFailed,
    ] {
        match fsm.on_event(event) {
            Ok(_) => {}
            Err(error) => unreachable!("setup failed: {error}"),
        }
    }
    assert_eq!(fsm.state(), SessionState::Ready);
    assert_eq!(hold.take_for_replay(), Ok(HoldEffect::ReplayHeldRequest));

    // Graceful close before replay: the held request is dropped.
    let (mut hold, _) = HeldBegin::start();
    match hold.on_commit_ok() {
        Ok(()) => {}
        Err(error) => unreachable!("commit ok failed: {error}"),
    }
    assert_eq!(hold.drop_for_close(), Ok(HoldEffect::DiscardHeldRequest));
    assert!(hold.take_for_replay().is_err(), "dropped is never replayed");
}
