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

//! SES-07 integration model: the FSM as the **single** safety authority,
//! driven by real SES-04 observer statuses and the SES-05 registry, and
//! the held `BEGIN` composed across full SES-00 migrations with exact
//! effect assertions (an internal `COMMIT` never forwards to the client).

use std::num::NonZeroU64;

use mysql_wire::{CapabilityFlags, CommandPacket, StatusFlags};
use session_core::boundary::{HeldBegin, HeldBeginPhase, HoldEffect, need_hold_request};
use session_core::command::{Command, PreparedMutation, dispatch};
use session_core::fsm::{SessionEffect, SessionEvent, SessionFsm, SessionState};
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

fn apply(fsm: &mut SessionFsm, event: SessionEvent) -> Vec<SessionEffect> {
    match fsm.on_event(event) {
        Ok(effects) => effects,
        Err(error) => unreachable!("{event:?} failed: {error}"),
    }
}

/// Migration never starts during a transaction, an unknown state, a
/// multi-result window, LOCAL INFILE, a cursor, or long data — proven by
/// issuing `ControlRedirect` in each condition and asserting no
/// `StartRedirectHandshake` is produced by the single FSM authority.
#[test]
fn redirect_never_starts_in_any_unsafe_state() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Open transaction (real observer status drives the FSM event).
    let mut fsm = authenticated_fsm();
    let query = [Command::Query.as_byte(), b'B'];
    let plan = dispatch(CommandPacket::decode(&query)?)?;
    let mut observer = ResponseObserver::new(plan.response, caps(), false, flush_threshold())?;
    let _ = apply(&mut fsm, SessionEvent::ClientCommand);
    let effect = observer.observe_backend(ResponsePacket::from_payload(&ok_packet(
        StatusFlags::IN_TRANS,
    ))?)?;
    let _ = apply(&mut fsm, effect.session_event());
    assert!(!fsm.is_safe_boundary());
    let effects = apply(&mut fsm, SessionEvent::ControlRedirect);
    assert!(
        !effects.contains(&SessionEffect::StartRedirectHandshake),
        "in-transaction redirect must queue"
    );
    assert_eq!(fsm.state(), SessionState::Ready);

    // 2. Unknown state after a disruption: still no migration, even at an
    //    otherwise idle boundary.
    let mut fsm = authenticated_fsm();
    let _ = apply(&mut fsm, SessionEvent::BackendStateUnknown);
    assert!(!fsm.is_safe_boundary());
    let effects = apply(&mut fsm, SessionEvent::ControlRedirect);
    assert!(
        !effects.contains(&SessionEffect::StartRedirectHandshake),
        "unknown-state redirect must queue"
    );
    // An authoritative status then releases the queued redirect.
    let _ = apply(&mut fsm, SessionEvent::ClientCommand);
    let effects = apply(&mut fsm, SessionEvent::BackendResponseTxnDone);
    assert!(
        effects.contains(&SessionEffect::StartRedirectHandshake),
        "authoritative status releases the queued redirect"
    );

    // 3. MORE_RESULTS window: the observer stays incomplete, the FSM stays
    //    in Response, and a redirect only queues.
    let mut fsm = authenticated_fsm();
    let plan = dispatch(CommandPacket::decode(&query)?)?;
    let mut observer = ResponseObserver::new(plan.response, caps(), false, flush_threshold())?;
    let _ = apply(&mut fsm, SessionEvent::ClientCommand);
    let effect = observer.observe_backend(ResponsePacket::from_payload(&ok_packet(
        StatusFlags::MORE_RESULTS_EXISTS,
    ))?)?;
    assert!(!observer.is_complete(), "MORE_RESULTS is not a completion");
    let _ = apply(&mut fsm, effect.session_event());
    assert_eq!(fsm.state(), SessionState::Response);
    assert!(!fsm.is_safe_boundary(), "MORE_RESULTS window is unsafe");
    let effects = apply(&mut fsm, SessionEvent::ControlRedirect);
    assert!(!effects.contains(&SessionEffect::StartRedirectHandshake));

    // 4. LOCAL INFILE in flight.
    let mut fsm = authenticated_fsm();
    let _ = apply(&mut fsm, SessionEvent::ClientCommand);
    let _ = apply(&mut fsm, SessionEvent::BackendLocalInfileRequest);
    let effects = apply(&mut fsm, SessionEvent::ControlRedirect);
    assert!(!effects.contains(&SessionEffect::StartRedirectHandshake));
    assert_eq!(fsm.state(), SessionState::LocalInfile);
    assert!(!fsm.is_safe_boundary(), "LOCAL INFILE phase is unsafe");

    // 5. Cursor / long data through the real registry feed the same
    //    authority via PreparedStatePending.
    let mut fsm = authenticated_fsm();
    let mut registry = PreparedRegistry::new();
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
    let _ = apply(&mut fsm, registry.session_event());
    assert!(!fsm.is_safe_boundary(), "open cursor blocks");
    let effects = apply(&mut fsm, SessionEvent::ControlRedirect);
    assert!(!effects.contains(&SessionEffect::StartRedirectHandshake));
    registry.apply_mutation(PreparedMutation::ClearAll);
    let _ = apply(&mut fsm, registry.session_event());
    // The queued redirect fires only once the guard clears and the next
    // command completes.
    let _ = apply(&mut fsm, SessionEvent::ClientCommand);
    let effects = apply(&mut fsm, SessionEvent::BackendResponseTxnDone);
    assert!(effects.contains(&SessionEffect::StartRedirectHandshake));
    Ok(())
}

/// Graceful close honors the same single authority: under Unknown it
/// drains rather than closing immediately, and only an authoritative
/// status closes it.
#[test]
fn drain_waits_for_unknown_state() {
    let mut fsm = authenticated_fsm();
    let _ = apply(&mut fsm, SessionEvent::BackendStateUnknown);
    let effects = apply(&mut fsm, SessionEvent::ControlGracefulClose);
    assert!(
        !effects.contains(&SessionEffect::CloseClient),
        "unknown state must not close immediately"
    );
    assert_eq!(fsm.state(), SessionState::Draining);
    // The next command's authoritative done-status reaches the boundary
    // and the drain completes.
    let _ = apply(&mut fsm, SessionEvent::ClientCommand);
    let effects = apply(&mut fsm, SessionEvent::BackendResponseTxnDone);
    assert!(effects.contains(&SessionEffect::CloseClient));
    assert_eq!(fsm.state(), SessionState::Closing);
}

/// The full held-BEGIN walk with exact effect assertions: the internal
/// COMMIT's OK produces **no client forwarding**, the boundary fires the
/// queued redirect, and the held request replays exactly once.
#[test]
fn held_begin_success_never_forwards_internal_commit() {
    let mut fsm = authenticated_fsm();
    for event in [
        SessionEvent::ClientCommand,
        SessionEvent::BackendResponseTxnOpen,
        SessionEvent::ControlRedirect,
    ] {
        let _ = apply(&mut fsm, event);
    }
    assert_eq!(fsm.state(), SessionState::Ready);
    assert!(fsm.flags().redirect_pending);
    assert!(!fsm.is_safe_boundary());

    // BEGIN arrives; the hold decision fires; the runtime substitutes the
    // internal COMMIT for the held request.
    assert!(need_hold_request(Command::Query, b"BEGIN", true, false));
    let (mut hold, effect) = HeldBegin::start();
    assert_eq!(effect, HoldEffect::SendInternalCommit);
    let effects = apply(&mut fsm, SessionEvent::ClientCommand);
    assert_eq!(effects, vec![SessionEffect::ForwardCommandToBackend]);

    // Internal COMMIT OK: the boundary logic runs with NO forwarding —
    // the redirect starts and nothing reaches the client.
    match hold.on_commit_ok() {
        Ok(()) => {}
        Err(error) => unreachable!("commit ok: {error}"),
    }
    let effects = apply(&mut fsm, SessionEvent::InternalResponseTxnDone);
    assert_eq!(
        effects,
        vec![SessionEffect::StartRedirectHandshake],
        "internal COMMIT OK must not forward to the client"
    );
    assert_eq!(fsm.state(), SessionState::RedirectPending);
    // The in-flight migration is itself a non-boundary phase.
    assert!(!fsm.is_safe_boundary());

    // Migration succeeds; the held BEGIN replays exactly once.
    let _ = apply(&mut fsm, SessionEvent::RedirectBackendReady);
    assert_eq!(hold.take_for_replay(), Ok(HoldEffect::ReplayHeldRequest));
    let effects = apply(&mut fsm, SessionEvent::ClientCommand);
    assert_eq!(effects, vec![SessionEffect::ForwardCommandToBackend]);
    assert_eq!(hold.phase(), HeldBeginPhase::Replayed);
    assert!(hold.take_for_replay().is_err(), "never duplicated");
}

/// The internal COMMIT error path: the runtime forwards the error exactly
/// once via the hold effect, and the FSM leaves `Command` with the
/// retained open-transaction state and no duplicate forwarding.
#[test]
fn held_begin_commit_error_forwards_exactly_once() {
    let mut fsm = authenticated_fsm();
    for event in [
        SessionEvent::ClientCommand,
        SessionEvent::BackendResponseTxnOpen,
        SessionEvent::ControlRedirect,
        SessionEvent::ClientCommand, // the held BEGIN's internal cycle
    ] {
        let _ = apply(&mut fsm, event);
    }
    let (mut hold, _) = HeldBegin::start();
    // COMMIT fails: the hold machine owns the single client forward.
    assert_eq!(
        hold.on_commit_error(),
        Ok(HoldEffect::ForwardCommitErrorToClient)
    );
    // The FSM exits Command through the internal ERROR path with NO
    // forwarding effect and — unlike the commit-OK-still-in-txn case — NO
    // `ResumeHeldRequest`: a statusless ERR keeps `serverStatus` (Go
    // `handleErrorPacket`), so the transaction is retained and the aborted
    // hold is answered by the forwarded error, never replayed.
    let effects = apply(&mut fsm, SessionEvent::InternalResponseError);
    assert_eq!(effects, Vec::new(), "no duplicate forwarding, no replay");
    assert_eq!(fsm.state(), SessionState::Ready);
    assert!(fsm.flags().in_txn, "commit failed: txn retained");
    assert!(fsm.flags().redirect_pending, "redirect stays queued");
    assert!(!fsm.is_safe_boundary());
    assert!(
        hold.take_for_replay().is_err(),
        "aborted hold never replays"
    );
}

/// A failed migration still replays the held BEGIN on the old backend,
/// and a graceful close instead drops it.
#[test]
fn held_begin_failure_and_close_paths() {
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
        let _ = apply(&mut fsm, event);
    }
    assert_eq!(fsm.state(), SessionState::Ready);
    assert_eq!(hold.take_for_replay(), Ok(HoldEffect::ReplayHeldRequest));

    let (mut hold, _) = HeldBegin::start();
    match hold.on_commit_ok() {
        Ok(()) => {}
        Err(error) => unreachable!("commit ok failed: {error}"),
    }
    assert_eq!(hold.drop_for_close(), Ok(HoldEffect::DiscardHeldRequest));
    assert!(hold.take_for_replay().is_err(), "dropped is never replayed");
}

/// An internal COMMIT that returns OK but still reports `IN_TRANS` cannot
/// migrate; the FSM authorizes the held request to replay once on the current
/// backend right away (`InternalResponseTxnOpen` → `ResumeHeldRequest`). This
/// is the branch a hardcoded `TxnDone` would silently swallow.
#[test]
fn held_begin_commit_ok_in_txn_replays_on_current_backend() {
    let mut fsm = authenticated_fsm();
    for event in [
        SessionEvent::ClientCommand,
        SessionEvent::BackendResponseTxnOpen,
        SessionEvent::ControlRedirect,
        SessionEvent::ClientCommand, // the held BEGIN's internal cycle
    ] {
        let _ = apply(&mut fsm, event);
    }
    let (mut hold, _) = HeldBegin::start();
    match hold.on_commit_ok() {
        Ok(()) => {}
        Err(error) => unreachable!("commit ok failed: {error}"),
    }
    // Commit succeeded but the transaction is still open: no migration, but
    // the held request must replay once on the current backend.
    let effects = apply(&mut fsm, SessionEvent::InternalResponseTxnOpen);
    assert_eq!(
        effects,
        vec![SessionEffect::ResumeHeldRequest],
        "commit-OK-still-in-txn replays on the current backend"
    );
    assert_eq!(fsm.state(), SessionState::Ready);
    assert!(fsm.flags().in_txn, "transaction stays open");
    assert!(fsm.flags().redirect_pending, "redirect stays queued");
    assert_eq!(hold.take_for_replay(), Ok(HoldEffect::ReplayHeldRequest));
    let effects = apply(&mut fsm, SessionEvent::ClientCommand);
    assert_eq!(effects, vec![SessionEffect::ForwardCommandToBackend]);
    assert!(hold.take_for_replay().is_err(), "never duplicated");
}

/// A successful migration emits the swap, the success report, and the replay
/// authorization in exactly that order. Dropping `ResumeHeldRequest` here
/// would strand a held BEGIN on the new backend forever.
#[test]
fn redirect_ready_authorizes_resume_after_swap() {
    let mut fsm = authenticated_fsm();
    for event in [
        SessionEvent::ClientCommand,
        SessionEvent::ControlRedirect,
        SessionEvent::BackendResponseTxnDone,
    ] {
        let _ = apply(&mut fsm, event);
    }
    assert_eq!(fsm.state(), SessionState::RedirectPending);
    let effects = apply(&mut fsm, SessionEvent::RedirectBackendReady);
    assert_eq!(
        effects,
        vec![
            SessionEffect::SwapBackend,
            SessionEffect::NotifyRedirectSucceeded,
            SessionEffect::ResumeHeldRequest,
        ],
        "resume must follow the swap and the success report"
    );
    assert_eq!(fsm.state(), SessionState::Ready);
}

/// A failed migration keeps the old backend and still authorizes the replay
/// (Go replays the held request whether the redirect succeeded or failed).
#[test]
fn redirect_failed_still_authorizes_resume() {
    let mut fsm = authenticated_fsm();
    for event in [
        SessionEvent::ClientCommand,
        SessionEvent::ControlRedirect,
        SessionEvent::BackendResponseTxnDone,
    ] {
        let _ = apply(&mut fsm, event);
    }
    assert_eq!(fsm.state(), SessionState::RedirectPending);
    let effects = apply(&mut fsm, SessionEvent::RedirectBackendFailed);
    assert_eq!(
        effects,
        vec![
            SessionEffect::NotifyRedirectFailed,
            SessionEffect::ResumeHeldRequest,
        ],
        "a failed redirect still replays the held request on the old backend"
    );
    assert_eq!(fsm.state(), SessionState::Ready);
}

/// While draining, a commit-OK-still-in-txn does NOT authorize a replay: Go
/// executes the held request only while `closeStatus < statusNotifyClose`, so
/// the graceful close drops it instead. This kills an unconditional resume.
#[test]
fn held_begin_commit_ok_in_txn_while_draining_drops_without_resume() {
    let mut fsm = authenticated_fsm();
    for event in [
        SessionEvent::ClientCommand,
        SessionEvent::BackendResponseTxnOpen,
        SessionEvent::ControlRedirect,
        SessionEvent::ClientCommand, // the held BEGIN's internal cycle
        SessionEvent::ControlGracefulClose,
    ] {
        let _ = apply(&mut fsm, event);
    }
    assert!(fsm.flags().draining, "graceful close armed");
    let effects = apply(&mut fsm, SessionEvent::InternalResponseTxnOpen);
    assert!(
        !effects.contains(&SessionEffect::ResumeHeldRequest),
        "draining drops the held request, never replays it"
    );
    assert_eq!(fsm.state(), SessionState::Draining);
    assert!(fsm.flags().in_txn, "transaction stays open");
}

/// Teardown never authorizes a replay: a held BEGIN seen only at close is
/// dropped by the runtime, so `teardown` must not emit `ResumeHeldRequest`.
#[test]
fn teardown_never_authorizes_resume() {
    let mut fsm = authenticated_fsm();
    for event in [
        SessionEvent::ClientCommand,
        SessionEvent::ControlRedirect,
        SessionEvent::BackendResponseTxnDone,
    ] {
        let _ = apply(&mut fsm, event);
    }
    assert_eq!(fsm.state(), SessionState::RedirectPending);
    let effects = apply(&mut fsm, SessionEvent::ClientEof);
    assert_eq!(fsm.state(), SessionState::Closing);
    assert!(
        !effects.contains(&SessionEffect::ResumeHeldRequest),
        "teardown drops the held request, never replays it"
    );
}

/// Unknown state survives every statusless ERR completion: a real
/// observer ERR, a change-user ERR, and an internal COMMIT ERR all end
/// their commands without restoring safety; only an authoritative OK/EOF
/// status clears the flag.
#[test]
fn unknown_state_survives_every_err_variant() -> Result<(), Box<dyn std::error::Error>> {
    use session_core::special::{ChangeUserEvent, ChangeUserRelay};

    // 1. Real ResponseObserver ERR.
    let mut fsm = authenticated_fsm();
    let _ = apply(&mut fsm, SessionEvent::BackendStateUnknown);
    let _ = apply(&mut fsm, SessionEvent::ClientCommand);
    let query = [Command::Query.as_byte(), b'B'];
    let plan = dispatch(CommandPacket::decode(&query)?)?;
    let mut observer = ResponseObserver::new(plan.response, caps(), false, flush_threshold())?;
    let mut err_packet = vec![0xff];
    err_packet.extend_from_slice(&1064_u16.to_le_bytes());
    err_packet.extend_from_slice(b"#42000syntax");
    let effect = observer.observe_backend(ResponsePacket::from_payload(&err_packet)?)?;
    assert_eq!(effect.status, None, "ERR carries no status");
    let _ = apply(&mut fsm, effect.session_event());
    assert_eq!(fsm.state(), SessionState::Ready);
    assert!(
        fsm.flags().txn_unknown,
        "observer ERR must not clear Unknown"
    );
    assert!(!fsm.is_safe_boundary());

    // 2. Change-user ERR through the SES-06 relay.
    let mut relay = ChangeUserRelay::new();
    let step = match relay.on_event(ChangeUserEvent::BackendError { code: 1045 }) {
        Ok(step) => step,
        Err(error) => unreachable!("relay: {error}"),
    };
    let _ = apply(&mut fsm, SessionEvent::ClientCommand);
    let Some(boundary) = step.session_event else {
        unreachable!("change-user ERR must produce a boundary event")
    };
    let _ = apply(&mut fsm, boundary);
    assert!(
        fsm.flags().txn_unknown,
        "change-user ERR must not clear Unknown"
    );
    assert!(!fsm.is_safe_boundary());

    // 3. Internal COMMIT ERR.
    let _ = apply(&mut fsm, SessionEvent::ClientCommand);
    let _ = apply(&mut fsm, SessionEvent::InternalResponseError);
    assert!(
        fsm.flags().txn_unknown,
        "internal ERR must not clear Unknown"
    );
    assert!(!fsm.is_safe_boundary());

    // Only an authoritative status restores safety.
    let _ = apply(&mut fsm, SessionEvent::ClientCommand);
    let _ = apply(&mut fsm, SessionEvent::BackendResponseTxnDone);
    assert!(!fsm.flags().txn_unknown);
    assert!(fsm.is_safe_boundary());
    Ok(())
}

/// Mid-command `MORE_RESULTS` terminators carry authoritative statuses
/// that must reach the FSM (Go updates `serverStatus` at **every** result
/// terminator), so a statusless final ERR decides the boundary on the
/// **latest** status, not the pre-command one.
#[test]
fn mid_multi_result_status_reaches_the_fsm() -> Result<(), Box<dyn std::error::Error>> {
    let query = [Command::Query.as_byte(), b'B'];
    let mut err_packet = vec![0xff];
    err_packet.extend_from_slice(&1064_u16.to_le_bytes());
    err_packet.extend_from_slice(b"#42000syntax");

    // A. txn open -> mid-result "done" -> final ERR: the retained state is
    //    "out of transaction", so the queued redirect is released.
    let mut fsm = authenticated_fsm();
    let plan = dispatch(CommandPacket::decode(&query)?)?;
    let mut observer = ResponseObserver::new(plan.response, caps(), false, flush_threshold())?;
    let _ = apply(&mut fsm, SessionEvent::ClientCommand);
    let effect = observer.observe_backend(ResponsePacket::from_payload(&ok_packet(
        StatusFlags::IN_TRANS,
    ))?)?;
    let _ = apply(&mut fsm, effect.session_event());
    let effects = apply(&mut fsm, SessionEvent::ControlRedirect);
    assert!(!effects.contains(&SessionEffect::StartRedirectHandshake));
    let plan = dispatch(CommandPacket::decode(&query)?)?;
    let mut observer = ResponseObserver::new(plan.response, caps(), true, flush_threshold())?;
    let _ = apply(&mut fsm, SessionEvent::ClientCommand);
    let effect = observer.observe_backend(ResponsePacket::from_payload(&ok_packet(
        StatusFlags::MORE_RESULTS_EXISTS,
    ))?)?;
    assert_eq!(
        effect.session_event(),
        SessionEvent::BackendResponsePartTxnDone,
        "a MORE_RESULTS terminator must expose its authoritative status"
    );
    let _ = apply(&mut fsm, effect.session_event());
    assert_eq!(fsm.state(), SessionState::Response);
    assert!(!fsm.flags().in_txn, "mid-result status must be applied");
    assert!(
        !fsm.is_safe_boundary(),
        "the command is still in flight: no boundary yet"
    );
    let effect = observer.observe_backend(ResponsePacket::from_payload(&err_packet)?)?;
    assert_eq!(effect.status, None, "ERR carries no status");
    let effects = apply(&mut fsm, effect.session_event());
    assert!(
        effects.contains(&SessionEffect::StartRedirectHandshake),
        "final ERR after a mid-result COMMIT must release the redirect"
    );

    // B. out of txn -> mid-result "open" -> final ERR: the retained state
    //    is "in transaction", so the queued redirect stays blocked.
    let mut fsm = authenticated_fsm();
    let plan = dispatch(CommandPacket::decode(&query)?)?;
    let mut observer = ResponseObserver::new(plan.response, caps(), false, flush_threshold())?;
    let _ = apply(&mut fsm, SessionEvent::ClientCommand);
    let effects = apply(&mut fsm, SessionEvent::ControlRedirect);
    assert!(!effects.contains(&SessionEffect::StartRedirectHandshake));
    let effect = observer.observe_backend(ResponsePacket::from_payload(&ok_packet(
        StatusFlags::MORE_RESULTS_EXISTS.union(StatusFlags::IN_TRANS),
    ))?)?;
    assert_eq!(
        effect.session_event(),
        SessionEvent::BackendResponsePartTxnOpen
    );
    let _ = apply(&mut fsm, effect.session_event());
    assert!(fsm.flags().in_txn, "mid-result BEGIN must be applied");
    let effect = observer.observe_backend(ResponsePacket::from_payload(&err_packet)?)?;
    let effects = apply(&mut fsm, effect.session_event());
    assert!(
        !effects.contains(&SessionEffect::StartRedirectHandshake),
        "final ERR after a mid-result BEGIN must keep the redirect queued"
    );
    assert!(!fsm.is_safe_boundary());

    // C. Unknown -> mid-result authoritative status -> final ERR: the
    //    part status restores knowledge, and the ERR retains it.
    let mut fsm = authenticated_fsm();
    let _ = apply(&mut fsm, SessionEvent::BackendStateUnknown);
    let effects = apply(&mut fsm, SessionEvent::ControlRedirect);
    assert!(!effects.contains(&SessionEffect::StartRedirectHandshake));
    let plan = dispatch(CommandPacket::decode(&query)?)?;
    let mut observer = ResponseObserver::new(plan.response, caps(), false, flush_threshold())?;
    let _ = apply(&mut fsm, SessionEvent::ClientCommand);
    let effect = observer.observe_backend(ResponsePacket::from_payload(&ok_packet(
        StatusFlags::MORE_RESULTS_EXISTS,
    ))?)?;
    let _ = apply(&mut fsm, effect.session_event());
    assert!(
        !fsm.flags().txn_unknown,
        "a mid-result authoritative status restores knowledge"
    );
    let effect = observer.observe_backend(ResponsePacket::from_payload(&err_packet)?)?;
    let effects = apply(&mut fsm, effect.session_event());
    assert!(
        !fsm.flags().txn_unknown,
        "the ERR retains the restored knowledge"
    );
    assert!(
        effects.contains(&SessionEffect::StartRedirectHandshake),
        "known + out-of-txn at the ERR boundary releases the redirect"
    );
    Ok(())
}

/// A late backend/internal ERR (or a late mid-result status) arriving
/// after an immediate close is tolerated in `Closing` and teardown still
/// completes — the in-flight-traffic race never becomes a
/// `TransitionError`.
#[test]
fn late_err_after_immediate_close_is_tolerated() -> Result<(), Box<dyn std::error::Error>> {
    let query = [Command::Query.as_byte(), b'B'];
    for late in [
        SessionEvent::BackendResponseErrorComplete,
        SessionEvent::InternalResponseError,
        SessionEvent::BackendResponsePartTxnDone,
        SessionEvent::BackendResponsePartTxnOpen,
        SessionEvent::InternalResponseTxnDone,
        SessionEvent::InternalResponseTxnOpen,
        SessionEvent::BackendStateUnknown,
    ] {
        let mut fsm = authenticated_fsm();
        let _ = apply(&mut fsm, SessionEvent::ClientCommand);
        let _ = apply(&mut fsm, SessionEvent::ControlCloseImmediate);
        assert_eq!(fsm.state(), SessionState::Closing);
        let effects = apply(&mut fsm, late);
        assert!(effects.is_empty(), "late {late:?} must be a silent no-op");
        assert_eq!(fsm.state(), SessionState::Closing);
        let _ = apply(&mut fsm, SessionEvent::TeardownComplete);
        assert_eq!(fsm.state(), SessionState::Closed);
    }

    // The real observer path: the command is mid-flight when the close
    // lands, and its final ERR arrives only afterwards.
    let mut fsm = authenticated_fsm();
    let plan = dispatch(CommandPacket::decode(&query)?)?;
    let mut observer = ResponseObserver::new(plan.response, caps(), false, flush_threshold())?;
    let _ = apply(&mut fsm, SessionEvent::ClientCommand);
    let _ = apply(&mut fsm, SessionEvent::ControlCloseImmediate);
    let mut err_packet = vec![0xff];
    err_packet.extend_from_slice(&1064_u16.to_le_bytes());
    err_packet.extend_from_slice(b"#42000syntax");
    let effect = observer.observe_backend(ResponsePacket::from_payload(&err_packet)?)?;
    let effects = apply(&mut fsm, effect.session_event());
    assert!(effects.is_empty());
    assert_eq!(fsm.state(), SessionState::Closing);
    let _ = apply(&mut fsm, SessionEvent::TeardownComplete);
    assert_eq!(fsm.state(), SessionState::Closed);
    Ok(())
}
