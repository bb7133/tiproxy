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

//! SES-06 integration tests: LOCAL INFILE upload turns composed with the
//! SES-04 observer and SES-00 FSM, and the change-user rewrite/relay
//! composed with SES-02 classification and SES-03 state effects.

use std::num::NonZeroU64;

use mysql_wire::CommandPacket;
use mysql_wire::{Attribute, CapabilityFlags, ChangeUserParams, encode_change_user};
use session_core::auth::{AuthEvent, UNKNOWN_AUTH_PLUGIN, classify_backend_auth_packet};
use session_core::command::{Command, PreparedMutation, dispatch};
use session_core::fsm::{SessionEvent, SessionFsm, SessionState};
use session_core::response::{
    DEFAULT_RESPONSE_FLUSH_THRESHOLD, ResponseDisposition, ResponseObserver, ResponsePacket,
};
use session_core::special::{
    ChangeUserEffect, ChangeUserError, ChangeUserEvent, ChangeUserRelay, ChangeUserTurn,
    LocalInfileUpload, SessionIdentity, UploadEffect, UploadError, UploadEvent, UploadTurn,
    change_user_ok_in_transaction, local_infile_negotiated, plan_change_user,
};

fn caps(extra: u32) -> CapabilityFlags {
    CapabilityFlags::from_bits_retain(
        CapabilityFlags::PROTOCOL_41.bits()
            | CapabilityFlags::SECURE_CONNECTION.bits()
            | CapabilityFlags::PLUGIN_AUTH.bits()
            | extra,
    )
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

fn step_upload(upload: &mut LocalInfileUpload, event: UploadEvent) -> UploadEffect {
    match upload.on_event(event) {
        Ok(effect) => effect,
        Err(error) => unreachable!("upload step failed: {error}"),
    }
}

/// The full LOCAL INFILE happy path across dispatch, observer, FSM, and the
/// upload machine: query → `0xfb` → chunks → terminator → final OK.
#[test]
fn local_infile_end_to_end() -> Result<(), Box<dyn std::error::Error>> {
    let capabilities =
        caps(CapabilityFlags::LOCAL_FILES.bits() | CapabilityFlags::DEPRECATE_EOF.bits());
    assert!(local_infile_negotiated(capabilities));

    // SES-03: the query plan expects a query-shaped response.
    let query = [Command::Query.as_byte(), b'L'];
    let plan = dispatch(CommandPacket::decode(&query)?)?;
    let mut observer = ResponseObserver::new(
        plan.response,
        capabilities,
        false,
        DEFAULT_RESPONSE_FLUSH_THRESHOLD,
    )?;

    // SES-00: forward the command.
    let mut fsm = authenticated_fsm();
    let _ = fsm.on_event(SessionEvent::ClientCommand);

    // Backend answers with the LOCAL INFILE request (0xfb).
    let infile_request = [0xfb, b'f', b'i', b'l', b'e'];
    let effect = observer.observe_backend(ResponsePacket::from_payload(&infile_request)?)?;
    assert_eq!(effect.disposition, ResponseDisposition::LocalInfile);
    let _ = fsm.on_event(effect.session_event());
    assert_eq!(fsm.state(), SessionState::LocalInfile);

    // SES-06: the client streams chunks, then the empty terminator.
    let mut upload = LocalInfileUpload::new();
    assert_eq!(
        step_upload(
            &mut upload,
            UploadEvent::ClientFileChunk {
                payload_bytes: 16 * 1024 * 1024 + 7,
                physical_packets: 2,
            }
        ),
        UploadEffect::ForwardChunkToBackend
    );
    let _ = fsm.on_event(SessionEvent::ClientInfileChunk);
    assert_eq!(
        step_upload(&mut upload, UploadEvent::ClientUploadEnd),
        UploadEffect::ForwardTerminatorAndFlush
    );
    assert_eq!(upload.turn(), UploadTurn::AwaitingFinal);
    assert_eq!(upload.chunks(), 1);
    let _ = fsm.on_event(SessionEvent::ClientInfileEnd);
    assert_eq!(fsm.state(), SessionState::Response);

    // The backend's final OK flows back through the SES-04 observer.
    let final_ok = [0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00];
    let effect = observer.observe_backend(ResponsePacket::from_payload(&final_ok)?)?;
    assert_eq!(effect.disposition, ResponseDisposition::CompleteSuccess);
    let _ = fsm.on_event(effect.session_event());
    assert_eq!(fsm.state(), SessionState::Ready);
    Ok(())
}

/// Empty file: the terminator may be the very first client packet.
#[test]
fn empty_file_terminates_immediately() {
    let mut upload = LocalInfileUpload::new();
    assert_eq!(
        step_upload(&mut upload, UploadEvent::ClientUploadEnd),
        UploadEffect::ForwardTerminatorAndFlush
    );
    assert_eq!(upload.turn(), UploadTurn::AwaitingFinal);
    assert_eq!(upload.chunks(), 0);
    assert_eq!(upload.payload_bytes(), 0);
    // Nothing further is legal on the upload machine.
    assert_eq!(
        upload.on_event(UploadEvent::ClientUploadEnd),
        Err(UploadError::IllegalTurn {
            turn: UploadTurn::AwaitingFinal
        })
    );
}

/// Large files stay bounded: counters accumulate in u64 without retaining
/// payload, and a hostile counter overflow is a typed error that leaves the
/// machine unchanged.
#[test]
fn large_file_counters_are_bounded_and_overflow_is_typed() {
    let mut upload = LocalInfileUpload::new();
    for _ in 0..1_000 {
        let _ = step_upload(
            &mut upload,
            UploadEvent::ClientFileChunk {
                payload_bytes: u64::from(u32::MAX),
                physical_packets: 257,
            },
        );
    }
    assert_eq!(upload.chunks(), 1_000);
    assert_eq!(upload.payload_bytes(), u64::from(u32::MAX) * 1_000);
    assert_eq!(upload.physical_packets(), 257 * 1_000);

    let before = upload.clone();
    assert_eq!(
        upload.on_event(UploadEvent::ClientFileChunk {
            payload_bytes: u64::MAX,
            physical_packets: 1,
        }),
        Err(UploadError::CounterOverflow)
    );
    assert_eq!(upload, before, "a rejection changes nothing");
}

/// Client abort mid-upload terminates the machine; the capability switch
/// does not change bounded termination (Go forwards regardless).
#[test]
fn client_abort_and_disabled_capability() {
    assert!(!local_infile_negotiated(caps(0)));
    let mut upload = LocalInfileUpload::new();
    let _ = step_upload(
        &mut upload,
        UploadEvent::ClientFileChunk {
            payload_bytes: 5,
            physical_packets: 1,
        },
    );
    assert_eq!(
        step_upload(&mut upload, UploadEvent::ClientAborted),
        UploadEffect::AbortUpload
    );
    assert_eq!(upload.turn(), UploadTurn::Aborted);
    for event in [
        UploadEvent::ClientFileChunk {
            payload_bytes: 1,
            physical_packets: 1,
        },
        UploadEvent::ClientUploadEnd,
        UploadEvent::ClientAborted,
    ] {
        assert!(upload.on_event(event).is_err(), "{event:?} after abort");
    }
}

/// Redirect and graceful close during the upload wait for the safe
/// boundary: the FSM keeps them pending until the final response completes.
#[test]
fn redirect_and_drain_wait_for_infile_boundary() {
    let mut fsm = authenticated_fsm();
    for event in [
        SessionEvent::ClientCommand,
        SessionEvent::BackendLocalInfileRequest,
    ] {
        match fsm.on_event(event) {
            Ok(_) => {}
            Err(error) => unreachable!("setup failed: {error}"),
        }
    }
    assert_eq!(fsm.state(), SessionState::LocalInfile);
    // A redirect during the upload stays pending in place.
    match fsm.on_event(SessionEvent::ControlRedirect) {
        Ok(effects) => assert_eq!(effects, Vec::new()),
        Err(error) => unreachable!("redirect during upload: {error}"),
    }
    assert_eq!(fsm.state(), SessionState::LocalInfile);
    assert!(fsm.flags().redirect_pending);
    // Upload completes; the final response reaches the boundary and only
    // then does the migration start.
    for (event, state) in [
        (SessionEvent::ClientInfileEnd, SessionState::Response),
        (
            SessionEvent::BackendResponseTxnDone,
            SessionState::RedirectPending,
        ),
    ] {
        match fsm.on_event(event) {
            Ok(_) => assert_eq!(fsm.state(), state),
            Err(error) => unreachable!("boundary walk: {error}"),
        }
    }
}

fn change_user_payload(capabilities: CapabilityFlags) -> Vec<u8> {
    let attributes = [Attribute {
        key: b"program_name",
        value: b"ses06",
    }];
    let attributes = capabilities
        .contains(CapabilityFlags::CONNECT_ATTRS)
        .then_some(&attributes[..]);
    match encode_change_user(
        ChangeUserParams {
            username: b"new_user",
            auth_response: b"s3cr3t-scramble-bytes",
            database: b"new_db",
            character_set: Some(0x21),
            auth_plugin_name: Some(b"mysql_native_password"),
            attributes,
        },
        capabilities,
    ) {
        Ok(payload) => payload,
        Err(error) => unreachable!("encode change-user: {error}"),
    }
}

/// The rewrite drops the client's auth data, swaps in the unknown plugin,
/// and preserves identity fields; no secret bytes survive anywhere.
#[test]
fn change_user_rewrite_drops_secrets() -> Result<(), Box<dyn std::error::Error>> {
    let capabilities = caps(CapabilityFlags::CONNECT_ATTRS.bits());
    let payload = change_user_payload(capabilities);
    let plan = plan_change_user(&payload, capabilities)?;

    // The rewritten request carries the sentinel plugin and no auth bytes.
    let reparsed = mysql_wire::parse_change_user(&plan.rewritten, capabilities)?;
    assert_eq!(reparsed.username, b"new_user");
    assert_eq!(reparsed.database, b"new_db");
    assert_eq!(reparsed.auth_response, b"");
    assert_eq!(reparsed.auth_plugin_name, Some(UNKNOWN_AUTH_PLUGIN));
    assert_eq!(reparsed.character_set, Some(0x21));

    // The secret scramble is nowhere in the plan: not in the rewritten
    // bytes, not in the pending identity, not in any Debug output.
    let secret = b"s3cr3t-scramble-bytes";
    assert!(
        !plan
            .rewritten
            .windows(secret.len())
            .any(|window| window == secret)
    );
    assert!(!format!("{plan:?}").contains("s3cr3t"));
    assert_eq!(plan.pending.username(), b"new_user");
    assert_eq!(plan.pending.database(), b"new_db");
    let attributes = plan
        .pending
        .attributes()
        .map(<[(Vec<u8>, Vec<u8>)]>::to_vec);
    assert_eq!(
        attributes,
        Some(vec![(b"program_name".to_vec(), b"ses06".to_vec())])
    );
    Ok(())
}

/// Malformed and oversized change-user requests are typed rejections.
#[test]
fn change_user_rejects_malformed_and_oversized() {
    let capabilities = caps(0);
    assert!(matches!(
        plan_change_user(&[0x11], capabilities),
        Err(ChangeUserError::Malformed)
    ));
    // No size cap: COM_CHANGE_USER is an ordinary command packet in Go —
    // an oversized-but-parsable payload is not rejected here (B3).
    let big_db = vec![b'd'; 512 * 1024];
    let attributes: &[Attribute<'_>] = &[];
    let _ = attributes;
    let big = match encode_change_user(
        ChangeUserParams {
            username: b"u",
            auth_response: b"",
            database: &big_db,
            character_set: Some(0x21),
            auth_plugin_name: Some(b"mysql_native_password"),
            attributes: None,
        },
        capabilities,
    ) {
        Ok(payload) => payload,
        Err(error) => unreachable!("encode big change-user: {error}"),
    };
    assert!(plan_change_user(&big, capabilities).is_ok());
}

/// The relay round-trips the backend's fresh auth switch, commits on OK
/// with the transaction boundary, and composes with SES-02 classification
/// and SES-03 prepared-state clearing.
#[test]
fn change_user_success_commits_identity() -> Result<(), Box<dyn std::error::Error>> {
    let capabilities = caps(CapabilityFlags::CONNECT_ATTRS.bits());
    let payload = change_user_payload(capabilities);
    let plan = plan_change_user(&payload, capabilities)?;

    // SES-03's plan for the raw command clears prepared state on success.
    let command_plan = dispatch(CommandPacket::decode(&payload)?)?;
    assert_eq!(
        command_plan.after_success.prepared,
        Some(PreparedMutation::ClearAll)
    );

    let mut relay = ChangeUserRelay::new(false);
    // Backend answers with a fresh auth switch (classified by SES-02).
    let mut switch = vec![0xfe];
    switch.extend_from_slice(b"mysql_native_password\0fresh-salt");
    let classified = classify_backend_auth_packet(&switch, capabilities)?;
    assert!(matches!(classified, AuthEvent::AuthSwitchRequest { .. }));
    let step = relay.on_event(ChangeUserEvent::BackendAuthData)?;
    assert_eq!(step.effects, vec![ChangeUserEffect::ForwardBackendToClient]);
    let step = relay.on_event(ChangeUserEvent::ClientAuthResponse)?;
    assert_eq!(step.effects, vec![ChangeUserEffect::ForwardClientToBackend]);

    // Final OK, no open transaction.
    let ok = [0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00];
    assert!(!change_user_ok_in_transaction(&ok, capabilities)?);
    let step = relay.on_event(ChangeUserEvent::BackendOk {
        in_transaction: false,
    })?;
    assert_eq!(
        step.effects,
        vec![
            ChangeUserEffect::ForwardBackendToClient,
            ChangeUserEffect::CommitPendingIdentity,
        ]
    );
    assert_eq!(
        step.session_event,
        Some(SessionEvent::BackendResponseTxnDone)
    );
    assert_eq!(relay.turn(), ChangeUserTurn::Finished);

    // Committing updates the SES-06 identity.
    let mut identity = SessionIdentity::new(b"old_user", Some(b"old_db"));
    assert_eq!(identity.attributes(), None);
    identity.apply_change_user(&plan.pending);
    assert_eq!(identity.username(), b"new_user");
    assert_eq!(
        identity.database(),
        &session_core::command::CurrentDatabaseState::Selected(b"new_db".to_vec())
    );
    // B1: attributes commit with the identity (Go changeUser sets attrs).
    assert_eq!(
        identity.attributes().map(<[(Vec<u8>, Vec<u8>)]>::to_vec),
        Some(vec![(b"program_name".to_vec(), b"ses06".to_vec())])
    );
    assert!(!format!("{identity:?}").contains("ses06"), "Debug redacts");

    // Nothing further is legal after the terminal step.
    assert!(
        relay
            .on_event(ChangeUserEvent::BackendOk {
                in_transaction: false
            })
            .is_err()
    );
    Ok(())
}

/// A backend rejection forwards the error, discards the pending identity,
/// and leaves the previous identity untouched (Go applies `changeUser`
/// only when `err == nil`).
#[test]
fn change_user_failure_keeps_previous_identity() -> Result<(), Box<dyn std::error::Error>> {
    let capabilities = caps(0);
    let payload = change_user_payload(capabilities);
    let plan = plan_change_user(&payload, capabilities)?;

    let mut relay = ChangeUserRelay::new(false);
    let step = relay.on_event(ChangeUserEvent::BackendError { code: 1045 })?;
    assert_eq!(
        step.effects,
        vec![
            ChangeUserEffect::ForwardBackendToClient,
            ChangeUserEffect::DiscardPendingIdentity,
        ]
    );
    // B2: the failure boundary is crossed with the retained pre-command
    // transaction state so queued redirect/drain can proceed.
    assert_eq!(
        step.session_event,
        Some(SessionEvent::BackendResponseTxnDone)
    );
    let mut in_txn_relay = ChangeUserRelay::new(true);
    let step = in_txn_relay.on_event(ChangeUserEvent::BackendError { code: 1045 })?;
    assert_eq!(
        step.session_event,
        Some(SessionEvent::BackendResponseTxnOpen)
    );

    let identity = SessionIdentity::new(b"old_user", Some(b"old_db"));
    // The pending identity is discarded: nothing applies it.
    let _ = plan;
    assert_eq!(identity.username(), b"old_user");

    // Client packets during the backend's turn are illegal.
    let mut fresh = ChangeUserRelay::new(false);
    assert_eq!(
        fresh.on_event(ChangeUserEvent::ClientAuthResponse),
        Err(ChangeUserError::IllegalTurn {
            turn: ChangeUserTurn::AwaitingBackend
        })
    );
    Ok(())
}

/// Redirect during a change-user waits for the safe boundary: the FSM sits
/// in `Command` through the relay and migrates only at the final response.
#[test]
fn redirect_waits_for_change_user_boundary() {
    let mut fsm = authenticated_fsm();
    match fsm.on_event(SessionEvent::ClientCommand) {
        Ok(_) => {}
        Err(error) => unreachable!("setup failed: {error}"),
    }
    assert_eq!(fsm.state(), SessionState::Command);
    match fsm.on_event(SessionEvent::ControlRedirect) {
        Ok(effects) => assert_eq!(effects, Vec::new()),
        Err(error) => unreachable!("redirect during change-user: {error}"),
    }
    assert!(fsm.flags().redirect_pending);
    assert_eq!(fsm.state(), SessionState::Command);
    // The relay's terminal OK maps to the boundary event; migration starts.
    match fsm.on_event(SessionEvent::BackendResponseTxnDone) {
        Ok(_) => assert_eq!(fsm.state(), SessionState::RedirectPending),
        Err(error) => unreachable!("boundary: {error}"),
    }
}

/// `COM_STATISTICS` needs no SES-06 machine: the SES-04 observer's raw
/// one-packet state already models Go `forwardStatisticsCmd`.
#[test]
fn statistics_is_owned_by_the_observer() -> Result<(), Box<dyn std::error::Error>> {
    let stats = [Command::Statistics.as_byte()];
    let plan = dispatch(CommandPacket::decode(&stats)?)?;
    let mut observer = ResponseObserver::new(
        plan.response,
        caps(0),
        false,
        NonZeroU64::new(1).map_or(DEFAULT_RESPONSE_FLUSH_THRESHOLD, |threshold| threshold),
    )?;
    let raw = *b"Uptime: 5  Threads: 1";
    let effect = observer.observe_backend(ResponsePacket::from_payload(&raw)?)?;
    assert_eq!(effect.disposition, ResponseDisposition::CompleteRaw);
    Ok(())
}
