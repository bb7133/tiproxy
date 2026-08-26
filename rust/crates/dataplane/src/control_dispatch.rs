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

//! Production control-command dispatch (CTL-06): the owner that puts
//! [`CommandGate`] and [`MeteringLedger`] on the real message path.
//!
//! [`ControlCommandHandler`] is **long-lived across control
//! reconnects**: a new control session updates the peer mode
//! ([`ControlCommandHandler::on_session_negotiated`]) but never rebuilds
//! the gate — terminal tombstones, unacked results, and watermarks must
//! survive exactly the epochs where a lost result needs cross-epoch
//! replay.
//!
//! Inbound commands consult the gate and map admissions to real
//! effects:
//!
//! - `Start` becomes the session's
//!   [`SessionControl`] (`Redirect` / `GracefulClose` /
//!   `CloseImmediate`) through the per-session registry;
//! - `Replay` / progress answers become outbound result envelopes;
//! - `Obsolete` answers a `DUPLICATE_REQUEST`-coded result the issuer
//!   ignores by id (never a new failure, never a re-execution);
//! - `SequenceMismatch` / `StaleGeneration` / `UnknownConnection`
//!   become typed protocol errors (`PROTOCOL_VIOLATION`,
//!   `STALE_GENERATION`, `RECONCILIATION_REQUIRED`).
//!
//! Session completions ([`ControlCommandHandler::redirect_completed`],
//! [`ControlCommandHandler::close_completed`]) produce each terminal
//! result exactly once through the gate. Drains collect their matched
//! set from the registered sessions at admission, ask graceful closes
//! immediately, and [`ControlCommandHandler::tick`] drives the force
//! phase from the command's absolute deadlines.

use std::collections::HashMap;

use control_proto::v1::{
    CloseCommand, CloseResult, ConnectionIdentity, DrainCommand, DrainResult, ErrorCode,
    ReconcileRequest, ReconcileSnapshot, RedirectCommand, RedirectResult,
};
use tokio::sync::mpsc;
use tokio::time::Instant;

use crate::control_commands::{
    CloseAdmission, CommandGate, DrainAdmission, DrainPhase, MeteringError, MeteringLedger,
    RedirectAdmission,
};
use crate::session::SessionControl;

/// Outbound answers the runtime writes back to the control stream.
#[derive(Debug, Clone, PartialEq)]
pub enum OutboundControl {
    /// A redirect's terminal (or replayed/obsolete) result.
    RedirectResult(RedirectResult),
    /// A close's terminal (or replayed/current-state) result.
    CloseResult(CloseResult),
    /// Drain progress, replay, conflict, or obsolete answer.
    DrainResult(DrainResult),
    /// A typed protocol error for the offending request.
    ProtocolError {
        /// The error code (`PROTOCOL_VIOLATION`, `STALE_GENERATION`,
        /// `RECONCILIATION_REQUIRED`).
        code: ErrorCode,
        /// The offending request id.
        request_id: u64,
        /// Static, payload-free detail.
        detail: &'static str,
    },
}

/// One registered live session: its control channel plus the metadata
/// drain scoping needs.
struct SessionEntry {
    control: mpsc::Sender<SessionControl>,
    listener_name: String,
}

/// The long-lived production owner of the command gate, metering
/// ledger, and per-session control channels. Single-owner: lives on the
/// control-dispatch task, no lock.
pub struct ControlCommandHandler {
    gate: CommandGate,
    metering: MeteringLedger,
    sessions: HashMap<u64, SessionEntry>,
}

impl Default for ControlCommandHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl ControlCommandHandler {
    /// Creates the handler once per process; it survives control
    /// reconnects.
    #[must_use]
    pub fn new() -> Self {
        Self {
            gate: CommandGate::new(),
            metering: MeteringLedger::new(),
            sessions: HashMap::new(),
        }
    }

    /// Applies a new control session's negotiation: peer mode follows
    /// the `RECONCILE_SESSION_REHYDRATION` capability. The gate is
    /// deliberately **not** rebuilt — tombstones, unacked results, and
    /// watermarks persist across epochs.
    pub fn on_session_negotiated(&mut self, rehydration_capability: bool) {
        self.gate.set_legacy_peer(!rehydration_capability);
    }

    /// Records the applied config snapshot generation (drain
    /// provenance).
    pub fn set_applied_generation(&mut self, generation: u64) {
        self.gate.set_applied_generation(generation);
    }

    /// Registers an admitted session with its control channel.
    pub fn register_session(
        &mut self,
        identity: ConnectionIdentity,
        namespace: &str,
        snapshot_generation: u64,
        listener_name: &str,
        control: mpsc::Sender<SessionControl>,
    ) {
        let connection_id = identity.connection_id;
        self.gate
            .register_connection(identity, namespace, snapshot_generation);
        self.sessions.insert(
            connection_id,
            SessionEntry {
                control,
                listener_name: listener_name.to_owned(),
            },
        );
    }

    /// Records the session's current backend (route/redirect success).
    pub fn set_backend(&mut self, connection_id: u64, backend_id: &str) {
        self.gate.set_backend(connection_id, backend_id);
    }

    /// Removes a session after its terminal CLOSED event, updating any
    /// active drain's accounting first.
    pub fn session_closed(&mut self, connection_id: u64, forced: bool) {
        self.gate.record_drain_close(connection_id, forced);
        self.gate.unregister_connection(connection_id);
        self.sessions.remove(&connection_id);
    }

    /// The metering producer (record/seal/replay flow is the
    /// composition's send loop).
    pub fn metering(&mut self) -> &mut MeteringLedger {
        &mut self.metering
    }

    /// Dispatches one `RedirectCommand` from the wire.
    pub fn handle_redirect(
        &mut self,
        request_id: u64,
        envelope_generation: u64,
        command: &RedirectCommand,
    ) -> Vec<OutboundControl> {
        match self.gate.admit_redirect(command, envelope_generation) {
            RedirectAdmission::Start => {
                if self.forward(command.connection_id, SessionControl::Redirect) {
                    Vec::new()
                } else {
                    // The session vanished between registration and
                    // dispatch: retire the admission with a failed
                    // terminal so the id never dangles.
                    self.gate
                        .complete_redirect(
                            command.connection_id,
                            &command.redirect_id,
                            false,
                            "",
                            ErrorCode::RedirectFailed,
                        )
                        .map(OutboundControl::RedirectResult)
                        .into_iter()
                        .collect()
                }
            }
            RedirectAdmission::DuplicatePending => Vec::new(),
            RedirectAdmission::Replay(result) => vec![OutboundControl::RedirectResult(result)],
            RedirectAdmission::Obsolete { .. } => {
                vec![OutboundControl::RedirectResult(RedirectResult {
                    connection_id: command.connection_id,
                    redirect_id: command.redirect_id.clone(),
                    previous_backend_id: String::new(),
                    backend_id: String::new(),
                    succeeded: false,
                    code: ErrorCode::DuplicateRequest.into(),
                    detail: String::new(),
                })]
            }
            RedirectAdmission::Conflict { .. } | RedirectAdmission::SequenceMismatch { .. } => {
                vec![OutboundControl::ProtocolError {
                    code: ErrorCode::ProtocolViolation,
                    request_id,
                    detail: "redirect id/sequence violates the serialization contract",
                }]
            }
            RedirectAdmission::StaleGeneration { .. } => vec![OutboundControl::ProtocolError {
                code: ErrorCode::StaleGeneration,
                request_id,
                detail: "redirect was minted for a different connection incarnation",
            }],
            RedirectAdmission::UnknownConnection => vec![OutboundControl::ProtocolError {
                code: ErrorCode::ReconciliationRequired,
                request_id,
                detail: "redirect for an unknown connection",
            }],
        }
    }

    /// Dispatches one `CloseCommand` from the wire.
    pub fn handle_close(
        &mut self,
        request_id: u64,
        envelope_generation: u64,
        command: &CloseCommand,
    ) -> Vec<OutboundControl> {
        match self.gate.admit_close(
            command.connection_id,
            &command.close_id,
            command.force,
            envelope_generation,
        ) {
            CloseAdmission::Start { force } => {
                let control = if force {
                    SessionControl::CloseImmediate
                } else {
                    SessionControl::GracefulClose
                };
                let _ = self.forward(command.connection_id, control);
                Vec::new()
            }
            CloseAdmission::Replay(result) | CloseAdmission::AlreadyClosing(result) => {
                vec![OutboundControl::CloseResult(result)]
            }
            CloseAdmission::StaleGeneration { .. } => vec![OutboundControl::ProtocolError {
                code: ErrorCode::StaleGeneration,
                request_id,
                detail: "close was minted for a different connection incarnation",
            }],
            CloseAdmission::UnknownConnection => vec![OutboundControl::ProtocolError {
                code: ErrorCode::ReconciliationRequired,
                request_id,
                detail: "close for an unknown connection",
            }],
        }
    }

    /// Dispatches one `DrainCommand`: admits it, asks graceful closes
    /// from every matched session, and answers progress.
    pub fn handle_drain(
        &mut self,
        request_id: u64,
        envelope_generation: u64,
        command: &DrainCommand,
        now: Instant,
        graceful_deadline: Instant,
        force_deadline: Instant,
    ) -> Vec<OutboundControl> {
        let matched: std::collections::BTreeSet<u64> = self
            .sessions
            .iter()
            .filter(|(_, entry)| {
                command.listener_names.is_empty()
                    || command.listener_names.contains(&entry.listener_name)
            })
            .map(|(id, _)| *id)
            .collect();
        let matched = matched
            .into_iter()
            .filter(|id| {
                command.backend_ids.is_empty()
                    || self
                        .gate
                        .connection_backend(*id)
                        .is_some_and(|backend| command.backend_ids.contains(&backend))
            })
            .collect::<std::collections::BTreeSet<u64>>();
        match self.gate.admit_drain(
            command,
            envelope_generation,
            graceful_deadline,
            force_deadline,
            matched.clone(),
        ) {
            DrainAdmission::Start => {
                for id in &matched {
                    let _ = self.forward(*id, SessionControl::GracefulClose);
                }
                let _ = now;
                self.gate
                    .drain_progress()
                    .map(OutboundControl::DrainResult)
                    .into_iter()
                    .collect()
            }
            DrainAdmission::Progress(result) | DrainAdmission::Replay(result) => {
                vec![OutboundControl::DrainResult(result)]
            }
            DrainAdmission::Conflict(result) => vec![OutboundControl::DrainResult(result)],
            DrainAdmission::Obsolete { .. } => vec![OutboundControl::DrainResult(DrainResult {
                drain_id: command.drain_id.clone(),
                active_connections: 0,
                gracefully_closed: 0,
                force_closed: 0,
                complete: true,
                code: ErrorCode::DuplicateRequest.into(),
                detail: String::new(),
            })],
            DrainAdmission::StaleGeneration { .. } => vec![OutboundControl::ProtocolError {
                code: ErrorCode::StaleGeneration,
                request_id,
                detail: "drain provenance predates the applied snapshot",
            }],
            DrainAdmission::SequenceMismatch { .. } => vec![OutboundControl::ProtocolError {
                code: ErrorCode::ProtocolViolation,
                request_id,
                detail: "drain id/sequence violates the one-issuance binding",
            }],
        }
    }

    /// Drives the active drain's phases: at the force deadline every
    /// remaining matched session is closed immediately. Returns current
    /// progress when a drain is active.
    pub fn tick(&mut self, now: Instant) -> Option<OutboundControl> {
        if self.gate.drain_phase(now) == Some(DrainPhase::Force) {
            for id in self.gate.drain_remaining() {
                let _ = self.forward(id, SessionControl::CloseImmediate);
            }
        }
        self.gate.drain_progress().map(OutboundControl::DrainResult)
    }

    /// A session's redirect finished: produces the terminal result
    /// exactly once (late/duplicate completions are suppressed by the
    /// gate).
    pub fn redirect_completed(
        &mut self,
        connection_id: u64,
        redirect_id: &str,
        succeeded: bool,
        new_backend_id: &str,
        code: ErrorCode,
    ) -> Option<OutboundControl> {
        self.gate
            .complete_redirect(connection_id, redirect_id, succeeded, new_backend_id, code)
            .map(OutboundControl::RedirectResult)
    }

    /// A session's accepted close finished: produces the terminal
    /// result exactly once.
    pub fn close_completed(
        &mut self,
        connection_id: u64,
        close_id: &str,
    ) -> Option<OutboundControl> {
        self.gate
            .complete_close(connection_id, close_id)
            .map(OutboundControl::CloseResult)
    }

    /// Builds the reconcile request from the gate's authoritative state
    /// plus the metering watermark.
    #[must_use]
    pub fn build_reconcile_request(&self, known_generation: u64) -> ReconcileRequest {
        self.gate
            .build_reconcile_request(known_generation, 0, self.metering.last_sequence())
    }

    /// Applies the answering snapshot: acknowledged metering retention
    /// drops, and the owed repairs (exact-tombstone replays) come back
    /// as outbound results. Ghost connections are the composition's
    /// CLOSED events.
    pub fn apply_reconcile_snapshot(
        &mut self,
        snapshot: &ReconcileSnapshot,
    ) -> (Vec<OutboundControl>, Vec<u64>) {
        self.metering.acked_through(snapshot.metering_sequence);
        let repairs = self.gate.apply_reconcile_snapshot(snapshot);
        let outbound = repairs
            .replay_redirect_results
            .into_iter()
            .map(OutboundControl::RedirectResult)
            .collect();
        (outbound, repairs.ghost_connections)
    }

    /// Metering batches the composition must (re)send: everything
    /// unacknowledged, in order.
    #[must_use]
    pub fn metering_replay(&self) -> Vec<control_proto::v1::MeteringBatch> {
        self.metering.replay()
    }

    /// Seals and returns the next metering batch for sending.
    ///
    /// # Errors
    ///
    /// Propagates the ledger's fail-closed bounds.
    pub fn seal_metering(
        &mut self,
    ) -> Result<Option<control_proto::v1::MeteringBatch>, MeteringError> {
        self.metering.seal()
    }

    fn forward(&mut self, connection_id: u64, control: SessionControl) -> bool {
        match self.sessions.get(&connection_id) {
            Some(entry) => entry.control.try_send(control).is_ok(),
            None => false,
        }
    }
}
