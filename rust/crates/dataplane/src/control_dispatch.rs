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

use std::collections::BTreeSet;
use std::time::Duration;

use control_proto::v1::control_envelope::Body;
use control_proto::v1::{
    CloseCommand, CloseResult, ConnectionEvent, ConnectionEventKind, ConnectionIdentity,
    ControlEnvelope, DrainCommand, DrainResult, ErrorCode, ErrorSource, Priority, ProtocolError,
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
    /// Matched sessions already told to force-close under the active
    /// drain: each id gets `CloseImmediate` exactly once, however many
    /// ticks land past the force deadline.
    force_notified: BTreeSet<u64>,
    next_request_id: u64,
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
            force_notified: BTreeSet::new(),
            next_request_id: 0,
        }
    }

    fn next_request_id(&mut self) -> u64 {
        self.next_request_id = self.next_request_id.saturating_add(1);
        self.next_request_id
    }

    /// Wraps one outbound answer as a complete control envelope with a
    /// request id, the relevant generation, and critical priority — the
    /// dispatch task owns the send.
    fn envelope(&mut self, outbound: OutboundControl, generation: u64) -> ControlEnvelope {
        let request_id = self.next_request_id();
        let body = match outbound {
            OutboundControl::RedirectResult(result) => Body::RedirectResult(result),
            OutboundControl::CloseResult(result) => Body::CloseResult(result),
            OutboundControl::DrainResult(result) => Body::DrainResult(result),
            OutboundControl::ProtocolError {
                code,
                request_id: offending,
                detail,
            } => Body::Error(ProtocolError {
                code: code.into(),
                offending_request_id: offending,
                retryable: false,
                detail: detail.to_owned(),
            }),
        };
        ControlEnvelope {
            protocol_version: 0,
            control_epoch: 0,
            generation,
            request_id,
            priority: Priority::Critical.into(),
            sent_unix_millis: 0,
            required_capabilities: Vec::new(),
            body: Some(body),
        }
    }

    /// Dispatches one inbound control envelope on the production path:
    /// redirect/close/drain commands and reconcile snapshots consult
    /// the gate; drain deadlines are converted from the wire against
    /// the supplied clock pair. Returns complete outbound envelopes.
    pub fn handle_envelope(
        &mut self,
        envelope: &ControlEnvelope,
        now: Instant,
        now_unix_millis: u64,
    ) -> Vec<ControlEnvelope> {
        let request_id = envelope.request_id;
        let generation = envelope.generation;
        match &envelope.body {
            Some(Body::RedirectCommand(command)) => {
                let command = command.clone();
                self.handle_redirect(request_id, generation, &command)
                    .into_iter()
                    .map(|out| self.envelope(out, generation))
                    .collect()
            }
            Some(Body::CloseCommand(command)) => {
                let command = command.clone();
                self.handle_close(request_id, generation, &command)
                    .into_iter()
                    .map(|out| self.envelope(out, generation))
                    .collect()
            }
            Some(Body::DrainCommand(command)) => {
                let command = command.clone();
                self.handle_drain(request_id, generation, &command, now, now_unix_millis)
                    .into_iter()
                    .map(|out| self.envelope(out, generation))
                    .collect()
            }
            Some(Body::ReconcileSnapshot(snapshot)) => {
                let snapshot = snapshot.clone();
                let (results, ghosts) = self.apply_reconcile_snapshot(&snapshot);
                let mut outbound: Vec<ControlEnvelope> = results
                    .into_iter()
                    .map(|out| self.envelope(out, snapshot.applied_generation))
                    .collect();
                outbound.extend(ghosts);
                outbound
            }
            _ => Vec::new(),
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

    /// Removes a session after it terminates, updating any active
    /// drain's accounting first, and produces the **sequenced** CLOSED
    /// lifecycle envelope (the event sequence rides the request id,
    /// which Go's per-epoch dedup and the reconcile
    /// `last_connection_event_sequence` both key on).
    pub fn session_closed(
        &mut self,
        connection_id: u64,
        forced: bool,
        error_source: ErrorSource,
    ) -> Option<ControlEnvelope> {
        let identity = self.gate.connection_identity(connection_id);
        let generation = self.gate.connection_generation(connection_id).unwrap_or(0);
        let backend_id = self
            .gate
            .connection_backend(connection_id)
            .unwrap_or_default();
        self.gate.record_drain_close(connection_id, forced);
        self.gate.unregister_connection(connection_id);
        self.sessions.remove(&connection_id);
        let identity = identity?;
        Some(self.closed_event(identity, &backend_id, generation, error_source))
    }

    fn closed_event(
        &mut self,
        identity: ConnectionIdentity,
        backend_id: &str,
        generation: u64,
        error_source: ErrorSource,
    ) -> ControlEnvelope {
        let sequence = self.gate.next_event_sequence();
        ControlEnvelope {
            protocol_version: 0,
            control_epoch: 0,
            generation,
            request_id: sequence,
            priority: Priority::Critical.into(),
            sent_unix_millis: 0,
            required_capabilities: Vec::new(),
            body: Some(Body::ConnectionEvent(ConnectionEvent {
                kind: ConnectionEventKind::Closed.into(),
                connection: Some(identity),
                backend_id: backend_id.to_owned(),
                namespace: String::new(),
                error_source: error_source.into(),
                client_in_bytes: 0,
                client_out_bytes: 0,
                backend_in_bytes: 0,
                backend_out_bytes: 0,
            })),
        }
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
                if self.forward(command.connection_id, control) {
                    Vec::new()
                } else {
                    // The session vanished (or its channel closed)
                    // between registration and dispatch: retire the
                    // accepted close with its terminal immediately so
                    // the gate never sticks in Closing.
                    self.gate
                        .complete_close(command.connection_id, &command.close_id)
                        .map(OutboundControl::CloseResult)
                        .into_iter()
                        .collect()
                }
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

    /// Dispatches one `DrainCommand`: admits it against the **wire**
    /// absolute deadlines (converted through the `now`/`now_unix_millis`
    /// clock pair), asks graceful closes from every matched session —
    /// or force-closes immediately when the force deadline already
    /// passed — and answers progress.
    pub fn handle_drain(
        &mut self,
        request_id: u64,
        envelope_generation: u64,
        command: &DrainCommand,
        now: Instant,
        now_unix_millis: u64,
    ) -> Vec<OutboundControl> {
        let to_instant = |deadline_ms: u64| {
            now + Duration::from_millis(deadline_ms.saturating_sub(now_unix_millis))
        };
        let graceful_deadline = to_instant(command.graceful_deadline_unix_millis);
        let force_deadline = to_instant(command.force_deadline_unix_millis);
        let matched: BTreeSet<u64> = self
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
            .collect::<BTreeSet<u64>>();
        match self.gate.admit_drain(
            command,
            envelope_generation,
            graceful_deadline,
            force_deadline,
            matched.clone(),
        ) {
            DrainAdmission::Start => {
                self.force_notified.clear();
                if command.force_deadline_unix_millis != 0
                    && now_unix_millis >= command.force_deadline_unix_millis
                {
                    // The command arrived already past its force
                    // deadline: never ask a graceful close first.
                    for id in &matched {
                        let _ = self.forward(*id, SessionControl::CloseImmediate);
                        self.force_notified.insert(*id);
                    }
                } else {
                    for id in &matched {
                        let _ = self.forward(*id, SessionControl::GracefulClose);
                    }
                }
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
    /// remaining matched session is closed immediately — **exactly
    /// once per session**, however many ticks land past the deadline.
    /// Returns current progress when a drain is active.
    pub fn tick(&mut self, now: Instant) -> Option<OutboundControl> {
        if self.gate.drain_phase(now) == Some(DrainPhase::Force) {
            for id in self.gate.drain_remaining() {
                if self.force_notified.insert(id) {
                    let _ = self.forward(id, SessionControl::CloseImmediate);
                }
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
    ) -> (Vec<OutboundControl>, Vec<ControlEnvelope>) {
        self.metering.acked_through(snapshot.metering_sequence);
        let repairs = self.gate.apply_reconcile_snapshot(snapshot);
        let outbound: Vec<OutboundControl> = repairs
            .replay_redirect_results
            .into_iter()
            .map(OutboundControl::RedirectResult)
            .collect();
        // Ghosts are answered here with sequenced terminal CLOSED
        // events built from the peer's own identity view, so both
        // sides converge without a separate composition step.
        let mut ghost_events = Vec::new();
        for remote in &snapshot.connections {
            if repairs.ghost_connections.contains(&remote.connection_id)
                && let Some(identity) = remote.identity.clone()
            {
                ghost_events.push(self.closed_event(
                    identity,
                    &remote.backend_id,
                    remote.generation,
                    ErrorSource::Proxy,
                ));
            }
        }
        (outbound, ghost_events)
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

/// Session-side notifications into the dispatch task.
#[derive(Debug)]
pub enum DispatchNotice {
    /// A new control session finished negotiation.
    Negotiated {
        /// Whether `RECONCILE_SESSION_REHYDRATION` was negotiated.
        rehydration_capability: bool,
    },
    /// A config snapshot generation was applied (CTL-05).
    AppliedGeneration(u64),
    /// An admitted session registers its control channel.
    RegisterSession {
        /// Admission identity.
        identity: ConnectionIdentity,
        /// Routing namespace.
        namespace: String,
        /// Admission snapshot generation.
        snapshot_generation: u64,
        /// Configured listener name (drain scoping).
        listener_name: String,
        /// The session loop's control channel.
        control: mpsc::Sender<SessionControl>,
    },
    /// The session's backend attached or changed.
    SetBackend {
        /// Connection id.
        connection_id: u64,
        /// New backend id.
        backend_id: String,
    },
    /// The session terminated.
    SessionClosed {
        /// Connection id.
        connection_id: u64,
        /// Whether a force close ended it.
        forced: bool,
        /// Failure attribution for the CLOSED event.
        error_source: ErrorSource,
    },
    /// A session's redirect finished.
    RedirectFinished {
        /// Connection id.
        connection_id: u64,
        /// The redirect id.
        redirect_id: String,
        /// Whether the migration succeeded.
        succeeded: bool,
        /// The owning backend after the redirect.
        backend_id: String,
        /// Failure code when unsuccessful.
        code: ErrorCode,
    },
    /// A session's accepted close finished.
    CloseFinished {
        /// Connection id.
        connection_id: u64,
        /// The close id.
        close_id: String,
    },
}

/// Cloneable session-facing handle to the dispatch task.
#[derive(Clone)]
pub struct ControlDispatchHandle {
    notices: mpsc::Sender<DispatchNotice>,
}

impl ControlDispatchHandle {
    /// Submits one notice; returns false when the dispatch task is gone.
    pub async fn notify(&self, notice: DispatchNotice) -> bool {
        self.notices.send(notice).await.is_ok()
    }
}

/// The control-transport receive half: implements the transport
/// [`control_proto::control_transport::Handler`], forwarding every
/// post-Hello envelope into the dispatch task's queue. Backpressure is
/// fail-closed: a full queue errors the stream, which triggers the
/// transport's reconnect path rather than silently dropping a command.
pub struct InboundForwarder {
    inbound: mpsc::Sender<ControlEnvelope>,
}

impl control_proto::control_transport::Handler for InboundForwarder {
    fn handle(
        &self,
        envelope: ControlEnvelope,
    ) -> Result<(), control_proto::control_transport::TransportError> {
        self.inbound.try_send(envelope).map_err(|_| {
            control_proto::control_transport::TransportError::Configuration(
                "control dispatch queue is full or closed".to_owned(),
            )
        })
    }
}

/// Wall-clock source for wire-deadline conversion (injected so tests
/// pin it; production passes a `SystemTime`-based closure).
pub type UnixMillisFn = fn() -> u64;

/// Runs the production dispatch loop: inbound envelopes from the
/// transport handler, notices from session tasks, and a periodic drain
/// tick, with every outbound envelope handed to `send`. This is the
/// long-lived single owner of [`ControlCommandHandler`]; it survives
/// control reconnects (`Negotiated` notices update the peer mode only).
pub async fn run_control_dispatch<F, Fut>(
    mut handler: ControlCommandHandler,
    mut inbound: mpsc::Receiver<ControlEnvelope>,
    mut notices: mpsc::Receiver<DispatchNotice>,
    tick_interval: Duration,
    unix_now_millis: UnixMillisFn,
    mut send: F,
) where
    F: FnMut(ControlEnvelope) -> Fut,
    Fut: Future<Output = ()>,
{
    let mut ticker = tokio::time::interval(tick_interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            biased;
            notice = notices.recv() => {
                let Some(notice) = notice else { break };
                match notice {
                    DispatchNotice::Negotiated { rehydration_capability } => {
                        handler.on_session_negotiated(rehydration_capability);
                    }
                    DispatchNotice::AppliedGeneration(generation) => {
                        handler.set_applied_generation(generation);
                    }
                    DispatchNotice::RegisterSession {
                        identity,
                        namespace,
                        snapshot_generation,
                        listener_name,
                        control,
                    } => {
                        handler.register_session(
                            identity,
                            &namespace,
                            snapshot_generation,
                            &listener_name,
                            control,
                        );
                    }
                    DispatchNotice::SetBackend { connection_id, backend_id } => {
                        handler.set_backend(connection_id, &backend_id);
                    }
                    DispatchNotice::SessionClosed { connection_id, forced, error_source } => {
                        if let Some(event) =
                            handler.session_closed(connection_id, forced, error_source)
                        {
                            send(event).await;
                        }
                    }
                    DispatchNotice::RedirectFinished {
                        connection_id,
                        redirect_id,
                        succeeded,
                        backend_id,
                        code,
                    } => {
                        if let Some(out) = handler.redirect_completed(
                            connection_id,
                            &redirect_id,
                            succeeded,
                            &backend_id,
                            code,
                        ) {
                            let generation = handler
                                .gate
                                .connection_generation(connection_id)
                                .unwrap_or(0);
                            let envelope = handler.envelope(out, generation);
                            send(envelope).await;
                        }
                    }
                    DispatchNotice::CloseFinished { connection_id, close_id } => {
                        if let Some(out) = handler.close_completed(connection_id, &close_id) {
                            let generation = handler
                                .gate
                                .connection_generation(connection_id)
                                .unwrap_or(0);
                            let envelope = handler.envelope(out, generation);
                            send(envelope).await;
                        }
                    }
                }
            }
            envelope = inbound.recv() => {
                let Some(envelope) = envelope else { break };
                let outbound =
                    handler.handle_envelope(&envelope, Instant::now(), unix_now_millis());
                for out in outbound {
                    send(out).await;
                }
            }
            _ = ticker.tick() => {
                if let Some(OutboundControl::DrainResult(progress)) =
                    handler.tick(Instant::now())
                {
                    let envelope =
                        handler.envelope(OutboundControl::DrainResult(progress), 0);
                    send(envelope).await;
                }
            }
        }
    }
}

/// Production wall clock for [`run_control_dispatch`].
#[must_use]
pub fn system_unix_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// Spawns the production control-dispatch task bound to the shared
/// control client: the returned [`InboundForwarder`] is the transport
/// handler for [`control_proto::control_transport::ControlClient::run`],
/// and the [`ControlDispatchHandle`] is the session-facing surface.
#[must_use]
pub fn spawn_control_dispatch(
    client: std::sync::Arc<control_proto::control_transport::ControlClient>,
    tick_interval: Duration,
) -> (
    ControlDispatchHandle,
    InboundForwarder,
    tokio::task::JoinHandle<()>,
) {
    let (inbound_tx, inbound_rx) = mpsc::channel(256);
    let (notice_tx, notice_rx) = mpsc::channel(256);
    let task = tokio::spawn(async move {
        run_control_dispatch(
            ControlCommandHandler::new(),
            inbound_rx,
            notice_rx,
            tick_interval,
            system_unix_millis,
            move |envelope| {
                let client = std::sync::Arc::clone(&client);
                async move {
                    let _ = client.send(envelope).await;
                }
            },
        )
        .await;
    });
    (
        ControlDispatchHandle { notices: notice_tx },
        InboundForwarder {
            inbound: inbound_tx,
        },
        task,
    )
}
