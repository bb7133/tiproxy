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

//! Production control-plane dispatch (CTL-06): the root that puts
//! [`CommandGate`] and [`MeteringLedger`] on the real message path.
//!
//! [`spawn_control_dispatch`] is the single composition entry: it binds
//! the **process-long-lived** [`ControlCommandHandler`] to the shared
//! control client. The returned [`InboundForwarder`] is the transport's
//! [`Handler`]: its `handle` **awaits** a bounded channel send, so a
//! slow dispatcher applies real backpressure through the read loop and
//! TCP to the Go sender's bounded lanes — a command the peer considers
//! delivered is never dropped and never buffered without bound.
//!
//! The dispatch loop is the explicit multiplexer for **every** inbound
//! body: commands and reconcile snapshots consult the gate;
//! `RouteAssignment` / `HandshakeDecision` / `HandshakeResult` forward
//! to their owning session's registered response channel (the capacity
//! bound is a per-session slot — overflow is a protocol violation the
//! peer is told about, a closed channel means the session ended and
//! close accounting owns the epilogue); snapshot bodies forward —
//! awaited — to the CTL-05 owner's channel; `Heartbeat` /
//! `ProtocolError` / `Hello`-family are the transport's and terminate
//! here; anything else is answered with a typed protocol error and
//! counted. Nothing is silently dropped.
//!
//! Reconnect is automatic and atomic: the loop watches the client's
//! connection state, whose `Connected` snapshot carries the epoch
//! **and** the negotiated capability bitmask in one value — on every
//! new session it updates the peer mode, sends the reconcile request
//! built from the gate's authoritative state, and replays every
//! unacknowledged metering batch, all bound to that exact epoch.
//!
//! Request-id lineage: every application-originated envelope takes its
//! id from the sender's **single checked allocator** (heartbeats
//! included; fail-closed at exhaustion), while **responses reuse the
//! initiating request id** — inline answers carry the inbound
//! command's id, and asynchronous terminals carry the id saved when
//! the command was admitted. Outgoing connection events use allocator
//! ids, and the recorded maximum is the reconcile request's
//! `last_connection_event_sequence`.
//!
//! Terminal `DrainResult`s are produced **proactively on the
//! completion transition** — the last matched session closing (or a
//! zero-match admission) answers the issuer without waiting for a
//! command replay. Force-phase `CloseImmediate` is marked delivered
//! only when the send **succeeds**: a full session channel retries on
//! the next tick, a closed one converges through the close path.

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use std::time::Duration;

use control_proto::control_transport::{ConnectionState, ControlClient, Handler, TransportError};
use control_proto::v1::control_envelope::Body;
use control_proto::v1::{
    CloseCommand, CloseResult, ConnectionEvent, ConnectionEventKind, ConnectionIdentity,
    ControlCapability, ControlEnvelope, DrainCommand, DrainResult, ErrorCode, ErrorSource,
    Priority, ProtocolError, ReconcileRequest, ReconcileSnapshot, RedirectCommand, RedirectResult,
};
use tokio::sync::{mpsc, watch};
use tokio::time::Instant;

use crate::control_commands::{
    CloseAdmission, CommandGate, DrainAdmission, DrainPhase, MeteringError, MeteringLedger,
    RedirectAdmission,
};
use crate::session::SessionControl;

/// Longest accepted distance between "now" and a wire drain deadline:
/// anything further ahead is a malformed command, not a schedule.
const MAX_DRAIN_DEADLINE_AHEAD_MILLIS: u64 = 30 * 24 * 60 * 60 * 1000;

/// Sentinel request id meaning "the dispatch loop must allocate from
/// the sender's checked allocator before sending".
const NEEDS_ALLOCATION: u64 = 0;

/// Outbound answers the gate produces before envelope wrapping.
#[derive(Debug, Clone, PartialEq)]
pub enum OutboundControl {
    /// A redirect's terminal (or replayed/obsolete) result.
    RedirectResult(RedirectResult),
    /// A close's terminal (or replayed/current-state) result.
    CloseResult(CloseResult),
    /// Drain progress, replay, conflict, terminal, or obsolete answer.
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

/// One registered live session: its control channel, its correlated
/// Go-response channel, and the drain-scoping metadata.
struct SessionEntry {
    control: mpsc::Sender<SessionControl>,
    responses: Option<mpsc::Sender<ControlEnvelope>>,
    listener_name: String,
}

/// The forwarding outcome of a session-directed channel send.
enum ForwardOutcome {
    Sent,
    Full,
    Gone,
}

/// The long-lived production owner of the command gate, metering
/// ledger, session channels, and initiating-request-id records.
/// Single-owner: lives on the dispatch task, no lock. Survives control
/// reconnects — the gate is never rebuilt, so tombstones, unacked
/// results, and watermarks persist exactly across the epochs where a
/// lost result needs cross-epoch replay.
pub struct ControlCommandHandler {
    gate: CommandGate,
    metering: MeteringLedger,
    sessions: HashMap<u64, SessionEntry>,
    /// Matched sessions whose force-phase `CloseImmediate` was
    /// **successfully delivered** under the active drain: marking
    /// happens only on a completed send, so a full channel retries on
    /// the next tick instead of losing the close.
    force_notified: BTreeSet<u64>,
    /// Initiating request ids for admitted redirects, keyed
    /// `(connection_id, redirect_id)`: asynchronous terminals reuse
    /// them (responses carry the initiating id — frozen ADR).
    initiating_redirect: HashMap<(u64, String), u64>,
    /// Initiating request ids for accepted closes.
    initiating_close: HashMap<(u64, String), u64>,
    /// Initiating request id for the admitted drain, by wire drain id.
    initiating_drain: HashMap<String, u64>,
    /// Inbound bodies that had no legal route here (each also answered
    /// with a typed protocol error — never silently dropped).
    unrouted: u64,
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
            initiating_redirect: HashMap::new(),
            initiating_close: HashMap::new(),
            initiating_drain: HashMap::new(),
            unrouted: 0,
        }
    }

    /// Applies a new control session's negotiation: peer mode follows
    /// the `RECONCILE_SESSION_REHYDRATION` capability. The gate is
    /// deliberately **not** rebuilt.
    pub fn on_session_negotiated(&mut self, rehydration_capability: bool) {
        self.gate.set_legacy_peer(!rehydration_capability);
    }

    /// Records the applied config snapshot generation (drain
    /// provenance).
    pub fn set_applied_generation(&mut self, generation: u64) {
        self.gate.set_applied_generation(generation);
    }

    /// The applied generation (the reconcile known-generation).
    #[must_use]
    pub const fn applied_generation(&self) -> u64 {
        self.gate.applied_generation()
    }

    /// Registers an admitted session with its control channel and its
    /// optional correlated-response channel.
    pub fn register_session(
        &mut self,
        identity: ConnectionIdentity,
        namespace: &str,
        snapshot_generation: u64,
        listener_name: &str,
        control: mpsc::Sender<SessionControl>,
        responses: Option<mpsc::Sender<ControlEnvelope>>,
    ) {
        let connection_id = identity.connection_id;
        self.gate
            .register_connection(identity, namespace, snapshot_generation);
        self.sessions.insert(
            connection_id,
            SessionEntry {
                control,
                responses,
                listener_name: listener_name.to_owned(),
            },
        );
    }

    /// Records the session's current backend (route/redirect success).
    pub fn set_backend(&mut self, connection_id: u64, backend_id: &str) {
        self.gate.set_backend(connection_id, backend_id);
    }

    /// Inbound bodies that had no legal route so far.
    #[must_use]
    pub const fn unrouted(&self) -> u64 {
        self.unrouted
    }

    /// The metering producer (record/seal/replay flow).
    pub fn metering(&mut self) -> &mut MeteringLedger {
        &mut self.metering
    }

    /// Records the allocator id an outgoing connection event was sent
    /// under (the reconcile `last_connection_event_sequence`).
    pub fn record_event_sequence(&mut self, request_id: u64) {
        self.gate.record_event_sequence(request_id);
    }

    /// Removes a session after it terminates. Returns the envelopes the
    /// termination itself owes: the **sequenced** CLOSED lifecycle
    /// event (id allocated at send), plus the **terminal
    /// `DrainResult`** when this close completes the active drain —
    /// the completion transition reaches the issuer proactively with
    /// the initiating request id, never via a command replay.
    pub fn session_closed(
        &mut self,
        connection_id: u64,
        forced: bool,
        error_source: ErrorSource,
    ) -> Vec<ControlEnvelope> {
        let identity = self.gate.connection_identity(connection_id);
        let generation = self.gate.connection_generation(connection_id).unwrap_or(0);
        let backend_id = self
            .gate
            .connection_backend(connection_id)
            .unwrap_or_default();
        let drain_terminal = self.gate.record_drain_close(connection_id, forced);
        self.gate.unregister_connection(connection_id);
        self.sessions.remove(&connection_id);
        self.force_notified.remove(&connection_id);

        let mut outbound = Vec::new();
        if let Some(identity) = identity {
            outbound.push(closed_event_envelope(
                identity,
                &backend_id,
                generation,
                error_source,
            ));
        }
        if let Some(terminal) = drain_terminal {
            let initiating = self
                .initiating_drain
                .get(&terminal.drain_id)
                .copied()
                .unwrap_or(NEEDS_ALLOCATION);
            outbound.push(result_envelope(
                OutboundControl::DrainResult(terminal),
                0,
                initiating,
            ));
        }
        outbound
    }

    /// Dispatches one inbound control envelope on the production path.
    /// Inline answers reuse the inbound request id; drain deadlines are
    /// validated and converted from the wire's absolute unix-millis
    /// against the supplied clock pair.
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
                self.dispatch_redirect(request_id, generation, &command)
            }
            Some(Body::CloseCommand(command)) => {
                let command = command.clone();
                self.dispatch_close(request_id, generation, &command)
            }
            Some(Body::DrainCommand(command)) => {
                let command = command.clone();
                self.dispatch_drain(request_id, generation, &command, now, now_unix_millis)
            }
            Some(Body::ReconcileSnapshot(snapshot)) => {
                let snapshot = snapshot.clone();
                self.dispatch_reconcile_snapshot(&snapshot)
            }
            Some(
                Body::RouteAssignment(_) | Body::HandshakeDecision(_) | Body::HandshakeResult(_),
            ) => self.dispatch_session_response(request_id, envelope),
            // The transport owns these bodies; reaching here is a legal
            // no-op, not a violation.
            Some(Body::Heartbeat(_) | Body::Error(_) | Body::Hello(_) | Body::HelloAck(_)) => {
                Vec::new()
            }
            // Every remaining body is Rust-originated or unroutable on
            // this side: tell the peer instead of silently dropping.
            Some(_) | None => {
                self.unrouted = self.unrouted.saturating_add(1);
                vec![result_envelope(
                    OutboundControl::ProtocolError {
                        code: ErrorCode::ProtocolViolation,
                        request_id,
                        detail: "body is not routable on the Rust control plane",
                    },
                    generation,
                    request_id,
                )]
            }
        }
    }

    fn dispatch_session_response(
        &mut self,
        request_id: u64,
        envelope: &ControlEnvelope,
    ) -> Vec<ControlEnvelope> {
        let connection_id = match &envelope.body {
            Some(Body::RouteAssignment(assignment)) => assignment.connection_id,
            Some(Body::HandshakeDecision(decision)) => decision.connection_id,
            Some(Body::HandshakeResult(result)) => result.connection_id,
            _ => 0,
        };
        let Some(entry) = self.sessions.get(&connection_id) else {
            // The session is gone: close accounting owns the epilogue,
            // and the peer learns through RECONCILIATION_REQUIRED.
            return vec![result_envelope(
                OutboundControl::ProtocolError {
                    code: ErrorCode::ReconciliationRequired,
                    request_id,
                    detail: "session response for an unknown connection",
                },
                envelope.generation,
                request_id,
            )];
        };
        let Some(responses) = &entry.responses else {
            self.unrouted = self.unrouted.saturating_add(1);
            return vec![result_envelope(
                OutboundControl::ProtocolError {
                    code: ErrorCode::ProtocolViolation,
                    request_id,
                    detail: "session did not register a response channel",
                },
                envelope.generation,
                request_id,
            )];
        };
        // The per-session slot bounds the adapter to one outstanding
        // answer; overflow is a protocol violation the peer must hear
        // about, not a silent drop. A closed channel means the session
        // ended between routing and delivery — its CLOSED event
        // already reconciles both sides.
        if let Err(mpsc::error::TrySendError::Full(_)) = responses.try_send(envelope.clone()) {
            return vec![result_envelope(
                OutboundControl::ProtocolError {
                    code: ErrorCode::ProtocolViolation,
                    request_id,
                    detail: "session response slot overflow",
                },
                envelope.generation,
                request_id,
            )];
        }
        Vec::new()
    }

    fn dispatch_redirect(
        &mut self,
        request_id: u64,
        generation: u64,
        command: &RedirectCommand,
    ) -> Vec<ControlEnvelope> {
        match self.gate.admit_redirect(command, generation) {
            RedirectAdmission::Start => {
                self.initiating_redirect.insert(
                    (command.connection_id, command.redirect_id.clone()),
                    request_id,
                );
                match self.forward(command.connection_id, SessionControl::Redirect) {
                    ForwardOutcome::Sent => Vec::new(),
                    // The session vanished (or its channel is jammed)
                    // between registration and dispatch: retire the
                    // admission with a failed terminal so the id never
                    // dangles.
                    ForwardOutcome::Full | ForwardOutcome::Gone => self
                        .redirect_completed(
                            command.connection_id,
                            &command.redirect_id,
                            false,
                            "",
                            ErrorCode::RedirectFailed,
                        )
                        .into_iter()
                        .collect(),
                }
            }
            RedirectAdmission::DuplicatePending => Vec::new(),
            RedirectAdmission::Replay(result) => vec![result_envelope(
                OutboundControl::RedirectResult(result),
                generation,
                request_id,
            )],
            RedirectAdmission::Obsolete { .. } => vec![result_envelope(
                OutboundControl::RedirectResult(RedirectResult {
                    connection_id: command.connection_id,
                    redirect_id: command.redirect_id.clone(),
                    previous_backend_id: String::new(),
                    backend_id: String::new(),
                    succeeded: false,
                    code: ErrorCode::DuplicateRequest.into(),
                    detail: String::new(),
                }),
                generation,
                request_id,
            )],
            RedirectAdmission::Conflict { .. } | RedirectAdmission::SequenceMismatch { .. } => {
                vec![result_envelope(
                    OutboundControl::ProtocolError {
                        code: ErrorCode::ProtocolViolation,
                        request_id,
                        detail: "redirect id/sequence violates the serialization contract",
                    },
                    generation,
                    request_id,
                )]
            }
            RedirectAdmission::StaleGeneration { .. } => vec![result_envelope(
                OutboundControl::ProtocolError {
                    code: ErrorCode::StaleGeneration,
                    request_id,
                    detail: "redirect was minted for a different connection incarnation",
                },
                generation,
                request_id,
            )],
            RedirectAdmission::UnknownConnection => vec![result_envelope(
                OutboundControl::ProtocolError {
                    code: ErrorCode::ReconciliationRequired,
                    request_id,
                    detail: "redirect for an unknown connection",
                },
                generation,
                request_id,
            )],
        }
    }

    fn dispatch_close(
        &mut self,
        request_id: u64,
        generation: u64,
        command: &CloseCommand,
    ) -> Vec<ControlEnvelope> {
        match self.gate.admit_close(
            command.connection_id,
            &command.close_id,
            command.force,
            generation,
        ) {
            CloseAdmission::Start { force } => {
                self.initiating_close.insert(
                    (command.connection_id, command.close_id.clone()),
                    request_id,
                );
                let control = if force {
                    SessionControl::CloseImmediate
                } else {
                    SessionControl::GracefulClose
                };
                match self.forward(command.connection_id, control) {
                    ForwardOutcome::Sent => Vec::new(),
                    // Retire the accepted close with its terminal
                    // immediately so the gate never sticks in Closing.
                    ForwardOutcome::Full | ForwardOutcome::Gone => self
                        .close_completed(command.connection_id, &command.close_id)
                        .into_iter()
                        .collect(),
                }
            }
            CloseAdmission::Replay(result) | CloseAdmission::AlreadyClosing(result) => {
                vec![result_envelope(
                    OutboundControl::CloseResult(result),
                    generation,
                    request_id,
                )]
            }
            CloseAdmission::StaleGeneration { .. } => vec![result_envelope(
                OutboundControl::ProtocolError {
                    code: ErrorCode::StaleGeneration,
                    request_id,
                    detail: "close was minted for a different connection incarnation",
                },
                generation,
                request_id,
            )],
            CloseAdmission::UnknownConnection => vec![result_envelope(
                OutboundControl::ProtocolError {
                    code: ErrorCode::ReconciliationRequired,
                    request_id,
                    detail: "close for an unknown connection",
                },
                generation,
                request_id,
            )],
        }
    }

    #[allow(clippy::too_many_lines)]
    fn dispatch_drain(
        &mut self,
        request_id: u64,
        generation: u64,
        command: &DrainCommand,
        now: Instant,
        now_unix_millis: u64,
    ) -> Vec<ControlEnvelope> {
        // Validate the wire's absolute deadlines before converting: a
        // force deadline before the graceful one, or a deadline
        // unreasonably far ahead, is a malformed command — checked
        // math, no `Instant` overflow on hostile values.
        let graceful_ahead = command
            .graceful_deadline_unix_millis
            .saturating_sub(now_unix_millis);
        let force_ahead = command
            .force_deadline_unix_millis
            .saturating_sub(now_unix_millis);
        if graceful_ahead > MAX_DRAIN_DEADLINE_AHEAD_MILLIS
            || force_ahead > MAX_DRAIN_DEADLINE_AHEAD_MILLIS
            || (command.force_deadline_unix_millis != 0
                && command.force_deadline_unix_millis < command.graceful_deadline_unix_millis)
        {
            return vec![result_envelope(
                OutboundControl::ProtocolError {
                    code: ErrorCode::ProtocolViolation,
                    request_id,
                    detail: "drain deadlines are malformed",
                },
                generation,
                request_id,
            )];
        }
        let graceful_deadline = now + Duration::from_millis(graceful_ahead);
        let force_deadline = now + Duration::from_millis(force_ahead);

        let matched: BTreeSet<u64> = self
            .sessions
            .iter()
            .filter(|(_, entry)| {
                command.listener_names.is_empty()
                    || command.listener_names.contains(&entry.listener_name)
            })
            .map(|(id, _)| *id)
            .filter(|id| {
                command.backend_ids.is_empty()
                    || self
                        .gate
                        .connection_backend(*id)
                        .is_some_and(|backend| command.backend_ids.contains(&backend))
            })
            .collect();
        match self.gate.admit_drain(
            command,
            generation,
            graceful_deadline,
            force_deadline,
            matched.clone(),
        ) {
            DrainAdmission::Start => {
                self.initiating_drain
                    .insert(command.drain_id.clone(), request_id);
                self.force_notified.clear();
                let mut outbound = Vec::new();
                if command.force_deadline_unix_millis != 0
                    && now_unix_millis >= command.force_deadline_unix_millis
                {
                    // Already past the force deadline: never ask a
                    // graceful close first.
                    outbound.extend(self.force_close_remaining());
                } else {
                    for id in &matched {
                        let _ = self.forward(*id, SessionControl::GracefulClose);
                    }
                }
                // A zero-match admission completes on arrival: its very
                // first answer is already the terminal result.
                let answer = self
                    .gate
                    .drain_progress()
                    .or_else(|| self.gate.completed_drain_result(&command.drain_id));
                outbound.extend(answer.map(|result| {
                    result_envelope(OutboundControl::DrainResult(result), generation, request_id)
                }));
                outbound
            }
            DrainAdmission::Progress(result)
            | DrainAdmission::Replay(result)
            | DrainAdmission::Conflict(result) => vec![result_envelope(
                OutboundControl::DrainResult(result),
                generation,
                request_id,
            )],
            DrainAdmission::Obsolete { .. } => vec![result_envelope(
                OutboundControl::DrainResult(DrainResult {
                    drain_id: command.drain_id.clone(),
                    active_connections: 0,
                    gracefully_closed: 0,
                    force_closed: 0,
                    complete: true,
                    code: ErrorCode::DuplicateRequest.into(),
                    detail: String::new(),
                }),
                generation,
                request_id,
            )],
            DrainAdmission::StaleGeneration { .. } => vec![result_envelope(
                OutboundControl::ProtocolError {
                    code: ErrorCode::StaleGeneration,
                    request_id,
                    detail: "drain provenance predates the applied snapshot",
                },
                generation,
                request_id,
            )],
            DrainAdmission::SequenceMismatch { .. } => vec![result_envelope(
                OutboundControl::ProtocolError {
                    code: ErrorCode::ProtocolViolation,
                    request_id,
                    detail: "drain id/sequence violates the one-issuance binding",
                },
                generation,
                request_id,
            )],
        }
    }

    /// Sends `CloseImmediate` to every remaining matched session under
    /// the active drain, marking delivery **only on a successful
    /// send**: `Full` leaves the session unmarked for the next tick,
    /// `Gone` converges the dead session through the close path (which
    /// also produces the terminal result on the completion transition).
    fn force_close_remaining(&mut self) -> Vec<ControlEnvelope> {
        let mut outbound = Vec::new();
        for id in self.gate.drain_remaining() {
            if self.force_notified.contains(&id) {
                continue;
            }
            match self.forward(id, SessionControl::CloseImmediate) {
                ForwardOutcome::Sent => {
                    self.force_notified.insert(id);
                }
                ForwardOutcome::Full => {
                    // Real backpressure: retry on the next tick.
                }
                ForwardOutcome::Gone => {
                    outbound.extend(self.session_closed(id, true, ErrorSource::Proxy));
                }
            }
        }
        outbound
    }

    /// Drives the active drain: every tick at (or past) the force
    /// deadline force-closes the remaining sessions per
    /// [`Self::force_close_remaining`]'s delivery rules. Progress is
    /// answered on duplicate commands and the terminal is produced on
    /// the completion transition — the tick emits envelopes only for
    /// dead-session convergence.
    pub fn tick(&mut self, now: Instant) -> Vec<ControlEnvelope> {
        if self.gate.drain_phase(now) == Some(DrainPhase::Force) {
            return self.force_close_remaining();
        }
        Vec::new()
    }

    /// A session's redirect finished: produces the terminal result
    /// exactly once (late/duplicate completions are suppressed by the
    /// gate), carrying the initiating request id.
    pub fn redirect_completed(
        &mut self,
        connection_id: u64,
        redirect_id: &str,
        succeeded: bool,
        new_backend_id: &str,
        code: ErrorCode,
    ) -> Option<ControlEnvelope> {
        let result = self.gate.complete_redirect(
            connection_id,
            redirect_id,
            succeeded,
            new_backend_id,
            code,
        )?;
        let generation = self.gate.connection_generation(connection_id).unwrap_or(0);
        let initiating = self
            .initiating_redirect
            .remove(&(connection_id, redirect_id.to_owned()))
            .unwrap_or(NEEDS_ALLOCATION);
        Some(result_envelope(
            OutboundControl::RedirectResult(result),
            generation,
            initiating,
        ))
    }

    /// A session's accepted close finished: produces the terminal
    /// result exactly once, carrying the initiating request id.
    pub fn close_completed(
        &mut self,
        connection_id: u64,
        close_id: &str,
    ) -> Option<ControlEnvelope> {
        let result = self.gate.complete_close(connection_id, close_id)?;
        let generation = self.gate.connection_generation(connection_id).unwrap_or(0);
        let initiating = self
            .initiating_close
            .remove(&(connection_id, close_id.to_owned()))
            .unwrap_or(NEEDS_ALLOCATION);
        Some(result_envelope(
            OutboundControl::CloseResult(result),
            generation,
            initiating,
        ))
    }

    /// Builds the reconcile request from the gate's authoritative state
    /// plus the metering watermark.
    #[must_use]
    pub fn build_reconcile_request(&self, known_generation: u64) -> ReconcileRequest {
        self.gate
            .build_reconcile_request(known_generation, 0, self.metering.last_sequence())
    }

    fn dispatch_reconcile_snapshot(
        &mut self,
        snapshot: &ReconcileSnapshot,
    ) -> Vec<ControlEnvelope> {
        self.metering.acked_through(snapshot.metering_sequence);
        let repairs = self.gate.apply_reconcile_snapshot(snapshot);
        let mut outbound: Vec<ControlEnvelope> = repairs
            .replay_redirect_results
            .into_iter()
            .map(|result| {
                let initiating = self
                    .initiating_redirect
                    .remove(&(result.connection_id, result.redirect_id.clone()))
                    .unwrap_or(NEEDS_ALLOCATION);
                let mut envelope = result_envelope(
                    OutboundControl::RedirectResult(result),
                    snapshot.applied_generation,
                    initiating,
                );
                envelope.required_capabilities =
                    vec![ControlCapability::ReconcileSessionRehydration as u64];
                envelope
            })
            .collect();
        // Ghosts are answered with sequenced terminal CLOSED events
        // built from the peer's own identity view, so both sides
        // converge without a separate composition step. Rehydration was
        // negotiated (the gate only reports ghosts then), so the events
        // declare the capability they rely on.
        for remote in &snapshot.connections {
            if repairs.ghost_connections.contains(&remote.connection_id)
                && let Some(identity) = remote.identity.clone()
            {
                let mut event = closed_event_envelope(
                    identity,
                    &remote.backend_id,
                    remote.generation,
                    ErrorSource::Proxy,
                );
                event.required_capabilities =
                    vec![ControlCapability::ReconcileSessionRehydration as u64];
                outbound.push(event);
            }
        }
        outbound
    }

    /// Metering batches the reconnect path must (re)send: everything
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

    fn forward(&mut self, connection_id: u64, control: SessionControl) -> ForwardOutcome {
        match self.sessions.get(&connection_id) {
            Some(entry) => match entry.control.try_send(control) {
                Ok(()) => ForwardOutcome::Sent,
                Err(mpsc::error::TrySendError::Full(_)) => ForwardOutcome::Full,
                Err(mpsc::error::TrySendError::Closed(_)) => ForwardOutcome::Gone,
            },
            None => ForwardOutcome::Gone,
        }
    }
}

/// Wraps one outbound answer as a complete control envelope. The
/// request id is the **initiating** command's id when known;
/// [`NEEDS_ALLOCATION`] defers to the dispatch loop's allocator.
/// `CloseResult` declares `PER_CONNECTION_CLOSE`, the capability its
/// semantics rely on.
fn result_envelope(outbound: OutboundControl, generation: u64, request_id: u64) -> ControlEnvelope {
    let (body, required_capabilities) = match outbound {
        OutboundControl::RedirectResult(result) => (Body::RedirectResult(result), Vec::new()),
        OutboundControl::CloseResult(result) => (
            Body::CloseResult(result),
            vec![ControlCapability::PerConnectionClose as u64],
        ),
        OutboundControl::DrainResult(result) => (Body::DrainResult(result), Vec::new()),
        OutboundControl::ProtocolError {
            code,
            request_id: offending,
            detail,
        } => (
            Body::Error(ProtocolError {
                code: code.into(),
                offending_request_id: offending,
                retryable: false,
                detail: detail.to_owned(),
            }),
            Vec::new(),
        ),
    };
    ControlEnvelope {
        protocol_version: 0,
        control_epoch: 0,
        generation,
        request_id,
        priority: Priority::Critical.into(),
        sent_unix_millis: 0,
        required_capabilities,
        body: Some(body),
    }
}

fn closed_event_envelope(
    identity: ConnectionIdentity,
    backend_id: &str,
    generation: u64,
    error_source: ErrorSource,
) -> ControlEnvelope {
    ControlEnvelope {
        protocol_version: 0,
        control_epoch: 0,
        generation,
        // Allocated by the dispatch loop from the sender's single
        // checked allocator; the id doubles as the event sequence Go's
        // per-epoch dedup and the reconcile watermark both key on.
        request_id: NEEDS_ALLOCATION,
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

/// Session-side notifications into the dispatch task.
#[derive(Debug)]
pub enum DispatchNotice {
    /// A config snapshot generation was applied (CTL-05).
    AppliedGeneration(u64),
    /// An admitted session registers its channels.
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
        /// Correlated Go answers (route assignments, handshake
        /// decisions/results) for this session, when it routes.
        responses: Option<mpsc::Sender<ControlEnvelope>>,
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

/// The transport receive half: forwards every post-Hello envelope into
/// the bounded dispatch queue with a **real await** — the read loop
/// stalls while the dispatcher is behind, propagating backpressure
/// through TCP to the Go sender's bounded lanes instead of dropping a
/// command the peer already considers delivered. A closed queue (the
/// dispatch task died) errors the stream and triggers reconnect.
pub struct InboundForwarder {
    inbound: mpsc::Sender<ControlEnvelope>,
}

impl Handler for InboundForwarder {
    async fn handle(&self, envelope: ControlEnvelope) -> Result<(), TransportError> {
        self.inbound
            .send(envelope)
            .await
            .map_err(|_| TransportError::Configuration("control dispatch task is gone".to_owned()))
    }
}

/// Wall-clock source for wire-deadline conversion (injected so tests
/// pin it; production passes [`system_unix_millis`]).
pub type UnixMillisFn = fn() -> u64;

/// Production wall clock for [`run_control_dispatch`].
#[must_use]
pub fn system_unix_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// The abstract sender the dispatch loop needs from the transport:
/// checked request-id allocation plus the send itself. Implemented by
/// the production [`ControlClient`]; tests substitute a fake.
pub trait DispatchSender: Send + Sync {
    /// Allocates the next request id (fail-closed at exhaustion).
    fn allocate_request_id(&self) -> Option<u64>;
    /// Sends one envelope on the control stream.
    fn send_envelope(
        &self,
        envelope: ControlEnvelope,
    ) -> impl Future<Output = Result<(), TransportError>> + Send;
}

impl DispatchSender for ControlClient {
    fn allocate_request_id(&self) -> Option<u64> {
        ControlClient::allocate_request_id(self)
    }

    async fn send_envelope(&self, envelope: ControlEnvelope) -> Result<(), TransportError> {
        self.send(envelope).await
    }
}

/// Stamps self-originated envelopes with allocator ids (recording
/// connection-event ids as the event sequence) and sends. Free-standing
/// so both selves of the loop borrow-split cleanly.
async fn dispatch_send<S: DispatchSender>(
    sender: &Arc<S>,
    handler: &mut ControlCommandHandler,
    mut envelope: ControlEnvelope,
) {
    if envelope.request_id == NEEDS_ALLOCATION {
        let Some(id) = sender.allocate_request_id() else {
            // Id space exhausted: fail closed rather than reuse.
            return;
        };
        envelope.request_id = id;
        if matches!(envelope.body, Some(Body::ConnectionEvent(_))) {
            handler.record_event_sequence(id);
        }
    }
    let _ = sender.send_envelope(envelope).await;
}

/// Runs the production dispatch loop: connection-state transitions
/// (peer-mode update + automatic reconcile + metering replay, bound to
/// one atomic epoch/capabilities snapshot), inbound envelopes (snapshot
/// bodies forwarded — awaited — to the CTL-05 owner), session notices,
/// and the periodic drain tick. This is the long-lived single owner of
/// [`ControlCommandHandler`]; it survives control reconnects.
#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
pub async fn run_control_dispatch<S: DispatchSender>(
    mut handler: ControlCommandHandler,
    sender: Arc<S>,
    mut state: watch::Receiver<ConnectionState>,
    mut inbound: mpsc::Receiver<ControlEnvelope>,
    mut notices: mpsc::Receiver<DispatchNotice>,
    snapshot_tx: Option<mpsc::Sender<ControlEnvelope>>,
    tick_interval: Duration,
    unix_now_millis: UnixMillisFn,
) {
    let mut ticker = tokio::time::interval(tick_interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            biased;
            changed = state.changed() => {
                if changed.is_err() {
                    break;
                }
                let snapshot = *state.borrow_and_update();
                if let ConnectionState::Connected { capabilities, .. } = snapshot {
                    // One atomic snapshot binds the epoch to the
                    // negotiated capabilities, so the peer-mode update,
                    // the reconcile request, and the metering replay
                    // below all act for exactly this session.
                    let rehydration = (capabilities
                        >> (ControlCapability::ReconcileSessionRehydration as u64))
                        & 1
                        == 1;
                    handler.on_session_negotiated(rehydration);
                    let request =
                        handler.build_reconcile_request(handler.applied_generation());
                    let envelope = ControlEnvelope {
                        request_id: NEEDS_ALLOCATION,
                        generation: request.known_generation,
                        priority: Priority::Critical.into(),
                        body: Some(Body::ReconcileRequest(request)),
                        ..ControlEnvelope::default()
                    };
                    dispatch_send(&sender, &mut handler, envelope).await;
                    for batch in handler.metering_replay() {
                        let envelope = ControlEnvelope {
                            request_id: NEEDS_ALLOCATION,
                            priority: Priority::Bulk.into(),
                            body: Some(Body::MeteringBatch(batch)),
                            ..ControlEnvelope::default()
                        };
                        dispatch_send(&sender, &mut handler, envelope).await;
                    }
                }
            }
            notice = notices.recv() => {
                let Some(notice) = notice else { break };
                match notice {
                    DispatchNotice::AppliedGeneration(generation) => {
                        handler.set_applied_generation(generation);
                    }
                    DispatchNotice::RegisterSession {
                        identity,
                        namespace,
                        snapshot_generation,
                        listener_name,
                        control,
                        responses,
                    } => {
                        handler.register_session(
                            identity,
                            &namespace,
                            snapshot_generation,
                            &listener_name,
                            control,
                            responses,
                        );
                    }
                    DispatchNotice::SetBackend { connection_id, backend_id } => {
                        handler.set_backend(connection_id, &backend_id);
                    }
                    DispatchNotice::SessionClosed { connection_id, forced, error_source } => {
                        for envelope in
                            handler.session_closed(connection_id, forced, error_source)
                        {
                            dispatch_send(&sender, &mut handler, envelope).await;
                        }
                    }
                    DispatchNotice::RedirectFinished {
                        connection_id,
                        redirect_id,
                        succeeded,
                        backend_id,
                        code,
                    } => {
                        if let Some(envelope) = handler.redirect_completed(
                            connection_id,
                            &redirect_id,
                            succeeded,
                            &backend_id,
                            code,
                        ) {
                            dispatch_send(&sender, &mut handler, envelope).await;
                        }
                    }
                    DispatchNotice::CloseFinished { connection_id, close_id } => {
                        if let Some(envelope) =
                            handler.close_completed(connection_id, &close_id)
                        {
                            dispatch_send(&sender, &mut handler, envelope).await;
                        }
                    }
                }
            }
            envelope = inbound.recv() => {
                let Some(envelope) = envelope else { break };
                if let Some(Body::StateSnapshot(_) | Body::SnapshotResult(_)) = &envelope.body {
                    // The CTL-05 snapshot owner consumes these; the
                    // send is awaited so its backpressure reaches the
                    // transport read loop too.
                    if let Some(snapshots) = &snapshot_tx {
                        let _ = snapshots.send(envelope).await;
                    }
                } else {
                    let outbound = handler.handle_envelope(
                        &envelope,
                        Instant::now(),
                        unix_now_millis(),
                    );
                    for out in outbound {
                        dispatch_send(&sender, &mut handler, out).await;
                    }
                }
            }
            _ = ticker.tick() => {
                for envelope in handler.tick(Instant::now()) {
                    dispatch_send(&sender, &mut handler, envelope).await;
                }
            }
        }
    }
}

/// Capacity of the bounded inbound dispatch queue: overflow stalls the
/// transport read loop (real backpressure), never drops.
const INBOUND_QUEUE_CAPACITY: usize = 256;

/// Spawns the production control-dispatch task bound to the shared
/// control client: the returned [`InboundForwarder`] is the transport
/// handler for [`ControlClient::run`], the [`ControlDispatchHandle`] is
/// the session-facing surface, and snapshot bodies forward to
/// `snapshot_tx` when the CTL-05 owner provides one.
#[must_use]
pub fn spawn_control_dispatch(
    client: Arc<ControlClient>,
    snapshot_tx: Option<mpsc::Sender<ControlEnvelope>>,
    tick_interval: Duration,
) -> (
    ControlDispatchHandle,
    InboundForwarder,
    tokio::task::JoinHandle<()>,
) {
    let (inbound_tx, inbound_rx) = mpsc::channel(INBOUND_QUEUE_CAPACITY);
    let (notice_tx, notice_rx) = mpsc::channel(INBOUND_QUEUE_CAPACITY);
    let state = client.subscribe_state();
    let task = tokio::spawn(run_control_dispatch(
        ControlCommandHandler::new(),
        client,
        state,
        inbound_rx,
        notice_rx,
        snapshot_tx,
        tick_interval,
        system_unix_millis,
    ));
    (
        ControlDispatchHandle { notices: notice_tx },
        InboundForwarder {
            inbound: inbound_tx,
        },
        task,
    )
}
