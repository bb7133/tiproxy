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
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
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
use crate::route_control::TrafficTotals;
use crate::session::SessionControl;

/// Observable dispatch counters, shared between the loop's handler and
/// the runtime (metrics/diagnostics export). Every "counted, never
/// silent" path in the dispatcher lands here.
#[derive(Debug, Default)]
pub struct DispatchStats {
    /// Inbound bodies with no legal route (each also answered).
    pub unrouted: AtomicU64,
    /// Stale-epoch inbound bodies discarded by policy.
    pub stale_dropped: AtomicU64,
    /// Terminal outbound send failures (converge via reconcile).
    pub send_failures: AtomicU64,
    /// Fail-closed metering rejections (record and seal).
    pub metering_failures: AtomicU64,
}

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

/// The dispatcher's verdict on arming a response expectation: only a
/// live session WITH a response channel can be armed — acknowledging
/// anything else would tell the caller to send a request whose answer
/// could never be delivered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpectArmVerdict {
    /// The expectation is armed; the caller may send its request.
    Armed,
    /// No session is registered under this connection id.
    UnknownConnection,
    /// The session registered without a response channel.
    NoResponseChannel,
}

/// The body kind a session's outstanding request expects back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseKind {
    /// A `RouteRequest` awaits `RouteAssignment` pushes.
    RouteAssignment,
    /// A `HandshakeResponseEvent` awaits the `HandshakeDecision`.
    HandshakeDecision,
}

/// The exact gate-admitted command identity a control directive
/// carries. The token enters the session channel **together with** the
/// command — before the session can observe it — so the terminal the
/// session later reports is bound to precisely the effect it executed:
/// there is no shared slot to write after the send and no state to
/// infer from, and an instantly completing session cannot outrun the
/// binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandToken {
    /// Which command family admitted this id.
    pub kind: CommandKind,
    /// The gate-admitted exact id (redirect id or close id).
    pub id: Arc<str>,
}

/// The command family a [`CommandToken`] belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandKind {
    /// A per-session redirect (`redirect_id`).
    Redirect,
    /// A per-session close (`close_id`).
    Close,
}

/// One unit on a session's control channel: the control signal plus —
/// for gate-admitted per-session commands — the token whose id the
/// completion notice must return. Drain-driven closes carry no token:
/// their terminal is the drain's own `DrainResult`, produced through
/// the close accounting path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionDirective {
    /// The control signal for the session loop.
    pub control: SessionControl,
    /// The admitted command identity, when one exists.
    pub command: Option<CommandToken>,
}

impl SessionDirective {
    /// A drain- or shutdown-driven directive with no per-command id.
    #[must_use]
    pub const fn bare(control: SessionControl) -> Self {
        Self {
            control,
            command: None,
        }
    }
}

/// One registered live session: its control channel, its correlated
/// Go-response channel, the currently armed response expectation, and
/// the drain-scoping metadata.
struct SessionEntry {
    control: mpsc::Sender<SessionDirective>,
    responses: Option<mpsc::Sender<ControlEnvelope>>,
    /// Fail-closed correlation: only a response matching the armed
    /// `(initiating request id, body kind)` is delivered; everything
    /// else — unsolicited, wrong id, wrong kind — is answered as a
    /// protocol violation so a stale answer can neither occupy the
    /// one-slot channel nor be mis-consumed by a newer exchange.
    expected: Option<(u64, ResponseKind)>,
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
    /// The active control session's atomic `(epoch, capability mask)`
    /// snapshot — `None` whenever the last observed transport state is
    /// not `Connected` (watch coalescing can collapse
    /// `Connected(N) → Disconnected` into one observation, so absence
    /// must be modeled, not just an old epoch left behind). Inbound
    /// envelopes carry their origin epoch on the wire, so staleness is
    /// decidable per frame against this.
    active_session: Option<(u64, u64)>,
    /// Whether the current session negotiated `RECONCILE_CONNECTIONS`:
    /// gates both sending reconcile requests and accepting snapshots.
    reconcile_capable: bool,
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
    /// Shared observable counters (see [`DispatchStats`]).
    stats: Arc<DispatchStats>,
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
            active_session: None,
            reconcile_capable: true,
            metering: MeteringLedger::new(),
            sessions: HashMap::new(),
            force_notified: BTreeSet::new(),
            initiating_redirect: HashMap::new(),
            initiating_close: HashMap::new(),
            initiating_drain: HashMap::new(),
            stats: Arc::new(DispatchStats::default()),
        }
    }

    /// Applies a new control session's negotiation: peer mode follows
    /// the `RECONCILE_SESSION_REHYDRATION` capability. The gate is
    /// deliberately **not** rebuilt. (`RECONCILE_CONNECTIONS` is
    /// assumed here; production uses [`Self::on_connected`], which
    /// derives both from the negotiated mask.)
    pub fn on_session_negotiated(&mut self, rehydration_capability: bool) {
        self.gate.set_legacy_peer(!rehydration_capability);
    }

    /// Applies a new session's **atomic** epoch + capability snapshot:
    /// records the active session inbound staleness is judged against
    /// and derives the peer mode and reconcile availability from the
    /// mask. Rehydration is enabled only under the full capability
    /// closure `RECONCILE_CONNECTIONS && RECONCILE_SESSION_REHYDRATION`
    /// (the handshake already rejects the illegal cap-3-only
    /// combination; this is the defensive derivation).
    pub fn on_connected(&mut self, epoch: u64, capabilities: u64) {
        self.active_session = Some((epoch, capabilities));
        let reconcile = (capabilities >> (ControlCapability::ReconcileConnections as u64)) & 1 == 1;
        let rehydration = reconcile
            && (capabilities >> (ControlCapability::ReconcileSessionRehydration as u64)) & 1 == 1;
        self.reconcile_capable = reconcile;
        self.gate.set_legacy_peer(!rehydration);
    }

    /// The transport left `Connected`: there is no active session, so
    /// nothing inbound can match "the current epoch" until the next
    /// `Connected` — watch coalescing can hide the intermediate
    /// `Connected`, and modeling absence (rather than keeping the old
    /// epoch) is what keeps a dead session's snapshot from being
    /// accepted as current.
    pub fn on_disconnected(&mut self) {
        self.active_session = None;
    }

    /// Whether the current session can reconcile (`RECONCILE_CONNECTIONS`).
    #[must_use]
    pub const fn reconcile_capable(&self) -> bool {
        self.reconcile_capable
    }

    /// The active session's negotiated epoch, if connected.
    #[must_use]
    pub fn active_epoch(&self) -> Option<u64> {
        self.active_session.map(|(epoch, _)| epoch)
    }

    /// The active session's negotiated `(epoch, capabilities)`, if
    /// connected (the stale-export repair path re-derives its
    /// capability gating from this).
    #[must_use]
    pub const fn active_session(&self) -> Option<(u64, u64)> {
        self.active_session
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
        control: mpsc::Sender<SessionDirective>,
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
                expected: None,
                listener_name: listener_name.to_owned(),
            },
        );
    }

    /// Records the session's current backend (route/redirect success).
    /// Returns true when the record was already exported in a reconcile
    /// request (the caller owes a stale-export repair).
    #[must_use]
    pub fn set_backend(&mut self, connection_id: u64, backend_id: &str) -> bool {
        self.gate.set_backend(connection_id, backend_id)
    }

    /// Adopts the decision-resolved namespace for lifecycle events and
    /// reconciliation. Returns true when the record was already exported
    /// in a reconcile request (the caller owes a stale-export repair).
    #[must_use]
    pub fn set_namespace(&mut self, connection_id: u64, namespace: &str) -> bool {
        self.gate.set_namespace(connection_id, namespace)
    }

    /// Arms the session's response expectation: the initiating request
    /// id it just sent and the body kind it awaits. Re-arming replaces
    /// the previous expectation (one outstanding exchange per session).
    /// The expectation stays armed after a match — Go may push an
    /// updated `RouteAssignment` under the same initiating id — until
    /// the next arm or the session closes.
    pub fn expect_response(
        &mut self,
        connection_id: u64,
        request_id: u64,
        kind: ResponseKind,
    ) -> ExpectArmVerdict {
        match self.sessions.get_mut(&connection_id) {
            Some(entry) if entry.responses.is_some() => {
                entry.expected = Some((request_id, kind));
                ExpectArmVerdict::Armed
            }
            Some(_) => ExpectArmVerdict::NoResponseChannel,
            None => ExpectArmVerdict::UnknownConnection,
        }
    }

    /// The shared observable counters.
    #[must_use]
    pub fn stats(&self) -> Arc<DispatchStats> {
        Arc::clone(&self.stats)
    }

    /// Inbound bodies that had no legal route so far.
    #[must_use]
    pub fn unrouted(&self) -> u64 {
        self.stats.unrouted.load(Ordering::Relaxed)
    }

    /// Stale-epoch inbound bodies discarded by policy so far.
    #[must_use]
    pub fn stale_dropped(&self) -> u64 {
        self.stats.stale_dropped.load(Ordering::Relaxed)
    }

    fn count_unrouted(&self) {
        self.stats.unrouted.fetch_add(1, Ordering::Relaxed);
    }

    /// Records one stale-epoch discard.
    pub fn count_stale_dropped(&self) {
        self.stats.stale_dropped.fetch_add(1, Ordering::Relaxed);
    }

    /// Records one terminal outbound send failure.
    pub fn count_send_failure(&self) {
        self.stats.send_failures.fetch_add(1, Ordering::Relaxed);
    }

    /// Records one metering delta into the ledger. The result is the
    /// **producer's**: an error means the delta was not absorbed and
    /// its ownership stays with the caller (fail-closed, counted).
    ///
    /// # Errors
    ///
    /// Propagates the ledger's fail-closed bounds.
    pub fn record_metering(
        &mut self,
        delta: control_proto::v1::MeteringDelta,
    ) -> Result<(), MeteringError> {
        let result = self.metering.record(delta);
        if result.is_err() {
            self.stats.metering_failures.fetch_add(1, Ordering::Relaxed);
        }
        result
    }

    /// Records one fail-closed seal rejection (for example: the
    /// unacked bound is reached because no reconcile ack path exists).
    pub fn count_metering_seal_failure(&self) {
        self.stats.metering_failures.fetch_add(1, Ordering::Relaxed);
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
        traffic: TrafficTotals,
    ) -> Vec<ControlEnvelope> {
        let identity = self.gate.connection_identity(connection_id);
        let generation = self.gate.connection_generation(connection_id).unwrap_or(0);
        let backend_id = self
            .gate
            .connection_backend(connection_id)
            .unwrap_or_default();
        let namespace = self
            .gate
            .connection_namespace(connection_id)
            .unwrap_or_default();
        let drain_terminal = self.gate.record_drain_close(connection_id, forced);
        self.gate.unregister_connection(connection_id);
        self.sessions.remove(&connection_id);
        self.force_notified.remove(&connection_id);
        // The session's pending initiating-id records die with it: any
        // later terminal for these ids is suppressed by the gate, so
        // the entries would otherwise leak forever.
        self.initiating_redirect
            .retain(|(id, _), _| *id != connection_id);
        self.initiating_close
            .retain(|(id, _), _| *id != connection_id);

        let mut outbound = Vec::new();
        if let Some(identity) = identity {
            outbound.push(closed_event_envelope(
                identity,
                &backend_id,
                &namespace,
                generation,
                error_source,
                traffic,
            ));
        }
        if let Some(terminal) = drain_terminal {
            // The terminal consumes the drain's initiating record: the
            // map holds at most the active drain's entry, never grows.
            let initiating = self
                .initiating_drain
                .remove(&terminal.drain_id)
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
                if !self.reconcile_capable {
                    // We never sent a ReconcileRequest this session: an
                    // unsolicited snapshot is a protocol violation.
                    self.count_unrouted();
                    return vec![result_envelope(
                        OutboundControl::ProtocolError {
                            code: ErrorCode::ProtocolViolation,
                            request_id,
                            detail: "reconcile snapshot without RECONCILE_CONNECTIONS",
                        },
                        generation,
                        request_id,
                    )];
                }
                if envelope.control_epoch != 0 {
                    // A snapshot is applied only while a session is
                    // actually active AND it originated in exactly that
                    // session. `None` (disconnected, or a coalesced
                    // Connected→Disconnected the loop never saw as
                    // Connected) and any epoch mismatch are superseded:
                    // the next session's automatic ReconcileRequest
                    // gets a fresh snapshot, and applying the stale
                    // view could regress acked metering / ghost state.
                    match self.active_session {
                        Some((epoch, _)) if epoch == envelope.control_epoch => {}
                        _ => {
                            self.count_stale_dropped();
                            return Vec::new();
                        }
                    }
                }
                let snapshot = snapshot.clone();
                self.dispatch_reconcile_snapshot(&snapshot)
            }
            // Correlated Go answers are delivered to their owning
            // session in EVERY epoch — the (connection_id, assignment /
            // decision) correlation makes late answers safe, and there
            // is no retry owner that would regenerate a dropped one.
            Some(Body::RouteAssignment(_) | Body::HandshakeDecision(_)) => {
                self.dispatch_session_response(request_id, envelope)
            }
            // The transport owns these bodies; reaching here is a legal
            // no-op, not a violation.
            Some(Body::Heartbeat(_) | Body::Error(_) | Body::Hello(_) | Body::HelloAck(_)) => {
                Vec::new()
            }
            // Every remaining body is unroutable here — including
            // Rust→Go-direction bodies arriving inbound
            // (`HandshakeResult`, `SnapshotResult`, `RouteResult`,
            // events, batches): tell the peer instead of silently
            // dropping.
            Some(_) | None => {
                self.count_unrouted();
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
        let (connection_id, kind) = match &envelope.body {
            Some(Body::RouteAssignment(assignment)) => {
                (assignment.connection_id, ResponseKind::RouteAssignment)
            }
            Some(Body::HandshakeDecision(decision)) => {
                (decision.connection_id, ResponseKind::HandshakeDecision)
            }
            _ => (0, ResponseKind::RouteAssignment),
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
            self.count_unrouted();
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
        // Fail-closed correlation: deliver only the armed
        // `(initiating id, kind)` pair. This is what makes late
        // answers from a previous epoch safe to keep delivering — a
        // stale or foreign answer is refused here instead of occupying
        // the slot or being mistaken for the current exchange's.
        match entry.expected {
            Some((expected_id, expected_kind))
                if expected_id == request_id && expected_kind == kind => {}
            Some(_) => {
                return vec![result_envelope(
                    OutboundControl::ProtocolError {
                        code: ErrorCode::ProtocolViolation,
                        request_id,
                        detail: "session response correlation mismatch",
                    },
                    envelope.generation,
                    request_id,
                )];
            }
            None => {
                return vec![result_envelope(
                    OutboundControl::ProtocolError {
                        code: ErrorCode::ProtocolViolation,
                        request_id,
                        detail: "unsolicited session response",
                    },
                    envelope.generation,
                    request_id,
                )];
            }
        }
        // The per-session slot bounds the adapter to one outstanding
        // answer; overflow is a protocol violation the peer must hear
        // about, not a silent drop. A closed channel means the session
        // ended between routing and delivery — answered like an
        // unknown connection so the peer reconciles instead of
        // mistaking silence for delivery.
        match responses.try_send(envelope.clone()) {
            Ok(()) => Vec::new(),
            Err(mpsc::error::TrySendError::Full(_)) => vec![result_envelope(
                OutboundControl::ProtocolError {
                    code: ErrorCode::ProtocolViolation,
                    request_id,
                    detail: "session response slot overflow",
                },
                envelope.generation,
                request_id,
            )],
            Err(mpsc::error::TrySendError::Closed(_)) => vec![result_envelope(
                OutboundControl::ProtocolError {
                    code: ErrorCode::ReconciliationRequired,
                    request_id,
                    detail: "session ended before its response was delivered",
                },
                envelope.generation,
                request_id,
            )],
        }
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
                let directive = SessionDirective {
                    control: SessionControl::Redirect,
                    command: Some(CommandToken {
                        kind: CommandKind::Redirect,
                        id: Arc::from(command.redirect_id.as_str()),
                    }),
                };
                match self.forward(command.connection_id, directive) {
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
                let directive = SessionDirective {
                    control: if force {
                        SessionControl::CloseImmediate
                    } else {
                        SessionControl::GracefulClose
                    },
                    command: Some(CommandToken {
                        kind: CommandKind::Close,
                        id: Arc::from(command.close_id.as_str()),
                    }),
                };
                match self.forward(command.connection_id, directive) {
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
                        let _ = self
                            .forward(*id, SessionDirective::bare(SessionControl::GracefulClose));
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
            match self.forward(id, SessionDirective::bare(SessionControl::CloseImmediate)) {
                ForwardOutcome::Sent => {
                    self.force_notified.insert(id);
                }
                ForwardOutcome::Full => {
                    // Real backpressure: retry on the next tick.
                }
                ForwardOutcome::Gone => {
                    outbound.extend(self.session_closed(
                        id,
                        true,
                        ErrorSource::Proxy,
                        TrafficTotals::default(),
                    ));
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
    pub fn build_reconcile_request(&mut self, known_generation: u64) -> ReconcileRequest {
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
                    &remote.namespace,
                    remote.generation,
                    ErrorSource::Proxy,
                    TrafficTotals::default(),
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

    fn forward(&mut self, connection_id: u64, directive: SessionDirective) -> ForwardOutcome {
        match self.sessions.get(&connection_id) {
            Some(entry) => match entry.control.try_send(directive) {
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
    namespace: &str,
    generation: u64,
    error_source: ErrorSource,
    traffic: TrafficTotals,
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
            namespace: namespace.to_owned(),
            error_source: error_source.into(),
            client_in_bytes: traffic.client_in,
            client_out_bytes: traffic.client_out,
            backend_in_bytes: traffic.backend_in,
            backend_out_bytes: traffic.backend_out,
        })),
    }
}

/// Session-side notifications into the dispatch task.
#[derive(Debug)]
pub enum DispatchNotice {
    /// A config snapshot generation was applied (CTL-05). The ack is
    /// the barrier between committing a snapshot and acknowledging it
    /// to Go: only after the dispatcher recorded the generation may
    /// the `SnapshotResult` OK go out, so commands minted against the
    /// new generation can never race an older applied view.
    AppliedGeneration {
        /// The committed generation.
        generation: u64,
        /// Completed when the dispatcher recorded it.
        applied: tokio::sync::oneshot::Sender<()>,
    },
    /// An admitted session registers its channels. `applied` is the
    /// causal barrier: interact with the session's registration (send
    /// requests, expect commands to find it) only after it fires.
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
        control: mpsc::Sender<SessionDirective>,
        /// Correlated Go answers (route assignments, handshake
        /// decisions/results) for this session, when it routes.
        responses: Option<mpsc::Sender<ControlEnvelope>>,
        /// Completed when the registration is applied.
        applied: tokio::sync::oneshot::Sender<()>,
    },
    /// Adopts the decision-resolved namespace for a session. The
    /// applied acknowledgement is a causal barrier: reconcile and
    /// lifecycle evidence reflect the update only after it fires, so
    /// callers proceed to the route conversation knowing every later
    /// observer sees the resolved namespace.
    SetNamespace {
        /// Stable connection id.
        connection_id: u64,
        /// The decision-resolved namespace.
        namespace: String,
        /// Completed when the update is applied.
        applied: tokio::sync::oneshot::Sender<()>,
    },
    /// The session's backend attached or changed.
    SetBackend {
        /// Connection id.
        connection_id: u64,
        /// New backend id.
        backend_id: String,
    },
    /// The session sent a request and awaits its correlated answer.
    ExpectResponse {
        /// Connection id.
        connection_id: u64,
        /// The initiating request id the answer must carry.
        request_id: u64,
        /// The body kind the answer must have.
        kind: ResponseKind,
        /// Completed with the dispatcher's arm verdict — the causal
        /// barrier: the session sends its request to Go only after an
        /// `Armed` verdict, so the answer cannot exist before the arm
        /// and a dead/channel-less session is never told to proceed.
        applied: tokio::sync::oneshot::Sender<ExpectArmVerdict>,
    },
    /// One metering delta from a session's accounting. The ack carries
    /// the ledger's fail-closed verdict; on `Err` the delta was NOT
    /// absorbed and its ownership stays with the producer (retry or
    /// declare the stream unhealthy per the ledger contract).
    Metering {
        /// The delta.
        delta: Box<control_proto::v1::MeteringDelta>,
        /// The producer's verdict channel.
        ack: tokio::sync::oneshot::Sender<Result<(), MeteringError>>,
    },
    /// The session terminated.
    SessionClosed {
        /// Connection id.
        connection_id: u64,
        /// Whether a force close ended it.
        forced: bool,
        /// Failure attribution for the CLOSED event.
        error_source: ErrorSource,
        /// Final byte totals for the CLOSED lifecycle event.
        traffic: TrafficTotals,
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

/// Cloneable session-facing handle to the dispatch task. The typed
/// methods are the production surface — `register_session` and
/// `expect_response` await the dispatch-applied acknowledgement, the
/// **causal barrier** callers must respect: send a request to Go only
/// after its expectation ack fired (so the answer cannot exist before
/// the arm), and if that send then fails, re-arm or replace the
/// expectation before the next exchange.
#[derive(Clone)]
pub struct ControlDispatchHandle {
    notices: mpsc::Sender<DispatchNotice>,
    stats: Arc<DispatchStats>,
}

/// A metering delta could not be handed to the ledger. Every variant
/// **returns the original delta**: ownership stays with the producer,
/// which retries or declares its stream unhealthy — the value is never
/// silently consumed by a failed handoff.
#[derive(Debug)]
pub enum MeteringRecordError {
    /// The ledger rejected the delta (fail-closed verdict).
    Rejected {
        /// The delta, returned to its owner.
        delta: control_proto::v1::MeteringDelta,
        /// The ledger's verdict.
        error: MeteringError,
    },
    /// The dispatch task is gone (or its ack channel closed before
    /// answering); the delta was not absorbed.
    DispatchUnavailable {
        /// The delta, returned to its owner.
        delta: control_proto::v1::MeteringDelta,
    },
}

/// Arming a response expectation failed; no request may be sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpectResponseError {
    /// No session is registered under this connection id.
    UnknownConnection,
    /// The session registered without a response channel.
    NoResponseChannel,
    /// The dispatch task is gone.
    DispatchUnavailable,
}

impl ControlDispatchHandle {
    /// Submits one notice; returns false when the dispatch task is
    /// gone. Crate-internal: production callers use the typed methods
    /// so the applied-ack causal contracts cannot be bypassed.
    pub(crate) async fn notify(&self, notice: DispatchNotice) -> bool {
        self.notices.send(notice).await.is_ok()
    }

    /// The dispatcher's observable counters.
    #[must_use]
    pub fn stats(&self) -> Arc<DispatchStats> {
        Arc::clone(&self.stats)
    }

    /// Records the applied config snapshot generation and **waits
    /// until the dispatcher recorded it** — the barrier callers (the
    /// snapshot owner) must pass before acknowledging the generation
    /// to Go. Returns false when the dispatch task is gone.
    pub async fn applied_generation(&self, generation: u64) -> bool {
        let (applied_tx, applied_rx) = tokio::sync::oneshot::channel();
        if !self
            .notify(DispatchNotice::AppliedGeneration {
                generation,
                applied: applied_tx,
            })
            .await
        {
            return false;
        }
        applied_rx.await.is_ok()
    }

    /// Registers an admitted session and **waits until the dispatcher
    /// applied it** — only then may the session be referenced (by
    /// requests, backends, or expected responses).
    #[allow(clippy::too_many_arguments)]
    pub async fn register_session(
        &self,
        identity: ConnectionIdentity,
        namespace: String,
        snapshot_generation: u64,
        listener_name: String,
        control: mpsc::Sender<SessionDirective>,
        responses: Option<mpsc::Sender<ControlEnvelope>>,
    ) -> bool {
        let (applied_tx, applied_rx) = tokio::sync::oneshot::channel();
        if !self
            .notify(DispatchNotice::RegisterSession {
                identity,
                namespace,
                snapshot_generation,
                listener_name,
                control,
                responses,
                applied: applied_tx,
            })
            .await
        {
            return false;
        }
        applied_rx.await.is_ok()
    }

    /// Records the session's current backend.
    pub async fn set_backend(&self, connection_id: u64, backend_id: String) -> bool {
        self.notify(DispatchNotice::SetBackend {
            connection_id,
            backend_id,
        })
        .await
    }

    /// Adopts the decision-resolved namespace for this session's
    /// lifecycle events and reconciliation, and WAITS for the applied
    /// acknowledgement. The precise guarantee: `true` means every
    /// reconcile built later exports the resolved value AND any
    /// reconcile that raced ahead with the seed has already been
    /// succeeded — in wire order, before the ack fired — by an
    /// explicit repair reconcile that actually entered the outbound
    /// path. `false` means the repair could not be placed on the wire
    /// (the epoch died or the enqueue failed): the caller must fail
    /// the session closed instead of routing. A stale export is also
    /// always backend-less (notices apply in order), so the peer can
    /// only have parked it as an orphan — never a live session under
    /// the seed — and the gate keeps the adopted value, so every later
    /// export (including the next epoch's automatic reconcile) reports
    /// it for accounting.
    pub async fn set_namespace(&self, connection_id: u64, namespace: String) -> bool {
        let (applied_tx, applied_rx) = tokio::sync::oneshot::channel();
        if !self
            .notify(DispatchNotice::SetNamespace {
                connection_id,
                namespace,
                applied: applied_tx,
            })
            .await
        {
            return false;
        }
        applied_rx.await.is_ok()
    }

    /// Arms the session's response expectation and **waits for the
    /// dispatcher's verdict**: the caller may send the corresponding
    /// request to Go only after `Ok(())` — which is issued only for a
    /// live session with a response channel, so the caller is never
    /// told to start an exchange whose answer could not be delivered.
    ///
    /// # Errors
    ///
    /// The dispatcher's arm rejection, or
    /// [`ExpectResponseError::DispatchUnavailable`] when the dispatch
    /// task is gone.
    pub async fn expect_response(
        &self,
        connection_id: u64,
        request_id: u64,
        kind: ResponseKind,
    ) -> Result<(), ExpectResponseError> {
        let (applied_tx, applied_rx) = tokio::sync::oneshot::channel();
        if !self
            .notify(DispatchNotice::ExpectResponse {
                connection_id,
                request_id,
                kind,
                applied: applied_tx,
            })
            .await
        {
            return Err(ExpectResponseError::DispatchUnavailable);
        }
        match applied_rx.await {
            Ok(ExpectArmVerdict::Armed) => Ok(()),
            Ok(ExpectArmVerdict::UnknownConnection) => Err(ExpectResponseError::UnknownConnection),
            Ok(ExpectArmVerdict::NoResponseChannel) => Err(ExpectResponseError::NoResponseChannel),
            Err(_) => Err(ExpectResponseError::DispatchUnavailable),
        }
    }

    /// Hands one metering delta to the ledger and returns the ledger's
    /// own fail-closed verdict. On `Err` the delta was **not**
    /// absorbed: ownership stays with the producer, which retries
    /// (`BacklogFull` clears on a reconcile ack) or declares its
    /// stream unhealthy per the ledger contract. Awaiting the verdict
    /// is itself the backpressure.
    ///
    /// # Errors
    ///
    /// [`MeteringRecordError::Rejected`] with the ledger's verdict, or
    /// [`MeteringRecordError::DispatchUnavailable`] when the dispatch
    /// task is gone.
    pub async fn record_metering(
        &self,
        delta: control_proto::v1::MeteringDelta,
    ) -> Result<(), MeteringRecordError> {
        // The producer keeps the original for the whole handoff: the
        // notice carries a copy, so every failure path — send failure,
        // ack closed, ledger rejection — can hand the value back.
        let (ack_tx, ack_rx) = tokio::sync::oneshot::channel();
        if !self
            .notify(DispatchNotice::Metering {
                delta: Box::new(delta.clone()),
                ack: ack_tx,
            })
            .await
        {
            return Err(MeteringRecordError::DispatchUnavailable { delta });
        }
        match ack_rx.await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => Err(MeteringRecordError::Rejected { delta, error }),
            Err(_) => Err(MeteringRecordError::DispatchUnavailable { delta }),
        }
    }

    /// The session terminated.
    pub async fn session_closed(
        &self,
        connection_id: u64,
        forced: bool,
        error_source: ErrorSource,
        traffic: TrafficTotals,
    ) -> bool {
        self.notify(DispatchNotice::SessionClosed {
            connection_id,
            forced,
            error_source,
            traffic,
        })
        .await
    }

    /// A session's redirect finished.
    pub async fn redirect_finished(
        &self,
        connection_id: u64,
        redirect_id: String,
        succeeded: bool,
        backend_id: String,
        code: ErrorCode,
    ) -> bool {
        self.notify(DispatchNotice::RedirectFinished {
            connection_id,
            redirect_id,
            succeeded,
            backend_id,
            code,
        })
        .await
    }

    /// A session's accepted close finished.
    pub async fn close_finished(&self, connection_id: u64, close_id: String) -> bool {
        self.notify(DispatchNotice::CloseFinished {
            connection_id,
            close_id,
        })
        .await
    }
}

/// The transport receive half with **global single in-flight
/// ownership**. `handle` awaits a bounded queue reservation (real
/// backpressure through the read loop and TCP); on session teardown
/// the one in-flight envelope is retained in a slot instead of being
/// dropped or blocking the join. `resume_session` — invoked by the
/// transport after the next session's write path is live but **before
/// its first read** — pumps the retained envelope into dispatch, so a
/// second retained frame can never come into existence: the next
/// reader starts only once the slot is empty.
pub struct InboundForwarder {
    inbound: mpsc::Sender<ControlEnvelope>,
    state: watch::Receiver<ConnectionState>,
    retained: Arc<StdMutex<Option<ControlEnvelope>>>,
}

/// Construction and observability for the forwarder.
impl InboundForwarder {
    /// Builds a forwarder over the dispatch inbound queue and the
    /// transport's connection-state watch (composition/tests; the
    /// production path is [`spawn_control_dispatch`]).
    #[must_use]
    pub fn new(
        inbound: mpsc::Sender<ControlEnvelope>,
        state: watch::Receiver<ConnectionState>,
    ) -> Self {
        Self {
            inbound,
            state,
            retained: Arc::new(StdMutex::new(None)),
        }
    }

    /// Whether a frame from a torn-down session is currently retained.
    ///
    /// # Errors
    ///
    /// Returns an error when the slot lock is poisoned.
    pub fn retains_frame(&self) -> Result<bool, TransportError> {
        let Ok(slot) = self.retained.lock() else {
            return Err(TransportError::Configuration(
                "retained slot poisoned".to_owned(),
            ));
        };
        Ok(slot.is_some())
    }
}

impl Handler for InboundForwarder {
    async fn handle(&self, envelope: ControlEnvelope) -> Result<(), TransportError> {
        let mut state = self.state.clone();
        tokio::select! {
            biased;
            permit = self.inbound.reserve() => {
                let Ok(permit) = permit else {
                    return Err(TransportError::Configuration(
                        "control dispatch task is gone".to_owned(),
                    ));
                };
                permit.send(envelope);
                Ok(())
            }
            _ = state.wait_for(|s| !matches!(s, ConnectionState::Connected { .. })) => {
                // Session teardown while the dispatcher is jammed:
                // retain the one in-flight frame (the slot is empty by
                // the resume invariant) and end the stream without
                // depending on outbound drain.
                let Ok(mut slot) = self.retained.lock() else {
                    return Err(TransportError::Configuration(
                        "retained slot poisoned".to_owned(),
                    ));
                };
                *slot = Some(envelope);
                Err(TransportError::Closed)
            }
        }
    }

    async fn resume_session(&self, _epoch: u64) -> Result<(), TransportError> {
        loop {
            // Clone-then-take keeps this cancel-safe: if the session
            // dies (or this future is dropped) mid-send, the slot still
            // owns the frame for the next resume — no loss, and the
            // take happens in the same poll as the successful send, so
            // no double delivery either.
            let pending = {
                let Ok(slot) = self.retained.lock() else {
                    return Err(TransportError::Configuration(
                        "retained slot poisoned".to_owned(),
                    ));
                };
                slot.clone()
            };
            let Some(envelope) = pending else {
                return Ok(());
            };
            let mut state = self.state.clone();
            tokio::select! {
                biased;
                permit = self.inbound.reserve() => {
                    let Ok(permit) = permit else {
                        return Err(TransportError::Configuration(
                            "control dispatch task is gone".to_owned(),
                        ));
                    };
                    permit.send(envelope);
                    let Ok(mut slot) = self.retained.lock() else {
                        return Err(TransportError::Configuration(
                            "retained slot poisoned".to_owned(),
                        ));
                    };
                    *slot = None;
                }
                _ = state.wait_for(|s| !matches!(s, ConnectionState::Connected { .. })) => {
                    // The session died before the pump finished: keep
                    // the frame retained for the next session's resume.
                    return Err(TransportError::Closed);
                }
            }
        }
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
/// checked request-id allocation plus the durable and session-scoped
/// sends. Implemented by the production [`ControlClient`]; tests
/// substitute a fake.
pub trait DispatchSender: Send + Sync {
    /// Allocates the next request id (fail-closed at exhaustion).
    fn allocate_request_id(&self) -> Option<u64>;
    /// Sends one durable (cross-reconnect) envelope.
    fn send_envelope(
        &self,
        envelope: ControlEnvelope,
    ) -> impl Future<Output = Result<(), TransportError>> + Send;
    /// Sends one envelope bound to exactly the given negotiated epoch;
    /// a stale binding fails with
    /// [`TransportError::StaleSessionEpoch`] (the owner regenerates on
    /// the next `Connected`).
    fn send_session_scoped(
        &self,
        envelope: ControlEnvelope,
        epoch: u64,
    ) -> impl Future<Output = Result<(), TransportError>> + Send;
}

impl DispatchSender for ControlClient {
    fn allocate_request_id(&self) -> Option<u64> {
        ControlClient::allocate_request_id(self)
    }

    async fn send_envelope(&self, envelope: ControlEnvelope) -> Result<(), TransportError> {
        self.send(envelope).await
    }

    async fn send_session_scoped(
        &self,
        envelope: ControlEnvelope,
        epoch: u64,
    ) -> Result<(), TransportError> {
        ControlClient::send_session_scoped(self, envelope, epoch).await
    }
}

/// Delivery policy for one outbound envelope.
#[derive(Clone, Copy)]
enum SendScope {
    /// Cross-reconnect retention: results, lifecycle events, metering
    /// batches — the peer dedups by request id / sequence.
    Durable,
    /// Valid only under exactly this negotiated epoch; regenerated by
    /// the next `Connected` transition when dropped as stale.
    Session(u64),
}

/// A condition the dispatch loop cannot continue past: the loop exits
/// with it, and the runtime supervisor cancels its sibling tasks and
/// propagates it as the join error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DispatchFatal {
    /// The sender's checked request-id space is exhausted.
    IdSpaceExhausted,
    /// The CTL-05 snapshot owner is gone.
    SnapshotOwnerGone,
    /// The metering ledger's strictly monotonic sequence space is
    /// exhausted; continuing would freeze or reuse a sequence.
    MeteringSequenceExhausted,
}

impl std::fmt::Display for DispatchFatal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IdSpaceExhausted => formatter.write_str("control request-id space is exhausted"),
            Self::SnapshotOwnerGone => formatter.write_str("CTL-05 snapshot owner is gone"),
            Self::MeteringSequenceExhausted => {
                formatter.write_str("metering sequence space is exhausted")
            }
        }
    }
}

/// Stamps self-originated envelopes with allocator ids and sends under
/// the given scope. The connection-event watermark advances only
/// **after** a successful send — a failed send converges through
/// reconcile omission instead of poisoning the watermark. Terminal
/// send failures are counted, never silent.
/// Where one outbound dispatch ended up — for callers whose guarantee
/// depends on it (the stale-export repair must not be presumed sent).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SendOutcome {
    /// Entered the outbound path.
    Sent,
    /// The bound epoch is no longer negotiated (or no session exists):
    /// the next `Connected` transition's automatic reconcile
    /// regenerates this state from the gate.
    StaleEpoch,
    /// Unrecoverable enqueue failure (queue full, owner closed, …).
    Failed,
}

async fn dispatch_send_outcome<S: DispatchSender>(
    sender: &Arc<S>,
    handler: &mut ControlCommandHandler,
    mut envelope: ControlEnvelope,
    scope: SendScope,
) -> Result<SendOutcome, DispatchFatal> {
    if envelope.request_id == NEEDS_ALLOCATION {
        let Some(id) = sender.allocate_request_id() else {
            // The id space is exhausted: every future send would have
            // to reuse or wrap, so the loop fails closed instead.
            return Err(DispatchFatal::IdSpaceExhausted);
        };
        envelope.request_id = id;
    }
    let is_event = matches!(envelope.body, Some(Body::ConnectionEvent(_)));
    let request_id = envelope.request_id;
    let result = match scope {
        SendScope::Durable => sender.send_envelope(envelope).await,
        SendScope::Session(epoch) => sender.send_session_scoped(envelope, epoch).await,
    };
    match result {
        Ok(()) => {
            if is_event {
                handler.record_event_sequence(request_id);
            }
            Ok(SendOutcome::Sent)
        }
        // Regenerated by the next Connected transition by design.
        Err(TransportError::StaleSessionEpoch) => Ok(SendOutcome::StaleEpoch),
        Err(_) => {
            handler.count_send_failure();
            Ok(SendOutcome::Failed)
        }
    }
}

async fn dispatch_send<S: DispatchSender>(
    sender: &Arc<S>,
    handler: &mut ControlCommandHandler,
    envelope: ControlEnvelope,
    scope: SendScope,
) -> Result<(), DispatchFatal> {
    dispatch_send_outcome(sender, handler, envelope, scope)
        .await
        .map(|_| ())
}

/// Runs the production dispatch loop: connection-state transitions
/// (peer-mode update + capability-gated automatic reconcile + metering
/// replay, all bound to one atomic epoch/capabilities snapshot),
/// inbound envelopes (from the live read path and from the retained
/// slot via `resume_session`, with `StateSnapshot` forwarded — awaited
/// — to the mandatory CTL-05 owner), session and metering notices, and
/// the periodic tick (drain force phase + metering seal). Select arms
/// are unbiased: tokio polls ready arms in random order, so no arm —
/// in particular the drain-deadline tick — can be starved indefinitely
/// by a busy neighbor. This is the long-lived single owner of
/// [`ControlCommandHandler`]; it survives control reconnects and exits
/// only on fatal conditions (owner channels gone, id space exhausted).
///
/// # Errors
///
/// Returns the [`DispatchFatal`] the loop cannot continue past; clean
/// channel-close cascades exit with `Ok`.
#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
pub async fn run_control_dispatch<S: DispatchSender>(
    mut handler: ControlCommandHandler,
    sender: Arc<S>,
    mut state: watch::Receiver<ConnectionState>,
    mut inbound: mpsc::Receiver<ControlEnvelope>,
    mut notices: mpsc::Receiver<DispatchNotice>,
    snapshot_tx: mpsc::Sender<ControlEnvelope>,
    tick_interval: Duration,
    unix_now_millis: UnixMillisFn,
) -> Result<(), DispatchFatal> {
    let mut ticker = tokio::time::interval(tick_interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        let step = tokio::select! {
            changed = state.changed() => {
                if changed.is_err() {
                    // The transport is gone: shutdown cascade, clean.
                    return Ok(());
                }
                // `changed()` marked the newest value seen: apply it
                // directly, then drain anything that raced in after.
                let snapshot = *state.borrow();
                // Causal barrier: adoptions enqueued before this
                // transition was observed apply BEFORE the
                // transition's automatic reconcile, so its export
                // already carries them. (Adoptions enqueued after are
                // covered by the stale-export repair.)
                drain_pending_notices(&sender, &mut handler, &mut notices).await?;
                let applied = apply_state(&sender, &mut handler, snapshot).await;
                match applied {
                    Ok(()) => {
                        apply_state_transitions(&sender, &mut handler, &mut state).await
                    }
                    Err(fatal) => Err(fatal),
                }
            }
            notice = notices.recv() => {
                let Some(notice) = notice else { return Ok(()) };
                apply_notice(&sender, &mut handler, notice).await
            }
            envelope = inbound.recv() => {
                let Some(envelope) = envelope else { return Ok(()) };
                // Deterministic state barrier: whatever order the
                // select observed things in, any pending connection
                // transition is applied BEFORE this envelope — a frame
                // pumped from a previous session can never be judged
                // against a session snapshot that predates it.
                apply_state_transitions(&sender, &mut handler, &mut state).await?;
                process_inbound(
                    &sender,
                    &mut handler,
                    &snapshot_tx,
                    envelope,
                    unix_now_millis,
                )
                .await
            }
            _ = ticker.tick() => {
                run_tick(&sender, &mut handler).await
            }
        };
        step?;
    }
}

/// Drains every pending connection-state observation: `Connected`
/// applies the atomic epoch/caps snapshot (with its automatic
/// reconcile and metering replay), every other state clears the
/// active session. Watch coalescing may have collapsed a `Connected`
/// away, and
/// modeling that absence is what keeps a dead session's frames from
/// matching "the current epoch".
async fn apply_state_transitions<S: DispatchSender>(
    sender: &Arc<S>,
    handler: &mut ControlCommandHandler,
    state: &mut watch::Receiver<ConnectionState>,
) -> Result<(), DispatchFatal> {
    while state.has_changed().unwrap_or(false) {
        let snapshot = *state.borrow_and_update();
        apply_state(sender, handler, snapshot).await?;
    }
    Ok(())
}

/// Applies every notice already sitting in the queue (never blocks).
async fn drain_pending_notices<S: DispatchSender>(
    sender: &Arc<S>,
    handler: &mut ControlCommandHandler,
    notices: &mut mpsc::Receiver<DispatchNotice>,
) -> Result<(), DispatchFatal> {
    // Bounded by the queue length observed at entry. This queue also
    // carries continuous producers (metering, session terminals,
    // redirect results) that can refill freed slots while apply awaits
    // outbound sends — chasing them would let the drain starve the
    // very transition it feeds. A notice arriving during the drain is
    // exactly the case the stale-export repair covers.
    let budget = notices.len();
    for _ in 0..budget {
        match notices.try_recv() {
            Ok(notice) => apply_notice(sender, handler, notice).await?,
            Err(_) => break,
        }
    }
    Ok(())
}

/// Applies one observed connection state to the handler.
async fn apply_state<S: DispatchSender>(
    sender: &Arc<S>,
    handler: &mut ControlCommandHandler,
    snapshot: ConnectionState,
) -> Result<(), DispatchFatal> {
    match snapshot {
        ConnectionState::Connected {
            epoch,
            capabilities,
        } => on_connected_transition(sender, handler, epoch, capabilities).await,
        ConnectionState::Disconnected | ConnectionState::Connecting | ConnectionState::Shutdown => {
            handler.on_disconnected();
            Ok(())
        }
    }
}

/// One atomic `Connected { epoch, capabilities }` snapshot drives the
/// peer mode, the capability-gated reconcile request (declaring
/// `RECONCILE_CONNECTIONS`, plus rehydration when negotiated), and the
/// metering replay — the session-scoped pieces are bound to exactly
/// this epoch and regenerated on the next transition if the session
/// dies first. Without `RECONCILE_CONNECTIONS` no request is sent and
/// no ack can ever arrive: the ledger's bounded unacked retention then
/// IS the backpressure (sealing fails closed at the bound).
async fn on_connected_transition<S: DispatchSender>(
    sender: &Arc<S>,
    handler: &mut ControlCommandHandler,
    epoch: u64,
    capabilities: u64,
) -> Result<(), DispatchFatal> {
    handler.on_connected(epoch, capabilities);
    if handler.reconcile_capable() {
        let _ = send_reconcile_request(sender, handler, epoch, capabilities).await?;
    }
    // Unacked metering is durable: delivery matters with or without an
    // ack path, and the consumer dedups by contiguous sequence.
    for batch in handler.metering_replay() {
        let envelope = ControlEnvelope {
            request_id: NEEDS_ALLOCATION,
            priority: Priority::Bulk.into(),
            body: Some(Body::MeteringBatch(batch)),
            ..ControlEnvelope::default()
        };
        dispatch_send(sender, handler, envelope, SendScope::Durable).await?;
    }
    Ok(())
}

/// Builds and sends one fresh reconcile request to the active session,
/// with the same capability gating as the automatic reconcile at
/// connection. Shared by the connected transition and the stale-export
/// repair path.
async fn send_reconcile_request<S: DispatchSender>(
    sender: &Arc<S>,
    handler: &mut ControlCommandHandler,
    epoch: u64,
    capabilities: u64,
) -> Result<SendOutcome, DispatchFatal> {
    let request = handler.build_reconcile_request(handler.applied_generation());
    let mut required = vec![ControlCapability::ReconcileConnections as u64];
    if (capabilities >> (ControlCapability::ReconcileSessionRehydration as u64)) & 1 == 1 {
        required.push(ControlCapability::ReconcileSessionRehydration as u64);
    }
    let envelope = ControlEnvelope {
        request_id: NEEDS_ALLOCATION,
        generation: request.known_generation,
        priority: Priority::Critical.into(),
        required_capabilities: required,
        body: Some(Body::ReconcileRequest(request)),
        ..ControlEnvelope::default()
    };
    dispatch_send_outcome(sender, handler, envelope, SendScope::Session(epoch)).await
}

/// Explicit repair for a stale export. A namespace/backend adoption
/// that lands on a record some reconcile request already exported means
/// the peer may have observed (and rehydrated or parked an orphan
/// from) the pre-adoption value, and known ids are not updated by
/// later reconciles on the peer — only orphans are retried. Wire FIFO
/// makes the repair the peer's LAST observation of the record, and the
/// gate's notice-order guarantee (namespace adopts before any backend
/// exists) means a stale export is always backend-less: it can only
/// have parked as an orphan, never a live wrong-router session. The
/// orphan then converges one of two ways, both clean: the backend
/// adoption's repair re-exports a routable record that resolves it
/// under the adopted values, or the peer's bounded orphan cleanup (or
/// the failed route conversation) terminates the session with an
/// ordinary CLOSED — a mid-handshake connection is not guaranteed to
/// SURVIVE a peer restart, only to never be attributed stale. No
/// active or reconcile-incapable session: nothing was exported to
/// repair — the next session's automatic reconcile carries the
/// adopted record.
async fn repair_stale_export<S: DispatchSender>(
    sender: &Arc<S>,
    handler: &mut ControlCommandHandler,
) -> Result<SendOutcome, DispatchFatal> {
    if !handler.reconcile_capable() {
        return Ok(SendOutcome::StaleEpoch);
    }
    let Some((epoch, capabilities)) = handler.active_session() else {
        return Ok(SendOutcome::StaleEpoch);
    };
    send_reconcile_request(sender, handler, epoch, capabilities).await
}

/// Records one metering delta and acks in one await-free step: the
/// verdict the producer sees is exactly the ledger's, and the delta is
/// either absorbed or still owned by the producer — never
/// accepted-then-dropped.
fn apply_metering_notice(
    handler: &mut ControlCommandHandler,
    delta: control_proto::v1::MeteringDelta,
    ack: tokio::sync::oneshot::Sender<Result<(), MeteringError>>,
) -> Result<(), DispatchFatal> {
    let result = handler.record_metering(delta);
    let fatal = matches!(result, Err(MeteringError::SequenceExhausted));
    let _ = ack.send(result);
    if fatal {
        // The strictly monotonic sequence space is gone: every future
        // seal would fail; stop fail-closed.
        return Err(DispatchFatal::MeteringSequenceExhausted);
    }
    Ok(())
}

async fn apply_notice<S: DispatchSender>(
    sender: &Arc<S>,
    handler: &mut ControlCommandHandler,
    notice: DispatchNotice,
) -> Result<(), DispatchFatal> {
    match notice {
        DispatchNotice::AppliedGeneration {
            generation,
            applied,
        } => {
            handler.set_applied_generation(generation);
            let _ = applied.send(());
        }
        DispatchNotice::RegisterSession {
            identity,
            namespace,
            snapshot_generation,
            listener_name,
            control,
            responses,
            applied,
        } => {
            handler.register_session(
                identity,
                &namespace,
                snapshot_generation,
                &listener_name,
                control,
                responses,
            );
            let _ = applied.send(());
        }
        DispatchNotice::SetBackend {
            connection_id,
            backend_id,
        } => {
            if handler.set_backend(connection_id, &backend_id) {
                // No ack path exists for backend adoption. A failed
                // repair still converges: the adopted value is already
                // in the gate, so the next Connected transition's
                // automatic reconcile re-exports it, and until then the
                // peer's stale record can only be a parked orphan whose
                // bounded cleanup terminates the session cleanly.
                let _ = repair_stale_export(sender, handler).await?;
            }
        }
        DispatchNotice::SetNamespace {
            connection_id,
            namespace,
            applied,
        } => {
            // The ack is granted ONLY when no repair was owed or the
            // repair actually entered the outbound path (`Sent`): the
            // commander observing `true` then means the stale export
            // is already succeeded, in wire order, by the repaired
            // one. `StaleEpoch` is NOT a wire barrier — an acked
            // session would immediately enqueue its durable
            // `RouteRequest`, which can reach the new peer before the
            // dispatcher even observes the `Connected` transition that
            // sends the automatic reconcile — and `Failed` never left
            // this process. Both drop the ack: the commander observes
            // `false` and the SQL session fails closed, which is
            // exactly the agreed boundary (a mid-handshake connection
            // does not survive a control-session loss; the gate still
            // holds the adopted value, so every later export —
            // including the next epoch's automatic reconcile — reports
            // it for accounting).
            let upheld = if handler.set_namespace(connection_id, &namespace) {
                repair_stale_export(sender, handler).await? == SendOutcome::Sent
            } else {
                true
            };
            if upheld {
                let _ = applied.send(());
            }
        }
        DispatchNotice::ExpectResponse {
            connection_id,
            request_id,
            kind,
            applied,
        } => {
            let verdict = handler.expect_response(connection_id, request_id, kind);
            let _ = applied.send(verdict);
        }
        DispatchNotice::Metering { delta, ack } => {
            apply_metering_notice(handler, *delta, ack)?;
        }
        DispatchNotice::SessionClosed {
            connection_id,
            forced,
            error_source,
            traffic,
        } => {
            for envelope in handler.session_closed(connection_id, forced, error_source, traffic) {
                dispatch_send(sender, handler, envelope, SendScope::Durable).await?;
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
                dispatch_send(sender, handler, envelope, SendScope::Durable).await?;
            }
        }
        DispatchNotice::CloseFinished {
            connection_id,
            close_id,
        } => {
            if let Some(envelope) = handler.close_completed(connection_id, &close_id) {
                dispatch_send(sender, handler, envelope, SendScope::Durable).await?;
            }
        }
    }
    Ok(())
}

async fn process_inbound<S: DispatchSender>(
    sender: &Arc<S>,
    handler: &mut ControlCommandHandler,
    snapshot_tx: &mpsc::Sender<ControlEnvelope>,
    envelope: ControlEnvelope,
    unix_now_millis: UnixMillisFn,
) -> Result<(), DispatchFatal> {
    if matches!(envelope.body, Some(Body::StateSnapshot(_))) {
        // The CTL-05 snapshot owner is a required dependency: the send
        // is awaited (its backpressure reaches the transport read
        // loop), and its loss is fatal rather than a silent drop.
        return snapshot_tx
            .send(envelope)
            .await
            .map_err(|_| DispatchFatal::SnapshotOwnerGone);
    }
    let outbound = handler.handle_envelope(&envelope, Instant::now(), unix_now_millis());
    for out in outbound {
        dispatch_send(sender, handler, out, SendScope::Durable).await?;
    }
    Ok(())
}

async fn run_tick<S: DispatchSender>(
    sender: &Arc<S>,
    handler: &mut ControlCommandHandler,
) -> Result<(), DispatchFatal> {
    for envelope in handler.tick(Instant::now()) {
        dispatch_send(sender, handler, envelope, SendScope::Durable).await?;
    }
    match handler.seal_metering() {
        Ok(Some(batch)) => {
            let envelope = ControlEnvelope {
                request_id: NEEDS_ALLOCATION,
                priority: Priority::Bulk.into(),
                body: Some(Body::MeteringBatch(batch)),
                ..ControlEnvelope::default()
            };
            dispatch_send(sender, handler, envelope, SendScope::Durable).await?;
        }
        Ok(None) => {}
        Err(MeteringError::SequenceExhausted) => {
            // The strictly monotonic sequence space is gone: every
            // future seal would fail identically, so the loop stops
            // fail-closed instead of living forever unable to seal.
            handler.count_metering_seal_failure();
            return Err(DispatchFatal::MeteringSequenceExhausted);
        }
        Err(_) => {
            // Recoverable fail-closed bound (for example: no reconcile
            // ack path): counted, and nothing is lost — a failed seal
            // leaves the open accumulation intact and sealed batches
            // stay retained until acknowledged.
            handler.count_metering_seal_failure();
        }
    }
    Ok(())
}

/// Capacity of the bounded inbound dispatch queue: overflow stalls the
/// transport read loop (real backpressure), never drops.
const INBOUND_QUEUE_CAPACITY: usize = 256;

/// Spawns the production control-dispatch task bound to the shared
/// control client: the returned [`InboundForwarder`] is the transport
/// handler for [`ControlClient::run`] (including the `resume_session`
/// retained-frame pump), the [`ControlDispatchHandle`] is the
/// session-facing surface, and `snapshot_tx` is the **required**
/// CTL-05 snapshot owner (its loss terminates the dispatch task).
#[must_use]
pub fn spawn_control_dispatch(
    client: Arc<ControlClient>,
    snapshot_tx: mpsc::Sender<ControlEnvelope>,
    tick_interval: Duration,
) -> (
    ControlDispatchHandle,
    InboundForwarder,
    tokio::task::JoinHandle<Result<(), DispatchFatal>>,
) {
    spawn_control_dispatch_with_handler(
        ControlCommandHandler::new(),
        client,
        snapshot_tx,
        tick_interval,
    )
}

/// [`spawn_control_dispatch`] with a caller-provided handler — the
/// assembly seam for alternate compositions and for regressions that
/// need to pre-populate gate or ledger state behind the public handle.
#[must_use]
pub fn spawn_control_dispatch_with_handler(
    handler: ControlCommandHandler,
    client: Arc<ControlClient>,
    snapshot_tx: mpsc::Sender<ControlEnvelope>,
    tick_interval: Duration,
) -> (
    ControlDispatchHandle,
    InboundForwarder,
    tokio::task::JoinHandle<Result<(), DispatchFatal>>,
) {
    let state = client.subscribe_state();
    spawn_control_dispatch_parts(handler, client, state, snapshot_tx, tick_interval)
}

/// The fully generic assembly seam: any [`DispatchSender`] plus an
/// externally owned connection-state watch. Compositions and
/// regressions that need an observable sender (or a driven state
/// watch) build here; the production paths delegate to it.
#[must_use]
pub fn spawn_control_dispatch_parts<S: DispatchSender + 'static>(
    handler: ControlCommandHandler,
    sender: Arc<S>,
    state: watch::Receiver<ConnectionState>,
    snapshot_tx: mpsc::Sender<ControlEnvelope>,
    tick_interval: Duration,
) -> (
    ControlDispatchHandle,
    InboundForwarder,
    tokio::task::JoinHandle<Result<(), DispatchFatal>>,
) {
    let (inbound_tx, inbound_rx) = mpsc::channel(INBOUND_QUEUE_CAPACITY);
    let (notice_tx, notice_rx) = mpsc::channel(INBOUND_QUEUE_CAPACITY);
    let forwarder = InboundForwarder {
        inbound: inbound_tx,
        state: state.clone(),
        retained: Arc::new(StdMutex::new(None)),
    };
    let handler_stats = handler.stats();
    let task = tokio::spawn(run_control_dispatch(
        handler,
        sender,
        state,
        inbound_rx,
        notice_rx,
        snapshot_tx,
        tick_interval,
        system_unix_millis,
    ));
    (
        ControlDispatchHandle {
            notices: notice_tx,
            stats: handler_stats,
        },
        forwarder,
        task,
    )
}
