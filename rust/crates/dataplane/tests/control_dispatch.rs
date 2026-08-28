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

//! CTL-06 production-dispatch tests: real envelopes drive the
//! long-lived [`ControlCommandHandler`] through `handle_envelope`,
//! `Start` admissions surface as [`SessionControl`] on the sessions'
//! channels, terminals carry the **initiating** request id and are
//! produced **proactively on the completion transition**, session
//! responses multiplex to their owners, unroutable bodies are answered
//! (never silently dropped), the force phase marks delivery only on a
//! successful send, and the dispatch loop reconciles + replays
//! metering automatically on every `Connected` state transition using
//! the sender's single checked allocator.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use control_proto::control_transport::{ConnectionState, Handler, SessionMeta, TransportError};
use control_proto::v1::control_envelope::Body;
use control_proto::v1::{
    CloseCommand, ConnectionIdentity, ControlCapability, ControlEnvelope, DrainCommand, ErrorCode,
    ErrorSource, MeteringDelta, ReconcileConnection, ReconcileSnapshot, RedirectCommand,
    RouteAssignment,
};
use dataplane::control_dispatch::{
    CommandKind, CommandToken, ControlCommandHandler, DispatchFatal, DispatchNotice,
    DispatchSender, InboundForwarder, ResponseKind, SessionDirective, TaggedEnvelope,
    run_control_dispatch,
};
use dataplane::session::SessionControl;
use tokio::sync::{mpsc, watch};
use tokio::time::Instant;

fn identity(connection_id: u64) -> ConnectionIdentity {
    ConnectionIdentity {
        connection_id,
        listener_address: "0.0.0.0:6000".to_owned(),
        client_address: "10.9.8.7:55555".to_owned(),
        proxy_address: "10.0.0.9:6000".to_owned(),
        public_endpoint: false,
    }
}

fn redirect(connection_id: u64, redirect_id: &str, sequence: u64) -> RedirectCommand {
    RedirectCommand {
        connection_id,
        redirect_id: redirect_id.to_owned(),
        backend_id: "tidb-b".to_owned(),
        backend_address: "10.0.0.2:4000".to_owned(),
        cluster_name: String::new(),
        deadline_unix_millis: 0,
        command_sequence: sequence,
    }
}

fn envelope(request_id: u64, generation: u64, body: Body) -> ControlEnvelope {
    ControlEnvelope {
        request_id,
        generation,
        body: Some(body),
        ..ControlEnvelope::default()
    }
}

fn error_code(envelope: &ControlEnvelope) -> Option<ErrorCode> {
    match &envelope.body {
        Some(Body::Error(error)) => ErrorCode::try_from(error.code).ok(),
        _ => None,
    }
}

struct Session {
    control: mpsc::Receiver<SessionDirective>,
}

fn register(
    handler: &mut ControlCommandHandler,
    connection_id: u64,
    listener: &str,
    backend: &str,
) -> Session {
    let (tx, rx) = mpsc::channel(8);
    handler.register_session(identity(connection_id), "ns-a", 7, listener, tx, None);
    let _ = handler.set_backend(connection_id, backend);
    Session { control: rx }
}

/// The full redirect chain on the production path: envelope in →
/// `SessionControl::Redirect` out → completion → terminal result with
/// the **initiating** request id → duplicate replays under the
/// duplicate's own id → evicted-obsolete answers `DUPLICATE_REQUEST`.
#[tokio::test(start_paused = true)]
async fn redirect_dispatch_end_to_end() {
    let mut handler = ControlCommandHandler::new();
    handler.on_session_negotiated(true);
    let mut session = register(&mut handler, 1, "sql-a", "tidb-a");
    let now = Instant::now();

    // Start: the session receives the control signal; nothing outbound.
    let inbound = envelope(10, 7, Body::RedirectCommand(redirect(1, "r-1", 1)));
    assert!(handler.handle_envelope(&inbound, now, 1_000).is_empty());
    assert_eq!(
        session.control.try_recv().map(|d| d.control),
        Ok(SessionControl::Redirect)
    );

    // The session finishes: exactly one terminal goes out, carrying the
    // initiating request id (the asynchronous answer to request 10).
    let Some(terminal) = handler.redirect_completed(1, "r-1", true, "tidb-b", ErrorCode::Ok) else {
        unreachable!("first completion must produce the result")
    };
    assert_eq!(terminal.request_id, 10, "terminal reuses the initiating id");
    let Some(Body::RedirectResult(result)) = &terminal.body else {
        unreachable!("terminal is a redirect result")
    };
    assert!(result.succeeded);
    assert!(
        handler
            .redirect_completed(1, "r-1", true, "tidb-b", ErrorCode::Ok)
            .is_none(),
        "second completion suppressed"
    );

    // A delayed duplicate replays the cached result under its own id.
    let dup = envelope(11, 7, Body::RedirectCommand(redirect(1, "r-1", 1)));
    let out = handler.handle_envelope(&dup, now, 1_001);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].request_id, 11, "inline replay answers the duplicate");
    assert_eq!(
        out[0].body,
        Some(Body::RedirectResult(result.clone())),
        "the exact terminal replays"
    );

    // Wrong sequence on the same id: protocol violation.
    let bad = envelope(12, 7, Body::RedirectCommand(redirect(1, "r-1", 9)));
    let out = handler.handle_envelope(&bad, now, 1_002);
    assert_eq!(error_code(&out[0]), Some(ErrorCode::ProtocolViolation));

    // Stale generation: typed stale error, never an action.
    let stale = envelope(13, 9, Body::RedirectCommand(redirect(1, "r-2", 2)));
    let out = handler.handle_envelope(&stale, now, 1_003);
    assert_eq!(error_code(&out[0]), Some(ErrorCode::StaleGeneration));

    // Unknown connection: reconciliation required.
    let unknown = envelope(14, 7, Body::RedirectCommand(redirect(99, "r-x", 1)));
    let out = handler.handle_envelope(&unknown, now, 1_004);
    assert_eq!(error_code(&out[0]), Some(ErrorCode::ReconciliationRequired));
}

/// Close dispatch: graceful and forced starts reach the session as the
/// right control signal, duplicates replay, completions are
/// exactly-once with the initiating id, and `CloseResult` declares the
/// `PER_CONNECTION_CLOSE` capability its semantics rely on.
#[tokio::test(start_paused = true)]
async fn close_dispatch_end_to_end() {
    let mut handler = ControlCommandHandler::new();
    handler.on_session_negotiated(true);
    let mut session = register(&mut handler, 1, "sql-a", "tidb-a");
    let now = Instant::now();

    let close = CloseCommand {
        connection_id: 1,
        close_id: "c-1".to_owned(),
        error_source: 0,
        reason: String::new(),
        force: false,
    };
    let inbound = envelope(20, 7, Body::CloseCommand(close.clone()));
    assert!(handler.handle_envelope(&inbound, now, 2_000).is_empty());
    assert_eq!(
        session.control.try_recv().map(|d| d.control),
        Ok(SessionControl::GracefulClose)
    );

    // Duplicate while closing: current state outbound, no second signal.
    let dup = envelope(21, 7, Body::CloseCommand(close.clone()));
    let out = handler.handle_envelope(&dup, now, 2_001);
    assert!(matches!(out[0].body, Some(Body::CloseResult(_))));
    assert_eq!(out[0].request_id, 21);
    assert!(
        session.control.try_recv().map(|d| d.control).is_err(),
        "no second close"
    );

    let Some(terminal) = handler.close_completed(1, "c-1") else {
        unreachable!("close completes once")
    };
    assert_eq!(terminal.request_id, 20, "terminal reuses the initiating id");
    assert_eq!(
        terminal.required_capabilities,
        vec![ControlCapability::PerConnectionClose as u64],
        "CloseResult declares PER_CONNECTION_CLOSE"
    );
    let Some(Body::CloseResult(result)) = &terminal.body else {
        unreachable!("terminal is a close result")
    };
    assert!(result.accepted);
    assert!(handler.close_completed(1, "c-1").is_none());
}

/// Drain dispatch: matched sessions get graceful closes at admission,
/// per-id accounting flows through `session_closed`, the force deadline
/// closes the remainder via `tick`, and the **completion transition
/// itself** produces the terminal `DrainResult` proactively with the
/// initiating request id — no command replay required.
#[tokio::test(start_paused = true)]
async fn drain_dispatch_runs_graceful_then_force() {
    let mut handler = ControlCommandHandler::new();
    handler.on_session_negotiated(true);
    handler.set_applied_generation(7);
    let mut a = register(&mut handler, 1, "sql-a", "tidb-a");
    let mut b = register(&mut handler, 2, "sql-a", "tidb-a");
    let mut other = register(&mut handler, 3, "sql-b", "tidb-a");

    let now = Instant::now();
    let now_ms: u64 = 1_000_000;
    let command = DrainCommand {
        drain_id: "d-1".to_owned(),
        listener_names: vec!["sql-a".to_owned()],
        backend_ids: Vec::new(),
        graceful_deadline_unix_millis: now_ms + 10_000,
        force_deadline_unix_millis: now_ms + 20_000,
        command_sequence: 1,
    };
    let inbound = envelope(30, 7, Body::DrainCommand(command.clone()));
    let out = handler.handle_envelope(&inbound, now, now_ms);
    assert_eq!(out.len(), 1, "start answers progress");
    assert_eq!(out[0].request_id, 30);
    let Some(Body::DrainResult(progress)) = &out[0].body else {
        unreachable!("start answers progress")
    };
    assert_eq!(progress.active_connections, 2, "scoped to sql-a only");
    assert_eq!(
        a.control.try_recv().map(|d| d.control),
        Ok(SessionControl::GracefulClose),
        "matched session asked to close at a safe point"
    );
    assert_eq!(
        b.control.try_recv().map(|d| d.control),
        Ok(SessionControl::GracefulClose)
    );
    assert!(
        other.control.try_recv().map(|d| d.control).is_err(),
        "out-of-scope listener untouched"
    );

    // One session drains gracefully: its CLOSED event is owed, but the
    // drain is not complete yet — no premature terminal.
    let closed = handler.session_closed(
        1,
        false,
        ErrorSource::ClientNetwork,
        dataplane::route_control::TrafficTotals::default(),
    );
    assert_eq!(closed.len(), 1, "CLOSED lifecycle event only");
    assert!(matches!(closed[0].body, Some(Body::ConnectionEvent(_))));

    // Past the force deadline the remainder is closed immediately —
    // exactly once, however many ticks land.
    let force_by = now + Duration::from_secs(20);
    assert!(handler.tick(force_by + Duration::from_millis(1)).is_empty());
    assert_eq!(
        b.control.try_recv().map(|d| d.control),
        Ok(SessionControl::CloseImmediate)
    );
    let _ = handler.tick(force_by + Duration::from_millis(2));
    let _ = handler.tick(force_by + Duration::from_millis(3));
    assert!(
        b.control.try_recv().map(|d| d.control).is_err(),
        "repeated force ticks never duplicate CloseImmediate"
    );

    // The LAST matched session closing is the completion transition:
    // the terminal DrainResult goes out proactively, addressed with
    // the initiating request id.
    let closed = handler.session_closed(
        2,
        true,
        ErrorSource::Proxy,
        dataplane::route_control::TrafficTotals::default(),
    );
    assert_eq!(closed.len(), 2, "CLOSED event plus the proactive terminal");
    assert!(matches!(closed[0].body, Some(Body::ConnectionEvent(_))));
    assert_eq!(
        closed[1].request_id, 30,
        "the terminal answers the initiating drain request"
    );
    let Some(Body::DrainResult(done)) = &closed[1].body else {
        unreachable!("completion transition produces the terminal")
    };
    assert!(done.complete);
    assert_eq!(done.gracefully_closed, 1);
    assert_eq!(done.force_closed, 1);

    // A duplicate command still replays the final result inline.
    let dup = envelope(31, 7, Body::DrainCommand(command.clone()));
    let out = handler.handle_envelope(&dup, force_by, now_ms + 20_001);
    assert_eq!(out[0].request_id, 31);
    let Some(Body::DrainResult(replayed)) = &out[0].body else {
        unreachable!("completed drain replays")
    };
    assert!(replayed.complete);

    // An evicted/obsolete duplicate answers DUPLICATE_REQUEST.
    let obsolete = DrainCommand {
        drain_id: "d-0".to_owned(),
        command_sequence: 1,
        ..command
    };
    let out = handler.handle_envelope(
        &envelope(32, 7, Body::DrainCommand(obsolete)),
        force_by,
        now_ms + 20_002,
    );
    let Some(Body::DrainResult(answer)) = &out[0].body else {
        unreachable!("obsolete answers a result")
    };
    assert_eq!(answer.code(), ErrorCode::DuplicateRequest);
}

/// A zero-match drain completes on arrival: its very first answer is
/// already the terminal result, not an empty progress that never
/// resolves.
#[tokio::test(start_paused = true)]
async fn zero_match_drain_answers_terminal_immediately() {
    let mut handler = ControlCommandHandler::new();
    handler.on_session_negotiated(true);
    handler.set_applied_generation(7);
    let _session = register(&mut handler, 1, "sql-a", "tidb-a");

    let command = DrainCommand {
        drain_id: "d-none".to_owned(),
        listener_names: vec!["no-such-listener".to_owned()],
        backend_ids: Vec::new(),
        graceful_deadline_unix_millis: 1_010_000,
        force_deadline_unix_millis: 1_020_000,
        command_sequence: 1,
    };
    let out = handler.handle_envelope(
        &envelope(33, 7, Body::DrainCommand(command)),
        Instant::now(),
        1_000_000,
    );
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].request_id, 33);
    let Some(Body::DrainResult(done)) = &out[0].body else {
        unreachable!("zero-match start answers the terminal")
    };
    assert!(done.complete, "no sessions matched: complete immediately");
    assert_eq!(done.active_connections, 0);
}

/// Malformed wire deadlines (force before graceful, or absurdly far
/// ahead) are rejected as protocol violations before any conversion —
/// hostile values never reach `Instant` arithmetic.
#[tokio::test(start_paused = true)]
async fn malformed_drain_deadlines_rejected() {
    let mut handler = ControlCommandHandler::new();
    handler.on_session_negotiated(true);
    handler.set_applied_generation(7);
    let now = Instant::now();

    let inverted = DrainCommand {
        drain_id: "d-bad".to_owned(),
        listener_names: Vec::new(),
        backend_ids: Vec::new(),
        graceful_deadline_unix_millis: 1_020_000,
        force_deadline_unix_millis: 1_010_000,
        command_sequence: 1,
    };
    let out = handler.handle_envelope(
        &envelope(40, 7, Body::DrainCommand(inverted)),
        now,
        1_000_000,
    );
    assert_eq!(error_code(&out[0]), Some(ErrorCode::ProtocolViolation));

    let absurd = DrainCommand {
        drain_id: "d-far".to_owned(),
        listener_names: Vec::new(),
        backend_ids: Vec::new(),
        graceful_deadline_unix_millis: u64::MAX,
        force_deadline_unix_millis: u64::MAX,
        command_sequence: 2,
    };
    let out = handler.handle_envelope(&envelope(41, 7, Body::DrainCommand(absurd)), now, 1_000_000);
    assert_eq!(error_code(&out[0]), Some(ErrorCode::ProtocolViolation));
}

/// The handler is long-lived across control reconnects: an epoch-N
/// terminal whose result was lost replays verbatim after an epoch-N+1
/// negotiation and reconcile — the gate state (tombstones, unacked
/// results, watermarks) survives; only the peer mode is updated. The
/// replay envelope declares the rehydration capability it rides on.
#[tokio::test(start_paused = true)]
async fn handler_survives_reconnect_and_replays_lost_terminal() {
    let mut handler = ControlCommandHandler::new();
    handler.on_session_negotiated(true);
    let mut session = register(&mut handler, 1, "sql-a", "tidb-a");
    let now = Instant::now();

    // Epoch N: a redirect completes but its result is lost in transit.
    let inbound = envelope(40, 7, Body::RedirectCommand(redirect(1, "r-1", 1)));
    let _ = handler.handle_envelope(&inbound, now, 4_000);
    assert_eq!(
        session.control.try_recv().map(|d| d.control),
        Ok(SessionControl::Redirect)
    );
    let Some(lost) = handler.redirect_completed(1, "r-1", true, "tidb-b", ErrorCode::Ok) else {
        unreachable!("terminal produced")
    };
    let Some(Body::RedirectResult(lost)) = lost.body else {
        unreachable!("terminal is a redirect result")
    };

    // Epoch N+1: a new control session negotiates (mode update only —
    // the gate is NOT rebuilt), then reconciles.
    handler.on_session_negotiated(true);
    let request = handler.build_reconcile_request(7);
    assert_eq!(request.connections[0].pending_redirect_id, "r-1");
    assert_eq!(request.connections[0].last_redirect_command_sequence, 1);

    let snapshot = ReconcileSnapshot {
        applied_generation: 7,
        connection_event_sequence: 0,
        metrics_sequence: 0,
        metering_sequence: 0,
        connections: vec![ReconcileConnection {
            connection_id: 1,
            backend_id: "tidb-a".to_owned(),
            namespace: "ns-a".to_owned(),
            redirect_pending: true,
            generation: 7,
            pending_redirect_id: "r-1".to_owned(),
            identity: None,
            last_redirect_command_sequence: 1,
        }],
    };
    let out = handler.handle_envelope(
        &envelope(50, 7, Body::ReconcileSnapshot(snapshot)),
        now,
        4_001,
    );
    assert_eq!(out.len(), 1);
    assert_eq!(
        out[0].body,
        Some(Body::RedirectResult(lost)),
        "the exact lost terminal replays across the epoch"
    );
    assert_eq!(
        out[0].required_capabilities,
        vec![ControlCapability::ReconcileSessionRehydration as u64],
        "the replay declares the rehydration capability"
    );
}

/// The full production entry: an already-force-expired drain command
/// force-closes immediately without a graceful ask, and ghost
/// connections in a reconcile snapshot come back as CLOSED event
/// envelopes built from the peer's identity view, deferred to the
/// sender's allocator for their sequence ids.
#[tokio::test(start_paused = true)]
async fn handle_envelope_production_path() {
    let mut handler = ControlCommandHandler::new();
    handler.on_session_negotiated(true);
    handler.set_applied_generation(7);
    let mut session = register(&mut handler, 1, "sql-a", "tidb-a");

    let now = Instant::now();
    let now_ms: u64 = 5_000_000;

    // An already-force-expired drain force-closes immediately.
    let expired = envelope(
        71,
        7,
        Body::DrainCommand(DrainCommand {
            drain_id: "d-exp".to_owned(),
            listener_names: Vec::new(),
            backend_ids: Vec::new(),
            graceful_deadline_unix_millis: now_ms - 2_000,
            force_deadline_unix_millis: now_ms - 1_000,
            command_sequence: 1,
        }),
    );
    let out = handler.handle_envelope(&expired, now, now_ms);
    assert!(matches!(out[0].body, Some(Body::DrainResult(_))));
    assert_eq!(
        session.control.try_recv().map(|d| d.control),
        Ok(SessionControl::CloseImmediate),
        "expired force deadline skips the graceful ask entirely"
    );

    // Ghosts in a reconcile snapshot become CLOSED envelopes whose
    // sequence ids are allocated at send time.
    let mut fresh = ControlCommandHandler::new();
    fresh.on_session_negotiated(true);
    let snapshot = envelope(
        72,
        7,
        Body::ReconcileSnapshot(ReconcileSnapshot {
            applied_generation: 7,
            connection_event_sequence: 0,
            metrics_sequence: 0,
            metering_sequence: 0,
            connections: vec![ReconcileConnection {
                connection_id: 9,
                backend_id: "tidb-a".to_owned(),
                namespace: "ns-a".to_owned(),
                redirect_pending: false,
                generation: 7,
                pending_redirect_id: String::new(),
                identity: Some(identity(9)),
                last_redirect_command_sequence: 0,
            }],
        }),
    );
    let out = fresh.handle_envelope(&snapshot, now, now_ms);
    assert_eq!(out.len(), 1, "one ghost, one CLOSED event");
    let Some(Body::ConnectionEvent(event)) = &out[0].body else {
        unreachable!("ghost answered with a CLOSED event")
    };
    assert_eq!(event.connection.as_ref().map(|i| i.connection_id), Some(9));
    assert_eq!(
        out[0].request_id, 0,
        "self-originated: the dispatch loop allocates the sequence id"
    );
}

/// A close whose session channel is gone terminates immediately instead
/// of wedging the gate in Closing.
#[tokio::test(start_paused = true)]
async fn close_forward_failure_terminates() {
    let mut handler = ControlCommandHandler::new();
    handler.on_session_negotiated(true);
    let session = register(&mut handler, 1, "sql-a", "tidb-a");
    drop(session); // the control channel closes

    let close = CloseCommand {
        connection_id: 1,
        close_id: "c-dead".to_owned(),
        error_source: 0,
        reason: String::new(),
        force: false,
    };
    let now = Instant::now();
    let out = handler.handle_envelope(&envelope(80, 7, Body::CloseCommand(close.clone())), now, 1);
    let Some(Body::CloseResult(result)) = &out[0].body else {
        unreachable!("dead session close terminates immediately")
    };
    assert!(result.accepted);
    assert_eq!(out[0].request_id, 80, "terminal answers the initiating id");
    // The duplicate replays the terminal, proving the gate moved on.
    let out = handler.handle_envelope(&envelope(81, 7, Body::CloseCommand(close)), now, 2);
    assert!(matches!(out[0].body, Some(Body::CloseResult(_))));
}

/// Correlated Go answers multiplex to their owning session's response
/// channel; a missing session, a missing channel, and a jammed slot are
/// each answered with a typed error — never silently dropped.
#[tokio::test(start_paused = true)]
async fn session_responses_route_to_owner() {
    let mut handler = ControlCommandHandler::new();
    handler.on_session_negotiated(true);
    let now = Instant::now();

    // A routing session registers a 1-slot response channel.
    let (control_tx, _control_rx) = mpsc::channel(8);
    let (resp_tx, mut resp_rx) = mpsc::channel(1);
    handler.register_session(identity(1), "ns-a", 7, "sql-a", control_tx, Some(resp_tx));
    // The session sent RouteRequest id=90 and awaits its assignment.
    handler.expect_response(1, 90, ResponseKind::RouteAssignment);

    let assignment = envelope(
        90,
        7,
        Body::RouteAssignment(RouteAssignment {
            connection_id: 1,
            assignment_id: "a-1".to_owned(),
            backend_id: "tidb-a".to_owned(),
            backend_address: "10.0.0.1:4000".to_owned(),
            cluster_name: String::new(),
            keyspace: String::new(),
            healthy: true,
            local: true,
            code: 0,
            detail: String::new(),
        }),
    );
    assert!(
        handler.handle_envelope(&assignment, now, 1).is_empty(),
        "routed to the owner, nothing outbound"
    );

    // The slot holds one outstanding answer: overflow is a violation
    // the peer hears about, not a silent drop.
    let out = handler.handle_envelope(&assignment, now, 2);
    assert_eq!(error_code(&out[0]), Some(ErrorCode::ProtocolViolation));

    let Ok(delivered) = resp_rx.try_recv() else {
        unreachable!("the session owns the answer")
    };
    assert_eq!(delivered.request_id, 90);

    // Unknown connection: reconciliation required.
    let orphan = envelope(
        91,
        7,
        Body::RouteAssignment(RouteAssignment {
            connection_id: 99,
            assignment_id: "a-x".to_owned(),
            backend_id: String::new(),
            backend_address: String::new(),
            cluster_name: String::new(),
            keyspace: String::new(),
            healthy: false,
            local: true,
            code: 0,
            detail: String::new(),
        }),
    );
    let out = handler.handle_envelope(&orphan, now, 3);
    assert_eq!(error_code(&out[0]), Some(ErrorCode::ReconciliationRequired));

    // A session without a response channel cannot own the answer.
    let mut no_channel = ControlCommandHandler::new();
    no_channel.on_session_negotiated(true);
    let _plain = register(&mut no_channel, 2, "sql-a", "tidb-a");
    let misdirected = envelope(
        92,
        7,
        Body::RouteAssignment(RouteAssignment {
            connection_id: 2,
            assignment_id: "a-2".to_owned(),
            backend_id: String::new(),
            backend_address: String::new(),
            cluster_name: String::new(),
            keyspace: String::new(),
            healthy: false,
            local: true,
            code: 0,
            detail: String::new(),
        }),
    );
    let out = no_channel.handle_envelope(&misdirected, now, 4);
    assert_eq!(error_code(&out[0]), Some(ErrorCode::ProtocolViolation));
    assert_eq!(no_channel.unrouted(), 1);
}

/// A body that has no legal route on the Rust side (for example a
/// `MeteringBatch` arriving inbound) is answered with a typed protocol
/// error and counted — nothing is silently dropped.
#[tokio::test(start_paused = true)]
async fn unroutable_bodies_are_answered_not_dropped() {
    let mut handler = ControlCommandHandler::new();
    handler.on_session_negotiated(true);
    let inbound = envelope(
        95,
        0,
        Body::MeteringBatch(control_proto::v1::MeteringBatch {
            sequence: 1,
            deltas: Vec::new(),
        }),
    );
    let out = handler.handle_envelope(&inbound, Instant::now(), 1);
    assert_eq!(error_code(&out[0]), Some(ErrorCode::ProtocolViolation));
    assert_eq!(handler.unrouted(), 1);
}

/// Force-phase `CloseImmediate` is marked delivered only when the send
/// succeeds: a full session channel stays unmarked and retries on the
/// next tick instead of losing the close.
#[tokio::test(start_paused = true)]
async fn force_close_marks_only_on_delivery() {
    let mut handler = ControlCommandHandler::new();
    handler.on_session_negotiated(true);
    handler.set_applied_generation(7);

    // Capacity-1 control channel, pre-filled so the force send jams.
    let (tx, mut rx) = mpsc::channel(1);
    handler.register_session(identity(1), "ns-a", 7, "sql-a", tx.clone(), None);
    let _ = handler.set_backend(1, "tidb-a");
    assert!(
        tx.try_send(SessionDirective::bare(SessionControl::GracefulClose))
            .is_ok(),
        "pre-fill the slot"
    );

    let now = Instant::now();
    let now_ms: u64 = 1_000_000;
    let command = DrainCommand {
        drain_id: "d-jam".to_owned(),
        listener_names: Vec::new(),
        backend_ids: Vec::new(),
        graceful_deadline_unix_millis: now_ms.saturating_sub(2_000),
        force_deadline_unix_millis: now_ms.saturating_sub(1_000),
        command_sequence: 1,
    };
    // Already force-expired: the admission tries CloseImmediate at
    // once, but the jammed channel must NOT count as notified.
    let _ = handler.handle_envelope(&envelope(96, 7, Body::DrainCommand(command)), now, now_ms);
    assert_eq!(
        rx.try_recv().map(|d| d.control),
        Ok(SessionControl::GracefulClose),
        "only the pre-filled message is in the slot"
    );
    assert!(rx.try_recv().is_err(), "the force send was jammed out");

    // The slot is free now: the next tick delivers exactly once.
    assert!(handler.tick(now + Duration::from_millis(1)).is_empty());
    assert_eq!(
        rx.try_recv().map(|d| d.control),
        Ok(SessionControl::CloseImmediate)
    );
    let _ = handler.tick(now + Duration::from_millis(2));
    assert!(rx.try_recv().is_err(), "delivered exactly once");
}

// ---------------------------------------------------------------------
// Dispatch-loop tests: reconnect automation and request-id lineage.
// ---------------------------------------------------------------------

/// Test double for the transport sender: a checked monotonic allocator
/// plus a capture of every sent envelope.
struct FakeSender {
    next: AtomicU64,
    sent: Mutex<Vec<(ControlEnvelope, Option<u64>)>>,
}

impl FakeSender {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            next: AtomicU64::new(0),
            sent: Mutex::new(Vec::new()),
        })
    }

    fn sent(&self) -> Vec<ControlEnvelope> {
        self.sent_with_scope()
            .into_iter()
            .map(|(envelope, _)| envelope)
            .collect()
    }

    fn sent_with_scope(&self) -> Vec<(ControlEnvelope, Option<u64>)> {
        let Ok(sent) = self.sent.lock() else {
            unreachable!("sent lock poisoned")
        };
        sent.clone()
    }

    fn push(&self, envelope: ControlEnvelope, scope: Option<u64>) {
        let Ok(mut sent) = self.sent.lock() else {
            unreachable!("sent lock poisoned")
        };
        sent.push((envelope, scope));
    }
}

impl DispatchSender for FakeSender {
    fn allocate_request_id(&self) -> Option<u64> {
        Some(self.next.fetch_add(1, Ordering::Relaxed) + 1)
    }

    async fn send_envelope(&self, envelope: ControlEnvelope) -> Result<(), TransportError> {
        self.push(envelope, None);
        Ok(())
    }

    async fn send_session_scoped(
        &self,
        envelope: ControlEnvelope,
        epoch: u64,
    ) -> Result<(), TransportError> {
        self.push(envelope, Some(epoch));
        Ok(())
    }
}

struct LoopHarness {
    sender: Arc<FakeSender>,
    state_tx: watch::Sender<ConnectionState>,
    notice_tx: mpsc::Sender<DispatchNotice>,
    inbound_tx: mpsc::Sender<TaggedEnvelope>,
    snapshot_rx: mpsc::Receiver<TaggedEnvelope>,
    stats: Arc<dataplane::control_dispatch::DispatchStats>,
    task: tokio::task::JoinHandle<Result<(), DispatchFatal>>,
}

fn session_meta(serial: u64, epoch: u64) -> SessionMeta {
    SessionMeta {
        serial,
        epoch,
        peer_process_id: Arc::from("go-fixture"),
        peer_started_unix_millis: 1_700_000_000_000,
    }
}

fn session_meta_as(process_id: &str, serial: u64, epoch: u64) -> SessionMeta {
    SessionMeta {
        serial,
        epoch,
        peer_process_id: Arc::from(process_id),
        peer_started_unix_millis: 1_700_000_000_000,
    }
}

fn tagged_on(envelope: ControlEnvelope, serial: u64, epoch: u64) -> TaggedEnvelope {
    TaggedEnvelope {
        envelope,
        origin: session_meta(serial, epoch),
    }
}

fn spawn_loop_with_tick(handler: ControlCommandHandler, tick: Duration) -> LoopHarness {
    let sender = FakeSender::new();
    let (state_tx, state_rx) = watch::channel(ConnectionState::Disconnected);
    let (inbound_tx, inbound_rx) = mpsc::channel(16);
    let (notice_tx, notice_rx) = mpsc::channel(16);
    let (snapshot_tx, snapshot_rx) = mpsc::channel(4);
    let stats = handler.stats();
    let task = tokio::spawn(run_control_dispatch(
        handler,
        Arc::clone(&sender),
        state_rx,
        inbound_rx,
        notice_rx,
        snapshot_tx,
        tick,
        || 1_000_000,
    ));
    LoopHarness {
        sender,
        state_tx,
        notice_tx,
        inbound_tx,
        snapshot_rx,
        stats,
        task,
    }
}

/// Sends a minimal (capability-less, so no automatic `ReconcileRequest`)
/// `Connected` for the go-fixture lineage so a harness has a live
/// session — the dispatch loop only processes inbound frames while a
/// session is live (a frame with no live lineage is deferred).
fn connect_go_fixture(harness: &LoopHarness, serial: u64) {
    harness
        .state_tx
        .send(ConnectionState::Connected {
            epoch: serial,
            serial,
            capabilities: 0,
            peer_process_id: Arc::from("go-fixture"),
            peer_started_unix_millis: 1_700_000_000_000,
        })
        .ok();
}

fn spawn_loop(handler: ControlCommandHandler) -> LoopHarness {
    spawn_loop_with_tick(handler, Duration::from_secs(3600))
}

/// Both capability bits the production reconnect automation gates on.
fn full_caps() -> u64 {
    (1u64 << (ControlCapability::ReconcileConnections as u64))
        | (1u64 << (ControlCapability::ReconcileSessionRehydration as u64))
}

async fn wait_for_sent(sender: &Arc<FakeSender>, count: usize) -> Vec<ControlEnvelope> {
    for _ in 0..1_000 {
        let sent = sender.sent();
        if sent.len() >= count {
            return sent;
        }
        tokio::task::yield_now().await;
    }
    unreachable!(
        "dispatch loop never sent {count} envelopes: {:?}",
        sender.sent()
    );
}

/// Every `Connected` transition automatically reconciles and replays
/// unacknowledged metering — with allocator-issued request ids and the
/// epoch's own capability mask deciding the peer mode.
#[tokio::test(start_paused = true)]
async fn connected_transition_reconciles_and_replays_metering() {
    let mut handler = ControlCommandHandler::new();
    handler.set_applied_generation(7);
    assert!(
        handler
            .metering()
            .record(MeteringDelta {
                keyspace: "ks-1".to_owned(),
                backend_id: "tidb-a".to_owned(),
                public_endpoint: false,
                response_bytes: 128,
                cross_location_bytes: 0,
            })
            .is_ok()
    );
    let Ok(Some(batch)) = handler.seal_metering() else {
        unreachable!("one open batch seals")
    };

    let harness = spawn_loop(handler);
    harness
        .state_tx
        .send(ConnectionState::Connected {
            epoch: 1,
            serial: 1,
            capabilities: full_caps(),
            peer_process_id: Arc::from("go-fixture"),
            peer_started_unix_millis: 1_700_000_000_000,
        })
        .ok();

    let sent = wait_for_sent(&harness.sender, 2).await;
    let scoped = harness.sender.sent_with_scope();
    let Some(Body::ReconcileRequest(request)) = &sent[0].body else {
        unreachable!("first automatic send is the reconcile request")
    };
    assert_eq!(request.known_generation, 7);
    assert_eq!(request.last_metering_sequence, batch.sequence);
    assert!(sent[0].request_id > 0, "allocator-issued id");
    assert_eq!(
        scoped[0].1,
        Some(1),
        "the reconcile request is session-scoped to its exact epoch"
    );
    assert_eq!(
        sent[0].required_capabilities,
        vec![
            ControlCapability::ReconcileConnections as u64,
            ControlCapability::ReconcileSessionRehydration as u64,
        ],
        "the request declares the capabilities it rides on"
    );
    let Some(Body::MeteringBatch(replayed)) = &sent[1].body else {
        unreachable!("unacked metering replays after the reconcile")
    };
    assert_eq!(replayed, &batch, "the exact sealed batch replays");
    assert_eq!(scoped[1].1, None, "metering batches are durable");
    assert!(
        sent[1].request_id > sent[0].request_id,
        "one checked allocator: ids strictly increase"
    );

    harness.task.abort();
}

/// Without `RECONCILE_CONNECTIONS` no reconcile request is sent — no
/// ack path can exist, so the ledger's bounded unacked retention is
/// the explicit backpressure — while durable metering still replays.
#[tokio::test(start_paused = true)]
async fn no_reconcile_capability_skips_request_and_replays_durably() {
    let mut handler = ControlCommandHandler::new();
    assert!(
        handler
            .metering()
            .record(MeteringDelta {
                keyspace: "ks-1".to_owned(),
                backend_id: "tidb-a".to_owned(),
                public_endpoint: false,
                response_bytes: 64,
                cross_location_bytes: 0,
            })
            .is_ok()
    );
    assert!(handler.seal_metering().is_ok());
    let harness = spawn_loop(handler);
    harness
        .state_tx
        .send(ConnectionState::Connected {
            epoch: 1,
            serial: 1,
            capabilities: 0,
            peer_process_id: Arc::from("go-fixture"),
            peer_started_unix_millis: 1_700_000_000_000,
        })
        .ok();
    let sent = wait_for_sent(&harness.sender, 1).await;
    assert!(
        matches!(sent[0].body, Some(Body::MeteringBatch(_))),
        "only the durable metering replay goes out"
    );
    assert!(
        !sent
            .iter()
            .any(|envelope| matches!(envelope.body, Some(Body::ReconcileRequest(_)))),
        "no ReconcileRequest without RECONCILE_CONNECTIONS"
    );
    harness.task.abort();
}

/// CLOSED lifecycle events take allocator ids, and the recorded maximum
/// feeds the next reconcile request's event-sequence watermark — the
/// id lineage the Go dedup and rehydration keys on.
#[tokio::test(start_paused = true)]
async fn closed_event_ids_feed_reconcile_watermark() {
    let mut handler = ControlCommandHandler::new();
    handler.set_applied_generation(7);
    let harness = spawn_loop(handler);

    let (control_tx, _control_rx) = mpsc::channel(8);
    harness
        .notice_tx
        .send(DispatchNotice::RegisterSession {
            identity: identity(1),
            namespace: "ns-a".to_owned(),
            snapshot_generation: 7,
            listener_name: "sql-a".to_owned(),
            control: control_tx,
            responses: None,
            applied: tokio::sync::oneshot::channel().0,
        })
        .await
        .ok();
    harness
        .notice_tx
        .send(DispatchNotice::SessionClosed {
            connection_id: 1,
            forced: false,
            error_source: ErrorSource::ClientNetwork,
            traffic: dataplane::route_control::TrafficTotals::default(),
        })
        .await
        .ok();

    let sent = wait_for_sent(&harness.sender, 1).await;
    let Some(Body::ConnectionEvent(_)) = &sent[0].body else {
        unreachable!("the close owes its CLOSED event")
    };
    let event_id = sent[0].request_id;
    assert!(event_id > 0, "allocator-issued event sequence");

    // The next session's automatic reconcile reports that id as the
    // event-sequence watermark.
    harness
        .state_tx
        .send(ConnectionState::Connected {
            epoch: 2,
            serial: 2,
            capabilities: full_caps(),
            peer_process_id: Arc::from("go-fixture"),
            peer_started_unix_millis: 1_700_000_000_000,
        })
        .ok();
    let sent = wait_for_sent(&harness.sender, 2).await;
    let Some(Body::ReconcileRequest(request)) = &sent[1].body else {
        unreachable!("reconnect reconciles automatically")
    };
    assert_eq!(
        request.last_connection_event_sequence, event_id,
        "the CLOSED event's allocator id is the reconcile watermark"
    );

    harness.task.abort();
}

/// Fail-closed response correlation: an answer with the wrong
/// initiating id, the wrong body kind, or no armed expectation is
/// refused as a protocol violation — a stale answer can neither occupy
/// the one-slot channel nor be mis-consumed by a newer exchange.
#[tokio::test(start_paused = true)]
async fn session_response_correlation_is_fail_closed() {
    let mut handler = ControlCommandHandler::new();
    handler.on_session_negotiated(true);
    let now = Instant::now();
    let (control_tx, _control_rx) = mpsc::channel(8);
    let (resp_tx, mut resp_rx) = mpsc::channel(1);
    handler.register_session(identity(1), "ns-a", 7, "sql-a", control_tx, Some(resp_tx));

    let assignment_body = |request_id: u64| {
        envelope(
            request_id,
            7,
            Body::RouteAssignment(RouteAssignment {
                connection_id: 1,
                assignment_id: "a-1".to_owned(),
                backend_id: "tidb-a".to_owned(),
                backend_address: "10.0.0.1:4000".to_owned(),
                cluster_name: String::new(),
                keyspace: String::new(),
                healthy: true,
                local: true,
                code: 0,
                detail: String::new(),
            }),
        )
    };

    // Nothing armed: unsolicited.
    let out = handler.handle_envelope(&assignment_body(90), now, 1);
    assert_eq!(error_code(&out[0]), Some(ErrorCode::ProtocolViolation));
    assert!(resp_rx.try_recv().is_err(), "nothing delivered");

    // Armed for id 90: a stale answer under id 41 is refused.
    handler.expect_response(1, 90, ResponseKind::RouteAssignment);
    let out = handler.handle_envelope(&assignment_body(41), now, 2);
    assert_eq!(error_code(&out[0]), Some(ErrorCode::ProtocolViolation));
    assert!(resp_rx.try_recv().is_err(), "mismatched id never delivered");

    // Wrong body kind under the right id is refused too.
    let decision = envelope(
        90,
        7,
        Body::HandshakeDecision(control_proto::v1::HandshakeDecision {
            connection_id: 1,
            accept: true,
            retry: false,
            code: 0,
            client_message: String::new(),
            namespace: String::new(),
        }),
    );
    let out = handler.handle_envelope(&decision, now, 3);
    assert_eq!(error_code(&out[0]), Some(ErrorCode::ProtocolViolation));
    assert!(
        resp_rx.try_recv().is_err(),
        "mismatched kind never delivered"
    );

    // The exact pair delivers — and stays armed for an updated push
    // under the same initiating id.
    assert!(
        handler
            .handle_envelope(&assignment_body(90), now, 4)
            .is_empty()
    );
    let Ok(delivered) = resp_rx.try_recv() else {
        unreachable!("the armed pair delivers")
    };
    assert_eq!(delivered.request_id, 90);
    assert!(
        handler
            .handle_envelope(&assignment_body(90), now, 5)
            .is_empty()
    );
    assert!(resp_rx.try_recv().is_ok(), "updated push under the same id");
}

/// Direction enforcement: Rust→Go bodies arriving inbound
/// (`HandshakeResult`, `SnapshotResult`) are protocol violations, not
/// routable responses.
#[tokio::test(start_paused = true)]
async fn wrong_direction_bodies_are_violations() {
    let mut handler = ControlCommandHandler::new();
    handler.on_session_negotiated(true);
    let _session = register(&mut handler, 1, "sql-a", "tidb-a");
    let now = Instant::now();

    let result = envelope(
        60,
        7,
        Body::HandshakeResult(control_proto::v1::HandshakeResult {
            connection_id: 1,
            backend_id: "tidb-a".to_owned(),
            ..control_proto::v1::HandshakeResult::default()
        }),
    );
    let out = handler.handle_envelope(&result, now, 1);
    assert_eq!(error_code(&out[0]), Some(ErrorCode::ProtocolViolation));

    let snapshot_result = envelope(
        61,
        7,
        Body::SnapshotResult(control_proto::v1::SnapshotResult {
            applied_generation: 7,
            code: 0,
            detail: String::new(),
        }),
    );
    let out = handler.handle_envelope(&snapshot_result, now, 2);
    assert_eq!(error_code(&out[0]), Some(ErrorCode::ProtocolViolation));
    assert_eq!(handler.unrouted(), 2);
}

/// Stale-epoch reconcile snapshots are superseded — the current
/// session\'s automatic request gets a fresh one — while commands from
/// any epoch still flow through the gate\'s own cross-epoch invariants;
/// without `RECONCILE_CONNECTIONS` an inbound snapshot is unsolicited.
#[tokio::test(start_paused = true)]
async fn reconcile_snapshot_epoch_and_capability_policy() {
    let mut handler = ControlCommandHandler::new();
    handler.on_connected(
        5,
        full_caps(),
        5,
        Arc::from("go-fixture"),
        1_700_000_000_000,
    );
    let now = Instant::now();

    let snapshot_from = |origin: u64| ControlEnvelope {
        request_id: 50,
        generation: 7,
        control_epoch: origin,
        body: Some(Body::ReconcileSnapshot(ReconcileSnapshot {
            applied_generation: 7,
            connection_event_sequence: 0,
            metrics_sequence: 0,
            metering_sequence: 0,
            connections: Vec::new(),
        })),
        ..ControlEnvelope::default()
    };

    // Origin epoch 4 under current epoch 5: superseded, counted.
    assert!(
        handler
            .handle_envelope(&snapshot_from(4), now, 1)
            .is_empty()
    );
    assert_eq!(handler.stale_dropped(), 1);

    // The current epoch\'s snapshot processes normally.
    assert!(
        handler
            .handle_envelope(&snapshot_from(5), now, 2)
            .is_empty()
    );
    assert_eq!(handler.stale_dropped(), 1);

    // A stale-epoch COMMAND still flows through the gate.
    let mut session = register(&mut handler, 1, "sql-a", "tidb-a");
    let mut command = envelope(51, 7, Body::RedirectCommand(redirect(1, "r-old", 1)));
    command.control_epoch = 4;
    assert!(handler.handle_envelope(&command, now, 3).is_empty());
    assert_eq!(
        session.control.try_recv().map(|d| d.control),
        Ok(SessionControl::Redirect)
    );

    // Without cap 2 an inbound snapshot is unsolicited.
    let mut legacy = ControlCommandHandler::new();
    legacy.on_connected(
        6,
        1u64 << (ControlCapability::ReconcileSessionRehydration as u64),
        6,
        Arc::from("go-fixture"),
        1_700_000_000_000,
    );
    let out = legacy.handle_envelope(&snapshot_from(6), now, 4);
    assert_eq!(error_code(&out[0]), Some(ErrorCode::ProtocolViolation));
}

/// The metering production path end to end: session deltas arrive as
/// notices, the tick seals the batch onto the wire durably, and the
/// ledger retains it until a reconcile ack.
#[tokio::test(start_paused = true)]
async fn metering_notices_seal_and_send_on_tick() {
    let handler = ControlCommandHandler::new();
    let harness = spawn_loop_with_tick(handler, Duration::from_millis(50));
    let (metering_ack_tx, metering_ack_rx) = tokio::sync::oneshot::channel();
    harness
        .notice_tx
        .send(DispatchNotice::Metering {
            delta: Box::new(MeteringDelta {
                keyspace: "ks-1".to_owned(),
                backend_id: "tidb-a".to_owned(),
                public_endpoint: false,
                response_bytes: 256,
                cross_location_bytes: 0,
            }),
            ack: metering_ack_tx,
        })
        .await
        .ok();
    let Ok(Ok(())) = metering_ack_rx.await else {
        unreachable!("the ledger absorbed the delta and acked the producer")
    };
    // Paused clock: sleeping past the tick interval fires the ticker.
    tokio::time::sleep(Duration::from_millis(120)).await;
    let sent = wait_for_sent(&harness.sender, 1).await;
    let Some(Body::MeteringBatch(batch)) = &sent[0].body else {
        unreachable!("the tick seals and sends the recorded delta")
    };
    assert_eq!(batch.deltas.len(), 1);
    assert_eq!(batch.deltas[0].response_bytes, 256);
    let scoped = harness.sender.sent_with_scope();
    assert_eq!(scoped[0].1, None, "metering batches are durable");
    harness.task.abort();
}

/// `StateSnapshot` bodies forward — awaited — to the mandatory CTL-05
/// owner with their wire metadata intact.
#[tokio::test(start_paused = true)]
async fn state_snapshots_forward_to_owner() {
    let handler = ControlCommandHandler::new();
    let mut harness = spawn_loop(handler);
    connect_go_fixture(&harness, 1);
    let snapshot = ControlEnvelope {
        request_id: 77,
        generation: 9,
        body: Some(Body::StateSnapshot(control_proto::v1::StateSnapshot {
            config: None,
            backends: Vec::new(),
            namespaces: Vec::new(),
        })),
        ..ControlEnvelope::default()
    };
    harness
        .inbound_tx
        .send(tagged_on(snapshot, 1, 1))
        .await
        .ok();
    let Some(forwarded) = harness.snapshot_rx.recv().await else {
        unreachable!("the snapshot owner receives the envelope")
    };
    assert_eq!(forwarded.envelope.request_id, 77);
    assert_eq!(forwarded.envelope.generation, 9);
    assert_eq!(forwarded.origin.serial, 1);
    harness.task.abort();
}

// ---------------------------------------------------------------------
// B2 forwarder regressions: retained-frame ownership and the resume
// pump (global ≤1, exactly-once, cancel-safe).
// ---------------------------------------------------------------------

async fn forwarder_fixture(
    capacity: usize,
) -> (
    InboundForwarder,
    mpsc::Receiver<TaggedEnvelope>,
    watch::Sender<ConnectionState>,
) {
    let (inbound_tx, inbound_rx) = mpsc::channel(capacity);
    let (state_tx, state_rx) = watch::channel(ConnectionState::Connected {
        epoch: 1,
        serial: 1,
        capabilities: full_caps(),
        peer_process_id: Arc::from("go-fixture"),
        peer_started_unix_millis: 1_700_000_000_000,
    });
    let forwarder = InboundForwarder::new(inbound_tx, state_rx);
    let Ok(()) = forwarder.resume_session(session_meta(1, 1)).await else {
        unreachable!("the first session's resume sets the origin")
    };
    (forwarder, inbound_rx, state_tx)
}

fn frame(request_id: u64) -> ControlEnvelope {
    envelope(request_id, 7, Body::RedirectCommand(redirect(1, "r-f", 1)))
}

/// Regression: handler blocked (inbound full) + session teardown. The
/// in-flight frame is retained — not dropped, not blocking — and
/// `handle` errors so the read loop joins.
#[tokio::test(start_paused = true)]
async fn blocked_handle_retains_frame_on_teardown() {
    let (forwarder, mut inbound_rx, state_tx) = forwarder_fixture(1).await;
    let Ok(()) = forwarder.handle(frame(1)).await else {
        unreachable!("first frame fits the queue")
    };

    let blocked = forwarder.handle(frame(2));
    tokio::pin!(blocked);
    // The queue is full: the handle must be pending (backpressure).
    assert!(
        futures_pending(&mut blocked).await,
        "full inbound applies real backpressure"
    );
    // Teardown: the transport publishes Disconnected before joining.
    state_tx.send(ConnectionState::Disconnected).ok();
    let result = blocked.await;
    assert!(result.is_err(), "the read loop converges with an error");
    let Ok(true) = forwarder.retains_frame() else {
        unreachable!("exactly the in-flight frame is retained")
    };
    // Nothing was lost or double-delivered into the queue.
    assert_eq!(inbound_rx.try_recv().map(|e| e.envelope.request_id), Ok(1));
    assert!(inbound_rx.try_recv().is_err());
}

/// Regression: the retained frame is pumped by `resume_session` —
/// independent of any new inbound — exactly once, after which the slot
/// is empty and a new session\'s frames flow normally.
#[tokio::test(start_paused = true)]
async fn resume_pumps_retained_frame_exactly_once() {
    let (forwarder, mut inbound_rx, state_tx) = forwarder_fixture(1).await;
    let Ok(()) = forwarder.handle(frame(1)).await else {
        unreachable!("first frame fits")
    };
    let blocked = forwarder.handle(frame(2));
    tokio::pin!(blocked);
    assert!(futures_pending(&mut blocked).await);
    state_tx.send(ConnectionState::Disconnected).ok();
    assert!(blocked.await.is_err());

    // Reconnect: drain the queue (the dispatcher made progress), then
    // the transport calls resume before reading any new frame.
    assert_eq!(inbound_rx.try_recv().map(|e| e.envelope.request_id), Ok(1));
    state_tx
        .send(ConnectionState::Connected {
            epoch: 2,
            serial: 2,
            capabilities: full_caps(),
            peer_process_id: Arc::from("go-fixture"),
            peer_started_unix_millis: 1_700_000_000_000,
        })
        .ok();
    let Ok(()) = forwarder.resume_session(session_meta(2, 2)).await else {
        unreachable!("the pump delivers the retained frame")
    };
    assert_eq!(
        inbound_rx.try_recv().map(|e| e.envelope.request_id),
        Ok(2),
        "the retained frame arrives exactly once"
    );
    let Ok(false) = forwarder.retains_frame() else {
        unreachable!("the slot is empty after the pump")
    };
    // A second resume is a no-op: no duplicate delivery.
    let Ok(()) = forwarder.resume_session(session_meta(2, 2)).await else {
        unreachable!("empty pump succeeds")
    };
    assert!(inbound_rx.try_recv().is_err(), "no double delivery");
}

/// Regression: the session dies again while the resume pump is still
/// backpressured — the pump aborts, the slot stays intact, and the
/// NEXT session\'s resume delivers exactly once. The reader never
/// started, so no second frame can exist (global ≤ 1).
#[tokio::test(start_paused = true)]
async fn teardown_during_resume_keeps_single_frame() {
    let (forwarder, mut inbound_rx, state_tx) = forwarder_fixture(1).await;
    let Ok(()) = forwarder.handle(frame(1)).await else {
        unreachable!("first frame fits")
    };
    let blocked = forwarder.handle(frame(2));
    tokio::pin!(blocked);
    assert!(futures_pending(&mut blocked).await);
    state_tx.send(ConnectionState::Disconnected).ok();
    assert!(blocked.await.is_err());

    // Session 2 starts its pump while the queue is STILL full — and
    // dies before the pump can deliver.
    state_tx
        .send(ConnectionState::Connected {
            epoch: 2,
            serial: 2,
            capabilities: full_caps(),
            peer_process_id: Arc::from("go-fixture"),
            peer_started_unix_millis: 1_700_000_000_000,
        })
        .ok();
    let resume = forwarder.resume_session(session_meta(2, 2));
    tokio::pin!(resume);
    assert!(
        futures_pending(&mut resume).await,
        "the pump is backpressured by the full queue"
    );
    state_tx.send(ConnectionState::Disconnected).ok();
    assert!(resume.await.is_err(), "the pump aborts on teardown");
    let Ok(true) = forwarder.retains_frame() else {
        unreachable!("the frame is still retained — never lost")
    };

    // Session 3: the queue drains, the pump completes, exactly once.
    assert_eq!(inbound_rx.try_recv().map(|e| e.envelope.request_id), Ok(1));
    state_tx
        .send(ConnectionState::Connected {
            epoch: 3,
            serial: 3,
            capabilities: full_caps(),
            peer_process_id: Arc::from("go-fixture"),
            peer_started_unix_millis: 1_700_000_000_000,
        })
        .ok();
    let Ok(()) = forwarder.resume_session(session_meta(3, 3)).await else {
        unreachable!("the third session\'s pump delivers")
    };
    assert_eq!(inbound_rx.try_recv().map(|e| e.envelope.request_id), Ok(2));
    assert!(
        inbound_rx.try_recv().is_err(),
        "exactly once across sessions"
    );
    let Ok(false) = forwarder.retains_frame() else {
        unreachable!("slot empty at the end")
    };
}

/// Polls a pinned future a bounded number of times and reports whether
/// it is still pending (paused-clock friendly).
async fn futures_pending<F: Future + Unpin>(future: &mut F) -> bool {
    for _ in 0..50 {
        let poll = futures_poll_once(future).await;
        if poll.is_some() {
            return false;
        }
        tokio::task::yield_now().await;
    }
    true
}

async fn futures_poll_once<F: Future + Unpin>(future: &mut F) -> Option<F::Output> {
    use std::future::poll_fn;
    use std::task::Poll;
    poll_fn(
        |context| match std::pin::Pin::new(&mut *future).poll(context) {
            Poll::Ready(output) => Poll::Ready(Some(output)),
            Poll::Pending => Poll::Ready(None),
        },
    )
    .await
}

/// The ordering barrier end to end: an unacked metering batch is
/// retained; `Connected(2)` and an epoch-2-claimed `ReconcileSnapshot`
/// acking it race through the two queues — the barrier applies the
/// state first, the snapshot is CURRENT and acks; then a coalesced
/// `Connected(3) → Disconnected` swallows epoch 3 entirely, and an
/// epoch-3 snapshot arriving afterwards must be dropped as stale
/// (no active session), never acking. The retained batch reappears in
/// the next session's replay if and only if it was never acked.
#[tokio::test(start_paused = true)]
async fn stale_snapshot_after_coalesced_connect_never_acks() {
    let mut handler = ControlCommandHandler::new();
    handler.set_applied_generation(7);
    assert!(
        handler
            .metering()
            .record(MeteringDelta {
                keyspace: "ks-1".to_owned(),
                backend_id: "tidb-a".to_owned(),
                public_endpoint: false,
                response_bytes: 64,
                cross_location_bytes: 0,
            })
            .is_ok()
    );
    let Ok(Some(batch)) = handler.seal_metering() else {
        unreachable!("one batch seals")
    };
    let harness = spawn_loop(handler);

    // Coalesced connect: Connected(2) collapses into Disconnected
    // before the dispatcher can observe it (same watch slot).
    harness
        .state_tx
        .send(ConnectionState::Connected {
            epoch: 2,
            serial: 2,
            capabilities: full_caps(),
            peer_process_id: Arc::from("go-fixture"),
            peer_started_unix_millis: 1_700_000_000_000,
        })
        .ok();
    harness.state_tx.send(ConnectionState::Disconnected).ok();
    // An epoch-2 snapshot claiming the metering ack arrives afterwards:
    // there is NO active session — it must be dropped, not applied.
    let stale_ack = ControlEnvelope {
        request_id: 50,
        generation: 7,
        control_epoch: 2,
        body: Some(Body::ReconcileSnapshot(ReconcileSnapshot {
            applied_generation: 7,
            connection_event_sequence: 0,
            metrics_sequence: 0,
            metering_sequence: batch.sequence,
            connections: Vec::new(),
        })),
        ..ControlEnvelope::default()
    };
    harness
        .inbound_tx
        .send(tagged_on(stale_ack, 2, 2))
        .await
        .ok();

    // The next real session replays everything unacknowledged: the
    // batch MUST still be there — the stale ack never applied.
    harness
        .state_tx
        .send(ConnectionState::Connected {
            epoch: 3,
            serial: 3,
            capabilities: full_caps(),
            peer_process_id: Arc::from("go-fixture"),
            peer_started_unix_millis: 1_700_000_000_000,
        })
        .ok();
    let sent = wait_for_sent(&harness.sender, 2).await;
    assert!(
        sent.iter().any(|envelope| matches!(
            &envelope.body,
            Some(Body::MeteringBatch(replayed)) if replayed.sequence == batch.sequence
        )),
        "the unacked batch replays: the dead session's ack was refused"
    );
    harness.task.abort();
}

/// The deterministic inbound-first barrier: a `Connected(2)` state
/// change and an old-epoch-1 snapshot are both queued before the loop
/// observes either. Whichever select arm wins, the pending state is
/// applied BEFORE the envelope — so the old snapshot is judged against
/// epoch 2 and dropped, never acking.
#[tokio::test(start_paused = true)]
async fn pending_connected_applies_before_queued_inbound() {
    let mut handler = ControlCommandHandler::new();
    handler.set_applied_generation(7);
    assert!(
        handler
            .metering()
            .record(MeteringDelta {
                keyspace: "ks-2".to_owned(),
                backend_id: "tidb-a".to_owned(),
                public_endpoint: false,
                response_bytes: 32,
                cross_location_bytes: 0,
            })
            .is_ok()
    );
    let Ok(Some(batch)) = handler.seal_metering() else {
        unreachable!("one batch seals")
    };
    // Queue BOTH before spawning the loop: the select's first pick is
    // genuinely arbitrary, and the barrier must make it irrelevant.
    let sender = FakeSender::new();
    let (state_tx, state_rx) = watch::channel(ConnectionState::Disconnected);
    let (inbound_tx, inbound_rx) = mpsc::channel(16);
    let (notice_tx, notice_rx) = mpsc::channel(16);
    let (snapshot_tx, _snapshot_rx) = mpsc::channel::<TaggedEnvelope>(4);
    state_tx
        .send(ConnectionState::Connected {
            epoch: 2,
            serial: 2,
            capabilities: full_caps(),
            peer_process_id: Arc::from("go-fixture"),
            peer_started_unix_millis: 1_700_000_000_000,
        })
        .ok();
    let old_ack = ControlEnvelope {
        request_id: 51,
        generation: 7,
        control_epoch: 1,
        body: Some(Body::ReconcileSnapshot(ReconcileSnapshot {
            applied_generation: 7,
            connection_event_sequence: 0,
            metrics_sequence: 0,
            metering_sequence: batch.sequence,
            connections: Vec::new(),
        })),
        ..ControlEnvelope::default()
    };
    inbound_tx.try_send(tagged_on(old_ack, 1, 1)).ok();
    let task = tokio::spawn(run_control_dispatch(
        handler,
        Arc::clone(&sender),
        state_rx,
        inbound_rx,
        notice_rx,
        snapshot_tx,
        Duration::from_secs(3600),
        || 1_000_000,
    ));
    let _ = &notice_tx;

    // Epoch 2's automatic replay proves the ordering: the reconcile
    // request went out AND the batch is still unacked (the old-epoch
    // snapshot was refused even if the inbound arm won the select).
    let sent = wait_for_sent(&sender, 2).await;
    assert!(sent.iter().any(|envelope| matches!(
        &envelope.body,
        Some(Body::MeteringBatch(replayed)) if replayed.sequence == batch.sequence
    )));
    // A second session still replays it: never acked.
    state_tx.send(ConnectionState::Disconnected).ok();
    state_tx
        .send(ConnectionState::Connected {
            epoch: 3,
            serial: 3,
            capabilities: full_caps(),
            peer_process_id: Arc::from("go-fixture"),
            peer_started_unix_millis: 1_700_000_000_000,
        })
        .ok();
    let sent = wait_for_sent(&sender, 4).await;
    let replays = sent
        .iter()
        .filter(|envelope| {
            matches!(
                &envelope.body,
                Some(Body::MeteringBatch(replayed)) if replayed.sequence == batch.sequence
            )
        })
        .count();
    assert!(replays >= 2, "the stale ack never applied: {replays}");
    task.abort();
}

/// The applied-ack causal contract through the REAL double-queue path:
/// registration and expectation are acknowledged by the dispatcher
/// before the session would send its request, so the answer — arriving
/// on the other queue — always finds the armed expectation.
#[tokio::test(start_paused = true)]
async fn applied_acks_order_arming_before_responses() {
    let handler = ControlCommandHandler::new();
    let harness = spawn_loop(handler);
    connect_go_fixture(&harness, 1);

    let (control_tx, _control_rx) = mpsc::channel(8);
    let (resp_tx, mut resp_rx) = mpsc::channel(1);
    let (register_ack_tx, register_ack_rx) = tokio::sync::oneshot::channel();
    harness
        .notice_tx
        .send(DispatchNotice::RegisterSession {
            identity: identity(1),
            namespace: "ns-a".to_owned(),
            snapshot_generation: 7,
            listener_name: "sql-a".to_owned(),
            control: control_tx,
            responses: Some(resp_tx),
            applied: register_ack_tx,
        })
        .await
        .ok();
    let Ok(()) = register_ack_rx.await else {
        unreachable!("registration is acknowledged when applied")
    };
    let (expect_ack_tx, expect_ack_rx) = tokio::sync::oneshot::channel();
    harness
        .notice_tx
        .send(DispatchNotice::ExpectResponse {
            connection_id: 1,
            request_id: 90,
            kind: ResponseKind::RouteAssignment,
            applied: expect_ack_tx,
        })
        .await
        .ok();
    let Ok(dataplane::control_dispatch::ExpectArmVerdict::Armed) = expect_ack_rx.await else {
        unreachable!("the expectation is acknowledged as armed")
    };

    // Only now would the session send its request — so the answer
    // cannot precede the arm. Inject it on the inbound queue.
    let answer = envelope(
        90,
        7,
        Body::RouteAssignment(RouteAssignment {
            connection_id: 1,
            assignment_id: "a-1".to_owned(),
            backend_id: "tidb-a".to_owned(),
            backend_address: "10.0.0.1:4000".to_owned(),
            cluster_name: String::new(),
            keyspace: String::new(),
            healthy: true,
            local: true,
            code: 0,
            detail: String::new(),
        }),
    );
    harness.inbound_tx.send(tagged_on(answer, 1, 1)).await.ok();
    let delivered = tokio::time::timeout(Duration::from_secs(1), resp_rx.recv()).await;
    let Ok(Some(delivered)) = delivered else {
        unreachable!("the armed answer is delivered: {delivered:?}")
    };
    assert_eq!(delivered.request_id, 90);
    harness.task.abort();
}

/// Metering ownership under saturation: when the ledger cannot absorb
/// a delta (open accumulation full AND the unacked retention bound
/// reached), the producer's ack carries the fail-closed verdict and
/// the delta is NOT silently dropped — its ownership stays with the
/// producer. Malformed deltas (oversized keys) are rejected the same
/// way. Nothing already retained is touched.
#[tokio::test(start_paused = true)]
async fn metering_saturation_rejects_producer_instead_of_dropping() {
    let mut handler = ControlCommandHandler::new();
    // Saturate: fill the unacked retention bound with sealed batches…
    for index in 0..1024_u32 {
        assert!(
            handler
                .metering()
                .record(MeteringDelta {
                    keyspace: format!("ks-{index}"),
                    backend_id: "tidb-a".to_owned(),
                    public_endpoint: false,
                    response_bytes: 1,
                    cross_location_bytes: 0,
                })
                .is_ok()
        );
        assert!(handler.seal_metering().is_ok());
    }
    // …and fill the open accumulation with distinct keys.
    for index in 0..1024_u32 {
        assert!(
            handler
                .metering()
                .record(MeteringDelta {
                    keyspace: format!("open-{index}"),
                    backend_id: "tidb-a".to_owned(),
                    public_endpoint: false,
                    response_bytes: 1,
                    cross_location_bytes: 0,
                })
                .is_ok()
        );
    }
    let harness = spawn_loop(handler);

    let (ack_tx, ack_rx) = tokio::sync::oneshot::channel();
    harness
        .notice_tx
        .send(DispatchNotice::Metering {
            delta: Box::new(MeteringDelta {
                keyspace: "one-too-many".to_owned(),
                backend_id: "tidb-a".to_owned(),
                public_endpoint: false,
                response_bytes: 1,
                cross_location_bytes: 0,
            }),
            ack: ack_tx,
        })
        .await
        .ok();
    let Ok(Err(_)) = ack_rx.await else {
        unreachable!("saturation must reject the producer, not drop the delta")
    };

    // Malformed input is rejected through the same ownership channel.
    let (ack_tx, ack_rx) = tokio::sync::oneshot::channel();
    harness
        .notice_tx
        .send(DispatchNotice::Metering {
            delta: Box::new(MeteringDelta {
                keyspace: "k".repeat(4096),
                backend_id: "tidb-a".to_owned(),
                public_endpoint: false,
                response_bytes: 1,
                cross_location_bytes: 0,
            }),
            ack: ack_tx,
        })
        .await
        .ok();
    let Ok(Err(_)) = ack_rx.await else {
        unreachable!("oversized keys are rejected to the producer")
    };
    harness.task.abort();
}

/// The applied-generation barrier semantics observable end to end:
/// once the typed ack fires (the snapshot owner sends its OK only
/// after this), every subsequently processed inbound command is
/// judged against the NEW applied generation — a drain minted under
/// the superseded generation is rejected stale, never admitted off an
/// older applied view.
#[tokio::test(start_paused = true)]
async fn applied_generation_ack_orders_before_inbound_commands() {
    let handler = ControlCommandHandler::new();
    let harness = spawn_loop(handler);
    connect_go_fixture(&harness, 1);

    // Before any applied generation, old-provenance drains are legal.
    let early = envelope(
        30,
        3,
        Body::DrainCommand(DrainCommand {
            drain_id: "d-early".to_owned(),
            listener_names: Vec::new(),
            backend_ids: Vec::new(),
            graceful_deadline_unix_millis: 1_010_000,
            force_deadline_unix_millis: 1_020_000,
            command_sequence: 1,
        }),
    );
    harness.inbound_tx.send(tagged_on(early, 1, 1)).await.ok();
    let sent = wait_for_sent(&harness.sender, 1).await;
    assert!(
        matches!(sent[0].body, Some(Body::DrainResult(_))),
        "pre-barrier provenance is admitted"
    );

    // The snapshot owner's barrier: notice + ack, awaited before the
    // OK would go to Go.
    let (ack_tx, ack_rx) = tokio::sync::oneshot::channel();
    harness
        .notice_tx
        .send(DispatchNotice::AppliedGeneration {
            generation: 7,
            applied: ack_tx,
        })
        .await
        .ok();
    let Ok(()) = ack_rx.await else {
        unreachable!("the dispatcher acknowledges the applied generation")
    };

    // After the ack, a drain minted under the superseded generation is
    // stale — the new applied view is guaranteed visible.
    let stale = envelope(
        31,
        3,
        Body::DrainCommand(DrainCommand {
            drain_id: "d-stale".to_owned(),
            listener_names: Vec::new(),
            backend_ids: Vec::new(),
            graceful_deadline_unix_millis: 1_010_000,
            force_deadline_unix_millis: 1_020_000,
            command_sequence: 2,
        }),
    );
    harness.inbound_tx.send(tagged_on(stale, 1, 1)).await.ok();
    let sent = wait_for_sent(&harness.sender, 2).await;
    assert_eq!(
        error_code(&sent[1]),
        Some(ErrorCode::StaleGeneration),
        "post-ack commands are judged against the new generation"
    );
    harness.task.abort();
}

/// Directives carry the gate-admitted exact command identity WITH the
/// signal — before the session can observe it — and drain-driven
/// closes carry no token (their terminal is the drain's own result).
#[tokio::test(start_paused = true)]
async fn directives_carry_exact_command_tokens() {
    let mut handler = ControlCommandHandler::new();
    handler.on_session_negotiated(true);
    handler.set_applied_generation(7);
    let mut session = register(&mut handler, 1, "sql-a", "tidb-a");
    let now = Instant::now();

    let _ = handler.handle_envelope(
        &envelope(10, 7, Body::RedirectCommand(redirect(1, "r-tok", 1))),
        now,
        1_000,
    );
    let Ok(directive) = session.control.try_recv() else {
        unreachable!("redirect directive delivered")
    };
    assert_eq!(directive.control, SessionControl::Redirect);
    assert_eq!(
        directive.command,
        Some(CommandToken {
            kind: CommandKind::Redirect,
            id: Arc::from("r-tok"),
        }),
        "the exact admitted id travels with the command"
    );

    let close = CloseCommand {
        connection_id: 1,
        close_id: "c-tok".to_owned(),
        error_source: 0,
        reason: String::new(),
        force: false,
    };
    let _ = handler.handle_envelope(&envelope(11, 7, Body::CloseCommand(close)), now, 1_001);
    let Ok(directive) = session.control.try_recv() else {
        unreachable!("close directive delivered")
    };
    assert_eq!(
        directive
            .command
            .as_ref()
            .map(|token| (&*token.id, token.kind)),
        Some(("c-tok", CommandKind::Close))
    );

    // Drain-driven graceful close: no per-command token.
    let drain = DrainCommand {
        drain_id: "d-tok".to_owned(),
        listener_names: Vec::new(),
        backend_ids: Vec::new(),
        graceful_deadline_unix_millis: 11_000,
        force_deadline_unix_millis: 21_000,
        command_sequence: 1,
    };
    let _ = handler.handle_envelope(&envelope(12, 7, Body::DrainCommand(drain)), now, 1_002);
    let Ok(directive) = session.control.try_recv() else {
        unreachable!("drain directive delivered")
    };
    assert_eq!(directive.control, SessionControl::GracefulClose);
    assert_eq!(directive.command, None, "drain closes carry no token");
}

/// The pinned instant-completion regression: a session that completes
/// the effect the moment the directive becomes visible — strictly
/// before any dispatcher code after the channel send could run — still
/// produces the terminal under the exact admitted id, because the id
/// arrived WITH the command and the completion notice returns the
/// token's own id. No post-send bookkeeping exists to race.
#[tokio::test(start_paused = true)]
async fn instant_completion_binds_exact_terminal_id() {
    let handler = ControlCommandHandler::new();
    let harness = spawn_loop(handler);
    connect_go_fixture(&harness, 1);

    // The instant session: every directive is answered with its
    // completion notice immediately, using only the carried token.
    let (control_tx, mut control_rx) = mpsc::channel::<SessionDirective>(8);
    let notices = harness.notice_tx.clone();
    let instant_session = tokio::spawn(async move {
        while let Some(directive) = control_rx.recv().await {
            let Some(token) = directive.command else {
                continue;
            };
            let notice = match token.kind {
                CommandKind::Redirect => DispatchNotice::RedirectFinished {
                    connection_id: 1,
                    redirect_id: token.id.to_string(),
                    succeeded: true,
                    backend_id: "tidb-b".to_owned(),
                    code: ErrorCode::Ok,
                },
                CommandKind::Close => DispatchNotice::CloseFinished {
                    connection_id: 1,
                    close_id: token.id.to_string(),
                },
            };
            let _ = notices.send(notice).await;
        }
    });

    let (register_ack_tx, register_ack_rx) = tokio::sync::oneshot::channel();
    harness
        .notice_tx
        .send(DispatchNotice::RegisterSession {
            identity: identity(1),
            namespace: "ns-a".to_owned(),
            snapshot_generation: 7,
            listener_name: "sql-a".to_owned(),
            control: control_tx,
            responses: None,
            applied: register_ack_tx,
        })
        .await
        .ok();
    let Ok(()) = register_ack_rx.await else {
        unreachable!("registration applied")
    };

    // Redirect admitted under request 40: the instant terminal must
    // carry redirect id "r-fast" AND answer request 40.
    harness
        .inbound_tx
        .send(tagged_on(
            envelope(40, 7, Body::RedirectCommand(redirect(1, "r-fast", 1))),
            1,
            1,
        ))
        .await
        .ok();
    let sent = wait_for_sent(&harness.sender, 1).await;
    let Some(Body::RedirectResult(result)) = &sent[0].body else {
        unreachable!("instant completion produced the redirect terminal")
    };
    assert_eq!(result.redirect_id, "r-fast", "exact admitted id");
    assert!(result.succeeded);
    assert_eq!(
        sent[0].request_id, 40,
        "the terminal answers the initiating request"
    );

    // Close admitted under request 41: same exactness.
    let close = CloseCommand {
        connection_id: 1,
        close_id: "c-fast".to_owned(),
        error_source: 0,
        reason: String::new(),
        force: false,
    };
    harness
        .inbound_tx
        .send(tagged_on(envelope(41, 7, Body::CloseCommand(close)), 1, 1))
        .await
        .ok();
    let sent = wait_for_sent(&harness.sender, 2).await;
    let Some(Body::CloseResult(result)) = &sent[1].body else {
        unreachable!("instant completion produced the close terminal")
    };
    assert_eq!(result.close_id, "c-fast");
    assert_eq!(sent[1].request_id, 41);

    instant_session.abort();
    harness.task.abort();
}

/// A reconcile that raced ahead of the decision adoption is never the
/// peer's LAST word: adopting namespace (and later backend) on an
/// already-exported record sends an explicit repair reconcile — in
/// wire order after the stale export, and for the namespace adoption
/// BEFORE its applied acknowledgement fires.
#[tokio::test(start_paused = true)]
async fn stale_namespace_export_is_repaired_by_a_fresh_reconcile() {
    let mut handler = ControlCommandHandler::new();
    handler.set_applied_generation(7);
    let (tx, _session_rx) = mpsc::channel(8);
    handler.register_session(identity(1), "default", 7, "sql-a", tx, None);

    let harness = spawn_loop(handler);
    // The reconnect wins the race: the automatic reconcile exports the
    // registration seed — necessarily backend-less (the notice order
    // guarantees no backend exists before the namespace adoption).
    harness
        .state_tx
        .send(ConnectionState::Connected {
            epoch: 1,
            serial: 1,
            capabilities: full_caps(),
            peer_process_id: Arc::from("go-fixture"),
            peer_started_unix_millis: 1_700_000_000_000,
        })
        .ok();
    let sent = wait_for_sent(&harness.sender, 1).await;
    let Some(Body::ReconcileRequest(request)) = &sent[0].body else {
        unreachable!("the connected transition reconciles automatically")
    };
    assert_eq!(request.connections[0].namespace, "default");
    assert!(
        request.connections[0].backend_id.is_empty(),
        "a pre-decision export is always backend-less"
    );

    // The adoption lands after the export: by the time the applied ack
    // fires, the repair reconcile is already in the outbound path.
    let (applied_tx, applied_rx) = tokio::sync::oneshot::channel();
    assert!(
        harness
            .notice_tx
            .send(DispatchNotice::SetNamespace {
                connection_id: 1,
                namespace: "ns-wired".to_owned(),
                applied: applied_tx,
            })
            .await
            .is_ok()
    );
    assert!(applied_rx.await.is_ok());
    let sent = harness.sender.sent();
    let Some(Body::ReconcileRequest(repair)) = &sent[1].body else {
        unreachable!("the adoption on an exported record repairs by reconcile")
    };
    assert_eq!(
        repair.connections[0].namespace, "ns-wired",
        "the repair re-exports the adopted namespace"
    );

    // The backend adoption on the (again) exported record repairs too:
    // that fresh record is what lets the peer resolve a parked orphan
    // under the resolved namespace/backend pair.
    assert!(
        harness
            .notice_tx
            .send(DispatchNotice::SetBackend {
                connection_id: 1,
                backend_id: "tidb-a".to_owned(),
            })
            .await
            .is_ok()
    );
    let sent = wait_for_sent(&harness.sender, 3).await;
    let Some(Body::ReconcileRequest(repair)) = &sent[2].body else {
        unreachable!("the backend adoption on an exported record repairs by reconcile")
    };
    assert_eq!(repair.connections[0].namespace, "ns-wired");
    assert_eq!(repair.connections[0].backend_id, "tidb-a");
    harness.task.abort();
}

/// An adoption already queued when the reconnect is observed applies
/// BEFORE the transition's automatic reconcile (the causal drain
/// barrier): the one export carries the adopted namespace and no
/// repair is ever needed.
#[tokio::test(start_paused = true)]
async fn queued_adoption_precedes_the_automatic_reconcile() {
    let mut handler = ControlCommandHandler::new();
    handler.set_applied_generation(7);
    let (tx, _session_rx) = mpsc::channel(8);
    handler.register_session(identity(1), "default", 7, "sql-a", tx, None);

    let harness = spawn_loop(handler);
    // Queue the adoption first — completed sends are visible to the
    // barrier no matter which select arm wins.
    let (applied_tx, applied_rx) = tokio::sync::oneshot::channel();
    assert!(
        harness
            .notice_tx
            .send(DispatchNotice::SetNamespace {
                connection_id: 1,
                namespace: "ns-wired".to_owned(),
                applied: applied_tx,
            })
            .await
            .is_ok()
    );
    harness
        .state_tx
        .send(ConnectionState::Connected {
            epoch: 1,
            serial: 1,
            capabilities: full_caps(),
            peer_process_id: Arc::from("go-fixture"),
            peer_started_unix_millis: 1_700_000_000_000,
        })
        .ok();
    assert!(applied_rx.await.is_ok());

    let sent = wait_for_sent(&harness.sender, 1).await;
    let Some(Body::ReconcileRequest(request)) = &sent[0].body else {
        unreachable!("the connected transition reconciles automatically")
    };
    assert_eq!(
        request.connections[0].namespace, "ns-wired",
        "the export already carries the queued adoption"
    );
    // Give the loop a chance to (wrongly) emit a repair; none may come.
    for _ in 0..50 {
        tokio::task::yield_now().await;
    }
    assert_eq!(
        harness.sender.sent().len(),
        1,
        "an unexported adoption owes no repair"
    );
    harness.task.abort();
}

/// A sender whose session-scoped sends fail on demand — the repair
/// path must not presume an always-successful transport.
struct ScriptedSender {
    next: AtomicU64,
    sent: Mutex<Vec<ControlEnvelope>>,
    fail_scoped_with: Mutex<Option<ScriptedFailure>>,
}

#[derive(Clone, Copy)]
enum ScriptedFailure {
    StaleEpoch,
    QueueFull,
    Closed,
}

impl ScriptedSender {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            next: AtomicU64::new(0),
            sent: Mutex::new(Vec::new()),
            fail_scoped_with: Mutex::new(None),
        })
    }

    fn sent(&self) -> Vec<ControlEnvelope> {
        let Ok(sent) = self.sent.lock() else {
            unreachable!("sent lock poisoned")
        };
        sent.clone()
    }

    fn fail_scoped_with(&self, failure: Option<ScriptedFailure>) {
        let Ok(mut mode) = self.fail_scoped_with.lock() else {
            unreachable!("mode lock poisoned")
        };
        *mode = failure;
    }
}

impl DispatchSender for ScriptedSender {
    fn allocate_request_id(&self) -> Option<u64> {
        Some(self.next.fetch_add(1, Ordering::Relaxed) + 1)
    }

    async fn send_envelope(&self, envelope: ControlEnvelope) -> Result<(), TransportError> {
        let Ok(mut sent) = self.sent.lock() else {
            unreachable!("sent lock poisoned")
        };
        sent.push(envelope);
        Ok(())
    }

    async fn send_session_scoped(
        &self,
        envelope: ControlEnvelope,
        _epoch: u64,
    ) -> Result<(), TransportError> {
        let failure = {
            let Ok(mode) = self.fail_scoped_with.lock() else {
                unreachable!("mode lock poisoned")
            };
            *mode
        };
        match failure {
            Some(ScriptedFailure::StaleEpoch) => Err(TransportError::StaleSessionEpoch),
            Some(ScriptedFailure::QueueFull) => Err(TransportError::QueueFull),
            Some(ScriptedFailure::Closed) => Err(TransportError::Closed),
            None => {
                let Ok(mut sent) = self.sent.lock() else {
                    unreachable!("sent lock poisoned")
                };
                sent.push(envelope);
                Ok(())
            }
        }
    }
}

struct ScriptedHarness {
    sender: Arc<ScriptedSender>,
    state_tx: watch::Sender<ConnectionState>,
    notice_tx: mpsc::Sender<DispatchNotice>,
    /// Held open so the loop's inbound arm never observes closure.
    _inbound_tx: mpsc::Sender<TaggedEnvelope>,
    /// Held open so snapshot forwarding never observes closure.
    _snapshot_rx: mpsc::Receiver<TaggedEnvelope>,
    task: tokio::task::JoinHandle<Result<(), DispatchFatal>>,
}

fn spawn_scripted_loop(handler: ControlCommandHandler) -> ScriptedHarness {
    let sender = ScriptedSender::new();
    let (state_tx, state_rx) = watch::channel(ConnectionState::Disconnected);
    let (inbound_tx, inbound_rx) = mpsc::channel(16);
    let (notice_tx, notice_rx) = mpsc::channel(16);
    let (snapshot_tx, snapshot_rx) = mpsc::channel(4);
    let task = tokio::spawn(run_control_dispatch(
        handler,
        Arc::clone(&sender),
        state_rx,
        inbound_rx,
        notice_rx,
        snapshot_tx,
        Duration::from_secs(3600),
        || 1_000_000,
    ));
    ScriptedHarness {
        sender,
        state_tx,
        notice_tx,
        _inbound_tx: inbound_tx,
        _snapshot_rx: snapshot_rx,
        task,
    }
}

async fn wait_for_scripted_sent(
    sender: &Arc<ScriptedSender>,
    count: usize,
) -> Vec<ControlEnvelope> {
    for _ in 0..1_000 {
        let sent = sender.sent();
        if sent.len() >= count {
            return sent;
        }
        tokio::task::yield_now().await;
    }
    unreachable!("scripted loop never sent {count} envelopes")
}

fn scripted_stale_export_handler() -> ControlCommandHandler {
    let mut handler = ControlCommandHandler::new();
    handler.set_applied_generation(7);
    let (tx, rx) = mpsc::channel(8);
    std::mem::forget(rx);
    handler.register_session(identity(1), "default", 7, "sql-a", tx, None);
    handler
}

/// A repair that did not actually enter the outbound path withholds
/// the applied ack: the commander observes `false` and the session
/// fails closed instead of routing while the peer's last observation
/// is the stale seed. `StaleEpoch` is included deliberately — it is
/// not a wire barrier: an acked session would enqueue its durable
/// `RouteRequest`, which can reach the new peer before the dispatcher
/// even observes the `Connected` transition that sends the automatic
/// reconcile.
#[tokio::test(start_paused = true)]
async fn failed_repair_send_withholds_the_namespace_ack() {
    for failure in [
        ScriptedFailure::StaleEpoch,
        ScriptedFailure::QueueFull,
        ScriptedFailure::Closed,
    ] {
        let harness = spawn_scripted_loop(scripted_stale_export_handler());
        harness
            .state_tx
            .send(ConnectionState::Connected {
                epoch: 1,
                serial: 1,
                capabilities: full_caps(),
                peer_process_id: Arc::from("go-fixture"),
                peer_started_unix_millis: 1_700_000_000_000,
            })
            .ok();
        // The automatic reconcile succeeds and exports the seed.
        let _ = wait_for_scripted_sent(&harness.sender, 1).await;
        // Every later session-scoped send fails unrecoverably.
        harness.sender.fail_scoped_with(Some(failure));
        let (applied_tx, applied_rx) = tokio::sync::oneshot::channel();
        assert!(
            harness
                .notice_tx
                .send(DispatchNotice::SetNamespace {
                    connection_id: 1,
                    namespace: "ns-wired".to_owned(),
                    applied: applied_tx,
                })
                .await
                .is_ok()
        );
        assert!(
            applied_rx.await.is_err(),
            "an unrecoverable repair failure must not ack the adoption"
        );
        harness.task.abort();
    }
}

/// A stale-epoch repair withholds the ack (the session fails closed),
/// and the gate still converges for accounting: it holds the adopted
/// value, so the next Connected transition's automatic reconcile
/// re-exports it — proven here by reconnecting and reading the
/// re-export.
#[tokio::test(start_paused = true)]
async fn stale_epoch_repair_withholds_the_ack_and_the_next_reconcile_re_exports() {
    let harness = spawn_scripted_loop(scripted_stale_export_handler());
    harness
        .state_tx
        .send(ConnectionState::Connected {
            epoch: 1,
            serial: 1,
            capabilities: full_caps(),
            peer_process_id: Arc::from("go-fixture"),
            peer_started_unix_millis: 1_700_000_000_000,
        })
        .ok();
    let _ = wait_for_scripted_sent(&harness.sender, 1).await;
    // The session dies between the export and the adoption: the repair
    // send observes a stale epoch.
    harness
        .sender
        .fail_scoped_with(Some(ScriptedFailure::StaleEpoch));
    let (applied_tx, applied_rx) = tokio::sync::oneshot::channel();
    assert!(
        harness
            .notice_tx
            .send(DispatchNotice::SetNamespace {
                connection_id: 1,
                namespace: "ns-wired".to_owned(),
                applied: applied_tx,
            })
            .await
            .is_ok()
    );
    assert!(
        applied_rx.await.is_err(),
        "a stale-epoch repair never entered the wire: the ack is withheld"
    );
    // The gate still converges for accounting: the next Connected
    // transition re-exports the adopted value.
    harness.sender.fail_scoped_with(None);
    harness
        .state_tx
        .send(ConnectionState::Connected {
            epoch: 2,
            serial: 2,
            capabilities: full_caps(),
            peer_process_id: Arc::from("go-fixture"),
            peer_started_unix_millis: 1_700_000_000_000,
        })
        .ok();
    let sent = wait_for_scripted_sent(&harness.sender, 2).await;
    let Some(Body::ReconcileRequest(request)) = &sent[sent.len() - 1].body else {
        unreachable!("the reconnect reconciles automatically")
    };
    assert_eq!(
        request.connections[0].namespace, "ns-wired",
        "the next-epoch reconcile exports the adopted namespace"
    );
    harness.task.abort();
}

/// Fix-2 lineage regression: a frame retained from lineage A's dead
/// session must NOT be pumped into a session belonging to a DIFFERENT
/// Go process — even when the new session negotiated the SAME wire
/// epoch value. The frame is dropped and counted; its owner (the new
/// Go) regenerates the desired state itself.
#[tokio::test(start_paused = true)]
async fn cross_lineage_retained_frame_is_dropped_not_pumped() {
    let (forwarder, mut inbound_rx, state_tx) = forwarder_fixture(1).await;
    let Ok(()) = forwarder.handle(frame(1)).await else {
        unreachable!("first frame fits")
    };
    let blocked = forwarder.handle(frame(2));
    tokio::pin!(blocked);
    assert!(futures_pending(&mut blocked).await);
    state_tx.send(ConnectionState::Disconnected).ok();
    assert!(blocked.await.is_err());
    let Ok(true) = forwarder.retains_frame() else {
        unreachable!("the in-flight frame is retained")
    };
    assert_eq!(inbound_rx.try_recv().map(|e| e.envelope.request_id), Ok(1));

    // The replacement Go negotiates the SAME wire epoch value 1 — but
    // it is a different process lineage.
    state_tx
        .send(ConnectionState::Connected {
            epoch: 1,
            serial: 2,
            capabilities: full_caps(),
            peer_process_id: Arc::from("go-fixture"),
            peer_started_unix_millis: 1_700_000_000_000,
        })
        .ok();
    let Ok(()) = forwarder
        .resume_session(session_meta_as("go-restarted", 2, 1))
        .await
    else {
        unreachable!("resume succeeds with nothing to pump")
    };
    assert!(
        inbound_rx.try_recv().is_err(),
        "the cross-lineage frame is NOT delivered"
    );
    let Ok(false) = forwarder.retains_frame() else {
        unreachable!("the slot is emptied by the drop")
    };
    assert_eq!(
        forwarder.cross_lineage_retained_dropped(),
        1,
        "the drop is observable"
    );

    // The new session's own frames flow normally, tagged with the NEW
    // origin.
    let Ok(()) = forwarder.handle(frame(3)).await else {
        unreachable!("the new session's frame fits")
    };
    let Ok(delivered) = inbound_rx.try_recv() else {
        unreachable!("the new session's frame is delivered")
    };
    assert_eq!(delivered.envelope.request_id, 3);
    assert_eq!(delivered.origin.serial, 2);
    assert_eq!(delivered.origin.peer_process_id.as_ref(), "go-restarted");
}

/// Fix-2 lineage regression, same-lineage side: a reconnect WITHIN one
/// Go process (epoch 1 → 2) keeps the one-shot retained delivery, and
/// the pumped frame still carries its ORIGIN session meta — it must be
/// judged against the session it was read on, not the new one.
#[tokio::test(start_paused = true)]
async fn same_lineage_retained_frame_pumps_once_with_origin_meta() {
    let (forwarder, mut inbound_rx, state_tx) = forwarder_fixture(1).await;
    let Ok(()) = forwarder.handle(frame(1)).await else {
        unreachable!("first frame fits")
    };
    let blocked = forwarder.handle(frame(2));
    tokio::pin!(blocked);
    assert!(futures_pending(&mut blocked).await);
    state_tx.send(ConnectionState::Disconnected).ok();
    assert!(blocked.await.is_err());
    assert_eq!(inbound_rx.try_recv().map(|e| e.envelope.request_id), Ok(1));

    // Same Go process, next epoch.
    state_tx
        .send(ConnectionState::Connected {
            epoch: 2,
            serial: 2,
            capabilities: full_caps(),
            peer_process_id: Arc::from("go-fixture"),
            peer_started_unix_millis: 1_700_000_000_000,
        })
        .ok();
    let Ok(()) = forwarder.resume_session(session_meta(2, 2)).await else {
        unreachable!("the pump delivers the retained frame")
    };
    let Ok(delivered) = inbound_rx.try_recv() else {
        unreachable!("the retained frame arrives")
    };
    assert_eq!(delivered.envelope.request_id, 2);
    assert_eq!(
        delivered.origin.serial, 1,
        "the frame keeps the ORIGIN it was read on"
    );
    assert_eq!(delivered.origin.epoch, 1);
    assert_eq!(forwarder.cross_lineage_retained_dropped(), 0);
    // One-shot semantics unchanged.
    let Ok(()) = forwarder.resume_session(session_meta(2, 2)).await else {
        unreachable!("empty pump succeeds")
    };
    assert!(inbound_rx.try_recv().is_err(), "no double delivery");
}

/// Fix-2 dispatch-gate regression: wire epoch VALUES repeat across Go
/// restarts, so a `ReconcileSnapshot` from a DEAD session that happens
/// to carry the CURRENT epoch value must still be refused — only the
/// tagged origin serial tells the sessions apart. The dead session's
/// metering ack never applies, the batch replays to every successor,
/// and each new session regenerates its own reconcile exchange.
#[expect(
    clippy::too_many_lines,
    reason = "three full sessions plus an interleaved late ack are one scenario"
)]
#[tokio::test(start_paused = true)]
async fn dead_session_snapshot_with_reused_epoch_value_never_acks() {
    let mut handler = ControlCommandHandler::new();
    handler.set_applied_generation(7);
    assert!(
        handler
            .metering()
            .record(MeteringDelta {
                keyspace: "ks-serial".to_owned(),
                backend_id: "tidb-a".to_owned(),
                public_endpoint: false,
                response_bytes: 64,
                cross_location_bytes: 0,
            })
            .is_ok()
    );
    let Ok(Some(batch)) = handler.seal_metering() else {
        unreachable!("one batch seals")
    };
    let harness = spawn_loop(handler);

    // Session A (serial 2, epoch 2): replays the unacked batch and
    // issues its reconcile request.
    harness
        .state_tx
        .send(ConnectionState::Connected {
            epoch: 2,
            serial: 2,
            capabilities: full_caps(),
            peer_process_id: Arc::from("go-fixture"),
            peer_started_unix_millis: 1_700_000_000_000,
        })
        .ok();
    let sent = wait_for_sent(&harness.sender, 2).await;
    let replays = |sent: &[ControlEnvelope]| {
        sent.iter()
            .filter(|envelope| {
                matches!(
                    &envelope.body,
                    Some(Body::MeteringBatch(replayed)) if replayed.sequence == batch.sequence
                )
            })
            .count()
    };
    assert_eq!(replays(&sent), 1, "session A replays the unacked batch");

    // Go restarts. The replacement session B negotiates the SAME wire
    // epoch VALUE 2 — a different serial is the only discriminator.
    harness.state_tx.send(ConnectionState::Disconnected).ok();
    harness
        .state_tx
        .send(ConnectionState::Connected {
            epoch: 2,
            serial: 3,
            capabilities: full_caps(),
            peer_process_id: Arc::from("go-fixture"),
            peer_started_unix_millis: 1_700_000_000_000,
        })
        .ok();

    // Session B replays the still-unacked batch too.
    let mut sent = Vec::new();
    for _ in 0..100_000 {
        sent = harness.sender.sent();
        if replays(&sent) >= 2 {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(replays(&sent), 2, "session B replays the unacked batch");

    // A late ack minted by DEAD session A arrives: control_epoch 2
    // matches the CURRENT epoch value, so an epoch-only gate would
    // accept it — the origin serial must refuse it.
    let late_ack = ControlEnvelope {
        request_id: 60,
        generation: 7,
        control_epoch: 2,
        body: Some(Body::ReconcileSnapshot(ReconcileSnapshot {
            applied_generation: 7,
            connection_event_sequence: 0,
            metrics_sequence: 0,
            metering_sequence: batch.sequence,
            connections: Vec::new(),
        })),
        ..ControlEnvelope::default()
    };
    harness
        .inbound_tx
        .send(tagged_on(late_ack, 2, 2))
        .await
        .ok();
    // A marker command queued BEHIND the ack (FIFO): once its terminal
    // is out, the ack was judged — while the epoch value is STILL 2.
    harness
        .inbound_tx
        .send(tagged_on(
            envelope(61, 7, Body::RedirectCommand(redirect(999, "marker-1", 1))),
            3,
            2,
        ))
        .await
        .ok();
    let mut sent = Vec::new();
    for _ in 0..100_000 {
        sent = harness.sender.sent();
        if sent.iter().any(|envelope| envelope.request_id == 61) {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(
        sent.iter().any(|envelope| envelope.request_id == 61),
        "the marker terminal proves the ack was judged under epoch value 2"
    );

    // Session C proves the refusal observably: the batch is STILL
    // unacked and replays a third time.
    harness.state_tx.send(ConnectionState::Disconnected).ok();
    harness
        .state_tx
        .send(ConnectionState::Connected {
            epoch: 3,
            serial: 4,
            capabilities: full_caps(),
            peer_process_id: Arc::from("go-fixture"),
            peer_started_unix_millis: 1_700_000_000_000,
        })
        .ok();
    let mut final_sent = Vec::new();
    for _ in 0..100_000 {
        final_sent = harness.sender.sent();
        if replays(&final_sent) >= 3 {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(
        replays(&final_sent),
        3,
        "the dead session's same-epoch-value ack was refused: the batch replays"
    );
    // Every session regenerated its own reconcile exchange.
    assert!(
        final_sent
            .iter()
            .filter(|envelope| matches!(envelope.body, Some(Body::ReconcileRequest(_))))
            .count()
            >= 2,
        "each successor session re-issues its reconcile request"
    );
    harness.task.abort();
}

/// Fix-2 outbound-scoping regression: an INLINE request error (a
/// `ProtocolError` answering one inbound frame) is bound to the exact
/// session the offending frame arrived on — if that session dies, the
/// error dies with it and can never false-resolve a successor's
/// exchange that reused the same request id. Lifecycle TERMINALS
/// (drain results and kin) stay durable across reconnects.
#[tokio::test(start_paused = true)]
async fn inline_request_errors_are_session_scoped_and_terminals_durable() {
    let mut handler = ControlCommandHandler::new();
    handler.set_applied_generation(7);
    let harness = spawn_loop(handler);
    harness
        .state_tx
        .send(ConnectionState::Connected {
            epoch: 2,
            serial: 2,
            capabilities: full_caps(),
            peer_process_id: Arc::from("go-fixture"),
            peer_started_unix_millis: 1_700_000_000_000,
        })
        .ok();

    // A drain minted under a superseded generation draws an inline
    // ProtocolError: scoped to the offending frame's origin session.
    let stale = envelope(
        70,
        3,
        Body::DrainCommand(DrainCommand {
            drain_id: "d-scoped".to_owned(),
            listener_names: Vec::new(),
            backend_ids: Vec::new(),
            graceful_deadline_unix_millis: 1_010_000,
            force_deadline_unix_millis: 1_020_000,
            command_sequence: 1,
        }),
    );
    harness.inbound_tx.send(tagged_on(stale, 2, 2)).await.ok();
    let mut with_scope = Vec::new();
    for _ in 0..100_000 {
        with_scope = harness.sender.sent_with_scope();
        if with_scope
            .iter()
            .any(|(envelope, _)| envelope.request_id == 70)
        {
            break;
        }
        tokio::task::yield_now().await;
    }
    let Some((error, scope)) = with_scope
        .iter()
        .find(|(envelope, _)| envelope.request_id == 70)
    else {
        unreachable!("the stale drain is answered")
    };
    assert_eq!(
        error_code(error),
        Some(ErrorCode::StaleGeneration),
        "the answer is the inline request error"
    );
    assert_eq!(
        *scope,
        Some(2),
        "the inline error is bound to the offending frame's origin session"
    );

    // A legal drain completes with a terminal: durable, never scoped.
    let valid = envelope(
        71,
        7,
        Body::DrainCommand(DrainCommand {
            drain_id: "d-durable".to_owned(),
            listener_names: Vec::new(),
            backend_ids: Vec::new(),
            graceful_deadline_unix_millis: 1_010_000,
            force_deadline_unix_millis: 1_020_000,
            command_sequence: 2,
        }),
    );
    harness.inbound_tx.send(tagged_on(valid, 2, 2)).await.ok();
    let mut with_scope = Vec::new();
    for _ in 0..100_000 {
        with_scope = harness.sender.sent_with_scope();
        if with_scope.iter().any(|(envelope, _)| {
            matches!(&envelope.body, Some(Body::DrainResult(result)) if result.drain_id == "d-durable")
        }) {
            break;
        }
        tokio::task::yield_now().await;
    }
    let Some((_, scope)) = with_scope.iter().find(|(envelope, _)| {
        matches!(&envelope.body, Some(Body::DrainResult(result)) if result.drain_id == "d-durable")
    }) else {
        unreachable!("the legal drain reaches its terminal")
    };
    assert_eq!(*scope, None, "lifecycle terminals stay durable");
    harness.task.abort();
}

/// Fix-2 queued-frame lineage regression (the "queued", not "retained",
/// seam): a frame from Go lineage A already sitting in the dispatch
/// inbound queue when Go restarts as lineage B must NOT reach the
/// `CommandGate` once B is the live session — it is dropped before any
/// handler side effect and answers nothing. An identical frame from the
/// LIVE lineage B does reach the gate (its unroutable body is answered),
/// proving the drop is lineage-specific rather than a blanket refusal.
#[tokio::test(start_paused = true)]
async fn queued_cross_lineage_frame_never_reaches_the_gate() {
    let handler = ControlCommandHandler::new();
    let harness = spawn_loop(handler);

    // Lineage B becomes the live session (wire epoch value 1). Its
    // start time matches `session_meta_as`, so a go-b origin is
    // exact-lineage and a go-a origin is foreign purely by process id.
    harness
        .state_tx
        .send(ConnectionState::Connected {
            epoch: 1,
            serial: 2,
            capabilities: full_caps(),
            peer_process_id: Arc::from("go-b"),
            peer_started_unix_millis: 1_700_000_000_000,
        })
        .ok();

    // An unroutable body (a MeteringBatch is never inbound-legal)
    // tagged with the DEAD lineage A, same wire epoch value 1: the gate
    // would answer it with a ProtocolViolation — but the lineage drop
    // must fire first, so it is swallowed with no answer.
    let a_frame = envelope(
        80,
        0,
        Body::MeteringBatch(control_proto::v1::MeteringBatch {
            sequence: 1,
            deltas: Vec::new(),
        }),
    );
    harness
        .inbound_tx
        .send(TaggedEnvelope {
            envelope: a_frame,
            origin: session_meta_as("go-a", 1, 1),
        })
        .await
        .ok();

    // The SAME unroutable body from the LIVE lineage B does reach the
    // gate: it is answered (proving the drop above was lineage-specific,
    // not a blanket refusal of unroutable bodies).
    let b_frame = envelope(
        81,
        0,
        Body::MeteringBatch(control_proto::v1::MeteringBatch {
            sequence: 2,
            deltas: Vec::new(),
        }),
    );
    harness
        .inbound_tx
        .send(TaggedEnvelope {
            envelope: b_frame,
            origin: session_meta_as("go-b", 2, 1),
        })
        .await
        .ok();

    // Both frames carry the same unroutable body, so each one that
    // reaches the gate yields one ProtocolViolation answer. Wait for
    // the drop and the answer, then confirm exactly one such answer
    // exists (B's), exactly one frame was lineage dropped (A's), and
    // exactly one frame was unrouted (B's). (B's connect also emits a
    // ReconcileRequest, which is not a ProtocolViolation answer.)
    let count_violations = |harness: &LoopHarness| {
        harness
            .sender
            .sent()
            .iter()
            .filter(|envelope| error_code(envelope) == Some(ErrorCode::ProtocolViolation))
            .count()
    };
    for _ in 0..100_000 {
        if count_violations(&harness) >= 1 {
            break;
        }
        tokio::task::yield_now().await;
    }
    wait_for_drop(&harness).await;
    // Let any erroneously-forwarded A answer race in, then assert the
    // totals.
    for _ in 0..1_000 {
        tokio::task::yield_now().await;
    }
    assert_eq!(
        count_violations(&harness),
        1,
        "only the live lineage's frame reached the gate and was answered"
    );
    assert_eq!(
        harness.stats.stale_dropped.load(Ordering::Relaxed),
        1,
        "exactly the dead lineage's frame was lineage dropped"
    );
    assert_eq!(
        harness.stats.unrouted.load(Ordering::Relaxed),
        1,
        "exactly the live lineage's frame was unrouted"
    );
    harness.task.abort();
}

async fn wait_for_drop(harness: &LoopHarness) {
    for _ in 0..100_000 {
        if harness.stats.stale_dropped.load(Ordering::Relaxed) >= 1 {
            return;
        }
        tokio::task::yield_now().await;
    }
}

/// Fix-2 no-live-session deferral (Blocker 1): a frame that arrives
/// while there is NO live session (a teardown was observed before the
/// frame was classified) must not be processed under an absent lineage
/// — it is held until the next `Connected` and only then classified
/// same-lineage (processed) or foreign (dropped). Here the deferred
/// frame is from a lineage the successor does not share, so once the
/// successor is live it is dropped, never reaching the gate; a frame
/// from the successor's own lineage is answered, proving the successor
/// is otherwise healthy.
#[tokio::test(start_paused = true)]
async fn no_live_session_frame_is_deferred_then_classified() {
    let handler = ControlCommandHandler::new();
    let harness = spawn_loop(handler);
    // The loop starts Disconnected: send a frame with NO live session.
    let orphan = envelope(
        70,
        0,
        Body::MeteringBatch(control_proto::v1::MeteringBatch {
            sequence: 1,
            deltas: Vec::new(),
        }),
    );
    harness
        .inbound_tx
        .send(TaggedEnvelope {
            envelope: orphan,
            origin: session_meta_as("go-a", 1, 1),
        })
        .await
        .ok();

    // While no session is live the frame is held: it neither reaches
    // the gate (no unrouted answer) nor is counted as dropped.
    for _ in 0..2_000 {
        tokio::task::yield_now().await;
    }
    assert_eq!(
        harness.stats.unrouted.load(Ordering::Relaxed),
        0,
        "a frame with no live session is not processed"
    );
    assert_eq!(
        harness.stats.stale_dropped.load(Ordering::Relaxed),
        0,
        "and not yet dropped — it is deferred"
    );
    assert!(
        harness.sender.sent().is_empty(),
        "the deferred frame produced nothing"
    );

    // A DIFFERENT lineage becomes live: the deferred frame is now
    // classified foreign and dropped before the gate.
    harness
        .state_tx
        .send(ConnectionState::Connected {
            epoch: 1,
            serial: 2,
            capabilities: full_caps(),
            peer_process_id: Arc::from("go-b"),
            peer_started_unix_millis: 1_700_000_000_000,
        })
        .ok();
    for _ in 0..100_000 {
        if harness.stats.stale_dropped.load(Ordering::Relaxed) >= 1 {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(
        harness.stats.stale_dropped.load(Ordering::Relaxed),
        1,
        "the deferred frame is dropped once the foreign successor is live"
    );
    assert_eq!(
        harness.stats.unrouted.load(Ordering::Relaxed),
        0,
        "the deferred foreign frame never reached the gate"
    );

    // The live successor's own frame is answered — it is healthy.
    let native = envelope(
        71,
        0,
        Body::MeteringBatch(control_proto::v1::MeteringBatch {
            sequence: 2,
            deltas: Vec::new(),
        }),
    );
    harness
        .inbound_tx
        .send(TaggedEnvelope {
            envelope: native,
            origin: session_meta_as("go-b", 2, 1),
        })
        .await
        .ok();
    for _ in 0..100_000 {
        if harness.stats.unrouted.load(Ordering::Relaxed) >= 1 {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(
        harness.stats.unrouted.load(Ordering::Relaxed),
        1,
        "the successor lineage's own frame reaches the gate"
    );
    harness.task.abort();
}
