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

use control_proto::control_transport::{ConnectionState, TransportError};
use control_proto::v1::control_envelope::Body;
use control_proto::v1::{
    CloseCommand, ConnectionIdentity, ControlCapability, ControlEnvelope, DrainCommand, ErrorCode,
    ErrorSource, MeteringDelta, ReconcileConnection, ReconcileSnapshot, RedirectCommand,
    RouteAssignment,
};
use dataplane::control_dispatch::{
    ControlCommandHandler, DispatchNotice, DispatchSender, run_control_dispatch,
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
    control: mpsc::Receiver<SessionControl>,
}

fn register(
    handler: &mut ControlCommandHandler,
    connection_id: u64,
    listener: &str,
    backend: &str,
) -> Session {
    let (tx, rx) = mpsc::channel(8);
    handler.register_session(identity(connection_id), "ns-a", 7, listener, tx, None);
    handler.set_backend(connection_id, backend);
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
    assert_eq!(session.control.try_recv(), Ok(SessionControl::Redirect));

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
        session.control.try_recv(),
        Ok(SessionControl::GracefulClose)
    );

    // Duplicate while closing: current state outbound, no second signal.
    let dup = envelope(21, 7, Body::CloseCommand(close.clone()));
    let out = handler.handle_envelope(&dup, now, 2_001);
    assert!(matches!(out[0].body, Some(Body::CloseResult(_))));
    assert_eq!(out[0].request_id, 21);
    assert!(session.control.try_recv().is_err(), "no second close");

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
        a.control.try_recv(),
        Ok(SessionControl::GracefulClose),
        "matched session asked to close at a safe point"
    );
    assert_eq!(b.control.try_recv(), Ok(SessionControl::GracefulClose));
    assert!(
        other.control.try_recv().is_err(),
        "out-of-scope listener untouched"
    );

    // One session drains gracefully: its CLOSED event is owed, but the
    // drain is not complete yet — no premature terminal.
    let closed = handler.session_closed(1, false, ErrorSource::ClientNetwork);
    assert_eq!(closed.len(), 1, "CLOSED lifecycle event only");
    assert!(matches!(closed[0].body, Some(Body::ConnectionEvent(_))));

    // Past the force deadline the remainder is closed immediately —
    // exactly once, however many ticks land.
    let force_by = now + Duration::from_secs(20);
    assert!(handler.tick(force_by + Duration::from_millis(1)).is_empty());
    assert_eq!(b.control.try_recv(), Ok(SessionControl::CloseImmediate));
    let _ = handler.tick(force_by + Duration::from_millis(2));
    let _ = handler.tick(force_by + Duration::from_millis(3));
    assert!(
        b.control.try_recv().is_err(),
        "repeated force ticks never duplicate CloseImmediate"
    );

    // The LAST matched session closing is the completion transition:
    // the terminal DrainResult goes out proactively, addressed with
    // the initiating request id.
    let closed = handler.session_closed(2, true, ErrorSource::Proxy);
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
    assert_eq!(session.control.try_recv(), Ok(SessionControl::Redirect));
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
        session.control.try_recv(),
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
    handler.set_backend(1, "tidb-a");
    assert!(
        tx.try_send(SessionControl::GracefulClose).is_ok(),
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
        rx.try_recv(),
        Ok(SessionControl::GracefulClose),
        "only the pre-filled message is in the slot"
    );
    assert!(rx.try_recv().is_err(), "the force send was jammed out");

    // The slot is free now: the next tick delivers exactly once.
    assert!(handler.tick(now + Duration::from_millis(1)).is_empty());
    assert_eq!(rx.try_recv(), Ok(SessionControl::CloseImmediate));
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
    sent: Mutex<Vec<ControlEnvelope>>,
}

impl FakeSender {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            next: AtomicU64::new(0),
            sent: Mutex::new(Vec::new()),
        })
    }

    fn sent(&self) -> Vec<ControlEnvelope> {
        let Ok(sent) = self.sent.lock() else {
            unreachable!("sent lock poisoned")
        };
        sent.clone()
    }
}

impl DispatchSender for FakeSender {
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
}

struct LoopHarness {
    sender: Arc<FakeSender>,
    state_tx: watch::Sender<ConnectionState>,
    notice_tx: mpsc::Sender<DispatchNotice>,
    _inbound_tx: mpsc::Sender<ControlEnvelope>,
    task: tokio::task::JoinHandle<()>,
}

fn spawn_loop(handler: ControlCommandHandler) -> LoopHarness {
    let sender = FakeSender::new();
    let (state_tx, state_rx) = watch::channel(ConnectionState::Disconnected);
    let (inbound_tx, inbound_rx) = mpsc::channel(16);
    let (notice_tx, notice_rx) = mpsc::channel(16);
    let task = tokio::spawn(run_control_dispatch(
        handler,
        Arc::clone(&sender),
        state_rx,
        inbound_rx,
        notice_rx,
        None,
        Duration::from_secs(3600),
        || 1_000_000,
    ));
    LoopHarness {
        sender,
        state_tx,
        notice_tx,
        _inbound_tx: inbound_tx,
        task,
    }
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
    let rehydration_bit = 1u64 << (ControlCapability::ReconcileSessionRehydration as u64);
    harness
        .state_tx
        .send(ConnectionState::Connected {
            epoch: 1,
            capabilities: rehydration_bit,
        })
        .ok();

    let sent = wait_for_sent(&harness.sender, 2).await;
    let Some(Body::ReconcileRequest(request)) = &sent[0].body else {
        unreachable!("first automatic send is the reconcile request")
    };
    assert_eq!(request.known_generation, 7);
    assert_eq!(request.last_metering_sequence, batch.sequence);
    assert!(sent[0].request_id > 0, "allocator-issued id");
    let Some(Body::MeteringBatch(replayed)) = &sent[1].body else {
        unreachable!("unacked metering replays after the reconcile")
    };
    assert_eq!(replayed, &batch, "the exact sealed batch replays");
    assert!(
        sent[1].request_id > sent[0].request_id,
        "one checked allocator: ids strictly increase"
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
    let rehydration_bit = 1u64 << (ControlCapability::ReconcileSessionRehydration as u64);

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
        })
        .await
        .ok();
    harness
        .notice_tx
        .send(DispatchNotice::SessionClosed {
            connection_id: 1,
            forced: false,
            error_source: ErrorSource::ClientNetwork,
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
            capabilities: rehydration_bit,
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
