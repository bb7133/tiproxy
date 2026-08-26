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
//! long-lived [`ControlCommandHandler`], `Start` admissions surface as
//! [`SessionControl`] on the sessions' channels, completions produce
//! each terminal result exactly once, obsolete duplicates answer
//! `DUPLICATE_REQUEST`, drains run graceful-then-force off the
//! deadlines, and the handler survives control reconnects with its
//! tombstones and watermarks intact.

use std::time::Duration;

use control_proto::v1::{
    CloseCommand, ConnectionIdentity, DrainCommand, ErrorCode, ReconcileConnection,
    ReconcileSnapshot, RedirectCommand,
};
use dataplane::control_dispatch::{ControlCommandHandler, OutboundControl};
use dataplane::session::SessionControl;
use tokio::sync::mpsc;
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
    handler.register_session(identity(connection_id), "ns-a", 7, listener, tx);
    handler.set_backend(connection_id, backend);
    Session { control: rx }
}

/// The full redirect chain on the production path: envelope in →
/// `SessionControl::Redirect` out → completion in → terminal result
/// envelope out → duplicate replays → evicted-obsolete duplicates
/// answer `DUPLICATE_REQUEST`.
#[tokio::test(start_paused = true)]
async fn redirect_dispatch_end_to_end() {
    let mut handler = ControlCommandHandler::new();
    handler.on_session_negotiated(true);
    let mut session = register(&mut handler, 1, "sql-a", "tidb-a");

    // Start: the session receives the control signal; nothing outbound.
    let out = handler.handle_redirect(10, 7, &redirect(1, "r-1", 1));
    assert!(out.is_empty());
    assert_eq!(session.control.try_recv(), Ok(SessionControl::Redirect));

    // The session finishes: exactly one terminal result goes out.
    let Some(OutboundControl::RedirectResult(result)) =
        handler.redirect_completed(1, "r-1", true, "tidb-b", ErrorCode::Ok)
    else {
        unreachable!("first completion must produce the result")
    };
    assert!(result.succeeded);
    assert!(
        handler
            .redirect_completed(1, "r-1", true, "tidb-b", ErrorCode::Ok)
            .is_none(),
        "second completion suppressed"
    );

    // A delayed duplicate command replays the cached result verbatim.
    let out = handler.handle_redirect(11, 7, &redirect(1, "r-1", 1));
    assert_eq!(out, vec![OutboundControl::RedirectResult(result)]);

    // Wrong sequence on the same id: protocol violation.
    let out = handler.handle_redirect(12, 7, &redirect(1, "r-1", 9));
    assert!(matches!(
        out.as_slice(),
        [OutboundControl::ProtocolError {
            code: ErrorCode::ProtocolViolation,
            ..
        }]
    ));

    // Stale generation: typed stale error, never an action.
    let out = handler.handle_redirect(13, 9, &redirect(1, "r-2", 2));
    assert!(matches!(
        out.as_slice(),
        [OutboundControl::ProtocolError {
            code: ErrorCode::StaleGeneration,
            ..
        }]
    ));

    // Unknown connection: reconciliation required.
    let out = handler.handle_redirect(14, 7, &redirect(99, "r-x", 1));
    assert!(matches!(
        out.as_slice(),
        [OutboundControl::ProtocolError {
            code: ErrorCode::ReconciliationRequired,
            ..
        }]
    ));
}

/// Close dispatch: graceful and forced starts reach the session as the
/// right control signal, duplicates replay, and completions are
/// exactly-once.
#[tokio::test(start_paused = true)]
async fn close_dispatch_end_to_end() {
    let mut handler = ControlCommandHandler::new();
    handler.on_session_negotiated(true);
    let mut session = register(&mut handler, 1, "sql-a", "tidb-a");

    let close = CloseCommand {
        connection_id: 1,
        close_id: "c-1".to_owned(),
        error_source: 0,
        reason: String::new(),
        force: false,
    };
    assert!(handler.handle_close(20, 7, &close).is_empty());
    assert_eq!(
        session.control.try_recv(),
        Ok(SessionControl::GracefulClose)
    );

    // Duplicate while closing: current state outbound, no second signal.
    let out = handler.handle_close(21, 7, &close);
    assert!(matches!(out.as_slice(), [OutboundControl::CloseResult(_)]));
    assert!(session.control.try_recv().is_err(), "no second close");

    let Some(OutboundControl::CloseResult(result)) = handler.close_completed(1, "c-1") else {
        unreachable!("close completes once")
    };
    assert!(result.accepted);
    assert!(handler.close_completed(1, "c-1").is_none());
}

/// Drain dispatch: matched sessions get graceful closes at admission,
/// per-id accounting flows through `session_closed`, the force deadline
/// closes the remainder via `tick`, and the completed drain replays.
#[tokio::test(start_paused = true)]
async fn drain_dispatch_runs_graceful_then_force() {
    let mut handler = ControlCommandHandler::new();
    handler.on_session_negotiated(true);
    handler.set_applied_generation(7);
    let mut a = register(&mut handler, 1, "sql-a", "tidb-a");
    let mut b = register(&mut handler, 2, "sql-a", "tidb-a");
    let mut other = register(&mut handler, 3, "sql-b", "tidb-a");

    let now = Instant::now();
    let graceful_by = now + Duration::from_secs(10);
    let force_by = now + Duration::from_secs(20);
    let command = DrainCommand {
        drain_id: "d-1".to_owned(),
        listener_names: vec!["sql-a".to_owned()],
        backend_ids: Vec::new(),
        graceful_deadline_unix_millis: 0,
        force_deadline_unix_millis: 0,
        command_sequence: 1,
    };
    let out = handler.handle_drain(30, 7, &command, now, graceful_by, force_by);
    let [OutboundControl::DrainResult(progress)] = out.as_slice() else {
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

    // One session drains gracefully.
    handler.session_closed(1, false);

    // Past the force deadline the remainder is closed immediately.
    let _ = handler.tick(force_by + Duration::from_millis(1));
    assert_eq!(b.control.try_recv(), Ok(SessionControl::CloseImmediate));
    handler.session_closed(2, true);

    // Completed: the duplicate command replays the final result.
    let out = handler.handle_drain(31, 7, &command, force_by, graceful_by, force_by);
    let [OutboundControl::DrainResult(done)] = out.as_slice() else {
        unreachable!("completed drain replays")
    };
    assert!(done.complete);
    assert_eq!(done.gracefully_closed, 1);
    assert_eq!(done.force_closed, 1);

    // An evicted/obsolete duplicate answers DUPLICATE_REQUEST.
    let obsolete = DrainCommand {
        drain_id: "d-0".to_owned(),
        command_sequence: 1,
        ..command.clone()
    };
    let out = handler.handle_drain(32, 7, &obsolete, force_by, graceful_by, force_by);
    let [OutboundControl::DrainResult(answer)] = out.as_slice() else {
        unreachable!("obsolete answers a result")
    };
    assert_eq!(answer.code(), ErrorCode::DuplicateRequest);
}

/// The handler is long-lived across control reconnects: an epoch-N
/// terminal whose result was lost replays verbatim after an epoch-N+1
/// negotiation and reconcile — the gate state (tombstones, unacked
/// results, watermarks) survives; only the peer mode is updated.
#[tokio::test(start_paused = true)]
async fn handler_survives_reconnect_and_replays_lost_terminal() {
    let mut handler = ControlCommandHandler::new();
    handler.on_session_negotiated(true);
    let mut session = register(&mut handler, 1, "sql-a", "tidb-a");

    // Epoch N: a redirect completes but its result is lost in transit.
    let _ = handler.handle_redirect(40, 7, &redirect(1, "r-1", 1));
    assert_eq!(session.control.try_recv(), Ok(SessionControl::Redirect));
    let Some(OutboundControl::RedirectResult(lost)) =
        handler.redirect_completed(1, "r-1", true, "tidb-b", ErrorCode::Ok)
    else {
        unreachable!("terminal produced")
    };

    // Epoch N+1: a new control session negotiates (mode update only —
    // the gate is NOT rebuilt), then reconciles.
    handler.on_session_negotiated(true);
    let request = handler.build_reconcile_request(7);
    assert_eq!(request.connections[0].pending_redirect_id, "r-1");
    assert_eq!(request.connections[0].last_redirect_command_sequence, 1);

    let (outbound, ghosts) = handler.apply_reconcile_snapshot(&ReconcileSnapshot {
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
    });
    assert_eq!(
        outbound,
        vec![OutboundControl::RedirectResult(lost)],
        "the exact lost terminal replays across the epoch"
    );
    assert!(ghosts.is_empty());
}
