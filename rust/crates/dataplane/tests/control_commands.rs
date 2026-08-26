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

//! CTL-06 model tests: duplicate, out-of-order, delayed, and lost
//! control messages against the single-owner [`CommandGate`] —
//! redirects act at most once with exactly one terminal result, closes
//! never schedule twice, drains are single-flight with replayable
//! progress and never-negative accounting, and reconciliation repairs
//! lost results and ghost connections in both restart directions.

use control_proto::v1::{
    DrainCommand, ErrorCode, ReconcileConnection, ReconcileSnapshot, RedirectCommand,
};
use dataplane::control_commands::{
    CloseAdmission, CommandGate, DrainAdmission, DrainPhase, RedirectAdmission,
};
use std::time::Duration;
use tokio::time::Instant;

fn redirect(connection_id: u64, redirect_id: &str) -> RedirectCommand {
    RedirectCommand {
        connection_id,
        redirect_id: redirect_id.to_owned(),
        backend_id: "tidb-b".to_owned(),
        backend_address: "10.0.0.2:4000".to_owned(),
        cluster_name: String::new(),
        deadline_unix_millis: 0,
    }
}

fn drain(drain_id: &str, listeners: &[&str], backends: &[&str]) -> DrainCommand {
    DrainCommand {
        drain_id: drain_id.to_owned(),
        listener_names: listeners.iter().map(|name| (*name).to_owned()).collect(),
        backend_ids: backends.iter().map(|id| (*id).to_owned()).collect(),
        graceful_deadline_unix_millis: 0,
        force_deadline_unix_millis: 0,
    }
}

fn gate_with_connection(connection_id: u64, backend: &str) -> CommandGate {
    let mut gate = CommandGate::new();
    gate.register_connection(connection_id, "ns-a", 7);
    gate.set_backend(connection_id, backend);
    gate
}

/// Duplicate and out-of-order redirect traffic acts at most once: the
/// pending duplicate is absorbed, the terminal duplicate replays the
/// cached result verbatim, a late completion is suppressed, and a
/// conflicting id while pending is surfaced as a violation.
#[test]
fn redirect_duplicates_act_at_most_once() {
    let mut gate = gate_with_connection(1, "tidb-a");

    assert_eq!(
        gate.admit_redirect(&redirect(1, "r-1")),
        RedirectAdmission::Start
    );
    assert_eq!(
        gate.admit_redirect(&redirect(1, "r-1")),
        RedirectAdmission::DuplicatePending,
        "duplicate of the pending id is absorbed"
    );
    assert_eq!(
        gate.admit_redirect(&redirect(1, "r-2")),
        RedirectAdmission::Conflict {
            pending_redirect_id: "r-1".to_owned()
        },
        "a different id while pending is a violation, never a second redirect"
    );

    // Exactly one terminal result.
    let result = gate.complete_redirect(1, "r-1", true, "tidb-b", ErrorCode::Ok);
    let Some(result) = result else {
        unreachable!("first completion must produce the result")
    };
    assert!(result.succeeded);
    assert_eq!(result.previous_backend_id, "tidb-a");
    assert_eq!(result.backend_id, "tidb-b");
    assert_eq!(
        gate.complete_redirect(1, "r-1", true, "tidb-b", ErrorCode::Ok),
        None,
        "a second completion for the same id is suppressed"
    );
    assert_eq!(
        gate.complete_redirect(1, "r-9", false, "", ErrorCode::RedirectFailed),
        None,
        "a completion for an id that was never pending is suppressed"
    );

    // The delayed duplicate command replays the cached result verbatim.
    assert_eq!(
        gate.admit_redirect(&redirect(1, "r-1")),
        RedirectAdmission::Replay(result.clone())
    );

    // A new id after the terminal starts a fresh redirect from the new
    // backend.
    assert_eq!(
        gate.admit_redirect(&redirect(1, "r-2")),
        RedirectAdmission::Start
    );
    let Some(second) = gate.complete_redirect(1, "r-2", false, "", ErrorCode::RedirectFailed)
    else {
        unreachable!("second redirect completes once")
    };
    assert!(!second.succeeded);
    assert_eq!(
        second.previous_backend_id, "tidb-b",
        "backend updated by r-1"
    );
    assert_eq!(
        second.backend_id, "tidb-b",
        "failed redirect keeps the owner"
    );

    // Unknown connections are never acted on.
    assert_eq!(
        gate.admit_redirect(&redirect(99, "r-1")),
        RedirectAdmission::UnknownConnection
    );
}

/// Replaying the identical admission/completion sequence leaves
/// identical state and produces no second side effect (idempotency
/// under a full duplicate storm).
#[test]
fn duplicate_storm_is_idempotent() {
    let mut gate = gate_with_connection(1, "tidb-a");
    let mut effects = Vec::new();
    for _ in 0..3 {
        for _ in 0..2 {
            if gate.admit_redirect(&redirect(1, "r-1")) == RedirectAdmission::Start {
                effects.push("start");
            }
            if let Some(result) = gate.complete_redirect(1, "r-1", true, "tidb-b", ErrorCode::Ok) {
                effects.push("result");
                let _ = result;
            }
        }
    }
    assert_eq!(effects, vec!["start", "result"], "one action, one result");
}

/// Close commands never schedule a second close: duplicates replay,
/// different ids on a closing connection report current state, and the
/// terminal result is produced exactly once.
#[test]
fn close_commands_schedule_at_most_once() {
    let mut gate = gate_with_connection(1, "tidb-a");

    assert_eq!(
        gate.admit_close(1, "c-1", false),
        CloseAdmission::Start { force: false }
    );
    // Duplicate while closing: replay the accepted state.
    let CloseAdmission::Replay(state) = gate.admit_close(1, "c-1", false) else {
        unreachable!("duplicate close id must replay")
    };
    assert_eq!(state.close_id, "c-1");
    assert!(state.accepted);
    // A different id while closing: current state, no second schedule.
    let CloseAdmission::AlreadyClosing(state) = gate.admit_close(1, "c-2", true) else {
        unreachable!("different close id must not schedule a second close")
    };
    assert_eq!(state.close_id, "c-1", "reports the actual closing id");

    // Exactly one terminal result.
    let Some(result) = gate.complete_close(1, "c-1") else {
        unreachable!("first completion produces the result")
    };
    assert_eq!(result.close_id, "c-1");
    assert_eq!(
        gate.complete_close(1, "c-1"),
        None,
        "second completion suppressed"
    );
    assert_eq!(
        gate.complete_close(1, "c-9"),
        None,
        "completion for an unscheduled id suppressed"
    );

    // Post-terminal: duplicate replays the terminal result; different
    // ids still report it.
    assert_eq!(
        gate.admit_close(1, "c-1", false),
        CloseAdmission::Replay(result.clone())
    );
    assert_eq!(
        gate.admit_close(1, "c-3", false),
        CloseAdmission::AlreadyClosing(result)
    );
    assert_eq!(
        gate.admit_close(42, "c-1", false),
        CloseAdmission::UnknownConnection
    );

    // Force close maps through.
    let mut gate = gate_with_connection(2, "tidb-a");
    assert_eq!(
        gate.admit_close(2, "c-f", true),
        CloseAdmission::Start { force: true }
    );
}

/// Drain is single-flight and replayable: the active id reports
/// progress, a different concurrent id is rejected as
/// `DRAIN_IN_PROGRESS`, accounting can never overshoot or go negative,
/// and a completed drain id replays its final result.
#[tokio::test(start_paused = true)]
async fn drain_is_single_flight_with_replayable_progress() {
    let mut gate = CommandGate::new();
    let now = Instant::now();
    let graceful_by = now + Duration::from_secs(10);
    let force_by = now + Duration::from_secs(20);

    assert_eq!(
        gate.admit_drain(&drain("d-1", &["sql-a"], &[]), graceful_by, force_by, 2),
        DrainAdmission::Start
    );
    // Scope selection: listener match with empty backend list matches
    // any backend; a different listener does not.
    assert!(gate.drain_selects("sql-a", "tidb-x"));
    assert!(!gate.drain_selects("sql-b", "tidb-x"));

    // Repeating the active id: progress, not a second drain.
    let DrainAdmission::Progress(progress) =
        gate.admit_drain(&drain("d-1", &["sql-a"], &[]), graceful_by, force_by, 2)
    else {
        unreachable!("active id must report progress")
    };
    assert_eq!(progress.active_connections, 2);
    assert_eq!(progress.gracefully_closed, 0);
    assert!(!progress.complete);

    // A different concurrent drain is rejected.
    let DrainAdmission::Conflict(conflict) =
        gate.admit_drain(&drain("d-2", &[], &[]), graceful_by, force_by, 5)
    else {
        unreachable!("concurrent drain must conflict")
    };
    assert_eq!(conflict.drain_id, "d-1", "reports the active drain");
    assert_eq!(conflict.code(), ErrorCode::DrainInProgress);

    // Phases follow the absolute deadlines.
    assert_eq!(gate.drain_phase(now), Some(DrainPhase::Graceful));
    assert_eq!(
        gate.drain_phase(now + Duration::from_secs(25)),
        Some(DrainPhase::Force)
    );

    // Accounting: one graceful, one forced completes the drain; extra
    // closes are ignored (a session closes once — never negative, never
    // overshooting).
    gate.record_drain_close(false);
    gate.record_drain_close(true);
    gate.record_drain_close(true);
    let DrainAdmission::Replay(done) =
        gate.admit_drain(&drain("d-1", &["sql-a"], &[]), graceful_by, force_by, 2)
    else {
        unreachable!("completed drain id must replay its final result")
    };
    assert!(done.complete);
    assert_eq!(done.gracefully_closed, 1);
    assert_eq!(done.force_closed, 1);
    assert_eq!(done.active_connections, 2);

    // With the drain complete, a new drain may start.
    assert_eq!(
        gate.admit_drain(&drain("d-2", &[], &["tidb-a"]), graceful_by, force_by, 0),
        DrainAdmission::Start
    );
    // Zero matched connections completes immediately.
    let DrainAdmission::Replay(empty) =
        gate.admit_drain(&drain("d-2", &[], &["tidb-a"]), graceful_by, force_by, 0)
    else {
        unreachable!("empty drain is complete immediately")
    };
    assert!(empty.complete);
}

/// Reconciliation, Rust-alive direction (Go restarted): the request
/// carries the gate's authoritative connection/backend pairs, pending
/// flags, and sequences; an empty answering snapshot demands no
/// repairs and preserves every session.
#[test]
fn go_restart_preserves_rust_sessions() {
    let mut gate = CommandGate::new();
    gate.register_connection(1, "ns-a", 7);
    gate.set_backend(1, "tidb-a");
    gate.register_connection(2, "ns-b", 7);
    gate.set_backend(2, "tidb-b");
    let _ = gate.admit_redirect(&redirect(2, "r-1"));
    let seq_a = gate.next_event_sequence();
    let seq_b = gate.next_event_sequence();
    assert!(seq_b > seq_a, "event sequences are monotonic");

    let request = gate.build_reconcile_request(9, 3, 4);
    assert_eq!(request.known_generation, 9);
    assert_eq!(request.last_connection_event_sequence, 2);
    assert_eq!(request.last_metrics_sequence, 3);
    assert_eq!(request.last_metering_sequence, 4);
    assert_eq!(request.connections.len(), 2);
    assert_eq!(request.connections[0].connection_id, 1);
    assert_eq!(request.connections[0].backend_id, "tidb-a");
    assert!(!request.connections[0].redirect_pending);
    assert_eq!(request.connections[1].connection_id, 2);
    assert!(request.connections[1].redirect_pending);

    // Go restarted with no memory of these sessions: nothing to repair,
    // sessions preserved.
    let repairs = gate.apply_reconcile_snapshot(&ReconcileSnapshot {
        applied_generation: 9,
        connection_event_sequence: 0,
        metrics_sequence: 0,
        metering_sequence: 0,
        connections: Vec::new(),
    });
    assert!(repairs.replay_redirect_results.is_empty());
    assert!(repairs.ghost_connections.is_empty());
    assert_eq!(gate.len(), 2, "existing sessions survive a Go restart");
}

/// Reconciliation, Rust-restarted direction: connections Go still
/// lists that this gate does not know are ghosts to answer with
/// terminal CLOSED events (no negative counts), and terminal redirect
/// results Go still believes pending are replayed verbatim.
#[test]
fn rust_restart_clears_ghosts_and_replays_lost_results() {
    // A fresh gate knows one live connection with a cached terminal
    // redirect result whose delivery was lost.
    let mut gate = gate_with_connection(5, "tidb-a");
    let _ = gate.admit_redirect(&redirect(5, "r-5"));
    let Some(lost) = gate.complete_redirect(5, "r-5", true, "tidb-b", ErrorCode::Ok) else {
        unreachable!("completion produces the result")
    };

    let repairs = gate.apply_reconcile_snapshot(&ReconcileSnapshot {
        applied_generation: 9,
        connection_event_sequence: 10,
        metrics_sequence: 0,
        metering_sequence: 0,
        connections: vec![
            // Go's view of the live connection: redirect still pending
            // (the terminal result was lost) → replay it.
            ReconcileConnection {
                connection_id: 5,
                backend_id: "tidb-a".to_owned(),
                namespace: "ns-a".to_owned(),
                redirect_pending: true,
            },
            // Ghosts: connections that died with the Rust restart.
            ReconcileConnection {
                connection_id: 9,
                backend_id: "tidb-a".to_owned(),
                namespace: "ns-a".to_owned(),
                redirect_pending: false,
            },
            ReconcileConnection {
                connection_id: 3,
                backend_id: "tidb-b".to_owned(),
                namespace: "ns-b".to_owned(),
                redirect_pending: true,
            },
        ],
    });
    assert_eq!(repairs.replay_redirect_results, vec![lost]);
    assert_eq!(
        repairs.ghost_connections,
        vec![3, 9],
        "every unknown connection is a ghost to close, sorted, exactly once"
    );

    // Applying the same snapshot twice yields the same repairs — the
    // replay itself is idempotent input for the Go side (duplicate
    // results return the cached outcome there).
    let again = gate.apply_reconcile_snapshot(&ReconcileSnapshot {
        applied_generation: 9,
        connection_event_sequence: 10,
        metrics_sequence: 0,
        metering_sequence: 0,
        connections: vec![ReconcileConnection {
            connection_id: 5,
            backend_id: "tidb-a".to_owned(),
            namespace: "ns-a".to_owned(),
            redirect_pending: true,
        }],
    });
    assert_eq!(again.replay_redirect_results.len(), 1);

    // A truly empty Rust restart: everything Go lists is a ghost.
    let mut empty = CommandGate::new();
    let repairs = empty.apply_reconcile_snapshot(&ReconcileSnapshot {
        applied_generation: 9,
        connection_event_sequence: 10,
        metrics_sequence: 0,
        metering_sequence: 0,
        connections: vec![ReconcileConnection {
            connection_id: 1,
            backend_id: "tidb-a".to_owned(),
            namespace: "ns-a".to_owned(),
            redirect_pending: false,
        }],
    });
    assert_eq!(repairs.ghost_connections, vec![1]);
    assert!(repairs.replay_redirect_results.is_empty());
}

/// A connection admitted under an older snapshot generation keeps that
/// generation for its whole life; a new incarnation registers with the
/// committed one — the reconcile request never mixes them up, and a
/// command for a retired id answers `UnknownConnection` instead of
/// touching the new connection.
#[test]
fn stale_generations_never_affect_new_connections() {
    let mut gate = CommandGate::new();
    gate.register_connection(1, "ns-a", 7);
    gate.set_backend(1, "tidb-a");
    // The connection closes; a new one is admitted under generation 9
    // reusing nothing from the old id.
    gate.unregister_connection(1);
    assert_eq!(
        gate.admit_redirect(&redirect(1, "r-old")),
        RedirectAdmission::UnknownConnection,
        "commands for the retired incarnation never act"
    );
    gate.register_connection(2, "ns-a", 9);
    gate.set_backend(2, "tidb-b");
    let request = gate.build_reconcile_request(9, 0, 0);
    assert_eq!(request.connections.len(), 1);
    assert_eq!(request.connections[0].connection_id, 2);
    assert_eq!(request.connections[0].backend_id, "tidb-b");
}
