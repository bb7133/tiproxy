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
    ConnectionIdentity, DrainCommand, ErrorCode, ReconcileConnection, ReconcileSnapshot,
    RedirectCommand,
};
use dataplane::control_commands::{
    CloseAdmission, CommandGate, DrainAdmission, DrainPhase, RedirectAdmission,
};
use std::time::Duration;
use tokio::time::Instant;

fn redirect(connection_id: u64, redirect_id: &str, command_sequence: u64) -> RedirectCommand {
    RedirectCommand {
        connection_id,
        redirect_id: redirect_id.to_owned(),
        backend_id: "tidb-b".to_owned(),
        backend_address: "10.0.0.2:4000".to_owned(),
        cluster_name: String::new(),
        deadline_unix_millis: 0,
        command_sequence,
    }
}

fn drain(drain_id: &str, sequence: u64, listeners: &[&str], backends: &[&str]) -> DrainCommand {
    DrainCommand {
        drain_id: drain_id.to_owned(),
        listener_names: listeners.iter().map(|name| (*name).to_owned()).collect(),
        backend_ids: backends.iter().map(|id| (*id).to_owned()).collect(),
        graceful_deadline_unix_millis: 0,
        force_deadline_unix_millis: 0,
        command_sequence: sequence,
    }
}

fn identity(connection_id: u64) -> ConnectionIdentity {
    ConnectionIdentity {
        connection_id,
        listener_address: "0.0.0.0:6000".to_owned(),
        client_address: "10.9.8.7:55555".to_owned(),
        proxy_address: "10.0.0.9:6000".to_owned(),
        public_endpoint: false,
    }
}

fn gate_with_connection(connection_id: u64, backend: &str) -> CommandGate {
    let mut gate = CommandGate::new();
    gate.register_connection(identity(connection_id), "ns-a", 7);
    let _ = gate.set_backend(connection_id, backend);
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
        gate.admit_redirect(&redirect(1, "r-1", 1), 7),
        RedirectAdmission::Start
    );
    assert_eq!(
        gate.admit_redirect(&redirect(1, "r-1", 1), 7),
        RedirectAdmission::DuplicatePending,
        "duplicate of the pending id is absorbed"
    );
    assert_eq!(
        gate.admit_redirect(&redirect(1, "r-2", 2), 7),
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
        gate.admit_redirect(&redirect(1, "r-1", 1), 7),
        RedirectAdmission::Replay(result.clone())
    );

    // A new id after the terminal starts a fresh redirect from the new
    // backend.
    assert_eq!(
        gate.admit_redirect(&redirect(1, "r-2", 2), 7),
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
        gate.admit_redirect(&redirect(99, "r-1", 1), 7),
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
            if gate.admit_redirect(&redirect(1, "r-1", 1), 7) == RedirectAdmission::Start {
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
        gate.admit_close(1, "c-1", false, 7),
        CloseAdmission::Start { force: false }
    );
    // Duplicate while closing: replay the accepted state.
    let CloseAdmission::Replay(state) = gate.admit_close(1, "c-1", false, 7) else {
        unreachable!("duplicate close id must replay")
    };
    assert_eq!(state.close_id, "c-1");
    assert!(state.accepted);
    // A different id while closing: current state, no second schedule.
    let CloseAdmission::AlreadyClosing(state) = gate.admit_close(1, "c-2", true, 7) else {
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
        gate.admit_close(1, "c-1", false, 7),
        CloseAdmission::Replay(result.clone())
    );
    assert_eq!(
        gate.admit_close(1, "c-3", false, 7),
        CloseAdmission::AlreadyClosing(result)
    );
    assert_eq!(
        gate.admit_close(42, "c-1", false, 7),
        CloseAdmission::UnknownConnection
    );

    // Force close maps through.
    let mut gate = gate_with_connection(2, "tidb-a");
    assert_eq!(
        gate.admit_close(2, "c-f", true, 7),
        CloseAdmission::Start { force: true }
    );
}

/// Drain is single-flight and replayable: the active id reports
/// progress, a different concurrent id is rejected as
/// `DRAIN_IN_PROGRESS`, accounting can never overshoot or go negative,
/// and a completed drain id replays its final result.
#[tokio::test(start_paused = true)]
#[allow(clippy::too_many_lines)]
async fn drain_is_single_flight_with_replayable_progress() {
    let mut gate = CommandGate::new();
    let now = Instant::now();
    let graceful_by = now + Duration::from_secs(10);
    let force_by = now + Duration::from_secs(20);

    let matched = std::collections::BTreeSet::from([101_u64, 102]);
    assert_eq!(
        gate.admit_drain(
            &drain("d-1", 1, &["sql-a"], &[]),
            1,
            graceful_by,
            force_by,
            matched.clone()
        ),
        DrainAdmission::Start
    );
    // Scope selection: listener match with empty backend list matches
    // any backend; a different listener does not.
    assert!(gate.drain_selects("sql-a", "tidb-x"));
    assert!(!gate.drain_selects("sql-b", "tidb-x"));

    // Repeating the active id: progress, not a second drain.
    let DrainAdmission::Progress(progress) = gate.admit_drain(
        &drain("d-1", 1, &["sql-a"], &[]),
        1,
        graceful_by,
        force_by,
        matched.clone(),
    ) else {
        unreachable!("active id must report progress")
    };
    assert_eq!(progress.active_connections, 2);
    assert_eq!(progress.gracefully_closed, 0);
    assert!(!progress.complete);

    // A different concurrent drain is rejected.
    let DrainAdmission::Conflict(conflict) = gate.admit_drain(
        &drain("d-2", 2, &[], &[]),
        1,
        graceful_by,
        force_by,
        std::collections::BTreeSet::from([1_u64]),
    ) else {
        unreachable!("concurrent drain must conflict")
    };
    assert_eq!(conflict.drain_id, "d-1", "reports the active drain");
    assert_eq!(conflict.code(), ErrorCode::DrainInProgress);

    // Phases follow the absolute deadlines, including the window
    // between graceful expiry and force.
    assert_eq!(gate.drain_phase(now), Some(DrainPhase::Graceful));
    assert_eq!(
        gate.drain_phase(now + Duration::from_secs(15)),
        Some(DrainPhase::GraceExpired)
    );
    assert_eq!(
        gate.drain_phase(now + Duration::from_secs(25)),
        Some(DrainPhase::Force)
    );

    // Per-id accounting: each matched session counts once (duplicate
    // closes are no-ops), out-of-scope ids never count — never
    // negative, never overshooting, by construction.
    gate.record_drain_close(101, false);
    gate.record_drain_close(101, true);
    gate.record_drain_close(999, true);
    gate.record_drain_close(102, true);
    let DrainAdmission::Replay(done) = gate.admit_drain(
        &drain("d-1", 1, &["sql-a"], &[]),
        1,
        graceful_by,
        force_by,
        matched,
    ) else {
        unreachable!("completed drain id must replay its final result")
    };
    assert!(done.complete);
    assert_eq!(done.gracefully_closed, 1);
    assert_eq!(done.force_closed, 1);
    assert_eq!(done.active_connections, 2);

    // With the drain complete, a new drain may start.
    assert_eq!(
        gate.admit_drain(
            &drain("d-2", 2, &[], &["tidb-a"]),
            1,
            graceful_by,
            force_by,
            std::collections::BTreeSet::new()
        ),
        DrainAdmission::Start
    );
    // Zero matched connections completes immediately.
    let DrainAdmission::Replay(empty) = gate.admit_drain(
        &drain("d-2", 2, &[], &["tidb-a"]),
        1,
        graceful_by,
        force_by,
        std::collections::BTreeSet::new(),
    ) else {
        unreachable!("empty drain is complete immediately")
    };
    assert!(empty.complete);

    // Out-of-order duplicate of the FIRST completed drain replays its
    // final result even after a later drain completed (tombstones, not
    // just last-completed).
    let DrainAdmission::Replay(old_replay) = gate.admit_drain(
        &drain("d-1", 1, &["sql-a"], &[]),
        1,
        graceful_by,
        force_by,
        std::collections::BTreeSet::from([7_u64]),
    ) else {
        unreachable!("delayed d-1 must replay, never restart")
    };
    assert!(old_replay.complete);
    assert_eq!(old_replay.gracefully_closed, 1);

    // Drain provenance: a command minted before the applied snapshot is
    // stale; equal or newer generations pass.
    gate.set_applied_generation(9);
    assert_eq!(
        gate.admit_drain(
            &drain("d-3", 3, &[], &[]),
            8,
            graceful_by,
            force_by,
            std::collections::BTreeSet::new()
        ),
        DrainAdmission::StaleGeneration {
            command_generation: 8,
            applied_generation: 9
        }
    );
}

/// Reconciliation, Rust-alive direction (Go restarted): the request
/// carries the gate's authoritative connection/backend pairs, pending
/// flags, and sequences; an empty answering snapshot demands no
/// repairs and preserves every session.
#[test]
fn go_restart_preserves_rust_sessions() {
    let mut gate = CommandGate::new();
    gate.register_connection(identity(1), "ns-a", 7);
    let _ = gate.set_backend(1, "tidb-a");
    gate.register_connection(identity(2), "ns-b", 7);
    let _ = gate.set_backend(2, "tidb-b");
    let _ = gate.admit_redirect(&redirect(2, "r-1", 1), 7);
    // Outgoing events carry allocator-issued ids; the gate records the
    // maximum as the reconcile watermark.
    gate.record_event_sequence(1);
    gate.record_event_sequence(2);
    gate.record_event_sequence(1);

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
    let _ = gate.admit_redirect(&redirect(5, "r-5", 1), 7);
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
                generation: 7,
                pending_redirect_id: String::new(),
                identity: None,
                last_redirect_command_sequence: 0,
            },
            // Ghosts: connections that died with the Rust restart.
            ReconcileConnection {
                connection_id: 9,
                backend_id: "tidb-a".to_owned(),
                namespace: "ns-a".to_owned(),
                redirect_pending: false,
                generation: 7,
                pending_redirect_id: String::new(),
                identity: None,
                last_redirect_command_sequence: 0,
            },
            ReconcileConnection {
                connection_id: 3,
                backend_id: "tidb-b".to_owned(),
                namespace: "ns-b".to_owned(),
                redirect_pending: true,
                generation: 7,
                pending_redirect_id: String::new(),
                identity: None,
                last_redirect_command_sequence: 0,
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
            generation: 7,
            pending_redirect_id: String::new(),
            identity: None,
            last_redirect_command_sequence: 0,
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
            generation: 7,
            pending_redirect_id: String::new(),
            identity: None,
            last_redirect_command_sequence: 0,
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
    gate.register_connection(identity(1), "ns-a", 7);
    let _ = gate.set_backend(1, "tidb-a");
    // The connection closes; a new one is admitted under generation 9
    // reusing nothing from the old id.
    gate.unregister_connection(1);
    assert_eq!(
        gate.admit_redirect(&redirect(1, "r-old", 1), 7),
        RedirectAdmission::UnknownConnection,
        "commands for the retired incarnation never act"
    );
    gate.register_connection(identity(2), "ns-a", 9);
    let _ = gate.set_backend(2, "tidb-b");
    let request = gate.build_reconcile_request(9, 0, 0);
    assert_eq!(request.connections.len(), 1);
    assert_eq!(request.connections[0].connection_id, 2);
    assert_eq!(request.connections[0].backend_id, "tidb-b");
}

/// Metering is deduplicated cumulative state: the open accumulation
/// merges by key, sealed batches carry strictly monotonic sequences,
/// replay after a reconnect is byte-identical under the original
/// sequences (the peer's greater-than dedup absorbs duplicates), a
/// reconcile ack drops exactly the acknowledged prefix, and the
/// retention bound fails closed instead of dropping.
#[test]
fn metering_is_deduplicated_cumulative_and_replayable() {
    use control_proto::v1::MeteringDelta;
    use dataplane::control_commands::{MAX_UNACKED_METERING_BATCHES, MeteringLedger};

    let delta = |keyspace: &str, bytes: u64| MeteringDelta {
        keyspace: keyspace.to_owned(),
        backend_id: "tidb-a".to_owned(),
        public_endpoint: false,
        response_bytes: bytes,
        cross_location_bytes: bytes / 2,
    };

    let mut ledger = MeteringLedger::new();
    assert_eq!(
        ledger.seal(),
        Ok(None),
        "nothing accumulated, nothing sealed"
    );

    // Same key merges cumulatively; different key stays separate.
    let _ = ledger.record(delta("ks-a", 100));
    let _ = ledger.record(delta("ks-a", 50));
    let _ = ledger.record(delta("ks-b", 10));
    let Ok(Some(first)) = ledger.seal() else {
        unreachable!("first seal")
    };
    assert_eq!(first.sequence, 1);
    assert_eq!(first.deltas.len(), 2);
    let merged = first
        .deltas
        .iter()
        .find(|entry| entry.keyspace == "ks-a")
        .map(|entry| (entry.response_bytes, entry.cross_location_bytes));
    assert_eq!(
        merged,
        Some((150, 75)),
        "same-key deltas merge cumulatively"
    );

    let _ = ledger.record(delta("ks-a", 7));
    let Ok(Some(second)) = ledger.seal() else {
        unreachable!("second seal")
    };
    assert_eq!(second.sequence, 2, "sequences are strictly monotonic");

    // Reconnect before any ack: replay is byte-identical, in order,
    // under the original sequences.
    assert_eq!(ledger.replay(), vec![first.clone(), second.clone()]);
    assert_eq!(ledger.last_sequence(), 2);

    // The peer's reconcile acknowledges through sequence 1: exactly the
    // acknowledged prefix drops; re-acking is idempotent.
    ledger.acked_through(1);
    assert_eq!(ledger.replay(), vec![second.clone()]);
    ledger.acked_through(1);
    assert_eq!(ledger.unacked_len(), 1);
    ledger.acked_through(2);
    assert_eq!(ledger.unacked_len(), 0, "fully acknowledged");

    // The retention bound fails closed: the accumulation stays intact
    // and no batch is dropped.
    let mut full = MeteringLedger::new();
    for index in 0..MAX_UNACKED_METERING_BATCHES {
        let _ = full.record(delta("ks", u64::try_from(index).unwrap_or(u64::MAX) + 1));
        assert!(full.seal().is_ok());
    }
    let _ = full.record(delta("ks", 5));
    let backlog = full.seal();
    assert!(backlog.is_err(), "backlog full fails closed, never drops");
    // The accumulation survives for a later seal after acks arrive.
    full.acked_through(1);
    let Ok(Some(late)) = full.seal() else {
        unreachable!("seal succeeds once space exists")
    };
    assert_eq!(
        late.sequence,
        u64::try_from(MAX_UNACKED_METERING_BATCHES).unwrap_or(u64::MAX) + 1
    );
}

/// Redirect terminal replay survives a control reconnect (a new Go
/// epoch): the gate's caches are keyed by `(connection_id,
/// redirect_id)` alone, deliberately independent of transport epochs
/// and request ids — while snapshot generations, a separate dimension,
/// only travel with connection incarnations and reconciliation.
#[test]
fn redirect_replay_survives_epochs_and_generations_stay_separate() {
    let mut gate = gate_with_connection(1, "tidb-a");
    let _ = gate.admit_redirect(&redirect(1, "r-1", 1), 7);
    let Some(result) = gate.complete_redirect(1, "r-1", true, "tidb-b", ErrorCode::Ok) else {
        unreachable!("completion produces the result")
    };

    // The control stream reconnects: a new epoch replays the duplicate
    // command (new request ids, same redirect id). The cached terminal
    // replays verbatim — no epoch or request-id dimension exists in the
    // key, by design.
    assert_eq!(
        gate.admit_redirect(&redirect(1, "r-1", 1), 7),
        RedirectAdmission::Replay(result.clone())
    );

    // Reconcile after the reconnect: Go still believes r-1 pending →
    // the same terminal result is the repair, regardless of epoch.
    let repairs = gate.apply_reconcile_snapshot(&ReconcileSnapshot {
        applied_generation: 11,
        connection_event_sequence: 0,
        metrics_sequence: 0,
        metering_sequence: 0,
        connections: vec![ReconcileConnection {
            connection_id: 1,
            backend_id: "tidb-a".to_owned(),
            namespace: "ns-a".to_owned(),
            redirect_pending: true,
            generation: 7,
            pending_redirect_id: String::new(),
            identity: None,
            last_redirect_command_sequence: 0,
        }],
    });
    assert_eq!(repairs.replay_redirect_results, vec![result]);

    // Generations are a different dimension: a new connection admitted
    // under generation 11 shares nothing with the closed generation-7
    // incarnation, and the old incarnation's commands never touch it.
    gate.unregister_connection(1);
    gate.register_connection(identity(2), "ns-a", 11);
    assert_eq!(
        gate.admit_redirect(&redirect(1, "r-2", 2), 7),
        RedirectAdmission::UnknownConnection,
        "the retired incarnation's id space is dead"
    );
    let request = gate.build_reconcile_request(11, 0, 0);
    assert_eq!(request.connections.len(), 1);
    assert_eq!(request.connections[0].connection_id, 2);
}

/// True out-of-order regression: after r1 AND r2 both finished, a
/// delayed duplicate of r1 replays r1's tombstone — an old id never
/// re-executes just because newer ids finished after it.
#[test]
fn delayed_old_redirect_id_replays_after_newer_terminals() {
    let mut gate = gate_with_connection(1, "tidb-a");
    let _ = gate.admit_redirect(&redirect(1, "r-1", 1), 7);
    let Some(first) = gate.complete_redirect(1, "r-1", true, "tidb-b", ErrorCode::Ok) else {
        unreachable!("r-1 completes")
    };
    let _ = gate.admit_redirect(&redirect(1, "r-2", 2), 7);
    let Some(second) = gate.complete_redirect(1, "r-2", true, "tidb-c", ErrorCode::Ok) else {
        unreachable!("r-2 completes")
    };

    assert_eq!(
        gate.admit_redirect(&redirect(1, "r-1", 1), 7),
        RedirectAdmission::Replay(first),
        "delayed r-1 replays its own tombstone, never re-executes"
    );
    assert_eq!(
        gate.admit_redirect(&redirect(1, "r-2", 2), 7),
        RedirectAdmission::Replay(second),
    );
    assert_eq!(
        gate.complete_redirect(1, "r-1", false, "", ErrorCode::RedirectFailed),
        None,
        "a delayed completion for a tombstoned id is suppressed"
    );
}

/// Connection-id reuse across a Rust restart: the same numeric id
/// admitted under a newer generation rejects commands stamped with the
/// old incarnation's generation — the guard is the generation, not the
/// id space.
#[test]
fn id_reuse_across_generations_rejects_stale_commands() {
    let mut gate = CommandGate::new();
    gate.register_connection(identity(1), "ns-a", 7);
    gate.unregister_connection(1);
    // Rust restarted: ids start from 1 again, new snapshot generation.
    gate.register_connection(identity(1), "ns-a", 9);
    let _ = gate.set_backend(1, "tidb-a");

    assert_eq!(
        gate.admit_redirect(&redirect(1, "r-old", 1), 7),
        RedirectAdmission::StaleGeneration {
            command_generation: 7,
            connection_generation: 9
        },
        "a command minted for the old incarnation never acts on the new one"
    );
    assert_eq!(
        gate.admit_close(1, "c-old", false, 7),
        CloseAdmission::StaleGeneration {
            command_generation: 7,
            connection_generation: 9
        }
    );
    // The correct generation acts normally; zero is legacy-tolerated.
    assert_eq!(
        gate.admit_redirect(&redirect(1, "r-new", 1), 9),
        RedirectAdmission::Start
    );
    let request = gate.build_reconcile_request(9, 0, 0);
    assert_eq!(request.connections[0].generation, 9);
    assert_eq!(request.connections[0].pending_redirect_id, "r-new");
    assert!(request.connections[0].redirect_pending);
}

/// Beyond the tombstone bound, obsolescence is proven by the watermark:
/// after 33 completed redirects evict r-1's record, a delayed duplicate
/// of r-1 is answered `Obsolete` — never `Start`, never re-executed.
#[test]
fn evicted_old_id_is_obsolete_never_reexecuted() {
    use dataplane::control_commands::MAX_TERMINAL_REDIRECTS_PER_CONNECTION;
    let mut gate = gate_with_connection(1, "tidb-a");
    let total = u64::try_from(MAX_TERMINAL_REDIRECTS_PER_CONNECTION).unwrap_or(u64::MAX) + 1;
    for index in 1..=total {
        let id = format!("r-{index}");
        assert_eq!(
            gate.admit_redirect(&redirect_seq(1, &id, index), 7),
            RedirectAdmission::Start,
            "{id}"
        );
        assert!(
            gate.complete_redirect(1, &id, true, "tidb-b", ErrorCode::Ok)
                .is_some()
        );
    }
    // r-1 is evicted; its delayed duplicate is provably obsolete.
    assert_eq!(
        gate.admit_redirect(&redirect_seq(1, "r-1", 1), 7),
        RedirectAdmission::Obsolete {
            command_sequence: 1,
            watermark: total,
        }
    );
    // The newest tombstone still replays normally.
    let newest = format!("r-{total}");
    assert!(matches!(
        gate.admit_redirect(&redirect_seq(1, &newest, total), 7),
        RedirectAdmission::Replay(_)
    ));
}

fn redirect_seq(connection_id: u64, redirect_id: &str, sequence: u64) -> RedirectCommand {
    redirect(connection_id, redirect_id, sequence)
}

/// An id is bound to exactly one issuance: the same id with a different
/// sequence is a protocol violation on both the pending and tombstone
/// paths, for redirects and drains alike.
#[tokio::test(start_paused = true)]
async fn same_id_with_different_sequence_is_a_violation() {
    let mut gate = gate_with_connection(1, "tidb-a");
    let _ = gate.admit_redirect(&redirect(1, "r-1", 1), 7);
    assert_eq!(
        gate.admit_redirect(&redirect_seq(1, "r-1", 5), 7),
        RedirectAdmission::SequenceMismatch {
            bound_sequence: 1,
            command_sequence: 5
        },
        "pending id bound to its sequence"
    );
    let _ = gate.complete_redirect(1, "r-1", true, "tidb-b", ErrorCode::Ok);
    assert_eq!(
        gate.admit_redirect(&redirect_seq(1, "r-1", 9), 7),
        RedirectAdmission::SequenceMismatch {
            bound_sequence: 1,
            command_sequence: 9
        },
        "tombstoned id bound to its sequence"
    );

    let now = Instant::now();
    let later = now + Duration::from_secs(10);
    let _ = gate.admit_drain(
        &drain("d-1", 1, &[], &[]),
        1,
        later,
        later,
        std::collections::BTreeSet::from([1_u64]),
    );
    assert!(matches!(
        gate.admit_drain(
            &drain("d-1", 4, &[], &[]),
            1,
            later,
            later,
            std::collections::BTreeSet::new(),
        ),
        DrainAdmission::SequenceMismatch {
            bound_sequence: 1,
            command_sequence: 4
        }
    ));
}

/// Reconcile requests carry both watermarks so a restarted issuer
/// resumes from watermark + 1 (never re-judging its own new commands
/// obsolete); strict peers reject zero sequences while a declared
/// legacy peer keeps the tombstone-only behavior.
#[tokio::test(start_paused = true)]
async fn watermarks_survive_reconcile_and_zero_sequences_fail_closed() {
    let mut gate = gate_with_connection(1, "tidb-a");
    let _ = gate.admit_redirect(&redirect_seq(1, "r-37", 37), 7);
    let _ = gate.complete_redirect(1, "r-37", true, "tidb-b", ErrorCode::Ok);
    let now = Instant::now();
    let later = now + Duration::from_secs(10);
    let _ = gate.admit_drain(
        &drain("d-9", 9, &[], &[]),
        1,
        later,
        later,
        std::collections::BTreeSet::new(),
    );
    let request = gate.build_reconcile_request(7, 0, 0);
    assert_eq!(
        request.connections[0].last_redirect_command_sequence, 37,
        "per-connection watermark restored to a fresh issuer"
    );
    assert_eq!(
        request.last_drain_command_sequence, 9,
        "issuer-wide drain watermark restored"
    );

    // Strict peer: zero sequence fails closed.
    assert_eq!(
        gate.admit_redirect(&redirect_seq(1, "r-zero", 0), 7),
        RedirectAdmission::Obsolete {
            command_sequence: 0,
            watermark: 37
        }
    );
    // Declared legacy peer: zero sequence and zero generation keep the
    // tombstone-only behavior.
    gate.set_legacy_peer(true);
    assert_eq!(
        gate.admit_redirect(&redirect_seq(1, "r-legacy", 0), 0),
        RedirectAdmission::Start
    );
}

/// The lost-result restart chain end to end on the Rust side: a
/// terminal result is produced but its delivery is never proven; the
/// reconcile request reports that exact id as pending, and the
/// answering snapshot naming it gets exactly that tombstone replayed —
/// while a snapshot showing nothing outstanding acknowledges the
/// terminals and stops the re-reporting.
#[test]
fn lost_result_restart_chain_reports_and_replays_exact_id() {
    let mut gate = gate_with_connection(1, "tidb-a");
    let _ = gate.admit_redirect(&redirect(1, "r-1", 1), 7);
    let Some(first) = gate.complete_redirect(1, "r-1", true, "tidb-b", ErrorCode::Ok) else {
        unreachable!("r-1 completes")
    };
    let _ = gate.admit_redirect(&redirect(1, "r-2", 2), 7);
    let Some(second) = gate.complete_redirect(1, "r-2", false, "", ErrorCode::RedirectFailed)
    else {
        unreachable!("r-2 completes")
    };

    // The result of r-2 (the latest unacked) may have been lost: the
    // request reports its exact id as pending.
    let request = gate.build_reconcile_request(7, 0, 0);
    assert!(request.connections[0].redirect_pending);
    assert_eq!(request.connections[0].pending_redirect_id, "r-2");

    // Fresh Go restores that id and echoes it: exactly r-2's tombstone
    // replays — never r-1's, even though both are cached.
    let repairs = gate.apply_reconcile_snapshot(&ReconcileSnapshot {
        applied_generation: 7,
        connection_event_sequence: 0,
        metrics_sequence: 0,
        metering_sequence: 0,
        connections: vec![ReconcileConnection {
            connection_id: 1,
            backend_id: "tidb-b".to_owned(),
            namespace: "ns-a".to_owned(),
            redirect_pending: true,
            generation: 7,
            pending_redirect_id: "r-2".to_owned(),
            identity: None,
            last_redirect_command_sequence: 2,
        }],
    });
    assert_eq!(repairs.replay_redirect_results, vec![second]);
    let _ = first;

    // A snapshot with nothing outstanding acknowledges the terminals:
    // the next request stops reporting a pending id.
    let _ = gate.apply_reconcile_snapshot(&ReconcileSnapshot {
        applied_generation: 7,
        connection_event_sequence: 0,
        metrics_sequence: 0,
        metering_sequence: 0,
        connections: vec![ReconcileConnection {
            connection_id: 1,
            backend_id: "tidb-b".to_owned(),
            namespace: "ns-a".to_owned(),
            redirect_pending: false,
            generation: 7,
            pending_redirect_id: String::new(),
            identity: None,
            last_redirect_command_sequence: 2,
        }],
    });
    let request = gate.build_reconcile_request(7, 0, 0);
    assert!(!request.connections[0].redirect_pending, "acked");
    assert_eq!(request.connections[0].pending_redirect_id, "");
}

/// Hostile long metering keys fail closed before any accumulation: a
/// single unbounded key could otherwise push one delta past the frame
/// bound.
#[test]
fn oversized_metering_keys_fail_closed() {
    use control_proto::v1::MeteringDelta;
    use dataplane::control_commands::{MAX_METERING_KEY_BYTES, MeteringError, MeteringLedger};
    let mut ledger = MeteringLedger::new();
    let hostile = MeteringDelta {
        keyspace: "k".repeat(MAX_METERING_KEY_BYTES + 1),
        backend_id: "tidb-a".to_owned(),
        public_endpoint: false,
        response_bytes: 1,
        cross_location_bytes: 0,
    };
    assert!(matches!(
        ledger.record(hostile),
        Err(MeteringError::OversizedKey {
            field: "keyspace",
            ..
        })
    ));
    assert_eq!(ledger.seal(), Ok(None), "nothing was accumulated");
}
