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

//! Idempotent control-command admission (CTL-06).
//!
//! Delayed, duplicate, or lost control messages must be harmless to
//! router and connection state (control protocol v1 §"Redirect and
//! drain", §"reconciliation"). [`CommandGate`] is the **single-owner**
//! component on the control-handler task that admits redirect, close,
//! and drain commands before they reach any session, and produces every
//! terminal result exactly once:
//!
//! - **Redirect** is keyed by `(connection_id, redirect_id)`. A
//!   duplicate of the pending id is absorbed (its one result is still
//!   coming); a duplicate of the terminal id replays the cached result;
//!   a *different* id while one is pending is a protocol violation (Go
//!   does not issue a new redirect until the prior id is terminal).
//!   Completion for an id that is not pending is suppressed — at most
//!   one terminal result per id, ever.
//! - **Close** is keyed by `(connection_id, close_id)`. A duplicate id
//!   replays the cached result; a *different* close id for an
//!   already-closing connection returns its current state without
//!   scheduling a second close (spec §`CloseCommand`).
//! - **Drain** is keyed by `drain_id`, at most one active. Repeating
//!   the active id returns current progress; a different concurrent id
//!   is rejected with `DRAIN_IN_PROGRESS`; re-issuing a *completed*
//!   drain id replays its final result. Graceful/force phases are
//!   decided against the command's absolute deadlines.
//! - **Reconciliation** (spec: Rust sends applied generation, active
//!   connection/backend pairs, redirect-pending flags, and delivery
//!   sequences; Go rebuilds idempotency/accounting state): the gate
//!   builds the `ReconcileRequest` from its own authoritative
//!   per-connection state and, from Go's answering snapshot, computes
//!   the terminal redirect results Go still believes are pending —
//!   "a lost result is replayed after reconciliation".
//! - **Connection events** carry a monotonic sequence
//!   ([`CommandGate::next_event_sequence`]) so lost OPENED/CLOSED
//!   events are detectable and repairable through the reconcile
//!   sequence exchange.
//!
//! Stale-generation isolation: every connection records the snapshot
//! generation it was admitted under (DPL-00 registry); the gate carries
//! that generation into reconciliation and never lets a command retire
//! state belonging to a different connection incarnation — unknown
//! connection ids answer `RECONCILIATION_REQUIRED` instead of acting.
//!
//! No `MySQL` payload bytes appear anywhere here: commands and results
//! carry identifiers, addresses, and counters only.

use std::collections::HashMap;

use control_proto::v1::{
    CloseResult, DrainCommand, DrainResult, ErrorCode, ReconcileConnection, ReconcileRequest,
    ReconcileSnapshot, RedirectCommand, RedirectResult,
};
use tokio::time::Instant;

/// Admission decision for one `RedirectCommand`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RedirectAdmission {
    /// New id at a quiescent connection: forward
    /// `SessionControl::Redirect` to the session loop; exactly one
    /// completion is now owed.
    Start,
    /// Duplicate of the pending id: absorb — its single terminal result
    /// is still coming.
    DuplicatePending,
    /// Duplicate of the last terminal id: replay the cached result
    /// verbatim.
    Replay(RedirectResult),
    /// A different id while one is pending: protocol violation (Go
    /// serializes redirects per connection on terminal results).
    Conflict {
        /// The id still awaiting its terminal result.
        pending_redirect_id: String,
    },
    /// The connection is unknown to this gate: answer
    /// `RECONCILIATION_REQUIRED`, never act.
    UnknownConnection,
}

/// Admission decision for one `CloseCommand`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CloseAdmission {
    /// New close id on an open connection: drive the session
    /// (`GracefulClose` or `CloseImmediate` when forced); exactly one
    /// `CloseResult` is now owed.
    Start {
        /// `RedirectableConn.ForceClose` mapping.
        force: bool,
    },
    /// Duplicate of the known close id: replay the cached result.
    Replay(CloseResult),
    /// A different close id while the connection is already closing:
    /// report current state, never schedule a second close.
    AlreadyClosing(CloseResult),
    /// The connection is unknown: answer `RECONCILIATION_REQUIRED`.
    UnknownConnection,
}

/// Admission decision for one `DrainCommand`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DrainAdmission {
    /// New drain: begin the graceful phase against the selected
    /// listeners/backends.
    Start,
    /// The active drain id repeated: current progress.
    Progress(DrainResult),
    /// A completed drain id repeated: its final result.
    Replay(DrainResult),
    /// A different id while one drain is active.
    Conflict(DrainResult),
}

/// Which drain phase applies at an instant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrainPhase {
    /// Sessions close only at safe boundaries.
    Graceful,
    /// Force-close everything still active.
    Force,
    /// Both deadlines passed and accounting is final.
    Complete,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RedirectState {
    Idle,
    Pending { redirect_id: String },
    Terminal(RedirectResult),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CloseState {
    Open,
    Closing { close_id: String, force: bool },
    Terminal(CloseResult),
}

/// Per-connection control-plane state: the gate's authority for
/// idempotency and reconciliation. Session/data state stays in the
/// session loop; only identifiers live here.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ConnectionControl {
    backend_id: String,
    namespace: String,
    snapshot_generation: u64,
    redirect: RedirectState,
    close: CloseState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DrainState {
    drain_id: String,
    listener_names: Vec<String>,
    backend_ids: Vec<String>,
    graceful_deadline: Instant,
    force_deadline: Instant,
    active_connections: u64,
    gracefully_closed: u64,
    force_closed: u64,
    complete: bool,
}

impl DrainState {
    fn result(&self, code: ErrorCode) -> DrainResult {
        DrainResult {
            drain_id: self.drain_id.clone(),
            active_connections: self.active_connections,
            gracefully_closed: self.gracefully_closed,
            force_closed: self.force_closed,
            complete: self.complete,
            code: code.into(),
            detail: String::new(),
        }
    }
}

/// Single-owner idempotent admission for redirect/close/drain plus
/// reconciliation state. Lives on the control-handler task; no lock.
#[derive(Debug, Default)]
pub struct CommandGate {
    connections: HashMap<u64, ConnectionControl>,
    drain: Option<DrainState>,
    last_completed_drain: Option<DrainState>,
    event_sequence: u64,
}

impl CommandGate {
    /// Creates an empty gate.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a connection the moment it is admitted, carrying the
    /// snapshot generation it was created under (stale generations can
    /// then never be confused with a new incarnation).
    pub fn register_connection(
        &mut self,
        connection_id: u64,
        namespace: &str,
        snapshot_generation: u64,
    ) {
        self.connections.insert(
            connection_id,
            ConnectionControl {
                backend_id: String::new(),
                namespace: namespace.to_owned(),
                snapshot_generation,
                redirect: RedirectState::Idle,
                close: CloseState::Open,
            },
        );
    }

    /// Records the connection's current backend (after a successful
    /// route/redirect).
    pub fn set_backend(&mut self, connection_id: u64, backend_id: &str) {
        if let Some(connection) = self.connections.get_mut(&connection_id) {
            backend_id.clone_into(&mut connection.backend_id);
        }
    }

    /// Removes a connection after its terminal CLOSED event; the drain
    /// accounting (if one is active and matched it) is updated by the
    /// caller via [`Self::record_drain_close`] first.
    pub fn unregister_connection(&mut self, connection_id: u64) {
        self.connections.remove(&connection_id);
    }

    /// Live connection count (never negative by construction).
    #[must_use]
    pub fn len(&self) -> usize {
        self.connections.len()
    }

    /// Whether the gate tracks no connections.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.connections.is_empty()
    }

    /// The next monotonic sequence for an outgoing connection event.
    pub fn next_event_sequence(&mut self) -> u64 {
        self.event_sequence = self.event_sequence.saturating_add(1);
        self.event_sequence
    }

    // ------------------------------------------------------------------
    // Redirect
    // ------------------------------------------------------------------

    /// Admits one `RedirectCommand` (at most once per id).
    pub fn admit_redirect(&mut self, command: &RedirectCommand) -> RedirectAdmission {
        let Some(connection) = self.connections.get_mut(&command.connection_id) else {
            return RedirectAdmission::UnknownConnection;
        };
        match &connection.redirect {
            RedirectState::Pending { redirect_id } => {
                if *redirect_id == command.redirect_id {
                    RedirectAdmission::DuplicatePending
                } else {
                    RedirectAdmission::Conflict {
                        pending_redirect_id: redirect_id.clone(),
                    }
                }
            }
            RedirectState::Terminal(result) if result.redirect_id == command.redirect_id => {
                RedirectAdmission::Replay(result.clone())
            }
            RedirectState::Idle | RedirectState::Terminal(_) => {
                connection.redirect = RedirectState::Pending {
                    redirect_id: command.redirect_id.clone(),
                };
                RedirectAdmission::Start
            }
        }
    }

    /// Completes the pending redirect with its **single** terminal
    /// result. Returns the result to send, or `None` when the
    /// completion does not match the pending id (late or duplicate
    /// session signals are suppressed — a terminal result is never
    /// produced twice).
    pub fn complete_redirect(
        &mut self,
        connection_id: u64,
        redirect_id: &str,
        succeeded: bool,
        new_backend_id: &str,
        code: ErrorCode,
    ) -> Option<RedirectResult> {
        let connection = self.connections.get_mut(&connection_id)?;
        match &connection.redirect {
            RedirectState::Pending {
                redirect_id: pending,
            } if pending == redirect_id => {}
            _ => return None,
        }
        let previous_backend_id = connection.backend_id.clone();
        if succeeded {
            new_backend_id.clone_into(&mut connection.backend_id);
        }
        let result = RedirectResult {
            connection_id,
            redirect_id: redirect_id.to_owned(),
            previous_backend_id,
            backend_id: if succeeded {
                new_backend_id.to_owned()
            } else {
                connection.backend_id.clone()
            },
            succeeded,
            code: code.into(),
            detail: String::new(),
        };
        connection.redirect = RedirectState::Terminal(result.clone());
        Some(result)
    }

    // ------------------------------------------------------------------
    // Close
    // ------------------------------------------------------------------

    /// Admits one `CloseCommand` (at most one scheduled close per
    /// connection; duplicate ids replay).
    pub fn admit_close(
        &mut self,
        connection_id: u64,
        close_id: &str,
        force: bool,
    ) -> CloseAdmission {
        let Some(connection) = self.connections.get_mut(&connection_id) else {
            return CloseAdmission::UnknownConnection;
        };
        match &connection.close {
            CloseState::Open => {
                connection.close = CloseState::Closing {
                    close_id: close_id.to_owned(),
                    force,
                };
                CloseAdmission::Start { force }
            }
            CloseState::Closing {
                close_id: current, ..
            } => {
                let accepted_state = CloseResult {
                    connection_id,
                    close_id: current.clone(),
                    accepted: true,
                    code: ErrorCode::Ok.into(),
                    detail: String::new(),
                };
                if current == close_id {
                    CloseAdmission::Replay(accepted_state)
                } else {
                    CloseAdmission::AlreadyClosing(accepted_state)
                }
            }
            CloseState::Terminal(result) => {
                if result.close_id == close_id {
                    CloseAdmission::Replay(result.clone())
                } else {
                    CloseAdmission::AlreadyClosing(result.clone())
                }
            }
        }
    }

    /// Records the accepted close's terminal `CloseResult` (once); a
    /// completion that does not match the scheduled id is suppressed.
    pub fn complete_close(&mut self, connection_id: u64, close_id: &str) -> Option<CloseResult> {
        let connection = self.connections.get_mut(&connection_id)?;
        match &connection.close {
            CloseState::Closing {
                close_id: current, ..
            } if current == close_id => {}
            _ => return None,
        }
        let result = CloseResult {
            connection_id,
            close_id: close_id.to_owned(),
            accepted: true,
            code: ErrorCode::Ok.into(),
            detail: String::new(),
        };
        connection.close = CloseState::Terminal(result.clone());
        Some(result)
    }

    // ------------------------------------------------------------------
    // Drain
    // ------------------------------------------------------------------

    /// Admits one `DrainCommand`.
    ///
    /// `matched_connections` is the number of live sessions selected by
    /// the command's listener/backend scope (counted by the caller,
    /// which owns session metadata) — recorded only on `Start`.
    pub fn admit_drain(
        &mut self,
        command: &DrainCommand,
        graceful_deadline: Instant,
        force_deadline: Instant,
        matched_connections: u64,
    ) -> DrainAdmission {
        if let Some(active) = &self.drain {
            if active.drain_id == command.drain_id {
                return DrainAdmission::Progress(active.result(ErrorCode::Ok));
            }
            return DrainAdmission::Conflict(active.result(ErrorCode::DrainInProgress));
        }
        if let Some(done) = &self.last_completed_drain
            && done.drain_id == command.drain_id
        {
            return DrainAdmission::Replay(done.result(ErrorCode::Ok));
        }
        self.drain = Some(DrainState {
            drain_id: command.drain_id.clone(),
            listener_names: command.listener_names.clone(),
            backend_ids: command.backend_ids.clone(),
            graceful_deadline,
            force_deadline,
            active_connections: matched_connections,
            gracefully_closed: 0,
            force_closed: 0,
            complete: matched_connections == 0,
        });
        if matched_connections == 0 {
            self.finish_drain();
        }
        DrainAdmission::Start
    }

    /// Whether a live session (by listener name and current backend) is
    /// inside the active drain's scope. An empty selector list matches
    /// everything (whole-proxy drain).
    #[must_use]
    pub fn drain_selects(&self, listener_name: &str, backend_id: &str) -> bool {
        let Some(drain) = &self.drain else {
            return false;
        };
        let listener_match = drain.listener_names.is_empty()
            || drain
                .listener_names
                .iter()
                .any(|name| name == listener_name);
        let backend_match =
            drain.backend_ids.is_empty() || drain.backend_ids.iter().any(|id| id == backend_id);
        listener_match && backend_match
    }

    /// The phase the active drain is in at `now`, if one is active.
    #[must_use]
    pub fn drain_phase(&self, now: Instant) -> Option<DrainPhase> {
        let drain = self.drain.as_ref()?;
        if drain.complete {
            Some(DrainPhase::Complete)
        } else if now >= drain.force_deadline {
            Some(DrainPhase::Force)
        } else {
            Some(DrainPhase::Graceful)
        }
    }

    /// Records one drained session closing. Counters never go negative
    /// or overshoot: closes beyond the matched population are ignored
    /// (a session can only close once).
    pub fn record_drain_close(&mut self, forced: bool) {
        let Some(drain) = self.drain.as_mut() else {
            return;
        };
        if drain.gracefully_closed + drain.force_closed >= drain.active_connections {
            return;
        }
        if forced {
            drain.force_closed += 1;
        } else {
            drain.gracefully_closed += 1;
        }
        if drain.gracefully_closed + drain.force_closed >= drain.active_connections {
            self.finish_drain();
        }
    }

    /// Current progress of the active drain (for the periodic report),
    /// if one is active.
    #[must_use]
    pub fn drain_progress(&self) -> Option<DrainResult> {
        self.drain.as_ref().map(|drain| drain.result(ErrorCode::Ok))
    }

    fn finish_drain(&mut self) {
        if let Some(mut drain) = self.drain.take() {
            drain.complete = true;
            self.last_completed_drain = Some(drain);
        }
    }

    // ------------------------------------------------------------------
    // Reconciliation
    // ------------------------------------------------------------------

    /// Builds the `ReconcileRequest` from the gate's authoritative
    /// state (spec: applied generation, active connection/backend
    /// pairs, redirect-pending flags, and delivery sequences).
    #[must_use]
    pub fn build_reconcile_request(
        &self,
        known_generation: u64,
        last_metrics_sequence: u64,
        last_metering_sequence: u64,
    ) -> ReconcileRequest {
        let mut connections: Vec<ReconcileConnection> = self
            .connections
            .iter()
            .map(|(connection_id, connection)| ReconcileConnection {
                connection_id: *connection_id,
                backend_id: connection.backend_id.clone(),
                namespace: connection.namespace.clone(),
                redirect_pending: matches!(connection.redirect, RedirectState::Pending { .. }),
            })
            .collect();
        connections.sort_by_key(|connection| connection.connection_id);
        ReconcileRequest {
            known_generation,
            last_connection_event_sequence: self.event_sequence,
            last_metrics_sequence,
            last_metering_sequence,
            connections,
        }
    }

    /// Applies Go's answering `ReconcileSnapshot` and returns the
    /// repairs this side owes:
    ///
    /// - terminal redirect results Go still believes are pending
    ///   ("a lost result is replayed after reconciliation");
    /// - ghost connections (Go lists them, this gate does not know
    ///   them) that the caller must answer with terminal CLOSED events
    ///   so Go's accounting converges without negative counts.
    #[must_use]
    pub fn apply_reconcile_snapshot(&mut self, snapshot: &ReconcileSnapshot) -> ReconcileRepairs {
        let mut replay_redirect_results = Vec::new();
        let mut ghost_connections = Vec::new();
        for remote in &snapshot.connections {
            match self.connections.get(&remote.connection_id) {
                None => ghost_connections.push(remote.connection_id),
                Some(local) => {
                    if remote.redirect_pending
                        && let RedirectState::Terminal(result) = &local.redirect
                    {
                        replay_redirect_results.push(result.clone());
                    }
                }
            }
        }
        ghost_connections.sort_unstable();
        replay_redirect_results.sort_by_key(|result| result.connection_id);
        ReconcileRepairs {
            replay_redirect_results,
            ghost_connections,
        }
    }
}

/// Repairs owed after applying a reconcile snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ReconcileRepairs {
    /// Cached terminal redirect results the peer still believes are
    /// pending: replay verbatim.
    pub replay_redirect_results: Vec<RedirectResult>,
    /// Connections the peer lists but this side does not know: answer
    /// with terminal CLOSED events (never negative counts).
    pub ghost_connections: Vec<u64>,
}
