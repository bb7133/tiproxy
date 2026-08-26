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

use std::collections::VecDeque;

use control_proto::v1::{
    CloseResult, ConnectionIdentity, DrainCommand, DrainResult, ErrorCode, MeteringBatch,
    MeteringDelta, ReconcileConnection, ReconcileRequest, ReconcileSnapshot, RedirectCommand,
    RedirectResult,
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
    /// The command's generation was minted for a different connection
    /// incarnation: answer `STALE_GENERATION`, never act.
    StaleGeneration {
        /// Generation the command was stamped with.
        command_generation: u64,
        /// Generation this connection was admitted under.
        connection_generation: u64,
    },
    /// The same command id arrived with a different sequence than it
    /// was first observed with: `PROTOCOL_VIOLATION`, never act (an id
    /// is bound to exactly one issuance).
    SequenceMismatch {
        /// The sequence the id is bound to.
        bound_sequence: u64,
        /// The mismatched sequence on this duplicate.
        command_sequence: u64,
    },
    /// The command's sequence is at or below the watermark and no cache
    /// holds its id: a delayed duplicate of an evicted terminal. Go's
    /// serialization proves its result was already consumed — the
    /// runtime answers with a `DUPLICATE_REQUEST`-coded result the
    /// issuer ignores by id; never act.
    Obsolete {
        /// The duplicate's sequence.
        command_sequence: u64,
        /// The connection's watermark.
        watermark: u64,
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
    /// The command's generation was minted for a different connection
    /// incarnation: answer `STALE_GENERATION`, never act.
    StaleGeneration {
        /// Generation the command was stamped with.
        command_generation: u64,
        /// Generation this connection was admitted under.
        connection_generation: u64,
    },
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
    /// The command's provenance generation predates the applied
    /// snapshot: answer `STALE_GENERATION`, never act. Drain is
    /// deliberately **not** per-connection exact-matched — one command
    /// spans sessions captured under different generations — so only
    /// command provenance is checked.
    StaleGeneration {
        /// Generation the command was stamped with.
        command_generation: u64,
        /// The gate's applied snapshot generation.
        applied_generation: u64,
    },
    /// The same drain id arrived with a different sequence than it was
    /// first observed with: `PROTOCOL_VIOLATION`, never act.
    SequenceMismatch {
        /// The sequence the id is bound to.
        bound_sequence: u64,
        /// The mismatched sequence on this duplicate.
        command_sequence: u64,
    },
    /// The command's sequence is at or below the issuer watermark and
    /// no tombstone holds its id: a delayed duplicate of an evicted
    /// completed drain — the runtime answers with a
    /// `DUPLICATE_REQUEST`-coded result the issuer ignores. Never
    /// restarts a drain.
    Obsolete {
        /// The duplicate's sequence.
        command_sequence: u64,
        /// The gate's drain watermark.
        watermark: u64,
    },
}

/// Which drain phase applies at an instant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrainPhase {
    /// Sessions are asked to close at safe boundaries.
    Graceful,
    /// The graceful deadline passed: no new safe-point asks; in-flight
    /// boundaries may still finish before the force deadline.
    GraceExpired,
    /// Force-close everything still active.
    Force,
    /// Accounting is final.
    Complete,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RedirectState {
    Idle,
    Pending {
        redirect_id: String,
        command_sequence: u64,
    },
}

/// Bounded per-connection terminal-result tombstones: delayed duplicates
/// of **any** finished redirect id replay their cached result instead of
/// re-executing. Go serializes redirects, so live traffic needs one
/// entry; the bound only caps pathological replay storms.
pub const MAX_TERMINAL_REDIRECTS_PER_CONNECTION: usize = 32;

/// Bounded completed-drain tombstones (same role as redirect
/// tombstones, proxy-wide).
pub const MAX_COMPLETED_DRAINS: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
enum CloseState {
    Open,
    Closing { close_id: String, force: bool },
    Terminal(CloseResult),
}

/// Per-connection control-plane state: the gate's authority for
/// idempotency and reconciliation. Session/data state stays in the
/// session loop; only identifiers live here.
/// One finished redirect: the cached result plus whether its delivery
/// has been proven by a reconcile snapshot (unacked results are the
/// exact ids a fresh Go lineage must learn about).
#[derive(Debug, Clone, PartialEq, Eq)]
struct TerminalRecord {
    result: RedirectResult,
    command_sequence: u64,
    unacked: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ConnectionControl {
    identity: ConnectionIdentity,
    backend_id: String,
    namespace: String,
    snapshot_generation: u64,
    redirect: RedirectState,
    /// Highest command sequence observed for this connection: a
    /// sequence at or below it that misses every cache is provably
    /// obsolete (Go serializes redirects, so issuing n+1 implies n's
    /// terminal was consumed) and never acts.
    redirect_watermark: u64,
    /// Terminal records in completion order (front = oldest); bounded —
    /// eviction is safe because obsolescence is proven by the
    /// watermark, not by cache residency.
    redirect_terminals: VecDeque<TerminalRecord>,
    close: CloseState,
}

impl ConnectionControl {
    fn terminal_result(&self, redirect_id: &str) -> Option<&RedirectResult> {
        self.redirect_terminals
            .iter()
            .map(|record| &record.result)
            .find(|result| result.redirect_id == redirect_id)
    }

    fn latest_unacked(&self) -> Option<&RedirectResult> {
        self.redirect_terminals
            .iter()
            .rev()
            .find(|record| record.unacked)
            .map(|record| &record.result)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DrainState {
    drain_id: String,
    command_sequence: u64,
    listener_names: Vec<String>,
    backend_ids: Vec<String>,
    graceful_deadline: Instant,
    force_deadline: Instant,
    /// Matched live sessions still open (per-id accounting: a session
    /// closes at most once, out-of-scope ids never count).
    remaining: std::collections::BTreeSet<u64>,
    matched_total: u64,
    gracefully_closed: u64,
    force_closed: u64,
    complete: bool,
}

impl DrainState {
    fn result(&self, code: ErrorCode) -> DrainResult {
        DrainResult {
            drain_id: self.drain_id.clone(),
            active_connections: self.matched_total,
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
    /// Completed-drain tombstones in completion order (front = oldest);
    /// a delayed duplicate of any completed drain id replays its final
    /// result instead of restarting a drain.
    completed_drains: VecDeque<DrainState>,
    event_sequence: u64,
    /// The last applied config snapshot generation (CTL-05): drain
    /// provenance is checked against it.
    applied_generation: u64,
    /// Issuer-wide drain sequence watermark (same obsolescence role as
    /// the per-connection redirect watermark).
    drain_watermark: u64,
    /// True only when the negotiated peer predates
    /// `RECONCILE_SESSION_REHYDRATION`: zero generations/sequences are
    /// then tolerated with the legacy tombstone-only behavior. The
    /// default is strict fail-closed.
    legacy_peer: bool,
}

impl CommandGate {
    /// Creates an empty gate.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a connection the moment it is admitted, carrying its
    /// full admission identity (re-emitted verbatim in reconciliation
    /// so a restarted Go lineage rebuilds identity-equal state) and the
    /// snapshot generation it was created under (stale generations can
    /// then never be confused with a new incarnation).
    pub fn register_connection(
        &mut self,
        identity: ConnectionIdentity,
        namespace: &str,
        snapshot_generation: u64,
    ) {
        let connection_id = identity.connection_id;
        self.connections.insert(
            connection_id,
            ConnectionControl {
                identity,
                backend_id: String::new(),
                namespace: namespace.to_owned(),
                snapshot_generation,
                redirect: RedirectState::Idle,
                redirect_watermark: 0,
                redirect_terminals: VecDeque::new(),
                close: CloseState::Open,
            },
        );
    }

    /// The connection's admission identity (for lifecycle events).
    #[must_use]
    pub fn connection_identity(&self, connection_id: u64) -> Option<ConnectionIdentity> {
        self.connections
            .get(&connection_id)
            .map(|connection| connection.identity.clone())
    }

    /// The connection's recorded snapshot generation.
    #[must_use]
    pub fn connection_generation(&self, connection_id: u64) -> Option<u64> {
        self.connections
            .get(&connection_id)
            .map(|connection| connection.snapshot_generation)
    }

    /// The connection's currently recorded backend id.
    #[must_use]
    pub fn connection_backend(&self, connection_id: u64) -> Option<String> {
        self.connections
            .get(&connection_id)
            .map(|connection| connection.backend_id.clone())
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

    /// Declares the negotiated peer legacy (predating
    /// `RECONCILE_SESSION_REHYDRATION`): zero generations and sequences
    /// are tolerated with tombstone-only dedup. Strict is the default.
    pub fn set_legacy_peer(&mut self, legacy: bool) {
        self.legacy_peer = legacy;
    }

    /// Records the applied config snapshot generation (from CTL-05
    /// snapshot application) for drain provenance checks.
    pub fn set_applied_generation(&mut self, generation: u64) {
        self.applied_generation = generation;
    }

    /// The applied config snapshot generation (the reconcile request's
    /// known generation).
    #[must_use]
    pub const fn applied_generation(&self) -> u64 {
        self.applied_generation
    }

    /// Records the request id an outgoing connection event was sent
    /// under: the ids come from the sender's single checked allocator
    /// (so they are monotonic), and the recorded maximum is the
    /// `last_connection_event_sequence` the reconcile request reports.
    pub fn record_event_sequence(&mut self, request_id: u64) {
        if request_id > self.event_sequence {
            self.event_sequence = request_id;
        }
    }

    // ------------------------------------------------------------------
    // Redirect
    // ------------------------------------------------------------------

    /// Admits one `RedirectCommand` (at most once per id).
    ///
    /// `command_generation` is the envelope's generation as stamped by
    /// Go from the connection's admission generation: a mismatch means
    /// the command was minted for a **different incarnation** and never
    /// acts (a Rust restart restarts connection ids from 1, so id reuse
    /// across generations is real). Zero is tolerated only for peers
    /// predating the field.
    pub fn admit_redirect(
        &mut self,
        command: &RedirectCommand,
        command_generation: u64,
    ) -> RedirectAdmission {
        let legacy = self.legacy_peer;
        let Some(connection) = self.connections.get_mut(&command.connection_id) else {
            return RedirectAdmission::UnknownConnection;
        };
        // State-bearing envelopes carry a nonzero generation (frozen
        // ADR); zero is tolerated only from a declared legacy peer.
        if command_generation != connection.snapshot_generation
            && !(legacy && command_generation == 0)
        {
            return RedirectAdmission::StaleGeneration {
                command_generation,
                connection_generation: connection.snapshot_generation,
            };
        }
        // A delayed duplicate of a cached finished id replays its
        // tombstone — after verifying the id is bound to the sequence
        // it was first issued with.
        if let Some(record) = connection
            .redirect_terminals
            .iter()
            .find(|record| record.result.redirect_id == command.redirect_id)
        {
            if command.command_sequence != record.command_sequence
                && !(legacy && command.command_sequence == 0)
            {
                return RedirectAdmission::SequenceMismatch {
                    bound_sequence: record.command_sequence,
                    command_sequence: command.command_sequence,
                };
            }
            return RedirectAdmission::Replay(record.result.clone());
        }
        if let RedirectState::Pending {
            redirect_id,
            command_sequence,
        } = &connection.redirect
        {
            if *redirect_id == command.redirect_id {
                if command.command_sequence != *command_sequence
                    && !(legacy && command.command_sequence == 0)
                {
                    return RedirectAdmission::SequenceMismatch {
                        bound_sequence: *command_sequence,
                        command_sequence: command.command_sequence,
                    };
                }
                return RedirectAdmission::DuplicatePending;
            }
            return RedirectAdmission::Conflict {
                pending_redirect_id: redirect_id.clone(),
            };
        }
        // Cache miss at Idle: the watermark decides new-vs-evicted. Go
        // issues n+1 only after consuming n's terminal, so a sequence at
        // or below the watermark whose id misses every cache is a
        // duplicate of an evicted, already-consumed terminal.
        let sequence = command.command_sequence;
        if sequence == 0 {
            if !legacy {
                return RedirectAdmission::Obsolete {
                    command_sequence: 0,
                    watermark: connection.redirect_watermark,
                };
            }
        } else if sequence <= connection.redirect_watermark {
            return RedirectAdmission::Obsolete {
                command_sequence: sequence,
                watermark: connection.redirect_watermark,
            };
        } else {
            connection.redirect_watermark = sequence;
        }
        connection.redirect = RedirectState::Pending {
            redirect_id: command.redirect_id.clone(),
            command_sequence: sequence,
        };
        RedirectAdmission::Start
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
        let bound_sequence = match &connection.redirect {
            RedirectState::Pending {
                redirect_id: pending,
                command_sequence,
            } if pending == redirect_id => *command_sequence,
            _ => return None,
        };
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
        connection.redirect = RedirectState::Idle;
        connection.redirect_terminals.push_back(TerminalRecord {
            result: result.clone(),
            command_sequence: bound_sequence,
            unacked: true,
        });
        while connection.redirect_terminals.len() > MAX_TERMINAL_REDIRECTS_PER_CONNECTION {
            let _ = connection.redirect_terminals.pop_front();
        }
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
        command_generation: u64,
    ) -> CloseAdmission {
        let self_legacy = self.legacy_peer;
        let Some(connection) = self.connections.get_mut(&connection_id) else {
            return CloseAdmission::UnknownConnection;
        };
        if command_generation != connection.snapshot_generation
            && !(self_legacy && command_generation == 0)
        {
            return CloseAdmission::StaleGeneration {
                command_generation,
                connection_generation: connection.snapshot_generation,
            };
        }
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
    /// `matched_connections` is the **id set** of live sessions selected
    /// by the command's listener/backend scope (collected by the caller,
    /// which owns session metadata) — recorded only on `Start`, and the
    /// authority for per-session exactly-once drain accounting.
    pub fn admit_drain(
        &mut self,
        command: &DrainCommand,
        command_generation: u64,
        graceful_deadline: Instant,
        force_deadline: Instant,
        matched_connections: std::collections::BTreeSet<u64>,
    ) -> DrainAdmission {
        // Provenance only: a drain minted before the applied snapshot
        // references configuration (listeners, backends) that may no
        // longer exist. Per-connection generations are deliberately not
        // matched here — one command spans mixed-generation sessions.
        // Zero provenance is tolerated only from a declared legacy peer.
        if (command_generation == 0 && !self.legacy_peer)
            || (command_generation != 0 && command_generation < self.applied_generation)
        {
            return DrainAdmission::StaleGeneration {
                command_generation,
                applied_generation: self.applied_generation,
            };
        }
        if let Some(active) = &self.drain {
            if active.drain_id == command.drain_id {
                if command.command_sequence != active.command_sequence
                    && !(self.legacy_peer && command.command_sequence == 0)
                {
                    return DrainAdmission::SequenceMismatch {
                        bound_sequence: active.command_sequence,
                        command_sequence: command.command_sequence,
                    };
                }
                return DrainAdmission::Progress(active.result(ErrorCode::Ok));
            }
            return DrainAdmission::Conflict(active.result(ErrorCode::DrainInProgress));
        }
        if let Some(done) = self
            .completed_drains
            .iter()
            .find(|done| done.drain_id == command.drain_id)
        {
            if command.command_sequence != done.command_sequence
                && !(self.legacy_peer && command.command_sequence == 0)
            {
                return DrainAdmission::SequenceMismatch {
                    bound_sequence: done.command_sequence,
                    command_sequence: command.command_sequence,
                };
            }
            return DrainAdmission::Replay(done.result(ErrorCode::Ok));
        }
        // Cache miss: the issuer-wide watermark proves evicted-completed
        // duplicates obsolete (the issuer is single-flight, so issuing a
        // later drain implies the earlier one completed).
        let sequence = command.command_sequence;
        if sequence == 0 {
            if !self.legacy_peer {
                return DrainAdmission::Obsolete {
                    command_sequence: 0,
                    watermark: self.drain_watermark,
                };
            }
        } else if sequence <= self.drain_watermark {
            return DrainAdmission::Obsolete {
                command_sequence: sequence,
                watermark: self.drain_watermark,
            };
        } else {
            self.drain_watermark = sequence;
        }
        let matched_total = u64::try_from(matched_connections.len()).unwrap_or(u64::MAX);
        self.drain = Some(DrainState {
            drain_id: command.drain_id.clone(),
            command_sequence: sequence,
            listener_names: command.listener_names.clone(),
            backend_ids: command.backend_ids.clone(),
            graceful_deadline,
            force_deadline,
            remaining: matched_connections,
            matched_total,
            gracefully_closed: 0,
            force_closed: 0,
            complete: matched_total == 0,
        });
        if matched_total == 0 {
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

    /// The phase the active drain is in at `now`, if one is active:
    /// safe-point closes are requested until the graceful deadline;
    /// between the deadlines no new graceful asks are made while
    /// in-flight boundaries finish; at the force deadline everything
    /// still open is force-closed.
    #[must_use]
    pub fn drain_phase(&self, now: Instant) -> Option<DrainPhase> {
        let drain = self.drain.as_ref()?;
        if drain.complete {
            Some(DrainPhase::Complete)
        } else if now >= drain.force_deadline {
            Some(DrainPhase::Force)
        } else if now >= drain.graceful_deadline {
            Some(DrainPhase::GraceExpired)
        } else {
            Some(DrainPhase::Graceful)
        }
    }

    /// Records one drained session closing, keyed by connection id: a
    /// session counts at most once (duplicate closes are no-ops) and an
    /// id outside the matched set never counts. Counters are monotonic
    /// and can never go negative or overshoot by construction.
    /// Returns the **terminal** `DrainResult` when this close completes
    /// the active drain (the completion transition must proactively
    /// reach the issuer — it never re-asks).
    pub fn record_drain_close(&mut self, connection_id: u64, forced: bool) -> Option<DrainResult> {
        let drain = self.drain.as_mut()?;
        if !drain.remaining.remove(&connection_id) {
            return None;
        }
        if forced {
            drain.force_closed += 1;
        } else {
            drain.gracefully_closed += 1;
        }
        if drain.remaining.is_empty() {
            self.finish_drain();
            return self
                .completed_drains
                .back()
                .map(|done| done.result(ErrorCode::Ok));
        }
        None
    }

    /// The terminal result of a completed drain by id (a zero-match
    /// admission completes immediately, so its very first answer is the
    /// terminal).
    #[must_use]
    pub fn completed_drain_result(&self, drain_id: &str) -> Option<DrainResult> {
        self.completed_drains
            .iter()
            .find(|done| done.drain_id == drain_id)
            .map(|done| done.result(ErrorCode::Ok))
    }

    /// Current progress of the active drain (for the periodic report),
    /// if one is active.
    #[must_use]
    pub fn drain_progress(&self) -> Option<DrainResult> {
        self.drain.as_ref().map(|drain| drain.result(ErrorCode::Ok))
    }

    /// The matched sessions still open under the active drain.
    #[must_use]
    pub fn drain_remaining(&self) -> Vec<u64> {
        self.drain
            .as_ref()
            .map(|drain| drain.remaining.iter().copied().collect())
            .unwrap_or_default()
    }

    fn finish_drain(&mut self) {
        if let Some(mut drain) = self.drain.take() {
            drain.complete = true;
            self.completed_drains.push_back(drain);
            while self.completed_drains.len() > MAX_COMPLETED_DRAINS {
                let _ = self.completed_drains.pop_front();
            }
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
                // "Pending" to the peer means: a redirect id whose
                // terminal result the peer may not have seen — either
                // truly in flight or finished with an unacknowledged
                // (possibly lost) result. The exact id lets a fresh
                // lineage restore it and lets the snapshot answer prove
                // which tombstone to replay.
                redirect_pending: matches!(connection.redirect, RedirectState::Pending { .. })
                    || connection.latest_unacked().is_some(),
                generation: connection.snapshot_generation,
                pending_redirect_id: match &connection.redirect {
                    RedirectState::Pending { redirect_id, .. } => redirect_id.clone(),
                    RedirectState::Idle => connection
                        .latest_unacked()
                        .map(|result| result.redirect_id.clone())
                        .unwrap_or_default(),
                },
                identity: Some(connection.identity.clone()),
                last_redirect_command_sequence: connection.redirect_watermark,
            })
            .collect();
        connections.sort_by_key(|connection| connection.connection_id);
        ReconcileRequest {
            known_generation,
            last_connection_event_sequence: self.event_sequence,
            last_metrics_sequence,
            last_metering_sequence,
            connections,
            last_drain_command_sequence: self.drain_watermark,
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
            match self.connections.get_mut(&remote.connection_id) {
                None => ghost_connections.push(remote.connection_id),
                Some(local) => {
                    if remote.redirect_pending {
                        if matches!(local.redirect, RedirectState::Pending { .. }) {
                            // Truly still in flight: the session will
                            // produce the one terminal result itself.
                        } else if !remote.pending_redirect_id.is_empty() {
                            // The peer names the exact id it still
                            // believes outstanding: replay that
                            // tombstone and only that tombstone.
                            if let Some(result) = local.terminal_result(&remote.pending_redirect_id)
                            {
                                replay_redirect_results.push(result.clone());
                            }
                        } else if let Some(result) = local.latest_unacked() {
                            // Legacy peer without the id field: Go
                            // serialization bounds the outstanding set
                            // to one, and only an unacked terminal can
                            // be it.
                            replay_redirect_results.push(result.clone());
                        }
                    } else {
                        // The peer's authoritative view has nothing
                        // outstanding: every terminal produced so far
                        // was seen or is obsolete — acknowledge them so
                        // later requests stop re-reporting.
                        for record in &mut local.redirect_terminals {
                            record.unacked = false;
                        }
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

/// Producer-side metering with **deduplicated cumulative** semantics
/// (CTL-06 scope): deltas accumulate into an open batch (merged by
/// `(keyspace, backend_id, public_endpoint)`), sealed batches carry a
/// strictly monotonic sequence and are retained until the peer's
/// reconcile acknowledges them. The consumer applies a batch only when
/// its sequence exceeds the last applied one, so at-least-once replay
/// with stable sequences never double-counts.
///
/// Sealed batches are **never coalesced**: a batch the peer may already
/// have applied must replay byte-identical under its original sequence,
/// or the dedup rule would double-count its deltas. Only the open
/// (never-sent) accumulation merges. Metrics, by contrast, are best
/// effort end to end: the transport sheds `MetricsBatch` bodies under
/// bulk-lane pressure with a typed local counter
/// (`control-proto::control_transport`), and nothing here depends on a
/// metrics sequence.
#[derive(Debug, Default)]
pub struct MeteringLedger {
    last_sealed_sequence: u64,
    open: Vec<MeteringDelta>,
    unacked: VecDeque<MeteringBatch>,
}

/// Typed metering-ledger failure: metering is never dropped, so every
/// bound fails closed for the caller to apply backpressure or declare
/// the control stream unhealthy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeteringError {
    /// The sealed-but-unacknowledged retention bound was hit.
    BacklogFull {
        /// Retained sealed batches.
        unacked: usize,
    },
    /// The strictly monotonic sequence space is exhausted; continuing
    /// would freeze or reuse a sequence and silently lose data.
    SequenceExhausted,
    /// A single delta's counters would overflow the cumulative entry.
    CounterOverflow,
    /// A metering key exceeds its byte bound; unbounded keys would let
    /// one delta alone exceed the control frame bound.
    OversizedKey {
        /// The offending field.
        field: &'static str,
        /// Observed bytes.
        actual: usize,
        /// The bound.
        limit: usize,
    },
}

/// Hard bound on retained sealed batches awaiting acknowledgement.
pub const MAX_UNACKED_METERING_BATCHES: usize = 1024;
/// Hard bound on one metering key field (`keyspace` / `backend_id`).
pub const MAX_METERING_KEY_BYTES: usize = 256;
/// Hard bound on deltas in one sealed batch. Worst-case encoded size is
/// provably inside the 1 MiB control frame bound:
/// `1024 deltas × (2 × (256 key bytes + 3 tag/len) + 2 × 11 varint
/// counters + 1 bool + ~6 framing) ≈ 1024 × 547 ≈ 548 KiB`, plus the
/// batch header — under 60% of the frame bound.
pub const MAX_DELTAS_PER_BATCH: usize = 1024;

impl MeteringLedger {
    /// Creates an empty ledger.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Accumulates one delta into the open batch, merging with an
    /// existing entry for the same `(keyspace, backend_id,
    /// public_endpoint)` key (cumulative, checked). When the open batch
    /// would exceed its delta bound the ledger seals it first, so a
    /// single batch always fits the control frame.
    ///
    /// # Errors
    ///
    /// Fails closed — nothing is recorded and nothing already recorded
    /// is lost — when a counter would overflow, or when an implied seal
    /// hits the retention or sequence bound.
    pub fn record(&mut self, delta: MeteringDelta) -> Result<(), MeteringError> {
        for (field, len) in [
            ("keyspace", delta.keyspace.len()),
            ("backend_id", delta.backend_id.len()),
        ] {
            if len > MAX_METERING_KEY_BYTES {
                return Err(MeteringError::OversizedKey {
                    field,
                    actual: len,
                    limit: MAX_METERING_KEY_BYTES,
                });
            }
        }
        if let Some(existing) = self.open.iter_mut().find(|entry| {
            entry.keyspace == delta.keyspace
                && entry.backend_id == delta.backend_id
                && entry.public_endpoint == delta.public_endpoint
        }) {
            let response = existing
                .response_bytes
                .checked_add(delta.response_bytes)
                .ok_or(MeteringError::CounterOverflow)?;
            let cross = existing
                .cross_location_bytes
                .checked_add(delta.cross_location_bytes)
                .ok_or(MeteringError::CounterOverflow)?;
            existing.response_bytes = response;
            existing.cross_location_bytes = cross;
            return Ok(());
        }
        if self.open.len() >= MAX_DELTAS_PER_BATCH {
            // Seal to keep every batch within the frame bound; the seal
            // itself fails closed on retention/sequence exhaustion.
            let _ = self.seal()?;
        }
        self.open.push(delta);
        Ok(())
    }

    /// Seals the open accumulation into the next sequenced batch for
    /// sending; returns `None` when nothing accumulated.
    ///
    /// # Errors
    ///
    /// Fails closed (leaving the accumulation intact) when the unacked
    /// retention bound is reached or the sequence space is exhausted —
    /// metering is never dropped, so the caller must apply backpressure
    /// instead.
    pub fn seal(&mut self) -> Result<Option<MeteringBatch>, MeteringError> {
        if self.open.is_empty() {
            return Ok(None);
        }
        if self.unacked.len() >= MAX_UNACKED_METERING_BATCHES {
            return Err(MeteringError::BacklogFull {
                unacked: self.unacked.len(),
            });
        }
        let sequence = self
            .last_sealed_sequence
            .checked_add(1)
            .ok_or(MeteringError::SequenceExhausted)?;
        self.last_sealed_sequence = sequence;
        let batch = MeteringBatch {
            sequence,
            deltas: std::mem::take(&mut self.open),
        };
        self.unacked.push_back(batch.clone());
        Ok(Some(batch))
    }

    /// The last sealed sequence (for `ReconcileRequest`).
    #[must_use]
    pub const fn last_sequence(&self) -> u64 {
        self.last_sealed_sequence
    }

    /// Applies the peer's acknowledged sequence (from its reconcile
    /// snapshot): every retained batch at or below it is dropped.
    pub fn acked_through(&mut self, sequence: u64) {
        while self
            .unacked
            .front()
            .is_some_and(|batch| batch.sequence <= sequence)
        {
            let _ = self.unacked.pop_front();
        }
    }

    /// Sealed batches the peer has not acknowledged, in sequence order:
    /// replayed verbatim after a reconnect. The peer's
    /// sequence-greater-than dedup makes the replay idempotent.
    #[must_use]
    pub fn replay(&self) -> Vec<MeteringBatch> {
        self.unacked.iter().cloned().collect()
    }

    /// Retained unacknowledged batch count.
    #[must_use]
    pub fn unacked_len(&self) -> usize {
        self.unacked.len()
    }
}
