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

//! The authoritative migration/drain safety boundary and the pending-redirect
//! `BEGIN` hold (SES-07), frozen from Go `finishedTxn`, `needHoldRequest`
//! (`cmd_processor_exec.go`), the held-request execution in
//! `backend_conn_mgr.go`, and the keyword lexer in `pkg/util/lex`.
//!
//! Three pieces:
//!
//! 1. [`SessionSafety`] — the single `is_safe_boundary` decision. Go:
//!    `finishedTxn` is false while `StatusInTrans` or `StatusQuit` is set or
//!    any prepared statement has pending long-data/cursor state. The Rust
//!    authority adds one hardening dimension: transaction knowledge is a
//!    tri-state, and a disruption (cancel, unclassifiable failure) makes it
//!    [`TxnKnowledge::Unknown`], which is **never** safe until an
//!    authoritative backend status refreshes it. A `MySQL` ERR keeps the
//!    previous known state (Go `handleErrorPacket` never touches
//!    `serverStatus`) — errors that still updated status mid-multi-statement
//!    are already reflected because every applied status went through
//!    [`SessionSafety::observe_status`].
//! 2. [`need_hold_request`] — the exact Go predicate: only a `COM_QUERY`
//!    that lexes as `BEGIN`/`START TRANSACTION`, only inside a transaction,
//!    and only with no pending prepared state. The SQL text is borrowed
//!    transiently; nothing here retains or logs query bytes.
//! 3. [`HeldBegin`] — the hold lifecycle: the proxy sends an **internal**
//!    `COMMIT` (never forwarded to the client), reaches the safe boundary,
//!    lets redirect/drain fire, and then replays the held `BEGIN` exactly
//!    once — or provably never: a `COMMIT` error forwards that error to the
//!    client as the answer to its `BEGIN` (Go's `IsMySQLError` path), and a
//!    graceful close drops the held request (Go executes it only while
//!    `closeStatus < statusNotifyClose`).
//!
//! The lexer is a byte-faithful port of Go `pkg/util/lex` `Lexer.NextToken`:
//! uppercased `[a-z]`, kept `[A-Z_]`, single/double quotes with backslash
//! escapes, `--`-to-newline and `/* */` comments, everything else a
//! delimiter. It exists to make the hold decision identical to Go's, and is
//! differential-tested against Go's own `TestStartTxn` table.

use core::fmt;

use crate::command::Command;

/// Byte-faithful port of Go `pkg/util/lex` `Lexer` over a borrowed query.
struct SqlLexer<'a> {
    sql: &'a [u8],
    index: usize,
}

impl<'a> SqlLexer<'a> {
    const fn new(sql: &'a [u8]) -> Self {
        Self { sql, index: 0 }
    }

    /// Returns the next uppercased identifier/keyword token, or `""` at the
    /// end, mirroring Go `NextToken` exactly.
    fn next_token(&mut self) -> Vec<u8> {
        let mut token = Vec::new();
        let mut in_single_line_comment = false;
        let mut in_multi_line_comment = false;
        let mut in_single_quote = false;
        let mut in_double_quote = false;
        while self.index < self.sql.len() {
            let char = self.sql[self.index];
            if in_single_line_comment {
                if char == b'\n' {
                    in_single_line_comment = false;
                }
            } else if in_multi_line_comment {
                if char == b'*'
                    && self.index + 1 < self.sql.len()
                    && self.sql[self.index + 1] == b'/'
                {
                    in_multi_line_comment = false;
                    self.index += 1;
                }
            } else if in_single_quote {
                if char == b'\\' {
                    self.index += 1;
                } else if char == b'\'' {
                    in_single_quote = false;
                }
            } else if in_double_quote {
                if char == b'\\' {
                    self.index += 1;
                } else if char == b'"' {
                    in_double_quote = false;
                }
            } else if char == b'-'
                && self.index + 1 < self.sql.len()
                && self.sql[self.index + 1] == b'-'
            {
                self.index += 1;
                in_single_line_comment = true;
            } else if char == b'/'
                && self.index + 1 < self.sql.len()
                && self.sql[self.index + 1] == b'*'
            {
                self.index += 1;
                in_multi_line_comment = true;
            } else if char == b'\'' {
                in_single_quote = true;
            } else if char == b'"' {
                in_double_quote = true;
            } else if char.is_ascii_lowercase() {
                token.push(char - b'a' + b'A');
            } else if char.is_ascii_uppercase() || char == b'_' {
                token.push(char);
            } else if !token.is_empty() {
                self.index += 1;
                return token;
            }
            self.index += 1;
        }
        token
    }
}

/// Go `lex.IsStartTxn`: the query's leading tokens are `BEGIN` or
/// `START TRANSACTION`. The query bytes are borrowed transiently.
#[must_use]
pub fn is_start_txn(sql: &[u8]) -> bool {
    let mut lexer = SqlLexer::new(sql);
    let first = lexer.next_token();
    if first == b"BEGIN" {
        return true;
    }
    if first == b"START" {
        return lexer.next_token() == b"TRANSACTION";
    }
    false
}

/// Go `needHoldRequest`, byte-for-byte: hold only a `COM_QUERY` that starts
/// a transaction, only while a transaction is open, and only when no
/// prepared statement has pending state (open result sets can still be
/// fetched after `COMMIT`/`ROLLBACK`). The trailing NUL Go strips is
/// stripped here too. Nothing from `data` is retained.
#[must_use]
pub fn need_hold_request(
    command: Command,
    data: &[u8],
    in_transaction: bool,
    has_pending_prepared: bool,
) -> bool {
    if command != Command::Query {
        return false;
    }
    if !in_transaction {
        return false;
    }
    if has_pending_prepared {
        return false;
    }
    let data = match data {
        [head @ .., 0] => head,
        _ => data,
    };
    is_start_txn(data)
}

/// What the session knows about the backend transaction state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxnKnowledge {
    /// The last applied backend status said whether a transaction is open.
    Known {
        /// `SERVER_STATUS_IN_TRANS` from that status.
        in_transaction: bool,
    },
    /// A disruption (cancel, abort, unclassifiable failure) invalidated the
    /// knowledge. Never a safe boundary until refreshed.
    Unknown,
}

/// The single authoritative redirect/drain boundary decision
/// (Go `finishedTxn` plus the unknown-state hardening).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionSafety {
    txn: TxnKnowledge,
    quit: bool,
    prepared_pending: bool,
}

impl Default for SessionSafety {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionSafety {
    /// A fresh session: no transaction, no quit, no prepared state.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            txn: TxnKnowledge::Known {
                in_transaction: false,
            },
            quit: false,
            prepared_pending: false,
        }
    }

    /// Current transaction knowledge.
    #[must_use]
    pub const fn txn(&self) -> TxnKnowledge {
        self.txn
    }

    /// Applies an authoritative backend status (every OK/EOF the observers
    /// apply, including mid-multi-statement statuses before an error).
    pub const fn observe_status(&mut self, in_transaction: bool) {
        self.txn = TxnKnowledge::Known { in_transaction };
    }

    /// Marks a disruption: the backend state can no longer be inferred.
    /// A `MySQL` ERR is **not** a disruption (Go keeps `serverStatus`);
    /// use this for cancellation, upload aborts, and unclassified failures.
    pub const fn observe_disruption(&mut self) {
        self.txn = TxnKnowledge::Unknown;
    }

    /// Marks `COM_QUIT` (Go `StatusQuit`): the session never reaches a safe
    /// boundary again.
    pub const fn mark_quit(&mut self) {
        self.quit = true;
    }

    /// Mirrors the SES-05 registry's pending long-data/cursor guard.
    pub const fn set_prepared_pending(&mut self, pending: bool) {
        self.prepared_pending = pending;
    }

    /// The one authoritative decision: redirect and graceful close may
    /// proceed only when this returns true. Callers ask only at command
    /// completion — a `MORE_RESULTS` continuation or an in-flight
    /// LOCAL INFILE/change-user is not a completion.
    #[must_use]
    pub const fn is_safe_boundary(&self) -> bool {
        matches!(
            self.txn,
            TxnKnowledge::Known {
                in_transaction: false
            }
        ) && !self.quit
            && !self.prepared_pending
    }
}

/// Lifecycle phase of one held `BEGIN`/`START TRANSACTION`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeldBeginPhase {
    /// The internal `COMMIT` was sent to the current backend; its response
    /// is pending. Nothing was forwarded to the client.
    CommitInFlight,
    /// The commit succeeded; the boundary is reachable and the original
    /// request waits for exactly-once replay after redirect/drain resolves.
    Held,
    /// The request was handed out for replay (terminal).
    Replayed,
    /// The internal commit failed with a `MySQL` error that was forwarded
    /// to the client as the answer to its `BEGIN` (terminal; Go's
    /// `IsMySQLError` path — the request is deliberately not executed).
    Aborted,
    /// A graceful close consumed the session before replay (terminal; Go
    /// executes the held request only while `closeStatus <
    /// statusNotifyClose`).
    Dropped,
}

/// Effects the runtime executes for the hold flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HoldEffect {
    /// Send `COMMIT` to the current backend **internally** — the response
    /// is consumed by the proxy, never forwarded to the client.
    SendInternalCommit,
    /// Forward the failed internal commit's error packet to the client.
    ForwardCommitErrorToClient,
    /// Re-dispatch the held request on the current (possibly new) backend.
    ReplayHeldRequest,
    /// The held request is gone; nothing is replayed.
    DiscardHeldRequest,
}

/// Wrong-phase operation on a held request. Carries phases only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HoldError {
    /// The phase the hold was in.
    pub phase: HeldBeginPhase,
}

impl fmt::Display for HoldError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "illegal held-BEGIN operation while {:?}", self.phase)
    }
}

impl std::error::Error for HoldError {}

/// The hold lifecycle machine. It never stores the query bytes — the
/// runtime owns the buffered request; this machine owns only the
/// exactly-once discipline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeldBegin {
    phase: HeldBeginPhase,
}

impl HeldBegin {
    /// Starts the hold: the caller must have checked [`need_hold_request`]
    /// and a pending redirect. The first effect is the internal commit.
    #[must_use]
    pub const fn start() -> (Self, HoldEffect) {
        (
            Self {
                phase: HeldBeginPhase::CommitInFlight,
            },
            HoldEffect::SendInternalCommit,
        )
    }

    /// Current phase.
    #[must_use]
    pub const fn phase(&self) -> HeldBeginPhase {
        self.phase
    }

    /// The internal commit succeeded: the transaction is closed and the
    /// request is held for replay. The caller applies the commit's status
    /// to [`SessionSafety`] (which makes the boundary safe).
    ///
    /// # Errors
    ///
    /// Returns [`HoldError`] outside [`HeldBeginPhase::CommitInFlight`].
    pub const fn on_commit_ok(&mut self) -> Result<(), HoldError> {
        match self.phase {
            HeldBeginPhase::CommitInFlight => {
                self.phase = HeldBeginPhase::Held;
                Ok(())
            }
            phase => Err(HoldError { phase }),
        }
    }

    /// The internal commit failed with a `MySQL` error: forward that error
    /// to the client and terminate the hold — the `BEGIN` is answered by
    /// the error, so it is neither lost nor silently duplicated.
    ///
    /// # Errors
    ///
    /// Returns [`HoldError`] outside [`HeldBeginPhase::CommitInFlight`].
    pub const fn on_commit_error(&mut self) -> Result<HoldEffect, HoldError> {
        match self.phase {
            HeldBeginPhase::CommitInFlight => {
                self.phase = HeldBeginPhase::Aborted;
                Ok(HoldEffect::ForwardCommitErrorToClient)
            }
            phase => Err(HoldError { phase }),
        }
    }

    /// Takes the held request for replay after redirect/drain resolved
    /// (success **or** failure — Go replays either way). Exactly once: a
    /// second take is a typed error.
    ///
    /// # Errors
    ///
    /// Returns [`HoldError`] outside [`HeldBeginPhase::Held`].
    pub const fn take_for_replay(&mut self) -> Result<HoldEffect, HoldError> {
        match self.phase {
            HeldBeginPhase::Held => {
                self.phase = HeldBeginPhase::Replayed;
                Ok(HoldEffect::ReplayHeldRequest)
            }
            phase => Err(HoldError { phase }),
        }
    }

    /// A graceful close arrived before replay: the held request is dropped
    /// (Go executes it only while `closeStatus < statusNotifyClose`).
    ///
    /// # Errors
    ///
    /// Returns [`HoldError`] outside [`HeldBeginPhase::Held`].
    pub const fn drop_for_close(&mut self) -> Result<HoldEffect, HoldError> {
        match self.phase {
            HeldBeginPhase::Held => {
                self.phase = HeldBeginPhase::Dropped;
                Ok(HoldEffect::DiscardHeldRequest)
            }
            phase => Err(HoldError { phase }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Go `TestStartTxn`'s table, verbatim, plus lexer edge cases that the
    /// Go lexer's quote/comment handling implies.
    #[test]
    fn start_txn_matches_go_test_table() {
        let go_table: [(&[u8], bool); 11] = [
            (b"begin", true),
            (b"BEGIN", true),
            (b"begin optimistic as of timestamp now()", true),
            (b"    begin", true),
            (b"start transaction", true),
            (b"START transaction", true),
            (b"start transaction with consistent snapshot", true),
            (b"begin; select 1", true),
            (b"/*+ some_hint */begin", true),
            (b"commit", false),
            (b"select 1; begin", false),
        ];
        for (sql, expected) in go_table {
            assert_eq!(
                is_start_txn(sql),
                expected,
                "{}",
                String::from_utf8_lossy(sql)
            );
        }
        // Lexer-implied edges: comments and quotes are skipped like Go.
        assert!(is_start_txn(b"-- comment\nbegin"));
        assert!(is_start_txn(b"/* multi\nline */ START /*x*/ TRANSACTION"));
        assert!(!is_start_txn(b"'begin'"));
        assert!(!is_start_txn(b"\"begin\""));
        assert!(!is_start_txn(b""));
        assert!(!is_start_txn(b"startransaction"));
        assert!(!is_start_txn(b"start compaction"));
    }

    /// Go `needHoldRequest`: command, transaction, and prepared gates in
    /// exactly Go's order, with the trailing NUL stripped.
    #[test]
    fn need_hold_request_matches_go_gates() {
        let begin = b"BEGIN";
        assert!(need_hold_request(Command::Query, begin, true, false));
        // A trailing NUL is tolerated like Go.
        assert!(need_hold_request(Command::Query, b"BEGIN\0", true, false));
        // Non-query commands never hold (BEGIN cannot be prepared).
        assert!(!need_hold_request(Command::StmtExecute, begin, true, false));
        // Outside a transaction there is nothing to commit first.
        assert!(!need_hold_request(Command::Query, begin, false, false));
        // Pending prepared results must survive COMMIT/ROLLBACK.
        assert!(!need_hold_request(Command::Query, begin, true, true));
        // Ordinary queries never hold.
        assert!(!need_hold_request(Command::Query, b"SELECT 1", true, false));
    }

    /// The authority matrix: only known-out-of-txn, no-quit, no-prepared is
    /// safe; ERR keeps knowledge; disruption is never safe until refreshed.
    #[test]
    fn safety_matrix_matches_finished_txn_plus_unknown_hardening() {
        let mut safety = SessionSafety::new();
        assert!(safety.is_safe_boundary(), "fresh session is at a boundary");

        safety.observe_status(true);
        assert!(!safety.is_safe_boundary(), "open transaction blocks");
        // A MySQL ERR is not a disruption: the caller simply does not call
        // observe_status (Go keeps serverStatus), so the state persists.
        assert!(!safety.is_safe_boundary());
        safety.observe_status(false);
        assert!(safety.is_safe_boundary());

        safety.set_prepared_pending(true);
        assert!(!safety.is_safe_boundary(), "prepared guard blocks");
        safety.set_prepared_pending(false);
        assert!(safety.is_safe_boundary());

        safety.observe_disruption();
        assert!(!safety.is_safe_boundary(), "unknown state is never safe");
        assert_eq!(safety.txn(), TxnKnowledge::Unknown);
        // Only an authoritative status refresh restores safety.
        safety.observe_status(false);
        assert!(safety.is_safe_boundary());

        safety.mark_quit();
        assert!(!safety.is_safe_boundary(), "quit never returns to safety");
        safety.observe_status(false);
        assert!(!safety.is_safe_boundary());
    }

    /// The held BEGIN is neither lost nor duplicated: exactly-once replay,
    /// terminal error/close paths, and every wrong-phase operation typed.
    #[test]
    fn held_begin_is_exactly_once() {
        // Happy path: commit ok -> held -> replay once.
        let (mut hold, effect) = HeldBegin::start();
        assert_eq!(effect, HoldEffect::SendInternalCommit);
        assert_eq!(hold.phase(), HeldBeginPhase::CommitInFlight);
        // Taking before the commit resolves is illegal.
        assert_eq!(
            hold.take_for_replay(),
            Err(HoldError {
                phase: HeldBeginPhase::CommitInFlight
            })
        );
        assert_eq!(hold.on_commit_ok(), Ok(()));
        assert_eq!(hold.phase(), HeldBeginPhase::Held);
        assert_eq!(hold.take_for_replay(), Ok(HoldEffect::ReplayHeldRequest));
        // A second take can never duplicate the BEGIN.
        assert_eq!(
            hold.take_for_replay(),
            Err(HoldError {
                phase: HeldBeginPhase::Replayed
            })
        );
        assert_eq!(
            hold.on_commit_ok(),
            Err(HoldError {
                phase: HeldBeginPhase::Replayed
            })
        );

        // Commit error: forwarded to the client, never replayed.
        let (mut hold, _) = HeldBegin::start();
        assert_eq!(
            hold.on_commit_error(),
            Ok(HoldEffect::ForwardCommitErrorToClient)
        );
        assert_eq!(hold.phase(), HeldBeginPhase::Aborted);
        assert_eq!(
            hold.take_for_replay(),
            Err(HoldError {
                phase: HeldBeginPhase::Aborted
            })
        );

        // Graceful close: dropped, never replayed.
        let (mut hold, _) = HeldBegin::start();
        assert_eq!(hold.on_commit_ok(), Ok(()));
        assert_eq!(hold.drop_for_close(), Ok(HoldEffect::DiscardHeldRequest));
        assert_eq!(hold.phase(), HeldBeginPhase::Dropped);
        assert_eq!(
            hold.take_for_replay(),
            Err(HoldError {
                phase: HeldBeginPhase::Dropped
            })
        );
        // Dropping is only legal from Held.
        let (mut hold, _) = HeldBegin::start();
        assert_eq!(
            hold.drop_for_close(),
            Err(HoldError {
                phase: HeldBeginPhase::CommitInFlight
            })
        );
    }
}
