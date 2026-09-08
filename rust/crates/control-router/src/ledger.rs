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

//! Exact session/attempt ownership, serialized by the enclosing router lock.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use control_routing::RouteAssignment;

/// Live connection accounting for one backend owner.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Accounting {
    /// Reserved connections whose backend handshake has not completed.
    reserved: u64,
    /// Established connections still owned by this backend.
    active: u64,
    incoming: u64,
    outgoing: u64,
}

impl Accounting {
    #[cfg(test)]
    pub(crate) const fn for_balance_test(
        active: u64,
        reserved: u64,
        incoming: u64,
        outgoing: u64,
    ) -> Self {
        Self {
            reserved,
            active,
            incoming,
            outgoing,
        }
    }

    #[cfg(test)]
    pub(crate) const fn for_factor_test(active: u64, reserved: u64) -> Self {
        Self {
            reserved,
            active,
            incoming: 0,
            outgoing: 0,
        }
    }

    /// Pending backend handshakes charged to this owner.
    #[must_use]
    pub const fn reserved(self) -> u64 {
        self.reserved
    }

    /// Established connections charged to this owner.
    #[must_use]
    pub const fn active(self) -> u64 {
        self.active
    }

    /// Accepted redirects targeting this owner, before physical completion.
    #[must_use]
    pub const fn incoming(self) -> u64 {
        self.incoming
    }

    /// Physical connections whose accepted redirect targets another owner.
    #[must_use]
    pub const fn outgoing(self) -> u64 {
        self.outgoing
    }

    /// Go transfers score on admission, but physical ownership only on success.
    #[must_use]
    pub const fn connection_score(self) -> u64 {
        self.active - self.outgoing + self.reserved + self.incoming
    }

    fn capacity_used(self) -> u64 {
        // Outgoing connections may fail and return their score. They must not
        // release capacity that would make that infallible rollback overflow.
        self.active + self.reserved + self.incoming
    }
}

/// An opaque session incarnation minted by one router.
///
/// Clones refer to the same session. A connection's externally supplied ID is
/// not sufficient to forge this handle or revive a closed session.
#[derive(Clone, Debug)]
pub struct Session {
    ledger: Arc<()>,
    sequence: u64,
}

#[derive(Debug)]
pub(crate) struct AccountIdentity {
    sequence: u64,
}

/// One immutable pending assignment and its exact settlement authority.
///
/// A clone represents the same attempt. Retrying an aborted attempt creates a
/// new reservation, so a late result can never settle its successor.
#[derive(Clone, Debug)]
pub struct Reservation {
    session: Session,
    sequence: u64,
    account: Arc<AccountIdentity>,
    assignment: RouteAssignment,
}

impl Reservation {
    pub(crate) fn belongs_to(&self, session: &Session) -> bool {
        Arc::ptr_eq(&self.session.ledger, &session.ledger)
            && self.session.sequence == session.sequence
    }

    /// Assignment metadata, independent of its private settlement identity.
    #[must_use]
    pub const fn assignment(&self) -> &RouteAssignment {
        &self.assignment
    }
}

/// Exact authority for one accepted migration in an isolated simulation.
/// This is deliberately distinct from an initial handshake reservation.
#[derive(Clone, Debug)]
pub struct Redirect {
    session: Session,
    sequence: u64,
    pub(crate) source: Arc<AccountIdentity>,
    pub(crate) target: Arc<AccountIdentity>,
    from: RouteAssignment,
    to: RouteAssignment,
    issued_at: Instant,
}

impl Redirect {
    /// Captured physical assignment before this operation.
    #[must_use]
    pub const fn from(&self) -> &RouteAssignment {
        &self.from
    }
    /// Captured destination; neither a new lookup nor settlement authority.
    #[must_use]
    pub const fn to(&self) -> &RouteAssignment {
        &self.to
    }
}

#[derive(Clone, Debug)]
struct Active {
    account: Arc<AccountIdentity>,
    assignment: RouteAssignment,
    redirect: Option<Redirect>,
    failed_at: Option<Instant>,
}

/// Whether a terminal event changed this ledger.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Settlement {
    /// The matching live state was settled exactly once.
    Applied,
    /// A duplicate, stale, foreign, or already closed event was ignored.
    Ignored,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LedgerError {
    ForeignSession,
    ClosedSession,
    AlreadyActive,
    ForeignAccount,
    Exhausted,
    Capacity,
    NotActive,
    RedirectPending,
    CoolingDown,
    SameAccount,
    CrossKeyspace,
}

#[derive(Clone, Debug)]
enum Stage {
    Idle,
    Pending(Reservation),
    Active(Box<Active>),
}

#[derive(Debug)]
struct Account {
    identity: Arc<AccountIdentity>,
    counts: Accounting,
    // Only actual connection/redirect success appends to this physical list.
    physical: Vec<u64>,
}

pub(crate) struct Ledger {
    identity: Arc<()>,
    next_session: u64,
    next_reservation: u64,
    next_account: u64,
    next_redirect: u64,
    max_sessions: usize,
    sessions: BTreeMap<u64, Stage>,
    accounts: BTreeMap<u64, Account>,
}

impl Ledger {
    pub(crate) fn new(max_sessions: usize) -> Self {
        Self {
            identity: Arc::new(()),
            next_session: 1,
            next_reservation: 1,
            next_account: 1,
            next_redirect: 1,
            max_sessions,
            sessions: BTreeMap::new(),
            accounts: BTreeMap::new(),
        }
    }

    pub(crate) fn open(&mut self) -> Result<Session, LedgerError> {
        if self.sessions.len() >= self.max_sessions {
            return Err(LedgerError::Capacity);
        }
        let next = self
            .next_session
            .checked_add(1)
            .ok_or(LedgerError::Exhausted)?;
        let session = Session {
            ledger: Arc::clone(&self.identity),
            sequence: self.next_session,
        };
        self.next_session = next;
        self.sessions.insert(session.sequence, Stage::Idle);
        Ok(session)
    }

    pub(crate) fn add_account(&mut self) -> Result<Arc<AccountIdentity>, LedgerError> {
        let next = self
            .next_account
            .checked_add(1)
            .ok_or(LedgerError::Exhausted)?;
        let identity = Arc::new(AccountIdentity {
            sequence: self.next_account,
        });
        self.next_account = next;
        self.accounts.insert(
            identity.sequence,
            Account {
                identity: Arc::clone(&identity),
                counts: Accounting::default(),
                physical: Vec::new(),
            },
        );
        Ok(identity)
    }

    pub(crate) fn counts(&self, identity: &Arc<AccountIdentity>) -> Option<Accounting> {
        self.account(identity).map(|account| account.counts)
    }

    pub(crate) fn prune(&mut self, identity: &Arc<AccountIdentity>) -> bool {
        if self.counts(identity) != Some(Accounting::default()) {
            return false;
        }
        self.accounts.remove(&identity.sequence);
        true
    }

    fn account(&self, identity: &Arc<AccountIdentity>) -> Option<&Account> {
        self.accounts
            .get(&identity.sequence)
            .filter(|account| Arc::ptr_eq(&account.identity, identity))
    }

    pub(crate) fn pending(&self, session: &Session) -> Result<Option<Reservation>, LedgerError> {
        match self.stage(session)? {
            Stage::Idle => Ok(None),
            Stage::Pending(reservation) => Ok(Some(reservation.clone())),
            Stage::Active(_) => Err(LedgerError::AlreadyActive),
        }
    }

    fn stage(&self, session: &Session) -> Result<&Stage, LedgerError> {
        if !Arc::ptr_eq(&session.ledger, &self.identity) {
            return Err(LedgerError::ForeignSession);
        }
        self.sessions
            .get(&session.sequence)
            .ok_or(LedgerError::ClosedSession)
    }

    pub(crate) fn reserve(
        &mut self,
        session: &Session,
        identity: &Arc<AccountIdentity>,
        mut assignment: RouteAssignment,
    ) -> Result<Reservation, LedgerError> {
        if let Some(reservation) = self.pending(session)? {
            return Ok(reservation);
        }
        let account = self.account(identity).ok_or(LedgerError::ForeignAccount)?;
        account
            .counts
            .capacity_used()
            .checked_add(1)
            .ok_or(LedgerError::Exhausted)?;
        let next = self
            .next_reservation
            .checked_add(1)
            .ok_or(LedgerError::Exhausted)?;
        assignment.connection_id = session.sequence;
        assignment.assignment_id = self.next_reservation.to_string();
        let reservation = Reservation {
            session: session.clone(),
            sequence: self.next_reservation,
            account: Arc::clone(identity),
            assignment,
        };
        // All fallible checks precede the first counter or state change.
        self.next_reservation = next;
        if let Some(account) = self.accounts.get_mut(&identity.sequence) {
            account.counts.reserved += 1;
        }
        self.sessions
            .insert(session.sequence, Stage::Pending(reservation.clone()));
        Ok(reservation)
    }

    pub(crate) fn finish(&mut self, reservation: &Reservation, connected: bool) -> Settlement {
        let Ok(Stage::Pending(pending)) = self.stage(&reservation.session) else {
            return Settlement::Ignored;
        };
        if pending.sequence != reservation.sequence
            || !Arc::ptr_eq(&pending.account, &reservation.account)
        {
            return Settlement::Ignored;
        }
        // Settle the captured account, never the latest backend-ID lookup.
        let Some(account) = self.accounts.get_mut(&reservation.account.sequence) else {
            return Settlement::Ignored;
        };
        if !Arc::ptr_eq(&account.identity, &reservation.account) {
            return Settlement::Ignored;
        }
        account.counts.reserved -= 1;
        let stage = if connected {
            account.counts.active += 1;
            account.physical.push(reservation.session.sequence);
            Stage::Active(Box::new(Active {
                account: Arc::clone(&reservation.account),
                assignment: reservation.assignment.clone(),
                redirect: None,
                failed_at: None,
            }))
        } else {
            Stage::Idle
        };
        self.sessions.insert(reservation.session.sequence, stage);
        Settlement::Applied
    }

    /// Physical arrival order, including pending redirects until they succeed.
    /// A session ID is an identity, never a sorting key for migrated arrivals.
    pub(crate) fn physical_sessions(&self, owner: &Arc<AccountIdentity>) -> Vec<Session> {
        self.account(owner)
            .into_iter()
            .flat_map(|account| &account.physical)
            .map(|&sequence| Session {
                ledger: Arc::clone(&self.identity),
                sequence,
            })
            .collect()
    }

    pub(crate) fn active_owner(
        &self,
        session: &Session,
    ) -> Result<&Arc<AccountIdentity>, LedgerError> {
        match self.stage(session)? {
            Stage::Active(active) => Ok(&active.account),
            _ => Err(LedgerError::NotActive),
        }
    }

    /// Read-only preparation. The enclosing lock must remain held until the
    /// bounded offer and accept/reject finish; no callback may reenter it.
    pub(crate) fn prepare_redirect(
        &self,
        session: &Session,
        target: &Arc<AccountIdentity>,
        mut assignment: RouteAssignment,
        now: Instant,
    ) -> Result<Redirect, LedgerError> {
        let Stage::Active(active) = self.stage(session)? else {
            return Err(LedgerError::NotActive);
        };
        if active.redirect.is_some() {
            return Err(LedgerError::RedirectPending);
        }
        if active
            .failed_at
            .is_some_and(|failed| now.saturating_duration_since(failed) < Duration::from_secs(3))
        {
            return Err(LedgerError::CoolingDown);
        }
        if Arc::ptr_eq(&active.account, target) {
            return Err(LedgerError::SameAccount);
        }
        if active.assignment.keyspace != assignment.keyspace {
            return Err(LedgerError::CrossKeyspace);
        }
        let source = self
            .account(&active.account)
            .ok_or(LedgerError::ForeignAccount)?;
        let target_account = self.account(target).ok_or(LedgerError::ForeignAccount)?;
        source
            .counts
            .outgoing
            .checked_add(1)
            .filter(|out| *out <= source.counts.active)
            .ok_or(LedgerError::Exhausted)?;
        target_account
            .counts
            .capacity_used()
            .checked_add(1)
            .ok_or(LedgerError::Exhausted)?;
        self.next_redirect
            .checked_add(1)
            .ok_or(LedgerError::Exhausted)?;
        assignment.connection_id = session.sequence;
        assignment.assignment_id = self.next_redirect.to_string();
        Ok(Redirect {
            session: session.clone(),
            sequence: self.next_redirect,
            source: Arc::clone(&active.account),
            target: Arc::clone(target),
            from: active.assignment.clone(),
            to: assignment,
            issued_at: now,
        })
    }

    pub(crate) fn admit_redirect(&mut self, redirect: Redirect, admitted: bool, now: Instant) {
        // Only called immediately after prepare_redirect under the same lock.
        if admitted {
            self.next_redirect += 1;
            self.accounts
                .get_mut(&redirect.source.sequence)
                .unwrap_or_else(|| unreachable!("prepared source"))
                .counts
                .outgoing += 1;
            self.accounts
                .get_mut(&redirect.target.sequence)
                .unwrap_or_else(|| unreachable!("prepared target"))
                .counts
                .incoming += 1;
        }
        let Some(Stage::Active(active)) = self.sessions.get_mut(&redirect.session.sequence) else {
            unreachable!("prepared active session")
        };
        if admitted {
            active.redirect = Some(redirect);
        } else {
            active.failed_at = Some(now);
        }
    }

    pub(crate) fn finish_redirect(
        &mut self,
        redirect: &Redirect,
        success: bool,
        _now: Instant,
    ) -> Settlement {
        let Ok(Stage::Active(active)) = self.stage(&redirect.session) else {
            return Settlement::Ignored;
        };
        let Some(pending) = &active.redirect else {
            return Settlement::Ignored;
        };
        if pending.sequence != redirect.sequence
            || !Arc::ptr_eq(&pending.source, &redirect.source)
            || !Arc::ptr_eq(&pending.target, &redirect.target)
        {
            return Settlement::Ignored;
        }
        self.release_redirect(redirect);
        if success {
            let source = self
                .accounts
                .get_mut(&redirect.source.sequence)
                .unwrap_or_else(|| unreachable!("retained source"));
            source.counts.active -= 1;
            source
                .physical
                .retain(|id| *id != redirect.session.sequence);
            let target = self
                .accounts
                .get_mut(&redirect.target.sequence)
                .unwrap_or_else(|| unreachable!("retained target"));
            target.counts.active += 1;
            target.physical.push(redirect.session.sequence);
        }
        let Some(Stage::Active(active)) = self.sessions.get_mut(&redirect.session.sequence) else {
            unreachable!("matching active session")
        };
        active.redirect = None;
        if success {
            active.account = Arc::clone(&redirect.target);
            active.assignment = redirect.to.clone();
            active.failed_at = None;
        } else {
            // Go's cooldown starts at issuance, not when the failure arrives.
            active.failed_at = Some(redirect.issued_at);
        }
        Settlement::Applied
    }

    fn release_redirect(&mut self, redirect: &Redirect) {
        self.accounts
            .get_mut(&redirect.source.sequence)
            .unwrap_or_else(|| unreachable!("retained source"))
            .counts
            .outgoing -= 1;
        self.accounts
            .get_mut(&redirect.target.sequence)
            .unwrap_or_else(|| unreachable!("retained target"))
            .counts
            .incoming -= 1;
    }

    pub(crate) fn close(&mut self, session: &Session) -> Settlement {
        if self.stage(session).is_err() {
            return Settlement::Ignored;
        }
        let Some(stage) = self.sessions.remove(&session.sequence) else {
            return Settlement::Ignored;
        };
        match stage {
            Stage::Idle => (),
            Stage::Pending(reservation) => {
                if let Some(account) = self.accounts.get_mut(&reservation.account.sequence) {
                    account.counts.reserved -= 1;
                }
            }
            Stage::Active(active) => {
                if let Some(redirect) = active.redirect {
                    self.release_redirect(&redirect);
                }
                if let Some(account) = self.accounts.get_mut(&active.account.sequence) {
                    account.counts.active -= 1;
                    account.physical.retain(|id| *id != session.sequence);
                }
            }
        }
        Settlement::Applied
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt::Write;

    fn must<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
        result.unwrap_or_else(|error| unreachable!("fixture failed: {error:?}"))
    }

    fn assignment(id: &str) -> RouteAssignment {
        RouteAssignment {
            backend_id: id.into(),
            ..RouteAssignment::default()
        }
    }

    #[test]
    fn pending_retransmission_commits_once_and_close_retires_the_session() {
        let mut ledger = Ledger::new(4);
        let account = must(ledger.add_account());
        let session = must(ledger.open());
        let first = must(ledger.reserve(&session, &account, assignment("a")));
        let duplicate = must(ledger.reserve(&session, &account, assignment("b")));
        assert_eq!(first.sequence, duplicate.sequence);
        assert_eq!(duplicate.assignment.backend_id, "a");
        assert_eq!(
            ledger.counts(&account),
            Some(Accounting {
                reserved: 1,
                active: 0,
                ..Accounting::default()
            })
        );
        assert_eq!(ledger.finish(&first, true), Settlement::Applied);
        assert_eq!(ledger.finish(&duplicate, false), Settlement::Ignored);
        assert_eq!(
            ledger.counts(&account),
            Some(Accounting {
                reserved: 0,
                active: 1,
                ..Accounting::default()
            })
        );
        assert_eq!(ledger.close(&session), Settlement::Applied);
        assert_eq!(ledger.close(&session), Settlement::Ignored);
        assert_eq!(ledger.finish(&first, true), Settlement::Ignored);
        assert_eq!(ledger.counts(&account), Some(Accounting::default()));
        assert!(matches!(
            ledger.reserve(&session, &account, assignment("a")),
            Err(LedgerError::ClosedSession)
        ));
    }

    #[test]
    fn failed_attempt_cannot_settle_its_successor_or_another_backend_owner() {
        let mut ledger = Ledger::new(4);
        let old = must(ledger.add_account());
        let new = must(ledger.add_account());
        let session = must(ledger.open());
        let first = must(ledger.reserve(&session, &old, assignment("same-id")));
        assert_eq!(ledger.finish(&first, false), Settlement::Applied);
        let second = must(ledger.reserve(&session, &new, assignment("same-id")));
        assert_eq!(ledger.finish(&first, true), Settlement::Ignored);
        assert_eq!(ledger.finish(&first, false), Settlement::Ignored);
        assert_eq!(ledger.counts(&old), Some(Accounting::default()));
        assert_eq!(
            ledger.counts(&new),
            Some(Accounting {
                reserved: 1,
                active: 0,
                ..Accounting::default()
            })
        );
        assert_eq!(ledger.finish(&second, true), Settlement::Applied);
        assert_eq!(ledger.close(&session), Settlement::Applied);
        assert_eq!(ledger.counts(&new), Some(Accounting::default()));
    }

    #[test]
    fn captured_owner_is_retained_until_idle_and_late_success_never_resurrects() {
        let mut ledger = Ledger::new(4);
        let old = must(ledger.add_account());
        let session = must(ledger.open());
        let first = must(ledger.reserve(&session, &old, assignment("a")));
        assert!(!ledger.prune(&old));
        assert_eq!(ledger.close(&session), Settlement::Applied);
        assert!(ledger.prune(&old));
        let new = must(ledger.add_account());
        let replacement = must(ledger.open());
        let next = must(ledger.reserve(&replacement, &new, assignment("a")));
        assert_eq!(ledger.finish(&first, true), Settlement::Ignored);
        assert_eq!(ledger.close(&session), Settlement::Ignored);
        assert_eq!(
            ledger.counts(&new),
            Some(Accounting {
                reserved: 1,
                active: 0,
                ..Accounting::default()
            })
        );
        assert_eq!(ledger.finish(&next, true), Settlement::Applied);
    }

    #[test]
    fn foreign_equal_sequences_are_not_authority() {
        let mut left = Ledger::new(4);
        let mut right = Ledger::new(4);
        let account_left = must(left.add_account());
        let account_right = must(right.add_account());
        let session_left = must(left.open());
        let session_right = must(right.open());
        let reservation = must(left.reserve(&session_left, &account_left, assignment("a")));
        let _ = must(right.reserve(&session_right, &account_right, assignment("a")));
        assert_eq!(right.finish(&reservation, true), Settlement::Ignored);
        assert_eq!(right.close(&session_left), Settlement::Ignored);
        assert!(right.counts(&account_left).is_none());
        assert!(!right.prune(&account_left));
        assert_eq!(
            right.counts(&account_right),
            Some(Accounting {
                reserved: 1,
                active: 0,
                ..Accounting::default()
            })
        );
    }

    #[test]
    fn overflow_and_capacity_fail_before_mutation_and_tables_do_not_grow_on_close() {
        let mut ledger = Ledger::new(1);
        let account = must(ledger.add_account());
        let session = must(ledger.open());
        assert!(matches!(ledger.open(), Err(LedgerError::Capacity)));
        ledger.next_reservation = u64::MAX;
        assert!(matches!(
            ledger.reserve(&session, &account, assignment("a")),
            Err(LedgerError::Exhausted)
        ));
        assert_eq!(ledger.counts(&account), Some(Accounting::default()));
        assert!(must(ledger.pending(&session)).is_none());
        ledger.close(&session);
        assert!(ledger.sessions.is_empty());
        ledger.next_session = u64::MAX;
        assert!(matches!(ledger.open(), Err(LedgerError::Exhausted)));
        assert!(ledger.sessions.is_empty());
        ledger.next_account = u64::MAX;
        assert!(matches!(ledger.add_account(), Err(LedgerError::Exhausted)));
        assert_eq!(ledger.accounts.len(), 1);
    }

    #[test]
    fn stable_account_keeps_all_active_and_pending_connections() {
        let mut ledger = Ledger::new(10);
        let account = must(ledger.add_account());
        let first = must(ledger.open());
        let second = must(ledger.open());
        let a = must(ledger.reserve(&first, &account, assignment("a")));
        ledger.finish(&a, true);
        let b = must(ledger.reserve(&second, &account, assignment("a")));
        assert_eq!(
            ledger.counts(&account).map(Accounting::connection_score),
            Some(2)
        );
        ledger.close(&first);
        assert_eq!(
            ledger.counts(&account),
            Some(Accounting {
                active: 0,
                reserved: 1,
                ..Accounting::default()
            })
        );
        ledger.finish(&b, true);
        assert_eq!(
            ledger.counts(&account).map(Accounting::connection_score),
            Some(1)
        );
    }
    #[test]
    fn shared_go_ledger_observation() {
        let Ok(input) = std::env::var("CPROUTE_LEDGER_FIXTURE") else {
            return;
        };
        let rows = must(std::fs::read_to_string(input));
        let mut output = String::new();
        let mut ledger = Ledger::new(10);
        let account = must(ledger.add_account());
        let mut session = None;
        let mut current: Option<Reservation> = None;
        let mut previous: Option<Reservation> = None;
        for row in rows
            .lines()
            .filter(|row| !row.is_empty() && !row.starts_with('#'))
        {
            let (id, action) = row
                .split_once('\t')
                .unwrap_or_else(|| unreachable!("two columns"));
            match action {
                "reserve" => {
                    previous = current.take();
                    let opened = must(ledger.open());
                    current = Some(must(ledger.reserve(&opened, &account, assignment("a"))));
                    session = Some(opened);
                }
                "repeat" => {
                    let repeated = must(ledger.reserve(
                        session.as_ref().unwrap_or_else(|| unreachable!()),
                        &account,
                        assignment("b"),
                    ));
                    assert_eq!(
                        repeated.sequence,
                        current.as_ref().unwrap_or_else(|| unreachable!()).sequence
                    );
                }
                "commit" | "fail" => {
                    ledger.finish(
                        current.as_ref().unwrap_or_else(|| unreachable!()),
                        action == "commit",
                    );
                }
                "close" => {
                    ledger.close(session.as_ref().unwrap_or_else(|| unreachable!()));
                }
                "old_commit" | "old_fail" => {
                    ledger.finish(
                        previous.as_ref().unwrap_or_else(|| unreachable!()),
                        action == "old_commit",
                    );
                }
                "fail_retry" => {
                    previous = current.take();
                    ledger.finish(previous.as_ref().unwrap_or_else(|| unreachable!()), false);
                    current = Some(must(ledger.reserve(
                        session.as_ref().unwrap_or_else(|| unreachable!()),
                        &account,
                        assignment("a"),
                    )));
                }
                _ => unreachable!("unknown fixture action"),
            }
            let counts = ledger.counts(&account).unwrap_or_else(|| unreachable!());
            must(writeln!(
                output,
                "{id}\t{}\t{}",
                counts.connection_score(),
                counts.active
            ));
        }
        must(std::fs::write(
            must(std::env::var("CPROUTE_LEDGER_OUTPUT")),
            output,
        ));
    }
}

#[cfg(test)]
#[path = "ledger_redirect_tests.rs"]
mod redirect_tests;

#[cfg(test)]
#[path = "ledger_arrival_tests.rs"]
mod arrival_tests;
