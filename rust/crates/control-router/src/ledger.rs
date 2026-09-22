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

#[cfg(test)]
use crate::factors::Factor;
use crate::factors::RedirectReason;
use crate::migration_history::MigrationHistory;
#[cfg(test)]
use crate::migration_history::{DurationKey, MAX_RETAINED_LABEL_SETS, TerminalKey};

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

/// Payload-free aggregate of one or more live router-incarnation ledgers.
///
/// This is observation only: it contains no session, backend, namespace, or
/// settlement identity and cannot authorize any routing operation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RouteLedgerEvidence {
    /// Router incarnations that are still alive, including retained routers.
    pub router_incarnations: u64,
    /// Open route sessions across those incarnations, including idle sessions.
    pub sessions: u64,
    /// Pending initial backend handshakes.
    pub reserved: u64,
    /// Established physical backend owners.
    pub active: u64,
    /// Accepted redirects awaiting physical arrival at their target.
    pub incoming: u64,
    /// Accepted redirects awaiting physical departure from their source.
    pub outgoing: u64,
    /// Exact redirect terminals that remain unsettled.
    pub unsettled_redirects: u64,
    /// Exact force-close terminals that remain unsettled.
    pub unsettled_closes: u64,
}

impl RouteLedgerEvidence {
    pub(crate) fn add(&mut self, other: Self) {
        self.router_incarnations = self
            .router_incarnations
            .saturating_add(other.router_incarnations);
        self.sessions = self.sessions.saturating_add(other.sessions);
        self.reserved = self.reserved.saturating_add(other.reserved);
        self.active = self.active.saturating_add(other.active);
        self.incoming = self.incoming.saturating_add(other.incoming);
        self.outgoing = self.outgoing.saturating_add(other.outgoing);
        self.unsettled_redirects = self
            .unsettled_redirects
            .saturating_add(other.unsettled_redirects);
        self.unsettled_closes = self.unsettled_closes.saturating_add(other.unsettled_closes);
    }
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

impl Session {
    pub(crate) const fn sequence(&self) -> u64 {
        self.sequence
    }
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
    reason: RedirectReason,
}

impl Redirect {
    pub(crate) const fn session(&self) -> &Session {
        &self.session
    }

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

    /// Why this migration was issued, frozen at acceptance. Settlement reads
    /// it back rather than recomputing, exactly as Go reads
    /// `connWrapper.redirectReason`.
    #[must_use]
    pub const fn reason(&self) -> RedirectReason {
        self.reason
    }

    /// When this migration was issued; the start of its Go-observed duration.
    #[must_use]
    pub const fn issued_at(&self) -> Instant {
        self.issued_at
    }

    /// Whether `other` is the same exact migration operation.
    ///
    /// Assignment ids and public connection ids are diagnostics.  Exact
    /// equality also requires the private router ledger/session incarnation
    /// and both retained backend owners.
    #[must_use]
    pub fn same_operation(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.session.ledger, &other.session.ledger)
            && self.session.sequence == other.session.sequence
            && self.sequence == other.sequence
            && Arc::ptr_eq(&self.source, &other.source)
            && Arc::ptr_eq(&self.target, &other.target)
    }
}

/// Exact authority for one admitted local force-close. It remains valid if
/// an accepted redirect settles before the physical close is observed.
#[derive(Clone, Debug)]
pub struct ForceClose {
    session: Session,
    sequence: u64,
    assignment: RouteAssignment,
}
impl ForceClose {
    pub(crate) const fn session(&self) -> &Session {
        &self.session
    }

    /// Assignment at close admission; diagnostic, not a settlement lookup.
    #[must_use]
    pub const fn assignment(&self) -> &RouteAssignment {
        &self.assignment
    }

    /// Whether `other` is the same exact admitted close operation.
    #[must_use]
    pub fn same_operation(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.session.ledger, &other.session.ledger)
            && self.session.sequence == other.session.sequence
            && self.sequence == other.sequence
    }
}

#[derive(Clone, Debug)]
struct Active {
    account: Arc<AccountIdentity>,
    assignment: RouteAssignment,
    redirect: Option<Redirect>,
    failed_at: Option<Instant>,
    closing: Option<ForceClose>,
}

/// Whether a terminal event changed this ledger.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Settlement {
    /// The matching live state was settled exactly once.
    Applied,
    /// A duplicate, stale, foreign, or already closed event was ignored.
    Ignored,
}

/// One settled migration, as Go observes it at `addMigrateMetrics`.
///
/// Go reads `from`, `to` and `reason` off the connection wrapper and the
/// elapsed time from `connWrapper.lastRedirect`, all captured when the
/// redirect was issued. This record carries the same frozen values so the
/// natively served `migrate_total`, `migrate_duration_seconds` and
/// `pending_migrate` series are label-identical to the retired Go ones.
#[derive(Clone, Debug, PartialEq)]
pub struct MigrationObservation {
    /// Physical source backend address at issue time. Go labels these series
    /// with `backend.addr`, the dial address, not the opaque routing id.
    pub from: String,
    /// Captured destination backend address at issue time.
    pub to: String,
    /// The frozen reason label.
    pub reason: RedirectReason,
    /// Which end of the migration this record reports.
    pub outcome: MigrationOutcome,
}

/// The two points at which Go touches the migration metrics.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum MigrationOutcome {
    /// The offer was accepted and the migration is in flight. Go increments
    /// `pending_migrate` here, and only for an accepted offer.
    Issued,
    /// The migration reached its terminal state. Go decrements
    /// `pending_migrate`, counts the result, and observes the elapsed time.
    Settled {
        /// Whether the migration succeeded.
        success: bool,
        /// Issue-to-settlement elapsed time, Go's `time.Since(lastRedirect)`.
        elapsed: Duration,
    },
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
    ForceClosing,
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

/// One migration label set, exactly Go's `(from, to, reason)`.
///
/// Held as owned strings because the backend addresses are captured when the
/// redirect is issued and must survive the routing state that produced them.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct MigrationLabels {
    /// Source backend address.
    pub from: String,
    /// Destination backend address.
    pub to: String,
    /// Reason frozen at issue.
    pub reason: RedirectReason,
}

/// The authoritative per-label-set migration state this ledger owns.
///
/// This is the truth the exposition reads, rather than a running total
/// accumulated from notifications: a lost notification leaves the reader
/// briefly stale, never permanently wrong.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MigrationTotals {
    /// Migrations accepted and not yet settled.
    pub pending: u64,
    /// Settled successfully, cumulative.
    pub succeeded: u64,
    /// Settled unsuccessfully, cumulative.
    pub failed: u64,
    /// Summed settlement latency in nanoseconds, cumulative.
    pub elapsed_nanos: u128,
}

pub(crate) struct Ledger {
    identity: Arc<()>,
    next_session: u64,
    next_reservation: u64,
    next_account: u64,
    next_redirect: u64,
    next_close: u64,
    max_sessions: usize,
    sessions: BTreeMap<u64, Stage>,
    accounts: BTreeMap<u64, Account>,
    /// Settled migrations awaiting publication. The ledger records; it never
    /// touches a metric registry itself.
    migrations: Vec<MigrationObservation>,
    /// Migrations accepted here and not yet settled, per label set.
    ///
    /// Only the in-flight count lives on the router. Cumulative history does
    /// not: destroying an incarnation would take it with them, and a
    /// cumulative series must never fall.
    pending_migrations: BTreeMap<MigrationLabels, u64>,
    /// Process-level cumulative history, shared with every other router.
    history: Arc<MigrationHistory>,
}

impl Ledger {
    pub(crate) fn new(max_sessions: usize) -> Self {
        Self::with_history(max_sessions, Arc::new(MigrationHistory::default()))
    }

    /// Builds a ledger that shares one process-level cumulative history.
    pub(crate) fn with_history(max_sessions: usize, history: Arc<MigrationHistory>) -> Self {
        Self {
            identity: Arc::new(()),
            next_session: 1,
            next_reservation: 1,
            next_account: 1,
            next_redirect: 1,
            next_close: 1,
            max_sessions,
            sessions: BTreeMap::new(),
            accounts: BTreeMap::new(),
            migrations: Vec::new(),
            pending_migrations: BTreeMap::new(),
            history,
        }
    }

    /// Physically owned connections per backend address, Go's `b_conn`.
    ///
    /// Go sets this from the backend's `connList` length, and that list only
    /// moves when a migration succeeds. The active assignment behaves the same
    /// way here -- it is rewritten on a successful settlement and left alone
    /// on a failed one -- so an accepted migration keeps counting against its
    /// source until it actually lands.
    ///
    /// Only established sessions count: a reservation that has not completed
    /// is not a physical connection, and neither is an incoming redirect that
    /// has not settled. Each session contributes exactly once.
    pub(crate) fn physical_connections(&self) -> BTreeMap<String, u64> {
        let mut counts: BTreeMap<String, u64> = BTreeMap::new();
        for stage in self.sessions.values() {
            if let Stage::Active(active) = stage {
                let address = &active.assignment.backend_address;
                if address.is_empty() {
                    continue;
                }
                // A refused address is not exposed. Admission happened when
                // the connection landed; counting it here anyway would let
                // the aggregation reinsert a series past the ceiling, so the
                // drop would be recorded and the series published regardless.
                if !self.history.knows_backend(address) {
                    continue;
                }
                *counts.entry(address.clone()).or_default() += 1;
            }
        }
        counts
    }

    /// Migrations in flight on this router, per label set.
    pub(crate) const fn pending_migrations(&self) -> &BTreeMap<MigrationLabels, u64> {
        &self.pending_migrations
    }

    /// The process-level cumulative history this ledger writes to.
    pub(crate) const fn history(&self) -> &Arc<MigrationHistory> {
        &self.history
    }

    /// Notes an accepted migration: in flight here, and its label set
    /// remembered process-wide so the series keeps reporting zero later.
    fn issue_migration(&mut self, labels: &MigrationLabels) {
        // One admission decision governs both halves of the metric. Tracking
        // pending under a separate per-ledger ceiling would let this ledger
        // fill up with sets the history never retained, and then refuse a set
        // the history did retain -- losing the real pending count of a series
        // still being exposed. A refusal costs the series, never the
        // migration: the redirect proceeds either way.
        if !self
            .history
            .remember(&labels.from, &labels.to, labels.reason)
        {
            return;
        }
        *self.pending_migrations.entry(labels.clone()).or_default() += 1;
    }

    /// Records a settlement. The in-flight count falls here; the cumulative
    /// terminal goes to the process-level history, which no router teardown
    /// can roll back. `pending` saturates at zero so an unmatched settlement
    /// cannot underflow.
    fn settle_migration(&mut self, labels: &MigrationLabels, success: bool, elapsed: Duration) {
        if let Some(pending) = self.pending_migrations.get_mut(labels) {
            *pending = pending.saturating_sub(1);
        }
        // Go settles through `PendingMigrateGuage.Dec()`, which recreates the
        // child if it was deleted, so a label set retired mid-flight comes
        // back when its migration lands. Re-admitting here keeps the one
        // admission decision in the one place the exposition reads.
        //
        // The value differs from Go in that case and deliberately so: Go's
        // `Dec()` on a recreated child reports -1, because it accumulates
        // decrements, while this pending count is read from the ledger and
        // cannot go below zero. A negative in-flight count is a Go artefact
        // of the delete, not a state the router can be in.
        self.history
            .remember(&labels.from, &labels.to, labels.reason);
        self.history
            .settle(&labels.from, &labels.to, labels.reason, success, elapsed);
    }

    /// Takes the migrations settled since the last drain.
    pub(crate) fn drain_migrations(&mut self) -> Vec<MigrationObservation> {
        std::mem::take(&mut self.migrations)
    }

    pub(crate) const fn set_max_sessions(&mut self, max_sessions: usize) {
        // Shrinking below the current population never evicts a live route.
        // It only rejects new opens until normal closes bring usage below the
        // reloadable bound.
        self.max_sessions = max_sessions;
    }

    pub(crate) fn evidence(&self) -> RouteLedgerEvidence {
        let mut evidence = RouteLedgerEvidence {
            router_incarnations: 1,
            sessions: u64::try_from(self.sessions.len()).unwrap_or(u64::MAX),
            ..RouteLedgerEvidence::default()
        };
        for account in self.accounts.values() {
            evidence.reserved = evidence.reserved.saturating_add(account.counts.reserved);
            evidence.active = evidence.active.saturating_add(account.counts.active);
            evidence.incoming = evidence.incoming.saturating_add(account.counts.incoming);
            evidence.outgoing = evidence.outgoing.saturating_add(account.counts.outgoing);
        }
        for stage in self.sessions.values() {
            if let Stage::Active(active) = stage {
                evidence.unsettled_redirects = evidence
                    .unsettled_redirects
                    .saturating_add(u64::from(active.redirect.is_some()));
                evidence.unsettled_closes = evidence
                    .unsettled_closes
                    .saturating_add(u64::from(active.closing.is_some()));
            }
        }
        evidence
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
            // Registered here, not when the exposition reads: a connection
            // that opens and closes between two scrapes must still leave its
            // address reporting zero.
            self.history
                .remember_backend(&reservation.assignment.backend_address);
            Stage::Active(Box::new(Active {
                account: Arc::clone(&reservation.account),
                assignment: reservation.assignment.clone(),
                redirect: None,
                closing: None,
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
        reason: RedirectReason,
    ) -> Result<Redirect, LedgerError> {
        let Stage::Active(active) = self.stage(session)? else {
            return Err(LedgerError::NotActive);
        };
        if active.closing.is_some() {
            return Err(LedgerError::ForceClosing);
        }
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
            reason,
        })
    }

    /// Go `Group.RedirectConnections` candidates: every active session that
    /// has no redirect pending (Go skips only `phaseRedirectNotify`; closing
    /// and cooling-down sessions are still offered).
    pub(crate) fn redirectable_sessions(&self) -> Vec<Session> {
        self.sessions
            .iter()
            .filter_map(|(sequence, stage)| match stage {
                Stage::Active(active) if active.redirect.is_none() => Some(Session {
                    ledger: Arc::clone(&self.identity),
                    sequence: *sequence,
                }),
                _ => None,
            })
            .collect()
    }

    /// Go's management/test reconnect: a redirect of the session to the
    /// backend it already owns. Unlike `prepare_redirect` it allows the same
    /// account and ignores the failure cooldown; a closing session is refused
    /// like Go's `Redirect` returning false, and a pending redirect is
    /// skipped by the caller. Accounting is the ordinary redirect accounting
    /// with source and target being one account.
    pub(crate) fn prepare_self_redirect(
        &self,
        session: &Session,
        now: Instant,
    ) -> Result<Redirect, LedgerError> {
        let Stage::Active(active) = self.stage(session)? else {
            return Err(LedgerError::NotActive);
        };
        if active.closing.is_some() {
            return Err(LedgerError::ForceClosing);
        }
        if active.redirect.is_some() {
            return Err(LedgerError::RedirectPending);
        }
        let account = self
            .account(&active.account)
            .ok_or(LedgerError::ForeignAccount)?;
        account
            .counts
            .outgoing
            .checked_add(1)
            .filter(|out| *out <= account.counts.active)
            .ok_or(LedgerError::Exhausted)?;
        account
            .counts
            .capacity_used()
            .checked_add(1)
            .ok_or(LedgerError::Exhausted)?;
        self.next_redirect
            .checked_add(1)
            .ok_or(LedgerError::Exhausted)?;
        let mut assignment = active.assignment.clone();
        assignment.connection_id = session.sequence;
        assignment.assignment_id = self.next_redirect.to_string();
        Ok(Redirect {
            session: session.clone(),
            sequence: self.next_redirect,
            source: Arc::clone(&active.account),
            target: Arc::clone(&active.account),
            from: active.assignment.clone(),
            to: assignment,
            issued_at: now,
            reason: RedirectReason::Test,
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
        if admitted {
            // Go increments the pending gauge only once the offer is accepted.
            // Recorded before the session borrow so the authoritative update
            // and the notification stay together in one place.
            let labels = MigrationLabels {
                from: redirect.from.backend_address.clone(),
                to: redirect.to.backend_address.clone(),
                reason: redirect.reason,
            };
            self.issue_migration(&labels);
            self.migrations.push(MigrationObservation {
                from: labels.from,
                to: labels.to,
                reason: labels.reason,
                outcome: MigrationOutcome::Issued,
            });
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
        now: Instant,
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
            // The connection is now physically the target's; register the
            // address at the moment it lands, for the same reason.
            self.history.remember_backend(&redirect.to.backend_address);
            // Go moves the connection with `removeConn(from)` + `addConn(to)`
            // and both call `setBackendConnMetrics`, so the source's series is
            // rewritten too. Ordinarily a no-op here; it matters after a
            // retention purge, where dropping the source's write would leave
            // the address Go shows at its new count silently absent.
            self.history
                .remember_backend(&redirect.from.backend_address);
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
        // Saturating: a settlement can never predate its own issuance, and a
        // non-monotonic reading must not panic a routing settlement.
        let elapsed = now.saturating_duration_since(redirect.issued_at);
        let labels = MigrationLabels {
            from: redirect.from.backend_address.clone(),
            to: redirect.to.backend_address.clone(),
            reason: redirect.reason,
        };
        self.settle_migration(&labels, success, elapsed);
        self.migrations.push(MigrationObservation {
            from: labels.from,
            to: labels.to,
            reason: labels.reason,
            outcome: MigrationOutcome::Settled { success, elapsed },
        });
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

    #[cfg(test)]
    pub(crate) fn worker_observation(&self, start: Instant) -> (Vec<u64>, Vec<u64>, Vec<i64>) {
        let mut pending = Vec::new();
        let mut closing = Vec::new();
        let mut failed = Vec::new();
        for id in 1..=6 {
            let mut failure = -1;
            if let Some(Stage::Active(active)) = self.sessions.get(&id) {
                if active.redirect.is_some() {
                    pending.push(id);
                } else if let Some(at) = active.failed_at {
                    failure =
                        i64::try_from(at.duration_since(start).as_nanos()).unwrap_or(i64::MAX);
                }
                if active.closing.is_some() {
                    closing.push(id);
                }
            }
            failed.push(failure);
        }
        (pending, closing, failed)
    }

    pub(crate) fn reject_keyspace(
        &mut self,
        session: &Session,
        now: Instant,
    ) -> Result<(), LedgerError> {
        let Stage::Active(active) = self.stage(session)? else {
            return Err(LedgerError::NotActive);
        };
        if active.closing.is_some() {
            return Err(LedgerError::ForceClosing);
        }
        if active.redirect.is_some() {
            return Err(LedgerError::RedirectPending);
        }
        let Some(Stage::Active(active)) = self.sessions.get_mut(&session.sequence) else {
            unreachable!("checked active");
        };
        active.failed_at = Some(now);
        Ok(())
    }
    pub(crate) fn prepare_close(
        &self,
        session: &Session,
        now: Instant,
    ) -> Result<ForceClose, LedgerError> {
        let Stage::Active(active) = self.stage(session)? else {
            return Err(LedgerError::NotActive);
        };
        if active.closing.is_some() {
            return Err(LedgerError::ForceClosing);
        }
        if active
            .failed_at
            .is_some_and(|failed| now.saturating_duration_since(failed) < Duration::from_secs(3))
        {
            return Err(LedgerError::CoolingDown);
        }
        self.next_close
            .checked_add(1)
            .ok_or(LedgerError::Exhausted)?;
        Ok(ForceClose {
            session: session.clone(),
            sequence: self.next_close,
            assignment: active.assignment.clone(),
        })
    }

    pub(crate) fn reject_close(
        &mut self,
        session: &Session,
        now: Instant,
    ) -> Result<(), LedgerError> {
        let Stage::Active(active) = self.stage(session)? else {
            return Err(LedgerError::NotActive);
        };
        if active.closing.is_some() {
            return Err(LedgerError::ForceClosing);
        }
        let Some(Stage::Active(active)) = self.sessions.get_mut(&session.sequence) else {
            unreachable!("checked active session")
        };
        active.failed_at = Some(now);
        Ok(())
    }
    pub(crate) fn admit_close(&mut self, close: ForceClose) {
        self.next_close += 1;
        let Some(Stage::Active(active)) = self.sessions.get_mut(&close.session.sequence) else {
            unreachable!("prepared active close");
        };
        active.closing = Some(close);
    }
    pub(crate) fn observe_close(&mut self, close: &ForceClose) -> Settlement {
        let Ok(Stage::Active(active)) = self.stage(&close.session) else {
            return Settlement::Ignored;
        };
        if active
            .closing
            .as_ref()
            .is_none_or(|pending| pending.sequence != close.sequence)
        {
            return Settlement::Ignored;
        }
        self.close(&close.session, Instant::now())
    }

    pub(crate) fn close(&mut self, session: &Session, now: Instant) -> Settlement {
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
                    // Go counts a migration interrupted by a close as a failed
                    // one, with its elapsed time. Releasing the accounting
                    // without recording it would leave `pending_migrate`
                    // permanently holding a migration that can never settle.
                    let elapsed = now.saturating_duration_since(redirect.issued_at);
                    let labels = MigrationLabels {
                        from: redirect.from.backend_address.clone(),
                        to: redirect.to.backend_address.clone(),
                        reason: redirect.reason,
                    };
                    self.settle_migration(&labels, false, elapsed);
                    self.migrations.push(MigrationObservation {
                        from: labels.from,
                        to: labels.to,
                        reason: labels.reason,
                        outcome: MigrationOutcome::Settled {
                            success: false,
                            elapsed,
                        },
                    });
                }
                if let Some(account) = self.accounts.get_mut(&active.account.sequence) {
                    account.counts.active -= 1;
                    account.physical.retain(|id| *id != session.sequence);
                }
                // Go's `removeConn` calls `setBackendConnMetrics` just as
                // `addConn` does, so a close recreates the child if the
                // address was deleted in between. Ordinarily a no-op -- the
                // address was admitted when the connection landed -- this
                // only matters after a retention purge, where Go would show
                // the address again at its new count and dropping the write
                // would leave it silently absent.
                self.history
                    .remember_backend(&active.assignment.backend_address);
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
    fn route_ledger_evidence_tracks_pending_active_and_terminal_state() {
        let mut ledger = Ledger::new(4);
        let source = must(ledger.add_account());
        let target = must(ledger.add_account());
        let session = must(ledger.open());
        assert_eq!(
            ledger.evidence(),
            RouteLedgerEvidence {
                router_incarnations: 1,
                sessions: 1,
                ..RouteLedgerEvidence::default()
            }
        );
        let reservation = must(ledger.reserve(&session, &source, assignment("a")));
        assert_eq!(ledger.evidence().reserved, 1);
        assert_eq!(ledger.finish(&reservation, true), Settlement::Applied);
        assert_eq!(ledger.evidence().active, 1);

        let redirect = must(ledger.prepare_redirect(
            &session,
            &target,
            assignment("b"),
            Instant::now(),
            RedirectReason::Balance(Factor::Connection),
        ));
        ledger.admit_redirect(redirect.clone(), true, Instant::now());
        let evidence = ledger.evidence();
        assert_eq!(
            (evidence.active, evidence.incoming, evidence.outgoing),
            (1, 1, 1)
        );
        assert_eq!(evidence.unsettled_redirects, 1);
        assert_eq!(ledger.close(&session, Instant::now()), Settlement::Applied);
        assert_eq!(
            ledger.evidence(),
            RouteLedgerEvidence {
                router_incarnations: 1,
                ..RouteLedgerEvidence::default()
            }
        );
    }

    #[test]
    fn self_redirect_keeps_the_account_and_rotates_physical_order() {
        let mut ledger = Ledger::new(4);
        let account = must(ledger.add_account());
        let first = must(ledger.open());
        let second = must(ledger.open());
        for session in [&first, &second] {
            let reservation = must(ledger.reserve(session, &account, assignment("a")));
            assert_eq!(ledger.finish(&reservation, true), Settlement::Applied);
        }
        assert_eq!(
            ledger
                .physical_sessions(&account)
                .iter()
                .map(|s| s.sequence)
                .collect::<Vec<_>>(),
            vec![first.sequence, second.sequence]
        );
        // Both are candidates; a pending redirect removes a session from the list.
        assert_eq!(ledger.redirectable_sessions().len(), 2);
        let redirect = must(ledger.prepare_self_redirect(&first, Instant::now()));
        assert!(Arc::ptr_eq(&redirect.source, &redirect.target));
        assert_eq!(redirect.from.backend_id, redirect.to.backend_id);
        assert_eq!(redirect.to.connection_id, first.sequence);
        ledger.admit_redirect(redirect.clone(), true, Instant::now());
        assert_eq!(
            ledger.redirectable_sessions().len(),
            1,
            "pending is skipped"
        );
        assert_eq!(
            ledger.prepare_self_redirect(&first, Instant::now()).err(),
            Some(LedgerError::RedirectPending)
        );
        let evidence = ledger.evidence();
        assert_eq!(
            (evidence.active, evidence.incoming, evidence.outgoing),
            (2, 1, 1)
        );
        assert_eq!(
            ledger.finish_redirect(&redirect, true, Instant::now()),
            Settlement::Applied
        );
        let evidence = ledger.evidence();
        assert_eq!(
            (evidence.active, evidence.incoming, evidence.outgoing),
            (2, 0, 0)
        );
        assert_eq!(
            ledger
                .physical_sessions(&account)
                .iter()
                .map(|s| s.sequence)
                .collect::<Vec<_>>(),
            vec![second.sequence, first.sequence],
            "Go removes and re-appends the connection in the same account"
        );
        // A failed self-redirect leaves the account and order untouched, and
        // the cooldown does not block the next management reconnect.
        let redirect = must(ledger.prepare_self_redirect(&second, Instant::now()));
        ledger.admit_redirect(redirect.clone(), true, Instant::now());
        assert_eq!(
            ledger.finish_redirect(&redirect, false, Instant::now()),
            Settlement::Applied
        );
        assert!(
            ledger
                .prepare_self_redirect(&second, Instant::now())
                .is_ok()
        );
        assert_eq!(
            ledger
                .prepare_redirect(
                    &second,
                    &account,
                    assignment("a"),
                    Instant::now(),
                    RedirectReason::Balance(Factor::Connection)
                )
                .err(),
            Some(LedgerError::CoolingDown),
            "the ordinary path keeps its cooldown and same-account refusal"
        );
        // A closing session is refused like Go's Redirect returning false.
        let third = must(ledger.open());
        let reservation = must(ledger.reserve(&third, &account, assignment("a")));
        assert_eq!(ledger.finish(&reservation, true), Settlement::Applied);
        let close = must(ledger.prepare_close(&third, Instant::now()));
        ledger.admit_close(close);
        assert_eq!(
            ledger.prepare_self_redirect(&third, Instant::now()).err(),
            Some(LedgerError::ForceClosing)
        );
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
        assert_eq!(ledger.close(&session, Instant::now()), Settlement::Applied);
        assert_eq!(ledger.close(&session, Instant::now()), Settlement::Ignored);
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
        assert_eq!(ledger.close(&session, Instant::now()), Settlement::Applied);
        assert_eq!(ledger.counts(&new), Some(Accounting::default()));
    }

    #[test]
    fn captured_owner_is_retained_until_idle_and_late_success_never_resurrects() {
        let mut ledger = Ledger::new(4);
        let old = must(ledger.add_account());
        let session = must(ledger.open());
        let first = must(ledger.reserve(&session, &old, assignment("a")));
        assert!(!ledger.prune(&old));
        assert_eq!(ledger.close(&session, Instant::now()), Settlement::Applied);
        assert!(ledger.prune(&old));
        let new = must(ledger.add_account());
        let replacement = must(ledger.open());
        let next = must(ledger.reserve(&replacement, &new, assignment("a")));
        assert_eq!(ledger.finish(&first, true), Settlement::Ignored);
        assert_eq!(ledger.close(&session, Instant::now()), Settlement::Ignored);
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
        assert_eq!(
            right.close(&session_left, Instant::now()),
            Settlement::Ignored
        );
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
        ledger.close(&session, Instant::now());
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
        ledger.close(&first, Instant::now());
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
                    ledger.close(
                        session.as_ref().unwrap_or_else(|| unreachable!()),
                        Instant::now(),
                    );
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
