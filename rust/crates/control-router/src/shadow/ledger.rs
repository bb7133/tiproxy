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

use std::collections::BTreeMap;

use super::{InvalidReason, Limits, Status};

/// Observed balance policy; factor lifetime is independent of owner lifetime.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Policy {
    /// Resource factors and queries are disabled.
    Connection,
    /// Resource factors precede locality.
    Resource,
    /// Locality precedes resource factors; the resource lifetime is retained.
    Location,
}

/// Authoritative observed lifecycle input. These values cannot issue an operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// Empty owner before its first configuration or factor evaluation.
    Begin,
    /// An actual policy application, including intermediate Connection transitions.
    Policy(Policy),
    /// A retained account was created, with a fresh identity and group identity.
    Account {
        /// Fresh diagnostic account identity.
        id: u64,
        /// Group inside this owner.
        group: u64,
    },
    /// A drained account was removed; its identity remains tombstoned.
    RemoveAccount(u64),
    /// A fresh connection incarnation was observed.
    Open(u64),
    /// A route reservation was accepted by Go.
    Reserve {
        /// Session incarnation.
        session: u64,
        /// Per-session route operation sequence.
        operation: u64,
        /// Captured retained account.
        account: u64,
    },
    /// Go observed an initial connection result; duplicates are legitimate no-ops.
    Created {
        /// Session incarnation.
        session: u64,
        /// Original route operation sequence.
        operation: u64,
        /// Whether the connection succeeded.
        success: bool,
    },
    /// Go accepted a redirect; score moves before physical ownership.
    Redirect {
        /// Session incarnation.
        session: u64,
        /// Monotonically increasing redirect sequence for this session.
        operation: u64,
        /// Captured retained target.
        target: u64,
    },
    /// Go observed a redirect terminal for the original operation.
    Redirected {
        /// Session incarnation.
        session: u64,
        /// Original redirect sequence.
        operation: u64,
        /// Whether physical migration succeeded.
        success: bool,
    },
    /// Go accepted a force-close, without settling accounting yet.
    Closing {
        /// Session incarnation.
        session: u64,
        /// Monotonically increasing close sequence for this session.
        operation: u64,
    },
    /// An actual observed close; duplicate closes do not settle twice.
    Closed(u64),
    /// A live data-plane session was rehydrated into this new empty Go owner.
    Rehydrate {
        /// Fresh session incarnation in this owner.
        session: u64,
        /// Captured retained account.
        account: u64,
    },
    /// Go refused an operation; accepted accounting is unchanged.
    Rejected {
        /// Session incarnation.
        session: u64,
    },
    /// The owner stopped accepting new operations; retained tails still settle.
    Retire,
    /// Explicit complete end after all session tails have closed.
    End,
    /// Contiguous liveness/coverage watermark without a ledger change.
    Watermark,
}

/// Accounting derived from accepted observations, never copied from a Go counter.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counts {
    /// Established physical connections.
    active: u64,
    /// Accepted initial routes awaiting their create result.
    reserved: u64,
    /// Accepted redirects whose target is this account.
    incoming: u64,
    /// Accepted redirects physically still on this account.
    outgoing: u64,
}
impl Counts {
    /// Established physical connections.
    #[must_use]
    pub const fn active(self) -> u64 {
        self.active
    }

    /// Accepted initial routes awaiting their create result.
    #[must_use]
    pub const fn reserved(self) -> u64 {
        self.reserved
    }

    /// Accepted redirects targeting this account.
    #[must_use]
    pub const fn incoming(self) -> u64 {
        self.incoming
    }

    /// Accepted redirects physically retained on this account.
    #[must_use]
    pub const fn outgoing(self) -> u64 {
        self.outgoing
    }

    /// Score owner count, preserving pending redirect accounting.
    #[must_use]
    pub const fn score(self) -> u64 {
        self.active - self.outgoing + self.reserved + self.incoming
    }
}

/// Whether a valid observed event changed lifecycle state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transition {
    /// An authoritative state transition was mirrored.
    Applied,
    /// An authoritative duplicate, rejection or watermark changed no accounting.
    Ignored,
}

/// Diagnostic account projection in stable identity order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountView {
    /// Retained diagnostic identity.
    pub id: u64,
    /// Group in the same owner.
    pub group: u64,
    /// Derived physical and score counters.
    pub counts: Counts,
    /// Actual observed physical arrival order.
    pub physical_order: Vec<u64>,
    /// Account removal was observed; the tombstone remains retained.
    pub removed: bool,
}

/// Value-only snapshot for reporting and cross-language comparison.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LedgerView {
    /// This slice compares lifecycle only; it cannot qualify complete routing shadow.
    pub lifecycle_only: bool,
    /// Fresh local owner identity, unrelated to serialized or production handles.
    pub local_owner: u64,
    /// Current interval qualification.
    pub status: Status,
    /// Last successfully compared record.
    pub compared_sequence: u64,
    /// Current private resource-factor lifetime, absent in Connection policy.
    pub factor_lifetime: Option<u64>,
    /// Derived accounts, including bounded tombstones.
    pub accounts: Vec<AccountView>,
    /// Sessions with accepted redirects awaiting a terminal.
    pub pending_redirects: Vec<u64>,
    /// Sessions marked closing but not physically closed.
    pub closing: Vec<u64>,
}

#[derive(Clone, Debug, Default)]
struct Session {
    bound: bool,
    reconnect: Option<u64>,
    closed: bool,
    active: Option<u64>,
    reservation: Option<(u64, u64)>,
    redirect: Option<(u64, u64, u64)>,
    closing: Option<u64>,
    route_watermark: u64,
    redirect_watermark: u64,
    close_watermark: u64,
}

pub(super) struct Mirror {
    limits: Limits,
    retired: bool,
    factor_lifetime: Option<u64>,
    next_factor: u64,
    accounts: BTreeMap<u64, AccountView>,
    sessions: BTreeMap<u64, Session>,
    // A caller fork copies only its affected keys. Omitted retained entries,
    // including tombstones, still consume the original population limits.
    hidden_accounts: usize,
    hidden_sessions: usize,
}
impl Mirror {
    // Borrow the independent physical list; caller visit witnesses never seed it.
    pub(super) fn caller_physical(&self, account: u64) -> Option<&[u64]> {
        self.accounts
            .get(&account)
            .filter(|account| !account.removed)
            .map(|account| account.physical_order.as_slice())
    }

    pub(super) fn caller_redirect_watermark(&self, session: u64) -> Option<u64> {
        self.sessions.get(&session).map(|s| s.redirect_watermark)
    }

    // The complete retained Group inventory, never seeded from filtered native inputs.
    pub(super) fn caller_account_ids(&self, group: u64) -> impl Iterator<Item = u64> + '_ {
        self.accounts
            .iter()
            .filter(move |(_, a)| a.group == group && !a.removed)
            .map(|(id, _)| *id)
    }

    // Callers validate the scope and reserve this charge before cloning. Four
    // times physical capacity also covers a temporary vector reallocation when
    // a staged lifecycle transition appends. New bounded keys fit the separate
    // caller stage allowance; original population limits still apply.
    pub(super) fn caller_clone_charge(
        &self,
        group: u64,
        sessions: &[u64],
    ) -> Result<usize, InvalidReason> {
        if self.hidden_accounts != 0 || self.hidden_sessions != 0 {
            return Err(InvalidReason::Lifecycle);
        }
        if sessions.len() > 64 {
            return Err(InvalidReason::Capacity);
        }
        for (index, id) in sessions.iter().enumerate() {
            if *id == 0 || sessions[..index].contains(id) {
                return Err(InvalidReason::Identity);
            }
        }
        let mut charge = size_of::<Self>();
        let mut accounts = 0;
        for account in self
            .accounts
            .values()
            .filter(|a| a.group == group && !a.removed)
        {
            accounts += 1;
            if accounts > 64 {
                return Err(InvalidReason::Capacity);
            }
            let vector = account
                .physical_order
                .capacity()
                .checked_mul(4 * size_of::<u64>())
                .ok_or(InvalidReason::Capacity)?;
            charge = charge
                .checked_add(16 * size_of::<(u64, AccountView)>())
                .and_then(|n| n.checked_add(vector))
                .ok_or(InvalidReason::Capacity)?;
        }
        charge
            .checked_add(sessions.len() * 16 * size_of::<(u64, Session)>())
            .ok_or(InvalidReason::Capacity)
    }

    pub(super) fn fork_caller(&self, group: u64, sessions: &[u64]) -> Self {
        let accounts: BTreeMap<_, _> = self
            .accounts
            .iter()
            .filter(|(_, account)| account.group == group && !account.removed)
            .map(|(id, account)| (*id, account.clone()))
            .collect();
        let sessions: BTreeMap<_, _> = sessions
            .iter()
            .filter_map(|id| self.sessions.get(id).map(|state| (*id, state.clone())))
            .collect();
        Self {
            limits: self.limits,
            retired: self.retired,
            factor_lifetime: self.factor_lifetime,
            next_factor: self.next_factor,
            hidden_accounts: self.accounts.len() - accounts.len(),
            hidden_sessions: self.sessions.len() - sessions.len(),
            accounts,
            sessions,
        }
    }

    // A caller cannot create/remove accounts, retire an owner or change a
    // policy. Only validated affected account/session entries are merged. All
    // other owner history, including omitted tombstones, remains untouched.
    pub(super) fn commit_caller(&mut self, staged: Self) {
        self.accounts.extend(staged.accounts);
        self.sessions.extend(staged.sessions);
    }

    pub(super) fn new(limits: Limits) -> Self {
        Self {
            limits,
            retired: false,
            factor_lifetime: None,
            next_factor: 1,
            accounts: BTreeMap::new(),
            sessions: BTreeMap::new(),
            hidden_accounts: 0,
            hidden_sessions: 0,
        }
    }

    pub(super) fn view(&self, local_owner: u64, status: Status, sequence: u64) -> LedgerView {
        LedgerView {
            lifecycle_only: true,
            local_owner,
            status,
            compared_sequence: sequence,
            factor_lifetime: self.factor_lifetime,
            accounts: self.accounts.values().cloned().collect(),
            pending_redirects: self
                .sessions
                .iter()
                .filter_map(|(id, s)| s.redirect.map(|_| *id))
                .collect(),
            closing: self
                .sessions
                .iter()
                .filter_map(|(id, s)| s.closing.map(|_| *id))
                .collect(),
        }
    }

    fn accepting(&self) -> Result<(), InvalidReason> {
        if self.retired {
            Err(InvalidReason::Lifecycle)
        } else {
            Ok(())
        }
    }

    fn account(&self, id: u64) -> Result<&AccountView, InvalidReason> {
        self.accounts
            .get(&id)
            .filter(|a| !a.removed)
            .ok_or(InvalidReason::Identity)
    }

    fn session(&self, id: u64) -> Result<Session, InvalidReason> {
        self.sessions
            .get(&id)
            .cloned()
            .ok_or(InvalidReason::Identity)
    }

    fn open(&mut self, id: u64) -> Result<(), InvalidReason> {
        self.accepting()?;
        if id == 0 || self.sessions.contains_key(&id) {
            return Err(InvalidReason::Identity);
        }
        if self.hidden_sessions + self.sessions.len() >= self.limits.sessions {
            return Err(InvalidReason::Capacity);
        }
        self.sessions.insert(id, Session::default());
        Ok(())
    }

    // Counter and physical-list checks precede every mutation. The touched set
    // contains at most two accounts, so this never clones the whole owner.
    fn change(
        &mut self,
        deltas: &[(u64, [i8; 4])],
        remove: Option<(u64, u64)>,
        append: Option<(u64, u64)>,
    ) -> Result<(), InvalidReason> {
        let mut changed = BTreeMap::<u64, Counts>::new();
        for (id, delta) in deltas {
            let mut counts = changed
                .get(id)
                .copied()
                .unwrap_or(self.account(*id)?.counts);
            for (value, difference) in [
                &mut counts.active,
                &mut counts.reserved,
                &mut counts.incoming,
                &mut counts.outgoing,
            ]
            .into_iter()
            .zip(delta)
            {
                *value = value
                    .checked_add_signed(i64::from(*difference))
                    .ok_or(InvalidReason::Lifecycle)?;
            }
            if counts.outgoing > counts.active {
                return Err(InvalidReason::Lifecycle);
            }
            counts
                .active
                .checked_add(counts.reserved)
                .and_then(|n| n.checked_add(counts.incoming))
                .ok_or(InvalidReason::Capacity)?;
            changed.insert(*id, counts);
        }
        let removal = if let Some((id, session)) = remove {
            Some((
                id,
                self.account(id)?
                    .physical_order
                    .iter()
                    .position(|s| *s == session)
                    .ok_or(InvalidReason::Lifecycle)?,
            ))
        } else {
            None
        };
        if let Some((id, session)) = append {
            let account = self.account(id)?;
            if account.physical_order.contains(&session) && remove != Some((id, session)) {
                return Err(InvalidReason::Lifecycle);
            }
            if account.physical_order.len() >= self.limits.sessions {
                return Err(InvalidReason::Capacity);
            }
        }
        for (id, counts) in changed {
            if let Some(account) = self.accounts.get_mut(&id) {
                account.counts = counts;
            }
        }
        if let Some((id, index)) = removal
            && let Some(account) = self.accounts.get_mut(&id)
        {
            account.physical_order.remove(index);
        }
        if let Some((id, session)) = append
            && let Some(account) = self.accounts.get_mut(&id)
        {
            account.physical_order.push(session);
        }
        Ok(())
    }

    fn reserve(
        &mut self,
        session: u64,
        operation: u64,
        account: u64,
    ) -> Result<Transition, InvalidReason> {
        self.accepting()?;
        let mut state = self.session(session)?;
        if state.closed
            || state.active.is_some()
            || state.reservation.is_some()
            || operation == 0
            || operation <= state.route_watermark
        {
            return Err(InvalidReason::Lifecycle);
        }
        self.change(&[(account, [0, 1, 0, 0])], None, None)?;
        state.reservation = Some((operation, account));
        state.route_watermark = operation;
        self.sessions.insert(session, state);
        Ok(Transition::Applied)
    }

    fn created(
        &mut self,
        session: u64,
        operation: u64,
        success: bool,
    ) -> Result<Transition, InvalidReason> {
        let mut state = self.session(session)?;
        let Some((pending, account)) = state.reservation else {
            return Ok(Transition::Ignored);
        };
        if pending != operation {
            return Ok(Transition::Ignored);
        }
        self.change(
            &[(account, [i8::from(success), -1, 0, 0])],
            None,
            success.then_some((account, session)),
        )?;
        state.reservation = None;
        if success {
            state.bound = true;
            state.active = Some(account);
        }
        self.sessions.insert(session, state);
        Ok(Transition::Applied)
    }

    fn redirect(
        &mut self,
        session: u64,
        operation: u64,
        target: u64,
    ) -> Result<Transition, InvalidReason> {
        self.accepting()?;
        let mut state = self.session(session)?;
        let source = state.active.ok_or(InvalidReason::Lifecycle)?;
        if state.closed
            || state.redirect.is_some()
            || state.reconnect.is_some()
            || state.closing.is_some()
            || operation == 0
            || operation <= state.redirect_watermark
            || source == target
        {
            return Err(InvalidReason::Lifecycle);
        }
        if self.account(source)?.group != self.account(target)?.group {
            return Err(InvalidReason::Lifecycle);
        }
        self.change(
            &[(source, [0, 0, 0, 1]), (target, [0, 0, 1, 0])],
            None,
            None,
        )?;
        state.redirect = Some((operation, source, target));
        state.redirect_watermark = operation;
        self.sessions.insert(session, state);
        Ok(Transition::Applied)
    }

    fn reconnected(
        &mut self,
        session: u64,
        operation: u64,
        success: bool,
    ) -> Result<Transition, InvalidReason> {
        let mut state = self.session(session)?;
        if state.reconnect != Some(operation) {
            return Ok(Transition::Ignored);
        }
        let account = state.active.ok_or(InvalidReason::Lifecycle)?;
        if success {
            self.change(&[], Some((account, session)), Some((account, session)))?;
        }
        state.reconnect = None;
        self.sessions.insert(session, state);
        Ok(Transition::Applied)
    }

    fn redirected(
        &mut self,
        session: u64,
        operation: u64,
        success: bool,
    ) -> Result<Transition, InvalidReason> {
        let mut state = self.session(session)?;
        if state.reconnect.is_some() {
            return self.reconnected(session, operation, success);
        }
        let Some((pending, source, target)) = state.redirect else {
            return Ok(Transition::Ignored);
        };
        if pending != operation {
            return Ok(Transition::Ignored);
        }
        let moved = i8::from(success);
        self.change(
            &[(source, [-moved, 0, 0, -1]), (target, [moved, 0, -1, 0])],
            success.then_some((source, session)),
            success.then_some((target, session)),
        )?;
        state.redirect = None;
        if success {
            state.active = Some(target);
        }
        self.sessions.insert(session, state);
        Ok(Transition::Applied)
    }

    fn closing(&mut self, session: u64, operation: u64) -> Result<Transition, InvalidReason> {
        self.accepting()?;
        let mut state = self.session(session)?;
        if state.closed
            || state.active.is_none()
            || state.closing.is_some()
            || operation == 0
            || operation <= state.close_watermark
        {
            return Err(InvalidReason::Lifecycle);
        }
        state.closing = Some(operation);
        state.close_watermark = operation;
        self.sessions.insert(session, state);
        Ok(Transition::Applied)
    }

    fn closed(&mut self, session: u64) -> Result<Transition, InvalidReason> {
        let mut state = self.session(session)?;
        if state.closed {
            return Ok(Transition::Ignored);
        }
        if let Some((_, account)) = state.reservation {
            self.change(&[(account, [0, -1, 0, 0])], None, None)?;
        } else if let Some((_, source, target)) = state.redirect {
            self.change(
                &[(source, [-1, 0, 0, -1]), (target, [0, 0, -1, 0])],
                Some((source, session)),
                None,
            )?;
        } else if let Some(account) = state.active {
            self.change(&[(account, [-1, 0, 0, 0])], Some((account, session)), None)?;
        }
        state.reconnect = None;
        state.closed = true;
        state.active = None;
        state.reservation = None;
        state.redirect = None;
        state.closing = None;
        self.sessions.insert(session, state);
        Ok(Transition::Applied)
    }

    fn rehydrate(&mut self, session: u64, account: u64) -> Result<Transition, InvalidReason> {
        self.accepting()?;
        self.account(account)?;
        if session == 0 || self.sessions.contains_key(&session) {
            return Err(InvalidReason::Identity);
        }
        if self.hidden_sessions + self.sessions.len() >= self.limits.sessions {
            return Err(InvalidReason::Capacity);
        }
        self.change(&[(account, [1, 0, 0, 0])], None, Some((account, session)))?;
        self.sessions.insert(
            session,
            Session {
                bound: true,
                active: Some(account),
                ..Session::default()
            },
        );
        Ok(Transition::Applied)
    }

    pub(super) fn totals(&self) -> (u64, u64) {
        self.accounts.values().fold((0, 0), |(score, physical), a| {
            (score + a.counts.score(), physical + a.counts.active())
        })
    }

    pub(super) fn connection(&self, id: u64) -> super::live::ConnectionState {
        let Some(s) = self.sessions.get(&id).filter(|s| s.bound) else {
            return super::live::ConnectionState::default();
        };
        super::live::ConnectionState {
            present: true,
            physical: s.active.unwrap_or(0),
            score_owner: s
                .redirect
                .map_or(s.active.unwrap_or(0), |(_, _, target)| target),
            redirect_pending: s.redirect.is_some() || s.reconnect.is_some(),
            closing: s.closing.is_some(),
            closed: s.closed,
        }
    }

    pub(super) fn account_group(&self, id: u64) -> Option<u64> {
        self.accounts.get(&id).map(|account| account.group)
    }

    pub(super) fn compact_account(&self, id: u64) -> Option<super::live::AccountWitness> {
        self.accounts.get(&id).and_then(|a| {
            Some(super::live::AccountWitness {
                id,
                score: i64::try_from(a.counts.score()).ok()?,
                physical: a.counts.active,
                head: a.physical_order.first().copied().unwrap_or(0),
                tail: a.physical_order.last().copied().unwrap_or(0),
            })
        })
    }

    pub(super) fn predecessor(&self, id: u64) -> u64 {
        self.sessions
            .get(&id)
            .and_then(|s| s.active)
            .and_then(|a| self.accounts.get(&a))
            .and_then(|a| {
                a.physical_order
                    .iter()
                    .position(|s| *s == id)
                    .and_then(|i| i.checked_sub(1))
                    .and_then(|i| a.physical_order.get(i))
            })
            .copied()
            .unwrap_or(0)
    }

    pub(super) fn pending_account(&self, id: u64) -> Option<u64> {
        self.sessions
            .get(&id)
            .and_then(|s| s.reservation.map(|(_, a)| a))
    }

    pub(super) fn group_empty(&self, group: u64) -> bool {
        self.accounts
            .values()
            .all(|a| a.group != group || a.removed)
    }

    pub(super) fn selection_done(&mut self, id: u64) -> Result<(), InvalidReason> {
        let mut s = self.session(id)?;
        if s.bound || s.closed || s.reservation.is_some() || s.active.is_some() {
            return Err(InvalidReason::Lifecycle);
        }
        s.closed = true;
        self.sessions.insert(id, s);
        Ok(())
    }

    // Administrative Go reconnection marks pending before checking the callback
    // result. This live-only transition preserves that behavior, including a
    // refused callback and an already-closing physical session. It changes no
    // score owner, and does not relax the v1 ordinary Redirect contract.
    pub(super) fn reconnect(
        &mut self,
        id: u64,
        operation: u64,
        account: u64,
    ) -> Result<(), InvalidReason> {
        let mut s = self.session(id)?;
        if s.closed
            || s.active != Some(account)
            || s.redirect.is_some()
            || s.reconnect.is_some()
            || operation == 0
            || operation <= s.redirect_watermark
        {
            return Err(InvalidReason::Lifecycle);
        }
        s.reconnect = Some(operation);
        s.redirect_watermark = operation;
        self.sessions.insert(id, s);
        Ok(())
    }

    pub(super) fn apply(&mut self, event: &Event) -> Result<Transition, InvalidReason> {
        match *event {
            Event::Begin => return Err(InvalidReason::ReplayedBegin),
            Event::Policy(policy) => {
                self.accepting()?;
                if policy == Policy::Connection {
                    self.factor_lifetime = None;
                } else if self.factor_lifetime.is_none() {
                    let next = self
                        .next_factor
                        .checked_add(1)
                        .ok_or(InvalidReason::Capacity)?;
                    self.factor_lifetime = Some(self.next_factor);
                    self.next_factor = next;
                }
            }
            Event::Account { id, group } => {
                self.accepting()?;
                if id == 0 || group == 0 || self.accounts.contains_key(&id) {
                    return Err(InvalidReason::Identity);
                }
                if self.hidden_accounts + self.accounts.len() >= self.limits.accounts {
                    return Err(InvalidReason::Capacity);
                }
                self.accounts.insert(
                    id,
                    AccountView {
                        id,
                        group,
                        counts: Counts::default(),
                        physical_order: Vec::new(),
                        removed: false,
                    },
                );
            }
            Event::RemoveAccount(id) => {
                let account = self.account(id)?;
                if account.counts != Counts::default() || !account.physical_order.is_empty() {
                    return Err(InvalidReason::Lifecycle);
                }
                if let Some(account) = self.accounts.get_mut(&id) {
                    account.removed = true;
                }
            }
            Event::Open(id) => self.open(id)?,
            Event::Reserve {
                session,
                operation,
                account,
            } => return self.reserve(session, operation, account),
            Event::Created {
                session,
                operation,
                success,
            } => return self.created(session, operation, success),
            Event::Redirect {
                session,
                operation,
                target,
            } => return self.redirect(session, operation, target),
            Event::Redirected {
                session,
                operation,
                success,
            } => return self.redirected(session, operation, success),
            Event::Closing { session, operation } => return self.closing(session, operation),
            Event::Closed(session) => return self.closed(session),
            Event::Rehydrate { session, account } => return self.rehydrate(session, account),
            Event::Rejected { session } => {
                self.session(session)?;
                return Ok(Transition::Ignored);
            }
            Event::Retire => {
                if self.retired {
                    return Err(InvalidReason::Lifecycle);
                }
                self.retired = true;
            }
            Event::End => {
                if !self.retired
                    || self.sessions.values().any(|s| !s.closed)
                    || self
                        .accounts
                        .values()
                        .any(|a| a.counts != Counts::default())
                {
                    return Err(InvalidReason::Lifecycle);
                }
            }
            Event::Watermark => return Ok(Transition::Ignored),
        }
        Ok(Transition::Applied)
    }
}
