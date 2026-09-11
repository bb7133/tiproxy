// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Router metadata rebuilt independently from the original health refresh
//! inputs and the values each grouping decision actually read: group inventory
//! and order, membership, the redirection gate and the Group / `NoGroup` /
//! Conflict / `ObserverError` classification of a client. Go's outcomes arrive
//! only as witnesses. Group identities are bound to the real `GroupCreated` /
//! native Init / `GroupRemoved` lifecycle; a failed construction is an explicit
//! pair, never silently dropped. This component has no factory, wire dispatch,
//! ledger or effect capability; the caller supplies the ledger's per-account
//! idle view for removals and the shared D+R+C+S admission for growth.
use self::state::{
    BackendState, GroupState, State, Visit, derive_outcome, union_size, values_clone_charge,
};
use super::pass::Groups;
use super::selection::ErrorClass;
use super::{Epoch, InvalidReason, LiveEvent};
use control_routing::group::{ClientInfo, GroupMatcher, MatchType};
use std::mem::size_of;

mod state;

/// Backends per refresh; more is a Capacity failure, never truncation.
pub const MAX_BACKENDS: usize = 64;
/// Aggregate grouping values per refresh, per contract; no per-backend bound.
pub const MAX_VALUES: usize = 256;
/// Longest single grouping value, matching the caller string bound.
pub const MAX_VALUE_BYTES: usize = 512;
/// Aggregate value bytes per refresh, matching the caller aggregate bound.
pub const MAX_REFRESH_VALUE_BYTES: usize = 64 << 10;
/// Retained groups, matching the frozen caller group bound.
pub const MAX_GROUPS: usize = super::pass::MAX_GROUPS;
/// Retained values across all backends and groups: every backend keeps at
/// most one read of `MAX_VALUES`, and every group at most one stored result.
pub const MAX_RETAINED_VALUES: usize = 2 * MAX_BACKENDS * MAX_VALUES;
/// Retained value bytes across all backends and groups, by the same rule.
pub const MAX_RETAINED_VALUE_BYTES: usize = 2 * MAX_BACKENDS * MAX_REFRESH_VALUE_BYTES;
/// Distinct listener ports the rebuilt conflict table may bind: every live
/// group's stored values.
pub const MAX_PORT_ENTRIES: usize = MAX_GROUPS * MAX_VALUES;

/// The router's fixed match rule, as the refresh actually read it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rule {
    /// One group accepts every client.
    All,
    /// Logical client address against member CIDRs.
    ClientCidr,
    /// Immediate peer address against member CIDRs.
    ProxyCidr,
    /// Listener port dispatch with cluster-scoped conflicts.
    Port,
}
impl Rule {
    /// Wire value 1..=4.
    #[must_use]
    pub const fn from_wire(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::All),
            2 => Some(Self::ClientCidr),
            3 => Some(Self::ProxyCidr),
            4 => Some(Self::Port),
            _ => None,
        }
    }
    const fn match_type(self) -> MatchType {
        match self {
            Self::All => MatchType::All,
            Self::ClientCidr => MatchType::ClientCidr,
            Self::ProxyCidr => MatchType::ProxyCidr,
            Self::Port => MatchType::Port,
        }
    }
    /// Whether Go reads grouping values for a healthy backend under this rule.
    const fn reads_values(self) -> bool {
        !matches!(self, Self::All)
    }
}

/// One backend exactly as the health loop read it, before any Group lock. The
/// router holds a wrapper for it exactly when `account` is nonzero.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Input {
    /// Stable observation identity; zero for a backend the router never held.
    pub account: u64,
    /// Health gate of this refresh.
    pub healthy: bool,
    /// Redirection support of this backend.
    pub support_redirection: bool,
    /// False when the fresh list no longer contains the backend.
    pub present: bool,
}

/// Refresh header: the complete input set of one actual refresh.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Begin {
    /// Monotonic per owner; decisions reference it.
    pub generation: u64,
    /// Exact equality class of the health observer error.
    pub observer_error: ErrorClass,
    /// The router's rule.
    pub rule: Rule,
    /// Actual health-loop order; an observer error carries none.
    pub inputs: Vec<Input>,
}
impl Input {
    /// The router holds a wrapper for this backend after the health loop.
    #[must_use]
    pub const fn held(&self) -> bool {
        self.account != 0
    }
}

impl Begin {
    /// Bounds and identity checks shared by decode and domain admission.
    ///
    /// # Errors
    /// Capacity beyond the frozen bounds; Identity for an unheld healthy or
    /// dropped backend, duplicates or an error/inputs mix.
    pub fn validate(&self) -> Result<(), InvalidReason> {
        if self.generation == 0
            || self.observer_error != ErrorClass::None && !self.inputs.is_empty()
        {
            return Err(InvalidReason::Identity);
        }
        if self.inputs.len() > MAX_BACKENDS {
            return Err(InvalidReason::Capacity);
        }
        for (i, input) in self.inputs.iter().enumerate() {
            // Go holds a wrapper for every healthy backend and for every
            // backend it already held; a dropped backend is reported unhealthy.
            if !input.held() && (input.healthy || !input.present)
                || !input.present && input.healthy
                || input.held() && self.inputs[..i].iter().any(|e| e.account == input.account)
            {
                return Err(InvalidReason::Identity);
            }
        }
        Ok(())
    }
}

/// Validate one copied value list against the per-refresh bounds.
fn validate_values(values: &[String]) -> Result<(), InvalidReason> {
    if values.len() > MAX_VALUES
        || values.iter().any(|v| v.len() > MAX_VALUE_BYTES)
        || values.iter().map(String::len).sum::<usize>() > MAX_REFRESH_VALUE_BYTES
    {
        return Err(InvalidReason::Capacity);
    }
    Ok(())
}

/// One backend's actual outcome, in Go's decision order, with the grouping
/// values that decision read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Assign {
    /// Refresh this decision belongs to.
    pub generation: u64,
    /// Zero-based decision index.
    pub index: u16,
    /// Backend identity.
    pub account: u64,
    /// Group after the decision; zero when none.
    pub group: u64,
    /// Backend left the router.
    pub removed: bool,
    /// This decision created `group`.
    pub created: bool,
    /// Go read the backend's grouping values for this decision.
    pub values_read: bool,
    /// The values as read; empty when not read.
    pub values: Vec<String>,
}
impl Assign {
    /// Shape checks shared by decode and domain admission.
    ///
    /// # Errors
    /// Identity for contradictory flags; Capacity beyond the value bounds.
    pub fn validate(&self) -> Result<(), InvalidReason> {
        if self.generation == 0
            || self.account == 0
            || self.removed && (self.group != 0 || self.values_read)
            || self.created && self.group == 0
            || self.removed && self.created
            || !self.values_read && !self.values.is_empty()
        {
            return Err(InvalidReason::Identity);
        }
        if usize::from(self.index) >= MAX_BACKENDS {
            return Err(InvalidReason::Capacity);
        }
        validate_values(&self.values)
    }
}

/// One member's actual `Cidr()` read inside `RefreshCidr`, in Go's map order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Member {
    /// Member backend identity.
    pub account: u64,
    /// The values as read.
    pub values: Vec<String>,
}

/// One Group's CIDR recomputation, witnessed inside that Group's lock: every
/// member read at its read site, then the value list exactly as stored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refresh {
    /// Refresh this recomputation belongs to.
    pub generation: u64,
    /// The refreshed group.
    pub group: u64,
    /// Go recomputed values (CIDR rules only).
    pub values_read: bool,
    /// The per-member reads; empty when not recomputed.
    pub members: Vec<Member>,
    /// The stored result; empty when not recomputed.
    pub values: Vec<String>,
    /// Whether the stored result parsed.
    pub parsed: bool,
}
impl Refresh {
    /// Shape checks shared by decode and domain admission.
    ///
    /// # Errors
    /// Identity for a zero group/account, duplicate member or an unread
    /// recomputation carrying data; Capacity beyond the value bounds.
    pub fn validate(&self) -> Result<(), InvalidReason> {
        if self.generation == 0
            || self.group == 0
            || !self.values_read
                && (!self.members.is_empty() || !self.values.is_empty() || !self.parsed)
        {
            return Err(InvalidReason::Identity);
        }
        if self.members.len() > MAX_BACKENDS {
            return Err(InvalidReason::Capacity);
        }
        for (i, member) in self.members.iter().enumerate() {
            if member.account == 0
                || self.members[..i]
                    .iter()
                    .any(|m| m.account == member.account)
            {
                return Err(InvalidReason::Identity);
            }
        }
        let total = self.members.iter().map(|m| m.values.len()).sum::<usize>() + self.values.len();
        let bytes = self
            .members
            .iter()
            .flat_map(|m| m.values.iter())
            .chain(self.values.iter())
            .map(String::len)
            .sum::<usize>();
        if total > MAX_VALUES
            || bytes > MAX_REFRESH_VALUE_BYTES
            || self
                .members
                .iter()
                .flat_map(|m| m.values.iter())
                .chain(self.values.iter())
                .any(|v| v.len() > MAX_VALUE_BYTES)
        {
            return Err(InvalidReason::Capacity);
        }
        Ok(())
    }
    /// Values and bytes this frame reads, for the per-refresh aggregate.
    fn read_size(&self) -> (usize, usize) {
        let lists = self
            .members
            .iter()
            .map(|m| m.values.as_slice())
            .chain([self.values.as_slice()]);
        lists.fold((0, 0), |(c, b), l| {
            (c + l.len(), b + l.iter().map(String::len).sum::<usize>())
        })
    }
}

/// Actual completion counts after CIDR refresh and conflict rebuild.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct End {
    /// Refresh this tail closes.
    pub generation: u64,
    /// Folded redirection gate.
    pub support_redirection: bool,
    /// Live groups after the refresh.
    pub groups: u16,
    /// Groups created in this refresh.
    pub created: u16,
    /// Backends removed in this refresh.
    pub removed: u16,
    /// Groups whose CIDR refresh failed to parse.
    pub refresh_failed: u16,
    /// Listener ports blocked by cluster conflicts.
    pub conflicts: u16,
}

/// A decoded metadata frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// Refresh header.
    Begin(Begin),
    /// One decision.
    Assign(Assign),
    /// One Group recomputation.
    Refresh(Refresh),
    /// Refresh tail.
    End(End),
}
/// Typed metadata boundary; carries no children and creates no groups.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Boundary {
    /// Owner epoch.
    pub epoch: Epoch,
    /// Journal sequence of this frame.
    pub sequence: u64,
    /// Frame content.
    pub event: Event,
}

/// Independent classification of one client for a given generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Classification {
    /// The derived group.
    Group(u64),
    /// No group matches or no group exists.
    NoGroup,
    /// The listener port is claimed by two clusters.
    Conflict,
    /// The health observer reported an error of this exact class.
    ObserverError(ErrorClass),
}

/// A group under construction: created, awaiting its native Init and binding.
#[derive(Clone, Copy, Debug)]
struct Construction {
    id: u64,
    init_seen: bool,
}

struct Open {
    begin: Begin,
    working: State,
    /// Distinct backends decided so far; fixed capacity `MAX_BACKENDS`.
    decided: Vec<u64>,
    /// A backend kept while unhealthy-but-busy: Go falls through to the
    /// ordinary group branch, so the next Assign must revisit it.
    revisit: Option<u64>,
    expected_decisions: usize,
    created: u16,
    removed: u16,
    refresh_failed: u16,
    /// Index of the next group whose Refresh frame is due, in Go slice order.
    refresh_cursor: usize,
    next_index: u16,
    /// `GroupCreated` seen, not yet bound by an Assign; fixed capacity `MAX_GROUPS`.
    pending_created: Vec<Construction>,
    /// Created then removed before any binding; fixed capacity `MAX_GROUPS`.
    failed_constructions: Vec<Construction>,
    /// `GroupRemoved` of a live group seen, awaiting the emptying Assign;
    /// fixed capacity `MAX_GROUPS`.
    pending_removed: Vec<u64>,
    /// Values and bytes Go read in this generation, with Go's own aggregate
    /// accounting (Assign values, Refresh member reads and stored results).
    read_values: usize,
    read_bytes: usize,
    require_native_init: bool,
}
impl Open {
    /// Fixed scratch capacity every refresh reserves at `begin`.
    const SCRATCH_HEAP: usize = MAX_BACKENDS * size_of::<u64>()
        + 2 * MAX_GROUPS * size_of::<Construction>()
        + MAX_GROUPS * size_of::<u64>();
    fn heap(&self) -> usize {
        self.working.heap()
            + self.begin.inputs.capacity() * size_of::<Input>()
            + self.decided.capacity() * size_of::<u64>()
            + self.pending_created.capacity() * size_of::<Construction>()
            + self.failed_constructions.capacity() * size_of::<Construction>()
            + self.pending_removed.capacity() * size_of::<u64>()
    }
    /// Charge one frame's reads against Go's per-refresh aggregate.
    fn account(&mut self, values: usize, bytes: usize) -> Result<(), InvalidReason> {
        self.read_values += values;
        self.read_bytes += bytes;
        if self.read_values > MAX_VALUES || self.read_bytes > MAX_REFRESH_VALUE_BYTES {
            return Err(InvalidReason::Capacity);
        }
        Ok(())
    }
}

/// Retained router metadata plus one open refresh. All changes are staged
/// until the End witness matches; a failure is sticky and keeps the last
/// committed state. Not installed in `LiveState` or any transport yet.
#[derive(Default)]
pub struct Tracker {
    last_generation: u64,
    state: State,
    open: Option<Open>,
    failed: Option<InvalidReason>,
    require_native_init: bool,
}

/// Shared admission of a projected retained charge before growth.
pub type Admit<'a> = &'a mut dyn FnMut(usize) -> Result<(), InvalidReason>;

impl Tracker {
    /// A tracker whose routers construct native policies: every created group
    /// must show its actual Init evaluation before it can be bound.
    #[must_use]
    pub fn native() -> Self {
        Self {
            require_native_init: true,
            ..Self::default()
        }
    }

    /// Bytes currently retained: own layout plus every heap capacity of the
    /// committed state and the open refresh.
    #[must_use]
    pub fn retained_charge(&self) -> usize {
        size_of::<Self>() + self.state.heap() + self.open.as_ref().map_or(0, Open::heap)
    }
    /// Bytes the working copy `begin` creates will hold: exact-capacity
    /// clones with the group and backend lists reserved to their bounds.
    #[must_use]
    pub fn clone_charge(&self) -> usize {
        self.state.working_clone_heap()
    }

    /// Last committed live group identities in Go order.
    ///
    /// # Errors
    /// Capacity when more groups are retained than the caller bound allows.
    pub fn known_groups(&self) -> Result<Groups, InvalidReason> {
        if self.state.groups.len() > MAX_GROUPS {
            return Err(InvalidReason::Capacity);
        }
        let mut ids = [0u64; MAX_GROUPS];
        for (slot, g) in ids.iter_mut().zip(&self.state.groups) {
            *slot = g.id;
        }
        Groups::new(&ids[..self.state.groups.len()])
    }
    /// Read-only matcher of a committed live group, for callers that replay the
    /// actual per-Group `Match` reads in known-group order instead of using the
    /// fixed-input `classify` convenience.
    ///
    /// # Errors
    /// Sticky failure or an open refresh.
    pub fn matcher(&self, group: u64) -> Result<Option<&GroupMatcher>, InvalidReason> {
        self.check()?;
        if self.open.is_some() {
            return Err(InvalidReason::Lifecycle);
        }
        Ok(self
            .state
            .groups
            .iter()
            .find(|g| g.id == group)
            .map(|g| &g.matcher))
    }
    /// Last committed folded redirection gate.
    #[must_use]
    pub const fn support_redirection(&self) -> bool {
        self.state.support_redirection
    }
    /// Last committed generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.last_generation
    }

    /// Open the next refresh with its complete inputs. Every retained backend
    /// must be covered by a held input. The working clone and the fixed
    /// per-refresh scratch are admitted before they are allocated; every later
    /// list of the refresh lives inside that reserved capacity.
    ///
    /// # Errors
    /// Sticky replay, overlap, ordering, coverage, admission or validation failures.
    pub fn begin(&mut self, begin: Begin, admit: Admit<'_>) -> Result<(), InvalidReason> {
        let result = self.check().and_then(|()| {
            if self.open.is_some() {
                return Err(InvalidReason::Lifecycle);
            }
            if self.last_generation.checked_add(1) != Some(begin.generation) {
                return Err(InvalidReason::Sequence);
            }
            begin.validate()?;
            if self.state.rule.is_some_and(|rule| rule != begin.rule) {
                return Err(InvalidReason::Witness);
            }
            self.check_coverage(&begin)?;
            let growth = self.clone_charge()
                + begin.inputs.capacity() * size_of::<Input>()
                + Open::SCRATCH_HEAP;
            admit(self.retained_charge() + growth)
        });
        self.remember(result)?;
        let mut working = self.state.working_clone();
        working.rule = Some(begin.rule);
        working.observer_error = begin.observer_error;
        let mut expected = 0;
        if begin.observer_error == ErrorClass::None {
            // Go's health loop: held backends update, unknown healthy ones are
            // added to the router, unknown unhealthy ones are ignored. Every
            // backend of the refreshed list votes on the redirection gate.
            let mut gate = true;
            for input in &begin.inputs {
                gate &= input.support_redirection;
                if !input.held() {
                    continue;
                }
                expected += 1;
                match working.backend_mut(input.account) {
                    Some(state) => state.support_redirection = input.support_redirection,
                    None => working.backends.push((
                        input.account,
                        BackendState {
                            support_redirection: input.support_redirection,
                            group: 0,
                            values: Vec::new(),
                            read_generation: 0,
                        },
                    )),
                }
            }
            working.support_redirection = gate;
        }
        self.open = Some(Open {
            begin,
            working,
            decided: Vec::with_capacity(MAX_BACKENDS),
            revisit: None,
            expected_decisions: expected,
            created: 0,
            removed: 0,
            refresh_failed: 0,
            refresh_cursor: 0,
            next_index: 0,
            pending_created: Vec::with_capacity(MAX_GROUPS),
            failed_constructions: Vec::with_capacity(MAX_GROUPS),
            pending_removed: Vec::with_capacity(MAX_GROUPS),
            read_values: 0,
            read_bytes: 0,
            require_native_init: self.require_native_init,
        });
        Ok(())
    }

    /// Every backend the router holds is an input (present or dropped), and a
    /// held input is either already retained or healthy.
    fn check_coverage(&self, begin: &Begin) -> Result<(), InvalidReason> {
        if begin.observer_error != ErrorClass::None {
            return Ok(());
        }
        for (account, _) in &self.state.backends {
            if !begin.inputs.iter().any(|i| i.account == *account) {
                return Err(InvalidReason::Witness);
            }
        }
        for input in &begin.inputs {
            let retained = input.held() && self.state.backend(input.account).is_some();
            if input.held() && !input.healthy && !retained {
                return Err(InvalidReason::Witness);
            }
        }
        Ok(())
    }

    /// Bind one actual group lifecycle event to the open refresh. Groups are
    /// only created or removed inside a refresh; a `GroupRemoved` of an unbound
    /// created group records a failed construction, one of a live group must
    /// be followed by the Assign that empties it. Other events are not group
    /// scoped and are ignored here.
    ///
    /// # Errors
    /// Lifecycle for an event outside a refresh or on an unknown group.
    pub fn group_event(&mut self, event: &LiveEvent) -> Result<(), InvalidReason> {
        let result = self.check().and_then(|()| {
            let open = self.open.as_mut().ok_or(InvalidReason::Lifecycle)?;
            match *event {
                LiveEvent::GroupCreated(id) => {
                    if id == 0
                        || open.working.group_index(id).is_some()
                        || open.pending_created.iter().any(|c| c.id == id)
                        || open.failed_constructions.iter().any(|c| c.id == id)
                    {
                        return Err(InvalidReason::Lifecycle);
                    }
                    // The lists were reserved to MAX_GROUPS at begin; a push
                    // never reallocates, and a full list is a capacity failure.
                    if open.pending_created.len() == open.pending_created.capacity()
                        || open.pending_created.len() + open.working.groups.len() >= MAX_GROUPS
                    {
                        return Err(InvalidReason::Capacity);
                    }
                    open.pending_created.push(Construction {
                        id,
                        init_seen: false,
                    });
                }
                LiveEvent::GroupRemoved(id) => {
                    if let Some(at) = open.pending_created.iter().position(|c| c.id == id) {
                        if open.failed_constructions.len() == open.failed_constructions.capacity() {
                            return Err(InvalidReason::Capacity);
                        }
                        let construction = open.pending_created.remove(at);
                        open.failed_constructions.push(construction);
                    } else if open.working.group_index(id).is_some()
                        && !open.pending_removed.contains(&id)
                    {
                        if open.pending_removed.len() == open.pending_removed.capacity() {
                            return Err(InvalidReason::Capacity);
                        }
                        open.pending_removed.push(id);
                    } else {
                        return Err(InvalidReason::Lifecycle);
                    }
                }
                _ => {}
            }
            Ok(())
        });
        self.remember(result)
    }

    /// Witness a native policy configuration evaluation (`Init` / `SetConfig`)
    /// for `group`: a group under construction becomes eligible for binding; a
    /// live group may be reconfigured; anything else is unknown.
    ///
    /// # Errors
    /// Lifecycle for an unknown group.
    pub fn native_init(&mut self, group: u64) -> Result<(), InvalidReason> {
        let result = self.check().and_then(|()| {
            if let Some(open) = self.open.as_mut() {
                if let Some(c) = open.pending_created.iter_mut().find(|c| c.id == group) {
                    c.init_seen = true;
                    return Ok(());
                }
                if open.working.group_index(group).is_some() {
                    return Ok(());
                }
                return Err(InvalidReason::Lifecycle);
            }
            if self.state.group_index(group).is_some() {
                Ok(())
            } else {
                Err(InvalidReason::Lifecycle)
            }
        });
        self.remember(result)
    }

    /// Consume one visit witness. `idle` is the ledger's view of the backend
    /// at the actual Group critical section: no physical connection and zero
    /// score. The witness must equal the independently derived outcome, a
    /// created or emptied group must match its real lifecycle, and a backend
    /// kept while unhealthy-but-busy must be revisited by the very next frame,
    /// exactly as Go's loop falls through to the ordinary group branch. Every
    /// allocation, including the trial parse, is admitted before it happens.
    ///
    /// # Errors
    /// Sticky ordering, identity, capacity, lifecycle, admission or witness failures.
    pub fn assign(
        &mut self,
        assign: &Assign,
        idle: impl FnOnce(u64) -> bool,
        admit: Admit<'_>,
    ) -> Result<(), InvalidReason> {
        let retained = self.retained_charge();
        let result = self.check().and_then(|()| {
            let open = self.open.as_mut().ok_or(InvalidReason::Lifecycle)?;
            assign.validate()?;
            if open.begin.generation != assign.generation {
                return Err(InvalidReason::Identity);
            }
            if open.begin.observer_error != ErrorClass::None || open.refresh_cursor != 0 {
                return Err(InvalidReason::Lifecycle);
            }
            if assign.index != open.next_index {
                return Err(InvalidReason::Sequence);
            }
            let rule = open.begin.rule;
            let (values, bytes) = (
                assign.values.len(),
                assign.values.iter().map(String::len).sum(),
            );
            open.account(values, bytes)?;
            if let Some(account) = open.revisit {
                return Self::apply_revisit(open, assign, account, retained, admit);
            }
            if open.decided.contains(&assign.account) {
                return Err(InvalidReason::Identity);
            }
            let input = *open
                .begin
                .inputs
                .iter()
                .find(|i| i.account == assign.account)
                .ok_or(InvalidReason::Witness)?;
            let current_group = open
                .working
                .backend(assign.account)
                .ok_or(InvalidReason::Witness)?
                .group;
            // Values are read exactly on the healthy paths of a value rule.
            let reads = input.healthy && input.present && rule.reads_values();
            if assign.values_read != reads {
                return Err(InvalidReason::Witness);
            }
            if reads && current_group == 0 {
                // The construction trial clones the values and parses them.
                admit(
                    retained
                        + values_clone_charge(&assign.values)
                        + GroupMatcher::construction_peak(rule.match_type(), assign.values.len()),
                )?;
            }
            let visit = Visit {
                healthy: input.healthy,
                present: input.present,
                account: assign.account,
                values: &assign.values,
                current_group,
                witness_group: assign.group,
            };
            let (removed, created, group, construction_failed) =
                derive_outcome(&open.working, rule, &visit, idle, || {
                    GroupMatcher::new(rule.match_type(), assign.values.clone()).is_ok()
                });
            if (removed, created, group) != (assign.removed, assign.created, assign.group) {
                return Err(InvalidReason::Witness);
            }
            let mut growth = if reads {
                values_clone_charge(&assign.values)
            } else {
                0
            };
            if created {
                growth += GroupState::creation_peak(rule, &assign.values);
            }
            admit(retained + growth)?;
            Self::apply_assign(open, assign, current_group, created, construction_failed)
        });
        self.remember(result)
    }

    /// The second visit of a backend kept while unhealthy-but-busy: Go's
    /// ordinary group branch reads its values (for a value rule) and keeps
    /// the group; nothing else may change.
    fn apply_revisit(
        open: &mut Open,
        assign: &Assign,
        account: u64,
        retained: usize,
        admit: Admit<'_>,
    ) -> Result<(), InvalidReason> {
        let rule = open.begin.rule;
        let current_group = open
            .working
            .backend(account)
            .ok_or(InvalidReason::Witness)?
            .group;
        if assign.account != account
            || assign.removed
            || assign.created
            || assign.group != current_group
            || assign.values_read != rule.reads_values()
        {
            return Err(InvalidReason::Witness);
        }
        if assign.values_read {
            admit(retained + values_clone_charge(&assign.values))?;
            let backend = open
                .working
                .backend_mut(account)
                .ok_or(InvalidReason::Witness)?;
            // An exact-capacity replacement is what was admitted; clone_from would
            // keep the old, larger capacity uncharged.
            #[allow(clippy::assigning_clones)]
            {
                backend.values = assign.values.clone();
            }
            backend.read_generation = open.begin.generation;
        }
        open.revisit = None;
        open.next_index += 1;
        Ok(())
    }

    fn apply_assign(
        open: &mut Open,
        assign: &Assign,
        current_group: u64,
        created: bool,
        construction_failed: bool,
    ) -> Result<(), InvalidReason> {
        let generation = open.begin.generation;
        if construction_failed {
            // Go created the Group, its policy ran Init, parsing failed and the
            // Group was removed again: the pair must have been observed.
            if open.failed_constructions.is_empty() {
                return Err(InvalidReason::Witness);
            }
            let failed = open.failed_constructions.remove(0);
            if open.require_native_init_for(failed) {
                return Err(InvalidReason::Lifecycle);
            }
        }
        if created {
            Self::create_group(open, assign)?;
        }
        if assign.removed {
            if current_group != 0 {
                let index = open
                    .working
                    .group_index(current_group)
                    .ok_or(InvalidReason::Witness)?;
                let g = &mut open.working.groups[index];
                g.members.retain(|m| *m != assign.account);
                let emptied = g.members.is_empty();
                let announced = open
                    .pending_removed
                    .iter()
                    .position(|r| *r == current_group);
                match (emptied, announced) {
                    (true, Some(at)) => {
                        open.pending_removed.remove(at);
                        open.working.groups.remove(index);
                    }
                    (false, None) => {}
                    _ => return Err(InvalidReason::Lifecycle),
                }
            }
            open.working.backends.retain(|(a, _)| *a != assign.account);
            open.removed += 1;
        } else {
            let input_unhealthy = open
                .begin
                .inputs
                .iter()
                .find(|i| i.account == assign.account)
                .is_some_and(|i| !i.healthy || !i.present);
            let backend = open
                .working
                .backend_mut(assign.account)
                .ok_or(InvalidReason::Witness)?;
            if assign.values_read {
                // An exact-capacity replacement is what was admitted; clone_from would
                // keep the old, larger capacity uncharged.
                #[allow(clippy::assigning_clones)]
                {
                    backend.values = assign.values.clone();
                }
                backend.read_generation = generation;
            }
            if assign.group != 0 && current_group == 0 {
                backend.group = assign.group;
                let index = open
                    .working
                    .group_index(assign.group)
                    .ok_or(InvalidReason::Witness)?;
                let members = &mut open.working.groups[index].members;
                if members.len() == members.capacity() {
                    return Err(InvalidReason::Capacity);
                }
                members.push(assign.account);
            }
            if input_unhealthy {
                // Kept while busy: Go's loop does not `continue`, so the
                // ordinary group branch visits this backend again next.
                open.revisit = Some(assign.account);
            }
        }
        if open.decided.len() == open.decided.capacity() {
            return Err(InvalidReason::Capacity);
        }
        open.decided.push(assign.account);
        open.next_index += 1;
        Ok(())
    }

    /// Bind a created group to its announced construction and retain it with
    /// the fixed member capacity the admission charged.
    fn create_group(open: &mut Open, assign: &Assign) -> Result<(), InvalidReason> {
        let rule = open.begin.rule;
        let at = open
            .pending_created
            .iter()
            .position(|c| c.id == assign.group)
            .ok_or(InvalidReason::Lifecycle)?;
        let construction = open.pending_created.remove(at);
        if open.require_native_init_for(construction) {
            return Err(InvalidReason::Lifecycle);
        }
        if open.working.groups.len() >= MAX_GROUPS {
            return Err(InvalidReason::Capacity);
        }
        let matcher = GroupMatcher::new(rule.match_type(), assign.values.clone())
            .map_err(|_| InvalidReason::Witness)?;
        open.working.groups.push(GroupState {
            id: assign.group,
            matcher,
            members: Vec::with_capacity(MAX_BACKENDS),
        });
        open.created += 1;
        Ok(())
    }

    /// Consume one Group recomputation witness, in Go's group order after the
    /// last decision. For a CIDR rule the member read tape must cover exactly
    /// the derived membership; the stored result must be the distinct union of
    /// those reads, and its parse outcome is derived and compared. Every
    /// retained copy is admitted before it is made; the union check allocates
    /// nothing.
    ///
    /// # Errors
    /// Sticky ordering, identity, capacity, admission or witness failures.
    pub fn refresh(&mut self, refresh: &Refresh, admit: Admit<'_>) -> Result<(), InvalidReason> {
        let retained = self.retained_charge();
        let result = self.check().and_then(|()| {
            let open = self.open.as_mut().ok_or(InvalidReason::Lifecycle)?;
            refresh.validate()?;
            if open.begin.generation != refresh.generation {
                return Err(InvalidReason::Identity);
            }
            if open.begin.observer_error != ErrorClass::None
                || open.revisit.is_some()
                || open.decided.len() != open.expected_decisions
            {
                return Err(InvalidReason::Lifecycle);
            }
            let cursor = open.refresh_cursor;
            if cursor >= open.working.groups.len()
                || open.working.groups[cursor].id != refresh.group
            {
                return Err(InvalidReason::Sequence);
            }
            let cidr = matches!(open.begin.rule, Rule::ClientCidr | Rule::ProxyCidr);
            if refresh.values_read != cidr {
                return Err(InvalidReason::Witness);
            }
            let (values, bytes) = refresh.read_size();
            open.account(values, bytes)?;
            if cidr {
                Self::apply_cidr_refresh(open, refresh, cursor, retained, admit)?;
            }
            open.refresh_cursor += 1;
            Ok(())
        });
        self.remember(result)
    }

    fn apply_cidr_refresh(
        open: &mut Open,
        refresh: &Refresh,
        cursor: usize,
        retained: usize,
        admit: Admit<'_>,
    ) -> Result<(), InvalidReason> {
        let members = &open.working.groups[cursor].members;
        if refresh.members.len() != members.len()
            || refresh
                .members
                .iter()
                .any(|m| !members.contains(&m.account))
        {
            return Err(InvalidReason::Witness);
        }
        // The stored result must be exactly the distinct union of the reads.
        let result = &refresh.values;
        let distinct = result
            .iter()
            .enumerate()
            .all(|(i, v)| !result[..i].contains(v));
        let covered = refresh
            .members
            .iter()
            .all(|m| m.values.iter().all(|v| result.contains(v)));
        let (union_count, _) = union_size(&refresh.members);
        if !distinct || !covered || union_count != result.len() {
            return Err(InvalidReason::Witness);
        }
        // Replaced backend value lists, the matcher's new value list and the
        // refresh's own transient (its internal clone and the freshly parsed
        // network list while the old one is alive) are admitted before any copy.
        let growth = refresh
            .members
            .iter()
            .map(|m| values_clone_charge(&m.values))
            .sum::<usize>()
            + values_clone_charge(result)
            + open.working.groups[cursor].matcher.refresh_peak(result);
        admit(retained + growth)?;
        for member in &refresh.members {
            let backend = open
                .working
                .backend_mut(member.account)
                .ok_or(InvalidReason::Witness)?;
            // An exact-capacity replacement is what was admitted; clone_from would
            // keep the old, larger capacity uncharged.
            #[allow(clippy::assigning_clones)]
            {
                backend.values = member.values.clone();
            }
            backend.read_generation = refresh.generation;
        }
        let group = &mut open.working.groups[cursor];
        let parsed = group.matcher.refresh_values(result.clone()).is_ok();
        if parsed != refresh.parsed {
            return Err(InvalidReason::Witness);
        }
        if !parsed {
            open.refresh_failed += 1;
        }
        Ok(())
    }

    /// Close the refresh: admit and rebuild the port table, derive the
    /// conflicts and gate, compare the tail witness against the derived counts
    /// and commit.
    ///
    /// # Errors
    /// Sticky incomplete refresh, unbound lifecycle, admission or tail witness mismatch.
    pub fn end(&mut self, end: End, admit: Admit<'_>) -> Result<(), InvalidReason> {
        let retained = self.retained_charge();
        let result = self.check().and_then(|()| {
            let open = self.open.as_mut().ok_or(InvalidReason::Lifecycle)?;
            if open.begin.generation != end.generation {
                return Err(InvalidReason::Identity);
            }
            if open.decided.len() != open.expected_decisions
                || open.revisit.is_some()
                || !open.pending_created.is_empty()
                || !open.failed_constructions.is_empty()
                || !open.pending_removed.is_empty()
            {
                return Err(InvalidReason::Lifecycle);
            }
            let groups =
                u16::try_from(open.working.groups.len()).map_err(|_| InvalidReason::Capacity)?;
            if open.begin.observer_error != ErrorClass::None {
                // Go returns before any grouping work: nothing is rebuilt and
                // the tail reports zero refresh failures and conflicts.
                let expected = End {
                    generation: end.generation,
                    support_redirection: self.state.support_redirection,
                    groups,
                    created: 0,
                    removed: 0,
                    refresh_failed: 0,
                    conflicts: 0,
                };
                return (expected == end)
                    .then_some(())
                    .ok_or(InvalidReason::Witness);
            }
            if open.refresh_cursor != open.working.groups.len() {
                return Err(InvalidReason::Lifecycle);
            }
            // Explicit aggregate bounds on what this generation would retain,
            // checked before the port table is planned or built.
            let (values, bytes) = open.working.retained_values();
            if values > MAX_RETAINED_VALUES || bytes > MAX_RETAINED_VALUE_BYTES {
                return Err(InvalidReason::Capacity);
            }
            let ports_heap = open.working.ports_plan(open.begin.rule)?;
            admit(retained + ports_heap)?;
            open.working.rebuild_ports(open.begin.rule);
            let expected = End {
                generation: end.generation,
                support_redirection: open.working.support_redirection,
                groups,
                created: open.created,
                removed: open.removed,
                refresh_failed: open.refresh_failed,
                conflicts: u16::try_from(open.working.conflicts)
                    .map_err(|_| InvalidReason::Capacity)?,
            };
            (expected == end)
                .then_some(())
                .ok_or(InvalidReason::Witness)
        });
        self.remember(result)?;
        if let Some(open) = self.open.take() {
            self.last_generation = open.begin.generation;
            self.state = open.working;
        }
        Ok(())
    }

    /// Classify a client against the last committed metadata of `generation`.
    ///
    /// # Errors
    /// Sticky failure, an open refresh, or a generation that is not the committed one.
    pub fn classify(
        &self,
        generation: u64,
        client: ClientInfo<'_>,
        listener_port: &str,
    ) -> Result<Classification, InvalidReason> {
        self.check()?;
        if self.open.is_some() {
            return Err(InvalidReason::Lifecycle);
        }
        if generation != self.last_generation || generation == 0 {
            return Err(InvalidReason::Identity);
        }
        if self.state.observer_error != ErrorClass::None {
            return Ok(Classification::ObserverError(self.state.observer_error));
        }
        Ok(match self.state.rule {
            Some(Rule::Port) => match self.state.ports.group_for(listener_port) {
                Err(_) => Classification::Conflict,
                Ok(None) => Classification::NoGroup,
                Ok(Some(id)) => Classification::Group(*id),
            },
            _ => self
                .state
                .groups
                .iter()
                .find(|g| g.matcher.matches(client))
                .map_or(Classification::NoGroup, |g| Classification::Group(g.id)),
        })
    }

    /// A final compared tail cannot contain an open refresh.
    ///
    /// # Errors
    /// Sticky failure or an open refresh.
    pub fn tail(&self) -> Result<(), InvalidReason> {
        self.check()?;
        if self.open.is_some() {
            Err(InvalidReason::Lifecycle)
        } else {
            Ok(())
        }
    }

    fn check(&self) -> Result<(), InvalidReason> {
        self.failed.map_or(Ok(()), Err)
    }
    fn remember(&mut self, result: Result<(), InvalidReason>) -> Result<(), InvalidReason> {
        if let Err(reason) = result {
            self.failed.get_or_insert(reason);
        }
        result
    }
}

impl Open {
    /// Whether binding `construction` must fail because its native Init was
    /// required but never witnessed. Stored on the open refresh so that
    /// `apply_assign` needs no tracker borrow.
    const fn require_native_init_for(&self, construction: Construction) -> bool {
        self.require_native_init && !construction.init_seen
    }
}

#[cfg(test)]
mod tests;
