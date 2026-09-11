// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Retained metadata state, its capacity-derived charges and the pure
//! derivations (decision, CIDR union, port conflicts) the tracker compares
//! against Go's witnesses. Every charge counts actual heap capacity: vectors
//! by `capacity()`, strings by `capacity()`, and the matcher and port table by
//! the layout-derived helpers `control_routing` exposes for them (network
//! element size, `collect` growth, reallocation transients, one full B-tree
//! node per entry plus a split allowance), which the out-of-tree
//! counting-allocator probe checks against requested bytes.
use super::{ErrorClass, InvalidReason, MAX_BACKENDS, MAX_GROUPS, MAX_PORT_ENTRIES, Member, Rule};
use control_routing::group::{GroupMatcher, PortRoutes};
use std::mem::{size_of, size_of_val};

/// Heap bytes actually held by a string list, by capacity.
pub(super) fn values_charge(values: &[String]) -> usize {
    values.iter().map(String::capacity).sum::<usize>()
}
/// Heap bytes an exact-capacity clone of `values` holds.
pub(super) fn values_clone_charge(values: &[String]) -> usize {
    size_of_val(values) + values.iter().map(String::len).sum::<usize>()
}
/// Heap bytes of a `Vec<String>` by its own capacity plus its strings' capacities.
pub(super) fn vec_charge(values: &Vec<String>) -> usize {
    values.capacity() * size_of::<String>() + values_charge(values)
}

#[derive(Clone, Debug)]
pub(super) struct GroupState {
    pub id: u64,
    /// Constructed only from exact-capacity clones; its heap is what
    /// `GroupMatcher::retained_heap` reports from its real capacities.
    pub matcher: GroupMatcher,
    /// Fixed capacity `MAX_BACKENDS`, reserved when the group is created.
    pub members: Vec<u64>,
}
impl GroupState {
    /// Heap bytes beyond the inline struct.
    pub(super) fn heap(&self) -> usize {
        self.matcher.retained_heap() + self.members.capacity() * size_of::<u64>()
    }
    /// Peak heap creating a group over an exact clone of `values` requests:
    /// the clone, the matcher construction peak and the member list.
    pub(super) fn creation_peak(rule: Rule, values: &[String]) -> usize {
        values_clone_charge(values)
            + GroupMatcher::construction_peak(rule.match_type(), values.len())
            + MAX_BACKENDS * size_of::<u64>()
    }
}

#[derive(Clone, Debug)]
pub(super) struct BackendState {
    pub support_redirection: bool,
    pub group: u64,
    /// Last grouping values Go actually read for this backend; always an
    /// exact-capacity clone, replaced whole.
    pub values: Vec<String>,
    /// Generation of that read; zero before any read.
    pub read_generation: u64,
}

#[derive(Clone, Debug)]
pub(super) struct State {
    pub rule: Option<Rule>,
    pub initialized: bool,
    pub detector_present: bool,
    pub observer_error: ErrorClass,
    pub support_redirection: bool,
    /// Live groups in Go's slice order: creation order with deletions.
    pub groups: Vec<GroupState>,
    pub backends: Vec<(u64, BackendState)>,
    pub ports: PortRoutes<u64>,
    pub conflicts: usize,
}
impl Default for State {
    fn default() -> Self {
        Self {
            rule: None,
            initialized: false,
            detector_present: false,
            observer_error: ErrorClass::None,
            support_redirection: false,
            groups: Vec::new(),
            backends: Vec::new(),
            ports: PortRoutes::default(),
            conflicts: 0,
        }
    }
}
impl State {
    /// Heap bytes this state holds beyond its inline struct.
    pub(super) fn heap(&self) -> usize {
        self.groups.capacity() * size_of::<GroupState>()
            + self.groups.iter().map(GroupState::heap).sum::<usize>()
            + self.backends.capacity() * size_of::<(u64, BackendState)>()
            + self
                .backends
                .iter()
                .map(|(_, b)| vec_charge(&b.values))
                .sum::<usize>()
            + self.ports.retained_heap()
    }
    /// Heap the working clone made by `begin` will hold: exact-capacity
    /// clones of every list, groups and backends reserved to their fixed
    /// bounds so that no later push reallocates, and the same port table.
    pub(super) fn working_clone_heap(&self) -> usize {
        MAX_GROUPS * size_of::<GroupState>()
            + self.groups.iter().map(GroupState::heap).sum::<usize>()
            + MAX_BACKENDS * size_of::<(u64, BackendState)>()
            + self
                .backends
                .iter()
                .map(|(_, b)| values_clone_charge(&b.values))
                .sum::<usize>()
            + self.ports.retained_heap()
    }
    /// The working clone itself, laid out exactly as `working_clone_heap` charged.
    pub(super) fn working_clone(&self) -> Self {
        let mut groups = Vec::with_capacity(MAX_GROUPS);
        groups.extend(self.groups.iter().map(|g| GroupState {
            id: g.id,
            matcher: g.matcher.clone(),
            members: {
                let mut m = Vec::with_capacity(MAX_BACKENDS);
                m.extend_from_slice(&g.members);
                m
            },
        }));
        let mut backends = Vec::with_capacity(MAX_BACKENDS);
        backends.extend(self.backends.iter().map(|(a, b)| {
            (
                *a,
                BackendState {
                    support_redirection: b.support_redirection,
                    group: b.group,
                    values: b.values.clone(),
                    read_generation: b.read_generation,
                },
            )
        }));
        Self {
            rule: self.rule,
            initialized: self.initialized,
            detector_present: self.detector_present,
            observer_error: self.observer_error,
            support_redirection: self.support_redirection,
            groups,
            backends,
            ports: self.ports.clone(),
            conflicts: self.conflicts,
        }
    }
    /// Retained grouping values across backends and groups, and their bytes.
    pub(super) fn retained_values(&self) -> (usize, usize) {
        let backend_values = self.backends.iter().map(|(_, b)| b.values.as_slice());
        let group_values = self.groups.iter().map(|g| g.matcher.values());
        backend_values
            .chain(group_values)
            .fold((0, 0), |(count, bytes), values| {
                (
                    count + values.len(),
                    bytes + values.iter().map(String::len).sum::<usize>(),
                )
            })
    }
    pub(super) fn group_index(&self, id: u64) -> Option<usize> {
        self.groups.iter().position(|g| g.id == id)
    }
    pub(super) fn backend(&self, account: u64) -> Option<&BackendState> {
        self.backends
            .iter()
            .find(|(a, _)| *a == account)
            .map(|(_, b)| b)
    }
    pub(super) fn backend_mut(&mut self, account: u64) -> Option<&mut BackendState> {
        self.backends
            .iter_mut()
            .find(|(a, _)| *a == account)
            .map(|(_, b)| b)
    }
    /// Every (group, value) pair of the live port groups whose port string
    /// was not seen in an earlier pair: the distinct ports Go's detector
    /// binds, enumerated without allocating.
    fn distinct_ports(&self) -> impl Iterator<Item = (&str, &str)> {
        self.groups.iter().enumerate().flat_map(move |(gi, g)| {
            g.matcher
                .values()
                .iter()
                .enumerate()
                .filter_map(move |(vi, value)| {
                    let (cluster, port) = value.split_once(':').unwrap_or(("", value.as_str()));
                    let earlier = self
                        .groups
                        .iter()
                        .take(gi + 1)
                        .enumerate()
                        .flat_map(|(gj, h)| {
                            let limit = if gj == gi {
                                vi
                            } else {
                                h.matcher.values().len()
                            };
                            h.matcher.values()[..limit].iter()
                        })
                        .any(|v| v.split_once(':').map_or(v.as_str(), |(_, p)| p) == port);
                    (!earlier).then_some((port, cluster))
                })
        })
    }
    /// Peak heap the port table rebuilt from the live groups may request:
    /// one entry charge per distinct port plus the split allowance. Bounded
    /// before any table is built.
    pub(super) fn ports_plan(&self, rule: Rule) -> Result<usize, InvalidReason> {
        if rule != Rule::Port {
            return Ok(0);
        }
        let mut heap = PortRoutes::<u64>::rebuild_allowance();
        let mut distinct = 0;
        for (port, cluster) in self.distinct_ports() {
            distinct += 1;
            if distinct > MAX_PORT_ENTRIES {
                return Err(InvalidReason::Capacity);
            }
            heap += PortRoutes::<u64>::entry_charge(port.len(), cluster.len());
        }
        Ok(heap)
    }
    /// Rebuild Go's port conflict detector from the live groups' raw values;
    /// the plan was admitted first, so no allocation here is unaccounted.
    pub(super) fn rebuild_ports(&mut self, rule: Rule) {
        let mut ports = PortRoutes::default();
        let mut conflicts = 0usize;
        if rule == Rule::Port {
            for g in &self.groups {
                for value in g.matcher.values() {
                    let (cluster, port) = value.split_once(':').unwrap_or(("", value.as_str()));
                    ports.bind(port, cluster, g.id);
                }
            }
            conflicts = self
                .distinct_ports()
                .filter(|(port, _)| ports.group_for(port).is_err())
                .count();
        }
        self.ports = ports;
        self.conflicts = conflicts;
    }
}

/// One backend visit as the tracker sees it: the health-loop input, the
/// values the visit read and the retained/witnessed groups.
pub(super) struct Visit<'a> {
    pub healthy: bool,
    pub present: bool,
    pub account: u64,
    pub values: &'a [String],
    pub current_group: u64,
    pub witness_group: u64,
}

/// Go's decision for one backend, derived only from retained state and the
/// visit. `parses` reports whether a fresh matcher over the values would
/// parse; the caller admits that trial before calling. Returns
/// `(removed, created, group, construction_failed)`; a created group takes the
/// witness id because Go allocates identities.
pub(super) fn derive_outcome(
    working: &State,
    rule: Rule,
    visit: &Visit<'_>,
    idle: impl FnOnce(u64) -> bool,
    parses: impl FnOnce() -> bool,
) -> (bool, bool, u64, bool) {
    if !visit.healthy || !visit.present {
        return if visit.current_group == 0 || idle(visit.account) {
            (true, false, 0, false)
        } else {
            (false, false, visit.current_group, false)
        };
    }
    if visit.current_group != 0 {
        return (false, false, visit.current_group, false);
    }
    let values = visit.values;
    match rule {
        Rule::All => working
            .groups
            .first()
            .map_or((false, true, visit.witness_group, false), |g| {
                (false, false, g.id, false)
            }),
        Rule::ClientCidr | Rule::ProxyCidr | Rule::Port => {
            if values.is_empty() {
                (false, false, 0, false)
            } else if let Some(g) = working.groups.iter().find(|g| g.matcher.intersects(values)) {
                (false, false, g.id, false)
            } else if parses() {
                (false, true, visit.witness_group, false)
            } else {
                // Construction failed: Go emits GroupCreated then GroupRemoved
                // and leaves the backend without a group.
                (false, false, 0, true)
            }
        }
    }
}

/// Number of distinct strings across the member reads and their total bytes,
/// without allocating: the size of the union Go's `RefreshCidr` value map
/// produces.
pub(super) fn union_size(members: &[Member]) -> (usize, usize) {
    let mut count = 0;
    let mut bytes = 0;
    for (i, member) in members.iter().enumerate() {
        for (j, value) in member.values.iter().enumerate() {
            let earlier_in_list = member.values[..j].contains(value);
            let earlier_member = members[..i].iter().any(|m| m.values.contains(value));
            if !earlier_in_list && !earlier_member {
                count += 1;
                bytes += value.len();
            }
        }
    }
    (count, bytes)
}
