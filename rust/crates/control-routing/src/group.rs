// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Pure Go-compatible group matching, with no backend or reservation ownership.

use std::collections::BTreeMap;
use std::mem::{MaybeUninit, size_of, size_of_val};
use std::net::{IpAddr, Ipv6Addr};

/// The router's immutable grouping rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MatchType {
    /// A single group accepts every connection.
    All,
    /// Match the logical client address (possibly supplied by PROXY protocol).
    ClientCidr,
    /// Match the immediate peer address supplied by the caller.
    ProxyCidr,
    /// Dispatch separately through [`PortRoutes`], scoped by listener port.
    Port,
}

/// Address metadata only; this type conveys no routing authority.
///
/// Addresses retain the Go `net.Addr.String()` representation, including its
/// `host:port` structure. The caller supplies the peer as `proxy_address` even
/// without PROXY protocol; a missing proxy address never falls back to client.
#[derive(Clone, Copy, Debug, Default)]
pub struct ClientInfo<'a> {
    /// Logical client address.
    pub client_address: Option<&'a str>,
    /// Immediate peer address.
    pub proxy_address: Option<&'a str>,
}

/// An invalid CIDR makes construction fail before a matcher is available.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidCidr {
    /// Index of the first invalid original value.
    pub index: usize,
}

#[derive(Clone, Debug)]
enum IpNetwork {
    V4 { network: u32, mask: u32 },
    V6 { network: u128, mask: u128 },
}

impl IpNetwork {
    fn parse(value: &str) -> Option<Self> {
        // Go netutil.ParseCIDRList supplies /32 for *both* address families.
        let (host, prefix) = value.split_once('/').unwrap_or((value, "32"));
        if prefix.is_empty() || !prefix.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        let prefix = prefix.parse::<u32>().ok()?;
        match host.parse::<IpAddr>().ok()? {
            IpAddr::V4(ip) if prefix <= 32 => {
                let mask = u32::MAX.checked_shl(32 - prefix).unwrap_or(0);
                Some(Self::V4 {
                    network: u32::from(ip) & mask,
                    mask,
                })
            }
            IpAddr::V6(ip) if prefix <= 128 => {
                let mask = u128::MAX.checked_shl(128 - prefix).unwrap_or(0);
                let network = u128::from(ip) & mask;
                // Go canonicalizes the *masked network* with To4. Doing this
                // before masking would turn a mapped /32 into an IPv4 /0.
                if let Some(ip) = Ipv6Addr::from(network).to_ipv4_mapped() {
                    let low_mask = u32::MAX.checked_shl(128 - prefix).unwrap_or(0);
                    Some(Self::V4 {
                        network: u32::from(ip),
                        mask: low_mask,
                    })
                } else {
                    Some(Self::V6 { network, mask })
                }
            }
            _ => None,
        }
    }

    fn contains(&self, ip: IpAddr) -> bool {
        let ip = match ip {
            IpAddr::V6(ip) => ip.to_ipv4_mapped().map_or(IpAddr::V6(ip), IpAddr::V4),
            ip @ IpAddr::V4(_) => ip,
        };
        match (self, ip) {
            (Self::V4 { network, mask }, IpAddr::V4(ip)) => u32::from(ip) & mask == *network,
            (Self::V6 { network, mask }, IpAddr::V6(ip)) => u128::from(ip) & mask == *network,
            _ => false,
        }
    }
}

// Mirrors net.SplitHostPort + net.ParseIP, not SocketAddr or a dial parser:
// empty/service-name ports are accepted, but hostnames and scoped IPs are not.
fn address_ip(address: &str) -> Option<IpAddr> {
    let (host, port) = address.rsplit_once(':')?;
    let host = if let Some(bracketed) = host.strip_prefix('[') {
        bracketed.strip_suffix(']')?
    } else {
        if host.contains(':') {
            return None;
        }
        host
    };
    if host.contains(['[', ']']) || port.contains(['[', ']']) {
        return None;
    }
    host.parse().ok()
}

/// Immutable matching values for one group.
///
/// This is the predicate used by Go `Group`, not the stateful router that
/// constructs, retains, refreshes, and removes groups. In particular it does
/// not authorize a backend selection or reserve a connection.
#[derive(Clone, Debug)]
pub struct GroupMatcher {
    rule: MatchType,
    values: Vec<String>,
    networks: Vec<IpNetwork>,
}

impl GroupMatcher {
    /// Copies the original values and parses CIDRs for a CIDR rule. No trimming,
    /// deduplication or normalization of the raw grouping values is performed.
    ///
    /// # Errors
    /// Returns [`InvalidCidr`] if any CIDR value is invalid. All/port rules do
    /// not parse their values, matching Go `Group.parseValues`.
    pub fn new(rule: MatchType, values: Vec<String>) -> Result<Self, InvalidCidr> {
        let networks = if matches!(rule, MatchType::ClientCidr | MatchType::ProxyCidr) {
            values
                .iter()
                .enumerate()
                .map(|(index, value)| IpNetwork::parse(value).ok_or(InvalidCidr { index }))
                .collect::<Result<Vec<_>, _>>()?
        } else {
            Vec::new()
        };
        Ok(Self {
            rule,
            values,
            networks,
        })
    }

    /// Refreshes an existing group's raw CIDR union.
    ///
    /// Go replaces raw values first, then parses them. On an invalid update it
    /// retains the previous parsed networks while exposing the new raw values.
    /// This differs from constructing a new invalid group, which is rejected.
    ///
    /// # Errors
    /// Returns [`InvalidCidr`] while preserving the prior matching networks.
    pub fn refresh_values(&mut self, values: Vec<String>) -> Result<(), InvalidCidr> {
        self.values = values;
        let parsed = Self::new(self.rule, self.values.clone())?;
        self.networks = parsed.networks;
        Ok(())
    }

    /// Bytes of one parsed network element, as retained by the matcher.
    pub const NETWORK_SIZE: usize = size_of::<IpNetwork>();

    /// Heap bytes this matcher holds right now: the value list by capacity,
    /// each string by capacity, and the parsed network list by capacity.
    #[must_use]
    pub fn retained_heap(&self) -> usize {
        vec_heap(&self.values) + self.networks.capacity() * size_of::<IpNetwork>()
    }

    /// Heap bytes the network list of a matcher over `values` CIDRs holds
    /// once built: `collect` grows it from four upwards while parsing a
    /// fallible iterator. All/port rules parse nothing.
    #[must_use]
    pub const fn networks_heap(rule: MatchType, values: usize) -> usize {
        if matches!(rule, MatchType::ClientCidr | MatchType::ProxyCidr) {
            collect_capacity(values) * size_of::<IpNetwork>()
        } else {
            0
        }
    }

    /// Peak heap bytes [`GroupMatcher::new`] requests beyond the value list it
    /// is given: the final network list plus the previous buffer that is still
    /// live while the last doubling copies into the new one.
    #[must_use]
    pub const fn construction_peak(rule: MatchType, values: usize) -> usize {
        let final_heap = Self::networks_heap(rule, values);
        let previous = collect_capacity(values);
        if final_heap != 0 && previous > 4 {
            final_heap + (previous / 2) * size_of::<IpNetwork>()
        } else {
            final_heap
        }
    }

    /// Heap bytes [`GroupMatcher::refresh_values`] requests beyond the new
    /// value list while the old network list is still alive: its internal
    /// clone of the values and the freshly parsed network list.
    #[must_use]
    pub fn refresh_peak(&self, values: &[String]) -> usize {
        size_of_val(values)
            + values.iter().map(String::len).sum::<usize>()
            + Self::construction_peak(self.rule, values.len())
    }

    /// Original, unnormalized group values.
    #[must_use]
    pub fn values(&self) -> &[String] {
        &self.values
    }

    /// Tests Go `Group.Match`. All/port groups return true; port routing must
    /// first use [`PortRoutes::group_for`] instead of scanning these predicates.
    #[must_use]
    pub fn matches(&self, client: ClientInfo<'_>) -> bool {
        let address = match self.rule {
            MatchType::ClientCidr => client.client_address,
            MatchType::ProxyCidr => client.proxy_address,
            MatchType::All | MatchType::Port => return true,
        };
        address
            .and_then(address_ip)
            .is_some_and(|ip| self.networks.iter().any(|network| network.contains(ip)))
    }

    /// Go's length-plus-membership equality, preserving its duplicate-value
    /// behavior. Raw strings are compared, not normalized networks or multisets.
    #[must_use]
    pub fn equal_values(&self, values: &[String]) -> bool {
        self.rule != MatchType::All
            && self.values.len() == values.len()
            && self.values.iter().all(|value| values.contains(value))
    }

    /// Raw-string intersection. Geometrically overlapping CIDRs alone do not
    /// intersect for the purpose of forming a group.
    #[must_use]
    pub fn intersects(&self, values: &[String]) -> bool {
        self.rule != MatchType::All && self.values.iter().any(|value| values.contains(value))
    }
}

/// Two distinct backend clusters claim the same raw listener port.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PortConflict;

#[derive(Clone, Debug)]
enum PortBinding<G> {
    Bound { cluster: String, group: G },
    Conflict,
}

/// One rebuilt listener-port dispatch table, equivalent to Go's detector.
///
/// Group references are opaque routing metadata, not source authority. A
/// conflict persists for the lifetime of this table even if a later bind names
/// the original cluster. Rebuild from the complete current group inventory by
/// constructing a new table; no incremental unbind or conflict-clear exists.
#[derive(Clone, Debug)]
pub struct PortRoutes<G> {
    ports: BTreeMap<String, PortBinding<G>>,
}

impl<G> Default for PortRoutes<G> {
    fn default() -> Self {
        Self {
            ports: BTreeMap::new(),
        }
    }
}

impl<G> PortRoutes<G> {
    /// Binds the raw port string. Empty ports are ignored; ports are not parsed
    /// or normalized. Within one cluster the latest group replaces the earlier
    /// one, while a different cluster makes this port persistently conflict.
    pub fn bind(&mut self, port: &str, cluster: &str, group: G) {
        if port.is_empty() {
            return;
        }
        match self.ports.get_mut(port) {
            Some(PortBinding::Conflict) => {}
            Some(binding @ PortBinding::Bound { .. }) => {
                let same_cluster = matches!(binding, PortBinding::Bound { cluster: owner, .. } if owner == cluster);
                *binding = if same_cluster {
                    PortBinding::Bound {
                        cluster: cluster.to_owned(),
                        group,
                    }
                } else {
                    PortBinding::Conflict
                };
            }
            None => {
                self.ports.insert(
                    port.to_owned(),
                    PortBinding::Bound {
                        cluster: cluster.to_owned(),
                        group,
                    },
                );
            }
        }
    }

    /// Resolves an exact listener-port string; an absent or empty port has no
    /// group. A conflict fails closed rather than falling through to any group.
    ///
    /// # Errors
    /// Returns [`PortConflict`] for a port claimed by distinct clusters.
    pub fn group_for(&self, port: &str) -> Result<Option<&G>, PortConflict> {
        match self.ports.get(port) {
            Some(PortBinding::Conflict) => Err(PortConflict),
            Some(PortBinding::Bound { group, .. }) => Ok(Some(group)),
            None => Ok(None),
        }
    }
}

/// Heap bytes a `Vec<String>` holds: its buffer by capacity plus each string.
fn vec_heap(values: &Vec<String>) -> usize {
    values.capacity() * size_of::<String>() + values.iter().map(String::capacity).sum::<usize>()
}

/// Capacity `collect` reaches for `len` elements pushed through a fallible
/// iterator with no size hint: zero stays unallocated, then four, doubling.
const fn collect_capacity(len: usize) -> usize {
    if len == 0 {
        return 0;
    }
    let mut capacity = 4;
    while capacity < len {
        capacity *= 2;
    }
    capacity
}

/// Layout mirror of a full `BTreeMap` internal node holding this table's key
/// and value types: the leaf part (parent link, index, length and eleven
/// key/value slots) plus twelve child edges. Every node allocation of the map
/// is at most this large, so charging one such node per bound entry bounds
/// the real tree from above.
#[repr(C)]
struct InternalNodeMirror<G> {
    _parent: *const (),
    _parent_idx: u16,
    _len: u16,
    _keys: [MaybeUninit<String>; 11],
    _vals: [MaybeUninit<PortBinding<G>>; 11],
    _edges: [*const (); 12],
}

impl<G> PortRoutes<G> {
    /// Nodes a single insertion may allocate transiently beyond the one node
    /// charged per entry: a split along the whole path of a tree that holds
    /// up to 16384 entries (height at most six with the minimum fill of five)
    /// plus a new root.
    pub const SPLIT_ALLOWANCE_NODES: usize = 8;

    /// Heap bytes one bound entry is charged: its key and cluster strings plus
    /// one full node, which bounds every node allocation the map makes.
    #[must_use]
    pub const fn entry_charge(port: usize, cluster: usize) -> usize {
        port + cluster + size_of::<InternalNodeMirror<G>>()
    }

    /// Transient bytes a rebuild may request beyond the sum of its entry
    /// charges: the split allowance.
    #[must_use]
    pub const fn rebuild_allowance() -> usize {
        Self::SPLIT_ALLOWANCE_NODES * size_of::<InternalNodeMirror<G>>()
    }

    /// Upper bound of the heap bytes this table holds: every entry's strings
    /// by capacity plus one full node per entry.
    #[must_use]
    pub fn retained_heap(&self) -> usize {
        self.ports
            .iter()
            .map(|(port, binding)| {
                let cluster = match binding {
                    PortBinding::Bound { cluster, .. } => cluster.capacity(),
                    PortBinding::Conflict => 0,
                };
                port.capacity() + cluster + size_of::<InternalNodeMirror<G>>()
            })
            .sum()
    }

    /// Number of bound ports, conflicts included.
    #[must_use]
    pub fn len(&self) -> usize {
        self.ports.len()
    }

    /// Whether no port is bound.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.ports.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn network(value: &str) -> IpNetwork {
        IpNetwork::parse(value).unwrap_or_else(|| unreachable!("valid fixture CIDR"))
    }
    fn ip(value: &str) -> IpAddr {
        value
            .parse()
            .unwrap_or_else(|error| unreachable!("fixture IP: {error}"))
    }

    #[test]
    fn prefix_defaults_and_mapped_networks_follow_go() {
        let default_v6 = network("2001:db8::1");
        assert!(default_v6.contains(ip("2001:db8:ffff::1")));
        assert!(!default_v6.contains(ip("2001:db9::1")));
        let mapped = network("::ffff:10.0.0.1/120");
        assert!(mapped.contains(ip("10.0.0.9")));
        assert!(mapped.contains(ip("::ffff:10.0.0.9")));
        assert!(!mapped.contains(ip("10.0.1.9")));
        let unprefixed = network("::ffff:10.0.0.1");
        assert!(!unprefixed.contains(ip("10.0.0.1")));
        assert!(unprefixed.contains(ip("::1")));
        assert!(!network("::/0").contains(ip("10.0.0.1")));
    }

    #[test]
    fn invalid_input_cannot_publish_a_partial_matcher() {
        assert_eq!(
            GroupMatcher::new(
                MatchType::ClientCidr,
                vec!["10.0.0.0/8".into(), "bad".into()]
            )
            .err(),
            Some(InvalidCidr { index: 1 })
        );
        for value in [
            "10.0.0.0/+8",
            "10.0.0.0/33",
            "::/129",
            "fe80::1%lo0/64",
            "10.0.0.0/8 ",
            "10.0.0.0/8/1",
        ] {
            assert!(IpNetwork::parse(value).is_none(), "{value}");
        }
    }

    #[test]
    fn raw_values_are_immutable_and_not_network_sets() {
        let original = vec!["10.0.0.1/8".into(), "10.0.0.1/8".into()];
        let matcher = GroupMatcher::new(MatchType::ClientCidr, original.clone())
            .unwrap_or_else(|error| unreachable!("fixture CIDR: {error:?}"));
        assert_eq!(matcher.values(), original);
        assert!(matcher.equal_values(&["10.0.0.1/8".into(), "unrelated".into()]));
        assert!(!matcher.intersects(&["10.0.0.0/8".into()]));
    }

    #[test]
    fn conflicting_port_never_self_heals() {
        let mut routes = PortRoutes::default();
        routes.bind("4000", "a", 1);
        routes.bind("4000", "a", 2);
        assert_eq!(routes.group_for("4000"), Ok(Some(&2)));
        routes.bind("4000", "b", 3);
        routes.bind("4000", "a", 4);
        assert_eq!(routes.group_for("4000"), Err(PortConflict));
        routes.bind("04000", "a", 5);
        assert_eq!(routes.group_for("04000"), Ok(Some(&5)));
        routes.bind("", "a", 6);
        assert_eq!(routes.group_for(""), Ok(None));
        routes = PortRoutes::default();
        routes.bind("4000", "a", 7);
        assert_eq!(routes.group_for("4000"), Ok(Some(&7)));
    }
}
