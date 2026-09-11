// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The charge helpers are consistent with the capacities the matcher and the
//! port table really hold. The allocator-level bound (requested bytes never
//! exceed the charge) is established by the out-of-tree counting-allocator
//! probe recorded with the checkpoint evidence, because the workspace forbids
//! `unsafe` and therefore a custom global allocator.
use control_routing::group::{GroupMatcher, MatchType, PortRoutes};
use std::mem::{size_of, size_of_val};

fn cidrs(n: usize) -> Vec<String> {
    (0..n)
        .map(|i| format!("10.{}.{}.0/24", i / 256, i % 256))
        .collect()
}
fn given(values: &[String]) -> usize {
    size_of_val(values) + values.iter().map(String::len).sum::<usize>()
}

#[test]
fn matcher_charges_follow_real_capacities() {
    for n in [0usize, 1, 3, 4, 5, 127, 128, 256] {
        let values = cidrs(n);
        let matcher = GroupMatcher::new(MatchType::ClientCidr, values.clone())
            .unwrap_or_else(|_| unreachable!("valid cidrs"));
        // The value list is moved in unchanged; the network list is grown by
        // `collect` from four upwards.
        assert_eq!(
            matcher.retained_heap(),
            given(&values) + GroupMatcher::networks_heap(MatchType::ClientCidr, n),
            "RETAINED_EQUALS_GIVEN_PLUS_NETWORKS n={n}"
        );
        // The construction peak additionally covers the buffer replaced by
        // the last doubling.
        let transient = if n > 4 {
            (n.next_power_of_two() / 2) * GroupMatcher::NETWORK_SIZE
        } else {
            0
        };
        assert_eq!(
            GroupMatcher::construction_peak(MatchType::ClientCidr, n),
            GroupMatcher::networks_heap(MatchType::ClientCidr, n) + transient,
            "CONSTRUCTION_PEAK n={n}"
        );
        let expected_networks = match n {
            0 => 0,
            1..=4 => 4,
            5..=8 => 8,
            _ => n.next_power_of_two(),
        };
        assert_eq!(
            GroupMatcher::networks_heap(MatchType::ClientCidr, n),
            expected_networks * GroupMatcher::NETWORK_SIZE,
            "COLLECT_CAPACITY n={n}"
        );
        assert_eq!(GroupMatcher::construction_peak(MatchType::Port, n), 0);
        // A refresh clones the new list internally and parses a fresh
        // network list before the old one is released.
        let fresh = cidrs(n);
        assert_eq!(
            matcher.refresh_peak(&fresh),
            given(&fresh) + GroupMatcher::construction_peak(MatchType::ClientCidr, n),
            "REFRESH_PEAK n={n}"
        );
    }
    assert_eq!(GroupMatcher::NETWORK_SIZE, 48, "NETWORK_SIZE_LAYOUT");
}

#[test]
fn port_charges_bound_every_entry_by_a_full_node() {
    let mut table: PortRoutes<u64> = PortRoutes::default();
    let mut charged = 0;
    for i in 0..400u64 {
        let port = format!("{}", 4000 + i);
        let cluster = format!("cluster-{}", i % 7);
        charged += PortRoutes::<u64>::entry_charge(port.len(), cluster.len());
        table.bind(&port, &cluster, i);
    }
    assert_eq!(table.len(), 400);
    assert!(!table.is_empty());
    // Every retained entry is charged its strings plus one full node, which
    // is never less than the strings it actually holds.
    assert!(table.retained_heap() >= 400 * (4 + 9));
    assert_eq!(
        table.retained_heap(),
        charged,
        "PORTS_RETAINED_EQUALS_SUM_OF_BIND_PEAKS"
    );
    // Eleven key slots, eleven binding slots (a String plus the group) and twelve edges.
    assert!(
        PortRoutes::<u64>::entry_charge(0, 0) >= 11 * (2 * size_of::<String>() + 8) + 12 * 8,
        "NODE_MIRROR_LAYOUT"
    );
}
