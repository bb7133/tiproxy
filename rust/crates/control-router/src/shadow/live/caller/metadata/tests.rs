// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::{
    Assign, Begin, Classification, End, Input, MAX_BACKENDS, MAX_VALUES, Member, Refresh, Rule,
    Tracker,
};
use crate::shadow::InvalidReason;
use crate::shadow::live::LiveEvent;
use crate::shadow::live::caller::selection::ErrorClass;
use control_routing::group::ClientInfo;
use std::cell::Cell;
use std::mem::size_of;

fn held(account: u64, healthy: bool) -> Input {
    Input {
        account,
        healthy,
        support_redirection: true,
        present: true,
    }
}
fn dropped(account: u64) -> Input {
    Input {
        account,
        healthy: false,
        support_redirection: true,
        present: false,
    }
}
fn begin(generation: u64, rule: Rule, inputs: Vec<Input>) -> Begin {
    Begin {
        generation,
        observer_error: ErrorClass::None,
        rule,
        inputs,
    }
}
fn values(list: &[&str]) -> Vec<String> {
    list.iter().map(|v| (*v).to_string()).collect()
}
fn assign(
    generation: u64,
    index: u16,
    account: u64,
    group: u64,
    created: bool,
    read: &[&str],
) -> Assign {
    Assign {
        generation,
        index,
        account,
        group,
        removed: false,
        created,
        values_read: true,
        values: values(read),
    }
}
fn unread(generation: u64, index: u16, account: u64, group: u64, removed: bool) -> Assign {
    Assign {
        generation,
        index,
        account,
        group,
        removed,
        created: false,
        values_read: false,
        values: Vec::new(),
    }
}
/// A CIDR refresh whose member tape is `reads` (account, values) and whose
/// stored result is `result`.
fn refresh(
    generation: u64,
    group: u64,
    reads: &[(u64, &[&str])],
    result: &[&str],
    parsed: bool,
) -> Refresh {
    Refresh {
        generation,
        group,
        values_read: true,
        members: reads
            .iter()
            .map(|(account, read)| Member {
                account: *account,
                values: values(read),
            })
            .collect(),
        values: values(result),
        parsed,
    }
}
fn unrefreshed(generation: u64, group: u64) -> Refresh {
    Refresh {
        generation,
        group,
        values_read: false,
        members: Vec::new(),
        values: Vec::new(),
        parsed: true,
    }
}
fn end(
    generation: u64,
    groups: u16,
    created: u16,
    removed: u16,
    refresh_failed: u16,
    conflicts: u16,
) -> End {
    End {
        generation,
        support_redirection: true,
        groups,
        created,
        removed,
        refresh_failed,
        conflicts,
    }
}
fn admit_all() -> impl FnMut(usize) -> Result<(), InvalidReason> {
    |_| Ok(())
}
fn client(address: &str) -> ClientInfo<'_> {
    ClientInfo {
        client_address: Some(address),
        proxy_address: None,
    }
}
fn created(t: &mut Tracker, id: u64) {
    assert!(t.group_event(&LiveEvent::GroupCreated(id)).is_ok());
    assert!(t.native_init(id).is_ok());
}
fn busy(_: u64) -> bool {
    false
}
fn idle(_: u64) -> bool {
    true
}

/// One CIDR refresh: a creates group 10, b joins by raw intersection, c has no
/// values, d fails construction (created+removed pair), e is never held.
fn cidr_first_refresh(t: &mut Tracker) {
    let inputs = vec![
        held(1, true),
        held(2, true),
        held(3, true),
        held(4, true),
        Input {
            account: 0,
            healthy: false,
            support_redirection: true,
            present: true,
        },
    ];
    assert!(
        t.begin(begin(1, Rule::ClientCidr, inputs), &mut admit_all())
            .is_ok()
    );
    created(t, 10);
    assert!(
        t.assign(
            &assign(1, 0, 1, 10, true, &["10.0.0.0/8"]),
            busy,
            &mut admit_all()
        )
        .is_ok()
    );
    assert!(
        t.assign(
            &assign(1, 1, 2, 10, false, &["10.0.0.0/8", "192.168.0.0/16"]),
            busy,
            &mut admit_all()
        )
        .is_ok()
    );
    assert!(
        t.assign(&assign(1, 2, 3, 0, false, &[]), busy, &mut admit_all())
            .is_ok()
    );
    created(t, 11);
    assert!(t.group_event(&LiveEvent::GroupRemoved(11)).is_ok());
    assert!(
        t.assign(
            &assign(1, 3, 4, 0, false, &["bad-cidr"]),
            busy,
            &mut admit_all()
        )
        .is_ok()
    );
    assert!(
        t.refresh(
            &refresh(
                1,
                10,
                &[(1, &["10.0.0.0/8"]), (2, &["10.0.0.0/8", "192.168.0.0/16"])],
                &["192.168.0.0/16", "10.0.0.0/8"],
                true
            ),
            &mut admit_all()
        )
        .is_ok()
    );
    assert!(t.end(end(1, 1, 1, 0, 0, 0), &mut admit_all()).is_ok());
}

#[test]
fn cidr_refresh_derives_inventory_membership_and_failed_construction() {
    let mut t = Tracker::native();
    cidr_first_refresh(&mut t);
    assert_eq!(t.generation(), 1);
    assert!(t.support_redirection());
    assert_eq!(
        t.classify(1, client("10.1.2.3:1"), "").ok(),
        Some(Classification::Group(10)),
        "METADATA_CIDR_GROUP"
    );
    assert_eq!(
        t.classify(1, client("172.16.0.1:1"), "").ok(),
        Some(Classification::NoGroup),
        "METADATA_CIDR_NO_GROUP"
    );
    assert!(
        t.matcher(10)
            .is_ok_and(|m| m.is_some_and(|m| m.values().len() == 2))
    );
    assert!(
        t.matcher(11).is_ok_and(|m| m.is_none()),
        "METADATA_FAILED_CONSTRUCTION_NOT_LIVE"
    );
    assert!(t.retained_charge() > t.clone_charge());

    // Second refresh: b changes to an invalid value; the group is kept, the
    // recomputation fails to parse and the old networks still match.
    let inputs = vec![held(1, true), held(2, true), held(3, true), held(4, true)];
    assert!(
        t.begin(begin(2, Rule::ClientCidr, inputs), &mut admit_all())
            .is_ok()
    );
    assert!(
        t.assign(
            &assign(2, 0, 1, 10, false, &["10.0.0.0/8"]),
            busy,
            &mut admit_all()
        )
        .is_ok()
    );
    assert!(
        t.assign(
            &assign(2, 1, 2, 10, false, &["bad-cidr"]),
            busy,
            &mut admit_all()
        )
        .is_ok()
    );
    assert!(
        t.assign(&assign(2, 2, 3, 0, false, &[]), busy, &mut admit_all())
            .is_ok()
    );
    created(&mut t, 12);
    assert!(t.group_event(&LiveEvent::GroupRemoved(12)).is_ok());
    assert!(
        t.assign(
            &assign(2, 3, 4, 0, false, &["bad-cidr"]),
            busy,
            &mut admit_all()
        )
        .is_ok()
    );
    assert!(
        t.refresh(
            &refresh(
                2,
                10,
                &[(1, &["10.0.0.0/8"]), (2, &["bad-cidr"])],
                &["bad-cidr", "10.0.0.0/8"],
                false
            ),
            &mut admit_all()
        )
        .is_ok()
    );
    assert!(t.end(end(2, 1, 0, 0, 1, 0), &mut admit_all()).is_ok());
    assert_eq!(
        t.classify(2, client("192.168.5.5:1"), "").ok(),
        Some(Classification::Group(10)),
        "METADATA_REFRESH_FAILURE_KEEPS_NETWORKS"
    );
}

#[test]
fn observer_error_rebuilds_nothing_and_classifies_by_exact_class() {
    let mut t = Tracker::native();
    cidr_first_refresh(&mut t);
    let error = Begin {
        generation: 2,
        observer_error: ErrorClass::NoBackend,
        rule: Rule::ClientCidr,
        inputs: Vec::new(),
    };
    assert!(t.begin(error, &mut admit_all()).is_ok());
    assert!(t.end(end(2, 1, 0, 0, 0, 0), &mut admit_all()).is_ok());
    assert_eq!(
        t.classify(2, client("10.1.2.3:1"), "").ok(),
        Some(Classification::ObserverError(ErrorClass::NoBackend)),
        "METADATA_EXACT_SENTINEL_CLASS"
    );
    let other = Begin {
        generation: 3,
        observer_error: ErrorClass::Other,
        rule: Rule::ClientCidr,
        inputs: Vec::new(),
    };
    assert!(t.begin(other, &mut admit_all()).is_ok());
    assert_eq!(
        t.end(end(3, 1, 0, 0, 1, 0), &mut admit_all()),
        Err(InvalidReason::Witness),
        "METADATA_ERROR_TAIL_WITNESS"
    );
}

#[test]
fn all_rule_keeps_busy_backend_and_removes_idle_with_real_group_removal() {
    let mut t = Tracker::default();
    assert!(
        t.begin(
            begin(1, Rule::All, vec![held(1, true), held(2, true)]),
            &mut admit_all()
        )
        .is_ok()
    );
    assert!(t.group_event(&LiveEvent::GroupCreated(10)).is_ok());
    let mut first = unread(1, 0, 1, 10, false);
    first.created = true;
    assert!(t.assign(&first, busy, &mut admit_all()).is_ok());
    assert!(
        t.assign(&unread(1, 1, 2, 10, false), busy, &mut admit_all())
            .is_ok()
    );
    assert!(t.refresh(&unrefreshed(1, 10), &mut admit_all()).is_ok());
    assert!(t.end(end(1, 1, 1, 0, 0, 0), &mut admit_all()).is_ok());
    assert_eq!(
        t.classify(1, client("1.2.3.4:1"), "").ok(),
        Some(Classification::Group(10))
    );

    // Unhealthy but busy: kept in its group.
    assert!(
        t.begin(
            begin(2, Rule::All, vec![held(1, false), held(2, true)]),
            &mut admit_all()
        )
        .is_ok()
    );
    // Kept inside the lock, then revisited by the ordinary group branch
    // (no values under MatchAll), then backend 2.
    assert!(
        t.assign(&unread(2, 0, 1, 10, false), busy, &mut admit_all())
            .is_ok()
    );
    assert!(
        t.assign(&unread(2, 1, 1, 10, false), busy, &mut admit_all())
            .is_ok(),
        "METADATA_REVISIT"
    );
    assert!(
        t.assign(&unread(2, 2, 2, 10, false), busy, &mut admit_all())
            .is_ok()
    );
    assert!(t.refresh(&unrefreshed(2, 10), &mut admit_all()).is_ok());
    assert!(t.end(end(2, 1, 0, 0, 0, 0), &mut admit_all()).is_ok());

    // Both dropped and idle: removed; the group empties after its real
    // GroupRemoved and no Refresh frame follows.
    assert!(
        t.begin(
            begin(3, Rule::All, vec![dropped(1), dropped(2)]),
            &mut admit_all()
        )
        .is_ok()
    );
    assert!(
        t.assign(&unread(3, 0, 1, 0, true), idle, &mut admit_all())
            .is_ok()
    );
    assert!(t.group_event(&LiveEvent::GroupRemoved(10)).is_ok());
    assert!(
        t.assign(&unread(3, 1, 2, 0, true), idle, &mut admit_all())
            .is_ok()
    );
    assert!(t.end(end(3, 0, 0, 2, 0, 0), &mut admit_all()).is_ok());
    assert_eq!(
        t.classify(3, client("1.2.3.4:1"), "").ok(),
        Some(Classification::NoGroup)
    );
    assert!(t.known_groups().is_ok_and(|g| g.as_slice().is_empty()));
}

#[test]
fn port_rule_derives_cluster_conflicts() {
    let mut t = Tracker::default();
    assert!(
        t.begin(
            begin(
                1,
                Rule::Port,
                vec![held(1, true), held(2, true), held(3, true)]
            ),
            &mut admit_all()
        )
        .is_ok()
    );
    assert!(t.group_event(&LiveEvent::GroupCreated(10)).is_ok());
    assert!(
        t.assign(
            &assign(1, 0, 1, 10, true, &["alpha:6000"]),
            busy,
            &mut admit_all()
        )
        .is_ok()
    );
    assert!(t.group_event(&LiveEvent::GroupCreated(11)).is_ok());
    assert!(
        t.assign(
            &assign(1, 1, 2, 11, true, &["beta:6000"]),
            busy,
            &mut admit_all()
        )
        .is_ok()
    );
    assert!(t.group_event(&LiveEvent::GroupCreated(12)).is_ok());
    assert!(
        t.assign(
            &assign(1, 2, 3, 12, true, &["beta:6001"]),
            busy,
            &mut admit_all()
        )
        .is_ok()
    );
    for group in [10, 11, 12] {
        assert!(t.refresh(&unrefreshed(1, group), &mut admit_all()).is_ok());
    }
    assert!(t.end(end(1, 3, 3, 0, 0, 1), &mut admit_all()).is_ok());
    assert_eq!(
        t.classify(1, client("1.2.3.4:1"), "6000").ok(),
        Some(Classification::Conflict)
    );
    assert_eq!(
        t.classify(1, client("1.2.3.4:1"), "6001").ok(),
        Some(Classification::Group(12))
    );
    assert_eq!(
        t.classify(1, client("1.2.3.4:1"), "6002").ok(),
        Some(Classification::NoGroup)
    );
}

#[test]
fn witnesses_lifecycle_and_sequence_are_sticky() {
    // A wrong outcome witness fails and keeps the last committed state.
    let mut t = Tracker::native();
    cidr_first_refresh(&mut t);
    assert!(
        t.begin(
            begin(
                2,
                Rule::ClientCidr,
                vec![held(1, true), held(2, true), held(3, true), held(4, true)]
            ),
            &mut admit_all()
        )
        .is_ok()
    );
    assert_eq!(
        t.assign(
            &assign(2, 0, 1, 0, false, &["10.0.0.0/8"]),
            busy,
            &mut admit_all()
        ),
        Err(InvalidReason::Witness),
        "METADATA_OUTCOME_WITNESS"
    );
    assert_eq!(
        t.end(end(2, 1, 0, 0, 0, 0), &mut admit_all()),
        Err(InvalidReason::Witness)
    );
    assert_eq!(t.generation(), 1);

    // Coverage: a retained backend missing from the inputs.
    let mut t = Tracker::native();
    cidr_first_refresh(&mut t);
    assert_eq!(
        t.begin(
            begin(2, Rule::ClientCidr, vec![held(1, true)]),
            &mut admit_all()
        ),
        Err(InvalidReason::Witness),
        "METADATA_INPUT_COVERAGE"
    );
}

#[test]
fn group_lifecycle_binding_is_sticky() {
    // A created group without its real GroupCreated event.
    let mut t = Tracker::default();
    assert!(
        t.begin(
            begin(1, Rule::ClientCidr, vec![held(1, true)]),
            &mut admit_all()
        )
        .is_ok()
    );
    assert_eq!(
        t.assign(
            &assign(1, 0, 1, 10, true, &["10.0.0.0/8"]),
            busy,
            &mut admit_all()
        ),
        Err(InvalidReason::Lifecycle),
        "METADATA_UNBOUND_CREATED"
    );

    // A created group whose native Init never ran.
    let mut t = Tracker::native();
    assert!(
        t.begin(
            begin(1, Rule::ClientCidr, vec![held(1, true)]),
            &mut admit_all()
        )
        .is_ok()
    );
    assert!(t.group_event(&LiveEvent::GroupCreated(10)).is_ok());
    assert_eq!(
        t.assign(
            &assign(1, 0, 1, 10, true, &["10.0.0.0/8"]),
            busy,
            &mut admit_all()
        ),
        Err(InvalidReason::Lifecycle),
        "METADATA_CREATED_WITHOUT_INIT"
    );

    // A failed construction that Go never announced.
    let mut t = Tracker::default();
    assert!(
        t.begin(
            begin(1, Rule::ClientCidr, vec![held(1, true)]),
            &mut admit_all()
        )
        .is_ok()
    );
    assert_eq!(
        t.assign(
            &assign(1, 0, 1, 0, false, &["bad-cidr"]),
            busy,
            &mut admit_all()
        ),
        Err(InvalidReason::Witness),
        "METADATA_SILENT_FAILED_CONSTRUCTION"
    );

    // An announced construction left unbound at End.
    let mut t = Tracker::default();
    assert!(
        t.begin(
            begin(1, Rule::ClientCidr, vec![held(1, true)]),
            &mut admit_all()
        )
        .is_ok()
    );
    assert!(t.group_event(&LiveEvent::GroupCreated(10)).is_ok());
    assert!(
        t.assign(&assign(1, 0, 1, 0, false, &[]), busy, &mut admit_all())
            .is_ok()
    );
    assert_eq!(
        t.end(end(1, 0, 0, 0, 0, 0), &mut admit_all()),
        Err(InvalidReason::Lifecycle),
        "METADATA_UNBOUND_GROUP_AT_END"
    );
}

#[test]
fn refresh_ordering_and_value_witnesses_are_sticky() {
    // Group events outside a refresh, and a Refresh before all decisions.
    let mut t = Tracker::default();
    assert_eq!(
        t.group_event(&LiveEvent::GroupCreated(10)),
        Err(InvalidReason::Lifecycle)
    );
    let mut t = Tracker::native();
    cidr_first_refresh(&mut t);
    assert!(
        t.begin(
            begin(
                2,
                Rule::ClientCidr,
                vec![held(1, true), held(2, true), held(3, true), held(4, true)]
            ),
            &mut admit_all()
        )
        .is_ok()
    );
    assert_eq!(
        t.refresh(
            &refresh(2, 10, &[(1, &["10.0.0.0/8"])], &["10.0.0.0/8"], true),
            &mut admit_all()
        ),
        Err(InvalidReason::Lifecycle),
        "METADATA_REFRESH_BEFORE_DECISIONS"
    );

    // The stored result must be exactly the distinct union of the member reads.
    let mut t = Tracker::native();
    cidr_first_refresh(&mut t);
    assert!(
        t.begin(
            begin(
                2,
                Rule::ClientCidr,
                vec![held(1, true), held(2, true), held(3, true), held(4, true)]
            ),
            &mut admit_all()
        )
        .is_ok()
    );
    assert!(
        t.assign(
            &assign(2, 0, 1, 10, false, &["10.0.0.0/8"]),
            busy,
            &mut admit_all()
        )
        .is_ok()
    );
    assert!(
        t.assign(
            &assign(2, 1, 2, 10, false, &["10.0.0.0/8", "192.168.0.0/16"]),
            busy,
            &mut admit_all()
        )
        .is_ok()
    );
    assert!(
        t.assign(&assign(2, 2, 3, 0, false, &[]), busy, &mut admit_all())
            .is_ok()
    );
    created(&mut t, 12);
    assert!(t.group_event(&LiveEvent::GroupRemoved(12)).is_ok());
    assert!(
        t.assign(
            &assign(2, 3, 4, 0, false, &["bad-cidr"]),
            busy,
            &mut admit_all()
        )
        .is_ok()
    );
    assert_eq!(
        t.refresh(
            &refresh(
                2,
                10,
                &[(1, &["10.0.0.0/8"]), (2, &["10.0.0.0/8", "192.168.0.0/16"])],
                &["10.0.0.0/8"],
                true
            ),
            &mut admit_all()
        ),
        Err(InvalidReason::Witness),
        "METADATA_REFRESH_VALUE_WITNESS"
    );
}

#[test]
fn generation_and_index_sequencing_are_sticky() {
    // Generation and index sequencing.
    let mut t = Tracker::default();
    assert_eq!(
        t.begin(begin(2, Rule::All, Vec::new()), &mut admit_all()),
        Err(InvalidReason::Sequence)
    );
    let mut t = Tracker::default();
    assert!(
        t.begin(
            begin(1, Rule::All, vec![held(1, true), held(2, true)]),
            &mut admit_all()
        )
        .is_ok()
    );
    assert!(t.group_event(&LiveEvent::GroupCreated(10)).is_ok());
    assert_eq!(
        t.assign(&unread(1, 1, 1, 10, false), busy, &mut admit_all()),
        Err(InvalidReason::Sequence)
    );
}

#[test]
fn bounds_and_admission_are_capacity_failures() {
    // A 65th input.
    let mut t = Tracker::default();
    let inputs: Vec<Input> = (1..=MAX_BACKENDS as u64 + 1)
        .map(|a| held(a, true))
        .collect();
    assert_eq!(
        t.begin(begin(1, Rule::All, inputs), &mut admit_all()),
        Err(InvalidReason::Capacity),
        "METADATA_BACKENDS_PLUS_ONE"
    );
    // Shared admission rejects the working clone before it is made.
    let mut t = Tracker::default();
    let mut deny = |_: usize| Err(InvalidReason::Capacity);
    assert_eq!(
        t.begin(begin(1, Rule::All, vec![held(1, true)]), &mut deny),
        Err(InvalidReason::Capacity)
    );
    assert_eq!(t.generation(), 0);
    // Retained aggregate bound: one backend reading 256 values is within the
    // per-refresh bound, and the group copy doubles it to the retained bound;
    // a second backend of the same size then exceeds retention.
    let mut t = Tracker::default();
    assert!(
        t.begin(
            begin(1, Rule::ClientCidr, vec![held(1, true), held(2, true)]),
            &mut admit_all()
        )
        .is_ok()
    );
    let wide: Vec<String> = (0..MAX_VALUES).map(|i| format!("10.{i}.0.0/16")).collect();
    assert!(t.group_event(&LiveEvent::GroupCreated(10)).is_ok());
    let mut first = assign(1, 0, 1, 10, true, &[]);
    first.values.clone_from(&wide);
    assert!(t.assign(&first, busy, &mut admit_all()).is_ok());
    // Joins group 10 by one shared raw value; the other 255 are new.
    let mut second = assign(1, 1, 2, 10, false, &[]);
    second.values = (0..MAX_VALUES)
        .map(|i| {
            if i == 0 {
                "10.0.0.0/16".to_string()
            } else {
                format!("11.{i}.0.0/16")
            }
        })
        .collect();
    assert_eq!(
        t.assign(&second, busy, &mut admit_all()),
        Err(InvalidReason::Capacity),
        "METADATA_RETAINED_VALUES_BOUND"
    );
}

#[test]
fn refresh_member_tape_rejects_extra_cidr_and_wrong_membership() {
    // c510c5b5: a busy member kept 10.0.0.0/8 across a generation in which
    // no Assign read its values; the stored result may not grow beyond what
    // the member reads inside RefreshCidr actually returned.
    let mut t = Tracker::native();
    assert!(
        t.begin(
            begin(1, Rule::ClientCidr, vec![held(1, true)]),
            &mut admit_all()
        )
        .is_ok()
    );
    created(&mut t, 10);
    assert!(
        t.assign(
            &assign(1, 0, 1, 10, true, &["10.0.0.0/8"]),
            busy,
            &mut admit_all()
        )
        .is_ok()
    );
    assert!(
        t.refresh(
            &refresh(1, 10, &[(1, &["10.0.0.0/8"])], &["10.0.0.0/8"], true),
            &mut admit_all()
        )
        .is_ok()
    );
    assert!(t.end(end(1, 1, 1, 0, 0, 0), &mut admit_all()).is_ok());
    // Generation 2: backend 1 unhealthy but busy (kept, then revisited with a read).
    assert!(
        t.begin(
            begin(2, Rule::ClientCidr, vec![held(1, false)]),
            &mut admit_all()
        )
        .is_ok()
    );
    assert!(
        t.assign(&unread(2, 0, 1, 10, false), busy, &mut admit_all())
            .is_ok()
    );
    assert!(
        t.assign(
            &assign(2, 1, 1, 10, false, &["10.0.0.0/8"]),
            busy,
            &mut admit_all()
        )
        .is_ok()
    );
    let forged = refresh(
        2,
        10,
        &[(1, &["10.0.0.0/8"])],
        &["10.0.0.0/8", "0.0.0.0/0"],
        true,
    );
    assert_eq!(
        t.refresh(&forged, &mut admit_all()),
        Err(InvalidReason::Witness),
        "METADATA_EXTRA_RESULT_CIDR"
    );

    // A member tape that is not the group's membership.
    let mut t = Tracker::native();
    assert!(
        t.begin(
            begin(1, Rule::ClientCidr, vec![held(1, true), held(2, true)]),
            &mut admit_all()
        )
        .is_ok()
    );
    created(&mut t, 10);
    assert!(
        t.assign(
            &assign(1, 0, 1, 10, true, &["10.0.0.0/8"]),
            busy,
            &mut admit_all()
        )
        .is_ok()
    );
    assert!(
        t.assign(&assign(1, 1, 2, 0, false, &[]), busy, &mut admit_all())
            .is_ok()
    );
    assert_eq!(
        t.refresh(
            &refresh(
                1,
                10,
                &[(1, &["10.0.0.0/8"]), (2, &[])],
                &["10.0.0.0/8"],
                true
            ),
            &mut admit_all()
        ),
        Err(InvalidReason::Witness),
        "METADATA_REFRESH_MEMBERSHIP"
    );
}

#[test]
fn revisit_must_follow_a_busy_keep_and_read_under_a_value_rule() {
    let mut t = Tracker::native();
    assert!(
        t.begin(
            begin(1, Rule::ClientCidr, vec![held(1, true), held(2, true)]),
            &mut admit_all()
        )
        .is_ok()
    );
    created(&mut t, 10);
    assert!(
        t.assign(
            &assign(1, 0, 1, 10, true, &["10.0.0.0/8"]),
            busy,
            &mut admit_all()
        )
        .is_ok()
    );
    assert!(
        t.assign(
            &assign(1, 1, 2, 10, false, &["10.0.0.0/8"]),
            busy,
            &mut admit_all()
        )
        .is_ok()
    );
    assert!(
        t.refresh(
            &refresh(
                1,
                10,
                &[(1, &["10.0.0.0/8"]), (2, &["10.0.0.0/8"])],
                &["10.0.0.0/8"],
                true
            ),
            &mut admit_all()
        )
        .is_ok()
    );
    assert!(t.end(end(1, 1, 1, 0, 0, 0), &mut admit_all()).is_ok());
    // Backend 1 busy: the next frame must be its revisit, not backend 2.
    assert!(
        t.begin(
            begin(2, Rule::ClientCidr, vec![held(1, false), held(2, true)]),
            &mut admit_all()
        )
        .is_ok()
    );
    assert!(
        t.assign(&unread(2, 0, 1, 10, false), busy, &mut admit_all())
            .is_ok()
    );
    assert_eq!(
        t.assign(
            &assign(2, 1, 2, 10, false, &["10.0.0.0/8"]),
            busy,
            &mut admit_all()
        ),
        Err(InvalidReason::Witness),
        "METADATA_REVISIT_ORDER"
    );
    // A revisit under a value rule must read values.
    let mut t = Tracker::native();
    assert!(
        t.begin(
            begin(1, Rule::ClientCidr, vec![held(1, true)]),
            &mut admit_all()
        )
        .is_ok()
    );
    created(&mut t, 10);
    assert!(
        t.assign(
            &assign(1, 0, 1, 10, true, &["10.0.0.0/8"]),
            busy,
            &mut admit_all()
        )
        .is_ok()
    );
    assert!(
        t.refresh(
            &refresh(1, 10, &[(1, &["10.0.0.0/8"])], &["10.0.0.0/8"], true),
            &mut admit_all()
        )
        .is_ok()
    );
    assert!(t.end(end(1, 1, 1, 0, 0, 0), &mut admit_all()).is_ok());
    assert!(
        t.begin(
            begin(2, Rule::ClientCidr, vec![held(1, false)]),
            &mut admit_all()
        )
        .is_ok()
    );
    assert!(
        t.assign(&unread(2, 0, 1, 10, false), busy, &mut admit_all())
            .is_ok()
    );
    assert_eq!(
        t.assign(&unread(2, 1, 1, 10, false), busy, &mut admit_all()),
        Err(InvalidReason::Witness),
        "METADATA_REVISIT_READS"
    );
}

#[test]
fn admission_is_exact_and_precedes_every_growth() {
    // Every admit argument is the retained charge the tracker holds right
    // after that growth (or the transient peak when an old list is replaced),
    // and a budget one byte short rejects before anything is allocated.
    let mut t = Tracker::native();
    let admitted = Cell::new(0usize);
    let mut record = |charge: usize| {
        admitted.set(charge);
        Ok(())
    };
    let before = t.retained_charge();
    assert!(
        t.begin(
            begin(1, Rule::ClientCidr, vec![held(1, true), held(2, true)]),
            &mut record
        )
        .is_ok()
    );
    assert_eq!(
        Some(admitted.get()),
        Some(t.retained_charge()),
        "METADATA_BEGIN_CHARGE_EXACT"
    );
    assert!(t.retained_charge() > before);
    created(&mut t, 10);
    assert!(
        t.assign(
            &assign(1, 0, 1, 10, true, &["10.0.0.0/8"]),
            busy,
            &mut record
        )
        .is_ok()
    );
    assert_eq!(
        Some(admitted.get()),
        Some(t.retained_charge()),
        "METADATA_ASSIGN_CHARGE_EXACT"
    );
    assert!(
        t.assign(
            &assign(1, 1, 2, 10, false, &["10.0.0.0/8", "192.168.0.0/16"]),
            busy,
            &mut record
        )
        .is_ok()
    );
    assert_eq!(
        Some(admitted.get()),
        Some(t.retained_charge()),
        "METADATA_JOIN_CHARGE_EXACT"
    );
    let peak_before_refresh = t.retained_charge();
    assert!(
        t.refresh(
            &refresh(
                1,
                10,
                &[(1, &["10.0.0.0/8"]), (2, &["10.0.0.0/8", "192.168.0.0/16"])],
                &["10.0.0.0/8", "192.168.0.0/16"],
                true
            ),
            &mut record
        )
        .is_ok()
    );
    // The refresh replaces two value lists and the matcher's list: the
    // admitted peak covers old and new together, and retention ends below it.
    assert!(admitted.get() > peak_before_refresh && admitted.get() >= t.retained_charge());
    assert!(t.end(end(1, 1, 1, 0, 0, 0), &mut record).is_ok());
    let generation_one = t.retained_charge();

    // Plus-one evidence on the next begin: the exact projected charge is
    // admitted, one byte less is a Capacity failure that changes nothing.
    let projected =
        generation_one + t.clone_charge() + 2 * size_of::<Input>() + super::Open::SCRATCH_HEAP;
    let mut short = |charge: usize| {
        if charge > projected - 1 {
            Err(InvalidReason::Capacity)
        } else {
            Ok(())
        }
    };
    assert_eq!(
        t.begin(
            begin(2, Rule::ClientCidr, vec![held(1, true), held(2, true)]),
            &mut short
        ),
        Err(InvalidReason::Capacity),
        "METADATA_BUDGET_PLUS_ONE"
    );
    assert_eq!(t.retained_charge(), generation_one);
    let mut t = Tracker::native();
    let mut seen = 0;
    let mut exact = |charge: usize| {
        seen = charge;
        Ok(())
    };
    assert!(
        t.begin(
            begin(1, Rule::ClientCidr, vec![held(1, true), held(2, true)]),
            &mut exact
        )
        .is_ok()
    );
    assert_eq!(seen, t.retained_charge(), "METADATA_BUDGET_EQUALITY");
}

#[test]
fn per_refresh_aggregate_matches_go_accounting() {
    // Go's scratch charges every Assign value and every Refresh member read
    // and stored result against 256 values / 64 KiB per refresh; the tracker
    // must fail at the same boundary.
    let mut t = Tracker::native();
    assert!(
        t.begin(
            begin(1, Rule::ClientCidr, vec![held(1, true)]),
            &mut admit_all()
        )
        .is_ok()
    );
    created(&mut t, 10);
    let wide: Vec<String> = (0..MAX_VALUES - 1)
        .map(|i| format!("10.{i}.0.0/16"))
        .collect();
    let mut first = assign(1, 0, 1, 10, true, &[]);
    first.values.clone_from(&wide);
    assert!(t.assign(&first, busy, &mut admit_all()).is_ok());
    // 255 read in Assign; the Refresh reads 255 more as a member and stores 255: over 256.
    let mut tape = refresh(1, 10, &[], &[], true);
    tape.members.push(Member {
        account: 1,
        values: wide.clone(),
    });
    tape.values.clone_from(&wide);
    assert_eq!(
        t.refresh(&tape, &mut admit_all()),
        Err(InvalidReason::Capacity),
        "METADATA_AGGREGATE_VALUES"
    );
}

#[test]
fn port_union_across_generations_is_planned_without_a_fixed_table() {
    // da94d89d: port groups retained from earlier generations accumulate
    // beyond one refresh's 256 reads; the rebuild plan counts every distinct
    // port without a fixed-size scratch and the table is admitted as a whole.
    let mut t = Tracker::default();
    let first: Vec<String> = (0..200).map(|i| format!("alpha:{}", 4000 + i)).collect();
    assert!(
        t.begin(begin(1, Rule::Port, vec![held(1, true)]), &mut admit_all())
            .is_ok()
    );
    assert!(t.group_event(&LiveEvent::GroupCreated(10)).is_ok());
    let mut create = assign(1, 0, 1, 10, true, &[]);
    create.values.clone_from(&first);
    assert!(t.assign(&create, busy, &mut admit_all()).is_ok());
    assert!(t.refresh(&unrefreshed(1, 10), &mut admit_all()).is_ok());
    assert!(t.end(end(1, 1, 1, 0, 0, 0), &mut admit_all()).is_ok());

    let second: Vec<String> = (0..200).map(|i| format!("beta:{}", 4200 + i)).collect();
    assert!(
        t.begin(
            begin(2, Rule::Port, vec![held(1, true), held(2, true)]),
            &mut admit_all()
        )
        .is_ok()
    );
    // The retained backend reads one changed value and keeps its group; with
    // the 200-port creation this generation reads 201 values, within the
    // per-refresh bound, while the live port union grows to 400.
    let keep = assign(2, 0, 1, 10, false, &["alpha:9999"]);
    assert!(t.assign(&keep, busy, &mut admit_all()).is_ok());
    assert!(t.group_event(&LiveEvent::GroupCreated(11)).is_ok());
    let mut create = assign(2, 1, 2, 11, true, &[]);
    create.values.clone_from(&second);
    assert!(t.assign(&create, busy, &mut admit_all()).is_ok());
    assert!(t.refresh(&unrefreshed(2, 10), &mut admit_all()).is_ok());
    assert!(t.refresh(&unrefreshed(2, 11), &mut admit_all()).is_ok());
    let admitted = Cell::new(0usize);
    let mut record = |charge: usize| {
        admitted.set(charge);
        Ok(())
    };
    assert!(
        t.end(end(2, 2, 1, 0, 0, 0), &mut record).is_ok(),
        "METADATA_PORT_UNION_400"
    );
    // The table plan admitted the whole 400-entry rebuild before it was built.
    assert!(
        admitted.get() > t.retained_charge() - 400 * 700,
        "METADATA_PORT_PLAN_ADMITTED"
    );
    assert_eq!(
        t.classify(2, client("1.2.3.4:1"), "4000").ok(),
        Some(Classification::Group(10))
    );
    assert_eq!(
        t.classify(2, client("1.2.3.4:1"), "4399").ok(),
        Some(Classification::Group(11))
    );
    assert_eq!(
        t.classify(2, client("1.2.3.4:1"), "4400").ok(),
        Some(Classification::NoGroup)
    );
    assert!(t.known_groups().is_ok_and(|g| g.as_slice() == [10, 11]));
}
