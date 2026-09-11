// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0
use super::*;

fn begin(support_redirection: bool) -> Begin {
    Begin {
        pass: 1,
        support_redirection,
        groups: Groups::new(&[9, 3]).unwrap_or_else(|_| unreachable!("valid fixture")),
    }
}
fn open(enabled: bool) -> Tracker {
    let b = begin(enabled);
    let mut tracker = Tracker::default();
    tracker
        .begin(&b, &b.groups, enabled)
        .unwrap_or_else(|_| unreachable!("valid fixture")); // Equal independent fixture inputs.
    tracker
}
#[test]
fn both_loops_and_disabled_close_are_complete() {
    for enabled in [true, false] {
        let mut tracker = open(enabled);
        assert_eq!(
            tracker.tail(),
            Err(InvalidReason::Lifecycle),
            "PASS_OPEN_TAIL"
        );
        if enabled {
            for group in [9, 3] {
                tracker
                    .group(1, Phase::Balance, group)
                    .unwrap_or_else(|_| unreachable!("valid fixture"));
            }
        }
        for group in [9, 3] {
            tracker
                .group(1, Phase::Close, group)
                .unwrap_or_else(|_| unreachable!("valid fixture"));
        }
        tracker
            .end(End {
                pass: 1,
                balanced: if enabled { 2 } else { 0 },
                closed: 2,
            })
            .unwrap_or_else(|_| unreachable!("valid fixture"));
        assert_eq!(tracker.tail(), Ok(()), "PASS_BOTH_LOOPS_CLOSE_DISABLED");
        assert_eq!(tracker.last_pass, 1);
    }
}
#[test]
fn witness_cannot_seed_inventory_or_gate() {
    for (groups, gate) in [([3, 9], true), ([9, 7], true), ([9, 3], false)] {
        let mut tracker = Tracker::default();
        assert_eq!(
            tracker.begin(
                &begin(true),
                &Groups::new(&groups).unwrap_or_else(|_| unreachable!("valid fixture")),
                gate
            ),
            Err(InvalidReason::Witness),
            "PASS_INDEPENDENT_INVENTORY_GATE"
        );
        assert!(tracker.open.is_none());
        assert!(
            tracker
                .begin(&begin(true), &begin(true).groups, true)
                .is_err(),
            "PASS_STICKY_FAILURE"
        );
    }
}
#[test]
fn order_duplicates_and_forged_tail_never_advance() {
    let cases = [
        (true, vec![(Phase::Balance, 3)]),
        (true, vec![(Phase::Balance, 9), (Phase::Close, 9)]),
        (true, vec![(Phase::Balance, 9), (Phase::Balance, 9)]),
        (false, vec![(Phase::Balance, 9)]),
        (false, vec![(Phase::Close, 7)]),
    ];
    for (enabled, calls) in cases {
        let mut tracker = open(enabled);
        let mut result = Ok(());
        for (phase, group) in calls {
            result = tracker.group(1, phase, group);
        }
        assert_eq!(
            result,
            Err(InvalidReason::Witness),
            "PASS_ORDER_NO_ALTERNATING"
        );
        assert!(
            tracker
                .end(End {
                    pass: 1,
                    balanced: 2,
                    closed: 2
                })
                .is_err()
        );
        assert_eq!(tracker.last_pass, 0, "PASS_FAILED_NO_COMMIT");
    }
    let mut tracker = open(false);
    assert_eq!(
        tracker.end(End {
            pass: 1,
            balanced: 0,
            closed: 2
        }),
        Err(InvalidReason::Witness),
        "PASS_NO_OMITTED_CLOSE"
    );
    assert_eq!(tracker.last_pass, 0);
}
#[test]
fn counts_incarnations_and_open_pass_are_fenced() {
    for end in [
        End {
            pass: 2,
            balanced: 0,
            closed: 2,
        },
        End {
            pass: 1,
            balanced: 1,
            closed: 2,
        },
        End {
            pass: 1,
            balanced: 0,
            closed: 1,
        },
    ] {
        let mut tracker = open(false);
        for group in [9, 3] {
            tracker
                .group(1, Phase::Close, group)
                .unwrap_or_else(|_| unreachable!("valid fixture"));
        }
        assert!(tracker.end(end).is_err(), "PASS_TAIL_COUNTS_ID");
        assert_eq!(tracker.last_pass, 0);
    }
    let mut tracker = open(true);
    assert_eq!(
        tracker.begin(&begin(true), &begin(true).groups, true),
        Err(InvalidReason::Lifecycle),
        "PASS_ONE_OPEN"
    );
    let mut tracker = Tracker::default();
    let empty = Groups::new(&[]).unwrap_or_else(|_| unreachable!("valid fixture"));
    for pass in [1, 2] {
        tracker
            .begin(
                &Begin {
                    pass,
                    support_redirection: true,
                    groups: empty.clone(),
                },
                &empty,
                true,
            )
            .unwrap_or_else(|_| unreachable!("valid fixture"));
        tracker
            .end(End {
                pass,
                balanced: 0,
                closed: 0,
            })
            .unwrap_or_else(|_| unreachable!("valid fixture"));
    }
    assert_eq!(
        tracker.begin(
            &Begin {
                pass: 2,
                support_redirection: true,
                groups: empty.clone()
            },
            &empty,
            true
        ),
        Err(InvalidReason::Sequence),
        "PASS_NO_REPLAY"
    );
    let mut exhausted = Tracker {
        last_pass: u64::MAX,
        ..Tracker::default()
    };
    assert_eq!(
        exhausted.begin(
            &Begin {
                pass: 0,
                support_redirection: true,
                groups: empty.clone()
            },
            &empty,
            true
        ),
        Err(InvalidReason::Sequence),
        "PASS_ID_NO_WRAP"
    );
}
#[test]
fn fixed_retention_and_group_equality_plus_one() {
    let ids: Vec<_> = (1..=65).collect();
    let groups = Groups::new(&ids[..64]).unwrap_or_else(|_| unreachable!("valid fixture"));
    assert_eq!(groups.as_slice(), &ids[..64], "PASS_GROUP_EQUAL");
    assert_eq!(
        Groups::new(&ids),
        Err(InvalidReason::Capacity),
        "PASS_GROUP_PLUS_ONE"
    );
    for invalid in [&[0][..], &[1, 1][..]] {
        assert_eq!(Groups::new(invalid), Err(InvalidReason::Identity));
    }
    assert_eq!(Tracker::CHARGE, size_of::<Tracker>());
    assert!(
        size_of_val(&Tracker::default()) <= 1024,
        "PASS_FIXED_RETAINED_LAYOUT"
    );
}

#[test]
fn foreign_pass_completion_is_not_a_group_visit() {
    let mut tracker = open(false);
    assert_eq!(
        tracker.group(2, Phase::Close, 9),
        Err(InvalidReason::Identity),
        "PASS_COMPLETION_ID"
    );
    assert_eq!(
        tracker
            .open
            .as_ref()
            .unwrap_or_else(|| unreachable!("open pass"))
            .completed,
        0
    );
}

#[test]
fn maximum_pass_calls_do_not_allow_an_extra_completion() {
    let ids: Vec<_> = (1..=64).collect();
    let groups = Groups::new(&ids).unwrap_or_else(|_| unreachable!("bounded inventory"));
    let begin = Begin {
        pass: 1,
        support_redirection: true,
        groups: groups.clone(),
    };
    for extra in [false, true] {
        let mut tracker = Tracker::default();
        tracker
            .begin(&begin, &groups, true)
            .unwrap_or_else(|_| unreachable!("header"));
        for phase in [Phase::Balance, Phase::Close] {
            for group in &ids {
                tracker
                    .group(1, phase, *group)
                    .unwrap_or_else(|_| unreachable!("all 128 completions"));
            }
        }
        if extra {
            assert_eq!(
                tracker.group(1, Phase::Close, 1),
                Err(InvalidReason::Witness),
                "PASS_NO_EXTRA_COMPLETION"
            );
        } else {
            assert_eq!(
                tracker.end(End {
                    pass: 1,
                    balanced: 64,
                    closed: 64
                }),
                Ok(()),
                "PASS_128_COMPLETIONS_EQUAL"
            );
        }
    }
}
