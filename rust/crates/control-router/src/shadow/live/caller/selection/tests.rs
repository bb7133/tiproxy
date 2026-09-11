// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0
use super::*;

fn result(account: u64) -> DerivedResult {
    DerivedResult {
        backend: account,
        error: ErrorClass::None,
        binding: Some(Binding {
            account,
            group: account + 100,
            operation: account + 200,
        }),
    }
}
fn success(t: &mut Tracker, next: u64, account: u64) {
    let excluded = t.excluded().to_vec();
    assert_eq!(t.begin(next, t.state.current(), &excluded), Ok(()));
    assert_eq!(
        t.attempt(next, 1, &excluded, result(account)),
        Ok(Continue::Return)
    );
    let mut after = excluded;
    after.push(account);
    assert_eq!(
        t.end(next, account, ErrorClass::None, account, &after),
        Ok(())
    );
}

#[test]
fn selection_exact_retry_and_original_finish_binding() {
    let mut t = Tracker::default();
    success(&mut t, 1, 1);
    assert_eq!(t.begin(2, 1, &[1]), Ok(()));
    let missing = DerivedResult {
        backend: 0,
        error: ErrorClass::NoBackend,
        binding: None,
    };
    assert_eq!(
        t.attempt(2, 1, &[1], missing),
        Ok(Continue::Retry),
        "SELECTOR_EXACT_RETRY"
    );
    assert_eq!(t.attempt(2, 2, &[], result(2)), Ok(Continue::Return));
    assert_eq!(t.current(), result(1).binding, "SELECTOR_NO_EARLY_COMMIT");
    assert_eq!(t.end(2, 2, ErrorClass::None, 2, &[2]), Ok(()));
    assert_eq!(
        t.finish_binding(2),
        result(2).binding.ok_or(InvalidReason::Witness),
        "SELECTOR_ORIGINAL_FINISH_BINDING"
    );
    assert_eq!(t.tail(), Ok(()));
}
#[test]
fn selection_other_error_keeps_current_and_propagates_backend() {
    let mut t = Tracker::default();
    success(&mut t, 1, 1);
    assert_eq!(t.begin(2, 1, &[1]), Ok(()));
    let ordinary = DerivedResult {
        backend: 9,
        error: ErrorClass::Other,
        binding: None,
    };
    assert_eq!(
        t.attempt(2, 1, &[1], ordinary),
        Ok(Continue::Return),
        "SELECTOR_WRAPPED_NOT_RETRIED"
    );
    assert_eq!(
        t.end(2, 9, ErrorClass::Other, 1, &[1]),
        Ok(()),
        "SELECTOR_ERROR_RETURN_AND_RETAINED_CURRENT"
    );
    assert_eq!(
        t.finish_binding(1),
        result(1).binding.ok_or(InvalidReason::Witness)
    );
}
#[test]
fn selection_second_sentinel_returns_with_cleared_history() {
    let mut t = Tracker::default();
    success(&mut t, 1, 1);
    assert_eq!(t.begin(2, 1, &[1]), Ok(()));
    let missing = DerivedResult {
        backend: 0,
        error: ErrorClass::NoBackend,
        binding: None,
    };
    assert_eq!(t.attempt(2, 1, &[1], missing), Ok(Continue::Retry));
    assert_eq!(
        t.attempt(2, 2, &[], missing),
        Ok(Continue::Return),
        "SELECTOR_SECOND_NEVER_RETRIES"
    );
    assert_eq!(t.end(2, 0, ErrorClass::NoBackend, 1, &[]), Ok(()));
    assert_eq!(
        t.finish_binding(1),
        result(1).binding.ok_or(InvalidReason::Witness)
    );
}
#[test]
fn selection_limit_accepts_equality_and_never_truncates() {
    let mut t = Tracker::default();
    for i in 1..=64 {
        success(&mut t, i, i);
    }
    let before = t.excluded().to_vec();
    assert_eq!(before.len(), MAX_EXCLUDED);
    assert_eq!(t.begin(65, 64, &before), Ok(()));
    assert_eq!(
        t.attempt(65, 1, &before, result(65)),
        Err(InvalidReason::Capacity),
        "SELECTOR_BOUND_PLUS_ONE"
    );
    assert_eq!(t.excluded(), before, "SELECTOR_CAPACITY_RETAINS_STATE");
    assert_eq!(t.current(), result(64).binding);
    assert_eq!(
        t.begin(65, 64, &before),
        Err(InvalidReason::Capacity),
        "SELECTOR_STICKY"
    );
}
#[test]
fn selection_duplicate_exclusions_are_original_history() {
    let mut t = Tracker::default();
    success(&mut t, 1, 1);
    success(&mut t, 2, 1);
    assert_eq!(t.excluded(), &[1, 1], "SELECTOR_NO_DEDUP");
}
#[test]
fn selection_late_mismatch_rolls_back_completed_state() {
    let mut t = Tracker::default();
    success(&mut t, 1, 1);
    assert_eq!(t.begin(2, 1, &[1]), Ok(()));
    assert_eq!(t.attempt(2, 1, &[1], result(2)), Ok(Continue::Return));
    assert_eq!(
        t.end(2, 2, ErrorClass::None, 2, &[1, 3]),
        Err(InvalidReason::Witness),
        "SELECTOR_LATE_WITNESS"
    );
    assert_eq!(t.excluded(), &[1], "SELECTOR_ROLLBACK_EXCLUSIONS");
    assert_eq!(t.current(), result(1).binding, "SELECTOR_ROLLBACK_CURRENT");
    assert_eq!(t.last_next, 1, "SELECTOR_ROLLBACK_ORDINAL");
}
#[test]
fn selection_missing_duplicate_foreign_and_open_tail_fail() {
    for kind in [
        "missing",
        "duplicate",
        "foreign",
        "end-before-attempt",
        "overlap",
    ] {
        let mut t = Tracker::default();
        assert_eq!(t.begin(1, 0, &[]), Ok(()));
        assert_eq!(
            t.tail(),
            Err(InvalidReason::Lifecycle),
            "SELECTOR_OPEN_TAIL"
        );
        let error = match kind {
            "missing" => t.attempt(1, 2, &[], result(1)).map(|_| ()),
            "duplicate" => {
                assert_eq!(t.attempt(1, 1, &[], result(1)), Ok(Continue::Return));
                t.attempt(1, 1, &[], result(1)).map(|_| ())
            }
            "foreign" => t.attempt(2, 1, &[], result(1)).map(|_| ()),
            "overlap" => t.begin(2, 0, &[]),
            _ => t.end(1, 1, ErrorClass::None, 1, &[1]),
        };
        assert!(error.is_err(), "SELECTOR_{kind}");
        assert!(t.excluded().is_empty());
        assert_eq!(t.current(), None);
    }
    let mut t = Tracker {
        last_next: u64::MAX,
        ..Tracker::default()
    };
    assert_eq!(
        t.begin(0, 0, &[]),
        Err(InvalidReason::Sequence),
        "SELECTOR_ORDINAL_OVERFLOW"
    );
}
#[test]
fn selection_invalid_success_and_finish_do_not_repair_state() {
    let mut t = Tracker::default();
    success(&mut t, 1, 1);
    assert_eq!(
        t.finish_binding(2),
        Err(InvalidReason::Witness),
        "SELECTOR_WRONG_FINISH"
    );
    assert_eq!(t.tail(), Err(InvalidReason::Witness));
    for binding in [
        None,
        Some(Binding {
            account: 2,
            group: 1,
            operation: 1,
        }),
        Some(Binding::default()),
    ] {
        let mut t = Tracker::default();
        assert_eq!(t.begin(1, 0, &[]), Ok(()));
        assert_eq!(
            t.attempt(
                1,
                1,
                &[],
                DerivedResult {
                    backend: 1,
                    error: ErrorClass::None,
                    binding
                }
            ),
            Err(InvalidReason::Witness),
            "SELECTOR_SUCCESS_BINDING"
        );
    }
}
