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

use super::*;

fn must<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
    result.unwrap_or_else(|error| unreachable!("fixture: {error:?}"))
}
fn assignment(id: &str) -> RouteAssignment {
    RouteAssignment {
        backend_id: id.into(),
        keyspace: "tenant".into(),
        ..RouteAssignment::default()
    }
}
fn active(ledger: &mut Ledger, owner: &Arc<AccountIdentity>) -> Session {
    let session = must(ledger.open());
    let reservation = must(ledger.reserve(&session, owner, assignment("a")));
    assert_eq!(ledger.finish(&reservation, true), Settlement::Applied);
    session
}
fn counts(ledger: &Ledger, owner: &Arc<AccountIdentity>) -> (u64, u64, u64, u64, u64) {
    let c = ledger
        .counts(owner)
        .unwrap_or_else(|| unreachable!("owner"));
    (
        c.connection_score(),
        c.active(),
        c.reserved(),
        c.incoming(),
        c.outgoing(),
    )
}

#[test]
fn redirect_transfers_score_then_physical_and_failure_returns_only_score() {
    let mut ledger = Ledger::new(8);
    let a = must(ledger.add_account());
    let b = must(ledger.add_account());
    let s = active(&mut ledger, &a);
    let now = Instant::now();
    let op = must(ledger.prepare_redirect(&s, &b, assignment("b"), now));
    assert_eq!(counts(&ledger, &a), (1, 1, 0, 0, 0));
    ledger.admit_redirect(op.clone(), true, now);
    assert_eq!(counts(&ledger, &a), (0, 1, 0, 0, 1));
    assert_eq!(counts(&ledger, &b), (1, 0, 0, 1, 0));
    assert!(!ledger.prune(&a));
    assert!(!ledger.prune(&b));
    assert!(matches!(
        ledger.prepare_redirect(&s, &b, assignment("b"), now),
        Err(LedgerError::RedirectPending)
    ));
    assert_eq!(ledger.finish_redirect(&op, true, now), Settlement::Applied);
    assert_eq!(counts(&ledger, &a), (0, 0, 0, 0, 0));
    assert_eq!(counts(&ledger, &b), (1, 1, 0, 0, 0));
    assert_eq!(ledger.finish_redirect(&op, false, now), Settlement::Ignored);
    // Success has no extra three-second cooldown.
    let back = must(ledger.prepare_redirect(&s, &a, assignment("a"), now));
    ledger.admit_redirect(back.clone(), true, now);
    assert_eq!(ledger.finish_redirect(&op, true, now), Settlement::Ignored);
    assert_eq!(
        ledger.finish_redirect(&back, false, now),
        Settlement::Applied
    );
    assert_eq!(counts(&ledger, &a), (0, 0, 0, 0, 0));
    assert_eq!(counts(&ledger, &b), (1, 1, 0, 0, 0));
    assert!(matches!(
        ledger.prepare_redirect(
            &s,
            &a,
            assignment("a"),
            now + Duration::from_nanos(2_999_999_999)
        ),
        Err(LedgerError::CoolingDown)
    ));
    assert!(
        ledger
            .prepare_redirect(&s, &a, assignment("a"), now + Duration::from_secs(3))
            .is_ok()
    );
    assert_eq!(ledger.close(&s), Settlement::Applied);
    assert_eq!(counts(&ledger, &b), (0, 0, 0, 0, 0));
}

#[test]
fn redirect_rejected_offer_records_cooldown_without_consuming_watermark_or_capacity() {
    let mut ledger = Ledger::new(4);
    let a = must(ledger.add_account());
    let b = must(ledger.add_account());
    let s = active(&mut ledger, &a);
    let now = Instant::now();
    let rejected = must(ledger.prepare_redirect(&s, &b, assignment("b"), now));
    ledger.admit_redirect(rejected.clone(), false, now);
    assert_eq!(ledger.next_redirect, rejected.sequence);
    assert_eq!(counts(&ledger, &a), (1, 1, 0, 0, 0));
    assert_eq!(counts(&ledger, &b), (0, 0, 0, 0, 0));
    assert_eq!(
        ledger.finish_redirect(&rejected, true, now),
        Settlement::Ignored
    );
    assert!(matches!(
        ledger.prepare_redirect(&s, &b, assignment("b"), now),
        Err(LedgerError::CoolingDown)
    ));
    let next = must(ledger.prepare_redirect(&s, &b, assignment("b"), now + Duration::from_secs(3)));
    assert_eq!(next.sequence, rejected.sequence);
    ledger.admit_redirect(next.clone(), true, now + Duration::from_secs(3));
    assert_eq!(ledger.next_redirect, next.sequence + 1);
}

#[test]
fn redirect_close_and_retired_equal_name_owners_ignore_all_late_and_foreign_results() {
    let mut ledger = Ledger::new(4);
    let a = must(ledger.add_account());
    let b = must(ledger.add_account());
    let s = active(&mut ledger, &a);
    let now = Instant::now();
    let op = must(ledger.prepare_redirect(&s, &b, assignment("same-name"), now));
    ledger.admit_redirect(op.clone(), true, now);
    assert_eq!(ledger.close(&s), Settlement::Applied);
    assert!(ledger.prune(&a));
    assert!(ledger.prune(&b));
    let replacement = must(ledger.add_account());
    let _ = active(&mut ledger, &replacement);
    for success in [true, false] {
        assert_eq!(
            ledger.finish_redirect(&op, success, now),
            Settlement::Ignored
        );
    }
    assert_eq!(ledger.close(&s), Settlement::Ignored);
    assert_eq!(counts(&ledger, &replacement), (1, 1, 0, 0, 0));
    let mut foreign = Ledger::new(4);
    let fa = must(foreign.add_account());
    let fb = must(foreign.add_account());
    let fs = active(&mut foreign, &fa);
    let fop = must(foreign.prepare_redirect(&fs, &fb, assignment("same-name"), now));
    foreign.admit_redirect(fop, true, now);
    assert_eq!(foreign.finish_redirect(&op, true, now), Settlement::Ignored);
    assert_eq!(counts(&foreign, &fa), (0, 1, 0, 0, 1));
    assert_eq!(counts(&foreign, &fb), (1, 0, 0, 1, 0));
}

#[test]
fn redirect_requires_active_owner_scope_and_capacity_for_every_possible_terminal() {
    let mut ledger = Ledger::new(4);
    let a = must(ledger.add_account());
    let b = must(ledger.add_account());
    let idle = must(ledger.open());
    let now = Instant::now();
    assert!(matches!(
        ledger.prepare_redirect(&idle, &b, assignment("b"), now),
        Err(LedgerError::NotActive)
    ));
    let pending = must(ledger.reserve(&idle, &a, assignment("a")));
    assert!(matches!(
        ledger.prepare_redirect(&idle, &b, assignment("b"), now),
        Err(LedgerError::NotActive)
    ));
    ledger.finish(&pending, true);
    assert!(matches!(
        ledger.prepare_redirect(&idle, &a, assignment("a"), now),
        Err(LedgerError::SameAccount)
    ));
    let mut other = assignment("b");
    other.keyspace.clear();
    assert!(matches!(
        ledger.prepare_redirect(&idle, &b, other, now),
        Err(LedgerError::CrossKeyspace)
    ));
    ledger.next_redirect = u64::MAX;
    assert!(matches!(
        ledger.prepare_redirect(&idle, &b, assignment("b"), now),
        Err(LedgerError::Exhausted)
    ));
    ledger.next_redirect = 1;
    ledger
        .accounts
        .get_mut(&b.sequence)
        .unwrap_or_else(|| unreachable!())
        .counts
        .active = u64::MAX;
    assert!(matches!(
        ledger.prepare_redirect(&idle, &b, assignment("b"), now),
        Err(LedgerError::Exhausted)
    ));
    assert_eq!(counts(&ledger, &a), (1, 1, 0, 0, 0));
    assert_eq!(ledger.next_redirect, 1);
    ledger
        .accounts
        .get_mut(&b.sequence)
        .unwrap_or_else(|| unreachable!())
        .counts = Accounting {
        active: u64::MAX,
        outgoing: 1,
        ..Accounting::default()
    };
    // A low score is insufficient: an outgoing failure must still fit.
    assert!(matches!(
        ledger.prepare_redirect(&idle, &b, assignment("b"), now),
        Err(LedgerError::Exhausted)
    ));
    let fresh = must(ledger.open());
    assert!(matches!(
        ledger.reserve(&fresh, &b, assignment("b")),
        Err(LedgerError::Exhausted)
    ));
}

#[test]
fn redirect_delayed_failure_does_not_restart_issuance_cooldown() {
    let mut ledger = Ledger::new(4);
    let a = must(ledger.add_account());
    let b = must(ledger.add_account());
    let s = active(&mut ledger, &a);
    let now = Instant::now();
    let op = must(ledger.prepare_redirect(&s, &b, assignment("b"), now));
    ledger.admit_redirect(op.clone(), true, now);
    let late = now + Duration::from_secs(10);
    assert_eq!(
        ledger.finish_redirect(&op, false, late),
        Settlement::Applied
    );
    assert!(
        ledger
            .prepare_redirect(&s, &b, assignment("b"), late)
            .is_ok()
    );
}

#[test]
fn redirect_connection_factor_reads_transferred_score_not_physical_count() {
    let mut ledger = Ledger::new(4);
    let a = must(ledger.add_account());
    let b = must(ledger.add_account());
    let s = active(&mut ledger, &a);
    let now = Instant::now();
    let op = must(ledger.prepare_redirect(&s, &b, assignment("b"), now));
    ledger.admit_redirect(op, true, now);
    let inputs: Vec<_> = [("a", a), ("b", b)]
        .into_iter()
        .map(|(id, owner)| crate::factors::Input {
            id: id.into(),
            counts: ledger.counts(&owner).unwrap_or_default(),
            owner,
            instance: id.into(),
            cluster: "default".into(),
            healthy: true,
            local: false,
            label_matches: true,
        })
        .collect();
    let mut policy = must(control_config::EffectiveConfig::default().routing());
    policy.balance_policy = control_config::RoutingBalancePolicy::Connection;
    let report = crate::factors::State::default().evaluate(
        &inputs,
        &policy,
        &crate::factors::Queries::new(),
        0,
    );
    for row in report.rows {
        let expected = u64::from(row.backend_id.as_ref() == "b");
        assert!(row.parts.contains(&(crate::Factor::Connection, expected)));
    }
}

#[test]
fn shared_go_redirect_observation() {
    use std::fmt::Write;
    let Ok(input) = std::env::var("CPROUTE_MIGRATION_FIXTURE") else {
        return;
    };
    let input = must(std::fs::read_to_string(input));
    let mut output = String::new();
    let mut ledger = Ledger::new(4);
    let mut a = must(ledger.add_account());
    let mut b = must(ledger.add_account());
    let mut session = must(ledger.open());
    let mut op: Option<Redirect> = None;
    let start = Instant::now();
    let mut offered = 0_u64;
    let mut watermark = -1_i64;
    for line in input
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
    {
        let row: Vec<_> = line.split('\t').collect();
        assert_eq!(row.len(), 4);
        let millis: u64 = must(row[2].parse());
        let now = start + Duration::from_millis(millis);
        match row[1] {
            "reset" => {
                ledger = Ledger::new(4);
                a = must(ledger.add_account());
                b = must(ledger.add_account());
                session = active(&mut ledger, &a);
                offered = 0;
                watermark = -1;
                op = None;
            }
            "balance" => {
                let (target, id) = if Arc::ptr_eq(must(ledger.active_owner(&session)), &a) {
                    (&b, "b")
                } else {
                    (&a, "a")
                };
                match ledger.prepare_redirect(&session, target, assignment(id), now) {
                    Ok(next) => {
                        offered += 1;
                        let accepted = row[3] == "1";
                        ledger.admit_redirect(next.clone(), accepted, now);
                        if accepted {
                            watermark = must(millis.try_into());
                            op = Some(next);
                        }
                    }
                    Err(LedgerError::CoolingDown | LedgerError::RedirectPending) => (),
                    Err(error) => unreachable!("unexpected {error:?}"),
                }
            }
            "success" | "failure" | "late_success" | "late_failure" => {
                ledger.finish_redirect(
                    op.as_ref().unwrap_or_else(|| unreachable!()),
                    row[1].ends_with("success"),
                    now,
                );
            }
            "close" => {
                ledger.close(&session);
            }
            "remove_source" => {
                assert!(!ledger.prune(&op.as_ref().unwrap_or_else(|| unreachable!()).source));
            }
            _ => unreachable!("fixture action"),
        }
        let ca = counts(&ledger, &a);
        let cb = counts(&ledger, &b);
        must(writeln!(
            output,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            row[0],
            ca.0,
            ca.1,
            cb.0,
            cb.1,
            offered,
            ledger.next_redirect - 1,
            watermark
        ));
    }
    must(std::fs::write(
        must(std::env::var("CPROUTE_MIGRATION_OUTPUT")),
        output,
    ));
}

#[test]
fn redirect_old_same_pair_terminal_cannot_settle_new_operation() {
    let mut ledger = Ledger::new(4);
    let a = must(ledger.add_account());
    let b = must(ledger.add_account());
    let s = active(&mut ledger, &a);
    let now = Instant::now();
    let old = must(ledger.prepare_redirect(&s, &b, assignment("b"), now));
    ledger.admit_redirect(old.clone(), true, now);
    assert_eq!(ledger.finish_redirect(&old, true, now), Settlement::Applied);
    let back = must(ledger.prepare_redirect(&s, &a, assignment("a"), now));
    ledger.admit_redirect(back.clone(), true, now);
    assert_eq!(
        ledger.finish_redirect(&back, true, now),
        Settlement::Applied
    );
    let current = must(ledger.prepare_redirect(&s, &b, assignment("b"), now));
    ledger.admit_redirect(current.clone(), true, now);
    assert!(Arc::ptr_eq(&old.source, &current.source));
    assert!(Arc::ptr_eq(&old.target, &current.target));
    assert_ne!(old.sequence, current.sequence);
    for success in [true, false] {
        assert_eq!(
            ledger.finish_redirect(&old, success, now),
            Settlement::Ignored
        );
        assert_eq!(counts(&ledger, &a), (0, 1, 0, 0, 1));
        assert_eq!(counts(&ledger, &b), (1, 0, 0, 1, 0));
    }
    assert_eq!(
        ledger.finish_redirect(&current, true, now),
        Settlement::Applied
    );
    assert_eq!(ledger.close(&s), Settlement::Applied);
    assert_eq!(counts(&ledger, &a), (0, 0, 0, 0, 0));
    assert_eq!(counts(&ledger, &b), (0, 0, 0, 0, 0));
}

#[test]
fn worker_close_tokens_reject_foreign_sequence_and_exhaustion() {
    let mut ledger = Ledger::new(8);
    let owner = must(ledger.add_account());
    let session = active(&mut ledger, &owner);
    let mut foreign = Ledger::new(8);
    let other_owner = must(foreign.add_account());
    let other_session = active(&mut foreign, &other_owner);
    let own = must(ledger.prepare_close(&session));
    let other = must(foreign.prepare_close(&other_session));
    ledger.admit_close(own.clone());
    foreign.admit_close(other.clone());
    assert_eq!(
        ledger.observe_close(&other),
        Settlement::Ignored,
        "WORKER_FOREIGN_CLOSE"
    );
    let mut wrong = own.clone();
    wrong.sequence += 1;
    assert_eq!(
        ledger.observe_close(&wrong),
        Settlement::Ignored,
        "WORKER_CLOSE_SEQUENCE"
    );
    assert_eq!(
        counts(&ledger, &owner),
        (1, 1, 0, 0, 0),
        "WORKER_CLOSE_ADMISSION_COUNTS"
    );
    assert!(matches!(
        ledger.prepare_close(&session),
        Err(LedgerError::ForceClosing)
    ));
    assert_eq!(ledger.observe_close(&own), Settlement::Applied);
    assert_eq!(ledger.observe_close(&own), Settlement::Ignored);
    let next = active(&mut ledger, &owner);
    assert_eq!(
        ledger.observe_close(&own),
        Settlement::Ignored,
        "WORKER_LATE_CLOSE"
    );
    ledger.next_close = u64::MAX;
    assert!(
        matches!(ledger.prepare_close(&next), Err(LedgerError::Exhausted)),
        "WORKER_CLOSE_EXHAUSTED"
    );
    assert_eq!(counts(&ledger, &owner), (1, 1, 0, 0, 0));
}
