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

#[test]
fn review_close_settles_accepted_migration_once() {
    let mut ledger = Ledger::new(8);
    let a = must(ledger.add_account());
    let b = must(ledger.add_account());
    let session = active(&mut ledger, &a);
    let now = Instant::now();
    let op = must(redirect(&ledger, &session, &b, assignment("b"), now));
    ledger.admit_redirect(op.clone(), true, now);
    assert_eq!(ledger.drain_migrations().len(), 1);
    assert_eq!(ledger.close(&session, Instant::now()), Settlement::Applied);
    assert_eq!(
        ledger.finish_redirect(&op, true, Instant::now()),
        Settlement::Ignored
    );
    let events = ledger.drain_migrations();
    assert_eq!(
        events.len(),
        1,
        "accepted migration closed early must emit a terminal"
    );
    assert!(matches!(
        events[0].outcome,
        MigrationOutcome::Settled { success: false, .. }
    ));
    // Not only the notification: the authoritative state must show the
    // migration finished and counted exactly once.
    assert_eq!(ledger.pending_migrations().values().sum::<u64>(), 0);
    assert_eq!(
        ledger.history().snapshot().terminals.values().sum::<u64>(),
        1
    );
}

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

/// The ledger's own tests are about accounting, not attribution, so they all
/// issue with one representative factor reason.
fn redirect(
    ledger: &Ledger,
    session: &Session,
    target: &Arc<AccountIdentity>,
    assignment: RouteAssignment,
    now: Instant,
) -> Result<Redirect, LedgerError> {
    ledger.prepare_redirect(
        session,
        target,
        assignment,
        now,
        RedirectReason::Balance(Factor::Connection),
    )
}

fn addressed(id: &str, addr: &str) -> RouteAssignment {
    RouteAssignment {
        backend_id: id.into(),
        backend_address: addr.into(),
        keyspace: "tenant".into(),
        ..RouteAssignment::default()
    }
}

#[test]
fn a_settled_migration_reports_the_reason_frozen_at_issue_and_its_elapsed_time() {
    let mut ledger = Ledger::new(8);
    let a = must(ledger.add_account());
    let b = must(ledger.add_account());
    let session = must(ledger.open());
    let reservation = must(ledger.reserve(&session, &a, addressed("a", "10.0.0.1:4000")));
    assert_eq!(ledger.finish(&reservation, true), Settlement::Applied);
    let issued = Instant::now();

    // The reason is chosen by the factor walk at issue time...
    let op = must(ledger.prepare_redirect(
        &session,
        &b,
        addressed("b", "10.0.0.2:4000"),
        issued,
        RedirectReason::Balance(Factor::Memory),
    ));
    ledger.admit_redirect(op.clone(), true, issued);
    // Go increments the pending gauge at acceptance, so the issue is its own
    // observation rather than something reconstructed at settlement.
    assert_eq!(
        ledger.drain_migrations(),
        vec![MigrationObservation {
            from: "10.0.0.1:4000".to_owned(),
            to: "10.0.0.2:4000".to_owned(),
            reason: RedirectReason::Balance(Factor::Memory),
            outcome: MigrationOutcome::Issued,
        }]
    );

    // ...and is read back at settlement, not recomputed from current scores.
    let settled = issued + Duration::from_millis(250);
    assert_eq!(
        ledger.finish_redirect(&op, true, settled),
        Settlement::Applied
    );
    let observed = ledger.drain_migrations();
    assert_eq!(
        observed,
        vec![MigrationObservation {
            // Go labels with `backend.addr`, never the opaque routing id.
            from: "10.0.0.1:4000".to_owned(),
            to: "10.0.0.2:4000".to_owned(),
            reason: RedirectReason::Balance(Factor::Memory),
            outcome: MigrationOutcome::Settled {
                success: true,
                elapsed: Duration::from_millis(250),
            },
        }]
    );
    assert_eq!(observed[0].reason.metric_name(), "memory");
    // Draining is destructive: a second publication cycle sees nothing.
    assert!(ledger.drain_migrations().is_empty());
}

#[test]
fn a_failed_migration_is_still_observed_and_a_self_redirect_reports_test() {
    let mut ledger = Ledger::new(8);
    let a = must(ledger.add_account());
    let b = must(ledger.add_account());
    let session = must(ledger.open());
    let reservation = must(ledger.reserve(&session, &a, addressed("a", "10.0.0.1:4000")));
    assert_eq!(ledger.finish(&reservation, true), Settlement::Applied);
    let issued = Instant::now();

    let op = must(ledger.prepare_redirect(
        &session,
        &b,
        addressed("b", "10.0.0.2:4000"),
        issued,
        RedirectReason::Balance(Factor::Status),
    ));
    ledger.admit_redirect(op.clone(), true, issued);
    assert_eq!(
        ledger.finish_redirect(&op, false, issued + Duration::from_millis(10)),
        Settlement::Applied
    );
    let observed = ledger.drain_migrations();
    assert_eq!(observed.len(), 2, "one issue and one settlement");
    assert_eq!(observed[0].outcome, MigrationOutcome::Issued);
    assert_eq!(
        observed[1].outcome,
        MigrationOutcome::Settled {
            success: false,
            elapsed: Duration::from_millis(10),
        },
        "a failure is observed with its elapsed time, not dropped"
    );
    assert_eq!(observed[1].reason.metric_name(), "status");

    // Go's RedirectConnections labels every migration `test`, whatever the score.
    let back = must(ledger.prepare_self_redirect(&session, issued));
    assert_eq!(back.reason(), RedirectReason::Test);
    assert_eq!(back.reason().metric_name(), "test");
}

#[test]
fn redirect_transfers_score_then_physical_and_failure_returns_only_score() {
    let mut ledger = Ledger::new(8);
    let a = must(ledger.add_account());
    let b = must(ledger.add_account());
    let s = active(&mut ledger, &a);
    let now = Instant::now();
    let op = must(redirect(&ledger, &s, &b, assignment("b"), now));
    assert_eq!(counts(&ledger, &a), (1, 1, 0, 0, 0));
    ledger.admit_redirect(op.clone(), true, now);
    assert_eq!(counts(&ledger, &a), (0, 1, 0, 0, 1));
    assert_eq!(counts(&ledger, &b), (1, 0, 0, 1, 0));
    assert!(!ledger.prune(&a));
    assert!(!ledger.prune(&b));
    assert!(matches!(
        redirect(&ledger, &s, &b, assignment("b"), now),
        Err(LedgerError::RedirectPending)
    ));
    assert_eq!(ledger.finish_redirect(&op, true, now), Settlement::Applied);
    assert_eq!(counts(&ledger, &a), (0, 0, 0, 0, 0));
    assert_eq!(counts(&ledger, &b), (1, 1, 0, 0, 0));
    assert_eq!(ledger.finish_redirect(&op, false, now), Settlement::Ignored);
    // Success has no extra three-second cooldown.
    let back = must(redirect(&ledger, &s, &a, assignment("a"), now));
    ledger.admit_redirect(back.clone(), true, now);
    assert_eq!(ledger.finish_redirect(&op, true, now), Settlement::Ignored);
    assert_eq!(
        ledger.finish_redirect(&back, false, now),
        Settlement::Applied
    );
    assert_eq!(counts(&ledger, &a), (0, 0, 0, 0, 0));
    assert_eq!(counts(&ledger, &b), (1, 1, 0, 0, 0));
    assert!(matches!(
        redirect(
            &ledger,
            &s,
            &a,
            assignment("a"),
            now + Duration::from_nanos(2_999_999_999)
        ),
        Err(LedgerError::CoolingDown)
    ));
    assert!(
        ledger
            .prepare_redirect(
                &s,
                &a,
                assignment("a"),
                now + Duration::from_secs(3),
                RedirectReason::Balance(Factor::Connection)
            )
            .is_ok()
    );
    assert_eq!(ledger.close(&s, Instant::now()), Settlement::Applied);
    assert_eq!(counts(&ledger, &b), (0, 0, 0, 0, 0));
}

#[test]
fn redirect_rejected_offer_records_cooldown_without_consuming_watermark_or_capacity() {
    let mut ledger = Ledger::new(4);
    let a = must(ledger.add_account());
    let b = must(ledger.add_account());
    let s = active(&mut ledger, &a);
    let now = Instant::now();
    let rejected = must(redirect(&ledger, &s, &b, assignment("b"), now));
    ledger.admit_redirect(rejected.clone(), false, now);
    assert_eq!(ledger.next_redirect, rejected.sequence);
    assert_eq!(counts(&ledger, &a), (1, 1, 0, 0, 0));
    assert_eq!(counts(&ledger, &b), (0, 0, 0, 0, 0));
    assert_eq!(
        ledger.finish_redirect(&rejected, true, now),
        Settlement::Ignored
    );
    assert!(matches!(
        redirect(&ledger, &s, &b, assignment("b"), now),
        Err(LedgerError::CoolingDown)
    ));
    let next = must(redirect(
        &ledger,
        &s,
        &b,
        assignment("b"),
        now + Duration::from_secs(3),
    ));
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
    let op = must(redirect(&ledger, &s, &b, assignment("same-name"), now));
    ledger.admit_redirect(op.clone(), true, now);
    assert_eq!(ledger.close(&s, Instant::now()), Settlement::Applied);
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
    assert_eq!(ledger.close(&s, Instant::now()), Settlement::Ignored);
    assert_eq!(counts(&ledger, &replacement), (1, 1, 0, 0, 0));
    let mut foreign = Ledger::new(4);
    let fa = must(foreign.add_account());
    let fb = must(foreign.add_account());
    let fs = active(&mut foreign, &fa);
    let fop = must(foreign.prepare_redirect(
        &fs,
        &fb,
        assignment("same-name"),
        now,
        RedirectReason::Balance(Factor::Connection),
    ));
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
        redirect(&ledger, &idle, &b, assignment("b"), now),
        Err(LedgerError::NotActive)
    ));
    let pending = must(ledger.reserve(&idle, &a, assignment("a")));
    assert!(matches!(
        redirect(&ledger, &idle, &b, assignment("b"), now),
        Err(LedgerError::NotActive)
    ));
    ledger.finish(&pending, true);
    assert!(matches!(
        redirect(&ledger, &idle, &a, assignment("a"), now),
        Err(LedgerError::SameAccount)
    ));
    let mut other = assignment("b");
    other.keyspace.clear();
    assert!(matches!(
        redirect(&ledger, &idle, &b, other, now),
        Err(LedgerError::CrossKeyspace)
    ));
    ledger.next_redirect = u64::MAX;
    assert!(matches!(
        redirect(&ledger, &idle, &b, assignment("b"), now),
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
        redirect(&ledger, &idle, &b, assignment("b"), now),
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
        redirect(&ledger, &idle, &b, assignment("b"), now),
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
    let op = must(redirect(&ledger, &s, &b, assignment("b"), now));
    ledger.admit_redirect(op.clone(), true, now);
    let late = now + Duration::from_secs(10);
    assert_eq!(
        ledger.finish_redirect(&op, false, late),
        Settlement::Applied
    );
    assert!(
        ledger
            .prepare_redirect(
                &s,
                &b,
                assignment("b"),
                late,
                RedirectReason::Balance(Factor::Connection)
            )
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
    let op = must(redirect(&ledger, &s, &b, assignment("b"), now));
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
        assert!(row.parts.contains(&(Factor::Connection, expected)));
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
                match redirect(&ledger, &session, target, assignment(id), now) {
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
                ledger.close(&session, Instant::now());
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
    let old = must(redirect(&ledger, &s, &b, assignment("b"), now));
    ledger.admit_redirect(old.clone(), true, now);
    assert_eq!(ledger.finish_redirect(&old, true, now), Settlement::Applied);
    let back = must(redirect(&ledger, &s, &a, assignment("a"), now));
    ledger.admit_redirect(back.clone(), true, now);
    assert_eq!(
        ledger.finish_redirect(&back, true, now),
        Settlement::Applied
    );
    let current = must(redirect(&ledger, &s, &b, assignment("b"), now));
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
    assert_eq!(ledger.close(&s, Instant::now()), Settlement::Applied);
    assert_eq!(counts(&ledger, &a), (0, 0, 0, 0, 0));
    assert_eq!(counts(&ledger, &b), (0, 0, 0, 0, 0));
}

#[test]
fn worker_close_tokens_reject_foreign_sequence_and_exhaustion() {
    let mut ledger = Ledger::new(8);
    let now = Instant::now();
    let owner = must(ledger.add_account());
    let session = active(&mut ledger, &owner);
    let mut foreign = Ledger::new(8);
    let other_owner = must(foreign.add_account());
    let other_session = active(&mut foreign, &other_owner);
    let own = must(ledger.prepare_close(&session, now));
    let other = must(foreign.prepare_close(&other_session, now));
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
        ledger.prepare_close(&session, now),
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
        matches!(
            ledger.prepare_close(&next, now),
            Err(LedgerError::Exhausted)
        ),
        "WORKER_CLOSE_EXHAUSTED"
    );
    assert_eq!(counts(&ledger, &owner), (1, 1, 0, 0, 0));
}

/// The authoritative state must not depend on anyone consuming the
/// notifications. Every observation is drained and thrown away here, exactly
/// as a full queue would drop it, and the state still describes reality.
#[test]
fn migration_state_survives_every_notification_being_dropped() {
    let mut ledger = Ledger::new(8);
    let history = Arc::clone(ledger.history());
    let a = must(ledger.add_account());
    let b = must(ledger.add_account());
    let session = must(ledger.open());
    let reservation = must(ledger.reserve(&session, &a, addressed("a", "10.0.0.1:4000")));
    assert_eq!(ledger.finish(&reservation, true), Settlement::Applied);
    let issued = Instant::now();

    let op = must(ledger.prepare_redirect(
        &session,
        &b,
        addressed("b", "10.0.0.2:4000"),
        issued,
        RedirectReason::Balance(Factor::Cpu),
    ));
    ledger.admit_redirect(op.clone(), true, issued);
    drop(ledger.drain_migrations()); // the issue notification is lost

    let labels = MigrationLabels {
        from: "10.0.0.1:4000".to_owned(),
        to: "10.0.0.2:4000".to_owned(),
        reason: RedirectReason::Balance(Factor::Cpu),
    };
    assert_eq!(
        ledger.pending_migrations().get(&labels).copied(),
        Some(1),
        "state is authoritative even though nothing consumed the event"
    );

    assert_eq!(
        ledger.finish_redirect(&op, true, issued + Duration::from_millis(80)),
        Settlement::Applied
    );
    drop(ledger.drain_migrations()); // the settlement notification is lost too

    // This is the case that permanently corrupted the delta-based gauge: the
    // terminal is gone and no future event will arrive, yet a reader still
    // sees a finished migration.
    assert_eq!(ledger.pending_migrations().get(&labels).copied(), Some(0));
    let snapshot = history.snapshot();
    assert_eq!(
        snapshot
            .terminals
            .get(&TerminalKey {
                from: "10.0.0.1:4000".to_owned(),
                to: "10.0.0.2:4000".to_owned(),
                reason: RedirectReason::Balance(Factor::Cpu),
                succeeded: true,
            })
            .copied(),
        Some(1)
    );
    let duration = snapshot
        .durations
        .get(&DurationKey {
            from: "10.0.0.1:4000".to_owned(),
            to: "10.0.0.2:4000".to_owned(),
            succeeded: true,
        })
        .unwrap_or_else(|| unreachable!("duration series recorded"));
    assert_eq!(duration.count, 1);
    assert_eq!(duration.sum_nanos, Duration::from_millis(80).as_nanos());
    // 80ms falls in every bucket at or above 0.1024s and none below it.
    let above: usize = duration.buckets.iter().filter(|count| **count == 1).count();
    assert!(above > 0 && above < duration.buckets.len());
}

/// Cumulative history must outlive the router that produced it: a counter
/// that falls back to zero when an incarnation is destroyed is a false reset.
#[test]
fn cumulative_history_outlives_the_ledger_that_recorded_it() {
    let history = Arc::new(MigrationHistory::default());
    {
        let mut ledger = Ledger::with_history(8, Arc::clone(&history));
        let a = must(ledger.add_account());
        let b = must(ledger.add_account());
        let session = must(ledger.open());
        let reservation = must(ledger.reserve(&session, &a, addressed("a", "10.0.0.1:4000")));
        assert_eq!(ledger.finish(&reservation, true), Settlement::Applied);
        let now = Instant::now();
        let op = must(ledger.prepare_redirect(
            &session,
            &b,
            addressed("b", "10.0.0.2:4000"),
            now,
            RedirectReason::Test,
        ));
        ledger.admit_redirect(op.clone(), true, now);
        assert_eq!(ledger.finish_redirect(&op, true, now), Settlement::Applied);
        assert_eq!(history.snapshot().terminals.values().sum::<u64>(), 1);
    }
    // The ledger is gone, as it would be when a router incarnation is dropped.
    assert_eq!(
        history.snapshot().terminals.values().sum::<u64>(),
        1,
        "destroying the router must not roll the cumulative series backwards"
    );
    assert_eq!(
        history.snapshot().known_pending.len(),
        1,
        "nor lose the label set, which would make the series disappear"
    );
}

/// The retained history is bounded against itself, and a full map must never
/// refuse the migration itself -- only its retention.
#[test]
fn retained_history_is_bounded_without_refusing_migrations() {
    let history = MigrationHistory::default();
    for index in 0..(MAX_RETAINED_LABEL_SETS + 16) {
        history.remember(
            &format!("10.0.0.1:{index}"),
            "10.0.0.2:4000",
            RedirectReason::Test,
        );
    }
    let snapshot = history.snapshot();
    assert_eq!(snapshot.known_pending.len(), MAX_RETAINED_LABEL_SETS);
    assert_eq!(snapshot.labels_dropped, 16);
}

#[test]
fn review_retained_label_remains_counted_after_unretained_churn() {
    fn issue(ledger: &mut Ledger, index: usize, settled: bool) -> MigrationLabels {
        let a = must(ledger.add_account());
        let b = must(ledger.add_account());
        let session = must(ledger.open());
        let from = format!("10.0.0.1:{index}");
        let reservation = must(ledger.reserve(&session, &a, addressed("a", &from)));
        assert_eq!(ledger.finish(&reservation, true), Settlement::Applied);
        let now = Instant::now();
        let op = must(ledger.prepare_redirect(
            &session,
            &b,
            addressed("b", "10.0.0.2:4000"),
            now,
            RedirectReason::Test,
        ));
        ledger.admit_redirect(op.clone(), true, now);
        if settled {
            assert_eq!(ledger.finish_redirect(&op, true, now), Settlement::Applied);
            assert_eq!(ledger.close(&session, now), Settlement::Applied);
        }
        drop(ledger.drain_migrations());
        MigrationLabels {
            from,
            to: "10.0.0.2:4000".to_owned(),
            reason: RedirectReason::Test,
        }
    }
    let history = Arc::new(MigrationHistory::default());
    let mut old = Ledger::with_history(8, Arc::clone(&history));
    for index in 0..MAX_RETAINED_LABEL_SETS {
        issue(&mut old, index, true);
    }
    let mut new = Ledger::with_history(8, Arc::clone(&history));
    for index in MAX_RETAINED_LABEL_SETS..MAX_RETAINED_LABEL_SETS * 2 {
        issue(&mut new, index, true);
    }
    let retained = issue(&mut new, 0, false);
    assert!(history.snapshot().known_pending.contains(&(
        retained.from.clone(),
        retained.to.clone(),
        retained.reason,
    )));
    assert_eq!(
        new.pending_migrations().get(&retained).copied(),
        Some(1),
        "unretained churn must not suppress a real pending migration for a globally retained label"
    );
}

/// Go counts a backend's `connList`, and that list only moves when a
/// migration succeeds. Each clause here is a way the count could drift from
/// Go if the wrong state were read.
#[test]
fn physical_connections_follow_gos_conn_list_exactly() {
    let mut ledger = Ledger::new(8);
    let a = must(ledger.add_account());
    let b = must(ledger.add_account());

    // A reservation is not yet a connection.
    let session = must(ledger.open());
    let reservation = must(ledger.reserve(&session, &a, addressed("a", "10.0.0.1:4000")));
    assert!(
        ledger.physical_connections().is_empty(),
        "an incomplete reservation is not a physical connection"
    );
    assert_eq!(ledger.finish(&reservation, true), Settlement::Applied);
    assert_eq!(
        ledger.physical_connections().get("10.0.0.1:4000").copied(),
        Some(1)
    );

    // An accepted migration keeps counting against its source: Go moves the
    // connection between lists only once it has actually landed.
    let now = Instant::now();
    let op = must(ledger.prepare_redirect(
        &session,
        &b,
        addressed("b", "10.0.0.2:4000"),
        now,
        RedirectReason::Test,
    ));
    ledger.admit_redirect(op.clone(), true, now);
    let counts = ledger.physical_connections();
    assert_eq!(counts.get("10.0.0.1:4000").copied(), Some(1));
    assert_eq!(
        counts.get("10.0.0.2:4000"),
        None,
        "an incoming redirect is not a connection until it settles"
    );

    // A failed migration leaves it on the source.
    assert_eq!(ledger.finish_redirect(&op, false, now), Settlement::Applied);
    assert_eq!(
        ledger.physical_connections().get("10.0.0.1:4000").copied(),
        Some(1)
    );

    // A successful one moves it, and never counts it twice.
    let op = must(ledger.prepare_redirect(
        &session,
        &b,
        addressed("b", "10.0.0.2:4000"),
        now + Duration::from_secs(4),
        RedirectReason::Test,
    ));
    ledger.admit_redirect(op.clone(), true, now + Duration::from_secs(4));
    assert_eq!(
        ledger.finish_redirect(&op, true, now + Duration::from_secs(4)),
        Settlement::Applied
    );
    let counts = ledger.physical_connections();
    assert_eq!(counts.get("10.0.0.1:4000"), None);
    assert_eq!(counts.get("10.0.0.2:4000").copied(), Some(1));
    assert_eq!(counts.values().sum::<u64>(), 1, "counted once, not twice");

    // Closing decrements exactly once.
    assert_eq!(
        ledger.close(&session, now + Duration::from_secs(5)),
        Settlement::Applied
    );
    assert!(ledger.physical_connections().is_empty());
}

/// Go creates the gauge child on the first `Set` and it stays. An address
/// whose last connection closes must therefore keep reporting zero rather
/// than disappearing from the exposition, which is what happens if the count
/// is derived only from currently active sessions.
#[test]
fn a_backend_address_keeps_reporting_after_its_last_connection_closes() {
    let history = Arc::new(MigrationHistory::default());
    let mut ledger = Ledger::with_history(8, Arc::clone(&history));
    let a = must(ledger.add_account());
    let session = must(ledger.open());
    let reservation = must(ledger.reserve(&session, &a, addressed("a", "10.0.0.1:4000")));
    assert_eq!(ledger.finish(&reservation, true), Settlement::Applied);
    assert_eq!(
        ledger.physical_connections().get("10.0.0.1:4000").copied(),
        Some(1)
    );

    assert_eq!(ledger.close(&session, Instant::now()), Settlement::Applied);
    assert!(
        ledger.physical_connections().is_empty(),
        "the ledger reports live counts only"
    );
    assert!(
        history.snapshot().known_backends.contains("10.0.0.1:4000"),
        "but the address is retained, so the exposition can still report it as zero"
    );
}

/// Registration happens when the connection lands, not when the exposition
/// reads. A connection that opens and closes entirely between two scrapes is
/// never seen by a read, so a read-time registration would lose its address
/// and the series would never report the zero.
#[test]
fn an_address_connected_and_closed_between_scrapes_still_reports() {
    let history = Arc::new(MigrationHistory::default());
    let mut ledger = Ledger::with_history(8, Arc::clone(&history));
    let a = must(ledger.add_account());

    // No scrape happens anywhere in this sequence.
    let session = must(ledger.open());
    let reservation = must(ledger.reserve(&session, &a, addressed("a", "10.0.0.9:4000")));
    assert_eq!(ledger.finish(&reservation, true), Settlement::Applied);
    assert_eq!(ledger.close(&session, Instant::now()), Settlement::Applied);

    assert!(
        history.snapshot().known_backends.contains("10.0.0.9:4000"),
        "the address must be known even though no read ever observed it live"
    );
}

/// A migration that lands registers the target address at the moment it
/// lands, for the same reason.
#[test]
fn a_migration_target_is_registered_when_it_lands() {
    let history = Arc::new(MigrationHistory::default());
    let mut ledger = Ledger::with_history(8, Arc::clone(&history));
    let a = must(ledger.add_account());
    let b = must(ledger.add_account());
    let session = must(ledger.open());
    let reservation = must(ledger.reserve(&session, &a, addressed("a", "10.0.0.1:4000")));
    assert_eq!(ledger.finish(&reservation, true), Settlement::Applied);
    let now = Instant::now();
    let op = must(ledger.prepare_redirect(
        &session,
        &b,
        addressed("b", "10.0.0.2:4000"),
        now,
        RedirectReason::Test,
    ));
    ledger.admit_redirect(op.clone(), true, now);
    assert!(
        !history.snapshot().known_backends.contains("10.0.0.2:4000"),
        "an accepted migration has not landed yet"
    );
    assert_eq!(ledger.finish_redirect(&op, true, now), Settlement::Applied);
    assert!(
        history.snapshot().known_backends.contains("10.0.0.2:4000"),
        "a successful settlement registers the target"
    );
}
