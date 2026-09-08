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
use crate::{MigrationSimulation, Session};
use std::time::Instant;

const A: &str = "default/127.0.0.1:4000";
const B: &str = "default/127.0.0.1:4001";
fn simulation(h: &Harness, capacity: usize) -> MigrationSimulation {
    must(MigrationSimulation::new(
        Arc::new(h.source.clone()),
        &h.topology,
        &h.runtime.handle().module_context(),
        "default",
        16,
        capacity,
        None,
    ))
}
async fn ready(sim: &MigrationSimulation) -> Candidate {
    must(
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Ok(candidate) = sim.router().capture() {
                    break candidate;
                }
                tokio::task::yield_now().await;
            }
        })
        .await,
    )
}
fn active(sim: &MigrationSimulation, candidate: &Candidate) -> Session {
    let s = must(sim.router().open());
    let r = must(
        sim.router()
            .reserve(&s, candidate, ClientInfo::default(), "", &[B]),
    );
    assert_eq!(r.assignment().backend_id, A);
    assert_eq!(sim.router().finish(&r, true), Settlement::Applied);
    s
}
fn counts(sim: &MigrationSimulation, id: &str) -> (u64, u64, u64, u64) {
    let c = sim.router().accounting(id).unwrap_or_default();
    (c.connection_score(), c.active(), c.incoming(), c.outgoing())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn migration_bounded_offer_and_retired_source_settlement() -> TestResult {
    let h = Harness::with_backends(
        "",
        "connection",
        &[("127.0.0.1:4000", &[]), ("127.0.0.1:4001", &[])],
    )
    .await?;
    let sim = simulation(&h, 1);
    let c = ready(&sim).await;
    let a = active(&sim, &c);
    let other = active(&sim, &c);
    let now = Instant::now();
    let p = must(sim.prepare(&a, &c, B));
    assert!(must(sim.offer_at(&p, now)));
    assert_eq!(counts(&sim, A), (1, 2, 0, 1));
    assert_eq!(counts(&sim, B), (1, 0, 1, 0));
    let refused = must(sim.prepare(&other, &c, B));
    assert!(!must(sim.offer_at(&refused, now)));
    assert_eq!(counts(&sim, A), (1, 2, 0, 1));
    assert_eq!(counts(&sim, B), (1, 0, 1, 0));
    let op = sim
        .take_redirect()
        .unwrap_or_else(|| unreachable!("accepted local token"));
    assert!(sim.take_redirect().is_none());
    assert!(matches!(
        sim.offer_at(&refused, now),
        Err(RouteError::CoolingDown)
    ));
    assert!(matches!(
        sim.offer_at(&p, now),
        Err(RouteError::RedirectPending)
    ));
    // Retire the source completely; exact accepted tokens still own settlement.
    h.runtime.begin_shutdown(ShutdownReason::Requested)?;
    assert!(matches!(
        sim.offer_at(&refused, now + Duration::from_secs(3)),
        Err(RouteError::ControlUnavailable)
    ));
    assert_eq!(sim.finish_at(&op, true, now), Settlement::Applied);
    assert_eq!(counts(&sim, A), (1, 1, 0, 0));
    assert_eq!(counts(&sim, B), (1, 1, 0, 0));
    assert_eq!(sim.router().close(&a), Settlement::Applied);
    assert_eq!(sim.finish_at(&op, false, now), Settlement::Ignored);
    assert_eq!(sim.router().close(&other), Settlement::Applied);
    assert_eq!(counts(&sim, A), (0, 0, 0, 0));
    assert_eq!(counts(&sim, B), (0, 0, 0, 0));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn migration_final_lock_rechecks_config_routing_and_health() -> TestResult {
    for change in ["config", "routing", "health"] {
        let h = Harness::with_backends(
            "",
            "connection",
            &[("127.0.0.1:4000", &[]), ("127.0.0.1:4001", &[])],
        )
        .await?;
        let sim = Arc::new(simulation(&h, 1));
        let c = ready(&sim).await;
        let s = active(&sim, &c);
        let p = must(sim.prepare(&s, &c, B));
        let lock = sim.router().hold_lock_for_test();
        let attempted = sim.router().observe_next_lock_for_test();
        let worker_sim = Arc::clone(&sim);
        let worker = std::thread::spawn(move || worker_sim.offer(&p));
        attempted.recv_timeout(Duration::from_secs(3))?;
        match change {
            "config" => h.patch("[balance]\npolicy=\"location\"", 3),
            "routing" => {
                h.fixture.backends(&[("127.0.0.1:4000", &[])]);
                let _ = h.changed_r(&c).await;
            }
            "health" => {
                tokio::time::timeout(Duration::from_secs(5), async {
                    loop {
                        if let Ok(next) = sim.router().capture()
                            && !Arc::ptr_eq(&next.health, &c.health)
                        {
                            break;
                        }
                        tokio::task::yield_now().await;
                    }
                })
                .await?;
            }
            _ => unreachable!(),
        }
        drop(lock);
        assert!(
            matches!(must(worker.join()), Err(RouteError::StaleCandidate)),
            "{change}"
        );
        assert!(sim.take_redirect().is_none());
        assert_eq!(counts(&sim, A), (1, 1, 0, 0));
        assert_eq!(counts(&sim, B), (0, 0, 0, 0));
        sim.router().close(&s);
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn migration_simulations_never_share_ownership_and_close_wins_terminal_races() -> TestResult {
    let h = Harness::with_backends(
        "",
        "connection",
        &[("127.0.0.1:4000", &[]), ("127.0.0.1:4001", &[])],
    )
    .await?;
    let sim = Arc::new(simulation(&h, 1));
    let foreign = simulation(&h, 1);
    for _ in 0..16 {
        let c = ready(&sim).await;
        let s = active(&sim, &c);
        let p = must(sim.prepare(&s, &c, B));
        assert!(matches!(foreign.offer(&p), Err(RouteError::StaleCandidate)));
        assert!(must(sim.offer(&p)));
        let op = sim.take_redirect().unwrap_or_else(|| unreachable!());
        assert_eq!(foreign.finish(&op, true), Settlement::Ignored);
        let other = Arc::clone(&sim);
        let terminal = op.clone();
        let worker = std::thread::spawn(move || other.finish(&terminal, true));
        assert_eq!(sim.router().close(&s), Settlement::Applied);
        let _ = must(worker.join());
        assert_eq!(sim.finish(&op, true), Settlement::Ignored);
        assert_eq!(counts(&sim, A), (0, 0, 0, 0));
        assert_eq!(counts(&sim, B), (0, 0, 0, 0));
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn migration_immediate_terminal_waits_for_accepted_ledger_commit() -> TestResult {
    let h = Harness::with_backends(
        "",
        "connection",
        &[("127.0.0.1:4000", &[]), ("127.0.0.1:4001", &[])],
    )
    .await?;
    let sim = Arc::new(simulation(&h, 1));
    for success in [true, false] {
        let c = ready(&sim).await;
        let s = active(&sim, &c);
        let p = must(sim.prepare(&s, &c, B));
        let (offered, release) = sim.router().hold_next_redirect_offer_for_test();
        let issuer = Arc::clone(&sim);
        let offer = std::thread::spawn(move || issuer.offer(&p));
        offered.recv_timeout(Duration::from_secs(3))?;
        let op = sim
            .take_redirect()
            .unwrap_or_else(|| unreachable!("offered token"));
        let attempted = sim.router().observe_next_lock_for_test();
        let consumer = Arc::clone(&sim);
        let (done, result) = std::sync::mpsc::channel();
        let terminal = std::thread::spawn(move || {
            let _ = done.send(consumer.finish(&op, success));
        });
        attempted.recv_timeout(Duration::from_secs(3))?;
        let early = result.recv_timeout(Duration::from_millis(100));
        release.send(())?;
        assert!(must(must(offer.join())));
        must(terminal.join());
        assert_eq!(
            early,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout),
            "MIGRATION_TERMINAL_BEFORE_COMMIT"
        );
        assert_eq!(
            result.recv_timeout(Duration::from_secs(3))?,
            Settlement::Applied
        );
        assert_eq!(
            counts(&sim, A),
            if success { (0, 0, 0, 0) } else { (1, 1, 0, 0) }
        );
        assert_eq!(
            counts(&sim, B),
            if success { (1, 1, 0, 0) } else { (0, 0, 0, 0) }
        );
        sim.router().close(&s);
    }
    Ok(())
}
