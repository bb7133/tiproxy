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
use crate::scheduler::{MigrationCommand, RoundClock, RouteCommandDispatcher};
use std::time::Instant;

const A: &str = "default/127.0.0.1:4000";
const B: &str = "default/127.0.0.1:4001";

fn active_on_a(router: &Router, candidate: &Candidate) -> crate::Session {
    let session = must(router.open());
    let reservation = must(router.reserve(&session, candidate, ClientInfo::default(), "", &[B]));
    assert_eq!(reservation.assignment().backend_id, A);
    assert_eq!(router.finish(&reservation, true), Settlement::Applied);
    session
}

fn counts(router: &Router, id: &str) -> (u64, u64, u64, u64) {
    let counts = router.accounting(id).unwrap_or_default();
    (
        counts.connection_score(),
        counts.active(),
        counts.incoming(),
        counts.outgoing(),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn production_dispatcher_settles_redirect_success_failure_and_expiry_once() -> TestResult {
    let harness = Harness::with_backends(
        "",
        "connection",
        &[("127.0.0.1:4000", &[]), ("127.0.0.1:4001", &[])],
    )
    .await?;
    let candidate = harness.ready().await;
    let router = Arc::clone(&harness.router);
    let dispatcher =
        RouteCommandDispatcher::with_redirect_ttl(Arc::clone(&router), Duration::from_secs(15));
    let session = active_on_a(&router, &candidate);
    let (registration, mut receiver) = must(dispatcher.register(&session, 7001, 8));

    let redirect = must(router.prepare_redirect(&session, &candidate, B));
    assert!(must(router.offer_redirect(
        &redirect,
        dispatcher.as_ref(),
        Instant::now()
    )));
    let envelope = tokio::time::timeout(Duration::from_secs(1), receiver.recv())
        .await?
        .ok_or("missing redirect")?;
    assert_eq!(envelope.public_connection_id(), 7001);
    let MigrationCommand::Redirect(token) = envelope.command().clone() else {
        return Err("expected redirect".into());
    };
    assert_eq!(envelope.finish_redirect(true), Settlement::Applied);
    assert_eq!(
        router.finish_redirect(&token, true, Instant::now()),
        Settlement::Ignored,
        "terminal token is single-use"
    );
    assert_eq!(counts(&router, A), (0, 0, 0, 0));
    assert_eq!(counts(&router, B), (1, 1, 0, 0));

    let redirect = must(router.prepare_redirect(&session, &candidate, A));
    assert!(must(router.offer_redirect(
        &redirect,
        dispatcher.as_ref(),
        Instant::now()
    )));
    let envelope = tokio::time::timeout(Duration::from_secs(1), receiver.recv())
        .await?
        .ok_or("missing failure redirect")?;
    let MigrationCommand::Redirect(token) = envelope.command().clone() else {
        return Err("expected redirect".into());
    };
    assert_eq!(envelope.finish_redirect(false), Settlement::Applied);
    assert_eq!(
        router.finish_redirect(&token, false, Instant::now()),
        Settlement::Ignored
    );
    let cooling = must(router.prepare_redirect(&session, &candidate, A));
    assert!(matches!(
        router.offer_redirect(&cooling, dispatcher.as_ref(), Instant::now()),
        Err(RouteError::CoolingDown)
    ));

    let expiring_session = active_on_a(&router, &candidate);
    let expiring = RouteCommandDispatcher::with_redirect_ttl(Arc::clone(&router), Duration::ZERO);
    let (expiring_registration, mut expiring_receiver) =
        must(expiring.register(&expiring_session, 7002, 1));
    let prepared = must(router.prepare_redirect(&expiring_session, &candidate, B));
    assert!(must(router.offer_redirect(
        &prepared,
        expiring.as_ref(),
        Instant::now()
    )));
    let expired = tokio::time::timeout(Duration::from_secs(1), expiring_receiver.recv())
        .await?
        .ok_or("missing expired redirect")?;
    assert_eq!(expired.redirect_budget(), Some(Duration::ZERO));
    assert_eq!(expired.finish_redirect(false), Settlement::Applied);

    drop(expiring_registration);
    drop(registration);
    assert_eq!(router.close(&expiring_session), Settlement::Applied);
    assert_eq!(router.close(&session), Settlement::Applied);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dispatcher_full_closed_and_duplicate_registration_preserve_cooldown_and_owner()
-> TestResult {
    let harness = Harness::with_backends(
        "",
        "connection",
        &[("127.0.0.1:4000", &[]), ("127.0.0.1:4001", &[])],
    )
    .await?;
    let candidate = harness.ready().await;
    let router = Arc::clone(&harness.router);
    let dispatcher = RouteCommandDispatcher::new(Arc::clone(&router));

    let full_session = active_on_a(&router, &candidate);
    let (full_registration, mut full_receiver) = must(dispatcher.register(&full_session, 8001, 0));
    assert!(matches!(
        dispatcher.register(&full_session, 9999, 8),
        Err(RouteError::AlreadyActive)
    ));
    let prepared = must(router.prepare_redirect(&full_session, &candidate, B));
    let now = Instant::now();
    assert!(!must(router.offer_redirect(
        &prepared,
        dispatcher.as_ref(),
        now
    )));
    let cooling = must(router.prepare_redirect(&full_session, &candidate, B));
    assert!(matches!(
        router.offer_redirect(&cooling, dispatcher.as_ref(), Instant::now()),
        Err(RouteError::CoolingDown)
    ));
    assert!(
        tokio::time::timeout(Duration::from_millis(20), full_receiver.recv())
            .await
            .is_err(),
        "duplicate registration did not replace the original zero-capacity FIFO"
    );
    drop(full_registration);

    let closed_session = active_on_a(&router, &candidate);
    let (closed_registration, closed_receiver) =
        must(dispatcher.register(&closed_session, 8002, 1));
    drop(closed_receiver);
    let prepared = must(router.prepare_redirect(&closed_session, &candidate, B));
    assert!(!must(router.offer_redirect(
        &prepared,
        dispatcher.as_ref(),
        Instant::now()
    )));
    let cooling = must(router.prepare_redirect(&closed_session, &candidate, B));
    assert!(matches!(
        router.offer_redirect(&cooling, dispatcher.as_ref(), Instant::now()),
        Err(RouteError::CoolingDown)
    ));

    drop(closed_registration);
    assert_eq!(router.close(&full_session), Settlement::Applied);
    assert_eq!(router.close(&closed_session), Settlement::Applied);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn force_close_rejection_records_cooldown_before_later_acceptance() -> TestResult {
    let harness = Harness::with_backends(
        "",
        "connection",
        &[("127.0.0.1:4000", &[]), ("127.0.0.1:4001", &[])],
    )
    .await?;
    let router = Arc::clone(&harness.router);
    let candidate = harness.ready().await;
    let session = active_on_a(&router, &candidate);

    harness.patch(
        "[proxy]\nfail-backend-list=[\"127.0.0.1:4000\"]\nfailover-timeout=0",
        3,
    );
    let candidate = harness.ready().await;
    let start = Instant::now();
    must(router.refresh_failover(&candidate, start));
    let dispatcher = RouteCommandDispatcher::new(Arc::clone(&router));
    let (full_registration, full_receiver) = must(dispatcher.register(&session, 9001, 0));
    let (_stop_tx, stop) = watch::channel(false);
    must(router.migration_round(
        &candidate,
        dispatcher.as_ref(),
        false,
        &stop,
        &RoundClock {
            fixed: Some((start, start, 1)),
        },
    ));
    assert_eq!(
        router
            .migration_progress()
            .values()
            .map(|progress| progress.closes)
            .sum::<u64>(),
        0,
        "full FIFO admits no close"
    );
    drop(full_receiver);
    drop(full_registration);

    let (registration, mut receiver) = must(dispatcher.register(&session, 9001, 1));
    must(router.migration_round(
        &candidate,
        dispatcher.as_ref(),
        false,
        &stop,
        &RoundClock {
            fixed: Some((start, start + Duration::from_secs(2), 2)),
        },
    ));
    assert!(
        tokio::time::timeout(Duration::from_millis(20), receiver.recv())
            .await
            .is_err(),
        "rejected close observes the three-second cooldown"
    );
    must(router.migration_round(
        &candidate,
        dispatcher.as_ref(),
        false,
        &stop,
        &RoundClock {
            fixed: Some((start, start + Duration::from_secs(4), 3)),
        },
    ));
    assert_eq!(
        router
            .migration_progress()
            .values()
            .map(|progress| progress.closes)
            .sum::<u64>(),
        1,
        "close is admitted after cooldown"
    );
    let envelope = tokio::time::timeout(Duration::from_secs(1), receiver.recv())
        .await?
        .ok_or("missing force close")?;
    assert!(matches!(
        envelope.command(),
        MigrationCommand::ForceClose(_)
    ));
    assert_eq!(envelope.observe_close(), Settlement::Applied);
    drop(registration);
    assert_eq!(router.close(&session), Settlement::Ignored);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn offer_unregister_barrier_drops_guards_outside_every_lock() -> TestResult {
    let harness = Harness::with_backends(
        "",
        "connection",
        &[("127.0.0.1:4000", &[]), ("127.0.0.1:4001", &[])],
    )
    .await?;
    let candidate = harness.ready().await;
    let router = Arc::clone(&harness.router);
    let session = active_on_a(&router, &candidate);
    let dispatcher = RouteCommandDispatcher::new(Arc::clone(&router));
    let (registration, mut receiver) = must(dispatcher.register(&session, 10001, 1));
    let prepared = must(router.prepare_redirect(&session, &candidate, B));
    let (offered, release) = router.hold_next_redirect_offer_for_test();
    let offer_router = Arc::clone(&router);
    let offer_dispatcher = Arc::clone(&dispatcher);
    let offer = std::thread::spawn(move || {
        offer_router.offer_redirect(&prepared, offer_dispatcher.as_ref(), Instant::now())
    });
    offered.recv_timeout(Duration::from_secs(5))?;

    let (dropped, dropped_rx) = std::sync::mpsc::channel();
    let unregister = std::thread::spawn(move || {
        drop(registration);
        let _ = dropped.send(());
    });
    assert_eq!(
        dropped_rx.recv_timeout(Duration::from_millis(50)),
        Err(std::sync::mpsc::RecvTimeoutError::Timeout),
        "guard waits for the router commit, without holding registry/FIFO locks"
    );
    let (replacement, replacement_receiver) = must(dispatcher.register(&session, 10002, 1));
    drop(replacement_receiver);
    drop(replacement);
    release.send(())?;
    assert!(must(must(offer.join())));
    unregister
        .join()
        .unwrap_or_else(|_| unreachable!("unregister thread"));
    dropped_rx.recv_timeout(Duration::from_secs(1))?;
    assert!(
        tokio::time::timeout(Duration::from_secs(1), receiver.recv())
            .await?
            .is_none(),
        "unregister closes the old receiver"
    );
    assert_eq!(counts(&router, A), (1, 1, 0, 0));
    assert_eq!(counts(&router, B), (0, 0, 0, 0));
    assert_eq!(router.close(&session), Settlement::Applied);
    Ok(())
}
