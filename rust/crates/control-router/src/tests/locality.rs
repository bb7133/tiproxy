// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Assignment locality is copied from real health rounds, independently of C.

use super::{Candidate, Harness, HealthCheckConfig, TestResult, must};
use crate::{RouteError, Settlement};
use control_routing::group::ClientInfo;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::sync::{Semaphore, watch};
use tokio::task::JoinHandle;

/// Each permit releases one real SQL greeting. The accepted count proves the
/// health round has already captured its zone before the test changes config.
struct HeldGreeter {
    address: String,
    permits: Arc<Semaphore>,
    accepted: watch::Receiver<u64>,
    task: JoinHandle<()>,
}

impl Drop for HeldGreeter {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl HeldGreeter {
    async fn new() -> TestResult<Self> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?.to_string();
        let permits = Arc::new(Semaphore::new(1));
        let release = Arc::clone(&permits);
        let (accepted, observed) = watch::channel(0);
        let task = tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                accepted.send_modify(|count| *count += 1);
                let Ok(permit) = release.acquire().await else {
                    return;
                };
                permit.forget();
                let _ = stream.write_all(&[3, 0, 0, 0, 0x0a, b'8', 0]).await;
            }
        });
        Ok(Self {
            address,
            permits,
            accepted: observed,
            task,
        })
    }

    async fn held(&mut self, round: u64) -> TestResult {
        tokio::time::timeout(
            Duration::from_secs(5),
            self.accepted.wait_for(|count| *count >= round),
        )
        .await??;
        assert_eq!(*self.accepted.borrow(), round, "one held probe per round");
        Ok(())
    }

    fn release(&self) {
        self.permits.add_permits(1);
    }
}

async fn observed(
    harness: &Harness,
    backend_id: &str,
    local: bool,
    previous: Option<&Candidate>,
) -> TestResult<Candidate> {
    Ok(tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Ok(candidate) = harness.router.capture() {
                let health = candidate.health.get(backend_id);
                if health.healthy
                    && health.local == local
                    && previous.is_none_or(|old| !Arc::ptr_eq(&old.health, &candidate.health))
                {
                    break candidate;
                }
            }
            tokio::task::yield_now().await;
        }
    })
    .await?)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn disabled_health_assignments_remain_not_local_under_every_proxy_zone() -> TestResult {
    let harness =
        Harness::with_backends("", "connection", &[("127.0.0.1:4000", &[("zone", "az-a")])])
            .await?;
    for (revision, zone) in [(3, ""), (4, "az-a"), (5, "az-b")] {
        harness.patch(&format!("[labels]\nzone = \"{zone}\""), revision);
        let candidate = harness.ready().await;
        let (session, reservation) = harness.reserve(&candidate);
        assert!(
            !candidate
                .health
                .get(&reservation.assignment().backend_id)
                .local
        );
        assert!(
            !reservation.assignment().local,
            "disabled health leaves Local=false"
        );
        assert_eq!(
            harness.router.finish(&reservation, false),
            Settlement::Applied
        );
        harness.router.close(&session);
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn assignment_locality_uses_the_exact_health_round_not_current_config() -> TestResult {
    let mut greeter = HeldGreeter::new().await?;
    let backend_id = format!("default/{}", greeter.address);
    let harness = Harness::with_health(
        "",
        "connection",
        &[(&greeter.address, &[("zone", "az-a")])],
        HealthCheckConfig {
            enabled: true,
            interval_nanos: 50_000_000,
            max_retries: 0,
            dial_timeout_nanos: 5_000_000_000,
            ..HealthCheckConfig::default()
        },
        "az-a",
    )
    .await?;
    let first = observed(&harness, &backend_id, true, None).await?;
    greeter.held(2).await?;

    // Current C advances while H and the held round still describe az-a.
    harness.patch("[labels]\nzone = \"az-b\"", 3);
    let pending_config = must(harness.router.capture());
    assert!(!Arc::ptr_eq(&first.config, &pending_config.config));
    assert!(Arc::ptr_eq(&first.routing, &pending_config.routing));
    assert!(Arc::ptr_eq(&first.health, &pending_config.health));
    let (old_session, old_reservation) = harness.reserve(&pending_config);
    assert!(
        old_reservation.assignment().local,
        "new C does not recompute old H"
    );

    greeter.release();
    let old_zone_round = observed(&harness, &backend_id, true, Some(&first)).await?;
    greeter.held(3).await?;
    greeter.release();
    let remote = observed(&harness, &backend_id, false, Some(&old_zone_round)).await?;
    greeter.held(4).await?;
    assert!(Arc::ptr_eq(&first.routing, &remote.routing));
    assert!(Arc::ptr_eq(&pending_config.config, &remote.config));
    let fresh_session = must(harness.router.open());
    assert!(matches!(
        harness.router.reserve(
            &fresh_session,
            &pending_config,
            ClientInfo::default(),
            "",
            &[]
        ),
        Err(RouteError::StaleCandidate)
    ));
    let remote_reservation =
        must(
            harness
                .router
                .reserve(&fresh_session, &remote, ClientInfo::default(), "", &[]),
        );
    assert!(!remote_reservation.assignment().local);
    assert!(
        old_reservation.assignment().local,
        "reserved metadata stays captured"
    );
    assert_eq!(
        harness.router.finish(&old_reservation, true),
        Settlement::Applied
    );
    assert_eq!(
        harness.router.finish(&old_reservation, false),
        Settlement::Ignored
    );

    // Empty current zone also must not turn an existing not-local H into local.
    harness.patch("[labels]\nzone = \"\"", 4);
    let empty_config = must(harness.router.capture());
    assert!(Arc::ptr_eq(&remote.health, &empty_config.health));
    let (empty_session, empty_reservation) = harness.reserve(&empty_config);
    assert!(!empty_reservation.assignment().local);
    greeter.release();
    let last_remote = observed(&harness, &backend_id, false, Some(&remote)).await?;
    greeter.held(5).await?;
    greeter.release();
    let everywhere = observed(&harness, &backend_id, true, Some(&last_remote)).await?;
    assert!(Arc::ptr_eq(&first.routing, &everywhere.routing));
    let (last_session, last_reservation) = harness.reserve(&everywhere);
    assert!(last_reservation.assignment().local);
    assert!(!remote_reservation.assignment().local);
    for session in [&old_session, &fresh_session, &empty_session, &last_session] {
        assert_eq!(harness.router.close(session), Settlement::Applied);
    }
    assert_eq!(
        harness
            .router
            .accounting(&backend_id)
            .map(crate::Accounting::connection_score),
        Some(0)
    );
    Ok(())
}
