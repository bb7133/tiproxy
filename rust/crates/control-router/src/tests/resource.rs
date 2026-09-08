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

//! Enabled selection preserves C/R/H, retry and pending accounting semantics.

use super::*;

async fn composed(policy: &str) -> TestResult<Harness> {
    let mut h = Harness::with_backends(
        "",
        policy,
        &[("127.0.0.1:4000", &[]), ("127.0.0.1:4001", &[])],
    )
    .await?;
    h.router = Arc::new(must(Router::new_with_factors(
        Arc::new(h.source.clone()),
        &h.topology,
        &h.runtime.handle().module_context(),
        "default",
        100,
        None,
    )));
    Ok(h)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn composed_missing_metrics_never_block_reservation_or_retry() -> TestResult {
    for policy in ["resource", "location", "connection"] {
        let h = composed(policy).await?;
        let candidate = h.ready().await;
        assert!(matches!(
            candidate.metrics,
            crate::authority::MetricInputs::Dynamic(None)
        ));
        let mut selector = must(h.router.selector());
        let first = must(selector.next(ClientInfo::default(), ""));
        assert_eq!(
            h.router
                .accounting(&first.assignment().backend_id)
                .map(crate::Accounting::reserved),
            Some(1),
            "COMPOSE_MISSING_METRICS_RESERVES"
        );
        assert_eq!(h.router.finish(&first, false), Settlement::Applied);
        let second = must(selector.next(ClientInfo::default(), ""));
        assert_ne!(
            first.assignment().backend_id,
            second.assignment().backend_id,
            "COMPOSE_RETRY_EXCLUSION"
        );
        assert_eq!(
            h.router.finish(&first, true),
            Settlement::Ignored,
            "COMPOSE_LATE_ATTEMPT_IGNORED"
        );
        assert_eq!(h.router.finish(&second, true), Settlement::Applied);
        drop(selector);
        assert_eq!(
            h.router
                .accounting(&second.assignment().backend_id)
                .map(crate::Accounting::connection_score),
            Some(0)
        );
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn composed_reserve_validates_config_after_acquiring_ledger_lock() -> TestResult {
    let h = composed("resource").await?;
    let candidate = h.ready().await;
    let session = must(h.router.open());
    let guard = h.router.hold_lock_for_test();
    let attempted = h.router.observe_next_lock_for_test();
    let router = Arc::clone(&h.router);
    let task = std::thread::spawn(move || {
        router.reserve(&session, &candidate, ClientInfo::default(), "", &[])
    });
    attempted.recv_timeout(Duration::from_secs(3))?;
    h.patch("[balance]\npolicy=\"location\"", 3);
    drop(guard);
    assert!(
        matches!(
            task.join().map_err(|_| "reserve thread")?,
            Err(RouteError::StaleCandidate)
        ),
        "COMPOSE_LOCK_BEFORE_FINAL_VALIDATE"
    );
    assert!(
        h.router.accounting("default/127.0.0.1:4000").is_none(),
        "COMPOSE_STALE_NO_LEDGER_EFFECT"
    );
    Ok(())
}
