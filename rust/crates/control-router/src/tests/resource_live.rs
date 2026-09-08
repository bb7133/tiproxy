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

//! Actual factor reservations across query, source and policy changes.

use super::*;
use crate::authority::MetricInputs;

fn reserve(
    router: &Router,
    candidate: &Candidate,
    excluded: &[&str],
    stage: &str,
) -> TestResult<(crate::Session, Reservation)> {
    let session = router
        .open()
        .map_err(|err| format!("COMPOSE_{stage}_OPEN: {err:?}"))?;
    let reservation = router
        .reserve(&session, candidate, ClientInfo::default(), "", excluded)
        .map_err(|err| format!("COMPOSE_{stage}_RESERVE: {err:?}"))?;
    Ok((session, reservation))
}
fn pick(router: &Router, candidate: &Candidate, stage: &str) -> TestResult<String> {
    let session = router
        .open()
        .map_err(|err| format!("COMPOSE_{stage}_OPEN: {err:?}"))?;
    let result = router
        .reserve_with_ticket(&session, candidate, ClientInfo::default(), "", &[], 1)
        .map_err(|err| format!("COMPOSE_{stage}_RESERVE: {err:?}"))?;
    let id = result.assignment().backend_id.clone();
    assert_eq!(router.close(&session), Settlement::Applied);
    Ok(id)
}
async fn candidate(
    router: &Router,
    stage: &str,
    wanted: impl Fn(&Candidate) -> bool,
) -> TestResult<Candidate> {
    Ok(tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            if let Ok(candidate) = router.capture()
                && wanted(&candidate)
            {
                break candidate;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .map_err(|err| format!("COMPOSE_{stage}_CANDIDATE_TIMEOUT: {err}"))?)
}
fn metric(candidate: &Candidate) -> Option<&MetricSnapshot> {
    match &candidate.metrics {
        MetricInputs::Dynamic(Some(snapshot)) => Some(snapshot),
        _ => None,
    }
}
fn has_cpu(candidate: &Candidate) -> bool {
    metric(candidate).is_some_and(|snapshot| {
        snapshot
            .query_result(QueryId::Cpu)
            .is_ok_and(|query| query.is_some())
    })
}
fn go_choice<'a>(live: &'a Live, case: &str) -> TestResult<&'a str> {
    let data: serde_json::Value =
        serde_json::from_slice(&std::fs::read(std::env::var("CPROUTE_RESOURCE_OUTPUT")?)?)?;
    match data[case].as_str() {
        Some("127.0.0.1:4000") => Ok(&live.ids[0]),
        Some("127.0.0.1:4001") => Ok(&live.ids[1]),
        _ => Err(format!("actual Go choice missing: {case}").into()),
    }
}

fn patch(live: &Live, policy: &str) -> TestResult {
    live.store.apply_toml(
        format!("[balance]\npolicy=\"{policy}\"").as_bytes(),
        None,
        live.store.current().source_revision().file_revision + 1,
        Path::new("/tmp"),
    )?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires owned CP003_CONNECTION_FILE; mandatory composition evidence"]
async fn composed_real_policy_queries_reservations_and_missing_windows() -> TestResult {
    tokio::time::timeout(Duration::from_secs(45), Box::pin(observe_composed())).await??;
    println!("CP-ROUTE-COMPOSE actual Resource/Location reservations and query lifecycle passed");
    Ok(())
}

#[allow(clippy::too_many_lines)]
async fn observe_composed() -> TestResult {
    // This row changes config, routing and metric authority explicitly. Keep
    // each real health round stable while its captured candidates are reserved;
    // the initial zone still comes through the real greeting/status health path.
    let mut live = start_with_health(true, 3_600_000_000_000, "[labels]\nzone=\"z0\"").await?;
    let router = Arc::new(must(Router::new_with_factors(
        Arc::new(live.store.clone()),
        &live.topology,
        &live.running.runtime.handle().module_context(),
        "default",
        100,
        Some(live.overlay.clone()),
    )));
    let mut sessions = Vec::new();
    let ready = candidate(&router, "INITIAL", |c| {
        c.health.get(&live.ids[0]).healthy && c.health.get(&live.ids[1]).healthy
    })
    .await?;
    for index in 0..2 {
        for count in 0..12 {
            let (session, reservation) =
                reserve(&router, &ready, &[&live.ids[1 - index]], "INITIAL_LOAD")?;
            if count < 10 {
                assert_eq!(router.finish(&reservation, true), Settlement::Applied);
            }
            sessions.push(session);
        }
    }
    // Make the wrong Connection path strictly prefer A, independently of the
    // ephemeral port order or ticket. Resource must still prefer healthy B.
    let mut strict_load = Vec::new();
    for _ in 0..4 {
        let (session, pending) = reserve(&router, &ready, &[&live.ids[0]], "STRICT_LOAD")?;
        assert_eq!(pending.assignment().backend_id, live.ids[1]);
        assert_eq!(router.finish(&pending, true), Settlement::Applied);
        strict_load.push(session);
    }
    assert_eq!(
        pick(&router, &ready, "CONNECTION_STRICT")?,
        go_choice(&live, "connection_strict")?,
        "COMPOSE_CONNECTION_STRICT_LOAD"
    );
    live.store.apply_toml(
        b"[labels]\nzone=\"z0\"\n[balance]\npolicy=\"resource\"",
        None,
        3,
        Path::new("/tmp"),
    )?;
    let first = candidate(&router, "RESOURCE", |c| {
        has_cpu(c) && c.health.get(&live.ids[0]).local && !c.health.get(&live.ids[1]).local
    })
    .await?;
    assert_eq!(
        pick(&router, &first, "RESOURCE_STRICT")?,
        go_choice(&live, "resource_strict")?,
        "COMPOSE_REAL_RESOURCE_PREFERS_HEALTH"
    );
    for session in strict_load {
        assert_eq!(router.close(&session), Settlement::Applied);
    }
    assert_eq!(
        pick(&router, &first, "RESOURCE")?,
        go_choice(&live, "resource")?
    );
    assert_eq!(
        router
            .accounting(&live.ids[0])
            .map(|c| (c.active(), c.reserved())),
        Some((10, 2)),
        "COMPOSE_REAL_PENDING_COUNTS"
    );
    let first_metric = metric(&first).ok_or("metric")?;
    let lineage = first_metric.cache_lineage("default").ok_or("lineage")?;
    // Label isolation must remain a factor. Group.Route still presents both
    // healthy backends to CPU, even when only one matches the label.
    live.store.apply_toml(
        b"[balance]\nlabel-name=\"zone\"",
        None,
        live.store.current().source_revision().file_revision + 1,
        Path::new("/tmp"),
    )?;
    let label_router = must(Router::new_with_factors(
        Arc::new(live.store.clone()),
        &live.topology,
        &live.running.runtime.handle().module_context(),
        "default",
        100,
        Some(live.overlay.clone()),
    ));
    let labeled = candidate(&label_router, "LABEL", has_cpu).await?;
    assert_eq!(
        pick(&label_router, &labeled, "LABEL")?,
        go_choice(&live, "label")?,
        "COMPOSE_REAL_LABEL_ISOLATION"
    );
    live.mode.store(1, Ordering::SeqCst);
    live.store.apply_toml(
        b"[balance]\nlabel-name=\"\"",
        None,
        live.store.current().source_revision().file_revision + 1,
        Path::new("/tmp"),
    )?;
    let (_, label_scores, _) = tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            let (snapshot, time) = current(&live.feed, &live.overlay, 0).await?;
            if snapshot.query_result(QueryId::Cpu)?.is_some_and(|q| {
                q.samples_for(&live.backend.address.to_string(), "default")
                    .is_none()
            }) && let Ok(scored) =
                label_router.factor_report(&snapshot, ClientInfo::default(), "")
            {
                break Ok::<_, Box<dyn std::error::Error + Send + Sync>>((snapshot, scored, time));
            }
        }
    })
    .await??;
    assert_eq!(
        cpu(&label_scores, &live.ids[0]),
        4,
        "COMPOSE_LABEL_REMAINS_IN_FACTOR_POOL"
    );
    live.mode.store(0, Ordering::SeqCst);
    patch(&live, "location")?;
    let located = candidate(&router, "LOCATION", has_cpu).await?;
    assert_eq!(
        pick(&router, &located, "LOCATION")?,
        go_choice(&live, "location")?,
        "COMPOSE_REAL_LOCATION_PREFERS_LOCAL"
    );
    assert!(
        lineage.same_history(
            &metric(&located)
                .ok_or("metric")?
                .cache_lineage("default")
                .ok_or("lineage")?
        ),
        "COMPOSE_REAL_LOCATION_RETAINS_HISTORY"
    );
    patch(&live, "resource")?;
    let before = candidate(&router, "BEFORE_ABA", has_cpu).await?;
    assert_eq!(pick(&router, &before, "BEFORE_ABA")?, live.ids[1]);
    let mut foreign = Harness::with_health(
        "",
        "connection",
        &[
            (live.addresses[0].as_str(), &[]),
            (live.addresses[1].as_str(), &[]),
        ],
        HealthCheckConfig {
            enabled: false,
            interval_nanos: 3_600_000_000_000,
            ..HealthCheckConfig::default()
        },
        "",
    )
    .await?;
    {
        let mut records = foreign
            .fixture
            .service
            .records
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        for record in records.iter_mut().filter(|r| r.key.ends_with(b"/info")) {
            let index =
                usize::from(String::from_utf8_lossy(&record.key).contains(&live.addresses[1]));
            record.value = serde_json::to_vec(
                &serde_json::json!({"ip":"127.0.0.1","status_port":if index == 0 { live.backend.address.port() } else { live.backend_b.address.port() }}),
            )?;
        }
    }
    foreign.router = Arc::new(must(Router::new_with_factors(
        Arc::new(foreign.source.clone()),
        &foreign.topology,
        &foreign.runtime.handle().module_context(),
        "default",
        100,
        Some(live.overlay.clone()),
    )));
    let initial_foreign = candidate(&foreign.router, "FOREIGN_INITIAL", |c| {
        c.routing.backends.backends.len() == 2
            && c.routing
                .backends
                .backends
                .iter()
                .all(|b| b.backend.status_port > 0)
    })
    .await?;
    // Empty metrics must prefer A for a real reason, not the ordering of
    // ephemeral SQL ports. Foreign health-risk data would instead prefer B.
    let mut foreign_load = Vec::new();
    for _ in 0..4 {
        let (session, pending) = reserve(
            &foreign.router,
            &initial_foreign,
            &[&live.ids[0]],
            "FOREIGN_LOAD",
        )?;
        assert_eq!(pending.assignment().backend_id, live.ids[1]);
        assert_eq!(foreign.router.finish(&pending, true), Settlement::Applied);
        foreign_load.push(session);
    }
    foreign.patch("[balance]\npolicy=\"resource\"", 3);
    let mut other = candidate(&foreign.router, "FOREIGN_POLICY", |_| true).await?;
    assert!(
        matches!(other.metrics, MetricInputs::Dynamic(None)),
        "COMPOSE_FOREIGN_OVERLAY_UNAVAILABLE"
    );
    let donor = candidate(&router, "DONOR", has_cpu).await?;
    assert!(!Arc::ptr_eq(&other.routing, &donor.routing));
    // Only input data is substituted; candidate C/R/H and ledger stay genuine.
    other.metrics = donor.metrics.clone();
    assert!(metric(&other).is_some_and(MetricSnapshot::still_current));
    assert_eq!(
        pick(&foreign.router, &other, "FOREIGN")?,
        live.ids[0],
        "COMPOSE_FOREIGN_CURRENT_R_DATA_IGNORED"
    );
    for session in foreign_load {
        assert_eq!(foreign.router.close(&session), Settlement::Applied);
    }
    // Neither collector nor router is polled between these committed changes.
    // Opaque config publication must remember the discarded factor lifetime.
    live.mode.store(1, Ordering::SeqCst);
    patch(&live, "connection")?;
    patch(&live, "resource")?;
    assert!(
        !metric(&before).ok_or("before")?.still_current(),
        "COMPOSE_REAL_QUERY_ABA_REVOKED"
    );
    let (_, cold, _) = tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            let (snapshot, report, time) = report(&router, &live.feed, &live.overlay, 0).await?;
            if snapshot.query_result(QueryId::Cpu)?.is_some_and(|q| {
                q.samples_for(&live.backend.address.to_string(), "default")
                    .is_none()
            }) {
                break Ok::<_, Box<dyn std::error::Error + Send + Sync>>((snapshot, report, time));
            }
        }
    })
    .await??;
    assert_eq!(
        cpu(&cold, &live.ids[0]),
        20,
        "COMPOSE_REAL_QUERY_ABA_COLD_CPU"
    );
    let retained = candidate(&router, "RECREATED", has_cpu).await?;
    assert_eq!(
        pick(&router, &retained, "RECREATED")?,
        go_choice(&live, "recreated")?,
        "COMPOSE_REAL_RECREATED_FACTORS"
    );
    // The genuine collector is held at its HTTP boundary while R changes.
    live.prom_release.send_replace(false);
    live.etcd
        .put(
            format!("/topology/tidb/{}/info", live.addresses[1]),
            format!(
                r#"{{"ip":"127.0.0.1","status_port":{},"version":"rotated"}}"#,
                live.backend_b.address.port()
            ),
            None,
        )
        .await?;
    let changed = candidate(&router, "ROUTING_CHANGED", |c| {
        !Arc::ptr_eq(&c.routing, &retained.routing)
    })
    .await?;
    assert!(!has_cpu(&changed), "COMPOSE_REAL_R_WINDOW_HAS_NO_INPUTS");
    for _ in 0..3 {
        assert_eq!(
            pick(&router, &changed, "MISSING")?,
            go_choice(&live, "missing")?,
            "COMPOSE_REAL_R_WINDOW_RESERVES"
        );
    }
    live.prom_release.send_replace(true);
    let resumed = candidate(&router, "RESUMED", has_cpu).await?;
    assert_eq!(
        pick(&router, &resumed, "RESTORED")?,
        go_choice(&live, "restored")?,
        "COMPOSE_REAL_R_WINDOW_RECOVERS"
    );
    let (retry_session, retry) = reserve(&router, &resumed, &[&live.ids[1]], "RETRY")?;
    assert_eq!(
        retry.assignment().backend_id,
        go_choice(&live, "retry")?,
        "COMPOSE_REAL_GO_RETRY"
    );
    router.close(&retry_session);
    // Retire the producer AFTER nonempty queries have been read but BEFORE
    // the final input fence. The ledger stays locked across this barrier.
    let (observed, release) = router.observe_next_metric_use_for_test();
    let work = Arc::clone(&router);
    let frozen = resumed.clone();
    let session = must(router.open());
    let blocked = std::thread::spawn(move || {
        let selected =
            work.reserve_with_ticket(&session, &frozen, ClientInfo::default(), "", &[], 1);
        work.close(&session);
        selected
    });
    assert_eq!(
        observed.recv_timeout(Duration::from_secs(3))?,
        6,
        "COMPOSE_BARRIER_READ_NONEMPTY_INPUTS"
    );
    // The snapshot is data: retiring only its producer cannot revoke C/R/H.
    live.running.collector.abort();
    tokio::time::timeout(Duration::from_secs(3), async {
        while metric(&resumed).is_some_and(MetricSnapshot::still_current) {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    release.send(())?;
    let guarded = blocked
        .join()
        .map_err(|_| "COMPOSE_FINAL_FENCE_THREAD")?
        .map_err(|err| format!("COMPOSE_FINAL_FENCE_RESERVE: {err:?}"))?;
    assert_eq!(
        guarded.assignment().backend_id,
        live.ids[0],
        "COMPOSE_FINAL_INPUT_FENCE_RESERVES_EMPTY"
    );
    assert_eq!(
        pick(&router, &resumed, "STALE_INPUT")?,
        live.ids[0],
        "COMPOSE_REAL_STALE_INPUT_RESERVES"
    );
    patch(&live, "connection")?;
    let independent = candidate(&router, "CONNECTION", |_| true).await?;
    assert!(
        live.ids
            .contains(&pick(&router, &independent, "CONNECTION")?),
        "COMPOSE_REAL_CONNECTION_INDEPENDENT"
    );
    for session in &sessions {
        router.close(session);
    }
    live.running
        .runtime
        .begin_shutdown(ShutdownReason::Requested)?;
    live.running
        .runtime
        .advance_shutdown(LifecyclePhase::Draining)?;
    live.running
        .runtime
        .advance_shutdown(LifecyclePhase::Stopping)?;
    let _ = (&mut live.running.collector).await;
    tokio::time::timeout(Duration::from_secs(5), &mut live.running.module).await??;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires owned CP003_CONNECTION_FILE; mandatory balance evidence"]
async fn balance_real_metrics_and_missing_window() -> TestResult {
    let live = start_with_health(true, 3_600_000_000_000, "[labels]\nzone=\"z0\"").await?;
    let sim = Arc::new(
        crate::MigrationSimulation::new(
            Arc::new(live.store.clone()),
            &live.topology,
            &live.running.runtime.handle().module_context(),
            "default",
            100,
            1,
            Some(live.overlay.clone()),
        )
        .map_err(|e| format!("balance simulation: {e:?}"))?,
    );
    let c = candidate(sim.router(), "BALANCE_LOAD", |c| {
        c.health.get(&live.ids[0]).healthy && c.health.get(&live.ids[1]).healthy
    })
    .await?;
    let mut sessions = Vec::new();
    for index in 0..2 {
        for _ in 0..10 {
            let (s, r) = reserve(sim.router(), &c, &[&live.ids[1 - index]], "BALANCE_LOAD")?;
            assert_eq!(sim.router().finish(&r, true), Settlement::Applied);
            sessions.push(s);
        }
    }
    patch(&live, "resource")?;
    let resource = candidate(sim.router(), "BALANCE_RESOURCE", has_cpu).await?;
    let plan = must(sim.prepare_balance(&resource, ClientInfo::default(), ""))
        .ok_or("BALANCE_REAL_PAIR")?;
    assert_eq!(
        plan.pair().from.as_ref(),
        live.ids[0],
        "BALANCE_REAL_METRICS_SOURCE"
    );
    assert_eq!(
        plan.pair().to.as_ref(),
        live.ids[1],
        "BALANCE_REAL_METRICS_TARGET"
    );
    assert_eq!(plan.redirects().len(), 10);
    assert_eq!(
        sim.router()
            .accounting(&live.ids[0])
            .map(crate::Accounting::outgoing),
        Some(0)
    );
    assert!(must(sim.offer(&plan.redirects()[0])));
    let accepted = sim.take_redirect().ok_or("BALANCE_REAL_ACCEPT")?;
    assert_eq!(sim.finish(&accepted, false), Settlement::Applied);

    // Retire the REAL producer after its nonempty queries were read and
    // before the final metric fence. Current C/R/H survives this input loss.
    let (read, release) = sim.router().observe_next_metric_use_for_test();
    let worker = Arc::clone(&sim);
    let captured = resource.clone();
    let planning =
        std::thread::spawn(move || worker.prepare_balance(&captured, ClientInfo::default(), ""));
    assert_eq!(
        read.recv_timeout(Duration::from_secs(5))?,
        6,
        "BALANCE_REAL_READ"
    );
    live.running.collector.abort();
    tokio::time::timeout(Duration::from_secs(5), async {
        while metric(&resource).is_some_and(MetricSnapshot::still_current) {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    release.send(())?;
    let fallback = must(planning.join())
        .map_err(|e| format!("BALANCE_RETIRED: {e:?}"))?
        .ok_or("BALANCE_EMPTY_PAIR")?;
    assert_eq!(
        fallback.pair().from.as_ref(),
        live.ids[1],
        "BALANCE_EMPTY_SOURCE"
    );
    assert_eq!(
        fallback.pair().reason,
        crate::Factor::Location,
        "BALANCE_EMPTY_LOCALITY"
    );
    // C/R/H revocation remains authoritative even when metric input is empty.
    patch(&live, "connection")?;
    assert!(matches!(
        sim.prepare_balance(&resource, ClientInfo::default(), ""),
        Err(RouteError::StaleCandidate)
    ));
    assert!(matches!(
        sim.offer(&fallback.redirects()[0]),
        Err(RouteError::StaleCandidate)
    ));
    for s in sessions {
        sim.router().close(&s);
    }
    stop_balance_live(live).await?;
    println!("CP-ROUTE-BALANCE real producer preparation and fences passed");
    Ok(())
}

async fn stop_balance_live(mut live: Live) -> TestResult {
    live.running
        .runtime
        .begin_shutdown(ShutdownReason::Requested)?;
    live.running
        .runtime
        .advance_shutdown(LifecyclePhase::Draining)?;
    live.running
        .runtime
        .advance_shutdown(LifecyclePhase::Stopping)?;
    let _ = (&mut live.running.collector).await;
    tokio::time::timeout(Duration::from_secs(5), &mut live.running.module).await??;
    live.etcd
        .delete(
            "/topology/",
            Some(etcd_client::DeleteOptions::new().with_prefix()),
        )
        .await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires owned CP003_CONNECTION_FILE; mandatory worker evidence"]
async fn worker_real_metrics_retirement_at_issuance() -> TestResult {
    let live = start_with_health(true, 3_600_000_000_000, "[labels]\nzone=\"z0\"").await?;
    let sim = Arc::new(must(crate::MigrationSimulation::new(
        Arc::new(live.store.clone()),
        &live.topology,
        &live.running.runtime.handle().module_context(),
        "default",
        100,
        1,
        Some(live.overlay.clone()),
    )));
    let c = candidate(sim.router(), "WORKER_LOAD", |c| {
        c.health.get(&live.ids[0]).healthy && c.health.get(&live.ids[1]).healthy
    })
    .await?;
    for index in 0..2 {
        for _ in 0..10 {
            let (_, r) = reserve(sim.router(), &c, &[&live.ids[1 - index]], "WORKER_LOAD")?;
            assert_eq!(sim.router().finish(&r, true), Settlement::Applied);
        }
    }
    patch(&live, "resource")?;
    let resource = candidate(sim.router(), "WORKER_RESOURCE", has_cpu).await?;
    let (stop_tx, stop) = watch::channel(false);
    let now = std::time::Instant::now();
    let wall = crate::selector::now_nanos().map_err(|e| format!("clock {e:?}"))?;
    must(sim.router().refresh_failover(&resource, now));
    must(sim.round_at(&resource, true, &stop, now, now, wall));
    let Some(crate::MigrationCommand::Redirect(first)) = sim.take_command() else {
        return Err("WORKER_REAL_RESOURCE_ADMISSION".into());
    };
    assert_eq!(
        first.from().backend_id,
        live.ids[0],
        "WORKER_REAL_RESOURCE_SOURCE"
    );
    assert_eq!(
        first.to().backend_id,
        live.ids[1],
        "WORKER_REAL_RESOURCE_TARGET"
    );
    assert_eq!(sim.finish(&first, false), Settlement::Applied);
    let (read, release) = sim.router().observe_next_metric_use_for_test();
    let worker = Arc::clone(&sim);
    let captured = resource.clone();
    let later = now + Duration::from_secs(5);
    let issuing = std::thread::spawn(move || {
        worker.round_at(&captured, true, &stop, later, later, wall + 5_000_000_000)
    });
    assert_eq!(
        read.recv_timeout(Duration::from_secs(5))?,
        6,
        "WORKER_REAL_NONEMPTY_READ"
    );
    live.running.collector.abort();
    tokio::time::timeout(Duration::from_secs(5), async {
        while metric(&resource).is_some_and(MetricSnapshot::still_current) {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    release.send(())?;
    must(must(issuing.join()));
    let Some(crate::MigrationCommand::Redirect(fallback)) = sim.take_command() else {
        return Err("WORKER_REAL_FALLBACK_ADMISSION".into());
    };
    assert_eq!(
        fallback.from().backend_id,
        live.ids[1],
        "WORKER_REAL_RETIRED_SOURCE"
    );
    assert_eq!(
        fallback.to().backend_id,
        live.ids[0],
        "WORKER_REAL_RETIRED_TARGET"
    );
    patch(&live, "connection")?;
    assert!(
        matches!(
            sim.round_at(&resource, true, &stop_tx.subscribe(), later, later, wall),
            Err(RouteError::StaleCandidate)
        ),
        "WORKER_REAL_RETIRED_CONFIG"
    );
    assert!(sim.take_command().is_none());
    assert_eq!(sim.finish(&fallback, true), Settlement::Applied);
    stop_balance_live(live).await?;
    println!("CP-ROUTE-WORKER real producer issuance and retirement passed");
    Ok(())
}
