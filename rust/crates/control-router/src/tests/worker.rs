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
use crate::{MigrationCommand, MigrationSimulation};
use std::time::Instant;
const A: &str = "default/127.0.0.1:4000";
const B: &str = "default/127.0.0.1:4001";

fn number(value: &serde_json::Value, key: &str) -> u64 {
    value[key].as_u64().unwrap_or(0)
}
fn text<'a>(value: &'a serde_json::Value, key: &str) -> &'a str {
    value[key].as_str().unwrap_or("")
}
async fn candidate(sim: &MigrationSimulation) -> Candidate {
    must(
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if let Ok(c) = sim.router().capture() {
                    break c;
                }
                tokio::task::yield_now().await;
            }
        })
        .await,
    )
}
fn policy(h: &Harness, rate: f64, timeout: u64, fail: &[&str], revision: u64) {
    let fail: Vec<_> = fail
        .iter()
        .map(|id| {
            if *id == "a" {
                "127.0.0.1:4000"
            } else {
                "127.0.0.1:4001"
            }
        })
        .collect();
    h.patch(&format!("[proxy]\nfail-backend-list={fail:?}\nfailover-timeout={timeout}\n[balance.status]\nmigrations-per-second={rate}"), revision);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shared_go_worker_clock_events() -> TestResult {
    let Ok(path) = std::env::var("CPROUTE_WORKER_FIXTURE") else {
        return Ok(());
    };
    let cases: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(path)?)?;
    let expected: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(
        std::env::var("CPROUTE_WORKER_EXPECTED")?,
    )?)?;
    let expected = expected.as_array().ok_or("expected rows")?;
    let mut rows = Vec::new();
    for case in cases.as_array().ok_or("cases")? {
        rows.extend(observe_case(case, &expected[rows.len()..]).await?);
    }
    assert_eq!(rows.len(), expected.len());
    if let Ok(output) = std::env::var("CPROUTE_WORKER_OUTPUT") {
        std::fs::write(output, serde_json::to_string_pretty(&rows)? + "\n")?;
    }
    println!("CP-ROUTE worker actual Go events matched: {}", rows.len());
    Ok(())
}

async fn simple_worker_harness() -> TestResult<Harness> {
    Harness::with_health(
        "",
        "connection",
        &[("127.0.0.1:4000", &[]), ("127.0.0.1:4001", &[])],
        HealthCheckConfig {
            enabled: false,
            interval_nanos: 3_600_000_000_000,
            ..HealthCheckConfig::default()
        },
        "",
    )
    .await
}
fn new_sim(h: &Harness, capacity: usize) -> MigrationSimulation {
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
fn connect_a(sim: &MigrationSimulation, c: &Candidate) -> crate::Session {
    let s = must(sim.router().open());
    let r = must(sim.router().reserve(&s, c, ClientInfo::default(), "", &[B]));
    assert_eq!(sim.router().finish(&r, true), Settlement::Applied);
    s
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn worker_source_notifications_close_without_redirect_and_join() -> TestResult {
    let h = simple_worker_harness().await?;
    let sim = Arc::new(new_sim(&h, 1));
    let c = candidate(&sim).await;
    let session = connect_a(&sim, &c);
    let (stop_tx, stop) = watch::channel(false);
    let child = Arc::clone(&sim);
    let worker = tokio::spawn(async move { child.run_worker(false, stop).await });
    tokio::time::timeout(Duration::from_secs(5), async {
        while !sim.worker_initialized() {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    policy(&h, 100.0, 0, &["a"], 3);
    let close = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if sim.progress().values().any(|p| p.closes > 0) {
                assert!(
                    sim.take_redirect().is_none(),
                    "WORKER_CLOSE_QUEUE_PRESERVED"
                );
                break sim
                    .take_command()
                    .unwrap_or_else(|| unreachable!("WORKER_CLOSE_QUEUE_PRESERVED"));
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .map_err(|e| format!("WORKER_SOURCE_NOTIFY: {e}"))?;
    let MigrationCommand::ForceClose(close) = close else {
        return Err("WORKER_DISABLED_REDIRECT".into());
    };
    assert_eq!(
        sim.router().accounting(A).map(crate::Accounting::active),
        Some(1),
        "WORKER_CLOSE_ADMISSION_ONLY"
    );
    assert!(
        matches!(
            sim.run_worker(false, stop_tx.subscribe()).await,
            Err(RouteError::WorkerRunning)
        ),
        "WORKER_SINGLE_OWNER"
    );
    stop_tx.send(true)?;
    must(tokio::time::timeout(Duration::from_secs(3), worker).await??);
    assert!(
        sim.take_command().is_none(),
        "WORKER_JOINED_NO_LATE_COMMAND"
    );
    h.runtime.begin_shutdown(ShutdownReason::Requested)?;
    assert_eq!(
        sim.observe_close(&close),
        Settlement::Applied,
        "WORKER_RETIRED_CLOSE"
    );
    assert_eq!(sim.observe_close(&close), Settlement::Ignored);
    assert_eq!(sim.router().close(&session), Settlement::Ignored);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn worker_cancellation_stops_the_physical_scan_after_first_offer() -> TestResult {
    let h = simple_worker_harness().await?;
    let sim = Arc::new(new_sim(&h, 8));
    let c = candidate(&sim).await;
    for _ in 0..6 {
        connect_a(&sim, &c);
    }
    policy(&h, 300.0, 60, &["a"], 3);
    let c = candidate(&sim).await;
    let now = Instant::now();
    must(sim.router().refresh_failover(&c, now));
    let (offered, release) = sim.router().hold_next_redirect_offer_for_test();
    let (stop_tx, stop) = watch::channel(false);
    let child = Arc::clone(&sim);
    let task =
        std::thread::spawn(move || child.round_at(&c, true, &stop, now, now, 100_000_000_000));
    offered.recv_timeout(Duration::from_secs(5))?;
    stop_tx.send(true)?;
    release.send(())?;
    must(must(task.join()));
    assert!(matches!(
        sim.take_command(),
        Some(MigrationCommand::Redirect(_))
    ));
    assert!(sim.take_command().is_none(), "WORKER_CANCEL_SCAN");
    assert_eq!(sim.progress().values().map(|s| s.redirects).sum::<u64>(), 1);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn worker_visits_every_group_without_client_port_selection() -> TestResult {
    let h = Harness::with_health(
        "port",
        "connection",
        &[
            ("127.0.0.1:4000", &[("tiproxy-port", "6000")]),
            ("127.0.0.1:4001", &[("tiproxy-port", "6000")]),
            ("127.0.0.1:5000", &[("tiproxy-port", "6001")]),
            ("127.0.0.1:5001", &[("tiproxy-port", "6001")]),
        ],
        HealthCheckConfig {
            enabled: false,
            interval_nanos: 3_600_000_000_000,
            ..HealthCheckConfig::default()
        },
        "",
    )
    .await?;
    let sim = new_sim(&h, 8);
    let c = candidate(&sim).await;
    for (port, excluded) in [("6000", B), ("6001", "default/127.0.0.1:5001")] {
        for _ in 0..3 {
            let s = must(sim.router().open());
            let r = must(
                sim.router()
                    .reserve(&s, &c, ClientInfo::default(), port, &[excluded]),
            );
            assert_eq!(sim.router().finish(&r, true), Settlement::Applied);
        }
    }
    h.patch("[proxy]\nfail-backend-list=[\"127.0.0.1:4000\",\"127.0.0.1:5000\"]\n[balance.status]\nmigrations-per-second=120",3);
    let c = candidate(&sim).await;
    let now = Instant::now();
    must(sim.router().refresh_failover(&c, now));
    let (_stop_tx, stop) = watch::channel(false);
    must(sim.round_at(&c, true, &stop, now, now, 100_000_000_000));
    assert_eq!(sim.progress().len(), 2, "WORKER_ALL_GROUPS");
    assert!(
        sim.progress().values().all(|s| s.redirects == 2),
        "WORKER_ALL_GROUP_BUDGETS"
    );
    let mut commands = 0;
    while sim.take_command().is_some() {
        commands += 1;
    }
    assert_eq!(commands, 4);
    Ok(())
}

async fn observe_case(
    case: &serde_json::Value,
    expected: &[serde_json::Value],
) -> TestResult<Vec<serde_json::Value>> {
    let mut rows = Vec::new();
    let (h, sim, sessions) = setup_case(case).await?;
    let start = Instant::now();
    let rate = case["rate"].as_f64().ok_or("rate")?;
    let timeout = case["timeout"].as_u64().unwrap_or(60);
    policy(&h, rate, timeout, &["a"], 3);
    let mut c = candidate(&sim).await;
    must(sim.router().refresh_failover(&c, start));
    let (_stop_tx, stop) = watch::channel(false);
    let mut redirects = BTreeMap::new();
    let mut closes = BTreeMap::new();
    let mut revision = 3;
    for e in case["events"].as_array().ok_or("events")? {
        let now = start + Duration::from_nanos(number(e, "at"));
        let id = number(e, "id");
        match text(e, "op") {
            "tick" => {
                let close =
                    start + Duration::from_nanos(e["close_at"].as_u64().unwrap_or(number(e, "at")));
                must(sim.round_at(
                    &c,
                    e["enabled"].as_bool().unwrap_or(true),
                    &stop,
                    now,
                    close,
                    100_000_000_000 + i64::try_from(number(e, "at"))?,
                ));
            }
            "config" => {
                revision += 1;
                let fail: Vec<_> = e["fail"]
                    .as_array()
                    .ok_or("fail")?
                    .iter()
                    .filter_map(serde_json::Value::as_str)
                    .collect();
                policy(&h, rate, timeout, &fail, revision);
                c = candidate(&sim).await;
                must(sim.router().refresh_failover(&c, now));
            }
            "drain" => {
                while let Some(command) = sim.take_command() {
                    match command {
                        MigrationCommand::Redirect(r) => {
                            redirects.insert(r.to().connection_id, r);
                        }
                        MigrationCommand::ForceClose(c) => {
                            closes.insert(c.assignment().connection_id, c);
                        }
                    }
                }
            }
            "success" | "failure" => {
                let r = redirects.get(&id).ok_or("drain redirect before terminal")?;
                sim.finish_at(r, text(e, "op") == "success", now);
            }
            "close" => {
                sim.observe_close(closes.get(&id).ok_or("drain close before observation")?);
            }
            "backstop" => {
                assert!(!must(sim.router().worker_backstop_for_test(
                    &sessions[&id],
                    &c,
                    &sim.sender,
                    now
                )));
            }
            _ => return Err("unknown worker event".into()),
        }
        let row = sim.router().worker_observation(
            start,
            &sim.sender,
            &format!("{}/{}", text(case, "name"), text(e, "label")),
        );
        assert_eq!(
            row,
            expected[rows.len()],
            "WORKER_GO_CLOCK {}",
            row["label"]
        );
        rows.push(row);
    }
    check_refusal_record(case, &sim)?;
    Ok(rows)
}

fn check_refusal_record(case: &serde_json::Value, sim: &MigrationSimulation) -> TestResult {
    if case["cross"].as_bool().unwrap_or(false) {
        let records = sim.keyspace_records();
        let record = records.values().next().ok_or("WORKER_KEYSPACE_RECORD")?;
        assert_eq!((&*record.from, &*record.to), (A, B));
        assert_eq!(
            (&*record.from_keyspace, &*record.to_keyspace),
            ("tenant", "other")
        );
        assert_eq!(record.physical_connections, 6);
        assert_eq!(record.refusals, 3);
        assert_eq!(
            record.reason,
            if text(case, "name") == "cross-tick" {
                Some(crate::Factor::Status)
            } else {
                None
            }
        );
    }
    Ok(())
}

async fn setup_case(
    case: &serde_json::Value,
) -> TestResult<(Harness, MigrationSimulation, BTreeMap<u64, crate::Session>)> {
    let cross = case["cross"].as_bool().unwrap_or(false);
    let h = Harness::with_health(
        "",
        "connection",
        &[
            ("127.0.0.1:4000", &[("keyspace", "tenant")]),
            (
                "127.0.0.1:4001",
                &[("keyspace", if cross { "other" } else { "tenant" })],
            ),
        ],
        HealthCheckConfig {
            enabled: false,
            interval_nanos: 3_600_000_000_000,
            ..HealthCheckConfig::default()
        },
        "",
    )
    .await?;
    let sim = must(MigrationSimulation::new(
        Arc::new(h.source.clone()),
        &h.topology,
        &h.runtime.handle().module_context(),
        "default",
        16,
        usize::try_from(number(case, "capacity"))?,
        None,
    ));
    let c = candidate(&sim).await;
    let mut sessions = BTreeMap::new();
    for id in 1..=6 {
        let session = must(sim.router().open());
        let r = must(
            sim.router()
                .reserve(&session, &c, ClientInfo::default(), "", &[B]),
        );
        assert_eq!(r.assignment().backend_id, A);
        assert_eq!(sim.router().finish(&r, true), Settlement::Applied);
        sessions.insert(id, session);
    }

    Ok((h, sim, sessions))
}
