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

//! Fixed two-actor barrier schedules over public routing/accounting calls.

// The fixed A/B barrier cases intentionally keep similarly named owned clones
// beside each other so every closure's actor and step remain auditable.
#![allow(clippy::similar_names)]

use super::*;
use crate::MigrationSimulation;
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::sync::{Arc, Mutex, PoisonError, mpsc};

const A: &str = "default/127.0.0.1:4000";
const B: &str = "default/127.0.0.1:4001";

type Call = Box<dyn Fn() -> (&'static str, String) + Send + 'static>;

fn event(actor: char, step: usize, call: &'static str, outcome: &str) -> serde_json::Value {
    serde_json::json!({"actor": actor.to_string(), "step": step, "call": call, "outcome": outcome})
}

fn run_schedule(release: &str, actors: [Vec<Call>; 2]) -> TestResult<Vec<serde_json::Value>> {
    let (ready_a_tx, ready_a_rx) = mpsc::channel();
    let (ready_b_tx, ready_b_rx) = mpsc::channel();
    let (run_a_tx, run_a_rx) = mpsc::channel();
    let (run_b_tx, run_b_rx) = mpsc::channel();
    let (events_tx, events_rx) = mpsc::channel();
    let worker = |actor: char,
                  calls: Vec<Call>,
                  ready: mpsc::Sender<usize>,
                  proceed: mpsc::Receiver<()>,
                  events: mpsc::Sender<serde_json::Value>| {
        std::thread::spawn(move || {
            for (step, call) in calls.into_iter().enumerate() {
                ready.send(step).map_err(|_| "barrier ready closed")?;
                proceed.recv().map_err(|_| "barrier release closed")?;
                let (name, outcome) = call();
                events
                    .send(event(actor, step, name, &outcome))
                    .map_err(|_| "history closed")?;
            }
            Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
        })
    };
    let mut actors = actors.into_iter();
    let first = worker(
        'A',
        actors.next().ok_or("actor A")?,
        ready_a_tx,
        run_a_rx,
        events_tx.clone(),
    );
    let second = worker(
        'B',
        actors.next().ok_or("actor B")?,
        ready_b_tx,
        run_b_rx,
        events_tx.clone(),
    );
    drop(events_tx);
    for token in release.chars() {
        match token {
            'A' => {
                ready_a_rx.recv()?;
                run_a_tx.send(())?;
            }
            'B' => {
                ready_b_rx.recv()?;
                run_b_tx.send(())?;
            }
            other => return Err(format!("unknown schedule actor {other}").into()),
        }
    }
    first.join().map_err(|_| "actor A panicked")??;
    second.join().map_err(|_| "actor B panicked")??;
    Ok(events_rx.into_iter().collect())
}

async fn harness() -> TestResult<Harness> {
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

fn simulation(h: &Harness, capacity: usize) -> MigrationSimulation {
    must(MigrationSimulation::new(
        Arc::new(h.source.clone()),
        &h.topology,
        &h.runtime.handle().module_context(),
        "default",
        32,
        capacity,
        None,
    ))
}

async fn candidate(sim: &MigrationSimulation) -> Candidate {
    must(
        tokio::time::timeout(Duration::from_secs(10), async {
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

fn active(sim: &MigrationSimulation, candidate: &Candidate) -> crate::Session {
    let session = must(sim.router().open());
    let reservation =
        must(
            sim.router()
                .reserve(&session, candidate, ClientInfo::default(), "", &[B]),
        );
    assert_eq!(sim.router().finish(&reservation, true), Settlement::Applied);
    session
}

fn settlement(value: Settlement) -> String {
    match value {
        Settlement::Applied => "applied",
        Settlement::Ignored => "ignored",
    }
    .to_string()
}

fn accounting(sim: &MigrationSimulation) -> serde_json::Value {
    let counts = |id| {
        sim.router().accounting(id).map_or([0; 4], |counts| {
            [
                counts.reserved(),
                counts.active(),
                counts.incoming(),
                counts.outgoing(),
            ]
        })
    };
    serde_json::json!({A: counts(A), B: counts(B)})
}

fn check_row(history: &[serde_json::Value], final_accounts: &serde_json::Value) -> Vec<String> {
    let mut violations = Vec::new();
    if history.len() != 8 {
        violations.push(format!("public history has {} events", history.len()));
    }
    for actor in ["A", "B"] {
        let mut steps: Vec<_> = history
            .iter()
            .filter(|row| row["actor"] == actor)
            .filter_map(|row| row["step"].as_u64())
            .collect();
        steps.sort_unstable();
        if steps != [0, 1, 2, 3] {
            violations.push(format!("actor {actor} steps {steps:?}"));
        }
    }
    if history.iter().any(|row| {
        row["outcome"]
            .as_str()
            .is_some_and(|outcome| outcome.starts_with("error:"))
    }) {
        violations.push("public call returned an unexpected error".to_string());
    }
    if final_accounts.as_object().is_none_or(|accounts| {
        accounts.values().any(|counts| {
            counts
                .as_array()
                .is_none_or(|counts| counts.iter().any(|count| count.as_u64() != Some(0)))
        })
    }) {
        violations.push(format!("nonzero final accounting {final_accounts}"));
    }
    violations
}

#[allow(clippy::too_many_lines)]
async fn update_case(release: &str) -> TestResult<(Vec<serde_json::Value>, serde_json::Value)> {
    let h = harness().await?;
    let sim = Arc::new(simulation(&h, 4));
    let initial = candidate(&sim).await;
    let session = Arc::new(Mutex::new(None));
    let reservation = Arc::new(Mutex::new(None));
    let source = h.source.clone();
    let revision = Arc::new(AtomicU64::new(2));
    let patch = move |selection: &'static str| {
        let source = source.clone();
        let revision = Arc::clone(&revision);
        Box::new(move || {
            let revision = revision.fetch_add(1, AtomicOrdering::AcqRel) + 1;
            let config = format!("[balance]\nrouting-policy=\"{selection}\"");
            match source
                .store
                .apply_toml(config.as_bytes(), None, revision, Path::new("/tmp"))
            {
                Ok(_) => ("ConfigUpdate", format!("revision:{revision}")),
                Err(error) => ("ConfigUpdate", format!("error:{error}")),
            }
        }) as Call
    };
    let a0_sim = Arc::clone(&sim);
    let a0_session = Arc::clone(&session);
    let a1_sim = Arc::clone(&sim);
    let a1_session = Arc::clone(&session);
    let a1_reservation = Arc::clone(&reservation);
    let a1_candidate = initial.clone();
    let a2_sim = Arc::clone(&sim);
    let a2_reservation = Arc::clone(&reservation);
    let a3_sim = Arc::clone(&sim);
    let a3_session = Arc::clone(&session);
    let b2_sim = Arc::clone(&sim);
    let b3_sim = Arc::clone(&sim);
    let actors = [
        vec![
            Box::new(move || match a0_sim.router().open() {
                Ok(value) => {
                    *a0_session.lock().unwrap_or_else(PoisonError::into_inner) = Some(value);
                    ("Open", "opened".to_string())
                }
                Err(RouteError::StaleCandidate) => ("Open", "stale-candidate".to_string()),
                Err(error) => ("Open", format!("error:{error:?}")),
            }) as Call,
            Box::new(move || {
                let guard = a1_session.lock().unwrap_or_else(PoisonError::into_inner);
                let Some(session) = guard.as_ref() else {
                    return ("Reserve", "skipped:no-session".to_string());
                };
                match a1_sim.router().reserve(
                    session,
                    &a1_candidate,
                    ClientInfo::default(),
                    "",
                    &[],
                ) {
                    Ok(value) => {
                        *a1_reservation
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner) = Some(value);
                        ("Reserve", "reserved".to_string())
                    }
                    Err(RouteError::StaleCandidate) => ("Reserve", "stale-candidate".to_string()),
                    Err(error) => ("Reserve", format!("error:{error:?}")),
                }
            }) as Call,
            Box::new(move || {
                let guard = a2_reservation
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                let Some(reservation) = guard.as_ref() else {
                    return ("Finish", "skipped:no-reservation".to_string());
                };
                (
                    "Finish",
                    settlement(a2_sim.router().finish(reservation, true)),
                )
            }) as Call,
            Box::new(move || {
                let guard = a3_session.lock().unwrap_or_else(PoisonError::into_inner);
                let Some(session) = guard.as_ref() else {
                    return ("Close", "skipped:no-session".to_string());
                };
                ("Close", settlement(a3_sim.router().close(session)))
            }) as Call,
        ],
        vec![
            patch("random"),
            patch("prefer-idle"),
            Box::new(move || match b2_sim.router().capture() {
                Ok(_) => ("Capture", "captured".to_string()),
                Err(error) => ("Capture", format!("error:{error:?}")),
            }) as Call,
            Box::new(move || {
                (
                    "HealthyBackendCount",
                    b3_sim.router().healthy_backend_count().to_string(),
                )
            }) as Call,
        ],
    ];
    let history = run_schedule(release, actors)?;
    let final_accounts = accounting(&sim);
    h.runtime.begin_shutdown(ShutdownReason::Requested)?;
    Ok((history, final_accounts))
}

#[allow(clippy::too_many_lines)]
async fn terminal_case(
    name: &str,
    release: &str,
) -> TestResult<(Vec<serde_json::Value>, serde_json::Value)> {
    let h = harness().await?;
    let sim = Arc::new(simulation(&h, 8));
    let current = candidate(&sim).await;
    let session = active(&sim, &current);
    let prepared = must(sim.prepare(&session, &current, B));
    assert!(must(sim.offer(&prepared)));
    let redirect = sim.take_redirect().ok_or("accepted redirect")?;
    let actors = match name {
        "close_racing_redirect_completion" => {
            let a = Arc::clone(&sim);
            let a_session = session.clone();
            let a2 = Arc::clone(&sim);
            let a2_session = session.clone();
            let a3 = Arc::clone(&sim);
            let a4 = Arc::clone(&sim);
            let b = Arc::clone(&sim);
            let b_redirect = redirect.clone();
            let b2 = Arc::clone(&sim);
            let b2_redirect = redirect.clone();
            let b3 = Arc::clone(&sim);
            let b3_redirect = redirect.clone();
            let b4 = Arc::clone(&sim);
            [
                vec![
                    Box::new(move || ("Close", settlement(a.router().close(&a_session)))) as Call,
                    Box::new(move || ("CloseDuplicate", settlement(a2.router().close(&a2_session))))
                        as Call,
                    Box::new(move || ("AccountingA", accounting(&a3).to_string())) as Call,
                    Box::new(move || ("AccountingB", accounting(&a4).to_string())) as Call,
                ],
                vec![
                    Box::new(move || ("FinishSuccess", settlement(b.finish(&b_redirect, true))))
                        as Call,
                    Box::new(move || {
                        (
                            "FinishSuccessDuplicate",
                            settlement(b2.finish(&b2_redirect, true)),
                        )
                    }) as Call,
                    Box::new(move || {
                        (
                            "FinishFailureLate",
                            settlement(b3.finish(&b3_redirect, false)),
                        )
                    }) as Call,
                    Box::new(move || ("Accounting", accounting(&b4).to_string())) as Call,
                ],
            ]
        }
        "duplicate_late_completion" => {
            let a = Arc::clone(&sim);
            let a_redirect = redirect.clone();
            let a2 = Arc::clone(&sim);
            let a2_redirect = redirect.clone();
            let a3 = Arc::clone(&sim);
            let a3_session = session.clone();
            let a4 = Arc::clone(&sim);
            let a4_redirect = redirect.clone();
            let b = Arc::clone(&sim);
            let b_redirect = redirect.clone();
            let b2 = Arc::clone(&sim);
            let b2_redirect = redirect.clone();
            let b3 = Arc::clone(&sim);
            let b3_session = session.clone();
            let b4 = Arc::clone(&sim);
            [
                vec![
                    Box::new(move || ("FinishSuccess", settlement(a.finish(&a_redirect, true))))
                        as Call,
                    Box::new(move || {
                        (
                            "FinishSuccessDuplicate",
                            settlement(a2.finish(&a2_redirect, true)),
                        )
                    }) as Call,
                    Box::new(move || ("Close", settlement(a3.router().close(&a3_session)))) as Call,
                    Box::new(move || {
                        (
                            "FinishSuccessLate",
                            settlement(a4.finish(&a4_redirect, true)),
                        )
                    }) as Call,
                ],
                vec![
                    Box::new(move || ("FinishFailure", settlement(b.finish(&b_redirect, false))))
                        as Call,
                    Box::new(move || {
                        (
                            "FinishFailureDuplicate",
                            settlement(b2.finish(&b2_redirect, false)),
                        )
                    }) as Call,
                    Box::new(move || ("CloseDuplicate", settlement(b3.router().close(&b3_session))))
                        as Call,
                    Box::new(move || ("Accounting", accounting(&b4).to_string())) as Call,
                ],
            ]
        }
        other => return Err(format!("unknown terminal case {other}").into()),
    };
    let history = run_schedule(release, actors)?;
    let final_accounts = accounting(&sim);
    h.runtime.begin_shutdown(ShutdownReason::Requested)?;
    Ok((history, final_accounts))
}

async fn shutdown_case(release: &str) -> TestResult<(Vec<serde_json::Value>, serde_json::Value)> {
    let h = harness().await?;
    let sim = Arc::new(simulation(&h, 8));
    let current = candidate(&sim).await;
    let established = active(&sim, &current);
    let waiting = must(sim.router().open());
    let pending = must(
        sim.router()
            .reserve(&waiting, &current, ClientInfo::default(), "", &[]),
    );
    let prepared = must(sim.prepare(&established, &current, B));
    assert!(must(sim.offer(&prepared)));
    let redirect = sim.take_redirect().ok_or("accepted redirect")?;
    let (stop_tx, stop) = watch::channel(false);
    let worker_sim = Arc::clone(&sim);
    let worker = tokio::spawn(async move { worker_sim.run_worker(true, stop).await });
    tokio::time::timeout(Duration::from_secs(5), async {
        while !sim.worker_initialized() {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    let worker = Arc::new(Mutex::new(Some(worker)));
    let runtime = tokio::runtime::Handle::current();
    let a_stop = stop_tx.clone();
    let a_worker = Arc::clone(&worker);
    let a2_runtime = runtime.clone();
    let a3 = Arc::clone(&sim);
    let a3_pending = pending.clone();
    let a4 = Arc::clone(&sim);
    let a4_waiting = waiting.clone();
    let b = Arc::clone(&sim);
    let b_redirect = redirect.clone();
    let b2 = Arc::clone(&sim);
    let b2_established = established.clone();
    let b3 = Arc::clone(&sim);
    let b3_redirect = redirect.clone();
    let b4 = Arc::clone(&sim);
    let actors = [
        vec![
            Box::new(move || match a_stop.send(true) {
                Ok(()) => ("ShutdownSignal", "sent".to_string()),
                Err(error) => ("ShutdownSignal", format!("error:{error}")),
            }) as Call,
            Box::new(move || {
                let Some(worker) = a_worker
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .take()
                else {
                    return ("ShutdownJoin", "error:missing worker".to_string());
                };
                match a2_runtime.block_on(worker) {
                    Ok(Ok(())) => ("ShutdownJoin", "joined".to_string()),
                    other => ("ShutdownJoin", format!("error:{other:?}")),
                }
            }) as Call,
            Box::new(move || {
                (
                    "FinishOutstanding",
                    settlement(a3.router().finish(&a3_pending, false)),
                )
            }) as Call,
            Box::new(move || ("CloseWaiting", settlement(a4.router().close(&a4_waiting)))) as Call,
        ],
        vec![
            Box::new(move || ("FinishRedirect", settlement(b.finish(&b_redirect, true)))) as Call,
            Box::new(move || {
                (
                    "CloseEstablished",
                    settlement(b2.router().close(&b2_established)),
                )
            }) as Call,
            Box::new(move || {
                (
                    "FinishRedirectLate",
                    settlement(b3.finish(&b3_redirect, false)),
                )
            }) as Call,
            Box::new(move || ("Accounting", accounting(&b4).to_string())) as Call,
        ],
    ];
    let history = run_schedule(release, actors)?;
    let final_accounts = accounting(&sim);
    h.runtime.begin_shutdown(ShutdownReason::Requested)?;
    Ok((history, final_accounts))
}

async fn run_case(name: &str, release: &str) -> TestResult<serde_json::Value> {
    let (history, final_accounts) = match name {
        "update_racing_next_finish" => update_case(release).await?,
        "close_racing_redirect_completion" | "duplicate_late_completion" => {
            terminal_case(name, release).await?
        }
        "shutdown_outstanding_requests" => shutdown_case(release).await?,
        other => return Err(format!("unknown concurrency case {other}").into()),
    };
    let violations = check_row(&history, &final_accounts);
    Ok(serde_json::json!({
        "case": name,
        "history": history,
        "final_accounts": final_accounts,
        "violations": violations,
    }))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires CPROUTE_CONCURRENCY_OUTPUT; run by dedicated concurrency evidence"]
async fn api_concurrency_focused() -> TestResult {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../tests/controlplane/cproute/api-differential/focused/concurrency.json");
    let spec: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(path)?)?;
    assert_eq!(spec["suite"], "concurrency");
    let cases = spec["cases"].as_array().ok_or("cases")?;
    let schedules = spec["schedules"].as_array().ok_or("schedules")?;
    assert_eq!((cases.len(), schedules.len()), (4, 16));
    let mut rows = Vec::new();
    for case in cases {
        let name = case.as_str().ok_or("case name")?;
        for schedule in schedules {
            let id = schedule["id"].as_str().ok_or("schedule id")?;
            let release = schedule["release"].as_str().ok_or("release")?;
            assert_eq!(release.len(), 8);
            assert_eq!(release.matches('A').count(), 4);
            assert_eq!(release.matches('B').count(), 4);
            let mut row = run_case(name, release).await?;
            row["schedule"] = serde_json::json!(id);
            assert_eq!(row["violations"], serde_json::json!([]), "{name}/{id}");
            rows.push(row);
        }
    }
    let negative_history = vec![serde_json::json!({"actor":"A","step":0})];
    let negative_accounts = serde_json::json!({A:[1,0,0,0],B:[0,0,0,0]});
    let detected = check_row(&negative_history, &negative_accounts);
    assert!(detected.len() >= 3);
    if let Ok(output) = std::env::var("CPROUTE_CONCURRENCY_OUTPUT") {
        let manifest = serde_json::json!({
            "engine": "rust",
            "suite": "concurrency",
            "rows": rows,
            "negative_control_detected": detected,
        });
        std::fs::write(output, serde_json::to_string_pretty(&manifest)? + "\n")?;
    }
    Ok(())
}
