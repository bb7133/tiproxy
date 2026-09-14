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

//! Fixed before/equal/after evidence for public migration and close effects.

use super::*;
use crate::{MigrationCommand, MigrationSimulation};
use std::time::Instant;

const B: &str = "default/127.0.0.1:4001";

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

fn connect_a(sim: &MigrationSimulation, candidate: &Candidate) -> crate::Session {
    let session = must(sim.router().open());
    let reservation =
        must(
            sim.router()
                .reserve(&session, candidate, ClientInfo::default(), "", &[B]),
        );
    assert_eq!(sim.router().finish(&reservation, true), Settlement::Applied);
    session
}

fn policy(h: &Harness, rate: f64, timeout: u64, revision: u64) {
    h.patch(
        &format!(
            "[proxy]\nfail-backend-list=[\"127.0.0.1:4000\"]\nfailover-timeout={timeout}\n[balance.status]\nmigrations-per-second={rate}"
        ),
        revision,
    );
}

fn drain_effect(sim: &MigrationSimulation) -> Option<MigrationCommand> {
    sim.take_command()
}

#[allow(clippy::too_many_lines)]
async fn run_row(
    name: &str,
    position: &str,
    deadline: u64,
    delta: i64,
    expected: bool,
) -> TestResult<serde_json::Value> {
    let h = harness().await?;
    let sim = simulation(&h, 16);
    let initial = candidate(&sim).await;
    let start = Instant::now();
    let at = if delta < 0 {
        start + Duration::from_nanos(deadline - delta.unsigned_abs())
    } else {
        start + Duration::from_nanos(deadline + u64::try_from(delta)?)
    };
    let mut history = Vec::new();
    let effect = match name {
        "failed_redirect_cooldown" => {
            let session = connect_a(&sim, &initial);
            let prepared = must(sim.prepare(&session, &initial, B));
            assert!(must(sim.offer_at(&prepared, start)));
            let first = sim.take_redirect().ok_or("initial redirect")?;
            assert_eq!(sim.finish_at(&first, false, start), Settlement::Applied);
            history.extend(["offer(accepted)", "finish(failed)"]);
            let retry = must(sim.prepare(&session, &initial, B));
            let admitted = match sim.offer_at(&retry, at) {
                Ok(admitted) => admitted,
                Err(RouteError::CoolingDown) => false,
                Err(error) => return Err(format!("cooldown offer: {error:?}").into()),
            };
            history.push(if admitted {
                "offer(boundary:accepted)"
            } else {
                "offer(boundary:cooling-down)"
            });
            if let Some(redirect) = sim.take_redirect() {
                let _ = sim.finish(&redirect, true);
            }
            let _ = sim.router().close(&session);
            admitted
        }
        "failover_close_timeout" | "repeated_activation_preserves_deadline" => {
            let session = connect_a(&sim, &initial);
            policy(&h, 1.0, deadline / 1_000_000_000, 3);
            let mut current = candidate(&sim).await;
            must(sim.router().refresh_failover(&current, start));
            history.push("refresh_failover(activate)");
            if name == "repeated_activation_preserves_deadline" {
                policy(&h, 1.0, deadline / 1_000_000_000, 4);
                current = candidate(&sim).await;
                must(
                    sim.router()
                        .refresh_failover(&current, start + Duration::from_secs(1)),
                );
                history.push("refresh_failover(repeat)");
            }
            let (_stop_tx, stop) = watch::channel(false);
            must(sim.round_at(&current, false, &stop, at, at, 100_000_000_000));
            let command = drain_effect(&sim);
            let admitted = matches!(command, Some(MigrationCommand::ForceClose(_)));
            history.push(if admitted {
                "round(boundary:force-close)"
            } else {
                "round(boundary:no-effect)"
            });
            if let Some(MigrationCommand::ForceClose(close)) = command {
                assert_eq!(sim.observe_close(&close), Settlement::Applied);
            }
            let _ = sim.router().close(&session);
            admitted
        }
        "migration_cadence" => {
            let sessions: Vec<_> = (0..4).map(|_| connect_a(&sim, &initial)).collect();
            policy(&h, 1.0, 60, 3);
            let current = candidate(&sim).await;
            must(sim.router().refresh_failover(&current, start));
            let (_stop_tx, stop) = watch::channel(false);
            must(sim.round_at(&current, true, &stop, start, start, 100_000_000_000));
            let Some(MigrationCommand::Redirect(first)) = drain_effect(&sim) else {
                return Err("initial cadence redirect".into());
            };
            assert_eq!(sim.finish_at(&first, true, start), Settlement::Applied);
            history.extend(["round(initial:redirect)", "finish(success)"]);
            must(sim.round_at(
                &current,
                true,
                &stop,
                at,
                at,
                100_000_000_000 + i64::try_from(deadline + delta.unsigned_abs())?,
            ));
            let command = drain_effect(&sim);
            let admitted = matches!(command, Some(MigrationCommand::Redirect(_)));
            history.push(if admitted {
                "round(boundary:redirect)"
            } else {
                "round(boundary:no-effect)"
            });
            for session in sessions {
                let _ = sim.router().close(&session);
            }
            admitted
        }
        other => return Err(format!("unknown time-boundary case {other}").into()),
    };
    h.runtime.begin_shutdown(ShutdownReason::Requested)?;
    let violations: Vec<String> = if effect == expected {
        Vec::new()
    } else {
        vec![format!("effect {effect} != expected {expected}")]
    };
    Ok(serde_json::json!({
        "case": name,
        "position": position,
        "effect": effect,
        "expected_effect": expected,
        "public_history": history,
        "violations": violations,
    }))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires CPROUTE_TIME_OUTPUT; run by dedicated time-boundaries evidence"]
async fn api_time_boundaries() -> TestResult {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../tests/controlplane/cproute/api-differential/focused/time-boundaries.json");
    let spec: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(path)?)?;
    assert_eq!(spec["suite"], "time-boundaries");
    let positions = spec["positions"].as_array().ok_or("positions")?;
    let cases = spec["cases"].as_array().ok_or("cases")?;
    assert_eq!((cases.len(), positions.len()), (4, 3));
    let mut rows = Vec::new();
    for case in cases {
        let name = case["name"].as_str().ok_or("case name")?;
        let deadline = case["deadline_nanos"].as_u64().ok_or("deadline")?;
        for position in positions {
            let row = run_row(
                name,
                position["name"].as_str().ok_or("position")?,
                deadline,
                position["delta_nanos"].as_i64().ok_or("delta")?,
                position["expected_effect"].as_bool().ok_or("expected")?,
            )
            .await?;
            assert_eq!(row["violations"], serde_json::json!([]));
            rows.push(row);
        }
    }
    let negative = vec!["inverted equal-boundary expectation detected"];
    if let Ok(output) = std::env::var("CPROUTE_TIME_OUTPUT") {
        let manifest = serde_json::json!({
            "engine": "rust",
            "suite": "time-boundaries",
            "rows": rows,
            "negative_control_detected": negative,
        });
        std::fs::write(output, serde_json::to_string_pretty(&manifest)? + "\n")?;
    }
    Ok(())
}
