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

//! Resource-release focused suite (API differential contract section 4): four
//! fixed cases, each repeated for the declared cycle count; afterwards owned
//! tasks and live connections return to baseline within a bounded drain. Only
//! public boundaries are asserted: per-backend `Accounting`, `lookup_backend`
//! after the backends leave routing, and the migration worker join.

use super::*;
use crate::scheduler::{CommandQueue, RoundClock};
use crate::{MigrationCommand, MigrationSimulation};
use std::sync::atomic::AtomicUsize;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

const A: &str = "default/127.0.0.1:4000";
const B: &str = "default/127.0.0.1:4001";

#[derive(Clone, Debug, Default)]
struct Snapshot {
    tasks: usize,
    accounts: BTreeMap<String, [u64; 4]>,
    retained_backends: Vec<String>,
    unjoined_workers: usize,
}

impl Snapshot {
    fn json(&self) -> serde_json::Value {
        serde_json::json!({"tasks": self.tasks, "accounts": self.accounts,
            "retained_backends": self.retained_backends, "unjoined_workers": self.unjoined_workers})
    }
}

/// Pure checker: no waiting, retries or router reads, so the negative control
/// can run it on a fixture.
fn check(baseline: &Snapshot, last: &Snapshot) -> Vec<String> {
    let mut violations = Vec::new();
    for (id, counts) in &last.accounts {
        if counts.iter().any(|count| *count != 0) {
            violations.push(format!(
                "{id} accounting reserved/active/incoming/outgoing {counts:?}"
            ));
        }
    }
    if !last.retained_backends.is_empty() {
        violations.push(format!(
            "backends retained after routing removal {:?}",
            last.retained_backends
        ));
    }
    if last.unjoined_workers != 0 {
        violations.push(format!(
            "{} migration workers not joined",
            last.unjoined_workers
        ));
    }
    if last.tasks > baseline.tasks {
        violations.push(format!(
            "tasks {} above baseline {}",
            last.tasks, baseline.tasks
        ));
    }
    violations
}

fn tasks() -> usize {
    tokio::runtime::Handle::current()
        .metrics()
        .num_alive_tasks()
}

async fn tasks_within(limit: usize, drain: Duration) -> (usize, Duration) {
    let start = Instant::now();
    loop {
        let n = tasks();
        if n <= limit || start.elapsed() >= drain {
            return (n, start.elapsed());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

fn accounts(router: &Router) -> BTreeMap<String, [u64; 4]> {
    [A, B]
        .into_iter()
        .filter_map(|id| {
            router.accounting(id).map(|a| {
                (
                    id.to_string(),
                    [a.reserved(), a.active(), a.incoming(), a.outgoing()],
                )
            })
        })
        .collect()
}

/// Removes every backend from the real routing producer and reports the IDs the
/// router still retains; a leaked reservation or connection keeps its owner.
async fn retained(h: &Harness, router: &Router) -> Vec<String> {
    let before = router.capture().ok();
    h.fixture.backends(&[]);
    let _ = tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            if let Ok(next) = router.capture()
                && before
                    .as_ref()
                    .is_none_or(|old| !Arc::ptr_eq(&old.routing, &next.routing))
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await;
    let out = [A, B]
        .into_iter()
        .filter(|id| router.lookup_backend(id).is_ok())
        .map(str::to_string)
        .collect();
    // Restore both owners for the next case and wait until routing sees them again.
    h.fixture
        .backends(&[("127.0.0.1:4000", &[]), ("127.0.0.1:4001", &[])]);
    must(
        tokio::time::timeout(Duration::from_secs(8), async {
            while !(router.capture().is_ok()
                && router.lookup_backend(A).is_ok()
                && router.lookup_backend(B).is_ok())
            {
                tokio::task::yield_now().await;
            }
        })
        .await,
    );
    out
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
        64,
        capacity,
        None,
    ))
}

async fn fresh(router: &Router, old: Option<&Candidate>) -> Candidate {
    must(
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if let Ok(c) = router.capture()
                    && old.is_none_or(|old| !Arc::ptr_eq(&old.config, &c.config))
                {
                    break c;
                }
                tokio::task::yield_now().await;
            }
        })
        .await,
    )
}

fn wall() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos()),
    )
    .unwrap_or(i64::MAX)
}

struct CaseRun {
    baseline: Snapshot,
    last: Snapshot,
    drained: Duration,
    effects: usize,
}

async fn finish_case(
    h: &Harness,
    router: &Router,
    baseline: Snapshot,
    drain: Duration,
    effects: usize,
) -> CaseRun {
    let mut last = Snapshot {
        accounts: accounts(router),
        ..Snapshot::default()
    };
    last.retained_backends = retained(h, router).await;
    let (tasks, drained) = tasks_within(baseline.tasks, drain).await;
    last.tasks = tasks;
    CaseRun {
        baseline,
        last,
        drained,
        effects,
    }
}

// Every creation fails; the retry excludes the first owner and fails too.
async fn failed_creation(h: &Harness, cycles: usize, drain: Duration) -> CaseRun {
    let sim = simulation(h, 1);
    let c = fresh(sim.router(), None).await;
    let cycle = || {
        let session = must(sim.router().open());
        let first = must(
            sim.router()
                .reserve(&session, &c, ClientInfo::default(), "", &[]),
        );
        let failed = first.assignment().backend_id.clone();
        assert_eq!(sim.router().finish(&first, false), Settlement::Applied);
        let retry =
            must(
                sim.router()
                    .reserve(&session, &c, ClientInfo::default(), "", &[failed.as_str()]),
            );
        assert_ne!(
            retry.assignment().backend_id,
            failed,
            "RETRY_EXCLUDES_FAILED_OWNER"
        );
        assert_eq!(sim.router().finish(&retry, false), Settlement::Applied);
        assert_eq!(sim.router().close(&session), Settlement::Applied);
    };
    cycle();
    let baseline = Snapshot {
        tasks: tasks(),
        ..Snapshot::default()
    };
    for _ in 0..cycles {
        cycle();
    }
    finish_case(h, sim.router(), baseline, drain, 0).await
}

// A connection on a drained owner is force-closed at a zero failover timeout;
// the client refuses and the close event cleans up.
async fn refused_effect_cleanup(
    h: &Harness,
    cycles: usize,
    drain: Duration,
    revision: &mut u64,
) -> CaseRun {
    let sim = simulation(h, 1);
    let offered = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&offered);
    let queue = CommandQueue::with_api_sink(
        8,
        Box::new(move |command| {
            assert!(
                matches!(command, MigrationCommand::ForceClose(_)),
                "ONLY_FORCE_CLOSE"
            );
            counter.fetch_add(1, Ordering::AcqRel);
            false
        }),
    );
    let (_stop_tx, stop) = watch::channel(false);
    let mut c = fresh(sim.router(), None).await;
    let cycle = async |c: &mut Candidate, revision: &mut u64| {
        let session = must(sim.router().open());
        let r = must(
            sim.router()
                .reserve(&session, c, ClientInfo::default(), "", &[B]),
        );
        assert_eq!(sim.router().finish(&r, true), Settlement::Applied);
        let before = offered.load(Ordering::Acquire);
        *revision += 1;
        h.patch(
            "[proxy]\nfail-backend-list=[\"127.0.0.1:4000\"]\nfailover-timeout=0\n",
            *revision,
        );
        h.source.deliver();
        *c = fresh(sim.router(), Some(c)).await;
        let now = Instant::now();
        must(sim.router().refresh_failover(c, now));
        let clock = RoundClock {
            fixed: Some((now, now, wall())),
        };
        must(
            sim.router()
                .migration_round(c, &queue, false, &stop, &clock),
        );
        assert!(
            offered.load(Ordering::Acquire) > before,
            "REFUSED_FORCE_CLOSE_ISSUED"
        );
        assert!(queue.take().is_none(), "REFUSED_EFFECT_NOT_QUEUED");
        assert_eq!(sim.router().close(&session), Settlement::Applied);
        *revision += 1;
        h.patch("[proxy]\nfail-backend-list=[]\n", *revision);
        h.source.deliver();
        *c = fresh(sim.router(), Some(c)).await;
        must(sim.router().refresh_failover(c, Instant::now()));
    };
    cycle(&mut c, revision).await;
    let baseline = Snapshot {
        tasks: tasks(),
        ..Snapshot::default()
    };
    for _ in 0..cycles {
        cycle(&mut c, revision).await;
    }
    let effects = offered.load(Ordering::Acquire);
    finish_case(h, sim.router(), baseline, drain, effects).await
}

// Each cycle runs the migration worker. With `outstanding`, stop arrives with a
// pending reservation and an accepted, uncompleted redirect whose late
// settlement must be harmless; otherwise it is a plain create/close lifecycle.
async fn worker_cycles(
    h: &Harness,
    cycles: usize,
    drain: Duration,
    outstanding: bool,
) -> TestResult<CaseRun> {
    let mut baseline = Snapshot::default();
    let mut unjoined = 0;
    let mut effects = 0;
    let mut last = None;
    for cycle in 0..=cycles {
        if cycle == 1 {
            baseline.tasks = tasks();
        }
        let sim = Arc::new(simulation(h, 8));
        let c = fresh(sim.router(), None).await;
        let (stop_tx, stop) = watch::channel(false);
        let child = Arc::clone(&sim);
        let worker = tokio::spawn(async move { child.run_worker(outstanding, stop).await });
        let established = must(sim.router().open());
        let r = must(
            sim.router()
                .reserve(&established, &c, ClientInfo::default(), "", &[B]),
        );
        assert_eq!(sim.router().finish(&r, true), Settlement::Applied);
        let mut late = None;
        if outstanding {
            let waiting = must(sim.router().open());
            let pending = must(
                sim.router()
                    .reserve(&waiting, &c, ClientInfo::default(), "", &[]),
            );
            let prepared = must(sim.prepare(&established, &c, B));
            assert!(must(sim.offer(&prepared)), "OUTSTANDING_REDIRECT_ACCEPTED");
            let redirect = sim.take_redirect().ok_or("outstanding redirect")?;
            effects += 1;
            late = Some((waiting, pending, redirect));
        }
        stop_tx.send(true)?;
        let joined = tokio::time::timeout(Duration::from_secs(3), worker).await;
        unjoined += usize::from(!matches!(joined, Ok(Ok(Ok(())))));
        if let Some((waiting, pending, redirect)) = late {
            let _ = sim.finish(&redirect, true);
            assert_eq!(sim.router().finish(&pending, false), Settlement::Applied);
            assert_eq!(sim.router().close(&waiting), Settlement::Applied);
            let _ = sim.finish(&redirect, false);
        }
        assert_eq!(sim.router().close(&established), Settlement::Applied);
        if cycle == cycles {
            last = Some(sim);
        }
    }
    let sim = last.ok_or("no cycles")?;
    let mut run = finish_case(h, sim.router(), baseline, drain, effects).await;
    run.last.unjoined_workers = unjoined;
    Ok(run)
}

// Negative control: a reservation without Finish keeps its owner retained and
// the same checker must report it; the fixture also covers every rule.
async fn negative_control(h: &Harness) -> Vec<String> {
    let sim = simulation(h, 1);
    let c = fresh(sim.router(), None).await;
    let session = must(sim.router().open());
    let leak = must(
        sim.router()
            .reserve(&session, &c, ClientInfo::default(), "", &[]),
    );
    let leaked = Snapshot {
        tasks: tasks(),
        accounts: accounts(sim.router()),
        retained_backends: retained(h, sim.router()).await,
        unjoined_workers: 0,
    };
    let detected = check(
        &Snapshot {
            tasks: leaked.tasks,
            ..Snapshot::default()
        },
        &leaked,
    );
    assert!(!detected.is_empty(), "NEGATIVE_CONTROL_DETECTS_LEAK");
    let fixture = Snapshot {
        tasks: 11,
        accounts: BTreeMap::from([(A.to_string(), [1, 0, 0, 0])]),
        retained_backends: vec![A.to_string()],
        unjoined_workers: 1,
    };
    assert_eq!(
        check(
            &Snapshot {
                tasks: 10,
                ..Snapshot::default()
            },
            &fixture
        )
        .len(),
        4
    );
    assert_eq!(sim.router().finish(&leak, false), Settlement::Applied);
    assert_eq!(sim.router().close(&session), Settlement::Applied);
    detected
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn api_resource_release() -> TestResult {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../tests/controlplane/cproute/api-differential/focused/resource-release.json");
    let spec: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(path)?)?;
    assert_eq!(spec["suite"], "resource-release");
    let cycles = usize::try_from(spec["cycles"].as_u64().ok_or("cycles")?)?;
    assert!(cycles > 0);
    let drain_millis = spec["drain_millis"].as_u64().ok_or("drain_millis")?;
    let drain = Duration::from_millis(drain_millis);
    let h = harness().await?;
    let mut revision = 10;
    let mut results = Vec::new();
    for name in spec["cases"].as_array().ok_or("cases")? {
        let name = name.as_str().ok_or("case name")?;
        let run = match name {
            "failed_creation" => failed_creation(&h, cycles, drain).await,
            "refused_effect_cleanup" => {
                refused_effect_cleanup(&h, cycles, drain, &mut revision).await
            }
            "shutdown_outstanding" => worker_cycles(&h, cycles, drain, true).await?,
            "repeated_create_close" => worker_cycles(&h, cycles, drain, false).await?,
            other => return Err(format!("unknown resource-release case {other}").into()),
        };
        let violations = check(&run.baseline, &run.last);
        assert!(violations.is_empty(), "case {name}: {violations:?}");
        results.push(serde_json::json!({
            "case": name, "cycles": cycles, "effects": run.effects, "baseline": run.baseline.json(),
            "final": run.last.json(), "drain_nanos": u64::try_from(run.drained.as_nanos()).unwrap_or(u64::MAX),
            "violations": violations,
        }));
    }
    let detected = negative_control(&h).await;
    if let Ok(output) = std::env::var("CPROUTE_RESOURCE_OUTPUT") {
        let manifest = serde_json::json!({
            "engine": "rust", "suite": "resource-release", "cycles": cycles,
            "drain_millis": drain_millis, "cases": results, "negative_control_detected": detected,
        });
        std::fs::write(output, serde_json::to_string_pretty(&manifest)? + "\n")?;
    }
    h.runtime.begin_shutdown(ShutdownReason::Requested)?;
    Ok(())
}
