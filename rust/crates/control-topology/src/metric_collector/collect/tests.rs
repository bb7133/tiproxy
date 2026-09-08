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
fn collector_query_encoding_and_range_round_time() -> Result<(), Box<dyn std::error::Error>> {
    let cpu = QueryId::Cpu.spec().expressions();
    let targets: Vec<_> = cpu
        .iter()
        .map(|expression| prom_target(QueryId::Cpu, expression, 123_456))
        .collect();
    assert!(targets.iter().all(Result::is_ok));
    assert_eq!(seconds(123_456), "123.456");
    assert_eq!(seconds(-1), "-0.001");
    assert!(cpu[0].contains("job="));
    assert!(cpu[1].contains("component="));
    assert_eq!(
        QueryId::Cpu.spec().expressions(),
        cpu,
        "COLLECTOR_QUERY_LABEL_NOT_PERSISTENT"
    );
    assert_eq!(
        service::encode_query("a &b=中+%"),
        "a+%26b%3D%E4%B8%AD%2B%25"
    );
    assert_eq!(
        split_address("[::1]:10080").map_err(|e| format!("{e:?}"))?,
        ("::1", 10080)
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn collector_backend_batch_joins_errors_panics_and_revocation()
-> Result<(), Box<dyn std::error::Error>> {
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct Finished(Arc<AtomicUsize>);
    impl Drop for Finished {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    for mode in ["panic", "stale", "capacity", "completed"] {
        let started = Arc::new(AtomicUsize::new(0));
        let dropped = Arc::new(AtomicUsize::new(0));
        let entered = Arc::new(tokio::sync::Notify::new());
        let gate = Arc::new(tokio::sync::Semaphore::new(0));
        let started_task = Arc::clone(&started);
        let dropped_task = Arc::clone(&dropped);
        let entered_task = Arc::clone(&entered);
        let gate_task = Arc::clone(&gate);
        let task = tokio::spawn(async move {
            let fence = GenerationGate::new();
            let addresses: Vec<_> = (0..150).map(|n| n.to_string()).collect();
            let mut values = Vec::new();
            let result = join_backends(
                &addresses,
                &fence,
                move |address| {
                    let started = Arc::clone(&started_task);
                    let dropped = Arc::clone(&dropped_task);
                    let entered = Arc::clone(&entered_task);
                    let gate = Arc::clone(&gate_task);
                    async move {
                        let _finish = Finished(dropped);
                        if started.fetch_add(1, Ordering::SeqCst) + 1 == 100 {
                            entered.notify_one();
                        }
                        let permit = gate.acquire().await.map_err(|_| RoundError::Stale)?;
                        permit.forget();
                        assert!(
                            !(address == "0" && mode == "panic"),
                            "intentional owned backend task panic"
                        );
                        if mode == "stale" {
                            return Err(RoundError::Stale);
                        }
                        if mode != "completed" && address != "0" {
                            std::future::pending::<()>().await;
                        }
                        if address == "1" {
                            Err(RoundError::Read)
                        } else {
                            Ok(address)
                        }
                    }
                },
                |value| {
                    if mode == "capacity" {
                        return Err(RoundError::Decode);
                    }
                    values.push(value);
                    Ok(())
                },
            )
            .await;
            (result, values)
        });
        tokio::time::timeout(Duration::from_secs(3), entered.notified()).await?;
        // All initial workers remain parked on the gate; allow every admitted
        // task to report entry before checking the concurrency bound.
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert_eq!(
            started.load(Ordering::SeqCst),
            100,
            "COLLECTOR_BACKEND_MAX_100"
        );
        gate.add_permits(150);
        let (result, values) = tokio::time::timeout(Duration::from_secs(3), task).await??;
        assert_eq!(
            started.load(Ordering::SeqCst),
            dropped.load(Ordering::SeqCst),
            "COLLECTOR_BACKEND_ALL_JOINED"
        );
        match mode {
            "panic" => assert!(
                matches!(result, Err(RoundError::Task)),
                "COLLECTOR_BACKEND_PANIC_NOT_COMPLETED"
            ),
            "stale" => assert!(
                matches!(result, Err(RoundError::Stale)),
                "COLLECTOR_BACKEND_STALE_NOT_COMPLETED"
            ),
            "capacity" => assert!(
                matches!(result, Err(RoundError::Decode)),
                "COLLECTOR_BACKEND_CAPACITY_NOT_COMPLETED"
            ),
            _ => {
                assert!(result.is_ok());
                assert_eq!(values.len(), 149, "COLLECTOR_BACKEND_COMPLETED_MISSING");
            }
        }
    }
    Ok(())
}

mod live;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn collector_batch_waits_for_canceled_child_destructor()
-> Result<(), Box<dyn std::error::Error>> {
    use std::sync::{Condvar, Mutex, PoisonError};
    struct JoinBoundary {
        released: Mutex<bool>,
        wake: Condvar,
        entered: tokio::sync::Notify,
    }
    struct BlockingDrop(Arc<JoinBoundary>);
    impl Drop for BlockingDrop {
        fn drop(&mut self) {
            self.0.entered.notify_one();
            let mut released = self
                .0
                .released
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            while !*released {
                released = self
                    .0
                    .wake
                    .wait(released)
                    .unwrap_or_else(PoisonError::into_inner);
            }
        }
    }
    let boundary = Arc::new(JoinBoundary {
        released: Mutex::new(false),
        wake: Condvar::new(),
        entered: tokio::sync::Notify::new(),
    });
    let worker_boundary = Arc::clone(&boundary);
    let started = Arc::new(tokio::sync::Notify::new());
    let task = tokio::spawn(async move {
        join_backends(
            &["victim".into(), "stale".into()],
            &GenerationGate::new(),
            move |name| {
                let boundary = Arc::clone(&worker_boundary);
                let started = Arc::clone(&started);
                async move {
                    if name == "victim" {
                        let _drop = BlockingDrop(boundary);
                        started.notify_one();
                        std::future::pending::<()>().await;
                    } else {
                        started.notified().await;
                    }
                    Err::<(), _>(RoundError::Stale)
                }
            },
            |()| Ok(()),
        )
        .await
    });
    let entered = tokio::time::timeout(Duration::from_secs(3), boundary.entered.notified()).await;
    // Let a wrongly completed parent publish its completion flag while the
    // canceled child's destructor remains demonstrably blocked.
    tokio::time::sleep(Duration::from_millis(30)).await;
    let completed_early = task.is_finished();
    *boundary
        .released
        .lock()
        .unwrap_or_else(PoisonError::into_inner) = true;
    boundary.wake.notify_all();
    entered?;
    let outcome = tokio::time::timeout(Duration::from_secs(3), task).await??;
    assert!(!completed_early, "COLLECTOR_CANCEL_JOIN_BEFORE_RETURN");
    assert!(matches!(outcome, Err(RoundError::Stale)));
    Ok(())
}

#[test]
fn factor_lineage_tracks_selected_history_not_round_or_unused_owners() {
    use crate::metric_collector::MetricCacheLineage;
    use crate::metrics::Source;
    let mut state = State::default();
    state.reader.complete_prom(BTreeMap::new());
    let first = state.result();
    let lineage = MetricCacheLineage(Arc::clone(&first.lineage));
    let replacement = State::default();
    assert!(
        !lineage.same_history(&MetricCacheLineage(Arc::clone(&replacement.lineage))),
        "FACTOR_LINEAGE_OPAQUE_IDENTITY"
    );
    let second = state.result();
    first.gate.revoke();
    assert!(
        lineage.same_history(&MetricCacheLineage(Arc::clone(&second.lineage))),
        "FACTOR_ROUND_NOT_LINEAGE"
    );
    state.reset_backend();
    assert_eq!(state.reader.source(), Source::Prometheus);
    assert!(
        lineage.same_history(&MetricCacheLineage(Arc::clone(&state.lineage))),
        "FACTOR_PROM_UNUSED_OWNER_CONTINUITY"
    );
    state.reader.complete_backend(BTreeMap::new(), true);
    let backend = MetricCacheLineage(Arc::clone(&state.lineage));
    state.reset_backend();
    assert!(
        !backend.same_history(&MetricCacheLineage(Arc::clone(&state.lineage))),
        "FACTOR_BACKEND_OWNER_COLD_START"
    );
}
