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
use crate::{BackendSourceMode, MetricCapture, MetricReadError, MetricSourceHandle};
use control_external::HttpTarget;

mod live;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::too_many_lines)]
async fn metric_applied_capture_fences_etcd_between_ranges_and_retries() -> Result<(), TestError> {
    for prom in [false, true] {
        for material in [false, true] {
            tokio::time::timeout(Duration::from_secs(5), async {
                let prefix = if prom { PROM_PREFIX } else { TIDB_PREFIX };
                let fixture = kv_fixture::spawn_gated_fixture(Vec::new(), prefix, prom)
                    .await
                    .ok_or("KV fixture")?;
                let timeout_ms = Arc::new(AtomicU64::new(500));
                let store = ConfigNamespaceStore::from_toml(
                    &config_single(100),
                    None,
                    &std::env::current_dir()?,
                )?;
                let stopped = Arc::new(Notify::new());
                let release = Arc::new(tokio::sync::Semaphore::new(0));
                let runner: ChildRunner = {
                    let stopped = Arc::clone(&stopped);
                    let release = Arc::clone(&release);
                    Arc::new(move |_, _, _, _, mut shutdown| {
                        let stopped = Arc::clone(&stopped);
                        let release = Arc::clone(&release);
                        Box::pin(async move {
                            let _ = shutdown.changed().await;
                            stopped.notify_one();
                            if let Ok(permit) = release.acquire().await {
                                permit.forget();
                            }
                            Ok(())
                        })
                    })
                };
                let (module, handle) = TopologyModule::new_with_child_runner_and_connector(
                    Arc::new(store.clone()),
                    Box::new(kv_fixture::FixtureFactory {
                        addr: fixture.addr,
                        timeout_ms: Arc::clone(&timeout_ms),
                    }),
                    Arc::new(StaticAdvertiseResolver::new("10.0.0.1")),
                    identity(),
                    disabled_health(),
                    runner,
                    counting_real_connector(&Arc::new(AtomicUsize::new(0))),
                )?;
                let mut running = MetricModule::start(module, handle)?;
                let capture = running.initial().await?;
                let old = capture.clone();
                let discovery = running
                    .handle
                    .discovery_handle()
                    .capture()
                    .map_err(|error| format!("capture: {error:?}"))?;
                let poll = tokio::spawn(async move {
                    if prom {
                        capture.poll_prometheus(CLUSTER_NAME).await.map(|_| ())
                    } else {
                        capture
                            .poll_cluster_topology(CLUSTER_NAME)
                            .await
                            .map(|_| ())
                    }
                });
                fixture.arrived.notified().await;
                if material {
                    timeout_ms.store(700, Ordering::SeqCst);
                    store.apply_toml(&config_single(200), None, 2, &std::env::current_dir()?)?;
                    stopped.notified().await;
                    assert!(running.handle.routing_handle().still_current(old.routing()));
                } else {
                    running.commands.send(epoch_result(0, 2))?;
                    metric_capture(&running.handle.metric_source(), 0, 2).await?;
                }
                assert!(
                    discovery.still_current(),
                    "discovery unchanged during metric withdrawal"
                );
                assert!(!old.still_current(), "METRIC_APPLIED_RANGE_REVOKED");
                fixture.release.notify_one();
                assert!(
                    matches!(poll.await?, Err(MetricReadError::Stale)),
                    "METRIC_APPLIED_RANGE_STALE_WINS"
                );
                assert_eq!(
                    fixture.range_count(prefix),
                    1,
                    "METRIC_APPLIED_RANGE_NO_RETRY"
                );
                assert_eq!(
                    fixture.range_count(KEYSPACE_PREFIX),
                    0,
                    "METRIC_APPLIED_RANGE_NO_SECOND_PREFIX"
                );
                release.add_permits(2);
                if material {
                    wait_observed(&mut running.handle.status(), 2).await?;
                }
                running.stop().await?;
                Ok::<_, TestError>(())
            })
            .await??;
        }
    }
    Ok(())
}

async fn metric_capture(
    feed: &MetricSourceHandle,
    epoch: u64,
    generation: u64,
) -> Result<MetricCapture, TestError> {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let (capture, revision, closed) = feed.snapshot();
            if let Some(capture) = capture
                && capture.routing().client_epoch == epoch
                && capture.routing().generation == generation
            {
                return Ok::<_, TestError>(capture);
            }
            if closed {
                return Err("metrics feed closed".into());
            }
            feed.wait_change(revision).await;
        }
    })
    .await?
}

struct MetricModule {
    task: ModuleTask,
    runtime: ControlRuntime,
    handle: super::super::TopologyModuleHandle,
    commands: tokio::sync::mpsc::UnboundedSender<EpochResult<MergedTopology>>,
}
impl MetricModule {
    fn start(
        mut module: TopologyModule,
        handle: super::super::TopologyModuleHandle,
    ) -> Result<Self, TestError> {
        module = module.with_metrics()?;
        let (refresh, commands) = commandable_refresh();
        module.set_refresh_override(refresh);
        let runtime = runtime()?;
        let context = runtime.handle().module_context();
        runtime.mark_ready()?;
        let task = tokio::spawn(Box::new(module).run(context));
        Ok(Self {
            task,
            runtime,
            handle,
            commands,
        })
    }
    async fn initial(&mut self) -> Result<MetricCapture, TestError> {
        wait_ready(&mut self.handle).await?;
        self.commands.send(epoch_result(0, 1))?;
        let capture = metric_capture(&self.handle.metric_source(), 0, 1).await?;
        wait_overlay_all_healthy(
            &self.handle.health_overlay_handle(),
            &self.handle.routing_handle(),
            capture.routing(),
        )
        .await?;
        Ok(capture)
    }
    async fn stop(self) -> Result<(), TestError> {
        request_stop(&self.runtime)?;
        tokio::time::timeout(Duration::from_secs(10), self.task).await???;
        self.runtime.finish()?;
        Ok(())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn metric_discovery_capture_fences_held_range_and_next_prefix_or_retry()
-> Result<(), TestError> {
    for prom in [false, true] {
        for cause in ["rotate", "drop", "owner"] {
            tokio::time::timeout(Duration::from_secs(5), async {
                let prefix = if prom { PROM_PREFIX } else { TIDB_PREFIX };
                let fixture = kv_fixture::spawn_gated_fixture(Vec::new(), prefix, prom)
                    .await
                    .ok_or("KV fixture")?;
                let registry = OwnershipRegistry::new();
                let lease = registry.claim(OwnerScope::Process, "metric-discovery-held")?;
                let (publisher, _) = DiscoveryPublisher::new();
                let connector = counting_real_connector(&Arc::new(AtomicUsize::new(0)));
                let material = vec![(
                    Arc::from(CLUSTER_NAME),
                    EtcdClientConfig::new([fixture.addr.to_string()], None)?,
                )];
                let prepared = publisher
                    .prepare(&connector, &lease.token(), material.clone())
                    .await
                    .map_err(|error| format!("prepare: {error:?}"))?;
                let capture = publisher.commit(prepared);
                let retained = capture.clone();
                let poll = tokio::spawn(async move {
                    if prom {
                        capture.poll_prometheus(CLUSTER_NAME).await.map(|_| ())
                    } else {
                        capture
                            .poll_cluster_topology(CLUSTER_NAME)
                            .await
                            .map(|_| ())
                    }
                });
                fixture.arrived.notified().await;
                match cause {
                    "rotate" => {
                        let prepared = publisher
                            .prepare(&connector, &lease.token(), material)
                            .await
                            .map_err(|error| format!("prepare: {error:?}"))?;
                        publisher.commit(prepared);
                    }
                    "drop" => drop(publisher),
                    _ => drop(lease),
                }
                assert!(!retained.still_current(), "METRIC_DISCOVERY_HELD_REVOKED");
                fixture.release.notify_one();
                assert_eq!(
                    poll.await?.err(),
                    Some(DiscoveryError::Stale),
                    "METRIC_DISCOVERY_HELD_STALE_WINS"
                );
                assert_eq!(fixture.range_count(prefix), 1, "METRIC_DISCOVERY_NO_RETRY");
                assert_eq!(
                    fixture.range_count(KEYSPACE_PREFIX),
                    0,
                    "METRIC_DISCOVERY_NO_SECOND_PREFIX"
                );
                assert_eq!(
                    retained.poll_prometheus(CLUSTER_NAME).await.err(),
                    Some(DiscoveryError::Stale)
                );
                assert_eq!(
                    fixture.range_count(prefix),
                    1,
                    "retained capture issued no new I/O"
                );
                Ok::<_, TestError>(())
            })
            .await??;
        }
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::too_many_lines)]
async fn metric_module_noop_health_refresh_rejection_and_current_zone() -> Result<(), TestError> {
    let store =
        ConfigNamespaceStore::from_toml(&config_single(100), None, &std::env::current_dir()?)?;
    let (factory, make) = DynFactory::new(Arc::new(|| client(500, b"pem-a")));
    let counters = Counters::default();
    let connects = Arc::new(AtomicUsize::new(0));
    let health = HealthCheckConfig {
        interval_nanos: 20_000_000,
        ..disabled_health()
    };
    let (module, handle) = TopologyModule::new_with_child_runner_and_connector(
        Arc::new(store.clone()),
        Box::new(factory),
        Arc::new(StaticAdvertiseResolver::new("10.0.0.1")),
        identity(),
        health,
        counting_runner(&counters),
        counting_connector(&connects),
    )?;
    let mut running = MetricModule::start(module, handle)?;
    let first = running.initial().await?;
    let feed = running.handle.metric_source();
    let revision = feed.snapshot().1;
    let h = running.handle.health_overlay_handle();
    let h0 = h.current_for(first.routing()).ok_or("initial H")?;
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if h.current_for(first.routing())
                .is_some_and(|next| !Arc::ptr_eq(&next, &h0))
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await?;
    assert_eq!(feed.snapshot().1, revision, "METRIC_H_REFRESH_NO_REFEED");
    assert!(first.still_current());
    assert_eq!(
        first.routing().backends.backends.len(),
        1,
        "full R retained"
    );
    assert_eq!(first.policy().interval(), Duration::from_secs(5));

    let mut status = running.handle.status();
    store.apply_toml(
        b"[labels]\nzone=\"az-1\"",
        None,
        2,
        &std::env::current_dir()?,
    )?;
    wait_observed(&mut status, 2).await?;
    assert_eq!(
        feed.proxy_zone().as_deref(),
        Some("az-1"),
        "METRIC_ZONE_ONLY"
    );
    assert_eq!(
        feed.snapshot().1,
        revision,
        "zone is separate from material"
    );
    assert_eq!(connects.load(Ordering::SeqCst), 1);

    set_make(&make, Arc::new(|| bad_client(700)));
    store.apply_toml(
        b"[labels]\nzone=\"az-2\"",
        None,
        3,
        &std::env::current_dir()?,
    )?;
    let rejected = wait_observed(&mut status, 3).await?;
    assert_eq!(
        rejected.last_rejection,
        Some(RejectionClass::MetricClientBuildFailed),
        "METRIC_BUILD_REJECTED"
    );
    assert_eq!(rejected.applied_generation, 2);
    assert_eq!(
        feed.proxy_zone().as_deref(),
        Some("az-2"),
        "METRIC_ZONE_AFTER_REJECTED_CLUSTER"
    );
    assert_eq!(feed.snapshot().1, revision, "METRIC_REJECT_PRESERVES_FEED");
    assert!(first.still_current());
    assert_eq!(counters.stops(), 0);
    assert_eq!(
        connects.load(Ordering::SeqCst),
        1,
        "METRIC_REJECT_BURNS_NO_EPOCH"
    );

    set_make(&make, Arc::new(|| client(900, b"pem-a")));
    store.apply_toml(&config_single(200), None, 4, &std::env::current_dir()?)?;
    wait_observed(&mut status, 4).await?;
    assert!(!first.still_current());
    assert!(
        feed.capture().is_none(),
        "old R cannot pair with new material"
    );
    running.commands.send(epoch_result(1, 1))?;
    let next = metric_capture(&feed, 1, 2).await?;
    assert_eq!(connects.load(Ordering::SeqCst), 2);
    running.stop().await?;
    assert!(!next.still_current(), "METRIC_MODULE_STOP_REVOKES");
    assert!(feed.snapshot().2);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn metric_module_source_replacement_static_transition_and_abort() -> Result<(), TestError> {
    let initial =
        String::from_utf8(config_single(100))?.replace("[proxy]", "[proxy]\npd-addrs=\"\"");
    let store =
        ConfigNamespaceStore::from_toml(initial.as_bytes(), None, &std::env::current_dir()?)?;
    let (factory, _) = DynFactory::new(Arc::new(|| client(500, b"pem-a")));
    let (module, handle) = TopologyModule::new_with_child_runner_and_connector(
        Arc::new(store.clone()),
        Box::new(factory),
        Arc::new(StaticAdvertiseResolver::new("10.0.0.1")),
        identity(),
        disabled_health(),
        counting_runner(&Counters::default()),
        counting_connector(&Arc::new(AtomicUsize::new(0))),
    )?;
    let mut running = MetricModule::start(module, handle)?;
    let first = running.initial().await?;
    let feed = running.handle.metric_source();
    running.commands.send(epoch_result(0, 2))?;
    let second = metric_capture(&feed, 0, 2).await?;
    assert!(!first.still_current(), "METRIC_R_REPLACEMENT");
    assert!(second.still_current());
    let mut status = running.handle.status();
    // The array belongs to proxy; configuration merges omitted arrays, so make
    // the removal explicit rather than relying on the absence of TOML entries.
    store.apply_toml(
        b"[proxy]\npd-addrs=\"\"\nbackend-clusters=[]",
        None,
        2,
        &std::env::current_dir()?,
    )?;
    wait_observed(&mut status, 2).await?;
    assert_eq!(
        running.handle.applied_mode(),
        Some(BackendSourceMode::Static)
    );
    assert!(feed.capture().is_none(), "METRIC_STATIC_NO_CLUSTER_READER");
    assert!(!second.still_current());
    running.task.abort();
    assert!(running.task.await.is_err_and(|error| error.is_cancelled()));
    assert!(feed.snapshot().2, "METRIC_MODULE_ABORT_CLOSES_FEED");
    request_stop(&running.runtime)?;
    running.runtime.finish()?;
    Ok(())
}
