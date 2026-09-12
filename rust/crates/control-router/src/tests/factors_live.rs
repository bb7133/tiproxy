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

//! Owned real etcd, Prometheus/backend HTTP, topology, collector and router.

use super::*;
use control_topology::metrics::QueryId;
use control_topology::{MetricCollector, MetricOverlayHandle, MetricSnapshot, MetricSourceHandle};
use std::net::SocketAddr;
use std::sync::atomic::AtomicU64;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinSet;

fn backend_body(request: &str) -> String {
    if request.starts_with("GET /status ") {
        r#"{"version":"8"}"#.into()
    } else {
        "process_cpu_seconds_total 100\ntidb_server_maxprocs 1\nprocess_resident_memory_bytes 20\ntidb_server_memory_quota_bytes 100\n".into()
    }
}

struct Greeting {
    address: SocketAddr,
    task: JoinHandle<()>,
}
impl Drop for Greeting {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Greeting {
    async fn new() -> TestResult<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let task = tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                let _ = socket.write_all(&[3, 0, 0, 0, 0x0a, b'8', 0]).await;
            }
        });
        Ok(Self { address, task })
    }
}

struct Http {
    address: SocketAddr,
    task: JoinHandle<()>,
}
impl Drop for Http {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Http {
    async fn new(body: Arc<dyn Fn(&str) -> String + Send + Sync>) -> TestResult<Self> {
        Self::gated(body, watch::channel(true).1).await
    }
    async fn gated(
        body: Arc<dyn Fn(&str) -> String + Send + Sync>,
        release: watch::Receiver<bool>,
    ) -> TestResult<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let task = tokio::spawn(async move {
            let mut workers = JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let Ok((mut socket, _)) = accepted else { break; };
                        let body = Arc::clone(&body);
                        let mut release = release.clone();
                        workers.spawn(async move {
                            let mut head = Vec::new();
                            while !head.ends_with(b"\r\n\r\n") && head.len() < 8192 {
                                let mut byte = [0];
                                if socket.read_exact(&mut byte).await.is_err() { return; }
                                head.push(byte[0]);
                            }
                            if release.wait_for(|released| *released).await.is_err() { return; }
                            let body = body(&String::from_utf8_lossy(&head));
                            let wire = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
                            let _ = socket.write_all(wire.as_bytes()).await;
                        });
                    }
                    _ = workers.join_next(), if !workers.is_empty() => {}
                }
            }
            workers.shutdown().await;
        });
        Ok(Self { address, task })
    }
}

struct MaterialFactory {
    endpoint: String,
    timeout: Arc<AtomicU64>,
}
impl TopologyClientFactory for MaterialFactory {
    fn build(
        &self,
        snapshot: &ConfigNamespaceSnapshot,
    ) -> Result<Vec<TopologyClusterClient>, String> {
        let timeout = self.timeout.load(Ordering::SeqCst);
        let client = EtcdClientConfig::new([self.endpoint.clone()], None)
            .map_err(|error| error.to_string())?
            .with_timeouts(
                Duration::from_secs(2),
                Duration::from_millis(timeout),
                Duration::from_secs(2),
                Duration::from_millis(100),
                Duration::from_secs(1),
            )
            .map_err(|error| error.to_string())?;
        Ok(snapshot
            .topology()
            .map_err(|error| error.to_string())?
            .backend_clusters
            .iter()
            .map(|cluster| TopologyClusterClient {
                cluster_name: Arc::clone(&cluster.name),
                client: client.clone(),
            })
            .collect())
    }
}

struct Running {
    runtime: ControlRuntime,
    module: JoinHandle<()>,
    collector: JoinHandle<()>,
}
impl Drop for Running {
    fn drop(&mut self) {
        self.collector.abort();
        self.module.abort();
    }
}

async fn current(
    feed: &MetricSourceHandle,
    overlay: &MetricOverlayHandle,
    after: i64,
) -> TestResult<(MetricSnapshot, i64)> {
    tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            if let Some(capture) = feed.capture()
                && let Some(snapshot) = overlay.current_for(&capture)
                && let Some(query) = snapshot.query_result(QueryId::Memory)?
                && let Some(updated) = query.updated_nanos
                && updated > after
            {
                return Ok((snapshot, updated));
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await?
}
fn cpu(report: &crate::FactorReport, id: &str) -> u64 {
    report
        .rows
        .iter()
        .find(|row| row.backend_id.as_ref() == id)
        .and_then(|row| {
            row.parts
                .iter()
                .find(|(factor, _)| *factor == crate::Factor::Cpu)
        })
        .map_or(u64::MAX, |(_, score)| *score)
}
async fn report(
    router: &Router,
    feed: &MetricSourceHandle,
    overlay: &MetricOverlayHandle,
    after: i64,
) -> TestResult<(MetricSnapshot, crate::FactorReport, i64)> {
    tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            let (snapshot, observed_time) = current(feed, overlay, after).await?;
            if let Ok(report) = router.factor_report(&snapshot, ClientInfo::default(), "") {
                return Ok((snapshot, report, observed_time));
            }
            tokio::task::yield_now().await;
        }
    })
    .await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires owned CP003_CONNECTION_FILE; mandatory factor evidence"]
async fn factor_real_producer_cache_and_authority() -> TestResult {
    tokio::time::timeout(Duration::from_secs(40), Box::pin(observe())).await??;
    println!("CP-METRIC-FACTORS real producer ledger continuity and authority passed");
    Ok(())
}

#[allow(clippy::too_many_lines)]
async fn observe() -> TestResult {
    let Live {
        mut etcd,
        backend,
        backend_b,
        addresses,
        ids,
        mode,
        prom_key,
        prom_info,
        store,
        timeout,
        topology,
        feed,
        overlay,
        mut running,
        endpoint,
        _greetings,
        _prom,
        prom_release: _,
    } = start(false).await?;
    let router = must(Router::new(
        Arc::new(store.clone()),
        &topology,
        &running.runtime.handle().module_context(),
        "default",
        100,
    ));
    let mut sessions = Vec::new();
    for (index, address) in addresses.iter().enumerate() {
        for count in 0..12 {
            let session = must(router.open());
            let reservation = tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    if let Ok(candidate) = router.capture()
                        && let Ok(reservation) = router.reserve(
                            &session,
                            &candidate,
                            ClientInfo::default(),
                            "",
                            &[&ids[1 - index]],
                        )
                    {
                        break reservation;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await?;
            assert_eq!(reservation.assignment().backend_address, *address);
            if count < 10 {
                assert_eq!(router.finish(&reservation, true), Settlement::Applied);
            }
            sessions.push(session);
        }
    }
    store.apply_toml(
        b"[balance]\npolicy=\"resource\"",
        None,
        3,
        Path::new("/tmp"),
    )?;
    let (first, scored, first_time) = report(&router, &feed, &overlay, 0)
        .await
        .map_err(|error| format!("initial report: {error}"))?;
    assert!(
        matches!(
            router.capture(),
            Err(RouteError::Unsupported(Unsupported::ResourcePolicy))
        ),
        "FACTOR_SELECTOR_REMAINS_UNSUPPORTED"
    );
    assert_eq!(
        cpu(&scored, &ids[0]),
        6,
        "FACTOR_REAL_PENDING_EXTRAPOLATION"
    );
    assert!(
        scored
            .rows
            .iter()
            .all(|row| row.parts.contains(&(crate::Factor::Location, 0))),
        "FACTOR_REAL_H_LOCAL"
    );
    let health = scored
        .rows
        .iter()
        .find(|row| row.backend_id.as_ref() == ids[0])
        .ok_or("health row")?;
    assert!(
        health.parts.contains(&(crate::Factor::Health, 2))
            && health.parts.contains(&(crate::Factor::Status, 0)),
        "FACTOR_REAL_HEALTH_RISK_SEPARATE_FROM_H"
    );
    let lineage = first.cache_lineage("default").ok_or("lineage")?;
    // Both sides remain current: only exact R pairing can reject this donor.
    let foreign = Harness::new("", "resource").await?;
    let foreign_source = foreign
        .topology
        .backend_source("default")
        .ok_or("foreign source")?;
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some(before) = foreign_source.current() {
                let (donor, _) = current(&feed, &overlay, 0).await?;
                let attempt = foreign
                    .router
                    .factor_report(&donor, ClientInfo::default(), "");
                if donor.still_current() && foreign_source.still_current(&before) {
                    assert!(attempt.is_err(), "FACTOR_FOREIGN_CURRENT_R_REJECTED");
                    return Ok::<_, Box<dyn std::error::Error + Send + Sync>>(());
                }
            }
            tokio::task::yield_now().await;
        }
    })
    .await??;
    mode.store(1, Ordering::SeqCst);
    let (second, scored, second_time) = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let (snapshot, report, observed_time) =
                report(&router, &feed, &overlay, first_time).await?;
            if snapshot.query_result(QueryId::Cpu)?.is_some_and(|query| {
                query
                    .samples_for(&backend.address.to_string(), "default")
                    .is_none()
            }) {
                return Ok::<_, Box<dyn std::error::Error + Send + Sync>>((
                    snapshot,
                    report,
                    observed_time,
                ));
            }
        }
    })
    .await??;
    assert!(
        lineage.same_history(&second.cache_lineage("default").ok_or("next lineage")?),
        "FACTOR_SAME_SOURCE_CONTINUITY"
    );
    assert_eq!(cpu(&scored, &ids[0]), 6, "FACTOR_REAL_MISSING_REUSES_CACHE");
    assert!(
        router
            .factor_report(&first, ClientInfo::default(), "")
            .is_err(),
        "FACTOR_OLD_ROUND_REJECTED"
    );
    // A real source switch starts new cache provenance; query time is newer,
    // backend IDs and ledger owners stay the same.
    etcd.delete(prom_key, None).await?;
    let switched = tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            let (snapshot, _, _) = report(&router, &feed, &overlay, second_time).await?;
            if !lineage.same_history(&snapshot.cache_lineage("default").ok_or("backend lineage")?) {
                return Ok::<_, Box<dyn std::error::Error + Send + Sync>>(snapshot);
            }
        }
    })
    .await??;
    let initial_backend_lineage = switched.cache_lineage("default").ok_or("backend lineage")?;
    let (_, old_feed_revision, _) = feed.snapshot();
    store.apply_toml(
        b"[labels]\nzone=\"factor-zone\"",
        None,
        4,
        Path::new("/tmp"),
    )?;
    let (zoned, zoned_time) = tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            let (snapshot, _, observed_time) = report(&router, &feed, &overlay, 0).await?;
            if !initial_backend_lineage
                .same_history(&snapshot.cache_lineage("default").ok_or("zone lineage")?)
            {
                return Ok::<_, Box<dyn std::error::Error + Send + Sync>>((
                    snapshot,
                    observed_time,
                ));
            }
        }
    })
    .await??;
    assert_eq!(
        feed.snapshot().1,
        old_feed_revision,
        "FACTOR_ZONE_WITHOUT_MATERIAL"
    );
    assert!(
        !switched.still_current(),
        "FACTOR_ZONE_RETIRES_OLD_OWNER_RESULT"
    );
    let backend_lineage = zoned.cache_lineage("default").ok_or("backend lineage")?;
    etcd.put(prom_key, prom_info, None).await?;
    let (restored, scored) = tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            let (snapshot, report, _) = report(&router, &feed, &overlay, zoned_time).await?;
            if snapshot.query_result(QueryId::Cpu)?.is_some_and(|query| {
                query
                    .samples_for(&backend_b.address.to_string(), "default")
                    .and_then(|samples| samples.last())
                    .is_some_and(|sample| (sample.value - 0.8).abs() < f64::EPSILON)
            }) {
                return Ok::<_, Box<dyn std::error::Error + Send + Sync>>((snapshot, report));
            }
        }
    })
    .await??;
    assert!(
        !backend_lineage.same_history(
            &restored
                .cache_lineage("default")
                .ok_or("restored lineage")?
        ),
        "FACTOR_SOURCE_ABA_NEW_LINEAGE"
    );
    assert_eq!(
        cpu(&scored, &ids[0]),
        20,
        "FACTOR_CROSS_LINEAGE_NO_CACHE_REUSE"
    );
    assert_eq!(router.accounting(&ids[0]).ok_or("counts")?.active(), 10);
    assert_eq!(router.accounting(&ids[0]).ok_or("counts")?.reserved(), 2);
    let retained = restored.cache_lineage("default").ok_or("lineage")?;
    timeout.store(700, Ordering::SeqCst);
    store.apply_toml(
        b"[labels]\nzone=\"material-rotation\"",
        None,
        5,
        Path::new("/tmp"),
    )?;
    let (_material_renewed, _) = tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            let (snapshot, report, _) = report(&router, &feed, &overlay, 0).await?;
            if !retained.same_history(
                &snapshot
                    .cache_lineage("default")
                    .ok_or("new material lineage")?,
            ) {
                return Ok::<_, Box<dyn std::error::Error + Send + Sync>>((snapshot, report));
            }
        }
    })
    .await??;
    assert!(
        router
            .factor_report(&restored, ClientInfo::default(), "")
            .is_err(),
        "FACTOR_RETIRED_MATERIAL_REJECTED"
    );
    mode.store(2, Ordering::SeqCst);
    store.apply_toml(format!("[proxy]\npd-addrs=\"\"\n[[proxy.backend-clusters]]\nname=\"default\"\npd-addrs=\"{endpoint}\"\n[[proxy.backend-clusters]]\nname=\"sibling\"\npd-addrs=\"{endpoint}\"").as_bytes(), None, 6, Path::new("/tmp"))?;
    let (renewed, multi) = tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            let (snapshot, result, _) = report(&router, &feed, &overlay, 0).await?;
            if result.rows.len() == 4
                && snapshot
                    .query_result(QueryId::Cpu)?
                    .is_some_and(|query| query.series.len() == 4)
            {
                return Ok::<_, Box<dyn std::error::Error + Send + Sync>>((snapshot, result));
            }
        }
    })
    .await??;
    for cluster in ["default", "sibling"] {
        assert_eq!(
            cpu(&multi, &format!("{cluster}/{}", addresses[0])),
            20,
            "FACTOR_REAL_TWO_CLUSTER_STALE_SAMPLE"
        );
        assert!(
            multi
                .rows
                .iter()
                .any(|row| row.backend_id.starts_with(cluster)),
            "FACTOR_REAL_CLUSTER_IDENTITY"
        );
    }
    assert_eq!(
        router
            .accounting(&ids[0])
            .ok_or("retained counts")?
            .active(),
        10,
        "FACTOR_MULTI_CLUSTER_LEDGER_OWNER"
    );
    running.collector.abort();
    tokio::time::timeout(Duration::from_secs(3), async {
        while renewed.still_current() {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    assert!(
        router
            .factor_report(&renewed, ClientInfo::default(), "")
            .is_err(),
        "FACTOR_FINAL_COLLECTOR_FENCE"
    );
    for session in &sessions {
        router.close(session);
    }
    running.runtime.begin_shutdown(ShutdownReason::Requested)?;
    running.runtime.advance_shutdown(LifecyclePhase::Draining)?;
    running.runtime.advance_shutdown(LifecyclePhase::Stopping)?;
    let _ = (&mut running.collector).await;
    tokio::time::timeout(Duration::from_secs(5), &mut running.module).await??;
    etcd.delete(
        "/topology/",
        Some(etcd_client::DeleteOptions::new().with_prefix()),
    )
    .await?;
    Ok(())
}

struct Live {
    etcd: etcd_client::Client,
    backend: Http,
    backend_b: Http,
    _greetings: [Greeting; 2],
    _prom: Http,
    addresses: [String; 2],
    ids: [String; 2],
    mode: Arc<AtomicU64>,
    prom_key: &'static str,
    prom_info: String,
    prom_release: watch::Sender<bool>,
    store: ConfigNamespaceStore,
    timeout: Arc<AtomicU64>,
    topology: TopologyModuleHandle,
    feed: MetricSourceHandle,
    overlay: MetricOverlayHandle,
    running: Running,
    endpoint: String,
}

async fn start(routing: bool) -> TestResult<Live> {
    start_with_health(routing, 50_000_000, "").await
}

#[allow(clippy::too_many_lines)]
async fn start_with_health(
    routing: bool,
    health_interval_nanos: i64,
    initial_labels: &str,
) -> TestResult<Live> {
    let endpoints: serde_json::Value =
        serde_json::from_slice(&std::fs::read(std::env::var("CP003_CONNECTION_FILE")?)?)?;
    let endpoint = endpoints["etcd_endpoint"]
        .as_str()
        .ok_or("etcd endpoint")?
        .to_owned();
    let mut etcd = etcd_client::Client::connect([endpoint.clone()], None).await?;
    let backend = Http::new(Arc::new(backend_body)).await?;
    let greeting_a = Greeting::new().await?;
    let greeting_b = Greeting::new().await?;
    let addresses = [
        greeting_a.address.to_string(),
        greeting_b.address.to_string(),
    ];
    let ids = addresses
        .each_ref()
        .map(|address| format!("default/{address}"));
    for (index, address) in addresses.iter().enumerate() {
        etcd.put(
            format!("/topology/tidb/{address}/info"),
            format!(
                r#"{{"ip":"127.0.0.1","status_port":{},"labels":{{"zone":"z{}"}}}}"#,
                backend.address.port(),
                index
            ),
            None,
        )
        .await?;
        etcd.put(format!("/topology/tidb/{address}/ttl"), "1", None)
            .await?;
    }
    // Use distinct operator labels while both real backend requests reach one
    // owned server. Instance labels are status endpoints, never routing IDs.
    let status_a = backend.address.to_string();
    // Distinct status IPs require a second real listener for unambiguous lookup.
    let backend_b = Http::new(Arc::new(backend_body)).await?;
    etcd.put(
        format!("/topology/tidb/{}/info", addresses[1]),
        format!(
            r#"{{"ip":"127.0.0.1","status_port":{}}}"#,
            backend_b.address.port()
        ),
        None,
    )
    .await?;
    let status_b = backend_b.address.to_string();
    let mode = Arc::new(AtomicU64::new(0));
    let prom_mode = Arc::clone(&mode);
    let prom_release = watch::channel(true).0;
    let prom = Http::gated(Arc::new(move |request| {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |time| time.as_secs());
        let cpu = request.contains("irate");
        let matrix = request.contains("query_range");
        let failure = request.contains("failed_cmds") || request.contains("backoff_seconds");
        let values = if cpu { ["0.2", "0.8"] } else if matrix { ["0.2", "0.2"] }
            else if failure { ["5", "0"] } else { ["10", "10"] };
        let mut series = Vec::new();
        for (index, instance) in [&status_a, &status_b].iter().enumerate() {
            if cpu && index == 0 && prom_mode.load(Ordering::SeqCst) == 1 {
                continue;
            }
            let sample_time = if cpu && index == 0 && prom_mode.load(Ordering::SeqCst) == 2 { now - 121 } else { now };
            series.push(if matrix {
                serde_json::json!({"metric":{"instance":instance},"values":[[sample_time,values[index]]]})
            } else {
                serde_json::json!({"metric":{"instance":instance},"value":[sample_time,values[index]]})
            });
        }
        serde_json::json!({"status":"success","data":{"resultType":if matrix { "matrix" } else { "vector" },"result":series}})
            .to_string()
    }), prom_release.subscribe())
    .await?;
    let prom_key = "/topology/prometheus/factor-evidence";
    let prom_info = format!(r#"{{"ip":"127.0.0.1","port":{}}}"#, prom.address.port());
    etcd.put(prom_key, prom_info.clone(), None).await?;
    let store = ConfigNamespaceStore::from_toml(
        format!("[proxy]\npd-addrs=\"\"\n[[proxy.backend-clusters]]\nname=\"default\"\npd-addrs=\"{endpoint}\"\n[balance]\npolicy=\"connection\"\n{initial_labels}").as_bytes(),
        None,
        Path::new("/tmp"),
    )?;
    let initial = store.current();
    store.apply(
        (**initial.effective()).clone(),
        vec![NamespaceConfig {
            namespace: "default".into(),
            ..NamespaceConfig::default()
        }],
        SourceRevision {
            file_revision: 2,
            etcd_revision: 0,
        },
        Path::new("/tmp"),
    )?;
    let registry = OwnershipRegistry::new();
    let runtime = ControlRuntime::claim_process(
        &registry,
        "factor-live",
        ControlConfig::new(
            1,
            Duration::from_secs(30),
            0,
            TlsPolicy::default(),
            LogLevel::Info,
            MetricsPolicy::default(),
        )?,
        Arc::new(NullSink),
    )?;
    runtime.mark_ready()?;
    let timeout = Arc::new(AtomicU64::new(500));
    let (module, mut topology) = TopologyModule::new(
        Arc::new(store.clone()),
        Box::new(MaterialFactory {
            endpoint: endpoint.clone(),
            timeout: Arc::clone(&timeout),
        }),
        Arc::new(StaticAdvertiseResolver::new("127.0.0.1")),
        TopologyRuntimeIdentity {
            version: "test".into(),
            git_hash: "test".into(),
            deploy_path: "/tmp".into(),
            start_timestamp: 1,
        },
        HealthCheckConfig {
            enabled: true,
            interval_nanos: health_interval_nanos,
            metrics_interval_nanos: 200_000_000,
            ..HealthCheckConfig::default()
        },
    )?;
    let module = module.with_metrics()?;
    let context = runtime.handle().module_context();
    let module = tokio::spawn(async move {
        let _ = Box::new(module).run(context).await;
    });
    tokio::time::timeout(Duration::from_secs(5), topology.wait_ready()).await??;
    let feed = topology.metric_source();
    let (collector, overlay) = if routing {
        MetricCollector::bind_for_routing(feed.clone(), "127.0.0.1:0".parse()?).await?
    } else {
        let bound = MetricCollector::bind(feed.clone(), "127.0.0.1:0".parse()?).await?;
        for query in control_topology::metrics::query_catalog() {
            bound.1.add_query(query.id);
        }
        bound
    };
    let context = runtime.handle().module_context();
    let collector = tokio::spawn(async move {
        let _ = Box::new(collector).run(context).await;
    });
    let running = Running {
        runtime,
        module,
        collector,
    };
    Ok(Live {
        etcd,
        backend,
        backend_b,
        addresses,
        ids,
        mode,
        prom_key,
        prom_info,
        prom_release,
        store,
        timeout,
        topology,
        feed,
        overlay,
        running,
        endpoint,
        _greetings: [greeting_a, greeting_b],
        _prom: prom,
    })
}

#[cfg(test)]
#[path = "resource_live.rs"]
mod resource_live;
