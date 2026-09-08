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
use control_etcd::{ElectionConfig, ElectionSession};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{Semaphore, mpsc};

struct HeldHttp {
    port: u16,
    entered: mpsc::UnboundedReceiver<String>,
    release: Arc<Semaphore>,
    task: tokio::task::JoinHandle<()>,
}
impl HeldHttp {
    async fn new(requests: usize) -> Result<Self, TestError> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        let (entered, rx) = mpsc::unbounded_channel();
        let release = Arc::new(Semaphore::new(0));
        let gate = Arc::clone(&release);
        let task = tokio::spawn(async move {
            let mut workers = tokio::task::JoinSet::new();
            for _ in 0..requests {
                let Ok((mut socket, _)) = listener.accept().await else {
                    return;
                };
                let entered = entered.clone();
                let release = Arc::clone(&gate);
                workers.spawn(async move {
                    let mut head = Vec::new();
                    while head.len() < 8192 && !head.ends_with(b"\r\n\r\n") {
                        let mut byte = [0u8; 1];
                        if socket.read_exact(&mut byte).await.is_err() {
                            return;
                        }
                        head.extend(byte);
                    }
                    let _ = entered.send(
                        String::from_utf8_lossy(&head)
                            .lines()
                            .next()
                            .unwrap_or("")
                            .to_owned(),
                    );
                    let Ok(permit) = release.acquire().await else {
                        return;
                    };
                    permit.forget();
                    // Real HTTP success with a held response-header boundary.
                    let _ = socket
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
                        )
                        .await;
                });
            }
            while let Some(result) = workers.join_next().await {
                assert!(result.is_ok(), "HTTP fixture child failed");
            }
        });
        Ok(Self {
            port,
            entered: rx,
            release,
            task,
        })
    }
    async fn arrived(&mut self) -> Result<String, TestError> {
        Ok(
            tokio::time::timeout(Duration::from_secs(3), self.entered.recv())
                .await?
                .ok_or("HTTP fixture closed")?,
        )
    }
    async fn finish(self, count: usize) -> Result<(), TestError> {
        self.release.add_permits(count);
        tokio::time::timeout(Duration::from_secs(3), self.task).await??;
        Ok(())
    }
}

pub(super) fn live_client(endpoint: String, request_ms: u64) -> EtcdClientConfig {
    EtcdClientConfig::new([endpoint], None)
        .and_then(|config| {
            config.with_timeouts(
                Duration::from_secs(1),
                Duration::from_millis(request_ms),
                Duration::from_secs(1),
                Duration::from_millis(500),
                Duration::from_secs(1),
            )
        })
        .unwrap_or_else(|error| unreachable!("fixture material: {error}"))
}

async fn live_session(
    owner: &super::super::super::OwnerToken,
    endpoint: &str,
    name: &str,
) -> Result<ElectionSession, TestError> {
    let root = format!("/tiproxy/cpmetric-applied/{}/{name}", std::process::id());
    Ok(ElectionSession::campaign(
        owner.clone(),
        live_client(endpoint.to_owned(), 2000),
        ElectionConfig::new(
            format!("{root}/owner"),
            "127.0.0.1:10080",
            format!("{root}/presence"),
            15,
        )?,
    )
    .await?)
}

/// Mandatory entrypoint runs this against a fresh real embedded-etcd fixture.
/// R is deliberately command-driven to hold its actual Arc, H and mode fixed
/// while the real registration child's `LeaseRevoke` is blocked in the proxy.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires CP003_CONNECTION_FILE; mandatory cpmetrics applied gate"]
async fn metric_module_real_etcd_cleanup_and_delayed_http() -> Result<(), TestError> {
    tokio::time::timeout(Duration::from_secs(25), Box::pin(observe())).await??;
    println!("CP-METRIC-APPLIED all live rows passed");
    Ok(())
}

#[allow(clippy::too_many_lines)]
async fn observe() -> Result<(), TestError> {
    let fixture: serde_json::Value =
        serde_json::from_slice(&std::fs::read(std::env::var("CP003_CONNECTION_FILE")?)?)?;
    let direct = fixture["etcd_endpoint"].as_str().ok_or("etcd endpoint")?;
    let proxy = fixture["proxy_endpoint"]
        .as_str()
        .ok_or("proxy endpoint")?
        .to_owned();
    let control = fixture["control_url"].as_str().ok_or("control URL")?;
    let http = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(3))
        .build()?;
    http.post(format!("{control}/release-cleanup"))
        .send()
        .await?
        .error_for_status()?;
    let mut observer = etcd_client::Client::connect([direct], None).await?;
    // A deliberately killed mutation can leave a lease awaiting TTL expiry.
    // The dedicated fixture has no other users; remove that prior registration
    // before observing the next process's real initial lease.
    observer
        .delete(crate::register::info_key("127.0.0.1:6000"), None)
        .await?;
    let store =
        ConfigNamespaceStore::from_toml(&config_single(100), None, &std::env::current_dir()?)?;
    let initial_proxy = proxy.clone();
    let (factory, make) =
        DynFactory::new(Arc::new(move || live_client(initial_proxy.clone(), 3000)));
    let (module, handle) = TopologyModule::new(
        Arc::new(store.clone()),
        Box::new(factory),
        Arc::new(StaticAdvertiseResolver::new("127.0.0.1")),
        identity(),
        disabled_health(),
    )?;
    let mut running = MetricModule::start(module, handle)?;
    let old = running.initial().await?;
    let owner = running.runtime.handle().module_context().owner().clone();
    let feed = running.handle.metric_source();
    let discovery = running
        .handle
        .discovery_handle()
        .capture()
        .map_err(|error| format!("discovery capture: {error:?}"))?;
    let routing = running.handle.routing_handle();
    let health = running.handle.health_overlay_handle();
    let h0 = health
        .current_for(old.routing())
        .ok_or("H before cleanup")?;
    let info_key = crate::register::info_key("127.0.0.1:6000");
    let registered_lease = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let response = observer.get(info_key.clone(), None).await?;
            if let Some(kv) = response.kvs().first() {
                return Ok::<_, TestError>(kv.lease());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await??;
    assert!(registered_lease > 0, "METRIC_REAL_REGISTRATION_LEASE");

    observer
        .put(
            "/topology/prometheus/applied",
            r#"{"ip":"127.0.0.1","port":9090}"#,
            None,
        )
        .await?;
    observer
        .put(
            "/topology/tidb/10.0.0.0:4000/info",
            r#"{"ip":"10.0.0.0","status_port":10080}"#,
            None,
        )
        .await?;
    observer
        .put("/topology/tidb/10.0.0.0:4000/ttl", "1", None)
        .await?;
    assert_eq!(
        old.poll_prometheus("cluster-a").await?.port,
        9090,
        "METRIC_REAL_PROM_DISCOVERY"
    );
    assert_eq!(
        old.poll_cluster_topology("cluster-a").await?.backends.len(),
        1,
        "METRIC_FULL_TOPOLOGY_READ"
    );

    // An actual ElectionWorkPermit is revoked independently of all feed inputs.
    let session = live_session(&owner, direct, "work").await?;
    let permit = session
        .authority()
        .capture_work()
        .ok_or("actual work permit")?;
    let mut server = HeldHttp::new(1).await?;
    let task_capture = old.clone();
    let task_permit = permit.clone();
    let port = server.port;
    let request = tokio::spawn(async move {
        task_capture
            .get_cluster_once(
                "cluster-a",
                "127.0.0.1",
                port,
                &HttpTarget::new("/metrics")?,
                &task_permit,
            )
            .await
    });
    assert_eq!(server.arrived().await?, "GET /metrics HTTP/1.1");
    session.shutdown().await?;
    assert!(
        old.still_current(),
        "material/source held fixed for work fence"
    );
    server.finish(1).await?;
    assert!(
        matches!(request.await?, Err(MetricReadError::Stale)),
        "METRIC_ACTUAL_WORK_HTTP_FENCE"
    );
    let blocked = TcpListener::bind("127.0.0.1:0").await?;
    assert!(
        matches!(
            old.get_cluster_once(
                "cluster-a",
                "127.0.0.1",
                blocked.local_addr()?.port(),
                &HttpTarget::status(),
                &permit
            )
            .await,
            Err(MetricReadError::Stale)
        ),
        "METRIC_ACTUAL_WORK_RETRY_FENCE"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(30), blocked.accept())
            .await
            .is_err(),
        "METRIC_ACTUAL_WORK_ZERO_IO"
    );

    let current_session = live_session(&owner, direct, "material").await?;
    let current_work = current_session
        .authority()
        .capture_work()
        .ok_or("new work permit")?;
    let mut server = HeldHttp::new(3).await?;
    let port = server.port;
    let mut requests = tokio::task::JoinSet::new();
    for target in [
        "/metrics",
        "/api/backend/metrics?cluster=cluster-a",
        "/api/v1/query?query=up",
    ] {
        let capture = old.clone();
        let work = current_work.clone();
        requests.spawn(async move {
            let path = HttpTarget::new(target)?;
            if target.starts_with("/api/v1/") {
                capture.get_prom_once("127.0.0.1", port, &path).await
            } else {
                capture
                    .get_cluster_once("cluster-a", "127.0.0.1", port, &path, &work)
                    .await
            }
        });
    }
    for _ in 0..3 {
        let _ = server.arrived().await?;
    }
    http.post(format!("{control}/hold-cleanup?rpc=LeaseRevoke"))
        .send()
        .await?
        .error_for_status()?;
    set_make(&make, Arc::new(move || live_client(proxy.clone(), 3100)));
    store.apply_toml(&config_single(200), None, 2, &std::env::current_dir()?)?;
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let state: serde_json::Value = serde_json::from_slice(
                &http
                    .get(format!("{control}/cleanup-state"))
                    .send()
                    .await?
                    .error_for_status()?
                    .bytes()
                    .await?,
            )?;
            if state["entered"] == true {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        Ok::<_, TestError>(())
    })
    .await??;
    assert!(owner.is_current() && current_work.still_current());
    assert!(
        routing.still_current(old.routing()),
        "R fixed across real cleanup hold"
    );
    assert!(
        health.still_current_for(&h0, old.routing(), &routing),
        "H retains its existing cleanup ordering"
    );
    assert!(
        discovery.still_current(),
        "old discovery remains published until cleanup completes"
    );
    assert_eq!(
        running.handle.applied_mode(),
        Some(BackendSourceMode::Dynamic)
    );
    assert!(!old.still_current(), "METRIC_REAL_CLEANUP_EARLY_REVOKE");
    assert!(
        feed.capture().is_none(),
        "METRIC_REAL_CLEANUP_FEED_WITHDRAWN"
    );
    assert_eq!(
        old.with_current(|| 1),
        None,
        "METRIC_REAL_FINAL_PUBLICATION"
    );
    server.finish(3).await?;
    while let Some(result) = requests.join_next().await {
        assert!(
            matches!(result?, Err(MetricReadError::Stale)),
            "METRIC_DELAYED_PROM_BACKEND_PEER_REVOKED"
        );
    }
    http.post(format!("{control}/release-cleanup"))
        .send()
        .await?
        .error_for_status()?;
    let mut status = running.handle.status();
    wait_observed(&mut status, 2).await?;
    assert!(
        observer
            .lease_time_to_live(registered_lease, None)
            .await?
            .ttl()
            <= 0,
        "METRIC_REAL_CLEANUP_REMOVES_OLD_LEASE"
    );
    assert!(!discovery.still_current(), "METRIC_CAPTURE_NOT_REDIRECTED");
    running.commands.send(epoch_result(1, 1))?;
    let next = metric_capture(&feed, 1, 2).await?;
    assert_eq!(next.poll_prometheus("cluster-a").await?.port, 9090);
    assert!(
        !old.still_current(),
        "METRIC_MATERIAL_ABA_NEVER_REQUALIFIES"
    );
    // Return to byte-identical A material with the same backend contents. The
    // real module commits a third discovery/R incarnation, never old authority.
    let restored_proxy = fixture["proxy_endpoint"]
        .as_str()
        .ok_or("proxy endpoint")?
        .to_owned();
    set_make(
        &make,
        Arc::new(move || live_client(restored_proxy.clone(), 3000)),
    );
    store.apply_toml(&config_single(100), None, 3, &std::env::current_dir()?)?;
    wait_observed(&mut status, 3).await?;
    running.commands.send(epoch_result(2, 1))?;
    let restored = metric_capture(&feed, 2, 3).await?;
    assert_eq!(old.routing().backends, restored.routing().backends);
    assert!(!Arc::ptr_eq(old.routing(), restored.routing()));
    assert!(
        !old.still_current() && !next.still_current(),
        "METRIC_REAL_A_B_A_AUTHORITY"
    );
    assert_eq!(restored.poll_prometheus("cluster-a").await?.port, 9090);
    current_session.shutdown().await?;
    running.stop().await?;
    assert!(!restored.still_current());
    observer
        .delete("/topology/prometheus/applied", None)
        .await?;
    observer
        .delete(
            "/topology/tidb/10.0.0.0:4000/",
            Some(etcd_client::DeleteOptions::new().with_prefix()),
        )
        .await?;
    Ok(())
}
