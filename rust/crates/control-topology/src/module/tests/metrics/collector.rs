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
use crate::metric_collector::test_http::Http;
use crate::metrics::QueryId;
use crate::{MetricCollector, MetricOverlayHandle, MetricSnapshot};

async fn ready_metrics(
    overlay: &MetricOverlayHandle,
    capture: &MetricCapture,
) -> Result<MetricSnapshot, TestError> {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some(value) = overlay.current_for(capture)
                && value.query_result(QueryId::Memory)?.is_some()
            {
                return Ok(value);
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await?
}
async fn exported(
    http: &reqwest::Client,
    address: std::net::SocketAddr,
) -> Result<serde_json::Value, TestError> {
    let bytes = http
        .get(format!(
            "http://{address}/api/backend/metrics?cluster=cluster-a"
        ))
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .await?;
    if bytes.is_empty() {
        Ok(serde_json::Value::Null)
    } else {
        Ok(serde_json::from_slice(&bytes)?)
    }
}
async fn owner_in_zone(
    etcd: &mut etcd_client::Client,
    zone: &str,
) -> Result<(Vec<u8>, i64), TestError> {
    let prefix = if zone.is_empty() {
        "/tiproxy/metric_reader/cluster-a/owner/".to_owned()
    } else {
        format!("/tiproxy/metric_reader/cluster-a/{zone}/owner/")
    };
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let records = etcd
                .get(
                    prefix.clone(),
                    Some(etcd_client::GetOptions::new().with_prefix()),
                )
                .await?;
            if let Some(kv) = records.kvs().first() {
                return Ok::<_, TestError>((kv.key().into(), kv.lease()));
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires CP003_CONNECTION_FILE; mandatory collector gate"]
async fn collector_real_module_zone_material_lifecycle() -> Result<(), TestError> {
    tokio::time::timeout(Duration::from_secs(30), Box::pin(observe())).await??;
    println!("CP-METRIC-COLLECTOR real module lifecycle passed");
    Ok(())
}
#[allow(clippy::too_many_lines)]
async fn observe() -> Result<(), TestError> {
    let endpoints: serde_json::Value =
        serde_json::from_slice(&std::fs::read(std::env::var("CP003_CONNECTION_FILE")?)?)?;
    let direct = endpoints["etcd_endpoint"].as_str().ok_or("direct")?;
    let proxy = endpoints["proxy_endpoint"]
        .as_str()
        .ok_or("proxy")?
        .to_owned();
    let control = endpoints["control_url"].as_str().ok_or("control")?;
    let http = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(3))
        .build()?;
    let mut etcd = etcd_client::Client::connect([direct], None).await?;
    let backend = Http::new(Arc::new(|_| {
        "process_resident_memory_bytes 25\ntidb_server_memory_quota_bytes 100\n".into()
    }))
    .await?;
    let prefix = format!("/topology/tidb/{}/", backend.address);
    etcd.put(
        format!("{prefix}info"),
        format!(
            r#"{{"ip":"127.0.0.1","status_port":{}}}"#,
            backend.address.port()
        ),
        None,
    )
    .await?;
    etcd.put(format!("{prefix}ttl"), "1", None).await?;
    let store =
        ConfigNamespaceStore::from_toml(&config_single(100), None, &std::env::current_dir()?)?;
    let source_proxy = proxy.clone();
    let (factory, make) = DynFactory::new(Arc::new(move || {
        live::live_client(source_proxy.clone(), 3000)
    }));
    let policy = HealthCheckConfig {
        metrics_interval_nanos: 50_000_000,
        interval_nanos: 20_000_000,
        ..disabled_health()
    };
    let (module, handle) = TopologyModule::new(
        Arc::new(store.clone()),
        Box::new(factory),
        Arc::new(StaticAdvertiseResolver::new("127.0.0.1")),
        identity(),
        policy,
    )?;
    let mut running = MetricModule::start(module, handle)?;
    let capture = running.initial().await?;
    let feed = running.handle.metric_source();
    let (collector, overlay) = MetricCollector::bind(feed.clone(), "127.0.0.1:0".parse()?).await?;
    overlay.add_query(QueryId::Memory);
    let address = collector.local_addr();
    let task = tokio::spawn(Box::new(collector).run(running.runtime.handle().module_context()));
    let _first = ready_metrics(&overlay, &capture).await?;
    let (global_key, global_lease) = owner_in_zone(&mut etcd, "").await?;
    let label = backend.address.to_string();
    let samples = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let wire = exported(&http, address).await?;
            if let Some(pairs) = wire["memory"][&label]["Step1History"].as_array()
                && pairs.len() >= 3
            {
                return Ok::<_, TestError>(pairs.len());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await??;
    assert!(samples >= 3, "COLLECTOR_H_REFRESH_PRESERVES_HISTORY");
    assert!(
        capture.still_current(),
        "H refresh leaves actual R/material fixed"
    );
    let revision = feed.snapshot().1;
    let mut status = running.handle.status();
    store.apply_toml(
        b"[labels]\nzone=\"az-1\"",
        None,
        2,
        &std::env::current_dir()?,
    )?;
    wait_observed(&mut status, 2).await?;
    let (_, first_zone_lease) = owner_in_zone(&mut etcd, "az-1").await?;
    assert_eq!(
        feed.snapshot().1,
        revision,
        "COLLECTOR_ZONE_ROTATES_WITHOUT_MATERIAL"
    );
    assert_ne!(
        global_lease, first_zone_lease,
        "COLLECTOR_ZONE_NEW_ELECTION"
    );
    assert!(
        etcd.get(global_key, None).await?.kvs().is_empty(),
        "COLLECTOR_ZONE_OLD_RECIPE_REMOVED"
    );
    assert!(
        etcd.lease_time_to_live(global_lease, None).await?.ttl() <= 0,
        "COLLECTOR_ZONE_OLD_LEASE_CLEANED"
    );
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
        Some(RejectionClass::MetricClientBuildFailed)
    );
    let (_, second_zone_lease) = owner_in_zone(&mut etcd, "az-2").await?;
    assert_ne!(
        first_zone_lease, second_zone_lease,
        "COLLECTOR_REJECTED_CLUSTER_APPLIES_COMMITTED_ZONE"
    );
    assert!(capture.still_current());
    assert_eq!(feed.snapshot().1, revision);
    // Recipe creation precedes campaign completion. Wait for a committed local
    // owner export so this row tests cleanup of an acquired session, separately
    // from the campaign-cancellation path whose lease expires by TTL.
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let wire = exported(&http, address).await?;
            if wire["memory"][&label]["Step1History"].is_array() {
                return Ok::<_, TestError>(());
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await??;
    let old = ready_metrics(&overlay, &capture).await?;
    // Hold the actual owner/registration cleanup while the module accepts new
    // material. R and H stay fixed; C must stop serving the old result directly.
    http.post(format!("{control}/hold-cleanup?rpc=LeaseRevoke"))
        .send()
        .await?
        .error_for_status()?;
    let replaced_proxy = proxy.clone();
    set_make(
        &make,
        Arc::new(move || live::live_client(replaced_proxy.clone(), 3100)),
    );
    store.apply_toml(&config_single(200), None, 4, &std::env::current_dir()?)?;
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let value: serde_json::Value = serde_json::from_slice(
                &http
                    .get(format!("{control}/cleanup-state"))
                    .send()
                    .await?
                    .bytes()
                    .await?,
            )?;
            if value["entered"] == true {
                return Ok::<_, TestError>(());
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await??;
    assert!(
        running
            .handle
            .routing_handle()
            .still_current(capture.routing())
    );
    assert!(
        !old.still_current(),
        "COLLECTOR_MODULE_EARLY_MATERIAL_WITHDRAWAL"
    );
    assert_eq!(
        old.with_current(|| 7),
        None,
        "COLLECTOR_MODULE_FINAL_PUBLICATION"
    );
    let status_code = http
        .get(format!(
            "http://{address}/api/backend/metrics?cluster=cluster-a"
        ))
        .send()
        .await?
        .status();
    assert_eq!(
        status_code,
        reqwest::StatusCode::SERVICE_UNAVAILABLE,
        "COLLECTOR_MODULE_NO_RETIRED_HTTP_EXPORT"
    );
    http.post(format!("{control}/release-cleanup"))
        .send()
        .await?
        .error_for_status()?;
    wait_observed(&mut status, 4).await?;
    running.commands.send(epoch_result(1, 1))?;
    let next = metric_capture(&feed, 1, 2).await?;
    let renewed = ready_metrics(&overlay, &next).await?;
    assert!(
        etcd.lease_time_to_live(second_zone_lease, None)
            .await?
            .ttl()
            <= 0,
        "COLLECTOR_MODULE_SCOPE_REMOTE_CLEANUP"
    );
    assert!(!old.still_current(), "COLLECTOR_MODULE_SOURCE_ABA");
    // Abort owns the collector future: serving withdrawal must not await a
    // parent consumer or an election task being scheduled again.
    task.abort();
    let _ = task.await;
    assert!(!renewed.still_current(), "COLLECTOR_MODULE_ABORT_WITHDRAWS");
    assert!(overlay.current_for(&next).is_none());
    running.stop().await?;
    backend.release();
    etcd.delete(
        prefix,
        Some(etcd_client::DeleteOptions::new().with_prefix()),
    )
    .await?;
    Ok(())
}
