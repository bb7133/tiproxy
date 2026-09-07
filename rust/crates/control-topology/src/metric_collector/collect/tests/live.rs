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
use crate::metric_collector::tests::{Fixture, TestError, live_endpoints};
use crate::metrics::Source;
use std::net::SocketAddr;
use std::sync::PoisonError;
use std::sync::atomic::{AtomicUsize, Ordering};

const MEMORY: &str = "process_resident_memory_bytes 25\ntidb_server_memory_quota_bytes 100\n";
const EMPTY: &str = r#"{"status":"success","data":{"resultType":"matrix","result":[]}}"#;
const NONEMPTY: &str = r#"{"status":"success","data":{"resultType":"matrix","result":[{"metric":{"instance":"backend","tiproxy_cluster":"wrong"},"values":[[123.456,"0.25"]]}]}}"#;
async fn prom_endpoint(
    etcd: &mut etcd_client::Client,
    address: SocketAddr,
) -> Result<(), TestError> {
    etcd.put(
        "/topology/prometheus/collector",
        format!(r#"{{"ip":"127.0.0.1","port":{}}}"#, address.port()),
        None,
    )
    .await?;
    Ok(())
}
async fn backend(
    etcd: &mut etcd_client::Client,
    address: SocketAddr,
    zone: &str,
) -> Result<(), TestError> {
    let key = format!("/topology/tidb/{address}");
    etcd.put(
        format!("{key}/info"),
        format!(
            r#"{{"ip":"127.0.0.1","status_port":{},"labels":{{"zone":"{zone}"}}}}"#,
            address.port()
        ),
        None,
    )
    .await?;
    etcd.put(format!("{key}/ttl"), "1", None).await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires CP003_CONNECTION_FILE; mandatory collector gate"]
async fn collector_real_prom_round_labels_empty_and_delayed_source() -> Result<(), TestError> {
    tokio::time::timeout(Duration::from_secs(15), Box::pin(prom_rounds())).await??;
    println!("CP-METRIC-COLLECTOR Prom rounds passed");
    Ok(())
}
#[allow(clippy::too_many_lines)]
async fn prom_rounds() -> Result<(), TestError> {
    let (direct, _, _) = live_endpoints()?;
    let f = Fixture::new(&direct).await?;
    let capture = f.capture()?;
    let (collector, _) = f.bound().await?;
    let mut etcd = etcd_client::Client::connect([direct], None).await?;
    let body_mode = Arc::new(AtomicUsize::new(0));
    let mode = Arc::clone(&body_mode);
    let mut prom = Http::new(Arc::new(move |path| {
        let query = reqwest::Url::parse(&format!("http://loopback{path}"))
            .ok()
            .and_then(|url| {
                url.query_pairs()
                    .find(|(name, _)| name == "query")
                    .map(|(_, value)| value.into_owned())
            })
            .unwrap_or_default();
        if mode.load(Ordering::SeqCst) == 2
            || (mode.load(Ordering::SeqCst) == 0 && query.contains("job="))
        {
            EMPTY.into()
        } else {
            NONEMPTY.into()
        }
    }))
    .await?;
    let backend_http = Http::new(Arc::new(|_| MEMORY.into())).await?;
    backend(&mut etcd, backend_http.address, "").await?;
    prom_endpoint(&mut etcd, prom.address).await?;
    let (stop, rx) = watch::channel(false);
    let mut owner = owner::OwnerWorker::start(
        &collector.shared,
        capture.clone(),
        "collector-fixture".into(),
        String::new(),
        rx,
    );
    // Fix the actual local role before testing erroneous backend fallback;
    // campaign completion must not mask the successful-empty assertion.
    let _local = owner_ready(&owner).await?;
    let mut state = State::default();
    for round_id in 0..3 {
        body_mode.store(round_id, Ordering::SeqCst);
        round(
            &collector.shared,
            &capture,
            "collector-fixture",
            &[QueryId::Memory],
            &mut owner,
            &mut state,
        )
        .await
        .map_err(|e| format!("round: {e:?}"))?;
        assert_eq!(
            state.reader.source(),
            Source::Prometheus,
            "COLLECTOR_PROM_EMPTY_NO_FALLBACK"
        );
        assert_eq!(backend_http.count(), 0, "COLLECTOR_PROM_NO_BACKEND_IO");
        let expected = if round_id == 1 { 1 } else { 2 };
        for attempt in 0..expected {
            let path = prom.next().await?;
            let url = reqwest::Url::parse(&format!("http://loopback{path}"))?;
            let query = url
                .query_pairs()
                .find(|(name, _)| name == "query")
                .ok_or("query")?
                .1
                .into_owned();
            assert!(
                query.contains(if attempt == 0 { "job=" } else { "component=" }),
                "COLLECTOR_PROM_LABEL_RESETS_EACH_ROUND"
            );
        }
        assert_eq!(
            state
                .reader
                .get(QueryId::Memory)
                .ok_or("memory")?
                .is_empty(),
            round_id == 2
        );
    }
    // Refresh the actual etcd endpoint record; both range queries share one end,
    // while completion timestamps come from their individual actual responses.
    let second = Http::new(Arc::new(|_| NONEMPTY.into())).await?;
    prom_endpoint(&mut etcd, second.address).await?;
    let results = read_prom(
        &capture,
        "collector-fixture",
        &[QueryId::Cpu, QueryId::Memory],
    )
    .await
    .map_err(|e| format!("prom: {e:?}"))?;
    assert_eq!(second.count(), 2, "COLLECTOR_PROM_ENDPOINT_REFRESH");
    let paths = second
        .paths
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone();
    let end = |path: &str| -> Result<String, TestError> {
        Ok(reqwest::Url::parse(&format!("http://loopback{path}"))?
            .query_pairs()
            .find(|(key, _)| key == "end")
            .ok_or("end")?
            .1
            .into_owned())
    };
    assert_eq!(
        end(&paths[0])?,
        end(&paths[1])?,
        "COLLECTOR_PROM_SHARED_ROUND_END"
    );
    assert!(
        results[&QueryId::Cpu].updated_nanos < results[&QueryId::Memory].updated_nanos,
        "COLLECTOR_PROM_PER_QUERY_UPDATE"
    );
    assert_eq!(
        results[&QueryId::Memory].series[0].labels["tiproxy_cluster"],
        "collector-fixture"
    );
    let mut delayed = Http::new(Arc::new(|_| NONEMPTY.into())).await?;
    delayed.hold();
    prom_endpoint(&mut etcd, delayed.address).await?;
    let task_capture = capture.clone();
    let request = tokio::spawn(async move {
        read_prom(&task_capture, "collector-fixture", &[QueryId::Memory]).await
    });
    delayed.next().await?;
    f.publication.withdraw_material();
    delayed.release();
    assert!(
        matches!(request.await?, Err(RoundError::Stale)),
        "COLLECTOR_DELAYED_PROM_SOURCE_REJECTED"
    );
    stop.send_replace(true);
    owner.stop().await;
    etcd.delete("/topology/prometheus/collector", None).await?;
    etcd.delete(
        format!("/topology/tidb/{}/", backend_http.address),
        Some(etcd_client::DeleteOptions::new().with_prefix()),
    )
    .await?;
    Ok(())
}

async fn json_get(http: &reqwest::Client, url: String) -> Result<serde_json::Value, TestError> {
    Ok(serde_json::from_slice(
        &http
            .get(url)
            .send()
            .await?
            .error_for_status()?
            .bytes()
            .await?,
    )?)
}
async fn owner_ready(owner: &owner::OwnerWorker) -> Result<Arc<owner::LocalOwner>, TestError> {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if let Some(local) = owner.capture_role().captured.clone() {
                return local;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .map_err(Into::into)
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires real Go peer and CP003_CONNECTION_FILE; mandatory collector gate"]
async fn collector_real_go_rust_owner_history_and_peer_replacement() -> Result<(), TestError> {
    tokio::time::timeout(Duration::from_secs(20), Box::pin(mixed_owners())).await??;
    tokio::time::timeout(Duration::from_secs(10), Box::pin(delayed_backend())).await??;
    println!("CP-METRIC-COLLECTOR actual Go Rust owner history passed");
    Ok(())
}

async fn delayed_backend() -> Result<(), TestError> {
    let (direct, _, _) = live_endpoints()?;
    let f = Fixture::new(&direct).await?;
    let capture = f.capture()?;
    let (collector, overlay) = f.bound().await?;
    let mut etcd = etcd_client::Client::connect([direct], None).await?;
    let mut backend_http = Http::new(Arc::new(|_| MEMORY.into())).await?;
    backend(&mut etcd, backend_http.address, "").await?;
    let (stop, receiver) = watch::channel(false);
    let owner = owner::OwnerWorker::start(
        &collector.shared,
        capture.clone(),
        "collector-fixture".into(),
        String::new(),
        receiver,
    );
    let _local = owner_ready(&owner).await?;
    let mut state = State::default();
    backend_http.hold();
    let shared = Arc::clone(&collector.shared);
    let task_capture = capture.clone();
    let delayed = tokio::spawn(async move {
        let outcome = backend_round(
            &shared,
            &task_capture,
            "collector-fixture",
            &[QueryId::Memory],
            &owner,
            &mut state,
        )
        .await;
        (owner, state, outcome)
    });
    assert_eq!(backend_http.next().await?, "/metrics");
    f.publication.withdraw_material();
    backend_http.release();
    let (owner, state, outcome) = delayed.await?;
    assert!(
        matches!(outcome, Err(RoundError::Stale)),
        "COLLECTOR_DELAYED_BACKEND_SOURCE_REJECTED"
    );
    assert!(state.history.entries().is_empty());
    assert!(overlay.current_for(&capture).is_none());
    assert_eq!(backend_http.count(), 1, "no obsolete fallback or retry");
    stop.send_replace(true);
    owner.stop().await;
    etcd.delete(
        format!("/topology/tidb/{}/", backend_http.address),
        Some(etcd_client::DeleteOptions::new().with_prefix()),
    )
    .await?;
    Ok(())
}
#[allow(clippy::too_many_lines)]
async fn mixed_owners() -> Result<(), TestError> {
    let (direct, proxy, _) = live_endpoints()?;
    let peer: serde_json::Value = serde_json::from_slice(&std::fs::read(std::env::var(
        "CPMETRICS_COLLECTOR_PEER_FILE",
    )?)?)?;
    let control = peer["control_url"].as_str().ok_or("peer control")?;
    let go_address = peer["owner_address"].as_str().ok_or("Go address")?;
    let http = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(3))
        .build()?;
    json_get(&http, format!("{control}/campaign?zone=")).await?;
    json_get(&http, format!("{control}/campaign?zone=east")).await?;
    let f = Fixture::new(&proxy).await?;
    let capture = f.capture()?;
    let (mut collector, overlay) = f.bound().await?;
    let address = collector.local_addr();
    let server = tokio::spawn(service::serve(
        collector.listener.take().ok_or("listener")?,
        Arc::clone(&collector.shared),
    ));
    let mut etcd = etcd_client::Client::connect([direct], None).await?;
    let east = Http::new(Arc::new(|_| MEMORY.into())).await?;
    let west_value = Arc::new(AtomicUsize::new(25));
    let served_value = Arc::clone(&west_value);
    let west = Http::new(Arc::new(move |_| {
        format!(
            "process_resident_memory_bytes {}\ntidb_server_memory_quota_bytes 100\n",
            served_value.load(Ordering::SeqCst)
        )
    }))
    .await?;
    let uncovered = Http::new(Arc::new(|_| MEMORY.into())).await?;
    for (backend_http, zone) in [(&east, "east"), (&west, "west"), (&uncovered, "uncovered")] {
        backend(&mut etcd, backend_http.address, zone).await?;
    }
    let produced = json_get(
        &http,
        format!(
            "{control}/produce?backend={}",
            service::encode_query(&east.address.to_string())
        ),
    )
    .await?;
    assert!(
        produced["memory"][east.address.to_string()]["Step2History"].is_array(),
        "COLLECTOR_ACTUAL_GO_PRODUCER"
    );
    let (stop, rx) = watch::channel(false);
    let owner = owner::OwnerWorker::start(
        &collector.shared,
        capture.clone(),
        "collector-fixture".into(),
        "west".into(),
        rx,
    );
    let local = owner_ready(&owner).await?;
    let prefix = cluster_prefix("collector-fixture");
    let records = capture
        .poll_metric_owners("collector-fixture", &prefix)
        .await?;
    assert_eq!(records.len(), 3, "COLLECTOR_PRESENCE_OUTSIDE_OWNER_PREFIX");
    assert!(
        records.iter().all(|r| r.lease > 0
            && r.created > 0
            && String::from_utf8_lossy(&r.key).contains("/owner/")),
        "COLLECTOR_MIXED_ACTUAL_RECIPE_KEYS"
    );
    let selected = select_owners(&prefix, records);
    assert_eq!(
        String::from_utf8_lossy(&selected["west"].value),
        address.to_string(),
        "COLLECTOR_RUST_ADVERTISES_ACTUAL_BINDING"
    );
    assert_eq!(
        String::from_utf8_lossy(&selected["east"].value),
        go_address,
        "COLLECTOR_RUST_OBSERVES_GO"
    );
    let go_observed = json_get(&http, format!("{control}/enumerate")).await?;
    assert_eq!(
        go_observed["zones"],
        serde_json::json!(["east", "west"]),
        "COLLECTOR_GO_OBSERVES_RUST_ZONES"
    );
    assert_eq!(
        go_observed["addresses"]
            .as_array()
            .ok_or("addresses")?
            .len(),
        2,
        "COLLECTOR_MIXED_ADDRESS_DEDUP"
    );
    assert!(
        go_observed["addresses"]
            .as_array()
            .ok_or("addresses")?
            .contains(&serde_json::json!(address.to_string()))
    );
    let mut state = State::default();
    backend_round(
        &collector.shared,
        &capture,
        "collector-fixture",
        &[QueryId::Memory],
        &owner,
        &mut state,
    )
    .await
    .map_err(|e| format!("backend round: {e:?}"))?;
    assert_eq!(east.count(), 1, "COLLECTOR_ZONE_OWNER_NOT_READ_TWICE");
    assert_eq!(west.count(), 1, "COLLECTOR_OWN_ZONE_READ");
    assert_eq!(uncovered.count(), 1, "COLLECTOR_UNCOVERED_ZONE_READ");
    let result = state.reader.get(QueryId::Memory).ok_or("memory")?;
    assert_eq!(result.series.len(), 3, "COLLECTOR_GO_HISTORY_MERGED");
    assert!(overlay.current_for(&capture).is_some(), "backend snapshot");
    let returned = json_get(
        &http,
        format!(
            "{control}/consume?address={}",
            service::encode_query(&address.to_string())
        ),
    )
    .await?;
    let returned = returned["memory"].as_object().ok_or("Go history")?;
    assert_eq!(
        returned.len(),
        2,
        "COLLECTOR_GO_CONSUMES_RUST_SELECTED_HISTORY"
    );
    assert!(
        returned.contains_key(&west.address.to_string())
            && returned.contains_key(&uncovered.address.to_string())
    );
    assert!(
        !returned.contains_key(&east.address.to_string()),
        "COLLECTOR_EXPORT_ONLY_OWNER_SELECTED"
    );
    // An old peer sample still suppresses fallback for ANY registered rule,
    // even though the following purge expires it. These calls exercise Go's
    // real history serialization and C's actual round ordering.
    json_get(&http, format!("{control}/age")).await?;
    state.reset_backend();
    let west_before = west.count();
    let uncovered_before = uncovered.count();
    backend_round(
        &collector.shared,
        &capture,
        "collector-fixture",
        &[QueryId::Cpu, QueryId::Memory],
        &owner,
        &mut state,
    )
    .await
    .map_err(|e| format!("expired round: {e:?}"))?;
    assert_eq!(
        west.count(),
        west_before + 1,
        "COLLECTOR_ANY_RULE_PREVENTS_FALLBACK"
    );
    assert_eq!(
        uncovered.count(),
        uncovered_before + 1,
        "COLLECTOR_ANY_RULE_UNCOVERED_FALLBACK"
    );
    assert_eq!(east.count(), 1, "COLLECTOR_MISSING_BEFORE_PURGE");
    assert_eq!(
        state
            .reader
            .get(QueryId::Memory)
            .ok_or("memory after purge")?
            .series
            .len(),
        2,
        "COLLECTOR_PURGES_EXPIRED_PEER_SAMPLE"
    );
    json_get(
        &http,
        format!(
            "{control}/produce?backend={}",
            service::encode_query(&east.address.to_string())
        ),
    )
    .await?;
    let snapshot = overlay
        .current_for(&capture)
        .ok_or("snapshot before replacement")?;
    // Unknown remote changes are not fabricated retirement. The next actual
    // enumeration observes a new full tuple and revokes the retained snapshot.
    let old_east = selected["east"].clone();
    json_get(&http, format!("{control}/retire?zone=east")).await?;
    json_get(&http, format!("{control}/campaign?zone=east")).await?;
    assert!(
        snapshot.still_current(),
        "COLLECTOR_UNOBSERVED_PEER_NOT_INVENTED_RETIREMENT"
    );
    let actual = select_owners(
        &prefix,
        capture
            .poll_metric_owners("collector-fixture", &prefix)
            .await?,
    );
    assert_ne!(actual["east"].lease, old_east.lease);
    assert_ne!(actual["east"].created, old_east.created);
    assert_eq!(actual["east"].value, old_east.value);
    let observed = observe_owners(&capture, "collector-fixture", &mut state.observation)
        .await
        .map_err(|e| format!("owners: {e:?}"))?;
    assert!(
        capture.still_current() && local.authority.capture_work().is_some(),
        "R material local session held fixed"
    );
    assert!(
        !snapshot.still_current(),
        "COLLECTOR_OBSERVED_PEER_REPLACEMENT_REVOKES"
    );
    assert_ne!(observed.members["east"].lease, old_east.lease);
    assert_ne!(observed.members["east"].created, old_east.created);
    assert_eq!(observed.members["east"].value, old_east.value);
    assert_eq!(
        snapshot.with_current(|| 7),
        None,
        "COLLECTOR_PEER_FINAL_PUBLICATION"
    );
    backend_round(
        &collector.shared,
        &capture,
        "collector-fixture",
        &[QueryId::Memory],
        &owner,
        &mut state,
    )
    .await
    .map_err(|e| format!("replaced round: {e:?}"))?;
    assert_eq!(
        state.history.entries()["memory"][&west.address.to_string()]
            .step1
            .len(),
        1,
        "COLLECTOR_PEER_COLD_START"
    );
    let held_snapshot = overlay.current_for(&capture).ok_or("held snapshot")?;
    json_get(&http, format!("{control}/hold-history")).await?;
    let task_shared = Arc::clone(&collector.shared);
    let task_capture = capture.clone();
    let delayed = tokio::spawn(async move {
        let outcome = backend_round(
            &task_shared,
            &task_capture,
            "collector-fixture",
            &[QueryId::Memory],
            &owner,
            &mut state,
        )
        .await;
        (owner, state, outcome)
    });
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if json_get(&http, format!("{control}/history-state")).await?["entered"] == true {
                return Ok::<_, TestError>(());
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await??;
    json_get(&http, format!("{control}/retire?zone=east")).await?;
    json_get(&http, format!("{control}/campaign?zone=east")).await?;
    json_get(&http, format!("{control}/release-history")).await?;
    let (owner, mut state, outcome) = delayed.await?;
    assert!(
        matches!(outcome, Err(RoundError::Stale)),
        "COLLECTOR_PEER_RECHECK_AFTER_HELD_HTTP"
    );
    assert!(capture.still_current() && local.authority.capture_work().is_some());
    assert!(
        !held_snapshot.still_current(),
        "COLLECTOR_HELD_PEER_REPLACEMENT_REVOKES"
    );
    backend_round(
        &collector.shared,
        &capture,
        "collector-fixture",
        &[QueryId::Memory],
        &owner,
        &mut state,
    )
    .await
    .map_err(|e| format!("final round: {e:?}"))?;
    west_value.store(50, Ordering::SeqCst);
    json_get(&http, format!("{control}/fail-history?enabled=true")).await?;
    backend_round(
        &collector.shared,
        &capture,
        "collector-fixture",
        &[QueryId::Memory],
        &owner,
        &mut state,
    )
    .await
    .map_err(|e| format!("completed peer error round: {e:?}"))?;
    let samples = state
        .reader
        .get(QueryId::Memory)
        .ok_or("selected backend result")?
        .samples_for(&west.address.to_string(), "collector-fixture")
        .ok_or("west samples")?;
    assert!(
        (samples.last().ok_or("last sample")?.value - 0.5).abs() < f64::EPSILON,
        "COLLECTOR_COMPLETED_ERROR_REPLACES_BACKEND_MAP"
    );
    assert_eq!(state.reader.source(), Source::Backend);
    json_get(&http, format!("{control}/fail-history?enabled=false")).await?;
    let retained = overlay.current_for(&capture).ok_or("new snapshot")?;
    stop.send_replace(true);
    assert!(
        !retained.still_current(),
        "COLLECTOR_STOP_DIRECT_SCOPE_WITHDRAWAL"
    );
    owner.stop().await;
    assert!(local.authority.capture_work().is_none());
    server.abort();
    let _ = server.await;
    for backend_http in [&east, &west, &uncovered] {
        etcd.delete(
            format!("/topology/tidb/{}/", backend_http.address),
            Some(etcd_client::DeleteOptions::new().with_prefix()),
        )
        .await?;
    }
    for zone in ["east", ""] {
        json_get(&http, format!("{control}/retire?zone={zone}")).await?;
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires CP003_CONNECTION_FILE; mandatory collector gate"]
async fn collector_real_immediate_first_round() -> Result<(), TestError> {
    let (direct, _, _) = live_endpoints()?;
    let f = Fixture::new(&direct).await?;
    let capture = f.capture()?;
    assert_eq!(capture.policy().interval(), Duration::from_secs(5));
    let (collector, overlay) = f.bound().await?;
    overlay.add_query(QueryId::Memory);
    let mut prom = Http::new(Arc::new(|_| NONEMPTY.into())).await?;
    let mut etcd = etcd_client::Client::connect([direct], None).await?;
    prom_endpoint(&mut etcd, prom.address).await?;
    let (stop, receiver) = watch::channel(false);
    let task = tokio::spawn(run_cluster(
        Arc::clone(&collector.shared),
        capture,
        "collector-fixture".into(),
        receiver,
    ));
    let first = tokio::time::timeout(Duration::from_secs(2), prom.requests.recv()).await;
    assert!(
        matches!(first, Ok(Some(_))),
        "COLLECTOR_IMMEDIATE_FIRST_READ"
    );
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(prom.count(), 1, "COLLECTOR_PINNED_INTERVAL_NO_BUSY_LOOP");
    stop.send_replace(true);
    tokio::time::timeout(Duration::from_secs(3), task).await??;
    etcd.delete("/topology/prometheus/collector", None).await?;
    // This row can stop before campaign returns a session. Dispose only this
    // fixture's possible unacquired recipe lease, which otherwise expires by TTL.
    let prefix = cluster_prefix("collector-fixture");
    let records = etcd
        .get(prefix, Some(etcd_client::GetOptions::new().with_prefix()))
        .await?;
    for record in records.kvs() {
        etcd.lease_revoke(record.lease()).await?;
    }
    println!("CP-METRIC-COLLECTOR immediate first round passed");
    Ok(())
}
