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
use crate::MetricCollector;
use crate::metric_collector::tests::live_endpoints;
use control_etcd::{ElectionConfig, ElectionError, ElectionState, RetirementReason};
use control_external::IoFence;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn election(name: &str, address: SocketAddr) -> Result<ElectionConfig, TestError> {
    Ok(ElectionConfig::new(
        format!("/tiproxy/collector-service/{name}/owner"),
        address.to_string(),
        format!("/tiproxy/collector-presence/{name}"),
        15,
    )?)
}
async fn get(address: SocketAddr, path: &str) -> Result<Vec<u8>, TestError> {
    let mut client = TcpStream::connect(address).await?;
    client
        .write_all(format!("GET {path} HTTP/1.1\r\nHost: loopback\r\n\r\n").as_bytes())
        .await?;
    let mut bytes = Vec::new();
    client.read_to_end(&mut bytes).await?;
    Ok(bytes)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires CP003_CONNECTION_FILE; mandatory collector gate"]
async fn collector_real_scoped_cleanup_and_retained_http() -> Result<(), TestError> {
    tokio::time::timeout(Duration::from_secs(30), Box::pin(observe())).await??;
    println!("CP-METRIC-COLLECTOR scoped cleanup and retained HTTP passed");
    Ok(())
}
#[allow(clippy::too_many_lines)]
async fn observe() -> Result<(), TestError> {
    let (direct, proxy, control) = live_endpoints()?;
    let http = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(3))
        .build()?;
    let mut observer = etcd_client::Client::connect([direct], None).await?;
    for method in ["Resign", "LeaseRevoke"] {
        let f = Fixture::new(&proxy).await?;
        let capture = f.capture()?;
        let (collector, overlay) = f.bound().await?;
        let gate = Arc::new(GenerationGate::new());
        let mut session = Box::pin(capture.campaign_metric_owner(
            "collector-fixture",
            election(method, collector.local_addr())?,
            Arc::clone(&gate) as Arc<dyn IoFence>,
        ))
        .await?;
        let authority = session.authority();
        let work = authority.capture_work().ok_or("work")?;
        let lease = session.snapshot().lease_id;
        let mut value = result();
        let local = owner::LocalOwner::from_session(&session);
        value.owner = Some(Arc::clone(&local));
        value.backend_proofs = vec![owner::Proof::Local(local)];
        if method == "LeaseRevoke" {
            value
                .reader
                .complete_prom(std::collections::BTreeMap::new());
        }
        assert!(
            collector
                .shared
                .publish(&capture, "collector-fixture", value, Some(&work))
        );
        let response =
            Response::capture(&collector.shared, "collector-fixture").ok_or("response")?;
        let before: serde_json::Value = serde_json::from_slice(
            &http
                .get(format!("{control}/cleanup-state"))
                .send()
                .await?
                .bytes()
                .await?,
        )?;
        let snapshot = overlay.current_for(&capture).ok_or("metric snapshot")?;
        gate.revoke();
        assert!(
            capture.still_current(),
            "source held fixed for session scope"
        );
        assert!(
            !authority.retains_local_ownership() && !work.still_current(),
            "COLLECTOR_SCOPE_DIRECT_AUTHORITY"
        );
        assert_eq!(
            snapshot.still_current(),
            method == "LeaseRevoke",
            "COLLECTOR_PROM_NOT_OWNER_DEPENDENT"
        );
        assert_eq!(
            response.with_current(|| 7),
            None,
            "COLLECTOR_HTTP_SCOPE_WRITE_FENCE"
        );
        assert!(
            matches!(session.keep_alive().await, Err(ElectionError::StaleScope)),
            "COLLECTOR_SCOPE_KEEPALIVE_RETIRES"
        );
        assert_eq!(
            session.snapshot().retirement_reason,
            Some(RetirementReason::ScopeRevoked)
        );
        let after: serde_json::Value = serde_json::from_slice(
            &http
                .get(format!("{control}/cleanup-state"))
                .send()
                .await?
                .bytes()
                .await?,
        )?;
        assert_eq!(
            before["started"], after["started"],
            "COLLECTOR_SCOPE_ZERO_NEW_RPC"
        );
        assert_eq!(
            before["forwarded"], after["forwarded"],
            "COLLECTOR_SCOPE_ZERO_KEEPALIVE_FRAME"
        );
        http.post(format!("{control}/hold-cleanup?rpc={method}"))
            .send()
            .await?
            .error_for_status()?;
        let shutdown = tokio::spawn(session.shutdown());
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let state: serde_json::Value = serde_json::from_slice(
                    &http
                        .get(format!("{control}/cleanup-state"))
                        .send()
                        .await?
                        .bytes()
                        .await?,
                )?;
                if state["entered"] == true {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            Ok::<_, TestError>(())
        })
        .await??;
        assert!(
            observer.lease_time_to_live(lease, None).await?.ttl() > 0,
            "COLLECTOR_CLEANUP_IS_ACTUALLY_HELD"
        );
        http.post(format!("{control}/release-cleanup"))
            .send()
            .await?
            .error_for_status()?;
        shutdown.await??;
        assert!(
            observer.lease_time_to_live(lease, None).await?.ttl() <= 0,
            "COLLECTOR_SCOPE_REMOTE_CLEANUP_REQUIRED"
        );
        assert!(
            !authority.retains_local_ownership() && !work.still_current(),
            "COLLECTOR_SCOPE_NEVER_REVIVES"
        );
    }
    let f = Fixture::new(&proxy).await?;
    let capture = f.capture()?;
    let (mut collector, _) = f.bound().await?;
    let binding = Arc::clone(&collector.shared.serving);
    let mut session = Box::pin(capture.campaign_metric_owner(
        "collector-fixture",
        election("uncertain", collector.local_addr())?,
        Arc::clone(&binding) as Arc<dyn IoFence>,
    ))
    .await?;
    let authority = session.authority();
    let old_work = authority.capture_work().ok_or("work")?;
    let mut value = result();
    let local = owner::LocalOwner::from_session(&session);
    value.owner = Some(Arc::clone(&local));
    value.backend_proofs = vec![owner::Proof::Local(local)];
    assert!(
        collector
            .shared
            .publish(&capture, "collector-fixture", value, Some(&old_work))
    );
    let response = Response::capture(&collector.shared, "collector-fixture").ok_or("response")?;
    let listener = collector.listener.take().ok_or("real listener")?;
    let server = tokio::spawn(serve(listener, Arc::clone(&collector.shared)));
    http.post(format!("{control}/stop"))
        .send()
        .await?
        .error_for_status()?;
    assert!(session.keep_alive().await.is_err());
    assert_eq!(session.snapshot().state, ElectionState::Uncertain);
    assert!(authority.retains_local_ownership());
    assert!(!old_work.still_current());
    assert!(
        !collector
            .shared
            .publish(&capture, "collector-fixture", result(), Some(&old_work)),
        "COLLECTOR_UNCERTAIN_FINAL_WORK_REJECTED"
    );
    assert_eq!(
        response.with_current(|| 7),
        Some(7),
        "COLLECTOR_HTTP_UNCERTAIN_RETAINED"
    );
    let bytes = get(
        collector.local_addr(),
        "/api/backend/metrics?cluster=collector-fixture",
    )
    .await?;
    assert!(
        bytes.ends_with(b"\r\n\r\n{}"),
        "COLLECTOR_HTTP_ACTUAL_UNCERTAIN_BODY"
    );
    http.post(format!("{control}/start"))
        .send()
        .await?
        .error_for_status()?;
    session.recover().await?;
    assert!(
        !old_work.still_current(),
        "COLLECTOR_RECOVERY_OLD_WORK_REJECTED"
    );
    assert!(authority.capture_work().is_some());
    server.abort();
    let _ = server.await;
    assert!(
        capture.still_current(),
        "source fixed across listener failure"
    );
    assert!(!binding.is_live(), "COLLECTOR_LISTENER_DROP_REVOKES");
    assert!(
        !authority.retains_local_ownership(),
        "COLLECTOR_LISTENER_SCOPE_DIRECT"
    );
    assert_eq!(
        response.with_current(|| 7),
        None,
        "COLLECTOR_HTTP_LISTENER_WRITE_FENCE"
    );
    session.shutdown().await?;
    // A real binding exists but is not activated: no owner can advertise it.
    let (unready, _) = MetricCollector::bind(f.handle.clone(), "127.0.0.1:0".parse()?).await?;
    let before: serde_json::Value = serde_json::from_slice(
        &http
            .get(format!("{control}/cleanup-state"))
            .send()
            .await?
            .bytes()
            .await?,
    )?;
    let result = Box::pin(capture.campaign_metric_owner(
        "collector-fixture",
        election("unready", unready.local_addr())?,
        Arc::clone(&unready.shared.serving) as Arc<dyn IoFence>,
    ))
    .await;
    assert!(
        matches!(result, Err(ElectionError::StaleScope)),
        "COLLECTOR_NO_CAMPAIGN_BEFORE_SERVING"
    );
    let after: serde_json::Value = serde_json::from_slice(
        &http
            .get(format!("{control}/cleanup-state"))
            .send()
            .await?
            .bytes()
            .await?,
    )?;
    assert_eq!(
        before["started"], after["started"],
        "COLLECTOR_UNREADY_ZERO_RPC"
    );
    assert!(
        observer
            .get(
                "/tiproxy/collector-service/unready/",
                Some(etcd_client::GetOptions::new().with_prefix())
            )
            .await?
            .kvs()
            .is_empty()
    );
    Ok(())
}
