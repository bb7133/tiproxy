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

//! Shared fixtures use the real source publication and real bound sockets.
use super::*;
use crate::discovery_publish::{DiscoveryConnector, DiscoveryPublisher, EpochResult};
use crate::metric_source::MetricPublication;
use crate::static_source::ModePublisher;
use crate::{BackendSourceMode, MergedTopology, RoutingSnapshotPublisher, TopologyClusterClient};
use control_config::{ConfigNamespaceStore, HealthCheckConfig};
use control_external::{EtcdClientConfig, EtcdConnector};
use control_plane::{OwnerLease, OwnerScope, OwnershipRegistry};

pub(super) type TestError = Box<dyn std::error::Error>;
pub(super) struct Fixture {
    _registry: OwnershipRegistry,
    pub lease: OwnerLease,
    pub publication: MetricPublication,
    pub handle: MetricSourceHandle,
    _discovery: DiscoveryPublisher,
    pub discovery_capture: crate::DiscoveryCapture,
    pub routing: RoutingSnapshotPublisher,
    pub mode: ModePublisher,
    pub clusters: Vec<TopologyClusterClient>,
}
impl Fixture {
    pub async fn new(endpoint: &str) -> Result<Self, TestError> {
        let registry = OwnershipRegistry::new();
        let lease = registry.claim(OwnerScope::Process, "collector-fixture")?;
        let config = ConfigNamespaceStore::from_toml(b"", None, &std::env::current_dir()?)?;
        let policy = HealthCheckConfig {
            max_retries: 0,
            dial_timeout_nanos: 3_000_000_000,
            metrics_timeout_nanos: 500_000_000,
            ..HealthCheckConfig::default()
        };
        let (mut publication, handle) = MetricPublication::new(Arc::new(config.clone()), policy);
        publication.enable()?;
        let clusters = vec![TopologyClusterClient {
            cluster_name: Arc::from("collector-fixture"),
            client: EtcdClientConfig::new([endpoint.to_owned()], None)?.with_timeouts(
                Duration::from_secs(1),
                Duration::from_millis(500),
                Duration::from_secs(1),
                Duration::from_millis(100),
                Duration::from_secs(1),
            )?,
        }];
        let (discovery, _) = DiscoveryPublisher::new();
        let prepared = publication.prepare(&lease.token(), &clusters)?;
        let connector: DiscoveryConnector = Arc::new(|owner, client| {
            Box::pin(async move { EtcdConnector::new(owner, client).connect().await })
        });
        let candidate = discovery
            .prepare(
                &connector,
                &lease.token(),
                vec![(
                    Arc::clone(&clusters[0].cluster_name),
                    clusters[0].client.clone(),
                )],
            )
            .await
            .map_err(|e| format!("prepare: {e:?}"))?;
        let discovery_capture = discovery.commit(candidate);
        publication.install(prepared, discovery_capture.clone());
        let (routing, _) = RoutingSnapshotPublisher::new();
        routing
            .publish(EpochResult {
                client_epoch: 0,
                value: MergedTopology::default(),
            })
            .map_err(|e| format!("publish: {e:?}"))?;
        let mode = ModePublisher::new();
        mode.publish(BackendSourceMode::Dynamic);
        publication.reconcile(
            routing.handle().current(),
            mode.subscribe().borrow().clone(),
        );
        Ok(Self {
            _registry: registry,
            lease,
            publication,
            handle,
            _discovery: discovery,
            discovery_capture,
            routing,
            mode,
            clusters,
        })
    }
    pub fn capture(&self) -> Result<MetricCapture, TestError> {
        self.handle
            .capture()
            .ok_or_else(|| "capture missing".into())
    }
    pub async fn bound(&self) -> Result<(MetricCollector, MetricOverlayHandle), TestError> {
        let (collector, overlay) =
            MetricCollector::bind(self.handle.clone(), "127.0.0.1:0".parse()?).await?;
        collector.shared.serving.activate(self.lease.token());
        collector.shared.lock().capture = Some(self.capture()?);
        Ok((collector, overlay))
    }
}
pub(super) fn result() -> ClusterResult {
    let mut reader = ReaderState::default();
    reader.complete_backend(BTreeMap::new(), true);
    ClusterResult {
        lineage: Arc::new(()),
        gate: GenerationGate::new(),
        reader,
        backend_proofs: Vec::new(),
        owner: None,
        export: Arc::from(b"{}".as_slice()),
    }
}

#[tokio::test]
async fn collector_binding_and_final_generation_publication() -> Result<(), TestError> {
    let f = Fixture::new("127.0.0.1:1").await?;
    let old = f.capture()?;
    let (collector, overlay) = f.bound().await?;
    assert!(
        collector
            .shared
            .publish(&old, "collector-fixture", result(), None)
    );
    let snapshot = overlay.current_for(&old).ok_or("snapshot")?;
    assert_eq!(snapshot.with_current(|| 7), Some(7));
    f.publication.withdraw_material();
    assert!(
        !snapshot.still_current(),
        "COLLECTOR_MATERIAL_DIRECT_INVALIDATION"
    );
    assert_eq!(
        snapshot.with_current(|| 7),
        None,
        "COLLECTOR_FINAL_SOURCE_CHECK"
    );
    assert!(
        !collector
            .shared
            .publish(&old, "collector-fixture", result(), None),
        "COLLECTOR_STALE_PUBLICATION"
    );
    let prepared = f.publication.prepare(&f.lease.token(), &f.clusters)?;
    let discovery = f.discovery_capture.clone();
    f.publication.install(prepared, discovery);
    f.publication.reconcile(
        f.routing.handle().current(),
        f.mode.subscribe().borrow().clone(),
    );
    let fresh = f.capture()?;
    collector.shared.lock().capture = Some(fresh.clone());
    assert!(
        collector
            .shared
            .publish(&fresh, "collector-fixture", result(), None)
    );
    let next = overlay.current_for(&fresh).ok_or("fresh snapshot")?;
    assert!(!snapshot.still_current(), "COLLECTOR_MATERIAL_ABA");
    drop(collector);
    assert!(!next.still_current(), "COLLECTOR_DROP_SERVING_REVOKED");
    assert_eq!(
        next.with_current(|| 7),
        None,
        "COLLECTOR_FINAL_SERVING_CHECK"
    );
    Ok(())
}

pub(super) fn live_endpoints() -> Result<(String, String, String), TestError> {
    let value: serde_json::Value =
        serde_json::from_slice(&std::fs::read(std::env::var("CP003_CONNECTION_FILE")?)?)?;
    Ok((
        value["etcd_endpoint"]
            .as_str()
            .ok_or("etcd endpoint")?
            .into(),
        value["proxy_endpoint"]
            .as_str()
            .ok_or("proxy endpoint")?
            .into(),
        value["control_url"].as_str().ok_or("control URL")?.into(),
    ))
}
