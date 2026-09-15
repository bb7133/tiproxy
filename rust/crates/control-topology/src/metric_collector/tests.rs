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
use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

pub(super) type TestError = Box<dyn std::error::Error>;
pub(super) struct Fixture {
    pub config: ConfigNamespaceStore,
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
            config,
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
        queries: None,
        lineage: Arc::new(()),
        gate: GenerationGate::new(),
        reader,
        backend_proofs: Vec::new(),
        owner: None,
        export: Arc::from(b"{}".as_slice()),
    }
}

#[tokio::test]
async fn routing_endpoint_separates_bind_and_peer_identity() -> Result<(), TestError> {
    let fixture = Fixture::new("127.0.0.1:1").await?;
    let (collector, _) = MetricCollector::bind_for_routing_endpoint(
        fixture.handle.clone(),
        "127.0.0.1:0".parse()?,
        "metric-peer.internal",
        Arc::new(PlainMetricConnectionAcceptor),
    )
    .await?;
    assert_eq!(collector.local_addr().ip().to_string(), "127.0.0.1");
    assert_eq!(
        collector.advertised_addr(),
        format!("metric-peer.internal:{}", collector.local_addr().port())
    );

    let (ipv6, _) = MetricCollector::bind_for_routing_endpoint(
        fixture.handle.clone(),
        "127.0.0.1:0".parse()?,
        "2001:db8::7",
        Arc::new(PlainMetricConnectionAcceptor),
    )
    .await?;
    assert_eq!(
        ipv6.advertised_addr(),
        format!("[2001:db8::7]:{}", ipv6.local_addr().port()),
        "an IPv6 owner value must remain an unambiguous host:port"
    );

    for invalid_host in ["bad host", "metric.example:1234", "metric.example?query"] {
        assert!(
            matches!(
                MetricCollector::bind_for_routing_endpoint(
                    fixture.handle.clone(),
                    "127.0.0.1:0".parse()?,
                    invalid_host,
                    Arc::new(PlainMetricConnectionAcceptor),
                )
                .await,
                Err(MetricCollectorError::AdvertisedHost)
            ),
            "an invalid peer identity is rejected before any module starts"
        );
    }
    Ok(())
}

#[tokio::test]
async fn routing_endpoint_uses_a_fixed_port_and_rejects_an_occupied_one() -> Result<(), TestError> {
    let fixture = Fixture::new("127.0.0.1:1").await?;
    let reservation = TcpListener::bind("127.0.0.1:0").await?;
    let fixed_address = reservation.local_addr()?;
    drop(reservation);

    let (collector, _) = MetricCollector::bind_for_routing_endpoint(
        fixture.handle.clone(),
        fixed_address,
        "metric-peer.internal",
        Arc::new(PlainMetricConnectionAcceptor),
    )
    .await?;
    assert_eq!(collector.local_addr(), fixed_address);
    assert_eq!(
        collector.advertised_addr(),
        format!("metric-peer.internal:{}", fixed_address.port()),
        "the fixed local port is also the elected peer identity"
    );
    drop(collector);

    let occupied = TcpListener::bind(fixed_address).await?;
    assert!(matches!(
        MetricCollector::bind_for_routing_endpoint(
            fixture.handle,
            fixed_address,
            "metric-peer.internal",
            Arc::new(PlainMetricConnectionAcceptor),
        )
        .await,
        Err(MetricCollectorError::Bind(_))
    ));
    drop(occupied);
    Ok(())
}

#[tokio::test]
async fn routing_endpoint_applies_the_injected_connection_policy() -> Result<(), TestError> {
    struct RejectingAcceptor(Arc<AtomicUsize>);
    impl MetricConnectionAcceptor for RejectingAcceptor {
        fn accept(&self, _stream: TcpStream) -> MetricAcceptFuture {
            let calls = Arc::clone(&self.0);
            Box::pin(async move {
                calls.fetch_add(1, Ordering::SeqCst);
                Err(io::Error::other("rejected by test connection policy"))
            })
        }
    }

    let fixture = Fixture::new("127.0.0.1:1").await?;
    let calls = Arc::new(AtomicUsize::new(0));
    let (mut collector, _) = MetricCollector::bind_for_routing_endpoint(
        fixture.handle,
        "127.0.0.1:0".parse()?,
        "127.0.0.1",
        Arc::new(RejectingAcceptor(Arc::clone(&calls))),
    )
    .await?;
    collector.shared.serving.activate(fixture.lease.token());
    let listener = collector.listener.take().ok_or("listener")?;
    let address = collector.local_addr();
    let server = tokio::spawn(service::serve(listener, Arc::clone(&collector.shared)));
    let mut client = TcpStream::connect(address).await?;
    client.write_all(b"GET / HTTP/1.1\r\n\r\n").await?;
    let mut body = Vec::new();
    let read = client.read_to_end(&mut body).await;
    assert!(
        body.is_empty(),
        "a rejected transport reaches no HTTP parser"
    );
    assert!(
        read.is_ok() || read.is_err_and(|error| error.kind() == io::ErrorKind::ConnectionReset),
        "the rejected TCP connection either closes or resets"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    server.abort();
    let _ = server.await;
    Ok(())
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
