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
use crate::RoutingSnapshotPublisher;
use crate::discovery_publish::{DiscoveryConnector, DiscoveryPublisher, EpochResult};
use crate::static_source::ModePublisher;
use control_config::ConfigNamespaceStore;
use control_external::{EtcdClientConfig, EtcdConnector};
use control_plane::{OwnerLease, OwnerScope, OwnershipRegistry};

type TestError = Box<dyn std::error::Error>;

fn must<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
    result.unwrap_or_else(|error| unreachable!("fixture failed: {error:?}"))
}

struct Fixture {
    _registry: OwnershipRegistry,
    lease: OwnerLease,
    publisher: MetricPublication,
    handle: MetricSourceHandle,
    discovery: DiscoveryPublisher,
    routing: RoutingSnapshotPublisher,
    mode: ModePublisher,
    clusters: Vec<TopologyClusterClient>,
}

impl Fixture {
    async fn new() -> Result<Self, TestError> {
        let registry = OwnershipRegistry::new();
        let lease = registry.claim(OwnerScope::Process, "metric-feed-test")?;
        let source = ConfigNamespaceStore::from_toml(b"", None, &std::env::current_dir()?)?;
        let (mut publisher, handle) =
            MetricPublication::new(Arc::new(source), HealthCheckConfig::default());
        publisher.enable()?;
        let clusters = vec![TopologyClusterClient {
            cluster_name: Arc::from("cluster-a"),
            client: EtcdClientConfig::new(["127.0.0.1:1".to_owned()], None)?,
        }];
        let (discovery, _) = DiscoveryPublisher::new();
        let prepared = publisher.prepare(&lease.token(), &clusters)?;
        let connector: DiscoveryConnector = Arc::new(|owner, client| {
            Box::pin(async move { EtcdConnector::new(owner, client).connect().await })
        });
        let candidate = must(
            discovery
                .prepare(
                    &connector,
                    &lease.token(),
                    vec![(
                        Arc::clone(&clusters[0].cluster_name),
                        clusters[0].client.clone(),
                    )],
                )
                .await,
        );
        let capture = discovery.commit(candidate);
        publisher.install(prepared, capture);
        let (routing, _) = RoutingSnapshotPublisher::new();
        must(routing.publish(EpochResult {
            client_epoch: 0,
            value: MergedTopology::default(),
        }));
        let mode = ModePublisher::new();
        mode.publish(BackendSourceMode::Dynamic);
        publisher.reconcile(
            routing.handle().current(),
            mode.subscribe().borrow().clone(),
        );
        assert!(handle.capture().is_some(), "METRIC_INITIAL_CAPTURE");
        Ok(Self {
            _registry: registry,
            lease,
            publisher,
            handle,
            discovery,
            routing,
            mode,
            clusters,
        })
    }
    fn capture(&self) -> MetricCapture {
        self.handle
            .capture()
            .unwrap_or_else(|| unreachable!("live capture"))
    }
    fn reconcile(&self) {
        self.publisher.reconcile(
            self.routing.handle().current(),
            self.mode.subscribe().borrow().clone(),
        );
    }
}

#[tokio::test]
async fn metric_noop_retains_capture_but_same_value_new_r_identity_revokes_it()
-> Result<(), TestError> {
    let f = Fixture::new().await?;
    let old = f.capture();
    let revision = f.handle.snapshot().1;
    f.reconcile();
    assert_eq!(f.handle.snapshot().1, revision);
    assert!(old.still_current());
    // A second real publisher has equal diagnostic stamps and content. Its
    // independently live source cannot keep the former feed authority alive.
    let (other, _) = RoutingSnapshotPublisher::new();
    must(other.publish(EpochResult {
        client_epoch: 0,
        value: MergedTopology::default(),
    }));
    f.publisher.reconcile(
        other.handle().current(),
        f.mode.subscribe().borrow().clone(),
    );
    assert!(
        old.routing().source_gate().is_live(),
        "independent old R remains live"
    );
    assert!(old.generation.material.discovery.still_current());
    assert!(!old.still_current(), "METRIC_SAME_VALUE_R_ABA");
    assert_eq!(
        old.with_current(|| "stale publication"),
        None,
        "METRIC_FINAL_PUBLICATION"
    );
    assert!(f.capture().still_current());
    Ok(())
}

#[tokio::test]
async fn metric_material_withdrawal_revokes_unpolled_capture_before_install()
-> Result<(), TestError> {
    let f = Fixture::new().await?;
    let old = f.capture();
    let prepared = f.publisher.prepare(&f.lease.token(), &f.clusters)?;
    f.publisher.withdraw_material();
    assert!(old.routing().source_gate().is_live());
    assert!(old.generation.material.discovery.still_current());
    assert!(old.generation.mode.is_live());
    assert!(f.lease.token().is_current());
    assert!(!old.still_current(), "METRIC_MATERIAL_EARLY_REVOKE");
    assert_eq!(old.with_current(|| true), None, "METRIC_FINAL_PUBLICATION");
    // Same applied discovery and same R: only the private material/feed identity
    // changes. Neither equal epoch nor identical client bytes revives old data.
    f.publisher
        .install(prepared, old.generation.material.discovery.clone());
    f.reconcile();
    assert!(f.capture().still_current());
    assert!(!old.still_current(), "METRIC_SAME_VALUE_MATERIAL_ABA");
    Ok(())
}

#[tokio::test]
async fn metric_direct_source_mode_discovery_and_original_owner_fences() -> Result<(), TestError> {
    for cause in ["source", "mode", "discovery", "owner"] {
        let f = Fixture::new().await?;
        let old = f.capture();
        match cause {
            "source" => f.routing.revoke_and_clear(),
            "mode" => f.mode.revoke(),
            "discovery" => f.discovery.revoke(),
            _ => {
                drop(f.lease);
            }
        }
        assert!(old.gate.is_live(), "feed was deliberately not reconciled");
        assert!(!old.still_current(), "METRIC_DIRECT_{cause}_FENCE");
        assert_eq!(old.with_current(|| true), None);
        let work = GenerationGate::new();
        assert!(
            matches!(
                old.get_cluster_once("missing", "127.0.0.1", 1, &HttpTarget::status(), &work)
                    .await,
                Err(MetricReadError::Stale)
            ),
            "stale wins absent cluster"
        );
    }
    Ok(())
}

#[tokio::test]
async fn metric_unique_writer_drop_and_revision_overflow_are_terminal() -> Result<(), TestError> {
    for overflow in [false, true] {
        let f = Fixture::new().await?;
        let old = f.capture();
        let (_, revision, _) = f.handle.snapshot();
        let changed = f.handle.wait_change(revision);
        tokio::pin!(changed);
        assert!(
            tokio::time::timeout(Duration::from_millis(1), &mut changed)
                .await
                .is_err()
        );
        if overflow {
            f.publisher.shared.lock().revision = u64::MAX;
            f.publisher.withdraw_material();
            f.reconcile();
        } else {
            drop(f.publisher);
        }
        assert!(!old.still_current(), "METRIC_TERMINAL_CAPTURE");
        assert!(f.handle.snapshot().2, "METRIC_TERMINAL_FEED");
        tokio::time::timeout(Duration::from_secs(1), changed).await?;
        assert!(f.handle.capture().is_none());
        // A waiter created AFTER the transition cannot lose notify_waiters.
        tokio::time::timeout(Duration::from_secs(1), f.handle.wait_change(revision)).await?;
    }
    Ok(())
}

#[tokio::test]
async fn metric_publication_serializes_with_withdrawal() -> Result<(), TestError> {
    let f = Fixture::new().await?;
    let capture = f.capture();
    std::thread::scope(|scope| {
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let captured = &capture;
        let writer = scope.spawn(move || {
            captured.with_current(|| {
                must(entered_tx.send(()));
                must(release_rx.recv());
                "published before withdrawal"
            })
        });
        must(entered_rx.recv());
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let publication = &f.publisher;
        let withdraw = scope.spawn(move || {
            must(started_tx.send(()));
            publication.withdraw_material();
        });
        must(started_rx.recv());
        assert!(capture.still_current());
        must(release_tx.send(()));
        assert_eq!(must(writer.join()), Some("published before withdrawal"));
        must(withdraw.join());
    });
    assert_eq!(
        capture.with_current(|| "late"),
        None,
        "METRIC_FINAL_PUBLICATION"
    );
    Ok(())
}

#[test]
fn metric_policy_is_validated_only_on_opt_in_and_pinned() -> Result<(), TestError> {
    let source = ConfigNamespaceStore::from_toml(b"", None, &std::env::current_dir()?)?;
    for (interval, timeout, expected) in [
        (0, 1, MetricConfigError::InvalidCadence),
        (1, 0, MetricConfigError::InvalidTimeout),
    ] {
        let config = HealthCheckConfig {
            metrics_interval_nanos: interval,
            metrics_timeout_nanos: timeout,
            ..HealthCheckConfig::default()
        };
        let (mut publication, handle) = MetricPublication::new(Arc::new(source.clone()), config);
        assert!(handle.capture().is_none());
        assert_eq!(publication.enable(), Err(expected));
    }
    let policy = MetricRuntimePolicy::new(HealthCheckConfig::default())?;
    assert_eq!(policy.interval(), Duration::from_secs(5));
    assert_eq!(policy.prom_timeout(), Duration::from_secs(3));
    Ok(())
}
