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

//! Applied source mode and namespace authority at the real reserve boundary.

use control_topology::BackendSourceMode;
use tokio::io::AsyncWriteExt;
use tokio::sync::{mpsc, oneshot};

use super::*;

struct Greeter {
    address: String,
    probes: mpsc::UnboundedReceiver<oneshot::Sender<bool>>,
    task: JoinHandle<()>,
}

impl Drop for Greeter {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Greeter {
    async fn new() -> TestResult<Self> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?.to_string();
        let (accepted, probes) = mpsc::unbounded_channel();
        let task = tokio::spawn(async move {
            let mut children = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    incoming = listener.accept() => {
                        let Ok((mut stream, _)) = incoming else { break; };
                        let (release, verdict) = oneshot::channel();
                        if accepted.send(release).is_err() { break; }
                        children.spawn(async move {
                            if verdict.await == Ok(true) {
                                let _ = stream.write_all(&[3, 0, 0, 0, 0x0a, b'8', 0]).await;
                            }
                        });
                    }
                    _ = children.join_next(), if !children.is_empty() => {}
                }
            }
        });
        Ok(Self {
            address,
            probes,
            task,
        })
    }

    async fn probe(&mut self) -> TestResult<oneshot::Sender<bool>> {
        Ok(
            tokio::time::timeout(Duration::from_secs(5), self.probes.recv())
                .await?
                .ok_or("greeter stopped")?,
        )
    }
}

fn namespace(name: &str, instances: &[&str]) -> NamespaceConfig {
    let mut namespace = NamespaceConfig {
        namespace: name.into(),
        ..NamespaceConfig::default()
    };
    namespace.backend.instances = instances.iter().map(|address| (*address).into()).collect();
    namespace
}

fn publish_namespaces(
    harness: &Harness,
    namespaces: Vec<NamespaceConfig>,
    revision: u64,
) -> TestResult {
    harness.source.store.apply(
        (**harness.source.store.current().effective()).clone(),
        namespaces,
        SourceRevision {
            file_revision: revision,
            etcd_revision: 0,
        },
        Path::new("/tmp"),
    )?;
    Ok(())
}

fn bind(harness: &Harness, name: &str) -> TestResult<Arc<Router>> {
    Router::new(
        Arc::new(harness.source.clone()),
        &harness.topology,
        &harness.runtime.handle().module_context(),
        name,
        100,
    )
    .map(Arc::new)
    .map_err(|error| format!("router binding: {error:?}").into())
}

async fn static_harness(
    health: HealthCheckConfig,
    namespaces: Vec<NamespaceConfig>,
) -> TestResult<Harness> {
    let mut harness = Harness::with_health("", "connection", &[], health, "").await?;
    harness.patch("[proxy]\nbackend-clusters=[]", 3);
    publish_namespaces(&harness, namespaces, 4)?;
    harness.source.deliver();
    harness.applied().await;
    harness.router = bind(&harness, "default")?;
    Ok(harness)
}

async fn verdict(router: &Router, address: &str, healthy: bool) -> TestResult<Candidate> {
    Ok(tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Ok(candidate) = router.capture()
                && candidate.backend.mode() == BackendSourceMode::Static
                && candidate.health.get(address).healthy == healthy
            {
                break candidate;
            }
            tokio::task::yield_now().await;
        }
    })
    .await?)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn static_reservations_follow_real_greeting_failure_and_recovery() -> TestResult {
    let mut greeter = Greeter::new().await?;
    let harness = static_harness(
        HealthCheckConfig {
            enabled: true,
            interval_nanos: 50_000_000,
            max_retries: 0,
            dial_timeout_nanos: 5_000_000_000,
            ..HealthCheckConfig::default()
        },
        vec![namespace("default", &[&greeter.address, &greeter.address])],
    )
    .await?;
    greeter
        .probe()
        .await?
        .send(true)
        .map_err(|_| "probe lost")?;
    let healthy = verdict(&harness.router, &greeter.address, true).await?;
    let failed_probe = greeter.probe().await?;
    assert_eq!(
        healthy.routing.backends.backends.len(),
        1,
        "raw duplicate IDs collapse"
    );
    let (session, reservation) = harness.reserve(&healthy);
    assert_eq!(reservation.assignment().backend_id, greeter.address);
    assert_eq!(reservation.assignment().backend_address, greeter.address);
    assert_eq!(reservation.assignment().cluster_name, "");
    assert!(
        reservation.assignment().local,
        "enabled health with an empty proxy zone is local"
    );
    assert_eq!(
        harness.router.finish(&reservation, true),
        Settlement::Applied
    );
    failed_probe.send(false).map_err(|_| "probe lost")?;
    let failed = verdict(&harness.router, &greeter.address, false).await?;
    let recovery_probe = greeter.probe().await?;
    let retry = must(harness.router.open());
    assert!(matches!(
        harness
            .router
            .reserve(&retry, &failed, ClientInfo::default(), "", &[]),
        Err(RouteError::NoBackend)
    ));
    assert!(matches!(
        harness
            .router
            .reserve(&retry, &healthy, ClientInfo::default(), "", &[]),
        Err(RouteError::StaleCandidate)
    ));
    recovery_probe.send(true).map_err(|_| "probe lost")?;
    let recovered = verdict(&harness.router, &greeter.address, true).await?;
    let _held = greeter.probe().await?;
    let next = must(
        harness
            .router
            .reserve(&retry, &recovered, ClientInfo::default(), "", &[]),
    );
    assert_eq!(
        harness
            .router
            .accounting(&greeter.address)
            .map(|a| (a.active(), a.reserved())),
        Some((1, 1))
    );
    assert_eq!(harness.router.finish(&next, false), Settlement::Applied);
    harness.router.close(&session);
    harness.router.close(&retry);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn disabled_static_sources_share_raw_addresses_but_not_reservations() -> TestResult {
    let mut greeter = Greeter::new().await?;
    let harness = static_harness(
        HealthCheckConfig {
            enabled: false,
            interval_nanos: 50_000_000,
            ..HealthCheckConfig::default()
        },
        vec![
            namespace("default", &[&greeter.address]),
            namespace("other", &[&greeter.address]),
        ],
    )
    .await?;
    let other = bind(&harness, "other")?;
    let first = verdict(&harness.router, &greeter.address, true).await?;
    let second = verdict(&other, &greeter.address, true).await?;
    assert!(!Arc::ptr_eq(&first.routing, &second.routing));
    assert!(!Arc::ptr_eq(&first.health, &second.health));
    let (session, reservation) = harness.reserve(&first);
    let foreign = must(other.open());
    assert!(matches!(
        other.reserve(&foreign, &first, ClientInfo::default(), "", &[]),
        Err(RouteError::StaleCandidate)
    ));
    let isolated = must(other.reserve(&foreign, &second, ClientInfo::default(), "", &[]));
    assert!(!reservation.assignment().local && !isolated.assignment().local);
    assert_eq!(other.finish(&reservation, true), Settlement::Ignored);
    assert_eq!(
        harness.router.finish(&reservation, true),
        Settlement::Applied
    );
    assert_eq!(
        other
            .accounting(&greeter.address)
            .map(|a| (a.active(), a.reserved())),
        Some((0, 1))
    );
    assert_eq!(
        harness
            .router
            .accounting(&greeter.address)
            .map(|a| (a.active(), a.reserved())),
        Some((1, 0))
    );
    assert!(
        matches!(
            greeter.probes.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ),
        "disabled health performs no SQL I/O"
    );
    harness.router.close(&session);
    other.close(&foreign);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rejected_clusters_keep_static_but_empty_dynamic_never_falls_back() -> TestResult {
    let harness = static_harness(
        HealthCheckConfig {
            enabled: false,
            interval_nanos: 60_000_000_000,
            ..HealthCheckConfig::default()
        },
        vec![namespace("default", &["127.0.0.1:4999"])],
    )
    .await?;
    let first = harness.ready().await;
    let (old_session, old_reservation) = harness.reserve(&first);
    harness.patch(&format!("[[proxy.backend-clusters]]\nname=\"default\"\npd-addrs=\"{}\"\n[balance]\nrouting-policy=\"random\"", harness.fixture.endpoint), 5);
    let pending = must(harness.router.capture());
    assert_eq!(pending.backend.mode(), BackendSourceMode::Static);
    assert!(Arc::ptr_eq(&first.routing, &pending.routing));
    assert!(Arc::ptr_eq(&first.health, &pending.health));
    assert_eq!(
        pending.policy.selection_policy,
        control_config::RoutingSelectionPolicy::Random
    );
    harness.reject.store(true, Ordering::SeqCst);
    harness.source.deliver();
    harness.applied().await;
    assert!(harness.topology.status().borrow().last_rejection.is_some());
    let rejected = must(harness.router.capture());
    let (admitted, attempted) = harness.reserve(&rejected);
    assert_eq!(attempted.assignment().backend_id, "127.0.0.1:4999");
    harness.router.close(&admitted);
    harness.reject.store(false, Ordering::SeqCst);
    harness.patch("[labels]\nzone=\"az-a\"", 6);
    harness.source.deliver();
    harness.applied().await;
    let dynamic = harness.ready().await;
    assert_eq!(dynamic.backend.mode(), BackendSourceMode::Dynamic);
    assert!(dynamic.routing.backends.backends.is_empty());
    let session = must(harness.router.open());
    assert!(matches!(
        harness
            .router
            .reserve(&session, &dynamic, ClientInfo::default(), "", &[]),
        Err(RouteError::NoBackend)
    ));
    assert_eq!(
        harness.router.finish(&old_reservation, true),
        Settlement::Applied
    );
    assert_eq!(harness.router.close(&old_session), Settlement::Applied);
    harness.patch("[proxy]\nbackend-clusters=[]", 7);
    harness.source.deliver();
    harness.applied().await;
    let restored = harness.ready().await;
    assert_eq!(restored.backend.mode(), BackendSourceMode::Static);
    assert!(!Arc::ptr_eq(&restored.health, &first.health));
    assert!(matches!(
        harness
            .router
            .reserve(&session, &first, ClientInfo::default(), "", &[]),
        Err(RouteError::StaleCandidate)
    ));
    let fresh = must(
        harness
            .router
            .reserve(&session, &restored, ClientInfo::default(), "", &[]),
    );
    assert_eq!(fresh.assignment().backend_id, "127.0.0.1:4999");
    harness.router.close(&session);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn revoked_mode_inside_real_registration_shutdown_prevents_locked_reservation() -> TestResult
{
    let registration = registration::Registration::new();
    let fixture = KvFixture::with_registration(Some(registration.clone())).await?;
    let harness = Harness::with_fixture(
        "",
        "connection",
        &[("127.0.0.1:4000", &[])],
        HealthCheckConfig {
            enabled: false,
            interval_nanos: 60_000_000_000,
            ..HealthCheckConfig::default()
        },
        "",
        fixture,
    )
    .await?;
    let mut registered = registration.puts.subscribe();
    tokio::time::timeout(
        Duration::from_secs(5),
        registered.wait_for(|count| *count >= 2),
    )
    .await??;
    registration.release.send_replace(false);
    // C is already new before capture. Only watch delivery to the module is
    // withheld; C and the old dynamic R/H remain exact throughout the window.
    harness.patch("[proxy]\nbackend-clusters=[]", 3);
    let candidate = must(harness.router.capture());
    assert_eq!(candidate.backend.mode(), BackendSourceMode::Dynamic);
    let session = must(harness.router.open());
    let lock = harness.router.hold_lock_for_test();
    let attempted = harness.router.observe_next_lock_for_test();
    let router = Arc::clone(&harness.router);
    let captured = candidate.clone();
    let owned = session.clone();
    let worker = std::thread::spawn(move || {
        router.reserve(&owned, &captured, ClientInfo::default(), "", &[])
    });
    attempted.recv_timeout(Duration::from_secs(2))?;
    harness.source.deliver();
    let mut revoking = registration.revoking.subscribe();
    tokio::time::timeout(Duration::from_secs(2), revoking.wait_for(|value| *value)).await??;
    assert!(Arc::ptr_eq(
        &candidate.config,
        &harness.source.store.current()
    ));
    let routing = harness.topology.routing_handle();
    let health = harness.topology.health_overlay_handle();
    assert!(health.still_current_for(&candidate.health, &candidate.routing, &routing));
    assert_eq!(harness.topology.status().borrow().applied_generation, 2);
    assert!(matches!(
        harness.router.capture(),
        Err(RouteError::ControlUnavailable)
    ));
    drop(lock);
    let result = must(worker.join());
    // Prove refusal was not explained by a coincident R/H change.
    assert!(health.still_current_for(&candidate.health, &candidate.routing, &routing));
    assert!(matches!(result, Err(RouteError::StaleCandidate)));
    assert!(
        harness
            .router
            .accounting("default/127.0.0.1:4000")
            .is_none()
    );
    registration.release.send_replace(true);
    harness.applied().await;
    assert_eq!(
        harness.ready().await.backend.mode(),
        BackendSourceMode::Static
    );
    harness.router.close(&session);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn static_namespace_aba_while_ledger_locked_refuses_work_and_preserves_other_namespace()
-> TestResult {
    let namespaces = vec![
        namespace("default", &["127.0.0.1:4999"]),
        namespace("other", &["127.0.0.1:4999"]),
    ];
    let harness = static_harness(
        HealthCheckConfig {
            enabled: false,
            interval_nanos: 60_000_000_000,
            ..HealthCheckConfig::default()
        },
        namespaces.clone(),
    )
    .await?;
    let first = harness.ready().await;
    let other = bind(&harness, "other")?;
    let other_before = verdict(&other, "127.0.0.1:4999", true).await?;
    let session = must(harness.router.open());
    let lock = harness.router.hold_lock_for_test();
    let attempted = harness.router.observe_next_lock_for_test();
    let router = Arc::clone(&harness.router);
    let candidate = first.clone();
    let owned = session.clone();
    let worker = std::thread::spawn(move || {
        router.reserve(&owned, &candidate, ClientInfo::default(), "", &[])
    });
    attempted.recv_timeout(Duration::from_secs(2))?;
    publish_namespaces(&harness, vec![namespaces[1].clone()], 5)?;
    publish_namespaces(&harness, namespaces, 6)?;
    assert!(matches!(
        harness.router.capture(),
        Err(RouteError::NamespaceReplaced)
    ));
    let other_now = must(other.capture());
    assert!(Arc::ptr_eq(&other_before.routing, &other_now.routing));
    assert!(Arc::ptr_eq(&other_before.health, &other_now.health));
    let admitted = must(other.open());
    let valid = must(other.reserve(&admitted, &other_now, ClientInfo::default(), "", &[]));
    drop(lock);
    assert!(matches!(
        must(worker.join()),
        Err(RouteError::StaleCandidate)
    ));
    assert!(matches!(
        harness.router.open(),
        Err(RouteError::NamespaceReplaced)
    ));
    assert!(harness.router.accounting("127.0.0.1:4999").is_none());
    harness.source.deliver();
    harness.applied().await;
    let replacement = bind(&harness, "default")?;
    let fresh = verdict(&replacement, "127.0.0.1:4999", true).await?;
    assert!(!Arc::ptr_eq(&first.routing, &fresh.routing));
    assert!(!Arc::ptr_eq(&first.health, &fresh.health));
    let new_session = must(replacement.open());
    let new = must(replacement.reserve(&new_session, &fresh, ClientInfo::default(), "", &[]));
    assert_eq!(replacement.close(&session), Settlement::Ignored);
    assert_eq!(harness.router.close(&session), Settlement::Applied);
    assert_eq!(other.finish(&valid, true), Settlement::Applied);
    assert_eq!(replacement.finish(&new, true), Settlement::Applied);
    other.close(&admitted);
    replacement.close(&new_session);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn composed_static_empty_uses_actual_namespace_mode_and_ledger() -> TestResult {
    let mut greeter = Greeter::new().await?;
    let mut harness = static_harness(
        HealthCheckConfig {
            enabled: true,
            interval_nanos: 50_000_000,
            ..HealthCheckConfig::default()
        },
        vec![namespace("default", &[&greeter.address])],
    )
    .await?;
    harness.patch("[balance]\npolicy=\"resource\"", 5);
    harness.router = Arc::new(must(Router::new_with_factors(
        Arc::new(harness.source.clone()),
        &harness.topology,
        &harness.runtime.handle().module_context(),
        "default",
        100,
        None,
    )));
    greeter
        .probe()
        .await?
        .send(true)
        .map_err(|_| "probe lost")?;
    let first = verdict(&harness.router, &greeter.address, true).await?;
    let _held = greeter.probe().await?;
    assert!(
        matches!(first.metrics, crate::authority::MetricInputs::StaticEmpty),
        "COMPOSE_STATIC_ACTUAL_EMPTY_SOURCE"
    );
    let (session, pending) = harness.reserve(&first);
    assert_eq!(pending.assignment().backend_address, greeter.address);
    assert!(pending.assignment().local, "COMPOSE_STATIC_H_LOCAL");
    assert_eq!(pending.assignment().cluster_name, "");
    let duplicate = must(
        harness
            .router
            .reserve(&session, &first, ClientInfo::default(), "", &[]),
    );
    assert_eq!(duplicate.assignment(), pending.assignment());
    assert_eq!(
        harness
            .router
            .accounting(&greeter.address)
            .map(crate::Accounting::reserved),
        Some(1),
        "COMPOSE_STATIC_PENDING_ONCE"
    );
    harness.patch("[balance]\npolicy=\"location\"", 6);
    let current = must(harness.router.capture());
    assert!(matches!(
        current.metrics,
        crate::authority::MetricInputs::StaticEmpty
    ));
    let (other, _) = harness.reserve(&current);
    assert!(
        matches!(
            harness
                .router
                .reserve(&session, &first, ClientInfo::default(), "", &[]),
            Err(RouteError::StaleCandidate)
        ),
        "COMPOSE_STATIC_FINAL_C"
    );
    assert_eq!(
        harness.router.finish(&pending, true),
        Settlement::Applied,
        "COMPOSE_STATIC_SETTLES_OLD_OWNER"
    );
    publish_namespaces(&harness, Vec::new(), 7)?;
    publish_namespaces(&harness, vec![namespace("default", &[&greeter.address])], 8)?;
    assert!(
        harness.router.capture().is_err(),
        "COMPOSE_STATIC_NAMESPACE_ABA"
    );
    assert!(
        harness
            .router
            .reserve(&other, &current, ClientInfo::default(), "", &[])
            .is_err()
    );
    assert_eq!(harness.router.close(&session), Settlement::Applied);
    assert_eq!(harness.router.close(&other), Settlement::Applied);
    Ok(())
}
