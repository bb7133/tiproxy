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

//! Owns the native sampler and export worker as one supervised resource.

use control_meter::service::Service;
use dataplane::{
    MeteringLedger,
    metering::{MeteringSamplerError, MeteringSourceRegistry, run_native_metering_sampler},
};
use std::{sync::Arc, time::Duration};
use tokio::sync::watch;

/// The process stops sessions before signaling `shutdown`. The sampler then
/// persists/ACKs the final counters before the export worker seals and flushes.
/// Both futures are owned here, so dropping this resource detaches no tasks.
pub(crate) async fn run(
    registry: MeteringSourceRegistry,
    ledger: MeteringLedger,
    meter: Arc<Service>,
    shutdown: watch::Sender<bool>,
    cadence: Duration,
) -> Result<(), MeteringSamplerError> {
    let (export_stop, export_shutdown) = watch::channel(false);
    let sampler = run_native_metering_sampler(
        registry,
        ledger,
        Arc::clone(&meter),
        shutdown.subscribe(),
        cadence,
    );
    let exporter = meter.run(export_shutdown);
    tokio::pin!(sampler, exporter);
    tokio::select! {
        result = &mut sampler => {
            export_stop.send_replace(true);
            let export = exporter.await;
            result?;
            export.map_err(MeteringSamplerError::NativeConsumer)
        }
        result = &mut exporter => {
            // An unexpected exporter exit is fatal. Stop/join the sampler;
            // rejected final intake remains in the producer WAL for restart.
            shutdown.send_replace(true);
            let _ = sampler.await;
            Err(MeteringSamplerError::NativeConsumer(result.err().unwrap_or(
                control_meter::Error::Export("native meter worker stopped unexpectedly")
            )))
        }
    }
}

/// Holds exclusive native process access to this metering state directory.
/// Go's Rust composition never opens these files. Legacy binaries must be
/// stopped before migration; their older code does not participate in this lock.
pub(crate) fn lock_state(directory: &std::path::Path) -> Result<std::fs::File, String> {
    std::fs::create_dir_all(directory).map_err(|_| "create native meter state directory")?;
    lock_file(&directory.join("rust-metering-owner.lock"))
}

/// The WAL path can be shared even when two processes use different workdirs.
pub(crate) fn lock_wal(path: &std::path::Path) -> Result<std::fs::File, String> {
    let mut lock = path.as_os_str().to_os_string();
    lock.push(".owner.lock");
    lock_file(std::path::Path::new(&lock))
}

fn lock_file(path: &std::path::Path) -> Result<std::fs::File, String> {
    use std::os::unix::fs::OpenOptionsExt;
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| "open native meter ownership lock")?;
    rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive)
        .map_err(|_| "native metering state already owned")?;
    Ok(file)
}

/// Waits for the negotiated owner assertion before opening consumer/outbox.
pub(crate) async fn wait_peer(
    mut state: watch::Receiver<control_proto::control_transport::ConnectionState>,
) -> Result<(), String> {
    use control_proto::{control_transport::ConnectionState, v1::ControlCapability};
    loop {
        match &*state.borrow_and_update() {
            ConnectionState::Connected { capabilities, .. } => {
                return if capabilities & (1 << ControlCapability::RustMeterOwner as u64) != 0 {
                    Ok(())
                } else {
                    Err("peer does not support native metering".into())
                };
            }
            ConnectionState::Shutdown => {
                return Err("control transport stopped before metering ownership".into());
            }
            _ => {}
        }
        state
            .changed()
            .await
            .map_err(|_| "control transport closed before metering ownership")?;
    }
}

/// Keeps SQL closed until native state recovery and all startup resources finish.
pub(crate) struct ReadyConsumer<C> {
    inner: C,
    ready: watch::Receiver<Option<bool>>,
}
impl<C> ReadyConsumer<C> {
    pub(crate) fn new(inner: C) -> (Self, watch::Sender<Option<bool>>) {
        let (ready, receiver) = watch::channel(None);
        (
            Self {
                inner,
                ready: receiver,
            },
            ready,
        )
    }
}
impl<C: dataplane::control_runtime::SnapshotConsumer> dataplane::control_runtime::SnapshotConsumer
    for ReadyConsumer<C>
{
    fn compose(
        &self,
        source: &control_proto::v1::StateSnapshot,
    ) -> Result<
        dataplane::control_runtime::SnapshotComposition,
        control_proto::snapshot::SnapshotError,
    > {
        self.inner.compose(source)
    }
    async fn apply(
        &mut self,
        snapshot: &Arc<control_proto::snapshot::ValidatedSnapshot>,
        still_current: &(dyn Fn() -> bool + Send + Sync),
    ) -> Result<(), control_proto::snapshot::SnapshotError> {
        loop {
            match *self.ready.borrow_and_update() {
                Some(true) => break,
                Some(false) => {
                    return Err(control_proto::snapshot::SnapshotError::unsupported(
                        "native metering startup failed",
                    ));
                }
                None => {}
            }
            self.ready.changed().await.map_err(|_| {
                control_proto::snapshot::SnapshotError::unsupported(
                    "native metering startup closed",
                )
            })?;
        }
        self.inner.apply(snapshot, still_current).await
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use control_plane::ownership::{OwnerScope, OwnershipRegistry};
    use control_proto::v1::MeteringSourceSnapshot;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(1);
    fn directory() -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "native-meter-owner-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&path).expect("test directory");
        path
    }
    #[test]
    fn state_lock_excludes_another_owner_and_releases_on_drop() {
        let path = directory();
        let first = lock_state(&path).expect("first owner");
        assert!(lock_state(&path).is_err());
        drop(first);
        drop(lock_state(&path).expect("successor"));
        let wal = path.join("producer.wal");
        let first = lock_wal(&wal).expect("first WAL owner");
        assert!(lock_wal(&wal).is_err());
        drop(first);
        drop(lock_wal(&wal).expect("WAL successor"));
        std::fs::remove_dir_all(path).expect("cleanup");
    }
    #[tokio::test]
    async fn peer_assertion_rejects_legacy_and_accepts_native_capability() {
        use control_proto::control_transport::ConnectionState;
        for (caps, pass) in [(1 << 6, false), ((1 << 6) | (1 << 7), true)] {
            let (_, receiver) = watch::channel(ConnectionState::Connected {
                epoch: 1,
                capabilities: caps,
                serial: 1,
                peer_process_id: Arc::from("peer"),
                peer_started_unix_millis: 1,
            });
            assert_eq!(wait_peer(receiver).await.is_ok(), pass);
        }
    }
    #[tokio::test]
    async fn serving_waits_for_recovery_and_failed_startup_never_applies() {
        use control_proto::snapshot::{SnapshotLineage, SnapshotStore, UnixTime};
        use control_proto::v1::{
            ConfigSnapshot, KeepalivePolicy, Listener, StateSnapshot, TlsPolicy,
        };
        use dataplane::control_runtime::SnapshotConsumer;
        let store = SnapshotStore::new([]).expect("store");
        let snapshot = StateSnapshot {
            config: Some(ConfigSnapshot {
                proxy_protocol: control_proto::v1::ProxyProtocolMode::Disabled as i32,
                frontend_keepalive: Some(KeepalivePolicy::default()),
                healthy_backend_keepalive: Some(KeepalivePolicy::default()),
                unhealthy_backend_keepalive: Some(KeepalivePolicy::default()),
                high_memory_reject_threshold: 0.9,
                connection_buffer_bytes: 32 * 1024,
                listeners: vec![Listener {
                    address: "127.0.0.1".into(),
                    port: 6000,
                    name: "sql".into(),
                }],
                server_version: "TiProxy-test".into(),
                frontend_tls: Some(TlsPolicy::default()),
                backend_tls: Some(TlsPolicy::default()),
                ..ConfigSnapshot::default()
            }),
            ..StateSnapshot::default()
        };
        let staged = store
            .stage(
                1,
                snapshot,
                UnixTime::since_unix_epoch(Duration::from_secs(1_700_000_000)),
                SnapshotLineage::for_tests("peer"),
            )
            .expect("snapshot");
        for ready in [false, true] {
            let applied = Arc::new(AtomicU64::new(0));
            let counter = Arc::clone(&applied);
            let inner = move |_: &Arc<control_proto::snapshot::ValidatedSnapshot>| {
                counter.fetch_add(1, Ordering::SeqCst);
                std::future::ready(Ok(()))
            };
            let (mut consumer, gate) = ReadyConsumer::new(inner);
            let apply = consumer.apply(staged.snapshot(), &|| true);
            tokio::pin!(apply);
            assert!(
                tokio::time::timeout(Duration::from_millis(20), &mut apply)
                    .await
                    .is_err()
            );
            assert_eq!(applied.load(Ordering::SeqCst), 0);
            gate.send_replace(Some(ready));
            assert_eq!(apply.await.is_ok(), ready);
            assert_eq!(applied.load(Ordering::SeqCst), u64::from(ready));
        }
    }
    async fn lifecycle(fail_export: bool, disabled: bool) {
        let path = directory();
        let owners = OwnershipRegistry::new();
        let lease = owners
            .claim(OwnerScope::Process, "native-test")
            .expect("owner");
        let wal = path.join("producer.wal");
        let mut ledger = MeteringLedger::open_persistent(wal.clone()).expect("ledger");
        ledger
            .record_snapshots(vec![MeteringSourceSnapshot {
                connection_id: 1,
                process_generation: ledger.process_generation(),
                backend_generation: 1,
                backend_id: "backend".into(),
                cluster_name: "cluster".into(),
                keyspace: "ks".into(),
                backend_inbound_bytes: 10,
                backend_outbound_bytes: 20,
                public_endpoint: true,
                r#final: true,
                ..MeteringSourceSnapshot::default()
            }])
            .expect("retained final batch");
        let registry = MeteringSourceRegistry::new(ledger.process_generation()).expect("registry");
        let config = if disabled {
            control_config::MeteringConfig::default()
        } else {
            control_config::MeteringConfig {
                provider_type: "localfs".into(),
                bucket: "bucket".into(),
                localfs: Some(control_config::LocalFsMeteringConfig {
                    base_path: path.join("objects").to_string_lossy().into_owned(),
                    create_dirs: true,
                    permissions: "0755".into(),
                }),
                ..control_config::MeteringConfig::default()
            }
        };
        let meter = Service::open(
            &config,
            path.join("consumer.json"),
            path.join("outbox.json"),
            lease.token(),
        )
        .await
        .expect("service");
        if fail_export {
            let objects = path.join("objects");
            if objects.exists() {
                std::fs::remove_dir_all(&objects).expect("remove empty store");
            }
            std::fs::write(objects, b"cannot create object directories").expect("fail store");
        }
        let ledger = dataplane::metering::recover_native_metering(ledger, Arc::clone(&meter))
            .await
            .expect("startup recovery");
        assert_eq!(
            ledger.unacked_len(),
            0,
            "retained WAL is recovered before serving"
        );
        assert_eq!(meter.checkpoint().expect("consumer checkpoint").sequence, 1);
        let (shutdown, _) = watch::channel(true);
        let result = run(
            registry,
            ledger,
            Arc::clone(&meter),
            shutdown,
            Duration::from_secs(1),
        )
        .await;
        assert_eq!(result.is_err(), fail_export);
        let restored = MeteringLedger::open_persistent(wal).expect("restored WAL");
        assert_eq!(
            restored.unacked_len(),
            0,
            "ACK follows durable consumer apply"
        );
        assert_eq!(restored.last_sequence(), 1);
        assert!(
            !meter.healthy(),
            "export lifecycle closed intake before returning"
        );
        if disabled {
            assert!(!path.join("outbox.json").exists());
        } else {
            let outbox = control_meter::Outbox::open(path.join("outbox.json"), lease.token())
                .expect("outbox");
            assert!(outbox.active().is_empty());
            assert_eq!(
                outbox.pending().is_some(),
                fail_export,
                "failed export remains durable; successful shutdown flushes final replay"
            );
        }
        drop(meter);
        drop(lease);
        std::fs::remove_dir_all(path).expect("cleanup");
    }
    #[tokio::test]
    async fn shutdown_replays_acks_then_flushes_before_owner_retirement() {
        lifecycle(false, false).await;
    }
    #[tokio::test]
    async fn final_export_failure_is_reported_and_retains_pending_outbox() {
        lifecycle(true, false).await;
    }
    #[tokio::test]
    async fn disabled_shutdown_acks_without_opening_outbox() {
        lifecycle(false, true).await;
    }
}
