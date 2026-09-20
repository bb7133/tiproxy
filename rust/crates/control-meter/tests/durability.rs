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

//! Crash, retry, and ownership coverage for the native durable meter.

#![allow(clippy::unwrap_used)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use control_meter::{
    Batch, Checkpoint, Consumer, Delta, DurableSink, Error, Outbox, Snapshot, SourceBaseline,
    SourceKey,
};
use control_plane::ownership::{OwnerLease, OwnerScope, OwnerToken, OwnershipRegistry};

static NEXT: AtomicU64 = AtomicU64::new(1);
const PRODUCER: &str = "0123456789abcdef0123456789abcdef";

struct Fixture {
    dir: PathBuf,
    registry: OwnershipRegistry,
    lease: OwnerLease,
}

impl Fixture {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "tiproxy-cp-meter-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&dir).unwrap();
        let registry = OwnershipRegistry::new();
        let lease = registry.claim(OwnerScope::Process, "meter-test").unwrap();
        Self {
            dir,
            registry,
            lease,
        }
    }
    fn owner(&self) -> OwnerToken {
        self.lease.token()
    }
    fn outbox(&self) -> Outbox {
        Outbox::open(self.dir.join("outbox.json"), self.owner()).unwrap()
    }
    fn consumer(&self) -> Consumer<Outbox> {
        Consumer::open(self.dir.join("consumer.json"), self.owner(), self.outbox()).unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn batch(sequence: u64, inbound: u64, outbound: u64) -> Batch {
    Batch {
        producer_id: PRODUCER.into(),
        sequence,
        snapshots: vec![Snapshot {
            key: SourceKey {
                connection_id: 1,
                process_generation: 1,
                backend_generation: 1,
            },
            baseline: SourceBaseline {
                backend_id: "backend-a".into(),
                cluster_name: "cluster".into(),
                keyspace: "ks".into(),
                local: false,
                public_endpoint: false,
                inbound_bytes: inbound,
                outbound_bytes: outbound,
                inbound_wrap_epoch: 0,
                outbound_wrap_epoch: 0,
            },
            final_sample: false,
        }],
    }
}

#[test]
fn absolute_dedup_restart_redirect_final_and_new_generation() {
    let f = Fixture::new();
    let mut c = f.consumer();
    assert!(c.apply(&batch(1, 10, 5)).unwrap());
    assert!(
        !c.apply(&batch(1, 999, 999)).unwrap(),
        "historical sequence is a Go-compatible no-op"
    );
    assert_eq!(
        (
            c.totals()[0].response_bytes,
            c.totals()[0].cross_location_bytes
        ),
        (10, 15)
    );
    drop(c);
    let mut c = f.consumer();
    assert!(c.apply(&batch(2, 15, 8)).unwrap());
    let mut next = batch(3, 20, 10);
    next.snapshots[0].final_sample = true;
    let mut redirected = batch(3, 7, 3).snapshots.remove(0);
    redirected.key.backend_generation = 2;
    redirected.baseline.backend_id = "backend-b".into();
    redirected.baseline.public_endpoint = true;
    next.snapshots.push(redirected);
    assert!(c.apply(&next).unwrap());
    let mut restart = batch(4, 2, 1);
    restart.snapshots[0].key.process_generation = 2;
    assert!(c.apply(&restart).unwrap());
    let stored: serde_json::Value =
        serde_json::from_slice(&fs::read(f.dir.join("consumer.json")).unwrap()).unwrap();
    assert_eq!(stored["sources"].as_array().unwrap().len(), 1);
    assert_eq!(c.sink().active()[0].private_response_bytes, 22);
    assert_eq!(c.sink().active()[0].public_response_bytes, 7);
    assert_eq!(c.sink().active()[0].cross_az_bytes, 43);
    assert_eq!(c.sink().checkpoint().unwrap().sequence, 4);
}

#[test]
fn invalid_input_never_changes_durable_state() {
    let f = Fixture::new();
    let mut c = f.consumer();
    c.apply(&batch(1, 10, 5)).unwrap();
    let before = fs::read(f.dir.join("consumer.json")).unwrap();
    let mut cases = vec![batch(3, 20, 10), batch(2, 9, 10)];
    let mut changed = batch(2, 20, 10);
    changed.snapshots[0].baseline.keyspace = "other".into();
    cases.push(changed);
    let mut duplicate = batch(2, 20, 10);
    duplicate.snapshots.push(duplicate.snapshots[0].clone());
    cases.push(duplicate);
    let mut mixed = batch(2, 20, 10);
    let mut second = mixed.snapshots[0].clone();
    second.key.connection_id = 2;
    second.key.process_generation = 2;
    mixed.snapshots.push(second);
    cases.push(mixed);
    let mut unknown = batch(2, 20, 10);
    unknown.snapshots[0].key.backend_generation = 0;
    cases.push(unknown);
    for invalid in cases {
        assert!(c.apply(&invalid).is_err());
        assert!(c.healthy());
        assert_eq!(c.checkpoint().sequence, 1);
        assert_eq!(fs::read(f.dir.join("consumer.json")).unwrap(), before);
    }
}

#[test]
fn one_wrap_is_accounted_without_resetting_attribution() {
    let f = Fixture::new();
    let mut c = f.consumer();
    let mut first = batch(1, u64::MAX - 2, 0);
    first.snapshots[0].baseline.local = true;
    c.apply(&first).unwrap();
    // Export the first window so the finite durable aggregate can accept more.
    let first_window = c.sink_mut().seal(60).unwrap().unwrap();
    c.sink_mut().exported(&first_window).unwrap();
    let mut next = first.clone();
    next.sequence = 2;
    next.snapshots[0].baseline.inbound_bytes = 4;
    next.snapshots[0].baseline.inbound_wrap_epoch = 1;
    c.apply(&next).unwrap();
    assert_eq!(c.sink().active()[0].private_response_bytes, 7);
    assert_eq!(
        c.totals()[0].response_bytes,
        u64::MAX,
        "diagnostic totals saturate as Go does"
    );
    next.sequence = 3;
    next.snapshots[0].baseline.inbound_wrap_epoch = 3;
    assert!(c.apply(&next).is_err());
}

#[test]
fn export_window_retries_identically_across_restart_and_new_traffic() {
    let f = Fixture::new();
    let mut c = f.consumer();
    c.apply(&batch(1, 10, 5)).unwrap();
    let id = c.sink().self_id().to_owned();
    let sealed = c.sink_mut().seal(60).unwrap().unwrap();
    c.sink_mut().export_failed();
    assert!(!c.healthy());
    assert_eq!(c.sink_mut().seal(120).unwrap().unwrap(), sealed);
    drop(c);
    let mut c = f.consumer();
    c.apply(&batch(2, 30, 15)).unwrap();
    assert_eq!(c.sink().self_id(), id);
    assert_eq!(c.sink_mut().seal(180).unwrap().unwrap(), sealed);
    let mut stale = sealed.clone();
    stale.timestamp = 120;
    assert!(c.sink_mut().exported(&stale).is_err());
    c.sink_mut().exported(&sealed).unwrap();
    let second = c.sink_mut().seal(180).unwrap().unwrap();
    assert_eq!(second.data[0].private_response_bytes, 20);
    assert_eq!(second.data[0].cross_az_bytes, 30);
    assert_eq!(second.timestamp, 180);
}

struct InterruptedSink {
    inner: Outbox,
    after_commit: bool,
}
impl DurableSink for InterruptedSink {
    fn healthy(&self) -> bool {
        self.inner.healthy()
    }
    fn checkpoint(&self) -> Option<Checkpoint> {
        self.inner.checkpoint()
    }
    fn apply(&mut self, producer: &str, sequence: u64, deltas: &[Delta]) -> Result<(), Error> {
        if self.after_commit {
            self.inner.apply(producer, sequence, deltas)?;
        }
        Err(Error::Io(std::io::Error::other(
            "simulated process stop around sink commit",
        )))
    }
}

#[test]
fn pending_replay_before_and_after_sink_commit_is_exactly_once() {
    for after_commit in [false, true] {
        let f = Fixture::new();
        let sink = InterruptedSink {
            inner: f.outbox(),
            after_commit,
        };
        let mut c = Consumer::open(f.dir.join("consumer.json"), f.owner(), sink).unwrap();
        assert!(c.apply(&batch(1, 10, 5)).is_err());
        assert!(!c.healthy());
        assert!(
            c.apply(&batch(1, 10, 5)).is_err(),
            "a failed consumer cannot ACK until reopened"
        );
        drop(c);
        let mut resumed = f.consumer();
        assert!(!resumed.apply(&batch(1, 10, 5)).unwrap());
        assert!(resumed.healthy());
        assert_eq!(resumed.sink().active()[0].private_response_bytes, 10);
        assert_eq!(resumed.sink().active()[0].cross_az_bytes, 15);
        resumed.apply(&batch(2, 20, 8)).unwrap();
        assert_eq!(resumed.sink().active()[0].private_response_bytes, 20);
    }
}

#[test]
fn corrupt_files_and_sink_checkpoint_loss_are_fatal() {
    let f = Fixture::new();
    let mut c = f.consumer();
    c.apply(&batch(1, 10, 5)).unwrap();
    drop(c);
    fs::remove_file(f.dir.join("outbox.json")).unwrap();
    assert!(Consumer::open(f.dir.join("consumer.json"), f.owner(), f.outbox()).is_err());
    fs::write(f.dir.join("outbox.json"), b"not JSON").unwrap();
    assert!(Outbox::open(f.dir.join("outbox.json"), f.owner()).is_err());
    fs::remove_file(f.dir.join("outbox.json")).unwrap();
    let _fresh = f.outbox();
    fs::set_permissions(f.dir.join("outbox.json"), fs::Permissions::from_mode(0o644)).unwrap();
    assert!(Outbox::open(f.dir.join("outbox.json"), f.owner()).is_err());
}

#[test]
fn persistence_failure_and_owner_retirement_prevent_ack() {
    let f = Fixture::new();
    let mut c = f.consumer();
    fs::rename(&f.dir, f.dir.with_extension("saved")).unwrap();
    fs::write(&f.dir, b"not a directory").unwrap();
    assert!(c.apply(&batch(1, 10, 5)).is_err());
    assert!(!c.healthy());
    fs::remove_file(&f.dir).unwrap();
    fs::rename(f.dir.with_extension("saved"), &f.dir).unwrap();
    drop(c);
    let mut c = f.consumer();
    f.lease.release();
    assert!(matches!(c.apply(&batch(1, 10, 5)), Err(Error::Retired)));
    assert!(!c.healthy());
}

#[tokio::test]
async fn local_export_matches_sdk_fields_and_refuses_existing_object() {
    use control_meter::LocalStore;
    use control_meter::export::{ObjectStore, encode_window, flush};
    use flate2::read::GzDecoder;
    use std::io::Read;
    use std::time::Duration;
    let f = Fixture::new();
    let store = LocalStore::new(&f.dir.join("objects"), "prefix/", true, "0750").unwrap();
    let mut c = f.consumer();
    c.apply(&batch(1, 10, 5)).unwrap();
    let window = c.sink_mut().seal(60).unwrap().unwrap();
    let object = encode_window(c.sink().self_id(), "", &window).unwrap();
    let path = f.dir.join("objects/prefix").join(&object.key);
    assert!(
        flush(c.sink_mut(), &store, "", 120, Duration::from_secs(2))
            .await
            .unwrap()
    );
    assert!(c.sink().pending().is_none());
    let bytes = fs::read(&path).unwrap();
    let mut decoded = String::new();
    GzDecoder::new(bytes.as_slice())
        .read_to_string(&mut decoded)
        .unwrap();
    let value: serde_json::Value = serde_json::from_str(&decoded).unwrap();
    assert_eq!(value["timestamp"], 60);
    assert_eq!(value["part"], 0);
    assert_eq!(value["shared_pool_id"], "default-shared-pool");
    assert_eq!(value["data"][0]["private_outBound_bytes"]["value"], 10);
    assert_eq!(value["data"][0]["crossZone_bytes"]["value"], 15);
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o750
    );
    assert!(store.put_new(&object.key, object.body).await.is_err());
    assert_eq!(fs::read(path).unwrap(), bytes);
}

#[tokio::test]
async fn export_failure_and_timeout_keep_pending_until_success() {
    use control_meter::LocalStore;
    use control_meter::export::{ObjectStore, UploadFuture, flush};
    use std::time::Duration;
    struct Never;
    impl ObjectStore for Never {
        fn put_new<'a>(&'a self, _key: &'a str, _body: Vec<u8>) -> UploadFuture<'a> {
            Box::pin(std::future::pending())
        }
    }
    let f = Fixture::new();
    let mut c = f.consumer();
    c.apply(&batch(1, 10, 5)).unwrap();
    let store = LocalStore::new(&f.dir.join("absent"), "", false, "").unwrap();
    assert!(
        flush(c.sink_mut(), &store, "pool", 60, Duration::from_secs(2))
            .await
            .is_err()
    );
    let window = c.sink().pending().unwrap().clone();
    assert!(!c.healthy());
    assert!(
        flush(c.sink_mut(), &Never, "pool", 120, Duration::from_millis(1))
            .await
            .is_err()
    );
    assert_eq!(c.sink().pending().unwrap(), &window);
    let store = LocalStore::new(&f.dir.join("objects"), "", true, "").unwrap();
    assert!(
        flush(c.sink_mut(), &store, "pool", 180, Duration::from_secs(2))
            .await
            .unwrap()
    );
    assert!(c.healthy());
    assert!(c.sink().pending().is_none());
}

struct GateStore {
    requests: std::sync::Mutex<Vec<(String, Vec<u8>)>>,
    started: tokio::sync::Semaphore,
    release: tokio::sync::Semaphore,
    fail: std::sync::atomic::AtomicBool,
}

impl GateStore {
    fn new() -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self {
            requests: std::sync::Mutex::new(Vec::new()),
            started: tokio::sync::Semaphore::new(0),
            release: tokio::sync::Semaphore::new(0),
            fail: std::sync::atomic::AtomicBool::new(false),
        })
    }
    async fn started(&self) {
        tokio::time::timeout(std::time::Duration::from_secs(5), self.started.acquire())
            .await
            .unwrap()
            .unwrap()
            .forget();
    }
}

struct SharedGateStore(std::sync::Arc<GateStore>);

impl control_meter::export::ObjectStore for SharedGateStore {
    fn put_new<'a>(
        &'a self,
        key: &'a str,
        body: Vec<u8>,
    ) -> control_meter::export::UploadFuture<'a> {
        Box::pin(async move {
            self.0.requests.lock().unwrap().push((key.to_owned(), body));
            self.0.started.add_permits(1);
            self.0.release.acquire().await.unwrap().forget();
            if self.0.fail.load(Ordering::SeqCst) {
                Err(Error::Export("injected"))
            } else {
                Ok(())
            }
        })
    }
}

#[tokio::test]
async fn runtime_ingests_during_upload_and_shutdown_flushes_the_final_delta() {
    use control_meter::runtime::Meter;
    let f = Fixture::new();
    let store = GateStore::new();
    let meter = Meter::new(f.consumer(), SharedGateStore(store.clone()), String::new());
    meter.apply(&batch(1, 10, 5)).unwrap();
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let worker = {
        let meter = meter.clone();
        tokio::spawn(async move { meter.run(shutdown_rx).await })
    };
    store.started().await;
    // A slow network must not block the second batch's durable ACK.
    meter.apply(&batch(2, 15, 8)).unwrap();
    assert_eq!(meter.checkpoint().unwrap().sequence, 2);
    let disk: serde_json::Value =
        serde_json::from_slice(&fs::read(f.dir.join("outbox.json")).unwrap()).unwrap();
    assert_eq!(disk["pending"]["data"][0]["private_response_bytes"], 10);
    assert_eq!(disk["data"][0]["private_response_bytes"], 5);
    shutdown_tx.send_replace(true);
    store.release.add_permits(1);
    store.started().await;
    assert!(
        !meter.healthy(),
        "shutdown must close intake before the final upload"
    );
    assert!(meter.apply(&batch(3, 20, 10)).is_err());
    store.release.add_permits(1);
    tokio::time::timeout(std::time::Duration::from_secs(5), worker)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let requests = store.requests.lock().unwrap();
    assert_eq!(requests.len(), 2);
    assert_ne!(
        requests[0].0, requests[1].0,
        "the final delta needs a separate minute key"
    );
    for ((_, compressed), expected) in requests.iter().zip([10, 5]) {
        let payload: serde_json::Value =
            serde_json::from_reader(flate2::read::GzDecoder::new(compressed.as_slice())).unwrap();
        assert_eq!(
            payload["data"][0]["private_outBound_bytes"]["value"],
            expected
        );
    }
    let disk: serde_json::Value =
        serde_json::from_slice(&fs::read(f.dir.join("outbox.json")).unwrap()).unwrap();
    assert!(disk.get("pending").is_none());
    assert_eq!(disk["data"], serde_json::json!([]));
}

#[tokio::test]
async fn runtime_upload_failure_pauses_intake_without_poisoning_the_consumer() {
    use control_meter::runtime::Meter;
    use std::time::Duration;
    let f = Fixture::new();
    let store = GateStore::new();
    store.fail.store(true, Ordering::SeqCst);
    store.release.add_permits(2);
    let meter = Meter::new(f.consumer(), SharedGateStore(store.clone()), String::new());
    meter.apply(&batch(1, 10, 5)).unwrap();
    assert!(meter.flush(60, Duration::from_secs(1)).await.is_err());
    assert!(!meter.healthy());
    let before = fs::read(f.dir.join("consumer.json")).unwrap();
    assert!(meter.apply(&batch(2, 15, 8)).is_err());
    assert_eq!(fs::read(f.dir.join("consumer.json")).unwrap(), before);
    store.fail.store(false, Ordering::SeqCst);
    assert!(meter.flush(180, Duration::from_secs(1)).await.unwrap());
    assert!(meter.healthy());
    meter.apply(&batch(2, 15, 8)).unwrap();
    let requests = store.requests.lock().unwrap();
    assert_eq!(
        requests[0], requests[1],
        "retry must keep the pending identity and bytes"
    );
}

#[tokio::test]
async fn runtime_cancelled_upload_keeps_pending_and_serializes_retry() {
    use control_meter::runtime::Meter;
    use std::time::Duration;
    let f = Fixture::new();
    let store = GateStore::new();
    let meter = Meter::new(f.consumer(), SharedGateStore(store.clone()), String::new());
    meter.apply(&batch(1, 10, 5)).unwrap();
    let upload = {
        let meter = meter.clone();
        tokio::spawn(async move { meter.flush(60, Duration::from_secs(5)).await })
    };
    store.started().await;
    let retry = {
        let meter = meter.clone();
        tokio::spawn(async move { meter.flush(120, Duration::from_secs(5)).await })
    };
    tokio::task::yield_now().await;
    assert_eq!(store.requests.lock().unwrap().len(), 1);
    upload.abort();
    assert!(upload.await.unwrap_err().is_cancelled());
    store.started().await;
    store.release.add_permits(1);
    assert!(retry.await.unwrap().unwrap());
    let requests = store.requests.lock().unwrap();
    assert_eq!(requests[0], requests[1]);
    assert!(f.outbox().pending().is_none());
}

#[tokio::test]
async fn runtime_failed_final_export_is_reported_and_remains_durable() {
    use control_meter::runtime::Meter;
    let f = Fixture::new();
    let store = GateStore::new();
    store.fail.store(true, Ordering::SeqCst);
    store.release.add_permits(2);
    let meter = Meter::new(f.consumer(), SharedGateStore(store.clone()), String::new());
    meter.apply(&batch(1, 10, 5)).unwrap();
    let failures = meter.export_failures();
    let (_, shutdown) = tokio::sync::watch::channel(true);
    assert!(meter.run(shutdown).await.is_err());
    assert_eq!(
        *failures.borrow(),
        2,
        "startup and final failure are both observable"
    );
    assert!(!meter.healthy());
    assert!(meter.apply(&batch(2, 15, 8)).is_err());
    let restored = f.outbox();
    assert_eq!(
        restored.pending().unwrap().data[0].private_response_bytes,
        10
    );
    assert_eq!(restored.checkpoint().unwrap().sequence, 1);
}

#[tokio::test]
async fn disabled_service_recovers_pending_without_touching_outbox() {
    use control_meter::{Intake, service::Service};
    let f = Fixture::new();
    // Crash before sink ingestion leaves a durable consumer pending batch.
    let mut interrupted = Consumer::open(
        f.dir.join("consumer.json"),
        f.owner(),
        InterruptedSink {
            inner: f.outbox(),
            after_commit: false,
        },
    )
    .unwrap();
    assert!(interrupted.apply(&batch(1, 10, 5)).is_err());
    drop(interrupted);
    // Disabled startup must neither parse nor repair any preexisting outbox.
    let outbox_path = f.dir.join("outbox.json");
    fs::write(&outbox_path, b"unreadable-as-outbox sentinel").unwrap();
    let config = control_config::MeteringConfig {
        provider_type: "not-a-provider".into(),
        endpoint: "invalid://do-not-open".into(),
        ..Default::default()
    };
    let service = Service::open(
        &config,
        f.dir.join("consumer.json"),
        outbox_path.clone(),
        f.owner(),
    )
    .await
    .unwrap();
    assert!(service.healthy());
    assert!(service.export_failures().is_none());
    assert!(!service.apply(&batch(1, 10, 5)).unwrap());
    assert!(service.apply(&batch(2, 20, 8)).unwrap());
    assert_eq!(service.checkpoint().unwrap().sequence, 2);
    let state: serde_json::Value =
        serde_json::from_slice(&fs::read(f.dir.join("consumer.json")).unwrap()).unwrap();
    assert_eq!(state["pending"], serde_json::json!([]));
    assert_eq!(
        fs::read(&outbox_path).unwrap(),
        b"unreadable-as-outbox sentinel"
    );
    drop(service);
    let restored = Service::open(
        &config,
        f.dir.join("consumer.json"),
        outbox_path.clone(),
        f.owner(),
    )
    .await
    .unwrap();
    assert!(!restored.apply(&batch(2, 20, 8)).unwrap());
    assert!(restored.apply(&batch(3, 21, 9)).unwrap());
    let (_, shutdown) = tokio::sync::watch::channel(true);
    restored.run(shutdown.clone()).await.unwrap();
    assert!(!restored.healthy());
    assert!(restored.apply(&batch(4, 22, 10)).is_err());
    assert!(restored.run(shutdown).await.is_err());
    assert_eq!(
        fs::read(&outbox_path).unwrap(),
        b"unreadable-as-outbox sentinel"
    );
}

#[tokio::test]
async fn service_factory_respects_disabled_predicate_and_rejects_checkpoint_reset() {
    use control_config::{LocalFsMeteringConfig, MeteringConfig};
    use control_meter::{Intake, service::Service};
    let f = Fixture::new();
    for (index, (kind, bucket)) in [("", "bucket"), ("localfs", ""), ("unsupported", "")]
        .into_iter()
        .enumerate()
    {
        let dir = f.dir.join(index.to_string());
        let config = MeteringConfig {
            provider_type: kind.into(),
            bucket: bucket.into(),
            localfs: Some(LocalFsMeteringConfig {
                base_path: dir.join("objects").to_string_lossy().into(),
                create_dirs: true,
                ..Default::default()
            }),
            ..Default::default()
        };
        let service = Service::open(
            &config,
            dir.join("consumer.json"),
            dir.join("outbox.json"),
            f.owner(),
        )
        .await
        .unwrap();
        assert!(service.apply(&batch(1, 10, 5)).unwrap());
        assert!(!dir.join("outbox.json").exists());
        assert!(!dir.join("objects").exists());
    }
    let config = MeteringConfig {
        provider_type: "localfs".into(),
        bucket: "bucket".into(),
        localfs: Some(LocalFsMeteringConfig {
            base_path: f.dir.join("objects").to_string_lossy().into(),
            ..Default::default()
        }),
        ..Default::default()
    };
    // Enabling after acknowledged disabled traffic cannot silently reset billing.
    assert!(
        Service::open(
            &config,
            f.dir.join("0/consumer.json"),
            f.dir.join("0/outbox.json"),
            f.owner()
        )
        .await
        .is_err()
    );
}

#[tokio::test]
async fn service_factory_keeps_localfs_options_and_recovers_pending_export() {
    use control_config::{LocalFsMeteringConfig, MeteringConfig};
    use control_meter::{Intake, service::Service};
    let f = Fixture::new();
    let root = f.dir.join("enabled");
    let mut config = MeteringConfig {
        provider_type: "gcs".into(),
        bucket: "bucket".into(),
        localfs: Some(LocalFsMeteringConfig {
            base_path: root.join("objects").to_string_lossy().into(),
            create_dirs: false,
            permissions: "0700".into(),
        }),
        prefix: "prefix".into(),
        ..Default::default()
    };
    assert!(
        Service::open(
            &config,
            root.join("consumer.json"),
            root.join("outbox.json"),
            f.owner()
        )
        .await
        .is_err()
    );
    assert!(
        !root.exists(),
        "invalid enabled provider must not create durable files"
    );
    config.provider_type = "localfs".into();
    let service = Service::open(
        &config,
        root.join("consumer.json"),
        root.join("outbox.json"),
        f.owner(),
    )
    .await
    .unwrap();
    assert!(!root.join("objects").exists(), "explicit false is retained");
    service.apply(&batch(1, 10, 5)).unwrap();
    let (_, shutdown) = tokio::sync::watch::channel(true);
    assert!(
        service.run(shutdown).await.is_err(),
        "missing destination must retain export"
    );
    let state: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join("outbox.json")).unwrap()).unwrap();
    assert!(state["pending"].is_object());
    drop(service);
    config.localfs.as_mut().unwrap().create_dirs = true;
    let service = Service::open(
        &config,
        root.join("consumer.json"),
        root.join("outbox.json"),
        f.owner(),
    )
    .await
    .unwrap();
    let (_, shutdown) = tokio::sync::watch::channel(true);
    service.run(shutdown).await.unwrap();
    assert!(root.join("objects/prefix/metering/ru").is_dir());
    let state: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join("outbox.json")).unwrap()).unwrap();
    assert!(state["pending"].is_null());
}

#[tokio::test]
async fn disabled_service_still_rejects_corruption_and_retired_owner() {
    use control_meter::{Intake, service::Service};
    let mut f = Fixture::new();
    let config = control_config::MeteringConfig::default();
    let path = f.dir.join("consumer.json");
    let outbox = f.dir.join("outbox.json");
    let service = Service::open(&config, path.clone(), outbox.clone(), f.owner())
        .await
        .unwrap();
    let retired = f.owner();
    let otherregistry = OwnershipRegistry::new();
    f.lease = otherregistry
        .claim(OwnerScope::Process, "other-owner")
        .unwrap();
    assert!(!service.healthy());
    assert!(service.apply(&batch(1, 10, 5)).is_err());
    assert!(
        Service::open(&config, path.clone(), outbox.clone(), retired)
            .await
            .is_err()
    );
    let replacement = f.registry.claim(OwnerScope::Process, "meter-test").unwrap();
    fs::write(&path, b"corrupt consumer").unwrap();
    assert!(
        Service::open(&config, path, outbox, replacement.token())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn credential_maintenance_progresses_during_export_and_is_cancelled_on_exit() {
    use control_meter::export::{MaintenanceFuture, ObjectStore, UploadFuture};
    use control_meter::runtime::Meter;
    use std::sync::{Arc, atomic::AtomicBool};
    use std::time::Duration;

    struct Store {
        lock: tokio::sync::Mutex<()>,
        started: tokio::sync::Semaphore,
        resume: tokio::sync::Notify,
        exited: Arc<AtomicBool>,
    }
    struct ExitFlag(Arc<AtomicBool>);
    impl Drop for ExitFlag {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }
    impl ObjectStore for Store {
        fn maintain(&self) -> MaintenanceFuture<'_> {
            Box::pin(async move {
                let _exit = ExitFlag(self.exited.clone());
                let guard = self.lock.lock().await;
                self.started.add_permits(1);
                self.resume.notified().await;
                drop(guard);
                std::future::pending().await
            })
        }
        fn put_new<'a>(&'a self, _: &'a str, _: Vec<u8>) -> UploadFuture<'a> {
            Box::pin(async move {
                self.started.acquire().await.unwrap().forget();
                self.resume.notify_one();
                // Maintenance must still be polled while this export waits.
                let _guard = self.lock.lock().await;
                Ok(())
            })
        }
    }
    let f = Fixture::new();
    let exited = Arc::new(AtomicBool::new(false));
    let store = Store {
        lock: tokio::sync::Mutex::new(()),
        started: tokio::sync::Semaphore::new(0),
        resume: tokio::sync::Notify::new(),
        exited: exited.clone(),
    };
    let meter = Meter::new(f.consumer(), store, String::new());
    meter.apply(&batch(1, 10, 5)).unwrap();
    let (_, shutdown) = tokio::sync::watch::channel(true);
    tokio::time::timeout(Duration::from_secs(2), meter.run(shutdown))
        .await
        .unwrap()
        .unwrap();
    assert!(exited.load(Ordering::SeqCst));
    assert!(f.outbox().pending().is_none());
}
