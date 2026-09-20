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
    _registry: OwnershipRegistry,
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
            _registry: registry,
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
    assert_eq!(c.sink().checkpoint().sequence, 4);
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
    fn checkpoint(&self) -> Checkpoint {
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
