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

//! Control-runtime composition tests: the single entry owns the
//! transport, dispatch, and snapshot tasks, and shutdown propagates
//! through the whole chain to a clean join.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use control_proto::control_transport::{ClientConfig, ControlClient, TransportError};
use control_proto::snapshot::{SnapshotError, SnapshotStore, UnixTime};
use control_proto::v1::control_envelope::Body;
use control_proto::v1::{
    ConfigSnapshot, ControlEnvelope, Hello, KeepalivePolicy, Listener, ProxyProtocolMode, Role,
    StateSnapshot, TlsPolicy,
};
use dataplane::control_dispatch::DispatchFatal;
use dataplane::control_runtime::{
    ControlRuntime, ControlRuntimeConfig, process_state_snapshot, spawn_control_runtime,
};

fn runtime_config(socket: std::path::PathBuf) -> ControlRuntimeConfig {
    let hello = Hello {
        role: Role::RustDataplane as i32,
        process_id: "runtime-test".to_owned(),
        supported_versions: vec![1],
        capabilities: vec![1, 2, 3],
        max_frame_bytes: 1024 * 1024,
        ..Hello::default()
    };
    let mut client = ClientConfig::with_defaults(socket, 0, hello);
    client.reconnect_base = Duration::from_millis(10);
    client.reconnect_cap = Duration::from_millis(20);
    ControlRuntimeConfig {
        client,
        tick_interval: Duration::from_millis(50),
        snapshot_queue: 4,
    }
}

/// The runtime owns its whole task chain: with no Go socket present it
/// keeps reconnecting, and `shutdown` cascades — the transport task
/// returns, the forwarder drops, the dispatch inbound closes, the
/// snapshot channel closes — so `join` completes cleanly.
#[tokio::test]
async fn runtime_shutdown_cascades_to_clean_join() {
    let directory = std::env::temp_dir().join(format!("tiproxy-rt-{}", std::process::id()));
    let socket = directory.join("missing-control.sock");
    let Ok(store) = SnapshotStore::new(Vec::new()) else {
        unreachable!("empty allowlist store constructs")
    };
    let Ok(runtime) = spawn_control_runtime(runtime_config(socket), store, |_snapshot: &_| Ok(()))
    else {
        unreachable!("valid configuration spawns")
    };
    let handle = runtime.handle();
    // The session surface is live even while disconnected.
    assert!(
        handle.applied_generation(7).await,
        "the dispatch task accepts notices"
    );
    runtime.shutdown();
    let joined = tokio::time::timeout(Duration::from_secs(2), runtime.join()).await;
    let Ok(Ok(())) = joined else {
        unreachable!("shutdown cascades to a clean join: {joined:?}")
    };
}

fn valid_snapshot() -> StateSnapshot {
    let keepalive = KeepalivePolicy {
        enabled: true,
        idle_millis: 60_000,
        probe_count: 5,
        interval_millis: 3_000,
        user_timeout_millis: 15_000,
    };
    StateSnapshot {
        config: Some(ConfigSnapshot {
            high_memory_reject_threshold: 0.9,
            connection_buffer_bytes: 32 * 1024,
            frontend_keepalive: Some(keepalive),
            healthy_backend_keepalive: Some(keepalive),
            unhealthy_backend_keepalive: Some(keepalive),
            proxy_protocol: ProxyProtocolMode::Disabled as i32,
            listeners: vec![Listener {
                address: "127.0.0.1".to_owned(),
                port: 6000,
                name: "sql-0".to_owned(),
            }],
            server_version: "TiProxy-test".to_owned(),
            frontend_tls: Some(TlsPolicy::default()),
            backend_tls: Some(TlsPolicy::default()),
            ..ConfigSnapshot::default()
        }),
        ..StateSnapshot::default()
    }
}

fn snapshot_envelope(request_id: u64, generation: u64) -> ControlEnvelope {
    ControlEnvelope {
        request_id,
        generation,
        body: Some(Body::StateSnapshot(valid_snapshot())),
        ..ControlEnvelope::default()
    }
}

fn test_now() -> UnixTime {
    UnixTime::since_unix_epoch(Duration::from_secs(1_700_000_000))
}

/// A consumer that rejects a configurable number of applications and
/// counts every call.
struct CountingConsumer {
    calls: Arc<AtomicU64>,
    reject_first: u64,
}

impl dataplane::control_runtime::SnapshotConsumer for CountingConsumer {
    fn apply(
        &mut self,
        _snapshot: &Arc<control_proto::snapshot::ValidatedSnapshot>,
    ) -> Result<(), SnapshotError> {
        let call = self.calls.fetch_add(1, Ordering::Relaxed) + 1;
        if call <= self.reject_first {
            return Err(SnapshotError::invalid("serving side rejected"));
        }
        Ok(())
    }
}

/// The snapshot transaction: a consumer rejection leaves the store on
/// the previous generation and a replay of the SAME generation re-runs
/// the consumer — success is acknowledged only after commit, and a
/// post-commit replay answers OK without re-running the consumer.
#[tokio::test]
async fn consumer_rejection_never_advances_the_store() {
    let Ok(store) = SnapshotStore::new(Vec::new()) else {
        unreachable!("store constructs")
    };
    let calls = Arc::new(AtomicU64::new(0));
    let mut consumer = CountingConsumer {
        calls: Arc::clone(&calls),
        reject_first: 1,
    };

    // First delivery: the consumer rejects generation 1.
    let (answer, applied) =
        process_state_snapshot(&store, &mut consumer, &snapshot_envelope(10, 1), test_now());
    assert_eq!(applied, None, "no applied generation on rejection");
    let Some(Body::SnapshotResult(result)) = &answer.body else {
        unreachable!("the owner answers a snapshot result")
    };
    assert_ne!(
        result.code(),
        control_proto::v1::ErrorCode::Ok,
        "the rejection is answered as a failure"
    );
    assert_eq!(
        answer.request_id, 10,
        "the answer carries the initiating id"
    );
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    let Ok(current) = store.current() else {
        unreachable!("store readable")
    };
    assert!(
        current.is_none(),
        "the store was NOT advanced by the rejected apply"
    );

    // Replay of the SAME generation: the consumer runs again — no
    // false acknowledgement off an advanced store — and now succeeds.
    let (answer, applied) =
        process_state_snapshot(&store, &mut consumer, &snapshot_envelope(11, 1), test_now());
    assert_eq!(applied, Some(1), "committed after consumer success");
    let Some(Body::SnapshotResult(result)) = &answer.body else {
        unreachable!("result body")
    };
    assert_eq!(
        result.code(),
        control_proto::v1::ErrorCode::Ok,
        "success only after consumer + commit"
    );
    assert_eq!(result.applied_generation, 1);
    assert_eq!(calls.load(Ordering::Relaxed), 2, "the consumer ran again");

    // Post-commit replay: committed implies the consumer succeeded —
    // answered OK without re-running it.
    let (answer, applied) =
        process_state_snapshot(&store, &mut consumer, &snapshot_envelope(12, 1), test_now());
    assert_eq!(applied, Some(1));
    let Some(Body::SnapshotResult(result)) = &answer.body else {
        unreachable!("result body")
    };
    assert_eq!(result.code(), control_proto::v1::ErrorCode::Ok);
    assert_eq!(
        calls.load(Ordering::Relaxed),
        2,
        "an idempotent replay does not re-run the consumer"
    );
}

/// The staged token holds the store's writer reservation: a concurrent
/// `apply` of a later generation cannot advance the store between a
/// consumer success and its commit, so "consumer applied N, store at
/// N+1, commit N fails" cannot happen.
#[tokio::test]
async fn staged_token_serializes_concurrent_writers() {
    let Ok(store) = SnapshotStore::new(Vec::new()) else {
        unreachable!("store constructs")
    };
    let store = Arc::new(store);
    let Ok(staged) = store.stage(1, valid_snapshot(), test_now()) else {
        unreachable!("generation 1 stages")
    };
    // A concurrent writer tries to jump to generation 2 while the
    // token is held: it must WAIT, not win.
    let racer = {
        let store = Arc::clone(&store);
        std::thread::spawn(move || store.apply(2, valid_snapshot(), test_now()).is_ok())
    };
    std::thread::sleep(Duration::from_millis(50));
    // The consumer "succeeded" during the reservation: commit MUST
    // succeed — a stale/conflict failure here would split serving and
    // store state.
    let Ok(outcome) = store.commit(staged) else {
        unreachable!("commit cannot fail while the token serializes writers")
    };
    assert!(outcome.changed);
    assert_eq!(outcome.snapshot.generation(), 1);
    let Ok(true) = racer.join() else {
        unreachable!("the delayed writer proceeds after the commit")
    };
    let Ok(Some(current)) = store.current() else {
        unreachable!("store readable")
    };
    assert_eq!(current.generation(), 2, "the racer applied strictly after");
}

fn supervised_client() -> Arc<ControlClient> {
    let directory = std::env::temp_dir().join(format!("tiproxy-sup-{}", std::process::id()));
    let socket = directory.join("missing-control.sock");
    let Ok(client) = ControlClient::new({
        let mut config = runtime_config(socket).client;
        config.reconnect_base = Duration::from_millis(10);
        config
    }) else {
        unreachable!("valid client config")
    };
    Arc::new(client)
}

/// Builds a runtime whose dispatch/snapshot tasks are test-controlled,
/// with a transport stand-in that ends only on requested shutdown —
/// driving exactly the production supervision/arbitration logic.
fn supervise_with(
    dispatch_result: Option<DispatchFatal>,
    snapshot_panics: bool,
) -> (ControlRuntime, Arc<ControlClient>) {
    let client = supervised_client();
    let (snapshot_tx, _snapshot_rx) = tokio::sync::mpsc::channel(1);
    let (handle, _forwarder, real_dispatch) = dataplane::control_dispatch::spawn_control_dispatch(
        Arc::clone(&client),
        snapshot_tx,
        Duration::from_secs(3600),
    );
    real_dispatch.abort();
    let transport = {
        let client = Arc::clone(&client);
        tokio::spawn(async move {
            while !client.is_shutdown() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            Ok::<(), TransportError>(())
        })
    };
    let dispatch = {
        let client = Arc::clone(&client);
        tokio::spawn(async move {
            if let Some(fatal) = dispatch_result {
                return Err(fatal);
            }
            // Ends on the cascade like the production loop (whose
            // channels close when the transport stops).
            while !client.is_shutdown() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            Ok(())
        })
    };
    let snapshots = if snapshot_panics {
        let task = tokio::spawn(std::future::pending::<()>());
        task.abort();
        task
    } else {
        let client = Arc::clone(&client);
        tokio::spawn(async move {
            while !client.is_shutdown() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
    };
    (
        ControlRuntime::supervise(Arc::clone(&client), handle, transport, dispatch, snapshots),
        client,
    )
}

/// Supervisor arbitration: a dispatch fatal and a clean snapshot exit
/// are ready simultaneously — whichever the supervisor observes first,
/// it joins everything and the REAL error wins; the cascade's clean
/// exits never mask it. The whole runtime converges within a timeout
/// without any explicit `shutdown()` call.
#[tokio::test]
async fn dispatch_fatal_wins_arbitration_over_clean_cascade() {
    let (runtime, _client) = supervise_with(Some(DispatchFatal::IdSpaceExhausted), false);
    let joined = tokio::time::timeout(Duration::from_secs(2), runtime.join()).await;
    let Ok(Err(error)) = joined else {
        unreachable!("the supervisor must surface the dispatch fatal: {joined:?}")
    };
    assert!(
        error.to_string().contains("request-id space is exhausted"),
        "the dispatch fatal is the first error, not the cascade: {error}"
    );
}

/// An unexpectedly terminated snapshot owner (no fatal anywhere else)
/// cancels the siblings and surfaces as the join error — without any
/// explicit `shutdown()` call.
#[tokio::test]
async fn snapshot_owner_death_cancels_siblings_and_errs() {
    let (runtime, _client) = supervise_with(None, true);
    let joined = tokio::time::timeout(Duration::from_secs(2), runtime.join()).await;
    let Ok(Err(error)) = joined else {
        unreachable!("the supervisor must surface the snapshot death: {joined:?}")
    };
    assert!(
        error.to_string().contains("snapshot owner"),
        "the snapshot owner's death is the root cause: {error}"
    );
}

/// A transport that exits cleanly WITHOUT a requested shutdown is an
/// unexpected termination, not a success.
#[tokio::test]
async fn unrequested_transport_exit_is_an_error() {
    let client = supervised_client();
    let (snapshot_tx, _snapshot_rx) = tokio::sync::mpsc::channel(1);
    let (handle, _forwarder, real_dispatch) = dataplane::control_dispatch::spawn_control_dispatch(
        Arc::clone(&client),
        snapshot_tx,
        Duration::from_secs(3600),
    );
    real_dispatch.abort();
    let transport = tokio::spawn(async { Ok::<(), TransportError>(()) });
    let dispatch = {
        let client = Arc::clone(&client);
        tokio::spawn(async move {
            while !client.is_shutdown() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            Ok(())
        })
    };
    let snapshots = {
        let client = Arc::clone(&client);
        tokio::spawn(async move {
            while !client.is_shutdown() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
    };
    let runtime = ControlRuntime::supervise(client, handle, transport, dispatch, snapshots);
    let joined = tokio::time::timeout(Duration::from_secs(2), runtime.join()).await;
    let Ok(Err(error)) = joined else {
        unreachable!("unrequested transport exit must err: {joined:?}")
    };
    assert!(error.to_string().contains("without a requested shutdown"));
}
