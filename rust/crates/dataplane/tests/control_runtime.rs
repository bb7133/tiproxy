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

use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use control_proto::control_transport::{
    ClientConfig, ConnectionState, ControlClient, SessionMeta, TransportError,
};
use control_proto::snapshot::{SnapshotError, SnapshotLineage, SnapshotStore, UnixTime};
use control_proto::v1::control_envelope::Body;
use control_proto::v1::{
    ConfigSnapshot, ControlEnvelope, Hello, KeepalivePolicy, Listener, ProxyProtocolMode, Role,
    StateSnapshot, TlsPolicy,
};
use dataplane::control_dispatch::DispatchFatal;
use dataplane::control_dispatch::{
    ExpectResponseError, MeteringRecordError, ResponseKind, TaggedEnvelope,
    spawn_control_dispatch_with_handler,
};
use dataplane::control_runtime::{
    ControlRuntime, ControlRuntimeConfig, SnapshotStep, process_state_snapshot,
    snapshot_owner_step, spawn_control_runtime,
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
    let Ok(runtime) = spawn_control_runtime(runtime_config(socket), store, |_snapshot: &_| {
        std::future::ready(Ok(()))
    }) else {
        unreachable!("valid configuration spawns")
    };
    let handle = runtime.handle();
    // The session surface is live even while disconnected.
    assert!(
        handle
            .applied_generation(7, Arc::from("go-fixture"), 1_700_000_000_000)
            .await,
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

fn test_session() -> SessionMeta {
    SessionMeta {
        serial: 7,
        epoch: 1,
        peer_process_id: Arc::from("go-fixture"),
        peer_started_unix_millis: 1_700_000_000_000,
    }
}

fn tagged(envelope: ControlEnvelope) -> TaggedEnvelope {
    TaggedEnvelope {
        envelope,
        origin: test_session(),
    }
}

fn tagged_as(envelope: ControlEnvelope, process_id: &str, serial: u64) -> TaggedEnvelope {
    TaggedEnvelope {
        envelope,
        origin: SessionMeta {
            serial,
            epoch: 1,
            peer_process_id: Arc::from(process_id),
            peer_started_unix_millis: 1_700_000_000_000,
        },
    }
}

/// A live-session state watch matching a `tagged_as` origin lineage.
fn live_state_as(process_id: &str, serial: u64) -> tokio::sync::watch::Receiver<ConnectionState> {
    let (keep_tx, rx) = tokio::sync::watch::channel(ConnectionState::Connected {
        epoch: 1,
        capabilities: 0,
        serial,
        peer_process_id: Arc::from(process_id),
        peer_started_unix_millis: 1_700_000_000_000,
    });
    std::mem::forget(keep_tx);
    rx
}

/// A watch receiver whose live session matches a given origin's Go
/// lineage — the owner's lineage gate passes for that origin.
fn live_state_for(origin: &SessionMeta) -> tokio::sync::watch::Receiver<ConnectionState> {
    let (keep_tx, rx) = tokio::sync::watch::channel(ConnectionState::Connected {
        epoch: origin.epoch,
        capabilities: 0,
        serial: origin.serial,
        peer_process_id: Arc::clone(&origin.peer_process_id),
        peer_started_unix_millis: origin.peer_started_unix_millis,
    });
    // Keep the sender alive so borrow() never sees a closed channel.
    std::mem::forget(keep_tx);
    rx
}

/// A watch receiver whose live session is a DIFFERENT Go lineage than
/// `origin` — the owner's lineage gate drops that origin.
fn foreign_state_for(origin: &SessionMeta) -> tokio::sync::watch::Receiver<ConnectionState> {
    let (tx, rx) = tokio::sync::watch::channel(ConnectionState::Connected {
        epoch: origin.epoch,
        capabilities: 0,
        serial: origin.serial + 1,
        peer_process_id: Arc::from("go-successor"),
        peer_started_unix_millis: origin.peer_started_unix_millis + 1,
    });
    std::mem::forget(tx);
    rx
}

/// `valid_snapshot` with a different listener port — equal generation,
/// different content.
fn variant_snapshot() -> StateSnapshot {
    let mut snapshot = valid_snapshot();
    if let Some(config) = snapshot.config.as_mut() {
        config.listeners[0].port = 6001;
    }
    snapshot
}

fn variant_envelope(request_id: u64, generation: u64) -> ControlEnvelope {
    ControlEnvelope {
        request_id,
        generation,
        body: Some(Body::StateSnapshot(variant_snapshot())),
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
        _still_current: &(dyn Fn() -> bool + Send + Sync),
    ) -> impl Future<Output = Result<(), SnapshotError>> + Send {
        let call = self.calls.fetch_add(1, Ordering::Relaxed) + 1;
        if call <= self.reject_first {
            return std::future::ready(Err(SnapshotError::invalid("serving side rejected")));
        }
        std::future::ready(Ok(()))
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
    let owner_state = live_state_for(&test_session());

    // First delivery: the consumer rejects generation 1.
    let (answer, applied) = process_state_snapshot(
        &store,
        &mut consumer,
        &owner_state,
        &tagged(snapshot_envelope(10, 1)),
        test_now(),
    )
    .await;
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
    let (answer, applied) = process_state_snapshot(
        &store,
        &mut consumer,
        &owner_state,
        &tagged(snapshot_envelope(11, 1)),
        test_now(),
    )
    .await;
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
    let (answer, applied) = process_state_snapshot(
        &store,
        &mut consumer,
        &owner_state,
        &tagged(snapshot_envelope(12, 1)),
        test_now(),
    )
    .await;
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
    let Ok(staged) = store.stage(
        1,
        valid_snapshot(),
        test_now(),
        SnapshotLineage::for_tests("go-fixture"),
    ) else {
        unreachable!("generation 1 stages")
    };
    // A concurrent writer tries to jump to generation 2 while the
    // token is held: it must WAIT, not win.
    let racer = {
        let store = Arc::clone(&store);
        std::thread::spawn(move || {
            store
                .apply(
                    2,
                    valid_snapshot(),
                    test_now(),
                    SnapshotLineage::for_tests("go-fixture"),
                )
                .is_ok()
        })
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

/// Abandoning the downstream phase releases the owned reservation without
/// committing the candidate, so a waiting synchronous writer can continue.
#[tokio::test]
async fn dropped_staged_token_releases_concurrent_writer() {
    let Ok(store) = SnapshotStore::new(Vec::new()) else {
        unreachable!("store constructs")
    };
    let store = Arc::new(store);
    let Ok(staged) = store.stage(
        1,
        valid_snapshot(),
        test_now(),
        SnapshotLineage::for_tests("go-fixture"),
    ) else {
        unreachable!("generation 1 stages")
    };
    let (started_tx, started_rx) = std::sync::mpsc::sync_channel(0);
    let (finished_tx, finished_rx) = std::sync::mpsc::sync_channel(0);
    let racer = {
        let store = Arc::clone(&store);
        std::thread::spawn(move || {
            let _ = started_tx.send(());
            let applied = store
                .apply(
                    2,
                    valid_snapshot(),
                    test_now(),
                    SnapshotLineage::for_tests("go-fixture"),
                )
                .is_ok();
            let _ = finished_tx.send(applied);
        })
    };
    let Ok(()) = started_rx.recv() else {
        unreachable!("racer started")
    };
    assert_eq!(
        finished_rx.recv_timeout(Duration::from_millis(20)),
        Err(std::sync::mpsc::RecvTimeoutError::Timeout),
        "the writer waits while the staged token is alive"
    );

    drop(staged);
    let Ok(true) = finished_rx.recv() else {
        unreachable!("the writer proceeds after the token is dropped")
    };
    let Ok(()) = racer.join() else {
        unreachable!("writer thread joined")
    };
    let Ok(Some(current)) = store.current() else {
        unreachable!("store readable")
    };
    assert_eq!(current.generation(), 2);
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
        let task = tokio::spawn(async {
            std::future::pending::<()>().await;
            Ok(())
        });
        task.abort();
        task
    } else {
        let client = Arc::clone(&client);
        tokio::spawn(async move {
            while !client.is_shutdown() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            Ok(())
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
            Ok(())
        })
    };
    let runtime = ControlRuntime::supervise(client, handle, transport, dispatch, snapshots);
    let joined = tokio::time::timeout(Duration::from_secs(2), runtime.join()).await;
    let Ok(Err(error)) = joined else {
        unreachable!("unrequested transport exit must err: {joined:?}")
    };
    assert!(error.to_string().contains("without a requested shutdown"));
}

/// Public-API metering ownership: every failure hands the ORIGINAL
/// delta back to the producer — ledger rejection under saturation and
/// dispatch unavailability alike — so a failed handoff never consumes
/// the value.
#[tokio::test]
async fn record_metering_returns_the_delta_on_every_failure() {
    // Saturate a handler exactly to the fail-closed bound…
    let mut handler = dataplane::control_dispatch::ControlCommandHandler::new();
    for index in 0..1024_u32 {
        assert!(
            handler
                .metering()
                .record(control_proto::v1::MeteringDelta {
                    keyspace: format!("ks-{index}"),
                    backend_id: "tidb-a".to_owned(),
                    public_endpoint: false,
                    response_bytes: 1,
                    cross_location_bytes: 0,
                })
                .is_ok()
        );
        assert!(handler.seal_metering().is_ok());
    }
    for index in 0..1024_u32 {
        assert!(
            handler
                .metering()
                .record(control_proto::v1::MeteringDelta {
                    keyspace: format!("open-{index}"),
                    backend_id: "tidb-a".to_owned(),
                    public_endpoint: false,
                    response_bytes: 1,
                    cross_location_bytes: 0,
                })
                .is_ok()
        );
    }
    // …and put it behind the PUBLIC handle.
    let client = supervised_client();
    let (snapshot_tx, _snapshot_rx) = tokio::sync::mpsc::channel(1);
    let (handle, _forwarder, dispatch) = spawn_control_dispatch_with_handler(
        handler,
        Arc::clone(&client),
        snapshot_tx,
        Duration::from_secs(3600),
    );

    let original = control_proto::v1::MeteringDelta {
        keyspace: "one-too-many".to_owned(),
        backend_id: "tidb-a".to_owned(),
        public_endpoint: false,
        response_bytes: 7,
        cross_location_bytes: 3,
    };
    let Err(MeteringRecordError::Rejected { delta, error: _ }) =
        handle.record_metering(original.clone()).await
    else {
        unreachable!("saturation rejects through the public API")
    };
    assert_eq!(delta, original, "the exact delta comes back to its owner");

    // Dispatch gone: same ownership contract.
    dispatch.abort();
    let _ = dispatch.await;
    let Err(MeteringRecordError::DispatchUnavailable { delta }) =
        handle.record_metering(original.clone()).await
    else {
        unreachable!("a dead dispatcher rejects, never consumes")
    };
    assert_eq!(delta, original);
    client.shutdown();
}

/// Public-API expectation arming is fail-closed: only a live session
/// WITH a response channel is armed; unknown sessions and channel-less
/// registrations refuse — the caller is never told to start an
/// exchange whose answer could not be delivered.
#[tokio::test]
async fn expect_response_verdicts_are_fail_closed() {
    let client = supervised_client();
    let (snapshot_tx, _snapshot_rx) = tokio::sync::mpsc::channel(1);
    let (handle, _forwarder, dispatch) = spawn_control_dispatch_with_handler(
        dataplane::control_dispatch::ControlCommandHandler::new(),
        Arc::clone(&client),
        snapshot_tx,
        Duration::from_secs(3600),
    );

    // Unknown connection.
    assert_eq!(
        handle
            .expect_response(9, 1, ResponseKind::RouteAssignment)
            .await,
        Err(ExpectResponseError::UnknownConnection)
    );

    // Registered WITHOUT a response channel.
    let (control_tx, _control_rx) = tokio::sync::mpsc::channel(4);
    let identity = control_proto::v1::ConnectionIdentity {
        connection_id: 1,
        listener_address: "0.0.0.0:6000".to_owned(),
        client_address: "10.9.8.7:1".to_owned(),
        proxy_address: "10.0.0.9:6000".to_owned(),
        public_endpoint: false,
    };
    assert!(
        handle
            .register_session(
                identity.clone(),
                "ns-a".to_owned(),
                7,
                "sql-a".to_owned(),
                control_tx.clone(),
                None,
            )
            .await
    );
    assert_eq!(
        handle
            .expect_response(1, 1, ResponseKind::RouteAssignment)
            .await,
        Err(ExpectResponseError::NoResponseChannel)
    );

    // Registered WITH a channel: armed.
    let (resp_tx, _resp_rx) = tokio::sync::mpsc::channel(1);
    let identity2 = control_proto::v1::ConnectionIdentity {
        connection_id: 2,
        ..identity
    };
    assert!(
        handle
            .register_session(
                identity2,
                "ns-a".to_owned(),
                7,
                "sql-a".to_owned(),
                control_tx,
                Some(resp_tx),
            )
            .await
    );
    assert_eq!(
        handle
            .expect_response(2, 5, ResponseKind::RouteAssignment)
            .await,
        Ok(())
    );

    dispatch.abort();
    assert_eq!(
        handle
            .expect_response(2, 6, ResponseKind::RouteAssignment)
            .await,
        Err(ExpectResponseError::DispatchUnavailable)
    );
    client.shutdown();
}

/// The snapshot owner's shutdown boundary: a requested shutdown
/// interrupting the applied-generation/answer path is the normal
/// cascade (clean exit), while a dispatcher that died UNEXPECTEDLY
/// under an in-flight snapshot is the owner's error.
#[tokio::test]
async fn snapshot_owner_shutdown_boundary() {
    // Clean side: shutdown already requested, dispatch alive — the
    // barrier passes and the answer send normalizes Closed to a clean
    // exit.
    let client = supervised_client();
    let (snapshot_tx, _snapshot_rx) = tokio::sync::mpsc::channel(1);
    let (handle, _forwarder, dispatch) = spawn_control_dispatch_with_handler(
        dataplane::control_dispatch::ControlCommandHandler::new(),
        Arc::clone(&client),
        snapshot_tx,
        Duration::from_secs(3600),
    );
    client.shutdown();
    let Ok(store) = SnapshotStore::new(Vec::new()) else {
        unreachable!("store constructs")
    };
    let mut consumer = CountingConsumer {
        calls: Arc::new(AtomicU64::new(0)),
        reject_first: 0,
    };
    let owner_state = live_state_for(&test_session());
    let step = snapshot_owner_step(
        &client,
        &handle,
        &store,
        &mut consumer,
        &owner_state,
        &tagged(snapshot_envelope(20, 1)),
    )
    .await;
    let Ok(SnapshotStep::CleanExit) = step else {
        unreachable!("requested shutdown normalizes to a clean exit: {step:?}")
    };
    let Some((generation, _)) = client.last_good_snapshot_age() else {
        unreachable!("committed snapshot updates transport diagnostics")
    };
    assert_eq!(generation, 1);
    dispatch.abort();

    // Fatal side: dispatch died unexpectedly (no shutdown), the
    // barrier cannot be passed — the owner errs for the supervisor.
    let client = supervised_client();
    let (snapshot_tx, _snapshot_rx) = tokio::sync::mpsc::channel(1);
    let (handle, _forwarder, dispatch) = spawn_control_dispatch_with_handler(
        dataplane::control_dispatch::ControlCommandHandler::new(),
        Arc::clone(&client),
        snapshot_tx,
        Duration::from_secs(3600),
    );
    dispatch.abort();
    let _ = dispatch.await;
    let Ok(store) = SnapshotStore::new(Vec::new()) else {
        unreachable!("store constructs")
    };
    let owner_state = live_state_for(&test_session());
    let step = snapshot_owner_step(
        &client,
        &handle,
        &store,
        &mut consumer,
        &owner_state,
        &tagged(snapshot_envelope(21, 1)),
    )
    .await;
    let Err(error) = step else {
        unreachable!("an unexpectedly dead dispatcher must err: {step:?}")
    };
    assert!(error.to_string().contains("applied-generation barrier"));
    client.shutdown();
}

/// Arbitration is select-order independent: transport AND dispatch
/// exit cleanly at the same instant with no shutdown requested —
/// whichever the supervisor observes first, the join must report an
/// unexpected termination, never Ok.
#[tokio::test]
async fn simultaneous_clean_exits_are_still_unexpected() {
    let client = supervised_client();
    let (snapshot_tx, _snapshot_rx) = tokio::sync::mpsc::channel(1);
    let (handle, _forwarder, real_dispatch) = dataplane::control_dispatch::spawn_control_dispatch(
        Arc::clone(&client),
        snapshot_tx,
        Duration::from_secs(3600),
    );
    real_dispatch.abort();
    // Both immediately ready and clean.
    let transport = tokio::spawn(async { Ok::<(), TransportError>(()) });
    let dispatch = tokio::spawn(async { Ok(()) });
    let snapshots = {
        let client = Arc::clone(&client);
        tokio::spawn(async move {
            while !client.is_shutdown() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            Ok(())
        })
    };
    let runtime = ControlRuntime::supervise(client, handle, transport, dispatch, snapshots);
    let joined = tokio::time::timeout(Duration::from_secs(2), runtime.join()).await;
    let Ok(Err(error)) = joined else {
        unreachable!("simultaneous clean exits must still err: {joined:?}")
    };
    assert!(error.to_string().contains("without a requested shutdown"));
}

/// A snapshot owner that exits cleanly FIRST without a requested
/// shutdown is an unexpected termination too.
#[tokio::test]
async fn snapshot_clean_first_exit_is_unexpected() {
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
            while !client.is_shutdown() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            Ok(())
        })
    };
    let snapshots = tokio::spawn(async { Ok(()) });
    let runtime = ControlRuntime::supervise(client, handle, transport, dispatch, snapshots);
    let joined = tokio::time::timeout(Duration::from_secs(2), runtime.join()).await;
    let Ok(Err(error)) = joined else {
        unreachable!("snapshot clean-first exit must err: {joined:?}")
    };
    assert!(
        error
            .to_string()
            .contains("snapshot owner exited without a requested shutdown"),
        "the first-exit task is named: {error}"
    );
}

/// Fix-2 collision regression: Go restarts and its replacement — a
/// DIFFERENT lineage on the SAME wire epoch value — re-sends the SAME
/// {request id, generation} with DIFFERENT content. The old rules
/// would reject it as a same-generation conflict (or falsely
/// deduplicate byte-equal content); the lineage-aware store applies it
/// as a fresh sequence, and the consumer serves the NEW content.
#[tokio::test]
async fn restarted_go_same_generation_different_content_applies_fresh() {
    let Ok(store) = SnapshotStore::new(Vec::new()) else {
        unreachable!("store constructs")
    };
    let calls = Arc::new(AtomicU64::new(0));
    let mut consumer = CountingConsumer {
        calls: Arc::clone(&calls),
        reject_first: 0,
    };

    // Incarnation A commits {request 1, generation 1}.
    let state_a = live_state_as("go-a", 1);
    let (answer, applied) = process_state_snapshot(
        &store,
        &mut consumer,
        &state_a,
        &tagged_as(snapshot_envelope(1, 1), "go-a", 1),
        test_now(),
    )
    .await;
    assert_eq!(applied, Some(1));
    let Some(Body::SnapshotResult(result)) = &answer.body else {
        unreachable!("result body")
    };
    assert_eq!(result.code(), control_proto::v1::ErrorCode::Ok);
    assert_eq!(calls.load(Ordering::Relaxed), 1);

    // Incarnation B (new lineage, same epoch VALUE, same request id,
    // same generation, different content): fresh sequence, applied,
    // consumer re-ran with the new content.
    let state_b = live_state_as("go-b", 2);
    let (answer, applied) = process_state_snapshot(
        &store,
        &mut consumer,
        &state_b,
        &tagged_as(variant_envelope(1, 1), "go-b", 2),
        test_now(),
    )
    .await;
    assert_eq!(applied, Some(1), "the new lineage's generation 1 commits");
    let Some(Body::SnapshotResult(result)) = &answer.body else {
        unreachable!("result body")
    };
    assert_eq!(
        result.code(),
        control_proto::v1::ErrorCode::Ok,
        "no same-generation conflict across lineages"
    );
    assert_eq!(
        calls.load(Ordering::Relaxed),
        2,
        "the consumer served the replacement content"
    );
    let Ok(Some(current)) = store.current() else {
        unreachable!("store serves the rollover")
    };
    let Some(port) = current
        .raw()
        .config
        .as_ref()
        .and_then(|config| config.listeners.first())
        .map(|listener| listener.port)
    else {
        unreachable!("listener survives the apply")
    };
    assert_eq!(port, 6001, "the NEW lineage's content is the one serving");

    // WITHIN incarnation B the ordinary rules are back: the same
    // generation with different content is a conflict again.
    let (answer, applied) = process_state_snapshot(
        &store,
        &mut consumer,
        &state_b,
        &tagged_as(snapshot_envelope(2, 1), "go-b", 2),
        test_now(),
    )
    .await;
    assert_eq!(applied, None);
    let Some(Body::SnapshotResult(result)) = &answer.body else {
        unreachable!("result body")
    };
    assert_ne!(result.code(), control_proto::v1::ErrorCode::Ok);
    assert_eq!(calls.load(Ordering::Relaxed), 2, "no consumer run");
}

/// Fix-2 lineage-gate regression: a snapshot whose ORIGIN belongs to a
/// DIFFERENT Go lineage than the live session must be dropped BEFORE
/// any transaction side effect — not staged, not consumed, not
/// committed, and never allowed to move last-good or the applied
/// generation. Its desired state belongs to a process that no longer
/// owns the control plane; the live Go re-sends on its own session.
#[tokio::test]
async fn foreign_lineage_snapshot_never_stages_or_advances_state() {
    let client = supervised_client();
    let (snapshot_tx, _snapshot_rx) = tokio::sync::mpsc::channel::<TaggedEnvelope>(1);
    let (handle, _forwarder, dispatch) = spawn_control_dispatch_with_handler(
        dataplane::control_dispatch::ControlCommandHandler::new(),
        Arc::clone(&client),
        snapshot_tx,
        Duration::from_secs(3600),
    );
    let Ok(store) = SnapshotStore::new(Vec::new()) else {
        unreachable!("store constructs")
    };
    let mut consumer = CountingConsumer {
        calls: Arc::new(AtomicU64::new(0)),
        reject_first: 0,
    };
    // The live session is a DIFFERENT Go lineage than the snapshot's
    // origin: the gate must fire before any transaction step.
    let origin = test_session();
    let owner_state = foreign_state_for(&origin);
    let step = snapshot_owner_step(
        &client,
        &handle,
        &store,
        &mut consumer,
        &owner_state,
        &tagged(snapshot_envelope(30, 1)),
    )
    .await;
    let Ok(SnapshotStep::Continue) = step else {
        unreachable!("a foreign-lineage snapshot is dropped, not fatal: {step:?}")
    };
    // NOTHING advanced: no consumer run, no store commit, no last-good.
    assert_eq!(
        consumer.calls.load(Ordering::Relaxed),
        0,
        "the serving consumer never ran"
    );
    let Ok(current) = store.current() else {
        unreachable!("store readable")
    };
    assert!(current.is_none(), "the store was never advanced");
    assert!(
        client.last_good_snapshot_age().is_none(),
        "last-good was never moved by a foreign lineage"
    );
    dispatch.abort();
    client.shutdown();
}

/// Fix-2 companion: a snapshot from the LIVE lineage — including a
/// same-lineage reconnect at a new serial/epoch — still applies once,
/// so the gate is lineage-specific and never blocks the current Go's
/// desired state.
#[tokio::test]
async fn live_lineage_snapshot_applies_even_across_epoch_bump() {
    let client = supervised_client();
    let (snapshot_tx, _snapshot_rx) = tokio::sync::mpsc::channel::<TaggedEnvelope>(1);
    let (handle, _forwarder, dispatch) = spawn_control_dispatch_with_handler(
        dataplane::control_dispatch::ControlCommandHandler::new(),
        Arc::clone(&client),
        snapshot_tx,
        Duration::from_secs(3600),
    );
    let Ok(store) = SnapshotStore::new(Vec::new()) else {
        unreachable!("store constructs")
    };
    let mut consumer = CountingConsumer {
        calls: Arc::new(AtomicU64::new(0)),
        reject_first: 0,
    };
    // Same Go lineage as the origin, but a later serial/epoch (a
    // reconnect): the gate passes on lineage, and the snapshot applies.
    let origin = test_session();
    let (keep_tx, owner_state) = tokio::sync::watch::channel(ConnectionState::Connected {
        epoch: origin.epoch + 5,
        capabilities: 0,
        serial: origin.serial + 5,
        peer_process_id: Arc::clone(&origin.peer_process_id),
        peer_started_unix_millis: origin.peer_started_unix_millis,
    });
    std::mem::forget(keep_tx);
    let step = snapshot_owner_step(
        &client,
        &handle,
        &store,
        &mut consumer,
        &owner_state,
        &tagged(snapshot_envelope(31, 1)),
    )
    .await;
    let Ok(SnapshotStep::Continue) = step else {
        unreachable!("the live lineage's snapshot applies: {step:?}")
    };
    assert_eq!(
        consumer.calls.load(Ordering::Relaxed),
        1,
        "consumer ran once"
    );
    let Ok(Some(current)) = store.current() else {
        unreachable!("the snapshot committed")
    };
    assert_eq!(current.generation(), 1);
    dispatch.abort();
    client.shutdown();
}

/// Fix-2 deadlock-avoidance + applied-generation lineage qualification
/// (the cross-await blocker): the owner must NOT hold the session lease
/// while awaiting the single-threaded dispatcher's applied-generation
/// ack, because the dispatcher can be blocked enqueuing outbound on a
/// lane that only drains after a transport teardown/reconnect — which
/// itself needs the lease. Here the dispatcher is wedged in a blocked
/// send; the owner commits A under the lease, releases it, and enters
/// the barrier. A teardown publisher that models the transport (locks
/// the SAME production lease and publishes Disconnected + Connected B)
/// must converge promptly — proving the lease is free during the
/// barrier. Once the send unblocks, the dispatcher applies the
/// successor and, under session B, REJECTS A's generation; the owner
/// converges. Everything is deadline-bounded.
struct BlockingSender {
    release: tokio::sync::watch::Receiver<bool>,
    next: AtomicU64,
}

impl dataplane::control_dispatch::DispatchSender for BlockingSender {
    fn allocate_request_id(&self) -> Option<u64> {
        Some(self.next.fetch_add(1, Ordering::Relaxed) + 1)
    }

    fn send_envelope(
        &self,
        _envelope: ControlEnvelope,
    ) -> impl Future<Output = Result<(), TransportError>> + Send {
        let mut release = self.release.clone();
        async move {
            // Block until released — models a full outbound lane that
            // does not drain until a reconnect.
            while !*release.borrow() {
                if release.changed().await.is_err() {
                    break;
                }
            }
            Ok(())
        }
    }

    fn send_session_scoped(
        &self,
        envelope: ControlEnvelope,
        _epoch: u64,
    ) -> impl Future<Output = Result<(), TransportError>> + Send {
        self.send_envelope(envelope)
    }
}

#[tokio::test]
async fn owner_releases_lease_before_the_dispatcher_barrier() {
    let client = supervised_client();
    let (release_tx, release_rx) = tokio::sync::watch::channel(false);
    let sender = Arc::new(BlockingSender {
        release: release_rx,
        next: AtomicU64::new(0),
    });
    let (snapshot_tx, _snapshot_rx) = tokio::sync::mpsc::channel::<TaggedEnvelope>(4);
    // One shared state watch drives the dispatcher's active session AND
    // the owner's lineage check.
    let (state_tx, state_rx) = tokio::sync::watch::channel(ConnectionState::Disconnected);
    let caps = 1u64 << 2; // RECONCILE_CONNECTIONS: on_connected sends a reconcile.
    let (handle, _forwarder, dispatch) = dataplane::control_dispatch::spawn_control_dispatch_parts(
        dataplane::control_dispatch::ControlCommandHandler::new(),
        Arc::clone(&sender),
        state_rx.clone(),
        snapshot_tx,
        Duration::from_secs(3600),
    );

    // Publish Connected A: on_connected sends a reconcile request, which
    // blocks on the sender — the dispatcher is now wedged.
    state_tx
        .send(ConnectionState::Connected {
            epoch: 1,
            capabilities: caps,
            serial: 1,
            peer_process_id: Arc::from("go-a"),
            peer_started_unix_millis: 1_700_000_000_000,
        })
        .ok();
    for _ in 0..200 {
        tokio::task::yield_now().await;
    }

    let Ok(store) = SnapshotStore::new(Vec::new()) else {
        unreachable!("store constructs")
    };
    let mut consumer = CountingConsumer {
        calls: Arc::new(AtomicU64::new(0)),
        reject_first: 0,
    };

    // Owner for A: commits + last-good under the lease, releases the
    // lease, then blocks in the applied-generation barrier (dispatcher
    // wedged).
    let owner_client = Arc::clone(&client);
    let owner_state = state_rx.clone();
    let owner = tokio::spawn(async move {
        let step = snapshot_owner_step(
            &owner_client,
            &handle,
            &store,
            &mut consumer,
            &owner_state,
            &tagged_as(snapshot_envelope(50, 1), "go-a", 1),
        )
        .await;
        (owner_client, store, step)
    });
    for _ in 0..200 {
        tokio::task::yield_now().await;
    }

    // The teardown publisher models the transport: it locks the SAME
    // production lease and publishes teardown + successor. If the owner
    // held the lease across the barrier (the deadlock), this would hang;
    // it must converge well within the deadline.
    let teardown_client = Arc::clone(&client);
    let teardown_state = state_tx.clone();
    let teardown = tokio::time::timeout(Duration::from_secs(5), async move {
        let lease = teardown_client.session_lease();
        let _guard = lease.lock().await;
        teardown_state.send(ConnectionState::Disconnected).ok();
        teardown_state
            .send(ConnectionState::Connected {
                epoch: 1,
                capabilities: caps,
                serial: 2,
                peer_process_id: Arc::from("go-b"),
                peer_started_unix_millis: 2_000_000_000_000,
            })
            .ok();
    })
    .await;
    assert!(
        teardown.is_ok(),
        "teardown through the lease converges — the owner does not hold the lease across the barrier"
    );

    // Unblock the dispatcher: it drains the wedged send, applies the
    // successor transition, then processes the applied-generation notice
    // under session B — rejecting A's generation — and acks. The owner
    // converges within the deadline.
    release_tx.send(true).ok();
    let joined = tokio::time::timeout(Duration::from_secs(5), owner).await;
    let Ok(Ok((client, store, step))) = joined else {
        unreachable!("the owner converges after the dispatcher drains")
    };
    let Ok(SnapshotStep::Continue) = step else {
        unreachable!("the owner step continues: {step:?}")
    };
    // A's serving/store/last-good landed under its own session.
    let Ok(Some(current)) = store.current() else {
        unreachable!("the store committed A")
    };
    assert_eq!(current.generation(), 1);
    let Some((generation, _)) = client.last_good_snapshot_age() else {
        unreachable!("last-good advanced to A's generation")
    };
    assert_eq!(generation, 1);
    let _ = release_tx;
    dispatch.abort();
    client.shutdown();
}
