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

//! DPL-03 serving-generation integration: first bind, atomic reload,
//! restart-required rejection, admission capture, and coordinated shutdown.

use std::error::Error;
use std::net::TcpListener as StdTcpListener;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use control_proto::control_transport::{ClientConfig, ControlClient};
use control_proto::snapshot::{
    CompositionGenerations, SnapshotErrorKind, SnapshotLineage, SnapshotStore, UnixTime,
    ValidatedSnapshot,
};
use control_proto::v1::{
    ConfigSnapshot, Hello, KeepalivePolicy, Listener, ProxyProtocolMode, Role, StateSnapshot,
    TlsPolicy,
};
use dataplane::control_dispatch::{
    ControlCommandHandler, ResponseKind, spawn_control_dispatch_with_handler,
};
use dataplane::control_runtime::{SnapshotComposition, SnapshotConsumer};
use dataplane::{
    AcceptedConnection, BoundSessionHandler, ConnectionHandler, DataplaneServer,
    DataplaneSnapshotConsumer, DispatchConnectionHandler, MemoryProbe, MemoryProbeError,
    MemorySample, ServingSnapshotComposer,
};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::timeout;

#[derive(Debug)]
struct FixedMemory;

impl MemoryProbe for FixedMemory {
    fn sample(&self) -> Result<MemorySample, MemoryProbeError> {
        Ok(MemorySample::now(1, 1024 * 1024 * 1024))
    }
}

fn control_client() -> Result<Arc<ControlClient>, Box<dyn Error>> {
    let hello = Hello {
        role: Role::RustDataplane as i32,
        process_id: "session-binding-test".to_owned(),
        supported_versions: vec![1],
        capabilities: vec![1, 2, 3],
        max_frame_bytes: 1024 * 1024,
        ..Hello::default()
    };
    Ok(Arc::new(ControlClient::new(ClientConfig::with_defaults(
        PathBuf::from("/tmp/tiproxy-missing-control.sock"),
        0,
        hello,
    ))?))
}

fn free_port() -> Result<u16, Box<dyn Error>> {
    let listener = StdTcpListener::bind(("127.0.0.1", 0))?;
    Ok(listener.local_addr()?.port())
}

fn snapshot(generation: u64, port: u16) -> Result<Arc<ValidatedSnapshot>, Box<dyn Error>> {
    let raw = raw_snapshot(port);
    let store = SnapshotStore::new([])?;
    Ok(store
        .apply(
            generation,
            raw,
            UnixTime::since_unix_epoch(Duration::from_secs(1_800_000_000)),
            SnapshotLineage::for_tests("go-fixture"),
        )?
        .snapshot)
}

fn raw_snapshot(port: u16) -> StateSnapshot {
    let keepalive = KeepalivePolicy {
        enabled: true,
        idle_millis: 0,
        probe_count: 0,
        interval_millis: 0,
        user_timeout_millis: 0,
    };
    StateSnapshot {
        config: Some(ConfigSnapshot {
            high_memory_reject_threshold: 0.9,
            connection_buffer_bytes: 4096,
            frontend_keepalive: Some(keepalive),
            healthy_backend_keepalive: Some(keepalive),
            unhealthy_backend_keepalive: Some(keepalive),
            proxy_protocol: ProxyProtocolMode::Disabled as i32,
            listeners: vec![Listener {
                address: "127.0.0.1".to_owned(),
                port: u32::from(port),
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

#[derive(Clone)]
struct MutableComposer {
    state: Arc<Mutex<ComposerState>>,
}

#[derive(Clone, Copy)]
struct ComposerState {
    generation: u64,
    config_generation: u64,
    max_connections: u64,
    listener_port: Option<u16>,
}

impl MutableComposer {
    fn with(generation: u64, config_generation: u64, max_connections: u64) -> Self {
        Self {
            state: Arc::new(Mutex::new(ComposerState {
                generation,
                config_generation,
                max_connections,
                listener_port: None,
            })),
        }
    }

    fn set(
        &self,
        generation: u64,
        config_generation: u64,
        max_connections: u64,
        listener_port: Option<u16>,
    ) {
        *self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = ComposerState {
            generation,
            config_generation,
            max_connections,
            listener_port,
        };
    }
}

impl ServingSnapshotComposer for MutableComposer {
    fn compose(
        &self,
        source: &StateSnapshot,
    ) -> Result<SnapshotComposition, control_proto::snapshot::SnapshotError> {
        let ComposerState {
            generation,
            config_generation,
            max_connections,
            listener_port,
        } = *self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut snapshot = source.clone();
        let config = snapshot
            .config
            .as_mut()
            .ok_or_else(|| control_proto::snapshot::SnapshotError::invalid("config is required"))?;
        config.max_connections = max_connections;
        if let Some(port) = listener_port {
            config.listeners[0].port = u32::from(port);
        }
        Ok(SnapshotComposition {
            snapshot,
            generation,
            config_generation,
        })
    }
}

#[tokio::test]
async fn first_bind_reload_reject_and_shutdown_keep_one_last_good_generation()
-> Result<(), Box<dyn Error>> {
    let port = free_port()?;
    let other_port = free_port()?;
    let (seen_tx, mut seen_rx) = mpsc::unbounded_channel();
    let handler: Arc<dyn ConnectionHandler> = Arc::new(move |connection: AcceptedConnection| {
        let seen_tx = seen_tx.clone();
        async move {
            let _ = seen_tx.send(connection.snapshot().generation());
            std::future::pending::<()>().await;
        }
    });
    let (mut consumer, serving) = DataplaneSnapshotConsumer::new(Arc::new(FixedMemory), handler);

    consumer.apply(&snapshot(1, port)?, &|| true).await?;
    let first = TcpStream::connect(("127.0.0.1", port)).await?;
    assert_eq!(
        timeout(Duration::from_secs(2), seen_rx.recv()).await?,
        Some(1)
    );

    consumer.apply(&snapshot(2, port)?, &|| true).await?;
    let second = TcpStream::connect(("127.0.0.1", port)).await?;
    assert_eq!(
        timeout(Duration::from_secs(2), seen_rx.recv()).await?,
        Some(2),
        "new admission captures the complete newly applied Arc"
    );

    let error = match consumer.apply(&snapshot(3, other_port)?, &|| true).await {
        Ok(()) => return Err("listener change unexpectedly applied".into()),
        Err(error) => error,
    };
    assert_eq!(error.kind(), SnapshotErrorKind::Unsupported);
    let third = TcpStream::connect(("127.0.0.1", port)).await?;
    assert_eq!(
        timeout(Duration::from_secs(2), seen_rx.recv()).await?,
        Some(2),
        "rejection preserves the prior last-good generation"
    );
    assert!(TcpStream::connect(("127.0.0.1", other_port)).await.is_err());

    let status = serving.status();
    assert_eq!(status.applied_generation, 2);
    assert_eq!(status.rejected_generation, 3);
    assert_eq!(status.applied_total, 2);
    assert_eq!(status.rejected_total, 1);
    assert!(status.last_good_age.is_some());

    drop((first, second, third));
    serving.shutdown().await?;
    assert!(TcpStream::connect(("127.0.0.1", port)).await.is_err());
    Ok(())
}

#[tokio::test]
async fn local_composition_advances_independently_and_rejects_atomically()
-> Result<(), Box<dyn Error>> {
    let port = free_port()?;
    let other_port = free_port()?;
    let composer = MutableComposer::with(1, 1, 11);
    let (seen_tx, mut seen_rx) = mpsc::unbounded_channel();
    let handler: Arc<dyn ConnectionHandler> = Arc::new(move |connection: AcceptedConnection| {
        let seen_tx = seen_tx.clone();
        async move {
            let snapshot = connection.snapshot();
            let config = snapshot.raw().config.as_ref();
            let _ = seen_tx.send((
                snapshot.generation(),
                snapshot.composition_generation(),
                config.map_or(0, |value| value.max_connections),
            ));
            std::future::pending::<()>().await;
        }
    });
    let (mut consumer, serving) = DataplaneSnapshotConsumer::new_with_composer(
        Arc::new(FixedMemory),
        handler,
        Arc::new(composer.clone()),
    );
    let store = SnapshotStore::new([])?;
    let source = raw_snapshot(port);
    let composition = consumer.compose(&source)?;
    let staged = store.stage_composed(
        7,
        source,
        composition.snapshot,
        CompositionGenerations {
            composition: composition.generation,
            config: composition.config_generation,
        },
        UnixTime::since_unix_epoch(Duration::from_secs(1_800_000_000)),
        SnapshotLineage::for_tests("go-fixture"),
    )?;
    consumer.apply(staged.snapshot(), &|| true).await?;
    store.commit(staged)?;

    let first = TcpStream::connect(("127.0.0.1", port)).await?;
    assert_eq!(
        timeout(Duration::from_secs(2), seen_rx.recv()).await?,
        Some((7, 1, 11))
    );

    composer.set(2, 2, 22, None);
    assert!(
        serving
            .reload_composed(
                &store,
                UnixTime::since_unix_epoch(Duration::from_secs(1_800_000_001)),
            )
            .await?
    );
    let second = TcpStream::connect(("127.0.0.1", port)).await?;
    assert_eq!(
        timeout(Duration::from_secs(2), seen_rx.recv()).await?,
        Some((7, 2, 22)),
        "local generation changes serving without advancing bridge generation"
    );
    let status = serving.status();
    assert_eq!(status.applied_generation, 7);
    assert_eq!(status.composition_generation, 2);
    assert_eq!(status.composition_applied_total, 1);

    composer.set(3, 3, 33, Some(other_port));
    let Err(error) = serving
        .reload_composed(
            &store,
            UnixTime::since_unix_epoch(Duration::from_secs(1_800_000_002)),
        )
        .await
    else {
        return Err("listener mutation was not rejected".into());
    };
    assert_eq!(error.kind(), SnapshotErrorKind::Unsupported);
    let third = TcpStream::connect(("127.0.0.1", port)).await?;
    assert_eq!(
        timeout(Duration::from_secs(2), seen_rx.recv()).await?,
        Some((7, 2, 22)),
        "a rejected local generation preserves last-good serving state"
    );
    assert!(TcpStream::connect(("127.0.0.1", other_port)).await.is_err());
    let status = serving.status();
    assert_eq!(status.composition_generation, 2);
    assert_eq!(status.rejected_composition_generation, 3);
    assert_eq!(status.composition_rejected_total, 1);

    drop((first, second, third));
    serving.shutdown().await?;
    Ok(())
}

/// Review reproduction (CP-ADMIN namespace-commit barrier): a config
/// generation published before the adapter advanced the composition counter
/// is carried by the next bridge re-compose at the unchanged counter. If that
/// apply is rejected, or the equivalent recomposition is skipped as
/// same-counter, the barrier watch must keep the last installed generation;
/// only the apply that actually installs the new view confirms it.
#[tokio::test]
async fn config_generation_is_confirmed_only_by_the_apply_that_installs_it()
-> Result<(), Box<dyn Error>> {
    let port = free_port()?;
    let other_port = free_port()?;
    let composer = MutableComposer::with(1, 1, 11);
    let handler: Arc<dyn ConnectionHandler> = Arc::new(|_connection: AcceptedConnection| async {
        std::future::pending::<()>().await;
    });
    let (mut consumer, serving) = DataplaneSnapshotConsumer::new_with_composer(
        Arc::new(FixedMemory),
        handler,
        Arc::new(composer.clone()),
    );
    let applied = serving.applied_config_generation();
    let store = SnapshotStore::new([])?;
    let source = raw_snapshot(port);
    let composition = consumer.compose(&source)?;
    let staged = store.stage_composed(
        7,
        source.clone(),
        composition.snapshot,
        CompositionGenerations {
            composition: composition.generation,
            config: composition.config_generation,
        },
        UnixTime::since_unix_epoch(Duration::from_secs(1_800_000_000)),
        SnapshotLineage::for_tests("go-fixture"),
    )?;
    consumer.apply(staged.snapshot(), &|| true).await?;
    store.commit(staged)?;
    assert_eq!(*applied.borrow(), 1, "initial bind installs config 1");

    // Config generation 2 is published; the adapter has not advanced the
    // composition counter. A bridge re-compose at counter 1 carries config 2
    // but is rejected (listener mutation): nothing may confirm generation 2.
    composer.set(1, 2, 22, Some(other_port));
    let composition = consumer.compose(&source)?;
    assert_eq!(
        (composition.generation, composition.config_generation),
        (1, 2)
    );
    let staged = store.stage_composed(
        8,
        source.clone(),
        composition.snapshot,
        CompositionGenerations {
            composition: composition.generation,
            config: composition.config_generation,
        },
        UnixTime::since_unix_epoch(Duration::from_secs(1_800_000_001)),
        SnapshotLineage::for_tests("go-fixture"),
    )?;
    let Err(error) = consumer.apply(staged.snapshot(), &|| true).await else {
        return Err("listener mutation was not rejected".into());
    };
    assert_eq!(error.kind(), SnapshotErrorKind::Unsupported);
    drop(staged);
    assert_eq!(
        *applied.borrow(),
        1,
        "a rejected bridge apply carrying config 2 must not confirm it"
    );

    // The same composition counter with a valid config 2 is skipped by the
    // recomposition path (same counter as the installed view) and still
    // confirms nothing.
    composer.set(1, 2, 22, None);
    assert!(
        !serving
            .reload_composed(
                &store,
                UnixTime::since_unix_epoch(Duration::from_secs(1_800_000_002)),
            )
            .await?
    );
    assert_eq!(
        *applied.borrow(),
        1,
        "a skipped recomposition confirms nothing"
    );

    // Only the adapter wake that installs config 2 confirms it.
    composer.set(2, 2, 22, None);
    assert!(
        serving
            .reload_composed(
                &store,
                UnixTime::since_unix_epoch(Duration::from_secs(1_800_000_003)),
            )
            .await?
    );
    assert_eq!(
        *applied.borrow(),
        2,
        "the installing apply confirms config 2"
    );
    let status = serving.status();
    assert_eq!(status.applied_generation, 7);
    assert_eq!(status.rejected_generation, 8);
    assert_eq!(status.composition_generation, 2);

    serving.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn admitted_session_gets_registration_expectation_and_backend_plumbing()
-> Result<(), Box<dyn Error>> {
    let client = control_client()?;
    let (snapshot_tx, _snapshot_rx) = mpsc::channel(1);
    let (dispatch, _forwarder, dispatch_owner) = spawn_control_dispatch_with_handler(
        ControlCommandHandler::new(),
        Arc::clone(&client),
        snapshot_tx,
        Duration::from_secs(3600),
    );
    let (observed_tx, mut observed_rx) = mpsc::unbounded_channel();
    let bound: Arc<dyn BoundSessionHandler> = Arc::new(
        move |_connection: AcceptedConnection, binding: dataplane::SessionControlBinding| {
            let observed_tx = observed_tx.clone();
            async move {
                let armed = binding
                    .expect_response(17, ResponseKind::HandshakeDecision)
                    .await;
                let backend = binding.set_backend("tidb-a").await;
                let _ = observed_tx.send((binding.connection_id(), armed, backend));
                std::future::pending::<()>().await;
            }
        },
    );
    let (connection_handler, installer) = DispatchConnectionHandler::new("default", bound);

    let port = free_port()?;
    let server = DataplaneServer::bind(snapshot(1, port)?, Arc::new(FixedMemory)).await?;
    let server_handle = server.handle();
    let server_owner = tokio::spawn(server.run(connection_handler));
    let client_connection = TcpStream::connect(("127.0.0.1", port)).await?;
    assert!(
        timeout(Duration::from_millis(20), observed_rx.recv())
            .await
            .is_err(),
        "admission waits instead of dropping a socket during runtime construction"
    );
    assert!(installer.install(dispatch));
    let Some((connection_id, armed, backend)) =
        timeout(Duration::from_secs(2), observed_rx.recv()).await?
    else {
        return Err("bound handler did not report".into());
    };
    assert_eq!(connection_id, 1);
    assert_eq!(armed, Ok(()));
    assert!(backend);

    drop(client_connection);
    server_handle.shutdown();
    server_owner.await??;
    dispatch_owner.abort();
    let _ = dispatch_owner.await;
    client.shutdown();
    Ok(())
}
