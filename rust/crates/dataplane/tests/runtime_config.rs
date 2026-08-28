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
use std::sync::Arc;
use std::time::Duration;

use control_proto::control_transport::{ClientConfig, ControlClient};
use control_proto::snapshot::{
    SnapshotErrorKind, SnapshotLineage, SnapshotStore, UnixTime, ValidatedSnapshot,
};
use control_proto::v1::{
    ConfigSnapshot, Hello, KeepalivePolicy, Listener, ProxyProtocolMode, Role, StateSnapshot,
    TlsPolicy,
};
use dataplane::control_dispatch::{
    ControlCommandHandler, ResponseKind, spawn_control_dispatch_with_handler,
};
use dataplane::control_runtime::SnapshotConsumer;
use dataplane::{
    AcceptedConnection, BoundSessionHandler, ConnectionHandler, DataplaneServer,
    DataplaneSnapshotConsumer, DispatchConnectionHandler, MemoryProbe, MemoryProbeError,
    MemorySample,
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
    let keepalive = KeepalivePolicy {
        enabled: true,
        idle_millis: 0,
        probe_count: 0,
        interval_millis: 0,
        user_timeout_millis: 0,
    };
    let raw = StateSnapshot {
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
    };
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

    consumer.apply(&snapshot(1, port)?).await?;
    let first = TcpStream::connect(("127.0.0.1", port)).await?;
    assert_eq!(
        timeout(Duration::from_secs(2), seen_rx.recv()).await?,
        Some(1)
    );

    consumer.apply(&snapshot(2, port)?).await?;
    let second = TcpStream::connect(("127.0.0.1", port)).await?;
    assert_eq!(
        timeout(Duration::from_secs(2), seen_rx.recv()).await?,
        Some(2),
        "new admission captures the complete newly applied Arc"
    );

    let error = match consumer.apply(&snapshot(3, other_port)?).await {
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
