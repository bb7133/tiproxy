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

//! End-to-end session-engine tests (DPL-04): a real listener admits a
//! raw `MySQL` client, the engine routes through the real dispatcher
//! (driven by an observable fake control sender), authenticates
//! against a scripted fake backend, serves commands, and resolves
//! every control command to its exact gate terminal.

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use control_proto::control_transport::{
    ClientConfig, ConnectionState, ControlClient, Handler, TransportError,
};
use control_proto::v1::control_envelope::Body;
use control_proto::v1::{
    CloseCommand, ControlEnvelope, DrainCommand, ErrorCode, Hello, RedirectCommand, Role,
    RouteAssignment,
};
use dataplane::control_dispatch::{
    ControlCommandHandler, DispatchSender, spawn_control_dispatch_parts,
};
use dataplane::session::SessionLoopConfig;
use dataplane::session_engine::EngineSessionOwner;
use dataplane::{
    BoundSessionHandler, DataplaneServer, DispatchConnectionHandler, SystemMemoryProbe,
};
use mysql_wire::{
    CapabilityFlags, HandshakeResponseParams, ResponseHeader, StatusFlags,
    encode_handshake_response, encode_initial_handshake, encode_ok_packet, parse_initial_handshake,
};
use proxy_io::{PacketReader, PacketWriter};
use session_core::handshake::build_greeting;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch};
use tokio::time::timeout;

// ---------------------------------------------------------------------
// Harness pieces
// ---------------------------------------------------------------------

/// Observable dispatch sender (the loop's outbound half).
struct FakeSender {
    next: AtomicU64,
    sent: Mutex<Vec<ControlEnvelope>>,
}

impl FakeSender {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            next: AtomicU64::new(1000),
            sent: Mutex::new(Vec::new()),
        })
    }

    fn sent(&self) -> Vec<ControlEnvelope> {
        let Ok(sent) = self.sent.lock() else {
            unreachable!("sent lock poisoned")
        };
        sent.clone()
    }
}

impl DispatchSender for FakeSender {
    fn allocate_request_id(&self) -> Option<u64> {
        Some(self.next.fetch_add(1, Ordering::Relaxed) + 1)
    }

    async fn send_envelope(&self, envelope: ControlEnvelope) -> Result<(), TransportError> {
        let Ok(mut sent) = self.sent.lock() else {
            unreachable!("sent lock poisoned")
        };
        sent.push(envelope);
        Ok(())
    }

    async fn send_session_scoped(
        &self,
        envelope: ControlEnvelope,
        _epoch: u64,
    ) -> Result<(), TransportError> {
        self.send_envelope(envelope).await
    }
}

fn control_client() -> Arc<ControlClient> {
    let hello = Hello {
        role: Role::RustDataplane as i32,
        process_id: "engine-test".to_owned(),
        supported_versions: vec![1],
        capabilities: vec![1, 2, 3],
        max_frame_bytes: 1024 * 1024,
        ..Hello::default()
    };
    let socket = std::env::temp_dir().join(format!("engine-test-{}.sock", std::process::id()));
    let Ok(client) = ControlClient::new(ClientConfig::with_defaults(socket, 0, hello)) else {
        unreachable!("valid client config")
    };
    Arc::new(client)
}

/// A scripted `MySQL` backend: greeting → read response → auth OK → OK
/// for every command until EOF/quit.
async fn run_fake_backend(listener: TcpListener) {
    let broad = CapabilityFlags::PROTOCOL_41
        | CapabilityFlags::LONG_PASSWORD
        | CapabilityFlags::SECURE_CONNECTION
        | CapabilityFlags::PLUGIN_AUTH
        | CapabilityFlags::CONNECT_WITH_DB
        | CapabilityFlags::TRANSACTIONS
        | CapabilityFlags::MULTI_STATEMENTS
        | CapabilityFlags::MULTI_RESULTS
        | CapabilityFlags::PS_MULTI_RESULTS
        | CapabilityFlags::CONNECT_ATTRS
        | CapabilityFlags::PLUGIN_AUTH_LENENC_CLIENT_DATA
        | CapabilityFlags::DEPRECATE_EOF
        | CapabilityFlags::LOCAL_FILES;
    while let Ok((stream, _)) = listener.accept().await {
        let (read, write) = stream.into_split();
        let mut reader = PacketReader::new(read);
        let mut writer = PacketWriter::new(write);
        let salt = [7_u8; 20];
        let params = build_greeting(
            broad,
            &salt,
            b"8.0.11-TiDB-fake",
            77,
            45,
            StatusFlags::from_bits_retain(0),
        );
        let Ok(greeting) = encode_initial_handshake(params) else {
            continue;
        };
        if writer.write_logical(&greeting, true).await.is_err() {
            continue;
        }
        // Handshake response.
        if reader.read_logical(64 * 1024).await.is_err() {
            continue;
        }
        writer.reset_sequence(reader.expected_sequence());
        let Ok(auth_ok) = encode_ok_packet(
            ResponseHeader::OK,
            0,
            0,
            StatusFlags::from_bits_retain(0x0002),
            0,
            b"",
            broad,
        ) else {
            continue;
        };
        if writer.write_logical(&auth_ok, true).await.is_err() {
            continue;
        }
        // Command loop: OK for everything until quit/EOF.
        loop {
            reader.reset_sequence(0);
            let Ok(packet) = reader.read_logical(1024 * 1024).await else {
                break;
            };
            if packet.payload.first() == Some(&0x01) {
                break; // COM_QUIT
            }
            if packet.payload.windows(5).any(|window| window == b"SLEEP") {
                // Simulates a long-running statement so a force
                // deadline can preempt an in-flight command.
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
            writer.reset_sequence(reader.expected_sequence());
            let Ok(ok) = encode_ok_packet(
                ResponseHeader::OK,
                1,
                0,
                StatusFlags::from_bits_retain(0x0002),
                0,
                b"",
                broad,
            ) else {
                break;
            };
            if writer.write_logical(&ok, true).await.is_err() {
                break;
            }
        }
    }
}

/// The whole stack under test.
struct Stack {
    server_handle: dataplane::DataplaneHandle,
    sender: Arc<FakeSender>,
    _state_tx: watch::Sender<ConnectionState>,
    _shutdown_tx: watch::Sender<bool>,
    drain_tx: watch::Sender<bool>,
    forwarder: Arc<dataplane::control_dispatch::InboundForwarder>,
    sql_port: u16,
    _server_task: tokio::task::JoinHandle<()>,
    dispatch_task: tokio::task::JoinHandle<Result<(), dataplane::control_dispatch::DispatchFatal>>,
    backend_port: u16,
}

async fn spawn_stack() -> Stack {
    // Fake backend.
    let Ok(backend_listener) = TcpListener::bind(("127.0.0.1", 0)).await else {
        unreachable!("backend bind")
    };
    let Ok(backend_addr) = backend_listener.local_addr() else {
        unreachable!("backend addr")
    };
    tokio::spawn(run_fake_backend(backend_listener));

    // Dispatch loop with an observable sender and a driven state watch.
    let sender = FakeSender::new();
    let (state_tx, state_rx) = watch::channel(ConnectionState::Disconnected);
    let (snapshot_tx, _snapshot_rx) = mpsc::channel(4);
    let (handle, forwarder, dispatch_task) = spawn_control_dispatch_parts(
        ControlCommandHandler::new(),
        Arc::clone(&sender),
        state_rx,
        snapshot_tx,
        Duration::from_millis(20),
    );

    // The engine owner over a real (never-connecting) control client.
    let client = control_client();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (drain_tx, drain_rx) = watch::channel(false);
    let owner: Arc<dyn BoundSessionHandler> = Arc::new(EngineSessionOwner::new(
        Arc::clone(&client),
        "default",
        shutdown_rx,
        drain_rx,
        SessionLoopConfig {
            handshake_deadline: Duration::from_secs(5),
            drain_deadline: Duration::from_millis(400),
            backend_check_interval: Duration::from_secs(60),
            cleanup_deadline: Duration::from_secs(2),
        },
    ));
    let (connection_handler, installer) = DispatchConnectionHandler::new("default", owner);
    assert!(installer.install(handle));

    // Real SQL listener.
    let Ok(sql_listener) = std::net::TcpListener::bind(("127.0.0.1", 0)) else {
        unreachable!("sql bind probe")
    };
    let Ok(sql_addr) = sql_listener.local_addr() else {
        unreachable!("sql addr")
    };
    drop(sql_listener);
    let snapshot = engine_snapshot(sql_addr.port());
    let Ok(server) = DataplaneServer::bind(snapshot, Arc::new(SystemMemoryProbe::new())).await
    else {
        unreachable!("dataplane bind")
    };
    let server_handle = server.handle();
    let server_task = tokio::spawn(async move {
        let _ = server.run(connection_handler).await;
    });

    Stack {
        server_handle,
        sender,
        _state_tx: state_tx,
        _shutdown_tx: shutdown_tx,
        drain_tx,
        forwarder: Arc::new(forwarder),
        sql_port: sql_addr.port(),
        _server_task: server_task,
        dispatch_task,
        backend_port: backend_addr.port(),
    }
}

fn engine_snapshot(port: u16) -> Arc<control_proto::snapshot::ValidatedSnapshot> {
    use control_proto::v1::{
        ConfigSnapshot, KeepalivePolicy, Listener, ProxyProtocolMode, StateSnapshot, TlsPolicy,
    };
    let keepalive = KeepalivePolicy {
        enabled: true,
        idle_millis: 60_000,
        probe_count: 5,
        interval_millis: 3_000,
        user_timeout_millis: 15_000,
    };
    let raw = StateSnapshot {
        config: Some(ConfigSnapshot {
            high_memory_reject_threshold: 0.9,
            connection_buffer_bytes: 32 * 1024,
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
    let Ok(store) = control_proto::snapshot::SnapshotStore::new(Vec::new()) else {
        unreachable!("store")
    };
    let Ok(outcome) = store.apply(
        1,
        raw,
        control_proto::snapshot::UnixTime::since_unix_epoch(Duration::from_secs(1_800_000_000)),
    ) else {
        unreachable!("snapshot applies")
    };
    outcome.snapshot
}

/// A raw `MySQL` client: performs the handshake and returns the packet
/// reader/writer for command exchanges.
struct MysqlClient {
    reader: PacketReader<tokio::net::tcp::OwnedReadHalf>,
    writer: PacketWriter<tokio::net::tcp::OwnedWriteHalf>,
    capabilities: CapabilityFlags,
}

impl MysqlClient {
    async fn connect(port: u16) -> Option<Self> {
        let stream = TcpStream::connect(("127.0.0.1", port)).await.ok()?;
        let (read, write) = stream.into_split();
        let mut reader = PacketReader::new(read);
        let mut writer = PacketWriter::new(write);
        let greeting = reader.read_logical(64 * 1024).await.ok()?;
        let parsed = parse_initial_handshake(&greeting.payload).ok()?;
        let capabilities = CapabilityFlags::PROTOCOL_41
            | CapabilityFlags::LONG_PASSWORD
            | CapabilityFlags::SECURE_CONNECTION
            | CapabilityFlags::PLUGIN_AUTH
            | CapabilityFlags::DEPRECATE_EOF;
        let _ = parsed;
        let response = encode_handshake_response(HandshakeResponseParams {
            capabilities,
            max_packet_size: 16 * 1024 * 1024,
            collation: 45,
            username: b"root",
            auth_response: b"",
            database: None,
            auth_plugin_name: Some(b"mysql_native_password"),
            attributes: None,
            zstd_level: None,
        })
        .ok()?;
        writer.reset_sequence(reader.expected_sequence());
        writer.write_logical(&response, true).await.ok()?;
        reader.reset_sequence(writer.next_sequence());
        // Auth result.
        let auth = reader.read_logical(64 * 1024).await.ok()?;
        if auth.payload.first() != Some(&0x00) {
            return None;
        }
        Some(Self {
            reader,
            writer,
            capabilities,
        })
    }

    async fn query_ok(&mut self, sql: &str) -> bool {
        let mut payload = vec![0x03_u8];
        payload.extend_from_slice(sql.as_bytes());
        self.writer.reset_sequence(0);
        if self.writer.write_logical(&payload, true).await.is_err() {
            return false;
        }
        self.reader.reset_sequence(1);
        let Ok(response) = self.reader.read_logical(64 * 1024).await else {
            return false;
        };
        let _ = self.capabilities;
        response.payload.first() == Some(&0x00)
    }

    async fn quit(mut self) {
        self.writer.reset_sequence(0);
        let _ = self.writer.write_logical(&[0x01], true).await;
    }
}

/// Keeps injecting the route assignment until the engine's armed
/// expectation consumes it (the engine's request ids are deterministic:
/// HandshakeResponseEvent=1, RouteRequest=2 on a fresh client, +2 per
/// later session on the same client).
fn spawn_route_answer(stack: &Stack, connection_id: u64, request_id: u64) {
    let forwarder = Arc::clone(&stack.forwarder);
    let backend_port = stack.backend_port;
    tokio::spawn(async move {
        let assignment = ControlEnvelope {
            request_id,
            generation: 1,
            body: Some(Body::RouteAssignment(RouteAssignment {
                connection_id,
                assignment_id: format!("a-{connection_id}"),
                backend_id: "tidb-fake".to_owned(),
                backend_address: format!("127.0.0.1:{backend_port}"),
                cluster_name: String::new(),
                keyspace: String::new(),
                healthy: true,
                local: true,
                code: ErrorCode::Ok as i32,
                detail: String::new(),
            })),
            ..ControlEnvelope::default()
        };
        for _ in 0..200 {
            let _ = forwarder.handle(assignment.clone()).await;
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    });
}

fn command_envelope(request_id: u64, body: Body) -> ControlEnvelope {
    ControlEnvelope {
        request_id,
        generation: 1,
        body: Some(body),
        ..ControlEnvelope::default()
    }
}

async fn wait_sent<F: Fn(&ControlEnvelope) -> bool>(
    sender: &Arc<FakeSender>,
    predicate: F,
) -> Option<ControlEnvelope> {
    for _ in 0..300 {
        if let Some(envelope) = sender.sent().into_iter().find(|e| predicate(e)) {
            return Some(envelope);
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    None
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

/// The full path: admission → registration → routed dial → auth relay
/// → command OK → quit, over real sockets end to end.
#[tokio::test]
async fn select_one_roundtrip_end_to_end() {
    let stack = spawn_stack().await;
    spawn_route_answer(&stack, 1, 2);
    let Some(mut client) = timeout(Duration::from_secs(5), MysqlClient::connect(stack.sql_port))
        .await
        .ok()
        .flatten()
    else {
        unreachable!("handshake+auth completes end to end")
    };
    assert!(client.query_ok("SELECT 1").await, "query round-trips");
    assert!(
        client.query_ok("SELECT 2").await,
        "second command reuses the session"
    );
    client.quit().await;
    // The CLOSED lifecycle event carries real traffic totals.
    let closed = wait_sent(
        &stack.sender,
        |e| matches!(&e.body, Some(Body::ConnectionEvent(event)) if event.kind == 3),
    )
    .await;
    let Some(closed) = closed else {
        unreachable!("session close emits the CLOSED event")
    };
    let Some(Body::ConnectionEvent(event)) = closed.body else {
        unreachable!()
    };
    assert!(event.client_in_bytes > 0, "totals captured: {event:?}");
    assert!(event.backend_in_bytes > 0);
    stack.dispatch_task.abort();
}

/// A per-connection `CloseCommand` resolves under its exact admitted id
/// with the initiating request id, and the client socket closes.
#[tokio::test]
async fn close_command_terminal_is_exact() {
    let stack = spawn_stack().await;
    spawn_route_answer(&stack, 1, 2);
    let Some(mut client) = timeout(Duration::from_secs(5), MysqlClient::connect(stack.sql_port))
        .await
        .ok()
        .flatten()
    else {
        unreachable!("session established")
    };
    assert!(client.query_ok("SELECT 1").await);

    let close = command_envelope(
        4321,
        Body::CloseCommand(CloseCommand {
            connection_id: 1,
            close_id: "c-exact".to_owned(),
            error_source: 0,
            reason: String::new(),
            force: false,
        }),
    );
    let _ = stack.forwarder.handle(close).await;
    let result = wait_sent(
        &stack.sender,
        |e| matches!(&e.body, Some(Body::CloseResult(result)) if result.close_id == "c-exact"),
    )
    .await;
    let Some(result) = result else {
        unreachable!("the close resolves under its exact admitted id")
    };
    assert_eq!(
        result.request_id, 4321,
        "terminal answers the initiating id"
    );
    // The graceful close lands at the idle boundary: the client's next
    // read observes EOF.
    let gone = timeout(Duration::from_secs(3), async {
        loop {
            if !client.query_ok("SELECT 3").await {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    assert!(gone.is_ok(), "the session closes at the safe boundary");
    stack.dispatch_task.abort();
}

/// A drain closes the session at the safe boundary and the completion
/// transition proactively produces the terminal `DrainResult`.
#[tokio::test]
async fn drain_closes_idle_session_and_completes() {
    let stack = spawn_stack().await;
    spawn_route_answer(&stack, 1, 2);
    let Some(mut client) = timeout(Duration::from_secs(5), MysqlClient::connect(stack.sql_port))
        .await
        .ok()
        .flatten()
    else {
        unreachable!("session established")
    };
    assert!(client.query_ok("SELECT 1").await);

    let now_ms = 1_000_000_u64;
    let drain = command_envelope(
        5000,
        Body::DrainCommand(DrainCommand {
            drain_id: "d-e2e".to_owned(),
            listener_names: Vec::new(),
            backend_ids: Vec::new(),
            graceful_deadline_unix_millis: now_ms,
            force_deadline_unix_millis: now_ms + 60_000,
            command_sequence: 1,
        }),
    );
    let _ = stack.forwarder.handle(drain).await;
    let terminal = wait_sent(&stack.sender, |e| {
        matches!(&e.body, Some(Body::DrainResult(result))
            if result.drain_id == "d-e2e" && result.complete)
    })
    .await;
    let Some(terminal) = terminal else {
        unreachable!("the last session closing completes the drain proactively")
    };
    assert_eq!(
        terminal.request_id, 5000,
        "the terminal answers the initiating drain request"
    );
    let _ = client;
    stack.dispatch_task.abort();
}

/// A control redirect is refused fail-closed under its exact id (this
/// slice keeps the backend; Go's refused-migration behavior) and the
/// session keeps serving.
#[tokio::test]
async fn redirect_refusal_is_exact_and_session_survives() {
    let stack = spawn_stack().await;
    spawn_route_answer(&stack, 1, 2);
    let Some(mut client) = timeout(Duration::from_secs(5), MysqlClient::connect(stack.sql_port))
        .await
        .ok()
        .flatten()
    else {
        unreachable!("session established")
    };
    assert!(client.query_ok("SELECT 1").await);

    let redirect = command_envelope(
        6000,
        Body::RedirectCommand(RedirectCommand {
            connection_id: 1,
            redirect_id: "r-e2e".to_owned(),
            backend_id: "tidb-other".to_owned(),
            backend_address: "127.0.0.1:1".to_owned(),
            cluster_name: String::new(),
            deadline_unix_millis: 0,
            command_sequence: 1,
        }),
    );
    let _ = stack.forwarder.handle(redirect).await;
    let result = wait_sent(
        &stack.sender,
        |e| matches!(&e.body, Some(Body::RedirectResult(result)) if result.redirect_id == "r-e2e"),
    )
    .await;
    let Some(result) = result else {
        unreachable!("the refused redirect resolves under its exact id")
    };
    let Some(Body::RedirectResult(result)) = result.body else {
        unreachable!()
    };
    assert!(!result.succeeded, "fail-closed refusal in this slice");
    assert!(
        client.query_ok("SELECT 4").await,
        "the session keeps its backend and keeps serving"
    );
    client.quit().await;
    stack.dispatch_task.abort();
}

/// Control-plane loss must not tear down a healthy session (control-v1
/// last-good): with the dispatcher gone, established traffic continues.
#[tokio::test]
async fn control_detach_keeps_session_serving() {
    let stack = spawn_stack().await;
    spawn_route_answer(&stack, 1, 2);
    let Some(mut client) = timeout(Duration::from_secs(5), MysqlClient::connect(stack.sql_port))
        .await
        .ok()
        .flatten()
    else {
        unreachable!("session established")
    };
    assert!(client.query_ok("SELECT 1").await);

    stack.dispatch_task.abort();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        client.query_ok("SELECT 5").await,
        "control detach is last-good: the session keeps serving"
    );
    client.quit().await;
}

/// The coordinated local shutdown order: stop-accept first (new
/// connections refused, existing sessions untouched), then the drain
/// signal closes idle sessions at their safe boundary — no force
/// needed for an idle session.
#[tokio::test]
async fn coordinated_shutdown_stops_accept_then_drains() {
    let stack = spawn_stack().await;
    spawn_route_answer(&stack, 1, 2);
    let Some(mut client) = timeout(Duration::from_secs(5), MysqlClient::connect(stack.sql_port))
        .await
        .ok()
        .flatten()
    else {
        unreachable!("session established")
    };
    assert!(client.query_ok("SELECT 1").await);

    // Phase 1: stop-accept. The live session keeps serving.
    stack.server_handle.stop_accepting();
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        TcpStream::connect(("127.0.0.1", stack.sql_port))
            .await
            .is_err(),
        "new connections are refused after stop-accept"
    );
    assert!(
        client.query_ok("SELECT 2").await,
        "existing sessions keep serving through stop-accept"
    );

    // Phase 2: graceful drain. The idle session closes at its safe
    // boundary and the CLOSED lifecycle event goes out.
    stack.drain_tx.send_replace(true);
    let closed = wait_sent(
        &stack.sender,
        |e| matches!(&e.body, Some(Body::ConnectionEvent(event)) if event.kind == 3),
    )
    .await;
    assert!(closed.is_some(), "the drained session closes and reports");
    stack.dispatch_task.abort();
}

/// A drain whose force deadline lands while a command is in flight
/// (never a safe boundary) force-closes the session: the terminal
/// DrainResult counts it as force-closed and the CLOSED lifecycle
/// event carries the proxy-shutdown attribution.
#[tokio::test]
async fn drain_force_deadline_preempts_in_flight_command() {
    let stack = spawn_stack().await;
    spawn_route_answer(&stack, 1, 2);
    let Some(mut client) = timeout(Duration::from_secs(5), MysqlClient::connect(stack.sql_port))
        .await
        .ok()
        .flatten()
    else {
        unreachable!("session established")
    };
    assert!(client.query_ok("SELECT 1").await);

    // Start a long statement: the backend stalls for seconds, so the
    // session sits mid-command with no safe boundary.
    let slow = tokio::spawn(async move { client.query_ok("SELECT SLEEP").await });
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Force deadline ~now: graceful already passed, force imminent.
    let now_ms = 1_000_000_u64;
    let drain = command_envelope(
        7000,
        Body::DrainCommand(DrainCommand {
            drain_id: "d-force".to_owned(),
            listener_names: Vec::new(),
            backend_ids: Vec::new(),
            graceful_deadline_unix_millis: now_ms.saturating_sub(1_000),
            force_deadline_unix_millis: now_ms.saturating_sub(500),
            command_sequence: 1,
        }),
    );
    let _ = stack.forwarder.handle(drain).await;

    let terminal = wait_sent(&stack.sender, |e| {
        matches!(&e.body, Some(Body::DrainResult(result))
            if result.drain_id == "d-force" && result.complete)
    })
    .await;
    let Some(terminal) = terminal else {
        unreachable!("the force phase completes the drain")
    };
    let Some(Body::DrainResult(result)) = terminal.body else {
        unreachable!()
    };
    assert_eq!(result.force_closed, 1, "the in-flight session was forced");

    let closed = wait_sent(
        &stack.sender,
        |e| matches!(&e.body, Some(Body::ConnectionEvent(event)) if event.kind == 3),
    )
    .await;
    let Some(closed) = closed else {
        unreachable!("the forced session reports CLOSED")
    };
    let Some(Body::ConnectionEvent(event)) = closed.body else {
        unreachable!()
    };
    assert_eq!(
        event.error_source, 6,
        "timeout force-close uses the proxy-shutdown source: {event:?}"
    );
    let _ = slow.await;
    stack.dispatch_task.abort();
}
