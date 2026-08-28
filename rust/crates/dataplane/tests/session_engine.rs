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
    ClientConfig, ConnectionState, ControlClient, Handler, SessionMeta, TransportError,
};
use control_proto::v1::control_envelope::Body;
use control_proto::v1::{
    CloseCommand, ControlEnvelope, DrainCommand, ErrorCode, HandshakeDecision, Hello,
    RedirectCommand, Role, RouteAssignment,
};
use dataplane::control_dispatch::{
    ControlCommandHandler, DispatchSender, spawn_control_dispatch_parts,
};
use dataplane::observability::{MetricsRecorder, Observation, QuitSource};
use dataplane::session::SessionLoopConfig;
use dataplane::session_engine::EngineSessionOwner;
use dataplane::{
    BoundSessionHandler, DataplaneServer, DispatchConnectionHandler, SystemMemoryProbe,
};
use mysql_wire::{
    CapabilityFlags, HandshakeResponseParams, ResponseHeader, StatusFlags, encode_eof_packet,
    encode_error_packet, encode_handshake_response, encode_initial_handshake,
    encode_length_encoded_bytes, encode_length_encoded_int, encode_ok_packet,
    parse_handshake_response, parse_initial_handshake,
};
use proxy_io::{PacketReader, PacketWriter};
use session_core::handshake::build_greeting;
use tokio::io::AsyncWriteExt;
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
/// Every fake session authenticates with a real non-empty native
/// password, so the whole harness exercises the unknown-plugin
/// re-authentication path against the backend's own salt.
const FAKE_BACKEND_PASSWORD: &str = "s3cret-pa55";

/// Minimal SHA-1 (test-only) for the native-password challenge.
#[expect(
    clippy::many_single_char_names,
    reason = "the FIPS-180 reference notation"
)]
fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [
        0x6745_2301,
        0xEFCD_AB89,
        0x98BA_DCFE,
        0x1032_5476,
        0xC3D2_E1F0,
    ];
    let mut message = data.to_vec();
    let bit_len = (data.len() as u64).wrapping_mul(8);
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&bit_len.to_be_bytes());
    for chunk in message.chunks_exact(64) {
        let mut w = [0_u32; 80];
        for (i, word) in chunk.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
        for (i, &word) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A82_7999),
                20..=39 => (b ^ c ^ d, 0x6ED9_EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDC),
                _ => (b ^ c ^ d, 0xCA62_C1D6),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(word);
            e = d;
            d = c;
            c = b;
            b = a.rotate_left(30);
            a = temp;
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }
    let mut out = [0_u8; 20];
    for (chunk, word) in out.chunks_exact_mut(4).zip(h) {
        chunk.copy_from_slice(&word.to_be_bytes());
    }
    out
}

/// `mysql_native_password`: SHA1(pwd) XOR SHA1(salt ++ SHA1(SHA1(pwd))).
fn native_scramble(password: &str, salt: &[u8]) -> Vec<u8> {
    if password.is_empty() {
        return Vec::new();
    }
    let stage1 = sha1(password.as_bytes());
    let stage2 = sha1(&stage1);
    let mut salted = salt.to_vec();
    salted.extend_from_slice(&stage2);
    let mask = sha1(&salted);
    stage1
        .iter()
        .zip(mask)
        .map(|(byte, mask)| byte ^ mask)
        .collect()
}

/// Go's authentication failure with the `using password` semantics.
async fn write_access_denied(
    writer: &mut PacketWriter<tokio::net::tcp::OwnedWriteHalf>,
    capabilities: CapabilityFlags,
) -> bool {
    let Ok(denied) = encode_error_packet(
        1045,
        Some(*b"28000"),
        b"Access denied for user 'root' (using password: YES)",
        capabilities,
    ) else {
        return false;
    };
    writer.write_logical(&denied, true).await.is_ok()
}

/// The fake backend's connection phase: greeting with its own salt,
/// Go-oracle unknown-plugin assertion (a `TiDB` verifying the mis-salted
/// scramble directly fails as access-denied), auth-switch challenge,
/// and strict scramble verification.
async fn fake_backend_auth(
    reader: &mut PacketReader<tokio::net::tcp::OwnedReadHalf>,
    writer: &mut PacketWriter<tokio::net::tcp::OwnedWriteHalf>,
    broad: CapabilityFlags,
) -> bool {
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
        return false;
    };
    if writer.write_logical(&greeting, true).await.is_err() {
        return false;
    }
    // Handshake response: strict wire sequence — it must continue the
    // greeting exchange at one, no silent resync.
    match reader.peek_packet().await {
        Ok(preview) if preview.sequence_id == 1 => {}
        _ => return false,
    }
    let Ok(response) = reader.read_logical(64 * 1024).await else {
        return false;
    };
    let Ok(parsed) = parse_handshake_response(&response.payload) else {
        return false;
    };
    if parsed.auth_plugin_name != Some(b"auth_unknown_plugin".as_slice()) {
        writer.reset_sequence(reader.expected_sequence());
        let _ = write_access_denied(writer, broad).await;
        return false;
    }
    // Re-request authentication against this backend's own salt.
    let mut switch = vec![0xFE_u8];
    switch.extend_from_slice(b"mysql_native_password\0");
    switch.extend_from_slice(&salt);
    switch.push(0);
    writer.reset_sequence(reader.expected_sequence());
    if writer.write_logical(&switch, true).await.is_err() {
        return false;
    }
    reader.reset_sequence(writer.next_sequence());
    let Ok(rescrambled) = reader.read_logical(64 * 1024).await else {
        return false;
    };
    writer.reset_sequence(reader.expected_sequence());
    if rescrambled.payload != native_scramble(FAKE_BACKEND_PASSWORD, &salt) {
        let _ = write_access_denied(writer, broad).await;
        return false;
    }
    let Ok(auth_ok) = encode_ok_packet(
        ResponseHeader::OK,
        0,
        0,
        StatusFlags::from_bits_retain(0x0002),
        0,
        b"",
        broad,
    ) else {
        return false;
    };
    writer.write_logical(&auth_ok, true).await.is_ok()
}

fn result_column(name: &[u8]) -> Vec<u8> {
    let mut payload = Vec::new();
    for field in [b"def".as_slice(), b"db", b"t", b"t", name, name] {
        assert!(encode_length_encoded_bytes(Some(field), &mut payload).is_ok());
    }
    encode_length_encoded_int(12, &mut payload);
    payload.extend_from_slice(&[45, 0, 11, 0, 0, 0, 0x03, 0, 0, 0, 0, 0]);
    payload
}

#[derive(Debug, Clone, Copy)]
enum SnapshotReply {
    Valid,
    SigningCertificateError,
    NullToken,
    EmptyToken,
    MalformedJson,
    OversizedJson,
    Disconnect,
}

async fn write_session_snapshot(
    reader: &PacketReader<tokio::net::tcp::OwnedReadHalf>,
    writer: &mut PacketWriter<tokio::net::tcp::OwnedWriteHalf>,
    session_states: &[u8],
    session_token: Option<&[u8]>,
) -> bool {
    writer.reset_sequence(reader.expected_sequence());
    let mut row = Vec::new();
    assert!(encode_length_encoded_bytes(Some(session_states), &mut row).is_ok());
    assert!(encode_length_encoded_bytes(session_token, &mut row).is_ok());
    for payload in [
        vec![2],
        result_column(b"Session_states"),
        result_column(b"Session_token"),
        encode_eof_packet(0, StatusFlags::AUTOCOMMIT).to_vec(),
        row,
    ] {
        if writer.write_logical(&payload, false).await.is_err() {
            return false;
        }
    }
    writer
        .write_logical(&encode_eof_packet(0, StatusFlags::AUTOCOMMIT), true)
        .await
        .is_ok()
}

async fn respond_to_snapshot_query(
    reader: &PacketReader<tokio::net::tcp::OwnedReadHalf>,
    writer: &mut PacketWriter<tokio::net::tcp::OwnedWriteHalf>,
    snapshot_reply: SnapshotReply,
    capabilities: CapabilityFlags,
) -> bool {
    if matches!(snapshot_reply, SnapshotReply::Disconnect) {
        return false;
    }
    if matches!(snapshot_reply, SnapshotReply::SigningCertificateError) {
        writer.reset_sequence(reader.expected_sequence());
        let Ok(error) = encode_error_packet(
            1105,
            Some(*b"HY000"),
            b"session token signing certificate unavailable",
            capabilities,
        ) else {
            return false;
        };
        return writer.write_logical(&error, true).await.is_ok();
    }

    let oversized;
    let (session_states, session_token): (&[u8], Option<&[u8]>) = match snapshot_reply {
        SnapshotReply::Valid => (
            br#"{"current-db":"snapshot_db","marker":"all-bytes-preserved"}"#,
            Some(b"signed-token-private"),
        ),
        SnapshotReply::NullToken => (br#"{"current-db":"snapshot_db"}"#, None),
        SnapshotReply::EmptyToken => (br#"{"current-db":"snapshot_db"}"#, Some(b"")),
        SnapshotReply::MalformedJson => (b"{", Some(b"signed-token-private")),
        SnapshotReply::OversizedJson => {
            oversized = vec![b'x'; 8 * 1024 * 1024 + 1];
            (&oversized, Some(b"signed-token-private"))
        }
        SnapshotReply::SigningCertificateError | SnapshotReply::Disconnect => {
            unreachable!("handled above")
        }
    };
    write_session_snapshot(reader, writer, session_states, session_token).await
}

async fn run_fake_backend(
    listener: TcpListener,
    transcript: Arc<Mutex<Vec<Vec<u8>>>>,
    snapshot_reply: SnapshotReply,
) {
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
        if !fake_backend_auth(&mut reader, &mut writer, broad).await {
            continue;
        }
        // Command loop: OK for everything until quit/EOF.
        let mut in_transaction = false;
        loop {
            reader.reset_sequence(0);
            // Strict wire sequence: every proxied command must restart
            // its exchange at zero, exactly like the Go oracle.
            match reader.peek_packet().await {
                Ok(preview) if preview.sequence_id == 0 => {}
                _ => break,
            }
            let Ok(packet) = reader.read_logical(1024 * 1024).await else {
                break;
            };
            if let Ok(mut commands) = transcript.lock() {
                commands.push(packet.payload.clone());
            }
            if packet.payload.first() == Some(&0x01) {
                break; // COM_QUIT
            }
            if packet.payload == b"\x03SHOW SESSION_STATES" {
                if !respond_to_snapshot_query(&reader, &mut writer, snapshot_reply, broad).await {
                    break;
                }
                continue;
            }
            if packet.payload.first() == Some(&0x18) {
                // COM_STMT_SEND_LONG_DATA has no response.
                continue;
            }
            if packet.payload.windows(5).any(|window| window == b"BEGIN") {
                in_transaction = true;
            }
            if packet.payload.windows(6).any(|window| window == b"COMMIT") {
                in_transaction = false;
            }
            if packet.payload.windows(5).any(|window| window == b"SLEEP") {
                // Simulates a long-running statement so a force
                // deadline can preempt an in-flight command.
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
            if packet.payload.windows(4).any(|window| window == b"HANG") {
                // A permanently stuck backend: only a force close ever
                // ends this command.
                tokio::time::sleep(Duration::from_secs(3600)).await;
            }
            writer.reset_sequence(reader.expected_sequence());
            let status = 0x0002 | u16::from(in_transaction);
            let Ok(ok) = encode_ok_packet(
                ResponseHeader::OK,
                1,
                0,
                StatusFlags::from_bits_retain(status),
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
    shutdown_tx: watch::Sender<bool>,
    drain_tx: watch::Sender<bool>,
    forwarder: Arc<dataplane::control_dispatch::InboundForwarder>,
    sql_port: u16,
    server_task: tokio::task::JoinHandle<()>,
    dispatch_task: tokio::task::JoinHandle<Result<(), dataplane::control_dispatch::DispatchFatal>>,
    backend_port: u16,
    metrics_rx: mpsc::Receiver<Observation>,
    backend_transcript: Arc<Mutex<Vec<Vec<u8>>>>,
}

async fn spawn_stack() -> Stack {
    spawn_stack_with_snapshot(SnapshotReply::Valid).await
}

async fn spawn_stack_with_snapshot(snapshot_reply: SnapshotReply) -> Stack {
    // Fake backend.
    let Ok(backend_listener) = TcpListener::bind(("127.0.0.1", 0)).await else {
        unreachable!("backend bind")
    };
    let Ok(backend_addr) = backend_listener.local_addr() else {
        unreachable!("backend addr")
    };
    let backend_transcript = Arc::new(Mutex::new(Vec::new()));
    tokio::spawn(run_fake_backend(
        backend_listener,
        Arc::clone(&backend_transcript),
        snapshot_reply,
    ));

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
    // The dispatch loop processes inbound frames only while a session is
    // live; publish the matching `Connected` (same lineage as the
    // forwarder resume below) so routed control answers are not deferred.
    state_tx
        .send(ConnectionState::Connected {
            epoch: 1,
            serial: 1,
            capabilities: 0,
            peer_process_id: Arc::from("go-fixture"),
            peer_started_unix_millis: 1_700_000_000_000,
        })
        .ok();
    let Ok(()) = forwarder
        .resume_session(SessionMeta {
            serial: 1,
            epoch: 1,
            peer_process_id: Arc::from("go-fixture"),
            peer_started_unix_millis: 1_700_000_000_000,
        })
        .await
    else {
        unreachable!("the first session's resume sets the frame origin")
    };

    // The engine owner over a real (never-connecting) control client.
    let client = control_client();
    let (metrics, metrics_rx) = MetricsRecorder::channel(128);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (drain_tx, drain_rx) = watch::channel(false);
    let owner: Arc<dyn BoundSessionHandler> = Arc::new(
        EngineSessionOwner::new(
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
        )
        .with_metrics(metrics),
    );
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
    // Mirror the executable's composition: forced shutdown holds the
    // abort backstop past the session owners' cleanup bound.
    let server = server.with_force_join_grace(Duration::from_secs(3));
    let server_handle = server.handle();
    let server_task = tokio::spawn(async move {
        let _ = server.run(connection_handler).await;
    });

    Stack {
        server_handle,
        sender,
        _state_tx: state_tx,
        shutdown_tx,
        drain_tx,
        forwarder: Arc::new(forwarder),
        sql_port: sql_addr.port(),
        server_task,
        dispatch_task,
        backend_port: backend_addr.port(),
        metrics_rx,
        backend_transcript,
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
        control_proto::snapshot::SnapshotLineage::for_tests("go-fixture"),
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
        Self::login(port, FAKE_BACKEND_PASSWORD).await.ok()
    }

    /// Full connection-phase flow with a real challenge/response; the
    /// error branch returns the terminal non-OK payload.
    async fn login(port: u16, password: &str) -> Result<Self, Vec<u8>> {
        let Ok(stream) = TcpStream::connect(("127.0.0.1", port)).await else {
            return Err(Vec::new());
        };
        let (read, write) = stream.into_split();
        let mut reader = PacketReader::new(read);
        let mut writer = PacketWriter::new(write);
        // Strict wire sequences throughout the connection phase: the
        // greeting opens at zero and every later packet continues its
        // exchange in lockstep.
        let Ok(preview) = reader.peek_packet().await else {
            return Err(Vec::new());
        };
        assert_eq!(preview.sequence_id, 0);
        let Ok(greeting) = reader.read_logical(64 * 1024).await else {
            return Err(Vec::new());
        };
        let Ok(parsed) = parse_initial_handshake(&greeting.payload) else {
            return Err(Vec::new());
        };
        let mut proxy_salt = parsed.auth_plugin_data_part_1.to_vec();
        proxy_salt.extend_from_slice(parsed.auth_plugin_data_part_2);
        let capabilities = CapabilityFlags::PROTOCOL_41
            | CapabilityFlags::LONG_PASSWORD
            | CapabilityFlags::SECURE_CONNECTION
            | CapabilityFlags::PLUGIN_AUTH
            | CapabilityFlags::DEPRECATE_EOF;
        // The first scramble answers the proxy's greeting salt.
        let first_scramble = native_scramble(password, &proxy_salt);
        let Ok(response) = encode_handshake_response(HandshakeResponseParams {
            capabilities,
            max_packet_size: 16 * 1024 * 1024,
            collation: 45,
            username: b"root",
            auth_response: &first_scramble,
            database: None,
            auth_plugin_name: Some(b"mysql_native_password"),
            attributes: None,
            zstd_level: None,
        }) else {
            return Err(Vec::new());
        };
        writer.reset_sequence(reader.expected_sequence());
        if writer.write_logical(&response, true).await.is_err() {
            return Err(Vec::new());
        }
        let expected_switch_sequence = writer.next_sequence();
        reader.reset_sequence(expected_switch_sequence);
        let Ok(preview) = reader.peek_packet().await else {
            return Err(Vec::new());
        };
        assert_eq!(preview.sequence_id, expected_switch_sequence);
        let Ok(switch) = reader.read_logical(64 * 1024).await else {
            return Err(Vec::new());
        };
        // The backend always re-requests authentication: the proxy's
        // unknown-plugin rewrite makes it challenge with its own salt.
        if switch.payload.first() != Some(&0xFE) {
            return Err(switch.payload);
        }
        let data = &switch.payload[1..];
        let Some(nul) = data.iter().position(|&byte| byte == 0) else {
            return Err(switch.payload.clone());
        };
        assert_eq!(&data[..nul], b"mysql_native_password");
        let mut backend_salt = &data[nul + 1..];
        if backend_salt.last() == Some(&0) {
            backend_salt = &backend_salt[..backend_salt.len() - 1];
        }
        assert_ne!(
            backend_salt,
            proxy_salt.as_slice(),
            "re-authentication challenges with the backend's own salt"
        );
        writer.reset_sequence(reader.expected_sequence());
        if writer
            .write_logical(&native_scramble(password, backend_salt), true)
            .await
            .is_err()
        {
            return Err(Vec::new());
        }
        let expected_result_sequence = writer.next_sequence();
        reader.reset_sequence(expected_result_sequence);
        let Ok(preview) = reader.peek_packet().await else {
            return Err(Vec::new());
        };
        assert_eq!(preview.sequence_id, expected_result_sequence);
        let Ok(outcome) = reader.read_logical(64 * 1024).await else {
            return Err(Vec::new());
        };
        if outcome.payload.first() != Some(&0x00) {
            return Err(outcome.payload);
        }
        Ok(Self {
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
        // Strict wire sequence: the response to a fresh command must
        // answer at one, whatever earlier exchanges left behind.
        match self.reader.peek_packet().await {
            Ok(preview) => assert_eq!(preview.sequence_id, 1),
            Err(_) => return false,
        }
        let Ok(response) = self.reader.read_logical(64 * 1024).await else {
            return false;
        };
        let _ = self.capabilities;
        response.payload.first() == Some(&0x00)
    }

    /// `COM_STMT_SEND_LONG_DATA`: fire-and-forget, no response.
    async fn send_long_data(&mut self, statement_id: u32) -> bool {
        let mut payload = vec![0x18_u8];
        payload.extend_from_slice(&statement_id.to_le_bytes());
        payload.extend_from_slice(&0_u16.to_le_bytes());
        payload.extend_from_slice(b"chunk");
        self.writer.reset_sequence(0);
        self.writer.write_logical(&payload, true).await.is_ok()
    }

    /// `COM_STMT_RESET`: clears the statement's long-data guard.
    async fn stmt_reset_ok(&mut self, statement_id: u32) -> bool {
        let mut payload = vec![0x1A_u8];
        payload.extend_from_slice(&statement_id.to_le_bytes());
        self.writer.reset_sequence(0);
        if self.writer.write_logical(&payload, true).await.is_err() {
            return false;
        }
        self.reader.reset_sequence(1);
        match self.reader.peek_packet().await {
            Ok(preview) => assert_eq!(preview.sequence_id, 1),
            Err(_) => return false,
        }
        let Ok(response) = self.reader.read_logical(64 * 1024).await else {
            return false;
        };
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
        // The production adapter always answers the handshake event
        // with a correlated accept decision; the engine consumes it
        // before requesting a route.
        let decision = ControlEnvelope {
            request_id: request_id - 1,
            generation: 1,
            body: Some(Body::HandshakeDecision(HandshakeDecision {
                connection_id,
                accept: true,
                retry: false,
                code: ErrorCode::Ok as i32,
                client_message: String::new(),
                namespace: "default".to_owned(),
            })),
            ..ControlEnvelope::default()
        };
        for _ in 0..200 {
            let _ = forwarder.handle(decision.clone()).await;
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    });
    let forwarder = Arc::clone(&stack.forwarder);
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
    for _ in 0..500 {
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

/// The real session path emits payload-free metrics with the legacy command
/// and quit-source labels. This is the bridge between the DPL-04 engine and
/// the DPL-05 exporter, not only an aggregator unit test.
#[tokio::test]
async fn session_path_emits_query_traffic_and_exact_quit_source() {
    let mut stack = spawn_stack().await;
    spawn_route_answer(&stack, 1, 2);
    let Some(mut client) = timeout(Duration::from_secs(5), MysqlClient::connect(stack.sql_port))
        .await
        .ok()
        .flatten()
    else {
        unreachable!("session established")
    };
    assert!(client.query_ok("SELECT 1").await);
    client.quit().await;

    let mut saw_handshake = false;
    let mut saw_query = false;
    let mut saw_close = false;
    let received = timeout(Duration::from_secs(5), async {
        while let Some(observation) = stack.metrics_rx.recv().await {
            match observation {
                Observation::HandshakeCompleted {
                    backend, traffic, ..
                } => {
                    assert!(backend.ends_with(&stack.backend_port.to_string()));
                    assert!(traffic.inbound_bytes > 0);
                    assert!(traffic.outbound_bytes > 0);
                    saw_handshake = true;
                }
                Observation::CommandCompleted {
                    backend,
                    command,
                    traffic,
                    ..
                } if command.name() == "Query" => {
                    assert!(backend.ends_with(&stack.backend_port.to_string()));
                    assert!(traffic.inbound_bytes > 0);
                    assert!(traffic.outbound_bytes > 0);
                    saw_query = true;
                }
                Observation::SessionClosed { source, .. } => {
                    assert_eq!(source, QuitSource::None);
                    saw_close = true;
                }
                _ => {}
            }
            if saw_handshake && saw_query && saw_close {
                return;
            }
        }
    })
    .await;
    assert!(
        received.is_ok(),
        "session observations reach the bounded queue"
    );
    assert!(saw_handshake && saw_query && saw_close);
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
        client.query_ok("SELECT after_snapshot").await,
        "the session keeps its backend and keeps serving"
    );
    let transcript = stack
        .backend_transcript
        .lock()
        .map_or_else(|_| Vec::new(), |commands| commands.clone());
    assert_eq!(
        transcript
            .iter()
            .filter(|payload| payload.as_slice() == b"\x03SHOW SESSION_STATES")
            .count(),
        1,
        "MIG-00 captures one snapshot at the redirect safe boundary"
    );
    assert!(
        transcript.iter().all(|payload| !payload
            .windows(b"signed-token-private".len())
            .any(|window| window == b"signed-token-private")),
        "the signed token is backend-to-proxy only"
    );
    let before = transcript
        .iter()
        .position(|payload| payload.as_slice() == b"\x03SELECT 1");
    let snapshot = transcript
        .iter()
        .position(|payload| payload.as_slice() == b"\x03SHOW SESSION_STATES");
    let after = transcript
        .iter()
        .position(|payload| payload.as_slice() == b"\x03SELECT after_snapshot");
    assert!(
        matches!((before, snapshot, after), (Some(before), Some(snapshot), Some(after)) if before < snapshot && snapshot < after),
        "the internal query is serialized between user commands: {transcript:?}"
    );
    client.quit().await;
    stack.dispatch_task.abort();
}

/// A backend ERR (pre-v9 missing signing certificate), a NULL/empty token,
/// and malformed but bounded JSON are complete internal responses. The
/// redirect fails, but the old backend stays aligned and serves the next user
/// command.
#[tokio::test]
async fn complete_snapshot_validation_failures_preserve_old_backend() {
    for behavior in [
        SnapshotReply::SigningCertificateError,
        SnapshotReply::NullToken,
        SnapshotReply::EmptyToken,
        SnapshotReply::MalformedJson,
    ] {
        let stack = spawn_stack_with_snapshot(behavior).await;
        spawn_route_answer(&stack, 1, 2);
        let Some(mut client) =
            timeout(Duration::from_secs(5), MysqlClient::connect(stack.sql_port))
                .await
                .ok()
                .flatten()
        else {
            unreachable!("session established for {behavior:?}")
        };
        assert!(client.query_ok("SELECT before_snapshot_failure").await);

        let redirect = command_envelope(
            6100,
            Body::RedirectCommand(RedirectCommand {
                connection_id: 1,
                redirect_id: format!("r-{behavior:?}"),
                backend_id: "tidb-other".to_owned(),
                backend_address: "127.0.0.1:1".to_owned(),
                cluster_name: String::new(),
                deadline_unix_millis: 0,
                command_sequence: 1,
            }),
        );
        let _ = stack.forwarder.handle(redirect).await;
        let result = wait_sent(&stack.sender, |envelope| {
            matches!(&envelope.body, Some(Body::RedirectResult(_)))
        })
        .await;
        let Some(ControlEnvelope {
            body: Some(Body::RedirectResult(result)),
            ..
        }) = result
        else {
            unreachable!("redirect terminal for {behavior:?}")
        };
        assert!(!result.succeeded);
        assert!(
            client.query_ok("SELECT after_snapshot_failure").await,
            "wire-complete {behavior:?} failure must preserve the old backend"
        );
        let snapshot_queries = stack.backend_transcript.lock().map_or(0, |commands| {
            commands
                .iter()
                .filter(|payload| payload.as_slice() == b"\x03SHOW SESSION_STATES")
                .count()
        });
        assert_eq!(snapshot_queries, 1);
        client.quit().await;
        stack.dispatch_task.abort();
    }
}

/// A backend disconnect or an oversized row leaves the internal response
/// incomplete. The engine reports the redirect terminal exactly once and
/// closes instead of reusing a poisoned old command stream.
#[tokio::test]
async fn incomplete_snapshot_failures_close_the_session() {
    for behavior in [SnapshotReply::Disconnect, SnapshotReply::OversizedJson] {
        let stack = spawn_stack_with_snapshot(behavior).await;
        spawn_route_answer(&stack, 1, 2);
        let Some(mut client) =
            timeout(Duration::from_secs(5), MysqlClient::connect(stack.sql_port))
                .await
                .ok()
                .flatten()
        else {
            unreachable!("session established for {behavior:?}")
        };
        assert!(client.query_ok("SELECT before_snapshot_disconnect").await);

        let redirect = command_envelope(
            6200,
            Body::RedirectCommand(RedirectCommand {
                connection_id: 1,
                redirect_id: format!("r-{behavior:?}"),
                backend_id: "tidb-other".to_owned(),
                backend_address: "127.0.0.1:1".to_owned(),
                cluster_name: String::new(),
                deadline_unix_millis: 0,
                command_sequence: 1,
            }),
        );
        let _ = stack.forwarder.handle(redirect).await;
        let result = wait_sent(&stack.sender, |envelope| {
            matches!(&envelope.body, Some(Body::RedirectResult(_)))
        })
        .await;
        let Some(ControlEnvelope {
            body: Some(Body::RedirectResult(result)),
            ..
        }) = result
        else {
            unreachable!("redirect terminal for {behavior:?}")
        };
        assert!(!result.succeeded);
        assert!(
            timeout(Duration::from_secs(3), async {
                loop {
                    if !client.query_ok("SELECT must_not_reuse_poisoned_wire").await {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .is_ok(),
            "incomplete {behavior:?} response must close the session"
        );
        stack.dispatch_task.abort();
    }
}

/// Contract #1 cancel-safety: control activity racing a fragmented
/// client command must not drop bytes the engine already consumed from
/// the wire — the exchange completes intact once the frame arrives.
#[tokio::test]
async fn control_activity_during_fragmented_command_keeps_wire_intact() {
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

    // Send only part of the next command's header, then let control
    // traffic win the engine's idle race while the frame is pending.
    let payload = b"\x03SELECT 6";
    let mut frame = vec![u8::try_from(payload.len()).unwrap_or(0), 0, 0, 0];
    frame.extend_from_slice(payload);
    assert!(client.writer.get_mut().write_all(&frame[..2]).await.is_ok());
    tokio::time::sleep(Duration::from_millis(100)).await;

    let redirect = command_envelope(
        6001,
        Body::RedirectCommand(RedirectCommand {
            connection_id: 1,
            redirect_id: "r-frag".to_owned(),
            backend_id: "tidb-other".to_owned(),
            backend_address: "127.0.0.1:1".to_owned(),
            cluster_name: String::new(),
            deadline_unix_millis: 0,
            command_sequence: 1,
        }),
    );
    let _ = stack.forwarder.handle(redirect).await;
    let refused = wait_sent(
        &stack.sender,
        |e| matches!(&e.body, Some(Body::RedirectResult(result)) if result.redirect_id == "r-frag"),
    )
    .await;
    assert!(refused.is_some(), "control served while the frame is open");

    // Complete the frame: nothing consumed earlier may be lost. A
    // desynced engine never answers, so the read is deadline-bounded.
    assert!(client.writer.get_mut().write_all(&frame[2..]).await.is_ok());
    client.reader.reset_sequence(1);
    match timeout(Duration::from_secs(5), client.reader.peek_packet()).await {
        Ok(Ok(preview)) => assert_eq!(preview.sequence_id, 1),
        other => unreachable!("the response survives the race: {other:?}"),
    }
    let Ok(Ok(response)) = timeout(
        Duration::from_secs(5),
        client.reader.read_logical(64 * 1024),
    )
    .await
    else {
        unreachable!("the fragmented command still round-trips")
    };
    assert_eq!(response.payload.first(), Some(&0x00));
    client.quit().await;
    stack.dispatch_task.abort();
}

/// Go's first-time handshake rewrite end to end: a real non-empty
/// native password authenticates only because the proxy forwards
/// `auth_unknown_plugin` with the original auth data preserved and the
/// backend re-challenges with its own salt (the fake backend rejects
/// any direct plugin, and the client asserts the switch salt differs
/// from the proxy greeting's).
#[tokio::test]
async fn non_empty_password_reauths_against_backend_salt() {
    let stack = spawn_stack().await;
    spawn_route_answer(&stack, 1, 2);
    let Ok(login) = timeout(
        Duration::from_secs(5),
        MysqlClient::login(stack.sql_port, FAKE_BACKEND_PASSWORD),
    )
    .await
    else {
        unreachable!("login completes")
    };
    let Ok(mut client) = login else {
        unreachable!("the re-authentication succeeds end to end")
    };
    assert!(client.query_ok("SELECT 1").await);
    client.quit().await;
    stack.dispatch_task.abort();
}

/// An initial-auth failure keeps Go's `using password` semantics on the
/// client-visible error.
#[tokio::test]
async fn wrong_password_reports_using_password() {
    let stack = spawn_stack().await;
    spawn_route_answer(&stack, 1, 2);
    let Ok(login) = timeout(
        Duration::from_secs(5),
        MysqlClient::login(stack.sql_port, "wrong-pa55"),
    )
    .await
    else {
        unreachable!("login terminates")
    };
    let Err(denied) = login else {
        unreachable!("a wrong password must be denied")
    };
    assert_eq!(
        denied.first(),
        Some(&0xFF),
        "MySQL error packet: {denied:?}"
    );
    assert!(
        String::from_utf8_lossy(&denied).contains("using password"),
        "Go's using-password semantics survive the relay: {denied:?}"
    );
    stack.dispatch_task.abort();
}

/// The full force ownership chain with a permanently stuck backend:
/// session shutdown and server shutdown back-to-back (the executable's
/// signal path) must return the server — every listener, session owner,
/// loop, and engine joined or aborted — emit the CLOSED terminal exactly
/// once before the control dispatch stops, and fit ONE force budget of
/// wall clock (no stacked cleanup deadlines).
#[tokio::test]
async fn forced_shutdown_with_stuck_backend_joins_everything_in_budget() {
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

    let slow = tokio::spawn(async move { client.query_ok("SELECT HANG").await });
    tokio::time::sleep(Duration::from_millis(100)).await;

    let started = std::time::Instant::now();
    stack.shutdown_tx.send_replace(true);
    stack.server_handle.shutdown();
    assert!(
        timeout(Duration::from_secs(5), stack.server_task)
            .await
            .is_ok_and(|joined| joined.is_ok()),
        "the server returns with every owned task joined"
    );
    let elapsed = started.elapsed();
    // Harness cleanup budget is 2s; one budget plus scheduling margins,
    // never the 4s+ two stacked deadlines would take.
    assert!(
        elapsed < Duration::from_secs(4),
        "one force budget: {elapsed:?}"
    );

    // The terminal work already happened — before the dispatch stops.
    let closed: Vec<_> = stack
        .sender
        .sent()
        .into_iter()
        .filter(|e| matches!(&e.body, Some(Body::ConnectionEvent(event)) if event.kind == 3))
        .collect();
    assert_eq!(closed.len(), 1, "CLOSED exactly once: {closed:?}");
    let Some(Body::ConnectionEvent(event)) = &closed[0].body else {
        unreachable!()
    };
    assert_eq!(event.error_source, 6, "shutdown attribution: {event:?}");
    stack.dispatch_task.abort();
    slow.abort();
}

/// Drain honors the transaction safe boundary end to end: an open
/// transaction (BEGIN, backend status `SERVER_STATUS_IN_TRANS`) defers
/// the graceful close; COMMIT clears it and the terminal follows.
#[tokio::test]
async fn drain_waits_for_open_transaction_commit() {
    let stack = spawn_stack().await;
    spawn_route_answer(&stack, 1, 2);
    let Some(mut client) = timeout(Duration::from_secs(5), MysqlClient::connect(stack.sql_port))
        .await
        .ok()
        .flatten()
    else {
        unreachable!("session established")
    };
    assert!(client.query_ok("BEGIN").await);

    stack.drain_tx.send_replace(true);
    tokio::time::sleep(Duration::from_millis(150)).await;
    let closed_early = stack
        .sender
        .sent()
        .into_iter()
        .filter(|e| matches!(&e.body, Some(Body::ConnectionEvent(event)) if event.kind == 3))
        .count();
    assert_eq!(
        closed_early, 0,
        "an open transaction defers the drain close"
    );

    assert!(
        client.query_ok("COMMIT").await,
        "the session still serves mid-drain"
    );
    let closed = wait_sent(
        &stack.sender,
        |e| matches!(&e.body, Some(Body::ConnectionEvent(event)) if event.kind == 3),
    )
    .await;
    assert!(closed.is_some(), "the drain closes at the COMMIT boundary");
    stack.dispatch_task.abort();
}

/// Drain honors the prepared long-data guard end to end: an unfinished
/// `COM_STMT_SEND_LONG_DATA` blocks the graceful close until
/// `COM_STMT_RESET` clears the guard.
#[tokio::test]
async fn drain_waits_for_prepared_long_data_guard() {
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
    assert!(client.send_long_data(7).await);
    tokio::time::sleep(Duration::from_millis(50)).await;

    stack.drain_tx.send_replace(true);
    tokio::time::sleep(Duration::from_millis(150)).await;
    let closed_early = stack
        .sender
        .sent()
        .into_iter()
        .filter(|e| matches!(&e.body, Some(Body::ConnectionEvent(event)) if event.kind == 3))
        .count();
    assert_eq!(
        closed_early, 0,
        "a pending long-data guard defers the drain close"
    );

    assert!(
        client.stmt_reset_ok(7).await,
        "the session still serves mid-drain"
    );
    let closed = wait_sent(
        &stack.sender,
        |e| matches!(&e.body, Some(Body::ConnectionEvent(event)) if event.kind == 3),
    )
    .await;
    assert!(closed.is_some(), "the drain closes once the guard clears");
    stack.dispatch_task.abort();
}

/// The accepted decision's namespace is the routing truth: it must
/// reach the wire on the session's CLOSED lifecycle event (and drive
/// the route conversation), not the pre-decision registration seed.
#[tokio::test]
async fn resolved_namespace_reaches_the_closed_event() {
    let stack = spawn_stack().await;
    // Decision resolves a NON-default namespace; route answers follow.
    let forwarder = Arc::clone(&stack.forwarder);
    tokio::spawn(async move {
        let decision = ControlEnvelope {
            request_id: 1,
            generation: 1,
            body: Some(Body::HandshakeDecision(HandshakeDecision {
                connection_id: 1,
                accept: true,
                retry: false,
                code: ErrorCode::Ok as i32,
                client_message: String::new(),
                namespace: "ns-wired".to_owned(),
            })),
            ..ControlEnvelope::default()
        };
        for _ in 0..200 {
            let _ = forwarder.handle(decision.clone()).await;
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    });
    let forwarder = Arc::clone(&stack.forwarder);
    let backend_port = stack.backend_port;
    tokio::spawn(async move {
        let assignment = ControlEnvelope {
            request_id: 2,
            generation: 1,
            body: Some(Body::RouteAssignment(RouteAssignment {
                connection_id: 1,
                assignment_id: "a-ns".to_owned(),
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
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    });

    let Some(mut client) = timeout(Duration::from_secs(5), MysqlClient::connect(stack.sql_port))
        .await
        .ok()
        .flatten()
    else {
        unreachable!("session established")
    };
    assert!(client.query_ok("SELECT 1").await);
    client.quit().await;

    let closed = wait_sent(
        &stack.sender,
        |e| matches!(&e.body, Some(Body::ConnectionEvent(event)) if event.kind == 3),
    )
    .await;
    let Some(closed) = closed else {
        unreachable!("the session reports CLOSED")
    };
    let Some(Body::ConnectionEvent(event)) = closed.body else {
        unreachable!()
    };
    assert_eq!(
        event.namespace, "ns-wired",
        "the CLOSED event carries the decision-resolved namespace"
    );
    stack.dispatch_task.abort();
}

/// The decision namespace is adopted VERBATIM: Go allows names far
/// beyond 255 bytes and multibyte characters, so any local byte-bound
/// truncation would silently rename an identity — and byte 255 of this
/// name is NOT a char boundary, so the old `truncate(255)` would panic
/// the session task outright.
#[tokio::test]
async fn long_multibyte_namespace_is_preserved_verbatim() {
    // 2 + 120×3 = 362 bytes; byte 255 splits a `界` (253 % 3 != 0).
    let long_namespace = format!("ns{}", "界".repeat(120));
    let stack = spawn_stack().await;
    let forwarder = Arc::clone(&stack.forwarder);
    let decision_namespace = long_namespace.clone();
    tokio::spawn(async move {
        let decision = ControlEnvelope {
            request_id: 1,
            generation: 1,
            body: Some(Body::HandshakeDecision(HandshakeDecision {
                connection_id: 1,
                accept: true,
                retry: false,
                code: ErrorCode::Ok as i32,
                client_message: String::new(),
                namespace: decision_namespace.clone(),
            })),
            ..ControlEnvelope::default()
        };
        for _ in 0..200 {
            let _ = forwarder.handle(decision.clone()).await;
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    });
    let forwarder = Arc::clone(&stack.forwarder);
    let backend_port = stack.backend_port;
    tokio::spawn(async move {
        let assignment = ControlEnvelope {
            request_id: 2,
            generation: 1,
            body: Some(Body::RouteAssignment(RouteAssignment {
                connection_id: 1,
                assignment_id: "a-long-ns".to_owned(),
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
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    });

    let Some(mut client) = timeout(Duration::from_secs(5), MysqlClient::connect(stack.sql_port))
        .await
        .ok()
        .flatten()
    else {
        unreachable!("session established")
    };
    assert!(client.query_ok("SELECT 1").await);
    client.quit().await;

    let closed = wait_sent(
        &stack.sender,
        |e| matches!(&e.body, Some(Body::ConnectionEvent(event)) if event.kind == 3),
    )
    .await;
    let Some(closed) = closed else {
        unreachable!("the session reports CLOSED")
    };
    let Some(Body::ConnectionEvent(event)) = closed.body else {
        unreachable!()
    };
    assert_eq!(
        event.namespace, long_namespace,
        "the CLOSED event preserves the full multibyte namespace verbatim"
    );
    stack.dispatch_task.abort();
}

/// Exact `MySQL` ERR packet contract (`CLIENT_PROTOCOL_41`): `0xFF` marker,
/// little-endian error code, `#` sql-state marker, 5-byte SQLSTATE,
/// and the FULL remaining message — approved vocabulary is asserted
/// verbatim, never by substring.
fn assert_exact_err_packet(payload: &[u8], code: u16, sqlstate: [u8; 5], message: &str) {
    assert_eq!(payload.first(), Some(&0xFF), "ERR marker: {payload:?}");
    assert!(payload.len() > 9, "ERR packet too short: {payload:?}");
    assert_eq!(
        u16::from_le_bytes([payload[1], payload[2]]),
        code,
        "ERR code: {payload:?}"
    );
    assert_eq!(payload[3], b'#', "sql-state marker: {payload:?}");
    assert_eq!(payload[4..9], sqlstate, "SQLSTATE: {payload:?}");
    assert_eq!(
        String::from_utf8_lossy(&payload[9..]),
        message,
        "ERR message must equal the approved vocabulary verbatim"
    );
}

/// A REJECTED handshake decision refuses the client on the wire with
/// the decision's approved message (never routes, never silently
/// hangs), and the session reports CLOSED.
#[tokio::test]
async fn rejected_handshake_decision_refuses_the_client() {
    let stack = spawn_stack().await;
    // Inject only a REJECT decision; no route answer exists at all.
    let forwarder = Arc::clone(&stack.forwarder);
    tokio::spawn(async move {
        let decision = ControlEnvelope {
            request_id: 1,
            generation: 1,
            body: Some(Body::HandshakeDecision(HandshakeDecision {
                connection_id: 1,
                accept: false,
                retry: false,
                code: ErrorCode::HandshakeRejected as i32,
                client_message: "failed to find a namespace".to_owned(),
                namespace: String::new(),
            })),
            ..ControlEnvelope::default()
        };
        for _ in 0..200 {
            let _ = forwarder.handle(decision.clone()).await;
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    });

    let Ok(refused) = timeout(
        Duration::from_secs(5),
        MysqlClient::login(stack.sql_port, FAKE_BACKEND_PASSWORD),
    )
    .await
    else {
        unreachable!("the refusal terminates the login promptly")
    };
    let Err(denied) = refused else {
        unreachable!("a rejected decision must refuse the client")
    };
    assert_exact_err_packet(&denied, 1105, *b"HY000", "failed to find a namespace");

    let closed = wait_sent(
        &stack.sender,
        |e| matches!(&e.body, Some(Body::ConnectionEvent(event)) if event.kind == 3),
    )
    .await;
    assert!(closed.is_some(), "the refused session reports CLOSED");
    stack.dispatch_task.abort();
}

/// A `NO_BACKEND` route answer refuses the client with Go's approved
/// vocabulary (error-parity row: `ErrProxyNoBackend` reaches the client
/// in Go mode) instead of silently dropping the connection, and the
/// session reports CLOSED.
#[tokio::test]
async fn no_backend_route_answer_refuses_the_client() {
    let stack = spawn_stack().await;
    // Accepted decision at request 1; the route request (2) answers a
    // terminal NO_BACKEND assignment.
    let forwarder = Arc::clone(&stack.forwarder);
    tokio::spawn(async move {
        let decision = ControlEnvelope {
            request_id: 1,
            generation: 1,
            body: Some(Body::HandshakeDecision(HandshakeDecision {
                connection_id: 1,
                accept: true,
                retry: false,
                code: ErrorCode::Ok as i32,
                client_message: String::new(),
                namespace: String::new(),
            })),
            ..ControlEnvelope::default()
        };
        for _ in 0..200 {
            let _ = forwarder.handle(decision.clone()).await;
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    });
    let forwarder = Arc::clone(&stack.forwarder);
    tokio::spawn(async move {
        let refusal = ControlEnvelope {
            request_id: 2,
            generation: 1,
            body: Some(Body::RouteAssignment(RouteAssignment {
                connection_id: 1,
                assignment_id: String::new(),
                backend_id: String::new(),
                backend_address: String::new(),
                cluster_name: String::new(),
                keyspace: String::new(),
                healthy: false,
                local: false,
                code: ErrorCode::NoBackend as i32,
                detail: "no available backend".to_owned(),
            })),
            ..ControlEnvelope::default()
        };
        for _ in 0..200 {
            let _ = forwarder.handle(refusal.clone()).await;
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    });

    let Ok(refused) = timeout(
        Duration::from_secs(5),
        MysqlClient::login(stack.sql_port, FAKE_BACKEND_PASSWORD),
    )
    .await
    else {
        unreachable!("the NO_BACKEND refusal terminates the login promptly")
    };
    let Err(denied) = refused else {
        unreachable!("a NO_BACKEND answer must refuse the client")
    };
    assert_exact_err_packet(
        &denied,
        1105,
        *b"HY000",
        "No available TiDB instances, please make sure TiDB is available",
    );

    let closed = wait_sent(
        &stack.sender,
        |e| matches!(&e.body, Some(Body::ConnectionEvent(event)) if event.kind == 3),
    )
    .await;
    assert!(closed.is_some(), "the refused session reports CLOSED");
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
/// `DrainResult` counts it as force-closed and the CLOSED lifecycle
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

/// The force phase of a full server shutdown (session shutdown and
/// server shutdown back-to-back, exactly the executable's signal path)
/// must not abort a session owner before its terminal work: the CLOSED
/// notice with shutdown attribution still goes out mid-command.
#[tokio::test]
async fn forced_shutdown_still_emits_session_closed() {
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

    // Mid-command, no safe boundary: the backend stalls for seconds.
    let slow = tokio::spawn(async move { client.query_ok("SELECT SLEEP").await });
    tokio::time::sleep(Duration::from_millis(100)).await;

    stack.shutdown_tx.send_replace(true);
    stack.server_handle.shutdown();

    let closed = wait_sent(
        &stack.sender,
        |e| matches!(&e.body, Some(Body::ConnectionEvent(event)) if event.kind == 3),
    )
    .await;
    let Some(closed) = closed else {
        unreachable!("the forced session still reports CLOSED")
    };
    let Some(Body::ConnectionEvent(event)) = closed.body else {
        unreachable!()
    };
    assert_eq!(
        event.error_source, 6,
        "forced shutdown uses the proxy-shutdown source: {event:?}"
    );
    let _ = slow.await;
    stack.dispatch_task.abort();
}
