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

//! The production session owner (DPL-04): composes the DPL-01
//! [`SessionLoop`] FSM with real `MySQL` wire I/O, control-plane routing,
//! and the CTL-06 terminal-effect notices.
//!
//! # Ownership
//!
//! One **engine task** owns every socket byte: both halves of the
//! client stream and, once dialed, of the backend. Bytes never cross
//! tasks. The [`SessionLoop`] owns the FSM in its own task; classified
//! [`SessionEvent`]s flow engine → loop over a one-slot channel into
//! the DPL-01 pump (the engine reads at most one frame beyond the last
//! event it handed over — exactly the pump's own classify-one-ahead
//! contract), and [`SessionEffect`]s flow loop → engine over a bounded
//! FIFO. Phase progression is command-gated: after the
//! `ClientHandshakeResponse` event the engine performs no backend work
//! until the FSM's `DialBackend` effect arrives.
//!
//! # Forward-then-observe
//!
//! Response bytes stream backend → client with a bounded 23-byte
//! prefix capture; classification runs on the captured metadata after
//! the packet is on the wire, exactly like Go (which parses while
//! forwarding). The FSM's `Forward*` effects therefore execute as
//! ordering acknowledgements: the effect confirms the FSM authorized
//! what the wire already carried. An effect the engine cannot honor in
//! its phase ends the session as a proxy-internal error — never a
//! silent divergence.
//!
//! # Authentication
//!
//! The multi-round backend authentication relay (auth switch, extra
//! data) is engine-internal via [`AuthRelay`]; the FSM observes only
//! the terminal `BackendAuthOk`/`BackendAuthFailed`, per the SES-00
//! vocabulary.
//!
//! # Slice scope (recorded for review)
//!
//! This slice serves the TLS-capable, uncompressed path. The greeting
//! advertises `SSL` iff this session's snapshot carries a frontend TLS server
//! config; when the client sends a strict `SSLRequest`, TLS is activated in
//! place on the client leg (and, per the backend TLS plan, on the backend leg
//! before any credential leaves) with the `MySQL` sequence continuing across
//! the upgrade. An `SSLRequest` against a greeting that withheld `SSL`, or a
//! malformed one, fails closed with no plaintext fallback. Compression is
//! advertised (`COMPRESS` + `ZSTD`) and, when a client negotiates it, activated
//! at the auth-OK boundary on each leg independently (WIRE-activation C); the
//! compressed sequence is slaved to the packet sequence and reset once per
//! command. `COM_CHANGE_USER` and
//! `COM_STMT_PREPARE` (the prepared special response flow) are
//! answered with a fixed unsupported error and the session closes. A
//! control redirect executes the bounded `SHOW SESSION_STATES` exchange at
//! the FSM safe boundary, validates the signed token/session JSON, dials and
//! authenticates the exact gate-admitted target with `tidb_session_token`,
//! restores the escaped state, and only then atomically replaces the backend
//! owner. Candidate-side failures drop the candidate while preserving the
//! aligned old backend; an old-backend disconnect or incomplete snapshot
//! response closes the poisoned session.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use control_proto::control_transport::ControlClient;
use control_proto::v1::control_envelope::Body;
use control_proto::v1::{
    ConnectionIdentity, ControlEnvelope, ErrorCode, ErrorSource as WireErrorSource,
    HandshakeMetadata, HandshakeResponseEvent, Priority, ProxyProtocolMode, RouteAssignment,
    RouteRequest, RouteResult,
};
use mysql_wire::{
    CapabilityFlags, CommandPacket, HandshakeResponseParams, StatusFlags, encode_error_packet,
    encode_handshake_response, encode_initial_handshake, encode_ssl_request,
    parse_handshake_response, parse_ssl_request,
};
use proxy_io::PacketIo;
use proxy_io::compression::{CompressedIo, CompressionAlgorithm, CompressionLimits};
use proxy_io::counted::{ByteCounters, CountedIo};
use proxy_io::direction::DirectionSync;
use proxy_io::proxy_protocol::{
    EncodeAddresses, ProxyCommand, ProxyVersion, TransportProtocol, encode_proxy_v2,
};
use proxy_io::tls::{
    DEFAULT_CONN_BUFFER_SIZE, accept_frontend, build_backend_config, connect_backend,
};
use session_core::auth::{
    AuthEffect, AuthEvent, AuthOutcome, AuthRelay, AuthTurn, BackendTlsMode, CompressionSelection,
    UNKNOWN_AUTH_PLUGIN, classify_backend_auth_packet, compression_selection,
    plan_backend_handshake, plan_backend_migration_handshake,
};
use session_core::command::{
    Command, CommandSessionState, CommandStateEffects, ExpectedResponse, SessionMutation, dispatch,
};
use session_core::error_source::FailureKind;
use session_core::fsm::{SessionEffect, SessionEvent};
use session_core::handshake::{
    ConnectionEndpoints, build_greeting, greeting_capability, negotiate_frontend, verify_backend,
};
use session_core::internal_client::{
    InternalLimits, InternalParserState, InternalProgress, InternalQuery, InternalResult,
    SessionStateSnapshot,
};
use session_core::prepared::{PrepareDisposition, PrepareObserver, PreparedRegistry};
use session_core::response::{
    DEFAULT_RESPONSE_FLUSH_THRESHOLD, FlushAction, ResponseDisposition, ResponseObserver,
    ResponsePacket,
};
use tokio::io::AsyncWriteExt;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinSet;

use crate::control_dispatch::{CommandKind, CommandToken, RedirectTarget, ResponseKind};
use crate::observability::{
    BackendTraffic, MetricsRecorder, Observation, QuitSource, SessionLogContext, log_session,
};
use crate::route::{
    AcquireError, CenteredJitter, DialSchedule, RouteChannel, RouteChannelError, RouteEngine,
};
use crate::route_control::{ClusterTcpDialer, TrafficTotals};
use crate::server::{AcceptedConnection, ConnectionFuture, SessionSeat};
use crate::session::{
    EffectHandler, SessionControl, SessionEnd, SessionEventSource, SessionLoop, SessionLoopConfig,
    SessionSummary,
};
use crate::session_control::{
    BoundSessionHandler, ResponseStream, SessionCommander, SessionControlBinding,
};
use crate::transport::{BackendTransport, ClientTransport};

/// The proxy's full advertised capability set, including `SSL`. `SSL` is
/// retained or stripped per session by [`proxy_capabilities`] according to
/// whether that session's snapshot carries a frontend TLS server config.
/// `COMPRESS` and `ZSTD_COMPRESSION_ALGORITHM` are advertised (WIRE-activation
/// C): a client that negotiates either activates compressed framing at the
/// auth-OK boundary.
fn proxy_capability_base() -> CapabilityFlags {
    CapabilityFlags::LONG_PASSWORD
        | CapabilityFlags::FOUND_ROWS
        | CapabilityFlags::LONG_FLAG
        | CapabilityFlags::CONNECT_WITH_DB
        | CapabilityFlags::NO_SCHEMA
        | CapabilityFlags::ODBC
        | CapabilityFlags::LOCAL_FILES
        | CapabilityFlags::IGNORE_SPACE
        | CapabilityFlags::PROTOCOL_41
        | CapabilityFlags::INTERACTIVE
        | CapabilityFlags::SSL
        | CapabilityFlags::IGNORE_SIGPIPE
        | CapabilityFlags::TRANSACTIONS
        | CapabilityFlags::RESERVED
        | CapabilityFlags::SECURE_CONNECTION
        | CapabilityFlags::MULTI_STATEMENTS
        | CapabilityFlags::MULTI_RESULTS
        | CapabilityFlags::PS_MULTI_RESULTS
        | CapabilityFlags::PLUGIN_AUTH
        | CapabilityFlags::CONNECT_ATTRS
        | CapabilityFlags::PLUGIN_AUTH_LENENC_CLIENT_DATA
        | CapabilityFlags::DEPRECATE_EOF
        | CapabilityFlags::COMPRESS
        | CapabilityFlags::ZSTD_COMPRESSION_ALGORITHM
}

/// The proxy capabilities for one session: the full base with `SSL`
/// advertised only when this session's snapshot has a frontend TLS server
/// config, so the advertised capability always matches the live capability.
fn proxy_capabilities(frontend_tls_available: bool) -> CapabilityFlags {
    greeting_capability(proxy_capability_base(), frontend_tls_available)
}

/// The client's leading capability flags — the first four little-endian bytes
/// that begin both an `SSLRequest` and a full handshake response. Used only to
/// classify the first client packet; a payload shorter than four bytes carries
/// no `SSL` bit and falls through to the (fail-closed) handshake parser.
fn leading_capabilities(payload: &[u8]) -> CapabilityFlags {
    if payload.len() < 4 {
        return CapabilityFlags::from_bits_retain(0);
    }
    let bits = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
    CapabilityFlags::from_bits_retain(bits)
}

/// Overwrites the leading capability flags of a handshake-response payload with
/// the trusted pre-TLS `SSLRequest` mask (Go `handshakeFirstTime`: the mask sent
/// before the encrypted response is authoritative, so it — not the in-TLS
/// response's own bytes — governs the response's field layout and negotiation).
/// A payload shorter than four bytes is left unchanged; it fails the subsequent
/// parse fail-closed.
fn normalize_leading_capabilities(payload: &mut [u8], trusted: CapabilityFlags) {
    if payload.len() >= 4 {
        payload[0..4].copy_from_slice(&trusted.bits().to_le_bytes());
    }
}

/// The SNI/server name for a backend TLS handshake: the host of a `host:port`
/// routing address, with any IPv6 brackets stripped (Go: "use the DNS name as
/// much as possible"; both DNS names and IP literals parse as a server name).
fn backend_server_name(address: &str) -> String {
    let host = address.rsplit_once(':').map_or(address, |(host, _)| host);
    host.trim_start_matches('[')
        .trim_end_matches(']')
        .to_owned()
}

/// Writes a PROXY protocol v2 header announcing the original client as the
/// source and the dialed backend as the destination, straight to the raw
/// backend socket before any `MySQL` byte. The family is unified across a
/// mixed client/backend IP pair exactly like Go's `unifyIPFamily`.
///
/// Any failure (unresolvable backend peer, encode, or write) fails closed as a
/// backend-network error — the preamble must reach the backend intact before
/// the handshake, so a partial or absent header is never tolerated.
async fn write_backend_proxy_v2_header(
    conn: &mut CountedIo<tokio::net::TcpStream>,
    client_addr: std::net::SocketAddr,
) -> Result<(), WireErrorSource> {
    // The header is written THROUGH the raw byte counter (this `CountedIo`
    // wraps the socket before the header is emitted), so its wire bytes count
    // once at the innermost layer just like Go's dial path.
    let Ok(backend_addr) = conn.get_ref().peer_addr() else {
        return Err(WireErrorSource::BackendNetwork);
    };
    let Ok(header) = encode_proxy_v2(
        ProxyVersion::V2,
        ProxyCommand::PROXY,
        TransportProtocol::STREAM,
        EncodeAddresses::Ip {
            src: (client_addr.ip(), client_addr.port()),
            dst: (backend_addr.ip(), backend_addr.port()),
        },
        &[],
    ) else {
        return Err(WireErrorSource::Proxy);
    };
    if conn.write_all(&header).await.is_err() {
        return Err(WireErrorSource::BackendNetwork);
    }
    Ok(())
}

/// Maps a per-leg [`CompressionSelection`] to the codec algorithm, or `None`
/// when the leg negotiated no compression.
fn selection_to_compression_algorithm(
    selection: CompressionSelection,
) -> Option<CompressionAlgorithm> {
    match selection {
        CompressionSelection::None => None,
        CompressionSelection::Zlib => Some(CompressionAlgorithm::Zlib),
        CompressionSelection::Zstd { level } => Some(CompressionAlgorithm::Zstd {
            level: i32::from(level),
        }),
    }
}

/// Failure of the fresh-exchange send for a proxy-owned query.
pub enum ProxyOwnedQueryError {
    /// The layered (compression) sequence could not be reset to a clean command
    /// boundary because a frame is still in flight.
    LayeredReset,
    /// The request could not be written to the backend.
    Send,
}

/// Starts a fresh proxy-owned command exchange on a backend [`PacketIo`]:
/// resets the compression layer to sequence zero (Go `cmd_processor_query`
/// parity), resets the packet write/read sequences, then sends `request`.
///
/// This is the single production seam for a proxy-owned query's reset+send, so
/// the migration snapshot and its regression exercise the same code. Deleting
/// the layered reset makes the sent frame carry the previous exchange's stale
/// compressed sequence, which the regression catches.
///
/// # Errors
///
/// [`ProxyOwnedQueryError::LayeredReset`] if the compressed layer is not at a
/// clean boundary; [`ProxyOwnedQueryError::Send`] if the write fails.
pub async fn send_proxy_owned_query<T>(
    io: &mut PacketIo<T>,
    request: &[u8],
) -> Result<(), ProxyOwnedQueryError>
where
    T: tokio::io::AsyncWrite + Unpin + DirectionSync,
{
    io.reset_layer_sequence()
        .map_err(|_| ProxyOwnedQueryError::LayeredReset)?;
    io.reset_write_sequence(0);
    io.reset_read_sequence(1);
    io.write_logical(request, true)
        .await
        .map_err(|_| ProxyOwnedQueryError::Send)?;
    Ok(())
}

/// Handshake-phase logical payload bound.
const HANDSHAKE_PAYLOAD_LIMIT: usize = 64 * 1024;
/// Client command / infile chunk payload bound for this slice.
const COMMAND_PAYLOAD_LIMIT: usize = 64 * 1024 * 1024;
/// Streaming prefix capture for response classification.
const RESPONSE_CAPTURE: usize = 23;
/// Engine effect-command queue depth (FSM effects per event are few).
const ENGINE_CMD_CAPACITY: usize = 16;
/// Engine → owner report queue depth.
const ENGINE_REPORT_CAPACITY: usize = 8;
/// Server-version bytes advertised in the proxy greeting.
const SERVER_VERSION: &[u8] = b"8.0.11-TiProxy-rs";
/// Fixed error for the fail-closed `COM_CHANGE_USER` slice boundary.
const ER_CHANGE_USER_UNSUPPORTED: (u16, [u8; 5], &str) = (
    1105,
    *b"HY000",
    "TiProxy-rs: COM_CHANGE_USER is not supported yet",
);

/// Bounds one candidate attempt by both the issuer's absolute deadline and
/// the dataplane acquisition budget. Zero is the legacy/control default and
/// still receives a finite bound.
fn candidate_budget(deadline_unix_millis: u64) -> Duration {
    let local = DialSchedule::default().total;
    if deadline_unix_millis == 0 {
        return local;
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let deadline = Duration::from_millis(deadline_unix_millis);
    deadline.saturating_sub(now).min(local)
}

/// Commands into the engine task.
enum EngineCmd {
    /// Execute one FSM effect in order.
    Effect(SessionEffect),
    /// Idle-safe backend liveness probe (KA-003).
    Probe(oneshot::Sender<bool>),
    /// Bind the exact gate-admitted redirect target before the FSM can emit
    /// `StartRedirectHandshake`. This command shares the effect FIFO, so the
    /// target cannot race or be inferred from mutable control state.
    PrepareRedirect(RedirectTarget),
}

/// Reports from the engine to the session owner.
#[derive(Debug)]
enum EngineReport {
    /// A redirect attempt finished.
    RedirectFinished {
        /// Whether the migration succeeded.
        succeeded: bool,
        /// The owning backend after the attempt.
        backend_id: String,
        /// Failure code when unsuccessful.
        code: ErrorCode,
    },
}

/// The engine's terminal accounting, returned from its task.
#[derive(Debug, Clone)]
struct EngineExit {
    totals: TrafficTotals,
    source: WireErrorSource,
    quit_source: QuitSource,
    backend_id: String,
    backend_address: String,
    cluster: String,
    capabilities: u64,
    /// The namespace the accepted decision resolved (the process seed
    /// until a decision arrives), so the owner's close log attributes
    /// the connection to its real routing class.
    namespace: String,
}

/// The event-source half: the loop's pump polls this; the engine feeds
/// it through a one-slot channel.
struct EventRx {
    events: mpsc::Receiver<SessionEvent>,
}

impl SessionEventSource for EventRx {
    async fn next_event(&mut self) -> Option<SessionEvent> {
        self.events.recv().await
    }
}

/// The effect-handler half: forwards each FSM effect into the engine's
/// FIFO and runs the idle-safe probe through the engine (the socket
/// owner).
struct CmdTx {
    cmds: mpsc::Sender<EngineCmd>,
}

impl EffectHandler for CmdTx {
    async fn execute(&mut self, effect: SessionEffect, _children: &mut JoinSet<()>) {
        // A closed engine means the wire is gone; the loop then
        // observes the exhausted event source.
        let _ = self.cmds.send(EngineCmd::Effect(effect)).await;
    }

    async fn backend_active(&mut self) -> bool {
        let (tx, rx) = oneshot::channel();
        if self.cmds.send(EngineCmd::Probe(tx)).await.is_err() {
            return false;
        }
        rx.await.unwrap_or(false)
    }
}

/// Route channel over the split #37 binding: every expectation is
/// armed — and acknowledged by the dispatcher — **before** the request
/// envelope that provokes the answer is sent.
struct BindingRouteChannel {
    client: Arc<ControlClient>,
    commander: SessionCommander,
    responses: ResponseStream,
    identity: ConnectionIdentity,
    metadata: HandshakeMetadata,
    namespace: String,
    generation: u64,
}

impl BindingRouteChannel {
    async fn send_durable(&self, body: Body) -> Result<u64, RouteChannelError> {
        let Some(request_id) = self.client.allocate_request_id() else {
            return Err(RouteChannelError::ControlLost);
        };
        let envelope = ControlEnvelope {
            request_id,
            priority: Priority::Control.into(),
            body: Some(body),
            ..ControlEnvelope::default()
        };
        self.client
            .send(envelope)
            .await
            .map_err(|_| RouteChannelError::ControlLost)?;
        Ok(request_id)
    }
}

impl RouteChannel for BindingRouteChannel {
    async fn request_route(
        &mut self,
        excluded_backend_ids: Vec<String>,
    ) -> Result<(), RouteChannelError> {
        let Some(request_id) = self.client.allocate_request_id() else {
            return Err(RouteChannelError::ControlLost);
        };
        // Causal barrier: the dispatcher acknowledges the armed
        // expectation before the request that provokes the answer.
        self.commander
            .expect_response(request_id, ResponseKind::RouteAssignment)
            .await
            .map_err(|_| RouteChannelError::ControlLost)?;
        let envelope = ControlEnvelope {
            request_id,
            generation: self.generation,
            priority: Priority::Control.into(),
            body: Some(Body::RouteRequest(RouteRequest {
                connection: Some(self.identity.clone()),
                handshake: Some(self.metadata.clone()),
                namespace_hint: self.namespace.clone(),
                excluded_backend_ids,
            })),
            ..ControlEnvelope::default()
        };
        self.client
            .send(envelope)
            .await
            .map_err(|_| RouteChannelError::ControlLost)
    }

    async fn next_assignment(&mut self) -> Result<RouteAssignment, RouteChannelError> {
        loop {
            let Some(envelope) = self.responses.recv().await else {
                return Err(RouteChannelError::ControlLost);
            };
            if let Some(Body::RouteAssignment(assignment)) = envelope.body {
                return Ok(assignment);
            }
            // A correlated non-assignment here is a dispatcher routing
            // bug; skip defensively rather than act on it.
        }
    }

    async fn report_result(&mut self, result: RouteResult) -> Result<(), RouteChannelError> {
        self.send_durable(Body::RouteResult(result))
            .await
            .map(|_| ())
    }
}

/// The production [`BoundSessionHandler`]: composes the engine for each
/// registered connection.
pub struct EngineSessionOwner {
    client: Arc<ControlClient>,
    namespace: Arc<str>,
    shutdown: watch::Receiver<bool>,
    drain: watch::Receiver<bool>,
    loop_config: SessionLoopConfig,
    metrics: MetricsRecorder,
}

impl EngineSessionOwner {
    /// Builds the owner for the given control client and namespace.
    #[must_use]
    pub fn new(
        client: Arc<ControlClient>,
        namespace: impl Into<Arc<str>>,
        shutdown: watch::Receiver<bool>,
        drain: watch::Receiver<bool>,
        loop_config: SessionLoopConfig,
    ) -> Self {
        Self {
            client,
            namespace: namespace.into(),
            shutdown,
            drain,
            loop_config,
            metrics: MetricsRecorder::default(),
        }
    }

    /// Attaches the process-wide non-blocking metrics recorder.
    #[must_use]
    pub fn with_metrics(mut self, metrics: MetricsRecorder) -> Self {
        self.metrics = metrics;
        self
    }
}

impl BoundSessionHandler for EngineSessionOwner {
    fn handle(
        &self,
        connection: AcceptedConnection,
        binding: SessionControlBinding,
    ) -> ConnectionFuture {
        let client = Arc::clone(&self.client);
        let namespace = self.namespace.to_string();
        let shutdown = self.shutdown.clone();
        let drain = self.drain.clone();
        let config = self.loop_config;
        let metrics = self.metrics.clone();
        Box::pin(async move {
            run_bound_session_observed(
                connection, binding, client, namespace, shutdown, drain, config, metrics,
            )
            .await;
        })
    }
}

/// Runs one admitted, registered session to completion: FSM loop plus
/// wire engine plus terminal notices. Every task is joined before this
/// returns, and every gate-admitted command token resolves to exactly
/// one terminal under its exact id.
#[allow(clippy::too_many_lines)]
pub async fn run_bound_session(
    connection: AcceptedConnection,
    binding: SessionControlBinding,
    client: Arc<ControlClient>,
    namespace: String,
    shutdown: watch::Receiver<bool>,
    drain: watch::Receiver<bool>,
    loop_config: SessionLoopConfig,
) {
    run_bound_session_observed(
        connection,
        binding,
        client,
        namespace,
        shutdown,
        drain,
        loop_config,
        MetricsRecorder::default(),
    )
    .await;
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn run_bound_session_observed(
    connection: AcceptedConnection,
    binding: SessionControlBinding,
    client: Arc<ControlClient>,
    namespace: String,
    shutdown: watch::Receiver<bool>,
    mut drain: watch::Receiver<bool>,
    loop_config: SessionLoopConfig,
    metrics: MetricsRecorder,
) {
    let accepted_at = tokio::time::Instant::now();
    let (stream, seat) = connection.into_session_io();
    let metadata = seat.metadata();
    let identity = ConnectionIdentity {
        connection_id: metadata.connection_id.get(),
        listener_address: metadata.listener_address.to_string(),
        client_address: metadata.peer_address.to_string(),
        proxy_address: metadata.listener_address.to_string(),
        public_endpoint: false,
    };
    let endpoints = ConnectionEndpoints {
        listener_addr: metadata.listener_address,
        client_addr: metadata.peer_address,
    };
    let log_context = SessionLogContext {
        connection_id: identity.connection_id,
        listener: metadata.listener_address.to_string(),
        client_address: metadata.peer_address.to_string(),
        proxy_client_address: metadata.peer_address.to_string(),
        namespace: namespace.clone(),
        generation: seat.snapshot().generation(),
    };

    let (mut directives, responses, commander) = binding.split();

    let (event_tx, event_rx) = mpsc::channel(1);
    let (cmd_tx, cmd_rx) = mpsc::channel(ENGINE_CMD_CAPACITY);
    let (report_tx, mut report_rx) = mpsc::channel(ENGINE_REPORT_CAPACITY);
    let (control_tx, control_rx) = mpsc::channel::<SessionControl>(8);

    // Wrap the raw client socket in the innermost byte counter before any
    // framing/TLS/compression layer; the handle survives in-place upgrades.
    let client_socket = CountedIo::new(stream);
    let client_counters = client_socket.counters();
    let engine = Engine {
        connection_id: identity.connection_id,
        endpoints,
        inbound_proxy_client: None,
        client_io: PacketIo::new(ClientTransport::Plain(client_socket)),
        client_counters,
        backend: None,
        candidate: None,
        redirect_target: None,
        retired_backend_in: 0,
        retired_backend_out: 0,
        events: event_tx,
        cmds: cmd_rx,
        reports: report_tx,
        route: Some(RouteSeed {
            client: Arc::clone(&client),
            commander: commander.clone(),
            responses,
            identity: identity.clone(),
            namespace,
        }),
        salt: [0; 20],
        negotiated: CapabilityFlags::from_bits_retain(0),
        client_handshake_raw: Vec::new(),
        relay_hold: None,
        cmd_state: None,
        in_transaction: false,
        prepared: PreparedRegistry::new(),
        pending_command: None,
        wire_end: None,
        quit_source: QuitSource::None,
        closing: false,
        accepted_at,
        handshake_deadline: loop_config.handshake_deadline,
        frontend_tls_active: false,
        metrics: metrics.clone(),
        log_context: log_context.clone(),
        seat,
    };

    // The owner watches the same shutdown signal the loop consumes, so
    // it can arm the shared absolute force budget the moment the signal
    // fires — not only when the loop finishes its own cleanup.
    let mut owner_shutdown = shutdown.clone();
    let session_loop = SessionLoop::new(
        EventRx { events: event_rx },
        CmdTx {
            cmds: cmd_tx.clone(),
        },
        control_rx,
        shutdown,
        loop_config,
    );
    let mut loop_task = AbortOnDrop(tokio::spawn(session_loop.run()));
    let mut engine_task = AbortOnDrop(tokio::spawn(engine.run()));

    // The owner: forwards directives while holding the exact command
    // tokens, consumes engine reports, and waits for the loop.
    let mut redirect_token: Option<CommandToken> = None;
    let mut close_token: Option<CommandToken> = None;
    let mut directives_open = true;
    let mut forced_by_control = false;
    // One absolute force budget: armed when the force signal is first
    // observed, it bounds the loop's own cleanup AND the engine join
    // below — never two stacked deadlines.
    let mut force_deadline: Option<tokio::time::Instant> = None;
    if *owner_shutdown.borrow() {
        force_deadline = Some(tokio::time::Instant::now() + loop_config.cleanup_deadline);
    }
    let mut drain_signaled = *drain.borrow();
    if drain_signaled {
        // Admitted after stop-accept began: close at the first safe
        // boundary.
        let _ = control_tx.send(SessionControl::GracefulClose).await;
    }
    let summary: Option<SessionSummary> = loop {
        tokio::select! {
            joined = &mut loop_task.0 => {
                break joined.ok();
            }
            changed = owner_shutdown.changed(), if force_deadline.is_none() => {
                if changed.is_err() || *owner_shutdown.borrow() {
                    force_deadline =
                        Some(tokio::time::Instant::now() + loop_config.cleanup_deadline);
                }
            }
            changed = drain.changed(), if !drain_signaled => {
                if changed.is_ok() && *drain.borrow() {
                    drain_signaled = true;
                    // Local coordinated shutdown: graceful close at the
                    // next safe boundary; the loop's drain deadline is
                    // the per-session force. No command token — this is
                    // not a gate-admitted command.
                    let _ = control_tx.send(SessionControl::GracefulClose).await;
                } else if changed.is_err() {
                    drain_signaled = true;
                }
            }
            directive = directives.recv(), if directives_open => {
                let Some(directive) = directive else {
                    // Control detach: last-good — the session continues;
                    // stop polling this arm.
                    directives_open = false;
                    continue;
                };
                match &directive.command {
                    Some(token) if token.kind == CommandKind::Redirect => {
                        redirect_token = Some(token.clone());
                    }
                    Some(token) => {
                        close_token = Some(token.clone());
                    }
                    None => {}
                }
                if let Some(target) = directive.redirect_target {
                    let _ = cmd_tx.send(EngineCmd::PrepareRedirect(target)).await;
                }
                if directive.control == SessionControl::CloseImmediate {
                    forced_by_control = true;
                    force_deadline.get_or_insert_with(|| {
                        tokio::time::Instant::now() + loop_config.cleanup_deadline
                    });
                }
                let _ = control_tx.send(directive.control).await;
            }
            report = report_rx.recv() => {
                if let Some(report) = report {
                    consume_report(report, &commander, &mut redirect_token).await;
                }
            }
        }
    };

    // The loop returned: its handler (holding one cmd sender clone) is
    // gone; drop ours so the engine drains and exits, then join it.
    drop(cmd_tx);
    // The engine may be blocked in a socket forward (a stalled backend
    // mid-command). A forced end shares the ONE absolute budget armed at
    // the force signal — whatever the loop's own cleanup already spent
    // is not re-granted here — then hard-cancels: the sockets drop with
    // the task, which IS the force close. A non-forced end (the client
    // quit) budgets its ordinary cleanup from now.
    let join_deadline = force_deadline
        .unwrap_or_else(|| tokio::time::Instant::now() + loop_config.cleanup_deadline);
    let engine_exit =
        if let Ok(joined) = tokio::time::timeout_at(join_deadline, &mut engine_task.0).await {
            joined.ok()
        } else {
            engine_task.0.abort();
            let _ = (&mut engine_task.0).await;
            None
        };
    while let Ok(report) = report_rx.try_recv() {
        consume_report(report, &commander, &mut redirect_token).await;
    }

    let totals = engine_exit
        .as_ref()
        .map(|exit| exit.totals)
        .unwrap_or_default();
    let shutdown_end = summary
        .as_ref()
        .is_some_and(|summary| summary.end == SessionEnd::ServerShutdown);
    let forced = shutdown_end || forced_by_control;
    // Go parity: a timeout/immediate force-close reports the proxy
    // shutdown source; everything else keeps the wire classification.
    let source = if forced {
        WireErrorSource::Shutdown
    } else {
        engine_exit
            .as_ref()
            .map_or(WireErrorSource::Proxy, |exit| exit.source)
    };
    let quit_source = if forced {
        QuitSource::ProxyQuit
    } else {
        engine_exit
            .as_ref()
            .map_or(QuitSource::ProxyError, |exit| exit.quit_source)
    };
    // Exactness: an unresolved redirect terminal fails closed so the
    // gate id never dangles; an accepted close that ran the session to
    // its end reports under its exact admitted id.
    if let Some(token) = redirect_token.take() {
        let _ = commander
            .redirect_finished(
                token.id.to_string(),
                false,
                engine_exit
                    .as_ref()
                    .map(|exit| exit.backend_id.clone())
                    .unwrap_or_default(),
                ErrorCode::RedirectFailed,
            )
            .await;
    }
    if let Some(token) = close_token.take() {
        let _ = commander.close_finished(token.id.to_string()).await;
    }
    metrics.try_record(Observation::SessionClosed {
        source: quit_source,
        lifetime: accepted_at.elapsed(),
        traffic: totals,
    });
    let (backend_id, backend_address, cluster, capabilities) =
        engine_exit.as_ref().map_or(("", "", "", 0), |exit| {
            (
                exit.backend_id.as_str(),
                exit.backend_address.as_str(),
                exit.cluster.as_str(),
                exit.capabilities,
            )
        });
    // Attribute the close to the namespace the decision resolved, not
    // the pre-decision process seed.
    let mut log_context = log_context;
    if let Some(exit) = engine_exit.as_ref()
        && !exit.namespace.is_empty()
    {
        log_context.namespace.clone_from(&exit.namespace);
    }
    log_session(
        "connection_closed",
        &log_context,
        backend_id,
        backend_address,
        cluster,
        capabilities,
        quit_source,
    );
    let _ = commander.session_closed(forced, source, totals).await;
}

/// Aborts the owned task when dropped: an externally cancelled session
/// owner never detaches its loop or engine task — abort cancels them at
/// their next await point and their sockets drop with them.
struct AbortOnDrop<T>(tokio::task::JoinHandle<T>);

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn consume_report(
    report: EngineReport,
    commander: &SessionCommander,
    redirect_token: &mut Option<CommandToken>,
) {
    match report {
        EngineReport::RedirectFinished {
            succeeded,
            backend_id,
            code,
        } => {
            if let Some(token) = redirect_token.take() {
                let _ = commander
                    .redirect_finished(token.id.to_string(), succeeded, backend_id, code)
                    .await;
            }
        }
    }
}

/// Route dependencies consumed at dial time.
struct RouteSeed {
    client: Arc<ControlClient>,
    commander: SessionCommander,
    responses: ResponseStream,
    identity: ConnectionIdentity,
    namespace: String,
}

/// The dialed backend's I/O and identity.
struct BackendIo {
    #[allow(clippy::struct_field_names)]
    backend_io: PacketIo<BackendTransport>,
    /// Raw-socket byte counters for THIS backend socket. A redirected backend
    /// gets a fresh `BackendIo` with its own counters, so a swap snapshots and
    /// closes out the old leg's totals rather than smearing them across sockets.
    counters: Arc<ByteCounters>,
    id: String,
    address: String,
    cluster: String,
    local: bool,
}

/// One client command held between its event and the FSM's forward
/// authorization.
struct PendingCommand {
    payload: Vec<u8>,
    command: Command,
    expected: ExpectedResponse,
    started: tokio::time::Instant,
    since_connection: Duration,
    traffic_before: BackendTraffic,
}

/// The single owner of all session wire I/O.
struct Engine {
    connection_id: u64,
    endpoints: ConnectionEndpoints,
    /// The real client address from an inbound PROXY v2 header, when the
    /// listener consumed one — used ONLY as the source of the outbound backend
    /// PROXY header, never for routing/admission/identity.
    inbound_proxy_client: Option<std::net::SocketAddr>,
    client_io: PacketIo<ClientTransport>,
    /// Raw-socket byte counters for the client socket. Created once at accept
    /// and kept for the session: TLS/compression upgrades wrap the same
    /// `CountedIo` in place, so this handle keeps counting the same socket.
    client_counters: Arc<ByteCounters>,
    backend: Option<BackendIo>,
    /// Fully authenticated/restored redirect target, invisible to command I/O
    /// until the FSM authorizes the atomic swap.
    candidate: Option<BackendIo>,
    /// Exact target carried by the one admitted redirect command.
    redirect_target: Option<RedirectTarget>,
    /// Traffic from successfully retired backend owners, retained for the
    /// connection-lifetime CLOSED event after an atomic swap.
    retired_backend_in: u64,
    retired_backend_out: u64,
    events: mpsc::Sender<SessionEvent>,
    cmds: mpsc::Receiver<EngineCmd>,
    reports: mpsc::Sender<EngineReport>,
    route: Option<RouteSeed>,
    salt: [u8; 20],
    negotiated: CapabilityFlags,
    /// The client's raw handshake-response payload, re-sent verbatim to
    /// the backend (the backend re-challenges through the auth-switch
    /// relay, so the proxy-salt-scaled reply is acceptable there).
    client_handshake_raw: Vec<u8>,
    /// A backend auth payload held between relay classification and its
    /// forward effect.
    relay_hold: Option<Vec<u8>>,
    cmd_state: Option<CommandSessionState>,
    in_transaction: bool,
    /// SES-00 prepared-statement registry: long-data/cursor guards
    /// synchronize into the FSM before command-completion boundaries.
    prepared: PreparedRegistry,
    pending_command: Option<PendingCommand>,
    wire_end: Option<WireErrorSource>,
    quit_source: QuitSource,
    closing: bool,
    accepted_at: tokio::time::Instant,
    /// Absolute handshake budget (Go parity, `handshake_deadline`), measured
    /// from `accepted_at`. TLS accept/connect consume the *remaining* budget
    /// rather than a fresh timer, so the whole handshake — plaintext greeting,
    /// `SSLRequest`, TLS, auth — shares one deadline.
    handshake_deadline: Duration,
    /// Whether the client upgraded this connection to TLS via `SSLRequest`.
    /// Drives the greeting-response `tls` metadata and capability trust.
    frontend_tls_active: bool,
    metrics: MetricsRecorder,
    log_context: SessionLogContext,
    seat: SessionSeat,
}

/// Outcome of waiting for one specific FSM effect.
enum Awaited {
    /// The expected effect arrived (any others were handled inline).
    Got,
    /// Teardown began (or the loop is gone); abandon the wire phase.
    Closing,
}

/// Whether a failed migration-snapshot attempt can safely return to the old
/// backend. Payload-bearing parser errors are deliberately collapsed here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SnapshotFailure {
    /// A complete response (including backend ERR) was consumed, so the old
    /// command stream remains aligned and reusable.
    OldBackendUsable,
    /// The backend disconnected while the internal exchange was in flight.
    BackendNetwork,
    /// The response ended before the parser could consume a complete result;
    /// keeping the connection would risk treating unread internal bytes as a
    /// user-command response.
    Desynchronized,
    /// Fixed allowlist construction failed, which is a proxy invariant.
    ProxyInvariant,
}

/// Secret-free failure class for candidate construction. No variant carries
/// token, session-state, SQL, or backend payload bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CandidateFailure {
    InvalidTarget,
    Dial,
    Handshake,
    Authentication,
    Restore,
}

/// Short-lived wire payload containing token or session-state bytes. Its
/// backing allocation is overwritten on every return path before release;
/// `Debug` is intentionally unavailable so diagnostics cannot print it.
struct SensitiveBytes(Vec<u8>);

impl SensitiveBytes {
    const fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl Drop for SensitiveBytes {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

/// Applies Go's second-handshake capability rules after the normal negotiated
/// intersection. The session token's encoding is payload-length driven:
/// `MakeHandshakeResponse` forces LENENC above 250 bytes even though real `TiDB`
/// greetings omit that bit.
fn migration_auth_capabilities(
    planned: CapabilityFlags,
    backend: CapabilityFlags,
    has_database: bool,
    token_length: usize,
) -> Result<CapabilityFlags, CandidateFailure> {
    let mut capabilities = planned.union(CapabilityFlags::PLUGIN_AUTH);
    capabilities = if has_database {
        if !backend.contains(CapabilityFlags::CONNECT_WITH_DB) {
            return Err(CandidateFailure::Handshake);
        }
        capabilities.union(CapabilityFlags::CONNECT_WITH_DB)
    } else {
        capabilities.without(CapabilityFlags::CONNECT_WITH_DB)
    };
    capabilities = if token_length > 250 {
        // Go's `MakeHandshakeResponse` forces the length-encoded auth form
        // for long payloads independently of the backend's advertised mask.
        capabilities.union(CapabilityFlags::PLUGIN_AUTH_LENENC_CLIENT_DATA)
    } else {
        capabilities.without(CapabilityFlags::PLUGIN_AUTH_LENENC_CLIENT_DATA)
    };
    Ok(capabilities)
}

impl Engine {
    async fn run(mut self) -> EngineExit {
        let end = self.lifecycle().await;
        if let Some(source) = end {
            self.wire_end.get_or_insert(source);
            if self.quit_source == QuitSource::None {
                self.quit_source = coarse_quit_source(source);
            }
        }
        // Drain remaining effects so teardown commands (close/classify)
        // execute even after a wire failure ended the lifecycle early.
        while let Some(cmd) = self.cmds.recv().await {
            if matches!(self.handle_cmd(cmd).await, Awaited::Closing) && self.closing {
                // Keep draining: ClassifySessionEnd may still follow.
            }
        }
        self.shutdown_io().await;
        let (backend_id, backend_address, cluster) = self.backend.as_ref().map_or_else(
            || (String::new(), String::new(), String::new()),
            |backend| {
                (
                    backend.id.clone(),
                    backend.address.clone(),
                    backend.cluster.clone(),
                )
            },
        );
        EngineExit {
            totals: self.totals(),
            source: self.wire_end.unwrap_or(WireErrorSource::ClientNetwork),
            quit_source: self.quit_source,
            backend_id,
            backend_address,
            cluster,
            capabilities: u64::from(self.negotiated.bits()),
            namespace: self.log_context.namespace.clone(),
        }
    }

    /// The main wire lifecycle; returns the classified end source when
    /// the wire (not the FSM) ended the session.
    #[allow(clippy::too_many_lines)]
    async fn lifecycle(&mut self) -> Option<WireErrorSource> {
        // Accept is complete by construction (the server admitted us).
        if self
            .events
            .send(SessionEvent::ConnectionAccepted)
            .await
            .is_err()
        {
            return Some(WireErrorSource::Proxy);
        }
        if !matches!(
            self.await_effect(SessionEffect::SendProxyGreeting).await,
            Awaited::Got
        ) {
            return None;
        }
        if let Err(source) = self.send_greeting().await {
            return Some(source);
        }

        // PROXY protocol v2 inbound (WIRE-activation B): once the greeting is
        // flushed, run a one-shot probe before the first client packet. A LB's
        // header is already buffered (sent before the greeting) and is consumed
        // here — its source becomes the outbound header's source; a direct
        // client, woken by the greeting, sends its handshake response, whose
        // leading bytes are peeked as non-magic and left intact (so it is never
        // blocked). The header wire bytes are not a MySQL packet and never
        // advance the sequence; a malformed header fails closed.
        if self.proxy_protocol_v2_enabled() {
            // The probe consumes the remaining absolute handshake budget (not a
            // fresh timer): a truncated header, or a client that opens the
            // connection but sends nothing, fails closed at the deadline with no
            // fallback, matching the frozen partial-header contract.
            let budget = self.handshake_budget_remaining();
            let probe = tokio::time::timeout(budget, self.client_io.probe_inbound_proxy_v2());
            let Ok(Ok(source)) = probe.await else {
                self.quit_source = QuitSource::ProxyMalformed;
                let _ = self.events.send(SessionEvent::ClientIoError).await;
                return Some(WireErrorSource::ClientNetwork);
            };
            self.inbound_proxy_client = source;
        }

        // First client packet after the greeting. A client that sets `SSL`
        // must send a strict 32-byte `SSLRequest` (Go: the pre-TLS capability
        // mask is authoritative); we then upgrade to TLS and read the real
        // handshake response inside the encrypted session. Otherwise the first
        // packet already is the plaintext handshake response.
        let frontend_tls_available = self.frontend_tls_available();
        let payload = match self.client_io.read_logical(HANDSHAKE_PAYLOAD_LIMIT).await {
            Ok(packet) => packet.payload,
            Err(error) => return Some(self.client_read_end(&error).await),
        };
        let ssl_request_capabilities =
            if leading_capabilities(&payload).contains(CapabilityFlags::SSL) {
                let Ok(ssl_request) = parse_ssl_request(&payload) else {
                    // SSL bit set but not a strict 32-byte SSLRequest: fail closed
                    // rather than falling back to a plaintext handshake response.
                    self.quit_source = QuitSource::ProxyMalformed;
                    let _ = self.events.send(SessionEvent::ClientIoError).await;
                    return Some(WireErrorSource::ClientNetwork);
                };
                if !frontend_tls_available {
                    // We only advertise SSL when a frontend config exists; a client
                    // asking to upgrade against a greeting that withheld SSL is a
                    // protocol violation.
                    self.quit_source = QuitSource::ProxyMalformed;
                    let _ = self.events.send(SessionEvent::ClientIoError).await;
                    return Some(WireErrorSource::ClientNetwork);
                }
                Some(ssl_request.capabilities)
            } else {
                None
            };

        let mut payload = if ssl_request_capabilities.is_some() {
            // FSM: Greeting --ClientSslRequest--> SslRequest (ActivateFrontendTls).
            if self
                .events
                .send(SessionEvent::ClientSslRequest)
                .await
                .is_err()
            {
                return Some(WireErrorSource::Proxy);
            }
            if !matches!(
                self.await_effect(SessionEffect::ActivateFrontendTls).await,
                Awaited::Got
            ) {
                return None;
            }
            if let Err(source) = self.activate_frontend_tls().await {
                return Some(source);
            }
            // FSM: SslRequest --TlsActivated--> Greeting (no effect). The real
            // handshake response arrives inside TLS; its MySQL sequence
            // continues (SSLRequest was seq 1, this is seq 2).
            if self.events.send(SessionEvent::TlsActivated).await.is_err() {
                return Some(WireErrorSource::Proxy);
            }
            match self.client_io.read_logical(HANDSHAKE_PAYLOAD_LIMIT).await {
                Ok(packet) => packet.payload,
                Err(error) => return Some(self.client_read_end(&error).await),
            }
        } else {
            payload
        };

        // Go parity: when TLS was negotiated, the pre-TLS `SSLRequest` mask is
        // authoritative, so overwrite the in-TLS response's leading capability
        // bytes with it BEFORE parsing. This makes layout-affecting bits
        // (CONNECT_WITH_DB / CONNECT_ATTRS / PLUGIN_AUTH_LENENC / ZSTD) — which
        // decide the response's field layout — come from the trusted mask, not
        // the untrusted second packet, and keeps the stored raw (re-parsed for
        // backend forwarding) consistent with what we negotiated.
        if let Some(ssl_capabilities) = ssl_request_capabilities {
            normalize_leading_capabilities(&mut payload, ssl_capabilities);
        }

        let Ok(parsed) = parse_handshake_response(&payload) else {
            self.quit_source = QuitSource::ProxyMalformed;
            let _ = self.events.send(SessionEvent::ClientIoError).await;
            return Some(WireErrorSource::ClientNetwork);
        };
        // After normalization `parsed.capabilities` is the trusted mask under
        // TLS (and the plaintext client mask otherwise), so it governs both the
        // parsed field layout and the negotiation.
        let negotiation = match negotiate_frontend(
            parsed.capabilities,
            proxy_capabilities(frontend_tls_available),
        ) {
            Ok(negotiation) => negotiation,
            Err(missing) => {
                self.quit_source = QuitSource::ClientHandshake;
                let (code, state, message) = missing.client_response();
                let seq = self.client_io.expected_read_sequence();
                self.client_io.reset_write_sequence(seq);
                let _ = self.write_client_error(code, state, message).await;
                let _ = self.events.send(SessionEvent::ClientIoError).await;
                return Some(WireErrorSource::ClientNetwork);
            }
        };
        self.negotiated = negotiation.negotiated();
        self.client_handshake_raw.clone_from(&payload);
        let metadata = HandshakeMetadata {
            user: String::from_utf8_lossy(parsed.username).into_owned(),
            database: parsed
                .database
                .map(|database| String::from_utf8_lossy(database).into_owned())
                .unwrap_or_default(),
            auth_plugin: parsed
                .auth_plugin_name
                .map(|plugin| String::from_utf8_lossy(plugin).into_owned())
                .unwrap_or_default(),
            capability: self.negotiated.bits(),
            collation: u32::from(parsed.collation),
            zstd_level: u32::from(parsed.zstd_level.unwrap_or(0)),
            connection_attributes: std::collections::BTreeMap::default(),
            tls: self.frontend_tls_active,
        };
        self.cmd_state = Some(CommandSessionState::new(self.negotiated, parsed.database));
        let routing = negotiation.routing_handshake(&parsed, self.endpoints);
        if self
            .events
            .send(SessionEvent::ClientHandshakeResponse)
            .await
            .is_err()
        {
            return Some(WireErrorSource::Proxy);
        }
        if !matches!(
            self.await_effect(SessionEffect::DialBackend).await,
            Awaited::Got
        ) {
            return None;
        }

        // Route + dial + backend greeting + verification + plan.
        let Some(mut seed) = self.route.take() else {
            return Some(WireErrorSource::Proxy);
        };
        let commander = seed.commander.clone();
        // The handshake event is a correlated exchange, not
        // fire-and-forget: the Go adapter ALWAYS answers it with a
        // HandshakeDecision, which must be consumed under its own armed
        // expectation — and a rejected handshake refuses the client
        // with the decision's approved message instead of routing.
        let Some(decision_id) = seed.client.allocate_request_id() else {
            return Some(WireErrorSource::Proxy);
        };
        if seed
            .commander
            .expect_response(decision_id, ResponseKind::HandshakeDecision)
            .await
            .is_err()
        {
            return Some(WireErrorSource::Proxy);
        }
        // Provenance: the adapter validates that handshake/route
        // envelopes carry the nonzero generation this connection was
        // admitted under.
        let admission_generation = self.seat.snapshot().generation();
        let event_envelope = ControlEnvelope {
            request_id: decision_id,
            generation: admission_generation,
            priority: Priority::Control.into(),
            body: Some(Body::HandshakeResponse(HandshakeResponseEvent {
                connection: Some(seed.identity.clone()),
                handshake: Some(metadata.clone()),
            })),
            ..ControlEnvelope::default()
        };
        if seed.client.send(event_envelope).await.is_err() {
            return Some(WireErrorSource::Proxy);
        }
        let decision = loop {
            let Some(answer) = seed.responses.recv().await else {
                return Some(WireErrorSource::Proxy);
            };
            if let Some(Body::HandshakeDecision(decision)) = answer.body {
                break decision;
            }
        };
        if !decision.accept {
            let message = if decision.client_message.is_empty() {
                "handshake rejected"
            } else {
                decision.client_message.as_str()
            };
            let seq = self.client_io.expected_read_sequence();
            self.client_io.reset_write_sequence(seq);
            let _ = self.write_client_error(1105, *b"HY000", message).await;
            let _ = self.events.send(SessionEvent::ClientIoError).await;
            return Some(WireErrorSource::Proxy);
        }
        // The accepted decision names the namespace the Go handshake
        // handler RESOLVED for this connection — the routing truth.
        // Adopt it VERBATIM for the route conversation and every wire
        // surface: Go imposes no 255-byte namespace bound, so any local
        // truncation would silently rename an identity (and a byte
        // bound could split a multibyte character). Only the log layer
        // bounds it, via its char-boundary-safe field escaping.
        let mut resolved_namespace = decision.namespace;
        if resolved_namespace.is_empty() {
            resolved_namespace = seed.namespace;
        }
        self.log_context.namespace.clone_from(&resolved_namespace);
        // The dispatcher's per-session record adopts it too, so CLOSED
        // events and reconciliation carry the routing truth on the
        // wire. The commander waits for the applied acknowledgement; a
        // lost acknowledgement means later observers could still see
        // the pre-decision seed, so the session fails closed instead
        // of routing with ambiguous attribution.
        if !commander.set_namespace(resolved_namespace.clone()).await {
            return Some(WireErrorSource::Proxy);
        }
        let channel = BindingRouteChannel {
            client: seed.client,
            commander: seed.commander,
            responses: seed.responses,
            identity: seed.identity,
            metadata,
            namespace: resolved_namespace,
            generation: admission_generation,
        };
        let mut route_engine = RouteEngine::new(
            channel,
            ClusterTcpDialer::new(self.metrics.clone()),
            DialSchedule::default(),
            CenteredJitter,
            self.connection_id,
        );
        let acquisition_started = tokio::time::Instant::now();
        let acquired = match route_engine.acquire(Vec::new()).await {
            Ok(acquired) => {
                self.metrics.try_record(Observation::GetBackend {
                    duration: acquisition_started.elapsed(),
                    succeeded: true,
                });
                acquired
            }
            Err(error) => {
                self.metrics.try_record(Observation::GetBackend {
                    duration: acquisition_started.elapsed(),
                    succeeded: false,
                });
                self.quit_source = acquire_quit_source(&error);
                // Go parity: a NO_BACKEND refusal reaches the client
                // as the approved vocabulary before the session closes
                // (Go maps router.ErrNoBackend to ErrProxyNoBackend in
                // ErrToClient); other acquire failures keep Go's
                // behavior of closing without a client error packet.
                if matches!(error, AcquireError::NoBackend { .. }) {
                    let seq = self.client_io.expected_read_sequence();
                    self.client_io.reset_write_sequence(seq);
                    let _ = self
                        .write_client_error(
                            1105,
                            *b"HY000",
                            "No available TiDB instances, please make sure TiDB is available",
                        )
                        .await;
                }
                let _ = self.events.send(SessionEvent::BackendIoError).await;
                return Some(WireErrorSource::Proxy);
            }
        };
        let backend_id = acquired.backend.backend_id.clone();
        let backend_address = acquired.backend.address.clone();
        let backend_cluster = acquired.backend.cluster_name.clone();
        let backend_local = acquired.backend.local;
        // Health-appropriate keepalive at dial time (KA-003 family):
        // the snapshot's healthy/unhealthy backend policy follows the
        // router-reported health of this assignment. Mid-session
        // health transitions re-apply with DPL-07's topology feed.
        {
            let config = self.seat.snapshot().raw().config.as_ref();
            let policy = if acquired.backend.healthy {
                config.and_then(|config| config.healthy_backend_keepalive)
            } else {
                config.and_then(|config| config.unhealthy_backend_keepalive)
            };
            if let Some(policy) = policy {
                let _ = proxy_io::socket::apply_keepalive(
                    &acquired.conn,
                    crate::server::snapshot_keepalive(&policy),
                );
            }
        }
        // Wrap the raw backend socket in the innermost byte counter now — before
        // the PROXY header, any backend TLS upgrade, and MySQL framing — so the
        // PROXY preamble, TLS records, compressed frames, and plain packets all
        // count once at the bottom of the stack. Keepalive above still ran on
        // the bare `TcpStream`.
        let mut backend_socket = CountedIo::new(acquired.conn);
        let backend_counters = backend_socket.counters();
        // PROXY protocol v2 (WIRE-activation B): when the snapshot enables it,
        // announce the ORIGINAL client address to the backend as a raw preamble
        // that precedes every MySQL byte. Written straight to the socket before
        // it is wrapped in MySQL framing (and before any backend TLS upgrade),
        // matching Go's dial path — the header is a transport preamble, not a
        // MySQL packet, so it must bypass the PacketIo sequence framing.
        let proxy_v2_result = if self.proxy_protocol_v2_enabled() {
            // Source is the original client: the inbound PROXY header's address
            // when the listener consumed one, else this connection's own peer.
            let client_src = self
                .inbound_proxy_client
                .unwrap_or(self.endpoints.client_addr);
            write_backend_proxy_v2_header(&mut backend_socket, client_src).await
        } else {
            Ok(())
        };
        if let Err(source) = proxy_v2_result {
            self.quit_source = QuitSource::BackendHandshake;
            let _ = self.events.send(SessionEvent::BackendIoError).await;
            return Some(source);
        }
        let mut backend = BackendIo {
            backend_io: PacketIo::new(BackendTransport::Plain(backend_socket)),
            counters: backend_counters,
            id: backend_id.clone(),
            address: backend_address,
            cluster: backend_cluster,
            local: backend_local,
        };
        let Ok(greeting_packet) = backend
            .backend_io
            .read_logical(HANDSHAKE_PAYLOAD_LIMIT)
            .await
        else {
            self.quit_source = QuitSource::BackendHandshake;
            let _ = self.events.send(SessionEvent::BackendIoError).await;
            return Some(WireErrorSource::BackendNetwork);
        };
        let greeting_payload = greeting_packet.payload;
        let Ok(backend_greeting) = mysql_wire::parse_initial_handshake(&greeting_payload) else {
            self.quit_source = QuitSource::BackendHandshake;
            let _ = self.events.send(SessionEvent::BackendIoError).await;
            return Some(WireErrorSource::BackendNetwork);
        };
        let backend_caps = backend_greeting.capabilities;
        let (require_backend_tls, backend_tls_available) = self.backend_tls_policy();
        if verify_backend(
            backend_caps,
            self.negotiated,
            proxy_capabilities(self.frontend_tls_available()),
            require_backend_tls,
        )
        .is_err()
        {
            self.quit_source = QuitSource::BackendHandshake;
            let _ = self.events.send(SessionEvent::BackendIoError).await;
            return Some(WireErrorSource::BackendNetwork);
        }
        let Ok(plan) = plan_backend_handshake(
            &routing,
            backend_caps,
            require_backend_tls,
            backend_tls_available,
        ) else {
            self.quit_source = QuitSource::BackendHandshake;
            let _ = self.events.send(SessionEvent::BackendIoError).await;
            return Some(WireErrorSource::Proxy);
        };
        // Backend TLS activates before any credential leaves the proxy: send a
        // plaintext SSLRequest, upgrade the backend transport, then the full
        // handshake response travels inside TLS.
        let backend_tls_result = if matches!(plan.tls, BackendTlsMode::Enabled) {
            self.upgrade_backend_tls(
                &mut backend,
                plan.capabilities,
                self.handshake_budget_remaining(),
            )
            .await
        } else {
            Ok(())
        };
        if let Err(source) = backend_tls_result {
            self.quit_source = QuitSource::BackendHandshake;
            let _ = self.events.send(SessionEvent::BackendIoError).await;
            return Some(source);
        }
        self.backend = Some(backend);
        if self
            .events
            .send(SessionEvent::BackendGreetingReceived)
            .await
            .is_err()
        {
            return Some(WireErrorSource::Proxy);
        }
        if !matches!(
            self.await_effect(SessionEffect::ForwardHandshakeToBackend)
                .await,
            Awaited::Got
        ) {
            return None;
        }
        // Go's `handshakeFirstTime` rewrite: forward the client's
        // response under the planned capability mask with the plugin
        // replaced by `auth_unknown_plugin` and the original auth data
        // preserved, so the backend re-requests authentication against
        // its own salt (the client's scramble answered the proxy's) and
        // keeps the `using password` semantics on failure.
        let forwarded = {
            let Ok(parsed) = parse_handshake_response(&self.client_handshake_raw) else {
                self.quit_source = QuitSource::ProxyMalformed;
                let _ = self.events.send(SessionEvent::ClientIoError).await;
                return Some(WireErrorSource::Proxy);
            };
            let attributes = parsed.attributes.map(|attributes| {
                attributes
                    .into_iter()
                    .filter_map(Result::ok)
                    .collect::<Vec<_>>()
            });
            let Ok(forwarded) = encode_handshake_response(HandshakeResponseParams {
                capabilities: plan.capabilities,
                max_packet_size: parsed.max_packet_size,
                collation: parsed.collation,
                username: parsed.username,
                auth_response: parsed.auth_response,
                database: parsed.database,
                auth_plugin_name: Some(UNKNOWN_AUTH_PLUGIN),
                attributes: attributes.as_deref(),
                // The zstd level is meaningful only when the BACKEND leg
                // negotiated zstd (its caps may differ from the client's). If
                // the backend did not advertise ZSTD, sending a level would
                // make `encode_handshake_response` reject the packet, so drop
                // it — matching Go, which carries the level per negotiated leg.
                zstd_level: if plan
                    .capabilities
                    .contains(CapabilityFlags::ZSTD_COMPRESSION_ALGORITHM)
                {
                    parsed.zstd_level
                } else {
                    None
                },
            }) else {
                self.quit_source = QuitSource::ProxyMalformed;
                let _ = self.events.send(SessionEvent::ClientIoError).await;
                return Some(WireErrorSource::Proxy);
            };
            forwarded
        };
        if let Some(backend) = self.backend.as_mut() {
            // Continue the backend channel's connection-phase counter after its
            // greeting. Under backend TLS the writer already advanced past the
            // plaintext SSLRequest (seq 1) to seq 2, so it continues as-is;
            // otherwise the plaintext response is the first write and aligns to
            // the greeting (reader observed seq 0 -> expects 1).
            if !matches!(backend.backend_io.get_ref(), BackendTransport::Tls(_)) {
                let next = backend.backend_io.expected_read_sequence();
                backend.backend_io.reset_write_sequence(next);
            }
            if backend
                .backend_io
                .write_logical(&forwarded, true)
                .await
                .is_err()
            {
                self.quit_source = QuitSource::BackendHandshake;
                let _ = self.events.send(SessionEvent::BackendIoError).await;
                return Some(WireErrorSource::BackendNetwork);
            }
        }

        // Engine-internal authentication relay; the FSM sees only the
        // terminal outcome.
        // Carry the client's negotiated zstd level into the relay so the
        // auth-OK compression effects select the right codec level (0 = absent).
        let mut relay = AuthRelay::new(
            self.negotiated,
            backend_caps,
            parsed.zstd_level.unwrap_or(0),
        );
        let auth_outcome = loop {
            match relay.turn() {
                AuthTurn::AwaitingBackend => {
                    let payload = match self.backend_read(HANDSHAKE_PAYLOAD_LIMIT).await {
                        Ok(payload) => payload,
                        Err(source) => {
                            self.quit_source = QuitSource::BackendHandshake;
                            let _ = self.events.send(SessionEvent::BackendIoError).await;
                            return Some(source);
                        }
                    };
                    let event = match classify_backend_auth_packet(&payload, self.negotiated) {
                        Ok(AuthEvent::BackendError { class, .. }) => AuthEvent::BackendError {
                            class,
                            handler_reconnect: false,
                        },
                        Ok(event) => event,
                        Err(_) => {
                            self.quit_source = QuitSource::BackendHandshake;
                            let _ = self.events.send(SessionEvent::BackendIoError).await;
                            return Some(WireErrorSource::BackendNetwork);
                        }
                    };
                    self.relay_hold = Some(payload);
                    let Ok(step) = relay.on_event(event) else {
                        self.quit_source = QuitSource::BackendHandshake;
                        let _ = self.events.send(SessionEvent::BackendIoError).await;
                        return Some(WireErrorSource::Proxy);
                    };
                    if let Err(source) = self.run_auth_effects(&step.effects).await {
                        return Some(source);
                    }
                    if let Some(outcome) = step.outcome {
                        break outcome;
                    }
                }
                AuthTurn::AwaitingClient => {
                    let payload = match self.client_io.read_logical(HANDSHAKE_PAYLOAD_LIMIT).await {
                        Ok(packet) => packet.payload,
                        Err(error) => return Some(self.client_read_end(&error).await),
                    };
                    self.relay_hold = Some(payload);
                    let Ok(step) = relay.on_event(AuthEvent::ClientAuthResponse) else {
                        self.quit_source = QuitSource::ClientHandshake;
                        let _ = self.events.send(SessionEvent::ClientIoError).await;
                        return Some(WireErrorSource::Proxy);
                    };
                    if let Err(source) = self.run_auth_effects(&step.effects).await {
                        return Some(source);
                    }
                    if let Some(outcome) = step.outcome {
                        break outcome;
                    }
                }
                AuthTurn::AwaitingReconnect | AuthTurn::Finished => {
                    // Reconnect is never approved in this slice, and a
                    // finished relay exits through the outcome above.
                    self.quit_source = QuitSource::BackendHandshake;
                    let _ = self.events.send(SessionEvent::BackendIoError).await;
                    return Some(WireErrorSource::Proxy);
                }
            }
        };
        match auth_outcome {
            AuthOutcome::Success => {
                if self.events.send(SessionEvent::BackendAuthOk).await.is_err() {
                    return Some(WireErrorSource::Proxy);
                }
                if !matches!(
                    self.await_effect(SessionEffect::AttachBackend).await,
                    Awaited::Got
                ) {
                    return None;
                }
                let _ = commander.set_backend(backend_id.clone()).await;
                if !matches!(
                    self.await_effect(SessionEffect::ForwardAuthResultToClient)
                        .await,
                    Awaited::Got
                ) {
                    return None;
                }
                let current = self.backend_traffic();
                self.metrics.try_record(Observation::HandshakeCompleted {
                    backend: self
                        .backend
                        .as_ref()
                        .map_or_else(String::new, |backend| backend.address.clone()),
                    duration: self.accepted_at.elapsed(),
                    traffic: current,
                    local: self.backend.as_ref().is_some_and(|backend| backend.local),
                });
                if let Some(backend) = &self.backend {
                    log_session(
                        "connection_ready",
                        &self.log_context,
                        &backend.id,
                        &backend.address,
                        &backend.cluster,
                        u64::from(self.negotiated.bits()),
                        QuitSource::None,
                    );
                }
            }
            AuthOutcome::Failed(kind) => {
                self.quit_source = failure_quit_source(kind);
                let _ = self.events.send(SessionEvent::BackendAuthFailed).await;
                return Some(failure_source(kind));
            }
        }

        // Ready: the command/response phases until the wire or the FSM
        // ends the session.
        self.command_phase().await
    }

    /// Ready/command/response/infile phases.
    #[allow(clippy::too_many_lines)]
    async fn command_phase(&mut self) -> Option<WireErrorSource> {
        // The compressed command-boundary reset must fire exactly once per
        // command. Control/probe activity loops via `continue` without a new
        // command boundary, so it must NOT re-reset the next command — whose
        // compressed frame `peek_packet` may already have decoded and staged
        // (advancing the shared sequence) when the control arm won the select.
        let mut just_served_control = false;
        loop {
            if self.closing {
                return None;
            }
            // Every client command starts a fresh wire exchange at sequence
            // zero, and its response answers at one. On a compressed leg the
            // compressed sequence also resets once per command (Go's
            // `ResetSequence`); the first read/write then slaves the uncompressed
            // sequence to it via the direction hooks. Skip the compressed reset
            // when merely re-entering after control activity, so a staged next
            // command is not rewound; the reset fails closed on in-flight data.
            if !just_served_control && self.client_io.reset_layer_sequence().is_err() {
                self.quit_source = QuitSource::ProxyError;
                let _ = self.events.send(SessionEvent::ClientIoError).await;
                return Some(WireErrorSource::Proxy);
            }
            just_served_control = false;
            self.client_io.reset_read_sequence(0);
            // Between commands: serve control effects and probes while
            // waiting for the next client command. Only the peek is
            // raced — it retains consumed bytes inside the reader, so a
            // losing arm never drops partial-frame progress. Once a
            // header is visible the logical read runs uncontended; a
            // client stalling mid-frame is bounded by the owner's force
            // deadline, like any other mid-command stall.
            let (payload, command_started) = tokio::select! {
                cmd = self.cmds.recv() => {
                    let cmd = cmd?;
                    match self.handle_cmd(cmd).await {
                        Awaited::Closing => return None,
                        // Control/probe served — not a new command boundary, so
                        // the next iteration must not reset the compressed layer.
                        Awaited::Got => {
                            just_served_control = true;
                            continue;
                        }
                    }
                }
                peeked = self.client_io.peek_packet() => {
                    if let Err(error) = peeked {
                        let source = self.client_read_end(&error).await;
                        return Some(source);
                    }
                    // The idle wait ends when the packet header becomes
                    // visible. Match Go's ExecuteCmd timer: include packet
                    // read/dispatch/response work, never connection idle time.
                    let started = tokio::time::Instant::now();
                    match self.client_io.read_logical(COMMAND_PAYLOAD_LIMIT).await {
                        Ok(packet) => (packet.payload, started),
                        Err(error) => {
                            let source = self.client_read_end(&error).await;
                            return Some(source);
                        }
                    }
                }
            };
            self.client_io.reset_write_sequence(1);
            // Extract the plan's owned facts before the payload moves:
            // CommandPlan borrows the packet bytes.
            let planned = {
                let Ok(command_packet) = CommandPacket::decode(&payload) else {
                    let _ = self.events.send(SessionEvent::ClientIoError).await;
                    return Some(WireErrorSource::ClientNetwork);
                };
                dispatch(command_packet)
                    .map(|plan| (plan.command, plan.response))
                    .ok()
            };
            let Some((command, expected)) = planned else {
                // Unknown command byte: rejected before any forward.
                let _ = self
                    .write_client_error(1047, *b"08S01", "Unknown command")
                    .await;
                continue;
            };
            if self.refuse_unsupported_command(command).await {
                return Some(WireErrorSource::ClientNetwork);
            }
            let event = if command == Command::Quit {
                SessionEvent::ClientCommandQuit
            } else {
                SessionEvent::ClientCommand
            };
            self.pending_command = Some(PendingCommand {
                payload,
                command,
                expected,
                started: command_started,
                since_connection: command_started.saturating_duration_since(self.accepted_at),
                traffic_before: self.backend_traffic(),
            });
            if self.events.send(event).await.is_err() {
                return Some(WireErrorSource::Proxy);
            }
            if event == SessionEvent::ClientCommandQuit {
                // Quit tears down: the FSM goes straight to Closing and
                // the teardown effects arrive; drain them here.
                if let Some(pending) = self.pending_command.take() {
                    self.record_command(&pending);
                }
                return None;
            }
            if !matches!(
                self.await_effect(SessionEffect::ForwardCommandToBackend)
                    .await,
                Awaited::Got
            ) {
                return None;
            }
            let Some(pending) = self.pending_command.take() else {
                return Some(WireErrorSource::Proxy);
            };
            if let Some(source) = self.forward_command_to_backend(&pending).await {
                self.record_command(&pending);
                return Some(source);
            }
            if let Some(sync) = self.apply_command_mutations(&pending, false)
                && self.events.send(sync).await.is_err()
            {
                return Some(WireErrorSource::Proxy);
            }

            if !pending.expected.waits_for_backend() {
                if self
                    .events
                    .send(SessionEvent::NoResponseCommandComplete)
                    .await
                    .is_err()
                {
                    return Some(WireErrorSource::Proxy);
                }
                self.record_command(&pending);
                continue;
            }
            let response_source = if pending.expected == ExpectedResponse::Prepare {
                self.prepare_response_rounds(&pending).await
            } else {
                self.response_rounds(&pending).await
            };
            self.record_command(&pending);
            if let Some(source) = response_source {
                return Some(source);
            }
            if self.closing {
                return None;
            }
        }
    }

    /// Answers the remaining fail-closed slice boundary before any forward:
    /// `COM_CHANGE_USER` is a follow-up slice (SES-06) — an explicit refusal,
    /// never a silent teardown. `COM_STMT_PREPARE` is now served by
    /// [`prepare_response_rounds`](Self::prepare_response_rounds).
    async fn refuse_unsupported_command(&mut self, command: Command) -> bool {
        let refusal = if command == Command::ChangeUser {
            Some(ER_CHANGE_USER_UNSUPPORTED)
        } else {
            None
        };
        let Some((code, state, message)) = refusal else {
            return false;
        };
        let _ = self.write_client_error(code, state, message).await;
        let _ = self.events.send(SessionEvent::ClientIoError).await;
        true
    }

    /// Forwards one accepted command to the backend on a fresh exchange:
    /// the request restarts at sequence zero and its response lineage
    /// answers from one.
    async fn forward_command_to_backend(
        &mut self,
        pending: &PendingCommand,
    ) -> Option<WireErrorSource> {
        let Some(backend) = self.backend.as_mut() else {
            return Some(WireErrorSource::Proxy);
        };
        // Reset the backend compressed sequence once for this command (no-op on
        // a plaintext/TLS backend leg); the direction hooks re-slave the
        // uncompressed sequence on the next write/read. Fails closed on
        // in-flight data.
        if backend.backend_io.reset_layer_sequence().is_err() {
            self.quit_source = QuitSource::ProxyError;
            let _ = self.events.send(SessionEvent::BackendIoError).await;
            return Some(WireErrorSource::Proxy);
        }
        let Some(backend) = self.backend.as_mut() else {
            return Some(WireErrorSource::Proxy);
        };
        backend.backend_io.reset_write_sequence(0);
        backend.backend_io.reset_read_sequence(1);
        if backend
            .backend_io
            .write_logical(&pending.payload, true)
            .await
            .is_err()
        {
            let _ = self.events.send(SessionEvent::BackendIoError).await;
            return Some(WireErrorSource::BackendNetwork);
        }
        None
    }

    /// Streams one command's backend response(s) to the client.
    async fn response_rounds(&mut self, pending: &PendingCommand) -> Option<WireErrorSource> {
        let Ok(mut observer) = ResponseObserver::new(
            pending.expected,
            self.negotiated,
            self.in_transaction,
            DEFAULT_RESPONSE_FLUSH_THRESHOLD,
        ) else {
            return Some(WireErrorSource::Proxy);
        };
        loop {
            let progress = {
                let Some(backend) = self.backend.as_mut() else {
                    return Some(WireErrorSource::Proxy);
                };
                let forwarded = PacketIo::forward_packet_to(
                    &mut backend.backend_io,
                    &mut self.client_io,
                    RESPONSE_CAPTURE,
                )
                .await;
                let Ok(progress) = forwarded else {
                    let _ = self.events.send(SessionEvent::BackendIoError).await;
                    return Some(WireErrorSource::BackendNetwork);
                };
                progress
            };
            let first_physical = progress.first_packet_length().unwrap_or(0);
            let Ok(packet) = ResponsePacket::from_forwarded(
                progress.captured_prefix(),
                progress.logical_payload_bytes(),
                first_physical,
                progress.physical_packets(),
            ) else {
                return Some(WireErrorSource::Proxy);
            };
            let Ok(effect) = observer.observe_backend(packet) else {
                let _ = self.events.send(SessionEvent::BackendIoError).await;
                return Some(WireErrorSource::BackendNetwork);
            };
            self.in_transaction = effect.in_transaction;
            if !matches!(effect.flush, FlushAction::None) && self.client_io.flush().await.is_err() {
                let _ = self.events.send(SessionEvent::ClientIoError).await;
                return Some(WireErrorSource::ClientNetwork);
            }
            let completes = matches!(
                effect.disposition,
                ResponseDisposition::CompleteSuccess | ResponseDisposition::CompleteRaw
            );
            if completes
                && let Some(sync) = self.apply_command_mutations(pending, true)
                && self.events.send(sync).await.is_err()
            {
                return Some(WireErrorSource::Proxy);
            }
            let event = effect.session_event();
            if self.events.send(event).await.is_err() {
                return Some(WireErrorSource::Proxy);
            }
            let expected_ack = match effect.disposition {
                ResponseDisposition::LocalInfile => SessionEffect::RequestLocalInfileFromClient,
                _ => SessionEffect::ForwardResponseToClient,
            };
            if !matches!(self.await_effect(expected_ack).await, Awaited::Got) {
                return None;
            }
            match effect.disposition {
                ResponseDisposition::Continue | ResponseDisposition::MoreResults => {}
                ResponseDisposition::LocalInfile => {
                    if let Some(source) = self.infile_rounds().await {
                        return Some(source);
                    }
                    if self.closing {
                        return None;
                    }
                }
                ResponseDisposition::CompleteSuccess
                | ResponseDisposition::CompleteRaw
                | ResponseDisposition::CompleteError { .. } => {
                    return None;
                }
            }
        }
    }

    /// Streams a `COM_STMT_PREPARE` special response to the client.
    ///
    /// The response is the prepare-OK header, then the declared parameter
    /// definitions, then the declared column definitions, with a classic EOF
    /// after each non-empty group unless `DEPRECATE_EOF` was negotiated; a
    /// leading ERR ends it immediately. [`PrepareObserver`] mirrors Go's
    /// `forwardPrepareCmd`: it counts the two metadata groups from the header,
    /// validates each classic EOF, and flushes exactly once at the terminal
    /// boundary. The prepare-OK carries no server status (Go leaves the
    /// transaction state untouched for a prepare), so `self.in_transaction` is
    /// never rewritten here. On success the returned metadata is registered
    /// before the completion event so a queued redirect or drain observes the
    /// fresh (Idle) guard.
    async fn prepare_response_rounds(
        &mut self,
        _pending: &PendingCommand,
    ) -> Option<WireErrorSource> {
        let mut observer = PrepareObserver::new(self.negotiated);
        loop {
            let progress = {
                let Some(backend) = self.backend.as_mut() else {
                    return Some(WireErrorSource::Proxy);
                };
                let forwarded = PacketIo::forward_packet_to(
                    &mut backend.backend_io,
                    &mut self.client_io,
                    RESPONSE_CAPTURE,
                )
                .await;
                let Ok(progress) = forwarded else {
                    let _ = self.events.send(SessionEvent::BackendIoError).await;
                    return Some(WireErrorSource::BackendNetwork);
                };
                progress
            };
            let first_physical = progress.first_packet_length().unwrap_or(0);
            let Ok(packet) = ResponsePacket::from_forwarded(
                progress.captured_prefix(),
                progress.logical_payload_bytes(),
                first_physical,
                progress.physical_packets(),
            ) else {
                return Some(WireErrorSource::Proxy);
            };
            // A malformed prepare header/EOF is a backend protocol violation:
            // fail closed and tear the session down, never silently forward on.
            let Ok(effect) = observer.observe(packet) else {
                let _ = self.events.send(SessionEvent::BackendIoError).await;
                return Some(WireErrorSource::BackendNetwork);
            };
            if !matches!(effect.flush, FlushAction::None) && self.client_io.flush().await.is_err() {
                let _ = self.events.send(SessionEvent::ClientIoError).await;
                return Some(WireErrorSource::ClientNetwork);
            }
            // Register before the completion event: reusing a statement ID
            // replaces any stale unknown-ID guard with a fresh Idle state
            // atomically. The registry's sync event must then reach the FSM
            // ahead of the command-completion boundary (the SES-00 ordering),
            // so a queued redirect or drain observes the fresh guard rather
            // than a stale pending one.
            if let PrepareDisposition::CompleteSuccess(metadata) = effect.disposition {
                self.prepared.register(metadata);
                if self
                    .events
                    .send(self.prepared.session_event())
                    .await
                    .is_err()
                {
                    return Some(WireErrorSource::Proxy);
                }
            }
            let event = self.prepare_session_event(effect.disposition);
            if self.events.send(event).await.is_err() {
                return Some(WireErrorSource::Proxy);
            }
            if !matches!(
                self.await_effect(SessionEffect::ForwardResponseToClient)
                    .await,
                Awaited::Got
            ) {
                return None;
            }
            match effect.disposition {
                PrepareDisposition::Continue => {}
                PrepareDisposition::CompleteSuccess(_)
                | PrepareDisposition::CompleteError { .. } => {
                    return None;
                }
            }
        }
    }

    /// Maps a prepare-response disposition onto the SES-00 FSM completion
    /// event. A prepare carries no server status, so the transaction state is
    /// the retained value (a prepare inside a transaction keeps it open;
    /// outside, done) — mirroring `ResponseEffect::session_event`.
    fn prepare_session_event(&self, disposition: PrepareDisposition) -> SessionEvent {
        match disposition {
            PrepareDisposition::Continue => SessionEvent::BackendResponsePart,
            PrepareDisposition::CompleteError { .. } => SessionEvent::BackendResponseErrorComplete,
            PrepareDisposition::CompleteSuccess(_) => {
                if self.in_transaction {
                    SessionEvent::BackendResponseTxnOpen
                } else {
                    SessionEvent::BackendResponseTxnDone
                }
            }
        }
    }

    /// The client LOCAL INFILE upload until the empty terminator.
    async fn infile_rounds(&mut self) -> Option<WireErrorSource> {
        // The upload continues each side's exchange in lockstep: the
        // client's next chunk follows the forwarded infile request, and
        // the chunks forwarded to the backend follow its request packet.
        let seq = self.client_io.next_write_sequence();
        self.client_io.reset_read_sequence(seq);
        if let Some(backend) = self.backend.as_mut() {
            let seq = backend.backend_io.expected_read_sequence();
            backend.backend_io.reset_write_sequence(seq);
        }
        loop {
            let payload = match self.client_io.read_logical(COMMAND_PAYLOAD_LIMIT).await {
                Ok(packet) => packet.payload,
                Err(error) => {
                    let source = self.client_read_end(&error).await;
                    return Some(source);
                }
            };
            let done = payload.is_empty();
            let event = if done {
                SessionEvent::ClientInfileEnd
            } else {
                SessionEvent::ClientInfileChunk
            };
            let ack = if done {
                SessionEffect::ForwardInfileEndToBackend
            } else {
                SessionEffect::ForwardInfileChunkToBackend
            };
            if self.events.send(event).await.is_err() {
                return Some(WireErrorSource::Proxy);
            }
            if !matches!(self.await_effect(ack).await, Awaited::Got) {
                return None;
            }
            let Some(backend) = self.backend.as_mut() else {
                return Some(WireErrorSource::Proxy);
            };
            if backend
                .backend_io
                .write_logical(&payload, done)
                .await
                .is_err()
            {
                let _ = self.events.send(SessionEvent::BackendIoError).await;
                return Some(WireErrorSource::BackendNetwork);
            }
            if done {
                // The final backend response continues after the last
                // uploaded chunk on both sides of the relay.
                let seq = backend.backend_io.next_write_sequence();
                backend.backend_io.reset_read_sequence(seq);
                let client_seq = self.client_io.expected_read_sequence();
                self.client_io.reset_write_sequence(client_seq);
                return None;
            }
        }
    }

    /// Waits for one specific effect, handling every other command
    /// inline; teardown-class effects switch the engine into closing.
    async fn await_effect(&mut self, expected: SessionEffect) -> Awaited {
        loop {
            let Some(cmd) = self.cmds.recv().await else {
                return Awaited::Closing;
            };
            match cmd {
                EngineCmd::Effect(effect) if effect == expected => return Awaited::Got,
                other => {
                    if matches!(self.handle_cmd(other).await, Awaited::Closing) {
                        return Awaited::Closing;
                    }
                }
            }
        }
    }

    /// Executes one out-of-band command (control effects, probes).
    async fn handle_cmd(&mut self, cmd: EngineCmd) -> Awaited {
        match cmd {
            EngineCmd::Probe(reply) => {
                let _ = reply.send(self.backend_alive());
                Awaited::Got
            }
            EngineCmd::PrepareRedirect(target) => {
                // The redirect gate admits at most one pending command. Any
                // second preparation would violate that serialization
                // contract; retain the first exact target and let the normal
                // terminal path fail closed if the invariant is ever broken.
                if self.redirect_target.is_none() && self.candidate.is_none() {
                    self.redirect_target = Some(target);
                }
                Awaited::Got
            }
            EngineCmd::Effect(effect) => self.handle_effect(effect).await,
        }
    }

    async fn handle_effect(&mut self, effect: SessionEffect) -> Awaited {
        match effect {
            SessionEffect::BeginDrainTimer => Awaited::Got,
            SessionEffect::StartRedirectHandshake => {
                self.handle_redirect_snapshot().await;
                Awaited::Got
            }
            SessionEffect::NotifyRedirectSucceeded => {
                let _ = self
                    .reports
                    .send(EngineReport::RedirectFinished {
                        succeeded: true,
                        backend_id: self
                            .backend
                            .as_ref()
                            .map(|backend| backend.id.clone())
                            .unwrap_or_default(),
                        code: ErrorCode::Ok,
                    })
                    .await;
                Awaited::Got
            }
            SessionEffect::NotifyRedirectFailed => {
                self.candidate = None;
                self.redirect_target = None;
                let _ = self
                    .reports
                    .send(EngineReport::RedirectFinished {
                        succeeded: false,
                        backend_id: self
                            .backend
                            .as_ref()
                            .map(|backend| backend.id.clone())
                            .unwrap_or_default(),
                        code: ErrorCode::RedirectFailed,
                    })
                    .await;
                Awaited::Got
            }
            SessionEffect::ReleaseBackend => {
                self.closing = true;
                Awaited::Closing
            }
            SessionEffect::CloseBackend => {
                self.closing = true;
                if let Some(backend) = self.backend.as_mut() {
                    let _ = backend.backend_io.flush().await;
                }
                Awaited::Closing
            }
            SessionEffect::CloseClient => {
                self.closing = true;
                let _ = self.client_io.flush().await;
                Awaited::Closing
            }
            SessionEffect::ClassifySessionEnd => {
                self.closing = true;
                self.wire_end.get_or_insert(WireErrorSource::Proxy);
                Awaited::Closing
            }
            SessionEffect::SwapBackend => {
                let Some(candidate) = self.candidate.take() else {
                    self.closing = true;
                    self.wire_end = Some(WireErrorSource::Proxy);
                    return Awaited::Closing;
                };
                let Some(previous) = self.backend.replace(candidate) else {
                    self.closing = true;
                    self.wire_end = Some(WireErrorSource::Proxy);
                    return Awaited::Closing;
                };
                self.retired_backend_in = self
                    .retired_backend_in
                    .saturating_add(previous.counters.inbound());
                self.retired_backend_out = self
                    .retired_backend_out
                    .saturating_add(previous.counters.outbound());
                self.redirect_target = None;
                // Dropping the previous sole owner closes it only after the
                // restored candidate has been installed atomically.
                drop(previous);
                Awaited::Got
            }
            SessionEffect::ActivateFrontendTls
            | SessionEffect::SendProxyGreeting
            | SessionEffect::DialBackend
            | SessionEffect::ForwardHandshakeToBackend
            | SessionEffect::ForwardAuthResultToClient
            | SessionEffect::AttachBackend
            | SessionEffect::ForwardCommandToBackend
            | SessionEffect::ForwardResponseToClient
            | SessionEffect::RequestLocalInfileFromClient
            | SessionEffect::ForwardInfileChunkToBackend
            | SessionEffect::ForwardInfileEndToBackend => {
                // A phase effect the engine did not expect here is an
                // invariant violation: fail closed as a proxy error.
                self.closing = true;
                self.wire_end = Some(WireErrorSource::Proxy);
                Awaited::Closing
            }
        }
    }

    async fn handle_redirect_snapshot(&mut self) {
        // MIG-00 binds the bounded snapshot query to the production socket
        // owner at the FSM safe boundary. MIG-01 consumes the validated
        // token/state only inside this task, builds a fully restored candidate,
        // and exposes it to the FSM only after the restore OK is consumed.
        match self.capture_migration_snapshot().await {
            Ok(snapshot) => {
                if let Some(state) = self.cmd_state.as_mut() {
                    state.replace_current_database_from_snapshot(snapshot.current_database());
                }
                let Some(target) = self.redirect_target.clone() else {
                    let _ = self.events.send(SessionEvent::RedirectBackendFailed).await;
                    return;
                };
                let budget = candidate_budget(target.deadline_unix_millis);
                if budget.is_zero() {
                    // Do not poll the connect future even once after an
                    // absolute deadline has expired: polling may already
                    // initiate target-side I/O before `timeout(0, ..)` wins.
                    let _ = self.events.send(SessionEvent::RedirectBackendFailed).await;
                    return;
                }
                let candidate = tokio::time::timeout(
                    budget,
                    self.establish_migration_candidate(&target, &snapshot),
                )
                .await;
                match candidate {
                    Ok(Ok(candidate)) => {
                        self.candidate = Some(candidate);
                        let _ = self.events.send(SessionEvent::RedirectBackendReady).await;
                    }
                    Ok(Err(_)) | Err(_) => {
                        // The candidate is local to the future and is dropped
                        // on every error/cancellation. The old backend remains
                        // the sole visible owner and stays sequence-aligned.
                        let _ = self.events.send(SessionEvent::RedirectBackendFailed).await;
                    }
                }
            }
            Err(SnapshotFailure::OldBackendUsable) => {
                let _ = self.events.send(SessionEvent::RedirectBackendFailed).await;
            }
            Err(SnapshotFailure::BackendNetwork) => {
                self.wire_end = Some(WireErrorSource::BackendNetwork);
                self.quit_source = QuitSource::BackendNetwork;
                let _ = self.events.send(SessionEvent::BackendIoError).await;
            }
            Err(SnapshotFailure::Desynchronized) => {
                self.wire_end = Some(WireErrorSource::Proxy);
                self.quit_source = QuitSource::ProxyMalformed;
                let _ = self.events.send(SessionEvent::BackendIoError).await;
            }
            Err(SnapshotFailure::ProxyInvariant) => {
                self.wire_end = Some(WireErrorSource::Proxy);
                self.quit_source = QuitSource::ProxyError;
                let _ = self.events.send(SessionEvent::BackendIoError).await;
            }
        }
    }

    /// Runs the single allowlisted MIG-00 query on the attached old backend.
    ///
    /// The engine owns both backend halves, and the FSM emits this effect only
    /// in `RedirectPending`, so no user command can share the exchange. A
    /// parser error after a complete terminator is recoverable; any earlier
    /// error poisons the connection instead of risking sequence confusion.
    async fn capture_migration_snapshot(
        &mut self,
    ) -> Result<SessionStateSnapshot, SnapshotFailure> {
        let limits = InternalLimits::default();
        let query = InternalQuery::ShowSessionStates;
        let request = query
            .encode(limits)
            .map_err(|_| SnapshotFailure::ProxyInvariant)?;
        let mut parser = query
            .parser(self.negotiated, limits)
            .map_err(|_| SnapshotFailure::ProxyInvariant)?;
        let Some(backend) = self.backend.as_mut() else {
            return Err(SnapshotFailure::ProxyInvariant);
        };

        // This proxy-owned `SHOW SESSION_STATES` is a fresh command exchange, so
        // on a compressed backend it must start from compressed sequence zero —
        // Go's `cmd_processor_query.go` calls `ResetSequence()` before every
        // proxy-owned query. The shared `send_proxy_owned_query` seam performs
        // that layered + packet reset and the send; the migration-snapshot
        // regression exercises the same helper.
        send_proxy_owned_query(&mut backend.backend_io, &request)
            .await
            .map_err(|error| match error {
                ProxyOwnedQueryError::LayeredReset => SnapshotFailure::ProxyInvariant,
                ProxyOwnedQueryError::Send => SnapshotFailure::BackendNetwork,
            })?;

        loop {
            let payload = backend
                .backend_io
                .read_logical(limits.max_result_bytes)
                .await
                .map_err(|_| SnapshotFailure::BackendNetwork)?
                .payload;
            match parser.consume(&payload) {
                Ok(InternalProgress::Continue) => {}
                Ok(InternalProgress::Complete(InternalResult::SessionStates(snapshot))) => {
                    return Ok(snapshot);
                }
                Ok(InternalProgress::Complete(InternalResult::Ok(_))) => {
                    return Err(SnapshotFailure::Desynchronized);
                }
                Err(_) if parser.state() == InternalParserState::Complete => {
                    return Err(SnapshotFailure::OldBackendUsable);
                }
                Err(_) => return Err(SnapshotFailure::Desynchronized),
            }
        }
    }

    /// Dials, authenticates, and restores one redirect target without making
    /// it visible to the command path. The caller owns the overall timeout;
    /// cancellation drops the local socket and every secret-bearing buffer.
    async fn establish_migration_candidate(
        &mut self,
        target: &RedirectTarget,
        snapshot: &SessionStateSnapshot,
    ) -> Result<BackendIo, CandidateFailure> {
        if target.backend_id.is_empty()
            || target.backend_address.is_empty()
            || !target.backend_healthy
        {
            return Err(CandidateFailure::InvalidTarget);
        }
        let stream = tokio::net::TcpStream::connect(&target.backend_address)
            .await
            .map_err(|_| {
                self.metrics.try_record(Observation::DialBackendFailed {
                    backend: target.backend_address.clone(),
                });
                CandidateFailure::Dial
            })?;
        let mut backend_socket = CountedIo::new(stream);
        let counters = backend_socket.counters();
        if self.proxy_protocol_v2_enabled() {
            let client_src = self
                .inbound_proxy_client
                .unwrap_or(self.endpoints.client_addr);
            write_backend_proxy_v2_header(&mut backend_socket, client_src)
                .await
                .map_err(|_| CandidateFailure::Dial)?;
        }
        let mut candidate = BackendIo {
            backend_io: PacketIo::new(BackendTransport::Plain(backend_socket)),
            counters,
            id: target.backend_id.clone(),
            address: target.backend_address.clone(),
            cluster: target.cluster_name.clone(),
            local: target.backend_local,
        };
        let greeting = candidate
            .backend_io
            .read_logical(HANDSHAKE_PAYLOAD_LIMIT)
            .await
            .map_err(|_| CandidateFailure::Handshake)?;
        let backend_greeting = mysql_wire::parse_initial_handshake(&greeting.payload)
            .map_err(|_| CandidateFailure::Handshake)?;
        let backend_caps = backend_greeting.capabilities;
        let (require_backend_tls, backend_tls_available) = self.backend_tls_policy();
        verify_backend(
            backend_caps,
            self.negotiated,
            proxy_capabilities(self.frontend_tls_available()),
            require_backend_tls,
        )
        .map_err(|_| CandidateFailure::Handshake)?;

        let parsed = parse_handshake_response(&self.client_handshake_raw)
            .map_err(|_| CandidateFailure::Handshake)?;
        let attributes = parsed.attributes.map(|attributes| {
            attributes
                .into_iter()
                .filter_map(Result::ok)
                .collect::<Vec<_>>()
        });
        let plan = plan_backend_migration_handshake(
            self.negotiated,
            attributes.is_some(),
            backend_caps,
            require_backend_tls,
            backend_tls_available,
        )
        .map_err(|_| CandidateFailure::Handshake)?;

        if matches!(plan.tls, BackendTlsMode::Enabled) {
            self.upgrade_backend_tls(
                &mut candidate,
                plan.capabilities,
                candidate_budget(target.deadline_unix_millis),
            )
            .await
            .map_err(|_| CandidateFailure::Handshake)?;
        }

        let capabilities = self
            .authenticate_migration_candidate(
                &mut candidate,
                snapshot,
                plan.capabilities,
                backend_caps,
            )
            .await?;
        self.restore_candidate_state(&mut candidate, snapshot.session_states(), capabilities)
            .await?;
        self.apply_candidate_keepalive(&candidate)?;
        Ok(candidate)
    }

    /// Applies the healthy-target policy after every transport upgrade, through
    /// the preserved innermost raw socket.
    fn apply_candidate_keepalive(&self, candidate: &BackendIo) -> Result<(), CandidateFailure> {
        let Some(policy) = self
            .seat
            .snapshot()
            .raw()
            .config
            .as_ref()
            .and_then(|config| config.healthy_backend_keepalive)
        else {
            return Ok(());
        };
        let Some(counted) = candidate.backend_io.get_ref().as_counted_stream() else {
            return Err(CandidateFailure::Handshake);
        };
        let _ = proxy_io::socket::apply_keepalive(
            counted.get_ref(),
            crate::server::snapshot_keepalive(&policy),
        );
        Ok(())
    }

    /// Sends the fixed session-token handshake and consumes its sole terminal
    /// response. Returns the exact capability mask governing the restored
    /// command channel.
    async fn authenticate_migration_candidate(
        &self,
        candidate: &mut BackendIo,
        snapshot: &SessionStateSnapshot,
        planned_capabilities: CapabilityFlags,
        backend_caps: CapabilityFlags,
    ) -> Result<CapabilityFlags, CandidateFailure> {
        // Go's second handshake uses the signed token as auth data under the
        // fixed `tidb_session_token` plugin. The authoritative current-db from
        // SHOW SESSION_STATES replaces (and may clear) the original database.
        let parsed = parse_handshake_response(&self.client_handshake_raw)
            .map_err(|_| CandidateFailure::Handshake)?;
        let attributes = parsed.attributes.map(|attributes| {
            attributes
                .into_iter()
                .filter_map(Result::ok)
                .collect::<Vec<_>>()
        });
        let database = snapshot.current_database().map(str::as_bytes);
        let capabilities = migration_auth_capabilities(
            planned_capabilities,
            backend_caps,
            database.is_some(),
            snapshot.session_token().len(),
        )?;
        let response = encode_handshake_response(HandshakeResponseParams {
            capabilities,
            max_packet_size: parsed.max_packet_size,
            collation: parsed.collation,
            username: parsed.username,
            auth_response: snapshot.session_token().as_bytes(),
            database,
            auth_plugin_name: Some(b"tidb_session_token"),
            attributes: attributes.as_deref(),
            zstd_level: parsed.zstd_level,
        })
        .map_err(|_| CandidateFailure::Handshake)?;
        let response = SensitiveBytes::new(response);
        if !matches!(candidate.backend_io.get_ref(), BackendTransport::Tls(_)) {
            let next = candidate.backend_io.expected_read_sequence();
            candidate.backend_io.reset_write_sequence(next);
        }
        candidate
            .backend_io
            .write_logical(&response.0, true)
            .await
            .map_err(|_| CandidateFailure::Handshake)?;
        candidate
            .backend_io
            .reset_read_sequence(candidate.backend_io.next_write_sequence());
        let auth_result = candidate
            .backend_io
            .read_logical(HANDSHAKE_PAYLOAD_LIMIT)
            .await
            .map_err(|_| CandidateFailure::Handshake)?;
        match classify_backend_auth_packet(&auth_result.payload, capabilities) {
            Ok(AuthEvent::BackendOk) => {}
            Ok(AuthEvent::BackendError { .. }) => {
                return Err(CandidateFailure::Authentication);
            }
            Ok(_) | Err(_) => return Err(CandidateFailure::Handshake),
        }

        // The auth OK is the exact MySQL boundary where the backend leg switches
        // to compressed framing. The restore query that follows must therefore
        // run through the negotiated codec, independently of the client leg.
        if let Some(algorithm) = selection_to_compression_algorithm(compression_selection(
            capabilities,
            parsed.zstd_level.unwrap_or(0),
        )) {
            Self::activate_candidate_backend_compression(candidate, algorithm)?;
        }
        Ok(capabilities)
    }

    /// Activates compression on a fully authenticated migration candidate
    /// without exposing it to the command path. This mirrors the normal backend
    /// auth-OK activation seam, but maps invariant failures to the candidate-only
    /// rollback path so the old backend remains usable.
    fn activate_candidate_backend_compression(
        candidate: &mut BackendIo,
        algorithm: CompressionAlgorithm,
    ) -> Result<(), CandidateFailure> {
        let endpoint = std::mem::replace(
            &mut candidate.backend_io,
            PacketIo::new(BackendTransport::Detached),
        );
        let (transport, upgrade_state, prefix) = endpoint.into_upgrade_parts();
        if !prefix.is_empty()
            || matches!(
                &transport,
                BackendTransport::Detached | BackendTransport::Compressed(_)
            )
        {
            return Err(CandidateFailure::Handshake);
        }
        let compressed = CompressedIo::new(transport, algorithm, CompressionLimits::default())
            .map_err(|_| CandidateFailure::Handshake)?;
        candidate.backend_io = PacketIo::from_upgrade_parts(
            BackendTransport::Compressed(Box::new(compressed)),
            upgrade_state,
        );
        Ok(())
    }

    /// Restores the exact escaped state and consumes a complete OK before the
    /// candidate can become visible. Any error drops only the candidate.
    async fn restore_candidate_state(
        &self,
        candidate: &mut BackendIo,
        session_states: &str,
        capabilities: CapabilityFlags,
    ) -> Result<(), CandidateFailure> {
        let limits = InternalLimits::default();
        let query = InternalQuery::SetSessionStates(session_states);
        let request = SensitiveBytes::new(
            query
                .encode(limits)
                .map_err(|_| CandidateFailure::Restore)?,
        );
        let mut parser = query
            .parser(capabilities, limits)
            .map_err(|_| CandidateFailure::Restore)?;
        send_proxy_owned_query(&mut candidate.backend_io, &request.0)
            .await
            .map_err(|_| CandidateFailure::Restore)?;
        loop {
            let payload = candidate
                .backend_io
                .read_logical(limits.max_result_bytes)
                .await
                .map_err(|_| CandidateFailure::Restore)?
                .payload;
            match parser
                .consume(&payload)
                .map_err(|_| CandidateFailure::Restore)?
            {
                InternalProgress::Continue => {}
                InternalProgress::Complete(InternalResult::Ok(_)) => return Ok(()),
                InternalProgress::Complete(InternalResult::SessionStates(_)) => {
                    return Err(CandidateFailure::Restore);
                }
            }
        }
    }

    /// Applies the plan's session and prepared mutations at their
    /// declared boundary. A prepared-registry change returns its SES-00
    /// synchronization event, which the caller MUST deliver before the
    /// command-completion boundary so a queued drain or redirect never
    /// crosses an unfinished long-data/cursor guard.
    fn apply_command_mutations(
        &mut self,
        pending: &PendingCommand,
        success_stage: bool,
    ) -> Option<SessionEvent> {
        let state = self.cmd_state.as_mut()?;
        // Re-derive the plan's mutations from the held payload: the
        // borrowed plan cannot outlive its packet, so mutations are
        // re-computed at their application point.
        let Ok(packet) = CommandPacket::decode(&pending.payload) else {
            return None;
        };
        let Ok(plan) = dispatch(packet) else {
            return None;
        };
        let effects: CommandStateEffects<'_> = if success_stage {
            plan.after_success
        } else {
            plan.after_forward
        };
        if let Some(mutation) = effects.session {
            state.apply(mutation);
            if matches!(mutation, SessionMutation::MarkQuit) {
                self.wire_end.get_or_insert(WireErrorSource::ClientNetwork);
            }
        }
        effects.prepared.map(|mutation| {
            self.prepared.apply_mutation(mutation);
            self.prepared.session_event()
        })
    }

    async fn run_auth_effects(&mut self, effects: &[AuthEffect]) -> Result<(), WireErrorSource> {
        for effect in effects {
            match effect {
                AuthEffect::ForwardBackendToClient => {
                    let Some(payload) = self.relay_hold.take() else {
                        return Err(WireErrorSource::Proxy);
                    };
                    // Connection-phase relay: both directions continue
                    // the one counter per channel in lockstep.
                    let seq = self.client_io.expected_read_sequence();
                    self.client_io.reset_write_sequence(seq);
                    if self.client_io.write_logical(&payload, true).await.is_err() {
                        let _ = self.events.send(SessionEvent::ClientIoError).await;
                        return Err(WireErrorSource::ClientNetwork);
                    }
                }
                AuthEffect::ForwardClientToBackend => {
                    let Some(payload) = self.relay_hold.take() else {
                        return Err(WireErrorSource::Proxy);
                    };
                    let Some(backend) = self.backend.as_mut() else {
                        return Err(WireErrorSource::Proxy);
                    };
                    let seq = backend.backend_io.expected_read_sequence();
                    backend.backend_io.reset_write_sequence(seq);
                    if backend
                        .backend_io
                        .write_logical(&payload, true)
                        .await
                        .is_err()
                    {
                        let _ = self.events.send(SessionEvent::BackendIoError).await;
                        return Err(WireErrorSource::BackendNetwork);
                    }
                }
                AuthEffect::ActivateClientCompression(selection) => {
                    // At the auth-OK boundary Go calls setCompress on the client
                    // leg; a `None` selection is a no-op, otherwise wrap the
                    // client transport in compressed framing (WIRE-C).
                    if let Some(algorithm) = selection_to_compression_algorithm(*selection) {
                        self.activate_client_compression(algorithm).await?;
                    }
                }
                AuthEffect::ActivateBackendCompression(selection) => {
                    // The backend leg negotiates independently (client caps
                    // masked by backend caps), so it may pick a different
                    // algorithm or none.
                    if let Some(algorithm) = selection_to_compression_algorithm(*selection) {
                        self.activate_backend_compression(algorithm).await?;
                    }
                }
                AuthEffect::ReconnectBackend => {
                    // Reconnect (session migration) is never approved in this
                    // slice.
                    return Err(WireErrorSource::Proxy);
                }
            }
        }
        Ok(())
    }

    /// Whether this session's snapshot carries a frontend TLS server config.
    /// Governs both the greeting `SSL` advertisement and the strict
    /// SSLRequest-vs-plaintext classification: a client may only upgrade if we
    /// actually advertised (and can serve) TLS.
    fn frontend_tls_available(&self) -> bool {
        self.seat.snapshot().frontend_server_config.is_some()
    }

    /// Remaining handshake budget from the absolute deadline (`accepted_at +
    /// handshake_deadline`), for TLS accept/connect. Saturates at zero so a
    /// blown budget fails closed immediately instead of granting a fresh wait.
    fn handshake_budget_remaining(&self) -> Duration {
        (self.accepted_at + self.handshake_deadline)
            .saturating_duration_since(tokio::time::Instant::now())
    }

    /// Upgrades the client transport to server-side TLS in place, preserving the
    /// `MySQL` sequence trackers and framing counters across the swap. The raw
    /// TLS handshake bytes are not `MySQL` packets, so they never enter the
    /// `PacketIo` framing counters — but they DO cross the wire through the
    /// innermost `CountedIo`, so they count toward the raw traffic totals, since
    /// the upgrade wraps that same counted socket rather than replacing it.
    ///
    /// The `SSLRequest`'s prefetched-but-unread bytes, if any, replay ahead of
    /// the TLS stream so no `ClientHello` byte is lost. Any failure — missing
    /// config, timeout, or handshake error — fails closed: the owner drops the
    /// socket (moved into `accept_frontend`, dropped on error), there is no
    /// plaintext fallback and no detached task.
    async fn activate_frontend_tls(&mut self) -> Result<(), WireErrorSource> {
        let Some(config) = self.seat.snapshot().frontend_server_config.clone() else {
            // Reached only if the snapshot lost its config between advertisement
            // and here; a client SSLRequest we cannot serve fails closed.
            self.quit_source = QuitSource::ProxyError;
            let _ = self.events.send(SessionEvent::ClientIoError).await;
            return Err(WireErrorSource::Proxy);
        };
        let timeout = self.handshake_budget_remaining();
        // Move the endpoint out to perform the value-consuming upgrade; the
        // sequence/counter state travels in the token, the raw socket in the
        // transport. `Detached` holds the field meanwhile and is never polled.
        let endpoint = std::mem::replace(
            &mut self.client_io,
            PacketIo::new(ClientTransport::Detached),
        );
        let (transport, upgrade_state, prefix) = endpoint.into_upgrade_parts();
        let ClientTransport::Plain(stream) = transport else {
            // A second activation on an already-upgraded transport is a proxy
            // invariant violation.
            self.quit_source = QuitSource::ProxyError;
            let _ = self.events.send(SessionEvent::ClientIoError).await;
            return Err(WireErrorSource::Proxy);
        };
        // `stream` was moved into `accept_frontend`; on error it is dropped —
        // the owner drops the socket. No plaintext fallback, no detached task.
        let Ok(frontend) =
            accept_frontend(stream, prefix, config, timeout, DEFAULT_CONN_BUFFER_SIZE).await
        else {
            self.quit_source = QuitSource::ClientHandshake;
            let _ = self.events.send(SessionEvent::ClientIoError).await;
            return Err(WireErrorSource::ClientNetwork);
        };
        self.client_io =
            PacketIo::from_upgrade_parts(ClientTransport::Tls(frontend), upgrade_state);
        self.frontend_tls_active = true;
        Ok(())
    }

    /// Wraps the client transport in `MySQL` compressed framing in place after
    /// authentication. Compression is the OUTERMOST transport layer (above any
    /// TLS), so it wraps the whole client transport, preserving the packet
    /// sequence trackers and framing counters across the swap. Activation lands
    /// at a clean command boundary (the auth-OK packet was just forwarded), so
    /// the prefetch prefix must be empty; a non-empty prefix, an already-wrapped
    /// transport, or a codec/config error fails closed.
    async fn activate_client_compression(
        &mut self,
        algorithm: CompressionAlgorithm,
    ) -> Result<(), WireErrorSource> {
        let endpoint = std::mem::replace(
            &mut self.client_io,
            PacketIo::new(ClientTransport::Detached),
        );
        let (transport, upgrade_state, prefix) = endpoint.into_upgrade_parts();
        if !prefix.is_empty()
            || matches!(
                &transport,
                ClientTransport::Detached | ClientTransport::Compressed(_)
            )
        {
            self.quit_source = QuitSource::ProxyError;
            let _ = self.events.send(SessionEvent::ClientIoError).await;
            return Err(WireErrorSource::Proxy);
        }
        let Ok(compressed) = CompressedIo::new(transport, algorithm, CompressionLimits::default())
        else {
            self.quit_source = QuitSource::ProxyError;
            let _ = self.events.send(SessionEvent::ClientIoError).await;
            return Err(WireErrorSource::Proxy);
        };
        self.client_io = PacketIo::from_upgrade_parts(
            ClientTransport::Compressed(Box::new(compressed)),
            upgrade_state,
        );
        Ok(())
    }

    /// Wraps the backend transport in `MySQL` compressed framing in place, as
    /// [`Self::activate_client_compression`] does for the client leg. The
    /// backend leg negotiates independently, so its algorithm may differ.
    async fn activate_backend_compression(
        &mut self,
        algorithm: CompressionAlgorithm,
    ) -> Result<(), WireErrorSource> {
        let Some(backend) = self.backend.as_mut() else {
            return Err(WireErrorSource::Proxy);
        };
        let endpoint = std::mem::replace(
            &mut backend.backend_io,
            PacketIo::new(BackendTransport::Detached),
        );
        let (transport, upgrade_state, prefix) = endpoint.into_upgrade_parts();
        if !prefix.is_empty()
            || matches!(
                &transport,
                BackendTransport::Detached | BackendTransport::Compressed(_)
            )
        {
            self.quit_source = QuitSource::ProxyError;
            let _ = self.events.send(SessionEvent::BackendIoError).await;
            return Err(WireErrorSource::Proxy);
        }
        let Ok(compressed) = CompressedIo::new(transport, algorithm, CompressionLimits::default())
        else {
            self.quit_source = QuitSource::ProxyError;
            let _ = self.events.send(SessionEvent::BackendIoError).await;
            return Err(WireErrorSource::Proxy);
        };
        let Some(backend) = self.backend.as_mut() else {
            return Err(WireErrorSource::Proxy);
        };
        backend.backend_io = PacketIo::from_upgrade_parts(
            BackendTransport::Compressed(Box::new(compressed)),
            upgrade_state,
        );
        Ok(())
    }

    /// The backend TLS policy for this session as `(require, available)`. A
    /// validated snapshot always carries a default backend policy object, so
    /// presence is read from the raw config's `backend_tls` rather than the
    /// validated policy's emptiness.
    fn backend_tls_policy(&self) -> (bool, bool) {
        let snapshot = self.seat.snapshot();
        let config = snapshot.raw().config.as_ref();
        let require = config.is_some_and(|config| config.require_backend_tls);
        let available = config.is_some_and(|config| config.backend_tls.is_some());
        (require, available)
    }

    /// Whether this session's snapshot enables the PROXY protocol v2 preamble
    /// on the backend dial (Go `proxy-protocol = "v2"`). The snapshot validator
    /// only admits `disabled`/`v2`, so any other value is treated as disabled.
    fn proxy_protocol_v2_enabled(&self) -> bool {
        self.seat
            .snapshot()
            .raw()
            .config
            .as_ref()
            .is_some_and(|config| {
                matches!(
                    ProxyProtocolMode::try_from(config.proxy_protocol),
                    Ok(ProxyProtocolMode::V2)
                )
            })
    }

    /// Upgrades the backend transport to client-side TLS in place. Sends the
    /// plaintext `SSLRequest` (seq 1, continuing after the backend greeting),
    /// runs the backend TLS handshake, then reattaches preserving the sequence
    /// trackers and framing counters (the raw TLS handshake bytes are not
    /// `MySQL` packets, so they skip the `PacketIo` framing counters, but they
    /// still count on the innermost `CountedIo` raw traffic totals); the full
    /// handshake response then travels inside TLS at seq 2.
    ///
    /// Any failure — config build, handshake, timeout, or the backend speaking
    /// before TLS — fails closed: the owner drops the socket (moved into
    /// `connect_backend`), no plaintext fallback, no detached task.
    async fn upgrade_backend_tls(
        &self,
        backend: &mut BackendIo,
        capabilities: CapabilityFlags,
        timeout: Duration,
    ) -> Result<(), WireErrorSource> {
        // The SSLRequest mirrors the client's max packet size and collation —
        // the same values the forwarded handshake response carries.
        let Ok(client) = parse_handshake_response(&self.client_handshake_raw) else {
            return Err(WireErrorSource::Proxy);
        };
        // Align the writer to continue after the greeting (reader observed seq
        // 0 -> expects 1) and send the plaintext SSLRequest at seq 1.
        let next = backend.backend_io.expected_read_sequence();
        backend.backend_io.reset_write_sequence(next);
        let ssl_request =
            encode_ssl_request(capabilities, client.max_packet_size, client.collation);
        if backend
            .backend_io
            .write_logical(&ssl_request, true)
            .await
            .is_err()
        {
            return Err(WireErrorSource::BackendNetwork);
        }
        let Ok(config) = build_backend_config(&self.seat.snapshot().backend_tls) else {
            return Err(WireErrorSource::Proxy);
        };
        let server_name = backend_server_name(&backend.address);
        // Move the endpoint out for the value-consuming upgrade; the
        // sequence/counter state travels in the token, the raw socket in the
        // transport. `Detached` holds the field meanwhile and is never polled.
        let io = std::mem::replace(
            &mut backend.backend_io,
            PacketIo::new(BackendTransport::Detached),
        );
        let (transport, upgrade_state, prefix) = io.into_upgrade_parts();
        let BackendTransport::Plain(stream) = transport else {
            return Err(WireErrorSource::Proxy);
        };
        if !prefix.is_empty() {
            // The backend sent bytes before TLS started (it must not); fail
            // closed rather than dropping them or feeding them into TLS.
            return Err(WireErrorSource::BackendNetwork);
        }
        let Ok(backend_tls) = connect_backend(
            stream,
            &server_name,
            config,
            timeout,
            DEFAULT_CONN_BUFFER_SIZE,
        )
        .await
        else {
            return Err(WireErrorSource::BackendNetwork);
        };
        backend.backend_io =
            PacketIo::from_upgrade_parts(BackendTransport::Tls(backend_tls), upgrade_state);
        Ok(())
    }

    async fn send_greeting(&mut self) -> Result<(), WireErrorSource> {
        fill_salt(&mut self.salt);
        let params = build_greeting(
            proxy_capabilities(self.frontend_tls_available()),
            &self.salt,
            SERVER_VERSION,
            self.connection_id,
            45,
            StatusFlags::from_bits_retain(0),
        );
        let Ok(encoded) = encode_initial_handshake(params) else {
            return Err(WireErrorSource::Proxy);
        };
        if self.client_io.write_logical(&encoded, true).await.is_err() {
            return Err(WireErrorSource::ClientNetwork);
        }
        Ok(())
    }

    async fn write_client_error(
        &mut self,
        code: u16,
        state: [u8; 5],
        message: &str,
    ) -> Result<(), WireErrorSource> {
        let Ok(encoded) =
            encode_error_packet(code, Some(state), message.as_bytes(), self.negotiated)
        else {
            return Err(WireErrorSource::Proxy);
        };
        if self.client_io.write_logical(&encoded, true).await.is_err() {
            return Err(WireErrorSource::ClientNetwork);
        }
        Ok(())
    }

    async fn client_read_end(&mut self, error: &proxy_io::PacketIoError) -> WireErrorSource {
        if is_clean_eof(error) {
            let _ = self.events.send(SessionEvent::ClientEof).await;
            WireErrorSource::ClientNetwork
        } else {
            let _ = self.events.send(SessionEvent::ClientIoError).await;
            WireErrorSource::ClientNetwork
        }
    }

    async fn backend_read(&mut self, limit: usize) -> Result<Vec<u8>, WireErrorSource> {
        let Some(backend) = self.backend.as_mut() else {
            return Err(WireErrorSource::Proxy);
        };
        match backend.backend_io.read_logical(limit).await {
            Ok(packet) => Ok(packet.payload),
            Err(_) => Err(WireErrorSource::BackendNetwork),
        }
    }

    fn backend_alive(&mut self) -> bool {
        let Some(backend) = self.backend.as_mut() else {
            return false;
        };
        let Some(counted) = backend.backend_io.get_ref().as_counted_stream() else {
            // Detached only during an in-progress TLS upgrade, before the
            // backend is exposed to probes; treat as alive rather than dead.
            return true;
        };
        // The probe reads the raw socket beneath `CountedIo`, but through its
        // count-aware `probe_try_read`, so any consumed byte is accounted on the
        // same seam before the session tears the connection down — Go counts it
        // too, since its liveness `Peek(1)` reads through `basicReadWriter`.
        let mut probe = [0_u8; 1];
        match counted.probe_try_read(&mut probe) {
            // Data outside a command or a clean EOF both mean the backend is not
            // idle-healthy (a consumed byte was already counted).
            Ok(_) => false,
            Err(error) => error.kind() == std::io::ErrorKind::WouldBlock,
        }
    }

    async fn shutdown_io(&mut self) {
        let _ = self.client_io.flush().await;
        if let Some(backend) = self.backend.as_mut() {
            let _ = backend.backend_io.flush().await;
        }
    }

    fn totals(&self) -> TrafficTotals {
        // Bytes come from the innermost raw counters (real wire I/O, Go's
        // `basicReadWriter` accounting); the framing-layer `PacketIo` byte
        // counters deliberately do not feed this metric.
        TrafficTotals {
            client_in: self.client_counters.inbound(),
            client_out: self.client_counters.outbound(),
            backend_in: self.retired_backend_in.saturating_add(
                self.backend
                    .as_ref()
                    .map_or(0, |backend| backend.counters.inbound()),
            ),
            backend_out: self.retired_backend_out.saturating_add(
                self.backend
                    .as_ref()
                    .map_or(0, |backend| backend.counters.outbound()),
            ),
        }
    }

    fn backend_traffic(&self) -> BackendTraffic {
        // Bytes from the raw socket counters; packet counts stay from the
        // `PacketIo` framing layer — mirroring Go's split of raw wire bytes vs
        // MySQL physical-packet counts.
        self.backend
            .as_ref()
            .map_or(BackendTraffic::default(), |backend| BackendTraffic {
                inbound_bytes: backend.counters.inbound(),
                inbound_packets: backend.backend_io.in_packets(),
                outbound_bytes: backend.counters.outbound(),
                outbound_packets: backend.backend_io.out_packets(),
            })
    }

    fn record_command(&self, pending: &PendingCommand) {
        let current = self.backend_traffic();
        let traffic = BackendTraffic {
            inbound_bytes: current
                .inbound_bytes
                .saturating_sub(pending.traffic_before.inbound_bytes),
            inbound_packets: current
                .inbound_packets
                .saturating_sub(pending.traffic_before.inbound_packets),
            outbound_bytes: current
                .outbound_bytes
                .saturating_sub(pending.traffic_before.outbound_bytes),
            outbound_packets: current
                .outbound_packets
                .saturating_sub(pending.traffic_before.outbound_packets),
        };
        let Some(backend) = &self.backend else {
            return;
        };
        self.metrics.try_record(Observation::CommandCompleted {
            backend: backend.address.clone(),
            command: pending.command,
            duration: pending.started.elapsed(),
            since_connection: pending.since_connection,
            traffic,
            local: backend.local,
        });
    }
}

/// Maps an auth failure to the wire error source.
const fn failure_source(kind: FailureKind) -> WireErrorSource {
    match kind {
        FailureKind::ClientHandshake
        | FailureKind::ClientCapability
        | FailureKind::PacketTooLarge
        | FailureKind::AuthenticationFailed => WireErrorSource::ClientNetwork,
        FailureKind::BackendHandshake
        | FailureKind::BackendCapability
        | FailureKind::BackendNoTls
        | FailureKind::BackendProxyProtocol
        | FailureKind::NoBackend => WireErrorSource::BackendNetwork,
        FailureKind::ProxyNoTls | FailureKind::ProxyInternal | FailureKind::ControlPlane => {
            WireErrorSource::Proxy
        }
        FailureKind::Shutdown => WireErrorSource::Shutdown,
    }
}

const fn failure_quit_source(kind: FailureKind) -> QuitSource {
    match kind {
        FailureKind::AuthenticationFailed => QuitSource::ClientAuthFail,
        FailureKind::ClientHandshake
        | FailureKind::ClientCapability
        | FailureKind::PacketTooLarge => QuitSource::ClientHandshake,
        FailureKind::BackendHandshake
        | FailureKind::BackendCapability
        | FailureKind::BackendNoTls
        | FailureKind::BackendProxyProtocol => QuitSource::BackendHandshake,
        FailureKind::NoBackend => QuitSource::ProxyNoBackend,
        FailureKind::ProxyNoTls | FailureKind::ProxyInternal | FailureKind::ControlPlane => {
            QuitSource::ProxyError
        }
        FailureKind::Shutdown => QuitSource::ProxyQuit,
    }
}

const fn acquire_quit_source(error: &AcquireError) -> QuitSource {
    match error {
        AcquireError::NoBackend { .. }
        | AcquireError::BudgetExhausted { .. }
        | AcquireError::ClusterUnsupported { .. } => QuitSource::ProxyNoBackend,
        AcquireError::Routing { .. }
        | AcquireError::MalformedAssignment { .. }
        | AcquireError::Channel(_) => QuitSource::ProxyError,
    }
}

const fn coarse_quit_source(source: WireErrorSource) -> QuitSource {
    match source {
        WireErrorSource::ClientNetwork => QuitSource::ClientNetwork,
        WireErrorSource::BackendNetwork => QuitSource::BackendNetwork,
        WireErrorSource::Shutdown => QuitSource::ProxyQuit,
        WireErrorSource::BackendSql => QuitSource::ClientSqlError,
        WireErrorSource::Proxy | WireErrorSource::Control => QuitSource::ProxyError,
        WireErrorSource::Unspecified => QuitSource::None,
    }
}

/// Whether a packet read error is a clean peer EOF at a packet
/// boundary.
fn is_clean_eof(error: &proxy_io::PacketIoError) -> bool {
    matches!(
        error,
        proxy_io::PacketIoError::Io { source, .. }
            if source.kind() == std::io::ErrorKind::UnexpectedEof
    )
}

/// Fills the greeting salt from OS entropy.
fn fill_salt(salt: &mut [u8; 20]) {
    let mut buffer = [0_u8; 20];
    if getrandom::getrandom(&mut buffer).is_ok() {
        *salt = buffer;
        // MySQL salts avoid NUL bytes (NUL-terminated on the wire).
        for byte in salt.iter_mut() {
            if *byte == 0 {
                *byte = 1;
            }
        }
    } else {
        // Entropy failure: derive a non-constant fallback rather than a
        // fixed salt.
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.subsec_nanos());
        for (index, byte) in salt.iter_mut().enumerate() {
            *byte = (seed
                .wrapping_add(u32::try_from(index).unwrap_or(0))
                .wrapping_mul(2_654_435_761)
                >> 24) as u8;
            if *byte == 0 {
                *byte = 1;
            }
        }
    }
}

#[cfg(test)]
mod tls_wiring_tests {
    use super::{
        backend_server_name, candidate_budget, leading_capabilities, migration_auth_capabilities,
        normalize_leading_capabilities, proxy_capabilities,
    };
    use mysql_wire::{
        CapabilityFlags, HandshakeResponseParams, encode_handshake_response, encode_ssl_request,
        parse_handshake_response, parse_ssl_request,
    };

    #[test]
    fn proxy_capabilities_advertise_ssl_only_when_available() {
        assert!(
            proxy_capabilities(true).contains(CapabilityFlags::SSL),
            "a frontend TLS config advertises SSL"
        );
        assert!(
            !proxy_capabilities(false).contains(CapabilityFlags::SSL),
            "no frontend TLS config strips SSL so advertisement matches capability"
        );
        // Everything except SSL is identical across the two, so only the SSL
        // bit is governed per snapshot.
        assert_eq!(
            proxy_capabilities(true).without(CapabilityFlags::SSL),
            proxy_capabilities(false),
        );
    }

    #[test]
    fn leading_capabilities_reads_the_ssl_bit() {
        // A strict 32-byte SSLRequest with SSL set classifies as SSL.
        let ssl_request = encode_ssl_request(
            CapabilityFlags::PROTOCOL_41 | CapabilityFlags::SSL,
            0x0100_0000,
            45,
        );
        assert!(leading_capabilities(&ssl_request).contains(CapabilityFlags::SSL));
        assert!(parse_ssl_request(&ssl_request).is_ok());

        // A plaintext-first packet without the SSL bit does not.
        let plain = encode_ssl_request(CapabilityFlags::PROTOCOL_41, 0x0100_0000, 45);
        assert!(!leading_capabilities(&plain).contains(CapabilityFlags::SSL));

        // A truncated leading window carries no SSL bit and falls through to
        // the (fail-closed) handshake parser.
        assert!(!leading_capabilities(&[0xff, 0xff]).contains(CapabilityFlags::SSL));
        assert!(!leading_capabilities(&[]).contains(CapabilityFlags::SSL));
    }

    #[test]
    fn normalize_leading_capabilities_governs_layout_affecting_parse()
    -> Result<(), Box<dyn std::error::Error>> {
        // The real (trusted) client asked for CONNECT_WITH_DB, so the response
        // is laid out with a database field, encoded here per the trusted mask.
        let trusted = CapabilityFlags::PROTOCOL_41
            | CapabilityFlags::SECURE_CONNECTION
            | CapabilityFlags::CONNECT_WITH_DB
            | CapabilityFlags::PLUGIN_AUTH;
        let encoded = encode_handshake_response(HandshakeResponseParams {
            capabilities: trusted,
            max_packet_size: 0x0100_0000,
            collation: 45,
            username: b"alice",
            auth_response: b"\x01\x02\x03",
            database: Some(b"shop"),
            auth_plugin_name: Some(b"mysql_native_password"),
            attributes: None,
            zstd_level: None,
        })?;

        // Simulate a hostile in-TLS second packet whose leading mask drops
        // CONNECT_WITH_DB — a layout-affecting mismatch. Parsing the SAME bytes
        // under that untrusted mask misreads the layout: no database, and the
        // "shop" bytes are consumed as the auth plugin name.
        let untrusted = trusted.without(CapabilityFlags::CONNECT_WITH_DB);
        let mut hostile = encoded.clone();
        hostile[0..4].copy_from_slice(&untrusted.bits().to_le_bytes());
        assert_eq!(leading_capabilities(&hostile), untrusted);
        let misread = parse_handshake_response(&hostile)?;
        assert_eq!(
            misread.database, None,
            "untrusted layout drops the database"
        );
        assert_eq!(
            misread.auth_plugin_name,
            Some(b"shop".as_ref()),
            "untrusted layout misreads the database bytes as the plugin name"
        );

        // Normalizing the leading bytes back to the trusted mask restores the
        // real layout: the database and plugin parse correctly.
        normalize_leading_capabilities(&mut hostile, trusted);
        assert_eq!(leading_capabilities(&hostile), trusted);
        let fixed = parse_handshake_response(&hostile)?;
        assert_eq!(fixed.capabilities, trusted);
        assert_eq!(fixed.database, Some(b"shop".as_ref()));
        assert_eq!(
            fixed.auth_plugin_name,
            Some(b"mysql_native_password".as_ref())
        );
        assert_eq!(fixed.username, b"alice");
        // A short payload is left untouched (it fails the subsequent parse).
        let mut short = [1_u8, 2, 3];
        normalize_leading_capabilities(&mut short, trusted);
        assert_eq!(short, [1, 2, 3]);
        Ok(())
    }

    #[test]
    fn backend_server_name_is_the_host_without_port_or_brackets() {
        assert_eq!(
            backend_server_name("tidb.example.com:4000"),
            "tidb.example.com"
        );
        assert_eq!(backend_server_name("127.0.0.1:4000"), "127.0.0.1");
        assert_eq!(backend_server_name("[::1]:4000"), "::1");
        // A bare host with no port is used verbatim.
        assert_eq!(backend_server_name("localhost"), "localhost");
    }

    #[test]
    fn migration_candidate_deadline_is_always_bounded() {
        assert_eq!(candidate_budget(0), super::DialSchedule::default().total);
        assert!(
            candidate_budget(1).is_zero(),
            "an already-expired absolute deadline cannot start candidate I/O"
        );
    }

    #[test]
    fn migration_token_length_governs_lenenc_independent_of_backend_advertisement()
    -> Result<(), super::CandidateFailure> {
        let planned = CapabilityFlags::PROTOCOL_41
            | CapabilityFlags::CONNECT_WITH_DB
            | CapabilityFlags::PLUGIN_AUTH_LENENC_CLIENT_DATA;
        let backend = CapabilityFlags::PROTOCOL_41 | CapabilityFlags::CONNECT_WITH_DB;

        let short = migration_auth_capabilities(planned, backend, true, 250)?;
        assert!(short.contains(CapabilityFlags::PLUGIN_AUTH));
        assert!(short.contains(CapabilityFlags::CONNECT_WITH_DB));
        assert!(
            !short.contains(CapabilityFlags::PLUGIN_AUTH_LENENC_CLIENT_DATA),
            "the Go-compatible boundary uses secure-connection encoding at 250 bytes"
        );

        let long = migration_auth_capabilities(planned, backend, true, 251)?;
        assert!(long.contains(CapabilityFlags::PLUGIN_AUTH));
        assert!(long.contains(CapabilityFlags::CONNECT_WITH_DB));
        assert!(
            long.contains(CapabilityFlags::PLUGIN_AUTH_LENENC_CLIENT_DATA),
            "Go forces length-encoded auth data above 250 bytes"
        );
        Ok(())
    }

    #[test]
    fn migration_database_capability_follows_the_authoritative_snapshot()
    -> Result<(), super::CandidateFailure> {
        let planned = CapabilityFlags::PROTOCOL_41 | CapabilityFlags::CONNECT_WITH_DB;
        let backend = CapabilityFlags::PROTOCOL_41 | CapabilityFlags::CONNECT_WITH_DB;

        let cleared = migration_auth_capabilities(planned, backend, false, 32)?;
        assert!(!cleared.contains(CapabilityFlags::CONNECT_WITH_DB));

        let unsupported = migration_auth_capabilities(
            planned,
            backend.without(CapabilityFlags::CONNECT_WITH_DB),
            true,
            32,
        );
        assert!(
            unsupported.is_err(),
            "a restored database fails closed when the candidate cannot encode it"
        );
        Ok(())
    }
}
