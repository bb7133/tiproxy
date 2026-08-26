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
//! This slice serves the TLS-disabled, uncompressed path: the greeting
//! advertises neither SSL nor compression, so a compliant client never
//! negotiates them; an `SSLRequest` against a no-SSL greeting is a
//! protocol violation and closes the session. `COM_CHANGE_USER` is
//! answered with a fixed unsupported error and the session closes. A
//! control redirect reports `NotifyRedirectFailed` fail-closed (the
//! gate terminal is exact and the session keeps its backend — Go's
//! refused-migration behavior); safe-boundary migration via
//! session-state transfer is the follow-up slice.

use std::sync::Arc;

use control_proto::control_transport::ControlClient;
use control_proto::v1::control_envelope::Body;
use control_proto::v1::{
    ConnectionIdentity, ControlEnvelope, ErrorCode, ErrorSource as WireErrorSource,
    HandshakeMetadata, HandshakeResponseEvent, Priority, RouteAssignment, RouteRequest,
    RouteResult,
};
use mysql_wire::{
    CapabilityFlags, CommandPacket, StatusFlags, encode_error_packet, encode_initial_handshake,
    parse_handshake_response,
};
use proxy_io::{PacketReader, PacketWriter};
use session_core::auth::{
    AuthEffect, AuthEvent, AuthOutcome, AuthRelay, AuthTurn, classify_backend_auth_packet,
    plan_backend_handshake,
};
use session_core::command::{
    Command, CommandSessionState, CommandStateEffects, ExpectedResponse, SessionMutation, dispatch,
};
use session_core::error_source::FailureKind;
use session_core::fsm::{SessionEffect, SessionEvent};
use session_core::handshake::{
    ConnectionEndpoints, build_greeting, greeting_capability, negotiate_frontend, verify_backend,
};
use session_core::response::{
    DEFAULT_RESPONSE_FLUSH_THRESHOLD, FlushAction, ResponseDisposition, ResponseObserver,
    ResponsePacket,
};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinSet;

use crate::control_dispatch::{CommandKind, CommandToken, ResponseKind};
use crate::route::{CenteredJitter, DialSchedule, RouteChannel, RouteChannelError, RouteEngine};
use crate::route_control::{TcpDialer, TrafficTotals};
use crate::server::{AcceptedConnection, ConnectionFuture, SessionSeat};
use crate::session::{
    EffectHandler, SessionControl, SessionEnd, SessionEventSource, SessionLoop, SessionLoopConfig,
    SessionSummary,
};
use crate::session_control::{
    BoundSessionHandler, ResponseStream, SessionCommander, SessionControlBinding,
};

/// The proxy's advertised capability mask for this slice: Go's
/// handshake set without SSL (frontend TLS disabled here) and without
/// compression bits (never negotiated, so the relay's compression
/// effects are unreachable).
fn proxy_capabilities() -> CapabilityFlags {
    let base = CapabilityFlags::LONG_PASSWORD
        | CapabilityFlags::FOUND_ROWS
        | CapabilityFlags::LONG_FLAG
        | CapabilityFlags::CONNECT_WITH_DB
        | CapabilityFlags::NO_SCHEMA
        | CapabilityFlags::ODBC
        | CapabilityFlags::LOCAL_FILES
        | CapabilityFlags::IGNORE_SPACE
        | CapabilityFlags::PROTOCOL_41
        | CapabilityFlags::INTERACTIVE
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
        | CapabilityFlags::DEPRECATE_EOF;
    greeting_capability(base, false)
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

/// Commands into the engine task.
enum EngineCmd {
    /// Execute one FSM effect in order.
    Effect(SessionEffect),
    /// Idle-safe backend liveness probe (KA-003).
    Probe(oneshot::Sender<bool>),
}

/// Reports from the engine to the session owner.
#[derive(Debug)]
enum EngineReport {
    /// A redirect attempt finished.
    RedirectFinished {
        /// Whether the migration succeeded (always false this slice).
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
    force_closed: bool,
    source: WireErrorSource,
    backend_id: String,
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
    handshake_event_sent: bool,
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
        if !self.handshake_event_sent {
            // The Go adapter admits routing only for a connection whose
            // handshake event it has seen.
            self.send_durable(Body::HandshakeResponse(HandshakeResponseEvent {
                connection: Some(self.identity.clone()),
                handshake: Some(self.metadata.clone()),
            }))
            .await?;
            self.handshake_event_sent = true;
        }
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
    loop_config: SessionLoopConfig,
}

impl EngineSessionOwner {
    /// Builds the owner for the given control client and namespace.
    #[must_use]
    pub fn new(
        client: Arc<ControlClient>,
        namespace: impl Into<Arc<str>>,
        shutdown: watch::Receiver<bool>,
        loop_config: SessionLoopConfig,
    ) -> Self {
        Self {
            client,
            namespace: namespace.into(),
            shutdown,
            loop_config,
        }
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
        let config = self.loop_config;
        Box::pin(async move {
            run_bound_session(connection, binding, client, namespace, shutdown, config).await;
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
    loop_config: SessionLoopConfig,
) {
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
    let (mut directives, responses, commander) = binding.split();

    let (event_tx, event_rx) = mpsc::channel(1);
    let (cmd_tx, cmd_rx) = mpsc::channel(ENGINE_CMD_CAPACITY);
    let (report_tx, mut report_rx) = mpsc::channel(ENGINE_REPORT_CAPACITY);
    let (control_tx, control_rx) = mpsc::channel::<SessionControl>(8);

    let (read_half, write_half) = stream.into_split();
    let engine = Engine {
        connection_id: identity.connection_id,
        endpoints,
        client_r: PacketReader::new(read_half),
        client_w: PacketWriter::new(write_half),
        backend: None,
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
        pending_command: None,
        force_closed: false,
        wire_end: None,
        closing: false,
        _seat: seat,
    };

    let session_loop = SessionLoop::new(
        EventRx { events: event_rx },
        CmdTx {
            cmds: cmd_tx.clone(),
        },
        control_rx,
        shutdown,
        loop_config,
    );
    let mut loop_task = tokio::spawn(session_loop.run());
    let engine_task = tokio::spawn(engine.run());

    // The owner: forwards directives while holding the exact command
    // tokens, consumes engine reports, and waits for the loop.
    let mut redirect_token: Option<CommandToken> = None;
    let mut close_token: Option<CommandToken> = None;
    let mut directives_open = true;
    let summary: Option<SessionSummary> = loop {
        tokio::select! {
            joined = &mut loop_task => {
                break joined.ok();
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
    let engine_exit = engine_task.await.ok();
    while let Ok(report) = report_rx.try_recv() {
        consume_report(report, &commander, &mut redirect_token).await;
    }

    let totals = engine_exit
        .as_ref()
        .map(|exit| exit.totals)
        .unwrap_or_default();
    let forced = summary
        .as_ref()
        .is_some_and(|summary| summary.end == SessionEnd::ServerShutdown)
        || engine_exit.as_ref().is_some_and(|exit| exit.force_closed);
    let source = engine_exit
        .as_ref()
        .map_or(WireErrorSource::Proxy, |exit| exit.source);
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
    let _ = commander.session_closed(forced, source, totals).await;
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
    reader: PacketReader<OwnedReadHalf>,
    writer: PacketWriter<OwnedWriteHalf>,
    id: String,
}

/// One client command held between its event and the FSM's forward
/// authorization.
struct PendingCommand {
    payload: Vec<u8>,
    expected: ExpectedResponse,
}

/// The single owner of all session wire I/O.
struct Engine {
    connection_id: u64,
    endpoints: ConnectionEndpoints,
    client_r: PacketReader<OwnedReadHalf>,
    client_w: PacketWriter<OwnedWriteHalf>,
    backend: Option<BackendIo>,
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
    pending_command: Option<PendingCommand>,
    force_closed: bool,
    wire_end: Option<WireErrorSource>,
    closing: bool,
    _seat: SessionSeat,
}

/// Outcome of waiting for one specific FSM effect.
enum Awaited {
    /// The expected effect arrived (any others were handled inline).
    Got,
    /// Teardown began (or the loop is gone); abandon the wire phase.
    Closing,
}

impl Engine {
    async fn run(mut self) -> EngineExit {
        let end = self.lifecycle().await;
        if let Some(source) = end {
            self.wire_end.get_or_insert(source);
        }
        // Drain remaining effects so teardown commands (close/classify)
        // execute even after a wire failure ended the lifecycle early.
        while let Some(cmd) = self.cmds.recv().await {
            if matches!(self.handle_cmd(cmd).await, Awaited::Closing) && self.closing {
                // Keep draining: ClassifySessionEnd may still follow.
            }
        }
        self.shutdown_io().await;
        EngineExit {
            totals: self.totals(),
            force_closed: self.force_closed,
            source: self.wire_end.unwrap_or(WireErrorSource::ClientNetwork),
            backend_id: self
                .backend
                .as_ref()
                .map(|backend| backend.id.clone())
                .unwrap_or_default(),
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

        // Client handshake response (no TLS negotiated: an SSLRequest
        // is a protocol violation against our greeting).
        let payload = match self.client_r.read_logical(HANDSHAKE_PAYLOAD_LIMIT).await {
            Ok(packet) => packet.payload,
            Err(error) => return Some(self.client_read_end(&error).await),
        };
        let Ok(parsed) = parse_handshake_response(&payload) else {
            let _ = self.events.send(SessionEvent::ClientIoError).await;
            return Some(WireErrorSource::ClientNetwork);
        };
        let negotiation = match negotiate_frontend(parsed.capabilities, proxy_capabilities()) {
            Ok(negotiation) => negotiation,
            Err(missing) => {
                let (code, state, message) = missing.client_response();
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
            tls: false,
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
        let Some(seed) = self.route.take() else {
            return Some(WireErrorSource::Proxy);
        };
        let commander = seed.commander.clone();
        let channel = BindingRouteChannel {
            client: seed.client,
            commander: seed.commander,
            responses: seed.responses,
            identity: seed.identity,
            metadata,
            namespace: seed.namespace,
            handshake_event_sent: false,
        };
        let mut route_engine = RouteEngine::new(
            channel,
            TcpDialer,
            DialSchedule::default(),
            CenteredJitter,
            self.connection_id,
        );
        let Ok(acquired) = route_engine.acquire(Vec::new()).await else {
            let _ = self.events.send(SessionEvent::BackendIoError).await;
            return Some(WireErrorSource::Proxy);
        };
        let backend_id = acquired.backend.backend_id.clone();
        let (backend_read, backend_write) = acquired.conn.into_split();
        let mut backend = BackendIo {
            reader: PacketReader::new(backend_read),
            writer: PacketWriter::new(backend_write),
            id: backend_id.clone(),
        };
        let Ok(greeting_packet) = backend.reader.read_logical(HANDSHAKE_PAYLOAD_LIMIT).await else {
            let _ = self.events.send(SessionEvent::BackendIoError).await;
            return Some(WireErrorSource::BackendNetwork);
        };
        let greeting_payload = greeting_packet.payload;
        let Ok(backend_greeting) = mysql_wire::parse_initial_handshake(&greeting_payload) else {
            let _ = self.events.send(SessionEvent::BackendIoError).await;
            return Some(WireErrorSource::BackendNetwork);
        };
        let backend_caps = backend_greeting.capabilities;
        if verify_backend(backend_caps, self.negotiated, proxy_capabilities(), false).is_err() {
            let _ = self.events.send(SessionEvent::BackendIoError).await;
            return Some(WireErrorSource::BackendNetwork);
        }
        let Ok(plan) = plan_backend_handshake(&routing, backend_caps, false, false) else {
            let _ = self.events.send(SessionEvent::BackendIoError).await;
            return Some(WireErrorSource::Proxy);
        };
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
        // Forward the client's response re-scoped to the planned
        // capability mask: the raw payload is byte-preserved except the
        // leading capability word, exactly Go's rewrite.
        let mut forwarded = self.client_handshake_raw.clone();
        let planned = plan.capabilities.bits().to_le_bytes();
        if forwarded.len() >= 4 {
            forwarded[..4].copy_from_slice(&planned);
        }
        if let Some(backend) = self.backend.as_mut() {
            // Continue the backend channel's connection-phase counter
            // after its greeting.
            let next = backend.reader.expected_sequence();
            backend.writer.reset_sequence(next);
            if backend
                .writer
                .write_logical(&forwarded, true)
                .await
                .is_err()
            {
                let _ = self.events.send(SessionEvent::BackendIoError).await;
                return Some(WireErrorSource::BackendNetwork);
            }
        }

        // Engine-internal authentication relay; the FSM sees only the
        // terminal outcome.
        let mut relay = AuthRelay::new(self.negotiated, backend_caps, 0);
        let auth_outcome = loop {
            match relay.turn() {
                AuthTurn::AwaitingBackend => {
                    let payload = match self.backend_read(HANDSHAKE_PAYLOAD_LIMIT).await {
                        Ok(payload) => payload,
                        Err(source) => {
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
                            let _ = self.events.send(SessionEvent::BackendIoError).await;
                            return Some(WireErrorSource::BackendNetwork);
                        }
                    };
                    self.relay_hold = Some(payload);
                    let Ok(step) = relay.on_event(event) else {
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
                    let payload = match self.client_r.read_logical(HANDSHAKE_PAYLOAD_LIMIT).await {
                        Ok(packet) => packet.payload,
                        Err(error) => return Some(self.client_read_end(&error).await),
                    };
                    self.relay_hold = Some(payload);
                    let Ok(step) = relay.on_event(AuthEvent::ClientAuthResponse) else {
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
            }
            AuthOutcome::Failed(kind) => {
                let _ = self.events.send(SessionEvent::BackendAuthFailed).await;
                return Some(failure_source(kind));
            }
        }

        // Ready: the command/response phases until the wire or the FSM
        // ends the session.
        self.command_phase().await
    }

    /// Ready/command/response/infile phases.
    async fn command_phase(&mut self) -> Option<WireErrorSource> {
        loop {
            if self.closing {
                return None;
            }
            // Between commands: serve control effects and probes while
            // waiting for the next client command.
            let payload = tokio::select! {
                cmd = self.cmds.recv() => {
                    let cmd = cmd?;
                    match self.handle_cmd(cmd).await {
                        Awaited::Closing => return None,
                        Awaited::Got => continue,
                    }
                }
                read = self.client_r.read_logical(COMMAND_PAYLOAD_LIMIT) => {
                    match read {
                        Ok(packet) => packet.payload,
                        Err(error) => {
                            let source = self.client_read_end(&error).await;
                            return Some(source);
                        }
                    }
                }
            };
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
            if command == Command::ChangeUser {
                // Fail-closed slice boundary.
                let (code, state, message) = ER_CHANGE_USER_UNSUPPORTED;
                let _ = self.write_client_error(code, state, message).await;
                let _ = self.events.send(SessionEvent::ClientIoError).await;
                return Some(WireErrorSource::ClientNetwork);
            }
            let event = if command == Command::Quit {
                SessionEvent::ClientCommandQuit
            } else {
                SessionEvent::ClientCommand
            };
            self.pending_command = Some(PendingCommand { payload, expected });
            if self.events.send(event).await.is_err() {
                return Some(WireErrorSource::Proxy);
            }
            if event == SessionEvent::ClientCommandQuit {
                // Quit tears down: the FSM goes straight to Closing and
                // the teardown effects arrive; drain them here.
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
            if let Some(backend) = self.backend.as_mut() {
                if backend
                    .writer
                    .write_logical(&pending.payload, true)
                    .await
                    .is_err()
                {
                    let _ = self.events.send(SessionEvent::BackendIoError).await;
                    return Some(WireErrorSource::BackendNetwork);
                }
            } else {
                return Some(WireErrorSource::Proxy);
            }
            self.apply_command_mutations(&pending, false);

            if !pending.expected.waits_for_backend() {
                if self
                    .events
                    .send(SessionEvent::NoResponseCommandComplete)
                    .await
                    .is_err()
                {
                    return Some(WireErrorSource::Proxy);
                }
                continue;
            }
            if let Some(source) = self.response_rounds(&pending).await {
                return Some(source);
            }
            if self.closing {
                return None;
            }
        }
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
                let forwarded = backend
                    .reader
                    .forward_packet_to(&mut self.client_w, RESPONSE_CAPTURE)
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
            if !matches!(effect.flush, FlushAction::None) && self.client_w.flush().await.is_err() {
                let _ = self.events.send(SessionEvent::ClientIoError).await;
                return Some(WireErrorSource::ClientNetwork);
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
                ResponseDisposition::CompleteSuccess | ResponseDisposition::CompleteRaw => {
                    self.apply_command_mutations(pending, true);
                    return None;
                }
                ResponseDisposition::CompleteError { .. } => {
                    return None;
                }
            }
        }
    }

    /// The client LOCAL INFILE upload until the empty terminator.
    async fn infile_rounds(&mut self) -> Option<WireErrorSource> {
        loop {
            let payload = match self.client_r.read_logical(COMMAND_PAYLOAD_LIMIT).await {
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
            if backend.writer.write_logical(&payload, done).await.is_err() {
                let _ = self.events.send(SessionEvent::BackendIoError).await;
                return Some(WireErrorSource::BackendNetwork);
            }
            if done {
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
            EngineCmd::Effect(effect) => self.handle_effect(effect).await,
        }
    }

    async fn handle_effect(&mut self, effect: SessionEffect) -> Awaited {
        match effect {
            SessionEffect::BeginDrainTimer => Awaited::Got,
            SessionEffect::StartRedirectHandshake => {
                // Fail-closed slice: refuse the migration; the session
                // keeps its backend (Go's refused-migration path).
                let _ = self.events.send(SessionEvent::RedirectBackendFailed).await;
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
                    let _ = backend.writer.flush().await;
                }
                Awaited::Closing
            }
            SessionEffect::CloseClient => {
                self.closing = true;
                self.force_closed = true;
                let _ = self.client_w.flush().await;
                Awaited::Closing
            }
            SessionEffect::ClassifySessionEnd => {
                self.closing = true;
                self.wire_end.get_or_insert(WireErrorSource::Proxy);
                Awaited::Closing
            }
            SessionEffect::SwapBackend
            | SessionEffect::ActivateFrontendTls
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

    fn apply_command_mutations(&mut self, pending: &PendingCommand, success_stage: bool) {
        let Some(state) = self.cmd_state.as_mut() else {
            return;
        };
        // Re-derive the plan's mutations from the held payload: the
        // borrowed plan cannot outlive its packet, so mutations are
        // re-computed at their application point.
        let Ok(packet) = CommandPacket::decode(&pending.payload) else {
            return;
        };
        let Ok(plan) = dispatch(packet) else {
            return;
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
        let _ = pending;
    }

    async fn run_auth_effects(&mut self, effects: &[AuthEffect]) -> Result<(), WireErrorSource> {
        for effect in effects {
            match effect {
                AuthEffect::ForwardBackendToClient => {
                    let Some(payload) = self.relay_hold.take() else {
                        return Err(WireErrorSource::Proxy);
                    };
                    if self.client_w.write_logical(&payload, true).await.is_err() {
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
                    if backend.writer.write_logical(&payload, true).await.is_err() {
                        let _ = self.events.send(SessionEvent::BackendIoError).await;
                        return Err(WireErrorSource::BackendNetwork);
                    }
                }
                AuthEffect::ActivateClientCompression(
                    session_core::auth::CompressionSelection::None,
                )
                | AuthEffect::ActivateBackendCompression(
                    session_core::auth::CompressionSelection::None,
                ) => {}
                AuthEffect::ActivateClientCompression(_)
                | AuthEffect::ActivateBackendCompression(_)
                | AuthEffect::ReconnectBackend => {
                    // Compression is never negotiated (the greeting
                    // withholds it) and reconnect is never approved in
                    // this slice.
                    return Err(WireErrorSource::Proxy);
                }
            }
        }
        Ok(())
    }

    async fn send_greeting(&mut self) -> Result<(), WireErrorSource> {
        fill_salt(&mut self.salt);
        let params = build_greeting(
            proxy_capabilities(),
            &self.salt,
            SERVER_VERSION,
            self.connection_id,
            45,
            StatusFlags::from_bits_retain(0),
        );
        let Ok(encoded) = encode_initial_handshake(params) else {
            return Err(WireErrorSource::Proxy);
        };
        if self.client_w.write_logical(&encoded, true).await.is_err() {
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
        if self.client_w.write_logical(&encoded, true).await.is_err() {
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
        match backend.reader.read_logical(limit).await {
            Ok(packet) => Ok(packet.payload),
            Err(_) => Err(WireErrorSource::BackendNetwork),
        }
    }

    fn backend_alive(&mut self) -> bool {
        let Some(backend) = self.backend.as_mut() else {
            return false;
        };
        let mut probe = [0_u8; 1];
        match backend.reader.get_mut().try_read(&mut probe) {
            // Data outside a command or a clean EOF both mean the
            // backend is not idle-healthy.
            Ok(_) => false,
            Err(error) => error.kind() == std::io::ErrorKind::WouldBlock,
        }
    }

    async fn shutdown_io(&mut self) {
        let _ = self.client_w.flush().await;
        if let Some(backend) = self.backend.as_mut() {
            let _ = backend.writer.flush().await;
        }
    }

    fn totals(&self) -> TrafficTotals {
        TrafficTotals {
            client_in: self.client_r.in_bytes(),
            client_out: self.client_w.out_bytes(),
            backend_in: self
                .backend
                .as_ref()
                .map_or(0, |backend| backend.reader.in_bytes()),
            backend_out: self
                .backend
                .as_ref()
                .map_or(0, |backend| backend.writer.out_bytes()),
        }
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
    if getrandom::fill(&mut buffer).is_ok() {
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
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
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
