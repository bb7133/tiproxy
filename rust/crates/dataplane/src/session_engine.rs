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
//! protocol violation and closes the session. `COM_CHANGE_USER` and
//! `COM_STMT_PREPARE` (the prepared special response flow) are
//! answered with a fixed unsupported error and the session closes. A
//! control redirect reports `NotifyRedirectFailed` fail-closed (the
//! gate terminal is exact and the session keeps its backend — Go's
//! refused-migration behavior); safe-boundary migration via
//! session-state transfer is the follow-up slice.

use std::sync::Arc;
use std::time::Duration;

use control_proto::control_transport::ControlClient;
use control_proto::v1::control_envelope::Body;
use control_proto::v1::{
    ConnectionIdentity, ControlEnvelope, ErrorCode, ErrorSource as WireErrorSource,
    HandshakeMetadata, HandshakeResponseEvent, Priority, RouteAssignment, RouteRequest,
    RouteResult,
};
use mysql_wire::{
    CapabilityFlags, CommandPacket, HandshakeResponseParams, StatusFlags, encode_error_packet,
    encode_handshake_response, encode_initial_handshake, parse_handshake_response,
};
use proxy_io::{PacketReader, PacketWriter};
use session_core::auth::{
    AuthEffect, AuthEvent, AuthOutcome, AuthRelay, AuthTurn, UNKNOWN_AUTH_PLUGIN,
    classify_backend_auth_packet, plan_backend_handshake,
};
use session_core::command::{
    Command, CommandSessionState, CommandStateEffects, ExpectedResponse, SessionMutation, dispatch,
};
use session_core::error_source::FailureKind;
use session_core::fsm::{SessionEffect, SessionEvent};
use session_core::handshake::{
    ConnectionEndpoints, build_greeting, greeting_capability, negotiate_frontend, verify_backend,
};
use session_core::prepared::PreparedRegistry;
use session_core::response::{
    DEFAULT_RESPONSE_FLUSH_THRESHOLD, FlushAction, ResponseDisposition, ResponseObserver,
    ResponsePacket,
};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinSet;

use crate::control_dispatch::{CommandKind, CommandToken, ResponseKind};
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
/// Fixed error for the fail-closed `COM_STMT_PREPARE` slice boundary.
const ER_STMT_PREPARE_UNSUPPORTED: (u16, [u8; 5], &str) = (
    1105,
    *b"HY000",
    "TiProxy-rs: COM_STMT_PREPARE is not supported yet",
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
        prepared: PreparedRegistry::new(),
        pending_command: None,
        wire_end: None,
        quit_source: QuitSource::None,
        closing: false,
        accepted_at,
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
    reader: PacketReader<OwnedReadHalf>,
    writer: PacketWriter<OwnedWriteHalf>,
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
    /// SES-00 prepared-statement registry: long-data/cursor guards
    /// synchronize into the FSM before command-completion boundaries.
    prepared: PreparedRegistry,
    pending_command: Option<PendingCommand>,
    wire_end: Option<WireErrorSource>,
    quit_source: QuitSource,
    closing: bool,
    accepted_at: tokio::time::Instant,
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

        // Client handshake response (no TLS negotiated: an SSLRequest
        // is a protocol violation against our greeting).
        let payload = match self.client_r.read_logical(HANDSHAKE_PAYLOAD_LIMIT).await {
            Ok(packet) => packet.payload,
            Err(error) => return Some(self.client_read_end(&error).await),
        };
        let Ok(parsed) = parse_handshake_response(&payload) else {
            self.quit_source = QuitSource::ProxyMalformed;
            let _ = self.events.send(SessionEvent::ClientIoError).await;
            return Some(WireErrorSource::ClientNetwork);
        };
        let negotiation = match negotiate_frontend(parsed.capabilities, proxy_capabilities()) {
            Ok(negotiation) => negotiation,
            Err(missing) => {
                self.quit_source = QuitSource::ClientHandshake;
                let (code, state, message) = missing.client_response();
                self.client_w
                    .reset_sequence(self.client_r.expected_sequence());
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
            self.client_w
                .reset_sequence(self.client_r.expected_sequence());
            let _ = self.write_client_error(1105, *b"HY000", message).await;
            let _ = self.events.send(SessionEvent::ClientIoError).await;
            return Some(WireErrorSource::Proxy);
        }
        // The accepted decision names the namespace the Go handshake
        // handler RESOLVED for this connection — the routing truth.
        // Adopt it for the route conversation and every lifecycle/log
        // surface; the process seed was only the pre-decision default.
        let mut resolved_namespace = decision.namespace;
        resolved_namespace.truncate(255);
        if resolved_namespace.is_empty() {
            resolved_namespace = seed.namespace;
        }
        self.log_context.namespace.clone_from(&resolved_namespace);
        // The dispatcher's per-session record adopts it too, so CLOSED
        // events and reconciliation carry the routing truth on the wire.
        let _ = commander.set_namespace(resolved_namespace.clone()).await;
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
        let (backend_read, backend_write) = acquired.conn.into_split();
        let mut backend = BackendIo {
            reader: PacketReader::new(backend_read),
            writer: PacketWriter::new(backend_write),
            id: backend_id.clone(),
            address: backend_address,
            cluster: backend_cluster,
            local: backend_local,
        };
        let Ok(greeting_packet) = backend.reader.read_logical(HANDSHAKE_PAYLOAD_LIMIT).await else {
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
        if verify_backend(backend_caps, self.negotiated, proxy_capabilities(), false).is_err() {
            self.quit_source = QuitSource::BackendHandshake;
            let _ = self.events.send(SessionEvent::BackendIoError).await;
            return Some(WireErrorSource::BackendNetwork);
        }
        let Ok(plan) = plan_backend_handshake(&routing, backend_caps, false, false) else {
            self.quit_source = QuitSource::BackendHandshake;
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
                zstd_level: parsed.zstd_level,
            }) else {
                self.quit_source = QuitSource::ProxyMalformed;
                let _ = self.events.send(SessionEvent::ClientIoError).await;
                return Some(WireErrorSource::Proxy);
            };
            forwarded
        };
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
                self.quit_source = QuitSource::BackendHandshake;
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
                    let payload = match self.client_r.read_logical(HANDSHAKE_PAYLOAD_LIMIT).await {
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
        loop {
            if self.closing {
                return None;
            }
            // Every client command starts a fresh wire exchange at
            // sequence zero, and its response lineage answers at one.
            self.client_r.reset_sequence(0);
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
                        Awaited::Got => continue,
                    }
                }
                peeked = self.client_r.peek_packet() => {
                    if let Err(error) = peeked {
                        let source = self.client_read_end(&error).await;
                        return Some(source);
                    }
                    // The idle wait ends when the packet header becomes
                    // visible. Match Go's ExecuteCmd timer: include packet
                    // read/dispatch/response work, never connection idle time.
                    let started = tokio::time::Instant::now();
                    match self.client_r.read_logical(COMMAND_PAYLOAD_LIMIT).await {
                        Ok(packet) => (packet.payload, started),
                        Err(error) => {
                            let source = self.client_read_end(&error).await;
                            return Some(source);
                        }
                    }
                }
            };
            self.client_w.reset_sequence(1);
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
            if self.refuse_unsupported_command(command, expected).await {
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
            let response_source = self.response_rounds(&pending).await;
            self.record_command(&pending);
            if let Some(source) = response_source {
                return Some(source);
            }
            if self.closing {
                return None;
            }
        }
    }

    /// Answers the fail-closed slice boundaries before any forward:
    /// `COM_CHANGE_USER` and the prepared special response flow
    /// (`COM_STMT_PREPARE` column metadata, cursors) are follow-up
    /// slices — an explicit refusal, never a silent teardown.
    async fn refuse_unsupported_command(
        &mut self,
        command: Command,
        expected: ExpectedResponse,
    ) -> bool {
        let refusal = if command == Command::ChangeUser {
            Some(ER_CHANGE_USER_UNSUPPORTED)
        } else if expected == ExpectedResponse::Prepare {
            Some(ER_STMT_PREPARE_UNSUPPORTED)
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
        backend.writer.reset_sequence(0);
        backend.reader.reset_sequence(1);
        if backend
            .writer
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

    /// The client LOCAL INFILE upload until the empty terminator.
    async fn infile_rounds(&mut self) -> Option<WireErrorSource> {
        // The upload continues each side's exchange in lockstep: the
        // client's next chunk follows the forwarded infile request, and
        // the chunks forwarded to the backend follow its request packet.
        self.client_r.reset_sequence(self.client_w.next_sequence());
        if let Some(backend) = self.backend.as_mut() {
            backend
                .writer
                .reset_sequence(backend.reader.expected_sequence());
        }
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
                // The final backend response continues after the last
                // uploaded chunk on both sides of the relay.
                backend
                    .reader
                    .reset_sequence(backend.writer.next_sequence());
                self.client_w
                    .reset_sequence(self.client_r.expected_sequence());
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
                    self.client_w
                        .reset_sequence(self.client_r.expected_sequence());
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
                    backend
                        .writer
                        .reset_sequence(backend.reader.expected_sequence());
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

    fn backend_traffic(&self) -> BackendTraffic {
        self.backend
            .as_ref()
            .map_or(BackendTraffic::default(), |backend| BackendTraffic {
                inbound_bytes: backend.reader.in_bytes(),
                inbound_packets: backend.reader.in_packets(),
                outbound_bytes: backend.writer.out_bytes(),
                outbound_packets: backend.writer.out_packets(),
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
