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

//! Pure session state machine: state plus event to effects (SES-00).
//!
//! The Go dataplane classifies packets by their first byte inside socket
//! code (`backend_conn_mgr.go`); this module replaces that with an explicit,
//! runtime-independent machine. Three contracts:
//!
//! 1. **Purity.** [`SessionFsm::on_event`] maps a classified event to a new
//!    state and a list of [`SessionEffect`]s. No I/O, no timers, no packet
//!    payloads — classification happens in the wire/transport layers, so
//!    `MySQL` payload bytes never enter this module.
//! 2. **Enumerability.** Every legal `(state, event, next-state)` triple is
//!    listed in [`TRANSITIONS`]; an exhaustive reachability test proves the
//!    machine and the table are exactly equal. Illegal pairs return the
//!    typed [`TransitionError`] and change nothing.
//! 3. **Single ownership.** All mutable session state lives inside
//!    [`SessionFsm`] behind `&mut self`; there is no interior mutability.
//!    Backend ownership is tracked explicitly: [`SessionEffect::AttachBackend`]
//!    requires no current owner, [`SessionEffect::SwapBackend`] replaces the
//!    owner atomically (session migration), and the exhaustive test proves
//!    two simultaneous owners are unreachable.
//!
//! Go-parity notes (from `backend_conn_mgr.go` and `authenticator.go`):
//! - The proxy **synthesizes** the greeting itself (own salt and proxy
//!   capability, Go `handshakeFirstTime`/`MakeInitialHandshake`); it does
//!   not relay a backend greeting. The backend is dialed only after the
//!   client's handshake response is accepted.
//! - Redirect and graceful close both wait for the transaction boundary
//!   (`finishedTxn`); graceful close wins over a pending redirect, and every
//!   accepted redirect signal is retired with **exactly one** result — a
//!   close from any pending state reports the failure synchronously, and a
//!   late target-handshake result is suppressed once (Go `ErrClosing` /
//!   `OnConnClosed` accounting).
//! - Migration is serialized with command execution (Go `processLock`), so
//!   client requests are illegal in [`SessionState::RedirectPending`]; the
//!   runtime queues them outside the machine. Go's narrow hold-and-replay
//!   (`needHoldRequest`: only an in-transaction `COM_QUERY`
//!   `BEGIN`/`START TRANSACTION` with no pending prepared statements,
//!   MIG-005) is deferred to SES-07 as a classified event refinement.
//! - A failed migration keeps the current backend attached.
//! - Graceful close before authentication closes immediately
//!   (Go `TestGracefulCloseBeforeHandshake`).
//!
//! State diagram (also in the crate README):
//!
//! ```text
//! Accept -> Greeting <-> SslRequest
//!             |  (client handshake response / dial backend)
//!             v
//!       FrontendHandshake -> BackendHandshake -> Ready <-> Command <-> Response
//!                                                  |          |           |
//!                                                  |          v           v
//!                                                  |     LocalInfile -> Response
//!                                                  v
//!                        （txn boundary）RedirectPending -> Ready
//!                                        Draining ----------> Closing -> Closed
//! ```

use core::fmt;

/// Session lifecycle states, mirroring the SES-00 scope list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SessionState {
    /// Transport accepted; PROXY/TLS sniffing not finished.
    Accept,
    /// The proxy-synthesized greeting was sent; waiting for the client's
    /// `SSLRequest` or handshake response (Go `handshakeFirstTime`).
    Greeting,
    /// Client sent `SSLRequest`; frontend TLS activation in progress
    /// (returns to [`Self::Greeting`] for the real handshake response).
    SslRequest,
    /// Client handshake response accepted; dialing the backend and waiting
    /// for its greeting.
    FrontendHandshake,
    /// Client credentials forwarded; initial backend authentication runs.
    BackendHandshake,
    /// Authenticated and idle; the backend owner is attached.
    Ready,
    /// A client command was forwarded; waiting for the backend to respond.
    Command,
    /// The backend response is streaming to the client.
    Response,
    /// `LOCAL INFILE` duplex: the client streams file data to the backend.
    LocalInfile,
    /// At a transaction boundary with a redirect in flight: the target
    /// backend handshake runs while the current owner stays attached.
    RedirectPending,
    /// Graceful close requested while a transaction is open; waiting for
    /// the boundary (or the drain deadline).
    Draining,
    /// Teardown in progress; stray traffic is tolerated without effects.
    Closing,
    /// Terminal. Every event is illegal; no effects can follow.
    Closed,
}

/// Classified session events: packets, control commands, timers, EOF, and
/// errors. Events carry no payload bytes by construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SessionEvent {
    /// Transport-level accept finished (PROXY/TLS sniff done).
    ConnectionAccepted,
    /// The initial backend greeting arrived.
    BackendGreetingReceived,
    /// The client answered the greeting with `SSLRequest`.
    ClientSslRequest,
    /// Frontend TLS activation completed.
    TlsActivated,
    /// The client handshake (auth) response arrived.
    ClientHandshakeResponse,
    /// The backend accepted authentication.
    BackendAuthOk,
    /// The backend rejected authentication.
    BackendAuthFailed,
    /// A regular client command arrived.
    ClientCommand,
    /// The client sent `COM_QUIT`.
    ClientCommandQuit,
    /// A non-final backend response chunk arrived.
    BackendResponsePart,
    /// The backend response completed with the transaction finished.
    BackendResponseTxnDone,
    /// The backend response completed with the transaction still open.
    BackendResponseTxnOpen,
    /// The backend requested `LOCAL INFILE` data from the client.
    BackendLocalInfileRequest,
    /// A non-final client `LOCAL INFILE` chunk arrived.
    ClientInfileChunk,
    /// The client finished the `LOCAL INFILE` stream (empty packet).
    ClientInfileEnd,
    /// Control plane: migrate this session to a new backend.
    ControlRedirect,
    /// Control plane: close gracefully at the next safe boundary.
    ControlGracefulClose,
    /// Control plane: close immediately.
    ControlCloseImmediate,
    /// The redirect target finished its handshake and can take over.
    RedirectBackendReady,
    /// The redirect target handshake failed; keep the current backend.
    RedirectBackendFailed,
    /// The client connection reached EOF.
    ClientEof,
    /// The backend connection reached EOF.
    BackendEof,
    /// The client connection failed with an I/O error.
    ClientIoError,
    /// The backend connection failed with an I/O error.
    BackendIoError,
    /// The handshake deadline expired (armed only before `Ready`).
    HandshakeTimerExpired,
    /// The drain deadline expired (armed by [`SessionEffect::BeginDrainTimer`]).
    DrainTimerExpired,
    /// The runtime finished tearing both connections down.
    TeardownComplete,
}

/// Side-effect instructions returned to the runtime; the machine itself
/// performs no I/O.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionEffect {
    /// Send the proxy-synthesized greeting to the client (own salt and
    /// proxy capability; Go `MakeInitialHandshake`).
    SendProxyGreeting,
    /// Dial the initial backend (candidate, not owner) after the client
    /// handshake response is accepted.
    DialBackend,
    /// Run the frontend TLS handshake.
    ActivateFrontendTls,
    /// Forward the client handshake response to the backend.
    ForwardHandshakeToBackend,
    /// Relay the backend authentication result to the client.
    ForwardAuthResultToClient,
    /// The authenticated backend becomes the sole owner (requires none).
    AttachBackend,
    /// Replace the owner with the redirect target atomically (migration).
    SwapBackend,
    /// Release the backend owner (teardown).
    ReleaseBackend,
    /// Forward the pending client command to the backend owner.
    ForwardCommandToBackend,
    /// Forward backend response data to the client.
    ForwardResponseToClient,
    /// Relay the backend `LOCAL INFILE` request to the client.
    RequestLocalInfileFromClient,
    /// Forward a client `LOCAL INFILE` chunk to the backend.
    ForwardInfileChunkToBackend,
    /// Forward the `LOCAL INFILE` terminator to the backend.
    ForwardInfileEndToBackend,
    /// Dial and authenticate the redirect target (candidate, not owner).
    StartRedirectHandshake,
    /// Report a successful migration to the control plane.
    NotifyRedirectSucceeded,
    /// Report a failed or refused migration to the control plane.
    NotifyRedirectFailed,
    /// Arm the drain deadline for a graceful close in progress.
    BeginDrainTimer,
    /// Close the client connection.
    CloseClient,
    /// Close the backend connection.
    CloseBackend,
    /// Classify the session end via `error_source` and report it.
    ClassifySessionEnd,
}

/// Typed rejection for an illegal `(state, event)` pair. Carries only the
/// pair — never payload bytes or connection detail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransitionError {
    /// The state the machine was in.
    pub state: SessionState,
    /// The event that is not legal in that state.
    pub event: SessionEvent,
}

impl fmt::Display for TransitionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "illegal session event {:?} in state {:?}",
            self.event, self.state
        )
    }
}

impl std::error::Error for TransitionError {}

/// Extended-state flags; exposed read-only for observability and tests.
#[expect(
    clippy::struct_excessive_bools,
    reason = "these are six independent extended-state dimensions of the \
              model; folding them into nested enums would obscure the \
              reachable-space enumeration the model test performs"
)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct SessionFlags {
    /// Authentication with the initial backend succeeded.
    pub authenticated: bool,
    /// Exactly one backend owner is attached.
    pub backend_owner: bool,
    /// The last completed response left a transaction open.
    pub in_txn: bool,
    /// A control-plane redirect awaits the next transaction boundary.
    pub redirect_pending: bool,
    /// A graceful close awaits the next transaction boundary.
    pub draining: bool,
    /// The session closed while a target handshake was in flight: its
    /// failure was already reported, so the one late result is suppressed.
    pub late_redirect_result: bool,
}

/// The pure session machine: the single owner of mutable session state.
///
/// `Clone` produces an independent value (used by the exhaustive model
/// test); it does not share mutable state.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct SessionFsm {
    state: SessionState,
    flags: SessionFlags,
}

impl Default for SessionState {
    fn default() -> Self {
        Self::Accept
    }
}

/// Effects produced by one transition, in execution order.
pub type Effects = Vec<SessionEffect>;

impl SessionFsm {
    /// A fresh session in [`SessionState::Accept`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The current state.
    #[must_use]
    pub const fn state(&self) -> SessionState {
        self.state
    }

    /// The current extended-state flags.
    #[must_use]
    pub const fn flags(&self) -> SessionFlags {
        self.flags
    }

    /// Applies one classified event.
    ///
    /// # Errors
    ///
    /// Returns [`TransitionError`] for an illegal `(state, event)` pair; the
    /// machine is unchanged and no effects are produced.
    pub fn on_event(&mut self, event: SessionEvent) -> Result<Effects, TransitionError> {
        let outcome = match self.state {
            SessionState::Accept => self.on_accept(event),
            SessionState::Greeting => self.on_greeting(event),
            SessionState::SslRequest => self.on_ssl_request(event),
            SessionState::FrontendHandshake => self.on_frontend_handshake(event),
            SessionState::BackendHandshake => self.on_backend_handshake(event),
            SessionState::Ready => self.on_ready(event),
            SessionState::Command => self.on_command(event),
            SessionState::Response => self.on_response(event),
            SessionState::LocalInfile => self.on_local_infile(event),
            SessionState::RedirectPending => self.on_redirect_pending(event),
            SessionState::Draining => self.on_draining(event),
            SessionState::Closing => self.on_closing(event),
            SessionState::Closed => None,
        };
        match outcome {
            Some((next, effects)) => {
                self.state = next;
                Ok(effects)
            }
            None => Err(TransitionError {
                state: self.state,
                event,
            }),
        }
    }

    /// Teardown effect sequence: retire a pending redirect with its one
    /// failure result, release the owner if attached, close both sides, and
    /// classify the session end.
    fn teardown(&mut self) -> Effects {
        let mut effects = Effects::new();
        if self.flags.redirect_pending {
            self.flags.redirect_pending = false;
            effects.push(SessionEffect::NotifyRedirectFailed);
        }
        if self.flags.backend_owner {
            self.flags.backend_owner = false;
            effects.push(SessionEffect::ReleaseBackend);
        }
        effects.push(SessionEffect::CloseBackend);
        effects.push(SessionEffect::CloseClient);
        effects.push(SessionEffect::ClassifySessionEnd);
        effects
    }

    fn on_accept(&mut self, event: SessionEvent) -> Option<(SessionState, Effects)> {
        match event {
            SessionEvent::ConnectionAccepted => Some((
                SessionState::Greeting,
                vec![SessionEffect::SendProxyGreeting],
            )),
            // Go parity: graceful close before the handshake finishes
            // closes immediately (`TestGracefulCloseBeforeHandshake`).
            SessionEvent::ClientEof
            | SessionEvent::ClientIoError
            | SessionEvent::ControlGracefulClose
            | SessionEvent::ControlCloseImmediate
            | SessionEvent::HandshakeTimerExpired => Some((SessionState::Closing, self.teardown())),
            _ => None,
        }
    }

    // No backend exists before the client handshake response is accepted
    // (Go dials in `handshakeFirstTime` only after `HandleHandshakeResp`),
    // so backend events are illegal in `Greeting` and `SslRequest`.
    fn on_greeting(&mut self, event: SessionEvent) -> Option<(SessionState, Effects)> {
        match event {
            SessionEvent::ClientSslRequest => Some((
                SessionState::SslRequest,
                vec![SessionEffect::ActivateFrontendTls],
            )),
            SessionEvent::ClientHandshakeResponse => Some((
                SessionState::FrontendHandshake,
                vec![SessionEffect::DialBackend],
            )),
            // Go parity: graceful close before the handshake finishes
            // closes immediately (`TestGracefulCloseBeforeHandshake`).
            SessionEvent::ClientEof
            | SessionEvent::ClientIoError
            | SessionEvent::ControlGracefulClose
            | SessionEvent::ControlCloseImmediate
            | SessionEvent::HandshakeTimerExpired => Some((SessionState::Closing, self.teardown())),
            _ => None,
        }
    }

    fn on_ssl_request(&mut self, event: SessionEvent) -> Option<(SessionState, Effects)> {
        match event {
            SessionEvent::TlsActivated => Some((SessionState::Greeting, Effects::new())),
            // Go parity: graceful close before the handshake finishes
            // closes immediately (`TestGracefulCloseBeforeHandshake`).
            SessionEvent::ClientEof
            | SessionEvent::ClientIoError
            | SessionEvent::ControlGracefulClose
            | SessionEvent::ControlCloseImmediate
            | SessionEvent::HandshakeTimerExpired => Some((SessionState::Closing, self.teardown())),
            _ => None,
        }
    }

    fn on_frontend_handshake(&mut self, event: SessionEvent) -> Option<(SessionState, Effects)> {
        match event {
            SessionEvent::BackendGreetingReceived => Some((
                SessionState::BackendHandshake,
                vec![SessionEffect::ForwardHandshakeToBackend],
            )),
            SessionEvent::ClientEof
            | SessionEvent::ClientIoError
            | SessionEvent::BackendEof
            | SessionEvent::BackendIoError
            | SessionEvent::ControlGracefulClose
            | SessionEvent::ControlCloseImmediate
            | SessionEvent::HandshakeTimerExpired => Some((SessionState::Closing, self.teardown())),
            _ => None,
        }
    }

    fn on_backend_handshake(&mut self, event: SessionEvent) -> Option<(SessionState, Effects)> {
        match event {
            SessionEvent::BackendAuthOk => {
                self.flags.authenticated = true;
                self.flags.backend_owner = true;
                Some((
                    SessionState::Ready,
                    vec![
                        SessionEffect::AttachBackend,
                        SessionEffect::ForwardAuthResultToClient,
                    ],
                ))
            }
            SessionEvent::BackendAuthFailed => {
                let mut effects = vec![SessionEffect::ForwardAuthResultToClient];
                effects.extend(self.teardown());
                Some((SessionState::Closing, effects))
            }
            SessionEvent::ClientEof
            | SessionEvent::ClientIoError
            | SessionEvent::BackendEof
            | SessionEvent::BackendIoError
            | SessionEvent::ControlGracefulClose
            | SessionEvent::ControlCloseImmediate
            | SessionEvent::HandshakeTimerExpired => Some((SessionState::Closing, self.teardown())),
            _ => None,
        }
    }

    fn on_ready(&mut self, event: SessionEvent) -> Option<(SessionState, Effects)> {
        match event {
            SessionEvent::ClientCommand => Some((
                SessionState::Command,
                vec![SessionEffect::ForwardCommandToBackend],
            )),
            SessionEvent::ControlRedirect => {
                // Go parity: the control plane keeps one outstanding signal
                // per session ("won't be notified again before
                // OnRedirectSucceed"), so a duplicate is illegal.
                if self.flags.redirect_pending {
                    return None;
                }
                self.flags.redirect_pending = true;
                if self.flags.in_txn {
                    // Go parity: wait for the transaction boundary.
                    Some((SessionState::Ready, Effects::new()))
                } else {
                    Some((
                        SessionState::RedirectPending,
                        vec![SessionEffect::StartRedirectHandshake],
                    ))
                }
            }
            SessionEvent::ControlGracefulClose => {
                if self.flags.in_txn {
                    self.flags.draining = true;
                    Some((SessionState::Draining, vec![SessionEffect::BeginDrainTimer]))
                } else {
                    Some((SessionState::Closing, self.teardown()))
                }
            }
            SessionEvent::ClientCommandQuit
            | SessionEvent::ControlCloseImmediate
            | SessionEvent::ClientEof
            | SessionEvent::ClientIoError
            | SessionEvent::BackendEof
            | SessionEvent::BackendIoError => Some((SessionState::Closing, self.teardown())),
            _ => None,
        }
    }

    /// Shared response-boundary handling for `Command` and `Response`.
    fn response_complete(&mut self, txn_done: bool) -> (SessionState, Effects) {
        self.flags.in_txn = !txn_done;
        let mut effects = vec![SessionEffect::ForwardResponseToClient];
        if txn_done && self.flags.draining {
            // Go parity: graceful close wins over a pending redirect;
            // `teardown` reports the refused redirect as failed.
            effects.extend(self.teardown());
            return (SessionState::Closing, effects);
        }
        if txn_done && self.flags.redirect_pending {
            effects.push(SessionEffect::StartRedirectHandshake);
            return (SessionState::RedirectPending, effects);
        }
        if self.flags.draining {
            // Transaction still open: keep waiting at the drain deadline.
            return (SessionState::Draining, effects);
        }
        (SessionState::Ready, effects)
    }

    fn on_command(&mut self, event: SessionEvent) -> Option<(SessionState, Effects)> {
        match event {
            SessionEvent::BackendResponsePart => Some((
                SessionState::Response,
                vec![SessionEffect::ForwardResponseToClient],
            )),
            SessionEvent::BackendResponseTxnDone => Some(self.response_complete(true)),
            SessionEvent::BackendResponseTxnOpen => Some(self.response_complete(false)),
            SessionEvent::BackendLocalInfileRequest => Some((
                SessionState::LocalInfile,
                vec![SessionEffect::RequestLocalInfileFromClient],
            )),
            SessionEvent::ControlRedirect => {
                // Duplicate signals are illegal (one outstanding per session).
                if self.flags.redirect_pending {
                    return None;
                }
                self.flags.redirect_pending = true;
                Some((SessionState::Command, Effects::new()))
            }
            SessionEvent::ControlGracefulClose => {
                self.flags.draining = true;
                Some((SessionState::Command, vec![SessionEffect::BeginDrainTimer]))
            }
            SessionEvent::ControlCloseImmediate
            | SessionEvent::ClientEof
            | SessionEvent::ClientIoError
            | SessionEvent::BackendEof
            | SessionEvent::BackendIoError => Some((SessionState::Closing, self.teardown())),
            SessionEvent::DrainTimerExpired => self.drain_deadline(),
            _ => None,
        }
    }

    /// The drain deadline is legal only while a graceful close armed it.
    fn drain_deadline(&mut self) -> Option<(SessionState, Effects)> {
        if self.flags.draining {
            Some((SessionState::Closing, self.teardown()))
        } else {
            None
        }
    }

    fn on_response(&mut self, event: SessionEvent) -> Option<(SessionState, Effects)> {
        match event {
            SessionEvent::BackendResponsePart => Some((
                SessionState::Response,
                vec![SessionEffect::ForwardResponseToClient],
            )),
            // A later statement in a multi-result COM_QUERY may request
            // LOCAL INFILE after an earlier result already moved the session
            // from Command to Response.
            SessionEvent::BackendLocalInfileRequest => Some((
                SessionState::LocalInfile,
                vec![SessionEffect::RequestLocalInfileFromClient],
            )),
            SessionEvent::BackendResponseTxnDone => Some(self.response_complete(true)),
            SessionEvent::BackendResponseTxnOpen => Some(self.response_complete(false)),
            SessionEvent::ControlRedirect => {
                // Duplicate signals are illegal (one outstanding per session).
                if self.flags.redirect_pending {
                    return None;
                }
                self.flags.redirect_pending = true;
                Some((SessionState::Response, Effects::new()))
            }
            SessionEvent::ControlGracefulClose => {
                self.flags.draining = true;
                Some((SessionState::Response, vec![SessionEffect::BeginDrainTimer]))
            }
            SessionEvent::ControlCloseImmediate
            | SessionEvent::ClientEof
            | SessionEvent::ClientIoError
            | SessionEvent::BackendEof
            | SessionEvent::BackendIoError => Some((SessionState::Closing, self.teardown())),
            SessionEvent::DrainTimerExpired => self.drain_deadline(),
            _ => None,
        }
    }

    fn on_local_infile(&mut self, event: SessionEvent) -> Option<(SessionState, Effects)> {
        match event {
            SessionEvent::ClientInfileChunk => Some((
                SessionState::LocalInfile,
                vec![SessionEffect::ForwardInfileChunkToBackend],
            )),
            SessionEvent::ClientInfileEnd => Some((
                SessionState::Response,
                vec![SessionEffect::ForwardInfileEndToBackend],
            )),
            SessionEvent::ControlRedirect => {
                // Duplicate signals are illegal (one outstanding per session).
                if self.flags.redirect_pending {
                    return None;
                }
                self.flags.redirect_pending = true;
                Some((SessionState::LocalInfile, Effects::new()))
            }
            SessionEvent::ControlGracefulClose => {
                self.flags.draining = true;
                Some((
                    SessionState::LocalInfile,
                    vec![SessionEffect::BeginDrainTimer],
                ))
            }
            SessionEvent::ControlCloseImmediate
            | SessionEvent::ClientEof
            | SessionEvent::ClientIoError
            | SessionEvent::BackendEof
            | SessionEvent::BackendIoError => Some((SessionState::Closing, self.teardown())),
            SessionEvent::DrainTimerExpired => self.drain_deadline(),
            _ => None,
        }
    }

    fn on_redirect_pending(&mut self, event: SessionEvent) -> Option<(SessionState, Effects)> {
        match event {
            SessionEvent::RedirectBackendReady => {
                self.flags.redirect_pending = false;
                Some((
                    SessionState::Ready,
                    vec![
                        SessionEffect::SwapBackend,
                        SessionEffect::NotifyRedirectSucceeded,
                    ],
                ))
            }
            SessionEvent::RedirectBackendFailed => {
                // Go parity: keep the current backend attached.
                self.flags.redirect_pending = false;
                Some((
                    SessionState::Ready,
                    vec![SessionEffect::NotifyRedirectFailed],
                ))
            }
            // Migration is serialized with command execution (Go
            // `processLock`), so client requests here are illegal; the
            // runtime queues them outside the machine. Go's narrow
            // hold-and-replay of an in-transaction BEGIN (MIG-005,
            // `needHoldRequest`) is a SES-07 refinement.
            SessionEvent::ControlGracefulClose
            | SessionEvent::ControlCloseImmediate
            | SessionEvent::ClientEof
            | SessionEvent::ClientIoError
            | SessionEvent::BackendEof
            | SessionEvent::BackendIoError => {
                // The target handshake is in flight: `teardown` reports the
                // failure now (exactly once) and the one late result is
                // suppressed in `Closing`.
                self.flags.late_redirect_result = true;
                Some((SessionState::Closing, self.teardown()))
            }
            // The drain deadline is never armed here: entering
            // `RedirectPending` requires a boundary with no close pending.
            _ => None,
        }
    }

    fn on_draining(&mut self, event: SessionEvent) -> Option<(SessionState, Effects)> {
        match event {
            SessionEvent::ClientCommand => Some((
                SessionState::Command,
                vec![SessionEffect::ForwardCommandToBackend],
            )),
            SessionEvent::ControlRedirect => {
                // Go parity: a redirect signal while closing is refused.
                Some((
                    SessionState::Draining,
                    vec![SessionEffect::NotifyRedirectFailed],
                ))
            }
            SessionEvent::ClientCommandQuit
            | SessionEvent::DrainTimerExpired
            | SessionEvent::ControlCloseImmediate
            | SessionEvent::ClientEof
            | SessionEvent::ClientIoError
            | SessionEvent::BackendEof
            | SessionEvent::BackendIoError => Some((SessionState::Closing, self.teardown())),
            _ => None,
        }
    }

    fn on_closing(&mut self, event: SessionEvent) -> Option<(SessionState, Effects)> {
        match event {
            SessionEvent::TeardownComplete => Some((SessionState::Closed, Effects::new())),
            // The in-flight migration's failure was already reported when
            // the close began, so the one late target-handshake result is
            // suppressed; a second result (or one without an in-flight
            // handshake) is illegal.
            SessionEvent::RedirectBackendReady | SessionEvent::RedirectBackendFailed => {
                if self.flags.late_redirect_result {
                    self.flags.late_redirect_result = false;
                    Some((SessionState::Closing, Effects::new()))
                } else {
                    None
                }
            }
            // A fresh redirect signal while closing is refused with its own
            // result (Go `ErrClosing`).
            SessionEvent::ControlRedirect => Some((
                SessionState::Closing,
                vec![SessionEffect::NotifyRedirectFailed],
            )),
            // In-flight traffic and repeated close signals are tolerated
            // without effects while tearing down.
            SessionEvent::ClientCommand
            | SessionEvent::ClientCommandQuit
            | SessionEvent::BackendResponsePart
            | SessionEvent::BackendResponseTxnDone
            | SessionEvent::BackendResponseTxnOpen
            | SessionEvent::BackendLocalInfileRequest
            | SessionEvent::ClientInfileChunk
            | SessionEvent::ClientInfileEnd
            | SessionEvent::ControlGracefulClose
            | SessionEvent::ControlCloseImmediate
            | SessionEvent::ClientEof
            | SessionEvent::BackendEof
            | SessionEvent::ClientIoError
            | SessionEvent::BackendIoError
            | SessionEvent::HandshakeTimerExpired
            | SessionEvent::DrainTimerExpired => Some((SessionState::Closing, Effects::new())),
            _ => None,
        }
    }
}

/// One legal transition: `from` × `event` → `to`. Flag-dependent branches
/// appear as separate rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Transition {
    /// Source state.
    pub from: SessionState,
    /// Triggering event.
    pub event: SessionEvent,
    /// Destination state.
    pub to: SessionState,
}

/// Shorthand for building [`TRANSITIONS`] rows.
const fn t(from: SessionState, event: SessionEvent, to: SessionState) -> Transition {
    Transition { from, event, to }
}

/// The complete legal transition relation. The exhaustive reachability test
/// proves this table and [`SessionFsm::on_event`] are exactly equal: every
/// row is reachable and no unlisted transition exists.
pub static TRANSITIONS: &[Transition] = &[
    // Accept
    t(
        SessionState::Accept,
        SessionEvent::ConnectionAccepted,
        SessionState::Greeting,
    ),
    t(
        SessionState::Accept,
        SessionEvent::ClientEof,
        SessionState::Closing,
    ),
    t(
        SessionState::Accept,
        SessionEvent::ClientIoError,
        SessionState::Closing,
    ),
    t(
        SessionState::Accept,
        SessionEvent::ControlCloseImmediate,
        SessionState::Closing,
    ),
    t(
        SessionState::Accept,
        SessionEvent::ControlGracefulClose,
        SessionState::Closing,
    ),
    t(
        SessionState::Accept,
        SessionEvent::HandshakeTimerExpired,
        SessionState::Closing,
    ),
    // Greeting
    t(
        SessionState::Greeting,
        SessionEvent::ClientSslRequest,
        SessionState::SslRequest,
    ),
    t(
        SessionState::Greeting,
        SessionEvent::ClientHandshakeResponse,
        SessionState::FrontendHandshake,
    ),
    t(
        SessionState::Greeting,
        SessionEvent::ClientEof,
        SessionState::Closing,
    ),
    t(
        SessionState::Greeting,
        SessionEvent::ClientIoError,
        SessionState::Closing,
    ),
    t(
        SessionState::Greeting,
        SessionEvent::ControlCloseImmediate,
        SessionState::Closing,
    ),
    t(
        SessionState::Greeting,
        SessionEvent::ControlGracefulClose,
        SessionState::Closing,
    ),
    t(
        SessionState::Greeting,
        SessionEvent::HandshakeTimerExpired,
        SessionState::Closing,
    ),
    // SslRequest
    t(
        SessionState::SslRequest,
        SessionEvent::TlsActivated,
        SessionState::Greeting,
    ),
    t(
        SessionState::SslRequest,
        SessionEvent::ClientEof,
        SessionState::Closing,
    ),
    t(
        SessionState::SslRequest,
        SessionEvent::ClientIoError,
        SessionState::Closing,
    ),
    t(
        SessionState::SslRequest,
        SessionEvent::ControlCloseImmediate,
        SessionState::Closing,
    ),
    t(
        SessionState::SslRequest,
        SessionEvent::ControlGracefulClose,
        SessionState::Closing,
    ),
    t(
        SessionState::SslRequest,
        SessionEvent::HandshakeTimerExpired,
        SessionState::Closing,
    ),
    // FrontendHandshake
    t(
        SessionState::FrontendHandshake,
        SessionEvent::BackendGreetingReceived,
        SessionState::BackendHandshake,
    ),
    t(
        SessionState::FrontendHandshake,
        SessionEvent::ClientEof,
        SessionState::Closing,
    ),
    t(
        SessionState::FrontendHandshake,
        SessionEvent::ClientIoError,
        SessionState::Closing,
    ),
    t(
        SessionState::FrontendHandshake,
        SessionEvent::BackendEof,
        SessionState::Closing,
    ),
    t(
        SessionState::FrontendHandshake,
        SessionEvent::BackendIoError,
        SessionState::Closing,
    ),
    t(
        SessionState::FrontendHandshake,
        SessionEvent::ControlCloseImmediate,
        SessionState::Closing,
    ),
    t(
        SessionState::FrontendHandshake,
        SessionEvent::ControlGracefulClose,
        SessionState::Closing,
    ),
    t(
        SessionState::FrontendHandshake,
        SessionEvent::HandshakeTimerExpired,
        SessionState::Closing,
    ),
    // BackendHandshake
    t(
        SessionState::BackendHandshake,
        SessionEvent::BackendAuthOk,
        SessionState::Ready,
    ),
    t(
        SessionState::BackendHandshake,
        SessionEvent::BackendAuthFailed,
        SessionState::Closing,
    ),
    t(
        SessionState::BackendHandshake,
        SessionEvent::ClientEof,
        SessionState::Closing,
    ),
    t(
        SessionState::BackendHandshake,
        SessionEvent::ClientIoError,
        SessionState::Closing,
    ),
    t(
        SessionState::BackendHandshake,
        SessionEvent::BackendEof,
        SessionState::Closing,
    ),
    t(
        SessionState::BackendHandshake,
        SessionEvent::BackendIoError,
        SessionState::Closing,
    ),
    t(
        SessionState::BackendHandshake,
        SessionEvent::ControlCloseImmediate,
        SessionState::Closing,
    ),
    t(
        SessionState::BackendHandshake,
        SessionEvent::ControlGracefulClose,
        SessionState::Closing,
    ),
    t(
        SessionState::BackendHandshake,
        SessionEvent::HandshakeTimerExpired,
        SessionState::Closing,
    ),
    // Ready
    t(
        SessionState::Ready,
        SessionEvent::ClientCommand,
        SessionState::Command,
    ),
    t(
        SessionState::Ready,
        SessionEvent::ClientCommandQuit,
        SessionState::Closing,
    ),
    t(
        SessionState::Ready,
        SessionEvent::ControlRedirect,
        SessionState::RedirectPending,
    ),
    t(
        SessionState::Ready,
        SessionEvent::ControlRedirect,
        SessionState::Ready,
    ),
    t(
        SessionState::Ready,
        SessionEvent::ControlGracefulClose,
        SessionState::Closing,
    ),
    t(
        SessionState::Ready,
        SessionEvent::ControlGracefulClose,
        SessionState::Draining,
    ),
    t(
        SessionState::Ready,
        SessionEvent::ControlCloseImmediate,
        SessionState::Closing,
    ),
    t(
        SessionState::Ready,
        SessionEvent::ClientEof,
        SessionState::Closing,
    ),
    t(
        SessionState::Ready,
        SessionEvent::ClientIoError,
        SessionState::Closing,
    ),
    t(
        SessionState::Ready,
        SessionEvent::BackendEof,
        SessionState::Closing,
    ),
    t(
        SessionState::Ready,
        SessionEvent::BackendIoError,
        SessionState::Closing,
    ),
    // Command
    t(
        SessionState::Command,
        SessionEvent::BackendResponsePart,
        SessionState::Response,
    ),
    t(
        SessionState::Command,
        SessionEvent::BackendResponseTxnDone,
        SessionState::Ready,
    ),
    t(
        SessionState::Command,
        SessionEvent::BackendResponseTxnDone,
        SessionState::RedirectPending,
    ),
    t(
        SessionState::Command,
        SessionEvent::BackendResponseTxnDone,
        SessionState::Closing,
    ),
    t(
        SessionState::Command,
        SessionEvent::BackendResponseTxnOpen,
        SessionState::Ready,
    ),
    t(
        SessionState::Command,
        SessionEvent::BackendResponseTxnOpen,
        SessionState::Draining,
    ),
    t(
        SessionState::Command,
        SessionEvent::BackendLocalInfileRequest,
        SessionState::LocalInfile,
    ),
    t(
        SessionState::Command,
        SessionEvent::ControlRedirect,
        SessionState::Command,
    ),
    t(
        SessionState::Command,
        SessionEvent::ControlGracefulClose,
        SessionState::Command,
    ),
    t(
        SessionState::Command,
        SessionEvent::ControlCloseImmediate,
        SessionState::Closing,
    ),
    t(
        SessionState::Command,
        SessionEvent::ClientEof,
        SessionState::Closing,
    ),
    t(
        SessionState::Command,
        SessionEvent::ClientIoError,
        SessionState::Closing,
    ),
    t(
        SessionState::Command,
        SessionEvent::BackendEof,
        SessionState::Closing,
    ),
    t(
        SessionState::Command,
        SessionEvent::BackendIoError,
        SessionState::Closing,
    ),
    t(
        SessionState::Command,
        SessionEvent::DrainTimerExpired,
        SessionState::Closing,
    ),
    // Response
    t(
        SessionState::Response,
        SessionEvent::BackendResponsePart,
        SessionState::Response,
    ),
    t(
        SessionState::Response,
        SessionEvent::BackendLocalInfileRequest,
        SessionState::LocalInfile,
    ),
    t(
        SessionState::Response,
        SessionEvent::BackendResponseTxnDone,
        SessionState::Ready,
    ),
    t(
        SessionState::Response,
        SessionEvent::BackendResponseTxnDone,
        SessionState::RedirectPending,
    ),
    t(
        SessionState::Response,
        SessionEvent::BackendResponseTxnDone,
        SessionState::Closing,
    ),
    t(
        SessionState::Response,
        SessionEvent::BackendResponseTxnOpen,
        SessionState::Ready,
    ),
    t(
        SessionState::Response,
        SessionEvent::BackendResponseTxnOpen,
        SessionState::Draining,
    ),
    t(
        SessionState::Response,
        SessionEvent::ControlRedirect,
        SessionState::Response,
    ),
    t(
        SessionState::Response,
        SessionEvent::ControlGracefulClose,
        SessionState::Response,
    ),
    t(
        SessionState::Response,
        SessionEvent::ControlCloseImmediate,
        SessionState::Closing,
    ),
    t(
        SessionState::Response,
        SessionEvent::ClientEof,
        SessionState::Closing,
    ),
    t(
        SessionState::Response,
        SessionEvent::ClientIoError,
        SessionState::Closing,
    ),
    t(
        SessionState::Response,
        SessionEvent::BackendEof,
        SessionState::Closing,
    ),
    t(
        SessionState::Response,
        SessionEvent::BackendIoError,
        SessionState::Closing,
    ),
    t(
        SessionState::Response,
        SessionEvent::DrainTimerExpired,
        SessionState::Closing,
    ),
    // LocalInfile
    t(
        SessionState::LocalInfile,
        SessionEvent::ClientInfileChunk,
        SessionState::LocalInfile,
    ),
    t(
        SessionState::LocalInfile,
        SessionEvent::ClientInfileEnd,
        SessionState::Response,
    ),
    t(
        SessionState::LocalInfile,
        SessionEvent::ControlRedirect,
        SessionState::LocalInfile,
    ),
    t(
        SessionState::LocalInfile,
        SessionEvent::ControlGracefulClose,
        SessionState::LocalInfile,
    ),
    t(
        SessionState::LocalInfile,
        SessionEvent::ControlCloseImmediate,
        SessionState::Closing,
    ),
    t(
        SessionState::LocalInfile,
        SessionEvent::ClientEof,
        SessionState::Closing,
    ),
    t(
        SessionState::LocalInfile,
        SessionEvent::ClientIoError,
        SessionState::Closing,
    ),
    t(
        SessionState::LocalInfile,
        SessionEvent::BackendEof,
        SessionState::Closing,
    ),
    t(
        SessionState::LocalInfile,
        SessionEvent::BackendIoError,
        SessionState::Closing,
    ),
    t(
        SessionState::LocalInfile,
        SessionEvent::DrainTimerExpired,
        SessionState::Closing,
    ),
    // RedirectPending
    t(
        SessionState::RedirectPending,
        SessionEvent::RedirectBackendReady,
        SessionState::Ready,
    ),
    t(
        SessionState::RedirectPending,
        SessionEvent::RedirectBackendFailed,
        SessionState::Ready,
    ),
    t(
        SessionState::RedirectPending,
        SessionEvent::ControlGracefulClose,
        SessionState::Closing,
    ),
    t(
        SessionState::RedirectPending,
        SessionEvent::ControlCloseImmediate,
        SessionState::Closing,
    ),
    t(
        SessionState::RedirectPending,
        SessionEvent::ClientEof,
        SessionState::Closing,
    ),
    t(
        SessionState::RedirectPending,
        SessionEvent::ClientIoError,
        SessionState::Closing,
    ),
    t(
        SessionState::RedirectPending,
        SessionEvent::BackendEof,
        SessionState::Closing,
    ),
    t(
        SessionState::RedirectPending,
        SessionEvent::BackendIoError,
        SessionState::Closing,
    ),
    // Draining
    t(
        SessionState::Draining,
        SessionEvent::ClientCommand,
        SessionState::Command,
    ),
    t(
        SessionState::Draining,
        SessionEvent::ClientCommandQuit,
        SessionState::Closing,
    ),
    t(
        SessionState::Draining,
        SessionEvent::ControlRedirect,
        SessionState::Draining,
    ),
    t(
        SessionState::Draining,
        SessionEvent::DrainTimerExpired,
        SessionState::Closing,
    ),
    t(
        SessionState::Draining,
        SessionEvent::ControlCloseImmediate,
        SessionState::Closing,
    ),
    t(
        SessionState::Draining,
        SessionEvent::ClientEof,
        SessionState::Closing,
    ),
    t(
        SessionState::Draining,
        SessionEvent::ClientIoError,
        SessionState::Closing,
    ),
    t(
        SessionState::Draining,
        SessionEvent::BackendEof,
        SessionState::Closing,
    ),
    t(
        SessionState::Draining,
        SessionEvent::BackendIoError,
        SessionState::Closing,
    ),
    // Closing
    t(
        SessionState::Closing,
        SessionEvent::TeardownComplete,
        SessionState::Closed,
    ),
    t(
        SessionState::Closing,
        SessionEvent::RedirectBackendReady,
        SessionState::Closing,
    ),
    t(
        SessionState::Closing,
        SessionEvent::RedirectBackendFailed,
        SessionState::Closing,
    ),
    t(
        SessionState::Closing,
        SessionEvent::ControlRedirect,
        SessionState::Closing,
    ),
    t(
        SessionState::Closing,
        SessionEvent::ClientCommand,
        SessionState::Closing,
    ),
    t(
        SessionState::Closing,
        SessionEvent::ClientCommandQuit,
        SessionState::Closing,
    ),
    t(
        SessionState::Closing,
        SessionEvent::BackendResponsePart,
        SessionState::Closing,
    ),
    t(
        SessionState::Closing,
        SessionEvent::BackendResponseTxnDone,
        SessionState::Closing,
    ),
    t(
        SessionState::Closing,
        SessionEvent::BackendResponseTxnOpen,
        SessionState::Closing,
    ),
    t(
        SessionState::Closing,
        SessionEvent::BackendLocalInfileRequest,
        SessionState::Closing,
    ),
    t(
        SessionState::Closing,
        SessionEvent::ClientInfileChunk,
        SessionState::Closing,
    ),
    t(
        SessionState::Closing,
        SessionEvent::ClientInfileEnd,
        SessionState::Closing,
    ),
    t(
        SessionState::Closing,
        SessionEvent::ControlGracefulClose,
        SessionState::Closing,
    ),
    t(
        SessionState::Closing,
        SessionEvent::ControlCloseImmediate,
        SessionState::Closing,
    ),
    t(
        SessionState::Closing,
        SessionEvent::ClientEof,
        SessionState::Closing,
    ),
    t(
        SessionState::Closing,
        SessionEvent::BackendEof,
        SessionState::Closing,
    ),
    t(
        SessionState::Closing,
        SessionEvent::ClientIoError,
        SessionState::Closing,
    ),
    t(
        SessionState::Closing,
        SessionEvent::BackendIoError,
        SessionState::Closing,
    ),
    t(
        SessionState::Closing,
        SessionEvent::HandshakeTimerExpired,
        SessionState::Closing,
    ),
    t(
        SessionState::Closing,
        SessionEvent::DrainTimerExpired,
        SessionState::Closing,
    ),
];
