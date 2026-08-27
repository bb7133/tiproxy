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

//! Strongly typed live-session control binding (DPL-03).
//!
//! Admission registers the Rust-owned connection id and immutable snapshot
//! generation with the CTL-06 dispatcher before any handshake/route request
//! can be sent. The bound session owner must call [`SessionControlBinding::expect_response`]
//! before sending that request and [`SessionControlBinding::set_backend`] after
//! a route succeeds. Terminal effect notices remain owned by DPL-04, and
//! metering production remains owned by DPL-06.

use std::future::Future;
use std::sync::{Arc, OnceLock};

use control_proto::v1::{ConnectionIdentity, ControlEnvelope};
use tokio::sync::{mpsc, watch};

use crate::control_dispatch::{
    ControlDispatchHandle, ExpectResponseError, ResponseKind, SessionDirective,
};
use crate::server::{AcceptedConnection, ConnectionFuture, ConnectionHandler};

const SESSION_CONTROL_CAPACITY: usize = 8;
const SESSION_RESPONSE_CAPACITY: usize = 1;

/// Per-session typed CTL-06 surface and inbound channels.
pub struct SessionControlBinding {
    dispatch: ControlDispatchHandle,
    connection_id: u64,
    control: mpsc::Receiver<SessionDirective>,
    responses: mpsc::Receiver<ControlEnvelope>,
}

impl SessionControlBinding {
    async fn register(
        dispatch: ControlDispatchHandle,
        connection: &AcceptedConnection,
        namespace: String,
    ) -> Option<Self> {
        let metadata = connection.metadata();
        let connection_id = metadata.connection_id.get();
        let identity = ConnectionIdentity {
            connection_id,
            listener_address: metadata.listener_address.to_string(),
            client_address: metadata.peer_address.to_string(),
            proxy_address: metadata.listener_address.to_string(),
            public_endpoint: false,
        };
        let (control_tx, control) = mpsc::channel(SESSION_CONTROL_CAPACITY);
        let (response_tx, responses) = mpsc::channel(SESSION_RESPONSE_CAPACITY);
        if !dispatch
            .register_session(
                identity,
                namespace,
                metadata.snapshot_generation,
                metadata.listener_name.to_string(),
                control_tx,
                Some(response_tx),
            )
            .await
        {
            return None;
        }
        Some(Self {
            dispatch,
            connection_id,
            control,
            responses,
        })
    }

    /// Rust-owned connection id registered with the dispatcher.
    #[must_use]
    pub const fn connection_id(&self) -> u64 {
        self.connection_id
    }

    /// Arms the one expected Go response. The caller may send the initiating
    /// request only after this returns `Ok(())`.
    ///
    /// # Errors
    ///
    /// Returns the dispatcher's fail-closed registration/channel verdict.
    pub async fn expect_response(
        &self,
        request_id: u64,
        kind: ResponseKind,
    ) -> Result<(), ExpectResponseError> {
        self.dispatch
            .expect_response(self.connection_id, request_id, kind)
            .await
    }

    /// Records the currently connected backend for commands/reconciliation.
    pub async fn set_backend(&self, backend_id: impl Into<String>) -> bool {
        self.dispatch
            .set_backend(self.connection_id, backend_id.into())
            .await
    }

    /// Receives the next control directive for the single-owner session
    /// loop: the signal plus — for gate-admitted per-session commands —
    /// the exact [`CommandToken`](crate::control_dispatch::CommandToken)
    /// whose id the completion notice must return. `None` means the
    /// dispatcher detached (control-v1 last-good: never a teardown
    /// reason by itself).
    pub async fn recv_control(&mut self) -> Option<SessionDirective> {
        self.control.recv().await
    }

    /// Receives the exactly correlated handshake/route response.
    pub async fn recv_response(&mut self) -> Option<ControlEnvelope> {
        self.responses.recv().await
    }

    /// Splits the binding into its three independent halves so the
    /// session owner can consume control directives, route/handshake
    /// responses, and the typed dispatch surface from different tasks
    /// without a lock: the directive stream (with its command tokens),
    /// the correlated-response stream, and the commander (dispatch
    /// operations bound to this connection id).
    #[must_use]
    pub fn split(self) -> (DirectiveStream, ResponseStream, SessionCommander) {
        (
            DirectiveStream {
                control: self.control,
            },
            ResponseStream {
                responses: self.responses,
            },
            SessionCommander {
                dispatch: self.dispatch,
                connection_id: self.connection_id,
            },
        )
    }
}

/// The control-directive half of a split [`SessionControlBinding`].
pub struct DirectiveStream {
    control: mpsc::Receiver<SessionDirective>,
}

impl DirectiveStream {
    /// Receives the next control directive; `None` means the dispatcher
    /// detached (control-v1 last-good: never a teardown reason).
    pub async fn recv(&mut self) -> Option<SessionDirective> {
        self.control.recv().await
    }
}

/// The correlated-response half of a split [`SessionControlBinding`].
pub struct ResponseStream {
    responses: mpsc::Receiver<ControlEnvelope>,
}

impl ResponseStream {
    /// Receives the next exactly correlated response envelope.
    pub async fn recv(&mut self) -> Option<ControlEnvelope> {
        self.responses.recv().await
    }
}

/// The typed dispatch surface of a split [`SessionControlBinding`],
/// bound to one connection id.
#[derive(Clone)]
pub struct SessionCommander {
    dispatch: ControlDispatchHandle,
    connection_id: u64,
}

impl SessionCommander {
    /// The bound connection id.
    #[must_use]
    pub const fn connection_id(&self) -> u64 {
        self.connection_id
    }

    /// Arms the one expected Go response; send the initiating request
    /// only after `Ok(())`.
    ///
    /// # Errors
    ///
    /// Returns the dispatcher's fail-closed verdict.
    pub async fn expect_response(
        &self,
        request_id: u64,
        kind: ResponseKind,
    ) -> Result<(), ExpectResponseError> {
        self.dispatch
            .expect_response(self.connection_id, request_id, kind)
            .await
    }

    /// Records the currently connected backend.
    pub async fn set_backend(&self, backend_id: impl Into<String>) -> bool {
        self.dispatch
            .set_backend(self.connection_id, backend_id.into())
            .await
    }

    /// Reports a finished redirect under its exact admitted id.
    pub async fn redirect_finished(
        &self,
        redirect_id: String,
        succeeded: bool,
        backend_id: String,
        code: control_proto::v1::ErrorCode,
    ) -> bool {
        self.dispatch
            .redirect_finished(self.connection_id, redirect_id, succeeded, backend_id, code)
            .await
    }

    /// Reports a finished accepted close under its exact admitted id.
    pub async fn close_finished(&self, close_id: String) -> bool {
        self.dispatch
            .close_finished(self.connection_id, close_id)
            .await
    }

    /// Reports the session's termination with its failure attribution
    /// and final traffic totals.
    pub async fn session_closed(
        &self,
        forced: bool,
        error_source: control_proto::v1::ErrorSource,
        traffic: crate::route_control::TrafficTotals,
    ) -> bool {
        self.dispatch
            .session_closed(self.connection_id, forced, error_source, traffic)
            .await
    }
}

/// The injected real session owner after CTL-06 registration. DPL-04 composes
/// its `SessionLoop`/effect implementation here; tests may use a deterministic
/// fake without weakening the production registration barrier.
pub trait BoundSessionHandler: Send + Sync + 'static {
    /// Runs one registered connection until its session lifecycle ends.
    fn handle(
        &self,
        connection: AcceptedConnection,
        binding: SessionControlBinding,
    ) -> ConnectionFuture;
}

impl<F, Fut> BoundSessionHandler for F
where
    F: Fn(AcceptedConnection, SessionControlBinding) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    fn handle(
        &self,
        connection: AcceptedConnection,
        binding: SessionControlBinding,
    ) -> ConnectionFuture {
        Box::pin(self(connection, binding))
    }
}

/// One-shot installer that resolves the construction cycle: the snapshot
/// consumer needs a connection handler before `spawn_control_runtime`, while
/// that function creates the dispatch handle sessions must receive.
#[derive(Clone)]
pub struct DispatchHandleInstaller {
    slot: Arc<OnceLock<ControlDispatchHandle>>,
    ready: watch::Sender<bool>,
}

impl DispatchHandleInstaller {
    /// Installs the runtime's dispatch handle exactly once.
    #[must_use]
    pub fn install(&self, handle: ControlDispatchHandle) -> bool {
        if self.slot.set(handle).is_err() {
            return false;
        }
        self.ready.send_replace(true);
        true
    }
}

/// Server-facing handler that performs the admission registration barrier and
/// then hands the connection to the injected session owner.
pub struct DispatchConnectionHandler {
    slot: Arc<OnceLock<ControlDispatchHandle>>,
    ready: watch::Receiver<bool>,
    namespace: Arc<str>,
    handler: Arc<dyn BoundSessionHandler>,
}

impl DispatchConnectionHandler {
    /// Creates the server handler and its one-shot dispatch installer.
    #[must_use]
    pub fn new(
        namespace: impl Into<Arc<str>>,
        handler: Arc<dyn BoundSessionHandler>,
    ) -> (Self, DispatchHandleInstaller) {
        let slot = Arc::new(OnceLock::new());
        let (ready, ready_rx) = watch::channel(false);
        (
            Self {
                slot: Arc::clone(&slot),
                ready: ready_rx,
                namespace: namespace.into(),
                handler,
            },
            DispatchHandleInstaller { slot, ready },
        )
    }
}

impl ConnectionHandler for DispatchConnectionHandler {
    fn handle(&self, connection: AcceptedConnection) -> ConnectionFuture {
        let slot = Arc::clone(&self.slot);
        let mut ready = self.ready.clone();
        let namespace = self.namespace.to_string();
        let handler = Arc::clone(&self.handler);
        Box::pin(async move {
            let dispatch = loop {
                if let Some(dispatch) = slot.get().cloned() {
                    break dispatch;
                }
                if ready.changed().await.is_err() {
                    return;
                }
            };
            let Some(binding) =
                SessionControlBinding::register(dispatch, &connection, namespace).await
            else {
                return;
            };
            handler.handle(connection, binding).await;
        })
    }
}
