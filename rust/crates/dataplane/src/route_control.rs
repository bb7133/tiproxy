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

//! Control-protocol binding for the route engine (DPL-02).
//!
//! [`ControlRouteChannel`] implements [`RouteChannel`] over the real
//! control envelopes: outgoing `RouteRequest`/`RouteResult` bodies go
//! through an [`EnvelopeSink`] (the composition wraps the shared
//! `control-proto` client, which owns epochs, request ids, and queue
//! lanes), and incoming `RouteAssignment`s arrive through a per-session
//! channel fed by [`AssignmentRouter`] — the single control-handler
//! task's connection-id dispatch table (single-owner: no lock).
//!
//! Connection lifecycle accounting (`ConnectionEvent` OPENED / CLOSED)
//! is built here too: the CLOSED event is what retires an assignment
//! that never got its terminal `RouteResult` (Go `closeStateLocked`
//! finishes it exactly once; see the retirement discipline in
//! [`crate::route`]).
//!
//! [`TcpDialer`] is the default direct dialer: **not** cluster-aware,
//! so the engine fails closed if a cluster-scoped assignment reaches it
//! (cluster DNS resolution is DPL-07).

use std::collections::HashMap;

use control_proto::v1::control_envelope::Body;
use control_proto::v1::{
    ConnectionEvent, ConnectionEventKind, ConnectionIdentity, ErrorSource, HandshakeMetadata,
    RouteAssignment, RouteRequest, RouteResult,
};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

use crate::route::{BackendDialer, DialFailure, RouteChannel, RouteChannelError};

/// Sends one control body on the session's behalf. The dataplane
/// composition implements this over the shared `control-proto` client
/// (assigning request ids, priority `CONTROL`, epoch, and timestamps);
/// tests fake it.
pub trait EnvelopeSink: Send {
    /// Queues one body for the control plane.
    fn send_control(
        &mut self,
        body: Body,
    ) -> impl Future<Output = Result<(), RouteChannelError>> + Send;
}

/// Capacity of each session's assignment channel. The adapter pushes at
/// most one outstanding assignment per connection (the next only after
/// a failed result), so one slot plus headroom for a race with a
/// re-request is enough.
const ASSIGNMENT_CHANNEL_CAPACITY: usize = 2;

/// The single control-handler task's dispatch table: incoming
/// `RouteAssignment`s are routed to the owning session's channel by
/// `connection_id`. Owned by one task — no lock anywhere.
#[derive(Default)]
pub struct AssignmentRouter {
    sessions: HashMap<u64, mpsc::Sender<RouteAssignment>>,
}

impl AssignmentRouter {
    /// Creates an empty dispatch table.
    #[must_use]
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
        }
    }

    /// Registers a session and returns the receiving half for its
    /// [`ControlRouteChannel`]. A previous registration for the same id
    /// is replaced (its receiver then observes `ControlLost`).
    pub fn register(&mut self, connection_id: u64) -> mpsc::Receiver<RouteAssignment> {
        let (tx, rx) = mpsc::channel(ASSIGNMENT_CHANNEL_CAPACITY);
        self.sessions.insert(connection_id, tx);
        rx
    }

    /// Removes a session (its channel closes; a blocked
    /// `next_assignment` observes `ControlLost`).
    pub fn unregister(&mut self, connection_id: u64) {
        self.sessions.remove(&connection_id);
    }

    /// Routes one incoming assignment. Returns false when no session
    /// owns the connection id (stale or raced close) — the caller
    /// should let close/reconcile accounting cover it rather than
    /// treating it as an error.
    pub fn dispatch(&mut self, assignment: RouteAssignment) -> bool {
        let connection_id = assignment.connection_id;
        let Some(tx) = self.sessions.get(&connection_id) else {
            return false;
        };
        if tx.try_send(assignment).is_ok() {
            return true;
        }
        // Full or closed: the session is gone or wedged; drop the entry
        // so later assignments fail fast.
        self.sessions.remove(&connection_id);
        false
    }

    /// Registered session count (metrics).
    #[must_use]
    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    /// Whether no session is registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }
}

/// Per-session [`RouteChannel`] over the real control envelopes.
pub struct ControlRouteChannel<S> {
    sink: S,
    assignments: mpsc::Receiver<RouteAssignment>,
    identity: ConnectionIdentity,
    handshake: HandshakeMetadata,
    namespace_hint: String,
}

impl<S: EnvelopeSink> ControlRouteChannel<S> {
    /// Builds the channel for one session. `identity` and `handshake`
    /// must be the same values the handshake event carried — the
    /// adapter rejects a `RouteRequest` whose identity differs from the
    /// handshake event (`PROTOCOL_VIOLATION`).
    pub const fn new(
        sink: S,
        assignments: mpsc::Receiver<RouteAssignment>,
        identity: ConnectionIdentity,
        handshake: HandshakeMetadata,
        namespace_hint: String,
    ) -> Self {
        Self {
            sink,
            assignments,
            identity,
            handshake,
            namespace_hint,
        }
    }
}

impl<S: EnvelopeSink> RouteChannel for ControlRouteChannel<S> {
    async fn request_route(
        &mut self,
        excluded_backend_ids: Vec<String>,
    ) -> Result<(), RouteChannelError> {
        let request = RouteRequest {
            connection: Some(self.identity.clone()),
            handshake: Some(self.handshake.clone()),
            namespace_hint: self.namespace_hint.clone(),
            excluded_backend_ids,
        };
        self.sink.send_control(Body::RouteRequest(request)).await
    }

    async fn next_assignment(&mut self) -> Result<RouteAssignment, RouteChannelError> {
        loop {
            match self.assignments.recv().await {
                // Defensive: the router dispatches by connection id, so
                // a mismatch is a routing bug upstream; skip rather
                // than act on another session's backend.
                Some(assignment) if assignment.connection_id == self.identity.connection_id => {
                    return Ok(assignment);
                }
                Some(_) => {}
                None => return Err(RouteChannelError::ControlLost),
            }
        }
    }

    async fn report_result(&mut self, result: RouteResult) -> Result<(), RouteChannelError> {
        self.sink.send_control(Body::RouteResult(result)).await
    }
}

/// Byte counters for the CLOSED lifecycle event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TrafficTotals {
    /// Bytes received from the client.
    pub client_in: u64,
    /// Bytes sent to the client.
    pub client_out: u64,
    /// Bytes received from the backend.
    pub backend_in: u64,
    /// Bytes sent to the backend.
    pub backend_out: u64,
}

/// Builds the OPENED lifecycle event (sent once the session is admitted
/// and its identity is known).
#[must_use]
pub fn connection_opened(identity: &ConnectionIdentity, namespace: &str) -> ConnectionEvent {
    ConnectionEvent {
        kind: ConnectionEventKind::Opened.into(),
        connection: Some(identity.clone()),
        backend_id: String::new(),
        namespace: namespace.to_owned(),
        error_source: ErrorSource::Unspecified.into(),
        client_in_bytes: 0,
        client_out_bytes: 0,
        backend_in_bytes: 0,
        backend_out_bytes: 0,
    }
}

/// Builds the CLOSED lifecycle event. Besides router connection-count
/// accounting, this is what retires an assignment the session never
/// answered with a terminal `RouteResult` (budget exhaustion, cluster
/// fail-closed, teardown mid-dial): Go `closeStateLocked` finishes the
/// unfinished assignment exactly once on this event.
#[must_use]
pub fn connection_closed(
    identity: &ConnectionIdentity,
    backend_id: &str,
    namespace: &str,
    error_source: ErrorSource,
    traffic: TrafficTotals,
) -> ConnectionEvent {
    ConnectionEvent {
        kind: ConnectionEventKind::Closed.into(),
        connection: Some(identity.clone()),
        backend_id: backend_id.to_owned(),
        namespace: namespace.to_owned(),
        error_source: error_source.into(),
        client_in_bytes: traffic.client_in,
        client_out_bytes: traffic.client_out,
        backend_in_bytes: traffic.backend_in,
        backend_out_bytes: traffic.backend_out,
    }
}

/// Direct TCP dialer: the default when no cluster resolver is
/// configured. Deliberately **not** cluster-aware — the engine fails
/// closed on cluster-scoped assignments instead of dialing outside the
/// scope (cluster DNS is DPL-07).
#[derive(Debug, Clone, Copy, Default)]
pub struct TcpDialer;

impl BackendDialer for TcpDialer {
    // CLUSTER_AWARE stays false: never silently ignore a cluster scope.
    type Conn = TcpStream;

    async fn dial(&mut self, address: &str, _cluster_name: &str) -> Result<TcpStream, DialFailure> {
        match TcpStream::connect(address).await {
            Ok(stream) => Ok(stream),
            Err(_) => Err(DialFailure::Connect),
        }
    }
}

/// Cluster-scoped TCP dialer (DPL-07). A standard cluster resolves its
/// backend addresses with the system resolver — exactly Go's
/// `DNSDialer` when the cluster declares no name servers, which is the
/// only shape the wire snapshot can express today
/// (`BackendCluster.NSServers` is not projected). A future serverless
/// projection carrying per-cluster name servers must extend this
/// dialer's resolution rather than fall back to it silently.
#[derive(Debug, Clone, Copy, Default)]
pub struct ClusterTcpDialer;

impl BackendDialer for ClusterTcpDialer {
    const CLUSTER_AWARE: bool = true;
    type Conn = TcpStream;

    async fn dial(&mut self, address: &str, _cluster_name: &str) -> Result<TcpStream, DialFailure> {
        match TcpStream::connect(address).await {
            Ok(stream) => Ok(stream),
            Err(_) => Err(DialFailure::Connect),
        }
    }
}
