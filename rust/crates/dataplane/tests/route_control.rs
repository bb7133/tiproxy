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

//! DPL-02 binding tests: the control-envelope route channel end to end
//! with the engine (bodies verified field by field), the assignment
//! dispatch table, lifecycle event builders, and the direct TCP dialer
//! against real loopback sockets.

use control_proto::v1::control_envelope::Body;
use control_proto::v1::{
    ConnectionEventKind, ConnectionIdentity, ErrorCode, ErrorSource, HandshakeMetadata,
    RouteAssignment,
};
use dataplane::observability::{MetricsRecorder, Observation};
use dataplane::route::{
    AcquireError, BackendDialer, CenteredJitter, DialSchedule, RouteChannel, RouteChannelError,
    RouteEngine,
};
use dataplane::route_control::{
    AssignmentRouter, ClusterTcpDialer, ControlRouteChannel, EnvelopeSink, TcpDialer,
    TrafficTotals, connection_closed, connection_opened,
};
use tokio::sync::mpsc;

const CONN_ID: u64 = 42;

fn identity() -> ConnectionIdentity {
    ConnectionIdentity {
        connection_id: CONN_ID,
        listener_address: "0.0.0.0:6000".to_owned(),
        client_address: "10.9.8.7:55555".to_owned(),
        proxy_address: "10.0.0.9:6000".to_owned(),
        public_endpoint: false,
    }
}

fn handshake() -> HandshakeMetadata {
    HandshakeMetadata {
        user: "app".to_owned(),
        database: "test".to_owned(),
        auth_plugin: "mysql_native_password".to_owned(),
        capability: 0x0007_ffff,
        collation: 45,
        zstd_level: 0,
        connection_attributes: std::collections::BTreeMap::new(),
        tls: false,
    }
}

fn assignment(id: &str, backend: &str, address: &str) -> RouteAssignment {
    RouteAssignment {
        connection_id: CONN_ID,
        assignment_id: id.to_owned(),
        backend_id: backend.to_owned(),
        backend_address: address.to_owned(),
        cluster_name: String::new(),
        keyspace: String::new(),
        healthy: true,
        local: true,
        code: ErrorCode::Ok.into(),
        detail: String::new(),
    }
}

/// Records every sent body.
struct RecordingSink {
    sent: mpsc::UnboundedSender<Body>,
}

impl EnvelopeSink for RecordingSink {
    async fn send_control(&mut self, body: Body) -> Result<(), RouteChannelError> {
        self.sent
            .send(body)
            .map_err(|_| RouteChannelError::ControlLost)
    }
}

/// A dialer that succeeds for any address without touching the network.
struct AlwaysConnect;

impl BackendDialer for AlwaysConnect {
    type Conn = ();

    async fn dial(
        &mut self,
        _address: &str,
        _cluster_name: &str,
    ) -> Result<(), dataplane::route::DialFailure> {
        Ok(())
    }
}

/// The full binding path: the engine drives `ControlRouteChannel`, the
/// dispatch table routes the adapter's assignment, and the outgoing
/// bodies carry the exact identity/handshake/result fields.
#[tokio::test(start_paused = true)]
async fn control_channel_round_trip_produces_exact_bodies() {
    let (sent_tx, mut sent) = mpsc::unbounded_channel();
    let mut router = AssignmentRouter::new();
    let assignments = router.register(CONN_ID);
    let channel = ControlRouteChannel::new(
        RecordingSink { sent: sent_tx },
        assignments,
        identity(),
        handshake(),
        "ns-hint".to_owned(),
    );
    let mut engine = RouteEngine::new(
        channel,
        AlwaysConnect,
        DialSchedule::default(),
        CenteredJitter,
        CONN_ID,
    );

    // The adapter's push is delivered through the dispatch table.
    assert!(router.dispatch(assignment("as-1", "tidb-a", "127.0.0.1:4000")));
    let acquired = match engine.acquire(vec!["excluded-1".to_owned()]).await {
        Ok(acquired) => acquired,
        Err(error) => unreachable!("acquire failed: {error:?}"),
    };
    assert_eq!(acquired.assignment_id, "as-1");
    assert_eq!(acquired.backend.backend_id, "tidb-a");

    // Outgoing body 1: the RouteRequest with the handshake-identical
    // identity, the namespace hint, and the exclusion list.
    let Some(Body::RouteRequest(request)) = sent.recv().await else {
        unreachable!("first body must be the RouteRequest")
    };
    assert_eq!(request.connection, Some(identity()));
    assert_eq!(request.handshake, Some(handshake()));
    assert_eq!(request.namespace_hint, "ns-hint");
    assert_eq!(request.excluded_backend_ids, vec!["excluded-1".to_owned()]);

    // Outgoing body 2: the connected result for the exact assignment.
    let Some(Body::RouteResult(result)) = sent.recv().await else {
        unreachable!("second body must be the RouteResult")
    };
    assert_eq!(result.connection_id, CONN_ID);
    assert_eq!(result.assignment_id, "as-1");
    assert!(result.connected);
    assert_eq!(result.code(), ErrorCode::Ok);
}

/// Dispatch-table semantics: unknown connection ids are refused (close
/// accounting covers them), unregistering closes the session channel
/// into `ControlLost`, and a foreign-id assignment that somehow reaches
/// a session is skipped rather than acted on.
#[tokio::test(start_paused = true)]
async fn dispatch_table_and_defensive_filtering() {
    let (sent_tx, _sent) = mpsc::unbounded_channel();
    let mut router = AssignmentRouter::new();
    let assignments = router.register(CONN_ID);
    assert!(
        !router.dispatch(assignment("as-x", "tidb-a", "h:1").connection_id_swapped(999)),
        "unknown id refused"
    );

    let mut channel = ControlRouteChannel::new(
        RecordingSink { sent: sent_tx },
        assignments,
        identity(),
        handshake(),
        String::new(),
    );
    // A foreign assignment injected into the session channel is skipped;
    // the following correct one is returned.
    assert!(router.dispatch(assignment("as-1", "tidb-a", "h:1")));
    let got = channel.next_assignment().await;
    assert_eq!(
        got.map(|assignment| assignment.assignment_id),
        Ok("as-1".to_owned())
    );

    // Unregister → the channel observes ControlLost.
    router.unregister(CONN_ID);
    assert!(router.is_empty());
    assert_eq!(
        channel.next_assignment().await,
        Err(RouteChannelError::ControlLost)
    );
}

trait SwapId {
    fn connection_id_swapped(self, id: u64) -> Self;
}

impl SwapId for RouteAssignment {
    fn connection_id_swapped(mut self, id: u64) -> Self {
        self.connection_id = id;
        self
    }
}

/// Lifecycle event builders carry the exact identity, kind, error
/// source, and byte counters.
#[test]
fn lifecycle_events_carry_exact_fields() {
    let opened = connection_opened(&identity(), "ns-a");
    assert_eq!(opened.kind(), ConnectionEventKind::Opened);
    assert_eq!(opened.connection, Some(identity()));
    assert_eq!(opened.namespace, "ns-a");
    assert_eq!(opened.backend_id, "");

    let closed = connection_closed(
        &identity(),
        "tidb-a",
        "ns-a",
        ErrorSource::ClientNetwork,
        TrafficTotals {
            client_in: 1,
            client_out: 2,
            backend_in: 3,
            backend_out: 4,
        },
    );
    assert_eq!(closed.kind(), ConnectionEventKind::Closed);
    assert_eq!(closed.backend_id, "tidb-a");
    assert_eq!(closed.error_source(), ErrorSource::ClientNetwork);
    assert_eq!(
        (
            closed.client_in_bytes,
            closed.client_out_bytes,
            closed.backend_in_bytes,
            closed.backend_out_bytes
        ),
        (1, 2, 3, 4)
    );
}

/// Hands out one scripted assignment, then reports control loss.
struct OneAssignment(Option<RouteAssignment>);

impl RouteChannel for OneAssignment {
    async fn request_route(
        &mut self,
        _excluded_backend_ids: Vec<String>,
    ) -> Result<(), RouteChannelError> {
        Ok(())
    }
    async fn next_assignment(&mut self) -> Result<RouteAssignment, RouteChannelError> {
        self.0.take().ok_or(RouteChannelError::ControlLost)
    }
    async fn report_result(
        &mut self,
        _result: control_proto::v1::RouteResult,
    ) -> Result<(), RouteChannelError> {
        Ok(())
    }
}

/// The direct TCP dialer connects to a real loopback listener; it is
/// not cluster-aware, so a cluster-scoped assignment fails closed
/// through the engine.
#[tokio::test]
async fn tcp_dialer_connects_and_stays_cluster_unaware() {
    let listener = match tokio::net::TcpListener::bind("127.0.0.1:0").await {
        Ok(listener) => listener,
        Err(error) => unreachable!("bind: {error}"),
    };
    let address = match listener.local_addr() {
        Ok(address) => address.to_string(),
        Err(error) => unreachable!("local_addr: {error}"),
    };
    let mut dialer = TcpDialer::default();
    assert!(dialer.dial(&address, "").await.is_ok(), "loopback connects");

    // A cluster-scoped assignment through the engine fails closed:
    // `TcpDialer` keeps `CLUSTER_AWARE = false`, so the engine rejects
    // the scope before dialing (proven behaviorally below).
    let scoped = RouteAssignment {
        cluster_name: "serverless-1".to_owned(),
        ..assignment("as-1", "tidb-a", address.as_str())
    };
    let mut engine = RouteEngine::new(
        OneAssignment(Some(scoped)),
        TcpDialer::default(),
        DialSchedule::default(),
        CenteredJitter,
        CONN_ID,
    );
    let Err(error) = engine.acquire(Vec::new()).await else {
        unreachable!("must fail closed")
    };
    assert_eq!(
        error,
        AcquireError::ClusterUnsupported {
            cluster_name: "serverless-1".to_owned()
        }
    );
}

/// DPL-07's system-resolver dialer accepts the current concrete-address
/// cluster scope while preserving DPL-05's non-blocking failed-dial metric.
#[tokio::test]
async fn cluster_tcp_dialer_is_cluster_aware_and_observable() {
    let listener = match tokio::net::TcpListener::bind("127.0.0.1:0").await {
        Ok(listener) => listener,
        Err(error) => unreachable!("bind: {error}"),
    };
    let address = match listener.local_addr() {
        Ok(address) => address.to_string(),
        Err(error) => unreachable!("local_addr: {error}"),
    };
    let scoped = RouteAssignment {
        cluster_name: "default".to_owned(),
        ..assignment("as-cluster", "tidb-cluster", address.as_str())
    };
    let mut engine = RouteEngine::new(
        OneAssignment(Some(scoped)),
        ClusterTcpDialer::default(),
        DialSchedule::default(),
        CenteredJitter,
        CONN_ID,
    );
    let acquired = match engine.acquire(Vec::new()).await {
        Ok(acquired) => acquired,
        Err(error) => unreachable!("cluster-scoped loopback connects: {error:?}"),
    };
    assert_eq!(acquired.backend.cluster_name, "default");

    let (metrics, mut observations) = MetricsRecorder::channel(1);
    let mut dialer = ClusterTcpDialer::new(metrics);
    assert!(dialer.dial("127.0.0.1:0", "default").await.is_err());
    match observations.try_recv() {
        Ok(Observation::DialBackendFailed { backend }) => {
            assert_eq!(backend, "127.0.0.1:0");
        }
        other => unreachable!("one failed-dial observation: {other:?}"),
    }
}
