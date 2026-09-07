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

//! Live-range coverage for [`control_topology::poll_prometheus`].
//!
//! The unit tests in `discovery.rs` inject the fetch through the `PrometheusFetch`
//! trait, so they never exercise the production `ConnectionFetch`: the exact
//! `/topology/prometheus` prefix, the `.with_prefix()` range, and the response
//! projection. This integration test closes that gap by driving the real
//! [`control_external::EtcdConnection`] against an in-process etcd v3 KV fixture
//! that implements real prefix-range semantics.
//!
//! The fixture is a hand-rolled single-route tonic adapter (no `build-server`,
//! no raw h2): [`tonic::server::Grpc::unary`] with a [`tonic_prost::ProstCodec`]
//! owns the `application/grpc` framing and trailers for the `Range` route over a
//! plaintext hyper HTTP/2 server. The wire messages are hand-defined to etcd
//! 0.20.0's field tags so the pinned `etcd_client` interoperates. Unlike a
//! fixed-key stub, the `Range` handler evaluates the request's `key`/`range_end`
//! against seeded data, so a wrong prefix or a dropped `.with_prefix()` returns
//! nothing and turns the test RED.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use control_external::{EtcdClientConfig, EtcdConnection, EtcdConnector};
use control_plane::{OwnerLease, OwnerScope, OwnershipRegistry};
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::service::TowerToHyperService;
use tokio::net::{TcpListener, TcpStream};
use tonic::codegen::{BoxFuture, Context, Poll, Service, http};
use tonic::server::{Grpc, NamedService, UnaryService};
use tonic_prost::ProstCodec;

/// The etcd v3 `Range` unary gRPC method path the pinned client calls.
const RANGE_PATH: &str = "/etcdserverpb.KV/Range";
/// The gRPC service name the pinned client routes against.
const KV_SERVICE_NAME: &str = "etcdserverpb.KV";

// ----- Wire-compatible etcd v3 messages (etcd 0.20.0 field tags) --------

/// `etcdserverpb.RangeRequest`: the fixture reads both the `key` (tag 1) and the
/// `range_end` (tag 2) so it can evaluate real range semantics. `etcd_client`'s
/// `with_prefix()` sets `range_end` to the prefix's right-open bound, while an
/// exact-key get leaves it empty.
#[derive(Clone, PartialEq, ::prost::Message)]
struct RangeRequest {
    #[prost(bytes = "vec", tag = "1")]
    key: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    range_end: Vec<u8>,
}

/// `etcdserverpb.ResponseHeader`.
#[derive(Clone, PartialEq, ::prost::Message)]
struct ResponseHeader {
    #[prost(uint64, tag = "1")]
    cluster_id: u64,
    #[prost(uint64, tag = "2")]
    member_id: u64,
    #[prost(int64, tag = "3")]
    revision: i64,
    #[prost(uint64, tag = "4")]
    raft_term: u64,
}

/// `mvccpb.KeyValue` (real etcd tags: `key` = 1, `value` = 5).
#[derive(Clone, PartialEq, ::prost::Message)]
struct KeyValue {
    #[prost(bytes = "vec", tag = "1")]
    key: Vec<u8>,
    #[prost(int64, tag = "2")]
    create_revision: i64,
    #[prost(int64, tag = "3")]
    mod_revision: i64,
    #[prost(int64, tag = "4")]
    version: i64,
    #[prost(bytes = "vec", tag = "5")]
    value: Vec<u8>,
    #[prost(int64, tag = "6")]
    lease: i64,
}

/// `etcdserverpb.RangeResponse`.
#[derive(Clone, PartialEq, ::prost::Message)]
struct RangeResponse {
    #[prost(message, optional, tag = "1")]
    header: Option<ResponseHeader>,
    #[prost(message, repeated, tag = "2")]
    kvs: Vec<KeyValue>,
    #[prost(bool, tag = "3")]
    more: bool,
    #[prost(int64, tag = "4")]
    count: i64,
}

// ----- The single-route etcd v3 KV fixture with real range semantics ----

/// The exact `(key, range_end)` of the last observed `Range` request.
type Observed = Arc<Mutex<Option<(Vec<u8>, Vec<u8>)>>>;

/// Shared fixture state: the seeded key/value pairs the `Range` handler filters,
/// plus the exact `(key, range_end)` of the last observed request so the test can
/// assert the frozen prefix and its right-open range bound.
#[derive(Clone)]
struct KvFixture {
    seeded: Arc<Vec<(Vec<u8>, Vec<u8>)>>,
    observed: Observed,
}

/// Evaluates enough etcd `Range` semantics for the test: with an empty
/// `range_end` it is an exact get (`k == key`); otherwise a half-open range
/// (`key <= k < range_end`). Matches are returned ascending by key.
fn range_scan(
    seeded: &[(Vec<u8>, Vec<u8>)],
    key: &[u8],
    range_end: &[u8],
) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut hits: Vec<(Vec<u8>, Vec<u8>)> = seeded
        .iter()
        .filter(|(k, _)| {
            if range_end.is_empty() {
                k.as_slice() == key
            } else {
                k.as_slice() >= key && k.as_slice() < range_end
            }
        })
        .cloned()
        .collect();
    hits.sort_by(|(a, _), (b, _)| a.cmp(b));
    hits
}

/// The `Range` unary handler: it decodes the request and answers the seeded
/// key/values selected by real range semantics, ascending by key.
struct RangeHandler {
    fixture: KvFixture,
}

impl UnaryService<RangeRequest> for RangeHandler {
    type Response = RangeResponse;
    type Future = BoxFuture<tonic::Response<RangeResponse>, tonic::Status>;

    fn call(&mut self, request: tonic::Request<RangeRequest>) -> Self::Future {
        let fixture = self.fixture.clone();
        Box::pin(async move {
            let message = request.into_inner();
            // Record the exact query bounds so the test can pin the frozen prefix
            // and its right-open range end, killing any narrow/broaden drift.
            *fixture
                .observed
                .lock()
                .unwrap_or_else(PoisonError::into_inner) =
                Some((message.key.clone(), message.range_end.clone()));
            let matches = range_scan(&fixture.seeded, &message.key, &message.range_end);
            let count = i64::try_from(matches.len()).unwrap_or(i64::MAX);
            let kvs = matches
                .into_iter()
                .map(|(key, value)| KeyValue {
                    key,
                    value,
                    ..KeyValue::default()
                })
                .collect();
            let header = ResponseHeader {
                cluster_id: 7,
                member_id: 11,
                revision: 42,
                raft_term: 3,
            };
            Ok(tonic::Response::new(RangeResponse {
                header: Some(header),
                kvs,
                more: false,
                count,
            }))
        })
    }
}

/// The `Range` route uses a prost codec so tonic frames the response; any other
/// path returns the `unimplemented` gRPC reply tonic's generated server sends.
impl Service<http::Request<Incoming>> for KvFixture {
    type Response = http::Response<tonic::body::Body>;
    type Error = Infallible;
    type Future = BoxFuture<Self::Response, Infallible>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: http::Request<Incoming>) -> Self::Future {
        let fixture = self.clone();
        Box::pin(async move {
            let response = if request.uri().path() == RANGE_PATH {
                let mut grpc = Grpc::new(ProstCodec::<RangeResponse, RangeRequest>::default());
                grpc.unary(RangeHandler { fixture }, request).await
            } else {
                unimplemented_reply()
            };
            Ok(response)
        })
    }
}

impl NamedService for KvFixture {
    const NAME: &'static str = KV_SERVICE_NAME;
}

/// The `unimplemented` gRPC reply for an unrouted path: HTTP 200 with a
/// `grpc-status: 12` header and the gRPC content type, matching tonic's
/// generated fallback.
fn unimplemented_reply() -> http::Response<tonic::body::Body> {
    let mut response = http::Response::new(tonic::body::Body::default());
    let headers = response.headers_mut();
    headers.insert(
        tonic::Status::GRPC_STATUS,
        http::HeaderValue::from_static("12"),
    );
    headers.insert(
        http::header::CONTENT_TYPE,
        tonic::metadata::GRPC_CONTENT_TYPE,
    );
    response
}

/// Binds a loopback listener on an ephemeral port and serves the single-route KV
/// adapter over each accepted plaintext connection. The accept loop is detached;
/// the test process bounds its lifetime. Returns the actual bound address.
async fn spawn_fixture(seeded: Vec<(Vec<u8>, Vec<u8>)>) -> Option<(SocketAddr, Observed)> {
    let observed: Observed = Arc::new(Mutex::new(None));
    let fixture = KvFixture {
        seeded: Arc::new(seeded),
        observed: Arc::clone(&observed),
    };
    let listener = TcpListener::bind("127.0.0.1:0").await.ok()?;
    let addr = listener.local_addr().ok()?;
    tokio::spawn(async move {
        loop {
            let Ok((stream, _peer)) = listener.accept().await else {
                return;
            };
            tokio::spawn(serve_connection(stream, fixture.clone()));
        }
    });
    Some((addr, observed))
}

/// Feeds one accepted plaintext connection into the single-route KV adapter via
/// hyper's HTTP/2 server, so tonic owns the gRPC framing and trailers.
async fn serve_connection(stream: TcpStream, fixture: KvFixture) {
    let service = TowerToHyperService::new(fixture);
    let builder = hyper::server::conn::http2::Builder::new(TokioExecutor::new());
    let _ = builder
        .serve_connection(TokioIo::new(stream), service)
        .await;
}

/// Builds a real owner-fenced [`EtcdConnection`] against the plaintext fixture.
/// The registry and lease are returned so the caller keeps the owner generation
/// current for the connection's whole lifetime.
async fn connect(addr: SocketAddr) -> Option<(OwnershipRegistry, OwnerLease, EtcdConnection)> {
    let registry = OwnershipRegistry::new();
    let lease = registry
        .claim(OwnerScope::Process, "prometheus-etcd-test")
        .ok()?;
    let config = EtcdClientConfig::new(vec![addr.to_string()], None).ok()?;
    let connection = EtcdConnector::new(lease.token(), config)
        .connect()
        .await
        .ok()?;
    Some((registry, lease, connection))
}

fn kv(key: &str, value: &str) -> (Vec<u8>, Vec<u8>) {
    (key.as_bytes().to_vec(), value.as_bytes().to_vec())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn poll_prometheus_reads_the_first_record_over_the_real_prefix_range() {
    let body = async {
        // The real record lives under SUFFIX keys, never the exact base key, so
        // an exact get (no `.with_prefix()`) finds nothing. `i1` is first by key
        // order and is the expected pick; `i2` is a decoy. The `/topology/tidb`
        // key is above the prefix's right-open bound and must be excluded.
        let seeded = vec![
            kv(
                "/topology/prometheus/i1",
                r#"{"ip":"1.1.1.1","binary_path":"/p","port":9090}"#,
            ),
            kv("/topology/prometheus/i2", r#"{"ip":"2.2.2.2","port":1}"#),
            kv("/topology/tidb/x", r#"{"ip":"9.9.9.9","port":1}"#),
        ];
        let Some((addr, observed)) = spawn_fixture(seeded).await else {
            unreachable!("the fixture binds an ephemeral loopback port");
        };
        let Some((_registry, _lease, mut connection)) = connect(addr).await else {
            unreachable!("the real EtcdConnection connects to the plaintext fixture");
        };

        let result = control_topology::poll_prometheus(&mut connection).await;
        let Ok(Some(info)) = result else {
            unreachable!("the prefix range yields the first record: {result:?}");
        };
        assert_eq!(
            info.ip, "1.1.1.1",
            "the first record by key order is chosen"
        );
        assert_eq!(info.port, 9090, "the first record's port is projected");
        assert_eq!(
            info.binary_path, "/p",
            "the first record is fully projected"
        );

        // Pin the frozen query to the EXACT prefix and its real right-open bound,
        // independent of what the seeded data happens to sort first: broadening
        // the prefix (e.g. to `/topology/`) or narrowing it changes `key`, and
        // dropping `.with_prefix()` empties `range_end`. `/topology/prometheus`
        // ends in `s` (0x73), so the right-open bound increments it to `t`.
        let captured = observed
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let Some((key, range_end)) = captured else {
            unreachable!("the fixture observed the Range request");
        };
        assert_eq!(
            key,
            b"/topology/prometheus".to_vec(),
            "the exact frozen prefix is queried"
        );
        assert_eq!(
            range_end,
            b"/topology/prometheut".to_vec(),
            "range_end is the prefix's right-open bound"
        );
    };
    if tokio::time::timeout(Duration::from_secs(5), body)
        .await
        .is_err()
    {
        unreachable!("the live prefix read completes well within the deadline");
    }
}
