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

//! Minimal real etcd registration RPCs with a held lease-revoke response.

use std::pin::Pin;
use std::sync::atomic::AtomicI64;

use futures_util::Stream;
use tonic::server::StreamingService;

use super::*;

#[derive(Clone)]
pub(super) struct Registration {
    pub(super) puts: watch::Sender<u64>,
    pub(super) revoking: watch::Sender<bool>,
    pub(super) release: watch::Sender<bool>,
    next_lease: Arc<AtomicI64>,
}

impl Registration {
    pub(super) fn new() -> Self {
        Self {
            puts: watch::channel(0).0,
            revoking: watch::channel(false).0,
            release: watch::channel(true).0,
            next_lease: Arc::new(AtomicI64::new(1)),
        }
    }
}

#[derive(Clone, PartialEq, prost::Message)]
pub(super) struct PutRequest {
    #[prost(bytes = "vec", tag = "1")]
    key: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    value: Vec<u8>,
    #[prost(int64, tag = "3")]
    lease: i64,
}
#[derive(Clone, PartialEq, prost::Message)]
pub(super) struct PutResponse {
    #[prost(message, optional, tag = "1")]
    header: Option<ResponseHeader>,
}

impl UnaryService<PutRequest> for KvService {
    type Response = PutResponse;
    type Future = BoxFuture<tonic::Response<PutResponse>, tonic::Status>;

    fn call(&mut self, request: tonic::Request<PutRequest>) -> Self::Future {
        let registration = self.registration.clone();
        Box::pin(async move {
            let registration = registration
                .ok_or_else(|| tonic::Status::unimplemented("registration disabled"))?;
            let request = request.into_inner();
            if request.lease <= 0 || !request.key.starts_with(b"/topology/tiproxy/") {
                return Err(tonic::Status::invalid_argument("registration lease/key"));
            }
            registration.puts.send_modify(|puts| *puts += 1);
            Ok(tonic::Response::new(PutResponse {
                header: Some(ResponseHeader { revision: 7 }),
            }))
        })
    }
}

#[derive(Clone, PartialEq, prost::Message)]
struct GrantRequest {
    #[prost(int64, tag = "1")]
    ttl: i64,
}
#[derive(Clone, PartialEq, prost::Message)]
struct GrantResponse {
    #[prost(message, optional, tag = "1")]
    header: Option<ResponseHeader>,
    #[prost(int64, tag = "2")]
    id: i64,
    #[prost(int64, tag = "3")]
    ttl: i64,
}
#[derive(Clone, PartialEq, prost::Message)]
struct RevokeRequest {
    #[prost(int64, tag = "1")]
    id: i64,
}
#[derive(Clone, PartialEq, prost::Message)]
struct RevokeResponse {
    #[prost(message, optional, tag = "1")]
    header: Option<ResponseHeader>,
}
#[derive(Clone, PartialEq, prost::Message)]
struct KeepAliveRequest {
    #[prost(int64, tag = "1")]
    id: i64,
}
#[derive(Clone, PartialEq, prost::Message)]
struct KeepAliveResponse {
    #[prost(message, optional, tag = "1")]
    header: Option<ResponseHeader>,
    #[prost(int64, tag = "2")]
    id: i64,
    #[prost(int64, tag = "3")]
    ttl: i64,
}

#[derive(Clone)]
pub(super) struct LeaseService(pub(super) Registration);

impl UnaryService<GrantRequest> for LeaseService {
    type Response = GrantResponse;
    type Future = BoxFuture<tonic::Response<GrantResponse>, tonic::Status>;

    fn call(&mut self, request: tonic::Request<GrantRequest>) -> Self::Future {
        let id = self.0.next_lease.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            Ok(tonic::Response::new(GrantResponse {
                header: Some(ResponseHeader { revision: 7 }),
                id,
                ttl: request.into_inner().ttl,
            }))
        })
    }
}

impl UnaryService<RevokeRequest> for LeaseService {
    type Response = RevokeResponse;
    type Future = BoxFuture<tonic::Response<RevokeResponse>, tonic::Status>;

    fn call(&mut self, _: tonic::Request<RevokeRequest>) -> Self::Future {
        let registration = self.0.clone();
        Box::pin(async move {
            registration.revoking.send_replace(true);
            let mut release = registration.release.subscribe();
            release
                .wait_for(|value| *value)
                .await
                .map_err(|_| tonic::Status::cancelled("fixture retired"))?;
            Ok(tonic::Response::new(RevokeResponse {
                header: Some(ResponseHeader { revision: 7 }),
            }))
        })
    }
}

impl StreamingService<KeepAliveRequest> for LeaseService {
    type Response = KeepAliveResponse;
    type ResponseStream =
        Pin<Box<dyn Stream<Item = Result<KeepAliveResponse, tonic::Status>> + Send>>;
    type Future = BoxFuture<tonic::Response<Self::ResponseStream>, tonic::Status>;

    fn call(
        &mut self,
        request: tonic::Request<tonic::Streaming<KeepAliveRequest>>,
    ) -> Self::Future {
        Box::pin(async move {
            let replies =
                futures_util::stream::unfold(request.into_inner(), |mut requests| async {
                    match requests.message().await {
                        Ok(Some(request)) => Some((
                            Ok(KeepAliveResponse {
                                header: Some(ResponseHeader { revision: 7 }),
                                id: request.id,
                                ttl: 45,
                            }),
                            requests,
                        )),
                        Ok(None) => None,
                        Err(error) => Some((Err(error), requests)),
                    }
                });
            Ok(tonic::Response::new(
                Box::pin(replies) as Self::ResponseStream
            ))
        })
    }
}

impl Service<http::Request<Body>> for LeaseService {
    type Response = http::Response<Body>;
    type Error = Infallible;
    type Future = BoxFuture<Self::Response, Infallible>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: http::Request<Body>) -> Self::Future {
        let handler = self.clone();
        Box::pin(async move {
            let response = match request.uri().path() {
                "/etcdserverpb.Lease/LeaseGrant" => {
                    Grpc::new(ProstCodec::<GrantResponse, GrantRequest>::default())
                        .unary(handler, request)
                        .await
                }
                "/etcdserverpb.Lease/LeaseRevoke" => {
                    Grpc::new(ProstCodec::<RevokeResponse, RevokeRequest>::default())
                        .unary(handler, request)
                        .await
                }
                "/etcdserverpb.Lease/LeaseKeepAlive" => {
                    Grpc::new(ProstCodec::<KeepAliveResponse, KeepAliveRequest>::default())
                        .streaming(handler, request)
                        .await
                }
                _ => return Ok(http::Response::new(Body::default())),
            };
            Ok(response)
        })
    }
}

impl NamedService for LeaseService {
    const NAME: &'static str = "etcdserverpb.Lease";
}
