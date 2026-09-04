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

//! Owner-fenced custom `etcd-client` transport (B3 slice 2b-1).
//!
//! This module assembles the frozen tower stack that `EtcdConnector::connect`
//! hands to `Client::from_channel` as the production etcd transport:
//!
//! ```text
//! Channel::Custom(BoxCloneSyncService(
//!     OwnerCallFence(                         // outside the Buffer
//!         Buffer<_, Request<Body>>(1024)(
//!             Balance(ServiceList(Vec<FailureBackoff<tonic::transport::Channel>>))))))
//! ```
//!
//! [`EtcdConnector::connect`](crate::etcd::EtcdConnector::connect) builds this
//! stack through [`build_custom_channel`] and hands it to
//! `Client::from_channel`, so it is the production etcd transport.
//!
//! Two owner fences guard the stack against a retired control generation:
//! [`OwnerCallFence`] sits *outside* the outer [`Buffer`] and fails a call closed
//! after `poll_ready` but before dispatch (the readiness-to-call gap), and
//! [`OwnerFencedDialer`] re-checks the owner after every awaited connect stage so
//! a connection completed by a stale generation is dropped rather than handed to
//! tonic.

use std::future::Future;
use std::net::SocketAddr;
use std::net::ToSocketAddrs;
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use control_plane::OwnerToken;
use http::Uri;
use hyper_util::rt::TokioIo;
use rustls::ClientConfig;
use rustls_pki_types::ServerName;
use socket2::{SockRef, TcpKeepalive};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tonic::body::Body;
use tonic::transport::Endpoint;
use tower::balance::p2c::Balance;
use tower::buffer::Buffer;
use tower::discover::ServiceList;
use tower::load::Load;
use tower::util::BoxCloneSyncService;
use tower::{BoxError, Service};

use crate::etcd::{EtcdClientConfig, EtcdConfigError};

/// Outer [`Buffer`] capacity: the frozen tonic/etcd default of 1024 in-flight
/// requests. This is the sole net-new request-side literal.
const BUFFER_CAPACITY: usize = 1024;

/// Initial failure-load backoff window (frozen: 1s, doubling to a 256s cap).
const BACKOFF_INITIAL: Duration = Duration::from_secs(1);
/// Maximum failure-load backoff window (frozen: 256s, no jitter).
const BACKOFF_MAX: Duration = Duration::from_secs(256);
/// HTTP/2 keepalive is never sent on idle connections (frozen policy).
const KEEP_ALIVE_WHILE_IDLE: bool = false;
/// Every dialed socket disables Nagle's algorithm (frozen policy).
const TCP_NODELAY: bool = true;
/// Upper bound on resolved addresses dialed for one endpoint within a single
/// connect budget, mirroring legacy tonic/hyper's bounded multi-address
/// fallback (a non-empty, order-preserving subset of the resolved set).
const MAX_RESOLVED_ADDRS: usize = 8;

/// The request type carried across the whole custom channel.
type TransportRequest = http::Request<Body>;
/// A boxed, `Send` future used by the leaf and fence services.
type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// The originating control owner was retired before the operation could commit.
#[derive(Debug, Error)]
#[error("stale control owner")]
pub(crate) struct StaleOwnerError;

/// A typed failure from one connect stage of [`OwnerFencedDialer`].
#[derive(Debug, Error)]
pub(crate) enum DialError {
    /// The owner generation was retired at a stage fence.
    #[error("stale control owner")]
    StaleOwner,
    /// Endpoint address resolution failed.
    #[error("etcd endpoint address resolution failed")]
    Resolve(#[source] std::io::Error),
    /// The TCP connection could not be established.
    #[error("etcd TCP connection failed")]
    Tcp(#[source] std::io::Error),
    /// The TLS handshake failed.
    #[error("etcd TLS handshake failed")]
    Tls(#[source] std::io::Error),
}

/// Returns `Ok` only while `owner` still holds its exact generation.
fn owner_fence(owner: &OwnerToken) -> Result<(), DialError> {
    if owner.is_current() {
        Ok(())
    } else {
        Err(DialError::StaleOwner)
    }
}

/// Locks a [`Mutex`], recovering the guard if a prior holder panicked.
fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A monotonic clock, injectable so failure-load state is deterministic in
/// tests.
pub(crate) trait Clock: Send + Sync + 'static {
    /// Returns the current instant.
    fn now(&self) -> Instant;
}

/// The production clock, reading the operating-system monotonic timer.
#[derive(Debug)]
pub(crate) struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

/// The comparable load metric for [`FailureBackoff`].
///
/// p2c prefers the *lower* value, and a backing-off endpoint must be
/// de-preferred, so `Healthy` sorts below `BackingOff`. The derived `PartialOrd`
/// orders by declaration order, giving exactly `Healthy < BackingOff`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum LoadMetric {
    /// The endpoint is not backing off; normal selection preference.
    Healthy,
    /// The endpoint failed recently and is de-preferred until its deadline.
    BackingOff,
}

/// Failure-load backoff state shared between the service and its response
/// futures.
#[derive(Debug)]
struct BackoffState {
    /// The instant until which the endpoint reports `BackingOff`, if any.
    deadline: Option<Instant>,
    /// The current backoff window length (doubles across distinct episodes).
    interval: Duration,
}

impl BackoffState {
    /// A fresh, healthy state at the initial backoff window.
    const fn new() -> Self {
        Self {
            deadline: None,
            interval: BACKOFF_INITIAL,
        }
    }

    /// Resets to the healthy baseline after a successful response.
    fn on_success(&mut self) {
        self.deadline = None;
        self.interval = BACKOFF_INITIAL;
    }

    /// Records a failure at `now`.
    ///
    /// A failure inside a live window only refreshes the deadline (no further
    /// doubling); a failure after a previous window expired opens a new episode
    /// and doubles the window up to the cap.
    fn on_failure(&mut self, now: Instant) {
        let live = self.deadline.is_some_and(|deadline| now < deadline);
        if live {
            self.deadline = Some(now + self.interval);
            return;
        }
        if self.deadline.is_some() {
            self.interval = (self.interval * 2).min(BACKOFF_MAX);
        }
        self.deadline = Some(now + self.interval);
    }

    /// The load metric observed at `now`.
    fn metric(&self, now: Instant) -> LoadMetric {
        if self.deadline.is_some_and(|deadline| now < deadline) {
            LoadMetric::BackingOff
        } else {
            LoadMetric::Healthy
        }
    }
}

/// Wraps a per-endpoint service with failure-load backoff.
///
/// It never removes, re-inserts, sleeps, or retries the current call: a failed
/// response only raises the endpoint's [`Load`] so p2c lowers its selection
/// preference until the backoff deadline expires. A failed endpoint can still be
/// selected if it or all peers are backing off.
pub(crate) struct FailureBackoff<S> {
    /// The wrapped per-endpoint service (a `tonic` [`Channel`] in production).
    inner: S,
    /// Shared backoff state, read by [`Load`] and written by response futures.
    state: Arc<Mutex<BackoffState>>,
    /// The injected clock.
    clock: Arc<dyn Clock>,
}

impl<S> FailureBackoff<S> {
    /// Wraps `inner`, starting healthy against the given `clock`.
    pub(crate) fn new(inner: S, clock: Arc<dyn Clock>) -> Self {
        Self {
            inner,
            state: Arc::new(Mutex::new(BackoffState::new())),
            clock,
        }
    }
}

impl<S, R> Service<R> for FailureBackoff<S>
where
    S: Service<R>,
    S::Error: Into<BoxError>,
    S::Response: Send + 'static,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = BoxError;
    type Future = BoxFuture<'static, Result<S::Response, BoxError>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, request: R) -> Self::Future {
        let state = Arc::clone(&self.state);
        let clock = Arc::clone(&self.clock);
        let future = self.inner.call(request);
        Box::pin(async move {
            let result = future.await;
            if result.is_ok() {
                lock(&state).on_success();
            } else {
                let now = clock.now();
                lock(&state).on_failure(now);
            }
            result.map_err(Into::into)
        })
    }
}

impl<S> Load for FailureBackoff<S> {
    type Metric = LoadMetric;

    fn load(&self) -> Self::Metric {
        let now = self.clock.now();
        lock(&self.state).metric(now)
    }
}

/// The owner fence that sits *outside* the outer [`Buffer`].
///
/// `poll_ready` delegates to the buffered inner service; `call` re-verifies the
/// owner and fails closed *without* touching the inner service when the
/// generation has been retired, closing the readiness-to-call gap that a bare
/// `Buffer` would leave open.
#[derive(Clone)]
pub(crate) struct OwnerCallFence<S> {
    /// The buffered balanced service.
    inner: S,
    /// The control owner this channel belongs to.
    owner: OwnerToken,
}

impl<S> OwnerCallFence<S> {
    /// Wraps `inner` with the owner fence.
    pub(crate) const fn new(inner: S, owner: OwnerToken) -> Self {
        Self { inner, owner }
    }
}

impl<S, R> Service<R> for OwnerCallFence<S>
where
    S: Service<R>,
    S::Error: Into<BoxError>,
    S::Response: Send + 'static,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = BoxError;
    type Future = BoxFuture<'static, Result<S::Response, BoxError>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, request: R) -> Self::Future {
        if !self.owner.is_current() {
            return Box::pin(std::future::ready(Err(
                Box::new(StaleOwnerError) as BoxError
            )));
        }
        let future = self.inner.call(request);
        Box::pin(async move { future.await.map_err(Into::into) })
    }
}

/// A unified plaintext-or-TLS stream that adapts to hyper IO via [`TokioIo`].
///
/// The `Tls` arm is boxed because `TlsStream` is substantially larger than a
/// bare `TcpStream`.
pub(crate) enum MaybeTlsStream {
    /// A plaintext TCP stream.
    Plain(TcpStream),
    /// A completed client TLS stream over TCP.
    Tls(Box<TlsStream<TcpStream>>),
}

impl AsyncRead for MaybeTlsStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_read(cx, buf),
            Self::Tls(stream) => Pin::new(stream.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for MaybeTlsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_write(cx, buf),
            Self::Tls(stream) => Pin::new(stream.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_flush(cx),
            Self::Tls(stream) => Pin::new(stream.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::Tls(stream) => Pin::new(stream.as_mut()).poll_shutdown(cx),
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_write_vectored(cx, bufs),
            Self::Tls(stream) => Pin::new(stream.as_mut()).poll_write_vectored(cx, bufs),
        }
    }

    fn is_write_vectored(&self) -> bool {
        match self {
            Self::Plain(stream) => stream.is_write_vectored(),
            Self::Tls(stream) => stream.is_write_vectored(),
        }
    }
}

/// The captured TLS parameters for one endpoint.
#[derive(Clone)]
pub(crate) struct TlsPlan {
    /// The 2a client configuration (verifier, protocol floor, mTLS material).
    config: Arc<ClientConfig>,
    /// The SNI name: the explicit domain override, else the logical host, never
    /// a resolved IP.
    server_name: ServerName<'static>,
}

/// Injectable DNS/TCP/TLS stages, so tests can substitute barrier-blocking
/// implementations while production uses [`ProdStageHooks`].
pub(crate) trait StageHooks: Send + Sync + 'static {
    /// Resolves `host:port` to a bounded, non-empty, order-preserving set of
    /// candidate socket addresses the dialer falls back across. Empty
    /// resolution is an error.
    fn resolve(
        &self,
        host: &str,
        port: u16,
    ) -> BoxFuture<'static, Result<Vec<SocketAddr>, DialError>>;

    /// Opens a TCP connection with `TCP_NODELAY` and the configured keepalive.
    fn tcp_connect(
        &self,
        addr: SocketAddr,
        keepalive: Duration,
    ) -> BoxFuture<'static, Result<TcpStream, DialError>>;

    /// Performs the client TLS handshake over an established TCP stream.
    fn tls_handshake(
        &self,
        stream: TcpStream,
        plan: TlsPlan,
    ) -> BoxFuture<'static, Result<MaybeTlsStream, DialError>>;
}

/// Collects a resolver's addresses into the bounded, order-preserving,
/// de-duplicated, non-empty candidate set the dialer falls back across.
///
/// This is the single production seam for multi-address preservation, so any
/// regression to a single address (a stray `.next()`/`.take(1)`) is caught by
/// its unit tests rather than silently degrading the resolver.
fn collect_candidates(
    resolved: impl Iterator<Item = SocketAddr>,
) -> Result<Vec<SocketAddr>, DialError> {
    let mut addrs: Vec<SocketAddr> = Vec::new();
    for addr in resolved {
        if addrs.len() >= MAX_RESOLVED_ADDRS {
            break;
        }
        if !addrs.contains(&addr) {
            addrs.push(addr);
        }
    }
    if addrs.is_empty() {
        return Err(DialError::Resolve(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "no address for endpoint",
        )));
    }
    Ok(addrs)
}

/// The production stage implementation: literal `host:port` resolution, a
/// `socket2`-configured TCP connect, and a `tokio-rustls` handshake.
#[derive(Debug)]
pub(crate) struct ProdStageHooks;

impl StageHooks for ProdStageHooks {
    fn resolve(
        &self,
        host: &str,
        port: u16,
    ) -> BoxFuture<'static, Result<Vec<SocketAddr>, DialError>> {
        // 2b-1 resolves the literal authority only; ns_servers-based discovery
        // fails closed to a later slice. Legacy tonic/hyper dials across the
        // whole resolved set, so the bounded, order-preserving set is returned
        // and the dialer falls back candidate by candidate.
        let authority = format!("{host}:{port}");
        Box::pin(async move {
            let resolved = tokio::task::spawn_blocking(move || authority.to_socket_addrs())
                .await
                .map_err(|error| DialError::Resolve(std::io::Error::other(error)))?
                .map_err(DialError::Resolve)?;
            collect_candidates(resolved)
        })
    }

    fn tcp_connect(
        &self,
        addr: SocketAddr,
        keepalive: Duration,
    ) -> BoxFuture<'static, Result<TcpStream, DialError>> {
        Box::pin(async move {
            let stream = TcpStream::connect(addr).await.map_err(DialError::Tcp)?;
            stream.set_nodelay(TCP_NODELAY).map_err(DialError::Tcp)?;
            let params = TcpKeepalive::new().with_time(keepalive);
            SockRef::from(&stream)
                .set_tcp_keepalive(&params)
                .map_err(DialError::Tcp)?;
            Ok(stream)
        })
    }

    fn tls_handshake(
        &self,
        stream: TcpStream,
        plan: TlsPlan,
    ) -> BoxFuture<'static, Result<MaybeTlsStream, DialError>> {
        Box::pin(async move {
            let connector = TlsConnector::from(plan.config);
            let tls = connector
                .connect(plan.server_name, stream)
                .await
                .map_err(DialError::Tls)?;
            Ok(MaybeTlsStream::Tls(Box::new(tls)))
        })
    }
}

/// A `Service<Uri>` connector that fences every awaited connect stage against a
/// stale owner.
///
/// The owner token is captured per endpoint (not shared). Each stage runs to
/// completion and is then re-checked: any post-await staleness drops the
/// successful result and returns [`DialError::StaleOwner`] rather than advancing
/// to the next stage or handing IO to tonic.
pub(crate) struct OwnerFencedDialer {
    /// The per-endpoint owner token.
    owner: OwnerToken,
    /// The logical host used for resolution and (absent an override) SNI.
    host: String,
    /// The endpoint port.
    port: u16,
    /// The TCP keepalive idle time.
    keepalive: Duration,
    /// TLS parameters, or `None` for a plaintext endpoint.
    tls: Option<TlsPlan>,
    /// The injectable connect stages.
    hooks: Arc<dyn StageHooks>,
}

impl Service<Uri> for OwnerFencedDialer {
    type Response = TokioIo<MaybeTlsStream>;
    type Error = DialError;
    type Future = BoxFuture<'static, Result<Self::Response, DialError>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _uri: Uri) -> Self::Future {
        let owner = self.owner.clone();
        let host = self.host.clone();
        let port = self.port;
        let keepalive = self.keepalive;
        let tls = self.tls.clone();
        let hooks = Arc::clone(&self.hooks);
        Box::pin(async move {
            owner_fence(&owner)?; // pre-DNS
            let addrs = hooks.resolve(&host, port).await?;
            owner_fence(&owner)?; // post-DNS
            // Legacy tonic/hyper falls back across the resolved address set
            // inside the single `Endpoint::connect_timeout` budget that already
            // wraps this whole future: a healthy later candidate still connects
            // when an earlier one is unreachable. No per-candidate timeout is
            // added — the sequential attempts share that one budget. This is
            // connection establishment, not RPC replay.
            let mut last_error: Option<DialError> = None;
            let mut connected: Option<TcpStream> = None;
            for addr in addrs {
                let result = hooks.tcp_connect(addr, keepalive).await;
                // Fence after EVERY candidate's await, before interpreting the
                // result or dialing the next one: a generation retired mid-attempt
                // must not initiate another socket connect.
                owner_fence(&owner)?;
                match result {
                    Ok(stream) => {
                        connected = Some(stream);
                        break;
                    }
                    Err(error) => last_error = Some(error),
                }
            }
            let Some(stream) = connected else {
                return Err(last_error.unwrap_or_else(|| {
                    DialError::Tcp(std::io::Error::new(
                        std::io::ErrorKind::NotConnected,
                        "endpoint resolved to no dialable address",
                    ))
                }));
            };
            // The successful candidate's await was already fenced in the loop
            // above, so no separate post-TCP fence is needed here.
            let stream = match tls {
                Some(plan) => hooks.tls_handshake(stream, plan).await?,
                None => MaybeTlsStream::Plain(stream),
            };
            owner_fence(&owner)?; // post-TLS
            Ok(TokioIo::new(stream))
        })
    }
}

/// The per-endpoint plan derived from the validated config, split so its TLS
/// wiring and config mirroring can be asserted directly.
pub(crate) struct EndpointBlueprint {
    /// The tonic transport URI: always `http://<authority>` so tonic's private
    /// connector never wraps TLS (avoiding `HttpsUriWithoutTlsSupport` and
    /// double-TLS); this dialer performs TLS itself.
    transport_uri: Uri,
    /// The logical `https://<authority>` origin for TLS endpoints, preserving
    /// the gRPC request scheme and authority via `Endpoint::origin`.
    origin: Option<Uri>,
    /// The SNI name for TLS endpoints.
    server_name: Option<ServerName<'static>>,
    /// The logical host used by the dialer for resolution.
    host: String,
    /// The endpoint port.
    port: u16,
    /// The whole-connector establishment budget.
    connect_timeout: Duration,
    /// The per-request deadline.
    request_timeout: Duration,
    /// The HTTP/2 keepalive ping interval.
    keep_alive_interval: Duration,
    /// The HTTP/2 keepalive ping timeout.
    keep_alive_timeout: Duration,
    /// The TCP keepalive idle time.
    tcp_keep_alive: Duration,
    /// The 2a client TLS configuration for TLS endpoints.
    tls: Option<Arc<ClientConfig>>,
}

impl EndpointBlueprint {
    /// Builds a blueprint from one normalized endpoint of `config`.
    ///
    /// # Errors
    ///
    /// Returns an [`EtcdConfigError`] if the (already validated) endpoint cannot
    /// be re-parsed, if the SNI name is invalid, or if the TLS material cannot
    /// form a client configuration.
    pub(crate) fn from_config(
        config: &EtcdClientConfig,
        index: usize,
        endpoint: &str,
    ) -> Result<Self, EtcdConfigError> {
        let malformed = || EtcdConfigError::InvalidEndpoint {
            index,
            reason: "endpoint could not be assembled",
        };
        let uri: Uri = endpoint.parse().map_err(|_| malformed())?;
        let authority = uri.authority().ok_or_else(malformed)?.clone();
        let host = uri.host().ok_or_else(malformed)?.to_owned();
        // A normalized endpoint may omit the port (e.g. `http://host`). Default
        // it by the endpoint's own scheme, exactly as legacy tonic does: the
        // normalized scheme is always present and is `https` iff TLS, so this is
        // zero-drift (443 under TLS, 80 for plaintext).
        let port = uri
            .port_u16()
            .unwrap_or(if uri.scheme_str() == Some("https") {
                443
            } else {
                80
            });
        let transport_uri = Uri::builder()
            .scheme("http")
            .authority(authority.clone())
            .path_and_query("/")
            .build()
            .map_err(|_| malformed())?;

        let (origin, server_name, tls) = match config.tls() {
            Some(tls) => {
                let origin = Uri::builder()
                    .scheme("https")
                    .authority(authority)
                    .path_and_query("/")
                    .build()
                    .map_err(|_| malformed())?;
                let sni = tls.domain_name().unwrap_or(&host).to_owned();
                let server_name =
                    ServerName::try_from(sni).map_err(|_| EtcdConfigError::InvalidEndpoint {
                        index,
                        reason: "invalid TLS server name",
                    })?;
                (Some(origin), Some(server_name), Some(tls.client_config()?))
            }
            None => (None, None, None),
        };

        Ok(Self {
            transport_uri,
            origin,
            server_name,
            host,
            port,
            connect_timeout: config.connect_timeout(),
            request_timeout: config.request_timeout(),
            keep_alive_interval: config.keep_alive_interval(),
            keep_alive_timeout: config.keep_alive_timeout(),
            tcp_keep_alive: config.tcp_keep_alive(),
            tls,
        })
    }

    /// Assembles the tonic [`Endpoint`], mirroring the config knobs.
    ///
    /// # Errors
    ///
    /// Returns an [`EtcdConfigError`] if the `http://` transport URI cannot form
    /// an endpoint.
    pub(crate) fn to_endpoint(&self, index: usize) -> Result<Endpoint, EtcdConfigError> {
        let mut endpoint = Endpoint::from_shared(self.transport_uri.to_string())
            .map_err(|_| EtcdConfigError::InvalidEndpoint {
                index,
                reason: "endpoint could not be assembled",
            })?
            .connect_timeout(self.connect_timeout)
            .timeout(self.request_timeout)
            .http2_keep_alive_interval(self.keep_alive_interval)
            .keep_alive_timeout(self.keep_alive_timeout)
            .keep_alive_while_idle(KEEP_ALIVE_WHILE_IDLE);
        if let Some(origin) = &self.origin {
            endpoint = endpoint.origin(origin.clone());
        }
        Ok(endpoint)
    }

    /// Builds the per-endpoint owner-fenced dialer.
    pub(crate) fn to_dialer(
        &self,
        owner: OwnerToken,
        hooks: Arc<dyn StageHooks>,
    ) -> OwnerFencedDialer {
        let tls = match (&self.tls, &self.server_name) {
            (Some(config), Some(server_name)) => Some(TlsPlan {
                config: Arc::clone(config),
                server_name: server_name.clone(),
            }),
            _ => None,
        };
        OwnerFencedDialer {
            owner,
            host: self.host.clone(),
            port: self.port,
            keepalive: self.tcp_keep_alive,
            tls,
            hooks,
        }
    }
}

/// Builds exactly one owner-fenced lazy service per configured endpoint.
///
/// This is the production-mandatory seam for the endpoint set: [`build_custom_channel`]
/// fans the balancer across precisely these services, so truncating or dropping
/// an endpoint (a `.take(1)` / `.skip(1)` regression) changes the returned count
/// and is caught by its unit test.
fn build_endpoint_services(
    config: &EtcdClientConfig,
    owner: &OwnerToken,
) -> Result<Vec<FailureBackoff<tonic::transport::Channel>>, EtcdConfigError> {
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let hooks: Arc<dyn StageHooks> = Arc::new(ProdStageHooks);
    let mut services = Vec::with_capacity(config.endpoints().len());
    for (index, endpoint) in config.endpoints().iter().enumerate() {
        let blueprint = EndpointBlueprint::from_config(config, index, endpoint)?;
        let dialer = blueprint.to_dialer(owner.clone(), Arc::clone(&hooks));
        let channel = blueprint
            .to_endpoint(index)?
            .connect_with_connector_lazy(dialer);
        services.push(FailureBackoff::new(channel, Arc::clone(&clock)));
    }
    Ok(services)
}

/// Builds the frozen owner-fenced custom `etcd-client` channel.
///
/// The returned [`etcd_client::Channel::Custom`] is the production etcd
/// transport: `EtcdConnector::connect` hands it to `Client::from_channel`. The
/// custom endpoints are lazy, so no network I/O happens here — the owner-fenced
/// DNS/TCP/TLS stages run on the first etcd operation.
///
/// # Errors
///
/// Returns an [`EtcdConfigError`] if any endpoint blueprint or tonic endpoint
/// cannot be assembled.
pub(crate) fn build_custom_channel(
    config: &EtcdClientConfig,
    owner: &OwnerToken,
) -> Result<etcd_client::Channel, EtcdConfigError> {
    let services = build_endpoint_services(config, owner)?;
    let balance = Balance::new(ServiceList::new::<TransportRequest>(services));
    let buffer = Buffer::new(balance, BUFFER_CAPACITY);
    let fenced = OwnerCallFence::new(buffer, owner.clone());
    Ok(etcd_client::Channel::Custom(BoxCloneSyncService::new(
        fenced,
    )))
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use control_plane::{OwnerScope, OwnershipRegistry};
    use tokio::net::TcpListener;
    use tokio::sync::Notify;
    use tower::util::rng::Rng;

    use super::{
        BUFFER_CAPACITY, Clock, DialError, EndpointBlueprint, FailureBackoff, LoadMetric,
        MaybeTlsStream, OwnerCallFence, StageHooks, StaleOwnerError, TlsPlan, build_custom_channel,
    };
    use crate::etcd::{EtcdClientConfig, EtcdTlsConfig, EtcdTlsPolicy};
    use rustls::ServerConfig;
    use rustls::server::{ClientHello, ResolvesServerCert};
    use rustls::sign::CertifiedKey;
    use rustls_pki_types::pem::PemObject;
    use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName};
    use socket2::SockRef;
    use std::fmt;
    use std::future::poll_fn;
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll};
    use std::time::{Duration, Instant};
    use tokio::net::TcpStream;
    use tokio::sync::oneshot;
    use tokio_rustls::TlsAcceptor;
    use tower::balance::p2c::Balance;
    use tower::buffer::Buffer;
    use tower::discover::ServiceList;
    use tower::load::Load;
    use tower::{BoxError, Service};

    /// A request body handle whose consumption is counted.
    type TestReq = Arc<AtomicUsize>;

    /// A manually advanced clock for deterministic backoff assertions.
    #[derive(Clone)]
    struct ManualClock {
        base: Instant,
        offset: Arc<Mutex<Duration>>,
    }

    impl ManualClock {
        fn new() -> Self {
            Self {
                base: Instant::now(),
                offset: Arc::new(Mutex::new(Duration::ZERO)),
            }
        }

        fn set(&self, offset: Duration) {
            *self
                .offset
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = offset;
        }
    }

    impl Clock for ManualClock {
        fn now(&self) -> Instant {
            self.base
                + *self
                    .offset
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
        }
    }

    /// A per-endpoint mock service that counts calls and consumes the body once.
    #[derive(Clone)]
    struct CountingEndpoint {
        id: usize,
        calls: Arc<AtomicUsize>,
        fail: Arc<AtomicBool>,
    }

    impl CountingEndpoint {
        fn new(id: usize) -> Self {
            Self {
                id,
                calls: Arc::new(AtomicUsize::new(0)),
                fail: Arc::new(AtomicBool::new(false)),
            }
        }
    }

    impl Service<TestReq> for CountingEndpoint {
        type Response = usize;
        type Error = BoxError;
        type Future = std::future::Ready<Result<usize, BoxError>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), BoxError>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, body: TestReq) -> Self::Future {
            self.calls.fetch_add(1, Ordering::SeqCst);
            body.fetch_add(1, Ordering::SeqCst);
            if self.fail.load(Ordering::SeqCst) {
                std::future::ready(Err(Box::new(StaleOwnerError) as BoxError))
            } else {
                std::future::ready(Ok(self.id))
            }
        }
    }

    /// A service whose readiness is permanently pending (never drains a buffer).
    struct NeverReady;

    impl Service<TestReq> for NeverReady {
        type Response = usize;
        type Error = BoxError;
        type Future = std::future::Ready<Result<usize, BoxError>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), BoxError>> {
            Poll::Pending
        }

        fn call(&mut self, _body: TestReq) -> Self::Future {
            std::future::ready(Ok(0))
        }
    }

    /// A deterministic `splitmix64` RNG for seeded p2c selection.
    struct SeededRng(u64);

    impl Rng for SeededRng {
        fn next_u64(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }
    }

    /// Which connect stage a [`BarrierHooks`] blocks inside its await.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Stage {
        Dns,
        Tcp,
        Tls,
    }

    /// Stage hooks that block one stage on a release notification and record how
    /// many times each stage was entered, so a fence can be tested precisely.
    struct BarrierHooks {
        block: Stage,
        addr: SocketAddr,
        entered: Arc<Notify>,
        release: Arc<Notify>,
        dns_calls: Arc<AtomicUsize>,
        tcp_calls: Arc<AtomicUsize>,
        tls_calls: Arc<AtomicUsize>,
    }

    impl BarrierHooks {
        fn new(block: Stage, addr: SocketAddr) -> Arc<Self> {
            Arc::new(Self {
                block,
                addr,
                entered: Arc::new(Notify::new()),
                release: Arc::new(Notify::new()),
                dns_calls: Arc::new(AtomicUsize::new(0)),
                tcp_calls: Arc::new(AtomicUsize::new(0)),
                tls_calls: Arc::new(AtomicUsize::new(0)),
            })
        }
    }

    impl StageHooks for BarrierHooks {
        fn resolve(
            &self,
            _host: &str,
            _port: u16,
        ) -> super::BoxFuture<'static, Result<Vec<SocketAddr>, DialError>> {
            self.dns_calls.fetch_add(1, Ordering::SeqCst);
            let block = self.block == Stage::Dns;
            let entered = Arc::clone(&self.entered);
            let release = Arc::clone(&self.release);
            let addr = self.addr;
            Box::pin(async move {
                if block {
                    entered.notify_one();
                    release.notified().await;
                }
                Ok(vec![addr])
            })
        }

        fn tcp_connect(
            &self,
            addr: SocketAddr,
            _keepalive: Duration,
        ) -> super::BoxFuture<'static, Result<TcpStream, DialError>> {
            self.tcp_calls.fetch_add(1, Ordering::SeqCst);
            let block = self.block == Stage::Tcp;
            let entered = Arc::clone(&self.entered);
            let release = Arc::clone(&self.release);
            Box::pin(async move {
                if block {
                    entered.notify_one();
                    release.notified().await;
                }
                TcpStream::connect(addr).await.map_err(DialError::Tcp)
            })
        }

        fn tls_handshake(
            &self,
            stream: TcpStream,
            _plan: TlsPlan,
        ) -> super::BoxFuture<'static, Result<MaybeTlsStream, DialError>> {
            self.tls_calls.fetch_add(1, Ordering::SeqCst);
            let block = self.block == Stage::Tls;
            let entered = Arc::clone(&self.entered);
            let release = Arc::clone(&self.release);
            Box::pin(async move {
                if block {
                    entered.notify_one();
                    release.notified().await;
                }
                // The fence test only needs the stage to succeed; no real
                // handshake is performed.
                Ok(MaybeTlsStream::Plain(stream))
            })
        }
    }

    /// Drives a `&mut` service to readiness then dispatches one request.
    async fn ready_call<S>(service: &mut S, request: TestReq) -> Result<S::Response, S::Error>
    where
        S: Service<TestReq>,
    {
        poll_fn(|cx| service.poll_ready(cx)).await?;
        service.call(request).await
    }

    /// A TLS config that skips CA verification (no trust anchor needed) with an
    /// explicit domain override.
    fn tls_config(domain: Option<&str>) -> EtcdTlsConfig {
        let policy = EtcdTlsPolicy {
            skip_ca_verification: true,
            ..EtcdTlsPolicy::default()
        };
        EtcdTlsConfig::new(None, None, None, domain.map(str::to_owned), policy)
            .unwrap_or_else(|error| unreachable!("tls config: {error}"))
    }

    fn owner() -> (OwnershipRegistry, control_plane::OwnerLease) {
        let registry = OwnershipRegistry::new();
        let lease = registry
            .claim(OwnerScope::Process, "owner-A")
            .unwrap_or_else(|error| unreachable!("claim: {error}"));
        (registry, lease)
    }

    #[tokio::test]
    async fn one_external_call_reaches_one_inner_service_once() {
        let (_registry, lease) = owner();
        let clock: Arc<dyn Clock> = Arc::new(super::SystemClock);
        let endpoint = CountingEndpoint::new(7);
        let calls = Arc::clone(&endpoint.calls);
        let balance = Balance::new(ServiceList::new::<TestReq>(vec![FailureBackoff::new(
            endpoint, clock,
        )]));
        let buffer = Buffer::new(balance, BUFFER_CAPACITY);
        let mut fenced = OwnerCallFence::new(buffer, lease.token());

        let body = Arc::new(AtomicUsize::new(0));
        let response = ready_call(&mut fenced, Arc::clone(&body))
            .await
            .unwrap_or_else(|error| unreachable!("call: {error}"));

        assert_eq!(response, 7, "the single endpoint answered");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "no replay: exactly one inner call"
        );
        assert_eq!(
            body.load(Ordering::SeqCst),
            1,
            "the body was consumed at most once"
        );
    }

    #[tokio::test]
    async fn p2c_spreads_across_ready_endpoints() {
        let clock: Arc<dyn Clock> = Arc::new(super::SystemClock);
        let endpoints: Vec<_> = (0..3).map(CountingEndpoint::new).collect();
        let counters: Vec<_> = endpoints.iter().map(|e| Arc::clone(&e.calls)).collect();
        let wrapped: Vec<_> = endpoints
            .into_iter()
            .map(|endpoint| FailureBackoff::new(endpoint, Arc::clone(&clock)))
            .collect();
        let mut balance =
            Balance::from_rng(ServiceList::new::<TestReq>(wrapped), SeededRng(0x1234_5678));

        for _ in 0..60 {
            let _ = ready_call(&mut balance, Arc::new(AtomicUsize::new(0)))
                .await
                .unwrap_or_else(|error| unreachable!("call: {error}"));
        }

        let used = counters
            .iter()
            .filter(|counter| counter.load(Ordering::SeqCst) > 0)
            .count();
        assert!(
            used >= 2,
            "p2c must spread across at least two endpoints, used {used}"
        );
    }

    #[test]
    fn outer_buffer_applies_backpressure_when_full() {
        let (mut buffer, _worker) = Buffer::<TestReq, _>::pair(NeverReady, BUFFER_CAPACITY);
        let waker = std::task::Waker::noop();
        let mut cx = Context::from_waker(waker);

        let mut responses = Vec::with_capacity(BUFFER_CAPACITY);
        for _ in 0..BUFFER_CAPACITY {
            let Poll::Ready(Ok(())) = buffer.poll_ready(&mut cx) else {
                unreachable!("a slot below capacity must be ready");
            };
            responses.push(buffer.call(Arc::new(AtomicUsize::new(0))));
        }
        assert!(
            matches!(buffer.poll_ready(&mut cx), Poll::Pending),
            "the {BUFFER_CAPACITY}th queued request exhausts the buffer"
        );
        drop(responses);
    }

    #[tokio::test]
    async fn failure_load_backs_off_refreshes_and_resets() {
        let clock = ManualClock::new();
        let endpoint = CountingEndpoint::new(0);
        let fail = Arc::clone(&endpoint.fail);
        let mut backoff = FailureBackoff::new(endpoint, Arc::new(clock.clone()) as Arc<dyn Clock>);

        assert!(
            LoadMetric::Healthy < LoadMetric::BackingOff,
            "healthy sorts below failed"
        );
        assert_eq!(backoff.load(), LoadMetric::Healthy, "starts healthy");

        // Fail at t=0: a 1s window opens.
        fail.store(true, Ordering::SeqCst);
        clock.set(Duration::ZERO);
        let _ = ready_call(&mut backoff, Arc::new(AtomicUsize::new(0))).await;
        assert_eq!(
            backoff.load(),
            LoadMetric::BackingOff,
            "failure raises load"
        );

        // Fail again at t=0.5 inside the live window: refresh only, no doubling.
        clock.set(Duration::from_millis(500));
        let _ = ready_call(&mut backoff, Arc::new(AtomicUsize::new(0))).await;
        clock.set(Duration::from_millis(1_400));
        assert_eq!(
            backoff.load(),
            LoadMetric::BackingOff,
            "refreshed 1s window still live"
        );
        clock.set(Duration::from_millis(1_600));
        assert_eq!(
            backoff.load(),
            LoadMetric::Healthy,
            "window is 1s from the refresh, proving no doubling to 2s"
        );

        // A new episode after expiry doubles the window to 2s.
        clock.set(Duration::from_millis(1_600));
        let _ = ready_call(&mut backoff, Arc::new(AtomicUsize::new(0))).await;
        clock.set(Duration::from_millis(3_500));
        assert_eq!(
            backoff.load(),
            LoadMetric::BackingOff,
            "2s window still live"
        );
        clock.set(Duration::from_millis(3_700));
        assert_eq!(backoff.load(), LoadMetric::Healthy, "2s window expired");

        // Success resets to the 1s baseline.
        fail.store(false, Ordering::SeqCst);
        clock.set(Duration::from_millis(3_700));
        let _ = ready_call(&mut backoff, Arc::new(AtomicUsize::new(0))).await;
        assert_eq!(
            backoff.load(),
            LoadMetric::Healthy,
            "success clears backoff"
        );
        fail.store(true, Ordering::SeqCst);
        clock.set(Duration::from_millis(4_000));
        let _ = ready_call(&mut backoff, Arc::new(AtomicUsize::new(0))).await;
        clock.set(Duration::from_millis(4_900));
        assert_eq!(
            backoff.load(),
            LoadMetric::BackingOff,
            "reset window is live at 0.9s"
        );
        clock.set(Duration::from_millis(5_100));
        assert_eq!(
            backoff.load(),
            LoadMetric::Healthy,
            "reset window is 1s, proving success returned to the baseline"
        );
    }

    async fn assert_stage_fence(block: Stage) {
        let (_registry, lease) = owner();
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|error| unreachable!("listener: {error}"));
        let addr = listener
            .local_addr()
            .unwrap_or_else(|error| unreachable!("addr: {error}"));
        let hooks = BarrierHooks::new(block, addr);

        let config =
            EtcdClientConfig::new(["etcd.internal:2379".to_owned()], Some(tls_config(None)))
                .unwrap_or_else(|error| unreachable!("config: {error}"));
        let blueprint = EndpointBlueprint::from_config(&config, 0, config.endpoints()[0].as_str())
            .unwrap_or_else(|error| unreachable!("blueprint: {error}"));
        let mut dialer =
            blueprint.to_dialer(lease.token(), Arc::clone(&hooks) as Arc<dyn StageHooks>);

        poll_fn(|cx| dialer.poll_ready(cx))
            .await
            .unwrap_or_else(|error| unreachable!("ready: {error}"));
        let uri = "http://etcd.internal:2379"
            .parse()
            .unwrap_or_else(|_| unreachable!());
        let future = dialer.call(uri);
        let handle = tokio::spawn(future);

        hooks.entered.notified().await; // the target stage is blocked in its await
        lease.release(); // retire the owner while the stage is mid-flight
        hooks.release.notify_one(); // let the stage succeed
        let result = handle
            .await
            .unwrap_or_else(|error| unreachable!("join: {error}"));

        assert!(
            matches!(result, Err(DialError::StaleOwner)),
            "the post-await fence must discard the successful stage"
        );
        let (dns, tcp, tls) = (
            hooks.dns_calls.load(Ordering::SeqCst),
            hooks.tcp_calls.load(Ordering::SeqCst),
            hooks.tls_calls.load(Ordering::SeqCst),
        );
        match block {
            Stage::Dns => assert_eq!((tcp, tls), (0, 0), "TCP/TLS must not run after a DNS fence"),
            Stage::Tcp => {
                assert_eq!(dns, 1, "DNS ran before the TCP stage");
                assert_eq!(tls, 0, "TLS must not run after a TCP fence");
            }
            Stage::Tls => {
                assert_eq!((dns, tcp), (1, 1), "DNS and TCP ran before the TLS stage");
                assert_eq!(tls, 1, "the TLS stage ran but its result was discarded");
            }
        }
    }

    #[tokio::test]
    async fn dialer_fences_dns_stage() {
        assert_stage_fence(Stage::Dns).await;
    }

    #[tokio::test]
    async fn dialer_fences_tcp_stage() {
        assert_stage_fence(Stage::Tcp).await;
    }

    #[tokio::test]
    async fn dialer_fences_tls_stage() {
        assert_stage_fence(Stage::Tls).await;
    }

    #[tokio::test]
    async fn owner_call_fence_closes_readiness_to_call_gap() {
        let (_registry, lease) = owner();
        let endpoint = CountingEndpoint::new(1);
        let calls = Arc::clone(&endpoint.calls);
        let clock: Arc<dyn Clock> = Arc::new(super::SystemClock);
        let balance = Balance::new(ServiceList::new::<TestReq>(vec![FailureBackoff::new(
            endpoint, clock,
        )]));
        let buffer = Buffer::new(balance, BUFFER_CAPACITY);
        let mut fenced = OwnerCallFence::new(buffer, lease.token());

        poll_fn(|cx| fenced.poll_ready(cx))
            .await
            .unwrap_or_else(|error| unreachable!("ready: {error}"));
        // Retire the owner AFTER readiness but BEFORE the call.
        lease.release();
        let error = fenced
            .call(Arc::new(AtomicUsize::new(0)))
            .await
            .err()
            .unwrap_or_else(|| unreachable!("stale owner must fail closed"));

        assert!(
            error.is::<StaleOwnerError>(),
            "the gap fails closed as a stale owner"
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "the inner service was never touched"
        );
    }

    #[tokio::test]
    async fn connect_timeout_trips_on_a_slow_stage() {
        let (_registry, lease) = owner();
        // A never-released DNS stage stalls the whole connector.
        let hooks = BarrierHooks::new(
            Stage::Dns,
            "127.0.0.1:1".parse().unwrap_or_else(|_| unreachable!()),
        );
        let config = EtcdClientConfig::new(["127.0.0.1:2379".to_owned()], None)
            .and_then(|config| {
                config.with_timeouts(
                    Duration::from_millis(50),
                    Duration::from_secs(5),
                    Duration::from_secs(10),
                    Duration::from_secs(3),
                    Duration::from_secs(30),
                )
            })
            .unwrap_or_else(|error| unreachable!("config: {error}"));
        let blueprint = EndpointBlueprint::from_config(&config, 0, config.endpoints()[0].as_str())
            .unwrap_or_else(|error| unreachable!("blueprint: {error}"));
        let dialer = blueprint.to_dialer(lease.token(), Arc::clone(&hooks) as Arc<dyn StageHooks>);
        let endpoint = blueprint
            .to_endpoint(0)
            .unwrap_or_else(|error| unreachable!("endpoint: {error}"));
        let mut channel = endpoint.connect_with_connector_lazy(dialer);

        let request = http::Request::builder()
            .method("POST")
            .uri("http://127.0.0.1:2379/")
            .body(super::Body::empty())
            .unwrap_or_else(|error| unreachable!("request: {error}"));
        poll_fn(|cx| channel.poll_ready(cx))
            .await
            .unwrap_or_else(|error| unreachable!("ready: {error}"));
        let outcome = tokio::time::timeout(Duration::from_secs(2), channel.call(request)).await;
        let Ok(result) = outcome else {
            unreachable!("the 50ms connect_timeout must fire well within 2s");
        };
        assert!(result.is_err(), "a stalled connector trips connect_timeout");
    }

    #[test]
    fn tls_endpoint_wires_http_transport_with_https_origin_and_hostname_sni() {
        let config = EtcdClientConfig::new(
            ["etcd.internal:2379".to_owned()],
            Some(tls_config(Some("sni.override.example"))),
        )
        .unwrap_or_else(|error| unreachable!("config: {error}"));
        let blueprint = EndpointBlueprint::from_config(&config, 0, config.endpoints()[0].as_str())
            .unwrap_or_else(|error| unreachable!("blueprint: {error}"));

        assert_eq!(
            blueprint.transport_uri.scheme_str(),
            Some("http"),
            "the transport URI is http:// so tonic never wraps TLS (no double-TLS)"
        );
        let origin = blueprint
            .origin
            .as_ref()
            .unwrap_or_else(|| unreachable!("a TLS endpoint carries an origin"));
        assert_eq!(
            origin.scheme_str(),
            Some("https"),
            "the gRPC origin stays https"
        );
        assert_eq!(
            origin.authority().map(http::uri::Authority::as_str),
            blueprint
                .transport_uri
                .authority()
                .map(http::uri::Authority::as_str),
            "origin and transport share one authority"
        );
        let server_name = blueprint
            .server_name
            .as_ref()
            .unwrap_or_else(|| unreachable!("a TLS endpoint carries an SNI name"));
        // The frozen invariant is that the SNI identity is the domain override
        // or the logical host, NEVER a resolved IP — not that it is always a
        // `DnsName` (an IP-literal logical host is a valid `IpAddress` identity;
        // see `tls_sni_is_the_logical_identity_never_a_resolved_ip`). Here the
        // override is a hostname, so the identity is exactly that override.
        assert_eq!(
            server_name.to_str(),
            "sni.override.example",
            "the domain override is used verbatim as the SNI identity"
        );

        // The endpoint assembles without HttpsUriWithoutTlsSupport (the http
        // transport URI is the guard) and is not auto-upgraded to TLS.
        blueprint
            .to_endpoint(0)
            .unwrap_or_else(|error| unreachable!("endpoint: {error}"));

        // Without an override, SNI falls back to the logical host.
        let no_override =
            EtcdClientConfig::new(["etcd.internal:2379".to_owned()], Some(tls_config(None)))
                .unwrap_or_else(|error| unreachable!("config: {error}"));
        let blueprint =
            EndpointBlueprint::from_config(&no_override, 0, no_override.endpoints()[0].as_str())
                .unwrap_or_else(|error| unreachable!("blueprint: {error}"));
        let server_name = blueprint
            .server_name
            .as_ref()
            .unwrap_or_else(|| unreachable!("SNI name"));
        assert_eq!(
            server_name.to_str(),
            "etcd.internal",
            "SNI falls back to the logical host"
        );

        // A plaintext endpoint has no origin, no SNI, and an http transport URI.
        let plain = EtcdClientConfig::new(["127.0.0.1:2379".to_owned()], None)
            .unwrap_or_else(|error| unreachable!("config: {error}"));
        let blueprint = EndpointBlueprint::from_config(&plain, 0, plain.endpoints()[0].as_str())
            .unwrap_or_else(|error| unreachable!("blueprint: {error}"));
        assert_eq!(blueprint.transport_uri.scheme_str(), Some("http"));
        assert!(
            blueprint.origin.is_none(),
            "plaintext endpoints have no origin"
        );
        assert!(
            blueprint.server_name.is_none(),
            "plaintext endpoints have no SNI"
        );
    }

    #[test]
    fn endpoint_and_socket_knobs_mirror_non_default_config() {
        // Non-default values on every knob, tracked through `with_timeouts`.
        let connect = Duration::from_secs(7);
        let request = Duration::from_secs(11);
        let keep_interval = Duration::from_secs(13);
        let keep_timeout = Duration::from_secs(4);
        let tcp_keep = Duration::from_secs(17);
        let config =
            EtcdClientConfig::new(["etcd.internal:2379".to_owned()], Some(tls_config(None)))
                .and_then(|config| {
                    config.with_timeouts(connect, request, keep_interval, keep_timeout, tcp_keep)
                })
                .unwrap_or_else(|error| unreachable!("config: {error}"));
        let blueprint = EndpointBlueprint::from_config(&config, 0, config.endpoints()[0].as_str())
            .unwrap_or_else(|error| unreachable!("blueprint: {error}"));

        assert_eq!(blueprint.connect_timeout, connect);
        assert_eq!(blueprint.request_timeout, request);
        assert_eq!(blueprint.keep_alive_interval, keep_interval);
        assert_eq!(blueprint.keep_alive_timeout, keep_timeout);
        assert_eq!(blueprint.tcp_keep_alive, tcp_keep);

        let endpoint = blueprint
            .to_endpoint(0)
            .unwrap_or_else(|error| unreachable!("endpoint: {error}"));
        assert_eq!(
            endpoint.get_connect_timeout(),
            Some(connect),
            "the connect_timeout reaches the Endpoint"
        );
        let keep_alive_while_idle = super::KEEP_ALIVE_WHILE_IDLE;
        assert!(
            !keep_alive_while_idle,
            "keepalive-while-idle is hardcoded false"
        );

        let (_registry, lease) = owner();
        let dialer = blueprint.to_dialer(lease.token(), Arc::new(super::ProdStageHooks));
        assert_eq!(
            dialer.keepalive, tcp_keep,
            "the socket keepalive mirrors tcp_keep_alive"
        );
        let tcp_nodelay = super::TCP_NODELAY;
        assert!(tcp_nodelay, "the dialer disables Nagle on every socket");

        // The frozen default TCP keepalive is 30s.
        let default_config = EtcdClientConfig::new(["etcd.internal:2379".to_owned()], None)
            .unwrap_or_else(|error| unreachable!("config: {error}"));
        assert_eq!(default_config.tcp_keep_alive(), Duration::from_secs(30));
    }

    #[tokio::test]
    async fn build_custom_channel_assembles_plain_and_tls_stacks() {
        let (_registry, lease) = owner();
        let plain = EtcdClientConfig::new(
            ["127.0.0.1:2379".to_owned(), "127.0.0.1:2380".to_owned()],
            None,
        )
        .unwrap_or_else(|error| unreachable!("config: {error}"));
        let channel = build_custom_channel(&plain, &lease.token())
            .unwrap_or_else(|error| unreachable!("plain channel: {error}"));
        assert!(
            matches!(channel, etcd_client::Channel::Custom(_)),
            "a custom channel is built"
        );

        let secure = EtcdClientConfig::new(
            ["etcd-a.internal:2379".to_owned()],
            Some(tls_config(Some("etcd.internal"))),
        )
        .unwrap_or_else(|error| unreachable!("config: {error}"));
        let channel = build_custom_channel(&secure, &lease.token())
            .unwrap_or_else(|error| unreachable!("tls channel: {error}"));
        assert!(
            matches!(channel, etcd_client::Channel::Custom(_)),
            "a TLS custom channel is built"
        );
    }

    #[tokio::test]
    async fn build_endpoint_services_builds_one_service_per_endpoint() {
        let (_registry, lease) = owner();
        let config = EtcdClientConfig::new(
            ["127.0.0.1:2379".to_owned(), "127.0.0.1:2380".to_owned()],
            None,
        )
        .unwrap_or_else(|error| unreachable!("config: {error}"));
        let services = super::build_endpoint_services(&config, &lease.token())
            .unwrap_or_else(|error| unreachable!("services: {error}"));
        // The balancer fans across exactly one service per configured endpoint;
        // a dropped or truncated endpoint (`.take(1)`/`.skip(1)`) changes this.
        assert_eq!(services.len(), 2, "one service per configured endpoint");
    }

    // ----- Fix 1: multi-address DNS fallback --------------------------------

    /// Stage hooks that resolve to a scripted candidate list and dial each
    /// candidate over a real socket, counting how often each stage runs. TLS is
    /// short-circuited to a plaintext stream so the same hooks drive the h2
    /// server tests below.
    struct ScriptedHooks {
        addrs: Vec<SocketAddr>,
        resolve_calls: Arc<AtomicUsize>,
        tcp_calls: Arc<AtomicUsize>,
    }

    impl StageHooks for ScriptedHooks {
        fn resolve(
            &self,
            _host: &str,
            _port: u16,
        ) -> super::BoxFuture<'static, Result<Vec<SocketAddr>, DialError>> {
            self.resolve_calls.fetch_add(1, Ordering::SeqCst);
            let addrs = self.addrs.clone();
            Box::pin(async move { Ok(addrs) })
        }

        fn tcp_connect(
            &self,
            addr: SocketAddr,
            _keepalive: Duration,
        ) -> super::BoxFuture<'static, Result<TcpStream, DialError>> {
            self.tcp_calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move { TcpStream::connect(addr).await.map_err(DialError::Tcp) })
        }

        fn tls_handshake(
            &self,
            stream: TcpStream,
            _plan: TlsPlan,
        ) -> super::BoxFuture<'static, Result<MaybeTlsStream, DialError>> {
            Box::pin(async move { Ok(MaybeTlsStream::Plain(stream)) })
        }
    }

    /// A bound-then-dropped local port that reliably refuses a connection.
    async fn refused_addr() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|error| unreachable!("bind: {error}"));
        let addr = listener
            .local_addr()
            .unwrap_or_else(|error| unreachable!("addr: {error}"));
        drop(listener);
        addr
    }

    /// Builds a plaintext dialer over the scripted hooks and drives one dial.
    async fn dial_over(
        addrs: Vec<SocketAddr>,
    ) -> (
        Result<super::TokioIo<MaybeTlsStream>, DialError>,
        Arc<AtomicUsize>,
        Arc<AtomicUsize>,
    ) {
        let (_registry, lease) = owner();
        let resolve_calls = Arc::new(AtomicUsize::new(0));
        let tcp_calls = Arc::new(AtomicUsize::new(0));
        let hooks = Arc::new(ScriptedHooks {
            addrs,
            resolve_calls: Arc::clone(&resolve_calls),
            tcp_calls: Arc::clone(&tcp_calls),
        });
        let config = EtcdClientConfig::new(["etcd.internal:2379".to_owned()], None)
            .unwrap_or_else(|error| unreachable!("config: {error}"));
        let blueprint = EndpointBlueprint::from_config(&config, 0, config.endpoints()[0].as_str())
            .unwrap_or_else(|error| unreachable!("blueprint: {error}"));
        let mut dialer = blueprint.to_dialer(lease.token(), hooks as Arc<dyn StageHooks>);
        poll_fn(|cx| dialer.poll_ready(cx))
            .await
            .unwrap_or_else(|error| unreachable!("ready: {error}"));
        let uri = "http://etcd.internal:2379"
            .parse()
            .unwrap_or_else(|_| unreachable!("uri"));
        let result = dialer.call(uri).await;
        (result, resolve_calls, tcp_calls)
    }

    #[tokio::test]
    async fn dialer_falls_back_to_a_live_candidate_after_a_dead_one() {
        let live_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|error| unreachable!("listener: {error}"));
        let live_addr = live_listener
            .local_addr()
            .unwrap_or_else(|error| unreachable!("addr: {error}"));
        let dead_addr = refused_addr().await;

        let (result, resolve_calls, tcp_calls) = dial_over(vec![dead_addr, live_addr]).await;

        assert!(
            result.is_ok(),
            "the dial falls back to the second, live candidate"
        );
        assert_eq!(
            resolve_calls.load(Ordering::SeqCst),
            1,
            "resolution runs exactly once for the whole fallback set"
        );
        assert_eq!(
            tcp_calls.load(Ordering::SeqCst),
            2,
            "the dead candidate is tried, then the live one"
        );
    }

    #[tokio::test]
    async fn dialer_surfaces_a_single_failure_when_every_candidate_fails() {
        let dead_first = refused_addr().await;
        let dead_second = refused_addr().await;

        let (result, resolve_calls, tcp_calls) = dial_over(vec![dead_first, dead_second]).await;

        // A single establishment failure surfaces from the TCP stage. Because
        // the dialer never yields a stream, tonic never dispatches the request,
        // so there is no RPC-level `Service::call` and no body replay: the
        // failure is reported once, not retried into a storm.
        assert!(
            matches!(result, Err(DialError::Tcp(_))),
            "every candidate failing yields one TCP establishment error"
        );
        assert_eq!(
            resolve_calls.load(Ordering::SeqCst),
            1,
            "resolution still runs exactly once, no retry storm"
        );
        assert_eq!(
            tcp_calls.load(Ordering::SeqCst),
            2,
            "each candidate is dialed exactly once"
        );
    }

    /// Hooks whose first candidate blocks in its `tcp_connect` await and then
    /// fails, while later candidates would succeed — so a generation retired
    /// during the first attempt must stop before the second candidate is dialed.
    struct FenceProbeHooks {
        addrs: Vec<SocketAddr>,
        tcp_calls: Arc<AtomicUsize>,
        entered: Arc<Notify>,
        release: Arc<Notify>,
    }

    impl StageHooks for FenceProbeHooks {
        fn resolve(
            &self,
            _host: &str,
            _port: u16,
        ) -> super::BoxFuture<'static, Result<Vec<SocketAddr>, DialError>> {
            let addrs = self.addrs.clone();
            Box::pin(async move { Ok(addrs) })
        }

        fn tcp_connect(
            &self,
            addr: SocketAddr,
            _keepalive: Duration,
        ) -> super::BoxFuture<'static, Result<TcpStream, DialError>> {
            let attempt = self.tcp_calls.fetch_add(1, Ordering::SeqCst);
            let entered = Arc::clone(&self.entered);
            let release = Arc::clone(&self.release);
            Box::pin(async move {
                if attempt == 0 {
                    entered.notify_one();
                    release.notified().await;
                    return Err(DialError::Tcp(std::io::Error::new(
                        std::io::ErrorKind::ConnectionRefused,
                        "first candidate refused",
                    )));
                }
                TcpStream::connect(addr).await.map_err(DialError::Tcp)
            })
        }

        fn tls_handshake(
            &self,
            stream: TcpStream,
            _plan: TlsPlan,
        ) -> super::BoxFuture<'static, Result<MaybeTlsStream, DialError>> {
            Box::pin(async move { Ok(MaybeTlsStream::Plain(stream)) })
        }
    }

    #[tokio::test]
    async fn dialer_fences_between_tcp_candidates() {
        let (_registry, lease) = owner();
        // A healthy second candidate: without the per-candidate fence the loop
        // would fall through and dial it after the owner retired.
        let live = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|error| unreachable!("listener: {error}"));
        let live_addr = live
            .local_addr()
            .unwrap_or_else(|error| unreachable!("addr: {error}"));
        let first_addr: SocketAddr = "127.0.0.1:9"
            .parse()
            .unwrap_or_else(|_| unreachable!("addr"));
        let tcp_calls = Arc::new(AtomicUsize::new(0));
        let entered = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let hooks = Arc::new(FenceProbeHooks {
            addrs: vec![first_addr, live_addr],
            tcp_calls: Arc::clone(&tcp_calls),
            entered: Arc::clone(&entered),
            release: Arc::clone(&release),
        });
        let config = EtcdClientConfig::new(["etcd.internal:2379".to_owned()], None)
            .unwrap_or_else(|error| unreachable!("config: {error}"));
        let blueprint = EndpointBlueprint::from_config(&config, 0, config.endpoints()[0].as_str())
            .unwrap_or_else(|error| unreachable!("blueprint: {error}"));
        let mut dialer = blueprint.to_dialer(lease.token(), hooks as Arc<dyn StageHooks>);
        poll_fn(|cx| dialer.poll_ready(cx))
            .await
            .unwrap_or_else(|error| unreachable!("ready: {error}"));
        let uri = "http://etcd.internal:2379"
            .parse()
            .unwrap_or_else(|_| unreachable!("uri"));
        let handle = tokio::spawn(dialer.call(uri));

        entered.notified().await; // the first candidate is blocked in its await
        lease.release(); // retire the owner mid-attempt
        release.notify_one(); // let the first attempt finish (it fails)
        let result = handle
            .await
            .unwrap_or_else(|error| unreachable!("join: {error}"));

        assert!(
            matches!(result, Err(DialError::StaleOwner)),
            "a per-candidate fence stops a retired generation"
        );
        assert_eq!(
            tcp_calls.load(Ordering::SeqCst),
            1,
            "the second candidate is never dialed after the owner retired"
        );
    }

    #[test]
    fn collect_candidates_preserves_bounded_ordered_unique_addresses() {
        let addr = |port: u16| -> SocketAddr {
            format!("127.0.0.1:{port}")
                .parse()
                .unwrap_or_else(|_| unreachable!("addr"))
        };
        // More than one address is preserved in order (a `.next()`/`.take(1)`
        // regression in the seam would fail here).
        let ordered = super::collect_candidates([addr(1), addr(2), addr(3)].into_iter())
            .unwrap_or_else(|error| unreachable!("collect: {error}"));
        assert_eq!(ordered, vec![addr(1), addr(2), addr(3)]);
        // Duplicates are removed, order preserved.
        let deduped = super::collect_candidates([addr(1), addr(1), addr(2), addr(1)].into_iter())
            .unwrap_or_else(|error| unreachable!("collect: {error}"));
        assert_eq!(deduped, vec![addr(1), addr(2)]);
        // The set is capped at MAX_RESOLVED_ADDRS, keeping the first N in order.
        let many: Vec<SocketAddr> = (1..=12).map(addr).collect();
        let capped = super::collect_candidates(many.clone().into_iter())
            .unwrap_or_else(|error| unreachable!("collect: {error}"));
        assert_eq!(capped.len(), super::MAX_RESOLVED_ADDRS);
        assert_eq!(capped.as_slice(), &many[..super::MAX_RESOLVED_ADDRS]);
        // An empty resolution fails closed.
        assert!(matches!(
            super::collect_candidates(std::iter::empty()),
            Err(DialError::Resolve(_))
        ));
    }

    // ----- Fix 2: endpoints without an explicit port ------------------------

    #[test]
    fn endpoints_without_an_explicit_port_default_by_scheme() {
        // Plaintext `http://host` (no port) defaults to 80.
        let plain = EtcdClientConfig::new(["http://etcd.internal".to_owned()], None)
            .unwrap_or_else(|error| unreachable!("config: {error}"));
        let blueprint = EndpointBlueprint::from_config(&plain, 0, plain.endpoints()[0].as_str())
            .unwrap_or_else(|error| unreachable!("blueprint: {error}"));
        assert_eq!(
            (blueprint.host.as_str(), blueprint.port),
            ("etcd.internal", 80),
            "a plaintext endpoint with no port defaults to 80"
        );

        // TLS `https://host` (no port) defaults to 443.
        let secure = EtcdClientConfig::new(["etcd.internal".to_owned()], Some(tls_config(None)))
            .unwrap_or_else(|error| unreachable!("config: {error}"));
        let blueprint = EndpointBlueprint::from_config(&secure, 0, secure.endpoints()[0].as_str())
            .unwrap_or_else(|error| unreachable!("blueprint: {error}"));
        assert_eq!(
            (blueprint.host.as_str(), blueprint.port),
            ("etcd.internal", 443),
            "a TLS endpoint with no port defaults to 443"
        );
    }

    // ----- Fix 3c: the SNI identity is the logical host, never a resolved IP -

    #[test]
    fn tls_sni_is_the_logical_identity_never_a_resolved_ip() {
        // An IPv4-literal logical host is a valid `IpAddress` identity for which
        // no SNI is sent — it is not (and must not be forced into) a `DnsName`.
        let ip_config =
            EtcdClientConfig::new(["127.0.0.1:2379".to_owned()], Some(tls_config(None)))
                .unwrap_or_else(|error| unreachable!("config: {error}"));
        let ip_blueprint =
            EndpointBlueprint::from_config(&ip_config, 0, ip_config.endpoints()[0].as_str())
                .unwrap_or_else(|error| unreachable!("blueprint: {error}"));
        let ip_name = ip_blueprint
            .server_name
            .as_ref()
            .unwrap_or_else(|| unreachable!("a TLS endpoint carries an identity"));
        assert!(
            matches!(ip_name, ServerName::IpAddress(_)),
            "an IP-literal logical host is an IpAddress identity, never a DnsName"
        );

        // A hostname logical host keeps its DnsName identity, and the dialer's
        // TlsPlan carries exactly that identity — never a resolved IP, even one
        // that resolution would return in place of the host.
        let host_config =
            EtcdClientConfig::new(["etcd.internal:2379".to_owned()], Some(tls_config(None)))
                .unwrap_or_else(|error| unreachable!("config: {error}"));
        let host_blueprint =
            EndpointBlueprint::from_config(&host_config, 0, host_config.endpoints()[0].as_str())
                .unwrap_or_else(|error| unreachable!("blueprint: {error}"));
        let (_registry, lease) = owner();
        let dialer = host_blueprint.to_dialer(lease.token(), Arc::new(super::ProdStageHooks));
        let plan = dialer
            .tls
            .clone()
            .unwrap_or_else(|| unreachable!("a TLS endpoint carries a TlsPlan"));
        assert!(
            matches!(plan.server_name, ServerName::DnsName(_)),
            "the identity for a hostname endpoint is a DnsName"
        );
        assert_eq!(
            plan.server_name.to_str(),
            "etcd.internal",
            "the dialer's TlsPlan SNI is the logical host"
        );
        // A candidate IP that resolution could return is never the SNI.
        assert_ne!(
            plan.server_name.to_str(),
            "203.0.113.7",
            "the SNI is never a resolved IP address"
        );
    }

    // ----- Fix 3a & Fix 4: an actual tonic Channel over an in-process h2 server

    /// Accepts one h2 connection, records the first request's `:scheme` and
    /// `:authority`, optionally delays, then answers a bare 200.
    async fn run_capturing_h2_server(
        listener: TcpListener,
        captured: oneshot::Sender<(Option<String>, Option<String>)>,
        response_delay: Duration,
    ) {
        let Ok((stream, _peer)) = listener.accept().await else {
            return;
        };
        let Ok(mut connection) = h2::server::handshake(stream).await else {
            return;
        };
        let mut captured = Some(captured);
        while let Some(Ok((request, mut responder))) = connection.accept().await {
            if let Some(sender) = captured.take() {
                let scheme = request.uri().scheme_str().map(str::to_owned);
                let authority = request
                    .uri()
                    .authority()
                    .map(|authority| authority.as_str().to_owned());
                let _ = sender.send((scheme, authority));
            }
            if !response_delay.is_zero() {
                tokio::time::sleep(response_delay).await;
            }
            let _ = responder.send_response(http::Response::new(()), true);
        }
    }

    /// Builds a TLS-origin channel whose dialer redirects (plaintext) to `addr`.
    /// The caller owns the lease behind `token`, keeping it current for the dial.
    fn channel_to(
        addr: SocketAddr,
        request_timeout: Option<Duration>,
        token: control_plane::OwnerToken,
    ) -> tonic::transport::Channel {
        let mut config =
            EtcdClientConfig::new(["etcd.internal:2379".to_owned()], Some(tls_config(None)))
                .unwrap_or_else(|error| unreachable!("config: {error}"));
        if let Some(timeout) = request_timeout {
            config = config
                .with_timeouts(
                    Duration::from_secs(5),
                    timeout,
                    Duration::from_secs(10),
                    Duration::from_secs(3),
                    Duration::from_secs(30),
                )
                .unwrap_or_else(|error| unreachable!("timeouts: {error}"));
        }
        let blueprint = EndpointBlueprint::from_config(&config, 0, config.endpoints()[0].as_str())
            .unwrap_or_else(|error| unreachable!("blueprint: {error}"));
        let hooks = Arc::new(ScriptedHooks {
            addrs: vec![addr],
            resolve_calls: Arc::new(AtomicUsize::new(0)),
            tcp_calls: Arc::new(AtomicUsize::new(0)),
        });
        let dialer = blueprint.to_dialer(token, hooks as Arc<dyn StageHooks>);
        blueprint
            .to_endpoint(0)
            .unwrap_or_else(|error| unreachable!("endpoint: {error}"))
            .connect_with_connector_lazy(dialer)
    }

    fn grpc_request(path: &str) -> http::Request<super::Body> {
        http::Request::builder()
            .method("POST")
            .uri(path)
            .body(super::Body::empty())
            .unwrap_or_else(|error| unreachable!("request: {error}"))
    }

    #[tokio::test]
    async fn tls_origin_drives_https_scheme_and_authority_over_the_transport() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|error| unreachable!("listener: {error}"));
        let addr = listener
            .local_addr()
            .unwrap_or_else(|error| unreachable!("addr: {error}"));
        let (sender, receiver) = oneshot::channel();
        tokio::spawn(run_capturing_h2_server(listener, sender, Duration::ZERO));

        let (_registry, lease) = owner();
        let mut channel = channel_to(addr, None, lease.token());
        poll_fn(|cx| channel.poll_ready(cx))
            .await
            .unwrap_or_else(|error| unreachable!("ready: {error}"));
        let response = tokio::time::timeout(
            Duration::from_secs(5),
            channel.call(grpc_request("https://etcd.internal:2379/svc/Method")),
        )
        .await;
        let Ok(Ok(response)) = response else {
            unreachable!("the call over the h2 server must complete");
        };
        assert_eq!(response.status(), 200, "the server answered 200");

        let Ok(Ok((scheme, authority))) =
            tokio::time::timeout(Duration::from_secs(5), receiver).await
        else {
            unreachable!("the server must have captured the request head");
        };
        // `.origin(https://...)` drives these pseudo-headers; deleting it makes
        // tonic fall back to the `http://` transport URI and `:scheme` becomes
        // `http`, turning this assertion RED.
        assert_eq!(
            scheme.as_deref(),
            Some("https"),
            "the https origin sets the request :scheme"
        );
        assert_eq!(
            authority.as_deref(),
            Some("etcd.internal:2379"),
            "the origin sets the request :authority"
        );
    }

    #[tokio::test]
    async fn request_timeout_fails_a_slow_response_but_not_a_fast_one() {
        let request_timeout = Duration::from_millis(300);
        let (_registry, lease) = owner();

        // Slow: the response is delayed well past the request timeout, so the
        // call must error. Deleting `.timeout(...)` lets the call wait out the
        // delay and succeed, turning this assertion RED.
        let slow_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|error| unreachable!("listener: {error}"));
        let slow_addr = slow_listener
            .local_addr()
            .unwrap_or_else(|error| unreachable!("addr: {error}"));
        let (slow_tx, _slow_rx) = oneshot::channel();
        tokio::spawn(run_capturing_h2_server(
            slow_listener,
            slow_tx,
            Duration::from_millis(1_500),
        ));
        let mut slow_channel = channel_to(slow_addr, Some(request_timeout), lease.token());
        poll_fn(|cx| slow_channel.poll_ready(cx))
            .await
            .unwrap_or_else(|error| unreachable!("ready: {error}"));
        let slow = tokio::time::timeout(
            Duration::from_secs(3),
            slow_channel.call(grpc_request("https://etcd.internal:2379/svc/Method")),
        )
        .await;
        let Ok(slow_result) = slow else {
            unreachable!("the request timeout must trip well within 3s");
        };
        assert!(
            slow_result.is_err(),
            "a response slower than the request timeout fails the call"
        );

        // Fast: the same request timeout, but a prompt response, so the call
        // succeeds — proving the timeout, not a broken connection, caused the
        // failure above.
        let fast_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|error| unreachable!("listener: {error}"));
        let fast_addr = fast_listener
            .local_addr()
            .unwrap_or_else(|error| unreachable!("addr: {error}"));
        let (fast_tx, _fast_rx) = oneshot::channel();
        tokio::spawn(run_capturing_h2_server(
            fast_listener,
            fast_tx,
            Duration::ZERO,
        ));
        let mut fast_channel = channel_to(fast_addr, Some(request_timeout), lease.token());
        poll_fn(|cx| fast_channel.poll_ready(cx))
            .await
            .unwrap_or_else(|error| unreachable!("ready: {error}"));
        let fast = tokio::time::timeout(
            Duration::from_secs(3),
            fast_channel.call(grpc_request("https://etcd.internal:2379/svc/Method")),
        )
        .await;
        let Ok(Ok(response)) = fast else {
            unreachable!("a prompt response within the timeout must succeed");
        };
        assert_eq!(response.status(), 200, "the prompt response is delivered");
    }

    // ----- Fix 3b: a real local-TLS handshake carries the chosen SNI --------

    /// A server certificate resolver that records the `ClientHello` SNI.
    struct SniCapturingResolver {
        observed: Arc<Mutex<Option<String>>>,
        certified: Arc<CertifiedKey>,
    }

    impl fmt::Debug for SniCapturingResolver {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("SniCapturingResolver")
                .finish_non_exhaustive()
        }
    }

    impl ResolvesServerCert for SniCapturingResolver {
        fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
            *self
                .observed
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) =
                client_hello.server_name().map(str::to_owned);
            Some(Arc::clone(&self.certified))
        }
    }

    /// A self-signed server certificate (PEM) with `hostname` in its SAN.
    fn self_signed_server_cert(hostname: &str) -> (String, String) {
        let mut params = rcgen::CertificateParams::new(vec![hostname.to_owned()])
            .unwrap_or_else(|error| unreachable!("cert params: {error}"));
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        let key = rcgen::KeyPair::generate().unwrap_or_else(|error| unreachable!("key: {error}"));
        let certificate = params
            .self_signed(&key)
            .unwrap_or_else(|error| unreachable!("self-signed: {error}"));
        (certificate.pem(), key.serialize_pem())
    }

    /// Builds a rustls `TlsAcceptor` whose resolver records the negotiated SNI.
    fn sni_capturing_acceptor(
        cert_pem: &str,
        key_pem: &str,
        observed: Arc<Mutex<Option<String>>>,
    ) -> TlsAcceptor {
        let certificate = CertificateDer::from_pem_slice(cert_pem.as_bytes())
            .unwrap_or_else(|error| unreachable!("cert: {error}"))
            .into_owned();
        let key = PrivateKeyDer::from_pem_slice(key_pem.as_bytes())
            .unwrap_or_else(|error| unreachable!("key: {error}"));
        let signing = rustls::crypto::ring::sign::any_supported_type(&key)
            .unwrap_or_else(|error| unreachable!("signing key: {error}"));
        let certified = Arc::new(CertifiedKey::new(vec![certificate], signing));
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(rustls::ALL_VERSIONS)
            .unwrap_or_else(|error| unreachable!("server versions: {error}"))
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(SniCapturingResolver {
                observed,
                certified,
            }));
        TlsAcceptor::from(Arc::new(config))
    }

    /// Drives `ProdStageHooks::tls_handshake` against a real local TLS server
    /// and asserts both the dialer's `TlsPlan` and the SNI observed on the wire.
    async fn assert_prod_tls_sni(domain_override: Option<&str>, expected_sni: &str) {
        let (cert_pem, key_pem) = self_signed_server_cert("etcd.internal");
        let observed = Arc::new(Mutex::new(None));
        let acceptor = sni_capturing_acceptor(&cert_pem, &key_pem, Arc::clone(&observed));
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|error| unreachable!("listener: {error}"));
        let addr = listener
            .local_addr()
            .unwrap_or_else(|error| unreachable!("addr: {error}"));
        let server = tokio::spawn(async move {
            if let Ok((stream, _peer)) = listener.accept().await {
                let _ = acceptor.accept(stream).await;
            }
        });

        let config = EtcdClientConfig::new(
            ["etcd.internal:2379".to_owned()],
            Some(tls_config(domain_override)),
        )
        .unwrap_or_else(|error| unreachable!("config: {error}"));
        let blueprint = EndpointBlueprint::from_config(&config, 0, config.endpoints()[0].as_str())
            .unwrap_or_else(|error| unreachable!("blueprint: {error}"));
        let (_registry, lease) = owner();
        let dialer = blueprint.to_dialer(lease.token(), Arc::new(super::ProdStageHooks));
        let plan = dialer
            .tls
            .clone()
            .unwrap_or_else(|| unreachable!("a TLS endpoint carries a TlsPlan"));
        assert_eq!(
            plan.server_name.to_str(),
            expected_sni,
            "the dialer's TlsPlan carries the chosen SNI identity"
        );

        let stream = TcpStream::connect(addr)
            .await
            .unwrap_or_else(|error| unreachable!("connect: {error}"));
        let handshaked = super::ProdStageHooks
            .tls_handshake(stream, plan)
            .await
            .unwrap_or_else(|error| unreachable!("client handshake: {error}"));
        assert!(
            matches!(handshaked, MaybeTlsStream::Tls(_)),
            "the handshake yields a TLS stream"
        );
        server
            .await
            .unwrap_or_else(|error| unreachable!("server task: {error}"));
        let captured = observed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        assert_eq!(
            captured.as_deref(),
            Some(expected_sni),
            "the server observed the chosen SNI on the wire"
        );
    }

    #[tokio::test]
    async fn prod_tls_handshake_sends_the_override_then_the_logical_host_sni() {
        // (i) an explicit domain override is the SNI sent on the wire.
        assert_prod_tls_sni(Some("sni.override.example"), "sni.override.example").await;
        // (ii) absent an override, the logical host is the SNI.
        assert_prod_tls_sni(None, "etcd.internal").await;
    }

    // ----- Fix 5: the dialer applies the socket knobs to a real socket ------

    #[tokio::test]
    async fn prod_tcp_connect_applies_nodelay_and_keepalive_to_the_socket() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|error| unreachable!("listener: {error}"));
        let addr = listener
            .local_addr()
            .unwrap_or_else(|error| unreachable!("addr: {error}"));
        let accept = tokio::spawn(async move {
            let accepted = listener.accept().await;
            // Hold the accepted connection open for the duration of the test.
            std::future::pending::<()>().await;
            drop(accepted);
        });

        // A non-default keepalive so the assertion cannot pass on a default.
        let keepalive = Duration::from_secs(17);
        let stream = super::ProdStageHooks
            .tcp_connect(addr, keepalive)
            .await
            .unwrap_or_else(|error| unreachable!("tcp connect: {error}"));

        assert!(
            stream
                .nodelay()
                .unwrap_or_else(|error| unreachable!("nodelay: {error}")),
            "the dialer disables Nagle on the socket"
        );
        let sock = SockRef::from(&stream);
        assert!(
            sock.keepalive()
                .unwrap_or_else(|error| unreachable!("keepalive: {error}")),
            "the dialer enables SO_KEEPALIVE on the socket"
        );
        #[cfg(target_os = "linux")]
        {
            let idle = sock
                .tcp_keepalive_time()
                .unwrap_or_else(|error| unreachable!("keepalive time: {error}"));
            assert!(
                idle >= Duration::from_secs(15) && idle <= Duration::from_secs(19),
                "the keepalive idle time reflects the non-default 17s, got {idle:?}"
            );
        }
        accept.abort();
    }
}
