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

//! Listener loop mirroring Go `pkg/server/api/server.go`.
//!
//! Without HTTP TLS every connection reaches the full route table over
//! HTTP/1.1 or cleartext HTTP/2 (Go `UseH2C`). With TLS configured the
//! first byte is sniffed like Go's `cmux`: a TLS record reaches the full
//! table through the acceptor, anything else reaches only the plaintext
//! readiness routes. The current TLS configuration is read per connection
//! from a watch channel so a rotated certificate applies to new connections
//! without rebinding. Connections are bounded by a permit count, every
//! connection task is tracked, and shutdown stops accepting, lets in-flight
//! requests finish within a grace period, then drops the rest.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use axum::Router;
use axum::body::Body;
use hyper::rt::{Read, ReadBufCursor, Write};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto::Builder;
use hyper_util::server::graceful::{GracefulShutdown, Watcher};
use hyper_util::service::TowerToHyperService;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Notify, Semaphore, watch};
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;
use tower::Service;

/// Reads the current `security.server-http-tls` server configuration for one
/// accepted connection; `None` serves plaintext only. Reading per connection
/// lets a rotated certificate apply without rebinding, like the metric server.
pub type TlsConfigSource = Arc<dyn Fn() -> Option<Arc<rustls::ServerConfig>> + Send + Sync>;

/// Listener tunables; defaults follow the Go server.
#[derive(Clone, Copy, Debug)]
pub struct ServeOptions {
    /// Go `DefConnTimeout`: HTTP/1 request-head read timeout, the
    /// activity-based idle timeout applied to HTTP/1 and HTTP/2 connections,
    /// and the `cmux` sniff timeout.
    pub connection_timeout: Duration,
    /// Concurrent connections admitted; further accepts are closed at once.
    pub max_connections: usize,
    /// Longest wait for in-flight requests after shutdown begins.
    pub shutdown_grace: Duration,
}

impl Default for ServeOptions {
    fn default() -> Self {
        Self {
            connection_timeout: Duration::from_secs(30),
            max_connections: 1024,
            shutdown_grace: Duration::from_secs(5),
        }
    }
}

/// Serves until `shutdown` turns true or the listener fails.
pub async fn serve(
    listener: TcpListener,
    full: Router,
    plaintext: Router,
    tls: TlsConfigSource,
    mut shutdown: watch::Receiver<bool>,
    options: ServeOptions,
) {
    let graceful = GracefulShutdown::new();
    let mut tasks = JoinSet::new();
    let permits = Arc::new(Semaphore::new(options.max_connections.max(1)));
    let mut builder = Builder::new(TokioExecutor::new());
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(options.connection_timeout);
    builder.http2().timer(TokioTimer::new());
    loop {
        let accepted = tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
                continue;
            }
            accepted = listener.accept() => accepted,
            // Reap finished connection tasks so the set never grows unbounded.
            Some(_) = tasks.join_next(), if !tasks.is_empty() => continue,
        };
        let Ok((stream, _)) = accepted else {
            // A failing listener is fatal for the server task; the owner
            // observes the task exit and decides.
            break;
        };
        let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
            drop(stream);
            continue;
        };
        let connection = Connection {
            tls: tls(),
            full: full.clone(),
            plaintext: plaintext.clone(),
            builder: builder.clone(),
            watcher: graceful.watcher(),
            timeout: options.connection_timeout,
        };
        tasks.spawn(async move {
            let _permit = permit;
            connection.run(stream).await;
        });
    }
    drop(listener);
    // Bounded stop: in-flight hyper connections get the grace period; every
    // task still alive after it (sniffing, handshaking, slow bodies) is
    // aborted and joined, so nothing outlives this future.
    let _ = tokio::time::timeout(options.shutdown_grace, graceful.shutdown()).await;
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
}

struct Connection {
    tls: Option<Arc<rustls::ServerConfig>>,
    full: Router,
    plaintext: Router,
    builder: Builder<TokioExecutor>,
    watcher: Watcher,
    timeout: Duration,
}

impl Connection {
    async fn run(self, stream: TcpStream) {
        let Some(config) = self.tls else {
            serve_io(stream, self.full, &self.builder, self.watcher, self.timeout).await;
            return;
        };
        // cmux: the first byte decides the branch; a silent peer is dropped
        // after the connection timeout instead of holding a permit forever.
        let mut first = [0_u8; 1];
        let Ok(Ok(1)) = tokio::time::timeout(self.timeout, stream.peek(&mut first)).await else {
            return;
        };
        if first[0] != 0x16 {
            serve_io(
                stream,
                self.plaintext,
                &self.builder,
                self.watcher,
                self.timeout,
            )
            .await;
            return;
        }
        let acceptor = TlsAcceptor::from(config);
        let Ok(Ok(stream)) = tokio::time::timeout(self.timeout, acceptor.accept(stream)).await
        else {
            return;
        };
        serve_io(stream, self.full, &self.builder, self.watcher, self.timeout).await;
    }
}

/// Serves one connection until hyper finishes, the graceful watcher ends it,
/// or the idle watchdog fires: no successful read or write for
/// `idle_timeout` closes the connection, the behaviour Go's `IdleTimeout`
/// gives HTTP/1 keep-alive and that hyper has no built-in equivalent for
/// on HTTP/2. Dropping the connection future closes the socket.
async fn serve_io<I>(
    io: I,
    router: Router,
    builder: &Builder<TokioExecutor>,
    watcher: Watcher,
    idle_timeout: Duration,
) where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let started = Instant::now();
    let activity = Arc::new(Activity {
        last: AtomicU64::new(0),
        active_requests: AtomicUsize::new(0),
        started,
        settled: Notify::new(),
    });
    let io = IdleIo {
        inner: TokioIo::new(io),
        activity: Arc::clone(&activity),
    };
    let service = Tracked {
        inner: router,
        activity: Arc::clone(&activity),
    };
    let connection = builder
        .serve_connection(io, TowerToHyperService::new(service))
        .into_owned();
    let guarded = watcher.watch(connection);
    tokio::pin!(guarded);
    // Go's IdleTimeout counts only the gap between requests: a request that
    // is still being read or handled keeps the connection alive however long
    // it takes, so the watchdog fires only with zero active requests.
    let watchdog = async {
        loop {
            if activity.active_requests.load(Ordering::Acquire) > 0 {
                // A request is in flight: wait for it to settle instead of
                // polling a deadline that already passed.
                activity.settled.notified().await;
                continue;
            }
            let last = Duration::from_millis(activity.last.load(Ordering::Acquire));
            let deadline = started + last + idle_timeout;
            tokio::select! {
                () = tokio::time::sleep_until(deadline.into()) => {}
                () = activity.settled.notified() => continue,
            }
            if activity.idle_for(idle_timeout) {
                return;
            }
        }
    };
    tokio::select! {
        _ = &mut guarded => {}
        () = watchdog => {}
    }
}

/// Per-connection liveness: last successful read/write/response instant and
/// the number of requests currently being read or handled.
struct Activity {
    last: AtomicU64,
    active_requests: AtomicUsize,
    started: Instant,
    /// Woken when a request settles so the watchdog re-arms its deadline
    /// (`notify_one`: a permit survives until the watchdog waits).
    settled: Notify,
}

impl Activity {
    fn touch(&self) {
        let elapsed = u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.last.store(elapsed, Ordering::Release);
    }

    /// True only when no request is in flight and nothing happened for
    /// `timeout`.
    fn idle_for(&self, timeout: Duration) -> bool {
        if self.active_requests.load(Ordering::Acquire) > 0 {
            return false;
        }
        let idle = self
            .started
            .elapsed()
            .saturating_sub(Duration::from_millis(self.last.load(Ordering::Acquire)));
        idle >= timeout
    }
}

/// Counts a request as active from dispatch until its response body has
/// been fully produced or dropped (a streaming body keeps the request
/// active), then stamps the activity instant so the idle gap starts after
/// the response.
#[derive(Clone)]
struct Tracked {
    inner: Router,
    activity: Arc<Activity>,
}

struct ActiveRequest(Arc<Activity>);

impl Drop for ActiveRequest {
    fn drop(&mut self) {
        self.0.active_requests.fetch_sub(1, Ordering::AcqRel);
        self.0.touch();
        // `notify_one` stores a permit when the single watchdog is not yet
        // waiting, so a settle between its check and its wait is never lost.
        self.0.settled.notify_one();
    }
}

impl Service<hyper::Request<hyper::body::Incoming>> for Tracked {
    type Response = <Router as Service<hyper::Request<hyper::body::Incoming>>>::Response;
    type Error = <Router as Service<hyper::Request<hyper::body::Incoming>>>::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        <Router as Service<hyper::Request<hyper::body::Incoming>>>::poll_ready(&mut self.inner, cx)
    }

    fn call(&mut self, request: hyper::Request<hyper::body::Incoming>) -> Self::Future {
        self.activity.active_requests.fetch_add(1, Ordering::AcqRel);
        let guard = ActiveRequest(Arc::clone(&self.activity));
        let future = self.inner.call(request);
        Box::pin(async move {
            let response = future.await?;
            Ok(response.map(|body| {
                Body::new(GuardedBody {
                    inner: body,
                    _guard: guard,
                })
            }))
        })
    }
}

/// Response body that releases the active-request guard only when the body
/// is exhausted or dropped.
struct GuardedBody {
    inner: Body,
    _guard: ActiveRequest,
}

impl hyper::body::Body for GuardedBody {
    type Data = axum::body::Bytes;
    type Error = axum::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
        Pin::new(&mut self.get_mut().inner).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        self.inner.size_hint()
    }
}

/// hyper I/O wrapper that stamps the last successful read or write.
struct IdleIo<I> {
    inner: TokioIo<I>,
    activity: Arc<Activity>,
}

impl<I> IdleIo<I> {
    fn touch(&self) {
        self.activity.touch();
    }
}

impl<I: AsyncRead + Unpin> Read for IdleIo<I> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: ReadBufCursor<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let poll = Pin::new(&mut this.inner).poll_read(cx, buf);
        if matches!(poll, Poll::Ready(Ok(()))) {
            this.touch();
        }
        poll
    }
}

impl<I: AsyncWrite + Unpin> Write for IdleIo<I> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let poll = Pin::new(&mut this.inner).poll_write(cx, buf);
        if matches!(poll, Poll::Ready(Ok(_))) {
            this.touch();
        }
        poll
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let poll = Pin::new(&mut this.inner).poll_write_vectored(cx, bufs);
        if matches!(poll, Poll::Ready(Ok(_))) {
            this.touch();
        }
        poll
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::health::{HealthInputs, HealthState};
    use crate::router::{AdminApp, AdminHooks, DataplaneStatus, full_router, plaintext_router};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
    use std::net::SocketAddr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn app() -> Arc<AdminApp> {
        let hooks = AdminHooks::fixed(
            HealthInputs {
                closing: false,
                namespaces_ready: true,
                applied_generation: 1,
                config_checksum: 7,
            },
            "# metrics\n".to_owned(),
            DataplaneStatus::default(),
            Arc::new(crate::config::MemoryConfigAdmin::default()),
        );
        let app = Arc::new(AdminApp::new(hooks, HealthState::new()));
        app.mark_ready();
        app
    }

    fn certificate() -> (Arc<rustls::ServerConfig>, CertificateDer<'static>) {
        let certified = rcgen::generate_simple_self_signed(["localhost".to_owned()]).unwrap();
        let cert = certified.cert.der().clone();
        let key = PrivateKeyDer::try_from(certified.signing_key.serialize_der()).unwrap();
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert.clone()], key)
        .unwrap();
        (Arc::new(config), cert)
    }

    async fn start(
        tls: Option<Arc<rustls::ServerConfig>>,
    ) -> (SocketAddr, watch::Sender<bool>, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let app = app();
        let tls: TlsConfigSource = Arc::new(move || tls.clone());
        let task = tokio::spawn(async move {
            serve(
                listener,
                full_router(Arc::clone(&app)),
                plaintext_router(app),
                tls,
                shutdown_rx,
                ServeOptions {
                    connection_timeout: Duration::from_secs(2),
                    shutdown_grace: Duration::from_millis(200),
                    ..ServeOptions::default()
                },
            )
            .await;
        });
        (address, shutdown_tx, task)
    }

    async fn plain_request(address: SocketAddr, target: &str) -> String {
        let mut stream = TcpStream::connect(address).await.unwrap();
        stream
            .write_all(
                format!("GET {target} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").as_bytes(),
            )
            .await
            .unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        String::from_utf8_lossy(&response).into_owned()
    }

    async fn tls_request(
        address: SocketAddr,
        cert: &CertificateDer<'static>,
        target: &str,
    ) -> String {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert.clone()).unwrap();
        let config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
        let stream = TcpStream::connect(address).await.unwrap();
        let mut stream = connector
            .connect(ServerName::try_from("localhost").unwrap(), stream)
            .await
            .unwrap();
        stream
            .write_all(
                format!("GET {target} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").as_bytes(),
            )
            .await
            .unwrap();
        let mut response = Vec::new();
        let _ = stream.read_to_end(&mut response).await;
        String::from_utf8_lossy(&response).into_owned()
    }

    #[tokio::test]
    async fn plaintext_listener_serves_the_full_table() {
        let (address, shutdown, task) = start(None).await;
        let metrics = plain_request(address, "/metrics").await;
        assert!(metrics.starts_with("HTTP/1.1 200 OK"), "{metrics}");
        assert!(metrics.ends_with("# metrics\n"));
        let health = plain_request(address, "/api/debug/health").await;
        assert!(health.ends_with("{\"config_checksum\":7}"), "{health}");
        shutdown.send_replace(true);
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .unwrap()
            .unwrap();
        assert!(TcpStream::connect(address).await.is_err() || plain_request_fails(address).await);
    }

    async fn plain_request_fails(address: SocketAddr) -> bool {
        let Ok(mut stream) = TcpStream::connect(address).await else {
            return true;
        };
        let _ = stream
            .write_all(b"GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n")
            .await;
        let mut buffer = Vec::new();
        let read =
            tokio::time::timeout(Duration::from_secs(1), stream.read_to_end(&mut buffer)).await;
        !matches!(read, Ok(Ok(n)) if n > 0)
    }

    #[tokio::test]
    async fn tls_listener_splits_plaintext_health_from_the_tls_table() {
        let (config, cert) = certificate();
        let (address, shutdown, task) = start(Some(config)).await;
        let plain_health = plain_request(address, "/debug/health").await;
        assert!(
            plain_health.starts_with("HTTP/1.1 200 OK"),
            "{plain_health}"
        );
        let plain_metrics = plain_request(address, "/metrics").await;
        assert!(plain_metrics.starts_with("HTTP/1.1 404"), "{plain_metrics}");
        let tls_metrics = tls_request(address, &cert, "/metrics").await;
        assert!(tls_metrics.starts_with("HTTP/1.1 200 OK"), "{tls_metrics}");
        assert!(tls_metrics.ends_with("# metrics\n"));
        shutdown.send_replace(true);
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn shutdown_reclaims_connections_still_sniffing_or_mid_request() {
        let (config, _cert) = certificate();
        let (address, shutdown, task) = start(Some(config)).await;
        // A peer that never sends a byte would otherwise hold its task until
        // the 2 s sniff timeout; shutdown must reclaim it within the grace.
        let mut silent = TcpStream::connect(address).await.unwrap();
        // A plaintext peer that sent a partial request head is inside hyper
        // and gets the grace period, then is dropped.
        let mut partial = TcpStream::connect(address).await.unwrap();
        partial
            .write_all(b"GET /debug/health HTTP/1.1\r\nHost: x\r\n")
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        let started = Instant::now();
        shutdown.send_replace(true);
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .unwrap()
            .unwrap();
        assert!(
            started.elapsed() < Duration::from_millis(1500),
            "{:?}",
            started.elapsed()
        );
        let mut buffer = [0_u8; 1];
        let closed = tokio::time::timeout(Duration::from_secs(1), silent.read(&mut buffer)).await;
        assert!(matches!(closed, Ok(Ok(0) | Err(_))), "{closed:?}");
        let closed = tokio::time::timeout(Duration::from_secs(1), partial.read(&mut buffer)).await;
        assert!(matches!(closed, Ok(Ok(0) | Err(_))), "{closed:?}");
    }

    #[tokio::test]
    async fn idle_keep_alive_connection_is_closed_after_the_timeout() {
        let (address, shutdown, task) = start(None).await;
        let mut stream = TcpStream::connect(address).await.unwrap();
        stream
            .write_all(b"GET /debug/health HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();
        let mut buffer = vec![0_u8; 4096];
        let n = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        assert!(String::from_utf8_lossy(&buffer[..n]).starts_with("HTTP/1.1 200 OK"));
        // Keep-alive: the connection stays open, then the 2 s idle watchdog
        // (connection_timeout in these tests) closes it without a request.
        let started = Instant::now();
        let closed = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buffer)).await;
        assert!(matches!(closed, Ok(Ok(0) | Err(_))), "{closed:?}");
        assert!(
            started.elapsed() >= Duration::from_millis(1500),
            "{:?}",
            started.elapsed()
        );
        shutdown.send_replace(true);
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn in_flight_request_is_not_closed_as_idle() {
        let (address, shutdown, task) = start(None).await;
        let mut stream = TcpStream::connect(address).await.unwrap();
        // Headers of a PUT whose body arrives only after the idle timeout
        // (2 s here): the request is active, so the watchdog must not fire.
        stream
            .write_all(
                b"PUT /api/debug/health HTTP/1.1\r\nHost: x\r\nContent-Length: 16\r\nContent-Type: application/json\r\n\r\n",
            )
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(2600)).await;
        stream.write_all(b"{\"healthy\":true}").await.unwrap();
        let mut buffer = vec![0_u8; 4096];
        let n = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        assert!(
            String::from_utf8_lossy(&buffer[..n]).starts_with("HTTP/1.1 200 OK"),
            "{}",
            String::from_utf8_lossy(&buffer[..n])
        );
        shutdown.send_replace(true);
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn silent_peer_is_dropped_after_the_sniff_timeout() {
        let (config, _cert) = certificate();
        let (address, shutdown, task) = start(Some(config)).await;
        let mut silent = TcpStream::connect(address).await.unwrap();
        let mut buffer = [0_u8; 1];
        let closed = tokio::time::timeout(Duration::from_secs(5), silent.read(&mut buffer)).await;
        assert!(matches!(closed, Ok(Ok(0) | Err(_))), "{closed:?}");
        shutdown.send_replace(true);
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .unwrap()
            .unwrap();
    }
    /// Reviewer regression (`CodexM5`, `e30148d9`): a peer still inside the TLS
    /// sniff when shutdown begins must be closed once `serve` completes.
    /// Reviewer regression (`CodexM5`, `813b3140`): the between-request idle
    /// timeout must not cancel a handler that is still producing its answer.
    #[tokio::test]
    async fn review_idle_timeout_does_not_cancel_an_active_handler() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (shutdown, stop) = watch::channel(false);
        let router = Router::new().route(
            "/slow",
            axum::routing::get(|| async {
                tokio::time::sleep(Duration::from_millis(200)).await;
                "finished"
            }),
        );
        let task = tokio::spawn(serve(
            listener,
            router.clone(),
            router,
            Arc::new(|| None),
            stop,
            ServeOptions {
                connection_timeout: Duration::from_millis(50),
                shutdown_grace: Duration::from_millis(50),
                ..ServeOptions::default()
            },
        ));
        let response =
            tokio::time::timeout(Duration::from_secs(2), plain_request(address, "/slow"))
                .await
                .unwrap();
        shutdown.send_replace(true);
        task.await.unwrap();
        assert!(
            response.starts_with("HTTP/1.1 200") && response.ends_with("finished"),
            "an active handler must outlive the between-request idle timeout: {response:?}"
        );
    }

    #[tokio::test]
    async fn review_shutdown_reclaims_silent_tls_sniff_connection() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (shutdown, stop) = watch::channel(false);
        let app = app();
        let (certificate, _) = certificate();
        let accepted = Arc::new(AtomicBool::new(false));
        let observed = Arc::clone(&accepted);
        let tls: TlsConfigSource = Arc::new(move || {
            observed.store(true, Ordering::Release);
            Some(Arc::clone(&certificate))
        });
        let task = tokio::spawn(serve(
            listener,
            full_router(Arc::clone(&app)),
            plaintext_router(app),
            tls,
            stop,
            ServeOptions {
                connection_timeout: Duration::from_secs(10),
                shutdown_grace: Duration::from_millis(20),
                ..ServeOptions::default()
            },
        ));
        let mut client = TcpStream::connect(address).await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            while !accepted.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        shutdown.send_replace(true);
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap();
        let mut byte = [0_u8; 1];
        let closed = tokio::time::timeout(Duration::from_millis(100), client.read(&mut byte)).await;
        assert!(
            matches!(closed, Ok(Ok(0) | Err(_))),
            "socket must be closed when serve completes: {closed:?}"
        );
    }

    // ---- diagnostics gRPC on the same listener (CP-ADMIN slice 4b) ----

    use control_external::diagnostics::{
        LogLevel, LogMessage, SearchLogRequest, SearchLogResponse, ServerInfoRequest,
        ServerInfoResponse,
    };
    use http::uri::PathAndQuery;
    use tonic_prost::ProstCodec;

    fn app_with_log(log_file: Option<std::path::PathBuf>) -> Arc<AdminApp> {
        let mut hooks = AdminHooks::fixed(
            HealthInputs {
                closing: false,
                namespaces_ready: true,
                applied_generation: 1,
                config_checksum: 7,
            },
            "# metrics\n".to_owned(),
            DataplaneStatus::default(),
            Arc::new(crate::config::MemoryConfigAdmin::default()),
        );
        hooks.log_file = log_file;
        let app = Arc::new(AdminApp::new(hooks, HealthState::new()));
        app.mark_ready();
        app
    }

    async fn start_app(
        app: Arc<AdminApp>,
        tls: Option<Arc<rustls::ServerConfig>>,
    ) -> (SocketAddr, watch::Sender<bool>, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let tls: TlsConfigSource = Arc::new(move || tls.clone());
        let task = tokio::spawn(async move {
            serve(
                listener,
                full_router(Arc::clone(&app)),
                plaintext_router(app),
                tls,
                shutdown_rx,
                ServeOptions {
                    connection_timeout: Duration::from_secs(5),
                    shutdown_grace: Duration::from_millis(200),
                    ..ServeOptions::default()
                },
            )
            .await;
        });
        (address, shutdown_tx, task)
    }

    fn log_fixture(lines: usize) -> std::path::PathBuf {
        use std::fmt::Write as _;
        let dir = std::env::temp_dir().join(format!(
            "tiproxy-cpdiag-grpc-{}-{lines}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut body = String::new();
        for i in 0..lines {
            let _ = writeln!(
                body,
                "[2019/08/26 06:19:{:02}.{:03} -04:00] [INFO] [p.go:1] [\"line {i}\"]",
                (i / 1000) % 60,
                i % 1000
            );
        }
        std::fs::write(dir.join("tiproxy.log"), body).unwrap();
        dir.join("tiproxy.log")
    }

    async fn plain_channel(address: SocketAddr) -> tonic::transport::Channel {
        tonic::transport::Endpoint::from_shared(format!("http://{address}"))
            .unwrap()
            .connect()
            .await
            .unwrap()
    }

    async fn tls_channel(
        address: SocketAddr,
        cert: CertificateDer<'static>,
    ) -> tonic::transport::Channel {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert).unwrap();
        let config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
        let service = tower::service_fn(move |_uri: http::Uri| {
            let connector = connector.clone();
            async move {
                let stream = TcpStream::connect(address).await?;
                let stream = connector
                    .connect(ServerName::try_from("localhost").unwrap(), stream)
                    .await?;
                Ok::<_, io::Error>(TokioIo::new(stream))
            }
        });
        // The connector performs TLS itself; tonic's own TLS feature is off,
        // so the endpoint keeps the plain scheme.
        tonic::transport::Endpoint::from_shared(format!("http://{address}"))
            .unwrap()
            .connect_with_connector(service)
            .await
            .unwrap()
    }

    async fn search(
        channel: tonic::transport::Channel,
        request: SearchLogRequest,
    ) -> Result<Vec<Vec<LogMessage>>, tonic::Status> {
        let mut client = tonic::client::Grpc::new(channel);
        client
            .ready()
            .await
            .map_err(|e| tonic::Status::unknown(e.to_string()))?;
        let mut stream = client
            .server_streaming(
                tonic::Request::new(request),
                PathAndQuery::from_static("/diagnosticspb.Diagnostics/search_log"),
                ProstCodec::<SearchLogRequest, SearchLogResponse>::default(),
            )
            .await?
            .into_inner();
        let mut batches = Vec::new();
        while let Some(response) = stream.message().await? {
            batches.push(response.messages);
        }
        Ok(batches)
    }

    async fn server_info(
        channel: tonic::transport::Channel,
        tp: i32,
    ) -> Result<ServerInfoResponse, tonic::Status> {
        let mut client = tonic::client::Grpc::new(channel);
        client
            .ready()
            .await
            .map_err(|e| tonic::Status::unknown(e.to_string()))?;
        client
            .unary(
                tonic::Request::new(ServerInfoRequest { tp }),
                PathAndQuery::from_static("/diagnosticspb.Diagnostics/server_info"),
                ProstCodec::<ServerInfoRequest, ServerInfoResponse>::default(),
            )
            .await
            .map(tonic::Response::into_inner)
    }

    /// `SearchLog` over plaintext HTTP/2 (gin `UseH2C` + `grpcServer`):
    /// batches of 1024 with a final partial batch, level and pattern
    /// filters applied, and Go's fixed error text for a missing path as the
    /// stream status.
    #[tokio::test]
    async fn grpc_over_h2c_streams_search_log_batches_and_reports_errors() {
        let log = log_fixture(2049);
        let (address, shutdown, task) = start_app(app_with_log(Some(log.clone())), None).await;
        let all = search(
            plain_channel(address).await,
            SearchLogRequest {
                start_time: 0,
                end_time: 0,
                levels: Vec::new(),
                patterns: Vec::new(),
                target: 0,
            },
        )
        .await
        .unwrap();
        assert_eq!(
            all.iter().map(Vec::len).collect::<Vec<_>>(),
            vec![1024, 1024, 1]
        );
        assert_eq!(all[0][0].message, "[p.go:1] [\"line 0\"]");
        assert_eq!(all[0][0].level, LogLevel::Info as i32);
        let filtered = search(
            plain_channel(address).await,
            SearchLogRequest {
                start_time: 0,
                end_time: 0,
                levels: vec![LogLevel::Warn as i32],
                patterns: vec!["line 7$".to_owned()],
                target: 0,
            },
        )
        .await
        .unwrap();
        assert_eq!(
            filtered,
            vec![Vec::<LogMessage>::new()],
            "no WARN lines: one empty batch"
        );
        let (no_log_address, shutdown2, task2) = start_app(app_with_log(None), None).await;
        let error = search(
            plain_channel(no_log_address).await,
            SearchLogRequest::default(),
        )
        .await
        .unwrap_err();
        assert_eq!(error.code(), tonic::Code::Unknown);
        assert_eq!(error.message(), "empty log file location configuration");
        let _ = std::fs::remove_dir_all(log.parent().unwrap());
        let _ = shutdown.send(true);
        let _ = shutdown2.send(true);
        let _ = task.await;
        let _ = task2.await;
    }

    /// `ServerInfo` answers the `sysutil` inventory over the wire, sorted by
    /// type and name; an unknown type answers no items.
    #[tokio::test]
    async fn grpc_server_info_answers_the_sysutil_inventory() {
        let (address, shutdown, task) = start_app(app_with_log(None), None).await;
        let channel = plain_channel(address).await;
        let load = server_info(channel.clone(), 3).await.unwrap().items;
        let keys: Vec<(String, String)> = load
            .iter()
            .map(|item| (item.tp.clone(), item.name.clone()))
            .collect();
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(keys, sorted, "sorted by type then name");
        assert!(
            keys.contains(&("cpu".to_owned(), "cpu".to_owned())),
            "load average item present: {keys:?}"
        );
        let unknown = server_info(channel, 7).await.unwrap().items;
        assert!(unknown.is_empty());
        let _ = shutdown.send(true);
        let _ = task.await;
    }

    /// gin's split needs `ProtoMajor == 2`: an HTTP/1.1 request with the
    /// gRPC content type is an ordinary route lookup and gets gin's 404.
    #[tokio::test]
    async fn http1_grpc_content_type_is_not_split_off() {
        let (address, shutdown, task) = start_app(app_with_log(None), None).await;
        let mut stream = TcpStream::connect(address).await.unwrap();
        stream
            .write_all(
                b"POST /diagnosticspb.Diagnostics/server_info HTTP/1.1\r\nHost: x\r\n\
                  Content-Type: application/grpc\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();
        let mut response = Vec::new();
        let _ = stream.read_to_end(&mut response).await;
        let response = String::from_utf8_lossy(&response);
        assert!(response.starts_with("HTTP/1.1 404 "), "{response}");
        assert!(response.ends_with("404 page not found"), "{response}");
        let _ = shutdown.send(true);
        let _ = task.await;
    }

    /// Under HTTP TLS the gRPC service sits behind the TLS branch of the
    /// sniff (cmux `TLS()` → engine with `grpcServer`): an HTTP/2 gRPC call
    /// over TLS reaches the service.
    #[tokio::test]
    async fn tls_h2_grpc_is_served_after_the_sniff() {
        let (tls, cert) = certificate();
        let log = log_fixture(3);
        let (address, shutdown, task) = start_app(app_with_log(Some(log.clone())), Some(tls)).await;
        let answer = server_info(tls_channel(address, cert.clone()).await, 7).await;
        assert!(answer.is_ok(), "served after the sniff: {answer:?}");
        let batches = search(
            tls_channel(address, cert).await,
            SearchLogRequest {
                start_time: 0,
                end_time: 0,
                levels: Vec::new(),
                patterns: Vec::new(),
                target: 0,
            },
        )
        .await
        .unwrap();
        assert_eq!(batches.iter().map(Vec::len).collect::<Vec<_>>(), vec![3]);
        let _ = std::fs::remove_dir_all(log.parent().unwrap());
        let _ = shutdown.send(true);
        let _ = task.await;
    }

    /// The readiness gate precedes the gRPC split (gin: `readyState` then
    /// `grpcServer`): before ready, a gRPC call gets the HTTP 500 answer.
    #[tokio::test]
    async fn grpc_waits_behind_the_readiness_gate() {
        let hooks = AdminHooks::fixed(
            HealthInputs {
                closing: false,
                namespaces_ready: true,
                applied_generation: 1,
                config_checksum: 7,
            },
            "# metrics\n".to_owned(),
            DataplaneStatus::default(),
            Arc::new(crate::config::MemoryConfigAdmin::default()),
        );
        let app = Arc::new(AdminApp::new(hooks, HealthState::new()));
        let (address, shutdown, task) = start_app(Arc::clone(&app), None).await;
        // gin's readiness gate answers HTTP 500 before the router; tonic maps
        // that to a non-OK status without a gRPC trailer.
        let error = server_info(plain_channel(address).await, 7)
            .await
            .unwrap_err();
        assert_ne!(error.code(), tonic::Code::Ok, "{error:?}");
        app.mark_ready();
        let answer = server_info(plain_channel(address).await, 7).await;
        assert!(answer.is_ok(), "served once ready: {answer:?}");
        let _ = shutdown.send(true);
        let _ = task.await;
    }
}
