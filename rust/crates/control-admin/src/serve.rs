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

use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use hyper::rt::{Read, Write};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto::Builder;
use hyper_util::server::graceful::{GracefulShutdown, Watcher};
use hyper_util::service::TowerToHyperService;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, watch};
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;

/// Reads the current `security.server-http-tls` server configuration for one
/// accepted connection; `None` serves plaintext only. Reading per connection
/// lets a rotated certificate apply without rebinding, like the metric server.
pub type TlsConfigSource = Arc<dyn Fn() -> Option<Arc<rustls::ServerConfig>> + Send + Sync>;

/// Listener tunables; defaults follow the Go server.
#[derive(Clone, Copy, Debug)]
pub struct ServeOptions {
    /// Go `DefConnTimeout`: request-head read timeout, idle timeout, and the
    /// `cmux` sniff timeout.
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
            serve_io(TokioIo::new(stream), self.full, &self.builder, self.watcher).await;
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
                TokioIo::new(stream),
                self.plaintext,
                &self.builder,
                self.watcher,
            )
            .await;
            return;
        }
        let acceptor = TlsAcceptor::from(config);
        let Ok(Ok(stream)) = tokio::time::timeout(self.timeout, acceptor.accept(stream)).await
        else {
            return;
        };
        serve_io(TokioIo::new(stream), self.full, &self.builder, self.watcher).await;
    }
}

async fn serve_io<I>(io: I, router: Router, builder: &Builder<TokioExecutor>, watcher: Watcher)
where
    I: Read + Write + Unpin + Send + 'static,
{
    let connection = builder
        .serve_connection(io, TowerToHyperService::new(router))
        .into_owned();
    let _ = watcher.watch(connection).await;
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
        let started = std::time::Instant::now();
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
}
