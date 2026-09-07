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

//! Owner-fenced, single-attempt HTTP `/status` probe for a backend cluster.
//!
//! [`ClusterHttpClient`] owns the TLS/HTTP exchange for one backend cluster's
//! per-backend `/status` health read (CP-TOPO #213-1) over the cluster's shared
//! owner-fenced raw connector ([`ClusterConnector`], CP-TOPO #215-1: the
//! explicit-nameserver resolver — or the system resolver when no `ns_servers` are
//! configured — plus the bounded candidate dial). It applies the cluster's
//! advanced TLS material
//! ([`EtcdTlsConfig::client_config`](crate::etcd::EtcdTlsConfig)) on top, so a
//! probe honors the exact DNS and TLS policy the cluster's etcd transport already
//! uses.
//!
//! One [`ClusterHttpClient::get_once`] is a SINGLE attempt bounded by one
//! absolute deadline covering the whole exchange — DNS resolve, candidate-IP TCP
//! connect(s), TLS handshake, request write, header read, and every body frame —
//! with NO per-stage budget refill. Retry, backoff, and the health decision are a
//! pure policy layer above this module (`control-topology`); this module never
//! retries, never parses the body, and never logs it.
//!
//! Every awaited stage is fenced against the process [`OwnerToken`] AND the
//! caller's source [`GenerationGate`] before and after it runs. A fence failure
//! is TERMINAL and wins over any coincident I/O error, so a retired owner or a
//! superseded routing source is never reported as a retryable transport failure.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use control_plane::OwnerToken;
use http::header::{CONNECTION, CONTENT_LENGTH, HOST};
use http::{Method, Request, StatusCode};
use http_body_util::{BodyExt, Empty};
use hyper::body::{Bytes, Incoming};
use hyper_util::rt::TokioIo;
use rustls::ClientConfig;
use rustls_pki_types::ServerName;
use thiserror::Error;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::cluster_connect::{
    ClusterConnectError, ClusterConnector, MAX_PROBE_TIMEOUT, parse_ip_literal,
};
use crate::etcd::{EtcdClientConfig, EtcdConfigError, GenerationGate};
use crate::explicit_dns::ResolveError;
use crate::http::MAX_HTTP_RESPONSE_BYTES;
use crate::transport::MaybeTlsStream;

/// The origin-form request target for a backend status probe.
const STATUS_PATH: &str = "/status";
/// The fixed production response-body cap for a status probe: 64 KiB, well under
/// the shared 16 MiB [`MAX_HTTP_RESPONSE_BYTES`] ceiling. The ceiling is only the
/// unbreakable maximum; this is the value production actually enforces.
pub const HEALTH_BODY_CAP: usize = 64 * 1024;

/// The validated per-probe policy: one absolute attempt deadline and a hard
/// response-body cap.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HttpProbePolicy {
    /// The single absolute deadline covering the WHOLE attempt (DNS + connect +
    /// TLS + request + response). No stage refills it.
    pub attempt_timeout: Duration,
    /// The hard cap on the accepted response body, enforced before and during
    /// the body read.
    pub max_response_bytes: usize,
}

impl HttpProbePolicy {
    /// Builds a validated policy with the fixed 64 KiB production body cap
    /// ([`HEALTH_BODY_CAP`]) and the given attempt (dial) timeout.
    ///
    /// This is the single shared entry point that a caller with no cluster to
    /// build still uses to reject an invalid dial timeout: a zero-cluster or a
    /// disabled health runtime validates its dial timeout here rather than
    /// relying on a per-cluster construction to catch it, so there is one source
    /// of truth for the attempt-timeout bound (no duplicated ceiling constant).
    ///
    /// # Errors
    /// Returns [`ClusterHttpConfigError::InvalidAttemptTimeout`] when
    /// `attempt_timeout` is zero or above the five-minute bound.
    pub fn validated(attempt_timeout: Duration) -> Result<Self, ClusterHttpConfigError> {
        let policy = Self {
            attempt_timeout,
            max_response_bytes: HEALTH_BODY_CAP,
        };
        policy.validate()?;
        Ok(policy)
    }

    /// Validates the policy: a non-zero attempt timeout no larger than five
    /// minutes and a non-zero body cap.
    fn validate(&self) -> Result<(), ClusterHttpConfigError> {
        if self.attempt_timeout.is_zero() || self.attempt_timeout > MAX_PROBE_TIMEOUT {
            return Err(ClusterHttpConfigError::InvalidAttemptTimeout(
                self.attempt_timeout,
            ));
        }
        if !(1..=MAX_HTTP_RESPONSE_BYTES).contains(&self.max_response_bytes) {
            return Err(ClusterHttpConfigError::InvalidResponseBound(
                self.max_response_bytes,
            ));
        }
        Ok(())
    }
}

/// A build-time rejection of the cluster HTTP probe material or policy.
#[derive(Debug, Error)]
pub enum ClusterHttpConfigError {
    /// The attempt timeout is zero or over its five-minute bound.
    #[error("invalid HTTP probe attempt timeout {0:?}")]
    InvalidAttemptTimeout(Duration),
    /// The response body cap is zero or above the shared 16 MiB HTTP ceiling.
    #[error("invalid HTTP probe response bound {0}")]
    InvalidResponseBound(usize),
    /// The cluster's explicit-nameserver resolver could not be built.
    #[error("HTTP probe explicit nameserver resolver could not be built")]
    Resolver(#[source] ResolveError),
    /// The cluster requires TLS but its material could not form a client
    /// configuration; the probe fails closed at construction (no plaintext
    /// fallback is ever created).
    #[error("HTTP probe TLS client configuration could not be built")]
    Tls(#[source] EtcdConfigError),
}

/// A stable single-attempt HTTP probe failure class.
///
/// [`Self::is_retryable`] partitions the classes: a terminal class stops the
/// policy layer's retry immediately, while a retryable class is a transient
/// transport condition the policy layer may retry.
#[derive(Debug, Error)]
pub enum ClusterHttpError {
    /// The process owner or the caller's source generation went stale mid-attempt.
    /// Terminal, and it wins over any coincident I/O error.
    #[error("HTTP probe fenced by a stale owner or source generation")]
    Fenced,
    /// DNS resolution failed for a non-stale reason. Retryable.
    #[error("HTTP probe DNS resolution failed")]
    Dns,
    /// The final exhausted-candidates dial error was connection-refused. Terminal
    /// (mirrors Go `IsRetryableError` treating refused as non-retryable).
    #[error("HTTP probe connection refused")]
    ConnectionRefused,
    /// A transport or read error other than a refused connection. Retryable.
    #[error("HTTP probe transport error")]
    Transport,
    /// The TLS handshake failed or the server name was unusable. Terminal (no
    /// plaintext fallback).
    #[error("HTTP probe TLS handshake failed")]
    Tls,
    /// The HTTP request could not be built or its write violated protocol.
    /// Terminal.
    #[error("HTTP probe request could not be built or written")]
    Request,
    /// The response status was not exactly 200. Terminal.
    #[error("HTTP probe returned status {0}")]
    Status(u16),
    /// The response body exceeded the configured cap (by `Content-Length` or
    /// mid-stream). Terminal.
    #[error("HTTP probe response exceeded {maximum} bytes")]
    BodyTooLarge {
        /// The configured response cap.
        maximum: usize,
    },
    /// The single absolute attempt deadline elapsed. Retryable.
    #[error("HTTP probe deadline elapsed")]
    Timeout,
}

impl From<ClusterConnectError> for ClusterHttpError {
    fn from(error: ClusterConnectError) -> Self {
        match error {
            ClusterConnectError::Fenced => Self::Fenced,
            ClusterConnectError::Dns => Self::Dns,
            ClusterConnectError::ConnectionRefused => Self::ConnectionRefused,
            ClusterConnectError::Transport => Self::Transport,
        }
    }
}

impl ClusterHttpError {
    /// Whether the policy layer may retry this failure. Only transient transport
    /// conditions (non-stale DNS failures, other transport/read errors, and
    /// timeouts) are retryable; every terminal class returns `false`.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::Dns | Self::Transport | Self::Timeout)
    }
}

/// An owner-fenced, single-attempt HTTP `/status` probe client for one backend
/// cluster's material and generation.
///
/// It privately holds the cluster's owner-fenced raw connector (the
/// explicit-nameserver resolver, absent when no `ns_servers` are configured, and
/// the bounded candidate dial), the cluster's TLS client configuration (absent
/// for a plaintext cluster), and the probe policy. It is reusable across probes
/// within one cluster-material/epoch.
#[derive(Clone)]
pub struct ClusterHttpClient {
    connector: ClusterConnector,
    tls: Option<Arc<ClientConfig>>,
    policy: HttpProbePolicy,
}

impl ClusterHttpClient {
    /// Builds a probe client from one cluster's etcd client material, the process
    /// owner token, and the probe policy.
    ///
    /// When the cluster configures `ns_servers`, an owner-fenced
    /// [`ExplicitResolver`] is built over them with the health policy's attempt
    /// timeout as its single resolution budget; otherwise resolution falls back to
    /// the system resolver. When the cluster configures TLS, its client
    /// configuration is built eagerly and reused for every probe; a plaintext
    /// cluster carries no TLS material.
    ///
    /// # Errors
    ///
    /// Returns a [`ClusterHttpConfigError`] for an invalid policy, an
    /// unbuildable explicit-nameserver resolver, or — for a TLS cluster whose
    /// material cannot form a client configuration — a terminal build failure
    /// (the probe fails closed at construction; a plaintext fallback is never
    /// created).
    pub fn from_cluster_material(
        config: &EtcdClientConfig,
        owner: OwnerToken,
        policy: HttpProbePolicy,
    ) -> Result<Self, ClusterHttpConfigError> {
        policy.validate()?;
        let connector =
            ClusterConnector::from_cluster_material(config, owner, policy.attempt_timeout)
                .map_err(ClusterHttpConfigError::Resolver)?;
        let tls = match config.tls() {
            Some(tls) => Some(tls.client_config().map_err(ClusterHttpConfigError::Tls)?),
            None => None,
        };
        Ok(Self {
            connector,
            tls,
            policy,
        })
    }

    /// Performs ONE `GET /status` attempt against `host:port`, bounded by a
    /// single absolute deadline of `policy.attempt_timeout` covering the whole
    /// exchange. Returns the raw response body on an exact HTTP 200; the body is
    /// never parsed or logged here.
    ///
    /// A literal-IP `host` dials directly with no wire query; a hostname resolves
    /// through the cluster resolver (or the system resolver) and its bounded
    /// candidate set is dialed in order under the one shared deadline. The rustls
    /// `ServerName` and the `Host` header are always the logical `host`, never a
    /// resolved IP.
    ///
    /// # Errors
    ///
    /// Returns a [`ClusterHttpError`]: [`Fenced`](ClusterHttpError::Fenced) when
    /// the owner or `source_gate` is stale (terminal, wins over I/O),
    /// [`Timeout`](ClusterHttpError::Timeout) when the deadline elapses, or a
    /// DNS / connect / TLS / protocol / status / body-cap failure classified by
    /// [`ClusterHttpError::is_retryable`].
    pub async fn get_once(
        &self,
        host: &str,
        port: u16,
        source_gate: &GenerationGate,
    ) -> Result<Bytes, ClusterHttpError> {
        match tokio::time::timeout(
            self.policy.attempt_timeout,
            self.attempt(host, port, source_gate),
        )
        .await
        {
            Ok(result) => result,
            Err(_elapsed) => {
                // A revoke coincident with the deadline is terminal and wins over
                // the timeout classification.
                self.fence(source_gate)?;
                Err(ClusterHttpError::Timeout)
            }
        }
    }

    /// The whole single attempt, run under the caller's `get_once` deadline.
    async fn attempt(
        &self,
        host: &str,
        port: u16,
        source_gate: &GenerationGate,
    ) -> Result<Bytes, ClusterHttpError> {
        // The connector fences pre-DNS, post-DNS, and around every candidate dial.
        let stream = self.connector.connect_once(host, port, source_gate).await?;
        let stream = self.maybe_tls(host, stream, source_gate).await?;
        self.exchange(host, port, stream, source_gate).await
    }

    /// Returns `Ok` only while the process owner AND the source generation are
    /// both current. A stale check is a terminal [`ClusterHttpError::Fenced`].
    fn fence(&self, source_gate: &GenerationGate) -> Result<(), ClusterHttpError> {
        self.connector
            .fence(source_gate)
            .map_err(ClusterHttpError::from)
    }

    /// Wraps the TCP stream in TLS when the cluster has TLS material (fenced
    /// before and after the handshake), else yields a plaintext stream. A TLS
    /// cluster never falls back to plaintext.
    async fn maybe_tls(
        &self,
        host: &str,
        stream: TcpStream,
        source_gate: &GenerationGate,
    ) -> Result<MaybeTlsStream, ClusterHttpError> {
        match &self.tls {
            Some(config) => {
                self.fence(source_gate)?; // pre-TLS
                let server_name = server_name_for(host)?;
                let connector = TlsConnector::from(Arc::clone(config));
                let outcome = connector.connect(server_name, stream).await;
                // Fence after the handshake await, before classifying: a stale
                // wins over a TLS handshake error.
                self.fence(source_gate)?;
                let tls = outcome.map_err(|_| ClusterHttpError::Tls)?;
                Ok(MaybeTlsStream::Tls(Box::new(tls)))
            }
            None => Ok(MaybeTlsStream::Plain(stream)),
        }
    }

    /// Drives the HTTP/1.1 exchange over the established stream: fresh connection
    /// (no pool), `GET /status`, exact-200 status, `Content-Length` pre-check, and
    /// a capped frame-by-frame body read, fenced at each step.
    async fn exchange(
        &self,
        host: &str,
        port: u16,
        stream: MaybeTlsStream,
        source_gate: &GenerationGate,
    ) -> Result<Bytes, ClusterHttpError> {
        self.fence(source_gate)?; // pre-request-write
        let io = TokioIo::new(stream);
        let Ok((mut sender, connection)) = hyper::client::conn::http1::handshake(io).await else {
            // A fence wins over the coincident handshake I/O error.
            self.fence(source_gate)?;
            return Err(ClusterHttpError::Transport);
        };
        // Fence after the handshake succeeds, before entering the next wire
        // effect (the request write), so a stale never issues a request.
        self.fence(source_gate)?;
        // Drive the connection concurrently; it is aborted once the body is read.
        let driver = tokio::spawn(async move {
            let _ = connection.await;
        });
        let outcome = self
            .send_and_read(&mut sender, host, port, source_gate)
            .await;
        driver.abort();
        outcome
    }

    /// Sends the request and reads the fenced, capped response body.
    async fn send_and_read(
        &self,
        sender: &mut hyper::client::conn::http1::SendRequest<Empty<Bytes>>,
        host: &str,
        port: u16,
        source_gate: &GenerationGate,
    ) -> Result<Bytes, ClusterHttpError> {
        let request = build_request(host, port)?;
        let Ok(response) = sender.send_request(request).await else {
            // A fence wins over the coincident request-write I/O error.
            self.fence(source_gate)?;
            return Err(ClusterHttpError::Transport);
        };
        self.fence(source_gate)?; // post-headers-read
        if response.status() != StatusCode::OK {
            return Err(ClusterHttpError::Status(response.status().as_u16()));
        }
        if let Some(length) = content_length(response.headers()) {
            // Reject an over-cap Content-Length BEFORE reading any body byte.
            let over =
                usize::try_from(length).map_or(true, |len| len > self.policy.max_response_bytes);
            if over {
                return Err(ClusterHttpError::BodyTooLarge {
                    maximum: self.policy.max_response_bytes,
                });
            }
        }
        self.collect_body(response.into_body(), source_gate).await
    }

    /// Accumulates the response body frame by frame under the hard cap, fenced
    /// before and after each frame. Never logs the body.
    async fn collect_body(
        &self,
        mut body: Incoming,
        source_gate: &GenerationGate,
    ) -> Result<Bytes, ClusterHttpError> {
        let mut collected: Vec<u8> = Vec::new();
        loop {
            self.fence(source_gate)?; // before each frame
            let Some(frame) = body.frame().await else {
                break;
            };
            self.fence(source_gate)?; // after each frame: a fence wins over the I/O result
            let frame = frame.map_err(|_| ClusterHttpError::Transport)?;
            if let Ok(data) = frame.into_data() {
                if collected.len().saturating_add(data.len()) > self.policy.max_response_bytes {
                    return Err(ClusterHttpError::BodyTooLarge {
                        maximum: self.policy.max_response_bytes,
                    });
                }
                collected.extend_from_slice(&data);
            }
        }
        // Final fence after the terminating EOF await, before returning success: a
        // revoke during the last frame or at EOF is terminal and never yields a
        // body from a superseded source.
        self.fence(source_gate)?;
        Ok(Bytes::from(collected))
    }
}

/// Builds the origin-form `GET /status HTTP/1.1` request with an explicit
/// `Host:` (logical host, IPv6 bracketed) and `Connection: close`.
fn build_request(host: &str, port: u16) -> Result<Request<Empty<Bytes>>, ClusterHttpError> {
    Request::builder()
        .method(Method::GET)
        .uri(STATUS_PATH)
        .header(HOST, host_header(host, port))
        .header(CONNECTION, "close")
        .body(Empty::<Bytes>::new())
        .map_err(|_| ClusterHttpError::Request)
}

/// Derives the rustls `ServerName` from the logical host: a `DnsName` for a
/// hostname, an `IpAddress` for a literal IP — never a resolved IP.
fn server_name_for(host: &str) -> Result<ServerName<'static>, ClusterHttpError> {
    if let Some(ip) = parse_ip_literal(host) {
        Ok(ServerName::IpAddress(ip.into()))
    } else {
        ServerName::try_from(host.to_owned()).map_err(|_| ClusterHttpError::Tls)
    }
}

/// Formats the `Host` header value for the logical host and port, bracketing an
/// IPv6 literal.
fn host_header(host: &str, port: u16) -> String {
    match parse_ip_literal(host) {
        Some(IpAddr::V6(addr)) => format!("[{addr}]:{port}"),
        Some(IpAddr::V4(addr)) => format!("{addr}:{port}"),
        None => format!("{host}:{port}"),
    }
}

/// Reads a non-negative `Content-Length` header value, if present and valid.
fn content_length(headers: &http::HeaderMap) -> Option<u64> {
    headers
        .get(CONTENT_LENGTH)?
        .to_str()
        .ok()?
        .trim()
        .parse::<u64>()
        .ok()
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex, PoisonError};
    use std::time::{Duration, Instant};

    use control_plane::OwnerLease;
    use rustls::ServerConfig;
    use rustls_pki_types::pem::PemObject;
    use rustls_pki_types::{CertificateDer, PrivateKeyDer};
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
    use tokio::net::{TcpListener, UdpSocket};
    use tokio::sync::Notify;
    use tokio_rustls::TlsAcceptor;

    use super::{
        ClusterHttpClient, ClusterHttpConfigError, ClusterHttpError, HEALTH_BODY_CAP,
        HttpProbePolicy,
    };
    use crate::etcd::{
        EtcdClientConfig, EtcdTlsConfig, EtcdTlsPolicy, EtcdTlsVersion, GenerationGate,
    };
    use crate::http::MAX_HTTP_RESPONSE_BYTES;
    use crate::probe_test_support::{ns_config, owner_lease, plaintext_config, spawn_dns};

    /// A whole-test wall-clock bound so a stalled socket trips well inside CI's
    /// patience. The probe's own attempt deadline is shorter still.
    const TEST_DEADLINE: Duration = Duration::from_secs(5);

    // --- ownership -------------------------------------------------------

    fn policy(attempt_timeout: Duration, max_response_bytes: usize) -> HttpProbePolicy {
        HttpProbePolicy {
            attempt_timeout,
            max_response_bytes,
        }
    }

    // --- a boxable loopback stream --------------------------------------

    trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
    impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}

    /// What the loopback server observed from the client's request.
    #[derive(Default)]
    struct Captured {
        request_line: Option<String>,
        host_header: Option<String>,
        sni: Option<String>,
    }

    fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
        mutex.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// A canned HTTP/1.1 response the loopback server writes back.
    #[derive(Clone)]
    enum Response {
        /// `200 OK` with an exact `Content-Length` body.
        Ok200(Vec<u8>),
        /// A bare status line (empty body).
        Status(u16),
        /// `200 OK` declaring a `Content-Length` far larger than the bytes sent,
        /// so a correct client rejects on the header before reading the body.
        OversizeContentLength(u64),
        /// `200 OK` chunked, streaming the given chunks with no `Content-Length`.
        Chunked(Vec<Vec<u8>>),
    }

    fn render(response: &Response) -> Vec<u8> {
        match response {
            Response::Ok200(body) => {
                let mut out = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                )
                .into_bytes();
                out.extend_from_slice(body);
                out
            }
            Response::Status(code) => {
                format!("HTTP/1.1 {code} STATUS\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    .into_bytes()
            }
            Response::OversizeContentLength(declared) => format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {declared}\r\nConnection: close\r\n\r\n"
            )
            .into_bytes(),
            Response::Chunked(chunks) => {
                let mut out =
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
                        .to_vec();
                for chunk in chunks {
                    out.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
                    out.extend_from_slice(chunk);
                    out.extend_from_slice(b"\r\n");
                }
                out.extend_from_slice(b"0\r\n\r\n");
                out
            }
        }
    }

    /// Reads the request head (up to and including the blank line).
    async fn read_head(io: &mut (impl AsyncReadExt + Unpin)) -> Vec<u8> {
        let mut buffer = Vec::new();
        let mut chunk = [0u8; 256];
        loop {
            match io.read(&mut chunk).await {
                Ok(0) | Err(_) => break,
                Ok(n) => buffer.extend_from_slice(&chunk[..n]),
            }
            if buffer.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        buffer
    }

    fn record_request(head: &[u8], captured: &Arc<Mutex<Captured>>) {
        let text = String::from_utf8_lossy(head);
        let mut lines = text.split("\r\n");
        let mut guard = lock(captured);
        guard.request_line = lines.next().map(str::to_owned);
        for line in lines {
            if let Some(value) = line
                .strip_prefix("Host: ")
                .or_else(|| line.strip_prefix("host: "))
            {
                guard.host_header = Some(value.to_owned());
            }
        }
    }

    /// Serves exactly one connection (optionally over TLS), records the request
    /// head and SNI, then writes the scripted response and closes.
    async fn serve_once(
        listener: TcpListener,
        acceptor: Option<TlsAcceptor>,
        captured: Arc<Mutex<Captured>>,
        response: Response,
    ) {
        let Ok((stream, _peer)) = listener.accept().await else {
            return;
        };
        let mut io: Box<dyn Stream> = match acceptor {
            Some(acceptor) => match acceptor.accept(stream).await {
                Ok(tls) => {
                    if let Some(name) = tls.get_ref().1.server_name() {
                        lock(&captured).sni = Some(name.to_owned());
                    }
                    Box::new(tls)
                }
                Err(_) => return,
            },
            None => Box::new(stream),
        };
        let head = read_head(&mut io).await;
        record_request(&head, &captured);
        let bytes = render(&response);
        let _ = io.write_all(&bytes).await;
        let _ = io.flush().await;
    }

    /// Binds a loopback listener and spawns a one-shot server for `response`.
    async fn spawn_server(
        acceptor: Option<TlsAcceptor>,
        response: Response,
    ) -> (SocketAddr, Arc<Mutex<Captured>>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|error| unreachable!("bind: {error}"));
        let addr = listener
            .local_addr()
            .unwrap_or_else(|error| unreachable!("addr: {error}"));
        let captured = Arc::new(Mutex::new(Captured::default()));
        tokio::spawn(serve_once(
            listener,
            acceptor,
            Arc::clone(&captured),
            response,
        ));
        (addr, captured)
    }

    // --- certificate + TLS server helpers -------------------------------

    /// A self-signed leaf CA and a reusable issuer.
    fn make_ca(common_name: &str) -> (String, rcgen::Issuer<'static, rcgen::KeyPair>) {
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new())
            .unwrap_or_else(|error| unreachable!("ca params: {error}"));
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
        ];
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, common_name);
        let key =
            rcgen::KeyPair::generate().unwrap_or_else(|error| unreachable!("ca key: {error}"));
        let cert = params
            .self_signed(&key)
            .unwrap_or_else(|error| unreachable!("ca self-signed: {error}"));
        let pem = cert.pem();
        (pem, rcgen::Issuer::new(params, key))
    }

    /// Signs a leaf certificate for `common_name`/`san` as server or client auth.
    fn make_leaf(
        issuer: &rcgen::Issuer<'static, rcgen::KeyPair>,
        common_name: &str,
        san: &str,
        server_auth: bool,
    ) -> (String, String) {
        let mut params = rcgen::CertificateParams::new(vec![san.to_owned()])
            .unwrap_or_else(|error| unreachable!("leaf params: {error}"));
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, common_name);
        params.extended_key_usages = vec![if server_auth {
            rcgen::ExtendedKeyUsagePurpose::ServerAuth
        } else {
            rcgen::ExtendedKeyUsagePurpose::ClientAuth
        }];
        let key =
            rcgen::KeyPair::generate().unwrap_or_else(|error| unreachable!("leaf key: {error}"));
        let cert = params
            .signed_by(&key, issuer)
            .unwrap_or_else(|error| unreachable!("leaf signed: {error}"));
        (cert.pem(), key.serialize_pem())
    }

    fn parse_chain(pem: &str) -> Vec<CertificateDer<'static>> {
        let mut chain = Vec::new();
        for cert in CertificateDer::pem_slice_iter(pem.as_bytes()) {
            chain.push(
                cert.unwrap_or_else(|error| unreachable!("cert: {error}"))
                    .into_owned(),
            );
        }
        chain
    }

    fn parse_key(pem: &str) -> PrivateKeyDer<'static> {
        PrivateKeyDer::from_pem_slice(pem.as_bytes())
            .unwrap_or_else(|error| unreachable!("key: {error}"))
    }

    fn roots(ca_pem: &str) -> Arc<rustls::RootCertStore> {
        let mut store = rustls::RootCertStore::empty();
        for cert in CertificateDer::pem_slice_iter(ca_pem.as_bytes()) {
            store
                .add(cert.unwrap_or_else(|error| unreachable!("ca cert: {error}")))
                .unwrap_or_else(|error| unreachable!("add root: {error}"));
        }
        Arc::new(store)
    }

    /// Builds a rustls server acceptor for the leaf, optionally requiring client
    /// auth against `client_ca_pem` and offering exactly `versions`.
    fn server_acceptor(
        cert_pem: &str,
        key_pem: &str,
        client_ca_pem: Option<&str>,
        versions: &[&'static rustls::SupportedProtocolVersion],
    ) -> TlsAcceptor {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let builder = ServerConfig::builder_with_provider(Arc::clone(&provider))
            .with_protocol_versions(versions)
            .unwrap_or_else(|error| unreachable!("server versions: {error}"));
        let builder = match client_ca_pem {
            Some(ca) => {
                let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
                    roots(ca),
                    provider,
                )
                .build()
                .unwrap_or_else(|error| unreachable!("client verifier: {error}"));
                builder.with_client_cert_verifier(verifier)
            }
            None => builder.with_no_client_auth(),
        };
        let config = builder
            .with_single_cert(parse_chain(cert_pem), parse_key(key_pem))
            .unwrap_or_else(|error| unreachable!("server cert: {error}"));
        TlsAcceptor::from(Arc::new(config))
    }

    /// A skip-CA client TLS policy plus optional CN pins / minimum version.
    fn skip_ca_tls(
        common_names: &[&str],
        minimum_version: Option<EtcdTlsVersion>,
        identity: Option<(&str, &str)>,
    ) -> EtcdTlsConfig {
        let policy = EtcdTlsPolicy {
            minimum_version,
            allowed_common_names: common_names.iter().map(|name| (*name).to_owned()).collect(),
            skip_ca_verification: true,
        };
        let (cert, key) = match identity {
            Some((cert, key)) => (
                Some(cert.as_bytes().to_vec()),
                Some(key.as_bytes().to_vec()),
            ),
            None => (None, None),
        };
        EtcdTlsConfig::new(None, cert, key, None, policy)
            .unwrap_or_else(|error| unreachable!("tls config: {error}"))
    }

    fn tls_config(tls: EtcdTlsConfig) -> EtcdClientConfig {
        EtcdClientConfig::new(["127.0.0.1:2379".to_owned()], Some(tls))
            .unwrap_or_else(|error| unreachable!("config: {error}"))
    }

    // --- a compact loopback DNS nameserver ------------------------------

    /// Spawns a loopback UDP nameserver answering `A` with `a`, `AAAA` with
    /// `aaaa` (each empty family is authoritative NODATA), returning its port.
    // ====================================================================
    // Policy validation and error classification.
    // ====================================================================

    #[test]
    fn policy_validation_rejects_zero_and_overbound_values() {
        let (_registry, lease) = owner_lease();
        let build = |p: HttpProbePolicy| {
            ClusterHttpClient::from_cluster_material(&plaintext_config(), lease.token(), p)
        };
        assert!(matches!(
            build(policy(Duration::ZERO, 16)),
            Err(ClusterHttpConfigError::InvalidAttemptTimeout(_))
        ));
        assert!(matches!(
            build(policy(Duration::from_secs(301), 16)),
            Err(ClusterHttpConfigError::InvalidAttemptTimeout(_))
        ));
        assert!(matches!(
            build(policy(Duration::from_secs(2), 0)),
            Err(ClusterHttpConfigError::InvalidResponseBound(0))
        ));
        // Above the shared 16 MiB HTTP ceiling is rejected (both just over the
        // bound and the extreme usize::MAX).
        assert!(matches!(
            build(policy(Duration::from_secs(2), MAX_HTTP_RESPONSE_BYTES + 1)),
            Err(ClusterHttpConfigError::InvalidResponseBound(_))
        ));
        assert!(matches!(
            build(policy(Duration::from_secs(2), usize::MAX)),
            Err(ClusterHttpConfigError::InvalidResponseBound(_))
        ));
        // The in-bound values (16 bytes and exactly the ceiling) still build.
        assert!(build(policy(Duration::from_secs(2), 16)).is_ok());
        assert!(build(policy(Duration::from_secs(2), MAX_HTTP_RESPONSE_BYTES)).is_ok());
    }

    #[test]
    fn validated_rejects_zero_and_overbound_timeouts_and_stamps_the_body_cap() {
        // The single shared entry point a zero-cluster or disabled runtime uses to
        // reject an invalid dial timeout: zero and just over five minutes are
        // rejected as `InvalidAttemptTimeout`.
        assert!(matches!(
            HttpProbePolicy::validated(Duration::ZERO),
            Err(ClusterHttpConfigError::InvalidAttemptTimeout(_))
        ));
        assert!(matches!(
            HttpProbePolicy::validated(Duration::from_secs(301)),
            Err(ClusterHttpConfigError::InvalidAttemptTimeout(_))
        ));
        // A valid timeout builds and carries EXACTLY the fixed 64 KiB production
        // body cap (never the 16 MiB ceiling).
        let policy = match HttpProbePolicy::validated(Duration::from_secs(2)) {
            Ok(policy) => policy,
            Err(error) => unreachable!("a two-second attempt timeout is valid: {error}"),
        };
        assert_eq!(policy.attempt_timeout, Duration::from_secs(2));
        assert_eq!(
            policy.max_response_bytes, HEALTH_BODY_CAP,
            "validated stamps the fixed 64 KiB body cap"
        );
        // The five-minute bound itself is inclusive.
        assert!(HttpProbePolicy::validated(Duration::from_secs(300)).is_ok());
    }

    #[test]
    fn is_retryable_partitions_the_error_classes() {
        // Terminal classes never retry.
        for terminal in [
            ClusterHttpError::Fenced,
            ClusterHttpError::ConnectionRefused,
            ClusterHttpError::Tls,
            ClusterHttpError::Request,
            ClusterHttpError::Status(500),
            ClusterHttpError::BodyTooLarge { maximum: 16 },
        ] {
            assert!(!terminal.is_retryable(), "{terminal:?} must be terminal");
        }
        // Transient transport conditions are retryable.
        for retryable in [
            ClusterHttpError::Dns,
            ClusterHttpError::Transport,
            ClusterHttpError::Timeout,
        ] {
            assert!(retryable.is_retryable(), "{retryable:?} must be retryable");
        }
    }

    // ====================================================================
    // Literal-IP plaintext probes (tests 4, 7, 6).
    // ====================================================================

    async fn get_once_literal(
        config: &EtcdClientConfig,
        acceptor: Option<TlsAcceptor>,
        host: &str,
        response: Response,
        cap: usize,
    ) -> (
        Result<hyper::body::Bytes, ClusterHttpError>,
        Arc<Mutex<Captured>>,
    ) {
        let (_registry, lease) = owner_lease();
        let (addr, captured) = spawn_server(acceptor, response).await;
        let client = ClusterHttpClient::from_cluster_material(
            config,
            lease.token(),
            policy(Duration::from_secs(2), cap),
        )
        .unwrap_or_else(|error| unreachable!("client: {error}"));
        let gate = GenerationGate::new();
        let result = client.get_once(host, addr.port(), &gate).await;
        (result, captured)
    }

    #[tokio::test]
    async fn literal_ipv4_plaintext_returns_the_body() {
        let (result, captured) = get_once_literal(
            &plaintext_config(),
            None,
            "127.0.0.1",
            Response::Ok200(b"{\"version\":\"v8\"}".to_vec()),
            1024,
        )
        .await;
        let body = result.unwrap_or_else(|error| unreachable!("probe: {error}"));
        assert_eq!(body.as_ref(), b"{\"version\":\"v8\"}");
        let guard = lock(&captured);
        assert_eq!(
            guard.request_line.as_deref(),
            Some("GET /status HTTP/1.1"),
            "origin-form request line"
        );
        assert!(
            guard
                .host_header
                .as_deref()
                .is_some_and(|value| value.starts_with("127.0.0.1:")),
            "the Host header is the logical host and port, got {:?}",
            guard.host_header
        );
    }

    #[tokio::test]
    async fn literal_ipv6_host_header_is_bracketed() {
        let listener = TcpListener::bind("[::1]:0").await;
        let Ok(listener) = listener else {
            // The host lacks IPv6 loopback; nothing to assert.
            return;
        };
        let addr = listener
            .local_addr()
            .unwrap_or_else(|error| unreachable!("addr: {error}"));
        let captured = Arc::new(Mutex::new(Captured::default()));
        tokio::spawn(serve_once(
            listener,
            None,
            Arc::clone(&captured),
            Response::Ok200(b"ok".to_vec()),
        ));

        let (_registry, lease) = owner_lease();
        let client = ClusterHttpClient::from_cluster_material(
            &plaintext_config(),
            lease.token(),
            policy(Duration::from_secs(2), 1024),
        )
        .unwrap_or_else(|error| unreachable!("client: {error}"));
        let gate = GenerationGate::new();
        let result = client.get_once("::1", addr.port(), &gate).await;
        assert!(result.is_ok(), "an IPv6 literal probe succeeds: {result:?}");
        assert_eq!(
            lock(&captured).host_header.as_deref(),
            Some(format!("[::1]:{}", addr.port()).as_str()),
            "the IPv6 Host header is bracketed"
        );
    }

    #[tokio::test]
    async fn non_200_status_is_terminal() {
        let (result, _captured) = get_once_literal(
            &plaintext_config(),
            None,
            "127.0.0.1",
            Response::Status(503),
            1024,
        )
        .await;
        let error = result
            .err()
            .unwrap_or_else(|| unreachable!("a non-200 fails"));
        assert!(matches!(error, ClusterHttpError::Status(503)));
        assert!(!error.is_retryable(), "a non-200 status is terminal");
    }

    #[tokio::test]
    async fn connection_refused_is_terminal() {
        // Bind then drop a port so it reliably refuses.
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|error| unreachable!("bind: {error}"));
        let addr = listener
            .local_addr()
            .unwrap_or_else(|error| unreachable!("addr: {error}"));
        drop(listener);

        let (_registry, lease) = owner_lease();
        let client = ClusterHttpClient::from_cluster_material(
            &plaintext_config(),
            lease.token(),
            policy(Duration::from_secs(2), 1024),
        )
        .unwrap_or_else(|error| unreachable!("client: {error}"));
        let gate = GenerationGate::new();
        let error = client
            .get_once("127.0.0.1", addr.port(), &gate)
            .await
            .err()
            .unwrap_or_else(|| unreachable!("a refused dial fails"));
        assert!(matches!(error, ClusterHttpError::ConnectionRefused));
        assert!(!error.is_retryable(), "connection-refused is terminal");
    }

    #[tokio::test]
    async fn content_length_over_cap_is_rejected_before_reading_the_body() {
        // The server declares a huge Content-Length and sends no body; a client
        // that read the body would hit EOF (a transport error), so a BodyTooLarge
        // proves the pre-read Content-Length check.
        let (result, _captured) = get_once_literal(
            &plaintext_config(),
            None,
            "127.0.0.1",
            Response::OversizeContentLength(1_000_000),
            16,
        )
        .await;
        let error = result
            .err()
            .unwrap_or_else(|| unreachable!("over-cap fails"));
        assert!(
            matches!(error, ClusterHttpError::BodyTooLarge { maximum: 16 }),
            "an over-cap Content-Length is rejected pre-read, got {error:?}"
        );
    }

    #[tokio::test]
    async fn chunked_body_over_cap_is_rejected_mid_stream() {
        // No Content-Length (chunked); the accumulated body crosses the cap on a
        // later frame, so the per-frame cap must trip.
        let (result, _captured) = get_once_literal(
            &plaintext_config(),
            None,
            "127.0.0.1",
            Response::Chunked(vec![vec![b'a'; 10], vec![b'b'; 10]]),
            16,
        )
        .await;
        let error = result
            .err()
            .unwrap_or_else(|| unreachable!("over-cap fails"));
        assert!(
            matches!(error, ClusterHttpError::BodyTooLarge { maximum: 16 }),
            "a chunked body over the cap is rejected mid-stream, got {error:?}"
        );
    }

    #[tokio::test]
    async fn chunked_body_within_cap_is_returned() {
        let (result, _captured) = get_once_literal(
            &plaintext_config(),
            None,
            "127.0.0.1",
            Response::Chunked(vec![b"ab".to_vec(), b"cd".to_vec()]),
            16,
        )
        .await;
        let body = result.unwrap_or_else(|error| unreachable!("probe: {error}"));
        assert_eq!(body.as_ref(), b"abcd", "chunked frames are concatenated");
    }

    // ====================================================================
    // Fencing (test 8, transport-level).
    // ====================================================================

    #[tokio::test]
    async fn a_revoked_owner_is_fenced_before_any_io() {
        let (_registry, lease) = owner_lease();
        let (addr, _captured) = spawn_server(None, Response::Ok200(b"ok".to_vec())).await;
        let client = ClusterHttpClient::from_cluster_material(
            &plaintext_config(),
            lease.token(),
            policy(Duration::from_secs(2), 1024),
        )
        .unwrap_or_else(|error| unreachable!("client: {error}"));
        lease.release(); // retire the owner
        let gate = GenerationGate::new();
        let error = client
            .get_once("127.0.0.1", addr.port(), &gate)
            .await
            .err()
            .unwrap_or_else(|| unreachable!("a retired owner fails closed"));
        assert!(matches!(error, ClusterHttpError::Fenced));
        assert!(!error.is_retryable(), "a fence is terminal");
    }

    #[tokio::test]
    async fn a_revoked_source_gate_is_fenced() {
        let (_registry, lease) = owner_lease();
        let (addr, _captured) = spawn_server(None, Response::Ok200(b"ok".to_vec())).await;
        let client = ClusterHttpClient::from_cluster_material(
            &plaintext_config(),
            lease.token(),
            policy(Duration::from_secs(2), 1024),
        )
        .unwrap_or_else(|error| unreachable!("client: {error}"));
        let gate = GenerationGate::new();
        gate.revoke(); // the source generation is superseded
        let error = client
            .get_once("127.0.0.1", addr.port(), &gate)
            .await
            .err()
            .unwrap_or_else(|| unreachable!("a revoked source gate fails closed"));
        assert!(matches!(error, ClusterHttpError::Fenced));
    }

    // ====================================================================
    // Advanced TLS honored end-to-end (test 5).
    // ====================================================================

    #[tokio::test]
    async fn skip_ca_tls_probe_succeeds_end_to_end() {
        let (_ca, issuer) = make_ca("test-ca");
        let (cert, key) = make_leaf(&issuer, "backend", "localhost", true);
        let acceptor = server_acceptor(&cert, &key, None, rustls::ALL_VERSIONS);
        let (result, _captured) = get_once_literal(
            &tls_config(skip_ca_tls(&[], None, None)),
            Some(acceptor),
            "127.0.0.1",
            Response::Ok200(b"{}".to_vec()),
            1024,
        )
        .await;
        assert!(result.is_ok(), "skip-CA TLS probe succeeds: {result:?}");
    }

    #[tokio::test]
    async fn cn_pin_allows_the_pinned_cn_and_denies_others() {
        let (_ca, issuer) = make_ca("test-ca");
        let (cert, key) = make_leaf(&issuer, "backend-cn", "localhost", true);

        // The pinned CN matches: the handshake and probe succeed.
        let acceptor = server_acceptor(&cert, &key, None, rustls::ALL_VERSIONS);
        let (allowed, _c1) = get_once_literal(
            &tls_config(skip_ca_tls(&["backend-cn"], None, None)),
            Some(acceptor),
            "127.0.0.1",
            Response::Ok200(b"{}".to_vec()),
            1024,
        )
        .await;
        assert!(allowed.is_ok(), "a matching CN pin succeeds: {allowed:?}");

        // A non-matching pin rejects the handshake terminally.
        let acceptor = server_acceptor(&cert, &key, None, rustls::ALL_VERSIONS);
        let (denied, _c2) = get_once_literal(
            &tls_config(skip_ca_tls(&["other-cn"], None, None)),
            Some(acceptor),
            "127.0.0.1",
            Response::Ok200(b"{}".to_vec()),
            1024,
        )
        .await;
        let error = denied
            .err()
            .unwrap_or_else(|| unreachable!("a wrong CN fails"));
        assert!(matches!(error, ClusterHttpError::Tls));
        assert!(!error.is_retryable(), "a TLS failure is terminal");
    }

    #[tokio::test]
    async fn minimum_version_1_3_rejects_a_1_2_only_server() {
        let (_ca, issuer) = make_ca("test-ca");
        let (cert, key) = make_leaf(&issuer, "backend", "localhost", true);
        let acceptor = server_acceptor(&cert, &key, None, &[&rustls::version::TLS12]);
        let (result, _captured) = get_once_literal(
            &tls_config(skip_ca_tls(&[], Some(EtcdTlsVersion::V1_3), None)),
            Some(acceptor),
            "127.0.0.1",
            Response::Ok200(b"{}".to_vec()),
            1024,
        )
        .await;
        let error = result
            .err()
            .unwrap_or_else(|| unreachable!("a version-floor mismatch fails"));
        assert!(matches!(error, ClusterHttpError::Tls));
    }

    #[tokio::test]
    async fn minimum_version_1_3_accepts_a_1_3_server() {
        let (_ca, issuer) = make_ca("test-ca");
        let (cert, key) = make_leaf(&issuer, "backend", "localhost", true);
        let acceptor = server_acceptor(&cert, &key, None, &[&rustls::version::TLS13]);
        let (result, _captured) = get_once_literal(
            &tls_config(skip_ca_tls(&[], Some(EtcdTlsVersion::V1_3), None)),
            Some(acceptor),
            "127.0.0.1",
            Response::Ok200(b"{}".to_vec()),
            1024,
        )
        .await;
        assert!(
            result.is_ok(),
            "a 1.3 floor and 1.3 server succeed: {result:?}"
        );
    }

    #[tokio::test]
    async fn mtls_presents_the_client_identity() {
        let (ca_pem, issuer) = make_ca("test-ca");
        let (server_cert, server_key) = make_leaf(&issuer, "backend", "localhost", true);
        let (client_cert, client_key) = make_leaf(&issuer, "tiproxy", "localhost", false);

        // A client identity from the trusted CA is accepted by the server.
        let acceptor = server_acceptor(
            &server_cert,
            &server_key,
            Some(&ca_pem),
            rustls::ALL_VERSIONS,
        );
        let (ok, _c1) = get_once_literal(
            &tls_config(skip_ca_tls(&[], None, Some((&client_cert, &client_key)))),
            Some(acceptor),
            "127.0.0.1",
            Response::Ok200(b"{}".to_vec()),
            1024,
        )
        .await;
        assert!(
            ok.is_ok(),
            "an mTLS probe with a trusted identity succeeds: {ok:?}"
        );

        // No client identity is rejected by the client-auth-requiring server.
        let acceptor = server_acceptor(
            &server_cert,
            &server_key,
            Some(&ca_pem),
            rustls::ALL_VERSIONS,
        );
        let (missing, _c2) = get_once_literal(
            &tls_config(skip_ca_tls(&[], None, None)),
            Some(acceptor),
            "127.0.0.1",
            Response::Ok200(b"{}".to_vec()),
            1024,
        )
        .await;
        assert!(
            missing.is_err(),
            "a missing client identity fails the mTLS probe"
        );
    }

    #[test]
    fn a_tls_required_source_with_unbuildable_material_fails_closed() {
        // skip_ca=false with unparseable CA bytes: EtcdTlsConfig accepts the bytes
        // at construction, but client_config() cannot build, so the probe client
        // fails closed rather than falling back to plaintext.
        let tls = EtcdTlsConfig::new(
            Some(b"not-a-pem-certificate".to_vec()),
            None,
            None,
            None,
            EtcdTlsPolicy::default(),
        )
        .unwrap_or_else(|error| unreachable!("tls config: {error}"));
        let config = tls_config(tls);
        let (_registry, lease) = owner_lease();
        let result = ClusterHttpClient::from_cluster_material(
            &config,
            lease.token(),
            policy(Duration::from_secs(2), 1024),
        );
        assert!(
            matches!(result, Err(ClusterHttpConfigError::Tls(_))),
            "a TLS cluster with unbuildable material fails closed at construction"
        );
    }

    // ====================================================================
    // Custom-nameserver resolution drives the dial (tests 1, 2, 3).
    // ====================================================================

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn custom_ns_resolution_drives_the_direct_dial() {
        let finished = tokio::time::timeout(TEST_DEADLINE, async {
            let dns_port = spawn_dns(vec![Ipv4Addr::LOCALHOST], Vec::new()).await;
            let (addr, captured) = spawn_server(None, Response::Ok200(b"{}".to_vec())).await;
            let config = ns_config(dns_port, None);
            let (_registry, lease) = owner_lease();
            let client = ClusterHttpClient::from_cluster_material(
                &config,
                lease.token(),
                policy(Duration::from_secs(2), 1024),
            )
            .unwrap_or_else(|error| unreachable!("client: {error}"));
            let gate = GenerationGate::new();
            // `svc.invalid` never resolves via the system resolver, so a success
            // proves the explicit nameserver's 127.0.0.1 drove the direct dial.
            let result = client.get_once("svc.invalid", addr.port(), &gate).await;
            assert!(result.is_ok(), "custom-NS probe succeeds: {result:?}");
            assert_eq!(
                lock(&captured).host_header.as_deref(),
                Some(format!("svc.invalid:{}", addr.port()).as_str()),
                "the Host header is the logical hostname, not the resolved IP"
            );
        })
        .await;
        assert!(finished.is_ok(), "the custom-NS probe finished in time");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn system_resolution_direct_dials_a_hostname() {
        let finished = tokio::time::timeout(TEST_DEADLINE, async {
            let (addr, captured) = spawn_server(None, Response::Ok200(b"{}".to_vec())).await;
            // No ns_servers: the system resolver resolves `localhost` to loopback,
            // then the client direct-dials the resolved address.
            let (_registry, lease) = owner_lease();
            let client = ClusterHttpClient::from_cluster_material(
                &plaintext_config(),
                lease.token(),
                policy(Duration::from_secs(2), 1024),
            )
            .unwrap_or_else(|error| unreachable!("client: {error}"));
            let gate = GenerationGate::new();
            let result = client.get_once("localhost", addr.port(), &gate).await;
            assert!(result.is_ok(), "system-resolved probe succeeds: {result:?}");
            assert_eq!(
                lock(&captured).host_header.as_deref(),
                Some(format!("localhost:{}", addr.port()).as_str()),
                "the Host header stays the logical hostname"
            );
        })
        .await;
        assert!(
            finished.is_ok(),
            "the system-resolution probe finished in time"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn multi_address_fallback_stays_within_one_attempt_budget() {
        let finished = tokio::time::timeout(TEST_DEADLINE, async {
            // The live server binds the IPv6 loopback; the resolver interleaves
            // the families as `[127.0.0.1:P, ::1:P]`, and nothing listens on the
            // IPv4 loopback at P, so its dial refuses fast (a real loopback RST)
            // and the fallback reaches `::1:P`. Both candidates share ONE 2s
            // attempt budget with no per-stage refill.
            let Ok(listener) = TcpListener::bind("[::1]:0").await else {
                return; // no IPv6 loopback on this host; nothing to assert
            };
            let addr = listener
                .local_addr()
                .unwrap_or_else(|error| unreachable!("addr: {error}"));
            tokio::spawn(serve_once(
                listener,
                None,
                Arc::new(Mutex::new(Captured::default())),
                Response::Ok200(b"{}".to_vec()),
            ));
            let live_port = addr.port();
            let dns_port = spawn_dns(vec![Ipv4Addr::LOCALHOST], vec![Ipv6Addr::LOCALHOST]).await;
            let config = ns_config(dns_port, None);
            let (_registry, lease) = owner_lease();
            let client = ClusterHttpClient::from_cluster_material(
                &config,
                lease.token(),
                policy(Duration::from_secs(2), 1024),
            )
            .unwrap_or_else(|error| unreachable!("client: {error}"));
            let gate = GenerationGate::new();
            let started = Instant::now();
            let result = client.get_once("svc.invalid", live_port, &gate).await;
            let elapsed = started.elapsed();
            assert!(
                result.is_ok(),
                "the live second candidate answers: {result:?}"
            );
            assert!(
                elapsed < Duration::from_secs(2),
                "the fallback stayed within one 2s budget, took {elapsed:?}"
            );
        })
        .await;
        assert!(finished.is_ok(), "the multi-address probe finished in time");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn hostname_https_sni_and_host_are_the_logical_host() {
        let finished = tokio::time::timeout(TEST_DEADLINE, async {
            let (_ca, issuer) = make_ca("test-ca");
            let (cert, key) = make_leaf(&issuer, "backend", "svc.test", true);
            let acceptor = server_acceptor(&cert, &key, None, rustls::ALL_VERSIONS);
            let dns_port = spawn_dns(vec![Ipv4Addr::LOCALHOST], Vec::new()).await;
            let (addr, captured) =
                spawn_server(Some(acceptor), Response::Ok200(b"{}".to_vec())).await;
            let config = ns_config(dns_port, Some(skip_ca_tls(&[], None, None)));
            let (_registry, lease) = owner_lease();
            let client = ClusterHttpClient::from_cluster_material(
                &config,
                lease.token(),
                policy(Duration::from_secs(2), 1024),
            )
            .unwrap_or_else(|error| unreachable!("client: {error}"));
            let gate = GenerationGate::new();
            // The logical host `svc.test` resolves to 127.0.0.1, but the SNI and
            // Host header must be the hostname, decoupled from the resolved IP.
            let result = client.get_once("svc.test", addr.port(), &gate).await;
            assert!(result.is_ok(), "hostname HTTPS probe succeeds: {result:?}");
            let guard = lock(&captured);
            assert_eq!(
                guard.sni.as_deref(),
                Some("svc.test"),
                "the wire SNI is the logical hostname, not 127.0.0.1"
            );
            assert_eq!(
                guard.host_header.as_deref(),
                Some(format!("svc.test:{}", addr.port()).as_str()),
                "the Host header is the logical hostname"
            );
        })
        .await;
        assert!(
            finished.is_ok(),
            "the hostname HTTPS probe finished in time"
        );
    }

    // ====================================================================
    // Fix 1: the fence-wins-over-I/O invariant on every await/timeout path.
    //
    // Each oracle stalls a specific stage, revokes the source gate while it is
    // stalled, then lets the stage complete (or the deadline fire); the result
    // must be terminal `Fenced`, never the stage's natural class. Reverting the
    // stage's post-await fence flips the oracle to that natural class (verified
    // in the report), because after that fence the stage returns its result with
    // no later fence able to reclassify it.
    // ====================================================================

    /// Spawns `get_once` against `host:port` under a fresh gate, returning the
    /// join handle and the gate the test revokes.
    fn spawn_probe(
        client: &ClusterHttpClient,
        host: &str,
        port: u16,
    ) -> (
        tokio::task::JoinHandle<Result<hyper::body::Bytes, ClusterHttpError>>,
        GenerationGate,
    ) {
        let gate = GenerationGate::new();
        let gate_task = gate.clone();
        let client = client.clone();
        let host = host.to_owned();
        let handle = tokio::spawn(async move { client.get_once(&host, port, &gate_task).await });
        (handle, gate)
    }

    fn plaintext_client(lease: &OwnerLease, attempt_timeout: Duration) -> ClusterHttpClient {
        ClusterHttpClient::from_cluster_material(
            &plaintext_config(),
            lease.token(),
            policy(attempt_timeout, 64 * 1024),
        )
        .unwrap_or_else(|error| unreachable!("client: {error}"))
    }

    /// A loopback server that writes `200 OK` headers (Connection: close, no
    /// Content-Length) and one body chunk, signals `first_sent`, waits for
    /// `release`, then either closes (EOF) or holds the connection open forever.
    async fn serve_gated_body(
        listener: TcpListener,
        first: Vec<u8>,
        first_sent: Arc<Notify>,
        release: Arc<Notify>,
        close_after_release: bool,
    ) {
        let Ok((mut stream, _peer)) = listener.accept().await else {
            return;
        };
        let _ = read_head(&mut stream).await;
        let _ = stream
            .write_all(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n")
            .await;
        let _ = stream.write_all(&first).await;
        let _ = stream.flush().await;
        first_sent.notify_one();
        release.notified().await;
        if close_after_release {
            drop(stream); // EOF terminates the body
        } else {
            std::future::pending::<()>().await; // hold the body open forever
        }
    }

    /// A loopback server that reads the request head, signals `request_read`, then
    /// holds the connection open forever, never sending a response — so the client
    /// stalls in `send_request().await` (the header read, which has no fence
    /// between the pre-write fence and the attempt deadline).
    async fn serve_read_then_hold(listener: TcpListener, request_read: Arc<Notify>) {
        let Ok((mut stream, _peer)) = listener.accept().await else {
            return;
        };
        let _ = read_head(&mut stream).await;
        request_read.notify_one();
        std::future::pending::<()>().await;
    }

    // (a) A revoke during a stalled attempt that then hits the deadline is
    //     terminal `Fenced`, never `Timeout` (the timeout-branch fence). The stall
    //     is in the header read (`send_request().await`), which has NO fence
    //     between the pre-write fence and the deadline, so only the timeout-branch
    //     fence can catch the revoke.
    #[tokio::test]
    async fn fence_wins_over_the_attempt_deadline() {
        let finished = tokio::time::timeout(TEST_DEADLINE, async {
            let (_registry, lease) = owner_lease();
            // A short attempt deadline the stalled header read will hit; the revoke
            // lands long before it (on `request_read`).
            let client = plaintext_client(&lease, Duration::from_millis(400));
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .unwrap_or_else(|error| unreachable!("bind: {error}"));
            let addr = listener
                .local_addr()
                .unwrap_or_else(|error| unreachable!("addr: {error}"));
            let request_read = Arc::new(Notify::new());
            tokio::spawn(serve_read_then_hold(listener, Arc::clone(&request_read)));
            let (handle, gate) = spawn_probe(&client, "127.0.0.1", addr.port());
            request_read.notified().await; // the probe is stalled awaiting response headers
            gate.revoke(); // revoke, then let the deadline fire (server holds open)
            let result = handle
                .await
                .unwrap_or_else(|error| unreachable!("join: {error}"));
            assert!(
                matches!(result, Err(ClusterHttpError::Fenced)),
                "a revoke coincident with the deadline is Fenced, not Timeout: {result:?}"
            );
        })
        .await;
        assert!(finished.is_ok(), "oracle (a) finished in time");
    }

    // (e) A revoke after the first body frame, released as EOF, is terminal
    //     `Fenced`, never `Ok` — the body/EOF fence invariant. NOTE: the final
    //     post-loop fence is defense-in-depth behind the pre-existing per-frame
    //     fences (which catch a revoke that lands on or before a data frame), so
    //     this asserts the observable invariant rather than isolating that single
    //     line (see the report).
    #[tokio::test]
    async fn fence_wins_over_the_body_eof() {
        let finished = tokio::time::timeout(TEST_DEADLINE, async {
            let (_registry, lease) = owner_lease();
            let client = plaintext_client(&lease, Duration::from_secs(2));
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .unwrap_or_else(|error| unreachable!("bind: {error}"));
            let addr = listener
                .local_addr()
                .unwrap_or_else(|error| unreachable!("addr: {error}"));
            let first_sent = Arc::new(Notify::new());
            let release = Arc::new(Notify::new());
            tokio::spawn(serve_gated_body(
                listener,
                b"partial-body".to_vec(),
                Arc::clone(&first_sent),
                Arc::clone(&release),
                true, // close (EOF) on release
            ));
            let (handle, gate) = spawn_probe(&client, "127.0.0.1", addr.port());
            first_sent.notified().await; // the first frame was read; probe stalls on the next
            gate.revoke();
            release.notify_one(); // release → server closes → client sees EOF
            let result = handle
                .await
                .unwrap_or_else(|error| unreachable!("join: {error}"));
            assert!(
                matches!(result, Err(ClusterHttpError::Fenced)),
                "a revoke at the body EOF is Fenced, not Ok: {result:?}"
            );
        })
        .await;
        assert!(finished.is_ok(), "oracle (e) finished in time");
    }

    /// A loopback nameserver that holds every response until `released`, signals
    /// `query_received` on the first query, then answers authoritative NODATA (no
    /// records) so resolution fails with a DNS class.
    async fn spawn_gated_dns() -> (u16, Arc<Notify>, Arc<AtomicBool>) {
        use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};

        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap_or_else(|error| unreachable!("bind dns: {error}"));
        let port = socket
            .local_addr()
            .unwrap_or_else(|error| unreachable!("dns addr: {error}"))
            .port();
        let query_received = Arc::new(Notify::new());
        let released = Arc::new(AtomicBool::new(false));
        let qr = Arc::clone(&query_received);
        let rel = Arc::clone(&released);
        tokio::spawn(async move {
            let mut buffer = vec![0u8; 2048];
            let mut signalled = false;
            loop {
                let Ok((len, src)) = socket.recv_from(&mut buffer).await else {
                    return;
                };
                let Ok(message) = Message::from_vec(&buffer[..len]) else {
                    continue;
                };
                let Some(query) = message.queries.first() else {
                    continue;
                };
                let qname = query.name().clone();
                let qtype = query.query_type();
                if !signalled {
                    signalled = true;
                    qr.notify_one();
                }
                while !rel.load(Ordering::SeqCst) {
                    tokio::task::yield_now().await;
                }
                let mut response = Message::new(message.id, MessageType::Response, OpCode::Query);
                response.metadata.authoritative = true;
                response.metadata.response_code = ResponseCode::NoError; // NODATA
                response.add_query(Query::query(qname, qtype));
                let Ok(bytes) = response.to_vec() else {
                    continue;
                };
                let _ = socket.send_to(&bytes, src).await;
            }
        });
        (port, query_received, released)
    }

    // (b) A revoke during a stalled DNS resolution that then fails is terminal
    //     `Fenced`, never `Dns` (the post-DNS-await fence).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fence_wins_over_a_dns_failure() {
        let finished = tokio::time::timeout(TEST_DEADLINE, async {
            let (_registry, lease) = owner_lease();
            let (dns_port, query_received, released) = spawn_gated_dns().await;
            let client = ClusterHttpClient::from_cluster_material(
                &ns_config(dns_port, None),
                lease.token(),
                policy(Duration::from_secs(2), 64 * 1024),
            )
            .unwrap_or_else(|error| unreachable!("client: {error}"));
            // A hostname forces the explicit-nameserver resolver path.
            let (handle, gate) = spawn_probe(&client, "svc.invalid", 10_080);
            query_received.notified().await; // resolution is stalled in-flight
            gate.revoke();
            released.store(true, Ordering::SeqCst); // release → NODATA → resolve fails
            let result = handle
                .await
                .unwrap_or_else(|error| unreachable!("join: {error}"));
            assert!(
                matches!(result, Err(ClusterHttpError::Fenced)),
                "a revoke coincident with a DNS failure is Fenced, not Dns: {result:?}"
            );
        })
        .await;
        assert!(finished.is_ok(), "oracle (b) finished in time");
    }

    /// A loopback server that waits for the client's `ClientHello` (via `peek`, not
    /// consuming it), signals `hello_seen`, waits for `release`, then EITHER writes
    /// garbage (an illegal handshake that fails) or completes a real TLS handshake
    /// with `acceptor` and records how many request bytes the client sent.
    async fn serve_gated_tls(
        listener: TcpListener,
        acceptor: Option<TlsAcceptor>,
        hello_seen: Arc<Notify>,
        release: Arc<Notify>,
        request_bytes: Arc<AtomicUsize>,
    ) {
        let Ok((stream, _peer)) = listener.accept().await else {
            return;
        };
        // Peek the ClientHello without consuming it, proving the client is past
        // its pre-TLS fence and blocked reading the ServerHello.
        let mut peek = [0u8; 8];
        let _ = stream.peek(&mut peek).await;
        hello_seen.notify_one();
        release.notified().await;
        match acceptor {
            None => {
                // An illegal handshake: garbage where a ServerHello belongs.
                let mut stream = stream;
                let _ = stream.write_all(b"\x00\x01\x02garbage").await;
                let _ = stream.flush().await;
            }
            Some(acceptor) => {
                if let Ok(mut tls) = acceptor.accept(stream).await {
                    let mut buffer = [0u8; 1024];
                    let read = tls.read(&mut buffer).await.unwrap_or(0);
                    request_bytes.store(read, Ordering::SeqCst);
                }
            }
        }
    }

    // (c) A revoke during a stalled TLS handshake that then fails is terminal
    //     `Fenced`, never `Tls` (the post-handshake-await fence).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fence_wins_over_a_tls_handshake_failure() {
        let finished = tokio::time::timeout(TEST_DEADLINE, async {
            let (_registry, lease) = owner_lease();
            let client = ClusterHttpClient::from_cluster_material(
                &tls_config(skip_ca_tls(&[], None, None)),
                lease.token(),
                policy(Duration::from_secs(2), 64 * 1024),
            )
            .unwrap_or_else(|error| unreachable!("client: {error}"));
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .unwrap_or_else(|error| unreachable!("bind: {error}"));
            let addr = listener
                .local_addr()
                .unwrap_or_else(|error| unreachable!("addr: {error}"));
            let hello_seen = Arc::new(Notify::new());
            let release = Arc::new(Notify::new());
            tokio::spawn(serve_gated_tls(
                listener,
                None, // garbage → handshake failure
                Arc::clone(&hello_seen),
                Arc::clone(&release),
                Arc::new(AtomicUsize::new(0)),
            ));
            let (handle, gate) = spawn_probe(&client, "127.0.0.1", addr.port());
            hello_seen.notified().await; // the handshake is stalled reading ServerHello
            gate.revoke();
            release.notify_one(); // release → garbage → handshake error
            let result = handle
                .await
                .unwrap_or_else(|error| unreachable!("join: {error}"));
            assert!(
                matches!(result, Err(ClusterHttpError::Fenced)),
                "a revoke coincident with a TLS failure is Fenced, not Tls: {result:?}"
            );
        })
        .await;
        assert!(finished.is_ok(), "oracle (c) finished in time");
    }

    // (d) A revoke after a SUCCESSFUL handshake, before the request, is terminal
    //     `Fenced` and NO request byte reaches the server (a post-handshake
    //     fence). NOTE: the post-handshake fences are defense-in-depth; this
    //     asserts the observable invariant (see the report for isolability).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fence_after_a_successful_handshake_sends_no_request() {
        let finished = tokio::time::timeout(TEST_DEADLINE, async {
            let (_registry, lease) = owner_lease();
            let (_ca, issuer) = make_ca("test-ca");
            let (cert, key) = make_leaf(&issuer, "backend", "localhost", true);
            let acceptor = server_acceptor(&cert, &key, None, rustls::ALL_VERSIONS);
            let client = ClusterHttpClient::from_cluster_material(
                &tls_config(skip_ca_tls(&[], None, None)),
                lease.token(),
                policy(Duration::from_secs(2), 64 * 1024),
            )
            .unwrap_or_else(|error| unreachable!("client: {error}"));
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .unwrap_or_else(|error| unreachable!("bind: {error}"));
            let addr = listener
                .local_addr()
                .unwrap_or_else(|error| unreachable!("addr: {error}"));
            let hello_seen = Arc::new(Notify::new());
            let release = Arc::new(Notify::new());
            let request_bytes = Arc::new(AtomicUsize::new(0));
            tokio::spawn(serve_gated_tls(
                listener,
                Some(acceptor), // complete a real handshake
                Arc::clone(&hello_seen),
                Arc::clone(&release),
                Arc::clone(&request_bytes),
            ));
            let (handle, gate) = spawn_probe(&client, "127.0.0.1", addr.port());
            hello_seen.notified().await; // the client is in the handshake, past pre-TLS
            gate.revoke();
            release.notify_one(); // release → handshake completes Ok, then the fence fires
            let result = handle
                .await
                .unwrap_or_else(|error| unreachable!("join: {error}"));
            assert!(
                matches!(result, Err(ClusterHttpError::Fenced)),
                "a revoke after a successful handshake is Fenced: {result:?}"
            );
            assert_eq!(
                request_bytes.load(Ordering::SeqCst),
                0,
                "no request byte is sent after a post-handshake revoke"
            );
        })
        .await;
        assert!(finished.is_ok(), "oracle (d) finished in time");
    }
}
