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

//! Session transport variants (A1 TLS activation, step 2a).
//!
//! The engine owns its client and backend byte streams through
//! [`proxy_io::PacketIo`]. To let a later step upgrade a plaintext
//! socket to TLS without changing every wire call site, the concrete
//! transport is an enum that implements [`AsyncRead`]/[`AsyncWrite`] by
//! delegating to whichever variant is active. This step wires only the
//! `Plain` variant, so the behavior is byte-identical to a bare
//! `TcpStream`; the `Tls` variants are defined but not constructed until
//! the TLS-upgrade step.

use std::pin::Pin;
use std::task::{Context, Poll};

use proxy_io::tls::{BackendTls, FrontendTls};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

/// The client-facing transport: a plaintext socket or, once upgraded, a
/// server-side TLS session over that socket.
///
/// The `Tls` variant wraps [`FrontendTls`] (the public frontend TLS
/// wrapper from `proxy-io`), whose `stream` field is the concrete
/// server TLS stream implementing `AsyncRead`/`AsyncWrite`.
#[allow(clippy::large_enum_variant)]
pub enum ClientTransport {
    /// Plaintext client socket.
    Plain(TcpStream),
    /// Server-side TLS over the client socket.
    Tls(FrontendTls<TcpStream>),
    /// Transient placeholder installed only while a TLS upgrade moves the
    /// concrete socket out of the endpoint (across the `accept` await). The
    /// engine never reads or writes the endpoint in this window — it either
    /// reattaches the upgraded transport or fails the session closed — so the
    /// I/O arms below fail closed rather than pretending to carry a socket.
    Detached,
}

/// A fail-closed error for the transient `Detached` transport, which is never
/// polled during the upgrade window.
fn detached_error() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::BrokenPipe,
        "transport detached for TLS upgrade",
    )
}

impl AsyncRead for ClientTransport {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(inner) => Pin::new(inner).poll_read(context, buf),
            Self::Tls(inner) => Pin::new(&mut inner.stream).poll_read(context, buf),
            Self::Detached => Poll::Ready(Err(detached_error())),
        }
    }
}

impl AsyncWrite for ClientTransport {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(inner) => Pin::new(inner).poll_write(context, data),
            Self::Tls(inner) => Pin::new(&mut inner.stream).poll_write(context, data),
            Self::Detached => Poll::Ready(Err(detached_error())),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(inner) => Pin::new(inner).poll_flush(context),
            Self::Tls(inner) => Pin::new(&mut inner.stream).poll_flush(context),
            Self::Detached => Poll::Ready(Err(detached_error())),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(inner) => Pin::new(inner).poll_shutdown(context),
            Self::Tls(inner) => Pin::new(&mut inner.stream).poll_shutdown(context),
            Self::Detached => Poll::Ready(Err(detached_error())),
        }
    }
}

/// The backend-facing transport: a plaintext socket or, once upgraded, a
/// client-side TLS session over that socket.
///
/// The `Tls` variant wraps [`BackendTls`] (the public backend TLS
/// wrapper from `proxy-io`), whose `stream` field is the concrete
/// client TLS stream implementing `AsyncRead`/`AsyncWrite`.
#[allow(clippy::large_enum_variant)]
pub enum BackendTransport {
    /// Plaintext backend socket (the only variant wired in step 2a).
    Plain(TcpStream),
    /// Client-side TLS over the backend socket.
    // constructed in A1 step 2b (TLS upgrade)
    #[allow(dead_code)]
    Tls(BackendTls<TcpStream>),
}

impl BackendTransport {
    /// Returns the underlying backend `TcpStream`, reaching through the
    /// TLS session when one is active.
    ///
    /// The idle-liveness probe issues a non-blocking `try_read` directly
    /// on the socket, so it must bypass the TLS record layer.
    pub fn as_tcp_stream(&self) -> &TcpStream {
        match self {
            Self::Plain(inner) => inner,
            Self::Tls(inner) => inner.stream.get_ref().0,
        }
    }
}

impl AsyncRead for BackendTransport {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(inner) => Pin::new(inner).poll_read(context, buf),
            Self::Tls(inner) => Pin::new(&mut inner.stream).poll_read(context, buf),
        }
    }
}

impl AsyncWrite for BackendTransport {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(inner) => Pin::new(inner).poll_write(context, data),
            Self::Tls(inner) => Pin::new(&mut inner.stream).poll_write(context, data),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(inner) => Pin::new(inner).poll_flush(context),
            Self::Tls(inner) => Pin::new(&mut inner.stream).poll_flush(context),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(inner) => Pin::new(inner).poll_shutdown(context),
            Self::Tls(inner) => Pin::new(&mut inner.stream).poll_shutdown(context),
        }
    }
}
