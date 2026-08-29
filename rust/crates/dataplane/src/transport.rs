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

//! Session transport variants (A1 TLS activation).
//!
//! The engine owns its client and backend byte streams through
//! [`proxy_io::PacketIo`]. To let the engine upgrade a plaintext socket to
//! TLS without changing every wire call site, the concrete transport is an
//! enum that implements [`AsyncRead`]/[`AsyncWrite`] by delegating to whichever
//! variant is active. A session begins on the `Plain` variant and, when a
//! client `SSLRequest` or a backend TLS plan activates TLS, the engine swaps in
//! the `Tls` variant in place via the state-preserving [`proxy_io::PacketIo`]
//! upgrade seam. `Detached` is a transient placeholder held only across the
//! upgrade `await` and is never polled.
//!
//! The innermost layer of every non-detached variant is a
//! [`proxy_io::counted::CountedIo`] wrapping the raw `TcpStream`, installed at
//! accept/dial before any PROXY/TLS/compression layer. It counts real wire
//! bytes exactly once at the bottom of the stack, mirroring Go `TiProxy`'s
//! innermost `basicReadWriter` accounting (WIRE-MTR); the session reads the
//! traffic totals through the shared [`proxy_io::counted::ByteCounters`] handle
//! rather than from the framing layer above.

use std::pin::Pin;
use std::task::{Context, Poll};

use proxy_io::compression::CompressedIo;
use proxy_io::counted::CountedIo;
use proxy_io::direction::DirectionSync;
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
    /// Plaintext client socket, byte-counted at the raw layer.
    Plain(CountedIo<TcpStream>),
    /// Server-side TLS over the byte-counted client socket.
    Tls(FrontendTls<CountedIo<TcpStream>>),
    /// `MySQL` compressed framing over the client transport, itself either
    /// plaintext or TLS (compression is the OUTERMOST transport layer, above
    /// TLS, mirroring Go's `compressedReadWriter -> tlsReadWriter ->
    /// basicReadWriter`). Activated after authentication when the client
    /// negotiated `COMPRESS`/`ZSTD` (slice C); boxed to keep this enum sized.
    Compressed(Box<CompressedIo<ClientTransport>>),
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
            Self::Compressed(inner) => Pin::new(&mut **inner).poll_read(context, buf),
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
            Self::Compressed(inner) => Pin::new(&mut **inner).poll_write(context, data),
            Self::Detached => Poll::Ready(Err(detached_error())),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(inner) => Pin::new(inner).poll_flush(context),
            Self::Tls(inner) => Pin::new(&mut inner.stream).poll_flush(context),
            Self::Compressed(inner) => Pin::new(&mut **inner).poll_flush(context),
            Self::Detached => Poll::Ready(Err(detached_error())),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(inner) => Pin::new(inner).poll_shutdown(context),
            Self::Tls(inner) => Pin::new(&mut inner.stream).poll_shutdown(context),
            Self::Compressed(inner) => Pin::new(&mut **inner).poll_shutdown(context),
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
    /// Plaintext backend socket, byte-counted at the raw layer.
    Plain(CountedIo<TcpStream>),
    /// Client-side TLS over the byte-counted backend socket.
    Tls(BackendTls<CountedIo<TcpStream>>),
    /// `MySQL` compressed framing over the backend transport, itself either
    /// plaintext or TLS (compression is the OUTERMOST transport layer, above
    /// TLS). Activated after authentication when the backend negotiated
    /// `COMPRESS`/`ZSTD` (slice C); boxed to keep this enum sized.
    Compressed(Box<CompressedIo<BackendTransport>>),
    /// Transient placeholder installed only while a TLS upgrade moves the
    /// concrete socket out of the endpoint (across the `connect` await). The
    /// engine never reads or writes the endpoint in this window — it either
    /// reattaches the upgraded transport or fails the session closed.
    Detached,
}

impl BackendTransport {
    /// Returns the innermost byte-counting wrapper over the backend socket,
    /// reaching through the TLS session when active, or `None` while the
    /// transport is detached for an in-progress upgrade.
    ///
    /// The idle-liveness probe issues a non-blocking read directly on the raw
    /// socket (bypassing the TLS record layer), but does so through
    /// [`CountedIo::probe_try_read`] so any byte it consumes is still counted on
    /// the same seam as the framed I/O — no separate counter mutator is exposed.
    pub fn as_counted_stream(&self) -> Option<&CountedIo<TcpStream>> {
        match self {
            Self::Plain(inner) => Some(inner),
            Self::Tls(inner) => Some(inner.stream.get_ref().0),
            Self::Compressed(inner) => inner.get_ref().as_counted_stream(),
            Self::Detached => None,
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
            Self::Compressed(inner) => Pin::new(&mut **inner).poll_read(context, buf),
            Self::Detached => Poll::Ready(Err(detached_error())),
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
            Self::Compressed(inner) => Pin::new(&mut **inner).poll_write(context, data),
            Self::Detached => Poll::Ready(Err(detached_error())),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(inner) => Pin::new(inner).poll_flush(context),
            Self::Tls(inner) => Pin::new(&mut inner.stream).poll_flush(context),
            Self::Compressed(inner) => Pin::new(&mut **inner).poll_flush(context),
            Self::Detached => Poll::Ready(Err(detached_error())),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(inner) => Pin::new(inner).poll_shutdown(context),
            Self::Tls(inner) => Pin::new(&mut inner.stream).poll_shutdown(context),
            Self::Compressed(inner) => Pin::new(&mut **inner).poll_shutdown(context),
            Self::Detached => Poll::Ready(Err(detached_error())),
        }
    }
}

/// Maps a compression codec error into a transport `io::Error` so the packet
/// layer's direction hooks can fail closed.
fn compression_io_error(error: proxy_io::compression::CompressionError) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, error)
}

impl DirectionSync for ClientTransport {
    fn begin_read(&mut self) -> std::io::Result<Option<u8>> {
        match self {
            Self::Compressed(inner) => inner.begin_read().map_err(compression_io_error),
            _ => Ok(None),
        }
    }

    fn begin_write(&mut self) -> std::io::Result<Option<u8>> {
        match self {
            Self::Compressed(inner) => inner.begin_write().map_err(compression_io_error),
            _ => Ok(None),
        }
    }

    fn reset_layer_sequence(&mut self) {
        if let Self::Compressed(inner) = self {
            inner.reset_sequence();
        }
    }
}

impl DirectionSync for BackendTransport {
    fn begin_read(&mut self) -> std::io::Result<Option<u8>> {
        match self {
            Self::Compressed(inner) => inner.begin_read().map_err(compression_io_error),
            _ => Ok(None),
        }
    }

    fn begin_write(&mut self) -> std::io::Result<Option<u8>> {
        match self {
            Self::Compressed(inner) => inner.begin_write().map_err(compression_io_error),
            _ => Ok(None),
        }
    }

    fn reset_layer_sequence(&mut self) {
        if let Self::Compressed(inner) = self {
            inner.reset_sequence();
        }
    }
}
