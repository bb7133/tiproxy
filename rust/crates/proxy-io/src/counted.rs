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

//! Innermost raw-socket byte accounting (WIRE-MTR).
//!
//! Go `TiProxy`'s `packetIO` delegates `InBytes`/`OutBytes` down through the
//! TLS and compression layers to the innermost `basicReadWriter`, so the
//! traffic metric counts real socket / TLS-record I/O, not the plaintext
//! `MySQL` bytes framed above those layers. [`CountedIo`] mirrors that: it
//! wraps the raw socket at the very bottom of the transport stack — beneath the
//! PROXY v2 probe, TLS, and compression — so every byte that actually crosses
//! the wire is counted exactly once regardless of the layers stacked above.
//!
//! The counters live behind an [`Arc`] so the owning session keeps a handle
//! that survives the value-consuming TLS/compression upgrades (which move the
//! `CountedIo` into a wrapper). One [`ByteCounters`] backs exactly one socket:
//! a redirected backend socket is wrapped in a fresh `CountedIo`, so the old
//! leg's totals can be snapshotted and closed out before the swap rather than
//! smeared across two sockets.

use std::io::IoSlice;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

/// Monotonic raw byte counters shared between a [`CountedIo`] and its owner.
///
/// Only bytes that a poll actually transferred are counted; a pending or failed
/// poll contributes nothing. Counts are monotonic for the lifetime of the one
/// socket the backing `CountedIo` wraps.
#[derive(Debug, Default)]
pub struct ByteCounters {
    inbound: AtomicU64,
    outbound: AtomicU64,
}

impl ByteCounters {
    /// Total bytes read from the socket so far.
    #[must_use]
    pub fn inbound(&self) -> u64 {
        self.inbound.load(Ordering::Relaxed)
    }

    /// Total bytes written to the socket so far.
    #[must_use]
    pub fn outbound(&self) -> u64 {
        self.outbound.load(Ordering::Relaxed)
    }

    fn add_inbound(&self, bytes: usize) {
        self.inbound.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    fn add_outbound(&self, bytes: usize) {
        self.outbound.fetch_add(bytes as u64, Ordering::Relaxed);
    }
}

/// Wraps a raw byte stream, counting only successfully transferred bytes at the
/// innermost layer of the transport stack.
pub struct CountedIo<T> {
    inner: T,
    counters: Arc<ByteCounters>,
}

impl<T> CountedIo<T> {
    /// Wraps `inner` with a fresh, independent set of counters.
    #[must_use]
    pub fn new(inner: T) -> Self {
        Self {
            inner,
            counters: Arc::new(ByteCounters::default()),
        }
    }

    /// Returns a handle to this socket's counters.
    ///
    /// The owner keeps the handle to read totals without traversing the layered
    /// transport, and it stays valid across the value-consuming TLS/compression
    /// upgrades that move this `CountedIo`.
    #[must_use]
    pub fn counters(&self) -> Arc<ByteCounters> {
        Arc::clone(&self.counters)
    }

    /// Consumes the wrapper and returns the inner transport.
    #[must_use]
    pub fn into_inner(self) -> T {
        self.inner
    }

    /// Returns a shared reference to the inner transport.
    #[must_use]
    pub const fn get_ref(&self) -> &T {
        &self.inner
    }

    /// Returns a mutable reference to the inner transport.
    pub const fn get_mut(&mut self) -> &mut T {
        &mut self.inner
    }
}

impl CountedIo<TcpStream> {
    /// Non-blocking idle-liveness read on the raw socket that counts any bytes
    /// it consumes on this wrapper's own counters — keeping real I/O and its
    /// accounting atomically bound here rather than exposing a counter mutator.
    /// A probe that consumes a real byte (before the session tears the
    /// connection down) is thus accounted exactly once, matching Go, whose
    /// liveness `Peek` reads through the counting `basicReadWriter`.
    ///
    /// A `WouldBlock` error is the healthy idle case (no data); `Ok(0)` is a
    /// clean EOF; `Ok(n)` with `n > 0` means `n` unexpected bytes were consumed
    /// and counted. Neither `WouldBlock` nor `Ok(0)` changes the counters.
    ///
    /// # Errors
    ///
    /// Propagates the underlying non-blocking read error (notably `WouldBlock`
    /// when the socket has no data ready).
    pub fn probe_try_read(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        let read = self.inner.try_read(buf)?;
        if read > 0 {
            self.counters.add_inbound(read);
        }
        Ok(read)
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for CountedIo<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let poll = Pin::new(&mut self.inner).poll_read(context, buf);
        if let Poll::Ready(Ok(())) = &poll {
            let read = buf.filled().len().saturating_sub(before);
            if read > 0 {
                self.counters.add_inbound(read);
            }
        }
        poll
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for CountedIo<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let poll = Pin::new(&mut self.inner).poll_write(context, data);
        if let Poll::Ready(Ok(written)) = &poll
            && *written > 0
        {
            self.counters.add_outbound(*written);
        }
        poll
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        let poll = Pin::new(&mut self.inner).poll_write_vectored(context, bufs);
        if let Poll::Ready(Ok(written)) = &poll
            && *written > 0
        {
            self.counters.add_outbound(*written);
        }
        poll
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}
