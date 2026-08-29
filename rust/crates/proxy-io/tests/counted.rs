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

//! Innermost raw-socket byte accounting (`CountedIo`, WIRE-MTR).
//!
//! Locks the counting contract: only bytes a poll actually transfers are
//! counted (a `Pending` or zero-length poll adds nothing), counts are
//! monotonic across reads and writes, and the shared handle observes them.

use std::io::{self, IoSlice};
use std::pin::Pin;
use std::task::{Context, Poll, Waker};

use proxy_io::counted::CountedIo;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};

/// A scripted inner transport: the first read (when armed) yields
/// `Poll::Pending`, later reads deliver the queued bytes, and every write is
/// accepted in full. It advertises vectored writes so the `poll_write_vectored`
/// counting path is exercised. The `CountedIo` counters — not this mock — are
/// what the assertions observe.
struct ScriptedIo {
    stall_next_read: bool,
    to_deliver: Vec<u8>,
}

impl ScriptedIo {
    fn new(stall_next_read: bool, to_deliver: Vec<u8>) -> Self {
        Self {
            stall_next_read,
            to_deliver,
        }
    }
}

impl AsyncRead for ScriptedIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.stall_next_read {
            self.stall_next_read = false;
            return Poll::Pending;
        }
        let take = self.to_deliver.len().min(buf.remaining());
        let chunk: Vec<u8> = self.to_deliver.drain(..take).collect();
        buf.put_slice(&chunk);
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for ScriptedIo {
    fn poll_write(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(data.len()))
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let total: usize = bufs.iter().map(|buf| buf.len()).sum();
        Poll::Ready(Ok(total))
    }

    fn is_write_vectored(&self) -> bool {
        true
    }

    fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn counts_match_bytes_transferred_and_are_monotonic() -> io::Result<()> {
    let (near, mut far) = tokio::io::duplex(64 * 1024);
    let mut counted = CountedIo::new(near);
    let counters = counted.counters();

    counted.write_all(b"hello ").await?;
    counted.write_all(b"world").await?;
    counted.flush().await?;
    assert_eq!(counters.outbound(), 11, "two writes accumulate");

    let mut drain = vec![0_u8; 11];
    far.read_exact(&mut drain).await?;

    far.write_all(b"reply").await?;
    far.flush().await?;
    let mut got = [0_u8; 5];
    counted.read_exact(&mut got).await?;
    assert_eq!(
        counters.inbound(),
        5,
        "reads counted separately from writes"
    );
    assert_eq!(
        counters.outbound(),
        11,
        "reads do not disturb the write count"
    );
    Ok(())
}

#[test]
fn a_pending_read_counts_nothing_until_it_completes() {
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    let mut counted = CountedIo::new(ScriptedIo::new(true, b"abcd".to_vec()));
    let counters = counted.counters();

    let mut store = [0_u8; 8];
    let mut buf = ReadBuf::new(&mut store);
    // First poll: the inner transport stalls; nothing may be counted.
    assert!(
        matches!(
            Pin::new(&mut counted).poll_read(&mut context, &mut buf),
            Poll::Pending
        ),
        "the scripted transport stalls the first read"
    );
    assert_eq!(counters.inbound(), 0, "a pending read counts nothing");

    // Second poll: the bytes arrive and exactly those are counted.
    assert!(matches!(
        Pin::new(&mut counted).poll_read(&mut context, &mut buf),
        Poll::Ready(Ok(()))
    ));
    assert_eq!(buf.filled(), b"abcd");
    assert_eq!(
        counters.inbound(),
        4,
        "only the delivered bytes are counted"
    );
}

#[test]
fn vectored_and_zero_length_writes_count_exactly_what_transferred() {
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    let mut counted = CountedIo::new(ScriptedIo::new(false, Vec::new()));
    let counters = counted.counters();

    // A zero-length write transfers nothing and must not be counted.
    assert!(matches!(
        Pin::new(&mut counted).poll_write(&mut context, &[]),
        Poll::Ready(Ok(0))
    ));
    assert_eq!(counters.outbound(), 0, "a zero-length write counts nothing");

    // A vectored write counts the sum of all buffers exactly once.
    let bufs = [IoSlice::new(b"abc"), IoSlice::new(b"defg")];
    assert!(matches!(
        Pin::new(&mut counted).poll_write_vectored(&mut context, &bufs),
        Poll::Ready(Ok(7))
    ));
    assert_eq!(counters.outbound(), 7, "vectored bytes counted once");
}

/// The count-aware idle-liveness probe on a real socket: a would-block (no data)
/// and a clean EOF (`Ok(0)`) add nothing, while a consumed `Ok(n)` adds exactly
/// `n`. This keeps the liveness probe from silently consuming raw bytes off the
/// socket without accounting for them (the seam bypass the review flagged).
#[tokio::test]
async fn probe_try_read_counts_only_consumed_bytes() -> io::Result<()> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let addr = listener.local_addr()?;
    let (peer, accepted) = tokio::join!(TcpStream::connect(addr), listener.accept());
    let mut peer = peer?;
    let (server, _) = accepted?;
    let counted = CountedIo::new(server);
    let counters = counted.counters();
    let mut probe = [0_u8; 8];

    // No data yet: the probe would block and counts nothing.
    let idle = counted.probe_try_read(&mut probe);
    assert!(
        matches!(&idle, Err(error) if error.kind() == io::ErrorKind::WouldBlock),
        "an idle socket must report WouldBlock, not a spurious read"
    );
    assert_eq!(counters.inbound(), 0, "WouldBlock counts nothing");

    // The peer sends three bytes: the probe consumes and counts exactly those.
    // `readable()` readiness is only a hint, so retry past a spurious WouldBlock
    // rather than treat it as a failure.
    peer.write_all(b"abc").await?;
    peer.flush().await?;
    let consumed = read_probe_blocking(&counted, &mut probe).await?;
    assert_eq!(consumed, 3, "the probe consumed the delivered bytes");
    assert_eq!(counters.inbound(), 3, "Ok(n) counts exactly n");

    // The peer closes: the probe reads a clean EOF and counts nothing more.
    drop(peer);
    let eof = read_probe_blocking(&counted, &mut probe).await?;
    assert_eq!(eof, 0, "a closed peer reads Ok(0)");
    assert_eq!(counters.inbound(), 3, "Ok(0) EOF adds nothing");
    Ok(())
}

/// Drives [`CountedIo::probe_try_read`] to its first non-`WouldBlock` result,
/// retrying past the false-positive readiness that `readable()` can report.
async fn read_probe_blocking(counted: &CountedIo<TcpStream>, buf: &mut [u8]) -> io::Result<usize> {
    loop {
        counted.get_ref().readable().await?;
        match counted.probe_try_read(buf) {
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            other => return other,
        }
    }
}
