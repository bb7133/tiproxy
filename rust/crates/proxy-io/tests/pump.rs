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

//! Deterministic bounded-memory and lifecycle tests for the duplex pump.

use std::collections::VecDeque;
use std::error::Error;
use std::io;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use proxy_io::{
    BufferPool, DirectionTermination, DuplexPump, DuplexPumpConfig, PumpCancellation,
    PumpConfigError, PumpDirection, PumpError, PumpOperation,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::time::{Instant, sleep, timeout};

#[derive(Debug, Default)]
struct IoStats {
    read_bytes: AtomicU64,
    write_bytes: AtomicU64,
    writes: AtomicU64,
    flushes: AtomicU64,
    shutdowns: AtomicU64,
}

#[derive(Debug)]
enum ReadBehavior {
    Chunks(VecDeque<Vec<u8>>),
    Infinite { byte: u8, chunk_size: usize },
    Pending,
    Reset,
}

#[derive(Debug)]
struct ScriptedIo {
    read: ReadBehavior,
    eof_after_chunks: bool,
    block_writes: bool,
    block_shutdown: bool,
    stats: Arc<IoStats>,
}

impl ScriptedIo {
    fn pending(stats: Arc<IoStats>) -> Self {
        Self {
            read: ReadBehavior::Pending,
            eof_after_chunks: false,
            block_writes: false,
            block_shutdown: false,
            stats,
        }
    }

    fn chunks(chunks: impl IntoIterator<Item = Vec<u8>>, eof: bool, stats: Arc<IoStats>) -> Self {
        Self {
            read: ReadBehavior::Chunks(chunks.into_iter().collect()),
            eof_after_chunks: eof,
            block_writes: false,
            block_shutdown: false,
            stats,
        }
    }

    fn infinite(chunk_size: usize, stats: Arc<IoStats>) -> Self {
        Self {
            read: ReadBehavior::Infinite {
                byte: b'x',
                chunk_size,
            },
            eof_after_chunks: false,
            block_writes: false,
            block_shutdown: false,
            stats,
        }
    }

    fn reset(stats: Arc<IoStats>) -> Self {
        Self {
            read: ReadBehavior::Reset,
            eof_after_chunks: false,
            block_writes: false,
            block_shutdown: false,
            stats,
        }
    }

    const fn with_blocked_writes(mut self) -> Self {
        self.block_writes = true;
        self
    }

    const fn with_blocked_shutdown(mut self) -> Self {
        self.block_shutdown = true;
        self
    }
}

impl AsyncRead for ScriptedIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let eof_after_chunks = self.eof_after_chunks;
        let (bytes, ready) = match &mut self.read {
            ReadBehavior::Chunks(chunks) => match chunks.pop_front() {
                Some(chunk) => {
                    if chunk.len() > output.remaining() {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "scripted chunk exceeds read buffer",
                        )));
                    }
                    output.put_slice(&chunk);
                    (chunk.len(), true)
                }
                None if eof_after_chunks => (0, true),
                None => (0, false),
            },
            ReadBehavior::Infinite { byte, chunk_size } => {
                let bytes = output.remaining().min(*chunk_size);
                output.initialize_unfilled_to(bytes).fill(*byte);
                output.advance(bytes);
                (bytes, true)
            }
            ReadBehavior::Pending => (0, false),
            ReadBehavior::Reset => {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    "scripted reset",
                )));
            }
        };
        if ready {
            self.stats
                .read_bytes
                .fetch_add(u64::try_from(bytes).unwrap_or(u64::MAX), Ordering::Relaxed);
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }
}

impl AsyncWrite for ScriptedIo {
    fn poll_write(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.block_writes {
            return Poll::Pending;
        }
        self.stats.write_bytes.fetch_add(
            u64::try_from(input.len()).unwrap_or(u64::MAX),
            Ordering::Relaxed,
        );
        self.stats.writes.fetch_add(1, Ordering::Relaxed);
        Poll::Ready(Ok(input.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.stats.flushes.fetch_add(1, Ordering::Relaxed);
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.block_shutdown {
            return Poll::Pending;
        }
        self.stats.shutdowns.fetch_add(1, Ordering::Relaxed);
        Poll::Ready(Ok(()))
    }
}

fn nonzero(value: usize) -> Result<NonZeroUsize, Box<dyn Error>> {
    NonZeroUsize::new(value).ok_or_else(|| "test value must be nonzero".into())
}

fn config(
    read_buffer_size: usize,
    write_high_water: usize,
    max_flush_delay: Duration,
) -> Result<DuplexPumpConfig, Box<dyn Error>> {
    Ok(DuplexPumpConfig {
        read_buffer_size: nonzero(read_buffer_size)?,
        write_high_water: nonzero(write_high_water)?,
        max_flush_delay,
        read_timeout: None,
        write_timeout: Duration::from_millis(100),
        shutdown_timeout: Duration::from_millis(100),
    })
}

#[test]
fn rejects_unbounded_or_impossible_policies_before_allocation() -> Result<(), Box<dyn Error>> {
    let high_water_below_read = config(8, 4, Duration::from_millis(1))?;
    assert!(matches!(
        DuplexPump::new(high_water_below_read),
        Err(PumpConfigError::HighWaterBelowReadBuffer {
            write_high_water: 4,
            read_buffer_size: 8,
        })
    ));

    let mut zero_flush_delay = config(4, 8, Duration::ZERO)?;
    assert!(matches!(
        DuplexPump::new(zero_flush_delay),
        Err(PumpConfigError::ZeroDuration {
            field: "max_flush_delay",
        })
    ));

    zero_flush_delay.max_flush_delay = Duration::from_millis(1);
    let undersized_pool = BufferPool::new(nonzero(2)?, nonzero(1)?);
    assert!(matches!(
        DuplexPump::with_pool(zero_flush_delay, undersized_pool),
        Err(PumpConfigError::PoolBufferTooSmall {
            pool_buffer_size: 2,
            read_buffer_size: 4,
        })
    ));
    Ok(())
}

#[tokio::test]
async fn parity_pkt_006_pool_reuses_fixed_buffers_with_bounded_idle_memory()
-> Result<(), Box<dyn Error>> {
    let config = config(4, 8, Duration::from_millis(5))?;
    let pool = BufferPool::new(nonzero(4)?, nonzero(2)?);
    let pump = DuplexPump::with_pool(config, pool.clone())?;

    for _ in 0..2 {
        let cancellation = PumpCancellation::new();
        cancellation.cancel();
        let left = ScriptedIo::pending(Arc::new(IoStats::default()));
        let right = ScriptedIo::pending(Arc::new(IoStats::default()));
        let report = pump.run(left, right, &cancellation).await?;
        assert_eq!(
            report.client_to_backend.termination,
            DirectionTermination::ExternalCancellation
        );
        assert_eq!(
            report.backend_to_client.termination,
            DirectionTermination::ExternalCancellation
        );
    }

    let stats = pool.stats();
    assert_eq!(stats.buffer_size, 4);
    assert_eq!(stats.max_idle, 2);
    assert_eq!(stats.active, 0);
    assert!(stats.idle <= 2);
    assert!(stats.allocations <= 2);
    assert!(stats.reuses >= 2);
    assert_eq!(stats.allocations + stats.reuses, 4);
    Ok(())
}

#[tokio::test]
async fn small_reads_batch_and_flush_before_the_latency_bound() -> Result<(), Box<dyn Error>> {
    let max_flush_delay = Duration::from_millis(10);
    let pump = DuplexPump::new(config(4, 8, max_flush_delay)?)?;
    let cancellation = PumpCancellation::new();
    let owner_cancellation = cancellation.clone();
    let client_stats = Arc::new(IoStats::default());
    let backend_stats = Arc::new(IoStats::default());
    let client = ScriptedIo::chunks(
        [vec![b'a'], vec![b'b'], vec![b'c'], vec![b'd']],
        false,
        client_stats,
    );
    let backend = ScriptedIo::pending(backend_stats.clone());
    let started = Instant::now();
    let owner = tokio::spawn(async move { pump.run(client, backend, &owner_cancellation).await });

    timeout(Duration::from_millis(200), async {
        while backend_stats.flushes.load(Ordering::Relaxed) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    let observed_latency = started.elapsed();
    assert!(observed_latency >= max_flush_delay);
    assert!(observed_latency < Duration::from_millis(200));
    cancellation.cancel();

    let report = timeout(Duration::from_millis(200), owner).await???;
    assert_eq!(report.client_to_backend.bytes_read, 4);
    assert_eq!(report.client_to_backend.bytes_written, 4);
    assert_eq!(report.client_to_backend.read_calls, 4);
    assert_eq!(report.client_to_backend.write_calls, 1);
    assert_eq!(report.client_to_backend.flushes, 1);
    assert_eq!(report.client_to_backend.maximum_buffered_bytes, 4);
    assert_eq!(backend_stats.writes.load(Ordering::Relaxed), 1);
    Ok(())
}

#[tokio::test]
async fn slow_destination_backpressures_at_the_high_water_mark_and_cancel_joins()
-> Result<(), Box<dyn Error>> {
    let pump = DuplexPump::new(config(4, 8, Duration::from_millis(50))?)?;
    let cancellation = PumpCancellation::new();
    let owner_cancellation = cancellation.clone();
    let client_stats = Arc::new(IoStats::default());
    let backend_stats = Arc::new(IoStats::default());
    let client = ScriptedIo::infinite(4, client_stats.clone());
    let backend = ScriptedIo::pending(backend_stats.clone()).with_blocked_writes();
    let owner = tokio::spawn(async move { pump.run(client, backend, &owner_cancellation).await });

    timeout(Duration::from_millis(200), async {
        while client_stats.read_bytes.load(Ordering::Relaxed) < 8 {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    sleep(Duration::from_millis(10)).await;
    assert_eq!(client_stats.read_bytes.load(Ordering::Relaxed), 8);
    assert_eq!(backend_stats.write_bytes.load(Ordering::Relaxed), 0);

    cancellation.cancel();
    let report = timeout(Duration::from_millis(200), owner).await???;
    assert_eq!(report.client_to_backend.bytes_read, 8);
    assert_eq!(report.client_to_backend.bytes_written, 0);
    assert_eq!(report.client_to_backend.maximum_buffered_bytes, 8);
    assert_eq!(report.client_to_backend.discarded_buffered_bytes, 8);
    assert_eq!(
        report.client_to_backend.termination,
        DirectionTermination::ExternalCancellation
    );
    assert_eq!(backend_stats.shutdowns.load(Ordering::Relaxed), 1);
    Ok(())
}

#[tokio::test]
async fn write_timeout_stops_a_blocked_destination_and_joins_its_peer() -> Result<(), Box<dyn Error>>
{
    let mut config = config(4, 4, Duration::from_millis(5))?;
    config.write_timeout = Duration::from_millis(20);
    let pump = DuplexPump::new(config)?;
    let cancellation = PumpCancellation::new();
    let client_stats = Arc::new(IoStats::default());
    let backend_stats = Arc::new(IoStats::default());

    let result = timeout(
        Duration::from_millis(200),
        pump.run(
            ScriptedIo::infinite(4, client_stats),
            ScriptedIo::pending(backend_stats.clone()).with_blocked_writes(),
            &cancellation,
        ),
    )
    .await?;
    let Err(error) = result else {
        return Err("blocked destination unexpectedly completed".into());
    };
    assert!(matches!(
        error,
        PumpError::Timeout {
            direction: PumpDirection::ClientToBackend,
            operation: PumpOperation::Write,
            ..
        }
    ));
    assert_eq!(backend_stats.shutdowns.load(Ordering::Relaxed), 1);
    Ok(())
}

#[tokio::test]
async fn eof_flushes_then_half_closes_both_directions_without_detached_tasks()
-> Result<(), Box<dyn Error>> {
    let pump = DuplexPump::new(config(4, 8, Duration::from_millis(5))?)?;
    let cancellation = PumpCancellation::new();
    let (client, mut client_peer) = tokio::io::duplex(64);
    let (backend, mut backend_peer) = tokio::io::duplex(64);
    let owner = tokio::spawn(async move { pump.run(client, backend, &cancellation).await });

    client_peer.write_all(b"select 1").await?;
    client_peer.shutdown().await?;
    let mut forwarded = Vec::new();
    timeout(
        Duration::from_millis(200),
        backend_peer.read_to_end(&mut forwarded),
    )
    .await??;
    assert_eq!(forwarded, b"select 1");

    let report = timeout(Duration::from_millis(200), owner).await???;
    assert_eq!(
        report.client_to_backend.termination,
        DirectionTermination::EndOfStream
    );
    assert_eq!(
        report.backend_to_client.termination,
        DirectionTermination::PeerTerminated
    );
    let mut client_output = Vec::new();
    timeout(
        Duration::from_millis(200),
        client_peer.read_to_end(&mut client_output),
    )
    .await??;
    assert!(client_output.is_empty());
    Ok(())
}

#[tokio::test]
async fn connection_reset_stops_peer_and_half_closes_both_destinations()
-> Result<(), Box<dyn Error>> {
    let pump = DuplexPump::new(config(4, 8, Duration::from_millis(5))?)?;
    let cancellation = PumpCancellation::new();
    let client_stats = Arc::new(IoStats::default());
    let backend_stats = Arc::new(IoStats::default());
    let client = ScriptedIo::reset(client_stats.clone());
    let backend = ScriptedIo::pending(backend_stats.clone());

    let result = timeout(
        Duration::from_millis(200),
        pump.run(client, backend, &cancellation),
    )
    .await?;
    let Err(error) = result else {
        return Err("reset unexpectedly completed".into());
    };
    match error {
        PumpError::Io {
            direction,
            operation,
            source,
        } => {
            assert_eq!(direction, PumpDirection::ClientToBackend);
            assert_eq!(operation, PumpOperation::Read);
            assert_eq!(source.kind(), io::ErrorKind::ConnectionReset);
        }
        other => return Err(format!("unexpected error: {other}").into()),
    }
    assert_eq!(client_stats.shutdowns.load(Ordering::Relaxed), 1);
    assert_eq!(backend_stats.shutdowns.load(Ordering::Relaxed), 1);
    Ok(())
}

#[tokio::test]
async fn read_timeout_stops_owner_and_both_directions_within_deadline() -> Result<(), Box<dyn Error>>
{
    let mut config = config(4, 8, Duration::from_millis(5))?;
    config.read_timeout = Some(Duration::from_millis(20));
    let pump = DuplexPump::new(config)?;
    let cancellation = PumpCancellation::new();
    let client_stats = Arc::new(IoStats::default());
    let backend_stats = Arc::new(IoStats::default());

    let result = timeout(
        Duration::from_millis(200),
        pump.run(
            ScriptedIo::pending(client_stats.clone()),
            ScriptedIo::pending(backend_stats.clone()),
            &cancellation,
        ),
    )
    .await?;
    let Err(error) = result else {
        return Err("idle read unexpectedly completed".into());
    };
    assert!(matches!(
        error,
        PumpError::Timeout {
            operation: PumpOperation::Read,
            ..
        }
    ));
    assert_eq!(client_stats.shutdowns.load(Ordering::Relaxed), 1);
    assert_eq!(backend_stats.shutdowns.load(Ordering::Relaxed), 1);
    Ok(())
}

#[tokio::test]
async fn shutdown_timeout_bounds_a_stuck_half_close() -> Result<(), Box<dyn Error>> {
    let mut config = config(4, 8, Duration::from_millis(5))?;
    config.shutdown_timeout = Duration::from_millis(20);
    let pump = DuplexPump::new(config)?;
    let cancellation = PumpCancellation::new();
    cancellation.cancel();

    let result = timeout(
        Duration::from_millis(200),
        pump.run(
            ScriptedIo::pending(Arc::new(IoStats::default())).with_blocked_shutdown(),
            ScriptedIo::pending(Arc::new(IoStats::default())).with_blocked_shutdown(),
            &cancellation,
        ),
    )
    .await?;
    let Err(error) = result else {
        return Err("blocked shutdown unexpectedly completed".into());
    };
    assert!(matches!(
        error,
        PumpError::Timeout {
            operation: PumpOperation::Shutdown,
            ..
        }
    ));
    Ok(())
}
