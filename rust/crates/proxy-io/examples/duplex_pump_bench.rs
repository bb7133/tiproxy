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

//! Dependency-free release benchmark for duplex-pump batching and memory bounds.

use std::error::Error;
use std::io;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use proxy_io::{DuplexPump, DuplexPumpConfig, PumpCancellation};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[derive(Debug)]
struct SyntheticEndpoint {
    remaining: Option<u64>,
    read_chunk: usize,
}

impl SyntheticEndpoint {
    const fn source(bytes: u64, read_chunk: usize) -> Self {
        Self {
            remaining: Some(bytes),
            read_chunk,
        }
    }

    const fn pending() -> Self {
        Self {
            remaining: None,
            read_chunk: 0,
        }
    }
}

impl AsyncRead for SyntheticEndpoint {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let Some(remaining) = self.remaining else {
            return Poll::Pending;
        };
        if remaining == 0 {
            return Poll::Ready(Ok(()));
        }
        let available = usize::try_from(remaining).unwrap_or(usize::MAX);
        let bytes = output.remaining().min(self.read_chunk).min(available);
        output.initialize_unfilled_to(bytes).fill(0x5a);
        output.advance(bytes);
        self.remaining = Some(remaining - u64::try_from(bytes).unwrap_or(u64::MAX));
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for SyntheticEndpoint {
    fn poll_write(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(input.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let quick = std::env::args().any(|argument| argument == "--quick");
    let bytes = if quick { 4_u64 << 20 } else { 64_u64 << 20 };
    let read_chunk = 256_usize;
    let read_buffer_size = NonZeroUsize::new(1024).ok_or("read buffer must be nonzero")?;
    let write_high_water =
        NonZeroUsize::new(32 * 1024).ok_or("write high water must be nonzero")?;
    let pump = DuplexPump::new(DuplexPumpConfig {
        read_buffer_size,
        write_high_water,
        max_flush_delay: Duration::from_millis(5),
        read_timeout: None,
        write_timeout: Duration::from_secs(5),
        shutdown_timeout: Duration::from_secs(1),
    })?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let started = Instant::now();
    let report = runtime.block_on(pump.run(
        SyntheticEndpoint::source(bytes, read_chunk),
        SyntheticEndpoint::pending(),
        &PumpCancellation::new(),
    ))?;
    let elapsed = started.elapsed();
    let direction = report.client_to_backend;

    if direction.bytes_read != bytes || direction.bytes_written != bytes {
        return Err("benchmark did not forward every byte".into());
    }
    if direction.maximum_buffered_bytes > write_high_water.get() {
        return Err("benchmark exceeded the configured high-water mark".into());
    }
    if direction.write_calls.saturating_mul(32) >= direction.read_calls {
        return Err("benchmark did not coalesce enough small reads".into());
    }

    println!(
        "bytes={} elapsed={elapsed:?} read_calls={} write_calls={} flushes={} max_buffered={} high_water={}",
        direction.bytes_read,
        direction.read_calls,
        direction.write_calls,
        direction.flushes,
        direction.maximum_buffered_bytes,
        write_high_water,
    );
    Ok(())
}
