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

use std::fmt;
use std::future::pending;
use std::io;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::watch;
use tokio::time::{Instant, sleep_until, timeout};

/// Default read-buffer size for a duplex forwarding direction.
pub const DEFAULT_PUMP_BUFFER_SIZE: usize = 32 * 1024;

/// Default maximum bytes staged for one forwarding direction.
pub const DEFAULT_WRITE_HIGH_WATER: usize = 64 * 1024;

const DEFAULT_IDLE_BUFFERS: usize = 4;

/// Direction in which a duplex-pump operation was running.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PumpDirection {
    /// Bytes moving from the frontend client to the backend.
    ClientToBackend,
    /// Bytes moving from the backend to the frontend client.
    BackendToClient,
}

impl fmt::Display for PumpDirection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ClientToBackend => formatter.write_str("client to backend"),
            Self::BackendToClient => formatter.write_str("backend to client"),
        }
    }
}

/// I/O operation that failed or exceeded its configured deadline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PumpOperation {
    /// Reading from a source stream.
    Read,
    /// Writing staged bytes to a destination stream.
    Write,
    /// Flushing a destination stream.
    Flush,
    /// Half-closing a destination stream.
    Shutdown,
}

impl fmt::Display for PumpOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read => formatter.write_str("read"),
            Self::Write => formatter.write_str("write"),
            Self::Flush => formatter.write_str("flush"),
            Self::Shutdown => formatter.write_str("shutdown"),
        }
    }
}

/// Invalid duplex-pump configuration.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PumpConfigError {
    /// The write queue cannot hold one maximum read.
    #[error(
        "write high-water mark {write_high_water} is smaller than read buffer {read_buffer_size}"
    )]
    HighWaterBelowReadBuffer {
        /// Configured maximum queued bytes per direction.
        write_high_water: usize,
        /// Configured maximum bytes read in one operation.
        read_buffer_size: usize,
    },
    /// A required deadline was configured as zero.
    #[error("{field} must be positive")]
    ZeroDuration {
        /// Stable configuration-field name.
        field: &'static str,
    },
    /// A shared pool cannot satisfy this pump's read-buffer size.
    #[error("buffer pool size {pool_buffer_size} is smaller than read buffer {read_buffer_size}")]
    PoolBufferTooSmall {
        /// Fixed buffer size supplied by the pool.
        pool_buffer_size: usize,
        /// Read-buffer size required by the pump.
        read_buffer_size: usize,
    },
}

/// Runtime failure from a duplex forwarding direction.
#[derive(Debug, Error)]
pub enum PumpError {
    /// A source or destination returned an I/O error.
    #[error("{direction} {operation} failed: {source}")]
    Io {
        /// Direction in which the error occurred.
        direction: PumpDirection,
        /// Operation that failed.
        operation: PumpOperation,
        /// Underlying transport error.
        #[source]
        source: io::Error,
    },
    /// An operation exceeded its configured deadline.
    #[error("{direction} {operation} exceeded deadline {deadline:?}")]
    Timeout {
        /// Direction in which the timeout occurred.
        direction: PumpDirection,
        /// Operation that timed out.
        operation: PumpOperation,
        /// Configured deadline duration.
        deadline: Duration,
    },
    /// A report counter could not represent another observation.
    #[error("{direction} {field} counter overflow")]
    CounterOverflow {
        /// Direction whose counter overflowed.
        direction: PumpDirection,
        /// Stable counter name.
        field: &'static str,
    },
}

impl PumpError {
    fn io(direction: PumpDirection, operation: PumpOperation, source: io::Error) -> Self {
        Self::Io {
            direction,
            operation,
            source,
        }
    }

    fn timed_out(direction: PumpDirection, operation: PumpOperation, deadline: Duration) -> Self {
        Self::Timeout {
            direction,
            operation,
            deadline,
        }
    }
}

/// Bounded-memory and deadline policy for a [`DuplexPump`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DuplexPumpConfig {
    /// Maximum bytes requested by one source read.
    pub read_buffer_size: NonZeroUsize,
    /// Hard maximum bytes staged per direction before a write is forced.
    pub write_high_water: NonZeroUsize,
    /// Maximum time that a nonempty staged write may wait for coalescing.
    pub max_flush_delay: Duration,
    /// Optional maximum idle time between successful source reads.
    pub read_timeout: Option<Duration>,
    /// Maximum time for one staged write or flush.
    pub write_timeout: Duration,
    /// Maximum time allowed to half-close one destination.
    pub shutdown_timeout: Duration,
}

impl Default for DuplexPumpConfig {
    fn default() -> Self {
        Self {
            read_buffer_size: NonZeroUsize::new(DEFAULT_PUMP_BUFFER_SIZE)
                .unwrap_or(NonZeroUsize::MIN),
            write_high_water: NonZeroUsize::new(DEFAULT_WRITE_HIGH_WATER)
                .unwrap_or(NonZeroUsize::MIN),
            max_flush_delay: Duration::from_millis(1),
            read_timeout: None,
            write_timeout: Duration::from_secs(30),
            shutdown_timeout: Duration::from_secs(1),
        }
    }
}

impl DuplexPumpConfig {
    fn validate(self) -> Result<Self, PumpConfigError> {
        if self.write_high_water < self.read_buffer_size {
            return Err(PumpConfigError::HighWaterBelowReadBuffer {
                write_high_water: self.write_high_water.get(),
                read_buffer_size: self.read_buffer_size.get(),
            });
        }
        for (field, duration) in [
            ("max_flush_delay", self.max_flush_delay),
            ("write_timeout", self.write_timeout),
            ("shutdown_timeout", self.shutdown_timeout),
        ] {
            if duration.is_zero() {
                return Err(PumpConfigError::ZeroDuration { field });
            }
        }
        if self.read_timeout.is_some_and(|duration| duration.is_zero()) {
            return Err(PumpConfigError::ZeroDuration {
                field: "read_timeout",
            });
        }
        Ok(self)
    }
}

/// Snapshot of a reusable buffer pool's allocation state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BufferPoolStats {
    /// Fixed size of every leased buffer.
    pub buffer_size: usize,
    /// Maximum buffers retained while idle.
    pub max_idle: usize,
    /// Buffers currently retained for reuse.
    pub idle: usize,
    /// Buffers currently leased by active forwarding directions.
    pub active: usize,
    /// Fresh allocations performed since pool creation.
    pub allocations: u64,
    /// Successful idle-buffer reuses since pool creation.
    pub reuses: u64,
}

#[derive(Debug)]
struct BufferPoolInner {
    buffer_size: NonZeroUsize,
    max_idle: NonZeroUsize,
    idle: Mutex<Vec<Vec<u8>>>,
    active: AtomicUsize,
    allocations: AtomicU64,
    reuses: AtomicU64,
}

/// Cloneable pool for fixed-size per-direction read buffers.
///
/// Active memory is exactly one fixed buffer per forwarding direction. Idle
/// memory is capped by `max_idle`; an excess returned buffer is dropped rather
/// than retained. The pool never waits for a buffer, so sharing it across
/// independent session owners cannot deadlock their lifecycles.
#[derive(Debug, Clone)]
pub struct BufferPool {
    inner: Arc<BufferPoolInner>,
}

impl BufferPool {
    /// Creates a fixed-size pool with a bounded idle cache.
    #[must_use]
    pub fn new(buffer_size: NonZeroUsize, max_idle: NonZeroUsize) -> Self {
        Self {
            inner: Arc::new(BufferPoolInner {
                buffer_size,
                max_idle,
                idle: Mutex::new(Vec::with_capacity(max_idle.get())),
                active: AtomicUsize::new(0),
                allocations: AtomicU64::new(0),
                reuses: AtomicU64::new(0),
            }),
        }
    }

    /// Returns the fixed size of a leased buffer.
    #[must_use]
    pub fn buffer_size(&self) -> usize {
        self.inner.buffer_size.get()
    }

    /// Returns an instantaneous allocation/reuse snapshot.
    #[must_use]
    pub fn stats(&self) -> BufferPoolStats {
        BufferPoolStats {
            buffer_size: self.buffer_size(),
            max_idle: self.inner.max_idle.get(),
            idle: self.lock_idle().len(),
            active: self.inner.active.load(Ordering::Relaxed),
            allocations: self.inner.allocations.load(Ordering::Relaxed),
            reuses: self.inner.reuses.load(Ordering::Relaxed),
        }
    }

    fn acquire(&self) -> PooledBuffer {
        let buffer = if let Some(buffer) = self.lock_idle().pop() {
            self.inner.reuses.fetch_add(1, Ordering::Relaxed);
            buffer
        } else {
            self.inner.allocations.fetch_add(1, Ordering::Relaxed);
            vec![0_u8; self.buffer_size()]
        };
        self.inner.active.fetch_add(1, Ordering::Relaxed);
        PooledBuffer {
            pool: self.clone(),
            buffer: Some(buffer),
        }
    }

    fn lock_idle(&self) -> MutexGuard<'_, Vec<Vec<u8>>> {
        match self.inner.idle.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

#[derive(Debug)]
struct PooledBuffer {
    pool: BufferPool,
    buffer: Option<Vec<u8>>,
}

impl PooledBuffer {
    fn as_mut_slice(&mut self) -> &mut [u8] {
        self.buffer.as_deref_mut().unwrap_or_default()
    }
}

impl Drop for PooledBuffer {
    fn drop(&mut self) {
        if let Some(buffer) = self.buffer.take() {
            let mut idle = self.pool.lock_idle();
            if idle.len() < self.pool.inner.max_idle.get() {
                idle.push(buffer);
            }
        }
        self.pool.inner.active.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Shared cancellation signal for a running [`DuplexPump`].
#[derive(Debug, Clone)]
pub struct PumpCancellation {
    sender: watch::Sender<bool>,
}

impl Default for PumpCancellation {
    fn default() -> Self {
        Self::new()
    }
}

impl PumpCancellation {
    /// Creates a signal in the running state.
    #[must_use]
    pub fn new() -> Self {
        let (sender, _) = watch::channel(false);
        Self { sender }
    }

    /// Requests termination of both pump directions.
    pub fn cancel(&self) {
        self.sender.send_replace(true);
    }

    /// Returns whether cancellation has been requested.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        *self.sender.borrow()
    }

    fn subscribe(&self) -> watch::Receiver<bool> {
        self.sender.subscribe()
    }
}

/// Reason one forwarding direction stopped without an I/O failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectionTermination {
    /// The source produced EOF after all staged bytes were flushed.
    EndOfStream,
    /// The owner requested cancellation.
    ExternalCancellation,
    /// The opposite direction ended or failed first.
    PeerTerminated,
}

/// Bounded accounting from one completed forwarding direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirectionReport {
    /// Direction represented by this report.
    pub direction: PumpDirection,
    /// Normal reason the direction stopped.
    pub termination: DirectionTermination,
    /// Source bytes accepted into the bounded staging path.
    pub bytes_read: u64,
    /// Bytes confirmed written to the destination.
    pub bytes_written: u64,
    /// Successful non-EOF source reads.
    pub read_calls: u64,
    /// Successful destination writes.
    pub write_calls: u64,
    /// Successful destination flushes.
    pub flushes: u64,
    /// Largest number of staged bytes observed.
    pub maximum_buffered_bytes: usize,
    /// Staged bytes discarded because cancellation or the peer direction won.
    pub discarded_buffered_bytes: usize,
}

impl DirectionReport {
    const fn new(direction: PumpDirection) -> Self {
        Self {
            direction,
            termination: DirectionTermination::PeerTerminated,
            bytes_read: 0,
            bytes_written: 0,
            read_calls: 0,
            write_calls: 0,
            flushes: 0,
            maximum_buffered_bytes: 0,
            discarded_buffered_bytes: 0,
        }
    }

    fn add(&mut self, field: &'static str, value: usize) -> Result<(), PumpError> {
        let value = u64::try_from(value).map_err(|_| PumpError::CounterOverflow {
            direction: self.direction,
            field,
        })?;
        let counter = match field {
            "bytes read" => &mut self.bytes_read,
            "bytes written" => &mut self.bytes_written,
            _ => {
                return Err(PumpError::CounterOverflow {
                    direction: self.direction,
                    field,
                });
            }
        };
        *counter = counter
            .checked_add(value)
            .ok_or(PumpError::CounterOverflow {
                direction: self.direction,
                field,
            })?;
        Ok(())
    }

    fn increment(&mut self, field: &'static str) -> Result<(), PumpError> {
        let counter = match field {
            "read calls" => &mut self.read_calls,
            "write calls" => &mut self.write_calls,
            "flushes" => &mut self.flushes,
            _ => {
                return Err(PumpError::CounterOverflow {
                    direction: self.direction,
                    field,
                });
            }
        };
        *counter = counter.checked_add(1).ok_or(PumpError::CounterOverflow {
            direction: self.direction,
            field,
        })?;
        Ok(())
    }
}

/// Accounting from both directions of a completed pump.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DuplexPumpReport {
    /// Frontend-to-backend direction.
    pub client_to_backend: DirectionReport,
    /// Backend-to-frontend direction.
    pub backend_to_client: DirectionReport,
}

/// Bounded, deadline-aware owner of two joined transport directions.
///
/// The pump spawns no tasks. Both direction futures are held by one `join!`, so
/// the owner cannot return while a peer direction remains detached. The first
/// EOF, error, reset, or cancellation signals the other direction; each then
/// half-closes its destination under `shutdown_timeout`.
#[derive(Debug, Clone)]
pub struct DuplexPump {
    config: DuplexPumpConfig,
    buffers: BufferPool,
}

impl DuplexPump {
    /// Creates a pump with a private bounded idle-buffer pool.
    ///
    /// # Errors
    ///
    /// Returns a typed error for an impossible high-water/deadline policy.
    pub fn new(config: DuplexPumpConfig) -> Result<Self, PumpConfigError> {
        let config = config.validate()?;
        let max_idle = NonZeroUsize::new(DEFAULT_IDLE_BUFFERS).unwrap_or(NonZeroUsize::MIN);
        Ok(Self {
            buffers: BufferPool::new(config.read_buffer_size, max_idle),
            config,
        })
    }

    /// Creates a pump that reuses a caller-owned pool across sessions.
    ///
    /// # Errors
    ///
    /// Returns a typed error for an invalid policy or undersized pool.
    pub fn with_pool(
        config: DuplexPumpConfig,
        buffers: BufferPool,
    ) -> Result<Self, PumpConfigError> {
        let config = config.validate()?;
        if buffers.buffer_size() < config.read_buffer_size.get() {
            return Err(PumpConfigError::PoolBufferTooSmall {
                pool_buffer_size: buffers.buffer_size(),
                read_buffer_size: config.read_buffer_size.get(),
            });
        }
        Ok(Self { config, buffers })
    }

    /// Returns this pump's immutable policy.
    #[must_use]
    pub const fn config(&self) -> DuplexPumpConfig {
        self.config
    }

    /// Returns the reusable read-buffer pool.
    #[must_use]
    pub const fn buffer_pool(&self) -> &BufferPool {
        &self.buffers
    }

    /// Runs both directions until EOF, reset/error, or cancellation.
    ///
    /// No payload leaves these local transports. A slow destination stops new
    /// source reads once its per-direction high-water mark is reached. Dropping
    /// this future is a hard connection abort; graceful owner cancellation must
    /// use `cancellation` so both write halves are shut down and joined.
    ///
    /// # Errors
    ///
    /// Returns a direction-attributed I/O, timeout, or accounting error after
    /// the peer direction has also observed termination and half-closed.
    pub async fn run<Client, Backend>(
        &self,
        client: Client,
        backend: Backend,
        cancellation: &PumpCancellation,
    ) -> Result<DuplexPumpReport, PumpError>
    where
        Client: AsyncRead + AsyncWrite + Unpin,
        Backend: AsyncRead + AsyncWrite + Unpin,
    {
        let (client_read, client_write) = tokio::io::split(client);
        let (backend_read, backend_write) = tokio::io::split(backend);
        let (peer_stop, _) = watch::channel(false);

        let client_to_backend = pump_direction(
            PumpDirection::ClientToBackend,
            client_read,
            backend_write,
            self.config,
            &self.buffers,
            DirectionControl {
                external_stop: cancellation.subscribe(),
                peer_stop: peer_stop.subscribe(),
                stop_sender: peer_stop.clone(),
            },
        );
        let backend_to_client = pump_direction(
            PumpDirection::BackendToClient,
            backend_read,
            client_write,
            self.config,
            &self.buffers,
            DirectionControl {
                external_stop: cancellation.subscribe(),
                peer_stop: peer_stop.subscribe(),
                stop_sender: peer_stop,
            },
        );

        let (client_to_backend, backend_to_client) =
            tokio::join!(client_to_backend, backend_to_client);
        match (client_to_backend, backend_to_client) {
            (Ok(client_to_backend), Ok(backend_to_client)) => Ok(DuplexPumpReport {
                client_to_backend,
                backend_to_client,
            }),
            (Err(error), _) | (_, Err(error)) => Err(error),
        }
    }
}

#[derive(Debug)]
struct DirectionControl {
    external_stop: watch::Receiver<bool>,
    peer_stop: watch::Receiver<bool>,
    stop_sender: watch::Sender<bool>,
}

async fn pump_direction<R, W>(
    direction: PumpDirection,
    mut source: R,
    mut destination: W,
    config: DuplexPumpConfig,
    buffers: &BufferPool,
    mut control: DirectionControl,
) -> Result<DirectionReport, PumpError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let result = pump_direction_inner(
        direction,
        &mut source,
        &mut destination,
        config,
        buffers,
        &mut control,
    )
    .await;

    // Wake the peer before awaiting shutdown so both deadlines run in parallel.
    control.stop_sender.send_replace(true);
    let shutdown = timeout(config.shutdown_timeout, destination.shutdown()).await;
    let shutdown = match shutdown {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(PumpError::io(direction, PumpOperation::Shutdown, error)),
        Err(_) => Err(PumpError::timed_out(
            direction,
            PumpOperation::Shutdown,
            config.shutdown_timeout,
        )),
    };

    match (result, shutdown) {
        (Err(error), _) | (Ok(_), Err(error)) => Err(error),
        (Ok(report), Ok(())) => Ok(report),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReadEvent {
    ExternalCancellation,
    PeerTerminated,
    FlushDue,
    ReadTimeout,
    Read(usize),
}

#[derive(Debug)]
struct DirectionState {
    report: DirectionReport,
    staged: Vec<u8>,
    staged_len: usize,
    flush_deadline: Option<Instant>,
    read_deadline: Option<Instant>,
}

impl DirectionState {
    fn new(direction: PumpDirection, config: DuplexPumpConfig) -> Self {
        Self {
            report: DirectionReport::new(direction),
            staged: vec![0_u8; config.write_high_water.get()],
            staged_len: 0,
            flush_deadline: None,
            read_deadline: config
                .read_timeout
                .map(|duration| Instant::now() + duration),
        }
    }

    fn stop(mut self, termination: DirectionTermination, discard: bool) -> DirectionReport {
        self.report.termination = termination;
        if discard {
            self.report.discarded_buffered_bytes =
                self.report.discarded_buffered_bytes.max(self.staged_len);
        }
        self.report
    }

    async fn flush<W>(
        &mut self,
        destination: &mut W,
        config: DuplexPumpConfig,
        control: &mut DirectionControl,
    ) -> Result<(), PumpError>
    where
        W: AsyncWrite + Unpin,
    {
        flush_staged(
            self.report.direction,
            destination,
            &self.staged[..self.staged_len],
            config.write_timeout,
            &mut control.external_stop,
            &mut control.peer_stop,
            &mut self.report,
        )
        .await?;
        self.staged_len = 0;
        self.flush_deadline = None;
        Ok(())
    }
}

async fn next_read_event<R>(
    direction: PumpDirection,
    source: &mut R,
    read_slice: &mut [u8],
    flush_deadline: Option<Instant>,
    read_deadline: Option<Instant>,
    control: &mut DirectionControl,
) -> Result<ReadEvent, PumpError>
where
    R: AsyncRead + Unpin,
{
    tokio::select! {
        biased;
        changed = control.external_stop.changed() => {
            let _ = changed;
            Ok(ReadEvent::ExternalCancellation)
        }
        changed = control.peer_stop.changed() => {
            let _ = changed;
            Ok(ReadEvent::PeerTerminated)
        }
        () = wait_until(flush_deadline) => Ok(ReadEvent::FlushDue),
        () = wait_until(read_deadline) => Ok(ReadEvent::ReadTimeout),
        result = source.read(read_slice) => {
            result
                .map(ReadEvent::Read)
                .map_err(|error| PumpError::io(direction, PumpOperation::Read, error))
        }
    }
}

async fn pump_direction_inner<R, W>(
    direction: PumpDirection,
    source: &mut R,
    destination: &mut W,
    config: DuplexPumpConfig,
    buffers: &BufferPool,
    control: &mut DirectionControl,
) -> Result<DirectionReport, PumpError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut state = DirectionState::new(direction, config);
    let mut read_buffer = buffers.acquire();

    loop {
        if *control.external_stop.borrow() {
            return Ok(state.stop(DirectionTermination::ExternalCancellation, true));
        }
        if *control.peer_stop.borrow() {
            return Ok(state.stop(DirectionTermination::PeerTerminated, true));
        }

        let read_slice = &mut read_buffer.as_mut_slice()[..config.read_buffer_size.get()];
        let event = next_read_event(
            direction,
            source,
            read_slice,
            state.flush_deadline,
            state.read_deadline,
            control,
        )
        .await?;

        match event {
            ReadEvent::ExternalCancellation => {
                return Ok(state.stop(DirectionTermination::ExternalCancellation, true));
            }
            ReadEvent::PeerTerminated => {
                return Ok(state.stop(DirectionTermination::PeerTerminated, true));
            }
            ReadEvent::ReadTimeout => {
                return Err(PumpError::timed_out(
                    direction,
                    PumpOperation::Read,
                    config.read_timeout.unwrap_or_default(),
                ));
            }
            ReadEvent::FlushDue => {
                state.flush(destination, config, control).await?;
            }
            ReadEvent::Read(0) => {
                if state.staged_len > 0 {
                    state.flush(destination, config, control).await?;
                }
                return Ok(state.stop(DirectionTermination::EndOfStream, false));
            }
            ReadEvent::Read(bytes) => {
                state.report.add("bytes read", bytes)?;
                state.report.increment("read calls")?;
                state.read_deadline = config
                    .read_timeout
                    .map(|duration| Instant::now() + duration);

                if state.staged_len > 0 && state.staged_len + bytes > state.staged.len() {
                    state.flush(destination, config, control).await?;
                }

                if state.staged_len == 0 {
                    state.flush_deadline = Some(Instant::now() + config.max_flush_delay);
                }
                let end = state.staged_len + bytes;
                state.staged[state.staged_len..end].copy_from_slice(&read_slice[..bytes]);
                state.staged_len = end;
                state.report.maximum_buffered_bytes =
                    state.report.maximum_buffered_bytes.max(state.staged_len);

                if state.staged_len == state.staged.len() {
                    state.flush(destination, config, control).await?;
                }
            }
        }
    }
}

async fn wait_until(deadline: Option<Instant>) {
    if let Some(deadline) = deadline {
        sleep_until(deadline).await;
    } else {
        pending::<()>().await;
    }
}

async fn flush_staged<W>(
    direction: PumpDirection,
    destination: &mut W,
    staged: &[u8],
    write_timeout: Duration,
    external_stop: &mut watch::Receiver<bool>,
    peer_stop: &mut watch::Receiver<bool>,
    report: &mut DirectionReport,
) -> Result<(), PumpError>
where
    W: AsyncWrite + Unpin,
{
    let write_deadline = Instant::now() + write_timeout;
    let mut position = 0_usize;
    while position < staged.len() {
        let written = tokio::select! {
            biased;
            changed = external_stop.changed() => {
                let _ = changed;
                report.termination = DirectionTermination::ExternalCancellation;
                report.discarded_buffered_bytes = staged.len() - position;
                return Ok(());
            }
            changed = peer_stop.changed() => {
                let _ = changed;
                report.termination = DirectionTermination::PeerTerminated;
                report.discarded_buffered_bytes = staged.len() - position;
                return Ok(());
            }
            () = sleep_until(write_deadline) => {
                return Err(PumpError::timed_out(direction, PumpOperation::Write, write_timeout));
            }
            result = destination.write(&staged[position..]) => {
                result.map_err(|error| PumpError::io(direction, PumpOperation::Write, error))?
            }
        };
        if written == 0 {
            return Err(PumpError::io(
                direction,
                PumpOperation::Write,
                io::Error::new(io::ErrorKind::WriteZero, "failed to write staged bytes"),
            ));
        }
        position += written;
        report.add("bytes written", written)?;
        report.increment("write calls")?;
    }

    let flush_deadline = Instant::now() + write_timeout;
    tokio::select! {
        biased;
        changed = external_stop.changed() => {
            let _ = changed;
            report.termination = DirectionTermination::ExternalCancellation;
            Ok(())
        }
        changed = peer_stop.changed() => {
            let _ = changed;
            report.termination = DirectionTermination::PeerTerminated;
            Ok(())
        }
        () = sleep_until(flush_deadline) => {
            Err(PumpError::timed_out(direction, PumpOperation::Flush, write_timeout))
        }
        result = destination.flush() => {
            result.map_err(|error| PumpError::io(direction, PumpOperation::Flush, error))?;
            report.increment("flushes")?;
            Ok(())
        }
    }
}
