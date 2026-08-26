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

//! Bounded, reconnecting Unix-domain transport owned by the Rust dataplane.
//!
//! The transport carries protobuf control metadata only. It never accepts a
//! `MySQL` packet, authentication response, query, certificate, or private key.

use std::fmt;
use std::io;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex as StdMutex, MutexGuard as StdMutexGuard};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use prost::Message;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::{Mutex, Notify, watch};
use tokio::time::{sleep, timeout};

use crate::v1::control_envelope::Body;
use crate::v1::{ControlEnvelope, ErrorCode, Heartbeat, Hello, HelloAck, Priority, Role};
use crate::{
    CONTROL_PROTOCOL_V1, DEFAULT_MAX_FRAME_BYTES, FrameError, decode_frame, encode_frame,
    negotiate_hello,
};

const FRAME_PREFIX_BYTES: usize = 4;
// Reserve the length prefix plus fields populated by the active session
// (epoch and timestamp) so queue and frame accounting never undercount.
const QUEUE_ENTRY_OVERHEAD: usize = 32;
/// ADR v1 hard cap on the reconnect backoff window: [`ControlClient::new`]
/// rejects any configured `reconnect_cap` above this value.
pub const MAX_RECONNECT_BACKOFF: Duration = Duration::from_secs(5);

/// One priority lane's count and byte bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueueLimit {
    /// Maximum queued records.
    pub messages: usize,
    /// Maximum encoded bytes, including the four-byte frame prefix.
    pub bytes: usize,
}

/// Bounds for all three v1 outbound lanes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueueLimits {
    /// Heartbeat, error, assignment-result, redirect, drain, and close traffic.
    pub critical: QueueLimit,
    /// Snapshot, routing, and handshake traffic.
    pub control: QueueLimit,
    /// Metrics and metering traffic.
    pub bulk: QueueLimit,
}

/// ADR v1 hard per-lane outbound-queue maxima.
///
/// This constant is the enforcement-side single source: [`ControlClient::new`]
/// rejects any configured lane whose message or byte bound exceeds it. The
/// cross-crate limits registry in `mysql-wire` mirrors these values, and the
/// `proxy-io` conformance suite pins the two sides exactly equal and proves
/// the accept/reject boundary against the real constructor.
pub const HARD_QUEUE_MAXIMA: QueueLimits = QueueLimits {
    critical: QueueLimit {
        messages: 4_096,
        bytes: 32 * 1_024 * 1_024,
    },
    control: QueueLimit {
        messages: 16_384,
        bytes: 128 * 1_024 * 1_024,
    },
    bulk: QueueLimit {
        messages: 1_024,
        bytes: 64 * 1_024 * 1_024,
    },
};

impl Default for QueueLimits {
    fn default() -> Self {
        Self {
            critical: QueueLimit {
                messages: 1_024,
                bytes: 8 * 1_024 * 1_024,
            },
            control: QueueLimit {
                messages: 4_096,
                bytes: 32 * 1_024 * 1_024,
            },
            bulk: QueueLimit {
                messages: 256,
                bytes: 16 * 1_024 * 1_024,
            },
        }
    }
}

/// Rust control-transport configuration.
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// Absolute path of the Go-owned Unix-domain socket.
    pub socket_path: PathBuf,
    /// Required owner UID of the socket inode.
    pub allowed_socket_uid: u32,
    /// Rust dataplane Hello. The transport normalizes its frame limit.
    pub local_hello: Hello,
    /// Capabilities that the Go peer must advertise.
    pub required_capabilities: Vec<u64>,
    /// Local hard frame limit, at most one MiB.
    pub max_frame_bytes: u32,
    /// Per-lane count and byte limits.
    pub queue_limits: QueueLimits,
    /// Deadline for connect and the complete Hello exchange.
    pub handshake_timeout: Duration,
    /// Idle interval before emitting a heartbeat.
    pub heartbeat_interval: Duration,
    /// Deadline for one peer frame and for queueing a heartbeat.
    pub peer_timeout: Duration,
    /// Deadline for one complete framed write.
    pub write_timeout: Duration,
    /// Initial full-jitter reconnect window.
    pub reconnect_base: Duration,
    /// Maximum full-jitter reconnect window, never above five seconds.
    pub reconnect_cap: Duration,
    /// Deterministic seed for reconnect jitter; zero derives a process-local seed.
    pub reconnect_jitter_seed: u64,
}

impl ClientConfig {
    /// Returns production v1 timing and queue defaults for one socket and Hello.
    #[must_use]
    pub fn with_defaults(
        socket_path: PathBuf,
        allowed_socket_uid: u32,
        local_hello: Hello,
    ) -> Self {
        Self {
            socket_path,
            allowed_socket_uid,
            local_hello,
            required_capabilities: Vec::new(),
            max_frame_bytes: DEFAULT_MAX_FRAME_BYTES,
            queue_limits: QueueLimits::default(),
            handshake_timeout: Duration::from_secs(5),
            heartbeat_interval: Duration::from_secs(1),
            peer_timeout: Duration::from_secs(3),
            write_timeout: Duration::from_secs(5),
            reconnect_base: Duration::from_millis(50),
            reconnect_cap: MAX_RECONNECT_BACKOFF,
            reconnect_jitter_seed: 0,
        }
    }
}

/// Observable connection state from the single mutable transport owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// No negotiated Go owner is available.
    Disconnected,
    /// A connection attempt or Hello exchange is in progress.
    Connecting,
    /// The Go owner assigned this nonzero control epoch with the
    /// bit-masked negotiated capabilities (bit per capability id below
    /// 64) — one atomic snapshot, so consumers never pair an epoch with
    /// another session's capabilities.
    Connected {
        /// The negotiated control epoch.
        epoch: u64,
        /// Bitmask of negotiated capability ids.
        capabilities: u64,
    },
    /// The transport was explicitly shut down.
    Shutdown,
}

/// Control transport, queue, protocol, or cancellation failure.
#[derive(Debug)]
pub enum TransportError {
    /// Invalid local configuration or unsafe socket metadata.
    Configuration(String),
    /// Unix socket or framed I/O failed.
    Io(io::Error),
    /// Protobuf framing or Hello negotiation failed.
    Frame(FrameError),
    /// A negotiated peer violated the control protocol.
    Protocol(String),
    /// A cancellation-aware operation exceeded its deadline.
    Timeout(&'static str),
    /// A session-scoped envelope was bound to an epoch that is no
    /// longer negotiated; the owner regenerates the work on the next
    /// `Connected` transition.
    StaleSessionEpoch,
    /// A non-droppable message cannot ever fit its configured lane.
    QueueFull,
    /// A metrics batch was deliberately shed under bulk-lane pressure.
    MetricsDropped,
    /// The owner was shut down and no longer accepts work.
    Closed,
}

impl fmt::Display for TransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Configuration(detail) => write!(formatter, "invalid control transport: {detail}"),
            Self::Io(error) => write!(formatter, "control transport I/O: {error}"),
            Self::Frame(error) => write!(formatter, "control transport frame: {error}"),
            Self::Protocol(detail) => write!(formatter, "control protocol violation: {detail}"),
            Self::Timeout(operation) => {
                write!(formatter, "control transport timed out during {operation}")
            }
            Self::QueueFull => formatter.write_str("control transport queue is full"),
            Self::MetricsDropped => formatter.write_str("control metrics dropped under pressure"),
            Self::Closed => formatter.write_str("control transport is closed"),
            Self::StaleSessionEpoch => {
                formatter.write_str("session-scoped envelope outlived its negotiated epoch")
            }
        }
    }
}

impl std::error::Error for TransportError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Frame(error) => Some(error),
            Self::Configuration(_)
            | Self::Protocol(_)
            | Self::Timeout(_)
            | Self::QueueFull
            | Self::StaleSessionEpoch
            | Self::MetricsDropped
            | Self::Closed => None,
        }
    }
}

impl From<io::Error> for TransportError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<FrameError> for TransportError {
    fn from(error: FrameError) -> Self {
        Self::Frame(error)
    }
}

/// Synchronous, bounded callback for one validated inbound control message.
///
/// Handlers must not block. Expensive work should enter a separately owned,
/// bounded executor so the peer read deadline remains meaningful.
pub trait Handler: Send + Sync {
    /// Handles one post-Hello envelope. The read loop **awaits** this
    /// call: a slow consumer applies real backpressure through TCP to
    /// the Go sender's bounded lanes instead of accumulating an
    /// unbounded queue or dropping a command the peer already
    /// considers delivered.
    ///
    /// # Errors
    ///
    /// Returning an error closes the current stream and triggers reconnect.
    fn handle(
        &self,
        envelope: ControlEnvelope,
    ) -> impl Future<Output = Result<(), TransportError>> + Send;

    /// Runs once per session, after the write path is live but
    /// **before the first frame is read**: a handler that retained an
    /// in-flight envelope from a previous session pumps it into its
    /// downstream here, so at most one such frame can exist globally
    /// (the next reader starts only after the slot is empty). The
    /// default is a no-op for handlers without retention.
    ///
    /// # Cancellation
    ///
    /// The transport selects this future against session teardown and
    /// shutdown: it may be **dropped at any await point** (for example
    /// when the writer fails while this pump is backpressured).
    /// Implementations must keep any retained state intact under
    /// cancellation — the next session's call resumes the pump.
    /// The transport serializes sessions, so at most one
    /// `resume_session` runs at any time.
    ///
    /// # Errors
    ///
    /// Returning an error ends the session before any frame is read.
    fn resume_session(
        &self,
        epoch: u64,
    ) -> impl Future<Output = Result<(), TransportError>> + Send {
        async move {
            let _ = epoch;
            Ok(())
        }
    }
}

impl<F> Handler for F
where
    F: Fn(ControlEnvelope) -> Result<(), TransportError> + Send + Sync,
{
    async fn handle(&self, envelope: ControlEnvelope) -> Result<(), TransportError> {
        self(envelope)
    }
}

/// The one Rust owner of connection, reconnect, queues, and shutdown state.
pub struct ControlClient {
    config: ClientConfig,
    queues: OutboundQueues,
    shutdown_tx: watch::Sender<bool>,
    state_tx: watch::Sender<ConnectionState>,
    epoch: AtomicU64,
    negotiated_frame_limit: AtomicU64,
    /// Bitmask of negotiated control capabilities (bit per capability id
    /// below 64), set on connect and cleared on disconnect.
    negotiated_caps: AtomicU64,
    next_request_id: AtomicU64,
    metrics_dropped: AtomicU64,
    /// Session-scoped envelopes discarded because their bound epoch was
    /// no longer negotiated at write (or enqueue) time; the owner
    /// regenerates that work on the next `Connected` transition.
    session_scoped_dropped: AtomicU64,
    reconnect_attempts: AtomicU64,
    running: AtomicBool,
    last_received: StdMutex<Option<Instant>>,
    last_good_snapshot: StdMutex<Option<(u64, Instant)>>,
    last_disconnect: StdMutex<Option<String>>,
}

impl ControlClient {
    /// Validates configuration and constructs a stopped owner.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::Configuration`] for invalid role, version,
    /// paths, timing, frame, or queue bounds.
    pub fn new(mut config: ClientConfig) -> Result<Self, TransportError> {
        normalize_config(&mut config)?;
        let initial_frame_limit = config.max_frame_bytes;
        let (shutdown_tx, _) = watch::channel(false);
        let (state_tx, _) = watch::channel(ConnectionState::Disconnected);
        Ok(Self {
            queues: OutboundQueues::new(config.queue_limits),
            config,
            shutdown_tx,
            state_tx,
            epoch: AtomicU64::new(0),
            negotiated_frame_limit: AtomicU64::new(u64::from(initial_frame_limit)),
            negotiated_caps: AtomicU64::new(0),
            next_request_id: AtomicU64::new(0),
            metrics_dropped: AtomicU64::new(0),
            session_scoped_dropped: AtomicU64::new(0),
            reconnect_attempts: AtomicU64::new(0),
            running: AtomicBool::new(false),
            last_received: StdMutex::new(None),
            last_good_snapshot: StdMutex::new(None),
            last_disconnect: StdMutex::new(None),
        })
    }

    /// Runs connect, Hello, the active session, and capped full-jitter reconnect.
    ///
    /// This future owns all socket I/O. Dropping it drops every reader, writer,
    /// heartbeat, and reconnect wait because no detached tasks are created.
    ///
    /// # Errors
    ///
    /// The loop returns only when local shutdown state cannot be observed.
    pub async fn run<H: Handler>(&self, handler: &H) -> Result<(), TransportError> {
        if self
            .running
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(TransportError::Configuration(
                "control transport already has a running owner".to_owned(),
            ));
        }
        let _running = RunningGuard(&self.running);
        let mut shutdown = self.shutdown_tx.subscribe();
        let mut backoff = self.config.reconnect_base;
        let mut jitter = FullJitter::new(self.config.reconnect_jitter_seed);
        loop {
            if *shutdown.borrow() {
                let _ = self.state_tx.send(ConnectionState::Shutdown);
                return Ok(());
            }
            let _ = self.state_tx.send(ConnectionState::Connecting);
            let connection = tokio::select! {
                result = self.connect_and_handshake() => result,
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        let _ = self.state_tx.send(ConnectionState::Shutdown);
                        return Ok(());
                    }
                    Err(TransportError::Protocol("shutdown state regressed".to_owned()))
                }
            };
            match connection {
                Ok(negotiated) => {
                    backoff = self.config.reconnect_base;
                    self.epoch.store(negotiated.epoch, Ordering::Release);
                    self.negotiated_frame_limit
                        .store(u64::from(negotiated.max_frame_bytes), Ordering::Release);
                    let mut caps_mask = 0_u64;
                    for capability in &negotiated.capabilities {
                        if *capability < 64 {
                            caps_mask |= 1 << capability;
                        }
                    }
                    self.negotiated_caps.store(caps_mask, Ordering::Release);
                    set_instant(&self.last_received, Some(Instant::now()));
                    let _ = self.state_tx.send(ConnectionState::Connected {
                        epoch: negotiated.epoch,
                        capabilities: caps_mask,
                    });
                    let result = self.run_connected(negotiated, handler).await;
                    if !matches!(result, Err(TransportError::Closed)) {
                        set_string(&self.last_disconnect, Some(result_to_string(&result)));
                    }
                }
                Err(error) => {
                    set_string(&self.last_disconnect, Some(error.to_string()));
                }
            }
            self.epoch.store(0, Ordering::Release);
            self.negotiated_caps.store(0, Ordering::Release);
            self.negotiated_frame_limit
                .store(u64::from(self.config.max_frame_bytes), Ordering::Release);
            let _ = self.state_tx.send(ConnectionState::Disconnected);
            if *shutdown.borrow() {
                continue;
            }
            self.reconnect_attempts.fetch_add(1, Ordering::Relaxed);
            let reconnect_wait = jitter.duration(backoff);
            backoff = backoff.saturating_mul(2).min(self.config.reconnect_cap);
            tokio::select! {
                () = sleep(reconnect_wait) => {}
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        let _ = self.state_tx.send(ConnectionState::Shutdown);
                        return Ok(());
                    }
                }
            }
        }
    }

    /// Queues a defensive copy in its declared priority lane.
    ///
    /// Metrics alone may return [`TransportError::MetricsDropped`]. Metering,
    /// assignment, redirect, drain, and all control work instead backpressure.
    ///
    /// # Errors
    ///
    /// Returns when the lane is permanently too small, metrics are shed, or
    /// shutdown cancels the wait.
    pub async fn send(&self, envelope: ControlEnvelope) -> Result<(), TransportError> {
        self.enqueue(envelope, None).await
    }

    async fn enqueue(
        &self,
        mut envelope: ControlEnvelope,
        session_epoch: Option<u64>,
    ) -> Result<(), TransportError> {
        if *self.shutdown_tx.borrow() {
            return Err(TransportError::Closed);
        }
        envelope.protocol_version = u32::from(CONTROL_PROTOCOL_V1);
        let size = envelope.encoded_len() + QUEUE_ENTRY_OVERHEAD;
        let frame_limit = self.negotiated_frame_limit.load(Ordering::Acquire);
        let frame_limit_usize = usize::try_from(frame_limit).unwrap_or(usize::MAX);
        if size > frame_limit_usize {
            return Err(FrameError::Oversized {
                length: size,
                limit: u32::try_from(frame_limit).unwrap_or(DEFAULT_MAX_FRAME_BYTES),
            }
            .into());
        }
        let drop_metrics = matches!(envelope.body, Some(Body::MetricsBatch(_)));
        let lane = match Priority::try_from(envelope.priority).unwrap_or(Priority::Control) {
            Priority::Critical => &self.queues.critical,
            Priority::Bulk => &self.queues.bulk,
            Priority::Unspecified | Priority::Control => &self.queues.control,
        };
        let result = lane
            .push(
                QueuedEnvelope {
                    envelope,
                    size,
                    session_epoch,
                },
                drop_metrics,
                self.shutdown_tx.subscribe(),
                &self.queues.not_empty,
            )
            .await;
        if matches!(result, Err(TransportError::MetricsDropped)) {
            self.metrics_dropped.fetch_add(1, Ordering::Relaxed);
        }
        result
    }

    /// Queues a **session-scoped** envelope bound to `epoch`: it is
    /// written only while that exact epoch is negotiated and otherwise
    /// dropped (counted in
    /// [`ControlClient::session_scoped_dropped`]) — correct because the
    /// owner regenerates such work on every `Connected` transition.
    /// Durable cross-reconnect work (results, lifecycle events,
    /// metering batches) must use [`ControlClient::send`] instead.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::StaleSessionEpoch`] when `epoch` is
    /// no longer the negotiated epoch at enqueue time, plus every
    /// [`ControlClient::send`] failure mode.
    pub async fn send_session_scoped(
        &self,
        envelope: ControlEnvelope,
        epoch: u64,
    ) -> Result<(), TransportError> {
        if epoch == 0 || self.epoch.load(Ordering::Acquire) != epoch {
            return Err(TransportError::StaleSessionEpoch);
        }
        self.enqueue(envelope, Some(epoch)).await
    }

    /// Requests cancellation of connect, queue, I/O, heartbeat, and backoff waits.
    pub fn shutdown(&self) {
        self.shutdown_tx.send_replace(true);
        self.queues.notify_all();
    }

    /// Subscribes to transport-owner connection state changes.
    #[must_use]
    pub fn subscribe_state(&self) -> watch::Receiver<ConnectionState> {
        self.state_tx.subscribe()
    }

    /// Whether the current control session negotiated the capability
    /// (false when disconnected).
    #[must_use]
    pub fn has_negotiated_capability(&self, capability: u64) -> bool {
        capability < 64 && (self.negotiated_caps.load(Ordering::Acquire) >> capability) & 1 == 1
    }

    /// Allocates the next request id for an application-originated
    /// envelope on this sender. One checked allocator serves every
    /// envelope (heartbeats included), so ids never repeat or regress
    /// within a sender; `None` means the id space is exhausted (fail
    /// closed — do not wrap).
    #[must_use]
    pub fn allocate_request_id(&self) -> Option<u64> {
        // Compare-and-swap: at MAX the update closure refuses, so no
        // concurrent caller can observe a transient wrap (a plain
        // fetch_add would briefly publish 0 and hand a second caller a
        // duplicate id 1).
        self.next_request_id
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                if current == u64::MAX {
                    None
                } else {
                    Some(current + 1)
                }
            })
            .ok()
            .map(|previous| previous + 1)
    }

    /// Returns the currently negotiated epoch, or zero when disconnected.
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.epoch.load(Ordering::Acquire)
    }

    /// Returns how many reconnect waits have been scheduled.
    #[must_use]
    pub fn reconnect_attempts(&self) -> u64 {
        self.reconnect_attempts.load(Ordering::Relaxed)
    }

    /// Session-scoped envelopes dropped for an epoch that was no
    /// longer negotiated (each is regenerated by its owner on the next
    /// `Connected` transition).
    #[must_use]
    pub fn session_scoped_dropped(&self) -> u64 {
        self.session_scoped_dropped.load(Ordering::Relaxed)
    }

    /// Returns the local count of intentionally shed metrics batches.
    #[must_use]
    pub fn metrics_dropped(&self) -> u64 {
        self.metrics_dropped.load(Ordering::Relaxed)
    }

    /// Returns the age of the last complete, validated peer frame.
    #[must_use]
    pub fn last_received_age(&self) -> Option<Duration> {
        lock_std(&self.last_received).map(|received| received.elapsed())
    }

    /// Records an atomically applied last-good snapshot generation.
    ///
    /// Lower generations never move the clock or generation backwards.
    pub fn mark_last_good_snapshot(&self, generation: u64) {
        if generation == 0 {
            return;
        }
        let mut last_good = lock_std(&self.last_good_snapshot);
        if last_good.is_none_or(|(current, _)| generation >= current) {
            *last_good = Some((generation, Instant::now()));
        }
    }

    /// Returns the last-good snapshot generation and its current age.
    #[must_use]
    pub fn last_good_snapshot_age(&self) -> Option<(u64, Duration)> {
        lock_std(&self.last_good_snapshot)
            .as_ref()
            .map(|(generation, applied)| (*generation, applied.elapsed()))
    }

    /// Returns the most recent connection or session error for diagnostics.
    #[must_use]
    pub fn last_disconnect(&self) -> Option<String> {
        lock_std(&self.last_disconnect).clone()
    }

    async fn connect_and_handshake(&self) -> Result<Negotiated, TransportError> {
        verify_socket(&self.config)?;
        let stream = timeout(
            self.config.handshake_timeout,
            UnixStream::connect(&self.config.socket_path),
        )
        .await
        .map_err(|_| TransportError::Timeout("connect"))??;
        let result = timeout(self.config.handshake_timeout, self.handshake(stream))
            .await
            .map_err(|_| TransportError::Timeout("Hello exchange"))??;
        Ok(result)
    }

    async fn handshake(&self, mut stream: UnixStream) -> Result<Negotiated, TransportError> {
        let remote_envelope = read_frame_async(&mut stream, self.config.max_frame_bytes).await?;
        let Some(Body::Hello(remote_hello)) = remote_envelope.body else {
            return Err(TransportError::Protocol("expected Go Hello".to_owned()));
        };
        if remote_envelope.protocol_version != u32::from(CONTROL_PROTOCOL_V1)
            || remote_hello.role != Role::GoControl as i32
        {
            return Err(TransportError::Protocol(
                "peer Hello must advertise Go role and protocol v1".to_owned(),
            ));
        }

        let local_hello = self.config.local_hello.clone();
        write_frame_async(
            &mut stream,
            &hello_envelope(local_hello.clone()),
            self.config.max_frame_bytes,
        )
        .await?;

        let ack_envelope = read_frame_async(&mut stream, self.config.max_frame_bytes).await?;
        let Some(Body::HelloAck(remote_ack)) = ack_envelope.body else {
            return Err(TransportError::Protocol("expected Go HelloAck".to_owned()));
        };
        validate_remote_ack(&remote_ack)?;
        let expected = negotiate_hello(
            &local_hello,
            &remote_hello,
            &self.config.required_capabilities,
            remote_ack.control_epoch,
        )?;
        if remote_ack.selected_version != expected.selected_version
            || remote_ack.negotiated_capabilities != expected.negotiated_capabilities
            || remote_ack.max_frame_bytes != expected.max_frame_bytes
        {
            return Err(TransportError::Protocol(
                "Go HelloAck does not match local negotiation".to_owned(),
            ));
        }
        write_frame_async(
            &mut stream,
            &hello_ack_envelope(expected),
            remote_ack.max_frame_bytes,
        )
        .await?;
        Ok(Negotiated {
            stream,
            epoch: remote_ack.control_epoch,
            max_frame_bytes: remote_ack.max_frame_bytes,
            capabilities: remote_ack.negotiated_capabilities,
        })
    }

    async fn run_connected<H: Handler>(
        &self,
        negotiated: Negotiated,
        handler: &H,
    ) -> Result<(), TransportError> {
        let Negotiated {
            stream,
            epoch,
            max_frame_bytes,
            capabilities,
        } = negotiated;
        let (mut reader, mut writer) = stream.into_split();
        let last_sent = StdMutex::new(Instant::now());
        let mut shutdown = self.shutdown_tx.subscribe();
        let (session_stop_tx, _) = watch::channel(false);
        // Two-phase session start: the write path (below) goes live
        // immediately so a jammed dispatcher can unblock on draining
        // lanes, but reading waits for `resume_session` — the handler
        // first pumps any frame retained from the previous session, so
        // a second retained frame can never come into existence.
        let read_loop = async {
            // The pump is selected against session teardown: if the
            // writer dies while resume is backpressured, the stop
            // signal cancels it (retention stays intact per the trait
            // contract) so the join below always converges.
            let mut resume_stop = session_stop_tx.subscribe();
            tokio::select! {
                result = handler.resume_session(epoch) => result?,
                changed = resume_stop.changed() => {
                    if changed.is_err() || *resume_stop.borrow() {
                        return Err(TransportError::Closed);
                    }
                    return Err(TransportError::Protocol(
                        "session stop state regressed".to_owned(),
                    ));
                }
            }
            self.read_loop(
                &mut reader,
                epoch,
                max_frame_bytes,
                &capabilities,
                handler,
                session_stop_tx.subscribe(),
            )
            .await
        };
        let write_loop = self.write_loop(
            &mut writer,
            epoch,
            max_frame_bytes,
            &last_sent,
            session_stop_tx.subscribe(),
        );
        let heartbeat_loop = self.heartbeat_loop(&last_sent, session_stop_tx.subscribe());
        tokio::pin!(read_loop, write_loop, heartbeat_loop);
        let first = tokio::select! {
            result = &mut read_loop => CompletedLoop::Read(result),
            result = &mut write_loop => CompletedLoop::Write(result),
            result = &mut heartbeat_loop => CompletedLoop::Heartbeat(result),
            changed = shutdown.changed() => {
                let result = if changed.is_err() || *shutdown.borrow() {
                    Err(TransportError::Closed)
                } else {
                    Err(TransportError::Protocol("shutdown state regressed".to_owned()))
                };
                CompletedLoop::Shutdown(result)
            }
        };
        session_stop_tx.send_replace(true);
        // Publish the teardown BEFORE joining the loops: the inbound
        // forwarder unblocks on this transition (retaining its one
        // in-flight frame), so the read loop's `handler.await` cannot
        // hold the join hostage while the dispatcher waits on outbound
        // lanes only a future session can drain.
        self.epoch.store(0, Ordering::Release);
        self.negotiated_caps.store(0, Ordering::Release);
        let _ = self.state_tx.send(ConnectionState::Disconnected);
        match first {
            CompletedLoop::Read(result) => {
                let _ = tokio::join!(&mut write_loop, &mut heartbeat_loop);
                result
            }
            CompletedLoop::Write(result) => {
                let _ = tokio::join!(&mut read_loop, &mut heartbeat_loop);
                result
            }
            CompletedLoop::Heartbeat(result) => {
                let _ = tokio::join!(&mut read_loop, &mut write_loop);
                result
            }
            CompletedLoop::Shutdown(result) => {
                let _ = tokio::join!(&mut read_loop, &mut write_loop, &mut heartbeat_loop);
                result
            }
        }
    }

    async fn read_loop<R: AsyncRead + Unpin, H: Handler>(
        &self,
        reader: &mut R,
        epoch: u64,
        max_frame_bytes: u32,
        capabilities: &[u64],
        handler: &H,
        mut session_stop: watch::Receiver<bool>,
    ) -> Result<(), TransportError> {
        loop {
            let envelope = tokio::select! {
                result = timeout(
                    self.config.peer_timeout,
                    read_frame_async(reader, max_frame_bytes),
                ) => result.map_err(|_| TransportError::Timeout("peer frame"))??,
                changed = session_stop.changed() => {
                    if changed.is_err() || *session_stop.borrow() {
                        return Err(TransportError::Closed);
                    }
                    continue;
                }
            };
            validate_session_envelope(&envelope, epoch, capabilities)?;
            set_instant(&self.last_received, Some(Instant::now()));
            handler.handle(envelope).await?;
        }
    }

    async fn write_loop<W: AsyncWrite + Unpin>(
        &self,
        writer: &mut W,
        epoch: u64,
        max_frame_bytes: u32,
        last_sent: &StdMutex<Instant>,
        mut session_stop: watch::Receiver<bool>,
    ) -> Result<(), TransportError> {
        loop {
            let (mut envelope, session_epoch) = tokio::select! {
                result = self.queues.next(self.shutdown_tx.subscribe()) => result?,
                changed = session_stop.changed() => {
                    if changed.is_err() || *session_stop.borrow() {
                        return Err(TransportError::Closed);
                    }
                    continue;
                }
            };
            if let Some(bound) = session_epoch
                && bound != epoch
            {
                // Session-scoped work bound to a dead epoch: consume it
                // (freeing lane space for durable work) and count — the
                // owner regenerated it on this session's `Connected`
                // transition.
                self.queues.commit(&envelope).await?;
                self.session_scoped_dropped.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            envelope.protocol_version = u32::from(CONTROL_PROTOCOL_V1);
            envelope.control_epoch = epoch;
            envelope.sent_unix_millis = unix_millis();
            let write_result = tokio::select! {
                result = timeout(
                    self.config.write_timeout,
                    write_frame_async(writer, &envelope, max_frame_bytes),
                ) => result
                    .map_err(|_| TransportError::Timeout("frame write"))
                    .and_then(std::convert::identity),
                changed = session_stop.changed() => {
                    if changed.is_err() || *session_stop.borrow() {
                        Err(TransportError::Closed)
                    } else {
                        Err(TransportError::Protocol("session stop state regressed".to_owned()))
                    }
                }
            };
            if let Err(error) = write_result {
                self.queues.rollback(&envelope).await?;
                return Err(error);
            }
            self.queues.commit(&envelope).await?;
            set_instant_value(last_sent, Instant::now());
        }
    }

    async fn heartbeat_loop(
        &self,
        last_sent: &StdMutex<Instant>,
        mut session_stop: watch::Receiver<bool>,
    ) -> Result<(), TransportError> {
        loop {
            tokio::select! {
                () = sleep(self.config.heartbeat_interval) => {}
                changed = session_stop.changed() => {
                    if changed.is_err() || *session_stop.borrow() {
                        return Err(TransportError::Closed);
                    }
                    continue;
                }
            }
            if *self.shutdown_tx.borrow() {
                return Err(TransportError::Closed);
            }
            if lock_std(last_sent).elapsed() < self.config.heartbeat_interval {
                continue;
            }
            let Some(heartbeat_id) = self.allocate_request_id() else {
                return Err(TransportError::Protocol(
                    "sender request-id space exhausted".to_owned(),
                ));
            };
            let heartbeat = ControlEnvelope {
                request_id: heartbeat_id,
                priority: Priority::Critical as i32,
                body: Some(Body::Heartbeat(Heartbeat {
                    monotonic_millis: 0,
                    applied_generation: self
                        .last_good_snapshot_age()
                        .map_or(0, |(generation, _)| generation),
                    active_connections: 0,
                    last_received_request_id: 0,
                })),
                ..Default::default()
            };
            let session_epoch = self.epoch.load(Ordering::Acquire);
            tokio::select! {
                result = timeout(
                    self.config.peer_timeout,
                    self.send_session_scoped(heartbeat, session_epoch),
                ) => {
                    match result.map_err(|_| TransportError::Timeout("heartbeat queue"))? {
                        // The session ended between the interval firing
                        // and the enqueue: the next session heartbeats
                        // for itself.
                        Err(TransportError::StaleSessionEpoch) | Ok(()) => {}
                        Err(error) => return Err(error),
                    }
                }
                changed = session_stop.changed() => {
                    if changed.is_err() || *session_stop.borrow() {
                        return Err(TransportError::Closed);
                    }
                }
            }
        }
    }
}

struct Negotiated {
    stream: UnixStream,
    epoch: u64,
    max_frame_bytes: u32,
    capabilities: Vec<u64>,
}

enum CompletedLoop {
    Read(Result<(), TransportError>),
    Write(Result<(), TransportError>),
    Heartbeat(Result<(), TransportError>),
    Shutdown(Result<(), TransportError>),
}

struct RunningGuard<'a>(&'a AtomicBool);

impl Drop for RunningGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

#[derive(Clone)]
struct QueuedEnvelope {
    envelope: ControlEnvelope,
    size: usize,
    /// `Some(epoch)` marks a session-scoped envelope: it may only be
    /// written under exactly this negotiated epoch and is dropped
    /// (counted) otherwise — the owner regenerates it on the next
    /// `Connected` transition. `None` marks durable-across-reconnect
    /// work (results, lifecycle events, metering batches) that must
    /// never be dropped; the peer dedups it by request id / sequence.
    session_epoch: Option<u64>,
}

struct LaneState {
    items: std::collections::VecDeque<QueuedEnvelope>,
    in_flight: Option<QueuedEnvelope>,
    bytes: usize,
}

struct LaneQueue {
    state: Mutex<LaneState>,
    limit: QueueLimit,
    space: Notify,
}

impl LaneQueue {
    fn new(limit: QueueLimit) -> Self {
        Self {
            state: Mutex::new(LaneState {
                items: std::collections::VecDeque::with_capacity(limit.messages),
                in_flight: None,
                bytes: 0,
            }),
            limit,
            space: Notify::new(),
        }
    }

    async fn push(
        &self,
        item: QueuedEnvelope,
        drop_when_full: bool,
        mut shutdown: watch::Receiver<bool>,
        not_empty: &Notify,
    ) -> Result<(), TransportError> {
        if item.size > self.limit.bytes {
            return if drop_when_full {
                Err(TransportError::MetricsDropped)
            } else {
                Err(TransportError::QueueFull)
            };
        }
        loop {
            if *shutdown.borrow() {
                return Err(TransportError::Closed);
            }
            let wait_for_space = self.space.notified();
            {
                let mut state = self.state.lock().await;
                let occupied = state.items.len() + usize::from(state.in_flight.is_some());
                if occupied < self.limit.messages && state.bytes + item.size <= self.limit.bytes {
                    state.bytes += item.size;
                    state.items.push_back(item);
                    not_empty.notify_one();
                    return Ok(());
                }
            }
            if drop_when_full {
                return Err(TransportError::MetricsDropped);
            }
            tokio::select! {
                () = wait_for_space => {}
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        return Err(TransportError::Closed);
                    }
                }
            }
        }
    }

    async fn pop(&self) -> Option<(ControlEnvelope, Option<u64>)> {
        let mut state = self.state.lock().await;
        if state.in_flight.is_some() {
            return None;
        }
        let item = state.items.pop_front()?;
        let envelope = item.envelope.clone();
        let session_epoch = item.session_epoch;
        state.in_flight = Some(item);
        Some((envelope, session_epoch))
    }

    async fn commit(&self) -> Result<(), TransportError> {
        let mut state = self.state.lock().await;
        let Some(item) = state.in_flight.take() else {
            return Err(TransportError::Protocol(
                "queue commit has no in-flight record".to_owned(),
            ));
        };
        state.bytes -= item.size;
        self.space.notify_waiters();
        Ok(())
    }

    async fn rollback(&self, not_empty: &Notify) -> Result<(), TransportError> {
        let mut state = self.state.lock().await;
        let Some(item) = state.in_flight.take() else {
            return Err(TransportError::Protocol(
                "queue rollback has no in-flight record".to_owned(),
            ));
        };
        state.items.push_front(item);
        not_empty.notify_one();
        Ok(())
    }

    fn notify_all(&self) {
        self.space.notify_waiters();
    }
}

struct OutboundQueues {
    critical: LaneQueue,
    control: LaneQueue,
    bulk: LaneQueue,
    cursor: Mutex<usize>,
    not_empty: Notify,
}

impl OutboundQueues {
    fn new(limits: QueueLimits) -> Self {
        Self {
            critical: LaneQueue::new(limits.critical),
            control: LaneQueue::new(limits.control),
            bulk: LaneQueue::new(limits.bulk),
            cursor: Mutex::new(0),
            not_empty: Notify::new(),
        }
    }

    async fn next(
        &self,
        mut shutdown: watch::Receiver<bool>,
    ) -> Result<(ControlEnvelope, Option<u64>), TransportError> {
        loop {
            if *shutdown.borrow() {
                return Err(TransportError::Closed);
            }
            let notified = self.not_empty.notified();
            let mut cursor = self.cursor.lock().await;
            for _ in 0..25 {
                let slot = *cursor;
                *cursor = (*cursor + 1) % 25;
                let queue = if slot < 16 {
                    &self.critical
                } else if slot < 24 {
                    &self.control
                } else {
                    &self.bulk
                };
                if let Some(popped) = queue.pop().await {
                    return Ok(popped);
                }
            }
            drop(cursor);
            tokio::select! {
                () = notified => {}
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        return Err(TransportError::Closed);
                    }
                }
            }
        }
    }

    fn notify_all(&self) {
        self.not_empty.notify_waiters();
        self.critical.notify_all();
        self.control.notify_all();
        self.bulk.notify_all();
    }

    fn lane(&self, envelope: &ControlEnvelope) -> &LaneQueue {
        match Priority::try_from(envelope.priority).unwrap_or(Priority::Control) {
            Priority::Critical => &self.critical,
            Priority::Bulk => &self.bulk,
            Priority::Unspecified | Priority::Control => &self.control,
        }
    }

    async fn commit(&self, envelope: &ControlEnvelope) -> Result<(), TransportError> {
        self.lane(envelope).commit().await
    }

    async fn rollback(&self, envelope: &ControlEnvelope) -> Result<(), TransportError> {
        self.lane(envelope).rollback(&self.not_empty).await
    }
}

async fn read_frame_async<R: AsyncRead + Unpin>(
    reader: &mut R,
    limit: u32,
) -> Result<ControlEnvelope, TransportError> {
    let mut prefix = [0_u8; FRAME_PREFIX_BYTES];
    reader.read_exact(&mut prefix).await?;
    let declared = u32::from_be_bytes(prefix);
    if declared == 0 {
        return Err(FrameError::EmptyFrame.into());
    }
    let normalized_limit = limit.min(DEFAULT_MAX_FRAME_BYTES);
    if declared > normalized_limit {
        return Err(FrameError::Oversized {
            length: declared as usize,
            limit: normalized_limit,
        }
        .into());
    }
    let body_len = usize::try_from(declared)
        .map_err(|_| TransportError::Protocol("frame length does not fit usize".to_owned()))?;
    let mut frame = Vec::with_capacity(FRAME_PREFIX_BYTES + body_len);
    frame.extend_from_slice(&prefix);
    frame.resize(FRAME_PREFIX_BYTES + body_len, 0);
    reader.read_exact(&mut frame[FRAME_PREFIX_BYTES..]).await?;
    Ok(decode_frame(&frame, normalized_limit)?)
}

async fn write_frame_async<W: AsyncWrite + Unpin>(
    writer: &mut W,
    envelope: &ControlEnvelope,
    limit: u32,
) -> Result<(), TransportError> {
    let frame = encode_frame(envelope, limit)?;
    writer.write_all(&frame).await?;
    writer.flush().await?;
    Ok(())
}

fn normalize_config(config: &mut ClientConfig) -> Result<(), TransportError> {
    if !config.socket_path.is_absolute() {
        return Err(TransportError::Configuration(
            "socket path must be absolute".to_owned(),
        ));
    }
    if config.local_hello.role != Role::RustDataplane as i32
        || !config
            .local_hello
            .supported_versions
            .contains(&u32::from(CONTROL_PROTOCOL_V1))
    {
        return Err(TransportError::Configuration(
            "local Hello must advertise Rust role and protocol v1".to_owned(),
        ));
    }
    if config.max_frame_bytes == 0 || config.max_frame_bytes > DEFAULT_MAX_FRAME_BYTES {
        config.max_frame_bytes = DEFAULT_MAX_FRAME_BYTES;
    }
    config.local_hello.max_frame_bytes = config.max_frame_bytes;
    if config.handshake_timeout.is_zero()
        || config.heartbeat_interval.is_zero()
        || config.peer_timeout <= config.heartbeat_interval
        || config.write_timeout.is_zero()
    {
        return Err(TransportError::Configuration(
            "deadlines must be positive and peer timeout must exceed heartbeat interval".to_owned(),
        ));
    }
    if config.reconnect_base.is_zero()
        || config.reconnect_cap < config.reconnect_base
        || config.reconnect_cap > MAX_RECONNECT_BACKOFF
    {
        return Err(TransportError::Configuration(
            "reconnect window must be positive, ordered, and capped at five seconds".to_owned(),
        ));
    }
    validate_queue_limits(config.queue_limits)
}

fn validate_queue_limits(limits: QueueLimits) -> Result<(), TransportError> {
    let hard = HARD_QUEUE_MAXIMA;
    for (name, configured, maximum) in [
        ("critical", limits.critical, hard.critical),
        ("control", limits.control, hard.control),
        ("bulk", limits.bulk, hard.bulk),
    ] {
        if configured.messages == 0
            || configured.bytes == 0
            || configured.messages > maximum.messages
            || configured.bytes > maximum.bytes
        {
            return Err(TransportError::Configuration(format!(
                "invalid {name} queue limit"
            )));
        }
    }
    Ok(())
}

fn verify_socket(config: &ClientConfig) -> Result<(), TransportError> {
    let metadata = std::fs::symlink_metadata(&config.socket_path)?;
    if !metadata.file_type().is_socket() {
        return Err(TransportError::Configuration(
            "control path is not a Unix-domain socket".to_owned(),
        ));
    }
    if metadata.mode() & 0o777 != 0o600 {
        return Err(TransportError::Configuration(format!(
            "control socket mode is {:o}, expected 600",
            metadata.mode() & 0o777
        )));
    }
    if metadata.uid() != config.allowed_socket_uid {
        return Err(TransportError::Configuration(format!(
            "control socket uid {} does not match allowed uid {}",
            metadata.uid(),
            config.allowed_socket_uid
        )));
    }
    Ok(())
}

fn validate_remote_ack(ack: &HelloAck) -> Result<(), TransportError> {
    if ack.rejection_code != ErrorCode::Ok as i32 {
        return Err(TransportError::Protocol(format!(
            "Go rejected Hello with code {}",
            ack.rejection_code
        )));
    }
    if ack.selected_version != u32::from(CONTROL_PROTOCOL_V1) || ack.control_epoch == 0 {
        return Err(TransportError::Protocol(
            "Go HelloAck selected an invalid version or epoch".to_owned(),
        ));
    }
    Ok(())
}

fn validate_session_envelope(
    envelope: &ControlEnvelope,
    epoch: u64,
    capabilities: &[u64],
) -> Result<(), TransportError> {
    if envelope.protocol_version != u32::from(CONTROL_PROTOCOL_V1) {
        return Err(TransportError::Protocol(format!(
            "peer sent protocol version {}",
            envelope.protocol_version
        )));
    }
    if envelope.control_epoch != epoch {
        return Err(TransportError::Protocol(format!(
            "peer sent stale epoch {}, expected {epoch}",
            envelope.control_epoch
        )));
    }
    for required in &envelope.required_capabilities {
        if !capabilities.contains(required) {
            return Err(TransportError::Protocol(format!(
                "peer message requires missing capability {required}"
            )));
        }
    }
    if matches!(
        envelope.body,
        Some(Body::Hello(_) | Body::HelloAck(_)) | None
    ) {
        return Err(TransportError::Protocol(
            "post-handshake envelope has an illegal body".to_owned(),
        ));
    }
    Ok(())
}

fn hello_envelope(hello: Hello) -> ControlEnvelope {
    ControlEnvelope {
        protocol_version: u32::from(CONTROL_PROTOCOL_V1),
        priority: Priority::Critical as i32,
        body: Some(Body::Hello(hello)),
        ..Default::default()
    }
}

fn hello_ack_envelope(ack: HelloAck) -> ControlEnvelope {
    ControlEnvelope {
        protocol_version: u32::from(CONTROL_PROTOCOL_V1),
        control_epoch: ack.control_epoch,
        priority: Priority::Critical as i32,
        body: Some(Body::HelloAck(ack)),
        ..Default::default()
    }
}

fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
        })
}

fn result_to_string(result: &Result<(), TransportError>) -> String {
    match result {
        Ok(()) => "control session ended".to_owned(),
        Err(error) => error.to_string(),
    }
}

fn lock_std<T>(mutex: &StdMutex<T>) -> StdMutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn set_instant(target: &StdMutex<Option<Instant>>, value: Option<Instant>) {
    *lock_std(target) = value;
}

fn set_instant_value(target: &StdMutex<Instant>, value: Instant) {
    *lock_std(target) = value;
}

fn set_string(target: &StdMutex<Option<String>>, value: Option<String>) {
    *lock_std(target) = value;
}

struct FullJitter {
    state: u64,
}

impl FullJitter {
    fn new(seed: u64) -> Self {
        let derived = unix_millis() ^ u64::from(std::process::id()).rotate_left(17);
        Self {
            state: if seed == 0 { derived.max(1) } else { seed },
        }
    }

    fn duration(&mut self, window: Duration) -> Duration {
        self.state ^= self.state << 13;
        self.state ^= self.state >> 7;
        self.state ^= self.state << 17;
        let nanos = u64::try_from(window.as_nanos()).unwrap_or(u64::MAX);
        Duration::from_nanos(self.state % nanos.saturating_add(1))
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::fs;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    use tokio::net::UnixListener;
    use tokio::sync::mpsc;
    use tokio::task::yield_now;

    use super::*;
    use crate::v1::{MeteringBatch, MetricsBatch, ProtocolError, RedirectResult, RouteAssignment};

    static NEXT_TEST_SOCKET: AtomicU64 = AtomicU64::new(1);

    struct TestSocket {
        directory: PathBuf,
        path: PathBuf,
        uid: u32,
    }

    impl TestSocket {
        fn bind() -> Result<(Self, UnixListener), TransportError> {
            let identifier = NEXT_TEST_SOCKET.fetch_add(1, Ordering::Relaxed);
            let directory = std::env::temp_dir()
                .join(format!("tiproxy-ctl-{}-{identifier}", std::process::id()));
            fs::create_dir(&directory)?;
            let path = directory.join("control.sock");
            let listener = UnixListener::bind(&path)?;
            fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o600))?;
            let uid = fs::symlink_metadata(&path)?.uid();
            Ok((
                Self {
                    directory,
                    path,
                    uid,
                },
                listener,
            ))
        }
    }

    impl Drop for TestSocket {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.path);
            let _ = fs::remove_dir(&self.directory);
        }
    }

    fn rust_hello() -> Hello {
        Hello {
            role: Role::RustDataplane as i32,
            process_id: "rust-fake-client".to_owned(),
            supported_versions: vec![u32::from(CONTROL_PROTOCOL_V1)],
            capabilities: vec![3, 7],
            max_frame_bytes: DEFAULT_MAX_FRAME_BYTES,
            ..Default::default()
        }
    }

    fn go_hello() -> Hello {
        Hello {
            role: Role::GoControl as i32,
            process_id: "go-fake-server".to_owned(),
            supported_versions: vec![u32::from(CONTROL_PROTOCOL_V1)],
            capabilities: vec![3, 5],
            max_frame_bytes: DEFAULT_MAX_FRAME_BYTES,
            ..Default::default()
        }
    }

    fn test_config(socket: &TestSocket) -> ClientConfig {
        let mut config = ClientConfig::with_defaults(socket.path.clone(), socket.uid, rust_hello());
        config.handshake_timeout = Duration::from_millis(250);
        config.heartbeat_interval = Duration::from_millis(20);
        config.peer_timeout = Duration::from_millis(100);
        config.write_timeout = Duration::from_millis(100);
        config.reconnect_base = Duration::from_millis(20);
        config.reconnect_cap = Duration::from_millis(80);
        config.reconnect_jitter_seed = 9;
        config
    }

    async fn fake_go_handshake(
        listener: &UnixListener,
        epoch: u64,
        partial_hello: bool,
    ) -> Result<UnixStream, TransportError> {
        let (mut stream, _) = listener.accept().await?;
        let local = go_hello();
        let local_envelope = hello_envelope(local.clone());
        if partial_hello {
            let frame = encode_frame(&local_envelope, DEFAULT_MAX_FRAME_BYTES)?;
            for byte in frame {
                stream.write_all(&[byte]).await?;
                yield_now().await;
            }
        } else {
            write_frame_async(&mut stream, &local_envelope, DEFAULT_MAX_FRAME_BYTES).await?;
        }
        let remote_envelope = read_frame_async(&mut stream, DEFAULT_MAX_FRAME_BYTES).await?;
        let Some(Body::Hello(remote)) = remote_envelope.body else {
            return Err(TransportError::Protocol(
                "fake Go peer expected Rust Hello".to_owned(),
            ));
        };
        let ack = negotiate_hello(&local, &remote, &[], epoch)?;
        write_frame_async(
            &mut stream,
            &hello_ack_envelope(ack.clone()),
            ack.max_frame_bytes,
        )
        .await?;
        let remote_ack = read_frame_async(&mut stream, ack.max_frame_bytes).await?;
        let Some(Body::HelloAck(remote_ack)) = remote_ack.body else {
            return Err(TransportError::Protocol(
                "fake Go peer expected Rust HelloAck".to_owned(),
            ));
        };
        if remote_ack != ack {
            return Err(TransportError::Protocol(
                "Rust HelloAck differs from Go selection".to_owned(),
            ));
        }
        Ok(stream)
    }

    fn heartbeat(epoch: u64, marker: u64) -> ControlEnvelope {
        ControlEnvelope {
            protocol_version: u32::from(CONTROL_PROTOCOL_V1),
            control_epoch: epoch,
            priority: Priority::Critical as i32,
            body: Some(Body::Heartbeat(Heartbeat {
                monotonic_millis: marker,
                ..Default::default()
            })),
            ..Default::default()
        }
    }

    async fn wait_for_epoch(
        state: &mut watch::Receiver<ConnectionState>,
        epoch: u64,
    ) -> Result<(), TransportError> {
        timeout(Duration::from_secs(1), async {
            loop {
                if matches!(*state.borrow(), ConnectionState::Connected { epoch: seen, .. } if seen == epoch)
                {
                    return Ok(());
                }
                state.changed().await.map_err(|_| TransportError::Closed)?;
            }
        })
        .await
        .map_err(|_| TransportError::Timeout("connected state"))?
    }

    #[tokio::test]
    async fn rust_fake_peer_partial_io_and_eof_join_cleanly() -> Result<(), Box<dyn Error>> {
        let (socket, listener) = TestSocket::bind()?;
        let client = Arc::new(ControlClient::new(test_config(&socket))?);
        let (message_tx, mut message_rx) = mpsc::unbounded_channel();
        let run_client = Arc::clone(&client);
        let client_task = tokio::spawn(async move {
            let handler = move |envelope| {
                message_tx
                    .send(envelope)
                    .map_err(|_| TransportError::Protocol("test receiver was dropped".to_owned()))
            };
            run_client.run(&handler).await
        });
        let server_task = tokio::spawn(async move {
            let mut stream = fake_go_handshake(&listener, 17, true).await?;
            write_frame_async(&mut stream, &heartbeat(17, 99), DEFAULT_MAX_FRAME_BYTES).await
        });

        let received = timeout(Duration::from_secs(1), message_rx.recv())
            .await?
            .ok_or("control handler channel closed")?;
        let Some(Body::Heartbeat(received_heartbeat)) = received.body else {
            return Err("expected heartbeat".into());
        };
        assert_eq!(received_heartbeat.monotonic_millis, 99);
        server_task.await??;
        timeout(Duration::from_secs(1), async {
            while client.reconnect_attempts() == 0 {
                yield_now().await;
            }
        })
        .await?;
        client.shutdown();
        timeout(Duration::from_secs(1), client_task).await???;
        Ok(())
    }

    #[tokio::test]
    async fn reconnects_with_a_new_epoch_and_no_orphaned_task() -> Result<(), Box<dyn Error>> {
        let (socket, listener) = TestSocket::bind()?;
        let client = Arc::new(ControlClient::new(test_config(&socket))?);
        let mut state = client.subscribe_state();
        let (message_tx, mut message_rx) = mpsc::unbounded_channel();
        let run_client = Arc::clone(&client);
        let client_task = tokio::spawn(async move {
            let handler = move |envelope| {
                message_tx
                    .send(envelope)
                    .map_err(|_| TransportError::Protocol("test receiver was dropped".to_owned()))
            };
            run_client.run(&handler).await
        });
        let server_task = tokio::spawn(async move {
            let first = fake_go_handshake(&listener, 1, false).await?;
            drop(first);
            let mut second = fake_go_handshake(&listener, 2, false).await?;
            write_frame_async(&mut second, &heartbeat(2, 2), DEFAULT_MAX_FRAME_BYTES).await?;
            sleep(Duration::from_millis(50)).await;
            Ok::<(), TransportError>(())
        });

        wait_for_epoch(&mut state, 2).await?;
        let received = timeout(Duration::from_secs(1), message_rx.recv())
            .await?
            .ok_or("control handler channel closed")?;
        assert!(matches!(received.body, Some(Body::Heartbeat(_))));
        assert_eq!(client.epoch(), 2);
        assert!(client.reconnect_attempts() >= 1);
        client.shutdown();
        timeout(Duration::from_secs(1), client_task).await???;
        server_task.await??;
        Ok(())
    }

    #[tokio::test]
    async fn oversized_peer_frame_is_fatal_and_retried() -> Result<(), Box<dyn Error>> {
        let (socket, listener) = TestSocket::bind()?;
        let mut config = test_config(&socket);
        config.reconnect_base = Duration::from_millis(100);
        config.reconnect_cap = Duration::from_millis(100);
        let client = Arc::new(ControlClient::new(config)?);
        let run_client = Arc::clone(&client);
        let client_task =
            tokio::spawn(async move { run_client.run(&|_| Ok::<(), TransportError>(())).await });
        let server_task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            stream
                .write_all(&(DEFAULT_MAX_FRAME_BYTES + 1).to_be_bytes())
                .await?;
            stream.flush().await?;
            sleep(Duration::from_millis(200)).await;
            Ok::<(), TransportError>(())
        });

        timeout(Duration::from_secs(1), async {
            loop {
                if client
                    .last_disconnect()
                    .is_some_and(|detail| detail.contains("exceeds limit"))
                {
                    break;
                }
                yield_now().await;
            }
        })
        .await?;
        assert!(client.reconnect_attempts() >= 1);
        client.shutdown();
        timeout(Duration::from_secs(1), client_task).await???;
        server_task.await??;
        Ok(())
    }

    #[tokio::test]
    async fn rejects_a_second_mutable_transport_owner() -> Result<(), Box<dyn Error>> {
        let (socket, _listener) = TestSocket::bind()?;
        let client = Arc::new(ControlClient::new(test_config(&socket))?);
        let run_client = Arc::clone(&client);
        let client_task =
            tokio::spawn(async move { run_client.run(&|_| Ok::<(), TransportError>(())).await });
        timeout(Duration::from_secs(1), async {
            while !client.running.load(Ordering::Acquire) {
                yield_now().await;
            }
        })
        .await?;
        let second = client.run(&|_| Ok::<(), TransportError>(())).await;
        assert!(matches!(second, Err(TransportError::Configuration(_))));
        client.shutdown();
        timeout(Duration::from_secs(1), client_task).await???;
        Ok(())
    }

    #[tokio::test]
    async fn queue_pressure_drops_only_metrics() -> Result<(), Box<dyn Error>> {
        let (socket, _listener) = TestSocket::bind()?;
        let mut config = test_config(&socket);
        config.queue_limits.bulk = QueueLimit {
            messages: 1,
            bytes: 1_024,
        };
        config.queue_limits.critical = QueueLimit {
            messages: 1,
            bytes: 1_024,
        };
        let client = ControlClient::new(config)?;
        let metrics = ControlEnvelope {
            priority: Priority::Bulk as i32,
            body: Some(Body::MetricsBatch(MetricsBatch::default())),
            ..Default::default()
        };
        client.send(metrics.clone()).await?;
        assert!(matches!(
            client.send(metrics).await,
            Err(TransportError::MetricsDropped)
        ));
        assert_eq!(client.metrics_dropped(), 1);

        let redirect = ControlEnvelope {
            priority: Priority::Critical as i32,
            body: Some(Body::RedirectResult(RedirectResult::default())),
            ..Default::default()
        };
        client.send(redirect.clone()).await?;
        assert!(
            timeout(Duration::from_millis(20), client.send(redirect))
                .await
                .is_err()
        );
        client.shutdown();
        Ok(())
    }

    #[tokio::test]
    async fn metering_backpressures_and_weighted_cycle_is_bounded() -> Result<(), Box<dyn Error>> {
        let (socket, _listener) = TestSocket::bind()?;
        let mut config = test_config(&socket);
        config.queue_limits = QueueLimits {
            critical: QueueLimit {
                messages: 32,
                bytes: 64 * 1_024,
            },
            control: QueueLimit {
                messages: 16,
                bytes: 64 * 1_024,
            },
            bulk: QueueLimit {
                messages: 2,
                bytes: 64 * 1_024,
            },
        };
        let client = ControlClient::new(config)?;
        for sequence in 0..16 {
            client
                .send(ControlEnvelope {
                    request_id: sequence,
                    priority: Priority::Critical as i32,
                    body: Some(Body::RedirectResult(RedirectResult::default())),
                    ..Default::default()
                })
                .await?;
        }
        for sequence in 0..8 {
            client
                .send(ControlEnvelope {
                    request_id: sequence,
                    priority: Priority::Control as i32,
                    body: Some(Body::RouteAssignment(RouteAssignment::default())),
                    ..Default::default()
                })
                .await?;
        }
        client
            .send(ControlEnvelope {
                priority: Priority::Bulk as i32,
                body: Some(Body::MeteringBatch(MeteringBatch::default())),
                ..Default::default()
            })
            .await?;

        for index in 0..25 {
            let (envelope, session_epoch) =
                client.queues.next(client.shutdown_tx.subscribe()).await?;
            let expected = if index < 16 {
                Priority::Critical
            } else if index < 24 {
                Priority::Control
            } else {
                Priority::Bulk
            };
            assert_eq!(Priority::try_from(envelope.priority)?, expected);
            assert_eq!(session_epoch, None, "plain send() enqueues durable work");
            client.queues.commit(&envelope).await?;
        }

        let metering = ControlEnvelope {
            priority: Priority::Bulk as i32,
            body: Some(Body::MeteringBatch(MeteringBatch::default())),
            ..Default::default()
        };
        client.send(metering.clone()).await?;
        client.send(metering.clone()).await?;
        assert!(
            timeout(Duration::from_millis(20), client.send(metering))
                .await
                .is_err()
        );
        client.shutdown();
        Ok(())
    }

    #[tokio::test]
    async fn write_timeout_requeues_critical_message() -> Result<(), Box<dyn Error>> {
        let (socket, listener) = TestSocket::bind()?;
        let mut config = test_config(&socket);
        config.write_timeout = Duration::from_millis(20);
        config.peer_timeout = Duration::from_millis(300);
        config.heartbeat_interval = Duration::from_millis(100);
        config.reconnect_base = Duration::from_millis(100);
        config.reconnect_cap = Duration::from_millis(100);
        let client = Arc::new(ControlClient::new(config)?);
        let mut state = client.subscribe_state();
        let run_client = Arc::clone(&client);
        let client_task =
            tokio::spawn(async move { run_client.run(&|_| Ok::<(), TransportError>(())).await });
        let server_task = tokio::spawn(async move {
            let _stream = fake_go_handshake(&listener, 8, false).await?;
            sleep(Duration::from_millis(250)).await;
            Ok::<(), TransportError>(())
        });
        wait_for_epoch(&mut state, 8).await?;
        for request_id in 1..=7 {
            client
                .send(ControlEnvelope {
                    request_id,
                    priority: Priority::Critical as i32,
                    body: Some(Body::Error(ProtocolError {
                        detail: "x".repeat(900 * 1_024),
                        ..Default::default()
                    })),
                    ..Default::default()
                })
                .await?;
        }
        timeout(Duration::from_secs(1), async {
            loop {
                if client
                    .last_disconnect()
                    .is_some_and(|detail| detail.contains("frame write"))
                {
                    break;
                }
                yield_now().await;
            }
        })
        .await?;
        assert!(!client.queues.critical.state.lock().await.items.is_empty());
        client.shutdown();
        timeout(Duration::from_secs(1), client_task).await???;
        server_task.await??;
        Ok(())
    }

    #[tokio::test]
    async fn last_good_generation_is_monotonic_and_jitter_is_capped() -> Result<(), Box<dyn Error>>
    {
        let (socket, _listener) = TestSocket::bind()?;
        let client = ControlClient::new(test_config(&socket))?;
        client.mark_last_good_snapshot(9);
        client.mark_last_good_snapshot(8);
        let (generation, _) = client
            .last_good_snapshot_age()
            .ok_or("missing last-good snapshot")?;
        assert_eq!(generation, 9);

        let mut first = FullJitter::new(42);
        let mut second = FullJitter::new(42);
        for window in [
            Duration::from_millis(50),
            Duration::from_millis(100),
            Duration::from_secs(5),
        ] {
            let delay = first.duration(window);
            assert_eq!(delay, second.duration(window));
            assert!(delay <= window);
        }
        Ok(())
    }

    /// A handler whose `resume_session` blocks until released, counting
    /// both hooks — the two-phase reconnect regressions drive it.
    struct GatedHandler {
        release: watch::Receiver<bool>,
        resume_calls: Arc<AtomicU64>,
        handled: Arc<AtomicU64>,
    }

    impl Handler for GatedHandler {
        async fn handle(&self, _envelope: ControlEnvelope) -> Result<(), TransportError> {
            self.handled.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }

        async fn resume_session(&self, _epoch: u64) -> Result<(), TransportError> {
            self.resume_calls.fetch_add(1, Ordering::Relaxed);
            let mut release = self.release.clone();
            loop {
                if *release.borrow() {
                    return Ok(());
                }
                if release.changed().await.is_err() {
                    return Err(TransportError::Closed);
                }
            }
        }
    }

    /// Two-phase reconnect: no frame is read (the handler is not
    /// invoked) until `resume_session` completes, even when the peer
    /// already wrote one — and releasing the gate delivers it.
    #[tokio::test]
    async fn reader_waits_for_resume_session() -> Result<(), Box<dyn Error>> {
        let (socket, listener) = TestSocket::bind()?;
        let client = Arc::new(ControlClient::new(test_config(&socket))?);
        let (release_tx, release_rx) = watch::channel(false);
        let resume_calls = Arc::new(AtomicU64::new(0));
        let frames = Arc::new(AtomicU64::new(0));
        let handler = GatedHandler {
            release: release_rx,
            resume_calls: Arc::clone(&resume_calls),
            handled: Arc::clone(&frames),
        };
        let run_client = Arc::clone(&client);
        let client_task = tokio::spawn(async move { run_client.run(&handler).await });
        let server_task = tokio::spawn(async move {
            let mut stream = fake_go_handshake(&listener, 1, false).await?;
            // A frame is on the wire immediately after the handshake.
            write_frame_async(&mut stream, &heartbeat(1, 9), DEFAULT_MAX_FRAME_BYTES).await?;
            sleep(Duration::from_millis(400)).await;
            Ok::<(), TransportError>(())
        });

        timeout(Duration::from_secs(1), async {
            while resume_calls.load(Ordering::Relaxed) == 0 {
                yield_now().await;
            }
        })
        .await?;
        sleep(Duration::from_millis(100)).await;
        assert_eq!(
            frames.load(Ordering::Relaxed),
            0,
            "no frame is read while resume_session is pending"
        );
        release_tx.send_replace(true);
        timeout(Duration::from_secs(1), async {
            while frames.load(Ordering::Relaxed) == 0 {
                yield_now().await;
            }
        })
        .await?;
        client.shutdown();
        timeout(Duration::from_secs(1), client_task).await???;
        server_task.await??;
        Ok(())
    }

    /// The writer failing while `resume_session` is still blocked must
    /// not deadlock the teardown join: the stop signal cancels the
    /// pump, the session converges, and the next session calls
    /// `resume_session` again.
    #[tokio::test]
    async fn writer_failure_during_blocked_resume_converges() -> Result<(), Box<dyn Error>> {
        let (socket, listener) = TestSocket::bind()?;
        let mut config = test_config(&socket);
        config.heartbeat_interval = Duration::from_millis(10);
        let client = Arc::new(ControlClient::new(config)?);
        let (release_tx, release_rx) = watch::channel(false);
        let resume_calls = Arc::new(AtomicU64::new(0));
        let frames = Arc::new(AtomicU64::new(0));
        let handler = GatedHandler {
            release: release_rx,
            resume_calls: Arc::clone(&resume_calls),
            handled: Arc::clone(&frames),
        };
        let run_client = Arc::clone(&client);
        let client_task = tokio::spawn(async move { run_client.run(&handler).await });
        let server_task = tokio::spawn(async move {
            // Session 1: die while the resume gate is still closed —
            // the client's heartbeat write fails against the dead
            // socket while resume_session is blocked.
            let first = fake_go_handshake(&listener, 1, false).await?;
            sleep(Duration::from_millis(60)).await;
            drop(first);
            // Session 2 proves the teardown converged and re-invoked
            // the pump.
            let second = fake_go_handshake(&listener, 2, false).await?;
            sleep(Duration::from_millis(200)).await;
            drop(second);
            Ok::<(), TransportError>(())
        });

        timeout(Duration::from_secs(2), async {
            while resume_calls.load(Ordering::Relaxed) < 2 {
                yield_now().await;
            }
        })
        .await?;
        assert_eq!(
            frames.load(Ordering::Relaxed),
            0,
            "no frame was read across both gated sessions"
        );
        release_tx.send_replace(true);
        client.shutdown();
        timeout(Duration::from_secs(1), client_task).await???;
        server_task.await??;
        Ok(())
    }
}
