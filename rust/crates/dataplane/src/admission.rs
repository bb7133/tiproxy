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

//! Atomic new-connection admission and Rust-process/cgroup memory pressure.
//!
//! Go checks memory before `max-connections`, allocates a connection ID only
//! after both checks, and estimates two configured buffers per live
//! connection. This module keeps that ordering under concurrency and returns
//! an RAII permit so panic, task abort, and ordinary close release both gauges.

#[cfg(target_os = "linux")]
use std::fs;
#[cfg(target_os = "linux")]
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

const MIN_CONNECTION_BUFFER_BYTES: u32 = 1024;
const MAX_CONNECTION_BUFFER_BYTES: u32 = 16 * 1024 * 1024;
const SYSTEM_MEMORY_REFRESH: Duration = Duration::from_secs(5);
const SYSTEM_MEMORY_EXPIRY: Duration = Duration::from_secs(15);

/// Immutable admission settings captured for one new connection.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AdmissionPolicy {
    /// Maximum live connections; zero means unlimited, matching Go.
    pub max_connections: u64,
    /// Reject at or above this memory ratio; zero disables the check.
    pub high_memory_reject_threshold: f64,
    /// One read or write buffer size. Admission reserves twice this value.
    pub connection_buffer_bytes: u32,
}

impl AdmissionPolicy {
    /// Validates and creates a new-session admission policy.
    ///
    /// # Errors
    ///
    /// Returns a typed policy error for a non-finite/out-of-range threshold
    /// or a buffer outside the snapshot contract.
    pub fn new(
        max_connections: u64,
        high_memory_reject_threshold: f64,
        connection_buffer_bytes: u32,
    ) -> Result<Self, AdmissionPolicyError> {
        if !high_memory_reject_threshold.is_finite()
            || !(0.0..=1.0).contains(&high_memory_reject_threshold)
            || (high_memory_reject_threshold > 0.0 && high_memory_reject_threshold < 0.5)
        {
            return Err(AdmissionPolicyError::InvalidMemoryThreshold);
        }
        if !(MIN_CONNECTION_BUFFER_BYTES..=MAX_CONNECTION_BUFFER_BYTES)
            .contains(&connection_buffer_bytes)
        {
            return Err(AdmissionPolicyError::InvalidConnectionBuffer);
        }
        Ok(Self {
            max_connections,
            high_memory_reject_threshold,
            connection_buffer_bytes,
        })
    }

    /// Returns the Go-equivalent read-plus-write buffer reservation.
    #[must_use]
    pub fn reserved_buffer_bytes(self) -> u64 {
        u64::from(self.connection_buffer_bytes) * 2
    }
}

/// Invalid admission settings supplied outside the validated snapshot path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AdmissionPolicyError {
    /// The high-memory threshold is not zero or within `[0.5, 1.0]`.
    #[error("high-memory reject threshold must be zero or between 0.5 and 1.0")]
    InvalidMemoryThreshold,
    /// The connection buffer is outside `[1 KiB, 16 MiB]`.
    #[error("connection buffer must be between 1 KiB and 16 MiB")]
    InvalidConnectionBuffer,
}

/// One memory observation used for an admission decision.
#[derive(Debug, Clone, Copy)]
pub struct MemorySample {
    /// Rust-process RSS or finite-cgroup current bytes.
    pub used_bytes: u64,
    /// Host or finite-cgroup memory limit in bytes.
    pub limit_bytes: u64,
    /// When this observation was made. Repeated cached samples retain it.
    pub observed_at: Instant,
}

impl MemorySample {
    /// Creates a timestamped observation.
    #[must_use]
    pub fn now(used_bytes: u64, limit_bytes: u64) -> Self {
        Self {
            used_bytes,
            limit_bytes,
            observed_at: Instant::now(),
        }
    }
}

/// Redacted failure to observe process/cgroup memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("memory usage is unavailable: {detail}")]
pub struct MemoryProbeError {
    detail: &'static str,
}

impl MemoryProbeError {
    /// Creates a redacted diagnostic. File contents and paths are excluded.
    #[must_use]
    pub const fn unavailable(detail: &'static str) -> Self {
        Self { detail }
    }

    /// Returns the stable diagnostic category.
    #[must_use]
    pub const fn detail(self) -> &'static str {
        self.detail
    }
}

/// Supplies cached or live Rust-process/cgroup memory observations.
pub trait MemoryProbe: Send + Sync {
    /// Returns the latest usable sample. Admission fails open on errors.
    ///
    /// # Errors
    ///
    /// Returns a redacted availability error when no fresh sample exists.
    fn sample(&self) -> Result<MemorySample, MemoryProbeError>;
}

#[derive(Debug, Default)]
struct SystemMemoryCache {
    sample: Option<MemorySample>,
    last_attempt: Option<Instant>,
}

/// Production Linux probe for Rust RSS under the effective finite cgroup or
/// host memory limit. Samples are refreshed at most every five seconds and
/// fail open after fifteen seconds without a usable refresh, matching Go's
/// admission freshness policy without an orphan background task.
#[derive(Debug, Default)]
pub struct SystemMemoryProbe {
    cache: Mutex<SystemMemoryCache>,
}

impl SystemMemoryProbe {
    /// Constructs an empty, lazily refreshed system probe.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            cache: Mutex::new(SystemMemoryCache {
                sample: None,
                last_attempt: None,
            }),
        }
    }
}

impl MemoryProbe for SystemMemoryProbe {
    fn sample(&self) -> Result<MemorySample, MemoryProbeError> {
        let now = Instant::now();
        let mut cache = lock(&self.cache);
        if let Some(sample) = cache.sample
            && now.saturating_duration_since(sample.observed_at) < SYSTEM_MEMORY_REFRESH
        {
            return Ok(sample);
        }
        if cache
            .last_attempt
            .is_some_and(|attempt| now.saturating_duration_since(attempt) < SYSTEM_MEMORY_REFRESH)
        {
            return cache
                .sample
                .filter(|sample| {
                    now.saturating_duration_since(sample.observed_at) <= SYSTEM_MEMORY_EXPIRY
                })
                .ok_or_else(|| {
                    MemoryProbeError::unavailable("memory sample refresh is rate-limited")
                });
        }
        cache.last_attempt = Some(now);
        match read_system_memory(now) {
            Ok(sample) => {
                cache.sample = Some(sample);
                Ok(sample)
            }
            Err(error) => cache
                .sample
                .filter(|sample| {
                    now.saturating_duration_since(sample.observed_at) <= SYSTEM_MEMORY_EXPIRY
                })
                .ok_or(error),
        }
    }
}

/// Why one accepted socket was rejected before session allocation.
#[derive(Debug, Clone, Copy, PartialEq, thiserror::Error)]
pub enum AdmissionRejection {
    /// Effective memory usage reached the configured threshold.
    #[error("memory usage {effective_used_bytes}/{limit_bytes} reached threshold {threshold}")]
    Memory {
        /// Sample plus post-sample connection-buffer delta.
        effective_used_bytes: u64,
        /// Effective process/cgroup memory limit.
        limit_bytes: u64,
        /// Threshold captured for this new connection.
        threshold: f64,
    },
    /// The live-connection boundary was already full.
    #[error("active connections {active_connections} reached maximum {max_connections}")]
    MaxConnections {
        /// Live admitted connections at the decision point.
        active_connections: u64,
        /// Captured nonzero maximum.
        max_connections: u64,
    },
}

/// Atomic admission gauges and counters.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AdmissionMetricsSnapshot {
    /// Current live admission permits.
    pub active_connections: u64,
    /// Current read-plus-write buffer reservation.
    pub connection_buffer_bytes: u64,
    /// Successful permit acquisitions.
    pub admitted_total: u64,
    /// Connections rejected for memory pressure.
    pub rejected_memory_total: u64,
    /// Connections rejected at the configured maximum.
    pub rejected_max_connections_total: u64,
    /// Memory observations that failed open.
    pub memory_probe_failures_total: u64,
}

#[derive(Debug, Default)]
struct AdmissionMetrics {
    active_connections: AtomicU64,
    connection_buffer_bytes: AtomicU64,
    admitted_total: AtomicU64,
    rejected_memory_total: AtomicU64,
    rejected_max_connections_total: AtomicU64,
    memory_probe_failures_total: AtomicU64,
}

#[derive(Debug, Default)]
struct AdmissionState {
    active_connections: u64,
    connection_buffer_bytes: u64,
    sampled_at: Option<Instant>,
    sampled_buffer_baseline: u64,
}

struct AdmissionInner {
    memory: Arc<dyn MemoryProbe>,
    state: Mutex<AdmissionState>,
    metrics: AdmissionMetrics,
}

/// Serializes memory and maximum checks so concurrent accepts cannot cross a
/// boundary, and owns RAII gauges for live permits.
#[derive(Clone)]
pub struct AdmissionController {
    inner: Arc<AdmissionInner>,
}

impl AdmissionController {
    /// Creates an admission owner using `memory`; probe failures fail open.
    #[must_use]
    pub fn new(memory: Arc<dyn MemoryProbe>) -> Self {
        Self {
            inner: Arc::new(AdmissionInner {
                memory,
                state: Mutex::new(AdmissionState::default()),
                metrics: AdmissionMetrics::default(),
            }),
        }
    }

    /// Checks memory first, then the live maximum, and atomically reserves a
    /// connection plus two buffers. No connection ID should be allocated
    /// before this succeeds.
    ///
    /// # Errors
    ///
    /// Returns the exact rejection class and boundary values.
    pub(crate) fn try_acquire(
        &self,
        policy: AdmissionPolicy,
    ) -> Result<AdmissionPermit, AdmissionRejection> {
        let mut state = lock(&self.inner.state);
        if let Some(rejection) = self.memory_rejection(&mut state, policy) {
            self.inner
                .metrics
                .rejected_memory_total
                .fetch_add(1, Ordering::Relaxed);
            return Err(rejection);
        }
        if policy.max_connections != 0 && state.active_connections >= policy.max_connections {
            self.inner
                .metrics
                .rejected_max_connections_total
                .fetch_add(1, Ordering::Relaxed);
            return Err(AdmissionRejection::MaxConnections {
                active_connections: state.active_connections,
                max_connections: policy.max_connections,
            });
        }

        let Some(active_connections) = state.active_connections.checked_add(1) else {
            self.inner
                .metrics
                .rejected_max_connections_total
                .fetch_add(1, Ordering::Relaxed);
            return Err(AdmissionRejection::MaxConnections {
                active_connections: state.active_connections,
                max_connections: u64::MAX,
            });
        };
        let reserved_buffer_bytes = policy.reserved_buffer_bytes();
        state.active_connections = active_connections;
        state.connection_buffer_bytes = state
            .connection_buffer_bytes
            .saturating_add(reserved_buffer_bytes);
        self.inner
            .metrics
            .active_connections
            .store(state.active_connections, Ordering::Release);
        self.inner
            .metrics
            .connection_buffer_bytes
            .store(state.connection_buffer_bytes, Ordering::Release);
        self.inner
            .metrics
            .admitted_total
            .fetch_add(1, Ordering::Relaxed);
        drop(state);
        Ok(AdmissionPermit {
            inner: Arc::clone(&self.inner),
            reserved_buffer_bytes,
        })
    }

    fn memory_rejection(
        &self,
        state: &mut AdmissionState,
        policy: AdmissionPolicy,
    ) -> Option<AdmissionRejection> {
        let threshold = policy.high_memory_reject_threshold;
        if threshold == 0.0 {
            return None;
        }
        let sample = match self.inner.memory.sample() {
            Ok(sample) if sample.limit_bytes > 0 => sample,
            Ok(_) | Err(_) => {
                self.inner
                    .metrics
                    .memory_probe_failures_total
                    .fetch_add(1, Ordering::Relaxed);
                return None;
            }
        };
        if state.sampled_at != Some(sample.observed_at) {
            state.sampled_at = Some(sample.observed_at);
            state.sampled_buffer_baseline = state.connection_buffer_bytes;
        }
        let effective_used_bytes = if state.connection_buffer_bytes >= state.sampled_buffer_baseline
        {
            sample
                .used_bytes
                .saturating_add(state.connection_buffer_bytes - state.sampled_buffer_baseline)
        } else {
            sample
                .used_bytes
                .saturating_sub(state.sampled_buffer_baseline - state.connection_buffer_bytes)
        };
        #[expect(
            clippy::cast_precision_loss,
            reason = "the configuration contract is a floating-point ratio; diagnostics retain the exact byte counters"
        )]
        let usage = effective_used_bytes as f64 / sample.limit_bytes as f64;
        (usage >= threshold).then_some(AdmissionRejection::Memory {
            effective_used_bytes,
            limit_bytes: sample.limit_bytes,
            threshold,
        })
    }

    /// Returns an atomic metrics snapshot.
    #[must_use]
    pub fn metrics(&self) -> AdmissionMetricsSnapshot {
        AdmissionMetricsSnapshot {
            active_connections: self
                .inner
                .metrics
                .active_connections
                .load(Ordering::Acquire),
            connection_buffer_bytes: self
                .inner
                .metrics
                .connection_buffer_bytes
                .load(Ordering::Acquire),
            admitted_total: self.inner.metrics.admitted_total.load(Ordering::Relaxed),
            rejected_memory_total: self
                .inner
                .metrics
                .rejected_memory_total
                .load(Ordering::Relaxed),
            rejected_max_connections_total: self
                .inner
                .metrics
                .rejected_max_connections_total
                .load(Ordering::Relaxed),
            memory_probe_failures_total: self
                .inner
                .metrics
                .memory_probe_failures_total
                .load(Ordering::Relaxed),
        }
    }
}

/// Live admission reservation. Dropping it releases both gauges exactly once.
pub(crate) struct AdmissionPermit {
    inner: Arc<AdmissionInner>,
    reserved_buffer_bytes: u64,
}

impl AdmissionPermit {
    pub(crate) const fn reserved_buffer_bytes(&self) -> u64 {
        self.reserved_buffer_bytes
    }
}

impl Drop for AdmissionPermit {
    fn drop(&mut self) {
        let mut state = lock(&self.inner.state);
        state.active_connections = state.active_connections.saturating_sub(1);
        state.connection_buffer_bytes = state
            .connection_buffer_bytes
            .saturating_sub(self.reserved_buffer_bytes);
        self.inner
            .metrics
            .active_connections
            .store(state.active_connections, Ordering::Release);
        self.inner
            .metrics
            .connection_buffer_bytes
            .store(state.connection_buffer_bytes, Ordering::Release);
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(target_os = "linux")]
fn read_system_memory(observed_at: Instant) -> Result<MemorySample, MemoryProbeError> {
    let process_status = fs::read_to_string("/proc/self/status")
        .map_err(|_| MemoryProbeError::unavailable("process RSS cannot be read"))?;
    let host_meminfo = fs::read_to_string("/proc/meminfo")
        .map_err(|_| MemoryProbeError::unavailable("host memory limit cannot be read"))?;
    let process_rss = parse_kib_field(&process_status, "VmRSS:")
        .ok_or_else(|| MemoryProbeError::unavailable("process RSS is malformed"))?;
    let host_limit = parse_kib_field(&host_meminfo, "MemTotal:")
        .filter(|limit| *limit > 0)
        .ok_or_else(|| MemoryProbeError::unavailable("host memory limit is malformed"))?;

    let cgroup = cgroup_memory_paths();
    let finite_cgroup = cgroup.and_then(|(current, maximum)| {
        let current = read_decimal_file(&current)?;
        let maximum_text = fs::read_to_string(maximum).ok()?;
        let maximum_text = maximum_text.trim();
        if maximum_text == "max" {
            return None;
        }
        let maximum = maximum_text.parse::<u64>().ok()?;
        // cgroup v1 represents "unlimited" with a near-i64-max sentinel.
        (maximum > 0 && maximum < host_limit.saturating_mul(16)).then_some((current, maximum))
    });
    let (used_bytes, limit_bytes) = finite_cgroup
        .map_or((process_rss, host_limit), |(current, maximum)| {
            (process_rss.max(current), host_limit.min(maximum))
        });
    Ok(MemorySample {
        used_bytes,
        limit_bytes,
        observed_at,
    })
}

#[cfg(not(target_os = "linux"))]
fn read_system_memory(_observed_at: Instant) -> Result<MemorySample, MemoryProbeError> {
    Err(MemoryProbeError::unavailable(
        "Rust process/cgroup probing requires Linux",
    ))
}

#[cfg(target_os = "linux")]
fn parse_kib_field(contents: &str, field: &str) -> Option<u64> {
    let line = contents.lines().find(|line| line.starts_with(field))?;
    let value = line[field.len()..]
        .split_whitespace()
        .next()?
        .parse::<u64>()
        .ok()?;
    value.checked_mul(1024)
}

#[cfg(target_os = "linux")]
fn read_decimal_file(path: &Path) -> Option<u64> {
    fs::read_to_string(path).ok()?.trim().parse::<u64>().ok()
}

#[cfg(target_os = "linux")]
fn cgroup_memory_paths() -> Option<(PathBuf, PathBuf)> {
    let membership = fs::read_to_string("/proc/self/cgroup").ok()?;
    for line in membership.lines() {
        let mut fields = line.splitn(3, ':');
        let _hierarchy = fields.next()?;
        let controllers = fields.next()?;
        let relative = fields.next()?.trim_start_matches('/');
        if controllers.is_empty() {
            let base = Path::new("/sys/fs/cgroup").join(relative);
            return Some((base.join("memory.current"), base.join("memory.max")));
        }
        if controllers
            .split(',')
            .any(|controller| controller == "memory")
        {
            let base = Path::new("/sys/fs/cgroup/memory").join(relative);
            return Some((
                base.join("memory.usage_in_bytes"),
                base.join("memory.limit_in_bytes"),
            ));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Barrier;
    use std::thread;

    #[derive(Debug)]
    struct FixedMemory(Mutex<Result<MemorySample, MemoryProbeError>>);

    impl FixedMemory {
        fn available(used_bytes: u64, limit_bytes: u64) -> Self {
            Self(Mutex::new(Ok(MemorySample::now(used_bytes, limit_bytes))))
        }
    }

    impl MemoryProbe for FixedMemory {
        fn sample(&self) -> Result<MemorySample, MemoryProbeError> {
            *lock(&self.0)
        }
    }

    fn policy(max_connections: u64, threshold: f64, buffer: u32) -> AdmissionPolicy {
        AdmissionPolicy::new(max_connections, threshold, buffer)
            .unwrap_or_else(|error| unreachable!("test policy: {error}"))
    }

    #[test]
    fn unlimited_and_raii_buffer_accounting() {
        let controller = AdmissionController::new(Arc::new(FixedMemory::available(1, 100)));
        let first = controller
            .try_acquire(policy(0, 0.0, 4096))
            .unwrap_or_else(|error| unreachable!("admit: {error}"));
        let second = controller
            .try_acquire(policy(0, 0.0, 4096))
            .unwrap_or_else(|error| unreachable!("admit: {error}"));
        assert_eq!(controller.metrics().active_connections, 2);
        assert_eq!(controller.metrics().connection_buffer_bytes, 16_384);
        drop(first);
        drop(second);
        assert_eq!(controller.metrics().active_connections, 0);
        assert_eq!(controller.metrics().connection_buffer_bytes, 0);
    }

    #[test]
    fn concurrent_max_boundary_is_exact() {
        const WORKERS: usize = 64;
        const LIMIT: u64 = 7;
        let controller = AdmissionController::new(Arc::new(FixedMemory::available(1, 100)));
        let barrier = Arc::new(Barrier::new(WORKERS));
        let mut workers = Vec::new();
        for _ in 0..WORKERS {
            let controller = controller.clone();
            let barrier = Arc::clone(&barrier);
            workers.push(thread::spawn(move || {
                barrier.wait();
                controller.try_acquire(policy(LIMIT, 0.0, 1024)).ok()
            }));
        }
        let permits: Vec<_> = workers
            .into_iter()
            .filter_map(|worker| worker.join().ok().flatten())
            .collect();
        assert_eq!(permits.len() as u64, LIMIT);
        let metrics = controller.metrics();
        assert_eq!(metrics.active_connections, LIMIT);
        assert_eq!(
            metrics.rejected_max_connections_total,
            WORKERS as u64 - LIMIT
        );
        drop(permits);
        assert_eq!(controller.metrics().active_connections, 0);
    }

    #[test]
    fn memory_check_precedes_max_and_tracks_post_sample_buffers() {
        let observed_at = Instant::now();
        let memory = Arc::new(FixedMemory(Mutex::new(Ok(MemorySample {
            used_bytes: 890,
            limit_bytes: 1000,
            observed_at,
        }))));
        let controller = AdmissionController::new(memory);
        let permit = controller
            .try_acquire(policy(1, 0.9, 10 * 1024 / 2))
            .unwrap_or_else(|error| unreachable!("first admit: {error}"));
        // The current buffer delta reaches the threshold, so memory wins even
        // though the max boundary is also full.
        let rejected = controller.try_acquire(policy(1, 0.9, 10 * 1024 / 2));
        assert!(matches!(rejected, Err(AdmissionRejection::Memory { .. })));
        let metrics = controller.metrics();
        assert_eq!(metrics.rejected_memory_total, 1);
        assert_eq!(metrics.rejected_max_connections_total, 0);
        drop(permit);
        assert_eq!(controller.metrics().connection_buffer_bytes, 0);
    }

    #[test]
    fn invalid_or_failed_memory_samples_fail_open() {
        let failed = Arc::new(FixedMemory(Mutex::new(Err(MemoryProbeError::unavailable(
            "test probe failure",
        )))));
        let controller = AdmissionController::new(failed);
        let permit = controller
            .try_acquire(policy(1, 0.9, 1024))
            .unwrap_or_else(|error| unreachable!("probe must fail open: {error}"));
        assert_eq!(controller.metrics().memory_probe_failures_total, 1);
        drop(permit);
    }

    #[test]
    fn policy_boundaries_are_validated() {
        assert!(AdmissionPolicy::new(0, 0.0, 1024).is_ok());
        assert!(AdmissionPolicy::new(1, 0.5, 16 * 1024 * 1024).is_ok());
        assert!(AdmissionPolicy::new(1, 0.49, 1024).is_err());
        assert!(AdmissionPolicy::new(1, f64::NAN, 1024).is_err());
        assert!(AdmissionPolicy::new(1, 0.9, 1023).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_kib_parser_is_bounded() {
        let contents = "Name:\ttiproxy-rs\nVmRSS:\t42 kB\n";
        assert_eq!(parse_kib_field(contents, "VmRSS:"), Some(42 * 1024));
        assert_eq!(parse_kib_field(contents, "VmSize:"), None);
        assert_eq!(
            parse_kib_field("VmRSS: 18446744073709551615 kB", "VmRSS:"),
            None
        );
    }
}
