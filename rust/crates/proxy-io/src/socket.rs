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

//! TCP listen, dial, keepalive, and socket policy (WIRE-06).
//!
//! The Go references are `pkg/proxy/proxy.go` (multi-address listeners and
//! actual bound-address reporting), `pkg/proxy/backend/backend_conn_mgr.go`
//! (dial timeout/backoff constants and healthy/unhealthy keepalive switching),
//! and `pkg/proxy/keepalive/` (platform socket options). Semantics preserved
//! bug-for-bug where observable:
//!
//! - `TCP_USER_TIMEOUT` is applied even when keepalive probing is disabled,
//!   exactly like Go's `setTimeout` running outside the `Enabled` branch.
//! - Zero idle/interval/probe values are skipped rather than treated as
//!   errors, matching Go's `val > 0` guards.
//! - `TCP_NODELAY` is enabled on every configured stream: Go inherits this
//!   from the Go runtime's default, while Tokio does not set it, so it must
//!   be explicit here to keep latency behavior identical.
//!
//! Platform policy: Linux implements the full keepalive contract. Other Unix
//! systems apply the portable subset through `socket2` and report which knobs
//! were skipped. Non-Unix platforms return a diagnostic error instead of
//! silently proxying with wrong socket policy.

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::net::{TcpListener, TcpStream, lookup_host};
use tokio::time::{Instant, sleep, timeout};

use crate::proxy_protocol::{
    FIXED_HEADER_LEN, MAGIC_V2, MagicSniff, ProxyAddresses, ProxyCommand, ProxyV2Decode,
    ProxyVersion, decode_after_magic, sniff_magic,
};
use crate::pump::PumpCancellation;

/// Go `DialTimeout`: budget for one connect attempt.
pub const DIAL_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(1);
/// Go `ConnectTimeout`: total budget across attempts and backoff.
pub const DIAL_TOTAL_TIMEOUT: Duration = Duration::from_secs(15);
/// Go backoff initial interval.
pub const BACKOFF_INITIAL: Duration = Duration::from_millis(100);
/// Go backoff maximum interval.
pub const BACKOFF_MAX: Duration = Duration::from_secs(4);
/// Go backoff multiplier.
pub const BACKOFF_MULTIPLIER: f64 = 2.0;
/// Go backoff randomization factor.
pub const BACKOFF_RANDOMIZATION: f64 = 0.5;

/// Typed socket-policy failures.
#[derive(Debug, thiserror::Error)]
pub enum SocketError {
    /// Binding one listener address failed.
    #[error("failed to bind {address}: {source}")]
    Bind {
        /// The address that failed to bind.
        address: SocketAddr,
        /// Underlying error.
        #[source]
        source: io::Error,
    },
    /// Resolving or dialing the target failed on the final attempt.
    #[error("failed to dial {target}: {source}")]
    Dial {
        /// The dial target.
        target: String,
        /// Underlying error from the last attempt.
        #[source]
        source: io::Error,
    },
    /// The total dial budget elapsed before a connection succeeded.
    #[error("dial {target} exceeded total budget {budget:?}")]
    DialBudgetExceeded {
        /// The dial target.
        target: String,
        /// The configured total budget.
        budget: Duration,
    },
    /// The caller cancelled the dial.
    #[error("dial {target} cancelled")]
    Cancelled {
        /// The dial target.
        target: String,
    },
    /// Applying socket options failed.
    #[error("failed to apply socket policy ({detail}): {source}")]
    Policy {
        /// Which option failed.
        detail: &'static str,
        /// Underlying error.
        #[source]
        source: io::Error,
    },
    /// The platform cannot express the requested socket policy.
    #[error("socket policy unsupported on this platform: {feature}")]
    UnsupportedPlatform {
        /// The missing capability.
        feature: &'static str,
    },
    /// Reading a PROXY protocol header failed.
    #[error("failed to read PROXY header: {source}")]
    ProxyHeader {
        /// Underlying error.
        #[source]
        source: io::Error,
    },
    /// The peer did not complete a promised PROXY header within the deadline.
    #[error("PROXY header timed out after {deadline:?}")]
    ProxyHeaderTimeout {
        /// The configured deadline.
        deadline: Duration,
    },
}

/// Keepalive policy for one stream, mirroring Go `config.KeepAlive`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeepalivePolicy {
    /// Whether keepalive probing is enabled (`SO_KEEPALIVE`).
    pub enabled: bool,
    /// Idle time before the first probe; zero is skipped like Go.
    pub idle: Duration,
    /// Probe count; zero is skipped like Go.
    pub probes: u32,
    /// Interval between probes; zero is skipped like Go.
    pub interval: Duration,
    /// `TCP_USER_TIMEOUT`; applied even when probing is disabled, like Go.
    pub user_timeout: Duration,
}

impl KeepalivePolicy {
    /// Go `DefaultKeepAlive` frontend policy: enabled, everything else unset.
    #[must_use]
    pub const fn frontend_default() -> Self {
        Self {
            enabled: true,
            idle: Duration::ZERO,
            probes: 0,
            interval: Duration::ZERO,
            user_timeout: Duration::ZERO,
        }
    }

    /// Go `DefaultKeepAlive` healthy-backend policy (conservative).
    #[must_use]
    pub const fn backend_healthy_default() -> Self {
        Self {
            enabled: true,
            idle: Duration::from_secs(60),
            probes: 5,
            interval: Duration::from_secs(3),
            user_timeout: Duration::from_secs(15),
        }
    }

    /// Go `DefaultKeepAlive` unhealthy-backend policy (aggressive).
    #[must_use]
    pub const fn backend_unhealthy_default() -> Self {
        Self {
            enabled: true,
            idle: Duration::from_secs(10),
            probes: 5,
            interval: Duration::from_secs(1),
            user_timeout: Duration::from_secs(5),
        }
    }
}

/// One bound listener with its OS-reported local address.
#[derive(Debug)]
pub struct BoundListener {
    /// The listening socket. Dropping it releases pending accepts.
    pub listener: TcpListener,
    /// The actual bound address; ephemeral requests report the real port.
    pub actual_address: SocketAddr,
}

/// Binds every requested address, reporting actual bound ports.
///
/// Matches Go `NewSQLServer`: all listeners bind up front, an ephemeral port
/// (`:0`) reports its real value, and any single failure aborts the whole set
/// (already-bound listeners drop and release their sockets).
///
/// # Errors
///
/// Returns the first bind failure with its address.
pub async fn bind_listeners(addresses: &[SocketAddr]) -> Result<Vec<BoundListener>, SocketError> {
    let mut bound = Vec::with_capacity(addresses.len());
    for &address in addresses {
        let listener = TcpListener::bind(address)
            .await
            .map_err(|source| SocketError::Bind { address, source })?;
        let actual_address = listener
            .local_addr()
            .map_err(|source| SocketError::Bind { address, source })?;
        bound.push(BoundListener {
            listener,
            actual_address,
        });
    }
    Ok(bound)
}

/// Dial policy; defaults mirror the Go constants exactly.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DialPolicy {
    /// Budget for one connect attempt.
    pub attempt_timeout: Duration,
    /// Total budget across resolution, attempts, and backoff.
    pub total_timeout: Duration,
    /// First backoff interval.
    pub backoff_initial: Duration,
    /// Maximum backoff interval.
    pub backoff_max: Duration,
    /// Backoff growth factor.
    pub multiplier: f64,
    /// Randomization factor in `[0, 1]`; zero makes backoff deterministic.
    pub randomization: f64,
}

impl Default for DialPolicy {
    fn default() -> Self {
        Self {
            attempt_timeout: DIAL_ATTEMPT_TIMEOUT,
            total_timeout: DIAL_TOTAL_TIMEOUT,
            backoff_initial: BACKOFF_INITIAL,
            backoff_max: BACKOFF_MAX,
            multiplier: BACKOFF_MULTIPLIER,
            randomization: BACKOFF_RANDOMIZATION,
        }
    }
}

/// Dials `target` (`host:port`; cluster-specific DNS input is resolved per
/// attempt) with per-attempt timeout and exponential backoff.
///
/// Cancellation through `cancel` stops the dial immediately, including while
/// sleeping between attempts. The stream is returned unconfigured; apply
/// [`configure_stream`] and a [`KeepalivePolicy`] before use.
///
/// # Errors
///
/// Returns a typed cancel, budget, resolution, or connect error.
pub async fn dial_with_backoff(
    target: &str,
    policy: DialPolicy,
    cancel: &PumpCancellation,
) -> Result<TcpStream, SocketError> {
    let started = Instant::now();
    let deadline = started + policy.total_timeout;
    let mut backoff = policy.backoff_initial;
    // Per-dial jitter seed: a shared fixed seed would synchronize backoff
    // across connections and defeat the thundering-herd randomization that
    // Go's backoff provides. Randomization 0 disables jitter entirely.
    let mut jitter_state = next_dial_seed();
    let mut cancelled = cancel.subscribe();
    let mut last_error: Option<io::Error> = None;

    loop {
        if *cancelled.borrow() {
            return Err(SocketError::Cancelled {
                target: target.to_owned(),
            });
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(budget_error(target, policy, last_error));
        }

        let attempt_budget = policy.attempt_timeout.min(remaining);
        let attempt = async {
            let mut resolve_error: Option<io::Error> = None;
            let addresses = match lookup_host(target).await {
                Ok(addresses) => addresses.collect::<Vec<_>>(),
                Err(error) => {
                    resolve_error = Some(error);
                    Vec::new()
                }
            };
            let mut connect_error = resolve_error;
            for address in addresses {
                match TcpStream::connect(address).await {
                    Ok(stream) => return Ok(stream),
                    Err(error) => connect_error = Some(error),
                }
            }
            Err(connect_error
                .unwrap_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no address resolved")))
        };
        let outcome = tokio::select! {
            biased;
            changed = cancelled.changed() => {
                let _ = changed;
                return Err(SocketError::Cancelled { target: target.to_owned() });
            }
            outcome = timeout(attempt_budget, attempt) => outcome,
        };
        match outcome {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(error)) => last_error = Some(error),
            Err(_) => {
                last_error = Some(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("connect attempt exceeded {attempt_budget:?}"),
                ));
            }
        }

        // Exponential backoff with optional bounded jitter, capped like Go.
        let sleep_for = jittered(backoff, policy.randomization, &mut jitter_state);
        let sleep_for = sleep_for.min(deadline.saturating_duration_since(Instant::now()));
        if sleep_for.is_zero() {
            return Err(budget_error(target, policy, last_error));
        }
        tokio::select! {
            biased;
            changed = cancelled.changed() => {
                let _ = changed;
                return Err(SocketError::Cancelled { target: target.to_owned() });
            }
            () = sleep(sleep_for) => {}
        }
        backoff = Duration::from_secs_f64(
            (backoff.as_secs_f64() * policy.multiplier).min(policy.backoff_max.as_secs_f64()),
        );
    }
}

fn budget_error(target: &str, policy: DialPolicy, last_error: Option<io::Error>) -> SocketError {
    last_error.map_or(
        SocketError::DialBudgetExceeded {
            target: target.to_owned(),
            budget: policy.total_timeout,
        },
        |source| SocketError::Dial {
            target: target.to_owned(),
            source,
        },
    )
}

static DIAL_SEED: AtomicU64 = AtomicU64::new(0x9e37_79b9_7f4a_7c15);

/// Returns a distinct odd seed per dial without a global RNG dependency.
fn next_dial_seed() -> u64 {
    DIAL_SEED
        .fetch_add(0x9e37_79b9_7f4a_7c15, Ordering::Relaxed)
        .wrapping_mul(0x2545_f491_4f6c_dd1d)
        | 1
}

/// Bounded multiplicative jitter without a global RNG: xorshift over the
/// caller-scoped state, scaled into `[1 - r, 1 + r]` like Go's backoff.
fn jittered(base: Duration, randomization: f64, state: &mut u64) -> Duration {
    if randomization <= 0.0 {
        return base;
    }
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    let bits = u32::try_from(*state >> 32).unwrap_or(0);
    let unit = f64::from(bits) / f64::from(u32::MAX);
    let factor = 2.0_f64.mul_add(randomization * unit, 1.0 - randomization);
    Duration::from_secs_f64(base.as_secs_f64() * factor)
}

/// Applies the universal stream policy: `TCP_NODELAY` on.
///
/// Go gets `TCP_NODELAY` from the runtime default; Tokio does not, so this
/// must be called on every accepted and dialed stream.
///
/// # Errors
///
/// Returns a typed policy error.
pub fn configure_stream(stream: &TcpStream) -> Result<(), SocketError> {
    stream
        .set_nodelay(true)
        .map_err(|source| SocketError::Policy {
            detail: "TCP_NODELAY",
            source,
        })
}

/// Observable keepalive state read back from the socket, for health-switch
/// verification and diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeepaliveReadback {
    /// Whether `SO_KEEPALIVE` is enabled.
    pub enabled: bool,
    /// `TCP_KEEPIDLE` when readable on this platform.
    pub idle: Option<Duration>,
    /// `TCP_KEEPINTVL` when readable on this platform.
    pub interval: Option<Duration>,
    /// `TCP_KEEPCNT` when readable on this platform.
    pub probes: Option<u32>,
    /// `TCP_USER_TIMEOUT` when readable on this platform (Linux).
    pub user_timeout: Option<Duration>,
}

#[cfg(unix)]
mod keepalive_unix {
    use super::{Duration, KeepalivePolicy, KeepaliveReadback, SocketError};
    use socket2::{SockRef, TcpKeepalive};
    use tokio::net::TcpStream;

    /// Applies keepalive with Go semantics on Unix platforms.
    pub fn apply(stream: &TcpStream, policy: KeepalivePolicy) -> Result<(), SocketError> {
        let socket = SockRef::from(stream);
        socket
            .set_keepalive(policy.enabled)
            .map_err(|source| SocketError::Policy {
                detail: "SO_KEEPALIVE",
                source,
            })?;
        if policy.enabled {
            let mut keepalive = TcpKeepalive::new();
            // Go skips zero values instead of erroring; mirror that.
            if !policy.idle.is_zero() {
                keepalive = keepalive.with_time(policy.idle);
            }
            if !policy.interval.is_zero() {
                keepalive = keepalive.with_interval(policy.interval);
            }
            #[cfg(not(target_os = "windows"))]
            if policy.probes > 0 {
                keepalive = keepalive.with_retries(policy.probes);
            }
            socket
                .set_tcp_keepalive(&keepalive)
                .map_err(|source| SocketError::Policy {
                    detail: "TCP keepalive parameters",
                    source,
                })?;
        }
        // Go applies the user timeout even when probing is disabled.
        #[cfg(target_os = "linux")]
        if !policy.user_timeout.is_zero() {
            socket
                .set_tcp_user_timeout(Some(policy.user_timeout))
                .map_err(|source| SocketError::Policy {
                    detail: "TCP_USER_TIMEOUT",
                    source,
                })?;
        }
        // Go's darwin build maps the timeout to TCP_RXT_CONNDROPTIME; this
        // crate forbids unsafe code and socket2 exposes no equivalent, so a
        // nonzero request must fail with a diagnostic instead of silently
        // succeeding with weaker semantics.
        #[cfg(not(target_os = "linux"))]
        if !policy.user_timeout.is_zero() {
            return Err(SocketError::UnsupportedPlatform {
                feature: "TCP_USER_TIMEOUT (Go darwin uses TCP_RXT_CONNDROPTIME; \
                          not exposed without unsafe code on this platform)",
            });
        }
        Ok(())
    }

    /// Reads back observable keepalive state.
    pub fn read(stream: &TcpStream) -> Result<KeepaliveReadback, SocketError> {
        let socket = SockRef::from(stream);
        let enabled = socket.keepalive().map_err(|source| SocketError::Policy {
            detail: "SO_KEEPALIVE readback",
            source,
        })?;
        let idle: Option<Duration> = socket.tcp_keepalive_time().ok();
        let interval: Option<Duration> = socket.tcp_keepalive_interval().ok();
        let probes: Option<u32> = socket.tcp_keepalive_retries().ok();
        #[cfg(target_os = "linux")]
        let user_timeout: Option<Duration> = socket.tcp_user_timeout().ok().flatten();
        #[cfg(not(target_os = "linux"))]
        let user_timeout: Option<Duration> = None;
        Ok(KeepaliveReadback {
            enabled,
            idle,
            interval,
            probes,
            user_timeout,
        })
    }
}

/// Applies a keepalive policy to a TCP stream.
///
/// Linux implements the full Go contract (`TCP_KEEPIDLE`/`CNT`/`INTVL` plus
/// `TCP_USER_TIMEOUT` even when probing is disabled). Other Unix systems
/// apply the portable subset; the user-timeout knob silently has no effect
/// there today, matching the reality that Go's darwin variant uses different
/// constants. Non-Unix platforms return a diagnostic error.
///
/// # Errors
///
/// Returns a typed policy or platform error.
pub fn apply_keepalive(stream: &TcpStream, policy: KeepalivePolicy) -> Result<(), SocketError> {
    #[cfg(unix)]
    {
        keepalive_unix::apply(stream, policy)
    }
    #[cfg(not(unix))]
    {
        let _ = (stream, policy);
        Err(SocketError::UnsupportedPlatform {
            feature: "TCP keepalive policy",
        })
    }
}

/// Reads back observable keepalive state for verification and diagnostics.
///
/// # Errors
///
/// Returns a typed policy or platform error.
pub fn read_keepalive(stream: &TcpStream) -> Result<KeepaliveReadback, SocketError> {
    #[cfg(unix)]
    {
        keepalive_unix::read(stream)
    }
    #[cfg(not(unix))]
    {
        let _ = stream;
        Err(SocketError::UnsupportedPlatform {
            feature: "TCP keepalive readback",
        })
    }
}

/// A PROXY v2 header read from a live socket, with owned data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedProxyHeader {
    /// Raw version nibble.
    pub version: ProxyVersion,
    /// Raw command nibble.
    pub command: ProxyCommand,
    /// Recovered source address, when the header carried one.
    pub source: Option<SocketAddr>,
    /// Recovered destination address, when the header carried one.
    pub destination: Option<SocketAddr>,
    /// Owned TLVs in wire order.
    pub tlvs: Vec<(u8, Vec<u8>)>,
}

/// Result of probing a live socket for a PROXY v2 header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyProbeOutcome {
    /// The decoded header, when the client sent one.
    pub header: Option<OwnedProxyHeader>,
    /// Application bytes consumed by the probe that belong to the `MySQL`
    /// stream. Empty when disabled or when a header was consumed exactly;
    /// nonempty only for a non-PROXY client, whose probed bytes must be
    /// replayed (for example through [`crate::tls::PrefixedIo`]) before the
    /// stream is used.
    pub replay: Vec<u8>,
}

/// Probes a live socket for a PROXY v2 header.
///
/// Mechanics match Go `pkg/proxy/net/proxy.go`: a four-byte probe decides
/// most non-PROXY clients, then the full magic confirms, then exactly the
/// header is consumed. Like Go's `bufio` peek — which also consumes from the
/// kernel into a userspace buffer and replays it — a non-PROXY client's
/// probed bytes are returned in `replay` so the application stream remains
/// byte-identical. Reads block for data instead of spinning on readiness,
/// so a slow or stalled client is bounded by `deadline` without burning CPU.
///
/// - `enabled == false`: nothing is read — zero bytes touched, empty replay.
/// - Enabled, non-PROXY client: probed bytes are returned for replay; the
///   stream carries the rest untouched.
/// - Enabled, PROXY client: exactly the header is consumed; empty replay.
///
/// # Errors
///
/// Returns a typed I/O or timeout error. A malformed-but-decodable header is
/// tolerated exactly as leniently as the codec (WIRE-05 semantics).
pub async fn read_proxy_header_if_present(
    stream: &mut TcpStream,
    enabled: bool,
    deadline: Duration,
) -> Result<ProxyProbeOutcome, SocketError> {
    if !enabled {
        return Ok(ProxyProbeOutcome {
            header: None,
            replay: Vec::new(),
        });
    }
    let result = timeout(deadline, read_proxy_header_inner(stream)).await;
    match result {
        Ok(inner) => inner,
        Err(_) => Err(SocketError::ProxyHeaderTimeout { deadline }),
    }
}

async fn read_proxy_header_inner(stream: &mut TcpStream) -> Result<ProxyProbeOutcome, SocketError> {
    use tokio::io::AsyncReadExt;

    // Go probes four bytes first to avoid waiting for a full magic when the
    // client never sends one. read_exact parks until data arrives, so there
    // is no readiness spin and the outer deadline stays enforceable.
    let mut probe = [0_u8; FIXED_HEADER_LEN];
    stream
        .read_exact(&mut probe)
        .await
        .map_err(|source| SocketError::ProxyHeader { source })?;
    if probe != MAGIC_V2[..FIXED_HEADER_LEN] {
        return Ok(ProxyProbeOutcome {
            header: None,
            replay: probe.to_vec(),
        });
    }
    let mut magic = [0_u8; MAGIC_V2.len()];
    magic[..FIXED_HEADER_LEN].copy_from_slice(&probe);
    stream
        .read_exact(&mut magic[FIXED_HEADER_LEN..])
        .await
        .map_err(|source| SocketError::ProxyHeader { source })?;
    if sniff_magic(&magic) != MagicSniff::Proxy {
        return Ok(ProxyProbeOutcome {
            header: None,
            replay: magic.to_vec(),
        });
    }

    // Confirmed PROXY: consume the fixed header, then the declared body.
    let mut fixed = [0_u8; FIXED_HEADER_LEN];
    stream
        .read_exact(&mut fixed)
        .await
        .map_err(|source| SocketError::ProxyHeader { source })?;
    let body_length = usize::from(u16::from_be_bytes([fixed[2], fixed[3]]));
    let mut wire = Vec::with_capacity(FIXED_HEADER_LEN + body_length);
    wire.extend_from_slice(&fixed);
    wire.resize(FIXED_HEADER_LEN + body_length, 0);
    stream
        .read_exact(&mut wire[FIXED_HEADER_LEN..])
        .await
        .map_err(|source| SocketError::ProxyHeader { source })?;

    match decode_after_magic(&wire) {
        ProxyV2Decode::Done { header, .. } => {
            let (source, destination) = match header.addresses {
                ProxyAddresses::Inet { src, dst } => {
                    (Some(SocketAddr::from(src)), Some(SocketAddr::from(dst)))
                }
                ProxyAddresses::Inet6 { src, dst } => {
                    (Some(SocketAddr::from(src)), Some(SocketAddr::from(dst)))
                }
                ProxyAddresses::Unix { .. } | ProxyAddresses::None => (None, None),
            };
            Ok(ProxyProbeOutcome {
                header: Some(OwnedProxyHeader {
                    version: header.version,
                    command: header.command,
                    source,
                    destination,
                    tlvs: header
                        .tlvs
                        .iter()
                        .map(|tlv| (tlv.type_byte, tlv.content.to_vec()))
                        .collect(),
                }),
                replay: Vec::new(),
            })
        }
        ProxyV2Decode::Incomplete { .. } => Err(SocketError::ProxyHeader {
            source: io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "declared PROXY body was not delivered",
            ),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dial_seeds_differ_and_zero_randomization_is_deterministic() {
        let first = next_dial_seed();
        let second = next_dial_seed();
        assert_ne!(first, second, "each dial must get a distinct jitter seed");

        // With randomization 0 the jitter is the identity regardless of seed.
        let mut state_a = first;
        let mut state_b = second;
        let base = Duration::from_millis(100);
        assert_eq!(jittered(base, 0.0, &mut state_a), base);
        assert_eq!(jittered(base, 0.0, &mut state_b), base);

        // With randomization on, distinct seeds produce distinct sequences
        // bounded inside [1 - r, 1 + r].
        let mut state_a = first;
        let mut state_b = second;
        let sequence_a: Vec<Duration> = (0..4).map(|_| jittered(base, 0.5, &mut state_a)).collect();
        let sequence_b: Vec<Duration> = (0..4).map(|_| jittered(base, 0.5, &mut state_b)).collect();
        assert_ne!(sequence_a, sequence_b, "sequences must not synchronize");
        for value in sequence_a.iter().chain(sequence_b.iter()) {
            assert!(*value >= base / 2 && *value <= base * 3 / 2);
        }
    }
}
