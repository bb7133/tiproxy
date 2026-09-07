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

//! Owner-fenced, single-attempt `MySQL` initial-handshake ("SQL greeting")
//! probe for one backend cluster (CP-TOPO #215-1).
//!
//! [`SqlGreetingProbe`] mirrors the SQL-port half of Go
//! `observer.DefaultHealthCheck.checkSqlPort` + `pnet.CheckSqlPort`
//! (`pkg/balance/observer/health_check.go`, `pkg/proxy/net/mysql.go`): it dials
//! the backend's SQL address over the cluster's raw TCP connector — no TLS, the
//! greeting precedes `MySQL`'s own TLS negotiation — and applies Go's MINIMAL
//! criterion to the server's first packet: after the complete four-byte packet
//! header, ONLY the first payload byte is read and judged; `0xff` (an `ERR`
//! packet, e.g. too-many-connections) is a failed greeting and any other first
//! byte is a live SQL layer. The `HandshakeV10` payload is never parsed, and
//! nothing is ever allocated or read according to the declared payload length,
//! so a hostile or huge declared length costs exactly five bytes.
//!
//! Go's two per-stage budgets are kept distinct, not merged into one absolute
//! deadline: the dial (DNS + connect) gets one full `DialTimeout`, and after a
//! successful dial the read deadline is set to a FRESH full `DialTimeout`. Retry
//! and backoff live in the policy layer above (`control-topology`); one
//! [`SqlGreetingProbe::check_once`] is exactly one attempt and never retries.
//!
//! Fail-closed divergence from Go: an empty first payload (declared length zero)
//! is [`SqlGreetingError::EmptyGreeting`], where Go would index past the empty
//! packet; a truncated header or first byte is the same `EOF`-shaped
//! [`SqlGreetingError::Transport`] Go reports. Every awaited stage is fenced
//! against the process owner AND the caller's source [`GenerationGate`]; a
//! fence failure is terminal and wins over any coincident I/O error.

use std::time::Duration;

use mysql_wire::{PacketHeader, ResponseHeader};
use thiserror::Error;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

use control_plane::OwnerToken;

use crate::cluster_connect::{ClusterConnectError, ClusterConnector, MAX_PROBE_TIMEOUT};
use crate::etcd::{EtcdClientConfig, GenerationGate};
use crate::explicit_dns::ResolveError;

/// A build-time rejection of the SQL-greeting probe policy or material.
#[derive(Debug, Error)]
pub enum SqlGreetingConfigError {
    /// The dial timeout is zero or over the five-minute probe bound. Checked
    /// before any resolver is built.
    #[error("invalid SQL greeting dial timeout {0:?}")]
    InvalidDialTimeout(Duration),
    /// The cluster's explicit-nameserver resolver could not be built.
    #[error("SQL greeting probe explicit nameserver resolver could not be built")]
    Resolver(#[source] ResolveError),
}

/// A stable single-attempt SQL-greeting failure class.
///
/// [`Self::is_retryable`] partitions the classes exactly as Go's
/// `IsRetryableError` does for this probe: only a refused connection (and a
/// fence, which Go has no equivalent of) is terminal; a DNS failure, a
/// transport/read error, a timeout, and an `ERR` first packet are all retried
/// by the policy layer.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum SqlGreetingError {
    /// The process owner or the caller's source generation went stale
    /// mid-attempt. Terminal, and it wins over any coincident I/O error.
    #[error("SQL greeting probe fenced by a stale owner or source generation")]
    Fenced,
    /// DNS resolution failed for a non-stale reason. Retryable.
    #[error("SQL greeting probe DNS resolution failed")]
    Dns,
    /// The final exhausted-candidates dial error was connection-refused.
    /// Terminal (Go treats refused as non-retryable).
    #[error("SQL greeting probe connection refused")]
    ConnectionRefused,
    /// A dial or read error other than a refused connection, including a
    /// connection closed before the header and first byte arrived. Retryable.
    #[error("SQL greeting probe transport error")]
    Transport,
    /// The dial budget or the fresh read budget elapsed. Retryable.
    #[error("SQL greeting probe deadline elapsed")]
    Timeout,
    /// The server's first packet is an `ERR` packet (`0xff`): the SQL layer
    /// answered but refused the session. Retryable (Go: "read initial handshake
    /// error", retried under the same budget).
    #[error("SQL greeting probe read an ERR packet as the initial handshake")]
    ErrGreeting,
    /// The server's first packet declares an empty payload, so it carries no
    /// header byte to judge. Terminal (a protocol violation; Go would panic).
    #[error("SQL greeting probe read an empty initial packet")]
    EmptyGreeting,
}

impl SqlGreetingError {
    /// Whether the policy layer may retry this failure.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::Dns | Self::Transport | Self::Timeout | Self::ErrGreeting
        )
    }
}

impl From<ClusterConnectError> for SqlGreetingError {
    fn from(error: ClusterConnectError) -> Self {
        match error {
            ClusterConnectError::Fenced => Self::Fenced,
            ClusterConnectError::Dns => Self::Dns,
            ClusterConnectError::ConnectionRefused => Self::ConnectionRefused,
            ClusterConnectError::Transport => Self::Transport,
        }
    }
}

/// An owner-fenced, single-attempt SQL-greeting probe for one backend cluster's
/// material and generation. Reusable across probes within one
/// cluster-material/epoch.
#[derive(Clone)]
pub struct SqlGreetingProbe {
    connector: ClusterConnector,
    dial_timeout: Duration,
}

impl SqlGreetingProbe {
    /// Builds the probe from one cluster's etcd client material, the process
    /// owner token, and Go's `DialTimeout`, which bounds the dial stage and,
    /// separately and afresh, the read stage.
    ///
    /// The cluster's raw connector is built HERE, with this same `dial_timeout`
    /// as its explicit-nameserver resolution budget, so Go's "DNS + connect share
    /// one whole `DialTimeout`" holds by construction: no caller can pair the
    /// probe with a connector whose resolver budget is shorter than the dial
    /// budget. The status-port TLS material is deliberately not consulted.
    ///
    /// # Errors
    ///
    /// Returns [`SqlGreetingConfigError::InvalidDialTimeout`] when
    /// `dial_timeout` is zero or above the five-minute probe bound (checked
    /// before any resolver is built), or
    /// [`SqlGreetingConfigError::Resolver`] when the cluster's explicit
    /// nameservers cannot form a resolver.
    pub fn from_cluster_material(
        config: &EtcdClientConfig,
        owner: OwnerToken,
        dial_timeout: Duration,
    ) -> Result<Self, SqlGreetingConfigError> {
        if dial_timeout.is_zero() || dial_timeout > MAX_PROBE_TIMEOUT {
            return Err(SqlGreetingConfigError::InvalidDialTimeout(dial_timeout));
        }
        let connector = ClusterConnector::from_cluster_material(config, owner, dial_timeout)
            .map_err(SqlGreetingConfigError::Resolver)?;
        Ok(Self {
            connector,
            dial_timeout,
        })
    }

    /// Performs ONE greeting attempt against `host:port`: a fenced resolve-and-
    /// dial under one full `dial_timeout`, then the first-packet judgement under
    /// a FRESH full `dial_timeout`. The connection is dropped (closed) on every
    /// return, as Go closes it.
    ///
    /// # Errors
    ///
    /// Returns a [`SqlGreetingError`]: [`Fenced`](SqlGreetingError::Fenced) when
    /// the owner or `source_gate` is stale (terminal, wins over I/O),
    /// [`Timeout`](SqlGreetingError::Timeout) when either stage budget elapses,
    /// or the DNS / dial / read / first-packet failure classified by
    /// [`SqlGreetingError::is_retryable`].
    pub async fn check_once(
        &self,
        host: &str,
        port: u16,
        source_gate: &GenerationGate,
    ) -> Result<(), SqlGreetingError> {
        let dialed = tokio::time::timeout(
            self.dial_timeout,
            self.connector.connect_once(host, port, source_gate),
        )
        .await;
        let mut stream = match dialed {
            Ok(result) => result?,
            Err(_elapsed) => {
                // A revoke coincident with the deadline is terminal and wins over
                // the timeout classification.
                self.connector.fence(source_gate)?;
                return Err(SqlGreetingError::Timeout);
            }
        };
        match tokio::time::timeout(
            self.dial_timeout,
            self.judge_first_packet(&mut stream, source_gate),
        )
        .await
        {
            Ok(result) => result,
            Err(_elapsed) => {
                self.connector.fence(source_gate)?;
                Err(SqlGreetingError::Timeout)
            }
        }
    }

    /// Go `pnet.CheckSqlPort`'s minimal criterion: the complete four-byte header,
    /// then exactly the first payload byte. Each read is fenced after its await
    /// so a stale owner/source wins over the I/O outcome.
    async fn judge_first_packet(
        &self,
        stream: &mut TcpStream,
        source_gate: &GenerationGate,
    ) -> Result<(), SqlGreetingError> {
        let mut header = [0u8; mysql_wire::PHYSICAL_PACKET_HEADER_LEN];
        let read = stream.read_exact(&mut header).await;
        self.connector.fence(source_gate)?;
        read.map_err(|_| SqlGreetingError::Transport)?;
        let header = PacketHeader::decode(&header).map_err(|_| SqlGreetingError::Transport)?;
        if header.payload_length() == 0 {
            return Err(SqlGreetingError::EmptyGreeting);
        }
        let mut first = [0u8; 1];
        let read = stream.read_exact(&mut first).await;
        self.connector.fence(source_gate)?;
        read.map_err(|_| SqlGreetingError::Transport)?;
        if ResponseHeader::from_byte(first[0]) == ResponseHeader::ERROR {
            return Err(SqlGreetingError::ErrGreeting);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;
    use tokio::sync::Notify;

    use super::{SqlGreetingConfigError, SqlGreetingError, SqlGreetingProbe};
    use crate::cluster_connect::{ClusterConnectError, MAX_PROBE_TIMEOUT};
    use crate::etcd::GenerationGate;
    use crate::probe_test_support::{
        ns_config, owner_lease, plaintext_config, spawn_dns_with_delay,
    };

    /// A whole-test wall-clock bound so a stalled socket trips well inside CI's
    /// patience. The probe's own dial timeout is shorter still.
    const TEST_DEADLINE: Duration = Duration::from_secs(5);
    /// Go `DialTimeout` for the rows below (short, so the timeout rows are fast).
    const DIAL_TIMEOUT: Duration = Duration::from_millis(250);

    /// What the scripted loopback `MySQL` server sends as its first packet.
    #[derive(Clone)]
    enum Greeting {
        /// A `HandshakeV10`-shaped packet: header + `0x0a` + a few payload bytes.
        V10,
        /// An `ERR` packet: header + `0xff` + a code and message (as `TiDB` sends
        /// for too-many-connections before any handshake).
        Err,
        /// Accept, then never write.
        Hang,
        /// Only the four-byte header, then close.
        CloseAfterHeader,
        /// A header declaring a ZERO-length payload.
        Empty,
        /// A header declaring the maximum payload length (16 MiB - 1) followed by
        /// ONE byte `0x0a`, then the connection is held open with nothing more.
        HugeLengthOneByte,
        /// The `V10` packet, but written only after `delay`.
        DelayedV10(Duration),
        /// Header first; then wait for the test's `release`; then the `0x0a` byte.
        ByteAfterRelease(Arc<Notify>),
    }

    /// A single-frame packet: the real four-byte header (via `mysql-wire`) for a
    /// payload of `first` followed by `rest`, sequence 0.
    fn packet(first: u8, rest: &[u8]) -> Vec<u8> {
        let len = u32::try_from(1 + rest.len()).unwrap_or_else(|_| unreachable!("tiny"));
        let header = mysql_wire::PacketHeader::new(len, 0)
            .unwrap_or_else(|error| unreachable!("header: {error}"));
        let mut bytes = header.encode().to_vec();
        bytes.push(first);
        bytes.extend_from_slice(rest);
        bytes
    }

    /// Spawns a loopback server answering every connection per `greeting`.
    async fn spawn_greeter(greeting: Greeting) -> SocketAddr {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap_or_else(|error| unreachable!("bind: {error}"));
        let addr = listener
            .local_addr()
            .unwrap_or_else(|error| unreachable!("addr: {error}"));
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _peer)) = listener.accept().await else {
                    return;
                };
                let script = greeting.clone();
                tokio::spawn(async move {
                    match script {
                        Greeting::V10 => {
                            let _ = stream.write_all(&packet(0x0a, b"8.0.11-TiDB\0")).await;
                        }
                        Greeting::Err => {
                            let _ = stream
                                .write_all(&packet(0xff, b"\x14\x04#08004Too many connections"))
                                .await;
                        }
                        Greeting::Hang => {
                            std::future::pending::<()>().await;
                        }
                        Greeting::CloseAfterHeader => {
                            let _ = stream.write_all(&[5, 0, 0, 0]).await;
                            let _ = stream.shutdown().await;
                        }
                        Greeting::Empty => {
                            let _ = stream.write_all(&[0, 0, 0, 0]).await;
                            std::future::pending::<()>().await;
                        }
                        Greeting::HugeLengthOneByte => {
                            let _ = stream.write_all(&[0xff, 0xff, 0xff, 0, 0x0a]).await;
                            std::future::pending::<()>().await;
                        }
                        Greeting::DelayedV10(delay) => {
                            tokio::time::sleep(delay).await;
                            let _ = stream.write_all(&packet(0x0a, b"8.0.11-TiDB\0")).await;
                        }
                        Greeting::ByteAfterRelease(release) => {
                            let _ = stream.write_all(&[5, 0, 0, 0]).await;
                            release.notified().await;
                            let _ = stream.write_all(b"\x0a").await;
                            std::future::pending::<()>().await;
                        }
                    }
                });
            }
        });
        addr
    }

    /// A probe over a plaintext, system-resolver cluster at `DIAL_TIMEOUT`.
    fn plaintext_probe(owner: control_plane::OwnerToken) -> SqlGreetingProbe {
        SqlGreetingProbe::from_cluster_material(&plaintext_config(), owner, DIAL_TIMEOUT)
            .unwrap_or_else(|error| unreachable!("probe: {error}"))
    }

    /// One literal-IP attempt against a scripted greeter, with its wall time.
    async fn check_literal(greeting: Greeting) -> (Result<(), SqlGreetingError>, Duration) {
        let (_registry, lease) = owner_lease();
        let addr = spawn_greeter(greeting).await;
        let probe = plaintext_probe(lease.token());
        let gate = GenerationGate::new();
        let started = Instant::now();
        let result = tokio::time::timeout(
            TEST_DEADLINE,
            probe.check_once("127.0.0.1", addr.port(), &gate),
        )
        .await
        .unwrap_or_else(|_| unreachable!("test deadline"));
        (result, started.elapsed())
    }

    // --- policy and classification ----------------------------------------

    // --- construction: the ONLY public entry, bounded by construction --------

    #[test]
    fn construction_rejects_a_zero_or_overbound_dial_timeout_before_any_resolver() {
        let (_registry, lease) = owner_lease();
        // An explicit-NS config whose resolver WOULD build: the timeout check
        // must reject first, so the resolver is never constructed.
        let config = ns_config(1, None);
        assert!(matches!(
            SqlGreetingProbe::from_cluster_material(&config, lease.token(), Duration::ZERO),
            Err(SqlGreetingConfigError::InvalidDialTimeout(timeout)) if timeout.is_zero()
        ));
        let over = MAX_PROBE_TIMEOUT + Duration::from_secs(1);
        assert!(matches!(
            SqlGreetingProbe::from_cluster_material(&config, lease.token(), over),
            Err(SqlGreetingConfigError::InvalidDialTimeout(timeout)) if timeout == over
        ));
        assert!(
            SqlGreetingProbe::from_cluster_material(&config, lease.token(), MAX_PROBE_TIMEOUT)
                .is_ok(),
            "the bound itself is accepted"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_resolver_budget_is_the_dial_timeout_by_construction() {
        // The nameserver answers only after 0.8 x DialTimeout. A connector built
        // with ANY shorter resolver budget would fail DNS; because the public
        // constructor uses the dial timeout itself as the budget, it succeeds.
        let (_registry, lease) = owner_lease();
        let addr = spawn_greeter(Greeting::V10).await;
        let dns_port =
            spawn_dns_with_delay(vec![Ipv4Addr::LOCALHOST], vec![], DIAL_TIMEOUT.mul_f32(0.8))
                .await;
        let probe = SqlGreetingProbe::from_cluster_material(
            &ns_config(dns_port, None),
            lease.token(),
            DIAL_TIMEOUT,
        )
        .unwrap_or_else(|error| unreachable!("probe: {error}"));
        let gate = GenerationGate::new();
        let result = tokio::time::timeout(
            TEST_DEADLINE,
            probe.check_once("tidb.internal", addr.port(), &gate),
        )
        .await
        .unwrap_or_else(|_| unreachable!("test deadline"));
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn is_retryable_mirrors_go_only_refused_and_fenced_are_terminal() {
        for retryable in [
            SqlGreetingError::Dns,
            SqlGreetingError::Transport,
            SqlGreetingError::Timeout,
            SqlGreetingError::ErrGreeting,
        ] {
            assert!(retryable.is_retryable(), "{retryable:?}");
        }
        for terminal in [
            SqlGreetingError::Fenced,
            SqlGreetingError::ConnectionRefused,
            SqlGreetingError::EmptyGreeting,
        ] {
            assert!(!terminal.is_retryable(), "{terminal:?}");
        }
    }

    #[test]
    fn connect_errors_map_class_for_class() {
        assert_eq!(
            SqlGreetingError::from(ClusterConnectError::Fenced),
            SqlGreetingError::Fenced
        );
        assert_eq!(
            SqlGreetingError::from(ClusterConnectError::Dns),
            SqlGreetingError::Dns
        );
        assert_eq!(
            SqlGreetingError::from(ClusterConnectError::ConnectionRefused),
            SqlGreetingError::ConnectionRefused
        );
        assert_eq!(
            SqlGreetingError::from(ClusterConnectError::Transport),
            SqlGreetingError::Transport
        );
    }

    // --- Go's minimal criterion on the first packet -------------------------

    #[tokio::test]
    async fn a_handshake_v10_first_byte_is_a_live_sql_layer() {
        let (result, _elapsed) = check_literal(Greeting::V10).await;
        assert_eq!(result, Ok(()));
    }

    #[tokio::test]
    async fn an_err_first_packet_is_a_retryable_failed_greeting() {
        let (result, _elapsed) = check_literal(Greeting::Err).await;
        assert_eq!(result, Err(SqlGreetingError::ErrGreeting));
    }

    #[tokio::test]
    async fn a_hung_greeting_times_out_under_the_fresh_read_budget() {
        let (result, elapsed) = check_literal(Greeting::Hang).await;
        assert_eq!(result, Err(SqlGreetingError::Timeout));
        assert!(
            elapsed >= DIAL_TIMEOUT && elapsed < DIAL_TIMEOUT * 4,
            "the read budget is one dial timeout (took {elapsed:?})"
        );
    }

    #[tokio::test]
    async fn a_refused_dial_is_terminal_connection_refused() {
        let (_registry, lease) = owner_lease();
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap_or_else(|error| unreachable!("bind: {error}"));
        let port = listener
            .local_addr()
            .unwrap_or_else(|error| unreachable!("addr: {error}"))
            .port();
        drop(listener);
        let probe = plaintext_probe(lease.token());
        let gate = GenerationGate::new();
        let started = Instant::now();
        let result = probe.check_once("127.0.0.1", port, &gate).await;
        assert_eq!(result, Err(SqlGreetingError::ConnectionRefused));
        assert!(
            started.elapsed() < DIAL_TIMEOUT,
            "refused short-circuits: no budget is waited out"
        );
    }

    #[tokio::test]
    async fn a_close_after_the_header_is_a_retryable_transport_failure() {
        let (result, _elapsed) = check_literal(Greeting::CloseAfterHeader).await;
        assert_eq!(result, Err(SqlGreetingError::Transport));
    }

    #[tokio::test]
    async fn an_empty_first_packet_fails_closed() {
        let (result, elapsed) = check_literal(Greeting::Empty).await;
        assert_eq!(result, Err(SqlGreetingError::EmptyGreeting));
        assert!(
            elapsed < DIAL_TIMEOUT,
            "an empty packet is judged on its header, without waiting for a byte"
        );
    }

    #[tokio::test]
    async fn a_huge_declared_length_costs_exactly_one_payload_byte() {
        // The server declares 16 MiB - 1 and sends ONE byte, then holds the
        // connection open forever: a probe that allocated or read by the declared
        // length would time out; the minimal criterion returns at once.
        let (result, elapsed) = check_literal(Greeting::HugeLengthOneByte).await;
        assert_eq!(result, Ok(()));
        assert!(
            elapsed < DIAL_TIMEOUT / 2,
            "judged on the first byte alone (took {elapsed:?})"
        );
    }

    // --- Go's two per-stage budgets are distinct, not one absolute deadline --

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_read_budget_is_fresh_after_a_slow_dial() {
        // DNS answers after 0.6 x DialTimeout and the greeting arrives 0.6 x
        // DialTimeout after connect: 1.2 x DialTimeout in total. One shared
        // absolute deadline would time out; Go's per-stage budgets succeed.
        let (_registry, lease) = owner_lease();
        let stage = DIAL_TIMEOUT.mul_f32(0.6);
        let addr = spawn_greeter(Greeting::DelayedV10(stage)).await;
        let dns_port = spawn_dns_with_delay(vec![Ipv4Addr::LOCALHOST], vec![], stage).await;
        let probe = SqlGreetingProbe::from_cluster_material(
            &ns_config(dns_port, None),
            lease.token(),
            DIAL_TIMEOUT,
        )
        .unwrap_or_else(|error| unreachable!("probe: {error}"));
        let gate = GenerationGate::new();
        let started = Instant::now();
        let result = tokio::time::timeout(
            TEST_DEADLINE,
            probe.check_once("tidb.internal", addr.port(), &gate),
        )
        .await
        .unwrap_or_else(|_| unreachable!("test deadline"));
        assert_eq!(result, Ok(()), "took {:?}", started.elapsed());
        assert!(
            started.elapsed() >= stage * 2,
            "both stages genuinely elapsed (took {:?})",
            started.elapsed()
        );
    }

    #[tokio::test]
    async fn a_greeting_slower_than_one_dial_timeout_times_out() {
        let (result, elapsed) = check_literal(Greeting::DelayedV10(DIAL_TIMEOUT * 2)).await;
        assert_eq!(result, Err(SqlGreetingError::Timeout));
        assert!(elapsed >= DIAL_TIMEOUT && elapsed < DIAL_TIMEOUT * 2);
    }

    // --- generation revoke races: the fence wins over the read outcome ------

    #[tokio::test]
    async fn a_source_revoked_between_the_header_and_the_first_byte_is_fenced() {
        let (_registry, lease) = owner_lease();
        let release = Arc::new(Notify::new());
        let addr = spawn_greeter(Greeting::ByteAfterRelease(Arc::clone(&release))).await;
        let probe = plaintext_probe(lease.token());
        let gate = Arc::new(GenerationGate::new());
        let revoker = Arc::clone(&gate);
        tokio::spawn(async move {
            // Let the header land and the probe park on the first byte, then
            // revoke and release the byte: the byte is a valid V10 header, but
            // the fence after the read must win.
            tokio::time::sleep(Duration::from_millis(50)).await;
            revoker.revoke();
            release.notify_one();
        });
        let result = tokio::time::timeout(
            TEST_DEADLINE,
            probe.check_once("127.0.0.1", addr.port(), &gate),
        )
        .await
        .unwrap_or_else(|_| unreachable!("test deadline"));
        assert_eq!(
            result,
            Err(SqlGreetingError::Fenced),
            "a stale source is terminal even though the greeting itself was valid"
        );
    }

    #[tokio::test]
    async fn a_revoked_owner_is_fenced_before_any_dial() {
        let (_registry, lease) = owner_lease();
        let addr = spawn_greeter(Greeting::V10).await;
        let probe = plaintext_probe(lease.token());
        drop(lease);
        let gate = GenerationGate::new();
        let result = probe.check_once("127.0.0.1", addr.port(), &gate).await;
        assert_eq!(result, Err(SqlGreetingError::Fenced));
    }
}
