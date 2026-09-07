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

//! Owner-fenced, bounded raw TCP connector for one backend cluster (CP-TOPO
//! #215-1). Crate-private: it is never exposed outside `control-external`.
//!
//! [`ClusterConnector`] is the cluster-scoped DNS + TCP layer shared by every
//! per-backend probe: the HTTP `/status` probe
//! ([`ClusterHttpClient`](crate::cluster_http::ClusterHttpClient)) layers its
//! TLS handshake and HTTP exchange on top, and the SQL-greeting probe
//! ([`SqlGreetingProbe`](crate::sql_greeting::SqlGreetingProbe)) reads the
//! `MySQL` initial handshake over the raw stream — the greeting precedes
//! `MySQL`'s own TLS negotiation, so the status-port TLS material is never
//! applied to it. It mirrors the cluster-scoped `BackendNetwork.DialContext`
//! seam of Go `observer.DefaultHealthCheck`.
//!
//! One [`ClusterConnector::connect_once`] is a single fenced DNS resolve plus an
//! in-order dial of the bounded candidate set. It carries NO deadline of its own,
//! which is exactly why it is crate-private: each public probe constructs its
//! own connector with ITS stage budget as the resolver budget and bounds every
//! `connect_once` under that same budget (the HTTP probe under its one absolute
//! attempt deadline, the SQL probe under Go's per-stage `DialTimeout`), so no
//! caller outside this crate can ever await it unbounded or pair it with a
//! mismatched resolver budget. Every awaited stage is fenced against the process
//! [`OwnerToken`] AND the caller's source [`GenerationGate`] before and after it
//! runs; a fence failure is TERMINAL and wins over any coincident DNS or I/O
//! error, so a retired owner or a superseded routing source is never reported as
//! a retryable transport failure.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use control_plane::OwnerToken;
use thiserror::Error;
use tokio::net::TcpStream;

use crate::dns_transport::TokioDnsTransport;
use crate::etcd::{EtcdClientConfig, GenerationGate};
use crate::explicit_dns::{Clock, DnsTransport, ExplicitResolver, ResolveError, SystemClock};

/// Upper bound on any single probe stage timeout (the HTTP attempt deadline and
/// the SQL dial/read budget share it): five minutes.
pub(crate) const MAX_PROBE_TIMEOUT: Duration = Duration::from_secs(300);
/// Maximum resolved candidate addresses dialed within one connect, a bounded,
/// order-preserving, de-duplicated subset (mirrors the etcd transport's bounded
/// multi-address fallback).
pub(crate) const MAX_CANDIDATES: usize = 8;

/// A stable single-connect failure class. Each public probe maps it class for
/// class into its own error, whose `is_retryable` partitions terminal from
/// transient.
#[derive(Debug, Error, PartialEq, Eq)]
pub(crate) enum ClusterConnectError {
    /// The process owner or the caller's source generation went stale
    /// mid-connect. Terminal, and it wins over any coincident DNS or I/O error.
    #[error("cluster connect fenced by a stale owner or source generation")]
    Fenced,
    /// DNS resolution failed for a non-stale reason (or yielded no address).
    /// Retryable.
    #[error("cluster connect DNS resolution failed")]
    Dns,
    /// The final exhausted-candidates dial error was connection-refused. Terminal
    /// (mirrors Go `IsRetryableError` treating refused as non-retryable).
    #[error("cluster connect connection refused")]
    ConnectionRefused,
    /// A dial error other than a refused connection. Retryable.
    #[error("cluster connect transport error")]
    Transport,
}

/// An owner-fenced raw TCP connector for one backend cluster's DNS material.
///
/// It privately holds the cluster's explicit-nameserver resolver (absent when no
/// `ns_servers` are configured, falling back to the system resolver) and the
/// process owner token. It carries no TLS: TLS is a property of the protocol
/// layered on top (the HTTP probe), not of the cluster dial. It is reusable
/// across connects within one cluster-material/epoch.
#[derive(Clone)]
pub(crate) struct ClusterConnector {
    owner: OwnerToken,
    resolver: Option<Arc<ExplicitResolver>>,
}

impl ClusterConnector {
    /// Builds a connector from one cluster's etcd client material and the process
    /// owner token.
    ///
    /// When the cluster configures `ns_servers`, an owner-fenced
    /// [`ExplicitResolver`] is built over them with `resolve_budget` as its single
    /// resolution budget; otherwise resolution falls back to the system resolver
    /// and `resolve_budget` is unused (the caller's stage deadline bounds it).
    ///
    /// # Errors
    ///
    /// Returns the [`ResolveError`] of an unbuildable explicit-nameserver
    /// resolver (an invalid budget, too many or non-normalized `ns_servers`).
    pub(crate) fn from_cluster_material(
        config: &EtcdClientConfig,
        owner: OwnerToken,
        resolve_budget: Duration,
    ) -> Result<Self, ResolveError> {
        let resolver = if config.ns_servers().is_empty() {
            None
        } else {
            let transport: Arc<dyn DnsTransport> = Arc::new(TokioDnsTransport);
            let clock: Arc<dyn Clock> = Arc::new(SystemClock);
            Some(Arc::new(ExplicitResolver::new(
                owner.clone(),
                config.ns_servers(),
                transport,
                clock,
                resolve_budget,
            )?))
        };
        Ok(Self { owner, resolver })
    }

    /// Returns `Ok` only while the process owner AND the source generation are
    /// both current. A stale check is a terminal [`ClusterConnectError::Fenced`].
    ///
    /// # Errors
    ///
    /// Returns [`ClusterConnectError::Fenced`] when either is stale.
    pub(crate) fn fence(&self, source_gate: &GenerationGate) -> Result<(), ClusterConnectError> {
        if self.owner.is_current() && source_gate.is_live() {
            Ok(())
        } else {
            Err(ClusterConnectError::Fenced)
        }
    }

    /// Performs ONE fenced resolve-and-dial of `host:port`, returning the raw
    /// plaintext stream. No deadline is applied here; the caller bounds the call.
    ///
    /// A literal-IP `host` dials directly with no wire query; a hostname resolves
    /// through the cluster resolver (or the system resolver) and its bounded
    /// candidate set is dialed in order, falling back candidate by candidate;
    /// only the LAST dial error (after exhaustion) classifies the result.
    ///
    /// # Errors
    ///
    /// Returns [`ClusterConnectError::Fenced`] when the owner or `source_gate` is
    /// stale at any fence (terminal, wins over DNS and I/O), else the DNS or
    /// classified dial failure.
    pub(crate) async fn connect_once(
        &self,
        host: &str,
        port: u16,
        source_gate: &GenerationGate,
    ) -> Result<TcpStream, ClusterConnectError> {
        self.fence(source_gate)?; // pre-DNS
        let candidates = self.resolve(host, port, source_gate).await?;
        self.fence(source_gate)?; // post-DNS
        self.connect(&candidates, source_gate).await
    }

    /// Resolves `host` to a bounded, ordered, de-duplicated candidate set. A
    /// literal IP is a single candidate with no wire query; a hostname resolves
    /// through the cluster resolver (never a second system lookup per candidate)
    /// or the system resolver when no `ns_servers` are configured.
    async fn resolve(
        &self,
        host: &str,
        port: u16,
        source_gate: &GenerationGate,
    ) -> Result<Vec<SocketAddr>, ClusterConnectError> {
        if let Some(ip) = parse_ip_literal(host) {
            return Ok(vec![SocketAddr::new(ip, port)]);
        }
        let resolved: Vec<SocketAddr> = if let Some(resolver) = &self.resolver {
            let outcome = resolver.resolve(host).await;
            // Fence after the resolve await, before classifying: a stale owner or
            // source gate is terminal and wins over any DNS error.
            self.fence(source_gate)?;
            outcome
                .map_err(|_| ClusterConnectError::Dns)?
                .into_iter()
                .map(|ip| SocketAddr::new(ip, port))
                .collect()
        } else {
            let authority = format!("{host}:{port}");
            let outcome = tokio::net::lookup_host(authority).await;
            self.fence(source_gate)?;
            outcome.map_err(|_| ClusterConnectError::Dns)?.collect()
        };
        let candidates = collect_candidates(resolved.into_iter());
        if candidates.is_empty() {
            return Err(ClusterConnectError::Dns);
        }
        Ok(candidates)
    }

    /// Dials the candidate set in order, falling back candidate by candidate;
    /// only the LAST dial error (after exhaustion) classifies the result. Each
    /// candidate's await is fenced before and after.
    async fn connect(
        &self,
        candidates: &[SocketAddr],
        source_gate: &GenerationGate,
    ) -> Result<TcpStream, ClusterConnectError> {
        let mut last_error: Option<std::io::Error> = None;
        for addr in candidates {
            self.fence(source_gate)?; // pre-connect
            let result = TcpStream::connect(*addr).await;
            self.fence(source_gate)?; // post-connect: a fence wins over the I/O result
            match result {
                Ok(stream) => return Ok(stream),
                Err(error) => last_error = Some(error),
            }
        }
        Err(classify_dial_error(last_error.as_ref()))
    }
}

/// Classifies the final exhausted-candidates dial error: a refused connection is
/// terminal, any other transport error is retryable.
fn classify_dial_error(error: Option<&std::io::Error>) -> ClusterConnectError {
    match error {
        Some(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
            ClusterConnectError::ConnectionRefused
        }
        _ => ClusterConnectError::Transport,
    }
}

/// Parses a bare or bracketed IP-literal host.
pub(crate) fn parse_ip_literal(host: &str) -> Option<IpAddr> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Some(ip);
    }
    host.strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .and_then(|inner| inner.parse::<IpAddr>().ok())
}

/// Collects resolved addresses into a bounded, order-preserving, de-duplicated
/// candidate set capped at [`MAX_CANDIDATES`].
fn collect_candidates(resolved: impl Iterator<Item = SocketAddr>) -> Vec<SocketAddr> {
    let mut addrs: Vec<SocketAddr> = Vec::new();
    for addr in resolved {
        if addrs.len() >= MAX_CANDIDATES {
            break;
        }
        if !addrs.contains(&addr) {
            addrs.push(addr);
        }
    }
    addrs
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::time::Duration;

    use tokio::net::TcpListener;
    use tokio::sync::mpsc;

    use super::{ClusterConnectError, ClusterConnector, MAX_CANDIDATES, collect_candidates};
    use crate::etcd::GenerationGate;
    use crate::probe_test_support::{
        ns_config, owner_lease, plaintext_config, spawn_dns, spawn_dns_with_delay,
    };

    /// A whole-test wall-clock bound so a stalled socket trips well inside CI's
    /// patience.
    const TEST_DEADLINE: Duration = Duration::from_secs(5);
    /// The resolver budget handed to the connector in every row.
    const RESOLVE_BUDGET: Duration = Duration::from_secs(2);

    /// A loopback listener that accepts every connection, reporting each accept
    /// on a channel: a positive row awaits the accept structurally, a negative
    /// row asserts the channel is empty (a fenced connect never dials, so no
    /// accept can ever arrive).
    async fn spawn_acceptor() -> (SocketAddr, mpsc::UnboundedReceiver<SocketAddr>) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap_or_else(|error| unreachable!("bind: {error}"));
        let addr = listener
            .local_addr()
            .unwrap_or_else(|error| unreachable!("addr: {error}"));
        let (accepted_tx, accepted_rx) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Ok((_stream, peer)) = listener.accept().await {
                if accepted_tx.send(peer).is_err() {
                    return;
                }
            }
        });
        (addr, accepted_rx)
    }

    /// Awaits the acceptor's report of one accepted connection.
    async fn wait_accepted(accepted: &mut mpsc::UnboundedReceiver<SocketAddr>) {
        tokio::time::timeout(TEST_DEADLINE, accepted.recv())
            .await
            .unwrap_or_else(|_| unreachable!("test deadline"))
            .unwrap_or_else(|| unreachable!("the acceptor is alive"));
    }

    /// A loopback port that nothing listens on (bound, then released).
    async fn closed_port() -> u16 {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap_or_else(|error| unreachable!("bind: {error}"));
        listener
            .local_addr()
            .unwrap_or_else(|error| unreachable!("addr: {error}"))
            .port()
    }

    fn sock(ip: [u8; 4], port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), port)
    }

    // --- candidate collection: collision / bound / order (pure) -----------

    #[test]
    fn candidates_are_deduplicated_order_preserving_and_capped() {
        let resolved = [
            sock([10, 0, 0, 2], 4000),
            sock([10, 0, 0, 1], 4000),
            sock([10, 0, 0, 2], 4000), // collision: an exact duplicate
            sock([10, 0, 0, 1], 4001), // same IP, different port: distinct
        ];
        let candidates = collect_candidates(resolved.into_iter());
        assert_eq!(
            candidates,
            vec![
                sock([10, 0, 0, 2], 4000),
                sock([10, 0, 0, 1], 4000),
                sock([10, 0, 0, 1], 4001)
            ],
            "duplicates collapse, first-seen order is kept"
        );

        let many = (0..20u8).map(|i| sock([10, 0, 1, i], 4000));
        let capped = collect_candidates(many);
        assert_eq!(capped.len(), MAX_CANDIDATES, "the candidate set is capped");
        assert_eq!(
            capped[0],
            sock([10, 0, 1, 0], 4000),
            "the cap keeps the FIRST candidates"
        );
        assert_eq!(capped[MAX_CANDIDATES - 1], sock([10, 0, 1, 7], 4000));
    }

    // --- literal IP: no wire query ---------------------------------------

    #[tokio::test]
    async fn a_literal_ip_dials_directly() {
        let (_registry, lease) = owner_lease();
        let (addr, mut accepted) = spawn_acceptor().await;
        let connector = ClusterConnector::from_cluster_material(
            &plaintext_config(),
            lease.token(),
            RESOLVE_BUDGET,
        )
        .unwrap_or_else(|error| unreachable!("connector: {error}"));
        let gate = GenerationGate::new();
        let stream = tokio::time::timeout(
            TEST_DEADLINE,
            connector.connect_once("127.0.0.1", addr.port(), &gate),
        )
        .await
        .unwrap_or_else(|_| unreachable!("test deadline"))
        .unwrap_or_else(|error| unreachable!("connect: {error}"));
        assert_eq!(
            stream
                .peer_addr()
                .unwrap_or_else(|error| unreachable!("peer: {error}")),
            addr,
            "the raw stream is connected to the literal address"
        );
        wait_accepted(&mut accepted).await;
        drop(stream);
    }

    // --- multi-address fallback through the cluster resolver ---------------

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_dead_candidate_falls_back_to_the_next_resolved_address() {
        let (_registry, lease) = owner_lease();
        let (addr, mut accepted) = spawn_acceptor().await;
        // The nameserver answers AAAA `::1` (nothing listens there on this port,
        // refused) AND A `127.0.0.1` (the acceptor): the dial must fall back.
        let dns_port = spawn_dns(vec![Ipv4Addr::LOCALHOST], vec![Ipv6Addr::LOCALHOST]).await;
        let connector = ClusterConnector::from_cluster_material(
            &ns_config(dns_port, None),
            lease.token(),
            RESOLVE_BUDGET,
        )
        .unwrap_or_else(|error| unreachable!("connector: {error}"));
        let gate = GenerationGate::new();
        let stream = tokio::time::timeout(
            TEST_DEADLINE,
            connector.connect_once("tidb.internal", addr.port(), &gate),
        )
        .await
        .unwrap_or_else(|_| unreachable!("test deadline"))
        .unwrap_or_else(|error| unreachable!("connect: {error}"));
        assert_eq!(
            stream
                .peer_addr()
                .unwrap_or_else(|error| unreachable!("peer: {error}"))
                .ip(),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            "the live candidate was dialed after the dead one"
        );
        wait_accepted(&mut accepted).await;
        drop(stream);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn every_candidate_refused_is_terminal_connection_refused() {
        let (_registry, lease) = owner_lease();
        let port = closed_port().await;
        let dns_port = spawn_dns(vec![Ipv4Addr::LOCALHOST], vec![Ipv6Addr::LOCALHOST]).await;
        let connector = ClusterConnector::from_cluster_material(
            &ns_config(dns_port, None),
            lease.token(),
            RESOLVE_BUDGET,
        )
        .unwrap_or_else(|error| unreachable!("connector: {error}"));
        let gate = GenerationGate::new();
        let result = tokio::time::timeout(
            TEST_DEADLINE,
            connector.connect_once("tidb.internal", port, &gate),
        )
        .await
        .unwrap_or_else(|_| unreachable!("test deadline"));
        let Err(error) = result else {
            unreachable!("a closed port cannot be dialed")
        };
        assert_eq!(error, ClusterConnectError::ConnectionRefused);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn no_resolved_address_is_a_retryable_dns_failure() {
        let (_registry, lease) = owner_lease();
        let dns_port = spawn_dns(vec![], vec![]).await;
        let connector = ClusterConnector::from_cluster_material(
            &ns_config(dns_port, None),
            lease.token(),
            RESOLVE_BUDGET,
        )
        .unwrap_or_else(|error| unreachable!("connector: {error}"));
        let gate = GenerationGate::new();
        let result = tokio::time::timeout(
            TEST_DEADLINE,
            connector.connect_once("tidb.internal", 4000, &gate),
        )
        .await
        .unwrap_or_else(|_| unreachable!("test deadline"));
        assert_eq!(result.err(), Some(ClusterConnectError::Dns));
    }

    // --- generation revoke races: the fence wins over DNS and I/O ----------

    #[tokio::test]
    async fn a_revoked_owner_is_fenced_before_any_io() {
        let (_registry, lease) = owner_lease();
        let (addr, mut accepted) = spawn_acceptor().await;
        let connector = ClusterConnector::from_cluster_material(
            &plaintext_config(),
            lease.token(),
            RESOLVE_BUDGET,
        )
        .unwrap_or_else(|error| unreachable!("connector: {error}"));
        drop(lease); // the owner retires before the connect starts
        let gate = GenerationGate::new();
        let result = connector
            .connect_once("127.0.0.1", addr.port(), &gate)
            .await;
        assert_eq!(result.err(), Some(ClusterConnectError::Fenced));
        assert!(accepted.try_recv().is_err(), "a fenced connect never dials");
    }

    #[tokio::test]
    async fn a_revoked_source_gate_wins_over_a_refused_dial() {
        let (_registry, lease) = owner_lease();
        let port = closed_port().await;
        let connector = ClusterConnector::from_cluster_material(
            &plaintext_config(),
            lease.token(),
            RESOLVE_BUDGET,
        )
        .unwrap_or_else(|error| unreachable!("connector: {error}"));
        let gate = GenerationGate::new();
        gate.revoke();
        let result = connector.connect_once("127.0.0.1", port, &gate).await;
        assert_eq!(
            result.err(),
            Some(ClusterConnectError::Fenced),
            "the fence is checked before the dial, so refused is never observed"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_source_revoked_during_resolution_is_fenced_not_dialed() {
        let (_registry, lease) = owner_lease();
        let (addr, mut accepted) = spawn_acceptor().await;
        // The nameserver answers correctly, but only after a delay long enough
        // for the gate to be revoked mid-resolve.
        let dns_port = spawn_dns_with_delay(
            vec![Ipv4Addr::LOCALHOST],
            vec![],
            Duration::from_millis(300),
        )
        .await;
        let connector = ClusterConnector::from_cluster_material(
            &ns_config(dns_port, None),
            lease.token(),
            RESOLVE_BUDGET,
        )
        .unwrap_or_else(|error| unreachable!("connector: {error}"));
        let gate = std::sync::Arc::new(GenerationGate::new());
        let revoker = std::sync::Arc::clone(&gate);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            revoker.revoke();
        });
        let result = tokio::time::timeout(
            TEST_DEADLINE,
            connector.connect_once("tidb.internal", addr.port(), &gate),
        )
        .await
        .unwrap_or_else(|_| unreachable!("test deadline"));
        assert_eq!(
            result.err(),
            Some(ClusterConnectError::Fenced),
            "a revoke landing during the DNS await is terminal and wins over the valid answer"
        );
        assert!(
            accepted.try_recv().is_err(),
            "the resolved address is never dialed once the source is stale"
        );
    }
}
