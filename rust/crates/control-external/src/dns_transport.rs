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

//! The production socket transport for [`ExplicitResolver`].
//!
//! [`TokioDnsTransport`] supplies the real UDP/TCP I/O and nameserver-hostname
//! bootstrap that back the frozen resolver state machine in
//! [`crate::explicit_dns`]. This module owns only sockets and wire framing; the
//! query/validation/cache/owner-fence logic stays in the resolver.
//!
//! Every stage consumes the single absolute deadline the resolver established at
//! the leader start: bind/connect/send and the whole TCP connect/write/read run
//! under one [`tokio::time::timeout_at`] anchored on that instant, never a fresh
//! per-stage timeout. The target host is resolved exclusively through the
//! explicit nameservers; the system resolver is used only to bootstrap a
//! nameserver *hostname* (mirroring Go's plain `net.Dialer`).

use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Instant;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::{Instant as TokioInstant, timeout_at};

use crate::explicit_dns::{DnsTransport, TransportError, UdpDatagram, UdpExchange};

/// A boxed, `Send` future matching the resolver's injectable transport seams.
type BoxFut<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// One over EDNS0's advertised 1232-byte UDP buffer, so an oversize datagram is
/// received truncated (`len > 1232`) and rejected by the resolver rather than
/// silently parsed.
const UDP_RECV_BUFFER_BYTES: usize = 1233;

/// The production DNS transport: connected-UDP send, a length-framed TCP
/// exchange, and system-resolver nameserver bootstrap.
#[derive(Debug, Default)]
pub(crate) struct TokioDnsTransport;

impl DnsTransport for TokioDnsTransport {
    fn udp_open(
        &self,
        server: SocketAddr,
        query: Vec<u8>,
        deadline: Instant,
    ) -> BoxFut<'static, Result<Box<dyn UdpExchange>, TransportError>> {
        Box::pin(async move {
            // bind -> connect -> send all share the single absolute deadline.
            let opened = timeout_at(TokioInstant::from_std(deadline), async move {
                let bind: SocketAddr = if server.is_ipv4() {
                    SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
                } else {
                    SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))
                };
                let socket = UdpSocket::bind(bind)
                    .await
                    .map_err(|_| TransportError::Unavailable)?;
                // Connected UDP: the kernel drops datagrams from any other peer,
                // pinning the source. `recv_from` still reports the real source
                // so the resolver's source check stays a genuine comparison.
                socket
                    .connect(server)
                    .await
                    .map_err(|_| TransportError::Unavailable)?;
                socket
                    .send(&query)
                    .await
                    .map_err(|_| TransportError::Unavailable)?;
                Ok::<Box<dyn UdpExchange>, TransportError>(Box::new(TokioUdpExchange { socket }))
            })
            .await;
            match opened {
                Ok(result) => result,
                Err(_elapsed) => Err(TransportError::Timeout),
            }
        })
    }

    fn tcp_exchange(
        &self,
        server: SocketAddr,
        query: Vec<u8>,
        deadline: Instant,
    ) -> BoxFut<'static, Result<Vec<u8>, TransportError>> {
        Box::pin(async move {
            let exchanged = timeout_at(TokioInstant::from_std(deadline), async move {
                let mut stream = TcpStream::connect(server)
                    .await
                    .map_err(|_| TransportError::Unavailable)?;
                stream
                    .set_nodelay(true)
                    .map_err(|_| TransportError::Unavailable)?;
                // Two-byte big-endian length prefix, then the query.
                let len = u16::try_from(query.len()).map_err(|_| TransportError::Unavailable)?;
                stream
                    .write_all(&len.to_be_bytes())
                    .await
                    .map_err(|_| TransportError::Unavailable)?;
                stream
                    .write_all(&query)
                    .await
                    .map_err(|_| TransportError::Unavailable)?;
                let mut len_buf = [0u8; 2];
                stream
                    .read_exact(&mut len_buf)
                    .await
                    .map_err(|_| TransportError::Unavailable)?;
                let response_len = usize::from(u16::from_be_bytes(len_buf));
                let mut payload = vec![0u8; response_len];
                stream
                    .read_exact(&mut payload)
                    .await
                    .map_err(|_| TransportError::Unavailable)?;
                Ok::<Vec<u8>, TransportError>(payload)
            })
            .await;
            match exchanged {
                Ok(result) => result,
                Err(_elapsed) => Err(TransportError::Timeout),
            }
        })
    }

    fn bootstrap(
        &self,
        host: Arc<str>,
        port: u16,
        deadline: Instant,
    ) -> BoxFut<'static, Result<Vec<IpAddr>, TransportError>> {
        Box::pin(async move {
            let authority = format!("{host}:{port}");
            // The one allowed system-resolver use: a *nameserver* hostname, run
            // on a blocking thread but bounded by the shared absolute deadline.
            let resolved = timeout_at(
                TokioInstant::from_std(deadline),
                tokio::task::spawn_blocking(move || {
                    authority
                        .to_socket_addrs()
                        .map(|addrs| addrs.map(|addr| addr.ip()).collect::<Vec<IpAddr>>())
                }),
            )
            .await;
            match resolved {
                Ok(Ok(Ok(addrs))) => Ok(addrs),
                Ok(Ok(Err(_)) | Err(_)) => Err(TransportError::Unavailable),
                Err(_elapsed) => Err(TransportError::Timeout),
            }
        })
    }
}

/// A bound, connected UDP socket for one nameserver attempt.
struct TokioUdpExchange {
    /// The connected UDP socket. Being connected, the kernel pins the source to
    /// the nameserver; `recv_from` still reports the real source so the
    /// resolver's own source check remains a genuine comparison.
    socket: UdpSocket,
}

impl UdpExchange for TokioUdpExchange {
    fn recv(&mut self, deadline: Instant) -> BoxFut<'_, Result<UdpDatagram, TransportError>> {
        Box::pin(async move {
            let mut buffer = vec![0u8; UDP_RECV_BUFFER_BYTES];
            let received = timeout_at(
                TokioInstant::from_std(deadline),
                self.socket.recv_from(&mut buffer),
            )
            .await;
            match received {
                Ok(Ok((len, source))) => {
                    buffer.truncate(len);
                    Ok(UdpDatagram {
                        source,
                        payload: buffer,
                    })
                }
                Ok(Err(_)) => Err(TransportError::Unavailable),
                Err(_elapsed) => Err(TransportError::Timeout),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use control_plane::{OwnerScope, OwnerToken, OwnershipRegistry};
    use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
    use hickory_proto::rr::rdata::A;
    use hickory_proto::rr::{Name, RData, Record, RecordType};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, UdpSocket};
    use tokio::sync::Notify;
    use tokio::task::JoinHandle;

    use super::TokioDnsTransport;
    use crate::explicit_dns::{Clock, DnsTransport, ExplicitResolver, ResolveError, SystemClock};

    /// The logical target the loopback nameserver answers for.
    const TARGET: &str = "svc.test";
    /// A target whose name never resolves through the system resolver, so its
    /// only resolution path is the explicit nameserver (the row-5 bootstrap row).
    const TARGET_INVALID: &str = "svc.invalid";
    /// The whole-test wall-clock bound: any real socket stall trips this well
    /// inside CI's patience, and the resolver's own budget is shorter still.
    const TEST_DEADLINE: Duration = Duration::from_secs(5);
    /// The resolver's single absolute resolution budget for these rows.
    const RESOLVE_BUDGET: Duration = Duration::from_secs(5);

    /// How the loopback nameserver answers the target's `A` query over UDP.
    #[derive(Clone, Copy)]
    enum AAnswer {
        /// A full, non-truncated `A <ip>`.
        Full(Ipv4Addr),
        /// A truncated (`TC=1`) `A <ip>` carrying a bogus address, so a live
        /// resolver must discard it and escalate to TCP.
        Truncated(Ipv4Addr),
    }

    /// The scripted behavior of one loopback nameserver instance.
    #[derive(Clone)]
    struct Behavior {
        /// The UDP `A` answer shape.
        udp_a: AAnswer,
        /// The full `A` address served over TCP (a truncation escalation target).
        tcp_a: Option<Ipv4Addr>,
        /// When present, the first UDP query parks here until the test releases it.
        gate: Option<Arc<Notify>>,
        /// When present, signalled once the first UDP query is received.
        arrived: Option<Arc<Notify>>,
    }

    impl Behavior {
        /// The default: a full UDP `A 127.0.0.1`, no TCP answer, no gate.
        fn full() -> Self {
            Self {
                udp_a: AAnswer::Full(Ipv4Addr::LOCALHOST),
                tcp_a: None,
                gate: None,
                arrived: None,
            }
        }
    }

    /// Separate UDP/TCP query counters, shared across the v4 and v6 listeners.
    #[derive(Default)]
    struct Counters {
        /// UDP `A` queries observed.
        udp_a: AtomicUsize,
        /// UDP `AAAA` queries observed.
        udp_aaaa: AtomicUsize,
        /// TCP queries observed.
        tcp: AtomicUsize,
    }

    /// A running loopback nameserver: the shared read-back port, its counters, and
    /// the detached listener tasks kept alive for the test's lifetime.
    struct DnsServer {
        /// The single UDP+TCP port (bound on both loopback families).
        port: u16,
        /// The per-protocol query counters.
        counters: Arc<Counters>,
        /// Detached listener tasks; dropped (not aborted) at test end.
        _tasks: Vec<JoinHandle<()>>,
    }

    /// Decodes a query datagram into `(id, qname, qtype)`.
    fn decode(bytes: &[u8]) -> Option<(u16, Name, RecordType)> {
        let message = Message::from_vec(bytes).ok()?;
        let query = message.queries.first()?;
        Some((message.id, query.name().clone(), query.query_type()))
    }

    /// Encodes an authoritative `A` response, optionally truncated.
    fn encode_a(id: u16, qname: &Name, ip: Ipv4Addr, truncated: bool) -> Vec<u8> {
        let mut message = Message::new(id, MessageType::Response, OpCode::Query);
        message.metadata.authoritative = true;
        message.metadata.truncation = truncated;
        message.metadata.response_code = ResponseCode::NoError;
        message.add_query(Query::query(qname.clone(), RecordType::A));
        let octets = ip.octets();
        message.add_answer(Record::from_rdata(
            qname.clone(),
            30,
            RData::A(A::new(octets[0], octets[1], octets[2], octets[3])),
        ));
        message
            .to_vec()
            .unwrap_or_else(|error| unreachable!("encode a: {error}"))
    }

    /// Encodes an authoritative, SOA-free NODATA (empty NOERROR) response, which
    /// the resolver returns but never caches — used for the `AAAA` family.
    fn encode_nodata(id: u16, qname: &Name, qtype: RecordType) -> Vec<u8> {
        let mut message = Message::new(id, MessageType::Response, OpCode::Query);
        message.metadata.authoritative = true;
        message.metadata.response_code = ResponseCode::NoError;
        message.add_query(Query::query(qname.clone(), qtype));
        message
            .to_vec()
            .unwrap_or_else(|error| unreachable!("encode nodata: {error}"))
    }

    /// Builds the UDP reply for one decoded query, bumping the matching counter.
    fn udp_reply(
        behavior: &Behavior,
        counters: &Counters,
        id: u16,
        qname: &Name,
        qtype: RecordType,
    ) -> Vec<u8> {
        match qtype {
            RecordType::A => {
                counters.udp_a.fetch_add(1, Ordering::SeqCst);
                match behavior.udp_a {
                    AAnswer::Full(ip) => encode_a(id, qname, ip, false),
                    AAnswer::Truncated(ip) => encode_a(id, qname, ip, true),
                }
            }
            RecordType::AAAA => {
                counters.udp_aaaa.fetch_add(1, Ordering::SeqCst);
                encode_nodata(id, qname, qtype)
            }
            other => encode_nodata(id, qname, other),
        }
    }

    /// The UDP responder loop: parks the first query on the gate (if any), then
    /// answers every query, replying from the same socket so the connected-UDP
    /// source pin holds.
    async fn udp_task(socket: UdpSocket, behavior: Behavior, counters: Arc<Counters>) {
        let mut buffer = vec![0u8; 2048];
        let mut gated = behavior.gate.is_some();
        loop {
            let Ok((len, src)) = socket.recv_from(&mut buffer).await else {
                return;
            };
            let Some((id, qname, qtype)) = decode(&buffer[..len]) else {
                continue;
            };
            let reply = udp_reply(&behavior, &counters, id, &qname, qtype);
            if let Some(arrived) = &behavior.arrived {
                arrived.notify_one();
            }
            if gated {
                if let Some(gate) = &behavior.gate {
                    gate.notified().await;
                }
                gated = false;
            }
            let _ = socket.send_to(&reply, src).await;
        }
    }

    /// The TCP responder loop: length-framed, one full `A` (or NODATA) per query.
    async fn tcp_task(listener: TcpListener, behavior: Behavior, counters: Arc<Counters>) {
        loop {
            let Ok((mut stream, _peer)) = listener.accept().await else {
                return;
            };
            let behavior = behavior.clone();
            let counters = Arc::clone(&counters);
            tokio::spawn(async move {
                let mut len_buf = [0u8; 2];
                if stream.read_exact(&mut len_buf).await.is_err() {
                    return;
                }
                let len = usize::from(u16::from_be_bytes(len_buf));
                let mut body = vec![0u8; len];
                if stream.read_exact(&mut body).await.is_err() {
                    return;
                }
                let Some((id, qname, qtype)) = decode(&body) else {
                    return;
                };
                counters.tcp.fetch_add(1, Ordering::SeqCst);
                let reply = match (qtype, behavior.tcp_a) {
                    (RecordType::A, Some(ip)) => encode_a(id, &qname, ip, false),
                    _ => encode_nodata(id, &qname, qtype),
                };
                let Ok(out_len) = u16::try_from(reply.len()) else {
                    return;
                };
                if stream.write_all(&out_len.to_be_bytes()).await.is_err() {
                    return;
                }
                let _ = stream.write_all(&reply).await;
            });
        }
    }

    /// Binds a loopback nameserver: UDP on `127.0.0.1:0` to learn the port `P`,
    /// then UDP and TCP on both `127.0.0.1:P` and `[::1]:P` (the v6 bind is
    /// best-effort, so a hostname nameserver that resolves to `::1` is answered
    /// promptly rather than timing out).
    async fn spawn_dns(behavior: Behavior) -> DnsServer {
        let counters = Arc::new(Counters::default());
        let v4_udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap_or_else(|error| unreachable!("bind udp v4: {error}"));
        let port = v4_udp
            .local_addr()
            .unwrap_or_else(|error| unreachable!("udp addr: {error}"))
            .port();
        let v4_tcp = TcpListener::bind((Ipv4Addr::LOCALHOST, port))
            .await
            .unwrap_or_else(|error| unreachable!("bind tcp v4: {error}"));

        let mut tasks = Vec::new();
        tasks.push(tokio::spawn(udp_task(
            v4_udp,
            behavior.clone(),
            Arc::clone(&counters),
        )));
        tasks.push(tokio::spawn(tcp_task(
            v4_tcp,
            behavior.clone(),
            Arc::clone(&counters),
        )));

        // Best-effort v6 loopback on the same port so a `localhost`-resolved
        // nameserver (`::1` first in rotation) never stalls the AAAA family.
        if let Ok(v6_udp) = UdpSocket::bind((Ipv6Addr::LOCALHOST, port)).await {
            tasks.push(tokio::spawn(udp_task(
                v6_udp,
                behavior.clone(),
                Arc::clone(&counters),
            )));
        }
        if let Ok(v6_tcp) = TcpListener::bind((Ipv6Addr::LOCALHOST, port)).await {
            tasks.push(tokio::spawn(tcp_task(
                v6_tcp,
                behavior.clone(),
                Arc::clone(&counters),
            )));
        }

        DnsServer {
            port,
            counters,
            _tasks: tasks,
        }
    }

    fn owner() -> (OwnershipRegistry, control_plane::OwnerLease, OwnerToken) {
        let registry = OwnershipRegistry::new();
        let lease = registry
            .claim(OwnerScope::Process, "dns-transport-owner")
            .unwrap_or_else(|error| unreachable!("claim: {error}"));
        let token = lease.token();
        (registry, lease, token)
    }

    /// Builds a resolver over the REAL [`TokioDnsTransport`] and system clock.
    fn build_real_resolver(token: OwnerToken, ns: &[Arc<str>]) -> ExplicitResolver {
        ExplicitResolver::new(
            token,
            ns,
            Arc::new(TokioDnsTransport) as Arc<dyn DnsTransport>,
            Arc::new(SystemClock) as Arc<dyn Clock>,
            RESOLVE_BUDGET,
        )
        .unwrap_or_else(|error| unreachable!("resolver: {error}"))
    }

    fn ns_literal(port: u16) -> Arc<str> {
        Arc::from(format!("127.0.0.1:{port}").as_str())
    }

    // ---------------------------------------------------------------------
    // Row 1: a literal-IP host is emitted directly with ZERO wire queries.
    // ---------------------------------------------------------------------
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn row1_literal_ip_host_bypasses_the_wire() {
        let finished = tokio::time::timeout(TEST_DEADLINE, async {
            let server = spawn_dns(Behavior::full()).await;
            let (_registry, _lease, token) = owner();
            let ns = ns_literal(server.port);
            let resolver = build_real_resolver(token, std::slice::from_ref(&ns));

            let result = resolver.resolve("127.0.0.1").await;
            assert_eq!(
                result,
                Ok(vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]),
                "a literal IP resolves to itself"
            );
            // A literal host must not issue any wire query: if the production
            // literal bypass regressed to a wire lookup, these counts would rise.
            assert_eq!(server.counters.udp_a.load(Ordering::SeqCst), 0);
            assert_eq!(server.counters.udp_aaaa.load(Ordering::SeqCst), 0);
            assert_eq!(server.counters.tcp.load(Ordering::SeqCst), 0);
        })
        .await;
        assert!(finished.is_ok(), "row1 must finish within the deadline");
    }

    // ---------------------------------------------------------------------
    // Row 2: a truncated UDP answer is discarded and TCP supplies the address.
    // ---------------------------------------------------------------------
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn row2_truncated_udp_escalates_to_tcp() {
        let finished = tokio::time::timeout(TEST_DEADLINE, async {
            let bogus = Ipv4Addr::new(10, 99, 99, 99);
            let real = Ipv4Addr::LOCALHOST;
            let behavior = Behavior {
                udp_a: AAnswer::Truncated(bogus),
                tcp_a: Some(real),
                ..Behavior::full()
            };
            let server = spawn_dns(behavior).await;
            let (_registry, _lease, token) = owner();
            let ns = ns_literal(server.port);
            let resolver = build_real_resolver(token, std::slice::from_ref(&ns));

            let result = resolver.resolve(TARGET).await;
            let Ok(addrs) = result else {
                unreachable!("row2 resolve must succeed: {result:?}");
            };
            assert!(
                addrs.contains(&IpAddr::V4(real)),
                "the address is the one served over TCP"
            );
            assert!(
                !addrs.contains(&IpAddr::V4(bogus)),
                "the truncated UDP answer's bogus address is discarded"
            );
            assert!(
                server.counters.udp_a.load(Ordering::SeqCst) >= 1,
                "the UDP A query ran first"
            );
            assert_eq!(
                server.counters.tcp.load(Ordering::SeqCst),
                1,
                "the truncated answer escalated to exactly one TCP query"
            );
        })
        .await;
        assert!(finished.is_ok(), "row2 must finish within the deadline");
    }

    // ---------------------------------------------------------------------
    // Row 3: each generation/resolver holds its own cache — no cross reuse.
    // ---------------------------------------------------------------------
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn row3_new_generation_does_not_reuse_prior_cache() {
        let finished = tokio::time::timeout(TEST_DEADLINE, async {
            let server = spawn_dns(Behavior::full()).await;
            let ns = ns_literal(server.port);

            let (_registry_a, _lease_a, token_a) = owner();
            let resolver_a = build_real_resolver(token_a, std::slice::from_ref(&ns));
            let first = resolver_a.resolve(TARGET).await;
            assert_eq!(first, Ok(vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]));
            let after_first = server.counters.udp_a.load(Ordering::SeqCst);
            assert!(after_first >= 1, "the first resolution queried the wire");

            // Same resolver: a warm positive cache answers with NO new wire query.
            let cached = resolver_a.resolve(TARGET).await;
            assert_eq!(cached, first, "the cached answer matches");
            assert_eq!(
                server.counters.udp_a.load(Ordering::SeqCst),
                after_first,
                "a warm cache issues no additional query"
            );

            // A fresh generation (new lease + resolver) has an empty cache and
            // must re-query — proving no cache is shared across generations.
            let (_registry_b, _lease_b, token_b) = owner();
            let resolver_b = build_real_resolver(token_b, std::slice::from_ref(&ns));
            let again = resolver_b.resolve(TARGET).await;
            assert_eq!(
                again, first,
                "the fresh generation resolves the same address"
            );
            assert!(
                server.counters.udp_a.load(Ordering::SeqCst) > after_first,
                "a new generation re-queries the nameserver"
            );
        })
        .await;
        assert!(finished.is_ok(), "row3 must finish within the deadline");
    }

    // ---------------------------------------------------------------------
    // Row 4: retiring the owner mid-resolution writes no cache and starts no TCP.
    // ---------------------------------------------------------------------
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn row4_retired_owner_caches_nothing_and_skips_tcp() {
        let finished = tokio::time::timeout(TEST_DEADLINE, async {
            let gate = Arc::new(Notify::new());
            let arrived = Arc::new(Notify::new());
            // A truncated UDP answer would tempt a live owner into a TCP retry;
            // a retired owner must take neither the TCP path nor the cache.
            let behavior = Behavior {
                udp_a: AAnswer::Truncated(Ipv4Addr::new(10, 99, 99, 99)),
                tcp_a: Some(Ipv4Addr::LOCALHOST),
                gate: Some(Arc::clone(&gate)),
                arrived: Some(Arc::clone(&arrived)),
            };
            let server = spawn_dns(behavior).await;
            let ns = ns_literal(server.port);

            let registry = OwnershipRegistry::new();
            let lease = registry
                .claim(OwnerScope::Process, "retire-owner")
                .unwrap_or_else(|error| unreachable!("claim: {error}"));
            let resolver = Arc::new(build_real_resolver(
                lease.token(),
                std::slice::from_ref(&ns),
            ));

            let task_resolver = Arc::clone(&resolver);
            let handle = tokio::spawn(async move { task_resolver.resolve(TARGET).await });

            // Wait until the server received the in-flight query, then retire the
            // owner and release the parked reply.
            arrived.notified().await;
            lease.release();
            gate.notify_one();

            let Ok(joined) = handle.await else {
                unreachable!("resolve task must not panic");
            };
            assert_eq!(
                joined,
                Err(ResolveError::StaleOwner),
                "the post-await owner fence discards the reply"
            );
            assert_eq!(
                server.counters.tcp.load(Ordering::SeqCst),
                0,
                "a retired owner starts no TCP escalation"
            );
            assert_eq!(resolver.cache_len(), 0, "a retired owner caches nothing");

            // A fresh generation still resolves against the (now ungated) server,
            // proving the earlier retirement wrote nothing durable.
            let before = server.counters.udp_a.load(Ordering::SeqCst);
            let (_registry2, _lease2, token2) = owner();
            let fresh = build_real_resolver(token2, std::slice::from_ref(&ns));
            let refreshed = fresh.resolve(TARGET).await;
            let Ok(addrs) = refreshed else {
                unreachable!("the fresh resolve must succeed: {refreshed:?}");
            };
            assert!(addrs.contains(&IpAddr::V4(Ipv4Addr::LOCALHOST)));
            assert!(
                server.counters.udp_a.load(Ordering::SeqCst) > before,
                "the fresh generation re-queried the nameserver"
            );
        })
        .await;
        assert!(finished.is_ok(), "row4 must finish within the deadline");
    }

    // ---------------------------------------------------------------------
    // Row 5: a hostname nameserver is bootstrapped once via the system resolver.
    // ---------------------------------------------------------------------
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn row5_nameserver_hostname_is_bootstrapped() {
        let finished = tokio::time::timeout(TEST_DEADLINE, async {
            let server = spawn_dns(Behavior::full()).await;
            let (_registry, _lease, token) = owner();
            // "localhost" is the ONE allowed system bootstrap (nameserver
            // hostname -> 127.0.0.1/::1); the target `svc.invalid` is resolved
            // ONLY via that explicit nameserver, never the system resolver.
            let ns: Arc<str> = Arc::from(format!("localhost:{}", server.port).as_str());
            let resolver = build_real_resolver(token, std::slice::from_ref(&ns));

            let result = resolver.resolve(TARGET_INVALID).await;
            assert_eq!(
                result,
                Ok(vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]),
                "the target resolves through the bootstrapped nameserver"
            );
            assert!(
                server.counters.udp_a.load(Ordering::SeqCst) >= 1,
                "the bootstrapped nameserver received the target's A query"
            );
        })
        .await;
        assert!(finished.is_ok(), "row5 must finish within the deadline");
    }
}
