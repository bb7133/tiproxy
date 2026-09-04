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

//! Shared, owner-fenced explicit-nameserver DNS resolution.
//!
//! [`ExplicitResolver`] resolves a logical host to a bounded, ordered, and
//! de-duplicated set of [`IpAddr`] by querying the cluster's explicit
//! nameservers — never the system resolver for the target host. It is a pure
//! state machine over an injectable [`DnsTransport`] and an injectable [`Clock`]
//! so it can be exhaustively unit-tested with a fake nameserver returning raw
//! bytes and a manually advanced clock. The production socket transport lives in
//! [`crate::dns_transport`].
//!
//! hickory-proto is used strictly as the DNS wire codec (building/encoding a
//! query [`Message`] and decoding responses). Compression pointers, label
//! parsing, and record decoding are hickory's responsibility; this module never
//! hand-parses the wire.
//!
//! Every awaited stage is owner-fenced before and after: a retired owner drops
//! any successful result, returns [`ResolveError::StaleOwner`], writes nothing to
//! the cache, and never advances to the next stage.

use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use control_plane::OwnerToken;
use futures_util::future::{FutureExt, Shared};
use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use thiserror::Error;

use crate::etcd::MAX_NS_SERVERS;

/// Maximum addresses retained from one combined resolution.
pub const MAX_RESOLVED_ADDRS: usize = 8;
/// Maximum positive/negative cache entries retained.
pub const MAX_CACHE_ENTRIES: usize = 256;
/// Maximum concurrent in-flight singleflight resolutions.
pub const MAX_INFLIGHT: usize = 64;
/// Maximum bootstrap addresses retained per nameserver hostname.
pub const MAX_NS_HOST_ADDRS: usize = 8;
/// Maximum flattened nameserver socket addresses queried per resolution.
pub const MAX_NS_SOCKET_ADDRS: usize = 32;
/// Maximum CNAME edges followed before failing closed.
pub const MAX_CNAME_DEPTH: usize = 8;
/// Positive TTL cap in seconds.
pub const POSITIVE_TTL_CAP_SECS: u32 = 5;
/// Negative TTL cap in seconds.
pub const NEGATIVE_TTL_CAP_SECS: u32 = 5;
/// Advertised EDNS0 UDP payload size.
pub const EDNS_UDP_PAYLOAD: u16 = 1232;
/// Maximum accepted UDP datagram length; a larger datagram is rejected without
/// parsing (the real transport reads into a 1233-byte probe buffer).
pub const MAX_UDP_PAYLOAD_BYTES: usize = 1232;
/// Maximum whole-resolution budget accepted at construction.
const MAX_BUDGET: Duration = Duration::from_secs(300);

/// A boxed, `Send` future used across the resolver's injectable seams.
type BoxFut<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// The public resolution outcome: a bounded, ordered, de-duplicated address set
/// or a stable failure class.
pub type Outcome = Result<Vec<IpAddr>, ResolveError>;

/// A monotonic clock, injectable so deadlines are deterministic under test.
pub trait Clock: Send + Sync + 'static {
    /// Returns the current instant.
    fn now(&self) -> Instant;
}

/// The production clock reading the operating-system monotonic timer.
#[derive(Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

/// One raw UDP datagram as delivered to a connected socket: the kernel-reported
/// source address and the payload bytes.
#[derive(Clone, Debug)]
pub struct UdpDatagram {
    /// The source address the operating system reported for this datagram.
    pub source: SocketAddr,
    /// The raw datagram payload.
    pub payload: Vec<u8>,
}

/// A transport-level failure for one exchange; the resolver treats every variant
/// as "abandon this attempt" and never caches on it.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum TransportError {
    /// The per-attempt deadline elapsed with no usable datagram.
    #[error("dns transport attempt timed out")]
    Timeout,
    /// The transport could not send or receive.
    #[error("dns transport unavailable")]
    Unavailable,
}

/// A bound, connected UDP exchange for one nameserver attempt.
///
/// The resolver drives the receive loop itself so it can enforce connected-UDP
/// source validation, oversize rejection, and spoofed-packet skipping while
/// staying within the single per-attempt deadline.
pub trait UdpExchange: Send {
    /// Receives the next datagram before `deadline`.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::Timeout`] when the per-attempt deadline elapses
    /// and [`TransportError::Unavailable`] on a socket error.
    fn recv(&mut self, deadline: Instant) -> BoxFut<'_, Result<UdpDatagram, TransportError>>;
}

/// The injectable DNS transport: UDP send/receive, TCP exchange, and nameserver
/// hostname bootstrap. Production wires real sockets in [`crate::dns_transport`];
/// tests substitute a fake nameserver returning raw bytes.
pub trait DnsTransport: Send + Sync + 'static {
    /// Sends `query` to `server` over a connected UDP socket and yields a handle
    /// the resolver receives replies from.
    ///
    /// # Errors
    ///
    /// Returns a [`TransportError`] when the datagram cannot be sent.
    fn udp_open(
        &self,
        server: SocketAddr,
        query: Vec<u8>,
        deadline: Instant,
    ) -> BoxFut<'static, Result<Box<dyn UdpExchange>, TransportError>>;

    /// Exchanges `query` with `server` over TCP, returning the decoded DNS
    /// message payload (the transport owns the 2-byte length framing).
    ///
    /// # Errors
    ///
    /// Returns a [`TransportError`] on connect, framing, or deadline failure.
    fn tcp_exchange(
        &self,
        server: SocketAddr,
        query: Vec<u8>,
        deadline: Instant,
    ) -> BoxFut<'static, Result<Vec<u8>, TransportError>>;

    /// Resolves a nameserver hostname to its bootstrap addresses (mirrors Go's
    /// plain `net.Dialer` reaching the nameserver — the one allowed
    /// system-resolver use). The target host never uses this path.
    ///
    /// # Errors
    ///
    /// Returns a [`TransportError`] when the nameserver hostname cannot be
    /// resolved; the resolver fails closed for that nameserver.
    fn bootstrap(
        &self,
        host: Arc<str>,
        port: u16,
        deadline: Instant,
    ) -> BoxFut<'static, Result<Vec<IpAddr>, TransportError>>;
}

/// Stable explicit-resolver failure classes.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ResolveError {
    /// The originating control owner was retired at a stage fence.
    #[error("stale control owner")]
    StaleOwner,
    /// The logical host is empty or not a valid DNS name.
    #[error("invalid DNS host")]
    InvalidHost,
    /// The configured resolution budget is zero or over-bound.
    #[error("invalid resolution budget")]
    InvalidBudget,
    /// The configured nameserver count exceeds its bound.
    #[error("too many nameservers: {count} exceeds {maximum}")]
    TooManyNsServers {
        /// Observed nameserver count.
        count: usize,
        /// Maximum nameserver count.
        maximum: usize,
    },
    /// One nameserver is not a normalized `host:port`.
    #[error("invalid nameserver at index {index}")]
    InvalidNsServer {
        /// Zero-based nameserver index.
        index: usize,
    },
    /// Secure transaction-id generation failed.
    #[error("DNS transaction-id randomness failed")]
    Randomness,
    /// The query message could not be encoded.
    #[error("DNS query encoding failed")]
    Encode,
    /// No usable nameserver socket address was available.
    #[error("no explicit nameservers available")]
    NoNameservers,
    /// The in-flight singleflight table is full.
    #[error("too many in-flight DNS resolutions")]
    TooManyInflight,
    /// The nameservers gave no authoritative answer (soft failure/timeout).
    #[error("DNS resolution failed")]
    LookupFailed,
    /// The name authoritatively resolves to no address of any family.
    #[error("DNS name resolves to no address")]
    NameResolution,
}

/// A parsed nameserver: a literal socket address or a hostname needing bootstrap.
#[derive(Clone, Debug)]
enum NsEntry {
    /// A resolved literal socket address.
    Literal(SocketAddr),
    /// A hostname resolved via the transport bootstrap path.
    Host {
        /// The nameserver hostname.
        host: Arc<str>,
        /// The nameserver port.
        port: u16,
    },
}

impl NsEntry {
    /// Parses one normalized `host:port` nameserver entry, enforcing the same
    /// spec as the config layer via [`crate::etcd::split_normalized_host_port`]
    /// (non-empty host, explicit non-zero port, bracketed host must be an IP
    /// literal). A host that is an IP literal becomes a resolved [`Self::Literal`];
    /// any other host becomes a [`Self::Host`] needing bootstrap.
    fn parse(raw: &str) -> Option<Self> {
        let (host, port) = crate::etcd::split_normalized_host_port(raw)?;
        match host.parse::<IpAddr>() {
            Ok(ip) => Some(Self::Literal(SocketAddr::new(ip, port))),
            Err(_) => Some(Self::Host {
                host: Arc::from(host),
                port,
            }),
        }
    }
}

/// The cached resolution result for one canonical host.
enum CacheResult {
    /// A positive address set.
    Positive(Vec<IpAddr>),
    /// An authoritative negative result.
    Negative,
}

/// One bounded cache entry with its absolute expiry.
struct CacheEntry {
    /// The cached result.
    result: CacheResult,
    /// The absolute expiry instant.
    expires_at: Instant,
}

impl CacheEntry {
    /// Reconstructs the public outcome from the cached result.
    fn outcome(&self) -> Outcome {
        match &self.result {
            CacheResult::Positive(addrs) => Ok(addrs.clone()),
            CacheResult::Negative => Err(ResolveError::NameResolution),
        }
    }
}

/// The kind of an authoritative negative answer, preserved so combining can
/// treat a name-wide NXDOMAIN differently from a type-specific NODATA.
#[derive(Clone, Copy)]
enum NegativeKind {
    /// Name-wide NXDOMAIN. `cache_ttl` is the SOA-derived TTL, or `None` when no
    /// SOA is present.
    NxDomain(Option<u32>),
    /// Type-specific NODATA (the name exists but has no records of this type).
    /// `cache_ttl` is the SOA-derived TTL, or `None` without an SOA.
    NoData(Option<u32>),
}

/// The per-family authoritative resolution outcome.
enum FamilyOutcome {
    /// At least one valid address of this family, with the chain/RR minimum TTL.
    Positive {
        /// The addresses in RR order.
        addrs: Vec<IpAddr>,
        /// The minimum TTL across the CNAME chain and address RRs.
        ttl: u32,
    },
    /// An authoritative negative answer, carrying its NXDOMAIN/NODATA kind.
    Negative(NegativeKind),
    /// A soft failure (timeout, SERVFAIL/REFUSED/FORMERR, malformed, CNAME
    /// loop/depth): never cached.
    SoftError,
}

/// Shared cache and in-flight singleflight state.
struct State {
    /// Positive/negative cache keyed by canonical absolute host.
    cache: HashMap<String, CacheEntry>,
    /// In-flight resolutions keyed by canonical absolute host.
    inflight: HashMap<String, SharedResolve>,
}

/// The immutable resolver core shared behind an `Arc`.
struct Inner {
    /// The captured control owner fence.
    owner: OwnerToken,
    /// The parsed nameservers in their frozen order.
    ns: Arc<[NsEntry]>,
    /// The injectable transport.
    transport: Arc<dyn DnsTransport>,
    /// The injectable clock.
    clock: Arc<dyn Clock>,
    /// The whole-resolution budget (the config `connect_timeout`).
    budget: Duration,
    /// The round-robin nameserver rotation cursor.
    rotation: AtomicUsize,
    /// The shared cache and in-flight table.
    state: Mutex<State>,
}

/// A shared, owner-fenced explicit-nameserver DNS resolver.
///
/// One `ExplicitResolver` is shared (behind an `Arc`) per cluster/channel/
/// generation. Concurrent callers for one host observe exactly one A and one
/// AAAA wire query.
#[derive(Clone)]
pub struct ExplicitResolver {
    /// The shared core.
    inner: Arc<Inner>,
}

/// The future produced for one leader resolution.
type ResolveFuture = Pin<Box<dyn Future<Output = Arc<Outcome>> + Send>>;
/// The shared, cloneable handle awaited by every caller of one host.
type SharedResolve = Shared<ResolveFuture>;

impl ExplicitResolver {
    /// Builds a resolver over the given owner, nameservers, transport, and clock.
    ///
    /// `ns_servers` are the already-normalized `host:port` entries in Go's
    /// frozen, duplicate-preserving order. `budget` is the single absolute
    /// resolution deadline (the config `connect_timeout`).
    ///
    /// # Errors
    ///
    /// Returns [`ResolveError::InvalidBudget`] for a zero or over-bound budget,
    /// [`ResolveError::TooManyNsServers`] beyond [`MAX_NS_SERVERS`], or
    /// [`ResolveError::InvalidNsServer`] for a non-normalized entry.
    pub fn new(
        owner: OwnerToken,
        ns_servers: &[Arc<str>],
        transport: Arc<dyn DnsTransport>,
        clock: Arc<dyn Clock>,
        budget: Duration,
    ) -> Result<Self, ResolveError> {
        if budget.is_zero() || budget > MAX_BUDGET {
            return Err(ResolveError::InvalidBudget);
        }
        if ns_servers.len() > MAX_NS_SERVERS {
            return Err(ResolveError::TooManyNsServers {
                count: ns_servers.len(),
                maximum: MAX_NS_SERVERS,
            });
        }
        let mut ns = Vec::with_capacity(ns_servers.len());
        for (index, raw) in ns_servers.iter().enumerate() {
            ns.push(NsEntry::parse(raw).ok_or(ResolveError::InvalidNsServer { index })?);
        }
        Ok(Self {
            inner: Arc::new(Inner {
                owner,
                ns: ns.into(),
                transport,
                clock,
                budget,
                rotation: AtomicUsize::new(0),
                state: Mutex::new(State {
                    cache: HashMap::new(),
                    inflight: HashMap::new(),
                }),
            }),
        })
    }

    /// Resolves `host` to a bounded, ordered, de-duplicated address set.
    ///
    /// A literal IP host is emitted directly with no wire query. Otherwise the
    /// canonical host shares one cache entry and one in-flight resolution across
    /// concurrent callers.
    ///
    /// # Errors
    ///
    /// Returns a stable [`ResolveError`]: invalid host, stale owner, no
    /// nameservers, over-inflight, an authoritative negative result, or a soft
    /// lookup failure.
    pub async fn resolve(&self, host: &str) -> Outcome {
        // A stale owner wins BEFORE any input or resolution work — the 2c freeze
        // lets a literal IP bypass DNS/NS, never the owner fence.
        if !self.inner.owner.is_current() {
            return Err(ResolveError::StaleOwner);
        }
        // 1. Literal-IP bypass: emit directly, no wire query, no cache.
        if let Some(ip) = parse_ip_literal(host) {
            return Ok(vec![ip]);
        }
        let key = canonical_key(host);
        let name = build_qname(&key)?;

        let shared = {
            let mut state = lock(&self.inner.state);
            let now = self.inner.clock.now();
            if let Some(entry) = state.cache.get(&key) {
                if entry.expires_at > now {
                    return entry.outcome();
                }
                state.cache.remove(&key);
            }
            if let Some(existing) = state.inflight.get(&key) {
                existing.clone()
            } else {
                if state.inflight.len() >= MAX_INFLIGHT {
                    return Err(ResolveError::TooManyInflight);
                }
                let shared = make_leader(&self.inner, key.clone(), name);
                state.inflight.insert(key.clone(), shared.clone());
                shared
            }
        };

        let outcome = shared.await;
        // Post-await owner fence: a retired owner drops the shared result.
        if !self.inner.owner.is_current() {
            return Err(ResolveError::StaleOwner);
        }
        (*outcome).clone()
    }
}

#[cfg(test)]
impl ExplicitResolver {
    /// Expands the configured nameservers exactly as a leader resolution would,
    /// so tests can assert the flattened, per-entry-ordered socket set directly.
    pub(crate) async fn flatten_ns_for_test(&self) -> Vec<SocketAddr> {
        let deadline = self.inner.clock.now() + self.inner.budget;
        self.inner
            .resolve_ns_servers(deadline)
            .await
            .unwrap_or_default()
    }

    /// Returns the number of live cache entries, so tests can assert that a
    /// fenced or uncacheable resolution wrote nothing.
    pub(crate) fn cache_len(&self) -> usize {
        lock(&self.inner.state).cache.len()
    }
}

/// Builds the shared leader future for one canonical host, capturing a `Weak`
/// core to avoid a reference cycle through the in-flight table.
fn make_leader(inner: &Arc<Inner>, key: String, name: Name) -> SharedResolve {
    let weak = Arc::downgrade(inner);
    let future: ResolveFuture = Box::pin(async move {
        match weak.upgrade() {
            Some(inner) => inner.resolve_once(key, name).await,
            None => Arc::new(Err(ResolveError::StaleOwner)),
        }
    });
    future.shared()
}

impl Inner {
    /// Runs one leader resolution: establishes the single absolute deadline,
    /// bootstraps nameservers, resolves A and AAAA concurrently, owner-fences,
    /// combines, writes the cache once, and clears the in-flight slot.
    async fn resolve_once(&self, key: String, name: Name) -> Arc<Outcome> {
        // Anchor BOTH the single absolute deadline and every cache expiry to the
        // leader's start instant (Go `lookupNetIP` takes `now` before the
        // lookup). Time elapsed during the query is not refilled into the cached
        // TTL, matching the single-deadline-no-refill rule.
        let started = self.clock.now();
        let deadline = started + self.budget;

        let servers = match self.resolve_ns_servers(deadline).await {
            Ok(servers) if !servers.is_empty() => servers,
            Ok(_) => return self.finish(&key, Err(ResolveError::NoNameservers), None),
            Err(error) => return self.finish(&key, Err(error), None),
        };
        if !self.owner.is_current() {
            return self.finish(&key, Err(ResolveError::StaleOwner), None);
        }

        let (a_result, aaaa_result) = tokio::join!(
            self.resolve_family(&name, RecordType::A, &servers, deadline),
            self.resolve_family(&name, RecordType::AAAA, &servers, deadline),
        );
        if !self.owner.is_current() {
            return self.finish(&key, Err(ResolveError::StaleOwner), None);
        }
        let a = match a_result {
            Ok(outcome) => outcome,
            Err(error) => return self.finish(&key, Err(error), None),
        };
        let aaaa = match aaaa_result {
            Ok(outcome) => outcome,
            Err(error) => return self.finish(&key, Err(error), None),
        };

        let (outcome, cache) = combine(&a, &aaaa, started);
        self.finish(&key, outcome, cache)
    }

    /// Clears the in-flight slot, writes the bounded cache when directed, and
    /// returns the shared outcome.
    ///
    /// An entry whose start-anchored expiry has already elapsed (the lookup
    /// consumed its whole TTL) is still returned to the caller but never cached.
    fn finish(&self, key: &str, outcome: Outcome, cache: Option<CacheEntry>) -> Arc<Outcome> {
        let mut state = lock(&self.state);
        state.inflight.remove(key);
        if let Some(entry) = cache {
            let now = self.clock.now();
            if entry.expires_at > now {
                insert_bounded(&mut state.cache, key.to_owned(), entry, now);
            }
        }
        Arc::new(outcome)
    }

    /// Expands the configured nameservers into a bounded flattened socket set
    /// within the single deadline, preserving config entry order.
    ///
    /// The config projection already sorts entries by their normalized entry
    /// string and keeps duplicates for rotation weight, so this expands each
    /// entry IN ENTRY ORDER: a literal entry is itself, and a hostname entry's
    /// bootstrap addresses are sorted, de-duplicated, and capped to
    /// [`MAX_NS_HOST_ADDRS`] WITHIN that entry only (so the kept set is
    /// independent of the system resolver's return order). Entries are then
    /// flattened in order and the total capped to [`MAX_NS_SOCKET_ADDRS`] with NO
    /// cross-entry sort and NO cross-entry dedup, so duplicate nameserver entries
    /// survive and keep their extra rotation weight. A hostname bootstrap failure
    /// fails closed for that entry.
    async fn resolve_ns_servers(&self, deadline: Instant) -> Result<Vec<SocketAddr>, ResolveError> {
        let mut out: Vec<SocketAddr> = Vec::new();
        for entry in self.ns.iter() {
            if out.len() >= MAX_NS_SOCKET_ADDRS {
                break;
            }
            match entry {
                NsEntry::Literal(addr) => out.push(*addr),
                NsEntry::Host { host, port } => {
                    if !self.owner.is_current() {
                        return Err(ResolveError::StaleOwner);
                    }
                    if self.clock.now() >= deadline {
                        break;
                    }
                    if let Ok(addrs) = self
                        .transport
                        .bootstrap(Arc::clone(host), *port, deadline)
                        .await
                    {
                        if !self.owner.is_current() {
                            return Err(ResolveError::StaleOwner);
                        }
                        // Per-entry ordering: sort + dedup + cap WITHIN this entry
                        // only, never across entries.
                        let mut entry_addrs: Vec<SocketAddr> = addrs
                            .into_iter()
                            .map(|ip| SocketAddr::new(ip, *port))
                            .collect();
                        entry_addrs.sort_unstable();
                        entry_addrs.dedup();
                        entry_addrs.truncate(MAX_NS_HOST_ADDRS);
                        out.extend(entry_addrs);
                    }
                }
            }
        }
        out.truncate(MAX_NS_SOCKET_ADDRS);
        Ok(out)
    }

    /// Resolves one address family, following the CNAME chain within the single
    /// deadline and enforcing anti-poisoning and loop/depth bounds.
    async fn resolve_family(
        &self,
        qname: &Name,
        rtype: RecordType,
        servers: &[SocketAddr],
        deadline: Instant,
    ) -> Result<FamilyOutcome, ResolveError> {
        let mut current = qname.clone();
        let mut visited: Vec<Name> = vec![current.clone()];
        let mut total_hops: usize = 0;
        let mut chain_ttl: u32 = u32::MAX;

        loop {
            if !self.owner.is_current() {
                return Err(ResolveError::StaleOwner);
            }
            let Some(message) = self
                .query_ns_set(&current, rtype, servers, deadline)
                .await?
            else {
                return Ok(FamilyOutcome::SoftError);
            };
            if !self.owner.is_current() {
                return Err(ResolveError::StaleOwner);
            }
            // Only authoritative NOERROR/NXDOMAIN answers are interpreted; a
            // SERVFAIL/REFUSED/FORMERR is a soft failure.
            let rcode = message.response_code;
            if !matches!(rcode, ResponseCode::NoError | ResponseCode::NXDomain) {
                return Ok(FamilyOutcome::SoftError);
            }

            // Walk the CNAME chain within this message FIRST — for both NOERROR
            // and NXDOMAIN — growing the accepted owner set, accumulating the
            // chain TTL, and enforcing loop/depth bounds. The negative SOA (for a
            // cross-zone NXDOMAIN/NODATA) is validated against the chain TERMINAL,
            // not the starting alias.
            let mut accepted: Vec<Name> = vec![current.clone()];
            let mut terminal = current.clone();
            loop {
                let Some((target, ttl)) = find_cname(&message.answers, &terminal) else {
                    break;
                };
                total_hops += 1;
                if total_hops > MAX_CNAME_DEPTH {
                    return Ok(FamilyOutcome::SoftError);
                }
                if visited.iter().any(|n| n == &target) || accepted.iter().any(|n| n == &target) {
                    return Ok(FamilyOutcome::SoftError);
                }
                chain_ttl = chain_ttl.min(ttl);
                accepted.push(target.clone());
                visited.push(target.clone());
                terminal = target;
            }

            if rcode == ResponseCode::NXDomain {
                // The terminal name authoritatively does not exist. Cache by the
                // min of the CNAME chain TTL and the terminal-anchored SOA TTL.
                return Ok(FamilyOutcome::Negative(NegativeKind::NxDomain(
                    chain_negative_ttl(&message, &terminal, chain_ttl),
                )));
            }

            // Anti-poisoning: accept only A/AAAA owned by a chain name.
            let mut addrs: Vec<IpAddr> = Vec::new();
            let mut addr_ttl: u32 = u32::MAX;
            for record in &message.answers {
                if record.dns_class == DNSClass::IN
                    && record.record_type() == rtype
                    && accepted.iter().any(|n| n == &record.name)
                    && let Some(ip) = rdata_ip(&record.data)
                {
                    addrs.push(ip);
                    addr_ttl = addr_ttl.min(record.ttl);
                }
            }
            if !addrs.is_empty() {
                let ttl = chain_ttl.min(addr_ttl);
                return Ok(FamilyOutcome::Positive { addrs, ttl });
            }

            if terminal == current {
                // No CNAME to follow: an empty NOERROR answer is NODATA, cached by
                // the min of the chain TTL and the terminal-anchored SOA TTL.
                return Ok(FamilyOutcome::Negative(NegativeKind::NoData(
                    chain_negative_ttl(&message, &terminal, chain_ttl),
                )));
            }
            // The terminal is in another zone; query it next under the same
            // deadline. Loop and depth were already enforced above.
            current = terminal;
        }
    }

    /// Queries the flattened nameserver set for one qtype from a round-robin
    /// start, trying each nameserver at most once within the single deadline.
    async fn query_ns_set(
        &self,
        name: &Name,
        rtype: RecordType,
        servers: &[SocketAddr],
        deadline: Instant,
    ) -> Result<Option<Message>, ResolveError> {
        let count = servers.len();
        if count == 0 {
            return Ok(None);
        }
        let start = self.rotation.fetch_add(1, Ordering::Relaxed) % count;
        for offset in 0..count {
            let now = self.clock.now();
            if now >= deadline {
                return Ok(None);
            }
            if !self.owner.is_current() {
                return Err(ResolveError::StaleOwner);
            }
            let server = servers[(start + offset) % count];
            let remaining = deadline.saturating_duration_since(now);
            let remaining_ns = u32::try_from(count - offset).unwrap_or(1).max(1);
            let attempt_deadline = now + remaining / remaining_ns;

            let id = random_txid()?;
            let query = build_query(name, rtype, id)?;
            if let Some(message) = self
                .udp_attempt(server, query, name, rtype, id, attempt_deadline)
                .await?
            {
                match message.response_code {
                    ResponseCode::ServFail | ResponseCode::Refused | ResponseCode::FormErr => {}
                    _ => return Ok(Some(message)),
                }
            }
        }
        Ok(None)
    }

    /// Performs one connected-UDP attempt against `server`, skipping spoofed or
    /// oversize datagrams and escalating a truncated answer to TCP.
    async fn udp_attempt(
        &self,
        server: SocketAddr,
        query: Vec<u8>,
        name: &Name,
        rtype: RecordType,
        id: u16,
        attempt_deadline: Instant,
    ) -> Result<Option<Message>, ResolveError> {
        let Ok(mut socket) = self
            .transport
            .udp_open(server, query, attempt_deadline)
            .await
        else {
            return Ok(None);
        };
        if !self.owner.is_current() {
            return Err(ResolveError::StaleOwner);
        }
        loop {
            let Ok(datagram) = socket.recv(attempt_deadline).await else {
                return Ok(None);
            };
            if !self.owner.is_current() {
                return Err(ResolveError::StaleOwner);
            }
            // Connected-UDP: a reply from a non-nameserver source is dropped.
            if datagram.source != server {
                continue;
            }
            // Oversize datagram: reject and move to the next nameserver.
            if datagram.payload.len() > MAX_UDP_PAYLOAD_BYTES {
                return Ok(None);
            }
            let Ok(message) = Message::from_vec(&datagram.payload) else {
                continue;
            };
            if !validate(&message, name, rtype, id) {
                continue;
            }
            if message.truncation {
                return self
                    .tcp_attempt(server, name, rtype, attempt_deadline)
                    .await;
            }
            return Ok(Some(message));
        }
    }

    /// Retries the same nameserver over TCP once within the attempt deadline.
    async fn tcp_attempt(
        &self,
        server: SocketAddr,
        name: &Name,
        rtype: RecordType,
        deadline: Instant,
    ) -> Result<Option<Message>, ResolveError> {
        let id = random_txid()?;
        let query = build_query(name, rtype, id)?;
        let Ok(bytes) = self.transport.tcp_exchange(server, query, deadline).await else {
            return Ok(None);
        };
        if !self.owner.is_current() {
            return Err(ResolveError::StaleOwner);
        }
        let Ok(message) = Message::from_vec(&bytes) else {
            return Ok(None);
        };
        if !validate(&message, name, rtype, id) {
            return Ok(None);
        }
        // A TCP response must be complete: a still-truncated reply is not a valid
        // full answer, so its (partial) records are neither used nor cached.
        if message.truncation {
            return Ok(None);
        }
        Ok(Some(message))
    }
}

/// Locks a [`Mutex`], recovering the guard if a prior holder panicked.
fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Parses a bare or bracketed IP literal host.
fn parse_ip_literal(host: &str) -> Option<IpAddr> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Some(ip);
    }
    host.strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .and_then(|inner| inner.parse::<IpAddr>().ok())
}

/// Computes the canonical absolute cache key: ASCII-lowercased, trailing dot
/// stripped.
fn canonical_key(host: &str) -> String {
    host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase()
}

/// Builds the absolute query name from a canonical host key.
fn build_qname(key: &str) -> Result<Name, ResolveError> {
    if key.is_empty() {
        return Err(ResolveError::InvalidHost);
    }
    let mut name = Name::from_ascii(key).map_err(|_| ResolveError::InvalidHost)?;
    name.set_fqdn(true);
    Ok(name)
}

/// Generates a random 16-bit transaction id via the platform CSPRNG.
fn random_txid() -> Result<u16, ResolveError> {
    let mut buffer = [0u8; 2];
    getrandom::getrandom(&mut buffer).map_err(|_| ResolveError::Randomness)?;
    Ok(u16::from_ne_bytes(buffer))
}

/// Encodes an EDNS0 recursion-desired query for one name and qtype.
fn build_query(name: &Name, rtype: RecordType, id: u16) -> Result<Vec<u8>, ResolveError> {
    let mut message = Message::new(id, MessageType::Query, OpCode::Query);
    message.metadata.recursion_desired = true;
    message.add_query(Query::query(name.clone(), rtype));
    let mut edns = Edns::new();
    edns.set_version(0);
    edns.set_max_payload(EDNS_UDP_PAYLOAD);
    message.set_edns(edns);
    message.to_vec().map_err(|_| ResolveError::Encode)
}

/// Validates a response against the sent query: connected QR/opcode/id and the
/// canonical single question (name/type/class IN).
fn validate(message: &Message, name: &Name, rtype: RecordType, id: u16) -> bool {
    message.message_type == MessageType::Response
        && message.op_code == OpCode::Query
        && message.id == id
        && message.queries.len() == 1
        && message.queries.first().is_some_and(|query| {
            query.name() == name
                && query.query_type() == rtype
                && query.query_class() == DNSClass::IN
        })
}

/// Finds a CNAME record in `answers` owned by `owner`, returning its target and
/// TTL.
fn find_cname(answers: &[Record], owner: &Name) -> Option<(Name, u32)> {
    answers.iter().find_map(|record| {
        if record.dns_class == DNSClass::IN
            && record.record_type() == RecordType::CNAME
            && &record.name == owner
            && let RData::CNAME(target) = &record.data
        {
            return Some((target.0.clone(), record.ttl));
        }
        None
    })
}

/// Extracts the [`IpAddr`] carried by an A or AAAA record.
fn rdata_ip(data: &RData) -> Option<IpAddr> {
    match data {
        RData::A(a) => Some(IpAddr::V4(a.0)),
        RData::AAAA(aaaa) => Some(IpAddr::V6(aaaa.0)),
        _ => None,
    }
}

/// Derives the negative-cache TTL from a trustworthy SOA in the authority
/// section, capped at [`NEGATIVE_TTL_CAP_SECS`]; `None` when uncacheable.
///
/// Anti-poisoning: an SOA is only usable when it is IN class AND its owner is the
/// enclosing zone of `qname` — i.e. the owner is `qname` itself or a DNS-label
/// ancestor. A wrong-class SOA (e.g. CH) or an unrelated/non-ancestor owner
/// (e.g. `evil.test`) is ignored, so the response is treated as uncacheable.
fn negative_ttl(message: &Message, qname: &Name) -> Option<u32> {
    for record in &message.authorities {
        if record.dns_class == DNSClass::IN
            && record.name.zone_of(qname)
            && let RData::SOA(soa) = &record.data
        {
            let ttl = record.ttl.min(soa.minimum).min(NEGATIVE_TTL_CAP_SECS);
            return (ttl > 0).then_some(ttl);
        }
    }
    None
}

/// Combines the terminal-anchored SOA TTL with the CNAME chain TTL for a
/// negative answer: the cached TTL is `min(chain TTL, SOA-derived TTL)`, so the
/// original host key is never cached longer than any CNAME in the chain permits.
/// Returns `None` (uncacheable) when there is no usable SOA or the combined TTL
/// is zero.
fn chain_negative_ttl(message: &Message, terminal: &Name, chain_ttl: u32) -> Option<u32> {
    negative_ttl(message, terminal).and_then(|soa_ttl| {
        let combined = soa_ttl.min(chain_ttl);
        (combined > 0).then_some(combined)
    })
}

/// Combines the per-family outcomes into the public result and an optional cache
/// entry whose expiry is anchored at `started` (the leader's start instant).
fn combine(
    a: &FamilyOutcome,
    aaaa: &FamilyOutcome,
    started: Instant,
) -> (Outcome, Option<CacheEntry>) {
    let (v4, a_ttl) = match a {
        FamilyOutcome::Positive { addrs, ttl } => (addrs.clone(), Some(*ttl)),
        _ => (Vec::new(), None),
    };
    let (v6, aaaa_ttl) = match aaaa {
        FamilyOutcome::Positive { addrs, ttl } => (addrs.clone(), Some(*ttl)),
        _ => (Vec::new(), None),
    };

    if a_ttl.is_some() || aaaa_ttl.is_some() {
        let addrs = interleave_dedup_cap(&v4, &v6);
        let mut ttl = u32::MAX;
        if let Some(value) = a_ttl {
            ttl = ttl.min(value);
        }
        if let Some(value) = aaaa_ttl {
            ttl = ttl.min(value);
        }
        let ttl = ttl.min(POSITIVE_TTL_CAP_SECS);
        let cache = (ttl > 0 && !addrs.is_empty()).then(|| CacheEntry {
            result: CacheResult::Positive(addrs.clone()),
            expires_at: started + Duration::from_secs(u64::from(ttl)),
        });
        return (Ok(addrs), cache);
    }

    // No positive family. A name-wide NXDOMAIN in EITHER family is authoritative
    // for the whole name, so it wins over the other family's soft failure
    // (timeout/SERVFAIL/malformed/loop): a soft failure must never downgrade a
    // proven NXDOMAIN to a lookup error. Only when NEITHER family is NXDOMAIN does
    // a soft failure suppress negative caching and downgrade any NODATA.
    let a_nxdomain = matches!(a, FamilyOutcome::Negative(NegativeKind::NxDomain(_)));
    let aaaa_nxdomain = matches!(aaaa, FamilyOutcome::Negative(NegativeKind::NxDomain(_)));
    if !a_nxdomain
        && !aaaa_nxdomain
        && (matches!(a, FamilyOutcome::SoftError) || matches!(aaaa, FamilyOutcome::SoftError))
    {
        return (Err(ResolveError::LookupFailed), None);
    }

    // An authoritative negative. `negative_cache_ttl` encodes the kind-aware
    // policy: a name-wide NXDOMAIN is cached by its SOA TTL when present
    // (regardless of the other family), while a pure NODATA is cached only when
    // both families are NODATA WITH an SOA.
    let cache = negative_cache_ttl(a, aaaa).map(|ttl| CacheEntry {
        result: CacheResult::Negative,
        expires_at: started + Duration::from_secs(u64::from(ttl)),
    });
    (Err(ResolveError::NameResolution), cache)
}

/// Decides the negative-cache TTL for a pair of family outcomes that the caller
/// has already resolved to an authoritative negative (a soft-failure family
/// contributes no kind and is ignored here).
///
/// A name-wide NXDOMAIN may be cached by its SOA TTL when an SOA is present,
/// regardless of the other family (which may be a soft failure). A pure NODATA is
/// cached only when BOTH families are NODATA WITH an SOA (TTL = the minimum of the
/// two per-family SOA TTLs). Any NODATA-without-SOA — or a NXDOMAIN with no SOA —
/// yields no cache. Returns the capped TTL, or `None` when the pair must not be
/// cached.
fn negative_cache_ttl(a: &FamilyOutcome, aaaa: &FamilyOutcome) -> Option<u32> {
    let a_kind = negative_kind(a);
    let aaaa_kind = negative_kind(aaaa);
    let is_nxdomain = |kind: &Option<NegativeKind>| matches!(kind, Some(NegativeKind::NxDomain(_)));

    if is_nxdomain(&a_kind) || is_nxdomain(&aaaa_kind) {
        // At least one family is a name-wide NXDOMAIN: cache by the smallest
        // available NXDOMAIN SOA TTL, or not at all when no SOA is present.
        return [a_kind, aaaa_kind]
            .into_iter()
            .flatten()
            .filter_map(|kind| match kind {
                NegativeKind::NxDomain(ttl) => ttl,
                NegativeKind::NoData(_) => None,
            })
            .min()
            .map(|ttl| ttl.min(NEGATIVE_TTL_CAP_SECS));
    }
    // Pure NODATA on both families: cache only when both carry an SOA TTL.
    match (a_kind, aaaa_kind) {
        (Some(NegativeKind::NoData(Some(a_ttl))), Some(NegativeKind::NoData(Some(aaaa_ttl)))) => {
            Some(a_ttl.min(aaaa_ttl).min(NEGATIVE_TTL_CAP_SECS))
        }
        _ => None,
    }
}

/// Returns the negative kind of a family outcome, if it is a negative.
fn negative_kind(outcome: &FamilyOutcome) -> Option<NegativeKind> {
    match outcome {
        FamilyOutcome::Negative(kind) => Some(*kind),
        _ => None,
    }
}

/// Interleaves A then AAAA addresses in RR order, de-duplicates preserving first
/// occurrence, then caps to [`MAX_RESOLVED_ADDRS`].
fn interleave_dedup_cap(v4: &[IpAddr], v6: &[IpAddr]) -> Vec<IpAddr> {
    let mut out: Vec<IpAddr> = Vec::new();
    let mut index = 0;
    while index < v4.len() || index < v6.len() {
        if let Some(ip) = v4.get(index) {
            push_unique(&mut out, *ip);
        }
        if let Some(ip) = v6.get(index) {
            push_unique(&mut out, *ip);
        }
        index += 1;
    }
    out.truncate(MAX_RESOLVED_ADDRS);
    out
}

/// Pushes `ip` only if it is not already present, preserving order.
fn push_unique(out: &mut Vec<IpAddr>, ip: IpAddr) {
    if !out.contains(&ip) {
        out.push(ip);
    }
}

/// Inserts a cache entry within [`MAX_CACHE_ENTRIES`]: when full, evict expired
/// first; if still full, return the result uncached.
fn insert_bounded(
    cache: &mut HashMap<String, CacheEntry>,
    key: String,
    entry: CacheEntry,
    now: Instant,
) {
    if cache.len() < MAX_CACHE_ENTRIES || cache.contains_key(&key) {
        cache.insert(key, entry);
        return;
    }
    cache.retain(|_, existing| existing.expires_at > now);
    if cache.len() < MAX_CACHE_ENTRIES {
        cache.insert(key, entry);
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex, PoisonError};
    use std::task::{Context, Poll, Waker};
    use std::time::{Duration, Instant};

    use control_plane::{OwnerLease, OwnerScope, OwnerToken, OwnershipRegistry};
    use futures_util::future::join_all;
    use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
    use hickory_proto::rr::rdata::{A, AAAA, CNAME, SOA};
    use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
    use tokio::sync::Notify;

    use super::{
        BoxFut, Clock, DnsTransport, ExplicitResolver, MAX_CACHE_ENTRIES, ResolveError,
        TransportError, UdpDatagram, UdpExchange, canonical_key,
    };

    // --- clock -----------------------------------------------------------

    #[derive(Clone)]
    struct ManualClock {
        base: Instant,
        offset: Arc<Mutex<Duration>>,
    }

    impl ManualClock {
        fn new() -> Self {
            Self {
                base: Instant::now(),
                offset: Arc::new(Mutex::new(Duration::ZERO)),
            }
        }

        fn guard(&self) -> std::sync::MutexGuard<'_, Duration> {
            self.offset.lock().unwrap_or_else(PoisonError::into_inner)
        }

        fn advance(&self, delta: Duration) {
            *self.guard() += delta;
        }

        fn advance_to(&self, target: Instant) {
            let current = self.now();
            if target > current {
                *self.guard() += target - current;
            }
        }

        fn elapsed(&self) -> Duration {
            *self.guard()
        }
    }

    impl Clock for ManualClock {
        fn now(&self) -> Instant {
            self.base + *self.guard()
        }
    }

    // --- fake transport --------------------------------------------------

    type UdpResponder =
        Arc<dyn Fn(u16, &Name, RecordType, SocketAddr) -> Vec<UdpDatagram> + Send + Sync>;
    type TcpResponder =
        Arc<dyn Fn(u16, &Name, RecordType, SocketAddr) -> Option<Vec<u8>> + Send + Sync>;

    struct FakeTransport {
        clock: ManualClock,
        udp: Mutex<HashMap<(String, RecordType), UdpResponder>>,
        tcp: Mutex<HashMap<(String, RecordType), TcpResponder>>,
        boot: Mutex<HashMap<String, Vec<IpAddr>>>,
        a_count: AtomicUsize,
        aaaa_count: AtomicUsize,
        tcp_count: AtomicUsize,
        yield_first: AtomicBool,
        gate_open: Arc<AtomicBool>,
        // A one-shot clock advance applied when the first UDP query is sent, so a
        // test can make a lookup consume wall-clock time during the exchange.
        pre_send_advance: Mutex<Option<Duration>>,
        // Total nameserver-hostname bootstrap attempts observed, so a test can
        // prove a failed/stale bootstrap is NOT cached (a second resolve re-runs).
        boot_count: AtomicUsize,
        // Hostnames whose bootstrap fails with a timeout, no matter the boot map.
        boot_fail: Mutex<HashSet<String>>,
        // A gate parking the bootstrap await, plus a signal fired once a bootstrap
        // is entered, so a test can retire the owner mid-bootstrap deterministically.
        boot_gate: Arc<AtomicBool>,
        boot_started: Arc<Notify>,
    }

    impl FakeTransport {
        fn new(clock: &ManualClock) -> Arc<Self> {
            Arc::new(Self {
                clock: clock.clone(),
                udp: Mutex::new(HashMap::new()),
                tcp: Mutex::new(HashMap::new()),
                boot: Mutex::new(HashMap::new()),
                a_count: AtomicUsize::new(0),
                aaaa_count: AtomicUsize::new(0),
                tcp_count: AtomicUsize::new(0),
                yield_first: AtomicBool::new(false),
                gate_open: Arc::new(AtomicBool::new(true)),
                pre_send_advance: Mutex::new(None),
                boot_count: AtomicUsize::new(0),
                boot_fail: Mutex::new(HashSet::new()),
                boot_gate: Arc::new(AtomicBool::new(true)),
                boot_started: Arc::new(Notify::new()),
            })
        }

        fn boot_count(&self) -> usize {
            self.boot_count.load(Ordering::SeqCst)
        }

        fn fail_bootstrap(&self, host: &str) {
            self.boot_fail
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .insert(host.to_owned());
        }

        fn close_boot_gate(&self) {
            self.boot_gate.store(false, Ordering::SeqCst);
        }

        fn open_boot_gate(&self) {
            self.boot_gate.store(true, Ordering::SeqCst);
        }

        fn boot_started(&self) -> Arc<Notify> {
            Arc::clone(&self.boot_started)
        }

        fn set_pre_send_advance(&self, delay: Duration) {
            *self
                .pre_send_advance
                .lock()
                .unwrap_or_else(PoisonError::into_inner) = Some(delay);
        }

        fn set_udp(&self, host: &str, rtype: RecordType, responder: UdpResponder) {
            self.udp
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .insert((host.to_owned(), rtype), responder);
        }

        fn set_tcp(&self, host: &str, rtype: RecordType, responder: TcpResponder) {
            self.tcp
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .insert((host.to_owned(), rtype), responder);
        }

        fn set_bootstrap(&self, host: &str, addrs: Vec<IpAddr>) {
            self.boot
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .insert(host.to_owned(), addrs);
        }

        fn a_count(&self) -> usize {
            self.a_count.load(Ordering::SeqCst)
        }

        fn aaaa_count(&self) -> usize {
            self.aaaa_count.load(Ordering::SeqCst)
        }

        fn tcp_count(&self) -> usize {
            self.tcp_count.load(Ordering::SeqCst)
        }

        fn plan_udp(&self, server: SocketAddr, query: &[u8]) -> Vec<UdpDatagram> {
            let Some((id, name, rtype)) = decode_query(query) else {
                return Vec::new();
            };
            // A one-shot wall-clock cost for the first query of a lookup.
            if let Some(delay) = self
                .pre_send_advance
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take()
            {
                self.clock.advance(delay);
            }
            match rtype {
                RecordType::A => {
                    self.a_count.fetch_add(1, Ordering::SeqCst);
                }
                RecordType::AAAA => {
                    self.aaaa_count.fetch_add(1, Ordering::SeqCst);
                }
                _ => {}
            }
            let key = (canonical_key(&name.to_ascii()), rtype);
            let responder = self
                .udp
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .get(&key)
                .cloned();
            match responder {
                Some(responder) => responder(id, &name, rtype, server),
                // Default: an authoritative NODATA (no SOA) — never cached.
                None => vec![datagram(
                    server,
                    encode(id, &name, rtype, ResponseCode::NoError, &[], &[], false),
                )],
            }
        }

        fn plan_tcp(&self, server: SocketAddr, query: &[u8]) -> Option<Vec<u8>> {
            let (id, name, rtype) = decode_query(query)?;
            let key = (canonical_key(&name.to_ascii()), rtype);
            let responder = self
                .tcp
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .get(&key)
                .cloned()?;
            responder(id, &name, rtype, server)
        }
    }

    impl DnsTransport for FakeTransport {
        fn udp_open(
            &self,
            server: SocketAddr,
            query: Vec<u8>,
            _deadline: Instant,
        ) -> BoxFut<'static, Result<Box<dyn UdpExchange>, TransportError>> {
            let datagrams = self.plan_udp(server, &query);
            let clock = self.clock.clone();
            let yield_first = self.yield_first.load(Ordering::SeqCst);
            let gate = Arc::clone(&self.gate_open);
            Box::pin(async move {
                Ok(Box::new(FakeUdp {
                    datagrams: datagrams.into_iter().collect(),
                    clock,
                    yield_first,
                    yielded: false,
                    gate,
                }) as Box<dyn UdpExchange>)
            })
        }

        fn tcp_exchange(
            &self,
            server: SocketAddr,
            query: Vec<u8>,
            _deadline: Instant,
        ) -> BoxFut<'static, Result<Vec<u8>, TransportError>> {
            self.tcp_count.fetch_add(1, Ordering::SeqCst);
            let out = self.plan_tcp(server, &query);
            Box::pin(async move { out.ok_or(TransportError::Unavailable) })
        }

        fn bootstrap(
            &self,
            host: Arc<str>,
            _port: u16,
            _deadline: Instant,
        ) -> BoxFut<'static, Result<Vec<IpAddr>, TransportError>> {
            self.boot_count.fetch_add(1, Ordering::SeqCst);
            let fail = self
                .boot_fail
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .contains(&*host);
            let out = self
                .boot
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .get(&*host)
                .cloned();
            let gate = Arc::clone(&self.boot_gate);
            let started = Arc::clone(&self.boot_started);
            Box::pin(async move {
                if fail {
                    return Err(TransportError::Timeout);
                }
                // Signal entry, then park (yielding so the runtime can retire the
                // owner) until the gate opens.
                started.notify_one();
                while !gate.load(Ordering::SeqCst) {
                    tokio::task::yield_now().await;
                }
                out.ok_or(TransportError::Unavailable)
            })
        }
    }

    struct FakeUdp {
        datagrams: std::collections::VecDeque<UdpDatagram>,
        clock: ManualClock,
        yield_first: bool,
        yielded: bool,
        gate: Arc<AtomicBool>,
    }

    impl UdpExchange for FakeUdp {
        fn recv(&mut self, deadline: Instant) -> BoxFut<'_, Result<UdpDatagram, TransportError>> {
            Box::pin(async move {
                // Block (re-checking on every poll) while the gate is closed, so
                // a test can park a stage in its await and release it later.
                let gate = Arc::clone(&self.gate);
                std::future::poll_fn(|_cx| {
                    if gate.load(Ordering::SeqCst) {
                        Poll::Ready(())
                    } else {
                        Poll::Pending
                    }
                })
                .await;
                if self.yield_first && !self.yielded {
                    self.yielded = true;
                    tokio::task::yield_now().await;
                }
                if let Some(datagram) = self.datagrams.pop_front() {
                    Ok(datagram)
                } else {
                    // A per-attempt timeout consumes the attempt's budget slice.
                    self.clock.advance_to(deadline);
                    Err(TransportError::Timeout)
                }
            })
        }
    }

    // --- encoding helpers ------------------------------------------------

    fn name(text: &str) -> Name {
        let mut parsed =
            Name::from_ascii(text).unwrap_or_else(|e| unreachable!("name {text}: {e}"));
        parsed.set_fqdn(true);
        parsed
    }

    fn datagram(source: SocketAddr, payload: Vec<u8>) -> UdpDatagram {
        UdpDatagram { source, payload }
    }

    fn a_record(owner: &Name, ip: [u8; 4], ttl: u32) -> Record {
        Record::from_rdata(
            owner.clone(),
            ttl,
            RData::A(A::new(ip[0], ip[1], ip[2], ip[3])),
        )
    }

    fn aaaa_record(owner: &Name, ttl: u32) -> Record {
        Record::from_rdata(
            owner.clone(),
            ttl,
            RData::AAAA(AAAA::new(0xfd00, 0, 0, 0, 0, 0, 0, 1)),
        )
    }

    fn cname_record(owner: &Name, target: &Name, ttl: u32) -> Record {
        Record::from_rdata(owner.clone(), ttl, RData::CNAME(CNAME(target.clone())))
    }

    fn soa_record(owner: &Name, minimum: u32, ttl: u32) -> Record {
        Record::from_rdata(
            owner.clone(),
            ttl,
            RData::SOA(SOA::new(
                name("ns.authority."),
                name("hostmaster.authority."),
                1,
                3600,
                600,
                86_400,
                minimum,
            )),
        )
    }

    fn encode(
        id: u16,
        question: &Name,
        qtype: RecordType,
        rcode: ResponseCode,
        answers: &[Record],
        authorities: &[Record],
        truncated: bool,
    ) -> Vec<u8> {
        let mut message = Message::new(id, MessageType::Response, OpCode::Query);
        message.metadata.authoritative = true;
        message.metadata.truncation = truncated;
        message.metadata.response_code = rcode;
        message.add_query(Query::query(question.clone(), qtype));
        for record in answers {
            message.add_answer(record.clone());
        }
        for record in authorities {
            message.add_authority(record.clone());
        }
        message
            .to_vec()
            .unwrap_or_else(|e| unreachable!("encode: {e}"))
    }

    fn decode_query(bytes: &[u8]) -> Option<(u16, Name, RecordType)> {
        let message = Message::from_vec(bytes).ok()?;
        let query = message.queries.first()?;
        Some((message.id, query.name().clone(), query.query_type()))
    }

    fn patch_id(mut bytes: Vec<u8>, id: u16) -> Vec<u8> {
        let raw = id.to_be_bytes();
        if bytes.len() >= 2 {
            bytes[0] = raw[0];
            bytes[1] = raw[1];
        }
        bytes
    }

    // --- ownership / resolver construction -------------------------------

    fn owner() -> (OwnershipRegistry, OwnerLease, OwnerToken) {
        let registry = OwnershipRegistry::new();
        let lease = registry
            .claim(OwnerScope::Process, "dns-owner")
            .unwrap_or_else(|e| unreachable!("claim: {e}"));
        let token = lease.token();
        (registry, lease, token)
    }

    fn ns(server: &str) -> Vec<Arc<str>> {
        vec![Arc::from(server)]
    }

    const NS_ADDR: &str = "10.0.0.53:53";

    fn ns_socket() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 53)), 53)
    }

    fn build_resolver(
        token: OwnerToken,
        servers: &[Arc<str>],
        transport: Arc<FakeTransport>,
        clock: &ManualClock,
        budget: Duration,
    ) -> ExplicitResolver {
        ExplicitResolver::new(
            token,
            servers,
            transport as Arc<dyn DnsTransport>,
            Arc::new(clock.clone()) as Arc<dyn Clock>,
            budget,
        )
        .unwrap_or_else(|e| unreachable!("resolver: {e}"))
    }

    fn ipv4(ip: [u8; 4]) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]))
    }

    // A golden, hand-authored A/AAAA-free response with compression pointers,
    // NOT produced by the production encoder, proving the hickory decode path:
    // question `cdn.example. A`, CNAME `cdn.example. -> origin.example.` (with a
    // pointer to the question's `example` label), then `origin.example. A
    // 203.0.113.7` (with a pointer to the CNAME target's name).
    const GOLDEN_CNAME_A: [u8; 66] = [
        0x00, 0x00, 0x84, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, // header
        0x03, b'c', b'd', b'n', 0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x00, // qname
        0x00, 0x01, 0x00, 0x01, // qtype A, qclass IN
        0xC0, 0x0C, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x09, // CNAME hdr
        0x06, b'o', b'r', b'i', b'g', b'i', b'n', 0xC0, 0x10, // origin + ptr to example
        0xC0, 0x29, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x04, // A hdr
        0xCB, 0x00, 0x71, 0x07, // 203.0.113.7
    ];

    // A malformed response whose answer name is a self-referential compression
    // pointer (offset 19 -> 19): hickory must reject it without panicking.
    const MALFORMED_POINTER_LOOP: [u8; 21] = [
        0x00, 0x00, 0x84, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, // header
        0x01, b'x', 0x00, 0x00, 0x01, 0x00, 0x01, // question x. A IN
        0xC0, 0x13, // answer name: pointer to offset 19 (itself)
    ];

    // ---------------------------------------------------------------------
    // 15. Literal-IP host is emitted directly with zero wire queries.
    // ---------------------------------------------------------------------
    #[tokio::test]
    async fn literal_ip_host_bypasses_wire() {
        let clock = ManualClock::new();
        let transport = FakeTransport::new(&clock);
        let (_registry, _lease, token) = owner();
        // A deliberately broken nameserver: any query would time out.
        let resolver = build_resolver(
            token,
            &ns(NS_ADDR),
            Arc::clone(&transport),
            &clock,
            Duration::from_secs(5),
        );

        let out = resolver.resolve("198.51.100.9").await;
        assert_eq!(out, Ok(vec![ipv4([198, 51, 100, 9])]));
        assert_eq!(transport.a_count(), 0);
        assert_eq!(transport.aaaa_count(), 0);

        let bracketed = resolver.resolve("[2001:db8::1]").await;
        assert_eq!(
            bracketed,
            Ok(vec![IpAddr::V6(Ipv6Addr::new(
                0x2001, 0xdb8, 0, 0, 0, 0, 0, 1
            ))])
        );
        assert_eq!(transport.a_count(), 0);
    }

    // ---------------------------------------------------------------------
    // 1. Golden compressed CNAME->A packet decodes to the right A.
    // ---------------------------------------------------------------------
    #[tokio::test]
    async fn golden_compressed_cname_a_decodes() {
        let clock = ManualClock::new();
        let transport = FakeTransport::new(&clock);
        let server = ns_socket();
        transport.set_udp(
            "cdn.example",
            RecordType::A,
            Arc::new(move |id, _n, _t, _s| {
                vec![datagram(server, patch_id(GOLDEN_CNAME_A.to_vec(), id))]
            }),
        );
        let (_registry, _lease, token) = owner();
        let resolver = build_resolver(
            token,
            &ns(NS_ADDR),
            Arc::clone(&transport),
            &clock,
            Duration::from_secs(5),
        );

        let out = resolver.resolve("cdn.example").await;
        assert_eq!(out, Ok(vec![ipv4([203, 0, 113, 7])]));
    }

    // ---------------------------------------------------------------------
    // 2. Malformed / compression-loop bytes -> skipped, no panic; good reply
    //    within budget still wins; malformed-only fails closed.
    // ---------------------------------------------------------------------
    #[tokio::test]
    async fn malformed_bytes_are_skipped_then_good_reply_wins() {
        let clock = ManualClock::new();
        let transport = FakeTransport::new(&clock);
        let server = ns_socket();
        let good = name("host.test");
        transport.set_udp(
            "host.test",
            RecordType::A,
            Arc::new(move |id, qname, _t, _s| {
                vec![
                    datagram(server, patch_id(MALFORMED_POINTER_LOOP.to_vec(), id)),
                    datagram(
                        server,
                        encode(
                            id,
                            qname,
                            RecordType::A,
                            ResponseCode::NoError,
                            &[a_record(&good, [192, 0, 2, 5], 30)],
                            &[],
                            false,
                        ),
                    ),
                ]
            }),
        );
        let (_registry, _lease, token) = owner();
        let resolver = build_resolver(
            token,
            &ns(NS_ADDR),
            Arc::clone(&transport),
            &clock,
            Duration::from_secs(5),
        );

        let out = resolver.resolve("host.test").await;
        assert_eq!(out, Ok(vec![ipv4([192, 0, 2, 5])]));
    }

    #[tokio::test]
    async fn malformed_only_fails_closed() {
        let clock = ManualClock::new();
        let transport = FakeTransport::new(&clock);
        let server = ns_socket();
        transport.set_udp(
            "host.test",
            RecordType::A,
            Arc::new(move |id, _n, _t, _s| {
                vec![datagram(
                    server,
                    patch_id(MALFORMED_POINTER_LOOP.to_vec(), id),
                )]
            }),
        );
        transport.set_udp(
            "host.test",
            RecordType::AAAA,
            Arc::new(move |id, _n, _t, _s| {
                vec![datagram(
                    server,
                    patch_id(MALFORMED_POINTER_LOOP.to_vec(), id),
                )]
            }),
        );
        let (_registry, _lease, token) = owner();
        let resolver = build_resolver(
            token,
            &ns(NS_ADDR),
            Arc::clone(&transport),
            &clock,
            Duration::from_secs(5),
        );

        assert_eq!(
            resolver.resolve("host.test").await,
            Err(ResolveError::LookupFailed)
        );
    }

    // ---------------------------------------------------------------------
    // 3. TXID mismatch is dropped; the correct reply wins.
    // ---------------------------------------------------------------------
    #[tokio::test]
    async fn txid_mismatch_is_dropped() {
        let clock = ManualClock::new();
        let transport = FakeTransport::new(&clock);
        let server = ns_socket();
        let host = name("host.test");
        transport.set_udp(
            "host.test",
            RecordType::A,
            Arc::new(move |id, qname, _t, _s| {
                // A spoof with the wrong id and the tempting address, then the
                // genuine reply.
                let spoof = encode(
                    id ^ 0x5555,
                    qname,
                    RecordType::A,
                    ResponseCode::NoError,
                    &[a_record(&host, [10, 10, 10, 10], 30)],
                    &[],
                    false,
                );
                let genuine = encode(
                    id,
                    qname,
                    RecordType::A,
                    ResponseCode::NoError,
                    &[a_record(&host, [192, 0, 2, 9], 30)],
                    &[],
                    false,
                );
                vec![datagram(server, spoof), datagram(server, genuine)]
            }),
        );
        let (_registry, _lease, token) = owner();
        let resolver = build_resolver(
            token,
            &ns(NS_ADDR),
            Arc::clone(&transport),
            &clock,
            Duration::from_secs(5),
        );

        assert_eq!(
            resolver.resolve("host.test").await,
            Ok(vec![ipv4([192, 0, 2, 9])])
        );
    }

    // ---------------------------------------------------------------------
    // 4. Wrong question (name) is dropped.
    // ---------------------------------------------------------------------
    #[tokio::test]
    async fn wrong_question_is_dropped() {
        let clock = ManualClock::new();
        let transport = FakeTransport::new(&clock);
        let server = ns_socket();
        let host = name("host.test");
        let other = name("evil.test");
        transport.set_udp(
            "host.test",
            RecordType::A,
            Arc::new(move |id, qname, _t, _s| {
                let wrong = encode(
                    id,
                    &other,
                    RecordType::A,
                    ResponseCode::NoError,
                    &[a_record(&other, [10, 10, 10, 10], 30)],
                    &[],
                    false,
                );
                let genuine = encode(
                    id,
                    qname,
                    RecordType::A,
                    ResponseCode::NoError,
                    &[a_record(&host, [192, 0, 2, 11], 30)],
                    &[],
                    false,
                );
                vec![datagram(server, wrong), datagram(server, genuine)]
            }),
        );
        let (_registry, _lease, token) = owner();
        let resolver = build_resolver(
            token,
            &ns(NS_ADDR),
            Arc::clone(&transport),
            &clock,
            Duration::from_secs(5),
        );

        assert_eq!(
            resolver.resolve("host.test").await,
            Ok(vec![ipv4([192, 0, 2, 11])])
        );
    }

    // ---------------------------------------------------------------------
    // 5. A reply from a non-nameserver source is dropped (connected UDP).
    // ---------------------------------------------------------------------
    #[tokio::test]
    async fn non_ns_source_is_dropped() {
        let clock = ManualClock::new();
        let transport = FakeTransport::new(&clock);
        let server = ns_socket();
        let attacker = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 66)), 53);
        let host = name("host.test");
        transport.set_udp(
            "host.test",
            RecordType::A,
            Arc::new(move |id, qname, _t, _s| {
                let spoof = encode(
                    id,
                    qname,
                    RecordType::A,
                    ResponseCode::NoError,
                    &[a_record(&host, [10, 10, 10, 10], 30)],
                    &[],
                    false,
                );
                let genuine = encode(
                    id,
                    qname,
                    RecordType::A,
                    ResponseCode::NoError,
                    &[a_record(&host, [192, 0, 2, 13], 30)],
                    &[],
                    false,
                );
                vec![datagram(attacker, spoof), datagram(server, genuine)]
            }),
        );
        let (_registry, _lease, token) = owner();
        let resolver = build_resolver(
            token,
            &ns(NS_ADDR),
            Arc::clone(&transport),
            &clock,
            Duration::from_secs(5),
        );

        assert_eq!(
            resolver.resolve("host.test").await,
            Ok(vec![ipv4([192, 0, 2, 13])])
        );
    }

    // ---------------------------------------------------------------------
    // 6. TC bit -> retried over TCP; the TCP answer is used.
    // ---------------------------------------------------------------------
    #[tokio::test]
    async fn truncated_answer_retries_over_tcp() {
        let clock = ManualClock::new();
        let transport = FakeTransport::new(&clock);
        let server = ns_socket();
        let host = name("host.test");
        let host_udp = host.clone();
        transport.set_udp(
            "host.test",
            RecordType::A,
            Arc::new(move |id, qname, _t, _s| {
                let truncated = encode(
                    id,
                    qname,
                    RecordType::A,
                    ResponseCode::NoError,
                    &[a_record(&host_udp, [10, 10, 10, 10], 30)],
                    &[],
                    true,
                );
                vec![datagram(server, truncated)]
            }),
        );
        transport.set_tcp(
            "host.test",
            RecordType::A,
            Arc::new(move |id, qname, _t, _s| {
                Some(encode(
                    id,
                    qname,
                    RecordType::A,
                    ResponseCode::NoError,
                    &[a_record(&host, [192, 0, 2, 15], 30)],
                    &[],
                    false,
                ))
            }),
        );
        let (_registry, _lease, token) = owner();
        let resolver = build_resolver(
            token,
            &ns(NS_ADDR),
            Arc::clone(&transport),
            &clock,
            Duration::from_secs(5),
        );

        assert_eq!(
            resolver.resolve("host.test").await,
            Ok(vec![ipv4([192, 0, 2, 15])])
        );
    }

    // ---------------------------------------------------------------------
    // 7. CNAME chain -> A succeeds; loop and over-depth fail closed.
    // ---------------------------------------------------------------------
    #[tokio::test]
    async fn cname_chain_resolves_and_loops_fail() {
        // Chain across responses: alias.test CNAME real.test, then real.test A.
        let clock = ManualClock::new();
        let transport = FakeTransport::new(&clock);
        let server = ns_socket();
        let alias = name("alias.test");
        let real = name("real.test");
        let real_for_a = real.clone();
        transport.set_udp(
            "alias.test",
            RecordType::A,
            Arc::new(move |id, qname, _t, _s| {
                vec![datagram(
                    server,
                    encode(
                        id,
                        qname,
                        RecordType::A,
                        ResponseCode::NoError,
                        &[cname_record(&alias, &real, 40)],
                        &[],
                        false,
                    ),
                )]
            }),
        );
        transport.set_udp(
            "real.test",
            RecordType::A,
            Arc::new(move |id, qname, _t, _s| {
                vec![datagram(
                    server,
                    encode(
                        id,
                        qname,
                        RecordType::A,
                        ResponseCode::NoError,
                        &[a_record(&real_for_a, [192, 0, 2, 21], 40)],
                        &[],
                        false,
                    ),
                )]
            }),
        );
        let (_registry, _lease, token) = owner();
        let resolver = build_resolver(
            token,
            &ns(NS_ADDR),
            Arc::clone(&transport),
            &clock,
            Duration::from_secs(5),
        );
        assert_eq!(
            resolver.resolve("alias.test").await,
            Ok(vec![ipv4([192, 0, 2, 21])])
        );
    }

    #[tokio::test]
    async fn cname_loop_fails_closed() {
        // A two-node loop: loop.test -> pong.test -> loop.test.
        let server = ns_socket();
        let clock2 = ManualClock::new();
        let transport2 = FakeTransport::new(&clock2);
        let loop_a = name("loop.test");
        let pong = name("pong.test");
        let loop_b = loop_a.clone();
        let pong_b = pong.clone();
        transport2.set_udp(
            "loop.test",
            RecordType::A,
            Arc::new(move |id, qname, _t, _s| {
                vec![datagram(
                    server,
                    encode(
                        id,
                        qname,
                        RecordType::A,
                        ResponseCode::NoError,
                        &[cname_record(&loop_a, &pong, 40)],
                        &[],
                        false,
                    ),
                )]
            }),
        );
        transport2.set_udp(
            "pong.test",
            RecordType::A,
            Arc::new(move |id, qname, _t, _s| {
                vec![datagram(
                    server,
                    encode(
                        id,
                        qname,
                        RecordType::A,
                        ResponseCode::NoError,
                        &[cname_record(&pong_b, &loop_b, 40)],
                        &[],
                        false,
                    ),
                )]
            }),
        );
        let (_registry2, _lease2, token2) = owner();
        let resolver2 = build_resolver(
            token2,
            &ns(NS_ADDR),
            Arc::clone(&transport2),
            &clock2,
            Duration::from_secs(5),
        );
        assert_eq!(
            resolver2.resolve("loop.test").await,
            Err(ResolveError::LookupFailed)
        );
    }

    // ---------------------------------------------------------------------
    // 8. A and AAAA are each queried exactly once for N concurrent callers.
    // ---------------------------------------------------------------------
    #[tokio::test]
    async fn concurrent_callers_share_one_query_per_family() {
        let clock = ManualClock::new();
        let transport = FakeTransport::new(&clock);
        transport.yield_first.store(true, Ordering::SeqCst);
        let server = ns_socket();
        let host = name("shared.test");
        let host_a = host.clone();
        transport.set_udp(
            "shared.test",
            RecordType::A,
            Arc::new(move |id, qname, _t, _s| {
                vec![datagram(
                    server,
                    encode(
                        id,
                        qname,
                        RecordType::A,
                        ResponseCode::NoError,
                        &[a_record(&host_a, [192, 0, 2, 31], 30)],
                        &[],
                        false,
                    ),
                )]
            }),
        );
        transport.set_udp(
            "shared.test",
            RecordType::AAAA,
            Arc::new(move |id, qname, _t, _s| {
                vec![datagram(
                    server,
                    encode(
                        id,
                        qname,
                        RecordType::AAAA,
                        ResponseCode::NoError,
                        &[aaaa_record(&host, 30)],
                        &[],
                        false,
                    ),
                )]
            }),
        );
        let (_registry, _lease, token) = owner();
        let resolver = build_resolver(
            token,
            &ns(NS_ADDR),
            Arc::clone(&transport),
            &clock,
            Duration::from_secs(5),
        );

        let calls = (0..16).map(|_| resolver.resolve("shared.test"));
        let results = join_all(calls).await;
        for result in &results {
            assert!(result.is_ok(), "concurrent resolve failed: {result:?}");
            assert_eq!(result.as_ref(), results[0].as_ref());
        }
        assert_eq!(transport.a_count(), 1);
        assert_eq!(transport.aaaa_count(), 1);
    }

    // ---------------------------------------------------------------------
    // 9. Positive TTL: cache hit, expiry re-query, TTL=0 uncached, 5s cap.
    // ---------------------------------------------------------------------
    #[tokio::test]
    async fn positive_ttl_cache_and_expiry() {
        let clock = ManualClock::new();
        let transport = FakeTransport::new(&clock);
        let server = ns_socket();
        let host = name("cache.test");
        transport.set_udp(
            "cache.test",
            RecordType::A,
            Arc::new(move |id, qname, _t, _s| {
                vec![datagram(
                    server,
                    encode(
                        id,
                        qname,
                        RecordType::A,
                        ResponseCode::NoError,
                        &[a_record(&host, [192, 0, 2, 41], 100)],
                        &[],
                        false,
                    ),
                )]
            }),
        );
        let (_registry, _lease, token) = owner();
        let resolver = build_resolver(
            token,
            &ns(NS_ADDR),
            Arc::clone(&transport),
            &clock,
            Duration::from_secs(5),
        );

        assert_eq!(
            resolver.resolve("cache.test").await,
            Ok(vec![ipv4([192, 0, 2, 41])])
        );
        assert_eq!(transport.a_count(), 1);
        // Within the 5s cap (TTL 100 capped to 5): still cached at 4s.
        clock.advance(Duration::from_secs(4));
        assert_eq!(
            resolver.resolve("cache.test").await,
            Ok(vec![ipv4([192, 0, 2, 41])])
        );
        assert_eq!(transport.a_count(), 1);
        // Past the cap: re-query.
        clock.advance(Duration::from_secs(2));
        assert_eq!(
            resolver.resolve("cache.test").await,
            Ok(vec![ipv4([192, 0, 2, 41])])
        );
        assert_eq!(transport.a_count(), 2);
    }

    #[tokio::test]
    async fn zero_ttl_is_never_cached() {
        let clock = ManualClock::new();
        let transport = FakeTransport::new(&clock);
        let server = ns_socket();
        let host = name("nocache.test");
        transport.set_udp(
            "nocache.test",
            RecordType::A,
            Arc::new(move |id, qname, _t, _s| {
                vec![datagram(
                    server,
                    encode(
                        id,
                        qname,
                        RecordType::A,
                        ResponseCode::NoError,
                        &[a_record(&host, [192, 0, 2, 43], 0)],
                        &[],
                        false,
                    ),
                )]
            }),
        );
        let (_registry, _lease, token) = owner();
        let resolver = build_resolver(
            token,
            &ns(NS_ADDR),
            Arc::clone(&transport),
            &clock,
            Duration::from_secs(5),
        );

        assert_eq!(
            resolver.resolve("nocache.test").await,
            Ok(vec![ipv4([192, 0, 2, 43])])
        );
        assert_eq!(
            resolver.resolve("nocache.test").await,
            Ok(vec![ipv4([192, 0, 2, 43])])
        );
        assert_eq!(transport.a_count(), 2);
    }

    // ---------------------------------------------------------------------
    // 10. Negative cache: NXDOMAIN and NODATA+SOA cached; SERVFAIL,
    //     NODATA-without-SOA, and timeout are not cached.
    // ---------------------------------------------------------------------
    #[tokio::test]
    async fn nxdomain_is_negatively_cached() {
        let clock = ManualClock::new();
        let transport = FakeTransport::new(&clock);
        let server = ns_socket();
        let host = name("gone.test");
        let responder: UdpResponder = Arc::new(move |id, qname, rtype, _s| {
            vec![datagram(
                server,
                encode(
                    id,
                    qname,
                    rtype,
                    ResponseCode::NXDomain,
                    &[],
                    &[soa_record(&host, 200, 3)],
                    false,
                ),
            )]
        });
        transport.set_udp("gone.test", RecordType::A, responder.clone());
        transport.set_udp("gone.test", RecordType::AAAA, responder);
        let (_registry, _lease, token) = owner();
        let resolver = build_resolver(
            token,
            &ns(NS_ADDR),
            Arc::clone(&transport),
            &clock,
            Duration::from_secs(5),
        );

        assert_eq!(
            resolver.resolve("gone.test").await,
            Err(ResolveError::NameResolution)
        );
        let queried = transport.a_count();
        clock.advance(Duration::from_secs(2));
        assert_eq!(
            resolver.resolve("gone.test").await,
            Err(ResolveError::NameResolution)
        );
        assert_eq!(
            transport.a_count(),
            queried,
            "second lookup must hit the negative cache"
        );
    }

    #[tokio::test]
    async fn servfail_is_not_cached() {
        let clock = ManualClock::new();
        let transport = FakeTransport::new(&clock);
        let server = ns_socket();
        let responder: UdpResponder = Arc::new(move |id, qname, rtype, _s| {
            vec![datagram(
                server,
                encode(id, qname, rtype, ResponseCode::ServFail, &[], &[], false),
            )]
        });
        transport.set_udp("broken.test", RecordType::A, responder.clone());
        transport.set_udp("broken.test", RecordType::AAAA, responder);
        let (_registry, _lease, token) = owner();
        let resolver = build_resolver(
            token,
            &ns(NS_ADDR),
            Arc::clone(&transport),
            &clock,
            Duration::from_secs(5),
        );

        assert_eq!(
            resolver.resolve("broken.test").await,
            Err(ResolveError::LookupFailed)
        );
        let first = transport.a_count();
        assert_eq!(
            resolver.resolve("broken.test").await,
            Err(ResolveError::LookupFailed)
        );
        assert!(transport.a_count() > first, "SERVFAIL must not be cached");
    }

    #[tokio::test]
    async fn nodata_without_soa_is_not_cached() {
        let clock = ManualClock::new();
        let transport = FakeTransport::new(&clock);
        let server = ns_socket();
        let responder: UdpResponder = Arc::new(move |id, qname, rtype, _s| {
            vec![datagram(
                server,
                encode(id, qname, rtype, ResponseCode::NoError, &[], &[], false),
            )]
        });
        transport.set_udp("empty.test", RecordType::A, responder.clone());
        transport.set_udp("empty.test", RecordType::AAAA, responder);
        let (_registry, _lease, token) = owner();
        let resolver = build_resolver(
            token,
            &ns(NS_ADDR),
            Arc::clone(&transport),
            &clock,
            Duration::from_secs(5),
        );

        assert_eq!(
            resolver.resolve("empty.test").await,
            Err(ResolveError::NameResolution)
        );
        let first = transport.a_count();
        assert_eq!(
            resolver.resolve("empty.test").await,
            Err(ResolveError::NameResolution)
        );
        assert!(
            transport.a_count() > first,
            "NODATA without SOA must not be cached"
        );
    }

    // ---------------------------------------------------------------------
    // 11. Anti-poisoning: an unrelated A in the answer is excluded.
    // ---------------------------------------------------------------------
    #[tokio::test]
    async fn unrelated_answer_is_excluded() {
        let clock = ManualClock::new();
        let transport = FakeTransport::new(&clock);
        let server = ns_socket();
        let host = name("host.test");
        let evil = name("evil.test");
        transport.set_udp(
            "host.test",
            RecordType::A,
            Arc::new(move |id, qname, _t, _s| {
                vec![datagram(
                    server,
                    encode(
                        id,
                        qname,
                        RecordType::A,
                        ResponseCode::NoError,
                        &[
                            a_record(&host, [192, 0, 2, 51], 30),
                            a_record(&evil, [6, 6, 6, 6], 30),
                        ],
                        &[],
                        false,
                    ),
                )]
            }),
        );
        let (_registry, _lease, token) = owner();
        let resolver = build_resolver(
            token,
            &ns(NS_ADDR),
            Arc::clone(&transport),
            &clock,
            Duration::from_secs(5),
        );

        let out = resolver.resolve("host.test").await;
        assert_eq!(out, Ok(vec![ipv4([192, 0, 2, 51])]));
    }

    // ---------------------------------------------------------------------
    // 12. Single absolute deadline: each flattened ns tried once across the one
    //     budget; a stalling nameserver never extends past it.
    // ---------------------------------------------------------------------
    #[tokio::test]
    async fn single_absolute_deadline_bounds_total() {
        let clock = ManualClock::new();
        let transport = FakeTransport::new(&clock);
        let servers: Vec<Arc<str>> = vec![
            Arc::from("10.0.0.1:53"),
            Arc::from("10.0.0.2:53"),
            Arc::from("10.0.0.3:53"),
        ];
        // Every attempt delivers no datagram, so each times out and consumes its
        // per-attempt slice of the single budget.
        let stall: UdpResponder = Arc::new(|_id, _n, _t, _s| Vec::new());
        transport.set_udp("stall.test", RecordType::A, stall.clone());
        transport.set_udp("stall.test", RecordType::AAAA, stall);
        let (_registry, _lease, token) = owner();
        let budget = Duration::from_secs(6);
        let resolver = build_resolver(token, &servers, Arc::clone(&transport), &clock, budget);

        assert_eq!(
            resolver.resolve("stall.test").await,
            Err(ResolveError::LookupFailed)
        );
        // Across both families and the single budget, each of the three
        // nameservers is contacted at most once in total.
        assert_eq!(transport.a_count() + transport.aaaa_count(), 3);
        // The clock never advanced beyond the single budget.
        assert!(
            clock.elapsed() <= budget,
            "elapsed {:?} exceeded budget",
            clock.elapsed()
        );
    }

    // ---------------------------------------------------------------------
    // 13. Bounds: cache eviction-of-expired-then-uncached, and config bounds.
    // ---------------------------------------------------------------------
    #[test]
    fn insert_bounded_evicts_expired_then_refuses_when_full() {
        use super::{CacheEntry, CacheResult, insert_bounded};
        let base = Instant::now();
        let mut cache: HashMap<String, CacheEntry> = HashMap::new();
        // Fill with entries that are already expired relative to `now`.
        for index in 0..MAX_CACHE_ENTRIES {
            cache.insert(
                format!("expired-{index}"),
                CacheEntry {
                    result: CacheResult::Negative,
                    expires_at: base + Duration::from_secs(1),
                },
            );
        }
        assert_eq!(cache.len(), MAX_CACHE_ENTRIES);
        // Now is past every entry's expiry: insert evicts expired then admits.
        let now = base + Duration::from_secs(10);
        insert_bounded(
            &mut cache,
            "fresh".to_owned(),
            CacheEntry {
                result: CacheResult::Positive(vec![ipv4([192, 0, 2, 1])]),
                expires_at: now + Duration::from_secs(5),
            },
            now,
        );
        assert_eq!(cache.len(), 1);
        assert!(cache.contains_key("fresh"));

        // Fill with entries that are all still live; a full cache refuses.
        let mut full: HashMap<String, CacheEntry> = HashMap::new();
        for index in 0..MAX_CACHE_ENTRIES {
            full.insert(
                format!("live-{index}"),
                CacheEntry {
                    result: CacheResult::Negative,
                    expires_at: now + Duration::from_secs(100),
                },
            );
        }
        insert_bounded(
            &mut full,
            "overflow".to_owned(),
            CacheEntry {
                result: CacheResult::Negative,
                expires_at: now + Duration::from_secs(100),
            },
            now,
        );
        assert_eq!(full.len(), MAX_CACHE_ENTRIES);
        assert!(
            !full.contains_key("overflow"),
            "a full live cache must not admit new entries"
        );
    }

    #[test]
    fn too_many_nameservers_is_rejected() {
        let clock = ManualClock::new();
        let transport = FakeTransport::new(&clock);
        let (_registry, _lease, token) = owner();
        let servers: Vec<Arc<str>> = (0..=super::MAX_NS_SERVERS)
            .map(|index| Arc::from(format!("10.0.0.{}:53", index % 250)))
            .collect();
        let built = ExplicitResolver::new(
            token,
            &servers,
            transport as Arc<dyn DnsTransport>,
            Arc::new(clock.clone()) as Arc<dyn Clock>,
            Duration::from_secs(5),
        );
        assert_eq!(
            built.err(),
            Some(ResolveError::TooManyNsServers {
                count: super::MAX_NS_SERVERS + 1,
                maximum: super::MAX_NS_SERVERS,
            })
        );
    }

    #[test]
    fn zero_budget_is_rejected() {
        let clock = ManualClock::new();
        let transport = FakeTransport::new(&clock);
        let (_registry, _lease, token) = owner();
        let built = ExplicitResolver::new(
            token,
            &ns(NS_ADDR),
            transport as Arc<dyn DnsTransport>,
            Arc::new(clock.clone()) as Arc<dyn Clock>,
            Duration::ZERO,
        );
        assert_eq!(built.err(), Some(ResolveError::InvalidBudget));
    }

    #[test]
    fn inflight_table_is_bounded() {
        let clock = ManualClock::new();
        let transport = FakeTransport::new(&clock);
        transport.gate_open.store(false, Ordering::SeqCst);
        let (_registry, _lease, token) = owner();
        let resolver = build_resolver(
            token,
            &ns(NS_ADDR),
            Arc::clone(&transport),
            &clock,
            Duration::from_secs(5),
        );

        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);
        let hosts: Vec<String> = (0..super::MAX_INFLIGHT)
            .map(|index| format!("h{index}.test"))
            .collect();
        let mut pending = Vec::new();
        for host in &hosts {
            let mut future = Box::pin(resolver.resolve(host));
            assert!(matches!(future.as_mut().poll(&mut cx), Poll::Pending));
            pending.push(future);
        }
        // The table is now full; a new host is rejected without a wire query.
        let mut overflow = Box::pin(resolver.resolve("overflow.test"));
        assert!(matches!(
            overflow.as_mut().poll(&mut cx),
            Poll::Ready(Err(ResolveError::TooManyInflight))
        ));
        drop(pending);
    }

    // ---------------------------------------------------------------------
    // 14. Owner retire fence: a barrier-blocked stage, retired mid-await, drops
    //     the successful result and returns StaleOwner without caching.
    // ---------------------------------------------------------------------
    #[test]
    fn retired_owner_discards_result_and_caches_nothing() {
        let clock = ManualClock::new();
        let transport = FakeTransport::new(&clock);
        transport.gate_open.store(false, Ordering::SeqCst);
        let server = ns_socket();
        let host = name("fenced.test");
        // A TRUNCATED UDP answer, so that — absent the fence — the resolver would
        // proceed to a TCP retry. The post-await fence must stop before that.
        transport.set_udp(
            "fenced.test",
            RecordType::A,
            Arc::new(move |id, qname, _t, _s| {
                vec![datagram(
                    server,
                    encode(
                        id,
                        qname,
                        RecordType::A,
                        ResponseCode::NoError,
                        &[a_record(&host, [192, 0, 2, 61], 30)],
                        &[],
                        true,
                    ),
                )]
            }),
        );
        let tcp_host = name("fenced.test");
        transport.set_tcp(
            "fenced.test",
            RecordType::A,
            Arc::new(move |id, qname, _t, _s| {
                Some(encode(
                    id,
                    qname,
                    RecordType::A,
                    ResponseCode::NoError,
                    &[a_record(&tcp_host, [192, 0, 2, 62], 30)],
                    &[],
                    false,
                ))
            }),
        );
        let registry = OwnershipRegistry::new();
        let lease = registry
            .claim(OwnerScope::Process, "dns-owner")
            .unwrap_or_else(|e| unreachable!("claim: {e}"));
        let resolver = build_resolver(
            lease.token(),
            &ns(NS_ADDR),
            Arc::clone(&transport),
            &clock,
            Duration::from_secs(5),
        );

        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);
        let mut future = Box::pin(resolver.resolve("fenced.test"));
        // The resolution parks in the gated receive stage.
        assert!(matches!(future.as_mut().poll(&mut cx), Poll::Pending));
        // Retire the owner while the stage is blocked, then release the gate.
        lease.release();
        transport.gate_open.store(true, Ordering::SeqCst);

        // The post-await fence discards the (now available) success.
        let outcome = loop {
            match future.as_mut().poll(&mut cx) {
                Poll::Ready(outcome) => break outcome,
                Poll::Pending => {}
            }
        };
        assert_eq!(outcome, Err(ResolveError::StaleOwner));
        // The fence fired before the truncation-triggered TCP retry, and nothing
        // was written to the cache.
        assert_eq!(
            transport.tcp_count(),
            0,
            "a retired owner must not start a TCP retry"
        );
        assert_eq!(
            resolver.cache_len(),
            0,
            "a retired owner must cache nothing"
        );
    }

    // ---------------------------------------------------------------------
    // 11b. Nameserver hostname bootstrap via the injected transport.
    // ---------------------------------------------------------------------
    #[tokio::test]
    async fn nameserver_hostname_bootstrap_is_used() {
        let clock = ManualClock::new();
        let transport = FakeTransport::new(&clock);
        transport.set_bootstrap("dns.internal", vec![IpAddr::V4(Ipv4Addr::new(10, 9, 9, 9))]);
        let boot_server = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 9, 9, 9)), 53);
        let host = name("host.test");
        transport.set_udp(
            "host.test",
            RecordType::A,
            Arc::new(move |id, qname, _t, _s| {
                vec![datagram(
                    boot_server,
                    encode(
                        id,
                        qname,
                        RecordType::A,
                        ResponseCode::NoError,
                        &[a_record(&host, [192, 0, 2, 71], 30)],
                        &[],
                        false,
                    ),
                )]
            }),
        );
        let (_registry, _lease, token) = owner();
        let resolver = build_resolver(
            token,
            &ns("dns.internal:53"),
            Arc::clone(&transport),
            &clock,
            Duration::from_secs(5),
        );

        assert_eq!(
            resolver.resolve("host.test").await,
            Ok(vec![ipv4([192, 0, 2, 71])])
        );
    }

    #[tokio::test]
    async fn failed_bootstrap_fails_closed() {
        let clock = ManualClock::new();
        let transport = FakeTransport::new(&clock);
        // No bootstrap entry registered: the nameserver hostname cannot resolve.
        let (_registry, _lease, token) = owner();
        let resolver = build_resolver(
            token,
            &ns("dns.internal:53"),
            Arc::clone(&transport),
            &clock,
            Duration::from_secs(5),
        );

        assert_eq!(
            resolver.resolve("host.test").await,
            Err(ResolveError::NoNameservers)
        );
        assert_eq!(transport.a_count(), 0);
    }

    // ---------------------------------------------------------------------
    // 11c. A bootstrap timeout is not cached: the next resolve re-bootstraps.
    // ---------------------------------------------------------------------
    #[tokio::test]
    async fn bootstrap_timeout_is_not_cached_and_rebootstraps() {
        let clock = ManualClock::new();
        let transport = FakeTransport::new(&clock);
        transport.fail_bootstrap("ns.internal");
        let (_registry, _lease, token) = owner();
        let resolver = build_resolver(
            token,
            &ns("ns.internal:53"),
            Arc::clone(&transport),
            &clock,
            Duration::from_secs(5),
        );

        assert_eq!(
            resolver.resolve("target.test").await,
            Err(ResolveError::NoNameservers),
            "a bootstrap timeout leaves no usable nameserver"
        );
        assert_eq!(
            resolver.resolve("target.test").await,
            Err(ResolveError::NoNameservers),
            "the second resolve also fails closed"
        );
        assert_eq!(
            transport.boot_count(),
            2,
            "the bootstrap failure was not cached, so the second resolve re-bootstraps"
        );
    }

    // ---------------------------------------------------------------------
    // 11d. Retiring the owner mid-bootstrap yields StaleOwner and caches nothing.
    // ---------------------------------------------------------------------
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn bootstrap_stale_owner_writes_no_cache() {
        let finished = tokio::time::timeout(Duration::from_secs(5), async {
            let clock = ManualClock::new();
            let transport = FakeTransport::new(&clock);
            // The bootstrap WOULD succeed, but the gate parks it until the owner
            // has been retired.
            transport.set_bootstrap("ns.internal", vec![IpAddr::V4(Ipv4Addr::new(10, 9, 9, 9))]);
            transport.close_boot_gate();
            let started = transport.boot_started();

            let registry = OwnershipRegistry::new();
            let lease = registry
                .claim(OwnerScope::Process, "boot-owner")
                .unwrap_or_else(|error| unreachable!("claim: {error}"));
            let resolver = Arc::new(build_resolver(
                lease.token(),
                &ns("ns.internal:53"),
                Arc::clone(&transport),
                &clock,
                Duration::from_secs(5),
            ));

            let task_resolver = Arc::clone(&resolver);
            let handle = tokio::spawn(async move { task_resolver.resolve("target.test").await });

            // Wait until the bootstrap is in flight, then retire the owner and
            // release the gate so the (now stale) bootstrap completes.
            started.notified().await;
            lease.release();
            transport.open_boot_gate();

            let Ok(joined) = handle.await else {
                unreachable!("resolve task must not panic");
            };
            assert_eq!(
                joined,
                Err(ResolveError::StaleOwner),
                "a bootstrap that completes after the owner retired is discarded"
            );
            assert_eq!(
                resolver.cache_len(),
                0,
                "a stale-owner bootstrap writes no cache entry for the target"
            );
        })
        .await;
        assert!(
            finished.is_ok(),
            "the retire-during-bootstrap row must finish within the deadline"
        );
    }

    // --- pure-helper unit tests -----------------------------------------

    #[test]
    fn canonical_key_lowercases_and_strips_trailing_dot() {
        assert_eq!(canonical_key("Host.Example.COM."), "host.example.com");
        assert_eq!(canonical_key("host"), "host");
    }

    #[test]
    fn interleave_dedup_caps_and_orders() {
        use super::interleave_dedup_cap;
        let v4: Vec<IpAddr> = (0..6).map(|i| ipv4([192, 0, 2, i])).collect();
        let v6: Vec<IpAddr> = (0u16..6)
            .map(|i| IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, i)))
            .collect();
        let out = interleave_dedup_cap(&v4, &v6);
        assert_eq!(out.len(), super::MAX_RESOLVED_ADDRS);
        assert_eq!(out[0], v4[0]);
        assert_eq!(out[1], v6[0]);
        assert_eq!(out[2], v4[1]);
    }

    // --- negative-response responder helpers -----------------------------

    fn sock(ip: [u8; 4], port: u16) -> SocketAddr {
        SocketAddr::new(ipv4(ip), port)
    }

    fn nodata_with_soa(owner: Name, class: DNSClass, minimum: u32, ttl: u32) -> UdpResponder {
        Arc::new(move |id, qname, rtype, server| {
            let mut soa = soa_record(&owner, minimum, ttl);
            soa.dns_class = class;
            vec![datagram(
                server,
                encode(id, qname, rtype, ResponseCode::NoError, &[], &[soa], false),
            )]
        })
    }

    fn nodata_no_soa() -> UdpResponder {
        Arc::new(move |id, qname, rtype, server| {
            vec![datagram(
                server,
                encode(id, qname, rtype, ResponseCode::NoError, &[], &[], false),
            )]
        })
    }

    fn nxdomain_with_soa(owner: Name, minimum: u32, ttl: u32) -> UdpResponder {
        Arc::new(move |id, qname, rtype, server| {
            vec![datagram(
                server,
                encode(
                    id,
                    qname,
                    rtype,
                    ResponseCode::NXDomain,
                    &[],
                    &[soa_record(&owner, minimum, ttl)],
                    false,
                ),
            )]
        })
    }

    // ---------------------------------------------------------------------
    // Blocker 3: per-entry NS flatten (order preserved, per-entry sort/dedup/cap,
    // duplicate entries survive, global cap 32, no cross-entry sort/dedup).
    // ---------------------------------------------------------------------
    #[tokio::test]
    async fn flatten_expands_hostname_entry_sorted_deduped_capped() {
        let clock = ManualClock::new();
        let transport = FakeTransport::new(&clock);
        // Out-of-order with a duplicate and more than eight distinct addresses.
        transport.set_bootstrap(
            "dns.internal",
            [9u8, 3, 3, 1, 7, 5, 2, 8, 4, 6]
                .into_iter()
                .map(|n| IpAddr::V4(Ipv4Addr::new(10, 0, 0, n)))
                .collect(),
        );
        let (_registry, _lease, token) = owner();
        let resolver = build_resolver(
            token,
            &ns("dns.internal:53"),
            Arc::clone(&transport),
            &clock,
            Duration::from_secs(5),
        );
        let flattened = resolver.flatten_ns_for_test().await;
        let expected: Vec<SocketAddr> = (1u8..=8).map(|n| sock([10, 0, 0, n], 53)).collect();
        assert_eq!(flattened, expected);
    }

    #[tokio::test]
    async fn flatten_preserves_duplicate_entries_and_config_order() {
        let clock = ManualClock::new();
        let transport = FakeTransport::new(&clock);
        // Entries in a fixed (config-projected) order, including a duplicate.
        let servers: Vec<Arc<str>> = vec![
            Arc::from("10.0.0.2:53"),
            Arc::from("10.0.0.1:53"),
            Arc::from("10.0.0.2:53"),
        ];
        let (_registry, _lease, token) = owner();
        let resolver = build_resolver(
            token,
            &servers,
            Arc::clone(&transport),
            &clock,
            Duration::from_secs(5),
        );
        let flattened = resolver.flatten_ns_for_test().await;
        // Entry order is preserved, the duplicate survives, and there is no
        // cross-entry numeric sort or dedup.
        assert_eq!(
            flattened,
            vec![
                sock([10, 0, 0, 2], 53),
                sock([10, 0, 0, 1], 53),
                sock([10, 0, 0, 2], 53),
            ]
        );
    }

    #[tokio::test]
    async fn flatten_caps_total_across_entries_to_32() {
        let clock = ManualClock::new();
        let transport = FakeTransport::new(&clock);
        let mut servers: Vec<Arc<str>> = Vec::new();
        for entry in 0u8..5 {
            let host = format!("host{entry}.internal");
            transport.set_bootstrap(
                &host,
                (0u8..8)
                    .map(|n| IpAddr::V4(Ipv4Addr::new(10, entry, 0, n)))
                    .collect(),
            );
            servers.push(Arc::from(format!("{host}:53")));
        }
        let (_registry, _lease, token) = owner();
        let resolver = build_resolver(
            token,
            &servers,
            Arc::clone(&transport),
            &clock,
            Duration::from_secs(5),
        );
        let flattened = resolver.flatten_ns_for_test().await;
        // Five entries * eight = 40 capped to 32; the fifth entry is dropped.
        assert_eq!(flattened.len(), super::MAX_NS_SOCKET_ADDRS);
        assert!(
            flattened.iter().all(|addr| match addr.ip() {
                IpAddr::V4(v4) => v4.octets()[1] < 4,
                IpAddr::V6(_) => false,
            }),
            "the fifth entry's addresses must be dropped by the global cap"
        );
    }

    // ---------------------------------------------------------------------
    // Blocker 4: direct-API validation matches config normalize_ns_server.
    // ---------------------------------------------------------------------
    #[test]
    fn ns_entry_parse_rejects_malformed_and_accepts_normalized() {
        let clock = ManualClock::new();
        let transport = FakeTransport::new(&clock);
        let (_registry, _lease, token) = owner();
        let build = |server: &str| {
            ExplicitResolver::new(
                token.clone(),
                &[Arc::from(server)],
                Arc::clone(&transport) as Arc<dyn DnsTransport>,
                Arc::new(clock.clone()) as Arc<dyn Clock>,
                Duration::from_secs(5),
            )
        };
        for rejected in ["dns.example:0", "10.0.0.1:0", "[dns.example]:53"] {
            assert_eq!(
                build(rejected).err(),
                Some(ResolveError::InvalidNsServer { index: 0 }),
                "must reject {rejected}"
            );
        }
        for accepted in ["dns.example:53", "10.0.0.1:53", "[2001:db8::1]:53"] {
            assert!(build(accepted).is_ok(), "must accept {accepted}");
        }
    }

    // ---------------------------------------------------------------------
    // Blocker 5: NXDOMAIN vs NODATA kind + SOA class/owner anti-poisoning.
    // ---------------------------------------------------------------------
    #[tokio::test]
    async fn nodata_with_soa_on_both_families_is_cached_and_expires() {
        let clock = ManualClock::new();
        let transport = FakeTransport::new(&clock);
        let responder = nodata_with_soa(name("nd.test"), DNSClass::IN, 200, 3);
        transport.set_udp("nd.test", RecordType::A, responder.clone());
        transport.set_udp("nd.test", RecordType::AAAA, responder);
        let (_registry, _lease, token) = owner();
        let resolver = build_resolver(
            token,
            &ns(NS_ADDR),
            Arc::clone(&transport),
            &clock,
            Duration::from_secs(5),
        );

        assert_eq!(
            resolver.resolve("nd.test").await,
            Err(ResolveError::NameResolution)
        );
        let queried = transport.a_count();
        clock.advance(Duration::from_secs(2));
        assert_eq!(
            resolver.resolve("nd.test").await,
            Err(ResolveError::NameResolution)
        );
        assert_eq!(transport.a_count(), queried, "cached within the SOA TTL");
        clock.advance(Duration::from_secs(2));
        assert_eq!(
            resolver.resolve("nd.test").await,
            Err(ResolveError::NameResolution)
        );
        assert!(transport.a_count() > queried, "re-queries after TTL expiry");
    }

    #[tokio::test]
    async fn nodata_without_soa_on_one_family_is_not_cached() {
        let clock = ManualClock::new();
        let transport = FakeTransport::new(&clock);
        transport.set_udp(
            "mix.test",
            RecordType::A,
            nodata_with_soa(name("mix.test"), DNSClass::IN, 200, 5),
        );
        transport.set_udp("mix.test", RecordType::AAAA, nodata_no_soa());
        let (_registry, _lease, token) = owner();
        let resolver = build_resolver(
            token,
            &ns(NS_ADDR),
            Arc::clone(&transport),
            &clock,
            Duration::from_secs(5),
        );

        assert_eq!(
            resolver.resolve("mix.test").await,
            Err(ResolveError::NameResolution)
        );
        let first = transport.a_count();
        assert_eq!(
            resolver.resolve("mix.test").await,
            Err(ResolveError::NameResolution)
        );
        assert!(
            transport.a_count() > first,
            "a NODATA-without-SOA family must block negative caching"
        );
    }

    #[tokio::test]
    async fn nxdomain_negative_ttl_is_soa_capped() {
        let clock = ManualClock::new();
        let transport = FakeTransport::new(&clock);
        // SOA minimum/TTL far above the 5s cap.
        let responder = nxdomain_with_soa(name("void.test"), 100_000, 100_000);
        transport.set_udp("void.test", RecordType::A, responder.clone());
        transport.set_udp("void.test", RecordType::AAAA, responder);
        let (_registry, _lease, token) = owner();
        let resolver = build_resolver(
            token,
            &ns(NS_ADDR),
            Arc::clone(&transport),
            &clock,
            Duration::from_secs(5),
        );

        assert_eq!(
            resolver.resolve("void.test").await,
            Err(ResolveError::NameResolution)
        );
        let queried = transport.a_count();
        clock.advance(Duration::from_secs(4));
        assert_eq!(
            resolver.resolve("void.test").await,
            Err(ResolveError::NameResolution)
        );
        assert_eq!(transport.a_count(), queried, "cached within the 5s cap");
        clock.advance(Duration::from_secs(2));
        assert_eq!(
            resolver.resolve("void.test").await,
            Err(ResolveError::NameResolution)
        );
        assert!(transport.a_count() > queried, "re-queries past the 5s cap");
    }

    #[tokio::test]
    async fn nxdomain_with_other_family_timeout_is_name_wide_and_cached() {
        // A returns an authoritative NXDOMAIN with an SOA; AAAA times out. A
        // name-wide NXDOMAIN must not be downgraded by the other family's soft
        // failure: the outcome is NameResolution (not LookupFailed) AND it is
        // negatively cached by the SOA TTL. Reordering the soft-failure check
        // ahead of the NXDOMAIN check turns this RED.
        let clock = ManualClock::new();
        let transport = FakeTransport::new(&clock);
        transport.set_udp(
            "gone.test",
            RecordType::A,
            nxdomain_with_soa(name("gone.test"), 200, 5),
        );
        let timeout: UdpResponder = Arc::new(|_id, _n, _t, _s| Vec::new());
        transport.set_udp("gone.test", RecordType::AAAA, timeout);
        let (_registry, _lease, token) = owner();
        // connect_timeout (2s) is below the SOA TTL (5s), so the budget the AAAA
        // timeout consumes still leaves the NXDOMAIN cache entry live at
        // completion (expiry is anchored at the leader start).
        let resolver = build_resolver(
            token,
            &ns(NS_ADDR),
            Arc::clone(&transport),
            &clock,
            Duration::from_secs(2),
        );

        assert_eq!(
            resolver.resolve("gone.test").await,
            Err(ResolveError::NameResolution),
            "an authoritative NXDOMAIN is name-wide even when the other family times out"
        );
        let queried = transport.a_count();
        clock.advance(Duration::from_secs(1));
        assert_eq!(
            resolver.resolve("gone.test").await,
            Err(ResolveError::NameResolution)
        );
        assert_eq!(
            transport.a_count(),
            queried,
            "the NXDOMAIN is negatively cached by its SOA TTL"
        );
        clock.advance(Duration::from_secs(4));
        assert_eq!(
            resolver.resolve("gone.test").await,
            Err(ResolveError::NameResolution)
        );
        assert!(
            transport.a_count() > queried,
            "re-queries once the SOA TTL expires"
        );
    }

    #[tokio::test]
    async fn nodata_soa_wrong_class_is_not_cached() {
        let clock = ManualClock::new();
        let transport = FakeTransport::new(&clock);
        // A CH-class SOA must not be trusted for the IN negative cache.
        let responder = nodata_with_soa(name("chaos.test"), DNSClass::CH, 200, 5);
        transport.set_udp("chaos.test", RecordType::A, responder.clone());
        transport.set_udp("chaos.test", RecordType::AAAA, responder);
        let (_registry, _lease, token) = owner();
        let resolver = build_resolver(
            token,
            &ns(NS_ADDR),
            Arc::clone(&transport),
            &clock,
            Duration::from_secs(5),
        );

        assert_eq!(
            resolver.resolve("chaos.test").await,
            Err(ResolveError::NameResolution)
        );
        let first = transport.a_count();
        assert_eq!(
            resolver.resolve("chaos.test").await,
            Err(ResolveError::NameResolution)
        );
        assert!(
            transport.a_count() > first,
            "CH-class SOA must not be cached"
        );
    }

    #[tokio::test]
    async fn nodata_soa_unrelated_owner_is_not_cached() {
        let clock = ManualClock::new();
        let transport = FakeTransport::new(&clock);
        // The SOA owner is unrelated to the queried name.
        let responder = nodata_with_soa(name("evil.test"), DNSClass::IN, 200, 5);
        transport.set_udp("victim.test", RecordType::A, responder.clone());
        transport.set_udp("victim.test", RecordType::AAAA, responder);
        let (_registry, _lease, token) = owner();
        let resolver = build_resolver(
            token,
            &ns(NS_ADDR),
            Arc::clone(&transport),
            &clock,
            Duration::from_secs(5),
        );

        assert_eq!(
            resolver.resolve("victim.test").await,
            Err(ResolveError::NameResolution)
        );
        let first = transport.a_count();
        assert_eq!(
            resolver.resolve("victim.test").await,
            Err(ResolveError::NameResolution)
        );
        assert!(
            transport.a_count() > first,
            "an unrelated SOA owner must not be cached"
        );
    }

    #[tokio::test]
    async fn nodata_soa_ancestor_owner_is_cached() {
        let clock = ManualClock::new();
        let transport = FakeTransport::new(&clock);
        // The SOA owner is the enclosing zone of the queried name.
        let responder = nodata_with_soa(name("zone.test"), DNSClass::IN, 200, 5);
        transport.set_udp("host.zone.test", RecordType::A, responder.clone());
        transport.set_udp("host.zone.test", RecordType::AAAA, responder);
        let (_registry, _lease, token) = owner();
        let resolver = build_resolver(
            token,
            &ns(NS_ADDR),
            Arc::clone(&transport),
            &clock,
            Duration::from_secs(5),
        );

        assert_eq!(
            resolver.resolve("host.zone.test").await,
            Err(ResolveError::NameResolution)
        );
        let queried = transport.a_count();
        clock.advance(Duration::from_secs(2));
        assert_eq!(
            resolver.resolve("host.zone.test").await,
            Err(ResolveError::NameResolution)
        );
        assert_eq!(
            transport.a_count(),
            queried,
            "an ancestor-owned IN SOA is cached"
        );
    }

    #[tokio::test]
    async fn cross_zone_nxdomain_soa_is_validated_against_the_terminal() {
        let clock = ManualClock::new();
        let transport = FakeTransport::new(&clock);
        let server = ns_socket();
        let missing = name("missing.other.test");
        let soa_owner = name("other.test");
        // Same-packet cross-zone NXDOMAIN: alias CNAME missing.other.test (chain
        // TTL 2), plus an `other.test` SOA (TTL 5). The SOA is an ancestor of the
        // TERMINAL, not of the starting alias, and the cached TTL is min(2, 5).
        let responder: UdpResponder = Arc::new(move |id, qname, rtype, _s| {
            vec![datagram(
                server,
                encode(
                    id,
                    qname,
                    rtype,
                    ResponseCode::NXDomain,
                    &[cname_record(qname, &missing, 2)],
                    &[soa_record(&soa_owner, 100, 5)],
                    false,
                ),
            )]
        });
        transport.set_udp("alias.example", RecordType::A, responder.clone());
        transport.set_udp("alias.example", RecordType::AAAA, responder);
        let (_registry, _lease, token) = owner();
        let resolver = build_resolver(
            token,
            &ns(NS_ADDR),
            Arc::clone(&transport),
            &clock,
            Duration::from_secs(30),
        );

        assert_eq!(
            resolver.resolve("alias.example").await,
            Err(ResolveError::NameResolution)
        );
        let queried = transport.a_count();
        // Within the min(chain=2, soa=5) TTL: served from the negative cache —
        // proving the SOA was validated against the terminal (else uncached).
        clock.advance(Duration::from_secs(1));
        assert_eq!(
            resolver.resolve("alias.example").await,
            Err(ResolveError::NameResolution)
        );
        assert_eq!(transport.a_count(), queried, "cached at the terminal SOA");
        // Past the CNAME chain TTL (2) but within the SOA TTL (5): must re-query,
        // proving the chain TTL (not just the SOA TTL) bounds the cache.
        clock.advance(Duration::from_secs(2));
        assert_eq!(
            resolver.resolve("alias.example").await,
            Err(ResolveError::NameResolution)
        );
        assert!(
            transport.a_count() > queried,
            "the CNAME chain TTL must bound the negative cache"
        );
    }

    #[tokio::test]
    async fn cache_expiry_is_anchored_at_leader_start() {
        let clock = ManualClock::new();
        let transport = FakeTransport::new(&clock);
        // The lookup consumes 4s of wall-clock time during the exchange; the
        // positive TTL is 5s, so a start-anchored entry expires at t0+5.
        transport.set_pre_send_advance(Duration::from_secs(4));
        let server = ns_socket();
        transport.set_udp(
            "anchor.test",
            RecordType::A,
            Arc::new(move |id, qname, _t, _s| {
                vec![datagram(
                    server,
                    encode(
                        id,
                        qname,
                        RecordType::A,
                        ResponseCode::NoError,
                        &[a_record(qname, [192, 0, 2, 99], 5)],
                        &[],
                        false,
                    ),
                )]
            }),
        );
        let (_registry, _lease, token) = owner();
        let resolver = build_resolver(
            token,
            &ns(NS_ADDR),
            Arc::clone(&transport),
            &clock,
            Duration::from_secs(30),
        );

        // First lookup finishes at t0+4; the entry expires at the start-anchored
        // t0+5, not the completion-anchored t0+9.
        assert_eq!(
            resolver.resolve("anchor.test").await,
            Ok(vec![ipv4([192, 0, 2, 99])])
        );
        let queried = transport.a_count();
        // Now at t0+6: past the start-anchored expiry, so the next resolve must
        // re-query. A completion-time anchor would still be valid (t0+9) here.
        clock.advance(Duration::from_secs(2));
        assert_eq!(
            resolver.resolve("anchor.test").await,
            Ok(vec![ipv4([192, 0, 2, 99])])
        );
        assert!(
            transport.a_count() > queried,
            "a start-anchored TTL must not be refilled by query time"
        );
    }

    // ---------------------------------------------------------------------
    // Missing-evidence rows.
    // ---------------------------------------------------------------------
    #[tokio::test]
    async fn cname_chain_over_max_depth_fails_closed() {
        let clock = ManualClock::new();
        let transport = FakeTransport::new(&clock);
        // Nine CNAME hops (n0 -> n1 -> ... -> n9): one over MAX_CNAME_DEPTH.
        for index in 0..9 {
            let owner = name(&format!("n{index}.test"));
            let target = name(&format!("n{}.test", index + 1));
            transport.set_udp(
                &format!("n{index}.test"),
                RecordType::A,
                Arc::new(move |id, qname, _t, s| {
                    vec![datagram(
                        s,
                        encode(
                            id,
                            qname,
                            RecordType::A,
                            ResponseCode::NoError,
                            &[cname_record(&owner, &target, 40)],
                            &[],
                            false,
                        ),
                    )]
                }),
            );
        }
        let terminal = name("n9.test");
        transport.set_udp(
            "n9.test",
            RecordType::A,
            Arc::new(move |id, qname, _t, s| {
                vec![datagram(
                    s,
                    encode(
                        id,
                        qname,
                        RecordType::A,
                        ResponseCode::NoError,
                        &[a_record(&terminal, [192, 0, 2, 90], 40)],
                        &[],
                        false,
                    ),
                )]
            }),
        );
        let (_registry, _lease, token) = owner();
        let resolver = build_resolver(
            token,
            &ns(NS_ADDR),
            Arc::clone(&transport),
            &clock,
            Duration::from_secs(5),
        );
        assert_eq!(
            resolver.resolve("n0.test").await,
            Err(ResolveError::LookupFailed)
        );
    }

    #[tokio::test]
    async fn oversize_udp_datagram_is_rejected_and_next_ns_used() {
        let clock = ManualClock::new();
        let transport = FakeTransport::new(&clock);
        let servers: Vec<Arc<str>> = vec![Arc::from("10.0.0.1:53"), Arc::from("10.0.0.2:53")];
        let bad = sock([10, 0, 0, 1], 53);
        let good = name("host.test");
        transport.set_udp(
            "host.test",
            RecordType::A,
            Arc::new(move |id, qname, _t, server| {
                if server == bad {
                    // Over the 1232 advertise: must be rejected, never parsed.
                    vec![datagram(server, oversize_response(id, qname, [6, 6, 6, 6]))]
                } else {
                    vec![datagram(
                        server,
                        encode(
                            id,
                            qname,
                            RecordType::A,
                            ResponseCode::NoError,
                            &[a_record(&good, [192, 0, 2, 95], 30)],
                            &[],
                            false,
                        ),
                    )]
                }
            }),
        );
        let (_registry, _lease, token) = owner();
        let resolver = build_resolver(
            token,
            &servers,
            Arc::clone(&transport),
            &clock,
            Duration::from_secs(5),
        );
        assert_eq!(
            resolver.resolve("host.test").await,
            Ok(vec![ipv4([192, 0, 2, 95])])
        );
    }

    #[tokio::test]
    async fn timeout_is_not_negatively_cached() {
        let clock = ManualClock::new();
        let transport = FakeTransport::new(&clock);
        let timeout: UdpResponder = Arc::new(|_id, _n, _t, _s| Vec::new());
        transport.set_udp("slow.test", RecordType::A, timeout.clone());
        transport.set_udp("slow.test", RecordType::AAAA, timeout);
        let (_registry, _lease, token) = owner();
        let resolver = build_resolver(
            token,
            &ns(NS_ADDR),
            Arc::clone(&transport),
            &clock,
            Duration::from_secs(2),
        );

        assert_eq!(
            resolver.resolve("slow.test").await,
            Err(ResolveError::LookupFailed)
        );
        let first = transport.a_count();
        assert_eq!(
            resolver.resolve("slow.test").await,
            Err(ResolveError::LookupFailed)
        );
        assert!(
            transport.a_count() > first,
            "a timeout must not be negatively cached"
        );
    }

    // ---------------------------------------------------------------------
    // Owner fence wins before any input/resolution work (even literal-IP).
    // ---------------------------------------------------------------------
    #[tokio::test]
    async fn stale_owner_wins_before_literal_ip_and_invalid_host() {
        let clock = ManualClock::new();
        let transport = FakeTransport::new(&clock);
        let registry = OwnershipRegistry::new();
        let lease = registry
            .claim(OwnerScope::Process, "dns-owner")
            .unwrap_or_else(|e| unreachable!("claim: {e}"));
        let resolver = build_resolver(
            lease.token(),
            &ns(NS_ADDR),
            Arc::clone(&transport),
            &clock,
            Duration::from_secs(5),
        );
        lease.release();

        // A literal IP would otherwise bypass to Ok(ip); the fence wins first.
        assert_eq!(
            resolver.resolve("198.51.100.9").await,
            Err(ResolveError::StaleOwner)
        );
        // An invalid host would otherwise be InvalidHost; the fence wins first.
        assert_eq!(resolver.resolve("").await, Err(ResolveError::StaleOwner));
        assert_eq!(transport.a_count(), 0);
        assert_eq!(transport.aaaa_count(), 0);
    }

    // ---------------------------------------------------------------------
    // Response header + question validation (QR / opcode / qtype / qclass).
    // ---------------------------------------------------------------------
    #[allow(clippy::too_many_arguments)]
    fn build_response(
        id: u16,
        question: &Name,
        q_type: RecordType,
        q_class: DNSClass,
        message_type: MessageType,
        op_code: OpCode,
        answers: &[Record],
        truncated: bool,
    ) -> Vec<u8> {
        let mut message = Message::new(id, message_type, op_code);
        message.metadata.response_code = ResponseCode::NoError;
        message.metadata.truncation = truncated;
        let mut query = Query::query(question.clone(), q_type);
        query.set_query_class(q_class);
        message.add_query(query);
        for record in answers {
            message.add_answer(record.clone());
        }
        message
            .to_vec()
            .unwrap_or_else(|e| unreachable!("encode: {e}"))
    }

    #[tokio::test]
    async fn response_header_and_question_validation_drops_malformed() {
        let cases: Vec<(&str, Malform)> = vec![
            (
                "qr_bit_is_a_query",
                Box::new(move |id, q| {
                    build_response(
                        id,
                        q,
                        RecordType::A,
                        DNSClass::IN,
                        MessageType::Query,
                        OpCode::Query,
                        &[a_record(q, [10, 10, 10, 10], 30)],
                        false,
                    )
                }),
            ),
            (
                "opcode_not_query",
                Box::new(move |id, q| {
                    build_response(
                        id,
                        q,
                        RecordType::A,
                        DNSClass::IN,
                        MessageType::Response,
                        OpCode::Status,
                        &[a_record(q, [10, 10, 10, 10], 30)],
                        false,
                    )
                }),
            ),
            (
                "question_qtype_mismatch",
                Box::new(move |id, q| {
                    build_response(
                        id,
                        q,
                        RecordType::AAAA,
                        DNSClass::IN,
                        MessageType::Response,
                        OpCode::Query,
                        &[a_record(q, [10, 10, 10, 10], 30)],
                        false,
                    )
                }),
            ),
            (
                "question_qclass_not_in",
                Box::new(move |id, q| {
                    build_response(
                        id,
                        q,
                        RecordType::A,
                        DNSClass::CH,
                        MessageType::Response,
                        OpCode::Query,
                        &[a_record(q, [10, 10, 10, 10], 30)],
                        false,
                    )
                }),
            ),
        ];

        for (label, malform) in cases {
            assert_udp_reply_dropped(label, malform).await;
        }
    }

    /// A boxed builder producing one malformed response for a given id and name.
    type Malform = Box<dyn Fn(u16, &Name) -> Vec<u8> + Send + Sync>;

    /// Asserts a malformed first datagram is dropped and the genuine reply wins.
    async fn assert_udp_reply_dropped(label: &str, malform: Malform) {
        let clock = ManualClock::new();
        let transport = FakeTransport::new(&clock);
        let server = ns_socket();
        let good = name("host.test");
        transport.set_udp(
            "host.test",
            RecordType::A,
            Arc::new(move |id, qname, _t, _s| {
                vec![
                    datagram(server, malform(id, qname)),
                    datagram(
                        server,
                        encode(
                            id,
                            qname,
                            RecordType::A,
                            ResponseCode::NoError,
                            &[a_record(&good, [192, 0, 2, 77], 30)],
                            &[],
                            false,
                        ),
                    ),
                ]
            }),
        );
        let (_registry, _lease, token) = owner();
        let resolver = build_resolver(
            token,
            &ns(NS_ADDR),
            Arc::clone(&transport),
            &clock,
            Duration::from_secs(5),
        );
        assert_eq!(
            resolver.resolve("host.test").await,
            Ok(vec![ipv4([192, 0, 2, 77])]),
            "case {label}: malformed response must be dropped"
        );
    }

    #[tokio::test]
    async fn tcp_malformed_reply_is_dropped_then_next_ns_used() {
        let clock = ManualClock::new();
        let transport = FakeTransport::new(&clock);
        let servers: Vec<Arc<str>> = vec![Arc::from("10.0.0.1:53"), Arc::from("10.0.0.2:53")];
        let bad = sock([10, 0, 0, 1], 53);
        let good = name("host.test");
        transport.set_udp(
            "host.test",
            RecordType::A,
            Arc::new(move |id, qname, _t, server| {
                if server == bad {
                    // Truncated UDP forces a TCP retry against the same ns.
                    vec![datagram(
                        server,
                        encode(
                            id,
                            qname,
                            RecordType::A,
                            ResponseCode::NoError,
                            &[a_record(qname, [10, 10, 10, 10], 30)],
                            &[],
                            true,
                        ),
                    )]
                } else {
                    vec![datagram(
                        server,
                        encode(
                            id,
                            qname,
                            RecordType::A,
                            ResponseCode::NoError,
                            &[a_record(&good, [192, 0, 2, 88], 30)],
                            &[],
                            false,
                        ),
                    )]
                }
            }),
        );
        // The TCP reply for the first ns is malformed (wrong opcode) and must be
        // dropped by the shared validate, moving on to the second ns.
        transport.set_tcp(
            "host.test",
            RecordType::A,
            Arc::new(|id, qname, _t, _s| {
                Some(build_response(
                    id,
                    qname,
                    RecordType::A,
                    DNSClass::IN,
                    MessageType::Response,
                    OpCode::Status,
                    &[a_record(qname, [10, 10, 10, 10], 30)],
                    false,
                ))
            }),
        );
        let (_registry, _lease, token) = owner();
        let resolver = build_resolver(
            token,
            &servers,
            Arc::clone(&transport),
            &clock,
            Duration::from_secs(5),
        );
        assert_eq!(
            resolver.resolve("host.test").await,
            Ok(vec![ipv4([192, 0, 2, 88])])
        );
    }

    #[tokio::test]
    async fn tcp_truncated_reply_is_rejected_then_next_ns_used() {
        let clock = ManualClock::new();
        let transport = FakeTransport::new(&clock);
        let servers: Vec<Arc<str>> = vec![Arc::from("10.0.0.1:53"), Arc::from("10.0.0.2:53")];
        let bad = sock([10, 0, 0, 1], 53);
        let good = name("host.test");
        transport.set_udp(
            "host.test",
            RecordType::A,
            Arc::new(move |id, qname, _t, server| {
                if server == bad {
                    vec![datagram(
                        server,
                        encode(
                            id,
                            qname,
                            RecordType::A,
                            ResponseCode::NoError,
                            &[a_record(qname, [10, 10, 10, 10], 30)],
                            &[],
                            true,
                        ),
                    )]
                } else {
                    vec![datagram(
                        server,
                        encode(
                            id,
                            qname,
                            RecordType::A,
                            ResponseCode::NoError,
                            &[a_record(&good, [192, 0, 2, 89], 30)],
                            &[],
                            false,
                        ),
                    )]
                }
            }),
        );
        // The TCP reply is ALSO truncated (partial): a TCP answer must be
        // complete, so it is rejected and the next ns is used.
        transport.set_tcp(
            "host.test",
            RecordType::A,
            Arc::new(|id, qname, _t, _s| {
                Some(encode(
                    id,
                    qname,
                    RecordType::A,
                    ResponseCode::NoError,
                    &[a_record(qname, [10, 10, 10, 10], 30)],
                    &[],
                    true,
                ))
            }),
        );
        let (_registry, _lease, token) = owner();
        let resolver = build_resolver(
            token,
            &servers,
            Arc::clone(&transport),
            &clock,
            Duration::from_secs(5),
        );
        assert_eq!(
            resolver.resolve("host.test").await,
            Ok(vec![ipv4([192, 0, 2, 89])])
        );
    }

    fn oversize_response(id: u16, qname: &Name, poison: [u8; 4]) -> Vec<u8> {
        let mut answers = vec![a_record(qname, poison, 30)];
        let mut index = 0u32;
        loop {
            let bytes = encode(
                id,
                qname,
                RecordType::A,
                ResponseCode::NoError,
                &answers,
                &[],
                false,
            );
            if bytes.len() > super::MAX_UDP_PAYLOAD_BYTES {
                return bytes;
            }
            let pad = name(&format!("pad{index}.example"));
            answers.push(a_record(&pad, [10, 0, 0, 1], 30));
            index += 1;
        }
    }
}
