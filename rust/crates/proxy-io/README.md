# TiProxy bounded transport I/O

`proxy-io` adapts the sans-I/O framing rules in `mysql-wire` to Tokio
`AsyncRead` and `AsyncWrite` transports. WIRE-01 owns physical and logical
packet streaming, sequence/accounting state, bounded prefix capture, and the
transport-facing equivalents of Go TiProxy's `ForwardPacketTo` and
`ForwardUntil`.

TLS, compression, socket-level PROXY protocol integration, socket admission,
backend selection, and session transitions remain separate WIRE/session tasks
(the sans-I/O PROXY v2 codec below is already implemented here). This crate
does not make routing decisions.

## Buffer and sequence ownership

- `PacketReader` owns five bytes of non-consuming prefetch plus one reusable
  32-KiB scratch buffer during a streaming call.
- `PacketWriter` regenerates physical headers with its own sequence; a forwarded
  source sequence is observed but is never copied to the destination.
- An exact multiple of `MAX_PAYLOAD_LEN` ends with the required empty physical
  packet. Empty logical payloads are represented by one empty physical packet.
- Source sequence mismatches remain observable and resynchronize to
  `received.wrapping_add(1)`, matching Go TiProxy. Readers and writers expose
  explicit reset methods for command boundaries.
- Forwarding retains no logical payload unless the caller requests a bounded
  prefix. `read_logical` is the explicit materializing API and drains an
  oversized message before returning its typed limit error.

The 1-GiB synthetic test supplies framing and payload lazily and writes to a
counting sink. It verifies that the reader/writer scratch size stays at 32 KiB,
the retained prefix stays at 1 KiB, and the physical packet/byte counters cover
the complete message.

## Cancellation contract

`forward_packet_to_cancellable` checks its cooperative cancellation probe only
before consuming the next physical header. It returns
`CancelledAtPacketBoundary` with a reusable `ForwardProgress`; resuming with the
same reader, writer, and progress continues at the next header without
duplicating bytes. `forward_until_cancellable` checks only between complete
logical packets.

Dropping either async future while an I/O operation is pending is not a safe
cancellation mechanism: the underlying `AsyncRead` or `AsyncWrite` may already
have transferred part of a header or payload. Owners must signal through the
probe and retain the same transport state until the boundary result arrives.

## Go parity evidence

`tests/corpus_streaming.rs` forwards the deterministic Go oracle traces byte for
byte and names the linked parity rows:

- `PARITY-PKT-002`: maximum fragment splitting and the exact-multiple empty
  terminator;
- `PARITY-PKT-003`: bounded capture while a multi-fragment command streams;
- `PARITY-PKT-004`: mismatch observation and tolerant sequence resynchronizing;
- `PARITY-PKT-005`: legal empty logical packet handling.

Unit tests add 1-byte, `MaxPayloadLen - 1`, `MaxPayloadLen`,
`MaxPayloadLen + 1`, sequence wrap/reset, non-consuming peek, independent
destination sequence, source/destination error attribution, resumable
cancellation, bounded oversized reads, `ForwardUntil`, and the synthetic 1-GiB
case.

Two intentional boundary decisions are recorded in the parity manifest:

- `WIRE-01-D1`: all Rust forwarding paths regenerate the physical header from
  the destination sequence. Go's no-data `ForwardUntil` fast path instead
  copies the source sequence byte while advancing a separate destination
  tracker; canonical traffic is identical, but a tolerated mismatch differs.
- `WIRE-01-D2`: peeking an empty physical packet returns `first_byte = None`
  after reading only its four-byte header. Go's unconditional five-byte peek
  blocks at EOF or reads across the packet boundary, which is why its LOCAL
  INFILE path must bypass `ForwardUntil`.

From the repository root:

```sh
cargo test --locked --manifest-path rust/Cargo.toml -p proxy-io
cargo clippy --locked --manifest-path rust/Cargo.toml \
  -p proxy-io --all-targets --all-features -- -D warnings
```

## Bounded duplex transport

WIRE-02 adds `DuplexPump` for future runtime/session phases that intentionally
proxy raw transport bytes after protocol negotiation. It does not replace the
packet-aware session state machine. Each joined direction owns one reusable
`BufferPool` lease and one fixed staging area:

- active userspace memory is bounded by
  `2 * (read_buffer_size + write_high_water)` per duplex connection;
- the shared pool retains at most `max_idle * buffer_size` bytes between
  connections and never waits for a lease, so unrelated session owners cannot
  deadlock one another;
- a destination write starts when the staging area reaches
  `write_high_water`, on EOF, or after `max_flush_delay`; while that write is
  pending, the direction performs no more source reads, applying slow-peer
  backpressure at the configured high-water mark;
- optional read-idle, write/flush, and half-close deadlines are explicit and
  direction-attributed in `PumpError`.

`DuplexPump::run` uses two futures held by one `tokio::join!`; it does not spawn
or detach tasks. The first EOF, connection reset/error, or
`PumpCancellation::cancel` wakes the peer direction, and both directions call
`AsyncWrite::shutdown` before the owner returns. Cancellation observed while a
staged write is pending discards only the unwritten staged suffix and reports
that count. This hard termination can therefore leave a partially written
staged byte range at the destination; it does not promise a message boundary.
Its upper termination bound is the configured write/flush deadline plus
`shutdown_timeout`.

This owner cancellation is a hard connection termination path. Resumable
packet forwarding must continue to use WIRE-01's cooperative packet-boundary
APIs; dropping a packet future mid-frame is still forbidden.

`tests/pump.rs` contains the Rust-side `PARITY-PKT-006` evidence for fixed pool
reuse, high-water backpressure, timer batching, EOF/reset/cancel propagation,
read/write deadlines, half-close, and joined owner termination. The release
benchmark uses 256-byte synthetic reads and asserts at least 32:1 write-call
coalescing while checking the exact high-water bound:

```sh
cargo run --locked --release --manifest-path rust/Cargo.toml \
  -p proxy-io --example duplex_pump_bench -- --quick
```

## PROXY protocol v2 (`proxy_protocol`)

Sans-I/O codecs matching Go TiProxy's observable behavior
(`pkg/proxy/proxyprotocol`, `pkg/proxy/net/proxy.go`):

- `sniff_magic` reduces both Go sniffing integrations (four-byte fast probe in
  `net/proxy.go`, incremental buffering in `listener.go`) to one pure prefix
  comparison: partial magic → need more, divergence → all buffered bytes are
  application data and none may be consumed, full match → decode.
- A known family with an unknown transport matches Go's inner network switch:
  no addresses are populated, but the cursor still advances past the address
  block before TLV scanning (unlike the short-body case, which does not
  advance).
- `decode_after_magic` is exactly as tolerant as Go `ParseProxyV2`: no field
  value is rejected, a short address body yields no addresses **and the
  address bytes are rescanned as TLVs** (Go leaves its cursor unadvanced —
  bug-for-bug, covered by tests), truncated TLV declarations are clamped, and
  sub-3-byte tails are dropped. Insufficient input reports the exact total
  needed instead of blocking.
- `encode_proxy_v2` reproduces Go `ToBytes` byte-for-byte for canonical
  inputs, including `unifyIPFamily` (v4/v4-mapped pairs stay v4, otherwise
  both widen to v6) and Go's unpadded Unix path write.

Intentional differences from Go are limited to the encode side and recorded
in the parity manifest's `WIRE-05` decision-ledger rows: a single TLV or the
aggregate body (addresses plus TLVs) exceeding the u16 length field
(`WIRE-05-D1`) and a Unix path above 108 bytes (`WIRE-05-D2`) return typed
errors instead of Go's silent frame corruption.

Zero-copy: decoded TLV contents and Unix path blocks borrow the caller's
buffer; the only allocations are the TLV `Vec` and encoder output.

The outbound PROXY-before-TLS ordering, socket integration, and the
`RemoteAddr`/`ProxyAddr` override policy stay with the async adapters
(WIRE-06) and session layers; this module is deliberately pure. Adapter
note: Go's `listener.go` returns the PROXY **destination** address from
`RemoteAddr` while the production path in `net/proxy.go` returns the
**source** address (both pass Go's tests only because src == dst there);
the Rust adapter must follow `net/proxy.go`.

## TLS (`tls`)

WIRE-04: frontend `SSLRequest` upgrade and backend client TLS over rustls
(the workspace-approved library; no openssl/native-tls).

- `accept_frontend` completes the server handshake through a
  `PrefixedIo` that replays already-buffered bytes first — Go's "handshake
  must read from the buffered reader" rule — bounded by an explicit timeout.
- `build_backend_config` derives the client configuration exclusively from
  `control-proto`'s `ValidatedTlsPolicy`: snapshot CA roots,
  `skip_ca_verification` (Go `InsecureSkipVerify`), optional client
  certificate/key, and the `""`/`"1.2"`/`"1.3"` minimum-version contract.
- `connect_backend` takes the routing-selected backend host as the server
  name; DNS names and IP literals both parse (Go's "use the DNS name as much
  as possible").
- `tls_buffer_sizes` is byte-for-byte Go `tlsBufferSizes` parity: reads clamp
  `size/4` into `[1 KiB, 4 KiB]`, writes clamp `size/2` into
  `[1 KiB, 16 KiB]`, zero normalizes to 32 KiB — a large base buffer never
  duplicates full-size TLS memory.
- Reload safety comes from the snapshot store: sessions capture an immutable
  `Arc` at establishment, a failed reload keeps last-good for new sessions,
  and a valid new certificate applies only to sessions created after it
  (integration-tested against `SnapshotStore`).
- Handshake facts exposed to upper layers are metadata-only
  (`TlsHandshakeInfo`); certificates, keys, and raw TLS bytes never leave the
  transport layer.

One safety-ledger row: `WIRE-04-D1` — Go's backend client TLS never
verifies the hostname even with a CA (`InsecureSkipVerify` plus a custom
verifier that omits `DNSName`); Rust's standard WebPKI path verifies the
routing-selected backend hostname. A deliberate strengthening, recorded in
the parity manifest with its compatibility impact. The TLS 1.2/1.3 floor was
already frozen by `control-proto` snapshot validation and adds no new row.
