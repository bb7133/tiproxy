# TiProxy bounded transport I/O

`proxy-io` adapts the sans-I/O framing rules in `mysql-wire` to Tokio
`AsyncRead` and `AsyncWrite` transports. WIRE-01 owns physical and logical
packet streaming, sequence/accounting state, bounded prefix capture, and the
transport-facing equivalents of Go TiProxy's `ForwardPacketTo` and
`ForwardUntil`.

TLS, compression, PROXY protocol, socket admission, backend selection, and
session transitions remain separate WIRE/session tasks. This crate does not
make routing decisions.

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
