# TiProxy MySQL wire primitives

`mysql-wire` is the sans-I/O protocol boundary for the Rust dataplane. It owns
fixed-width and length-encoded integers, physical-packet headers, sequence
tracking, capability/status/command constants, response headers, OK/ERR/EOF
payloads, protocol-10 handshakes, connection attributes, and
`COM_CHANGE_USER` fields. SES-05 adds prepared-statement fixed prefixes,
prepare-OK metadata, and full `COM_STMT_EXECUTE` parameter codecs.

It does not read sockets, join multi-packet logical messages, buffer or flush
writes, negotiate TLS/compression, or choose session transitions. WIRE-01's
`proxy-io` adapter owns the first three; later transport and `session-core`
tasks own the rest. This crate provides only the allocation-free logical
fragment plan shared by bounded writers.

## Ownership and allocation

All parsers take a caller-owned `&[u8]`. Variable-width fields and `raw` views
in decoded values borrow that same slice:

```rust
use mysql_wire::PhysicalPacket;

let wire = [3, 0, 0, 7, b'a', b'b', b'c'];
let (packet, tail) = PhysicalPacket::decode(&wire)?;
assert_eq!(packet.payload(), &wire[4..]);
assert!(tail.is_empty());
# Ok::<(), mysql_wire::DecodeError>(())
```

Normal decoding therefore allocates neither a payload buffer nor per-field
strings/maps. Connection attributes retain order and duplicate keys through a
borrowed iterator. Encoders allocate only their returned `Vec`, or append to a
caller-owned `Vec` where the API makes that explicit.

## Safety and Go compatibility

- Every external length is bounds-checked before slicing or allocation.
- Truncated, overflowing, undefined (`0xff`), and non-canonical
  length-encoded values return `DecodeError`; they never panic.
- A legal empty physical packet remains valid, while interpreting it as a
  command returns `DecodeError::EmptyCommandPacket`.
- Incoming sequence mismatches preserve Go TiProxy behavior: report an
  observable mismatch, accept the packet, and resynchronize to
  `received.wrapping_add(1)`.
- The strict rejection of non-canonical lengths is required by issue #17 even
  though Go accepts longer-than-needed length encodings. The undefined `0xff`
  marker remains a distinct invalid-value error.
- Protocol-4.1 ERR packets require the `#` SQLSTATE marker; Go currently skips
  that byte without checking it.
- Initial greetings require protocol version 10 and a zero filler, and every
  capability-selected handshake/change-user field must be complete. Go's
  unchecked or tolerant malformed-input paths are not copied.
- Prepared codecs validate every fixed field before indexing and keep the
  unsigned marker exact (`0x80`, not merely nonzero). Execute values borrow
  packet bytes; temporal lengths and length-encoded string/blob/JSON/vector
  values are checked before slicing. The five-byte command/statement prefix
  remains separately decodable for transparent multi-packet streaming.
- These intentional safety differences are recorded in the parity manifest's
  WIRE-00 and SES-05 decision ledger rows. Canonical Go corpus vectors have no
  wire-level difference.

## Tests

From the repository root:

```sh
cargo test --locked --manifest-path rust/Cargo.toml -p mysql-wire
cargo clippy --locked --manifest-path rust/Cargo.toml \
  -p mysql-wire --all-targets --all-features -- -D warnings
```

`tests/corpus.rs` reads the checked-in deterministic gzip traces emitted by the
Go oracle. Its individually selectable tests name the linked parity IDs,
including `PARITY-PKT-001/002/004/005/007`, `PARITY-HS-001/003/006/011`,
`PARITY-RSP-001/002/003/006`, `PARITY-CMD-017`, and `PARITY-PS-004`.
Property-style deterministic
tests cover 20,000 packet-header and length-encoded-integer values; adversarial
tests exercise every prefix of valid messages plus pseudo-random hostile input.

## External-input limits (`limits`)

WIRE-07 centralizes every registered bound on peer-supplied lengths — the
Go 1-MiB pre-handshake cap, the command-prefix capture size, and the
control-protocol ADR caps (frame, connection attributes, diagnostic text) —
with check helpers that reject a hostile declaration **before** any
allocation and error messages that never echo input bytes or paths.
Transport-owned defaults stay in `proxy-io` and are anchored by conformance
tests there. LOCAL INFILE's aggregate size is recorded as unbounded Go
parity pending bounded streaming in the session/runtime layers — not as an
accepted terminal state.
