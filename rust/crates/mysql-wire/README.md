# TiProxy MySQL wire primitives

`mysql-wire` is the sans-I/O protocol boundary for the Rust dataplane. It owns
fixed-width and length-encoded integers, physical-packet headers, sequence
tracking, capability/status/command constants, response headers, OK/ERR/EOF
payloads, protocol-10 handshakes, connection attributes, and
`COM_CHANGE_USER` fields.

It does not read sockets, join multi-packet logical messages, buffer or flush
writes, negotiate TLS/compression, or choose session transitions. Those layers
belong to WIRE-01 and later `proxy-io` / `session-core` tasks.

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
- The strict rejection of non-canonical lengths and typed rejection of
  malformed greetings are intentional safety fixes required by issue #17;
  canonical Go corpus vectors have no wire-level difference.

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
`PARITY-RSP-001/002/003`, and `PARITY-CMD-017`. Property-style deterministic
tests cover 20,000 packet-header and length-encoded-integer values; adversarial
tests exercise every prefix of valid messages plus pseudo-random hostile input.
