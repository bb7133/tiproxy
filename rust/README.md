# TiProxy Rust workspace

This workspace is the production home of the TiProxy Rust dataplane. It starts
with explicit crate boundaries and build policy only; protocol behavior is added
under separately reviewed parity tasks.

## Crate boundaries

- `mysql-wire` owns wire-format types and codecs, but not sockets.
- `proxy-io` owns client/backend transports and their future TLS, compression,
  and PROXY protocol layers, but not routing policy.
- `session-core` owns the protocol-independent session lifecycle and migration
  state.
- `control-proto` owns the versioned control-plane contract between Go and Rust.
  MySQL packet payloads are forbidden at this boundary.
- `dataplane` composes the four libraries without moving hot-path traffic into
  the control plane.
- `tiproxy-rs` is the deployable executable.

Every crate has empty default features. New optional behavior must be additive,
must document its deployment impact, and must pass `--all-features` linting.

## Build policy

The repository pins Rust 1.89.0, which is also the minimum supported Rust
version (MSRV), and uses Rust edition 2024. The lockfile is committed. From the
repository root, use:

```sh
make rust-build
make rust-test
make rust-lint
make rust-release RUST_TARGET=x86_64-unknown-linux-gnu
make rust-release RUST_TARGET=aarch64-unknown-linux-gnu
```

The release targets expect the selected standard library and linker to already
be available. CI installs those prerequisites on matching Linux builders.

`tiproxy-rs --version` reports the semantic version, source commit, and build
time. Release automation can override them with `TIPROXY_VERSION`,
`TIPROXY_COMMIT`, and `TIPROXY_BUILD_TIME`; otherwise the build script derives
local values.
