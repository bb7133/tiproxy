# TiProxy Rust workspace

This workspace is the production home of the TiProxy Rust dataplane. Protocol
behavior is added under separately reviewed parity tasks while the crate
boundaries and build policy remain stable.

## Crate boundaries

- `mysql-wire` owns runtime-independent wire-format types and codecs, but not
  sockets or logical-message streaming. Its borrowing and safety contract is
  documented in [`crates/mysql-wire/README.md`](crates/mysql-wire/README.md).
- `proxy-io` owns bounded async physical/logical packet streaming and the
  client/backend transport layers that later add TLS, compression, and PROXY
  protocol, but not routing policy. Its buffering and cancellation contract is
  documented in [`crates/proxy-io/README.md`](crates/proxy-io/README.md).
- `session-core` owns the protocol-independent session lifecycle and migration
  state.
- `control-proto` owns the versioned control-plane contract between Go and Rust.
  MySQL packet payloads are forbidden at this boundary.
- `control-plane` owns the process-local Rust control-domain seam, unique-owner
  lease, versioned config/TLS views, ordered lifecycle, and bounded runtime
  observations. It intentionally does not depend on `control-proto`.
- `dataplane` composes the four libraries without moving hot-path traffic into
  the control plane. Its listener, admission, and registry contracts are
  documented in [`crates/dataplane/README.md`](crates/dataplane/README.md).
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
make rust-doc-test
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

Supply-chain policy, pinned CI tools, vulnerability exceptions, and the CI
negative-test strategy are documented in [`ci/README.md`](ci/README.md).
