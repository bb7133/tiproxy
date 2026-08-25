# Real TiDB dataplane integration topology

This directory owns a reproducible, test-only TiDB topology for dataplane
validation. Component versions are pinned in `versions.env`; the topology uses
one PD, one TiKV, **two TiDB backends**, one TiProxy process, and a deliberately
protocol-agnostic TCP fault injector. Certificates are generated for each run
and removed during cleanup.

## Current capability boundary

The Go baseline is operational:

```sh
make dataplane-integration-go
```

That target exercises these variants sequentially: plain, TLS, inbound and
backend PROXY v2, zlib, zstd, and TLS + PROXY v2 + zstd. Each variant runs a
real `SELECT 1`, drops the next client connection, verifies recovery, collects
redacted diagnostics, and checks that its ports and owned processes have been
released. Run one variant with:

```sh
tests/dataplane/integration/run.sh --mode go --variant plain
```

The Rust entrypoint is intentionally blocked:

```sh
make dataplane-integration
```

FND-01 currently provides only `tiproxy-rs --version`; it has no MySQL listener,
Go control bridge, health endpoint, or shutdown protocol. `preflight.sh`
therefore exits 78 before starting TiDB. It requires an explicit, comma-separated
`--integration-capabilities` response and still refuses to launch until the real
Go/Rust launch contract is wired. A raw TCP relay or the Go dataplane is never
reported as Rust success.

The remaining implementation dependencies are:

- Go/Rust control bridge and lifecycle contract: #10-#15.
- MySQL wire and transport path: #17-#19 and #21-#24; compression also needs #20.
- Session command path sufficient for `SELECT 1`: #25-#29.
- Operational Rust runtime, readiness, and shutdown: #34-#37.

Those issues must update the preflight/launcher contract when their real
interfaces exist. Until then, the Rust part of issue #6's first acceptance item
and Rust log collection cannot truthfully pass.

## Diagnostics and safety

Artifacts are retained under `tests/dataplane/integration/artifacts/` (or
`DATAPLANE_ARTIFACT_ROOT`) and ignored by Git. `collect-diagnostics.sh` collects
Go TiProxy, TiUP/TiDB, fault injector, and preflight output through `redact.awk`.
It excludes private-key/certificate files and removes suspicious authentication
lines and URL user-info. Rust preflight output is collected now; actual Rust
runtime logs will enter the same directory once that process exists.

Cleanup only signals PIDs whose command lines contain this run's unique path or
tag, asks TiUP to clean that exact validated tag, removes generated keys, and
probes every reserved port. It never kills by process name or deletes TiUP's
shared data directory.

Run framework-only checks without provisioning TiDB:

```sh
make dataplane-integration-self-test
```

`.github/workflows/dataplane-integration.yml` runs that self-contained check on
relevant pull requests and pushes. Its manual dispatch is the CI entrypoint for
a real topology: it installs the exact TiUP release from `versions.env` only
after verifying the published archive SHA-256, runs the selected mode/variant,
and uploads the redacted artifact directory even on failure. Rust dispatches
are expected to fail at capability preflight until the dependencies above land;
their diagnostic artifact makes that boundary observable without claiming a
successful Rust query.

Override `DATAPLANE_PORT_OFFSET` for a reserved CI port range. The default is a
process-derived offset between 10000 and 11900; the `all` run reserves six
non-overlapping 100-port ranges.
