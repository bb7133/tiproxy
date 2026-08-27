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

The Rust dataplane runs the same plain-variant topology for real:

```sh
tests/dataplane/integration/run.sh --mode rust --variant plain
```

`preflight.sh` demands the capability contract from
`tiproxy-rs --integration-capabilities` — currently
`control-bridge-v1,mysql-listener,health-endpoint,graceful-shutdown`.
The launcher enables the Go config's `rust-dataplane` gate (the Go
process cedes the SQL listeners and serves only the control plane and
API), waits for the control socket (created under `/tmp` with the run's
tag: macOS caps `sun_path` well below the artifact path length), starts
`tiproxy-rs` with a `--health-port` readiness endpoint that answers 200
only after the first applied generation, and then runs the same
`SELECT 1`, drop-next recovery, diagnostics, and port-release checks as
the Go baseline. Both modes additionally prove the namespace/topology
matrix (DPL-07 #41): two admin-API-seeded namespaces map alice and bob
over the PD-backed backend set (`proxy.pd-addrs` always registers an
implicit backend cluster, so `backend.instances` cannot pin a backend),
`SELECT @@port` proves each user lands on a real backend, and
delta-scoped per-connection log evidence attributes each row's single
connection to exactly its expected namespace — ns-alpha, ns-beta, and
root's PD-backed default. Cleanup stops the Rust process with SIGINT — the
coordinated-shutdown path. TLS, PROXY protocol, and compression
variants remain refused by the capability contract until their Rust
slices exist; a raw TCP relay or the Go dataplane is never reported as
Rust success.

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
