# Real TiDB dataplane integration topology

This directory owns a reproducible, test-only TiDB topology for dataplane
validation. Component versions are pinned in `versions.env`; the topology uses
TWO real PD-backed clusters — cluster-a with one PD, one TiKV, and **two TiDB
backends** (plus the TiProxy process), and cluster-b as a second playground
under its own tag and port window (+100) with one PD, one TiKV, and **one TiDB
backend** — plus a deliberately protocol-agnostic TCP fault injector.
Certificates are generated for each run and removed during cleanup; each run
therefore consumes two 100-port windows.

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
over the PD-backed backend set (with any explicit backend cluster
configured — as here — the `FallbackFetcher` serves the merged PD
topology and `backend.instances` cannot pin a backend),
`SELECT @@port` proves each user lands on a real backend, and
delta-scoped per-connection log evidence attributes each row's single
connection to exactly its expected namespace — ns-alpha, ns-beta, and
root's PD-backed default. The cluster×listener matrix (DPL-07 cluster
dimension) then proves deterministic backend-class selection: the
topology runs TWO real PD-backed clusters (a second playground under
its own tag and port window), the proxy exposes two consecutive
listeners via `proxy.port-range` with `balance.routing-rule = "port"`,
and each cluster's TiDB instances carry that listener's
`tiproxy-port` topology label — so listener A can only select
cluster-a and listener B only cluster-b, identically in both modes,
with per-listener delta-scoped evidence (Go route `target`, Rust
`connection_ready` backend_addr+cluster) and bidirectional
cross-checks. Per-cluster NSServer parity is explicitly out of scope
(the wire snapshot does not project name servers). The
no-keyspace-migration phase (DPL-07 acceptance) then proves that
router-issued dynamic backend redirects are keyspace-stable: an
isolated MatchAll instance puts both clusters (label-injected
keyspaces ks-old/ks-new, with session-token signing certs on every
backend so redirection support is real and evidenced per backend)
into one group, pins a persistent FIFO-driven session onto ks-old via
fail-backend-list, hot-swaps the list so the router genuinely tries
to push it to ks-new, and asserts the bounded structured guard hit
attributed to that exact connection, the swap's absorption through a
NEW connection landing on ks-new, and the old session's unchanged
CONNECTION_ID and backend. The claim is deliberately scoped: the
guard constrains router-issued redirects at their shared issuance
boundary; direct connection-manager Redirect calls are a separate
seam. Error parity (same
slice family) then
proves the same semantic ERR in both modes: a bind conflict fails fast
naming the port with no residue, and with ALL THREE TiDB servers (both clusters) killed and
evicted a new connection receives Go's approved 1105/HY000 "No
available TiDB instances" vocabulary; the unknown-namespace refusal is
documented as unreachable under the current public bootstrap/admin
semantics (in-memory namespace store + default auto-create + upsert-only
commit) with the vocabulary contract pinned by a session-engine e2e. Cleanup stops the Rust process with SIGINT — the
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
and uploads the redacted artifact directory even on failure.

Override `DATAPLANE_PORT_OFFSET` for a reserved CI port range. The default is a
process-derived offset between 10000 and 11900; each run consumes two 100-port
windows (the second backend cluster lives at +100), and the `all` run reserves
six non-overlapping 200-port allocations — twelve 100-port windows in total.
