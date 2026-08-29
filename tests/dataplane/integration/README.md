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

The Rust dataplane runs the plain, TLS, and PROXY variant topologies for real:

```sh
tests/dataplane/integration/run.sh --mode rust --variant plain
tests/dataplane/integration/run.sh --mode rust --variant tls
tests/dataplane/integration/run.sh --mode rust --variant proxy
```

`preflight.sh` demands the capability contract from
`tiproxy-rs --integration-capabilities` — currently
`control-bridge-v1,mysql-listener,health-endpoint,graceful-shutdown,tls,proxy-v2`
(`tls` is wired by WIRE-activation A1 and `proxy-v2` by WIRE-activation B;
`zlib`/`zstd` stay absent until their slice exists, so those variants are
still refused).
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
coordinated-shutdown path. The PROXY protocol variant additionally exercises
WIRE-activation B: the fault proxy prepends an inbound PROXY v2 header on the
client leg (consumed by a greeting-first probe), the dataplane emits an
outbound PROXY v2 header on the backend dial, and the direct listener-B
connection — which carries no inbound header — is served without blocking. The
compression variants remain refused by the capability contract until their
Rust slice exists; a raw TCP relay or the Go dataplane is never reported as
Rust success.

### SES-02 live authentication matrix (#27)

Both modes additionally run a live authentication matrix that provisions
users on the real cluster and proves, THROUGH the proxy, that the
dataplane relays the real handshake end to end (Rust `session-core`
`AuthRelay`, frozen from Go `pkg/proxy/backend/authenticator.go`). The
live rows below exercise the two plugins a stock `mysql` client can drive
against a bare TiUP playground — `mysql_native_password` and
`caching_sha2_password` — plus wrong-password and `REQUIRE SSL`
enforcement, identically in Go and Rust modes; the remaining plugins are
pass-throughs covered by the `session-core` unit matrix (below), not by a
live row:

- **`mysql_native_password`** authenticates over the variant's own
  transport.
- **`caching_sha2_password`** full-auth is relayed intact over TLS
  (the client sends the password in the clear inside TLS and the proxy
  carries the whole auth-switch + full-auth exchange to the backend —
  the only plugin with a fast path in the relay). The non-TLS
  RSA-public-key path depends on the backend serving a key and is left
  to the `session-core` handshake unit matrix, so this row asserts
  success only on a TLS-frontend variant.
- **A wrong password** is rejected end to end with an explicit
  access-denied (1045) error, never a silent hang or spurious success.
- **`REQUIRE SSL`** enforcement is decided by the proxy→backend link,
  not the client link (TiDB checks the connection it actually
  terminates, which is the proxy's backend dial). Without backend TLS
  (`require_backend_tls=false`) the backend link is plaintext, so a
  `REQUIRE SSL` user is refused regardless of the client's transport;
  with backend TLS (the `tls` variants) the backend link is always TLS,
  so the same user authenticates even from a `--ssl-mode=DISABLED`
  client. This backend-link semantic is identical in Go and Rust modes
  (verified with `--mode go --variant tls`).

Plugins without a fast path in the relay (`tidb_sm3_password`,
`mysql_clear_password`, `auth_socket`, `tidb_session_token`,
`tidb_auth_token`, `authentication_ldap_simple`,
`authentication_ldap_sasl`, and any unknown `Other`) are straight
pass-throughs; a stock `mysql` client against a bare TiUP playground
cannot exercise them without extra client plugins or an LDAP/JWKS
backend, so their relay behavior is covered by the `session-core`
handshake unit matrix rather than this live phase — name classification
(`plugin_classification_matches_go_list`), fast-path gating to
`caching_sha2_password` only (`sha2_fast_path_is_plugin_gated`), and a
per-plugin pass-through matrix proving none of them short-circuits the
relay (`pass_through_plugins_have_no_fast_path`).

### MIG-01 live same-keyspace migration (#43)

Rust runs also exercise a real same-keyspace backend migration inside the
isolated keyspace-guard topology. After every TiDB backend has published a
session-token signing certificate, a FIFO-driven client is pinned to cluster
A's first backend, selects a nonempty current database, and sets a user
variable. The test then changes the real Go router's fail-backend list so the
second backend is the only routeable member of that keyspace. A fresh
connection proves the new route has absorbed, and fresh structured Go evidence
binds the exact A0 -> A1 redirect command to the persistent proxy connection.
The same still-running client must subsequently report A1's `@@port` while
retaining both `DATABASE()` and the user variable. This is the live oracle for
TiDB's signed `SHOW SESSION_STATES` result, the `tidb_session_token` second
handshake, `SET SESSION_STATES`, and atomic owner swap; a disconnected/replaced
client cannot pass it. The phase restores the original A0 pin before the
separate cross-keyspace refusal test starts.

Today this row runs in the admitted Rust plain and TLS variants. Its
candidate-failure rollback matrix remains in the deterministic session-engine
E2E, where invalid/expired tokens, unhealthy/expired/unreachable targets, and
restore ERR/disconnect all preserve the aligned old backend. PROXY-v2 and
compression are not claimed by this live row until WIRE-B/C activate those
shared transports; once admitted, the same row automatically runs inside
their variants as well.

## Control-frame dropper (chaos-E2E control-loss)

`controldropper/` is a test-only man-in-the-middle for the Go/Rust **control**
Unix socket, used by the CTL-06 chaos-E2E chains to model a control message the
Go side accepted-as-sent but never observed. It is inserted between the Rust
dataplane (`--control-socket <front>`) and the Go control socket
(`--target-socket <go.sock>`), copies Go→Rust raw, and inspects Rust→Go frames
by a field-level protowire scan — forwarding every frame **byte-identical**
except the single frame a chain arms it to lose.

Selection always carries a mandatory `connection_id`, never a bare kind filter,
so a concurrent same-kind frame for a *different* connection/health probe is
never eaten by mistake. The per-kind contract differs because the identity a
chain can observe before the frame flies differs:

- **`route-result-connected`** requires a nonzero `connection_id`; `assignment_id`
  is **optional**. The assignment id is generated by Go and never logged on
  either side, so a chaos test cannot know it before the RouteResult is sent —
  and `connection_id` alone is already exact within a Rust lineage. When a test
  *does* supply `assignment_id`, it is matched strictly (both fields must
  match); an explicitly empty `assignment_id` is rejected and `backend_id` is
  forbidden. Chain (a) arms the connection-id-only form.
- **`connection-event-closed`** requires a nonzero `connection_id` **and** a
  non-empty `backend_id` (both readable from Rust's `connection_ready` log
  before the CLOSED is sent); `assignment_id` is forbidden. Chain (b) uses it.

```sh
# Chain (a): drop the connected RouteResult for exactly connection 12
# (connection-id-only; assignment_id is unobservable pre-flight).
curl -sf -XPOST "$admin/arm" \
  -d '{"kind":"route-result-connected","connection_id":12}'
# Chain (b): drop the CLOSED ConnectionEvent for connection 12 on backend tidb-b.
curl -sf -XPOST "$admin/arm" \
  -d '{"kind":"connection-event-closed","connection_id":12,"backend_id":"tidb-b"}'
```

`GET /state` is the evidence surface: it reports the armed selector, an ordered
`events` timeline (`arm`/`drop`/`release`/`connect`/`disconnect`), `connect_count`
/ `reconnect_count` / `release_count`, `forwarded`, `held`, and a `dropped`
list whose records carry each lost frame's exact wire identity
(`control_epoch`, `generation`, `request_id`, `connection_id`, `assignment_id`,
`backend_id`). With `--pause-after-drop` the link tears down the instant the
frame is lost and refuses to dial upstream until `POST /release`, modeling a
control link wedged until the chain lets it recover (a `release` advances the
reconnect count as the successor session dials again). The front socket is
clamped to `0600` and owned by the run's user. Its self-tests run in
`self-test.sh` (`go test .../controldropper`): byte-equivalence, exact
single-frame drop, exact-selector enforcement (partial/incompatible/unknown
selectors are refused), a concurrent same-kind frame for **another** connection
left untouched under both the strict and the connection-id-only selector,
drop-record-matches-wire, the `0600` socket invariant, and hold-until-release
with reconnect accounting. Because the connection-id-only selector is exact on
the connection (not the assignment), it *does* match the same connection under
a later assignment while the strict selector does not — both directions are
covered.

The **runtime wiring** has landed: the keyspace-guard phase of `run.sh` (for
`--mode rust --variant plain`) launches and holds the dropper, points the Rust
dataplane's `--control-socket` at the dropper front while the dropper dials the
Go control socket, asserts byte-transparent passthrough while unarmed, then
drives `/arm` + `/state` + `/release` for the four chaos chains before cleaning
up the process/socket under ownership checks. The four chains built on it are:
(a) a lost `RouteResult{connected}` leaves a live-but-uncounted session that the
automatic reconcile restores to exactly +1; (b) a lost `ConnectionEvent{CLOSED}`
leaves a ghost that the reconcile clears to exactly the live count; (c) a
one-sided Go restart the surviving Rust session rides through and the new
incarnation rehydrates; (d) a one-sided Rust restart whose dead-session ghost
the successor Rust control session's empty reconcile zeroes before a fresh
session is counted.

## Diagnostics and safety

Artifacts are retained under `tests/dataplane/integration/artifacts/` (or
`DATAPLANE_ARTIFACT_ROOT`) and ignored by Git. `collect-diagnostics.sh` collects
Go TiProxy, TiUP/TiDB, fault injector, and preflight output through `redact.awk`.
It excludes private-key/certificate files and removes suspicious authentication
lines and URL user-info. Rust dataplane runtime logs (the proxy log, the
keyspace-guard-phase `tiproxy-rs-ka.log`, and the dropper `/state` snapshots the
chains persist) land in the same run directory alongside the Go output.

Cleanup signals long-lived service/daemon PIDs (TiProxy, the Rust dataplane,
the dropper, TiUP) only when their command lines contain this run's unique path
or tag; the FIFO-driven transient `mysql` clients a chain spawns are reaped
best-effort by the exact PID this script just spawned and persisted to
`state.env`, not by an ownership scan. Cleanup asks TiUP to clean that exact
validated tag, removes generated keys, and probes every reserved port. It never
kills by process name or deletes TiUP's shared data directory.

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
