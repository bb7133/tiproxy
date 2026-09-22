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

The Rust dataplane runs the same six transport families for real:

```sh
tests/dataplane/integration/run.sh --mode rust --variant plain
tests/dataplane/integration/run.sh --mode rust --variant tls
tests/dataplane/integration/run.sh --mode rust --variant proxy
tests/dataplane/integration/run.sh --mode rust --variant compress-zlib
tests/dataplane/integration/run.sh --mode rust --variant compress-zstd
tests/dataplane/integration/run.sh --mode rust --variant tls-proxy-zstd
```

`preflight.sh` demands the capability contract from
`tiproxy-rs --integration-capabilities` — currently
`in-process-control-runtime,control-bridge-v1,rust-route-owner,rust-meter-owner,rust-api-owner,mysql-listener,health-endpoint,graceful-shutdown,tls,proxy-v2,zlib,zstd`.
The launcher refuses any variant whose required capability is absent; it never
substitutes a raw TCP relay or the Go dataplane for a Rust success.
The launcher enables the Go config's `rust-dataplane` gate (the Go
process cedes the SQL listeners and serves only the control plane and
API), waits for the control socket (created under `/tmp` with the run's
tag: macOS caps `sun_path` well below the artifact path length), starts
`tiproxy-rs` with a `--health-port` readiness endpoint that answers 200
only after the first applied generation, and then runs the same
`SELECT 1`, drop-next recovery, diagnostics, and port-release checks as
the Go baseline. Both modes additionally prove the namespace/topology
matrix (DPL-07 #41): two namespaces map alice and bob
over the PD-backed backend set (with any explicit backend cluster
configured — as here — the `FallbackFetcher` serves the merged PD
topology and `backend.instances` cannot pin a backend),
`SELECT @@port` proves each user lands on a real backend, and
delta-scoped per-connection log evidence attributes each row's single
connection to exactly its expected namespace — ns-alpha, ns-beta, and
root's PD-backed default. Go mode seeds them through its process-local admin
API; cap6 Rust mode writes the authoritative persistent
`/config/ns/{default,ns-alpha,ns-beta}` set. Persisting `default` is deliberate:
the first explicit namespace set replaces the one-shot process seed, so an
operator who wants to retain the fallback must materialize
`/config/ns/default` before or with that first update. A directed Rust
regression locks both outcomes (omitted default disappears; materialized
default coexists with the exact seed incarnation). The cluster×listener matrix (DPL-07 cluster
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
fail-backend-list, and hot-swaps the list so ks-new is the sole routeable
target. In legacy Go mode the runner retains the bounded structured guard
record. In cap6 Rust mode it instead requires the authoritative `/config/proxy`
generation to absorb (a NEW connection lands on ks-new), while the exact old
session keeps its CONNECTION_ID and ks-old backend and the Rust route ledger
has zero incoming/outgoing/unsettled tokens. This proves the local issuance
boundary refused the healthy sole candidate without consulting or emitting a
Go route command. Error parity (same
slice family) then
proves the same semantic ERR in both modes: a bind conflict fails fast
naming the port with no residue, and with ALL THREE TiDB servers (both clusters) killed and
evicted a new connection receives Go's approved 1105/HY000 "No
available TiDB instances" vocabulary. The namespace regression above also
pins the exact 1105/HY000 namespace-missing response once an explicit
persistent set intentionally omits `default`. Cleanup stops the Rust process with SIGINT — the
coordinated-shutdown path. The PROXY protocol variant additionally exercises
WIRE-activation B: the fault proxy prepends an inbound PROXY v2 header on the
client leg (consumed by a greeting-first probe), the dataplane emits an
outbound PROXY v2 header on the backend dial, and the direct listener-B
connection — which carries no inbound header — is served without blocking. The
compression variants exercise WIRE-C over real TiDB: classic zlib, negotiated
zstd, and the combined frontend TLS + inbound/outbound PROXY v2 + zstd path.
Each run proves a real query, recovery, migration, diagnostics, and owned
cleanup under the selected transport.

### T4 route-owner capability fence

The focused ownership regression is a public target:

```sh
make dataplane-t4-integration
```

It starts the real Rust process and real TiDB topology through a byte-transparent
control intermediary, proves compatible cap6 negotiation by successful SQL and
forwarded frames, then replaces only the intermediary with a test Go-role peer
whose negotiated set deliberately omits `RUST_ROUTE_OWNER`. Rust advertises
cap6 and closes before acknowledging that incomplete session. The same Rust
process stays healthy and admits a new real `SELECT 1` after 32 seconds, beyond
the removed legacy route-authority grace. The JSON artifact records attempts,
missing-capability rejections, Rust cap6 advertisement, and any unexpected
negotiated session (which must remain zero).

This gate does not delete the v1 route messages. Phase 1 keeps their protobuf
tags/types as non-actionable tombstones and counts an injected retired body
without effects. Any later Phase 2 is a separate dead-path-only PR: delete
legacy adapters/handlers, retain the numeric tombstones until protocol v2, and
do not add routing behavior or repair a Phase-1 qualification failure there.

Full T4 qualification additionally sets `DATAPLANE_T4_QUALIFICATION=1`. For
each physical run it also requires `DATAPLANE_T4_ROW=M1` through `M9`, places
the byte-transparent control tap on the complete process lifetime for every
protocol variant, and retains both `t4-route-audit-final.json` (the main
topology) and `t4-route-audit-ka-final.json` (the migration/restart topology).
The tap audits both
directions without decoding/remarshalling and fails the cell if it observes any
of the eleven retired Handshake/Route/Connection/Redirect/Close bodies, any
backend/namespace in `StateSnapshot`, or any connection/event-sequence routing
state in reconcile. A positive connect and forwarded-frame count proves the
zero is from the live control path rather than an unattached observer.

Every cell also retains an append-only `t4-process-lineage.json`: start,
crash/restart, predecessor PID, parent PID, and OS process-start evidence for
both TiDB playgrounds, both Go/Rust pairs, the ingress proxy, and each control
tap. The before/after Rust health receipts carry exact payload-free
config-file/etcd, topology observed/applied, and routing generation/client-epoch
stamps. The cell manifest hashes those receipts, the two route audits, process
lineage, row receipt, binaries, and rendered configs; missing evidence fails
closed instead of producing a partial pass.

The Rust health surface also publishes payload-free totals across current and
retained router incarnations. Qualification captures
`t4-ledger-before.json` and `t4-ledger-after.json` and requires zero sessions,
reserved/active/incoming/outgoing counts, and unsettled redirect/close
terminals at both boundaries. Retired namespace routers stay in the diagnostic
until their last session/worker lease drops, so replacement cannot hide a leak.

For M5, each physical run repeatedly admits a real SQL connection until the
production route plane's payload-free health diagnostic proves that the
successful reservation consumed nonempty live health, CPU, and memory inputs.
The exact JSON response is retained as `t4-m5-route-inputs.json`; a mock
selector, replay fixture, or API-only probe cannot satisfy this gate.
The M5 row (and any later cell that depends on CPU/memory inputs) must be
recorded on Linux with real TiDB: the Go process collector depends on procfs,
so Darwin TiDB exports neither `process_cpu_seconds_total` nor
`process_resident_memory_bytes`. A Darwin M5 run is preserved as incomplete,
never counted as pass. Every physical artifact records `uname -sm` so this
boundary is machine-checkable.

M9 runs a separate live owner-restart oracle. It drops the control bridge for
more than 30 seconds, performs a real A0-to-A1 local redirect during the loss,
and requires both the existing session and a fresh post-grace admission to
work. It then executes Go-only, Rust-only, and whole-process restarts in quiet
and real backend-command-in-flight states. A pre-restart CP-ADMIN drain seeds
wire sequence 1; after a Go restart the tap must see reconcile restore
watermark 1 and the next targeted drain use sequence 2 and close its one
session exactly once. Replacement Rust processes must expose a zero ledger
before fresh admission, and whole restarts must rebind the same endpoints and
workdirs without port, lease, or WAL identity collision.

Namespace setup in Rust mode writes the real CP-CFG input at
`/config/ns/*`; the legacy Go namespace HTTP API is process-local and is not a
Rust routing authority. The startup `default` namespace is only a one-shot
in-process seed. Before an operator writes the first explicit namespace, they
must persist `/config/ns/default` too if default fallback must remain: the
first explicit namespace mutation makes that prefix the complete authoritative
set, and an omitted default then correctly yields namespace-missing
1105/HY000. The runner materializes `default` before `ns-alpha`/`ns-beta`, and
the control-router regression locks both the omitted and materialized cases.

### VAL-01 external-driver smoke (#48)

The Rust/plain topology can additionally run two native external drivers
against the same real TiDB backends:

```sh
DATAPLANE_SMOKE=1 tests/dataplane/integration/run.sh \
  --mode rust --variant plain
```

The adapters are pinned in-tree: Go `go-sql-driver/mysql v1.10.0` and Python
`mysql-connector-python 9.4.0`. Both run the key connection/query/transaction/
prepared-statement workload, and each driver's compression row must produce
exactly one fresh Rust `connection_closed` record carrying `CLIENT_COMPRESS`.
A missing driver, unreadable log, zero or ambiguous close records, or a silent
compression downgrade fails the acceptance run by default. Driver-level TLS is
a documented follow-up; the proxy TLS path itself is covered by the dedicated
TLS variants and authentication matrix below.

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
variable. The test then changes the active owner's fail-backend list so the
second backend is the only routeable member of that keyspace. In cap6 rows the
mutation is committed to `/config/proxy`, consumed by Rust CP-CFG, and scheduled
by the local route owner; the legacy Go admin API is used only in Go mode. A
fresh connection proves the new route has absorbed.
The same still-running client must subsequently report A1's `@@port` while
retaining both `DATABASE()` and the user variable. This is the live oracle for
TiDB's signed `SHOW SESSION_STATES` result, the `tidb_session_token` second
handshake, `SET SESSION_STATES`, and atomic owner swap; a disconnected/replaced
client cannot pass it. The phase restores the original A0 pin before the
separate cross-keyspace refusal test starts.

This row runs in every admitted Rust variant: plain, TLS, outbound PROXY v2,
zlib, zstd, and TLS+PROXY+zstd. Its candidate-failure rollback matrix remains
in the deterministic session-engine E2E, where invalid/expired tokens,
unhealthy/expired/unreachable targets, and restore ERR/disconnect all preserve
the aligned old backend. Dedicated real-socket rows additionally isolate zlib
candidate activation and the combined zstd+PROXY-v2 candidate ordering while
checking exact retired-plus-current raw-byte totals.

### MIG-02 atomic redirect lifecycle (#44)

MIG-02 closes the control/accounting boundary around that live MIG-01 swap.
The production Rust local FIFO binds each accepted redirect token to the
router-issued target backend. A successful terminal changes the physical
owner; a failed terminal keeps the old owner and settles that exact local
`(old,target)` ledger operation. This prevents failed redirects from leaking an
incoming/outgoing count while a late or duplicate terminal touches an unrelated
assignment.

The deterministic acceptance rows deliberately complement, rather than repeat,
the real-TiDB migration phase:

- `redirect_restores_candidate_and_swaps_atomically` drives the production
  dispatcher and session engine through success, a completed duplicate, and a
  stale generation. Backend accept/transcript counters prove one candidate
  dial, one snapshot, one restore, zero stale-target I/O, and that every later
  user command reaches only the new owner. Final CLOSED accounting still
  includes the retired old socket and current socket exactly once.
- The Go `TestRouterAdapterWithFakeRustUDSPeer` framed-Unix-socket test was
  deleted at #223 Phase 2 together with `router_adapter.go`; the Rust side of
  that seam is still covered by the dataplane integration suite.
- `TestRedirectFailureBalancesExactRouteAccounting` uses the production
  `ScoreBasedRouter` health/rebalance loop. It observes the real old-to-target
  pending gauge rise, feeds the exact failed Rust terminal, and requires the
  gauge to return to its prior baseline once; replay cannot decrement it twice.

Together these rows make the live A0 -> A1 result a single-owner atomic swap
with generation-safe, idempotent control effects and balanced Go accounting.

## Control-frame dropper (chaos-E2E control-loss)

`controldropper/` is a test-only man-in-the-middle for the Go/Rust **control**
Unix socket. In cap6 qualification it is a byte-transparent full-run audit tap;
its old CTL-06 route-frame loss mode is retained only for explicit
`DATAPLANE_LEGACY_ROUTE_CHAOS=1` compatibility testing. It is inserted between the Rust
dataplane (`--control-socket <front>`) and the Go control socket
(`--target-socket <go.sock>`), audits both directions by a field-level
protowire scan, and forwards every frame **byte-identical** except the single
Rust→Go frame a chaos chain arms it to lose. Go→Rust has no fault seam.

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
reconnect count as the successor session dials again). It also exposes
`route_audit`, whose fixed retired-body catalog, aggregate state/reconcile
routing-field counts, CP-ADMIN drain-command maximum, reconcile drain
watermark, and ordered metering watermarks are copied under the same mutex
before JSON encoding. Metering batch/ACK entries include only a one-way
SHA-256 producer-id fingerprint, never the raw producer id or metering payload;
qualification rejects a missing/malformed fingerprint or any producer change
within one audited WAL lineage. CP-ADMIN is not retired route traffic; M9 uses
the drain sequences and producer fingerprint to prove restart recovery while
the route fields remain zero. The front socket is clamped to
`0600` and owned by the run's
user. Its self-tests run in
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
Rust/plain or every formal T4 cell) launches and holds the dropper, points the Rust
dataplane's `--control-socket` at the dropper front while the dropper dials the
Go control socket, and asserts byte-transparent passthrough while unarmed. A
formal M9 row uses only disconnect/restart and CP-ADMIN observation—never a
retired route body. The optional legacy comparison drives `/arm` + `/state` +
`/release` for four old chaos chains before cleaning up the process/socket
under ownership checks. Those compatibility-only chains are:
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

For the formal T4 recording, dispatch that workflow against the exact frozen
ref with `t4_qualification=true`. The dedicated Linux job disables the ordinary
single-topology job, allows the complete matrix up to six hours, runs
`make dataplane-t4-qualification` once, and uploads the whole immutable evidence
root even on first failure. Qualification dispatches on the same ref do not
cancel an active recording attempt.

The workflow stages the frozen design snapshot vendored next to the integration
scripts at the recorder's repository-derived workspace root. The recorder
rejects it unless its SHA-256 remains
`eddcc7fb9ece5e82d45ae3b953567197664d4c6633ef3861a5d6a8f677f06f2e`.
The CI job installs and verifies the protobuf compiler, creates the evidence
root under `runner.temp` (outside the clean Git checkout) before invoking the
recorder, and tees its full output there with `pipefail` enabled. The upload
action therefore receives a canonical path without `..`, and a zero-cell
preflight or build failure retains both its nonzero status and the exact ref,
platform, and failure log instead of producing an evidence-free red job.
Before any topology starts, CI also installs the frozen playground version and
the frozen PD, TiKV, and TiDB versions through four serial TiUP invocations,
then verifies that each exact version is present. This idempotent prewarm makes
the shared `TIUP_HOME` manifests and component cache complete before the two
playgrounds in a cell start concurrently. Each launch also names the frozen
playground component version explicitly, so TiUP does not run a concurrent
latest-version metadata check. This does not change the dual-cluster topology
or the qualification matrix.
The qualifier builds both binaries on the clean runner: the Rust dataplane
under test and the residual Go TiProxy bridge used by the real-topology
harness. It hashes both into the root and per-cell immutable receipts.

GitHub exposes `workflow_dispatch` only after that workflow file exists on the
repository's default branch. A fork-only/exact-tree commit cannot be manually
dispatched by workflow name before merge; that is a CI control-plane
availability limit, not a test pass. Until then, run the same public Make
targets on the exact tree and preserve their artifact directory. Once the
workflow exists on the default branch, manual dispatch must use the exact
qualified ref and record the Actions run ID in the evidence manifest.

Override `DATAPLANE_PORT_OFFSET` for a reserved CI port range. The default is a
process-derived offset between 10000 and 11900; each run consumes two 100-port
windows (the second backend cluster lives at +100), and the `all` run reserves
six non-overlapping 200-port allocations — twelve 100-port windows in total.
