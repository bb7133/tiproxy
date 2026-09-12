# Router API differential recorder (design, head 1 rev 3 — documentation only)

Status: revised design for review (addresses CodexM5 reviews dd0b295e and 8c02ac33);
no code, no CI change, no frozen-file change. Owner: ClaudeHome (split C, bb7133
2026-09-12). Reviewer: CodexM5. Baseline `a9c497c3` (`../contract.md` §1–§3).
Input format: trace v1 as accepted by `../run.py` `validate()` at PR #258 `a98bee78`
(12 ops; extended `health.backends`; checkpoint `healthy_backend_count` /
`server_version`). Any new op or field is announced in #workflow before use.

## 0. Dependencies on the runner (owned by CodexM5) — stated explicitly

- D1 `tick` and effect comparison: today `run.py` compares `effects` literally against
  `expect.effects` (`causal()` equality, then `EFFECT_LEDGER` requires `from == ledger`). A
  recorded trace with a **random** earlier choice can legally have Go and Rust on different
  backends, so a literal `from`/`to` in `expect` would reject a correct engine. The recorder
  will emit `expect.effects` with `from: "@session"` (the engine's own current assignment
  for that session) and `to` as a declared destination **set** (`legal_to`), and the
  runner needs to accept that form. **This is an interface draft, not a settled rule**: when
  a random earlier choice also changes *which* session should migrate or *whether* a
  migration is due, swapping `from`/`to` while copying Go's effect list is still wrong; the
  constraint is handled in CodexM5's runner extension. Until D1 lands, recorded traces are
  replayable only for slots whose prior selections are all unique; every other slot is
  marked `requires: ["effects-v2"]` in the manifest and does not count toward N.
- D2 `metrics` inputs: Prometheus responses observed by the proxy are archived raw (§3) but
  cannot be replayed until the metrics input op exists in the runner (CodexM5's metrics/time
  extension). Slots whose family outcomes depend on metric-driven balance are recorded
  with the raw archive and marked `requires: ["metrics-input"]`.
- D3 external timer delivery: replay must deliver the recorded `tick` schedule itself; the
  runner already treats `tick` as an input (adapter calls the real rebalance). No change.

## 1. Time and ordering (review point 1)

- **Ticks are inputs, not outputs.** The harness owns rebalance scheduling in the recorded
  proxy: it disables the router's background `rebalanceLoop` (the same `Init`-with-cancelled
  context technique the adapter uses) and drives `rebalance` itself from a **pre-declared
  timer schedule** (every 10 ms, the production `rebalanceInterval`, plus the declared
  boundary instants for each configured timeout: `timeout − 1 ns` and `timeout`). Every
  scheduled iteration is recorded as a `tick` with its declared `at_nanos`, whether or not
  Go produced an effect. Nothing is filtered by Go's output; nothing is added after the fact.
  If a declared boundary instant did not actually run (harness fault), the recording is
  **archived permanently as `incomplete`** together with the missing-boundary reason and all
  raw inputs/outputs; it does not count toward N. A new capture gets a new attempt ID
  (`<slot>-a<N>`) and never replaces or overwrites the first failure. Boundary events are
  never synthesized.
- **Consumption, not delivery.** `health` / `source_error` / `config` events carry the
  `at_nanos` at which the router **finished applying** the input (recorded inside the
  wrapper after the real handler returns), not the moment a channel tee saw the message.
  The ordering of these events relative to `open`/`next`/`finish`/`close` is the real
  consumption order under the router lock.
- **Clocks.** `at_nanos` is the harness logical clock (monotonic since trace start) that
  also feeds the proxy's clock overlay during recording, so the recorded timeouts are
  exact by construction; the raw wall clock of every input and effect is archived
  separately (§3) and never used for replay assertions.

## 2. Public-semantics derivation (review point 2) — `derive_expectations.py`

Separate rules per operation; when a rule cannot be proven from the recorded public
inputs the script **refuses to emit an expectation**, keeps the raw record, prints the
seq, and the slot is not counted.

- `next`: candidate set = backends **healthy and not in active failover** in the last
  consumed inventory, filtered by the routing rule fixed at Init (`all` /
  `client_cidr` / `proxy_cidr` / `port` with the session's ClientInfo and the
  `tiproxy-port` label), minus the selector's exclusions. Exclusion semantics follow
  `backend_selector.go:24-37`: after a failed attempt the backend is excluded; when the
  candidate set is exhausted an **exact** `ErrNoBackend` resets the exclusions and retries
  once, a **wrapped** no-backend does not. The derivation therefore tracks the exclusion list
  per session and emits `exclude_previous` only on a retry within the same attempt cycle.
  `|candidates| == 1` → `backend`; `> 1` → `legal_backends`; `== 0` → the expected error
  class is a **fixed mapping from inputs**, never "whatever was recorded": if an observer
  error is active (router `observeError`, `router_score.go:128-130,238`) the identity maps
  1:1 — `no_backend` → `no_backend`, `wrapped_no_backend` → `wrapped_no_backend`,
  `port_conflict` → `port_conflict`, the other three → `source_error:<identity>`; if the
  listener port is claimed by two clusters → `port_conflict`; ordinary exhaustion of the
  candidate set (no observer error) can only be the **exact** `no_backend` (exclusion
  exhaustion never produces the wrapped sentinel). Any recorded outcome outside this
  mapping is a discrepancy candidate: the script refuses and keeps the raw record.
  Public balance-policy constraints (`location` preferring local backends, etc.) restrict
  the legal set only where the policy's public rule is deterministic from inputs; the real
  `prefer-idle` chooses randomly within a threshold (`factor_balance.go:287-345`) and is
  **not** a strict-idlest rule, so no such example is used. Where a constraint cannot be
  proven, the slot is marked `requires: ["policy-constraint:<pair>"]` and **does not count
  toward acceptance**; an "unrestricted" set is raw evidence only, never a qualified trace.
- `lookup`: expectation is `ok` + the named backend iff that backend ID is **retained** by
  the router (`router.backends`, `router_score.go:172-181`), which includes unhealthy
  backends still holding connections and is unaffected by an observer error; otherwise
  `unknown_backend`.
- `rehydrate`: `ok` + backend iff the named backend is retained by its group
  (`group.go:514-517`) **and** the session is idle; unhealthy retention and observer error do
  not by themselves make it fail. The recorder only issues rehydrate on idle sessions.
- `checkpoint`: `healthy_backend_count` = 0 if an observer error is active
  (`router_score.go:187`), else count of healthy backends **not** in active failover
  (fail-backend-list marking per `group.go` `updateFailoverLocked`, including its "ignore
  the list when it would leave no routeable backend" guard); `legal_server_versions` = the
  versions of the **current round's** healthy backends when that set is non-empty (a
  superseded version is no longer legal once a new round has a definite non-empty healthy
  version); only when the current round has no healthy backend is the previously retained
  version the sole legal value. Never the union of all history.
- `finish` / `close` / `config` / `source_error`: outcomes as recorded; `invalid_config`
  is recorded at the **validation entry** (the config manager's `SetTOMLConfig` result),
  not by inspecting the applied config.

## 3. Effects and random choices (review point 3)

Recorded Go effects (`redirect` / `force_close`, acceptance, callbacks) are **output
evidence** only. `expect.effects` is derived as: kind, session, operation ordinal,
`from: "@session"` (each engine's own current assignment), `legal_to` = the declared
destination set derived from public inputs at that tick (healthy, not failover, in the
group, ≠ from), `accepted` from the recorded client-side acceptance policy (refusals are
scripted by the harness, not observed). This requires D1; until then the recorder
emits the literal form only for slots where all prior choices were unique, and marks the
rest `requires: ["effects-v2"]`.

## 4. Required outcomes — how each is actually triggered (review point 4)

| Family / outcome (contract §3) | Real trigger and evidence |
| --- | --- |
| successful selection / Finish / close | mysql clients through the real listener; `Finish(true)` observed in `backend_conn_mgr.go:341`. |
| failed creation and retry | a **real dial failure**: the harness adds a backend whose TiDB process is stopped but whose PD topology entry is still present (`env.sh tidb-stop` without deregistration → health check marks it unhealthy only after the check interval); within that window `Next` selects it, `dialBackend` fails, `Finish(false)` at `:341`, backoff retries `Next` with the backend excluded (`:330`). Evidence: the recorded `finish success=false` followed by `next` `exclude_previous`. |
| no-backend followed by recovery | `env.sh tidb-stop` of every member of the routed group → `Next` returns `ErrNoBackend` (`:330` → `ErrProxyNoBackend`, no Finish); then `tidb-start` → recovery. |
| initial empty state, first health | proxy started with the harness holding the first `HealthResult` until the first client attempt is recorded. |
| health loss / recovery | `env.sh tidb-kill` / `tidb-start`; real health check transitions. |
| drain activation / unchanged / clear / reentry | `fail-backend-list` + `failover-timeout` config updates via the real config manager; the "list would leave no routeable backend" guard is recorded as a no-op activation when it applies. |
| refused then accepted redirect | the harness's `RedirectableConn` wrapper refuses the first `Redirect` for one scripted session (client-side acceptance is a public boundary), accepts the next. |
| late completion after close, no duplicate settlement | the wrapper delays one `OnRedirectSucceed` until after the client closed. |
| valid / invalid config | `SetTOMLConfig` with a valid and an invalid document; outcome from the validator's return. |
| backend addition / removal | `env.sh tidb-add` / `tidb-remove`. |
| source error and recovery | **Declared external fault wrapper at the `BackendFetcher` boundary** (`observer.BackendFetcher` interface, composed in `pkg/manager/namespace/manager.go:76-78`): the harness wraps the real `FallbackFetcher` and, for a scripted window, returns the declared error (`context.Canceled`, `context.DeadlineExceeded`, a topology-unavailable error); the real observer converts it into `HealthResult{err}` (`backend_observer.go:95-101`) and the real router consumes it. This is the only place a live-run source error can be produced deterministically: `PDFetcher` retries infinitely and never returns an error (`backend_fetcher.go:93-104`), and stopping Prometheus does not produce an observer error. Evidence: the wrapper logs the injected error and the recorded `source_error` carries the consumption `at_nanos`. Exact/wrapped no-backend and port-conflict identities are produced by the router itself, not injected. |
| group-routing input change | config update of the group-routing inputs on the live config manager. |
| close / recreate / rehydrate | **router-level**, not a process restart (a process restart cannot keep client sockets): the harness calls the real `ScoreBasedRouter.Close()`, constructs a new router with the same observer/config, and re-attaches the surviving connections via `RehydrateConn` (`AssignmentRehydrator`), then a pending redirect's terminal result exercises `LookupBackend`. Driver = the harness, using only the public `Router` / `AssignmentRehydrator` methods. |
| CIDR match / no-match | clients from two loopback source addresses (`127.0.0.1`, `127.0.0.2`). |
| port conflict and recovery | two listeners; a `tiproxy-port` label collision introduced through the topology (second cluster entry) and removed. |

## 5. Compilable test-build wiring (review point 5)

`BackendSelector` is a concrete struct with private closures (`backend_selector.go:16-22`)
and `router.Router.GetBackendSelector` returns it by value, so the recording seam must
live **inside package `router`** and is compiled only under a build tag:

- **`next` / `finish` are recorded at the public method return, never inside the
  selector's closures.** Wrapping `routeOnce` would record calls the caller never sees: with
  one backend, after a `Finish(false)`, the next public `Next()` first hits the exact
  `ErrNoBackend`, clears the exclusions and retries successfully inside a single call
  (`backend_selector.go:24-31`); only the single public result is a recordable event.
  Wiring: a test-build **overlay** of the proxy call site (the same `go -overlay` mechanism
  `run.py` uses for the clock) substitutes, in `pkg/proxy/backend/backend_conn_mgr.go`,
  `selector.Next()` → `apireplay.Next(&selector, ...)` and `selector.Finish(mgr, ok)` →
  `apireplay.Finish(&selector, mgr, ok, ...)`, where the `apireplay` test package calls the
  real public `BackendSelector.Next` / `Finish` and records the returned value or error
  once per public call. `CloseObservation` is **not** a connection close; it ends the
  selection call. Connection `close` is recorded only from the real
  `ConnEventReceiver.OnConnClosed` (`backend_conn_mgr.go:286,935`) through the
  `RedirectableConn` wrapper.
- `pkg/balance/router/recording_apireplay.go` (`//go:build apireplay`): `RecordingRouter`
  wraps `*ScoreBasedRouter`, implements `Router` and `AssignmentRehydrator`, records
  `open` (ClientInfo) when `GetBackendSelector` is called, and records `lookup` /
  `rehydrate` at their public returns. It adds no field to `ScoreBasedRouter`, no closure
  wrapping and no call site in untagged production files.
- `pkg/balance/observer` needs no tag: `BackendObserver` and `BackendFetcher` are
  interfaces; `RecordingObserver` (tees consumed results) and `FaultFetcher` (§4) live in
  the harness package.
- Composition: `pkg/manager/namespace/recording_apireplay.go` (`//go:build apireplay`)
  adds `NewNamespaceManagerForRecording(sink)` that composes exactly what
  `manager.go:76-98` composes, substituting the fault fetcher, the recording observer and
  the recording router. The harness (`tests/controlplane/cproute/api-differential/recorder/`,
  same tag) builds the real proxy the way `pkg/server/server.go:65,201,212` does:
  `proxy.NewSQLServer(...)` with a handshake handler whose `NsMgr` is the recording
  manager. No private hook, no change to untagged production code.
- Clock: the harness applies the same `apiReplayNow` overlay that `run.py` uses, driven by
  the harness logical clock, so recorded `at_nanos` and replayed timing are the same basis.
- Metrics: raw Prometheus responses seen by the proxy are archived (D2) and not replayed
  until the metrics input op exists.

## 6. Archive and manifest (contract §3)

Per slot: `go_source_sha`, build tag/flags, environment manifest (PD/TiKV/TiDB/Prometheus
versions and topology, proxy TOML), the declared timer schedule, workload and fault
operation log with wall-clock timestamps, raw `HealthResult`/config/Prometheus archive
with hashes, event count, completed-session count, duration, normalized input/output
hashes, `trace_sha256`, `environment_manifest_sha256`, `recorded_at_utc`, and
`requires: [...]` (empty when replayable on the current runner). `trace-matrix.tsv` rows are
filled after recording; the list is frozen before the first K run.

## 7. Deliverables

1. This design + `recording-plan.tsv` (head 1, rev 3).
2. `derive_expectations.py` + the tagged wrappers/composition + harness driver (head 2),
   validated by replaying a harness-recorded run of the existing `smoke.json` scenario shape
   through `run.py` on both engines.
3. N01 (`normal / connection / prefer-idle / all`) recorded, derived, replayed (head 3);
   then the remaining 17 slots. Counts stay 0/18, 0/3, 0/3 until a slot passes replay.
