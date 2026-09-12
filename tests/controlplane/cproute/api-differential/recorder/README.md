# Router API differential recorder (design, head 1 — documentation only)

Status: design for review; no code, no CI change, no frozen-file change.
Owner: ClaudeHome (work split C, bb7133 2026-09-12). Reviewer: CodexM5.
Baseline: `a9c497c3` (`../contract.md` §2 comparison rules, §3 recorded corpus N=18 / K=3).
Input format: trace v1 exactly as accepted by `../run.py` `validate()` at PR #258 head
`a98bee78` (ops `health`, `source_error`, `config`, `open`, `next`, `finish`, `close`,
`checkpoint`, `tick`, `redirect_result`, `lookup`, `rehydrate`; extended `health.backends`
fields; checkpoint `healthy_backend_count` / `server_version`). New ops or fields are
announced in #workflow before use.

## 1. What is recorded, and where

The recorder is a Go **test-build harness** that runs the real proxy against a real
cluster and observes only at the boundaries the contract names (§1, §3). It never adds
caller hooks, getter tapes or private-state capture.

| Boundary | Real Go site | Wrapper | Event(s) |
| --- | --- | --- | --- |
| Health input | `observer.BackendObserver.Subscribe` channel consumed by `ScoreBasedRouter` (`router_score.go` `healthCh`) | `recordingObserver` delegates `Subscribe`, tees every `HealthResult` | `health` (full backend inventory: cluster, address, keyspace, ip, status_port, labels, healthy, local, server_version, support_redirection — all explicit) or `source_error` (identity from the result error: `no_backend` / `wrapped_no_backend` / `port_conflict` / `topology_unavailable` / `cancelled` / `deadline_exceeded`) |
| Config input | config manager delivery to `router.setConfig` / `Group.SetConfig` | `recordingConfig` tees the applied TOML | `config` (+ `invalid_config` outcome when rejected) |
| Route / Next / Finish | `pkg/proxy/backend/backend_conn_mgr.go:318-341` (`GetBackendSelector`, `Next`, `Finish`) | `recordingRouter` implements `router.Router`, delegates to the real `ScoreBasedRouter`, wraps the returned selector | `open` (ClientInfo: client, proxy, listener port), `next` (backend / error class), `finish` (success) |
| Close | `OnConnClosed` via the conn event receiver (`backend_conn_mgr.go:286,935`) | `recordingConn` wraps the proxy's `RedirectableConn` | `close` |
| Migration / drain effects | `RedirectableConn.Redirect` / `ForceClose` issued by `Group.Balance` / failover | `recordingConn` records acceptance and refusal | `tick` (one per real `rebalance` iteration that produced effects, effects listed per session in causal order) |
| Callbacks | `OnRedirectSucceed` / `OnRedirectFail` | `recordingConn` | `redirect_result` |
| Rehydration | `AssignmentRehydrator.RehydrateConn` / `LookupBackend` (`router.go:38-42`) | `recordingRouter` | `rehydrate`, `lookup` (used by the recreate/rehydrate scenario) |
| Read-only state | `ConnCount`, `HealthyBackendCount`, `ServerVersion` | read at quiescent points | `checkpoint` |

Time: `at_nanos` = monotonic nanoseconds since trace start, taken at the wrapper boundary.
Replay uses `run.py`'s existing overlay clock; the recorder does not record any internal
`time.Now` sequence. Ticks are emitted only for rebalance iterations that produced an
effect, plus one tick immediately before and one at each declared timeout boundary so the
before/equal semantics of §2 are replayable.

Logical session IDs: `<slot>-<n>` with a per-recording monotonic counter; never reused.
Late callbacks bind to the recorded `recordingConn` object, not to an ID lookup.

Raw archive (separate from the trace, hashes in the manifest): every `HealthResult` and
config document as delivered, Prometheus responses observed by the proxy, and the
workload/fault operation log with timestamps. Nothing is inferred backwards from Go's
selection results.

## 2. Expectations (`derive_expectations.py`, head 2)

The only judging code in the recording line. It reads the recorded **public inputs**
(`health`, `source_error`, `config`) and the recorded outcomes, and writes `expect`:

- `next` / `rehydrate` / `lookup`: candidate set = healthy backends at that `at_nanos`,
  restricted by the routing rule fixed at Init (`all` / `client_cidr` / `proxy_cidr` /
  `port` using the session's ClientInfo and the `tiproxy-port` label), minus the session's
  excluded backends (`exclude_previous` after a failed attempt). `|candidates| == 1` →
  `backend`; otherwise `legal_backends`. A single recorded Go result never makes a choice
  unique. Error classes come from the recorded public outcome and must be explainable by the
  inputs (observer error active → `source_error:<identity>`; empty candidate set → exact or
  wrapped no-backend as recorded; conflicting clusters on a port → `port_conflict`).
- `checkpoint`: `healthy_backend_count` from the inputs; `legal_server_versions` = versions
  of healthy backends in the current inventory ∪ previously legal retained versions.
- `tick` effects: from the recorded wrapper events (kind, session, operation, from, to,
  accepted). Timing boundaries are asserted only at explicitly declared ticks.
- The script rejects a trace whose recorded outcome is not explainable by its inputs
  (that is a real discrepancy candidate, not something to paper over) and prints the seq.

## 3. Manifest and provenance (contract §3)

Per slot: `go_source_sha` (recorded tree), build flags, environment manifest (PD/TiKV/TiDB/
Prometheus versions, topology, proxy TOML), workload and fault operation log, source-input
hashes, event count, completed-session count, duration, normalized input/output hashes,
`trace_sha256`, `environment_manifest_sha256`, `recorded_at_utc`. `trace-matrix.tsv` rows
are filled only after each recording; the list is frozen before the first K run.

## 4. Environment and workload

Environment: task #88 pinned v8.5.1 cluster on bb7133-home (`slice3-env/env.sh`): PD
127.0.0.1:2379, TiKV, TiDB 4001-4003 (+ tidb-0 for add/remove), Prometheus 9090.
Proxy: real `tiproxy` binary built from the recorded tree, `proxy.toml` pointing at that PD,
policy / routing-policy / routing-rule per slot.
Workload: `mysql` clients (`/opt/homebrew/opt/mysql-client/bin/mysql`) driven by the
harness: ≥ 100 completed connection lifecycles over ≥ 60 s per slot (`SELECT 1` plus a short
sleep), with failed-creation attempts injected by pointing some sessions at a listener whose
backend set is empty at that moment.
Fault operations per family (required outcomes from contract §3):
- normal: start with an empty inventory (first health after proxy start), then steady
  traffic; one no-backend window created by `env.sh tidb-stop` of all members of the routed
  group followed by `tidb-start` (recovery).
- failover: `env.sh tidb-kill` (health loss) and `tidb-start` (recovery); drain activation
  via `fail-backend-list` config with a timeout, unchanged reactivation, clear and reentry;
  one refused redirect (harness refuses the first Redirect for one session), late completion
  after close, no duplicate settlement.
- config/source change: valid config update and an invalid one (rejected); backend
  addition/removal (`tidb-add` / `tidb-remove`); source error and recovery (PD/Prometheus
  stop/start → observer error identities); group-routing input change; one
  close/recreate/rehydrate lifecycle (proxy restart with rehydration of surviving
  connections).
CIDR slots include match and no-match clients (two client addresses via loopback aliases);
Port slots include a port conflict and recovery (two listeners, one `tiproxy-port` label
collision introduced and removed).

## 5. Deliverables

1. This design + `recording-plan.tsv` (per slot: family, policies, rule, workload, fault
   operations, required outcomes) — head 1 (no code).
2. `derive_expectations.py` + recorder harness (`recorder_test.go`, `recording_*.go`
   wrappers, `record.py` driver) — head 2; validated on a synthetic replay of the harness
   against `run.py`.
3. N01 (`normal / connection / prefer-idle / all`) recorded, derived, replayed through
   `run.py` on both engines — head 3; then the remaining 17 slots in family order.
Acceptance counts remain 0/18, 0/3, 0/3 until a recorded slot passes replay.
