# TiProxy Rust dataplane composition

`dataplane` owns the SQL listener and frontend admission lifecycle. It stops at
an admitted, registered `TcpStream`: `mysql-wire` owns packet formats,
`proxy-io` owns transport mechanics, and `session-core` owns session policy.
The DPL-01 runtime is injected through `ConnectionHandler`, so this layer does
not duplicate protocol or routing state.

## Accept lifecycle

The initial validated control snapshot is preflighted before any listener is
bound. Traffic replay fails explicitly. All configured addresses (including a
Go-expanded port range) bind as one attempt; a failure drops every socket
opened by that attempt, and successful listeners report their OS-observed
addresses.

For every accepted socket, the server:

1. captures one immutable snapshot generation;
2. checks memory pressure, then `max-connections` (`0` is unlimited);
3. applies mandatory socket policy;
4. allocates a nonzero process-lifetime connection ID and inserts payload-free
   metadata into the registry;
5. applies best-effort frontend keepalive and transfers ownership to the
   injected connection handler.

The registry lease contains the admission permit. Normal return, rejection,
panic, task cancellation, listener shutdown, and ID exhaustion therefore all
drop the frontend fd, remove registry membership, and release the two-buffer
reservation exactly once. The registry accepts validated nonzero IDs from the
control protocol for later close/reconcile composition.

## Admission and reload

`AdmissionController` serializes the memory and maximum checks, so concurrent
accepts cannot cross a configured boundary. `SystemMemoryProbe` samples Linux
process RSS under the effective finite cgroup/host limit at most every five
seconds. A usable cached observation expires after fifteen seconds; probe
failure then fails open, matching Go's availability posture. Connection buffer
deltas since a sample are included immediately rather than waiting for the
next `/proc` read.

Reload publishes a complete validated snapshot atomically for new connections.
Existing handlers retain their captured `Arc`. Listener changes remain
restart-required under control protocol v1; DPL-03 owns any later listener
generation policy.

This implements the Rust targets behind `PARITY-ADM-001`, `PARITY-ADM-002`,
`PARITY-KA-001`, the new-session subset of `PARITY-CFG-001`, and the
capture/replay preflight in `PARITY-EXCL-001`.

DPL-03 composes this server with CTL-05 in `runtime_config`: the first valid
snapshot binds all SQL listeners before it is acknowledged, later snapshots
atomically replace the complete generation for new admissions, and any bind,
validation, or restart-required listener rejection preserves the last-good
generation. `session_control` registers each admitted connection with CTL-06
before handing it to an injected session owner, and exposes typed
`SetBackend`/`ExpectResponse` plumbing. Terminal close/redirect effects and
metering production remain owned by DPL-04 and DPL-06 respectively.

From the repository root:

```sh
cargo test --locked --manifest-path rust/Cargo.toml -p dataplane
cargo clippy --locked --manifest-path rust/Cargo.toml \
  -p dataplane --all-targets --all-features -- -D warnings
```

## Session event loop (`session`, DPL-01)

`SessionLoop` is the single owner of one session's mutable state: the
SES-00 FSM, the armed one-shot deadline (handshake until the
authenticating transition itself disarms it, drain when
`BeginDrainTimer` fires), the backend-active probe cadence (Go
`checkBackendActive`, gated to idle-safe states — `Ready`/`Draining` —
per KA-003 so it never races command I/O), and the child-operation
`JoinSet`. There is no session mutex: the `EffectHandler` (which may
spawn **tracked** children but cannot own session state) borrows `&mut`
for one call at a time, and the `SessionEventSource` (SES-layer
classification; the loop never sees packet bytes) is moved into a
dedicated **pump task** that reserves the one-slot channel's permit
**before** reading the transport, polls each `next_event` future to
completion, and submits through the permit — the loop selects on the
channel's cancel-safe `recv`, so classifier futures holding partial
read state are never dropped by a lost select race, and the classifier
is never more than one event ahead of the loop (real backpressure).

Biased select order: server shutdown (with the current value checked
first, so a shutdown that predates the loop is never missed), control
commands, the armed deadline, the probe, finished children, pumped
transport events. Control-channel closure follows control-protocol v1
last-good semantics: it never tears down an established session — the
arm is disabled, traffic continues, and the detachment is reported in
`SessionSummary`. When the FSM enters `Closing` the loop seals the
machine with `TeardownComplete`; the tracked teardown children drain in
the terminal cleanup. That cleanup runs exactly once, owned by `run`,
under **one absolute budget** (`cleanup_deadline`): the pump stops
first — the source, standing for the transport, releases before any
child is waited on — then children drain normally (teardown effects
complete exactly once), and only stragglers are aborted and joined in a
reserved slice of the same window. Every exit path (client/backend EOF,
server shutdown, normal close) drives the FSM's teardown effects
exactly once.

`tests/session_loop.rs` runs under Tokio's paused-time deterministic
scheduler: scripted lifecycle with exact effect order; stuck children
aborted only after the drain window while a slow teardown child runs to
observable completion; the terminal sequence bounded by one
`cleanup_deadline` with the source provably dropped before a teardown
child completes; the classifier held to at most one event of
read-ahead; all six redirect × transport command boundary ×
shutdown arrival orders with quiesced hand-offs; a
shutdown-precheck domination case (three stimuli provably pending,
shutdown observed before the select) and a genuine three-select-arm
race — control, finished child, and pumped boundary event, none with a
precheck — polled simultaneously with the biased order observable
(exactly-once teardown asserted in each); the
handshake deadline firing pre-auth but an authenticated fully idle
session (probe disabled, no events) surviving far past it; a
pre-existing shutdown observed at start; probe ticks skipping in-flight
commands and resuming at the boundary; control detachment with the
session still serving complete commands afterwards; and a multi-await
classifier under select-arm noise delivering every event exactly once.
The no-detached-task property is structural: handlers only ever receive
`&mut JoinSet`, and the pump task is owned and stopped by the loop.

### Session migration (`MIG-00` / `MIG-01`)

An admitted redirect carries its exact backend id, address, cluster, and
absolute deadline into the socket-owner FIFO before the FSM can start the
migration. At the next safe boundary, the engine runs bounded
`SHOW SESSION_STATES` on the old owner, validates a nonempty signed token and
top-level JSON, and synchronizes the authoritative `current-db`. It then builds
an invisible candidate in this order: dial the exact target over a fresh raw
counter owner, optionally send outbound PROXY v2 before the greeting, read and
verify the greeting, optionally send `SSLRequest` and upgrade to backend TLS,
send a second handshake using `tidb_session_token`, consume the sole auth OK,
activate independently negotiated zlib/zstd framing, send the escaped
`SET SESSION_STATES`, and consume its OK. Only the FSM's subsequent
`SwapBackend` effect can atomically install that fully restored candidate;
old-backend raw traffic is retained in the connection-lifetime totals before
the previous sole owner is dropped.

Candidate-only failures (dial/deadline, malformed greeting, invalid or expired
token, restore ERR or disconnect) drop the candidate and leave the aligned old
backend usable. An incomplete or disconnected old-backend snapshot still
closes the poisoned session. Session-state and token strings, plus the two
wire buffers that carry them, are overwritten on drop and never enter logs or
control messages. The executable supports the path over plain, backend TLS,
outbound PROXY v2, zlib, and zstd transports, including their admitted combined
variants. Deterministic real-socket coverage lives in
`redirect_restores_candidate_and_swaps_atomically`,
`redirect_restores_candidate_over_backend_tls`,
`redirect_restores_candidate_over_zlib`, and
`redirect_restores_candidate_over_zstd_and_proxy_v2`; the last row also proves
retired-plus-current raw accounting across a compressed candidate.

## Route client and dial retry (`route` / `route_control`, DPL-02)

Rust never duplicates balance policy: backend choice stays on the Go
side behind the control protocol. `RouteEngine` implements the consumer
half of `pkg/controlbridge`'s `RouterAdapter` exactly — one
`RouteRequest` opens the exchange, the adapter pushes an assignment
immediately and another after every **failed** `RouteResult`, and a
non-OK assignment (`NO_BACKEND`, internal) is the terminal answer.

Retirement follows the ADR (one terminal `RouteResult` **or**
connection close): a failed result is sent only for a candidate
failure the session keeps re-selecting past. Locally terminal outcomes
— budget exhaustion, an unsupported cluster scope, or teardown
mid-dial (cancelling the `acquire` future) — send no result, because
`handleRouteResult(false)` would make the adapter reserve yet another
backend for a dying session; `unretired_assignment()` exposes what the
`ConnectionEvent(CLOSED)` accounting (Go `closeStateLocked`, reconcile
as backstop) must retire.

Dial parity with `getBackendIO`: a per-dial timeout (1s) bounds each
attempt, a total budget (`ConnectTimeout`) bounds the acquisition, and
failures back off 100ms ×2 ±50% capped — with the jitter from a
session-owned `JitterSource` (`SplitMixJitter` hashes connection seed +
assignment id + attempt; no global randomness; clamped with a
non-finite guard). `BackendDialer` carries the assignment's
`cluster_name` on every dial; a dialer declares `CLUSTER_AWARE`, and
the engine **fails closed** (`ClusterUnsupported`) when a cluster scope
reaches a cluster-unaware dialer — the direct `TcpDialer` never
silently ignores it. Cluster DNS resolution itself is DPL-07.

`route_control` binds the engine to the real envelopes:
`ControlRouteChannel` builds `RouteRequest`/`RouteResult` bodies (the
identity must equal the handshake event's — the adapter rejects
mismatches), `AssignmentRouter` is the control-handler task's
single-owner dispatch table, and `connection_opened`/`connection_closed`
build the lifecycle events. `tests/route_engine.rs` (13 paused-time
tests: two-backend failover with exact backoff timing, all-down
`NO_BACKEND`, both budget bounds, the exact Go nominal backoff series,
cancelled-acquire close accounting, cluster fail-closed/passthrough,
jitter determinism and extreme-value delay bounds) and
`tests/route_control.rs` (exact envelope bodies end to end, dispatch
filtering, lifecycle fields, real-loopback TCP dialing) cover it.

## Idempotent control commands (`control_commands`, CTL-06)

Delayed, duplicate, or lost control messages must be harmless to
router and connection state. `CommandGate` is the single-owner
admission point on the control-handler task:

- **Redirect** keyed `(connection_id, redirect_id)`: pending
  duplicates absorb, terminal duplicates replay the cached result
  verbatim (across control reconnects — the cache deliberately has no
  epoch or request-id dimension), conflicting ids surface, late
  completions are suppressed: at most one terminal result per id.
- **Close** keyed `(connection_id, close_id)`: duplicates replay; a
  different id on a closing connection reports the actual closing id
  without a second schedule.
- **Drain** is single-flight by `drain_id`: the active id reports
  progress, a different concurrent id answers `DRAIN_IN_PROGRESS`, a
  completed id replays its final result, and graceful/force phases
  follow the command's absolute deadlines with never-negative,
  never-overshooting counters.
- **Reconciliation**: the request is built from the gate's
  authoritative connection/backend/redirect-pending state plus
  monotonic event sequences; applying the answering snapshot yields
  the terminal redirect results the peer still believes pending
  (replayed verbatim) and the ghost connections to close — both
  restart directions (Go restart preserves Rust sessions; Rust
  restart clears ghosts exactly once) are model-tested.
- **Metering** (`MeteringLedger`): deduplicated cumulative producer —
  open accumulation merges by `(keyspace, backend, public-endpoint)`,
  sealed batches carry strictly monotonic sequences and are retained
  verbatim (never coalesced) until the reconcile acknowledgement, and
  the retention bound fails closed instead of dropping. The Go
  consumer (`pkg/controlbridge::MeteringConsumer`) applies only
  strictly advancing sequences, so at-least-once replay never
  double-counts. Metrics stay best-effort end to end (transport-level
  shed with a typed counter).

The Go issuer half (`pkg/controlbridge::DrainIssuer`) mirrors the
single-flight rule locally before anything reaches the wire. The
operational picture lives in
`docs/design/rust-dataplane-reconciliation-runbook.md`.
