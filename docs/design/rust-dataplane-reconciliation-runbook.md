# Rust dataplane reconciliation runbook (CTL-06)

Operational reference for redirect/drain/close idempotency and the residual
Go↔Rust restart exchange. Protocol authority:
`rust-control-protocol-v1.md` §"Last-good state and control loss",
§"Redirect and drain". Implementations: Rust
`dataplane::control_commands` (`CommandGate`, `MeteringLedger`), Go
`pkg/controlbridge` (the route-owner residual handler, `DrainIssuer`, and
`MeteringConsumer`). `RouterAdapter` remains only as Phase-1 legacy source/test
material; bundled Rust-owner production neither constructs it nor runs
`ResolveOrphans`.

## Phase-1 route-owner boundary

Capability `RUST_ROUTE_OWNER` is required for every bundled Rust-mode control
session. It is a compatibility assertion, not a runtime switch. Once the Rust
process has started in this mode, control loss or a reconnect missing cap6 does
not transfer route ownership back to Go and does not impose the old 30-second
admission expiry.

- Rust resolves namespace, selects/reserves backends, owns the session route
  lease, schedules redirect/failover/force-close, and settles every terminal
  locally.
- Go receives no route lifecycle body and constructs no `RouterAdapter`.
  Injected legacy bodies are nonfatal protocol violations with a counter
  increment and a provably unchanged route-state hash.
- Reconcile is residual only: request connections and connection-event sequence
  are empty/zero; response connections are empty. It may acknowledge snapshot,
  metrics, metering, and drain lineage but may not create, finish, redirect,
  rehydrate, orphan-resolve, or close a route.
- CP-METER continues retaining/replaying its local ledger while disconnected.
  CP-ADMIN drain is unavailable until reconnect; process-local shutdown still
  follows the normal bounded drain/force/join chain.
- A migration command targeting a session whose long-lived route lease has
  already unregistered is rejected directly, before allocating a command
  envelope or touching that session FIFO. The router records its bounded
  refusal cooldown, and no detached redirect/close guard survives the verdict.

The detailed Go route reconciliation text below is retained as the legacy
capabilities 1–3 oracle for Phase 1. It is not a description of the cap6
production path and becomes dead-path deletion in Phase 2.

## Invariants the machines enforce (no operator action)

| Situation | Behavior |
| --- | --- |
| Duplicate or delayed `RedirectCommand` (same id) | Acts at most once: pending duplicates absorb; terminal duplicates replay the cached `RedirectResult` verbatim. |
| New redirect id while one is pending | Protocol violation surfaced; Go never issues one (it serializes on terminal results). |
| Duplicate `CloseCommand` (same id) | Replays the cached `CloseResult`. |
| Different close id while closing | Reports the actual closing id's state; never schedules a second close. |
| Duplicate `DrainCommand` (active id; legacy composition only — under `RUST_ROUTE_OWNER` both drain bodies are retired tombstones and operator drains are issued inside the Rust process, see `rust-control-admin.md`) | Returns current progress; never a second drain. Protocol `drain_id` is an **incarnation-unique wire operation id** (`<operator-label>@<128-bit boot nonce>`): one Go issuer incarnation binds each operator label to exactly one wire id/sequence, including across reconnects/epochs. A fresh Go restart re-requesting the same label is **a new operation by definition** (resuming would require persisting the label→wire mapping, which is deliberately not claimed); a previous incarnation's still-active drain surfaces through the `DRAIN_IN_PROGRESS` answer (`DrainIssuer::ForeignActiveDrain`) for the composition to wait on and retry. |
| Different drain id while one is active | `DRAIN_IN_PROGRESS` (both sides reject — Go locally before sending, Rust at the gate). |
| Re-issued completed drain id (idle) | Replays the final result. |
| Duplicate/reordered `MeteringBatch` | Same-producer sequences `<= last` are idempotently skipped; only `last+1` applies, while a gap (`> last+1`) is fatal. The producer's single WAL-ordered sender therefore prevents both double-count and skips. |
| Shed `MetricsBatch` | Best effort by design: dropped under bulk-lane pressure with a local counter; nothing depends on a metrics sequence. |
| Command for an unknown connection id | `RECONCILIATION_REQUIRED`; never acts on another incarnation. |

## Generation layering

Two dimensions guard against stale state and are deliberately separate
from transport epochs and request ids:

- **Per-session commands** (`RedirectCommand`, `CloseCommand`): the Go
  side stamps the envelope with the generation the target session was
  admitted under; the Rust gate **exact-matches** it against the
  connection's recorded generation and answers `STALE_GENERATION` on a
  mismatch — a Rust restart restarts connection ids from 1, so id
  reuse across incarnations is real and the generation is the guard.
- **Drain** (`DrainCommand`): one command spans sessions captured under
  different generations, so the envelope carries the issuing lineage's
  **config generation** and the Rust gate checks provenance only
  (reject `< applied_generation`), never per-connection equality.
- The same connection's later envelopes (`RouteRequest`,
  `ConnectionEvent`) must not drift from the generation its handshake
  established; drift is a `PROTOCOL_VIOLATION`, never silently
  rewritten.
- Redirect/close terminal-result tombstones are keyed by
  `(connection_id, id)` alone: replay works **across** control
  reconnects and Go epochs by design.

## Command sequences and provable obsolescence

Every `RedirectCommand` carries a per-connection monotonically
increasing `command_sequence` and every `DrainCommand` an issuer-wide
one. An id is bound to exactly one issuance: the same id with a
different sequence is a `PROTOCOL_VIOLATION`. Tombstone caches are
bounded, and eviction is **provably safe**: Go issues command *n+1*
only after consuming *n*'s terminal, so a sequence at or below the
watermark whose id misses every cache is a duplicate of an evicted,
already-consumed terminal — the gate answers `Obsolete`, and the
runtime replies with a `DUPLICATE_REQUEST`-coded result that the
issuer ignores by id (never a new failure, never a re-execution).
Watermarks survive restarts through reconciliation
(`ReconcileConnection.last_redirect_command_sequence`,
`ReconcileRequest.last_drain_command_sequence`): a restarted issuer
resumes from watermark + 1. Since CP-ADMIN slice 3 the drain watermark is
reported by Rust for diagnostics only; the local issuer keeps its lineage
inside the process and Go restores nothing.

All of this — the additive reconcile fields, nonzero sequences, and
the rehydration/orphan lifecycle — is gated by the
`RECONCILE_SESSION_REHYDRATION` capability. A legacy peer keeps the
original `RECONCILE_CONNECTIONS` behavior: identification by omission,
tombstone-only dedup, zero generations/sequences tolerated, and no
orphan closes (a healthy old-peer session is never killed by the new
lifecycle).

## Production ownership

The gates are on the real message paths on both sides:

- **Rust** — `dataplane::control_runtime::spawn_control_runtime` is
  the **single composition entry**: it constructs the `ControlClient`
  and places every task under one **supervisor** — as soon as any
  task terminates the supervisor cancels the siblings via transport
  shutdown, joins everything, and only then arbitrates: a real error
  (dispatch fatal, transport failure, snapshot-owner failure, panic)
  always wins over the clean cascade exits it triggers, whichever exit
  the select observed first; and with no real error and no requested
  shutdown, the FIRST clean exit of **any** task is itself reported as
  an unexpected termination. The CTL-05 snapshot owner applies each
  `StateSnapshot` as a **transaction**: `SnapshotStore::stage`
  validates without committing (the staged token holds the store's
  writer reservation, so no concurrent writer can advance the store
  between the phases), the serving-side consumer applies, and only
  then `commit` publishes — a consumer rejection leaves the store on
  the previous generation, so a replay of the same generation re-runs
  the consumer instead of being falsely acknowledged. After a
  successful commit the owner passes the **applied-generation
  barrier** (the dispatcher acknowledges recording the generation
  before the `SnapshotResult` OK goes to Go, so commands minted
  against the new generation can never race an older applied view),
  and its failure semantics are explicit: barrier/send failures under
  a requested shutdown are the clean cascade, the same failures
  without one propagate to the supervisor. The **process-long-lived**
  `ControlCommandHandler` lives on the dispatch task. The
  `InboundForwarder`'s `handle` **awaits** a bounded queue
  reservation, so a slow dispatcher stalls the read loop and the
  backpressure is real — through TCP to the Go sender's bounded lanes —
  instead of an unbounded Rust-side queue or a dropped command the
  peer considers delivered. **Teardown cannot deadlock on that await**:
  the transport publishes `Disconnected` before joining its loops, the
  forwarder then retains its one in-flight frame in a slot, and the
  next session runs **two-phase**: the write path goes live first
  (draining the lanes a jammed dispatcher waits on), then the
  transport awaits the handler's `resume_session` pump — selected
  against session stop, cancel-safe, retention intact under
  cancellation — and only after the slot is empty does the new reader
  start. At most one retained frame can therefore exist globally, it
  is delivered to dispatch exactly once, and old read paths always
  join (no detached tasks).

  The dispatch loop is the explicit multiplexer for **every** inbound
  body, with **wire-epoch policy** (each envelope carries its origin
  `control_epoch`, validated on read): commands (redirect/close/drain)
  from any epoch consult the gate — its generation, sequence-watermark,
  and tombstone invariants are exactly the cross-epoch safety
  argument; a `ReconcileSnapshot` from a dead epoch is superseded
  (dropped, counted — the current session's automatic request gets a
  fresh one) and one arriving without negotiated
  `RECONCILE_CONNECTIONS` is an unsolicited protocol violation;
  `RouteAssignment` / `HandshakeDecision` deliver to the owning
  session in every epoch under **fail-closed correlation** — the
  session arms `(initiating request id, body kind)` through the typed
  `ControlDispatchHandle::expect_response`, which awaits the
  dispatcher's **typed verdict**: only a live session WITH a response
  channel is armed (`UnknownConnection` / `NoResponseChannel` refuse,
  so a caller is never told to start an exchange whose answer could
  not be delivered), the request goes to Go only after `Ok(())`
  (registration carries the same applied-ack contract), and an
  unsolicited, wrong-id, or wrong-kind answer
  is refused as a violation instead of occupying the one-slot channel
  or being mis-consumed by a newer exchange (a closed response channel
  is answered `RECONCILIATION_REQUIRED`, not treated as delivered);
  `StateSnapshot` forwards — awaited — to the **required** snapshot
  owner (its loss terminates dispatch); Rust→Go-direction bodies
  arriving inbound (`HandshakeResult`, `SnapshotResult`, results,
  events, batches) are protocol violations. Nothing is silently
  dropped, and the select is unbiased so no arm — in particular the
  drain-force tick — can be starved indefinitely.

  Reconnect is automatic, atomic, and **capability-gated**: the
  `Connected { epoch, capabilities }` watch snapshot carries both
  values in one read, and the handler models the **active session as
  an `Option`** — every non-`Connected` observation clears it, so a
  watch-coalesced `Connected → Disconnected` can never leave a stale
  epoch behind, and a dead session's `ReconcileSnapshot` is refused
  (it must match the currently active epoch exactly); a deterministic
  barrier drains pending state observations **before** each inbound
  envelope, so a frame from a previous session is always judged
  against the newest session snapshot regardless of select order. The
  handshake **rejects cap-3-without-cap-2 on both sides** and the peer
  mode derives rehydration only from `cap2 && cap3`. The peer mode
  updates from the mask, and — only
  when `RECONCILE_CONNECTIONS` was negotiated — the reconcile request
  (declaring `[RECONCILE_CONNECTIONS, RECONCILE_SESSION_REHYDRATION]`
  as negotiated) is sent **session-scoped**: the transport queue entry
  is bound to that exact epoch and is dropped (counted) rather than
  written under a later epoch, because the next `Connected` transition
  regenerates it. Durable command results and CLOSED events are never
  epoch-dropped and survive reconnects under their operation identities.
  Metering deliberately has only one cross-session owner: its application
  WAL. Every metering wire copy is session-scoped, so the transport drops an
  old serial instead of retaining a second durable copy that could overtake
  WAL replay. Producer-qualified absolute metering opens one ordered sender
  only after the current session's `ReconcileSnapshot` arrives; the snapshot
  is a readiness gate, not a trim authority, because v1 carries its sequence
  without a producer id. The WAL is trimmed only by a producer-qualified
  `MeteringAck`. Without
  `RECONCILE_CONNECTIONS` no request is sent and no ack can arrive:
  the ledger's bounded unacked retention (fail-closed seal at the
  bound) is then the explicit backpressure. Metering has its full
  production lifecycle with **producer-owned failure**: sessions call
  `ControlDispatchHandle::record_metering`, which keeps the original
  delta at the producer and sends a copy — every failure (ledger
  rejection, dispatch gone, ack closed) **returns the original delta**
  to its owner, which retries (`BacklogFull` clears on a qualified
  metering ACK) or declares its stream unhealthy; sequence exhaustion — from a
  record or from the periodic seal — is a dispatch fatal. The tick seals
  batches into the WAL and sends only when the current session's delivery
  gate is open; reconnect regenerates everything unacknowledged from the WAL
  head under the successor serial. Because WAL trimming requires an ACK and
  every ACK is at or below the peer's applied watermark, the WAL head is
  always `<= applied+1`: duplicates are skipped and the first new batch is
  necessarily contiguous. Every counted path is exported
  through the shared `DispatchStats`.

  **Request-id lineage**: every application-originated envelope takes
  its id from the sender's single checked allocator (heartbeats
  included; compare-and-swap at the terminal value, so concurrent
  callers can never observe a transient wrap), while **responses reuse
  the initiating request id** — inline answers carry the inbound
  command's id and asynchronous terminals carry the id saved at
  admission (records are consumed at terminal production and die with
  their session, so the maps are bounded). CLOSED lifecycle events
  take allocator ids, and the recorded maximum — advanced only
  **after a successful send** — is the reconcile
  `last_connection_event_sequence`; a failed send is counted and
  converges through reconcile omission. Allocator exhaustion
  terminates the dispatch loop fail-closed. **Terminal `DrainResult`s
  are produced proactively on the completion transition** with the
  initiating id, and force-phase `CloseImmediate` is marked delivered
  only when the send succeeds. Wire drain deadlines are validated
  (force before graceful, or an absurd horizon, is a protocol
  violation) before any clock conversion.
- **Go** — `pkg/controlbridge.NewBridge` owns the mode-0600 control
  listener (`transport.Listen` + `Serve`) and the route-owner residual
  handler. In bundled Rust mode its config intentionally has no router,
  handshake, or topology attachment; it constructs no `RouterAdapter`
  and has no orphan-resolution cadence. Metering batches apply with
  contiguous-sequence dedup, drain results route to the issuer, and every
  empty residual `ReconcileRequest` restores the issuer's drain watermark
  before the handler answers with an empty route snapshot. `NewDrainIssuer`
  is **fallible**: the incarnation
  nonce is the safety anchor for drain wire-id lineage, so a
  crypto/rand failure refuses to construct rather than degrade to a
  guessable nonce. An observed foreign drain (a previous incarnation's
  wire id answered `DRAIN_IN_PROGRESS`) clears when its terminal
  result arrives and arms the consume-once `ForeignDrainResolved`
  retry signal.

At executable shutdown, all control-plane modules share one ten-second join
budget. Expiry aborts the remaining module tasks and then awaits every join
handle before runtime finish, so a stuck module is observable but cannot hang
shutdown or escape as a detached task.

**DPL-04 session ownership and drain**: `tiproxy-rs` now runs the
production session owner: one engine task owns all four socket halves
of a session, the DPL-01 FSM drives it through the one-slot pump
contract, and the CTL-06 terminal notices are produced at the real
effect completion points under the exact gate-admitted ids carried by
the session directives' command tokens. Coordinated local shutdown
follows stop-accept (`DataplaneHandle::stop_accepting`; listeners
close, sessions continue) → safe-boundary graceful drain (the owner
injects a token-free graceful close; the loop's drain deadline is the
per-session force) → the absolute grace deadline
(`--drain-grace-seconds`) forces and joins everything — a session
stalled mid-command by an unresponsive backend is hard-cancelled at
the cleanup budget, reported force-closed with the proxy-shutdown
source. The Go operator entry is `Bridge.StartDrain` (HTTP:
`POST /api/dataplane/drain`, progress at
`GET /api/dataplane/drain/:id`): one absolute deadline budget per
drain id, idempotent re-issue under the incarnation-scoped wire
binding, foreign-drain rejection until its terminal resolves, epoch
re-sync replaying the active drain to a restarted lineage, and the
issuer's send-failure semantics keeping responsibility with the next
retry. Drain budgets are validated before any reservation (negative
waits, deadlines past the shared 30-day cap, or a not-yet-applied
configuration generation are rejected as 400/503), and a correlated
`ProtocolError` completes its issuance as an observable failure and
releases the single-flight slot. The force phase is one ownership
chain: session owners hold abort-on-drop guards over their loop and
engine tasks, the force budget is a single absolute deadline armed at
the force signal (never stacked cleanup deadlines), and the server's
listener owners hold their abort backstop
(`DataplaneServer::with_force_join_grace`) until every session owner
finishes its terminal work — the CLOSED notice survives the
executable's back-to-back session/server shutdown even with a
permanently stuck backend.

**Scope honesty**: DPL-03 starts both composition entries behind the
Go `rust-dataplane.enabled` gate. Go owns the bridge and monotonic
snapshot publisher; `tiproxy-rs` owns the control runtime, first SQL
listener bind, atomic serving-generation updates, and the typed
`RegisterSession` / `SetBackend` / `ExpectResponse` session seam. The
concrete session effects that emit `SessionClosed`, `RedirectFinished`,
and `CloseFinished` land in DPL-04, metering producers in DPL-06, and
namespace/topology projection in DPL-07. Issue #16's end-to-end lost
Assigned/Closed and restart acceptance therefore stays **open** until
those dependent integrations land.

**Lineage is the control epoch, not the config generation**: a Rust
restart can keep the same snapshot generation, so closed-connection
tombstones and same-id replacement are scoped by the control-session
epoch (a restart forces a reconnect and a new epoch; a same-process
lineage never reuses ids). Both arrival orders — handshake before
reconcile and reconcile before handshake — retire a stale same-id
incarnation exactly once.

## Restart matrix

### Go restarts (Rust and its SQL sessions survive)

1. Control loss: established sessions keep forwarding; redirects and
   drains pause; new sessions follow the 30s last-good grace, then fail
   closed before allocation.
2. On reconnect, Rust sends `ReconcileRequest`: applied generation,
   every live `connection/backend` pair, `redirect_pending` flags, and
   last event/metric/metering sequences (`CommandGate::build_reconcile_request`,
   `MeteringLedger::last_sequence`).
3. The fresh Go lineage **identifies** unknown Rust connections by
   omitting them from `ReconcileSnapshot` — it never adopts accounting
   blindly and never issues redirects/drains before reconciliation.
4. Rust applies the snapshot: absent connections are **preserved**
   (never torn down by reconciliation), and any cached terminal
   `RedirectResult` the snapshot still marks pending is replayed
   verbatim (`ReconcileRepairs::replay_redirect_results`).
5. The current session's residual `ReconcileSnapshot` opens metering delivery;
   Rust then replays the producer WAL verbatim from its retained head under one
   session-scoped sender. Same-producer sequences at or below the consumer's
   applied watermark are skipped, `last+1` applies, and a gap is fatal. The
   snapshot's bare `metering_sequence` is readiness evidence only — it has no
   producer id and cannot trim a producer-qualified WAL. Only
   `MeteringAck { producer_id, sequence }` trims retained batches. A lost ACK
   therefore permits ordered duplicates but never double-counting or a gap.

#### Legacy rehydration and orphans (non-cap6 compatibility only)

For each live pair in `ReconcileRequest` unknown to the fresh lineage,
the adapter rebuilds real state through two production seams:
`AttachRouterLookup` (namespace → router, wired to the namespace
manager) and the router's `AssignmentRehydrator` (`RehydrateConn`
attaches the connection to its backend exactly as a successful
assignment — score, connection list, event receiver — and returns the
`BackendInst` so `ServerAddr`/close accounting work; `LookupBackend`
rebinds a restored pending redirect's target when its terminal result
arrives). The reconcile entry carries the full admission
`ConnectionIdentity` (additive field), so later `ConnectionEvent`s pass
identity equality, plus the connection's `generation` and
`pending_redirect_id` — a restored pending redirect blocks new
redirects until its (replayed) terminal result retires it exactly once.

A pair that cannot be rehydrated (unknown namespace/backend, missing
identity) becomes an **orphan**: identified by omission from the
snapshot (Rust keeps the session alive), excluded from redirect/drain
by construction (no connection object exists), and retried by
`ResolveOrphans`. After `MaxOrphanResolveAttempts` failed rehydrations
the adapter closes the session with a generation-stamped
per-connection `CloseCommand` — and responsibility transfers only when
that close actually reached the **current** negotiated sender with the
`PER_CONNECTION_CLOSE` capability. Failed sends keep the orphan for
the next attempt, and a **compare-and-delete in one critical section**
(the current-sender comparison and the deletion share the same
`adapter.mu` hold, linearized with `rememberSender` and reconcile)
guards the deletion: a stale sender's in-flight `Send` returning nil
after a reconnect rotation does not transfer the obligation into the
dead lineage — and no rotation-plus-reconcile can land between a
separate compare and delete, because there is no window between them.
The orphan is retained and the next cadence re-sends on the live
sender. `AttachRouterLookup`/`ResolveOrphans` remain only in the legacy
adapter test path during Phase 1. The cap6 bridge does not attach or call them.
A reused
connection id arriving under a new generation/identity retires the
stale incarnation's accounting exactly once before the rebuild.

### Legacy Rust restart reconciliation (non-cap6 compatibility only)

1. The new Rust process sends `ReconcileRequest` with its (initially
   empty) connection list.
2. Go removes every absent Rust connection from handler and router
   accounting **exactly once** (`closeStateLocked`; duplicate
   reconciles are idempotent — no double `selector.Finish`, no negative
   connection counts), answers with its authoritative snapshot.
3. Ghost connections Go still lists that Rust does not know
   (`ReconcileRepairs::ghost_connections`) are answered with terminal
   CLOSED events so both sides converge.

## Operator checks

- **Drain progress**: repeat the same `drain_id` — both sides return
  current absolute counters (`gracefully_closed`, `force_closed`,
  `complete`); a differing id answers `DRAIN_IN_PROGRESS` and
  identifies the active drain.
- **Metering backpressure and durability**: `MeteringLedger` retains at
  most `MAX_UNACKED_METERING_BATCHES` sealed batches with hard key and
  per-batch bounds; every bound is a typed fail-closed signal
  (`MeteringError`) — backpressure, never a drop. This satisfies the
  protocol's retain-**or**-backpressure branch; retention is
  **in-memory only**: unacknowledged batches do not survive a Rust
  process crash (crash durability is an explicit non-goal here and a
  candidate follow-up enhancement).
- **Stuck redirect**: on the legacy path, Go does not issue another redirect
  until the pending one terminates. In cap6 production the process-local
  scheduler owns the pending token; its timeout delivers local `ForceClose`,
  the RAII terminal settles once, and no `CloseCommand` crosses the bridge.

## Test evidence

- Rust: `crates/dataplane/tests/control_commands.rs` — duplicate/
  out-of-order/lost matrix, duplicate-storm idempotency, both restart
  directions, stale-incarnation isolation, metering
  seal/replay/ack/backlog, epoch-crossing redirect replay.
- Go: `pkg/controlbridge/drain_metering_test.go` — drain single-flight
  and idempotent results, wire-contract roundtrip, metering sequence
  dedup, Go-restart identification with metering acknowledgement;
  `router_adapter_test.go::TestRouterAdapterRedirectEvictionAndReconcile`
  — duplicate redirect-result exactly-once, Rust-restart eviction
  exactly-once with idempotent re-apply, duplicate CLOSED exactly-once.
- Phase-1 cap6: `pkg/controlbridge/route_owner_handler_test.go` injects every
  retired family and proves violation+1 with an unchanged state hash, plus
  empty-only residual reconcile and zero handler counters;
  `crates/dataplane/tests/control_dispatch.rs` proves the symmetric Rust
  tombstones; `make dataplane-t4-integration` proves compatible startup,
  rejected missing-cap6 reconnect, and fresh SQL admission beyond 30 seconds.

## Phase 2 deletion constraint

After the exact Phase-1 tree and full live matrix pass, a separate PR may
delete `RouterAdapter`, correlated handshake/route response machinery,
redirect/orphan/per-route-close bridge code, and the legacy route journals.
That PR is dead-path deletion plus residual-handler simplification only: it
must not repair a Phase-1 matrix failure or add routing behavior. Deprecated v1
message definitions and numeric tags remain tombstones until protocol v2.
