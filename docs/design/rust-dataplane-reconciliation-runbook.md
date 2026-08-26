# Rust dataplane reconciliation runbook (CTL-06)

Operational reference for redirect/drain/close idempotency and
Go↔Rust restart reconciliation. Protocol authority:
`rust-control-protocol-v1.md` §"Last-good state and control loss",
§"Redirect and drain". Implementations: Rust
`dataplane::control_commands` (`CommandGate`, `MeteringLedger`), Go
`pkg/controlbridge` (`RouterAdapter`, `DrainIssuer`,
`MeteringConsumer`).

## Invariants the machines enforce (no operator action)

| Situation | Behavior |
| --- | --- |
| Duplicate or delayed `RedirectCommand` (same id) | Acts at most once: pending duplicates absorb; terminal duplicates replay the cached `RedirectResult` verbatim. |
| New redirect id while one is pending | Protocol violation surfaced; Go never issues one (it serializes on terminal results). |
| Duplicate `CloseCommand` (same id) | Replays the cached `CloseResult`. |
| Different close id while closing | Reports the actual closing id's state; never schedules a second close. |
| Duplicate `DrainCommand` (active id) | Returns current progress; never a second drain. Protocol `drain_id` is an **incarnation-unique wire operation id** (`<operator-label>@<128-bit boot nonce>`): one Go issuer incarnation binds each operator label to exactly one wire id/sequence, including across reconnects/epochs. A fresh Go restart re-requesting the same label is **a new operation by definition** (resuming would require persisting the label→wire mapping, which is deliberately not claimed); a previous incarnation's still-active drain surfaces through the `DRAIN_IN_PROGRESS` answer (`DrainIssuer::ForeignActiveDrain`) for the composition to wait on and retry. |
| Different drain id while one is active | `DRAIN_IN_PROGRESS` (both sides reject — Go locally before sending, Rust at the gate). |
| Re-issued completed drain id (idle) | Replays the final result. |
| Duplicate/reordered `MeteringBatch` | Applies only the contiguous next sequence (`last+1`); duplicates and gaps are refused (the producer replays in order, so gaps converge), and totals never double-count or skip a batch. |
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
resumes from watermark + 1.

All of this — the additive reconcile fields, nonzero sequences, and
the rehydration/orphan lifecycle — is gated by the
`RECONCILE_SESSION_REHYDRATION` capability. A legacy peer keeps the
original `RECONCILE_CONNECTIONS` behavior: identification by omission,
tombstone-only dedup, zero generations/sequences tolerated, and no
orphan closes (a healthy old-peer session is never killed by the new
lifecycle).

## Production ownership

The gates are on the real message paths on both sides:

- **Rust** — `dataplane::control_dispatch`: `spawn_control_dispatch`
  binds the **process-long-lived** `ControlCommandHandler` to the shared
  control client. The returned `InboundForwarder` is the transport
  `Handler` for `ControlClient::run`: its `handle` **awaits** a bounded
  channel send, so a slow dispatcher stalls the read loop and the
  backpressure is real — through TCP to the Go sender's bounded lanes —
  instead of an unbounded Rust-side queue (Go frees lane quota once a
  frame is written, so only await-backpressure actually bounds memory)
  or a dropped command the peer considers delivered. The dispatch loop
  is the explicit multiplexer for **every** inbound body: commands and
  reconcile snapshots consult the gate; `RouteAssignment` /
  `HandshakeDecision` / `HandshakeResult` forward to the owning
  session's registered response channel (slot overflow is answered as a
  protocol violation, a closed channel defers to close accounting);
  snapshot bodies forward — awaited — to the CTL-05 owner; transport
  bodies terminate; anything else is answered with a typed protocol
  error and counted. Nothing is silently dropped. Reconnect is
  automatic and atomic: the loop watches the client's connection
  state, whose `Connected { epoch, capabilities }` snapshot carries
  both values in one atomic read — on every new session it updates the
  peer mode from the negotiated capability mask, sends the reconcile
  request built from the gate, and replays unacknowledged metering,
  all bound to exactly that session. Control reconnects update the
  peer mode only; the gate, its tombstones, unacked results, and
  watermarks are never rebuilt — cross-epoch replay depends on them.
  `handle_envelope` consumes real `ControlEnvelope`s (wire deadlines
  validated — force before graceful or absurdly far ahead is a
  protocol violation — then converted against an injected clock pair;
  a command arriving past its force deadline force-closes immediately)
  and emits complete outbound envelopes. **Request-id lineage**: every
  application-originated envelope takes its id from the sender's
  single checked allocator (heartbeats included; fail-closed at
  exhaustion, never wrapping), while **responses reuse the initiating
  request id** — inline answers carry the inbound command's id and
  asynchronous terminals carry the id saved at admission. CLOSED
  lifecycle events (session terminations and reconcile ghosts) take
  allocator ids, and the recorded maximum is the reconcile
  `last_connection_event_sequence` both Go's per-epoch dedup and
  rehydration key on. **Terminal `DrainResult`s are produced
  proactively on the completion transition** — the last matched
  session closing (or a zero-match admission) answers the issuer with
  the initiating id, never waiting for a command replay — and
  force-phase `CloseImmediate` is marked delivered only when the send
  succeeds: a full session channel retries on the next tick, a closed
  one converges through the close path.
- **Go** — `pkg/controlbridge.CompositeControlHandler` (transport
  handler) composes the `RouterAdapter`, `DrainIssuer`, and
  `MeteringConsumer`: metering batches apply with contiguous-sequence
  dedup, drain results route to the issuer, and every
  `ReconcileRequest` restores the issuer's drain watermark before the
  adapter answers. `NewDrainIssuer` is **fallible**: the incarnation
  nonce is the safety anchor for drain wire-id lineage, so a
  crypto/rand failure refuses to construct rather than degrade to a
  guessable nonce. An observed foreign drain (a previous incarnation's
  wire id answered `DRAIN_IN_PROGRESS`) clears when its terminal
  result arrives and arms the consume-once `ForeignDrainResolved`
  retry signal.

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
5. Rust replays unacknowledged `MeteringBatch`s verbatim under their
   original sequences; the consumer's greater-than dedup absorbs any
   the old lineage had applied. The snapshot's `metering_sequence` is
   the consumer's **applied** sequence, which lets the ledger drop its
   acknowledged retention.

#### Rehydration and orphans (Go restart)

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
the next attempt, and a **compare-and-delete** re-reads the current
sender after a successful send: a stale sender's in-flight `Send`
returning nil after a reconnect rotation does not transfer the
obligation into the dead lineage — the orphan is retained and the next
cadence re-sends on the live sender. `AttachRouterLookup`/`ResolveOrphans` are seams:
the composition wiring (namespace manager, maintenance cadence) lands
with the DPL-03/05 integrations, and the no-leak property holds *given
that cadence* — it is not claimed for an unwired binary. A reused
connection id arriving under a new generation/identity retires the
stale incarnation's accounting exactly once before the rebuild.

### Rust restarts (Go and its router survive)

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
- **Stuck redirect**: if a redirect never terminates, Go will not issue
  another for that connection; force the session closed
  (`CloseCommand`, `force=true`) — close accounting retires the
  assignment, and the redirect result is suppressed exactly once.

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
