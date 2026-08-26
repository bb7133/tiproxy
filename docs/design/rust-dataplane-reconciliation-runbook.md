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
| Duplicate `DrainCommand` (active id) | Returns current progress; never a second drain. |
| Different drain id while one is active | `DRAIN_IN_PROGRESS` (both sides reject — Go locally before sending, Rust at the gate). |
| Re-issued completed drain id (idle) | Replays the final result. |
| Duplicate/reordered `MeteringBatch` | Applies only when the sequence strictly advances; totals never double-count. |
| Shed `MetricsBatch` | Best effort by design: dropped under bulk-lane pressure with a local counter; nothing depends on a metrics sequence. |
| Command for an unknown connection id | `RECONCILIATION_REQUIRED`; never acts on another incarnation. |

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
- **Metering backpressure**: `MeteringLedger` retains at most
  `MAX_UNACKED_METERING_BATCHES` sealed batches; hitting the bound is a
  typed fail-closed signal (`MeteringBacklogFull`) meaning reconciles
  have not acknowledged for too long — treat the control stream as
  unhealthy rather than expecting dropped metering.
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
