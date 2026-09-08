# CP-ROUTE 222-2B: owned migration worker

Run `make controlplane-cproute-worker-evidence` with the repository's pinned
Rust and Go toolchains. This gate has a separate 30-minute CI job; existing
migration, factor-pair, resource, collector and routing gates remain enabled.

The opt-in `MigrationSimulation::run_worker` future borrows its owner. The
caller signals its stop receiver and awaits completion before releasing that
owner. There is no detached child, production router endpoint, SQL payload or
new control-protocol message. Production activation and observation-only shadow
composition remain later slices.

One router lock covers all groups' Balance passes, followed by all groups'
timeout-close passes. Each group reads fresh monotonic time in each pass.
Configuration and backend notifications update failover activation independently
of the delayed 10ms ticker; missed ticks are skipped. A disabled redirect
capability still permits timeout close admission. First effective failover time
is retained until the list is removed or its all-routeable-healthy safeguard
suppresses it.

Only accepted redirects consume group budget and advance its timestamp. Pending,
closing and less-than-three-second failure cooldown sessions are skipped in
physical arrival order. The ordinary rate formula truncates nanoseconds exactly
like Go: below 20ms, `(10ms-1ns)/interval+1`; otherwise, one at an elapsed interval.
The agreed extreme-rate difference clamps zero truncation to 1ns and caps a scan
at the source physical population. NaN and nonpositive rates issue nothing.

The single bounded FIFO yields opaque `MigrationCommand::Redirect` or
`MigrationCommand::ForceClose` tokens through `take_command`. Close admission
marks closing without changing physical or score counts. Rejected close remains
retryable. Only the exact observed-close token settles the current retained
memberships, including a redirect that completed after close admission. A close
that arrives first invalidates a later redirect result. Foreign, duplicate and
wrong-sequence closes cannot settle; sequence exhaustion fails before admission.
The old redirect-only queue accessor exists only in tests and preserves a close
at the front.

Pair keyspace refusal records one refusal per round before any session scan.
The separate issuance backstop marks failure cooldown without advancing accepted
budget. Per-group saturating counters and the latest structured refusal are
bounded; records contain current backend/keyspace IDs, factor reason where
available, physical population and accumulated refusals, at most once per 10s.
They carry diagnostics only and cannot authorize a command.

## Evidence

- `events.json` drives 18 scenarios / 94 observations through actual Go
  `FactorBasedBalance`, `Group.Balance`, timeout closure and terminal handlers,
  and then the Rust worker. The Go overlay substitutes only `time.Now()` reads
  in `group.go`. It does not replace algorithms or expected decisions.
- Every observation compares physical/score counts, bounded FIFO order,
  pending/closing sessions, failure times, accepted group timestamp and refusal
  counts. Rates around 20ms and 10ms, fractional rates, exact cooldown/deadline
  equality, full queues, both close/result orders, fail-list ABA, repeated
  activation, all-failed suppression and both keyspace refusal paths are shared.
- Runtime tests use actual config/topology/health handles, all port groups,
  a mid-scan cancellation barrier, source notification after initialization,
  sole-worker ownership, stop/join, and close settlement after owner retirement.
  A paused Tokio clock separately checks first tick and missed-tick behavior.
- The mandatory real-producer test owns etcd, greeting/status sources and a
  collector. It first admits a resource-driven migration, then retires the
  actual collector after candidate capture but before the final metrics fence.
  The second round must use empty-source locality fallback. Exact config
  revocation prevents new issuance while an accepted command still settles.
- `mutations.py` compiles each changed candidate in its own copied source/target,
  requires exit 101 at the named semantic assertion, and restores a complete
  runtime/live baseline. Compiler failures never count as kills. The optional
  `CPROUTE_WORKER_TARGET_SEED` must name an idle target; the runner clones it into
  its exclusive temporary target and never builds in the seed.
