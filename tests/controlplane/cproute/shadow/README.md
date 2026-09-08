# Routing lifecycle observation (222-3 slices 1 and 2A)

The default-disabled observer captures actual Go router transitions and sends
bounded v2 batches over a local Unix socket to an optional task inside the existing
`tiproxy-rs` process. Rust derives its own lifecycle ledger, then compares Go's
output witnesses. Every envelope and diagnostic explicitly reports
`lifecycle_only=true`, `factors=false`, `selection=false`, `scheduler=false`.

The [v1 foundation contract](contract.md) and [actual recorder contract](recorder-contract.md)
define the boundary. Issue222/issue147 remain open for factor/read-window and
full-routing observation. Production routing ownership remains in issue223.

## Enablement and lifetime

Set `rust-dataplane.routing-shadow-socket` to a fresh absolute path in a directory
owned by the process UID with mode0700. Rust dataplane mode must be enabled, traffic
replay disabled, and the observation path distinct from the control socket. This
field requires restart and defaults empty. The Rust binary also accepts an explicit
`--routing-shadow-socket` option; configuration supplies its default.

Go binds a mode0600 socket and installs the recorder factory before namespace,
policy or health initialization. Capture does not wait for the first consumer.
The socket admits one same-UID peer and rejects reverse traffic. Errors disable
observation or invalidate evidence without failing SQL startup or changing routing.
Both processes cancel and join their observer tasks on rollback and shutdown.

Only fresh construction establishes a comparison interval. Namespace replacement
invalidates the old observer owner without closing the old production router.
Disconnect preserves invalid history; reconnect admits naturally created owners
only. It never seeds the mirror from current production counters. Abandoning a
selector before Finish invalidates its whole owner (UnpairedDiscard), preserving
Go's unrefunded reservation; a late real Finish(false) updates Go only.

## Capture and bounds

Under the existing Group lock, fixed helpers copy actual account score/physical
counts, head/tail, arrival predecessor and connection before/after state. The
per-owner leaf mutex serializes bounded sequence assignment and nonblocking queue
admission. It performs no I/O, callback, producer read, queue wait or retry. The
mandatory Invalid check precedes witness copying. Capture cannot write production
accounting, phase or routing decisions.

At most four events, two account witnesses and one connection comprise a batch.
Each retained batch is charged8192bytes, conservatively bounding actual encoded
storage; both queued and writer-owned batches hold their credit. Hard limits are
4096records,64MiB and a1MiB frame body. The128owner registry retains tombstones.
Overflow emits an out-of-band invalid summary even when the queue is full;
last_admitted never advances Rust's compared sequence. Invalid state is sticky.
Rust diagnostics retain the original producer cause and
last admitted sequence separately from comparison progress; per-frame totals
refresh only the changed owner, with full refresh on interval loss or shutdown.

Actual administrative same-backend reconnects use a separate marker with no
incoming/outgoing redirect accounting. They can reorder physical arrival within
the same account. The v1 ordinary redirect semantics and wire bytes remain intact.

## Reproducible gates

- `make controlplane-cproute-shadow-evidence`: original56 real-Go/v1 Rust rows,
  strict framing, API/dependency isolation and24 compiling mutations.
- `make controlplane-cproute-recorder-evidence`: actual factory/router capture,
  independent v2 comparison, real UDS faults, lifecycle rollback/join, bounded
  recorder faults and31 additional compiling mutations. A separate30-minute CI
  job runs it, retaining all existing control-plane jobs.

The positive recorder workload is fixed:60seconds, two owners, two groups per
owner, eight clients,200accepted lifecycle operations/second, plus concurrent
backend publication. Disabled and enabled workloads use identical work. The gate
requires12000operations, continuous comparison, zero invalid/mismatch/loss and
settled independent totals. Before PASS, the test consumer must independently
compare through each complete owner epoch's final admitted sequence, including
metadata after the final business operation. Those boundaries travel only over
test-control stdin, never as inputs to the mirror or as reverse UDS traffic.
It reports queue/bytes and cycle/group-lock latency
percentiles. A separate helper microtiming uses actual wrapper state but repeated
diagnostic input; that component measurement never counts as lifecycle evidence.

Both mutation runners copy sources, compile each fault, require its designated
semantic assertion, restore sources and verify the baseline. They reuse one
caller-owned Cargo target sequentially. Do not run concurrent Cargo commands on
that target while either mutation runner runs. Compiler failures never count as
mutation kills.

These tests use real Go routing APIs and the exact consumer used in `tiproxy-rs`,
with controlled backend callbacks. They do not qualify real SQL workload latency,
factor/candidate comparison, weighted-ticket selection or scheduler advice.
Slice2B adds those observation inputs and independent comparisons; slice3 must
freeze and run real SQL/etcd/health/collector acceptance before issue223 activation.

## Actual read prerequisites (2B-1a)

`make controlplane-cproute-read-foundation-evidence` verifies mixed v2 batch and
1MiB capture reservations under the shared 4096-record/64MiB budget, plus actual
Prom/Backend query publication provenance and single-load source selection.
It runs complete touched Go package race tests and 26 compiling semantic faults.
The older recorder job retains all 31 faults and both fixed 60-second workloads;
the v1 job retains its 24 faults.

This preparation change keeps wire v2 and `lifecycle_only=true`, with factors,
selection and scheduler all false. `LeaseEvaluation` only reserves accounting
space; it has no arena, frame, publication operation or comparison credit yet.
The constructor-only prerequisite `BindObservationOwner` binds bounded Go
loss-notification metadata. Query/source exhaustion immediately invalidates every
bound owner before any getter/consumer runs; future reads cannot recover it.
Native factor construction has not installed that binding in production yet.
No production clock callsite is changed. The next implementation adds the actual
native factor read tape, bounded storage and independent Rust comparison under
[frozen v1.1](read-contract.md); full 2B acceptance remains pending.

## Native time prerequisites (2B-1b)

`make controlplane-cproute-time-evidence` verifies the bounded Go time projection
and the shared pure Rust `control-routing::go_time` arithmetic. The gate uses
fresh actual Go Add/Sub/Equal/raw-identity outputs (12 clock rows and 5 sample
rows), separate startup zone-limit processes at512/513 bytes, complete observation
Go race tests, Rust domain tests and24 compiling mutations. It preserves the
existing26 foundation,31 recorder and24 v1 mutations and the fixed60s windows.

TimeProjection is not yet installed in native factor construction. Its fixed
128-pointer Location registry is bounded to2KiB of entries per owner on64-bit
Go (at most256KiB across128 owners); no entries are evicted or reused. Origin
construction receives two already captured startup values and validates their
raw monotonic suffix difference against Sub; only Go1.25.12 is supported.
Per-evaluation projection does not format time, reread a clock or use unsafe or
reflection; test-only Sizeof checks the fixed dictionary layout. Rust separately
tests raw-monotonic reconstruction at int64 equality/overflow and Add stripping.
Synthetic extreme monotonic operands in these Rust tests are not presented as
Go-created runtime values; the Go oracle uses only public time operations.

This prerequisite still uses v2 lifecycle-only transport, with all factor,
selection and scheduler coverage false. The origin's version/baseline metadata
and time values are not yet in a v3 codec. Production factor time callsites and
existing Rust resource-factor arithmetic remain unchanged. Actual native capture,
arenas/publication, codec, retained factor histories and independent comparison
remain required before claiming2B-1 complete.
