# Routing shadow foundation (222-3, first slice)

This slice provides an observation-only lifecycle mirror and its temporary legacy
codec. It does not connect a production observation socket, instrument Go router
hot paths, run factor comparison, or enable Rust routing ownership. Every mirror
view explicitly reports `lifecycle_only = true`.

The frozen design is [contract.md](contract.md), v1.2, reviewed by ClaudeHome in
Raft #workflow:a5314eb7 (1588b11a, 4e2be5c6, d1f7cbe2, 9ca22d87). Production
activation remains in issue223. This slice is part of issue222/issue147.

## Implemented boundary

`control-router::shadow` takes plain observations, with no production Router,
reservation, session endpoint, command queue or config/backend-store handle. Its
own bounded registry retains `(process, owner, nonce)` identities, local owner
identities, account/session tombstones and separate resource-factor lifetimes.
Resource/Location switches preserve that factor lifetime; Connection revokes it
and later re-entry creates another lifetime inside the same owner epoch.

A first contiguous Begin establishes an empty mirror. Missing construction
history, nonce reuse, sequence gaps/duplicates, unknown session identity and
population exhaustion invalidate evidence. Invalid state is sticky for the owner;
a new Go process can establish a new owner while the old invalid interval remains
retained. The producer must start before owner initialization; the live attach
and reconnect protocol enforcing that fact is a subsequent slice. Replaying a
saved complete corpus is a test operation, never proof of a current live baseline.

The mirror derives reservations, active counts, incoming/outgoing redirects and
physical arrival lists independently from accepted lifecycle events. Redirect
admission moves score; its matching success moves physical membership. Close
admission marks closing only. An observed close settles retained physical and
score owners, whether it precedes or follows a redirect terminal. Known old or
closed operation terminals remain no-ops; an unknown session means missing history.
Retirement permits settlement of the retained tail, and End requires it to be
closed. EOF without complete owner ends fails the owned corpus entrypoint.

`legacy-router-shadow` owns serialization. Domain crates do not depend on it or
on control-proto. Each frame is a four-byte big-endian length followed by strict
JSON, with decimal-string u64 identities/sequences. Duplicate and unknown fields,
unknown versions/event kinds, noncanonical/overflowing IDs, oversize and truncated
frames are rejected. Empty event variants use empty struct variants: serde's
internally tagged unit variants otherwise accept unwanted fields.

The consumer inbox bounds both 4096 queued records and64MiB encoded-byte charge,
including frame prefixes; a frame body is at most1MiB. Decoded events in this
slice contain only fixed-size values, so that byte charge is conservative. The
inbox never evicts older records to make room. Its errors must invalidate the
owner/stream at the future live composition; this primitive does not claim to
implement the Go recorder's Invalid fast path, lock ordering or backpressure.

## Evidence

Run `make controlplane-cproute-shadow-evidence` with the pinned Rust toolchain.
The gate executes domain and strict-codec tests, checks the API/dependency
boundary, compares56 immediate real-Go/Rust lifecycle observations, rejects an
unsealed EOF, then compiles semantic mutations and verifies a restored baseline.

The Go fixture executes actual Group Route/onCreate/Rehydrate, final redirect
admission, failover timeout-close and terminal handlers. Endpoint admission is
controllable; expected counts, physical lists and pending/closing state are read
from Go after each event. No observer patches Go accounting or lifecycle flags.
The three scenarios cover both close/result orders, rejected redirect and close
admission, failure retaining arrival order, accepted retry and successful arrival.
The fixture owns its metadata Begin/Retire/End boundaries; it is not a production
factory/transport/restart harness. Identity, sequence, resource-token lifecycle,
capacity and missing-history faults are tested separately in the domain.

The 24 mutations must compile, then fail the named semantic assertion or API
isolation check. Compiler errors, stale mutation anchors and unrelated failures
are errors, never kills. The runner copies sources and clones/copies an idle
baseline Cargo target into one exclusive temporary target, mutates sequentially,
restores source after each case, and verifies all baseline tests again. Temporary
sources/targets are removed at exit and original source bytes are checked.
Do not run another Cargo build while this gate is seeding its baseline target.

The Rust workflow adds an independent30-minute shadow evidence job; it retains
all existing migration, worker, factor, collector, applied and quality jobs.

## Remaining before full222-3 acceptance

- Actual Go factory/group/factor/bridge observation, including RouteableBackends
  cache updates, read-time metrics/clock values and complete accepted/rejected
  events captured under existing locks. Implement recorder leaf-lock ordering,
  atomic sequence/admission, Invalid-before-copy, bounded loss and joined drain.
- Same-process Rust socket composition, start-before-owner enforcement and
  observed source revocation/retirement/reconnect. Preserve all invalid intervals
  and require explicit fresh owner history after observer-only restart.
- Independent factor/candidate/weighted-ticket comparison under the frozen
  equal-vector normalization, plus actual scheduler/failover comparison.
- Sustained owned Go-authority/Rust-SQL sessions with real etcd/health/collector,
  rotations, faults and one-sided restarts. Declare coverage/load/duration and
  enabled/disabled lock-hold and request-latency thresholds before that gate.

A clean lifecycle corpus does not satisfy those remaining routing/shadow checks.
