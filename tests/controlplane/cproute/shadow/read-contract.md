# CP-ROUTE 222-3 slice 2B: actual read windows and routing comparison, frozen v1.1

Task #81, #workflow:a5314eb7. Base main
4b678ed013add2619239a000a6640c7c7726d0e0 (PR250 merged, peer c99debfa verified).
This refines the accepted shadow v1.2 and recorder v1.1 contracts. Peer
0c4384f7 accepted all five review points on September 9, 2026, subject to the
conditions incorporated below. This frozen contract is not implementation evidence.
No production Rust routing activation, new daemon, or ControlEnvelope extension.

## 1. Source findings that determine the design

- Go factor_balance.go: BackendToRoute, RouteableBackends and BackendsToBalance
  all call stateful updateScore; N=0 and the balance N<=1 paths return before it.
  Observe those early returns without inventing query/time/cache work.
- Resource and Location preserve the same CPU/memory/health factor objects.
  Switching to Connection destroys them; reentry constructs fresh objects.
- CPU/memory consume actual query results, conditionally refresh snapshots,
  read a snapshot time and separately check expiry. Health reads failure then
  total per indicator, skips total when failure is empty, retains old query
  results and may update snapshots even when no later connection is selected.
- query_result.go QueryResult currently has only Value and UpdateTime.
  ClusterReader.GetQueryResult selects an atomic source, then the selected
  reader's existing mutex returns its stored result. A later source load or
  metrics getter would not identify the read that influenced this evaluation.
- Go GetSamplePair4Backend/GetSample4Backend select the first matching instance
  and optional cluster series. CPU EWMA and memory OOM use the complete used
  series. Only copying the final sample or the calculated risk loses inputs.
- Go has several actual time reads per evaluation, plus UnixMicro tickets and
  scheduler reads. Rust factors::State::evaluate currently accepts one Queries
  map and one now; it also constructs preference and balance reports together.
  A direct call using an end-of-evaluation snapshot cannot prove live parity.
- PromReader/BackendReader RemoveQuery removes the expression/rule but does not
  erase queryResults. Go may still return an older published result; CPU/memory
  cache refresh keys on UpdateTime, not a new diagnostic publication token.
  Metadata must describe that behavior, not introduce a new reset/expiry rule.
- Go sort.Slice only compares packed score. The actual order inside equal full
  factor vectors is permitted as a witness only after independent score proof.
  It can influence traversal, advice and which random candidate has weight11.

## 2. Construction, identities and coverage

Continue factory-only installation before Group/policy Init. Bind a concrete
internal factor recorder to (epoch,group incarnation) when the actual native
FactorBasedBalance is constructed. No attach setter, policy decorator that
re-evaluates, observer callback to a production object, or retained BackendCtx.
Actual local variables are copied while the original production lock is held.
The recorder/drain still never acquires Group, policy or metrics-reader locks.

Each owner/group/config application, backend incarnation, cluster reader,
source-mode transition, query registration and published query result has a
checked diagnostic identity. Allocate producer/query metadata at the actual
creation/publication/removal boundary under existing serialization. Returned
QueryResult carries immutable metadata from that exact publication. Source
selection and its diagnostic generation must be one coherent load (for example
an immutable atomic selector value), not separately loaded kind/generation.
The six allowlisted queries retain their actual register/remove lifetimes.
A result retained after unregister remains attributable to its original
publication when Go actually returns it; do not invent an empty result. Source
or publication identity changes alone do not reset a factor cache when Go's
actual timestamp/config/lifetime rules would retain it.
Diagnostic IDs must not become production Rust source/authority handles.

The existing owner epoch cannot be reset to recover omitted history. A private
shadow resource-factor token is created at enable, preserved across Resource ↔
Location, revoked on Connection, and replaced on reentry, including coalesced
config changes. No ResourceIncarnation constructor is opened for shadow.

Use a new strict v3 observation dialect alongside unchanged v1/v2 decoders.
Native v3 owners advertise installed capabilities and separate exercised counts;
v1/v2 remain lifecycle-only. Unsupported custom policies may still supply v2
lifecycle evidence but cannot qualify as v3 full-routing evidence. Partial
2B deliveries explicitly retain false selection/scheduler coverage until wired.
Namespace/owner disappearance and shutdown keep 2A's sticky Invalid semantics.

## 3. The actual read record

One Evaluation is bound to epoch, group, policy incarnation, actual entrypoint,
input account order and a monotonically checked local evaluation ID. Its ordered
read tape contains only values from the actual evaluation:

1. Config/backend reads: exact used balance/routing policy and thresholds,
   label matching inputs, health/locality provenance, backend metadata and
   selected retained account. Score/physical counts are witnessed against the
   independently maintained lifecycle ledger, not copied into that ledger.
2. Query reads: fixed query kind, source/query/publication identity, result kind,
   actual Empty distinction and UpdateTime; preserve the conditional read order.
   Record immutable allowlisted instance/cluster series with their original
   order and sample timestamps/IEEE754 value bits. Wrong kinds and missing
   series remain distinct. Do not call another GetQueryResult for observation.
   If projecting to used accounts, retain the matching labels and first-match
   order and independently validate selection; do not supply a Go chosen value
   without its lookup evidence. No PromQL, credentials or arbitrary labels.
3. Clock reads: named callsite plus occurrence ordinal and the value actually
   used there. Replace a time.Since call, where necessary, with one named clock
   read whose Sub result is used by production; never evaluate Since and then
   call Now to annotate it. Preserve Go's monotonic-vs-wall comparison rules:
   record wall time, monotonic-presence and process-relative monotonic instant
   derived from that same time.Time and a startup origin. No second clock read.
   Every epoch coverage frame carries the process startup origin once. Rust
   independently applies Go Sub: use monotonic instants only if BOTH operands
   have monotonic data; otherwise use wall time, including duration saturation.
   All factor time comparisons follow this rule, with no Go boolean backfill.
   Stored query/config/failover times carry matching time-domain information.
   The validation capsule lists every production Since-to-Now/Sub callsite,
   with Go equivalence tests for operands with and without monotonic data.
   A time that cannot be represented exactly invalidates evidence, not routing.
4. Outputs, kept separate: factor order/bit widths, each full vector and packed
   score, routeability, actual post-sort account order, actual advice calls and
   their order/results, candidate/ticket traversal and returned pair/decision.

Captured flags like Empty must be recomputed from captured structure. A read
that did not occur is absent, rather than synthesized as an empty query. Rust
must consume the expected named tape in order with no missing/extra reads;
changing query/time order cannot pass by replaying a final map/single timestamp.
Retained Health queries and every factor cache evolve from their own prior
compared state; a new input cannot backfill or reset that state after a gap.

## 4. Bounded capture and atomic qualification (fixed limits)

Keep the existing lifecycle path's 8192-byte charge and 4096-record/64MiB limits.
V3 Evaluation is a variable-size record with a conservatively reserved 1MiB
lease: at most512KiB bounded copied input/output storage plus512KiB encoding
storage. Its encoded body is additionally bounded by512KiB (below the existing
1MiB frame ceiling). Fixed caps:64 input accounts,6 query kinds,4096 total used
samples,64 named clock reads and128 total ordered query/time read items,
512 bytes per allowlisted string,64KiB total strings. Backend field projections
are separately bounded by the64-account array; no unbounded getter transcript.
Each equality and +1 boundary needs a distinct semantic assertion. These are
qualification bounds, not restrictions on how many backends Go may route.

Before copying, obtain a nonblocking shared record+byte lease from the same
recorder budget. Charge in-flight capture, queued records and writer ownership
until release. Use a bounded reusable arena, not a new uncharged query clone.
The record and byte counters change atomically as one admission reservation;
1MiB leases may not borrow uncounted space from the 2A queue. Replace the
fixed credit with one atomic (records, bytes) admission under a short leaf lock;
no CAS retry or capacity wait. Verify the arena layout and encoder upper bound
in tests, including simultaneous writer buffers and mixed v2/v3 equality and
+1 at both 4096 records and 64MiB. Popping a writer delivery never releases it.
The capsule repeats every fixed cap in this section. Slice3 real clusters must
fit these caps; revise the limits before acceptance if they do not, never truncate.

Do not hold the owner leaf mutex throughout a policy evaluation. Capture into
that evaluation's private leased buffer under its existing Group/policy lock;
after the actual call, publish the completed record and assign its owner sequence
atomically under the short leaf mutex, STILL within the same Group critical
section: after the policy call returns and before Group unlock. Lifecycle batches
from that group must not acquire a sequence between evaluation and publication.
This allows concurrent groups without
serializing whole factor evaluations. No partial evaluation gets a sequence or
comparison credit; no queue wait, retry, I/O, re-score or producer re-query.
Reserve inability, capture/encoding limit, sequence exhaustion or malformed
identity invalidates the whole observation owner. Go proceeds with its result.
All leases return on invalidation, failed publish, writer failure and shutdown.

Rust validates the full Evaluation into staged private state, independently
computes and compares it, then advances that owner's compared prefix. A wrong
witness leaves the previous compared sequence and permanently invalidates the
owner. Bounded capture records do not authorize unbounded retained query state:
add a separate64MiB total diagnostic retained-query/history budget across owners,
including cached Health results and staged evaluation data, with no silent
history eviction. Existing owner/account/session limits remain in force.

## 5. Shared independent computation and order proof

Refactor existing Rust factor computation into pure phases shared by the staged
router and shadow: update a factor from its supplied read window; compose rows;
validate/resolve equal-vector ordering; walk actual entrypoint-specific advice;
compute candidates/pair/ticket result. Normal production-facing APIs preserve
their current behavior. Before any production caller migration, keep its
existing evaluate(now) entrypoint and add a direct equivalence test: the same
inputs/query values and one time repeated into the ordered read tape must yield
the same report and next factor history. Keep cache ownership identity private and independent
of production registration/command capabilities; shadow does not construct a
Router, Candidate, CommandQueue, production reservation or ResourceIncarnation.

Compute per-account factor vectors, packed scores and routeability first.
Only then inspect the proposed Go sort witness: exact input permutation, no
missing/duplicate/foreign accounts, monotonically increasing scores, and only
within-equal-full-vector reordering. Reject non-equal swaps. Use this validated
order for the same advice calls/traversal; do not rescore after adopting it.
Entrypoint early exits and negative/inverted advice stops remain observable.

Share the pure ticket mapping already used by reserve_with_ticket; never call
that reservation API from shadow. Idlest has no invented ticket. Random uses
seed%(10N+1)%N over its independently derived eligible order (first11,others10);
prefer-idle uses uniform tickets over its independently derived actual idxes
order. N=0/1 must preserve actual Go early-return/index behavior. Exhaust every
ticket in complete periods in deterministic real-Go tests. Live samples are
coverage/distribution diagnostics, not an IID significance claim.

Keep binary64 sample bits, tagged NaN/inf and exact discrete comparisons.
Use the existing factors/tests.rs numeric policy: migration pair rates compare
exactly or with abs(actual-Go)<=abs(Go)*1e-10; per-factor advice counts compare
exactly or with abs(actual-Go)<=max(abs(Go),1)*1e-10. Infinity signs/tags and NaN
categories compare explicitly. Factor segments, packed scores, candidates,
advice kinds, decisions, and scheduler quota/cooldown results stay exact.
Compute scheduling from Rust's independently derived rate; a discrete boundary
difference still fails even if the scalar rate is within tolerance. Never feed
the Go rate back to make that boundary pass or increase tolerance after failure.

## 6. Route and scheduler composition

Route observations include listener/group matching, backend exclusions/retries,
actual input membership and the selector/session binding already carried to
Finish. Compare chosen account/no-backend before pairing the actual reservation
transition. Do not change Go routing or call into Rust production selection.

Record each actual balance/close round and group order, capability checks, pair
keyspace guard, named balance and separately fresh close times, actual physical
scan order, force-closing/pending/cooldown skips, quota and last-accepted time,
admission booleans, and the existing lifecycle operation token. The shadow uses
its retained ledger/history plus shared pure scheduling arithmetic to compute
expected advice/eligible attempts; only observed actual admission results advance
its accepted watermark/accounting. No effect sender or rejected-admission refund.

Failover activation/removal/suppression and config changes are ordered inputs.
Retain first activation, timeout equality and retryable refused ForceClose.
RouteableBackends calls from failover protection also evolve factor history.
Close-after-result and result-after-close still settle via exact old identities.
Config/source rotation does not authorize resetting lifecycle or factor history.

## 7. Reviewable delivery and fixed acceptance

2B-1: actual read tape/provenance + native factor capture + shared independent
factor phases, with all three entrypoints and factor lifetimes. Advertise
factors=true only for the installed path; selection/scheduler remain false.
Require actual Go methods over real metadata/query objects, private UDS → the
exact in-process consumer, and concurrent publication interleaved between reads.

2B-2: group/selection/tickets + scheduler/failover comparison and complete v3
coverage. This completes2B but still does not complete real SQL slice3 or issue223.
If a source finding changes these boundaries or caps, publish a revision before
implementation or qualification; do not silently weaken the accepted contract.

Deterministic cases: all three factor entrypoints and their early exits; status,
health, memory, CPU history/expiry edges; missing/stale/empty/wrong-kind queries;
NaN/inf; query/source ABA and unregister-with-retained-result; Resource↔Location→Connection→Resource; equal-vector
and non-equal permutations; every ticket period; no-route/unique/tied pair;
quota/cooldown/failover equality, capability-disabled close, cross-keyspace and
actual accepted/refused/late terminal ordering. Use independent barriers to
force differing query generations between successive real reads.

Positive full2B integration gate frozen before execution: all9 combinations
of Connection/Resource/Location balance policy × idlest/random/prefer-idle routing.
Each combination runs disabled and enabled for60seconds,2owners×2groups×8clients,
200accepted lifecycle operations/s and concurrent backend/query/config changes.
Require12000 operations and1200 publications per window, nonzero all-required
entrypoint/decision/round coverage, zero Invalid/mismatch/loss, bounded leased
memory, and independently compared final metadata fences plus settled ledgers.
Controlled real Go APIs/consumer are used here; real SQL/etcd/collector acceptance
and its latency thresholds remain a separately frozen slice3.

Record enabled/disabled capture/lock/request-cycle p50/p95/p99, queue/lease and
retained-state high water. A95% confidence claim from wall-clock random samples
is forbidden. Initial CI estimate uses PR250 run34262292530 attempt2: actual
recorder job 18:18:58–18:25:52 UTC = 6m54s, including 2m of workload and 31 faults.
Replacing two windows by eighteen gives a 22m54s lower estimate before the added
factor faults/build work. Start with a separate45-minute full2B job; record the
measured deterministic/build/mutation overhead before qualification. If the
estimate or observed upper budget exceeds45m, split by balance-policy family
into two independent45-minute jobs (Connection vs Resource+Location), distributing
faults explicitly. Never shorten a60s window, reduce nine combinations, or drop
old checks to fit. The estimate is not a guarantee for cold or slower runners.

New compiling faults must kill: skipped Routeable history; merging distinct
clock reads into one; replacing a factor query with the final snapshot; dropping
producer identity while accepting comparison; swapping Health failure/total read
order; query/time item cap+1 accepted; post-hoc query/time reread; mismatched source generation from split atomic loads; publish after Group unlock; retained Health query replaced by latest;
CPU/memory series reduced to final sample; Go score/cache backfill; non-equal tie
swap/duplicate ID; wrong advice stop; altered11:10/uniform ticket law; reused
factor token; uncharged in-flight arena/writer; partial evaluation qualification;
missing fresh close time; refused admission advances quota; failover activation
reset; and a shadow effect capability (API/dependency isolation). Preserve old
v1 24/v2 31 mutation baselines, original CP gates, full Go lint/touched -race and
Rust lint/test/build. All Ready/merge evidence binds to one reviewed exact SHA.

## Freeze record

Peer0c4384f7 accepted the actual clock/source model, mixed atomic lease, shared
pure computation, numerical boundaries and staged delivery with the conditions
now incorporated. All five conditions are normative, including the same-Group-lock
publish mutation and the CI budget measurement/split fallback. Peer pre-review
2c6c28b4's ordered-reader, compatibility, output-only and four specific faults
remain incorporated. No further design approval is pending; proceed with2B-1,
then submit a Draft and exact-head validation capsule for independent review.

## Exhaustion clarification (peer4a47098b, adopted9f6b8f4f)

Diagnostic counter exhaustion must directly and permanently invalidate every
observation owner bound to that source in Go, like NextIdentity exhaustion in2A.
Do not publish an exhausted read item and defer the decision to Rust. No later
read item from that invalid source may be admitted. Any Go-local failure marker
is internal metadata and must not be serialized as a v3 read.

Every identity field present in v3 (producer, query, publication, named clock)
rejects zero at schema decoding. Missing/empty results use explicit result kinds;
an absent publication is represented by the corresponding structural variant,
not a fabricated zero publication ID. The compiling fault that replaces immediate
Go owner invalidation with zero identity and continued publication must fail.

## Time representation clarification (9789981d, c2679eb6, 2caac6b6)

Every v3 time value has an explicit arithmetic domain. Go time.Time carries
internal year-1 wall seconds, nanoseconds, owner-local Location pointer-identity
token, monotonic presence and relative nanoseconds. Raw cache equality includes
the Location token, even for different pointers with the same name/offset.
Prometheus model.Time retains signed millisecond ticks; subtraction and subsequent
multiplication by1ms both wrap. They must not use Go time.Time saturating Sub.

A process/nonce startup origin carries `origin_baseline_present`, its raw Go
monotonic baseline and the Go toolchain version. Only the audited Go1.25.12
representation is accepted. Before formatting either of two startup-captured
values, bound its zone name to512 bytes. Strictly parse the monotonic suffix and
verify that the exact raw difference equals the second value's Sub(origin).
Reject unknown formatting, overflow, toolchains or self-check mismatch for the
whole observation process. The extra clock sample is startup-only.

Retain128 distinct Location pointers per owner in a fixed array (2KiB of entries
on64-bit Go,256KiB across128 owners); never evict/reuse identities. Boundary128
is allowed;129 invalidates observation without changing Go routing. Projecting
a monotonic time against a wall-only origin, or a saturated Sub(origin), also
invalidates observation. The v3 consumer rejects a needed but absent baseline,
raw-ext reconstruction overflow, zero Location token or invalid packed-wall data.

Rust GoTime Add reproduces wall normalization, packed-wall range stripping,
Go's signed-second overflow clamps and monotonic-overflow stripping. Domain
mutations independently change sample wrapping to saturation and Go saturation
to wrapping. Other mutations normalize Location names, bypass startup validation,
format/resample on the hot path, retain monotonic data after overflow, or accept
an unrepresentable baseline reconstruction. Health all-empty/zero-time expiry,
N<=1/Empty early exits and three Since callsite read order remain native-capture
acceptance obligations; these pure prerequisites do not qualify those paths.
