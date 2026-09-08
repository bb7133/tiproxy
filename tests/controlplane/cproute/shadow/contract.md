# CP-ROUTE 222-3: observation transport and comparison contract, v1.2

Status: v1.1 frozen by peer4e2be5c6 after1588b11a; v1.2 clarifies separate
owner and Resource/Location factor lifetimes (89ed9b1d, peer ACCEPTd1f7cbe2).
This is an accepted design, not an implemented shadow or cutover approval.
Author: CodexM5. Canonical task81 / #workflow:a5314eb7. Baseline: merged PR245,
main c410c57077da0eabdbd55dcce2ecc9db0106c5b7, tree
8a2f3db93262cb139b57f40270907c8dab122051. 222-1/2 supply the retained-account
ledger, actual factor evaluation and migration worker. Issue147 remains open;
222-3 supplies observation evidence and issue223 owns production activation.

## 1. Ownership and transport decision

Go remains the only production assignment, redirect and force-close owner. Add
an opt-in, read-only observation journal at the existing Go/Rust migration
boundary. Its consumer lives inside the existing tiproxy-rs process. A dedicated
ShadowState accepts immutable domain values and produces comparison records;
its constructor has no Router, MigrationSimulation, SessionEndpoint, command
sender, admission callback or source-publication capability. Reuse pure factor
and accounting operations through value-only views; do not run the normal
worker and discard commands. Production control messages continue unchanged.

Proposed transport: a separately named local Unix socket, owned and joined by
the existing bridge lifecycle, carrying Go-to-Rust diagnostic frames. This is
an explicit temporary observation channel, listed for deletion at cutover; it
is not a new ControlEnvelope variant or another Rust service. The Go server
currently starts a control listener, not a Rust child, so an inherited-FD-only
proposal would not fit the current process composition. Keep transport/codec
in the legacy adapter and tiproxy-rs composition. control-router and
control-routing must not acquire control-proto or transport dependencies.

Default is disabled. Explicit enablement configures both endpoints before
namespace/router creation. Use a fresh absolute socket path in the private run
directory, mode0600 and the existing same-UID peer validation pattern. One
consumer; no network listener, command request, production acknowledgment or
automatic fallback to effect mode. A disconnected observer cannot alter Go
routing, close sessions or request a source refresh.

Version1 framing: u32 big-endian length followed by a strict typed JSON
record. Every frame carries `(process incarnation, owner incarnation, nonce,
seq)`; the one socket may multiplex owners, but each owner has an independent
contiguous sequence and invalidation state. Bound each frame to1MiB and the in-memory queue to4096 records AND64MiB;
whichever limit is reached first wins. Bound field/collection construction too,
so an oversized record is rejected before an unbounded copy under a group lock.
Use decimal strings for u64 identities, scores, sequences and nanoseconds;
floating observations use an explicit finite/missing/NaN/+inf/-inf union so
invalid/missing metrics cannot accidentally become zero. Reject duplicate keys,
unknown schema versions, unknown event kinds and malformed values. Constants
are initial diagnostic limits, tested at equality and limit+1, not silent
truncation limits. No raw SQL, authentication bytes, TLS material, whole config
objects or arbitrary metric/log labels; use an allowlisted routing projection.

## 2. Capture must observe the real computation once

Lock order is router -> group -> fbb -> recorder, with only the subset required
by the existing operation taken. Recorder is a leaf lock: while held, acquire no
other lock, allocate no unbounded memory and perform no I/O. Drain/socket tasks
never acquire router/group/fbb locks. Once an epoch is Invalid, its recorder
entry checks that state with one atomic read and returns before any value copy;
invalid observation must not keep copying production state under these locks.

Source audit at the baseline:

- group.go Route selects and increments the score under the group lock;
  onCreateConn and terminal handlers settle under the group lock.
- router_score.go holds its lock across group selection/Route, configuration
  updates and all-group rebalance, but onCreate runs without that router lock;
  RehydrateConn explicitly releases it before taking group locks.
- factor_balance.go updateScore changes stateful factor caches. All three
  BackendToRoute, BackendsToBalance AND RouteableBackends call it. Failover
  protection can therefore update factor history even without a route or tick.
- RouteAssignment in control.proto carries an assignment, not factor vectors.
  ReconcileSnapshot lacks complete reservations, score/physical owners, factor
  histories, failover clocks and physical arrival order. Neither is a shadow
  baseline.

Instrument the actual accepted transition and every actual factor evaluation,
including routeable checks. Capture inputs and outputs from that same execution
while its existing serialization is held. Do not rescore to observe, re-query a
producer, reread a clock or invoke a user callback. A fixed internal recorder
only makes bounded value copies and attempts queue admission; encoding and I/O
run outside production locks. An evaluation's immutable input record is given
to Rust's independent factor implementation; Go's scores/advice/decision are
comparison outputs, never the Rust input oracle.

Required record families:

| Family | Required information and comparison boundary |
| --- | --- |
| Owner/group lifecycle | Go process incarnation, namespace/router incarnation, retained group/account identities, creation/removal/config application and source-mode lineage. Names/addresses are values, not identities. |
| Actual reads | Used config/topology/health fields, locality provenance, missing/stale/empty metric distinctions, each used metric result's producer/query lineage and allowlisted samples, and named clock-read values. Preserve the actual read order of stateful evaluations. |
| Factor evaluation | Operation kind and input account order; factor order/bit widths; Go factor vectors and total scores; post-sort tie order; advice/rate/reason; Rust independently recomputes them from its own history. Include evaluations returning no candidate. |
| Route attempt | Listener/group selection inputs, exclusions/retry cycle, eligible candidates, policy weights/ticket, no-backend or chosen retained account, reservation identity and accepted score delta. |
| Connection lifecycle | Reservation acceptance/rejection, create success/failure, rehydrate, redirect admission/rejection and terminal, force-close admission/rejection and observed close; exact session/operation identities, before/after physical and score membership, physical arrival order. |
| Scheduler/failover | Actual round/group ordering, time reads including fresh close time, last accepted watermark, quota/cooldown, first activation/removal/suppression, pair refusal and issuance backstop. |
| Coverage/termination | Enumerated captured operation counts, sequence range, queue loss/oversize status, explicit clean end and final account totals. Periodic watermark for freshness; it is not evidence that an unobserved path ran. |

Give every source evaluation a retained owner identity and a bounded explicit
read projection. Preserve empty-source fallback as data. A second Rust producer
may be audited separately, but its independently timed latest snapshot cannot
silently replace the Go read window in a deterministic differential comparison.
Runtime source-fence evidence from220/221/222 remains mandatory. The codec must
not turn observed Go identity strings into production Rust authority handles.

Sequence allocation and queue insertion are one serialized recorder operation;
fetch_add followed by a separate concurrent enqueue is forbidden. No socket
write, waiting for consumer capacity or retry loop occurs under a group lock.
If bounded admission cannot complete (capacity, size, sequence exhaustion or
recorder contention), atomically invalidate the observation epoch and return
without changing production state. The drain owns no router/group lock and
never calls back. Implementation must demonstrate useful sustained capture
under concurrent load; frequent invalidation is a failed shadow run, not a
passing availability result.

## 3. Baseline, gaps and restarts

Version1 deliberately requires observation to start BEFORE the authoritative
owner's first policy initialization or accounting mutation. BeginOwner declares
an empty ledger and initial immutable settings; initial configuration, backend
publication, factor calls and later rehydration are observed normally. Attach
through the namespace/router factory, including later namespace creation.
BeginOwner precedes SetConfig and the first OnBackendStatusChange, both of which
can update factor history through failover routeable checks. Groups created
later inside a router are events in that owner epoch, not new epochs.
A connection existing in the Rust data plane after a Go restart enters this
new empty Go lineage through its actual observed rehydration. It is not seeded
from a ReconcileSnapshot copied into shadow accounting. A Go crash/disappearance
invalidates the old epoch because its tail cannot be verified; a new process
incarnation begins a new epoch. Keep both the invalid old and observed new
intervals in the report.

No live-state snapshot is claimed by taking the router lock. Late attachment,
missing construction history or observer restart while Go retains the same
owner is UnsupportedBaseline/Invalid, never a green partially initialized
mirror. Resumption requires an explicit fresh authoritative owner incarnation
whose history is captured from its empty start. Do not restart production just
to repair a diagnostic observer. Until a separately reviewed atomic checkpoint
protocol exists, that owner remains unqualified. Natural namespace/process
recreation can establish a new epoch; the earlier invalid interval remains in
the report. A failed epoch cannot be overwritten by a new passing epoch.

Epoch identity is `(Go process incarnation, namespace/router owner incarnation,
observation start nonce)`. The domain mirror creates a fresh local owner token
in a ShadowState-owned registry for that explicit BeginOwner mapping. This is
separate from the factor lifetime represented by control-config's
ResourceIncarnation. Shadow records have their own private resource-factor
lifetime token: initial enable creates it, Resource <-> Location preserves it,
Connection disables/revokes it, and re-enabling creates a new token even after
coalesced notifications. Owner and factor tokens are never registered in
production ConfigNamespaceStore, BackendSource or other production handles;
the production ResourceIncarnation constructor is not opened for shadow use.
Neither equal names nor a replayed serialized ID can reattach to a retired owner. Config,
backend source and metrics producer rotations within the owner are ordered
observations with their own retained identities, not excuses to reset its
ledger or epoch. Source/config revocation invalidates new candidate authority;
already accepted operations still settle against captured old owners. A real
namespace/router retirement prohibits new admissions but keeps its observed
retained-session tail until closure/rehydration ownership is explicitly
accounted. Do not declare CleanEnded while that tail can still mutate. New
namespace creation gets a distinct BeginOwner and mirror incarnation. An
unexpected owner disappearance or unmatched transfer invalidates the old
epoch; it cannot borrow the new owner's baseline or clear its mismatch history.

Within an owner epoch, checked contiguous sequence order is mandatory. A gap,
duplicate/reordered journal frame, overflow, cross-incarnation reference,
unknown identity or truncated/disconnected stream invalidates comparison. Do
not reset counts from the next event, reorder an unbounded buffer or turn a
missing event into a no-op. An authoritative Go duplicate terminal is different:
it is a new contiguous journal record and must compare as the real lifecycle
no-op. A missing data-plane result is also legitimate input: pending ownership
must remain pending until Go observes a valid settlement or close.

State is Disabled, AwaitingBegin, Comparing, Invalid or CleanEnded. Only a
contiguous bounded run with explicit coverage and end/watermarks can qualify an
interval; Invalid is sticky per epoch. Publish reason, last compared sequence,
source lineage and bounded mismatch context. A stalled stream becomes stale
and unqualified even before EOF. All worker/drain/socket tasks are cancellable
and awaited before their owner is destroyed; their errors cannot close SQL
connections. Cancellation never manufactures a CleanEnded record.

## 4. Ties and weighted selection

Do not compare unrelated wall-clock samples or map iteration orders as if they
were deterministic decisions. Do not normalize away a real factor difference.

1. Compare factor order, per-factor scores, total packed score and routeability
   exactly by retained account. Distinct total scores preserve strict order.
   When totals match, require equality of the full vector before treating them
   as an unspecified-order class; inconsistent packing is a mismatch.
2. Record Go's actual input order and post-sort order as read-only execution
   witnesses. Rust independently recomputes scores and its sorted score classes
   BEFORE inspecting the proposed post-sort order, then verifies that the witness
   is a permutation of exactly the same accounts in nondecreasing score order,
   then uses only the validated within-equal-vector permutation when replaying
   candidate traversal/stateful BalanceCount calls. This aligns unspecified
   ties without choosing a backend by address, ephemeral port or lowest ID.
   The witness cannot supply advice, eligibility, weights, rates or a decision.
   A bad permutation is a mismatch; there is no fallback address/port/ID sort.
3. Unique idlest choices and unique migration pairs compare exact identities.
   With ties, compare the admissible equivalence class AND replay the actual
   validated traversal: target routeability, positive source physical/score
   counts, factor priority, negative advice/inverted stop, strict0.0001 cutoff,
   keyspace guards and rate/reason must still match. Class membership alone
   cannot hide an incorrect scan or factor-cache update.
4. Random routing with N eligible entries uses weights11 for the first eligible
   sorted entry and10 for every other entry, denominator10N+1; the actual Go
   formula is seed%(10N+1)%N. Preserve which member got the extra ticket as a
   validated ordering witness. Do not average it across ties and weaken the
   per-decision contract. Prefer-idle independently calculates the eligible set
   and uses uniform tickets over its actual idxes traversal. N=0/1 behavior is
   checked separately, without inventing a sampled ticket.
5. Record the exact Go clock-derived ticket read and compare Rust's policy
   mapping for that ticket after independently computing candidates/weights.
   Share the pure ticket-mapping path used by reserve_with_ticket; do not call
   Router::reserve_with_ticket or mint a production reservation from shadow.
   This tests the same decision input, not a separate random draw. Also exhaust
   the complete ticket period in deterministic real-Go differential rows to
   prove the11:10 and uniform laws. Live wall-clock samples are not assumed
   statistically uniform; report live candidate/ticket coverage and distribution
   diagnostics without claiming an IID significance test. Different clocks in
   production scheduling do not authorize routing-weight changes at cutover.

Any normalization is limited to these unspecified orders. A difference in
namespace/group choice, source identity, factor history, filter, count, quota,
clock boundary, admission or lifecycle settlement remains a mismatch.

## 5. Delivery and acceptance

First implementation slice: bounded typed journal/decoder, start-empty epoch
state machine and value-only mirror; deterministic Go/Rust records and faults.
Second: actual Go factory/group/factor/adapter observation and same-process
Rust consumer, default disabled. Third: sustained owned live differential and
fault evidence. These are reviewable slices, not independent production owners;
a replay fixture alone does not complete222-3. Freeze this contract before code.

Owned live acceptance must use real Go controlbridge routing and real Rust
SQL sessions, actual topology/health/collector and namespace/config/source
rotations. Exercise source ABA, retained backend removal, group changes,
concurrent creates/rehydration, rejected/full admission, pending redirects,
both close/result orders, dropped/duplicate data-plane results and independent
observation loss/duplicate/reorder/oversize. Restart Go with existing data-plane
sessions to prove captured rehydration; restart only the observer to prove the
same-owner epoch stays invalid. Prove cancellation/join, bounded memory and that
Go SQL decisions/accounting continue when the observer stalls or dies.

The capsule must distinguish valid compared operations, unexercised paths and
invalid/stale intervals. Cover every record family and all three routing
policies in a declared sustained load interval; zero mismatches with zero
coverage is not a pass. Include quantitative queue/memory and latency results
against disabled observation, including group-lock hold-time and request-latency
   distributions. Review the workload/duration/coverage thresholds
before the final live gate; do not invent them after observing results.

Required mutations include trusting Go scores as Rust input, skipping
RouteableBackends history, rereading metrics/time, permitting a non-equal tie
permutation, altering11:10 weights, accepting late attach, resetting on a gap,
duplicate settlement, foreign-owner aliasing, marking pending close settled,
blocking Go on a full observation queue, and giving ShadowState an effect
capability (dependency/API isolation check). Also reject replayed BeginOwner
serialized IDs as continuation, copying after Invalid, and a drain taking a
group lock, and reusing a retired shadow factor token on Connection -> Resource
re-entry inside the same observation epoch. Each fault must compile and fail
its named semantic row; retain a restored baseline and all old CP gates.

## Accepted peer decisions (1588b11a)

A. Accepted the explicit temporary local sideband at the legacy boundary, no
   ControlEnvelope growth, with a value-only consumer in the existing Rust
   process and strict bounded-loss invalidation.
B. Accepted start-empty-only epochs forv1, including real rehydration after Go
   restart and fail-loud unsupported late attach/observer-only restart. A live
   atomic checkpoint is future work, not an inferred feature of Reconcile.
C. Accepted validated within-equal-vector order/ticket witnesses plus independent
   scoring, advice, eligibility, weights and lifecycle comparison. This replaces
   comparing independent clock samples while preserving the actual Go laws.
