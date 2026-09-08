# CP-ROUTE 222-3 slice 2: actual capture and Rust observation consumer

Frozen implementation boundary v1.1, September 8, 2026.
Peer47148b1d accepted the boundary and specified these four revisions;
author adopted them in c2b1b3b2. This text incorporates all four.
Owner: CodexM5, Raft task81 / #workflow:a5314eb7.
Base: main1a8400cbcca93c5bcde97e4d9467f336e661ab72, treea1c1014e.
Parent contract: committed shadow/contract.md v1.2. PR246 is merged;
this document does not claim that the live observer already exists.

## Delivery boundary

Implement the second contract slice in two reviewable PRs: 2A actual lifecycle
capture plus transport/composition; 2B actual factor/read-window capture and
independent route/scheduler comparison. Both are needed before slice3 sustained
full-routing acceptance. 2A must continue reporting lifecycle_only=true and
explicitly mark factors, selection and scheduler advice as uncovered. Merely
moving the fixture onto a socket will not qualify as actual capture.

2A includes production-call-site observation under a default-disabled startup
flag, bounded journal admission, typed Go witnesses, a local Unix side channel,
and one owned consumer task inside the existing tiproxy-rs process. It adds no
production control-protocol message, Rust routing authority or second service.

## Source-audited placement and identity

- Server currently builds namespaces BEFORE startRustDataplane. Build the
  observer service and install its fixed namespace factory before namespace
  Init; bind transport before construction but do not wait for a peer. The
  startup queue retains Begin and initial events until the first Rust consumer
  connects. Failures never retroactively seed from current router state.
- Namespace build creates the observer owner before policy Init, SetConfig or
  health application. Both initial and future namespaces use this factory.
  A router constructed through an unobserved/test path stays Disabled; there is
  no setter that attaches to an already initialized production router.
- The process incarnation and startup nonce are nonzero random identifiers;
  owner IDs monotonically increase in the process, bounded and never reused.
  Namespace/address strings are bounded explanatory values, not registry keys.
- Retained group, backend-account and connection wrapper observation IDs belong
  to that owner. Use wrapper incarnation, not address, ConnectionID reuse or a
  reconstructed snapshot. Group/account removals retain their observer history.
- A selector exists before it has a connection object. Carry an observer-only
  selection/session token and attempt number through its Route/Finish closure;
  bind it to the actual connWrapper on successful creation. Instrument explicit
  selection termination in both Go backend creation and controlbridge pending
  state cleanup. Every actual Finish(conn,false) maps ONLY to Created(false),
  reflecting Go's reserved-score rollback. Never map abandonment to Closed:
  the existing mirror Closed would incorrectly refund a pending reservation.
  If a selector is discarded without Finish, mark the entire owner Invalid
  (UnpairedDiscard), preserving the exact Go path and its unrefunded count.
  A later real Finish(false) changes only Go accounting and cannot restore
  comparison qualification. No diagnostic termination may refund the mirror.
  This outcome fails the positive 60-second gate; the independent discard test
  and compiling mutation must reject silent or session-only invalidation. Audit all cleanup paths before adding
  hooks, and prefer existing actual Finish calls over synthetic events.
- Namespace CommitNamespaces currently replaces/deletes entries without closing
  old routers. Record disappearance as Invalid for the old observer owner and
  retain it; do not close production objects or report a clean retirement. The
  replacement namespace independently starts a fresh owner. After Invalid,
  retain only known ledger/queued tail/Invalid summaries, without new witness
  copying or a final-settlement claim. Late Retire/End also cannot clear Invalid. Normal Router.Close
  may record Retire; End additionally requires a fully settled retained tail.
  Any later actual operation after End invalidates that interval.

## Actual capture and witnesses

All capture is an internal fixed implementation, not an arbitrary callback.
Router/group/fbb locks retain their current production order. Attach IDs and
record events in the same critical section as the actual transition; drain and
transport never take those locks. No observer may rerun selection, query metrics,
read an alternative clock or write connScore/connList/phase/forceClosing.

| Real boundary | Captured lifecycle and witness |
| --- | --- |
| Factory / group creation / AddBackend / removeBackendIfIdle | Begin; distinct group/account identity; actual creation/removal, including same-address recreation. |
| Route / selector retry / Finish / abandon | Open/Reserve, accepted attempt identity and selected account; actual Finish(false) is Created(false). Unpaired discard is a diagnostic fact with no synthetic refund/Closed. Preserve score increment before Finish and rollback only when Go does it. |
| RehydrateConn | Fresh owner/session binding on the actual accepted rehydration; no selection or snapshot seeding. |
| redirectConn | Accepted or refused issuance, actual operation number/from/to; score movement on acceptance. Capture force-close and cross-keyspace refusal without introducing observer effects. |
| onRedirectFinished / OnConnClosed | Actual terminal identity, duplicate/closed no-op, physical arrival/movement and exact close/result ordering. |
| CloseTimedOutFailoverConnections | Actual ForceClose acceptance/refusal; closing marker without prematurely settling score or physical ownership. |
| Namespace removal / Router.Close | Explicit disappearance invalidation versus Retire; retained tail and truthful End. |

Witnesses are outputs, never Rust inputs. For every changed account capture Go's
actual ConnScore, connList.Len and physical head/tail IDs; capture the affected
connection's actual before/after physical and score owner, phase and closing
flag. Fixed-size mutation records name at most two affected accounts and the
actual arrival predecessor. This proves ordered transition effects without an
O(all sessions) list copy under the group lock. Rust first applies the event to
its own mirror, then compares these output witnesses. It does not replace its
counters or order from them. Compound changes publish as one bounded batch with fixed maxima: two account
witnesses, one predecessor ID and one connection before/after state. A consumer
cannot compare between halves of an actual atomic transition. Compare only
after applying the entire independent mirror transition. Witness disagreement
is a mismatch; never backfill from a witness.

Administrative/test RedirectConnections is captured as a distinct Reconnect
marker: its actual pending phase is retained even when Redirect refuses. It
changes no mirror accounting or pending_redirects and is not evidence for the
production balance path. Its actual terminal may move physical arrival order
within the same account. Ordinary v1 Redirect/Redirected semantics stay intact.

The first-slice Policy event is owner-wide whereas real policy/cache lifetimes
belong to groups. Do not use that event to pretend full per-group factor history
is captured. Add explicit group-scoped coverage/lifecycle metadata now; 2B adds
actual config/health/locality/metric/time reads, all three factor entrypoints
(including RouteableBackends), stateful history and independent factor/selection
comparison under the frozen equal-vector/ticket rules.

## Recorder and bounded loss

Use a bounded owner registry and per-owner producer serialization. A producer
checks one atomic Invalid flag BEFORE constructing a witness, then acquires
that owner's leaf Mutex. It rechecks validity and fixed field/collection bounds.
This is bounded internal serialization, not a capacity wait: its critical
section has no I/O, callback, producer read, queue wait or admission retry.
This explicitly amends the parent v1.2 phrase that producer contention itself
invalidates an epoch: ordinary same-owner group concurrency is serialized;
failed nonblocking queue/budget admission still invalidates.
Inside that leaf lock: reserve bounded aggregate record/byte budget, assign the
next sequence and attempt nonblocking buffered-channel admission. Advance the
stored sequence only for the admitted batch. No fetch_add sequence followed by
an independently ordered enqueue; no waiting for queue space, I/O or retry loop.
Capacity/oversize/sequence exhaustion invalidate the owner
atomically. Subsequent calls return before witness copying. No Go decision or
accounting value depends on the admission result.

The consumer drains the channel without taking a producer lock, preventing every
socket dequeue from contending with a hot path. The aggregate channel is bounded
at4096 records and64MiB charged retained bytes, with frame body <=1MiB. Count
queued and drain-owned pending data until released; no unbounded batch or
unaccounted writer backlog. Initially witnesses are fixed-size; compute a safe
encoded upper bound before admission and verify actual encoded size off locks.
Retained owner/account/session registries have explicit caps and tombstones.

An out-of-band atomic invalidation slot per bounded owner lets the drain publish
loss even if the data queue is full. It must preserve the last successful
sequence, invalidate already compared evidence, and never masquerade as a new
contiguous lifecycle event or a clean End. Dequeued older records cannot restore
qualification. Drain snapshots only recorder-owned values; it cannot call a
router or production endpoint. Any encoding/write failure invalidates the
transport interval and is diagnostic, never a SQL shutdown trigger.

Contention is a measured design condition: nonblocking failure alone is not
success. The positive concurrent gate below must retain useful complete capture.
If it cannot, revise admission architecture; do not silently reduce coverage or
relax the declared validity threshold after seeing the results.

## Framing, connection and shutdown

Keep the existing strict v1 corpus codec unchanged. Live transport uses a
separately versioned v2 envelope for lifecycle batch+witness, owner invalidation
and stream coverage. Every owner envelope retains process/owner/nonce. Ordinary
records retain contiguous sequence; invalidation explicitly carries last
admitted sequence and reason and cannot increment compared_sequence. Rust does
not accept legacy witness-free v1 frames as live compared evidence. Unknown
versions/kinds/fields, duplicate keys, malformed values and oversize are fatal
to that observation transport. All IDs remain canonical decimal u64 strings.

The temporary adapter owns a fresh absolute mode0600 socket in a private run
directory and validates same-UID peers on both ends, using existing platform
credential patterns. Rust option/config enables the consumer only explicitly.
A second observer never replaces the first. No control command or acknowledgment
comes back through this channel.

The first consumer can drain the retained pre-construction queue. After a real
consumer disconnects, all incomplete owners are invalidated and old queued data
cannot become a baseline for a replacement observer. A reconnect receives only
retained Invalid summaries for those owners; only naturally recreated owners
with newly observed Begin may compare. A Go restart changes process identity;
a surviving Rust consumer retains old invalid history and accepts the new
process's empty-owner Begin/actual rehydration. A Rust observer-only restart
cannot request or cause a production restart to manufacture qualification.

Owner watermarks and a fixed stale deadline qualify freshness, not unobserved
coverage. Consumer errors publish bounded diagnostic status and preserve the
Rust SQL runtime. Put its cancellation/join into the existing startup rollback
and normal shutdown owner; do not supervise an observation task as a mandatory
SQL-control child. Go shutdown stops acceptance, invalidates unfinished epochs,
closes listener/writer and joins both tasks, without manufacturing CleanEnded.

## Verification before a 2A PR can be Ready

1. Preserve v1 codec/domain/56 real-Go rows and24 compiling faults; strict v2
   Go/Rust golden frames and version/duplicate/unknown/oversize/truncation tests.
2. Drive real namespace factory and router APIs, including initial policy calls,
   later group creation/account removal/same-address recreation, selector retry
   and abandon, rehydrate, redirects/refusals, closing/refusals and both result
   orders. Remove manual event creation from the actual-capture gate. Rust
   recomputes counts/order and a changed Go witness must be rejected.
3. Real local sockets: start before owner, delayed first consumer, forced
   overflow, duplicate peer, slow reader, malformed frame, disconnect/reconnect,
   wrong nonce/sequence, same-owner restart refusal, new owner after reconnect,
   queued old-owner/new-owner interleaving after same-name namespace replacement,
   watermark stall, shutdown and startup rollback. Go control routing/accounting
   continue and no observer task/FD remains after join.
4. Recorder tests prove Invalid-before-copy, atomic batch sequence/admission,
   independent count and byte budgets at equality/+1, no lock/I/O callback from
   drain, no growing invalid tombstones or writer backlog. Compile each injected
   fault first, require its named assertion, and restore the baseline.
5. Positive concurrent capture: two owners, two groups per owner, eight clients,
   200 accepted lifecycle operations/second total for60 seconds, plus concurrent
   backend publication. Require nonzero coverage of all exercised operations,
   zero gap/loss/Invalid/mismatch and exact drained totals. Capacity/slow-reader
   negative runs separately prove bounded invalidation and unaffected routing.
   This is a recorder integration gate, not the later real-TiDB load acceptance.
6. Record enabled/disabled retained bytes, queue high-water, capture latency and
   group lock hold p50/p95/p99 under identical work; enforce <=4096 records and
   <=64MiB charged backlog. Before full live slice3, separately freeze real SQL
   duration/coverage and latency thresholds for all three routing policies.
7. Full required Go lint and touched packages with -race; full Rust lint/test/build;
   old CP gates and a separate budgeted recorder/transport CI job. Frozen SHA,
   truthful scope capsule, independent review and all CI precede guarded merge.
