# Router API differential recorder

Test-build recorder for the frozen API-only contract at `a9c497c3`
([contract](../contract.md), [recording plan](recording-plan.tsv)). CodexM5
owns implementation and recording following the September 12 takeover. This
implementation is incomplete; recording an archive does not qualify a corpus slot.
The four frozen acceptance/inventory files are unchanged.

## Implemented boundary

`record.py` generates exact-text overlays from the current source tree. The proxy's
public `GetBackendSelector`, `Next` and `Finish` calls pass through `apireplay`;
router and factor clock reads use the declared logical timer schedule. Missing or duplicated
anchors abort the build. Every Go/Git subprocess receives the same canonical `PWD`
used by the overlay keys, so a logical symlink cannot change source lookup. A generated
backend init marker attests that Go applied the overlay; `record.py` executes the built
binary's marker check and refuses an uninstrumented build. Production files are never
edited by the overlay.

The optional `config.clock_origin_nanos` is the Unix-nanosecond origin of the
recording scheduler. Real captures always include it; replay adds each event's
`at_nanos` to that origin. Older traces without the field retain their original
1700000000-second epoch. The single shared Go test clock covers router/group and
CPU/memory/health/status-factor reads in both recording and replay. Rust's per-router
test clock and migration round use that same public event time; production clocks
and random selection tickets continue to use their existing clock sources. Original
wall timings remain in each raw archive record. The 24-hour offset bound and the
origin range are checked before invoking either engine.

The recorder now publishes whole external metric query sets through
`harness.MetricsInputs`. It forwards factor query registration to the real cluster
reader, samples all six public queries (`cpu`, `memory`, `failure_pd`, `total_pd`,
`failure_tikv`, `total_tikv`) at the declared default five-second metrics cadence,
then installs the copied set and records its `metrics` event under the scheduler.
Factor getters see only that publication; they neither poll nor append records.
Unchanged sets are not repeated, and a later all-null set explicitly clears input
data. An unsupported source result rejects the entire replacement and marks the
capture incomplete while retaining the previous publication.

Each `queries` object contains all six keys, with null for an unavailable result.
A result preserves vector/matrix shape, series and sample order, every label,
`updated_nanos` and each original `timestamp_ms`. Sample `value` is a round-trip
decimal string, including `NaN`, `+Inf`, `-Inf` and negative zero. A null update time
preserves Go's zero time separately from Unix epoch zero. No private provenance,
factor cache, score or query-getter sequence is serialized.

Both API replay adapters now consume whole publications. Go uses the shared
`metrics/` value decoder and swaps the complete result map before the next public
call. Rust's test-only input owns a real bound collector lifetime, pairs with the
actual routing/discovery/mode/config/owner capabilities, and publishes an immutable
merged result through the metric snapshot path. No network collector runs during
replay. The query packet is already merged: it is not split/re-merged, relabeled or
retimestamped. One merged input history preserves its cache lineage across data
and health updates; an accepted Resource → Connection → Resource transition starts
a new lineage, and replacement/Drop revoke old snapshots.

The raw packet and both replay adapters preserve Go zero time as
`updated_nanos: null`, distinct from Unix epoch `0`. Native factor history starts
at the same zero key and uses strict expiry comparisons without narrowing that
zero time into an i64 timestamp. The synthetic 170-event metric-time case covers
CPU, memory and both health indicators, same-update cache retention, one-nanosecond
updates, and the exact 60/120-second boundaries followed by one nanosecond.
Raw capture manifests are always unqualified and explicitly pending derivation;
they do not guess policy dependencies. The independent deriver is the sole source
of `requires`: a recorded history that claims metric observations but contains no
whole-publication event keeps `metrics-input`, while any recorded publication is
replayed by both adapters and supplies that input. The writer also marks the
otherwise impossible observed-without-publication state incomplete. The same
170-event input is now independently derived from each engine's public rows with
no residual policy dependency. A separate
bounded two-backend case also derives Resource redirect cadence, stable health
refresh scoring and same-update retention from the same public packets and
connection history. General multi-group and ambiguous Resource
effect/cadence qualification remains incomplete and separately blocked.

CI pairs the synthetic real-router producer's 17 events/three publications and
checks its input-defined A, A, B selection sequence in both engines. This small
scenario is adapter evidence, not general resource parity or a qualifying trace.
The raw archive, input-derived expectations, stored Go result, paired engine
outputs and this scenario assertion are preserved together.

Every whole health/config input, timer iteration, public call and terminal callback
executes with its record under one scheduler lock. Calls retain their public return
values and errors. No private router state, getter tape or closure interception is
used to reconstruct decisions. Real `BackendSelector.Next` owns its internal retry
and exclusion reset; only its final public return is recorded.

An established connection ends at its real `OnConnClosed` callback. An unsuccessful
selector ends when the proxy returns from that selector's scope: the overlaid deferred
`EndSelection` preserves `CloseObservation` and emits a terminal session event. It
never invents `Finish(false)` or closes an established connection. A still-pending
reservation or missing terminal event makes the recording incomplete.

The connection wrapper gives each public effect a monotonically increasing operation
ID. A terminal redirect callback binds to the accepted redirect's stored ID and
endpoints, even if force-close issued another operation meanwhile. A successful first
callback updates the public assignment; duplicates and callbacks after close do not
resurrect a session. An unmatched callback is preserved as a recorder error.

The harness composes a real proxy, factor policy, PD-backed observer and cluster
manager. Scripted actions support environment commands, an explicit `await_env`
barrier, config changes, fetcher-boundary source-error windows, checkpoints, a
global one-shot refusal, and one delayed real redirect callback followed by a
scripted client close. Failover scripts use `failover_select` to take a public
checkpoint, choose one backend currently assigned to a held client, arm an optional
global `refuse` or per-connection `delay` control, and apply a positive-timeout drain
inside the same serialized boundary. The global refusal is consumed by the next
effect request regardless of its session. `failover_repeat` reapplies the exact
target/timeout, while
`failover_clear` exits it. This avoids hard-coding a randomly assigned held
session or allowing an ordinary tick to consume a one-shot control first.
Environment commands in one batch may run concurrently, but every
batch must end with `await_env`; a script that overlaps a later phase or ends with
an unjoined command is rejected before capture. Unconsumed refusal/delay controls
and an unsettled delayed callback make the attempt incomplete. A fault wraps the
real `BackendFetcher`; the real observer then publishes the error. Stopping PD alone
is not guaranteed to publish an error because the production fetcher retries.

`-listen` accepts the same comma-separated address list as the real proxy and the
workload covers listeners and optional source addresses as a product. The regular
client count must cover every listener/source combination or the attempt is rejected
before capture. The clients still drive complete connect/query/close lifecycles. `-held-clients` adds
supplemental long-lived query sessions for real redirect/force-close callbacks;
their public client addresses identify their API sessions during finalization, so
their query counts are reported separately and they never inflate the completed-
lifecycle qualification count.

Source-error scripts accept only `cancelled`, `deadline_exceeded`,
`topology_unavailable`, or the empty string to clear a fault. Invalid names, unknown
JSON fields, unsupported actions and negative offsets are rejected before opening
an attempt or starting services. Only the declared topology sentinel (including a
wrapped sentinel) has that identity. Other external failures remain
`unclassified_source_error` in the raw and normalized evidence and make the capture
incomplete; error payload text is never archived as a substitute identity.

The API CI job also exercises the actual observer subscription, input forwarder,
router and recorder with a fixed synthetic inventory: initial empty routing, all
three fault windows and recovery after each. It checks the writer's stored Go rows
with the common comparator and replays the resulting 36-event trace through both
engines. The raw archive, derived inputs and paired outputs share the existing CI
artifact. Its provenance is explicitly `synthetic`; it does not count toward N/K or
replace live PD/TiDB/Prometheus recordings.

## Archive lifecycle

Each attempt has a new directory; archive and output files are created exclusively.
The completed workload joins its clients. Finalization then cancels and joins tick,
action, environment-command and health-forwarding producers, closes the real SQL
server and waits for its connection callbacks, checks all open/pending/active
sessions, and records the final checkpoint. Only then is the raw archive synced and
closed and its immutable snapshot converted and hashed. Archive write/sync/close
errors and unsettled sessions make the capture incomplete.

Files are `archive.jsonl`, `trace.json` (inputs without expectations), `go.json`,
`manifest.json`, `environment-manifest.json`, `proxy.toml`, and the exact
`actions.json` when supplied. Before it opens an attempt or starts live services,
the recorder requires a JSON environment snapshot with the host identity, TiDB/PD/
TiKV/Prometheus component versions and artifact hashes, binary identities, and live
endpoints. It copies the exact source bytes exclusively into the attempt and binds
their SHA-256 to both the capture summary and top-level manifest. The manifest also
records source head/tree/dirty status, workload duration, completed and failed
connection counts, script hash, event count and all three data hashes. `record.py`
embeds the build source identity; a dirty or unidentified build is incomplete.
The `completed_connections` qualification count is reconstructed only from distinct
recorded `open` → successful `finish` → `close` lifecycles. Independent workload query
counters remain separately reported; if the recorder sees fewer complete API lifecycles
than successful queries, the capture is incomplete. This catches missing or partially
applied call-site instrumentation even after the build attestation.
`qualified` is always false here: derivation, common schema validation, same-tree
paired replay and the frozen corpus gates remain separate requirements.

Original failed attempts are retained. N01-a1 panicked before output finalization;
N01-a2 left 87 selectors open and fails the common validator's empty-final-checkpoint
gate. Its original `recorded` manifest must not be interpreted as qualification.

## Expectation derivation and remaining dependencies

`derive_expectations.py` derives public legal sets and error classes from inputs and
history, validates recorded Go choices against Go's own exclusion history, and
refuses unexplained results. Next, Lookup and Rehydrate have distinct rules. Config
uses a full TOML parser; unknown routing-affecting fields are refused. Retention
includes pending reservations and accepted redirects. Health recovery clears prior
retention ambiguity. `exclude_history` supplies the full pre-exclusion candidate
set: each engine subtracts its own complete selector cycle and resets only on exact
exhaustion/no-backend. A reset in Go does not erase the other engine's history.
Location preference is evaluated on the remaining candidates using `prefer_local`,
which contains only locality verdicts from the public health input. These expectation
fields are removed from both replay inputs. Failover marking and its all-members guard are per group;
force-close due time and acceptance come from inputs, logical time and public history.

ClientCIDR and ProxyCIDR derive matching from the respective public address and
the `cidr` labels. Members keep their existing group across label changes; the
group's union refreshes after each complete health input. Invalid refreshes retain
the last parsed networks, while an invalid new group cannot route. IPv4-mapped
addresses and Go's default `/32` for bare labels are preserved. New admissions
whose grouping depends on backend iteration order, a route matching multiple
groups, simultaneous group removal/admission, and ambiguous retained membership
are refused explicitly. No recorded group choice resolves those cases.

Two synthetic 105-event cases exercise the actual adapters with opposite client
and proxy addresses, match/no-match, retained membership, valid/invalid/empty label
updates, IPv6, mapped IPv4, ungrouped Lookup/Rehydrate, and the per-group failover
guard. CI also derives their expectations from inputs plus recorded Go public
history, checks them against the hand-written scenarios, and validates both
engines again. These are adapter/deriver checks, not qualifying recordings.

The first paired CIDR run after the Go address fix exposed two Rust differences:
rejection of a valid routing-rule write and restoration onto an ungrouped backend.
The config store now accepts routing-rule updates for future routers; each existing
router keeps its construction rule, including when all of its groups are later
removed and recreated. Other restart-required fields retain their existing checks.
Rehydrate requires a known group before reserving or activating a connection;
Lookup still exposes known ungrouped metadata. The original scenarios and failure
artifacts are retained unchanged.

The following dependencies withhold a slot from acceptance:

- `effects-v2`: an unsupported history still cannot express every engine's legal
  effect set. Bounded Connection and connection-equivalent histories instead emit
  an input-derived relative cadence descriptor; the runner resolves owners and
  operations from each engine's own public assignment ledger. Non-migrating
  failover closes use the same public-history predicate.
- `policy-constraint:<policy>/prefer-idle`: not all factor advice can yet be derived
  from the available public inputs. An unrestricted candidate set is not qualification.
- `metrics-input`: an older recorded history claims that metric data was observed
  but provides no whole-publication event before the policy needs it. New captures
  set `metrics_observed` only after recording actual nonempty data and fail closed
  if that state lacks a publication. Both paired adapters consume every recorded
  publication; only the independent history deriver may add or clear this gate.
- `migration-cadence`: required by contract §4 for unsupported histories and derived
  from input capability and session/destination history even if every observed
  redirect is deleted. Whole-health support-redirection AND semantics disable the
  balance pass; independent failover closes still run. Destinations must have
  exactly the source's current public keyspace, including empty == empty for legacy
  inputs. When every possible pair crosses keyspaces, migration is impossible.
  Whole health updates replace keyspaces; missing retained sources keep their last
  delivered value. Bounded Connection histories now describe every current group,
  member health/keyspace and input-derived Status scoring call without choosing an
  owner. The runner applies Connection/Status priority, ratio/rate, physical FIFO,
  slow/fast cadence, cooldown, keyspace and one-shot refusal independently to each
  engine's ledger. Resource/Location histories use this same relative model only
  when all higher-priority public factors are proven neutral. The existing bounded
  Resource model may also derive an exact pair from complete metric packets.
  Ambiguous group lifetimes, unmodeled factor advice and histories whose legal
  alternatives exceed the bounded model retain this dependency.

Additional planned work includes timer boundary expansion and
router Close/recreate/rehydrate for the config/source family. The
presence of a row in `recording-plan.tsv` does not mean its driver is implemented.
Captures with unresolved dependencies remain raw evidence and do not count toward
the 18 slots, three rounds or focused acceptance groups.

## Commands

Run from the repository root, with build/output directories outside the source tree:

```sh
python3 tests/controlplane/cproute/api-differential/recorder/record.py build --out /tmp/api-record-build
/tmp/api-record-build/record -slot N01 -attempt a3 -duration 150s -clients 8 \
  -out /path/to/new-recordings -script /path/to/actions.json -env /path/to/env.sh \
  -environment-manifest /path/to/environment-manifest.json
python3 tests/controlplane/cproute/api-differential/recorder/derive_expectations.py \
  /path/to/new-recordings/N01-a3/trace.json /path/to/new-recordings/N01-a3/go.json \
  --output /path/to/new-recordings/N01-a3/derived.json
go test -race -tags apireplay ./tests/controlplane/cproute/api-differential/recorder/...
```

Failover attempts additionally pass `-held-clients`. The checked-in F01--F06
scripts use the following atomic action shapes; every nonempty drain has a
strictly positive timeout:

```json
[
  {"at_ms": 10000, "kind": "failover_select", "failover_timeout_seconds": 60, "effect_control": "refuse"},
  {"at_ms": 20000, "kind": "failover_repeat"},
  {"at_ms": 30000, "kind": "failover_clear"},
  {"at_ms": 40000, "kind": "failover_select", "failover_timeout_seconds": 60, "effect_control": "delay"},
  {"at_ms": 50000, "kind": "close_delayed_redirect", "timeout_ms": 20000},
  {"at_ms": 55000, "kind": "failover_clear"},
  {"at_ms": 70000, "kind": "env", "args": ["tidb-stop", "0"]},
  {"at_ms": 70001, "kind": "await_env"}
]
```

`scripts/record_failover.py` binds F01--F06 to `failover-slots.tsv`, requires
redirection on and held sessions, snapshots the post-label environment, and
combines raw qualification with `validate_failover.py`. The event gate requires
checkpoint-derived activation, unchanged activation, clear/reentry, a refused
then accepted redirect, a redirect completion after close, health loss/recovery,
the all-members failover guard, zero duplicate/unsettled operations and an empty
final ledger. CIDR match/no-match and Port conflict/recovery are checked in every
applicable slot. These scripts and synthetic validator tests are candidate
infrastructure; they do not count as recorded corpus evidence by themselves.

The writer distinguishes the existing per-session `refuse` input from the scripted
global one-shot control. For `failover_select`, the latter is projected as
`refuse_next: 1` on the same serialized config input that arms the real client
control, rather than on the later tick where Go happened to consume it. Each adapter
therefore rejects its own first non-session-refused Redirect or ForceClose attempt
in that failover window, even when legal engine-relative cadence moves the attempt
to another tick or session. Empty ticks retain the control; a second arm, a failover
clear, or trace end while it remains pending fails closed. The concrete consuming
effect is archived only to prove unique consumption and its internal marker never
appears in Go output rows. Older tick-level `refuse_next` inputs remain replayable,
but a config arm and legacy tick arm cannot overlap. More than one consumption in a
tick is invalid. If one session both accepts and rejects effects for reasons that
cannot be represented by these inputs, the attempt is incomplete. The failover
validator still requires the recorded rejected redirect to originate from the
checkpoint-selected failed backend; an unrelated earlier migration makes that
attempt incomplete rather than weakening the intended outcome.

Each recorded accepted redirect receives a stable logical reference
`redirect/<ordinal>`. For an ordinary callback, the input's logical session is first
mapped to that engine's session and the reference can bind only that session's oldest
outstanding accepted redirect, never an operation from another session. Legal
assignment differences may move the corresponding effect to another tick. The
callback reports `no_effect` when that session has no outstanding redirect; it is an
error to do so while the session has one. The tick-level cadence predicate still
independently rejects any missing or extra effect that its ledger requires, and the
final ledger rejects accepted effects left without a same-session callback or close.
Every paired manifest reports accepted redirects, callback and close settlement
counts, no-effect callbacks, zero unsettled accepted effects and the per-operation
settlement path separately for Go and Rust.

The scripted close used by the delayed-callback probe is strict and carries the
same reference as its following callback. It must bind an outstanding effect;
when its logical session has no outstanding effect, the engine must have exactly
one global unbound redirect. Multiple global candidates are ambiguous and fail
closed rather than letting output order choose the handle. Closing the uniquely
identified concrete connection swaps logical close handles, so the remaining
scripted closes still settle every engine's live connection exactly once. A stale
strict reference fails the common ledger.

Run `run.py.validate()` on a derived trace before any replay claim. A nonempty
`requires` list remains a blocker even when that structural validation passes.

Connection/prefer-idle emits public-history predicates rather than an unresolved
policy dependency. The common runner applies them independently to each engine's
reservations, established connections and accepted redirects. Recorded Go is checked
by the same predicates without exporting its ledger into replay inputs. Empty ticks
are proven from disabled redirection or absence of possible migration
sessions/destinations. A supported active balance tick carries `redirect_cadence`:
input-derived group epochs, member health/keyspace and any Status scoring calls.
The runner combines that descriptor with each engine's connection counts, physical
insertion order, retained unhealthy rate, cooldown and cadence clock to enumerate
its legal effect sequence. A pending global one-shot refusal may expose more than
one legal group order; the bounded alternatives are explicit and no observed Go
choice is used as Rust input.

After a non-unique selection, `force_close_due` declares the backends whose failover
deadline has arrived, derived from config, whole health inputs and event time. The
common comparator resolves each engine's own established owners, effect ordinals
and accepted-close history, and composes closes after redirects in production order.
Reservations are not established owners; refusal remains retryable and acceptance
suppresses subsequent closes, including across clear/reentry, until the connection
is closed. A backend can remain past its failover deadline without being due when
its last established owner has already closed: Go removes the connection from the
backend list in `OnConnClosed`, and the timeout worker can only act on connections
still present in that list. Independent session effects may commute.

The 86-event force-close smoke covers random and connection/prefer-idle choices,
before/equal/after deadlines, unchanged activation, repeated refusal, acceptance,
clear/reentry, zero timeout and cleanup. CI runs the real adapters, derives the same
expectations independently from each engine's public history and checks both outputs.
The 87-event keyspace variant enables redirection and changes only public whole
health inputs: named versus legacy empty, then two distinct named keyspaces on
refresh. Both real engines must still issue only the input-derived failover closes.
The original 86-event event sequence stays unchanged. Its reference predicates say
that the cleanup tick after the final close has no due backend, while the immediately
preceding tick with live owners remains due. Both variants require identical
independently derived expectations and no unresolved dependencies.
Counterexamples also force different legal owners and reject missing, early,
duplicated or misdirected effects. These tests do not qualify recorded slots.
Original recordings and earlier derivations stay immutable;
a new derivation must use a new output filename and does not alone qualify a slot.

Connection-factor migration now derives the selected pair, connection ratio and
rate from public inputs and exact current ownership. An earlier random choice no
longer poisons the remainder of a trace after that session has closed; uncertainty
that is still active, or that seeded a retained unhealthy Status rate, remains a
dependency.
It accounts for pending reservations and accepted redirects, uses physical insertion
order from Finish/Rehydrate/successful completion, and checks the slow/fast cadence
boundary at 20ms. The fast budget uses `(10ms - 1ns) / interval + 1`; refusals neither
consume that budget nor advance the group clock. Refused requests and failed
completions retry only at or after three seconds from request issuance. Successful
completions append physical ownership at the destination, and a new group starts
with a new cadence clock. Previously completed or closed operation handles cannot
settle a later request on the same logical session in expectation derivation.

`cadence_smoke.py` generates written scenarios for explicit/default rate, exact
ratio and interval boundaries, refusals, delayed failures, re-enabling redirection,
FIFO, stale/late callbacks, close before completion and group recreation. CI runs
the real adapters and derives identical expectations independently from each output.
Python counterexample rows are written test data and are not engine evidence.

This increment retains the migration dependency for ambiguous group lifetimes,
unmodeled Resource/Location migration factors, incomplete public Status scoring,
or an alternative set outside the bounded relative model. It also refuses to seed
a cadence clock from an earlier unverified migration. The Python relative-effects
counterexample lets two engine rows choose different legal owners and callback counts.
The generated relative-effects smoke consumes a global refusal and resolves
a strict delayed close plus late callback through the accepted-effect alias in both
real adapters. Both are synthetic evidence, not a qualifying recording, and neither
freezes the 18-slot manifest.

Resource `prefer-idle` selection now has a bounded input-derived case: two
healthy, equally local backends in one group, unique public ownership, no label
isolation or retry cycle, and complete metric rows keyed by the public health
`ip:status_port` fields. The derivation applies the production factor order and
advice gates across health error ratios, memory OOM risk, CPU EWMA/buckets and
connection count. It distinguishes Go's year-one zero time from Unix epoch zero,
retains same-update snapshots, handles one-nanosecond changes and uses the strict
60/120-second expiry boundaries. Policy transitions reset factor lifetimes, and
the bounded model includes the config-time scoring call that can seed a recreated
factor from the retained whole packet. A whole health refresh can likewise seed
or retain that cache when the same two healthy members, metric identities and
factor inputs remain unchanged; its observed and proposed-failover scoring views
are then equal. Incomplete rows, topology/failover changes, unsupported group
shapes, retries and unsupported tick scoring keep the explicit
`policy-constraint:resource/prefer-idle` dependency. The 170-event metric-time
fixture and existing 17-event metrics-producer trace now derive their choices
independently from both engines with no dependency; both remain synthetic and do
not count toward the frozen 18-slot corpus.

`resource_cadence_smoke.py` fixes six public connections to the high-CPU backend,
then derives the production Resource factor pair and 10/s migration cadence. It
checks the stable health refresh's two scoring views. When a later changed packet
has the same update time, the prior factor snapshot remains. It also covers the
exact 100 ms boundary, a refused request that does not consume the one-acceptance
budget, successful callback ownership, and the CPU negative-advice guard after
current estimates cross. A complete supported tick preserves factor cache lineage;
incomplete metric ownership or any unsupported shape keeps `migration-cadence`
instead of copying observed effects. The scenario is synthetic adapter evidence
and does not qualify a recording slot.

`status_cadence_smoke.py` extends constrained Connection histories to unhealthy
status migration. The first unhealthy scoring call captures its input-derived
connection rate; later count decreases keep that rate. A healthy scoring call
clears it, while a different member's scoring call prunes an unaccessed entry
strictly after 60 seconds. The failover guard's two public-input scoring passes
are included, so even an unchanged failover-list update can refresh the rate.
Explicit status rates override it. Status precedes connection count and no
migration targets an unhealthy backend.

The Go replay now also routes the status factor's clock through the declared
public event time. The scenario checks rate retention, support pauses, recovery,
all-unhealthy groups, exact expiry through intervening Next calls, unchanged
failover masks, the all-members guard and explicit override. Both engines and
both derivations run in CI. Status is present and retained across all three public
balance policies. A Resource/Location tick can therefore use the same exact
status/connection cadence when the complete lifetime proves its metric factors
neutral; an engine-relative owner that could seed an unhealthy snapshot still
withholds that history until a healthy scoring call clears it.

The first paired status run found that Rust skipped Status scoring on the
Connection routing path and during failover refresh. A recovered or expired
source therefore kept an old migration rate and issued requests early. Connection
Next now uses the factor path, retaining valid scoring history even when factors
reject every candidate. Failover refresh performs both observed-healthy and
proposed-mask scoring passes for Connection. The unchanged public scenario checks
these changes against the preserved first Go/Rust outputs.

The Rust replay-only adapter tolerates `metric input source unavailable` solely on
the immediate sync after an accepted config changes the normalized backend-cluster
set. That set replacement retires the old source before the next recorded health
publication binds the new one. Initial sync, health sync, non-cluster config sync,
and every other error remain fatal; a focused Rust counterexample checks both the
non-cluster and wrong-error boundaries. Production Rust routing code is unchanged.
