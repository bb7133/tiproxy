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
anchors abort the build. Production files are never edited by the overlay.

The optional `config.clock_origin_nanos` is the Unix-nanosecond origin of the
recording scheduler. Real captures always include it; replay adds each event's
`at_nanos` to that origin. Older traces without the field retain their original
1700000000-second epoch. The single shared Go test clock covers router/group and
CPU/memory/health-factor reads in both recording and replay. Rust's per-router
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
Recordings that claim metric observations but contain no metric events keep their
`metrics-input` dependency. General resource-policy/effect/cadence qualification
remains incomplete and separately blocked.

CI pairs the synthetic real-router producer's 17 events/three publications and
checks its input-defined A, A, B selection sequence in both engines. This small
scenario is adapter evidence, not general resource parity or a qualifying trace.
The raw archive, dependency-bearing derivation, stored Go result, paired engine
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
manager. Scripted actions currently support environment commands, config changes,
fetcher-boundary source-error windows and checkpoints. A fault wraps the real
`BackendFetcher`; the real observer then publishes the error. Stopping PD alone is
not guaranteed to publish an error because the production fetcher retries.

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
`manifest.json`, `proxy.toml`, and the exact `actions.json` when supplied. The manifest
records source head/tree/dirty status, workload duration, completed and failed
connection counts, script hash, event count and all three data hashes. `record.py`
embeds the build source identity; a dirty or unidentified build is incomplete.
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

- `effects-v2`: effects depend on each engine's own prior assignments, including which
  session should migrate and whether a redirect is due. Non-migrating failover
  closes now use the public-history predicate described below.
- `policy-constraint:<policy>/prefer-idle`: not all factor advice can yet be derived
  from the available public inputs. An unrestricted candidate set is not qualification.
- `metrics-input`: recorded query values still need paired publication adapters.
  New captures set `metrics_observed` only after publishing actual nonempty data;
  older captures' reader-presence flag is retained as historical evidence and does
  not prove complete inputs. The producer archive alone does not clear this gate.
- `migration-cadence`: explicitly required by contract §4. This dependency is derived
  from input capability and session/destination history even if every observed
  redirect is deleted. Whole-health support-redirection AND semantics disable the
  balance pass; independent failover closes still run. Destinations must also have
  exactly the source's current public keyspace, including empty == empty for legacy
  inputs. When every possible pair crosses keyspaces, migration is impossible;
  compatible alternatives retain the cadence dependency because the factors may
  choose a different pair and the router does not retry another destination.
  Whole health updates replace keyspaces; missing retained sources keep their last
  delivered value. Legal observed redirects are
  withheld until exact cadence/effect eligibility is implemented. No further scope
  approval is needed to implement this requirement.

Additional planned work includes timer boundary expansion, scripted refusal/delayed
callbacks, router Close/recreate/rehydrate, CIDR/no-match and multiple-listener/cluster
scenarios. The presence of a row in `recording-plan.tsv` does not mean its driver is
implemented. Captures with unresolved dependencies remain raw evidence and do not
count toward the 18 slots, three rounds or focused acceptance groups.

## Commands

Run from the repository root, with build/output directories outside the source tree:

```sh
python3 tests/controlplane/cproute/api-differential/recorder/record.py build --out /tmp/api-record-build
/tmp/api-record-build/record -slot N01 -attempt a3 -duration 150s -clients 8 \
  -out /path/to/new-recordings -script /path/to/actions.json -env /path/to/env.sh
python3 tests/controlplane/cproute/api-differential/recorder/derive_expectations.py \
  /path/to/new-recordings/N01-a3/trace.json /path/to/new-recordings/N01-a3/go.json \
  --output /path/to/new-recordings/N01-a3/derived.json
go test -race -tags apireplay ./tests/controlplane/cproute/api-differential/recorder/...
```

Run `run.py.validate()` on a derived trace before any replay claim. A nonempty
`requires` list remains a blocker even when that structural validation passes.

Connection/prefer-idle now emits a public-history predicate rather than an unresolved
policy dependency. The common runner applies it independently to each engine's
reservations, established connections and accepted redirects. Recorded Go is checked
by that same predicate without exporting its ledger into the replay inputs. Empty
ticks are proven from disabled redirection or absence of possible migration
sessions/destinations. After a non-unique selection, `force_close_due` declares the
backends whose failover deadline has arrived, derived from config, whole health
inputs and event time. The common comparator resolves each engine's own established
owners, effect ordinals and accepted-close history. Reservations are not established
owners; refusal remains retryable and acceptance suppresses subsequent closes,
including across clear/reentry, until the connection is closed. Independent session
effects may commute. This predicate does not authorize redirects or clear the
migration-cadence dependency.

The 86-event force-close smoke covers random and connection/prefer-idle choices,
before/equal/after deadlines, unchanged activation, repeated refusal, acceptance,
clear/reentry, zero timeout and cleanup. CI runs the real adapters, derives the same
expectations independently from each engine's public history and checks both outputs.
The 87-event keyspace variant enables redirection and changes only public whole
health inputs: named versus legacy empty, then two distinct named keyspaces on
refresh. Both real engines must still issue only the input-derived failover closes.
The original 86-event scenario stays unchanged. Both variants require identical
independently derived expectations and no unresolved dependencies.
Counterexamples also force different legal owners and reject missing, early,
duplicated or misdirected effects. These tests do not qualify recorded slots.
Original recordings and earlier derivations stay immutable;
a new derivation must use a new output filename and does not alone qualify a slot.
