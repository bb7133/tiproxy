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

The recording producer is implemented; paired Go/Rust metric publication adapters
and resource-policy qualification remain incomplete. Every trace containing a
`metrics` event retains `metrics-input`, even for an empty set. The common entrypoint
rejects such traces before creating an output directory or launching engines,
regardless of removable provenance tags. CI preserves a synthetic real-router
producer archive and its explicit dependencies, separately from paired smoke runs.

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

The following dependencies withhold a slot from acceptance:

- `effects-v2`: effects depend on each engine's own prior assignments, including which
  session should move and whether an effect is due. Copying Go's effect list with
  variable endpoints is insufficient.
- `policy-constraint:<policy>/prefer-idle`: not all factor advice can yet be derived
  from the available public inputs. An unrestricted candidate set is not qualification.
- `metrics-input`: recorded query values still need paired publication adapters.
  New captures set `metrics_observed` only after publishing actual nonempty data;
  older captures' reader-presence flag is retained as historical evidence and does
  not prove complete inputs. The producer archive alone does not clear this gate.
- `migration-cadence`: explicitly required by contract §4. This dependency is derived
  from input capability and session/destination history even if every observed
  redirect is deleted. Whole-health support-redirection AND semantics disable the
  balance pass; independent failover closes still run. Legal observed redirects are
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
sessions/destinations, together with absence of due failover candidates;
effect ownership/cadence remains unresolved when either can still depend on the
engine's assignments. Original recordings and earlier derivations stay immutable;
a new derivation must use a new output filename and does not alone qualify a slot.
