# Router API differential implementation

The four acceptance/inventory files are unchanged from frozen a9c497c3,
confirmed in message 53119a02. Their endpoint is the completion criterion.

The initial implementation connects one common input to the real Go router,
factor policy and selector, and the real Rust module sources, router and
selector. The adapters never receive oracle outputs. They report public
results and client assignments; the comparator independently reconstructs the
logical connection ledger from Next/Finish/close results and checks public
connection accounting. Ambiguous choices must belong to the declared legal
set; uniquely specified choices and error classes must match.

Run the synthetic adapter check:

```sh
python3 tests/controlplane/cproute/api-differential/run.py \
  tests/controlplane/cproute/api-differential/smoke.json --output /tmp/router-api-new-run
```

Use a new output directory for each run. The runner preserves both raw outputs,
input hash, source identity and command logs. CI runs it in one 45-minute job.
Synthetic adapter checks count as zero recorded traces and zero corpus rounds.

Go replay drains its background loop after the real Init and delivers inputs
synchronously to the exact production health/config handlers. Rust replay uses
the existing config/module fixture. The test-only `api-replay` feature delivers
whole observer inputs through the actual routing and health publishers; a
background network probe cannot replace a recorded health verdict.
Both then call their actual public selector and accounting APIs. This is input
scheduling in a test adapter, not a duplicate routing implementation. No internal
caller capture is attached. Recording will use the live Go loop and actual
TiDB/PD/Prometheus sources, preserving values at these external boundaries.

Whole external metric publications also enter both adapters. The test-only Rust
publisher uses current routing/discovery/config/owner fences and keeps the merged
series order; neither engine receives query-getter history or factor snapshots.
The 17-event synthetic producer case exercises this boundary. Both adapters keep
Go year-one zero time (`null`) distinct from Unix epoch (`0`); a separate synthetic
API case checks initial updates and exact expiry boundaries. Generic resource-policy
and migration-cadence qualification remain dependencies of real recordings.

Implementation is limited to three increments of the same replacement PR:

1. Common input validation, Go/Rust API adapters and basic selection/retry/
   Finish/close comparison. The initial smoke had 19 events; it verifies empty
   initialization, two-backend selection/retry, unique selection after removal,
   invalid config rejection and the final empty connection ledger.
2. External health/config/metric/error inputs, migration/close callbacks,
   rehydration and clock scheduling; live recorder using the existing test
   environment; finish the same comparator's eight mutation checks.
3. Record and freeze all 18 real traces; run the fixed three focused suites,
   six fixed distribution comparisons and K=3 corpus rounds on the candidate
   tree. Diagnose actual failures without replacing traces or changing limits.

Current acceptance counts: recordings 0/18, rounds 0/3, focused suites 0/3,
comparator mutants 8/8 on reviewed a71d65b6 (repeat on the final candidate). The initial adapter rejects unsupported operations;
it does not silently treat missing implementation as a passing observation.
Old instrumentation deletion stays in a separate PR after replacement
acceptance. No old per-getter, caller-envelope or per-boundary fault work is
part of these increments.

The next adapter delta expands smoke to 55 events. It includes a refused
redirect, the three-second cooldown boundary, failed and successful terminal
callbacks, a redirect followed by force-close and late completion, and named
lookup/rehydration with unknown-backend rejection. These remain synthetic.
The single comparator groups effects by logical session, retaining each
session's causal order while permitting independent sessions to commute.
`--comparator-check` mutates this comparator at eight labelled assertions and
restores it against the retained actual Go output. The artifact includes each
mutated source and verdict; it does not create per-API mutation families.

Go uses a build overlay for the one logical event clock in router/group code;
all values and overlay hashes are preserved. No private state is seeded and
no clock-read tape is recorded. Rust uses its existing test round clock.
Rust's new lookup/rehydration methods operate on its real source and ledger,
without routing a new selection; duplicate or non-idle restoration is rejected.
Health readiness is checked through public topology/health source handles.

The first 55-event CI run at ad2920cc failed before `migrate/3`: the
scenario attempted another migration three seconds after the last accepted
one, while the default one-connection status migration cadence was five
seconds. The original input/output failure is preserved. The synthetic
cooldown scenario now explicitly configures one migration per second, so the
three-second retry boundary can be checked independently. This does not change
the acceptance contract or a recorded corpus trace. Rust's non-idle/closed
rehydration rejection is also covered by a direct public-API unit test.


The health-input increment adds 43 synthetic events (84 primary + 14 Port = 98 total): unhealthy and
nonlocal verdicts, version retention, a backend without redirection support
that still receives a timed force-close, and two clusters sharing the same
address/port with conflict and recovery, and a locality verdict reversal. They do not count as corpus recording
or as completion of the fixed focused suites.

`health.backends` keeps required `address` and `labels`. Optional public fields
are `cluster` (default `default`), `ip` (default `127.0.0.1`), `keyspace`,
`status_port`, `healthy`, `local`, `server_version`, and `support_redirection`.
The three booleans default true for old synthetic inputs; other omitted fields
are empty/zero. Real recordings write every value explicitly. Identity is
`cluster/address` for a nonempty cluster and `address` for an empty cluster.
Two clusters may therefore publish the same address without losing identity.

Checkpoints always return `healthy_backend_count` and `server_version` from
real router methods, alongside assignments/count. Expectations may specify an
exact healthy count and `legal_server_versions`: a declared set derived from
public health inputs and legally retained earlier versions. Several healthy
versions may be returned because Go map traversal is unordered. Without a
version set the engines must agree. Healthy counts always agree, including
checkpoints whose older trace omitted an explicit expected count.

The Rust source seam is compiled only when the test dependency enables
`control-topology/api-replay`. It replaces the handle's dynamic R/H inputs;
configuration, namespace, mode, owner and publisher retirement checks remain
active. It does not inject groups, factors, selected backends or accounting.
The real scheduler now honors the delivered redirection capability while still
performing timeout closure. Existing network probe producers retain their
previous enabled capability default; wiring their SQL capability detection is
part of the later production composition, not claimed by this API replay.


The first health-increment run at 77c33bd6 failed: the old composition fixture
needed the new struct fields, and the combined synthetic incorrectly expected
`routing-rule` to change at runtime. Go fixes that rule during Init. The Port
14-event segment now starts a fresh router from `port-smoke.json`; the primary
84-event trace retains its All startup rule. CI invokes the same runner for
both and uploads both output directories. The original 97-event first-failure
input/output and ZIP remain archived; no recorded trace was altered.

A targeted Go-only diagnosis also caught a missing scenario input: becoming
unhealthy alone does not activate the configured failover timeout. The
capability/timeout scenario now explicitly delivers `fail-backend-list` before
the boundary ticks. Its original no-effect output remains preserved. The Rust
public healthy count excludes active failover backends, matching Go `Healthy`
rather than only the observer's health bit.

The locality reversal explicitly selects `prefer-idle`: the trace's initial
`random` selection intentionally permits a remote backend and cannot justify
a unique-local expectation. That invalid synthetic assumption and its raw Go
result are preserved with the second diagnosis.


`source_error` delivers one failed observer result with an `error` identity:
`no_backend`, `wrapped_no_backend`, `port_conflict`, `topology_unavailable`,
`cancelled`, or `deadline_exceeded`. Unknown identities fail input validation.
The first three preserve the existing routing error classes; the last three
produce distinct `source_error:<identity>` results. Go receives the actual error
through its production health-result handler. Rust publishes a new fenced
observer result and its real reservation/health-count methods interpret the
error. The previous topology, health metadata, version and established
connections remain available, including lookup, rehydration, Finish and timeout
closure. A successful health result clears the error; a config update does not.

The 82-event `source-error-smoke.json` exercises initial failure, all six error
identities with retained connections, Finish after failed observation, lookup
and rehydration during failure, config rejection/acceptance without error
clearance, timeout closure while the observer is failing, explicit recovery and
an authoritative empty result. CI runs all three synthetic inputs through the
same runner and uploads a third `routing-api-source-error` directory. The common
eight comparator mutations remain a single round on the primary trace.

Error publication is currently enabled by the test-only `api-replay` feature.
The existing network discovery refresh still retains its last successful result
on a failed poll; forwarding its qualified failure into the observer publisher
belongs to the remaining producer integration. This slice does not claim that
live-source error forwarding or arbitrary error identities are complete.


The first source-error run at 1773e57f failed its synthetic expectation at
seq 61: both engines correctly produced no force-close. The only backend was
still healthy, so listing it in fail-backend-list would remove every routeable
backend; both implementations ignore that list for the group. The first
78-event input, identical raw engine outputs and failing CI artifact are retained.
The corrected scenario first asserts no close in this protected state, then
delivers an explicit unhealthy verdict and a new observer error. This activates
failover at that health event and tests the before/equal timeout ticks while the
observer is failing. No runtime algorithm changed to satisfy the scenario.


The full retry-history increment adds `expect.exclude_history: true` on successful
Next expectations. `backend` / `legal_backends` then declare the healthy candidate
set before selector exclusions. Each engine's comparator tracks all successful Next
results, preserves them across failed Finish and health/config updates, and subtracts
that engine's complete cycle. Exhaustion resets the cycle before the same Next call;
a returned exact no-backend also resets it, while wrapped no-backend and other errors
retain it. Old `exclude_previous` expectations remain supported and are mutually
exclusive with the new mode.

An optional `expect.prefer_local` subset applies Location/prefer-idle's public
locality rule after subtraction. It allows a remote backend once all remaining local
choices have been tried, and requires a local backend again after full exhaustion.
Both fields are assertion metadata only and are stripped from Go and Rust inputs.
The deriver keeps uncertainty across a reset that happened only in Go, so it cannot
mistakenly reuse Go's reset for Rust. Policy/effect and metrics dependencies remain
explicit; this does not qualify the recorded corpus.

`retry-smoke.json` contains 115 synthetic events for complete cycles, topology removal
and restoration, exact/wrapped observer errors and local-to-remote fallback. CI uses
the same replay/comparison entrypoint and uploads `routing-api-retry` with the other
three smoke artifacts. Six direct comparator regressions reject invalid histories;
the common comparator mutation table remains the same eight faults.

Connection/prefer-idle expectations use `expect.prefer_idle_conn: true` together
with full exclusion history. The common comparator derives each engine's outstanding
reservations from successful Next, Finish, Rehydrate, accepted Redirect, callback
and Close events. It applies the configured ratio and migration-rate cutoff to that
engine's remaining candidates, including the 16-bit factor saturation. No recorded
Go count or choice is passed to Rust. Config updates come from the original TOML;
invalid updates preserve the last accepted configuration.

The recorder deriver uses the same predicate to reject unexplained recorded Go
choices. A non-unique choice does not by itself make every later tick ambiguous:
a disabled migration pass or absence of any possible session/destination, together
with no possibly-owned backend at a due failover deadline, prove an empty effect set. Enabled redirection and ambiguous
failover ownership still retain their effect/cadence dependencies. The retry fixture
also exercises busy-backend exclusion, full-cycle exhaustion before preference,
rate-cutoff equality, ratio updates and closing retained sessions. Twelve direct
regressions and 29 derivation counterexamples cover these rules; recorded corpus
qualification and the eight common comparator faults remain separate gates.
