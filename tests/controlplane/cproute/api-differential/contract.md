# Router API differential acceptance

Status: documentation proposal for review; no implementation or deletion in this commit.
Owner: CodexM5, task #81. Reviewer: ClaudeHome.
Reference implementation: `29d0f64fd85e727061d88b69e182aa5f2d62f398`.
Existing main: `00272c3e2fd749ee33e67fd2fc0ec31aed056b6d`.

Human decision `122ce57a` in #workflow:a5314eb7 (2026-09-11): compare router
external API inputs, outputs and observable effects; Rust and Go need not use
identical internal logic. This supersedes the earlier native-2B2 requirement
for per-getter tapes, caller envelopes and step-by-step internal equivalence.
It does not waive externally visible routing or connection correctness.

## 1. The finite boundary

The names used in discussion describe operations, not five identically named
Go methods. The adapters map the following finite set to the existing code:

| Operation | Existing Go boundary | Compare |
| --- | --- | --- |
| Router lifecycle | construction/Init, Router.Close | configuration result, initial availability, shutdown completion; no Init getter tape |
| Route / Next | Router.GetBackendSelector(ClientInfo), BackendSelector.Next | returned backend identity or error; externally observed retry sequence across Next calls |
| Finish | BackendSelector.Finish(conn, success) | subsequent availability and connection accounting, successful/failed creation |
| Backend update | BackendObserver health-result delivery | effects of health, topology and observer-error input on subsequent public operations |
| SetConfig | validated config input/channel | accepted/rejected update and subsequent routing/failover behavior; no Group SetConfig child trace |
| Migration and drain | RedirectableConn.Redirect / ForceClose; ConnEventReceiver callbacks | requested connection/destination, acceptance/refusal, later success/failure/close and exactly-once settlement |
| Read-only state | Router.ConnCount / HealthyBackendCount / ServerVersion; test client's assigned backend | documented observable values and final logical connection ledger |
| Rehydration | AssignmentRehydrator.RehydrateConn / LookupBackend | existing connection restored once, unknown backend rejected, late result settles original operation |

A timer tick, source response, callback outcome or config/health delivery is an
input at the test boundary. It is not a new internal observation family.
The two adapters may expose different native methods. A thin test adapter
normalizes those methods; it must invoke the real routing implementation,
not implement a second router or replay Go's decisions into Rust state.

Rust receives the same external inputs as Go. Go output is an oracle result,
never a Rust input used to seed selected groups, factor vectors or ledgers.
Inputs referring to a prior result use a logical session/operation handle;
each engine resolves that handle to its own result. This is necessary when
both engines make different legal random choices.

## 2. Comparison rules

- Stable public backend/cluster/keyspace and logical session IDs are compared.
  Allocator IDs, map order, private sequence numbers, child spans, factor read
  tapes, internal scores and memory layouts are excluded.
- A uniquely determined selection must match exactly. For a deliberately
  ambiguous or random choice, both results must belong to the scenario's
  declared legal set. This set is defined by public input and scenario
  expectations; never obtain it by reading either engine's internal shortlist.
- Both public policies, `random` and `prefer-idle`, can make random choices.
  We do not require a common RNG, identical wall-clock tickets or identical
  backend selection at each call. Retry outcomes and final state are checked
  relative to each engine's previous legal result.
- Error outcomes distinguish the exact no-backend sentinel, a wrapped
  no-backend error, port conflict and other configured source errors where
  callers can observe the distinction. Do not compare logging text.
- Compare effects in causal order for each session. Independent sessions may
  commute; a global callback order or internal lock order is not required.
  Missing, duplicated or incorrectly targeted effects are failures. Refused
  effects remain retryable where the public behavior requires it.
- At each explicit quiescent checkpoint, the expected logical ledger is
  reconstructed from API returns and accepted/completed effects. Router counts
  and test-client assignments must agree with it. Final closure leaves zero
  live connections and no unsettled accepted operations. Do not compare Go
  private `connScore` or require Rust's private representation to match it.
- Time-sensitive behavior compares before/equal/after a declared public
  deadline under a test clock. Timer plumbing may be injected at the test
  boundary. Do not record or demand every internal `time.Now` invocation.
  Real-run timings are separately reported; they are not nanosecond parity.
- Different internal arithmetic is allowed. An existing valid public input
  producing an externally different error, panic, route or effect remains a
  real discrepancy; it cannot be dismissed as an internal difference.

Random choice has one additional bounded distribution check: each of the six
public balance/routing policy pairs runs 50,000 independent selections per
engine on a fixed, declared, multi-backend scenario. Close/failed-Finish resets
each trial so input population is stable. Every selected backend must be legal;
for each backend, the absolute Go/Rust selection-frequency difference must be
at most 0.02. The manifest fixes candidates, source inputs and arrival schedule
before running. This is an engineering acceptance threshold, not a proof of
identical distributions or a guarantee of no sampling failures. The two-engine
frequency difference has sampling variance from both engines; time-derived
choices are not assumed to be IID. A failure is recorded and diagnosed, not rerun until
it happens to pass. No internal ticket injection is used to force equality.

## 3. Recorded corpus: N = 18, K = 3

[trace-matrix.tsv](trace-matrix.tsv) fixes 18 slots:
These are required recording slots, not already recorded or passing traces.
Every row is currently pending. Before the first qualifying run, fill all
recorded_at_utc, trace_sha256, go_source_sha and environment_manifest_sha256
fields, bind them to the raw trace files, and freeze the complete manifest.
No pending row or substituted recording can count toward N or K.
The three trace families (normal, failover, config/source change) are multiplied by
six publicly accepted policy pairs (Connection/Resource/Location times
prefer-idle/random). The internal-only `idlest` configuration is not a new
public acceptance combination; its public validation result remains covered.
The matrix distributes All, ClientCIDR, ProxyCIDR and Port over every family.

Each slot must be recorded from an actual Go TiProxy run against the existing
TiDB/PD/Prometheus test environment, for at least 60 seconds and at least 100
completed connection lifecycles. These are real executions of a controlled
workload, not a claim to contain customer production traffic. Synthetic traces
may supplement boundary tests but cannot count toward N.

The recorder sits in test wrappers around external input delivery, API return
and effect/callback boundaries. It records only the fields needed to replay
routing. It does not add internal caller hooks or copy SQL, credentials or
arbitrary error/log payloads. Record external topology/health/config/metric
values used in the run, not merely references to a mutable live source.

Each trace manifest contains the Go source/build identity, environment versions,
workload/fault operations, source-input hashes, event count, completed-session
count, duration and normalized input/output hashes. Record source errors as
named test outcomes. The trace import format is test data, not a runtime
control-plane protocol; one schema/size-validation boundary is sufficient.

Required family outcomes are finite:

| Family | Outcomes required in every trace |
| --- | --- |
| normal | successful selection/Finish/close; failed creation and retry; no-backend followed by recovery; initial empty state followed by first health |
| failover | health loss/recovery; configured drain activation, unchanged activation, clear and reentry; one refused then accepted redirect or close; late completion after close; no duplicate settlement |
| config/source change | valid config update and invalid public-config rejection; backend addition/removal; source error and recovery; group-routing input change; one close/recreate/rehydrate lifecycle |

CIDR traces include match and no-match clients. Port traces include a port
conflict and recovery. Outcomes must be present in recorded events; a script
that attempted to trigger them is not evidence that they occurred.

K means three complete consecutive qualifying corpus runs on one candidate
source tree: 18 paired Go/Rust replays per run, 54 paired replays in total.
The trace data is immutable between these runs. Use a declared logical clock
and deterministic delivery schedule for replay; preserve original timings in
the recording. Restore a fresh engine before each trace. Do not recapture or
replace a failed trace to hide its result. A source fix resets K and preserves
the failing trace and first result.

A qualifying run has zero violations of section 2. Legal random divergence is
not counted as a mismatch. A corpus passing these checks establishes this
bounded acceptance scope, not all possible production executions.

## 4. Three focused suites and one comparator check

These are fixed suites, not one new runner per API or per payload field:

| Suite | Fixed cases | Run budget |
| --- | --- | --- |
| concurrency | update racing with Next/Finish; close racing with redirect completion; duplicate/late completion; shutdown with outstanding requests | four cases, 16 predeclared barrier schedules each; assert public history/accounting and run Go race detection |
| resource release | failed creation; refused effect followed by cleanup; shutdown with outstanding operations; repeated create/close | four cases, 100 cycles each; owned tasks/handles and live connections return to baseline after a bounded drain |
| time boundaries | failed-redirect cooldown; failover close timeout; migration cadence; repeated activation preserving its deadline | four cases, immediately-before/equal/after, 12 rows; expected API/effect behavior only |

One comparator mutation table has eight faults: accept a wrong backend, accept
an illegal random backend, erase an error distinction, omit a retry result,
drop an effect, duplicate a terminal result, ignore a final-ledger discrepancy,
and accept missing/truncated input. Each mutated comparator must fail its
intended externally labelled assertion; the restored comparator must pass.
This table demonstrates detection sensitivity once for the common comparator.
It is not a reason to create a separate mutation framework for each API.

Use one differential runner and one artifact manifest. CI may shard independent
corpus slots. Preserve the existing 45-minute per-job limit; a timeout is a
failed/incomplete run, not permission to reduce N, K or scenario outcomes.
Ordinary deltas use static review, same-tree CI and those artifacts; duplicate
full local runs are reserved for diagnosing a concrete failure.

## 5. Retention and retirement

[retirement-inventory.tsv](retirement-inventory.tsv) enumerates all 138 paths
changed by PR255 at the reference SHA. Actions are plans for a separate code
change, not permission to delete whole packages blindly.

- Retain real Go/Rust routing, grouping, scheduling and lifecycle algorithms.
  Preserve functional bug fixes independently from observation changes.
- Reuse the business scenarios from Route/Next/Finish/Balance/metadata/startup
  tests, expressed through the finite external boundary. Do not preserve their
  internal tapes, frame-shape or exact atomic-step requirements.
- Retire PR255-only v4 caller schemas/codecs, metadata/startup reconstruction,
  per-boundary envelopes, snapshot-charge mirrors and the seven new per-family
  runners. Retain their existing evidence as an immutable migration archive.
- Mixed files lose only the retired instrumentation/dispatch/imports. In
  particular, the pre-PR v2/v3 observation, recorder, native factor codec and
  shared routing helpers must not be deleted wholesale while used elsewhere.
- The already-merged runtime shadow infrastructure is a second, explicit
  removal unit, enumerated at the main baseline in
  [merged-retirement-inventory.tsv](merged-retirement-inventory.tsv): Go observation producer/UDS service, Rust legacy-router-shadow
  decoder/consumer and their call sites/tests. Recheck the listed references on
  the replacement implementation baseline and remove them together after the
  API differential is accepted and no remaining rollout consumer requires them.
  Until that removal, their existing safety checks continue to apply; they do
  not acquire new internal-equivalence acceptance requirements.
- The merged production selector/factor/owner logic and bridge messages needed
  by the current Go owner are retained. Their ownership cutover/removal follows
  issue223's single-owner checks, not a test-count or LOC target.

Keep PR255 as Draft/evidence while the replacement is prepared from main.
Its existing internal shadow code is not a prerequisite to merge for the new
API framework. Useful fixes/scenarios may be carried individually with clear
provenance. Implement the API adapters and any genuine externally observable
Rust parity repairs in one replacement PR; put deletion of old instrumentation
in a separate reviewable PR with this inventory and CI. This avoids mixing
removal with claims that the new comparator already works.

## 6. Done means done

The new router differential acceptance is complete when: N=18 recorded traces
meet provenance/outcome requirements; K=3 complete paired runs pass; all three
focused suites and the eight comparator faults pass; retained-code regression
CI is green on the tested tree; and the independent review finds no blocker
against this document. Then issue a cutover-readiness decision and proceed to
the already defined issue223 single-owner/live protocol matrix. Passing this
suite is not permission to merge or claim the ownership switch has happened.

A blocker must identify a listed API behavior, required corpus/suite outcome,
real resource/concurrency defect or comparator blind spot, and show a concrete
counterexample or missing required evidence. Fix such defects without deleting
the original failure. Optional coverage, generalization and internal algorithm
comparison go to follow-up work and do not extend this endpoint.

Stop: new v4 caller payloads; per-getter read tapes; Group/Rust private-step
identity requirements; per-boundary fault frameworks; C4 router-pass and
SetConfig/failover internal capture; activation of the old v4 online shadow.
Do not reopen the earlier 2B2 18-window/12,000-operation/lease-charge contracts
as additional gates: this human-approved API scope replaces that internal
qualification contract. Existing standalone regression checks protect code
that is still present until its separate retirement.

This documentation commit is the review point for the concrete numbers and
comparison rules. It changes no executable code, CI job or existing evidence.
