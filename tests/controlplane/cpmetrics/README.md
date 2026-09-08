# CP-METRICS query/history core evidence (#221-1)

Run `make controlplane-cpmetrics-evidence` from the repository root with the pinned Rust and Go toolchains. The Rust CI quality job runs this target after CP-ROUTE evidence.

This slice adds the staged `control_topology::metrics` data core. It performs no I/O and carries no routing, material, process-owner or election authority. The collector/retirement/owner-service lifecycle remains #221-2; factor caches and actual Resource/Location router composition remain #221-3 / #220-3C. Existing typed policy gates and production ownership are unchanged.

## What runs

The entrypoint generates **152 unique observations** from production Go code on every invocation, checks the exact family counts and uniqueness, and feeds them to the actual Rust data core:

- 96 fixed-query observations call the six production factor QueryExpr/QueryRule definitions: expression spellings, range endpoints/15s step, backend metric functions and history transforms. Includes missing families, zero denominators, NaN/Inf, per-counter integer truncation, subsecond CPU intervals, counter resets and unordered history.
- 38 reader observations call Go's owner-history decoding, mergeHistory, purgeHistory, findMissingBackendAddrs, label matching, cluster attachment and owner-only marshal selection. Includes whole-step replacement, equal timestamp retention, unknown rule/backend preservation, exact retention boundary, mixed-case Go JSON field names, operator/IPv6 labels and missing cluster labels.
- One **six-step source sequence** runs Go ClusterReader.readMetrics against real loopback Prom/backend/peer HTTP and embedded etcd. Successful empty Prom remains selected; nil Prom fetcher produces ErrNoProm and backend fallback; a failing peer makes the completed backend map change without changing the previous source. Rust executes the same completed-event sequence against ReaderState. This proves the data-state transition, not a Rust network/election runtime.
- One multi-cluster observation calls the real Go mergeQueryResults and compares maximum **nanosecond** query update time while retaining old per-sample millisecond timestamps. Factor-level aging/default scores are reserved for slice3, not claimed here.
- Seven real HTTP PromReader observations verify successful/empty vector and matrix decoding, duplicate series order, API failures and malformed timestamp/value types.
- Nine Go filterMetrics/parseMetrics observations verify prefix filtering, untyped values, ignored HELP/TYPE comments, escaped/duplicate/invalid labels, explicit timestamps and malformed selected lines.

Rust also tests capacity rejection without partially changing old history, retaining Step1 before CPU has a usable range, original sample age vs query update time, and bounded output serialization. History capacity accounting is maintained incrementally; an observation does not rescan every backend in the cluster.

The runner copies the Rust workspace to a fresh directory with a unique Cargo target, then compiles **17 production mutations**. A mutation must compile, complete a failing test run, and identify its required observation/test; a build error, hang or unrelated failure is not accepted. Mutations cover query step, cluster timestamps/labels, CPU interval/reset, integer truncation, history equality/replacement, any-rule fallback, expiry equality, source-map/source-choice separation, empty Prom, owner export filtering, field folding, fractional timestamps, raw-sample retention and wire output bounds. A restored baseline must pass. No hand-edited expected output or modified Go implementation is used.

## Data and compatibility limits

There are six fixed queries, not a PromQL interpreter. Exposition is the Go-filtered untyped subset consumed by those queries. The parser ignores unrelated lines, and retains selected prefix-family behavior. The public DTOs are data and may not authorize runtime results; the future producer must bind exact applied source/material and CP-ETCD capabilities before publishing.

Explicit bounds are 16MiB per body/output, 100k series/history entries, 1M retained sample pairs per cluster, 128 input labels per series and 4096 bytes per token/label. A lexical pass limits JSON nesting to16, structural nodes to1M and raw string tokens to6×4096 bytes before serde allocates collections; decoded labels/keys get their own byte checks. Both known and unknown fields consume this budget. No partial success is returned after crossing a limit. The output writer rejects growth before exceeding 16MiB, including long finite float spellings. Future timestamps cannot grow history without limit because the independent count cap still applies.

Go-compatible owner JSON accepts null/empty histories and case-insensitive struct fields. Empty containers are normalized to empty maps/arrays for semantic comparison; the existing Go endpoint accepts both null and empty arrays. SamplePair remains `[decimal Unix seconds, "float"]`, including NaN/Inf. Timestamp decoding uses the pinned prometheus/common v0.65.0 decimal-millisecond truncation, including its historical negative-fraction behavior; exponent timestamps are rejected by both. Rust enables only serde_json's already-resolved `raw_value` feature to preserve the exact timestamp token instead of rounding through f64. Query update timestamps retain nanosecond changes, matching Go factor cache equality.

Rust bounds intentionally reject unsupported oversized/malformed input instead of preserving Go's unlimited allocations. Error-counter conversion also rejects non-finite/out-of-i64-range values or overflowing sums; Go's float-to-int overflow is architecture-dependent and is outside this supported counter domain. CPU/memory IEEE NaN/Inf transformations retain their normal Go paths. These input limits are not evidence of universal parity for arbitrary hostile Prometheus payloads.

## Integration boundaries

The data-state core distinguishes selected source from each reader's result map. Backend aggregate errors may retain source while replacing a completed map; successful empty Prom does not trigger backend. Missing means no active rule has Step2, before purge. History merge replaces each entire step only if its last timestamp is newer and does not filter unknown backends by current topology. Those data rules do not grant stale ownership permission.

At collection integration, use opaque retained discovery/material authority and a synchronously revocable CP-ETCD session capability. Clear authority before abort/join or slow resign/revoke; do not use copied numeric epochs/watch snapshots as the sole fence. Consume actual health only from H and preserve the existing ledger's two locked checks. No Resource/Location enablement, owner election/HTTP service, legacy-bridge expansion, manifest lift, or closure of #221/#220/#147 is part of this PR.

## Applied material and bounded transport (#221-2B)

Run `make controlplane-cpmetrics-applied-evidence`. The separate mandatory Rust
`Applied metrics material and transport evidence` CI job runs it alongside the
unchanged quality job. Its dedicated embedded-etcd fixture and isolated Cargo
mutation target have no production identity or shared mutable build output.

`TopologyModule::with_metrics()` opts into passive preparation/publication only.
The module's unique writer builds HTTP clients from the same validated cluster
bytes before any live mutation or discovery epoch reservation. After successful
preparation it withdraws metrics authority **before** the first registration
cleanup await. Health retains its existing withdrawal order. The resulting
`MetricCapture` retains exact R, mode, applied material, original owner and actual
`DiscoveryCapture` identities. A no-op preserves the feed; a replacement makes
old captures permanently stale, including same-content replacements. An H-only
refresh never re-feeds metrics. The later collector must reset histories on this
feed transition; this slice does not start that collector.

`DiscoveryCapture` exposes bounded full-cluster topology and Prometheus reads,
without exposing its etcd client. Every metric discovery RPC/retry carries the
additional material/source fence, including while the original discovery set
remains published during slow registration cleanup. `EtcdConnection` forks
preserve their original owner/generation and all extra fences conjunctively.
Current proxy zone comes from committed `routing().proxy_labels["zone"]`, even
when applying the candidate cluster material fails. Static mode publishes no
synthetic etcd reader; empty factor captures remain #221-3.

`HttpTarget` admits bounded ASCII origin-form paths/encoded queries. The existing
`get_once` still uses `/status`; metric targets share its explicit DNS, candidate
dial, cluster TLS, logical-host SNI, deadline and body fences. Prom HTTP uses the
system resolver without synthetic cluster/TLS material. A supplied backend work
or peer fence is checked together with material/source at every effect boundary;
this reusable transport does not itself mint election/publication authority.
Normal completion aborts and joins its HTTP connection driver, and cancellation
aborts it through a Drop guard. Metric bodies remain capped at 16 MiB and health
bodies at 64 KiB.

The gate covers:

- Real HTTP target, DNS/TLS/SNI, large bounded body, cancellation and independent
  source/work revocation against coincident DNS/TLS/body failures; no new attempt
  after retirement. A real `ElectionWorkPermit` is also exercised against HTTP.
- Actual feed identity/ABA, serialized final publication, writer Drop, revision
  overflow/waiting, mode/source/original-owner fences and additive etcd forks.
- Real module opt-in, H refresh, rejected client retention with no burned epoch,
  zone-only and rejected-cluster-plus-zone changes, static transition and abort.
- Held KV Range with discovery rotation/Drop/owner loss, and independently held
  applied material/R with discovery kept live: no second prefix or Prom retry.
- A real module registrar blocked in the CP003 protobuf proxy's `LeaseRevoke`:
  R, H, process owner, Dynamic mode, discovery and work remain live while old
  metrics captures and delayed Prom/backend/peer responses are already stale.
  Releasing cleanup removes the old remote lease and permits a fresh pairing.

The isolated mutation runner requires 16 production mutants to compile and fail
their named live/boundary assertions. Compile failures, timeouts and unrelated
test failures do not count; a restored baseline must pass. The existing 152 Go
observations/17 core mutations and all CP-ROUTE evidence remain separate required
gates. Actual collector scheduling, mixed Go/Rust owner enumeration/history HTTP,
listener readiness and factor/router composition remain subsequent slices.


## 221-2C collector and owner service

`make controlplane-cpmetrics-collector-evidence` runs seven collector unit tests,
five required real-runtime groups and compiling production mutations followed by
the restored baseline. The separate mandatory Rust CI job has a 30-minute budget;
the existing CP-METRICS 152 observations / 17 mutants, applied-material 16 mutants,
CP-ETCD authority eight mutants and CP-ROUTE 46 mutants remain unchanged.

The collector is an opt-in `ControlModule`. `MetricCollector::bind` binds the real
in-process HTTP socket before an owner can advertise it. Only `run` activates
serving under its original process owner. No binary/production composition is
enabled here. The later composition slice must use the authorized same-process
endpoint and deployment TLS policy; this staged standalone listener is plain HTTP.

The immediate first round and restart-pinned interval use applied cluster material.
Every Prom round re-reads the endpoint, captures one range end, tries job then
component afresh and records each completed query's real update time. Successful
empty results select Prom. Backend rounds use full topology independently of H,
join at most 100 active backend tasks, merge peer history, decide any-rule missing
fallback before purge, and export only originally owner-selected addresses.
Completed backend HTTP/parse failures represent missing observations. Aggregate
completed peer/topology failures still replace the backend map before preserving
the selected reader; panic/cancel/stale/incomplete joins cannot publish a round.

Owner campaigns retain the original process token and exact applied etcd material.
A monotonic source/material/serving scope fences normal RPCs and escaped streams;
it never includes the session's own work permit. Scope expiry directly invalidates
retained authority and becomes terminal local retirement when processed. Private
cleanup remains fenced by the original process owner and still resigns/revokes the
actual acquired session after local scope withdrawal. A canceled campaign that has
not returned an acquired session can leave its unacquired lease to the existing
TTL expiry path; tests distinguish recipe creation from committed owner export.

Local data retains opaque `ElectionAuthority`; new work needs a confirmed interval
permit. Copied lease/revision/member diagnostics can only reject a contradiction
with an actual etcd observation; they never create authority. Peer records retain
full key/value/lease/create-revision tuples selected by Go's prefix parsing and
minimum revision per zone, with address deduplication. Actual Go and Rust owners
use `<prefix>[/cluster][/zone]/owner/<lease-hex>` with status host:port values and
TTL 15; Rust session presence keys are outside `/tiproxy/metric_reader`.

Backend history cold-starts on applied source/material changes and locally observed
local/peer owner replacement. Normal H refresh preserves history. A remote change
cannot retire a peer until it is locally observed; a second enumeration after the
HTTP fetch rejects a response from a replaced identity. Prom-selected data remains
independent of unused backend owners. Zone is read from committed config at backend
round entry, including zone-only updates and valid zone updates whose cluster
candidate was rejected. Old scope is withdrawn before awaiting election cleanup.
The live groups also hold real Prom and backend responses across material
withdrawal and reject their rounds without publishing obsolete history or retries.

Every captured metric snapshot and HTTP body carries source/result/serving and
selected owner provenance. Short synchronous uses lock binding, source feed, peer
observation/scope/role, local retained authority (or work permit), then overlay or
socket write. Phase uncertainty accepts already-committed HTTP output but rejects
new work; recovery cannot resurrect a prior permit. Listener exit and module Drop
withdraw eligibility before child cancellation. Bound request headers are at most
8 KiB, decoded query values 4 KiB, HTTP histories 16 MiB, and at most 100 requests
are active with a five-second handler budget. Owner enumeration caps 10,000 records,
2 KiB keys, 256-byte advertised values and 16 MiB total key/value bytes.

`collector.py` starts a fresh embedded-etcd proxy and a compiled real Go
`BackendReader` test peer for each live observation, then tears both down. The
Go peer's control API only drives test inputs and calls the existing election,
owner enumeration, backend history producer and owner HTTP consumer. Histories
cross real TCP in both directions. Logs report payload-free invariant names;
connection descriptions and ports remain in owned temporary directories.

### Staged factors and ledger consumer

`make controlplane-cpmetrics-factor-evidence` generates 95 multi-step observations
from the actual Go factor methods, then drives the Rust factor state with the same
queries, samples, clocks and counts. The Go overlay changes only clock reads;
score composition, `CanBeRouted`, `BalanceCount` and both selection methods run
unchanged. The comparison includes each score segment, advice and 63-ticket
selection distributions. The separate runtime row owns real etcd, SQL greetings,
backend/status HTTP, Prometheus HTTP, `TopologyModule`, `MetricCollector` and the
router's reservation ledger. The entrypoint also compiles isolated mutations and
requires their named observations to fail before restoring and rerunning baseline.

The public `Router::factor_report` is a diagnostic consumer and cannot reserve or
migrate a connection. Resource/Location capture/reserve remain typed Unsupported
until the subsequent selector-composition slice. Static-source empty metric
qualification and the final policy-subscription lifecycle belong to that slice;
production composition remains disabled until CP integration.

Each collector cluster issues an opaque cache lineage for its selected history.
Ordinary same-source rounds retain it despite replacement of the snapshot's round
gate. Capture/material/R replacement, backend owner/peer/zone cold starts and
selected-source switches replace it. Unused backend ownership changes preserve
Prometheus lineage. The router stores caches under stable ledger account identity,
retains sample times, and clears resource state for a replaced lineage; an ID or
newer UpdateTime cannot authorize reuse. A snapshot's final current-authority
closure still guards evaluation and cache commit.

Cold starts across authority/source changes are an explicit difference from Go's
long-lived factor objects. With healthy I/O, Prometheus range data restores the
cache at the first new completed round; backend CPU needs a valid pair at least
one second apart. Empty/missing samples and unavailable I/O retain their specified
Go defaults, so no recovery bound is claimed during failed acquisition. Within a
lineage, global query expiry, per-sample cache expiry, missing defaults and pending
connection extrapolation follow the actual Go observations exactly.
