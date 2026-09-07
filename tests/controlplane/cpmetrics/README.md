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
