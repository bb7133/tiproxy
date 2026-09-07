# CP-ROUTE input projection evidence

This gate compares the normalized routing policy and namespace-binding inputs
from the production Go configuration model with `control-config`'s immutable
Rust projection. It covers factor policy, routing/group policy, stable labels,
failed-backend normalization, failover timeout, namespace order and identity,
static backend endpoints, and backend TLS policy.

The observer contains no topology, health, resource, or connection-accounting
authority. Those remain separate generation-fenced inputs to CP-ROUTE. The
legacy control protocol also remains outside the new `control-routing` domain
crate; only the edge adapter converts route metadata to and from wire messages.
`proto-wire-files.txt` freezes the three existing bridge files that may still
handle route envelopes; any expansion or domain leak makes the gate fail.

Run:

```bash
make controlplane-cproute-evidence
```

The gate first requires byte-exact Go/Rust JSON equality for both the default
and a fully populated custom input, then changes the Rust balance-policy
observation and requires the comparator to reject it.


## Pure group primitives (CP-ROUTE #220, head 220-1)

The same gate also feeds `groups/match.tsv` and `groups/port.tsv` to the
production Go `Group` / private `portConflictDetector` through a package-local
test observer, and to the production Rust `GroupMatcher` / `PortRoutes` through
an example. The 52 matching and 20 sequential port observations must be
byte-identical. Observers only decode fixtures and serialize method results.
They do not implement alternate group policies.

The matching table fixes these Go details:

- All and port `Group.Match` predicates return true. A port router dispatches
  through the separate port table, never by scanning that predicate.
- CIDR matching selects the supplied client or proxy address; a missing proxy
  address does not fall back. The calling layer supplies the peer address when
  PROXY protocol is absent. IP extraction follows `SplitHostPort` + `ParseIP`,
  so empty/service-name ports are accepted but hostnames/scoped IPs are not.
- A missing CIDR prefix means `/32`, including IPv6. Mapped IPv6 clients are
  canonicalized like Go `IPNet.Contains`; the masked network is canonicalized
  only after applying its mask. An IPv6 `::/0` does not match an IPv4 client.
- Group equality/intersection use original strings, including case and spaces;
  geometrical overlap is irrelevant. Equality keeps Go's length-plus-membership
  duplicate behavior, rather than replacing it with set or multiset equality.
- One invalid CIDR rejects construction; all/port values are not CIDR-parsed.
- Empty listener ports are ignored. Same-cluster bind replaces a group,
  different-cluster bind blocks the raw port for the whole table lifetime.
  Subsequent binds cannot heal it. A complete rebuild can restore service.

Six mutations directly edit a temporary copy of the production Rust source:
proxy fallback, raw-value trimming, default IPv6 `/128`, cross-cluster overwrite,
conflict self-healing, and removal of mapped-client canonicalization. Each must
compile/run successfully and disagree with the real Go observations; compiler
errors and crashes fail the gate. The unmodified copy and restored copy must
both agree. No repository source is mutated by the gate.

These primitives own no backend selection or reservation. The next section
covers their stateful composition. `control-routing` remains dependency-free;
production route/bridge ownership is unchanged.

The earlier config observer's `allowed_common_names` sorting/trimming is the
already accepted CP-CFG normalization shared by both observers; it is not a
claim that the production Go config layer performs that normalization itself.


## Staged selector and accounting (head 220-2)

`control-router` owns one namespace router incarnation. It captures independent
current config C, routing source R, and the exact live health overlay H for R.
It revalidates the private source-bundle identity, exact C and H/R gates after
acquiring the ledger mutex and immediately before reserve. Retained snapshots
never grant authority. Pending/rejected topology configuration can use old valid
R/H with current C; material commit revokes H synchronously until new R/H arrives.

Namespace identities are private store-minted `Arc` handles, carried unchanged
across global policy and material updates. Namespace replacement, removal and
identical re-creation mint different identities even if no consumer observed
the intermediate snapshot. They do not enter checksums, content equality,
public routing projections, or existing byte-exact observations.

Accounting owners survive source/epoch replacement, unhealthy observations and
removal while reservations or live connections remain. Each session and attempt
has an opaque router-bound identity and a checked never-reused sequence. A
terminal settles the captured accounting owner without consulting current C/R/H.
Duplicates, foreign handles, closed sessions and superseded attempts have no
counter effects. Closed sessions are removed instead of growing tombstone sets.

Supported selection is connection balance with prefer-idle/random, group
matching and one-attempt opaque-ID exclusions. Go's clamped connection factor,
raw-count migration advice, candidate set and clock-ticket weights are retained.
Production tickets use Unix microseconds with the original modulo rules; a
private seam exists solely for deterministic evidence. Rust uses stable opaque-ID
order for equal clamped scores; this is an implementation choice, not Go-exact
ordering (`sort.Slice` is unstable). Tests compare eligible sets and weights,
not the identity of a particular tied representative.

Admission and reserve intentionally require the Ready lifecycle phase;
Quiescing/Draining stop new work while existing handles can still settle. Group
and port tables are refreshed under the ledger lock only when the observed R/H
pair changes. Their cost, plus per-selection sorting, needs workload measurement
before production composition in 220-3.

The new API is **not wired to dataplane or tiproxy-rs**; the evidence gate rejects
those manifest dependencies. Resource (including the global default), location,
business-label isolation, fail lists, nonempty proxy-zone metadata and static-only
fallback return typed Unsupported before reservation. Global config acceptance
is unchanged. Static backends must later obtain authoritative health; namespace
addresses are not converted into healthy observations. Zone metadata must later
come from the Go-equivalent health observation, not be recomputed from current C.
Retry/exclusion orchestration, resource factors, redirects and production cutover
remain later work. This head does not close #220 or #147.

Evidence layers:

- `ledger/events.tsv`: 17 event rows run through the real Go RouterAdapter and
  ScoreBasedRouter, compared with Rust's production ledger. Includes pending
  retransmission, failure plus retry, duplicate/late results, new sessions and
  both pending/active close. Go bridge IDs cannot be reopened after close; rows
  mint new connections and late results retain their old assignment IDs.
- `choice/weights.tsv`: actual Go FactorBasedBalance and FactorConnCount versus
  the Rust selector's private choice function. A Go overlay changes only its
  two clock reads in a temporary source copy. Fourteen rows enumerate complete
  ticket periods, covering random 11:10 weights, prefer-idle eligibility, custom
  thresholds/rates, zero counts and 16-bit clamp ties. No alternative Go score
  or choice implementation serves as the oracle.
- Real ConfigNamespaceStore / TopologyModule / health publisher with a local
  minimal etcd Range service: watch-delivery and Range-response barriers pin
  pending, rejected and committed states; actual mutex barriers cover C, R and
  H replacement while reserve waits. Tests cover namespace ABA, lifecycle,
  CIDR rejection/refresh, retained owners, prune/reappearance, port conflicts,
  opaque exclusions and close/success races. Health is produced by the real
  module's explicitly disabled-probe policy, never fabricated from a namespace.
- The evidence gate invokes `python3 tests/controlplane/cproute/mutations.py`,
  which copies the Rust workspace to
  an isolated directory and changes production authority/ledger/selector code.
  Eight regressions must compile and complete with failed runtime tests: skipping
  C/H checks, resetting accounting on refresh, settling the latest owner,
  duplicate settlement, retaining closed authority, silent resource fallback,
  and namespace-content identity. Compilation errors or process crashes do not
  count as a kill. Baseline and restored sources must pass.

`make controlplane-cproute-evidence` requires every layer above, including all
eight selector mutations, both locally and in the hosted Rust workflow.
Also run `make lint`, `make rust-lint`, `make rust-test`, `make rust-build`, and Go
router/bridge/factor package tests. The mutation runner uses a separate target
directory and never changes repository source.
