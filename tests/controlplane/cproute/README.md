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
matching, label/status eligibility, per-group fail-list protection, and opaque-ID
exclusions. `Router::selector` owns a connection retry cycle: only NoBackend
clears prior attempts and tries once more; port conflicts preserve exclusions.
Every finish takes the exact reservation; dropping the selector closes its
session and releases pending/active accounting. Go's clamped connection factor,
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
nonempty proxy-zone metadata and static-only
fallback return typed Unsupported before reservation. Global config acceptance
is unchanged. Static backends must later obtain authoritative health; namespace
addresses are not converted into healthy observations. Zone metadata must later
come from the Go-equivalent health observation, not be recomputed from current C.
Resource factors, timed failover/redirects and production cutover
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
- `composition/eligibility.json`: 21 updates through the real Go ConfigManager,
  FactorBasedBalance and Group.Route versus production Rust eligibility, plus
  13 address-to-PodName edge cases. Covers label renaming/disabling, omitted and
  empty TOML label tables, same-address/different-cluster IDs, unhealthy and
  label-ineligible members outside the all-failed denominator, independent
  groups, exact pod/address matching and explicit exclusions. Go TOML updates
  merge labels; they cannot change a populated map back to nil. Direct synthetic
  FactorLabel.SetConfig transitions that bypass ConfigManager are not the
  accepted configuration-update contract represented by this fixture.
- `composition/retry.json`: eight events through the real Go BackendSelector,
  Group.Route and port conflict detector versus Rust Selector with real
  ConfigNamespaceStore/TopologyModule/health publication. Covers disappearance,
  reappearance, exhausted and empty cycles, conflict and recovery. Successful
  observations abort their exact attempt before the next event; separate Rust
  regressions cover retransmission, late and foreign settlement, current policy
  on unchanged R/H, and close after commit.
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
  Sixteen regressions must compile and complete with failed runtime tests: skipping
  C/H checks, resetting accounting on refresh, settling the latest owner,
  duplicate settlement, retaining closed authority, silent resource fallback,
  namespace-content identity, label/status bypass, incorrect pod matching, both
  fail-list safeguard branches, retry exclusions in its denominator, port-error
  cycle reset, and cross-session selector settlement. Fresh Go composition/retry
  outputs are asserted inside the Rust runtime tests for each mutation.
  Compilation errors or process crashes do not
  count as a kill. Baseline and restored sources must pass.

`make controlplane-cproute-evidence` requires every layer above, including all
nineteen selector mutations, both locally and in the hosted Rust workflow.
Also run `make lint`, `make rust-lint`, `make rust-test`, `make rust-build`, and Go
router/bridge/factor package tests. The mutation runner uses a separate target
directory and never changes repository source.

## Health-round locality (head 220-3 B1)

The health product carries Go `BackendHealth.Local`. `run_health_round` reads the
proxy `zone` label from its `ProxyZoneSource` exactly once at round start (Go
`checkHealth` reads the config once before the fan-out) and stamps every verdict
after collection with Go's `setLocal` rule: no/empty proxy zone marks every
backend local; otherwise only an exact `labels["zone"]` match is local. A
disabled health check publishes all-healthy with `Local=false`. Selectors consume
locality with the exact H; nothing recomputes it from the current config.

- `locality/rounds.json`: 12 config-history steps (nil labels, empty table,
  zone set/omitted/other-label/upper-case/empty, disabled rounds in between)
  over 7 backends, through the real Go `ConfigManager` + `DefaultBackendObserver.
  checkHealth` (`pkg/balance/observer/cproute_locality_evidence_test.go`) versus
  the production `run_health_round` + `ConfigNamespaceStore` zone read
  (`health_loop::tests::shared_go_locality_observation`), compared byte-for-byte.
- `locality/mutations.py`: six compiling mutations of `health_loop.rs` that a
  runtime test must kill — disabled round marks local, empty zone compared as a
  zone, case-insensitive compare, unlabelled backend local under a set zone,
  zone read after the round, zone re-read at each probe construction (killed by
  the concurrency-1 held fan-out row L7). Each run asserts the fresh Go output.

### Selector assignment locality

`control-router` copies `Local` from the selected backend's exact captured H
into the reservation, matching Go `RouterAdapter.sendAssignmentLocked` reading
`backend.Local()`. The actual Go health rule is covered by the shared locality
observation above. A proxy zone is now supported for connection policy; resource
and location factors remain separately unsupported. Static source routing is
covered by the namespace source composition below.

`control-router/src/tests/locality.rs` composes the real config source, topology
module, health loop, and selector. Disabled health always assigns `Local=false`,
including unset, matching, and mismatching proxy zones. Enabled rows use held
real SQL greeting probes: new C plus still-current old H keeps the observed
locality, later rounds change it without rotating R, an old H cannot reserve,
and already reserved metadata and settlement remain bound to the original
reservation. These rows do not insert a fabricated health map.

Three additional compiling selector mutations must fail those runtime rows:
constant true, constant false, and recomputing locality from current config.
The existing current-H authority mutation remains mandatory.

## Namespace static backend source (head 220-3 B2)

Go's `FallbackFetcher` serves a namespace from its static instance list IFF the
APPLIED backend cluster map is empty (`backendcluster.Manager.HasBackendClusters`);
the same observer probes those addresses through the empty-cluster default
network (system resolver, plain TCP, SQL greeting only — no `/status` stage
because a static backend has no IP, and no namespace TLS), and a replaced
namespace is a new observer. In Rust the mode is the topology module's applied
`RegistrationPlan` — never the pending config nor an empty/failed discovery —
published as a `ModeEpoch` whose gate is revoked BEFORE a new plan, discovery
commit or epoch is published. One `StaticBackendProducer` per namespace
incarnation composes the existing routing publisher (raw-address ids, empty
cluster name, diagnostic epoch 0), health feed/overlay and health loop; it is
parked (no probing, unroutable) in Dynamic mode, runs a fresh round on
re-activation, and is revoked synchronously on replacement/removal/teardown.
Consumers hold an opaque `BackendSourceHandle` and capture a
`BackendSourceSnapshot` (handle identity, exact mode epoch, R, H) that is
re-checked — together with the namespace incarnation at the config source —
at every side-effect boundary; `current()` ends with that same check.

- `static/modes.json`: six cluster-configuration steps through the real Go
  `Manager.syncClusters`/`HasBackendClusters` + `FallbackFetcher` +
  `StaticFetcher` over embedded etcd (`pkg/manager/backendcluster/
  cproute_static_evidence_test.go`) versus the real `TopologyModule` applied
  plan and static producer (`static_source::tests::shared_go_static_mode_observation`),
  compared byte-for-byte. Static identity = raw address (duplicates collapse,
  whitespace variants are distinct, IPv6 literal and host names verbatim). One
  step is an ACCEPTED DIVERGENCE recorded with both observations: Go commits
  per cluster (old `a` removed even though new `b` fails → empty map → static),
  Rust rejects the whole generation and retains `a` (dynamic).
- Module rows (real `TopologyModule` + real loopback SQL greeters): static list
  served with real greeting verdicts, failure and recovery; disabled health =
  all-healthy/Local=false with zero I/O; the same address in two namespaces is
  the same id in two isolated sources, held per producer; a namespace removed
  in C fails closed at the source before the run loop reconciles and an
  identical re-creation is a new producer; Static→Dynamic parks the producer
  (a held probe cannot publish), Dynamic→Static runs a fresh round; a rejected
  cluster generation keeps the last-good mode but still reconciles namespaces;
  mode identity is the exact epoch (same R/H after Static→Dynamic→Static is
  refused; revoke-before-publish closes the window; an empty dynamic
  discovery is served empty, never as the static list).
- Commit window (real `reconfigure`): with the run loop parked inside the
  Dynamic→Static window (the registration child's shutdown is held), a Dynamic
  snapshot from real discovery is already refused, nothing is capturable, and
  a consumer that captured it before waiting on a lock performs zero side
  effects after the lock is granted. Static producers are parked/activated
  BEFORE the new epoch is published, so a parked static H is withdrawn the
  instant Dynamic is visible and re-activation always yields a fresh H.
- `static/mutations.py`: eleven compiling mutations a runtime test must kill —
  mode from the pending config instead of the applied plan; namespaces
  reconciled only on accepted generations; the outgoing mode epoch revoked
  only at publish (not before the new plan/commit); static producers parked
  after the epoch publish; mode identity by value; namespace not checked at
  the source; inactive static keeps probing; empty dynamic discovery falls
  back to static; producer reused across incarnations; static health
  fabricated without a probe; static backend runs the status stage.


### Router consumption of the applied source

`control-router` binds a `BackendSourceHandle` to its namespace incarnation and
retains the opaque `BackendSourceSnapshot` in each candidate. It checks source
authority at capture completion, after acquiring the real ledger mutex, and
immediately before reserving. Current C, router identity, namespace incarnation,
owner and lifecycle remain independent checks. The raw config cluster list no
longer blocks capture, and `Unsupported::StaticFallback` is removed. A newly
replaced namespace must have its producer reconciled before a new router binds.
Resource/location factors and production dataplane wiring remain gated.

`control-router/src/tests/sources.rs` uses real topology/health producers:
static greeting failure/recovery changes actual reservation eligibility;
disabled health uses no SQL I/O and keeps identical raw IDs isolated between
namespaces; pending/rejected cluster material keeps the applied static source
with current policy; empty applied Dynamic never falls back; mode cycles create
fresh H and old reservations settle only their original accounts. A skipped
static namespace removal/recreation while the ledger is locked rejects the old
router, preserves the other namespace, and produces a fresh router/source.

The mode commit-window row establishes a real registration lease through tonic
LeaseGrant, streaming LeaseKeepAlive and KV Put, then holds LeaseRevoke inside
`stop_children`. C_new is captured before delivering the module notification.
The outgoing mode is revoked while that same C and old dynamic R/H remain
current, verified both before and after the reserve worker runs. Releasing the
real ledger mutex inside this window must refuse the candidate without creating
an accounting record. A private test signal marks the actual lock attempt, so
moving validation before the lock cannot pass due to thread scheduling.

Four additional compiling selector mutations must fail these rows: omit mode
validation while retaining R/H checks; validate only before the ledger lock;
use raw C emptiness to block the still-applied Dynamic source; bind every
namespace to the default source. The first two must fail the real lease-revoke
window row specifically. The full entry contains 46 mutations (6 group,
23 selector/source, 6 locality, 11 static-producer).

### Opt-in Resource/Location reservations

`make controlplane-cproute-resource-evidence` adds actual factor reservations,
automatic query lifetimes, static-empty qualification and missing-metric source
windows. See [resource/README.md](resource/README.md). The original entrypoint
and its 46 mutations remain unchanged; production composition remains gated.
