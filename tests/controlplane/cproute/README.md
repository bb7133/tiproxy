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

These primitives own no backend selection or reservation. Stateful group
retention/refresh, exact config/routing/health source capture, assignment
accounting, factor policy, and production cutover remain later #220/#147 work.
The existing production route/bridge ownership is unchanged; `control-routing`
continues to have no dependencies and the lockfile is unchanged.

The earlier config observer's `allowed_common_names` sorting/trimming is the
already accepted CP-CFG normalization shared by both observers; it is not a
claim that the production Go config layer performs that normalization itself.
