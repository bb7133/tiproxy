# CP-ROUTE 222-2A: factor pairs and physical arrival

Run `make controlplane-cproute-balance-evidence` with the pinned Rust toolchain
and repository Go toolchain. CI runs this after the existing migration ledger
gate. The entrypoint owns and stops its embedded etcd fixture.

This slice adds actual factor-driven **preparation** to the isolated
`MigrationSimulation`. It does not run a scheduler or admit commands by itself.
Every prepared entry goes through the existing final bounded-offer fence.
Production routing, failover-close effects and observational shadow remain
later slices.

## Required evidence

- Actual Go `FactorBasedBalance.BackendsToBalance` executes over the existing
  95 factor histories plus nine focused balance cases. Rust compares the exact
  source, target, rate and reason. The only overlay replaces clock reads; no
  score, advice or pair-selection result is injected. This retains the existing
  score, routeability and selection-weight comparisons.
- Unique actionable pairs cover zero physical connections, zero score after
  outgoing transfer, incoming-only ownership, next-worst fallback, inverted
  priority, negative advice at an equal higher-priority segment, strict
  `0.0001` cutoff and clamped equal total scores. Unspecified Go tie ordering
  is not asserted as a port/map ordering contract.
- `arrival.tsv` drives actual Go `Group.RehydrateConn`, `redirectConn` and
  terminal handlers, then the Rust ledger. `arrival.expected.tsv` is captured
  Go output and rechecked on every run. Its 21 rows distinguish session identity
  from physical arrival: connection 3 completes before 1, successful migration
  appends to the target's tail, failure/rejection retains order, and close while
  pending removes physical and score ownership before a late result.
- Runtime tests use the real namespace config/topology/health source handles.
  A removed-but-physically-active source remains scoreable. Fail-list Status
  overrides obey the all-current-routeable-observed-healthy safeguard.
- The owned real etcd/greeting/status/collector test selects the Resource pair,
  issues and settles a local admission, then retires the collector after six
  nonempty queries were read but before the final metric fence. It must discard
  those values and their cache lineage and choose the opposite locality pair.
  Configuration revocation still rejects preparation and final issuance.
- Sixteen compiling mutations must fail the named pair, arrival or runtime
  regression, followed by a restored baseline. A compiler error is not a kill.

A cross-keyspace pair refusal still retains the factor history computed before
Go's admission guard; it changes no connection counts. A runtime regression
checks the first Status rate survives that refusal and a later population drop.

Preparation commits factor cache history only after current C/R/H and metric
authority checks; it changes no session counts. The ledger alone owns physical
order. Source vectors include pending redirects until success; incoming
redirects are absent until they physically arrive. The next slice will apply
pending/force-close/cooldown eligibility and accepted-only rate quotas while
walking this order.

The later 222-2B worker must preserve the accepted contract: 10ms ticks with
missed-tick skipping, Go's rate thresholds, 3s failure cooldown, first failover
activation time, retryable bounded close admission and later observed close,
and cancellation/join. The explicit extreme-rate difference remains a 1ns
minimum interval and at most the physical source population per round. These
worker behaviors are not claimed by this foundation slice.

For local acceleration only, `CPROUTE_BALANCE_TARGET_SEED` may name an **idle**
Cargo target. The mutation runner clones it to its own temporary directory;
it never writes or builds in the seed.
