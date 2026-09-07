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
