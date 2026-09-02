# Control-plane parity evidence

This directory freezes the Go control-plane oracle for the incremental
single-process Rust migration.

- `contracts.v1.json`: contract owners, source/test anchors, observed fields,
  Rust handoffs, fault bindings, and exact legacy bridge inventory.
- `fault-scenarios.v1.json`: deterministic failure/restart scenario vocabulary.
- `schema/`: stable JSON formats for catalogs and differential observations.
- `internal/contract/`: strict validation, normalization, and first-divergence
  comparison.
- `differential/`: CLI and synthetic comparator self-test fixtures.

Run the gates:

```bash
make controlplane-contracts
make controlplane-differential-self-test
go test ./tests/controlplane/...
```

Compare paired real observations from a later migration slice:

```bash
make controlplane-differential \
  CONTROLPLANE_BASELINE=/path/to/go-observations.json \
  CONTROLPLANE_CANDIDATE=/path/to/rust-observations.json
```

The `testdata` observations are deliberately synthetic. They prove comparator
behavior only and must never be cited as Go/Rust production parity evidence.

Observation state is a public semantic projection. Do not record raw MySQL
packets, SQL text, authentication material, credentials, or arbitrary payloads.
The validator rejects secret-bearing keys and overlong strings.
