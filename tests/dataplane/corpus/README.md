# TiProxy dataplane protocol corpus

This directory is the language-neutral oracle for observable Go dataplane
behavior. It contains only synthetic traffic. Production captures, credentials,
and customer SQL are prohibited.

## Layout

- `schema.json` defines the versioned metadata contract.
- `v1/manifest.json` indexes stable cases and expected behavior.
- `v1/cases/*.trace.gz` contains deterministic gzip-compressed binary traces.
- `cmd/corpus` is the Go oracle exporter, validator, and differential comparator.

Every uncompressed trace uses this little-endian container format:

```text
8 bytes  magic "TPXCRP1\n"
u32      record count
repeat record count times:
  u8     direction (1 client->proxy, 2 proxy->client,
                    3 backend->proxy, 4 proxy->backend)
  u64    byte length N
  N      raw MySQL wire bytes, including physical packet headers
```

The manifest records negotiated capabilities, initial state, direction, physical
packet counts, Go source/test provenance, expected effects, terminal state,
status flags, and errors. `parity_ids` link cases to
`docs/design/rust-dataplane-parity.md`; they are not redefined here.

## Regenerate and validate

Run commands from the repository root:

```bash
go run ./tests/dataplane/corpus/cmd/corpus -mode generate
go run ./tests/dataplane/corpus/cmd/corpus -mode check
go test ./tests/dataplane/corpus/...
```

`-mode check` validates every trace and regenerates the corpus into a temporary
directory. Any file-list or byte difference fails, so two consecutive generator
runs must be identical.

## Differential consumers

The production Rust consumer and sharded CI comparator live in
`tests/dataplane/differential`; see its README for the payload-free observation
schema, first-divergence report, mutation self-check, and parity coverage gate.
The commands below remain useful for validating a standalone final-result
observation against the corpus schema.

A Go or Rust consumer writes observations using the schema's
`observation_set` definition. To create a complete expected-output skeleton:

```bash
go run ./tests/dataplane/corpus/cmd/corpus -mode expected \
  -implementation rust > /tmp/rust-observed.json
```

After the implementation replaces the expected fields with its actual results,
compare it with the oracle:

```bash
go run ./tests/dataplane/corpus/cmd/corpus -mode compare \
  -observed /tmp/rust-observed.json
```

Unknown, missing, duplicate, or behaviorally different cases fail with the case
ID and exact expected/actual values. `TestComparatorDetectsMutatedImplementation`
keeps this drift detection itself under test.

## Adding a case

1. Add the case to `internal/corpus.Build` using deterministic, synthetic bytes.
2. Link every relevant parity ID and current Go source/test.
3. Regenerate and run `-mode check` plus the package tests.
4. Update the compatibility matrix if the behavior is driver-visible.

The v1 files are immutable inputs to differential testing. A breaking metadata
or container change requires `v2/` and an incremented `schema_version`.
