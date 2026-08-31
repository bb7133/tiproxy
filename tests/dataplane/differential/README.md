# Go/Rust dataplane differential runner

This harness replays the immutable, synthetic Go oracle in
`tests/dataplane/corpus/v1` through the merged Rust wire, handshake, command,
response, prepared-statement, migration-result, and session-FSM seams. It does
not copy the manifest's expected result into the Rust observation.

The Go side owns the comparison contract:

- every selected case and record must exist in manifest order;
- direction, initial sequence, logical payload length, and physical packet
  count must match the Go-generated trace metadata;
- the final Rust state, outcome, server status, and error must match the Go
  oracle; and
- the first mismatch is emitted as JSON with `case_id`, zero-based
  `packet_index`, field, expected/observed values, and the Go/Rust effect
  summaries available at that boundary.

Only payload-free metadata and bounded parser/FSM effect names are emitted.
Random salt bytes, connection IDs, timing, addresses, and SQL/auth payloads are
never compared or printed. The v1 manifest and trace files remain read-only; a
breaking oracle change requires a new corpus version.

## Local commands

Run the complete corpus as one shard:

```bash
make dataplane-differential DIFFERENTIAL_SHARD_INDEX=0 DIFFERENTIAL_SHARD_COUNT=1
```

Run the same four shards used by CI:

```bash
for shard in 0 1 2 3; do
  make dataplane-differential \
    DIFFERENTIAL_SHARD_INDEX="$shard" \
    DIFFERENTIAL_SHARD_COUNT=4
done
```

Prove that a known Rust final-state mutation is rejected with exact case,
packet, state, and effect evidence:

```bash
make dataplane-differential-mutation
```

Validate bidirectional parity coverage:

```bash
make dataplane-differential-coverage
```

## Parity coverage policy

Every ID parsed from `docs/design/rust-dataplane-parity.md` must be in exactly
one of these sets:

1. referenced by at least one v1 corpus case; or
2. listed in `parity-exclusions.json` with a concrete reason explaining why
   the behavior needs a live socket, control-plane actor, process lifecycle,
   configuration/filesystem state, or another non-corpus harness.

The gate also rejects corpus IDs absent from the manifest, exclusion IDs absent
from the manifest, and stale exclusions for newly covered IDs. Therefore a new
parity row cannot silently bypass differential coverage.
