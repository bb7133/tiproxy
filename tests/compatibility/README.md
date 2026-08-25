# TiProxy driver compatibility contract

This directory freezes the client-facing compatibility contract used to compare
the Go and Rust dataplanes. The contract is intentionally data, not test-runner
code: the integration topology consumes the manifest and implements each
`workload_id` once for every listed driver adapter.

## Files

- `driver-matrix.v1.json` pins the drivers and their build environments, records
  capability support, selects the cases that block canary and cutover, and links
  every case to stable IDs in `docs/design/rust-dataplane-parity.md`.
- `workloads.v1.json` defines the minimal, language-neutral operations and
  assertions. Driver adapters translate connection options without changing the
  assertions.
- `fixtures/local-infile.csv` is the only file a positive `LOCAL INFILE` case is
  allowed to expose.
- `matrix_test.go` is the semantic validator. It checks IDs and references and
  enforces positive and negative coverage for every capability and driver.

Run the validator with:

```sh
go test ./tests/compatibility
```

The validator does not open a database connection. Live execution belongs to
the integration topology so the same TiDB, certificate authority, proxy build,
and fault injection are used for the Go and Rust dataplanes.

## Execution contract

The live runner must provide the environment variables declared in
`driver-matrix.v1.json`. It must execute each case twice, once with
`TIPROXY_DATAPLANE=go` and once with `TIPROXY_DATAPLANE=rust`, and store:

1. the matrix and workload version;
2. the TiProxy and TiDB image digests and Git commit;
3. the driver artifact version and runtime image digest;
4. the advertised, requested, and negotiated capability flags;
5. the normalized outcome (`success`, `rejection`, or `error`), MySQL error
   code/SQLSTATE when present, and transport/TLS error class otherwise; and
6. the output assertions and duration.

An adapter must fail the case if a requested capability is not negotiated. A
successful query after a silent fallback is therefore a failure, not a pass.
Transport failures are acceptable only where the manifest explicitly requires
one and the TiProxy log contains the expected stable error class.

## Blocking policy

`blocking` cases gate both canary expansion and cutover. `non_blocking` cases
document intentionally unsupported combinations, but they still have to return
the explicit configuration/protocol error named by the case. A non-blocking
case must never silently become a successful uncompressed, unencrypted, or
text-protocol session.

The compatibility contract is frozen only after the approval records in the
manifest contain both a product owner and a MySQL protocol owner. Until then,
the file is technically complete but cannot be used to authorize cutover.

## Updating the matrix

Changes require a new `matrix_version`, updated source URLs when a dependency is
repinned, validation, and owner re-approval. Do not change an existing case ID's
meaning. Add a new ID and retire the old case with an explanation instead.
