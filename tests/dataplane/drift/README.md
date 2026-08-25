# Go/Rust dataplane parity drift gate

This gate prevents a Go dataplane change from bypassing the Rust parity
manifest and protocol corpus during the rewrite. It is a semantic Git-diff
check: Go comments, formatting, and `*_test.go` changes do not trigger it, while
production declarations and expressions do.

## CI usage

The repository's CI entry point is the Make target:

```sh
make parity-drift PARITY_DRIFT_BASE=origin/main PARITY_DRIFT_HEAD=HEAD
```

The checker evaluates every monitored semantic change against
`watch-policy.json`:

- command and error-source changes need a matching parity-manifest row change
  and a matching corpus case/material change;
- config, metric, routing, and other dataplane changes need a matching
  parity-manifest row change; and
- a reviewed no-impact declaration may replace those artifacts for the exact
  before/after semantic hashes it names.

The failure output names the file, behavior area, missing artifact, accepted
manifest prefixes, and semantic hashes. Use `-mode hashes` to print a
declaration-ready inventory:

```sh
go run ./tests/dataplane/drift/cmd/drift \
  -mode hashes -base origin/main -head HEAD
```

The checker uses only the Go standard library and local Git objects. It does
not download or execute remote scripts.

## No-impact declarations

A semantically changed production file can be classified as behavior-neutral
with `.github/parity-no-impact/<id>.json`. The declaration must list the exact
base/head semantic SHA-256 values printed by the checker, explain why observable
MySQL/config/routing/metrics behavior cannot change, and link a code-owner
review. `.github/CODEOWNERS` protects the declaration directory; branch
protection must require code-owner reviews.

Declarations are narrow waivers, not labels. A later semantic edit changes the
hash and invalidates the waiver automatically. Declarations cannot waive a
different path, a test failure, or a malformed policy/manifest/corpus.

## Weekly report

Run:

```sh
tests/dataplane/drift/report-weekly.sh
```

With no arguments the script reads the audited Go commit from
`docs/design/rust-dataplane-parity.md` and compares it with `HEAD`. Optional
first and second arguments override the base and head revisions. The report is
Markdown and exits nonzero when drift is outstanding, so the scheduler can
publish the output and alert its owner.

## Gate retirement

Remove the gate only after all of the following are true:

1. the Go SQL listener/dataplane path under `pkg/proxy` is deleted or cannot be
   selected in any supported build/configuration;
2. the Rust dataplane is the sole production owner of frontend/backend MySQL
   sockets and every non-retired P0/P1 parity row is `PARITY-VERIFIED`;
3. rollback no longer starts the Go dataplane; and
4. the TiProxy product owner and MySQL protocol owner approve a PR that retires
   the gate, manifest-update checklist, and weekly schedule together.

Do not retire it merely because a cutover flag defaults to Rust or because no
drift was reported for a period of time.
