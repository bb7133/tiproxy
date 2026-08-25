# Rust CI and supply-chain policy

The Rust jobs use the repository's pinned toolchain and always pass `--locked`.
GitHub Actions are pinned to full commit SHAs, and the tool installers use exact
crate versions with the crates' published lockfiles. CI never pipes a remote
script into a shell.

The quality job checks formatting, Clippy with warnings denied, unit tests, and
doc tests. Supply-chain checks use `cargo-audit` 0.22.2 and `cargo-deny` 0.20.2
to reject vulnerable or yanked dependencies, duplicate versions, wildcard
requirements, unapproved licenses, and unknown registries or Git sources.
Negative tests deliberately inject one violation for each gate and must observe
the expected diagnostic. Their fixtures live outside the production workspace.

Release jobs run natively on Linux amd64 and arm64, build with `--locked`,
execute each artifact's `--version`, verify the exact version/commit/build-time
string, and upload the stripped binary plus its SHA-256 checksum.

## Vulnerability exceptions

Exceptions are temporary risk acceptances, not permanent allow-list entries.
To add one:

1. Add the advisory ID to `advisories.ignore` in both `.cargo/audit.toml` and
   `deny.toml`.
2. Add a matching `[[exceptions]]` entry to
   `vulnerability-exceptions.toml` with exactly these fields:
   - `advisory`: a `RUSTSEC-YYYY-NNNN` ID;
   - `owner`: the accountable GitHub `@handle` or `@team`;
   - `rationale`: at least 20 characters describing bounded exposure and the
     remediation plan;
   - `expires`: an ISO date after the day CI runs.
3. Link the review to the remediation issue and remove all three entries before
   the expiry date.

`check_vulnerability_exceptions.py` rejects expired, malformed, duplicate, or
out-of-sync exceptions before either scanner runs.
