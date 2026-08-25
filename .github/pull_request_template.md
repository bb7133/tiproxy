<!--

Thank you for contributing to TiProxy!

PR Title Format:
1. pkg [, pkg2, pkg3]: what's changed
2. *: what's changed

-->

### What problem does this PR solve?
<!--

Please create an issue first to describe the problem.

There MUST be one line starting with "Issue Number:  " and 
linking the relevant issues via the "close: #xxx" or "ref: #xxx".

For more info, check https://pingcap.github.io/tidb-dev-guide/contribute-to-tidb/contribute-code.html#referring-to-an-issue.

-->

Issue Number: close #xxx

Problem Summary:

What is changed and how it works:

### Check List

Tests <!-- At least one of them must be included. -->

- [ ] Unit test
- [ ] Integration test
- [ ] Manual test (add detailed scripts or steps below)
- [ ] No code

Notable changes

- [ ] Has configuration change
- [ ] Has HTTP API interfaces change
- [ ] Has tiproxyctl change
- [ ] Other user behavior changes

Dataplane parity drift (choose one when monitored Go dataplane files change)

- [ ] Not applicable: only comments, formatting, or `*_test.go` files changed
- [ ] Updated `docs/design/rust-dataplane-parity.md` and the protocol corpus when required
- [ ] Added an exact-hash declaration under `.github/parity-no-impact/` and obtained CODEOWNERS approval
- [ ] Ran `make parity-drift PARITY_DRIFT_BASE=<target-base> PARITY_DRIFT_HEAD=HEAD`

### Release note

<!-- compatibility change, improvement, bugfix, and new feature need a release note -->

Please refer to [Release Notes Language Style Guide](https://pingcap.github.io/tidb-dev-guide/contribute-to-tidb/release-notes-style-guide.html) to write a quality release note.

```release-note
None
```
