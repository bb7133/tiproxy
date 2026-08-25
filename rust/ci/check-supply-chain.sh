#!/usr/bin/env bash

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)

command -v cargo-audit >/dev/null || {
    echo "cargo-audit is required; run 'make rust-install-tools'" >&2
    exit 1
}
command -v cargo-deny >/dev/null || {
    echo "cargo-deny is required; run 'make rust-install-tools'" >&2
    exit 1
}

python3 "$repo_root/rust/ci/check_vulnerability_exceptions.py"
"$repo_root/rust/ci/run-cargo-audit.sh"
cargo deny --manifest-path "$repo_root/rust/Cargo.toml" \
    --config "$repo_root/rust/deny.toml" check advisories bans licenses sources
