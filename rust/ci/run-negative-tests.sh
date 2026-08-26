#!/usr/bin/env bash

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
export CARGO_TERM_COLOR=never
export NO_COLOR=1

expect_failure() {
    local name=$1
    local pattern=$2
    shift 2
    local log="$scratch/${name}.log"
    if "$@" >"$log" 2>&1; then
        echo "negative test '$name' unexpectedly passed" >&2
        return 1
    fi
    if ! grep -F "$pattern" "$log" >/dev/null; then
        echo "negative test '$name' failed for the wrong reason; expected '$pattern'" >&2
        sed -n '1,160p' "$log" >&2
        return 1
    fi
    echo "negative test '$name' detected the intended failure"
}

copy_workspace() {
    local name=$1
    mkdir -p "$scratch/$name"
    cp -R "$repo_root/rust" "$scratch/$name/rust"
    rm -rf "$scratch/$name/rust/target"
}

insert_dependency() {
    local manifest=$1
    local dependency=$2
    python3 - "$manifest" "$dependency" <<'PY'
import pathlib
import sys

manifest = pathlib.Path(sys.argv[1])
dependency = sys.argv[2]
contents = manifest.read_text()
needle = "[dependencies]\n"
if needle not in contents:
    raise SystemExit(f"dependency insertion point not found in {manifest}")
manifest.write_text(contents.replace(needle, f"{needle}{dependency}\n", 1))
PY
}

copy_workspace formatting
printf '\npub fn deliberately_unformatted( )->u8{1}\n' \
    >>"$scratch/formatting/rust/crates/mysql-wire/src/lib.rs"
expect_failure formatting "Diff in" cargo fmt --all \
    --manifest-path "$scratch/formatting/rust/Cargo.toml" -- --check

copy_workspace clippy
printf '\n/// Deliberately violates the unused-variable lint.\npub fn deliberate_clippy_failure() {\n    let unused_value = 1;\n}\n' \
    >>"$scratch/clippy/rust/crates/mysql-wire/src/lib.rs"
expect_failure clippy "unused variable" env CARGO_TARGET_DIR="$scratch/clippy/target" \
    cargo clippy --locked --workspace --all-targets --all-features \
    --manifest-path "$scratch/clippy/rust/Cargo.toml" -- -D warnings

copy_workspace stale-lockfile
insert_dependency "$scratch/stale-lockfile/rust/crates/tiproxy-rs/Cargo.toml" \
    'forbidden-license = { path = "../../ci/fixtures/forbidden-license" }'
expect_failure stale-lockfile "lock file" env CARGO_TARGET_DIR="$scratch/stale-lockfile/target" \
    cargo check --locked --workspace --manifest-path "$scratch/stale-lockfile/rust/Cargo.toml"

copy_workspace license
insert_dependency "$scratch/license/rust/crates/tiproxy-rs/Cargo.toml" \
    'forbidden-license = { path = "../../ci/fixtures/forbidden-license" }'
cargo generate-lockfile --manifest-path "$scratch/license/rust/Cargo.toml"
expect_failure license "GPL-3.0-only" cargo deny \
    --manifest-path "$scratch/license/rust/Cargo.toml" \
    --config "$repo_root/rust/deny.toml" check licenses

copy_workspace vulnerability
insert_dependency "$scratch/vulnerability/rust/crates/tiproxy-rs/Cargo.toml" 'time = "=0.1.43"'
cargo generate-lockfile --manifest-path "$scratch/vulnerability/rust/Cargo.toml"
expect_failure vulnerability "RUSTSEC-2020-0071" cargo audit \
    --file "$scratch/vulnerability/rust/Cargo.lock" --deny warnings \
    --target-arch x86_64 --target-arch aarch64 --target-os linux

copy_workspace expired-exception
python3 - "$scratch/expired-exception/rust" <<'PY'
import pathlib
import sys

rust_dir = pathlib.Path(sys.argv[1])
for path in [rust_dir / ".cargo" / "audit.toml", rust_dir / "deny.toml"]:
    path.write_text(path.read_text().replace("ignore = []", 'ignore = ["RUSTSEC-2020-0071"]', 1))
(rust_dir / "vulnerability-exceptions.toml").write_text(
    """schema_version = 1
[[exceptions]]
advisory = "RUSTSEC-2020-0071"
owner = "@security-team"
rationale = "A deliberately expired negative-test exception."
expires = 2020-01-01
"""
)
PY
expect_failure expired-exception "expired on 2020-01-01" python3 \
    "$repo_root/rust/ci/check_vulnerability_exceptions.py" \
    --exceptions "$scratch/expired-exception/rust/vulnerability-exceptions.toml" \
    --audit-config "$scratch/expired-exception/rust/.cargo/audit.toml" \
    --deny-config "$scratch/expired-exception/rust/deny.toml" \
    --today 2026-01-01
