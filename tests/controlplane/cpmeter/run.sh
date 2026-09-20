#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../../.."
output="${CPMETER_OUTPUT:-$(mktemp -d)}"
mkdir -p "$output"
build_dir=$(mktemp -d)
trap 'rm -rf "$build_dir"' EXIT
"${GO:-go}" build -o "$build_dir/go-observer" ./tests/controlplane/cpmeter/go-observer
"${CARGO:-cargo}" build --locked --manifest-path rust/Cargo.toml -p control-meter --example observer
target_dir=$("${CARGO:-cargo}" metadata --locked --no-deps --format-version 1 --manifest-path rust/Cargo.toml | "${PYTHON:-python3}" -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')
"${PYTHON:-python3}" tests/controlplane/cpmeter/compare.py --go "$build_dir/go-observer" --rust "$target_dir/debug/examples/observer" --output "$output"
printf 'Metering evidence: %s\n' "$output"
