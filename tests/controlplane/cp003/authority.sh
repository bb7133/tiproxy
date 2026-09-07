#!/usr/bin/env bash
# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
tmp_dir=$(mktemp -d)
fixture_pid=""
cleanup() {
    if [[ -n "$fixture_pid" ]]; then
        kill "$fixture_pid" 2>/dev/null || true
        wait "$fixture_pid" 2>/dev/null || true
    fi
    rm -rf "$tmp_dir"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
cd "$repo_root"
go build -o "$tmp_dir/fixture" ./tests/controlplane/cp003/go-fixture
"$tmp_dir/fixture" -connection-file "$tmp_dir/connection.json" -data-dir "$tmp_dir/etcd" >"$tmp_dir/fixture.log" 2>&1 &
fixture_pid=$!
ready=false
for _ in $(seq 1 200); do
    if [[ -s "$tmp_dir/connection.json" ]]; then ready=true; break; fi
    if ! kill -0 "$fixture_pid" 2>/dev/null; then
        cat "$tmp_dir/fixture.log" >&2
        exit 1
    fi
    sleep 0.05
done
if [[ "$ready" != true ]]; then echo 'CP-AUTHORITY fixture readiness timeout' >&2; exit 1; fi
export CP003_CONNECTION_FILE="$tmp_dir/connection.json"
cargo run --locked --quiet --manifest-path rust/Cargo.toml -p control-etcd --example cpauthority_observer
python3 tests/controlplane/cp003/authority_mutations.py
