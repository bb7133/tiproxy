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
if [[ "$ready" != true ]]; then echo 'CP-METRIC-APPLIED fixture readiness timeout' >&2; exit 1; fi
export CP003_CONNECTION_FILE="$tmp_dir/connection.json"
cargo test --locked --manifest-path rust/Cargo.toml -p control-external --lib metric_
cargo test --locked --manifest-path rust/Cargo.toml -p control-topology --lib metric_
cargo test --locked --manifest-path rust/Cargo.toml -p control-topology --lib metric_module_real_etcd_cleanup_and_delayed_http -- --ignored --nocapture
python3 tests/controlplane/cpmetrics/applied_mutations.py
