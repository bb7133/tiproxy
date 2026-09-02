#!/usr/bin/env bash
# Copyright 2026 PingCAP, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
tmp_dir=$(mktemp -d)
fixture_pid=""

cleanup() {
    if [[ -n "$fixture_pid" ]]; then
        kill -9 "$fixture_pid" 2>/dev/null || true
        wait "$fixture_pid" 2>/dev/null || true
    fi
    rm -rf "$tmp_dir"
}
trap cleanup EXIT INT TERM

wait_for_file() {
    local path=$1
    for _ in $(seq 1 200); do
        if [[ -s "$path" ]]; then
            return 0
        fi
        if ! kill -0 "$fixture_pid" 2>/dev/null; then
            echo "CP-ETCD fixture exited before writing $path" >&2
            return 1
        fi
        sleep 0.05
    done
    echo "timed out waiting for CP-ETCD fixture file $path" >&2
    return 1
}

run_rust_observer() {
    local output=$1
    shift
    CP003_CONNECTION_FILE="$tmp_dir/connection.json" "$@" \
        cargo run --locked --quiet --manifest-path rust/Cargo.toml \
        -p control-etcd --example cp003_observer >"$output"
}

compare() {
    local candidate=$1
    go run ./tests/controlplane/differential/cmd/controlplane-differential \
        -mode compare -baseline "$tmp_dir/go.json" -candidate "$candidate"
}

cd "$repo_root"
go build -o "$tmp_dir/go-observer" ./tests/controlplane/cp003/go-observer
go build -o "$tmp_dir/go-fixture" ./tests/controlplane/cp003/go-fixture
"$tmp_dir/go-observer" -data-dir "$tmp_dir/go-etcd" >"$tmp_dir/go.json"

"$tmp_dir/go-fixture" \
    -connection-file "$tmp_dir/connection.json" \
    -data-dir "$tmp_dir/rust-etcd" &
fixture_pid=$!
wait_for_file "$tmp_dir/connection.json"

run_rust_observer "$tmp_dir/rust.json" env
compare "$tmp_dir/rust.json"

run_rust_observer "$tmp_dir/rust-mutated-retire.json" env CP003_MUTATE_TRANSIENT_RETIRE=1
set +e
compare "$tmp_dir/rust-mutated-retire.json"
status=$?
set -e
if [[ "$status" -ne 1 ]]; then
    echo "CP-ETCD transient-retirement mutation was not killed (status=$status)" >&2
    exit 1
fi

run_rust_observer "$tmp_dir/rust-mutated-lease.json" env CP003_MUTATE_LEASE_REUSE=1
set +e
compare "$tmp_dir/rust-mutated-lease.json"
status=$?
set -e
if [[ "$status" -ne 1 ]]; then
    echo "CP-ETCD lease-reuse mutation was not killed (status=$status)" >&2
    exit 1
fi
