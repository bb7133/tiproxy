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

cleanup_fixture() {
    if [[ -n "$fixture_pid" ]]; then
        kill -9 "$fixture_pid" 2>/dev/null || true
        wait "$fixture_pid" 2>/dev/null || true
        fixture_pid=""
    fi
}

cleanup() {
    cleanup_fixture
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
            echo "CP-CFG fixture exited before writing $path" >&2
            return 1
        fi
        sleep 0.05
    done
    echo "timed out waiting for CP-CFG fixture file $path" >&2
    return 1
}

dump_go() {
    local mode=$1
    local output=$2
    CP004_DUMP_TOML="$mode" "$tmp_dir/go-observer" >"$output"
}

dump_rust() {
    local mode=$1
    local output=$2
    shift 2
    CP004_DUMP_TOML="$mode" "$@" cargo run --locked --quiet \
        --manifest-path rust/Cargo.toml -p control-config \
        --example cp004_observer >"$output"
}

expect_cmp_failure() {
    local baseline=$1
    local candidate=$2
    local label=$3
    set +e
    cmp -s "$baseline" "$candidate"
    local status=$?
    set -e
    if [[ "$status" -eq 0 ]]; then
        echo "CP-CFG $label mutation was not killed" >&2
        return 1
    fi
}

run_live() {
    local label=$1
    shift
    local connection="$tmp_dir/$label-connection.json"
    local status=0
    "$tmp_dir/go-fixture" \
        -connection-file "$connection" \
        -data-dir "$tmp_dir/$label-etcd" &
    fixture_pid=$!
    wait_for_file "$connection"
    CP004_CONNECTION_FILE="$connection" "$@" cargo run --locked --quiet \
        --manifest-path rust/Cargo.toml -p control-config \
        --example cp004_live >"$tmp_dir/$label.json" || status=$?
    cleanup_fixture
    return "$status"
}

expect_live_failure() {
    local label=$1
    shift
    set +e
    run_live "$label" "$@"
    local status=$?
    set -e
    if [[ "$status" -eq 0 ]]; then
        echo "CP-CFG $label mutation was not killed" >&2
        return 1
    fi
    cleanup_fixture
}

cd "$repo_root"
go build -o "$tmp_dir/go-observer" ./tests/controlplane/cp004/go-observer
go build -o "$tmp_dir/go-fixture" ./tests/controlplane/cp003/go-fixture

for mode in default partial full; do
    dump_go "$mode" "$tmp_dir/go-$mode.toml"
    dump_rust "$mode" "$tmp_dir/rust-$mode.toml" env
    cmp "$tmp_dir/go-$mode.toml" "$tmp_dir/rust-$mode.toml"
done

CP004_DUMP_NAMESPACE=1 "$tmp_dir/go-observer" >"$tmp_dir/go-namespace.json"
CP004_DUMP_NAMESPACE=1 cargo run --locked --quiet \
    --manifest-path rust/Cargo.toml -p control-config \
    --example cp004_observer >"$tmp_dir/rust-namespace.json"
cmp "$tmp_dir/go-namespace.json" "$tmp_dir/rust-namespace.json"

dump_rust full "$tmp_dir/rust-full-mutated.toml" env CP004_MUTATE_SKIP_PROJECTION=1
expect_cmp_failure "$tmp_dir/go-full.toml" "$tmp_dir/rust-full-mutated.toml" "field-projection"

run_live live env
expect_live_failure generation env CP004_MUTATE_GENERATION_SKIP=1
expect_live_failure invalid env CP004_MUTATE_INVALID_OVERWRITE=1
expect_live_failure lease env CP004_MUTATE_LEASE_ATTACHED=1
expect_live_failure old-owner env CP004_MUTATE_OLD_OWNER_WRITE=1

echo "CP-CFG/NS differential and real-etcd evidence passed"
