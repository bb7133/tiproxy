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
            echo "CP-002 Go fixture exited before writing $path" >&2
            return 1
        fi
        sleep 0.05
    done
    echo "timed out waiting for CP-002 fixture file $path" >&2
    return 1
}

start_fixture() {
    local generation=$1
    local addr=$2
    local connection="$tmp_dir/connection-$generation.json"
    local observation="$tmp_dir/go-$generation.json"
    "$tmp_dir/go-fixture" \
        -addr "$addr" \
        -connection-file "$connection" \
        -observation-file "$observation" \
        -data-dir "$tmp_dir/etcd-$generation" \
        -generation "$generation" &
    fixture_pid=$!
    wait_for_file "$connection"
    wait_for_file "$observation"
}

cd "$repo_root"
go build -o "$tmp_dir/go-fixture" ./tests/controlplane/cp002/go-fixture

start_fixture 1 "127.0.0.1:0"
CP002_CONNECTION_FILE="$tmp_dir/connection-1.json" \
CP002_GENERATION=1 \
cargo run --locked --quiet --manifest-path rust/Cargo.toml \
    -p control-external --example cp002_observer >"$tmp_dir/rust-1.json"
go run ./tests/controlplane/differential/cmd/controlplane-differential \
    -mode compare -baseline "$tmp_dir/go-1.json" -candidate "$tmp_dir/rust-1.json"

etcd_endpoint=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["etcd_endpoint"])' "$tmp_dir/connection-1.json")
kill -9 "$fixture_pid"
wait "$fixture_pid" 2>/dev/null || true
fixture_pid=""

start_fixture 2 "$etcd_endpoint"
CP002_CONNECTION_FILE="$tmp_dir/connection-2.json" \
CP002_GENERATION=2 \
cargo run --locked --quiet --manifest-path rust/Cargo.toml \
    -p control-external --example cp002_observer >"$tmp_dir/rust-2.json"
go run ./tests/controlplane/differential/cmd/controlplane-differential \
    -mode compare -baseline "$tmp_dir/go-2.json" -candidate "$tmp_dir/rust-2.json"

set +e
CP002_CONNECTION_FILE="$tmp_dir/connection-2.json" \
CP002_GENERATION=2 \
CP002_MUTATE_ENDPOINT=1 \
cargo run --locked --quiet --manifest-path rust/Cargo.toml \
    -p control-external --example cp002_observer \
    >"$tmp_dir/rust-mutated-endpoint.json" 2>"$tmp_dir/rust-mutated-endpoint.err"
status=$?
set -e
if [[ "$status" -eq 0 ]]; then
    echo "CP-002 endpoint mutation was not killed" >&2
    exit 1
fi

set +e
CP002_CONNECTION_FILE="$tmp_dir/connection-2.json" \
CP002_GENERATION=2 \
CP002_MUTATE_TLS=1 \
cargo run --locked --quiet --manifest-path rust/Cargo.toml \
    -p control-external --example cp002_observer \
    >"$tmp_dir/rust-mutated-tls.json" 2>"$tmp_dir/rust-mutated-tls.err"
status=$?
set -e
if [[ "$status" -eq 0 ]]; then
    echo "CP-002 TLS-policy mutation was not killed" >&2
    exit 1
fi

CP002_CONNECTION_FILE="$tmp_dir/connection-2.json" \
CP002_GENERATION=2 \
CP002_MUTATE_GENERATION=1 \
cargo run --locked --quiet --manifest-path rust/Cargo.toml \
    -p control-external --example cp002_observer >"$tmp_dir/rust-mutated.json"
set +e
go run ./tests/controlplane/differential/cmd/controlplane-differential \
    -mode compare -baseline "$tmp_dir/go-2.json" -candidate "$tmp_dir/rust-mutated.json"
status=$?
set -e
if [[ "$status" -ne 1 ]]; then
    echo "CP-002 owner-generation mutation was not killed (status=$status)" >&2
    exit 1
fi
