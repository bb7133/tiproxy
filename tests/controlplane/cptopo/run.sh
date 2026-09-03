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

# CP-TOPO self-registration / discovery evidence against the restartable
# production-Go embedded-etcd fixture shared with CP003/CP004.

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
cd "$repo_root"
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
            echo "CP-TOPO fixture exited before writing $path" >&2
            return 1
        fi
        sleep 0.05
    done
    echo "timed out waiting for CP-TOPO fixture file $path" >&2
    return 1
}

# The embedded etcd fixture is shared with CP003/CP004.
go build -o "$tmp_dir/go-fixture" ./tests/controlplane/cp003/go-fixture

connection="$tmp_dir/connection.json"
"$tmp_dir/go-fixture" -connection-file "$connection" -data-dir "$tmp_dir/cptopo-etcd" &
fixture_pid=$!
wait_for_file "$connection"

output="$tmp_dir/cptopo.out"
CPTOPO_CONNECTION_FILE="$connection" cargo run --locked --quiet \
    --manifest-path rust/Cargo.toml -p control-topology --example cptopo_live \
    >"$output"

if ! grep -q "CPTOPO_LIVE_OK" "$output"; then
    echo "CP-TOPO live evidence did not pass" >&2
    cat "$output" >&2
    exit 1
fi

echo "CP-TOPO live evidence passed"
