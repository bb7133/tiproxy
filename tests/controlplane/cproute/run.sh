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
trap 'rm -rf "$tmp_dir"' EXIT INT TERM

cd "$repo_root"

if rg -n 'control_proto|control-proto' \
    rust/crates/control-routing rust/crates/dataplane/src/route.rs; then
    echo "CP-ROUTE domain leaks the legacy protocol dependency" >&2
    exit 1
fi
while IFS= read -r file; do
    if rg -q 'control_proto' "$file"; then
        printf '%s\n' "$file"
    fi
done < <(rg -l 'Route(Assignment|Request|Result)' rust/crates/dataplane/src) \
    | LC_ALL=C sort >"$tmp_dir/proto-wire-files.txt"
cmp tests/controlplane/cproute/proto-wire-files.txt "$tmp_dir/proto-wire-files.txt"

go build -o "$tmp_dir/go-observer" ./tests/controlplane/cproute/go-observer
for mode in default custom; do
    CPROUTE_MODE="$mode" "$tmp_dir/go-observer" >"$tmp_dir/go-$mode.json"
    CPROUTE_MODE="$mode" cargo run --locked --quiet \
        --manifest-path rust/Cargo.toml -p control-config \
        --example cproute_observer >"$tmp_dir/rust-$mode.json"
    cmp "$tmp_dir/go-$mode.json" "$tmp_dir/rust-$mode.json"
done

CPROUTE_MUTATE_POLICY=1 cargo run --locked --quiet \
    --manifest-path rust/Cargo.toml -p control-config \
    --example cproute_observer >"$tmp_dir/rust-mutated.json"
set +e
cmp -s "$tmp_dir/go-custom.json" "$tmp_dir/rust-mutated.json"
status=$?
set -e
if [[ "$status" -eq 0 ]]; then
    echo "CP-ROUTE routing-policy mutation was not killed" >&2
    exit 1
fi

echo "CP-ROUTE config and namespace projection evidence passed"
