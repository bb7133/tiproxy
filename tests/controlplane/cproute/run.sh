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

if grep -R -n -E 'control_proto|control-proto' \
    rust/crates/control-routing rust/crates/control-router rust/crates/dataplane/src/route.rs; then
    echo "CP-ROUTE domain leaks the legacy protocol dependency" >&2
    exit 1
fi
# Temporary selector capability gaps must never reach production callers.
if grep -n -E 'control-router|control_router' \
    rust/crates/dataplane/Cargo.toml rust/crates/tiproxy-rs/Cargo.toml; then
    echo "CP-ROUTE staged selector is prematurely wired to production" >&2
    exit 1
fi
while IFS= read -r file; do
    if grep -q 'control_proto' "$file"; then
        printf '%s\n' "$file"
    fi
done < <(grep -R -l -E 'Route(Assignment|Request|Result)' rust/crates/dataplane/src) \
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

CPROUTE_GROUP_FIXTURES="$repo_root/tests/controlplane/cproute/groups" \
    CPROUTE_GROUP_OUTPUT="$tmp_dir/go-groups.tsv" \
    go test ./pkg/balance/router -run '^TestCPRouteGroupObservation$' -count=1
cargo run --locked --quiet --manifest-path rust/Cargo.toml -p control-routing \
    --example group_observer -- tests/controlplane/cproute/groups >"$tmp_dir/rust-groups.tsv"
cmp "$tmp_dir/go-groups.tsv" "$tmp_dir/rust-groups.tsv"
python3 tests/controlplane/cproute/groups/mutations.py "$tmp_dir/go-groups.tsv"
echo "CP-ROUTE group matching and port-conflict evidence passed"

CPROUTE_LEDGER_FIXTURE="$repo_root/tests/controlplane/cproute/ledger/events.tsv" \
CPROUTE_LEDGER_OUTPUT="$tmp_dir/go-ledger.tsv" \
    go test ./pkg/controlbridge -run '^TestCPRouteLedgerObservation$' -count=1
CPROUTE_LEDGER_FIXTURE="$repo_root/tests/controlplane/cproute/ledger/events.tsv" \
CPROUTE_LEDGER_OUTPUT="$tmp_dir/rust-ledger.tsv" \
    cargo test --locked --quiet --manifest-path rust/Cargo.toml -p control-router \
        ledger::tests::shared_go_ledger_observation -- --exact
cmp "$tmp_dir/go-ledger.tsv" "$tmp_dir/rust-ledger.tsv"
echo "CP-ROUTE reservation accounting evidence passed"

# Inject deterministic ticks into a temporary copy of the actual Go selector.
# No selection, scoring or weight calculation is replaced by an oracle.
python3 - "$repo_root" "$tmp_dir" <<'PY'
import json
from pathlib import Path
import sys
root, temp = map(Path, sys.argv[1:])
source = root / 'pkg/balance/factor/factor_balance.go'
original = source.read_text()
assert original.count('time.Now().UnixMicro()') == 2
copy = temp / 'factor_balance.go'
copy.write_text(original.replace('time.Now().UnixMicro()', 'cprouteTicket'))
(temp / 'overlay.json').write_text(json.dumps({'Replace': {str(source): str(copy)}}))
PY
CPROUTE_CLOCK_OVERLAY=1 \
CPROUTE_CHOICE_FIXTURE="$repo_root/tests/controlplane/cproute/choice/weights.tsv" \
CPROUTE_CHOICE_OUTPUT="$tmp_dir/go-choice.tsv" \
    go test -overlay "$tmp_dir/overlay.json" ./pkg/balance/factor -run '^TestCPRouteChoiceObservation$' -count=1
CPROUTE_CHOICE_FIXTURE="$repo_root/tests/controlplane/cproute/choice/weights.tsv" \
CPROUTE_CHOICE_OUTPUT="$tmp_dir/rust-choice.tsv" \
    cargo test --locked --quiet --manifest-path rust/Cargo.toml -p control-router \
        selector::tests::shared_go_choice_observation -- --exact
cmp "$tmp_dir/go-choice.tsv" "$tmp_dir/rust-choice.tsv"
echo "CP-ROUTE connection policy candidate and weight evidence passed"

CPROUTE_COMPOSITION_FIXTURE="$repo_root/tests/controlplane/cproute/composition/eligibility.json" \
CPROUTE_COMPOSITION_OUTPUT="$tmp_dir/go-composition.tsv" \
    go test ./pkg/balance/router -run '^TestCPRouteCompositionObservation$' -count=1
CPROUTE_COMPOSITION_FIXTURE="$repo_root/tests/controlplane/cproute/composition/eligibility.json" \
CPROUTE_COMPOSITION_OUTPUT="$tmp_dir/rust-composition.tsv" \
    cargo test --locked --quiet --manifest-path rust/Cargo.toml -p control-router \
        selector::composition_tests::shared_go_composition_observation -- --exact
cmp "$tmp_dir/go-composition.tsv" "$tmp_dir/rust-composition.tsv"
echo "CP-ROUTE label/status/fail-list composition evidence passed"

CPROUTE_RETRY_FIXTURE="$repo_root/tests/controlplane/cproute/composition/retry.json" \
CPROUTE_RETRY_OUTPUT="$tmp_dir/go-retry.tsv" \
    go test ./pkg/balance/router -run '^TestCPRouteRetryObservation$' -count=1
CPROUTE_RETRY_FIXTURE="$repo_root/tests/controlplane/cproute/composition/retry.json" \
CPROUTE_RETRY_OUTPUT="$tmp_dir/rust-retry.tsv" \
    cargo test --locked --quiet --manifest-path rust/Cargo.toml -p control-router \
        tests::shared_go_retry_observation -- --exact
cmp "$tmp_dir/go-retry.tsv" "$tmp_dir/rust-retry.tsv"
echo "CP-ROUTE retry cycle and port-conflict evidence passed"

python3 tests/controlplane/cproute/mutations.py
echo "CP-ROUTE selector authority and accounting mutation evidence passed"

# CP-ROUTE 220-3 B1: the health round's locality (Go checkHealth + setLocal
# through the real ConfigManager) versus the production run_health_round with
# the real ConfigNamespaceStore zone read, over one shared config history.
CPROUTE_LOCALITY_FIXTURE="$repo_root/tests/controlplane/cproute/locality/rounds.json" \
CPROUTE_LOCALITY_OUTPUT="$tmp_dir/go-locality.tsv" \
    go test ./pkg/balance/observer -run '^TestCPRouteLocalityObservation$' -count=1
CPROUTE_LOCALITY_FIXTURE="$repo_root/tests/controlplane/cproute/locality/rounds.json" \
CPROUTE_LOCALITY_OUTPUT="$tmp_dir/rust-locality.tsv" \
    cargo test --locked --quiet --manifest-path rust/Cargo.toml -p control-topology \
        health_loop::tests::shared_go_locality_observation -- --exact
cmp "$tmp_dir/go-locality.tsv" "$tmp_dir/rust-locality.tsv"
echo "CP-ROUTE health-round locality evidence passed"

python3 tests/controlplane/cproute/locality/mutations.py "$tmp_dir/go-locality.tsv"
echo "CP-ROUTE health-round locality mutation evidence passed"

# CP-ROUTE 220-3 B2: backend-source mode (Go backendcluster.Manager applied
# map + FallbackFetcher + StaticFetcher over real embedded etcd) versus the real
# TopologyModule's applied plan and static producer, over one shared step
# fixture that also records the accepted Go/Rust divergence step.
CPROUTE_STATIC_FIXTURE="$repo_root/tests/controlplane/cproute/static/modes.json" \
CPROUTE_STATIC_OUTPUT="$tmp_dir/go-static.tsv" \
    go test ./pkg/manager/backendcluster -run '^TestCPRouteStaticModeObservation$' -count=1
CPROUTE_STATIC_FIXTURE="$repo_root/tests/controlplane/cproute/static/modes.json" \
CPROUTE_STATIC_OUTPUT="$tmp_dir/rust-static.tsv" \
    cargo test --locked --quiet --manifest-path rust/Cargo.toml -p control-topology \
        static_source::tests::shared_go_static_mode_observation -- --exact
cmp "$tmp_dir/go-static.tsv" "$tmp_dir/rust-static.tsv"
echo "CP-ROUTE backend-source mode evidence passed"

python3 tests/controlplane/cproute/static/mutations.py "$tmp_dir/go-static.tsv"
echo "CP-ROUTE backend-source mode mutation evidence passed"
