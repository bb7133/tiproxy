#!/usr/bin/env bash
# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)
tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT INT TERM
cd "$repo_root"
export CPROUTE_BALANCE_CASES=1
python3 - "$repo_root" "$tmp_dir" <<'PYCLOCK'
import json
import sys
from pathlib import Path
root, temp = map(Path, sys.argv[1:])
replacements = {}
for name in ['cpu', 'memory', 'health', 'status', 'balance']:
    path = root / f'pkg/balance/factor/factor_{name}.go'
    original = path.read_text()
    assert 'time.Now()' in original
    revised = original.replace('time.Now().UnixMicro()', 'cpFactorTicket')
    revised = revised.replace('time.Now()', 'cpFactorNow').replace('time.Since(', 'cpFactorNow.Sub(')
    copied = temp / path.name
    copied.write_text(revised)
    replacements[str(path)] = str(copied)
(temp / 'overlay.json').write_text(json.dumps({'Replace': replacements}))
PYCLOCK
export CPMETRICS_FACTOR_OUTPUT="$tmp_dir/go-factors.json"
export CPMETRICS_FACTOR_CLOCK=1
go test -overlay "$tmp_dir/overlay.json" ./pkg/balance/factor -run '^TestCPMetricsFactorObservation$' -count=1 -v
cargo test --locked --manifest-path rust/Cargo.toml -p control-router --lib factors::tests:: -- --nocapture

export CPROUTE_ARRIVAL_FIXTURE="$repo_root/tests/controlplane/cproute/balance/arrival.tsv"
export CPROUTE_ARRIVAL_EXPECTED="$repo_root/tests/controlplane/cproute/balance/arrival.expected.tsv"
CPROUTE_ARRIVAL_OUTPUT="$tmp_dir/go-arrival.tsv" \
    go test ./pkg/balance/router -run '^TestCPRouteArrivalObservation$' -count=1
cmp "$tmp_dir/go-arrival.tsv" tests/controlplane/cproute/balance/arrival.expected.tsv
CPROUTE_ARRIVAL_OUTPUT="$tmp_dir/rust-arrival.tsv" \
    cargo test --locked --manifest-path rust/Cargo.toml -p control-router --lib shared_go_physical_arrival_order
cmp "$tmp_dir/go-arrival.tsv" "$tmp_dir/rust-arrival.tsv"
echo 'CP-ROUTE actual Go balance and physical arrival observations passed'
go build -o "$tmp_dir/fixture" ./tests/controlplane/cp003/go-fixture
export CPMETRICS_FACTOR_FIXTURE_BIN="$tmp_dir/fixture"
python3 tests/controlplane/cproute/balance/live.py
python3 tests/controlplane/cproute/balance/mutations.py
