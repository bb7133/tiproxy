#!/usr/bin/env bash
# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)
task_tmp=$(mktemp -d)
trap 'rm -rf "$task_tmp"' EXIT INT TERM
cd "$root"
python3 - "$root" "$task_tmp" <<'PYCLOCK'
import json,sys
from pathlib import Path
root,tmp=map(Path,sys.argv[1:])
source=root/'pkg/balance/router/group.go'
s=source.read_text();assert 'curTime := time.Now()' in s
copy=tmp/'group.go';copy.write_text(s.replace('time.Now()', 'cpWorkerNow'))
(tmp/'overlay.json').write_text(json.dumps({'Replace':{str(source):str(copy)}}))
PYCLOCK
export CPROUTE_WORKER_FIXTURE="$root/tests/controlplane/cproute/worker/events.json"
CPROUTE_WORKER_CLOCK=1 CPROUTE_WORKER_OUTPUT="$task_tmp/go.json" go test -overlay "$task_tmp/overlay.json" ./pkg/balance/router -run '^TestCPRouteWorkerObservation$' -count=1 -v
export CPROUTE_WORKER_EXPECTED="$task_tmp/go.json"
CPROUTE_WORKER_OUTPUT="$task_tmp/rust.json" cargo test --locked --manifest-path rust/Cargo.toml -p control-router shared_go_worker_clock_events -- --nocapture

cargo test --locked --manifest-path rust/Cargo.toml -p control-router worker_ -- --nocapture
go build -o "$task_tmp/fixture" ./tests/controlplane/cp003/go-fixture
export CPMETRICS_FACTOR_FIXTURE_BIN="$task_tmp/fixture"
python3 tests/controlplane/cproute/worker/live.py
python3 tests/controlplane/cproute/worker/mutations.py
