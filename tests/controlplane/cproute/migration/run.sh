#!/usr/bin/env bash
# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)
task_tmp=$(mktemp -d)
trap 'rm -rf "$task_tmp"' EXIT INT TERM
cd "$root"
python3 - "$root" "$task_tmp" <<'PY'
from pathlib import Path
import json,sys
root,temp=map(Path,sys.argv[1:])
source=root/'pkg/balance/router/group.go'
s=source.read_text()
assert s.count('curTime := time.Now()') == 1
copy=temp/'group.go'
copy.write_text(s.replace('curTime := time.Now()','curTime := cpMigrationNow'))
(temp/'overlay.json').write_text(json.dumps({'Replace':{str(source):str(copy)}}))
PY
export CPROUTE_MIGRATION_FIXTURE="$root/tests/controlplane/cproute/migration/events.tsv"
CPROUTE_MIGRATION_CLOCK=1 CPROUTE_MIGRATION_OUTPUT="$task_tmp/go.tsv" \
    go test -overlay "$task_tmp/overlay.json" ./pkg/balance/router -run '^TestCPRouteMigrationObservation$' -count=1
CPROUTE_MIGRATION_OUTPUT="$task_tmp/rust.tsv" \
    cargo test --locked --manifest-path rust/Cargo.toml -p control-router \
    ledger::redirect_tests::shared_go_redirect_observation -- --exact
cmp "$task_tmp/go.tsv" "$task_tmp/rust.tsv"
printf 'CP-ROUTE migration Go/Rust lifecycle matched: %s rows\n' "$(wc -l < "$task_tmp/go.tsv")"

# The observer above populates a cold dependency cache before offline mutations.
python3 tests/controlplane/cproute/migration/mutations.py
