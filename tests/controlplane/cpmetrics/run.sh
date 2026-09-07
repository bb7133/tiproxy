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
export CPMETRICS_RULE_OUTPUT="$tmp_dir/rules.jsonl"
export CPMETRICS_HISTORY_OUTPUT="$tmp_dir/history.jsonl"
export CPMETRICS_SOURCE_OUTPUT="$tmp_dir/source.jsonl"
export CPMETRICS_MERGE_OUTPUT="$tmp_dir/merge.jsonl"
export CPMETRICS_PROM_OUTPUT="$tmp_dir/prom.jsonl"
export CPMETRICS_BACKEND_OUTPUT="$tmp_dir/backend.jsonl"
go test ./pkg/balance/factor ./pkg/balance/metricsreader ./pkg/manager/backendcluster \
    -run '^TestCPMetrics.*Observation$' -count=1
python3 - "$tmp_dir" <<'PYCOUNTS'
import json
import sys
from pathlib import Path
root = Path(sys.argv[1])
expected = {"rules":96, "history":38, "source":1, "merge":1, "prom":7, "backend":9}
names = set()
for part, count in expected.items():
    rows = [json.loads(line) for line in (root / f"{part}.jsonl").read_text().splitlines()]
    if len(rows) != count:
        raise SystemExit(f"missing Go {part} observations: {len(rows)} != {count}")
    for row in rows:
        if row["name"] in names:
            raise SystemExit(f"duplicate Go observation: {row['name']}")
        names.add(row["name"])
print(f"CP-METRICS generated {len(names)} unique actual-Go observations")
PYCOUNTS
cargo test --locked --manifest-path rust/Cargo.toml -p control-topology --lib metrics:: -- --nocapture
python3 tests/controlplane/cpmetrics/mutations.py
echo "CP-METRICS query/history evidence passed (staged data core; no runtime authority)"
