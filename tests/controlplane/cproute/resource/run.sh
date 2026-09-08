#!/usr/bin/env bash
# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)
temp_dir=$(mktemp -d)
trap 'rm -rf "$temp_dir"' EXIT INT TERM
cd "$repo_root"
export CPROUTE_RESOURCE_OUTPUT="$temp_dir/go-resource.json"
go test ./pkg/balance/router -run '^TestCPRouteResourceObservation$' -count=1 -v
go build -o "$temp_dir/fixture" ./tests/controlplane/cp003/go-fixture
export CPMETRICS_FACTOR_FIXTURE_BIN="$temp_dir/fixture"
python3 tests/controlplane/cproute/resource/live.py
python3 tests/controlplane/cproute/resource/mutations.py
