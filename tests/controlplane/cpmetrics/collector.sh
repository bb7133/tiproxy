#!/usr/bin/env bash
# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT
cd "$repo_root"
cargo fetch --locked --manifest-path rust/Cargo.toml
go build -o "$tmp_dir/fixture" ./tests/controlplane/cp003/go-fixture
go test -c -o "$tmp_dir/go-peer" ./pkg/balance/metricsreader
export CPMETRICS_COLLECTOR_FIXTURE_BIN="$tmp_dir/fixture"
export CPMETRICS_COLLECTOR_GO_BIN="$tmp_dir/go-peer"
python3 tests/controlplane/cpmetrics/collector.py
python3 tests/controlplane/cpmetrics/collector_mutations.py
