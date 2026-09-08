#!/usr/bin/env bash
# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)
cd "$root"
temporary=$(mktemp -d)
trap 'rm -rf "$temporary"' EXIT
go test -race ./pkg/balance/observation -count=1
go build -o "$temporary/oracle" ./tests/controlplane/cproute/shadow/time-oracle
"$temporary/oracle" > "$temporary/fresh.tsv"
TIPROXY_CLOCK_ORACLE="$temporary/fresh.tsv" cargo test --locked --manifest-path rust/Cargo.toml -p control-routing
# Exercise the actual startup formatter in separate fixture processes. An
# over-bound name is rejected before String can allocate from that name.
"$temporary/oracle" -origin-zone-bytes=512 > "$temporary/zone-equal.tsv"
TIPROXY_CLOCK_ORACLE="$temporary/zone-equal.tsv" cargo test --locked --manifest-path rust/Cargo.toml -p control-routing go_time::tests::actual_go_oracle -- --exact
if "$temporary/oracle" -origin-zone-bytes=513 > "$temporary/zone-plus-one.log" 2>&1; then
  echo 'TIME_ORIGIN_ZONE_PLUS_ONE: unexpectedly accepted' >&2
  exit 1
fi
if ! grep -Fq 'observation startup time zone exceeds bound' "$temporary/zone-plus-one.log"; then
  cat "$temporary/zone-plus-one.log" >&2
  exit 1
fi
python3 tests/controlplane/cproute/shadow/time-mutations.py
