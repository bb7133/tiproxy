#!/usr/bin/env bash
# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)
task_tmp=$(mktemp -d)
trap 'rm -rf "$task_tmp"' EXIT INT TERM
cd "$root"
python3 tests/controlplane/cproute/shadow/isolation.py "$root"
cargo test --locked --manifest-path rust/Cargo.toml -p control-router shadow::
cargo test --locked --manifest-path rust/Cargo.toml -p legacy-router-shadow
cargo test --locked --manifest-path rust/Cargo.toml -p tiproxy-rs routing_observer
cargo build --locked --manifest-path rust/Cargo.toml -p legacy-router-shadow --examples
CP_ROUTE_LIVE_FRAMES="$task_tmp/actual.frames" go test -race ./pkg/balance/router -run '^TestObservationActualLifecycle$' -count=1 -v
rust/target/debug/examples/live_check "$task_tmp/actual.frames"
go test -race ./pkg/balance/observation ./pkg/controlbridge/shadow ./pkg/manager/namespace -count=1
go test -race ./pkg/balance/router -run '^TestObservation(Abandon|Invalid|Default|Capture)' -count=1 -v
# Frozen 60-second disabled and enabled workloads; no reduced-duration fallback.
CP_ROUTE_LIVE_SOCKET_CHECK="$root/rust/target/debug/examples/live_socket_check" go test -race ./pkg/balance/router -run '^TestObservation(Sustained|SocketSettlementReport)$' -count=1 -timeout=180s -v
python3 tests/controlplane/cproute/shadow/live-mutations.py
