#!/usr/bin/env bash
# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)
cd "$root"
temporary=$(mktemp -d)
trap 'rm -rf "$temporary"' EXIT
CP_ROUTE_BALANCE_HOOK_FRAMES="$temporary/balance.frames" go test ./pkg/balance/router -run '^TestBalanceHooks' -count=1
cargo run --locked --manifest-path rust/Cargo.toml -p legacy-router-shadow --example balance_hook_check -- "$temporary/balance.frames"
python3 tests/controlplane/cproute/shadow/balance-hooks-mutations.py
