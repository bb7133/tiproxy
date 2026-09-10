#!/usr/bin/env bash
# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)
cd "$root"
temporary=$(mktemp -d)
trap 'rm -rf "$temporary"' EXIT
evidence="${CP_ROUTE_ROUTE_HOOK_EVIDENCE:-$temporary/evidence}"
mkdir -p "$evidence"
export CP_ROUTE_ROUTE_HOOK_EVIDENCE="$evidence"
git rev-parse HEAD > "$evidence/tested-commit.txt"
CP_ROUTE_ROUTE_HOOK_FRAMES="$evidence/route.frames" go test ./pkg/balance/router -run '^TestRouteHooks' -count=1 2>&1 | tee "$evidence/go.log"
cargo run --locked --manifest-path rust/Cargo.toml -p legacy-router-shadow --example route_hook_check -- "$evidence/route.frames" 2>&1 | tee "$evidence/rust.log"
python3 tests/controlplane/cproute/shadow/route-hooks-mutations.py
