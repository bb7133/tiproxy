#!/usr/bin/env bash
# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)
cd "$root"
temporary=$(mktemp -d)
trap 'rm -rf "$temporary"' EXIT
export CP_ROUTE_SELECTOR_EVIDENCE="${CP_ROUTE_SELECTOR_EVIDENCE:-$temporary/evidence}"
mkdir -p "$CP_ROUTE_SELECTOR_EVIDENCE"
git rev-parse HEAD > "$CP_ROUTE_SELECTOR_EVIDENCE/tested-commit.txt"
cargo build --locked --manifest-path rust/Cargo.toml -p legacy-router-shadow --example selector_check
python3 tests/controlplane/cproute/shadow/selector-core-mutations.py
