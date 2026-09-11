#!/usr/bin/env bash
# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)
cd "$root"
python3 tests/controlplane/cproute/shadow/router-attempt-mutations.py --check-anchors
temporary=$(mktemp -d)
trap 'rm -rf "$temporary"' EXIT
export CP_ROUTE_ROUTER_ATTEMPT_EVIDENCE="${CP_ROUTE_ROUTER_ATTEMPT_EVIDENCE:-$temporary/evidence}"
mkdir -p "$CP_ROUTE_ROUTER_ATTEMPT_EVIDENCE"
git rev-parse HEAD > "$CP_ROUTE_ROUTER_ATTEMPT_EVIDENCE/tested-commit.txt"
python3 tests/controlplane/cproute/shadow/router-attempt-mutations.py
