#!/usr/bin/env bash
# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)
cd "$root"
go test -race ./pkg/balance/observation ./pkg/balance/metricsreader ./pkg/balance/factor -count=1
python3 tests/controlplane/cproute/shadow/read-foundation-mutations.py
