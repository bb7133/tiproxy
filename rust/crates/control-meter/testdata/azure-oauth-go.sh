#!/usr/bin/env bash
# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
repo=$(cd "$(dirname "$0")/../../../.." && pwd)
probe=$(mktemp -d)
trap 'rm -rf "$probe"' EXIT
# Keep the exact production module graph; no SDK source is patched.
sed -e 's|^module .*|module azure-oauth-probe|' \
    -e "s|github.com/pingcap/tiproxy/lib => ./lib|github.com/pingcap/tiproxy/lib => $repo/lib|" \
    "$repo/go.mod" > "$probe/go.mod"
cp "$repo/go.sum" "$probe/go.sum"
cp "$repo/rust/crates/control-meter/testdata/azure-oauth-go.go" "$probe/main.go"
cd "$probe"
TZ=UTC GOWORK=off go vet -mod=readonly .
TZ=UTC GOWORK=off go run -mod=readonly .
