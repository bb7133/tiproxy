#!/usr/bin/env bash
set -euo pipefail
repo=$(cd "$(dirname "$0")/../../../.." && pwd)
fixture="$repo/rust/crates/control-meter/testdata/aws-adaptive-go.go"
probe=$(mktemp -d)
trap 'rm -rf "$probe"' EXIT
cat > "$probe/go.mod" <<'MOD'
module github.com/aws/aws-sdk-go-v2/probe

go 1.24.0

require (
 github.com/aws/aws-sdk-go-v2 v1.42.1
 github.com/aws/smithy-go v1.27.3
)
MOD
cp "$repo/go.sum" "$probe/go.sum"
cp "$fixture" "$probe/main.go"
cd "$probe"
GOWORK=off go run -mod=readonly .
