#!/usr/bin/env bash
# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)
cd "$root"
temporary=$(mktemp -d)
trap 'rm -rf "$temporary"' EXIT

go test -race ./pkg/balance/observation ./pkg/balance/factor ./pkg/balance/router ./pkg/controlbridge/shadow ./pkg/manager/namespace ./pkg/server -count=1
export CP_ROUTE_NATIVE_NUMERIC="$temporary/numeric.json"
go test ./pkg/balance/factor -run '^TestNativeNumericConversions$' -count=1
cargo test --locked --manifest-path rust/Cargo.toml -p control-router native_numeric -- --nocapture
CP_ROUTE_NATIVE_FRAMES="$temporary/factors.frames" go test ./pkg/balance/factor -run '^TestNativeFactorFrames$' -count=1
cargo run --locked --manifest-path rust/Cargo.toml -p legacy-router-shadow --example native_check -- "$temporary/factors.frames"
# A capable Apple host additionally executes actual AMD64 Go under Rosetta;
# Ubuntu AMD64 CI generates its oracle natively. Never relabel a captured file.
if [[ $(uname -s) == Darwin && $(go env GOHOSTARCH) == arm64 ]] && arch -x86_64 /usr/bin/true 2>/dev/null; then
  GOARCH=amd64 CP_ROUTE_NATIVE_NUMERIC="$temporary/numeric-amd64.json" go test ./pkg/balance/factor -run '^TestNativeNumericConversions$' -count=1
  CP_ROUTE_NATIVE_NUMERIC="$temporary/numeric-amd64.json" cargo test --locked --manifest-path rust/Cargo.toml -p control-router native_numeric -- --nocapture
  GOARCH=amd64 CP_ROUTE_NATIVE_FRAMES="$temporary/factors-amd64.frames" go test ./pkg/balance/factor -run '^TestNativeFactorFrames$' -count=1
  cargo run --locked --manifest-path rust/Cargo.toml -p legacy-router-shadow --example native_check -- "$temporary/factors-amd64.frames"
fi
unset CP_ROUTE_NATIVE_NUMERIC
CP_ROUTE_NATIVE_MIXED_FRAMES="$temporary/mixed.frames" go test ./pkg/balance/router -run '^TestNativeGroupMixedFrames$' -count=1
cargo run --locked --manifest-path rust/Cargo.toml -p legacy-router-shadow --example native_live_check -- "$temporary/mixed.frames"
cargo test --locked --manifest-path rust/Cargo.toml -p control-router shadow::
cargo test --locked --manifest-path rust/Cargo.toml -p legacy-router-shadow
python3 tests/controlplane/cproute/shadow/isolation.py "$root"
python3 tests/controlplane/cproute/shadow/native-mutations.py
# C1 uses actual Group.Balance calls, independently replayed as one v4 parent.
bash tests/controlplane/cproute/shadow/balance-hooks-run.sh
# C2 first checkpoint: actual Group-local Route, not outer selector metadata.
bash tests/controlplane/cproute/shadow/route-hooks-run.sh
# Pure Next transitions use actual Go oracles; outer metadata binding remains separate.
bash tests/controlplane/cproute/shadow/selector-core-run.sh
cargo build --locked --manifest-path rust/Cargo.toml -p legacy-router-shadow --example live_socket_check
export CP_ROUTE_LIVE_SOCKET_CHECK="$root/rust/target/debug/examples/live_socket_check"
go test ./pkg/balance/router -run '^TestNativeObservationSocketSettlement$' -count=1 -v
# The measurement wrapper delegates to the real factor object. This test-only
# adapter permits the wrapper to forward TakeObservation; normal production
# factory binding remains the concrete native type and is tested above.
python3 - "$root" "$temporary" <<'PYTIMING'
import json,sys
from pathlib import Path
root, temp = map(Path,sys.argv[1:])
path = root/'pkg/balance/router/group.go'
source = path.read_text()
old = 'g.policy.(*factor.FactorBasedBalance)'
assert source.count(old) == 1
source = source.replace(old, 'g.policy.(interface { TakeObservation() *observation.Evaluation })')
# The concrete construction fence still needs the factor import. Only the
# publication adapter is replaced for this test-only timing wrapper.
copy = temp/'group.go'; copy.write_text(source)
(temp/'timings-overlay.json').write_text(json.dumps({'Replace': {str(path): str(copy)}}))
PYTIMING
CP_ROUTE_NATIVE_TIMINGS=1 go test -overlay "$temporary/timings-overlay.json" ./pkg/balance/router -run '^TestNativeObservationSustained$' -count=1 -failfast -timeout=25m -v
