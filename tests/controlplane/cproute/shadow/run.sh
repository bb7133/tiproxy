#!/usr/bin/env bash
# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)
task_tmp=$(mktemp -d)
trap 'rm -rf "$task_tmp"' EXIT INT TERM
cd "$root"
cargo test --locked --manifest-path rust/Cargo.toml -p control-router shadow::
cargo test --locked --manifest-path rust/Cargo.toml -p legacy-router-shadow
python3 tests/controlplane/cproute/shadow/isolation.py "$root"
CPROUTE_SHADOW_OUTPUT="$task_tmp/go" go test ./pkg/balance/router -run '^TestCPRouteShadowObservation$' -count=1
cargo build --locked --manifest-path rust/Cargo.toml -p legacy-router-shadow --example observe
rust/target/debug/examples/observe "$task_tmp/go.bin" > "$task_tmp/rust.tsv"
cmp "$task_tmp/go.tsv" "$task_tmp/rust.tsv"
printf 'CP-ROUTE shadow lifecycle Go/Rust matched: %s rows\n' "$(wc -l < "$task_tmp/go.tsv")"
python3 - "$task_tmp/go.bin" "$task_tmp/unsealed.bin" <<'PY'
from pathlib import Path
import struct,sys
source=Path(sys.argv[1]).read_bytes()
position=0
last=0
while position < len(source):
    last=position
    length=struct.unpack('>I',source[position:position+4])[0]
    position+=4+length
assert position==len(source)
Path(sys.argv[2]).write_bytes(source[:last])
PY
if rust/target/debug/examples/observe "$task_tmp/unsealed.bin" > "$task_tmp/unsealed.tsv" 2> "$task_tmp/unsealed.log"; then
    echo 'SHADOW_UNSEALED_EOF was silently accepted' >&2
    exit 1
fi
python3 - "$task_tmp/unsealed.log" <<'PY_CHECK'
from pathlib import Path
import sys
text=Path(sys.argv[1]).read_text()
assert 'SHADOW_UNSEALED_EOF' in text, text
PY_CHECK
python3 tests/controlplane/cproute/shadow/mutations.py
