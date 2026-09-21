#!/usr/bin/env bash
# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# CP-ADMIN slice 4d evidence: the real tiproxyctl binary runs the same command
# script against the production Go API server (plaintext, and the cmux TLS
# branch with auto certificates, using --insecure) and against the Rust admin
# listener; stdout and exit codes must match except where the script declares
# a divergence owned by the design document.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
GO="${GO:-go}"
CARGO="${CARGO:-cargo}"
script="$root/tests/controlplane/cpctl/script.json"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT INT TERM

(cd "$root" && "$GO" build -o "$tmp_dir/tiproxyctl" ./cmd/tiproxyctl)
binary="$tmp_dir/tiproxyctl"
(cd "$root" && CPCTL_CAPTURE_OUT="$tmp_dir/go.json" CPCTL_SCRIPT="$script" CPCTL_TIPROXYCTL="$binary" \
  "$GO" test ./pkg/server/api -run '^TestCPCtlCapture$' -count=1 >"$tmp_dir/go-test.log" 2>&1) \
  || { cat "$tmp_dir/go-test.log" >&2; exit 1; }
(cd "$root/rust" && CPCTL_SCRIPT="$script" CPCTL_TIPROXYCTL="$binary" CPADMIN_CURRENT_DIR="$root/pkg/server/api" \
  "$CARGO" run --locked --quiet -p control-admin --example cpctl_replay >"$tmp_dir/rust.json")
python="${PYTHON:-}"
if [ -z "$python" ]; then
  for candidate in python3.13 python3.12 python3.11 python3; do
    if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -c 'import tomllib' >/dev/null 2>&1; then
      python="$candidate"
      break
    fi
  done
fi
[ -n "$python" ] || { echo "no Python >= 3.11 with tomllib found (set PYTHON)" >&2; exit 1; }
"$python" "$root/tests/controlplane/cpctl/compare.py" "$script" "$tmp_dir/go.json" "$tmp_dir/rust.json"
if [ -n "${CPCTL_EVIDENCE_DIR:-}" ]; then
  mkdir -p "$CPCTL_EVIDENCE_DIR"
  cp "$tmp_dir/go.json" "$tmp_dir/rust.json" "$CPCTL_EVIDENCE_DIR/"
fi
