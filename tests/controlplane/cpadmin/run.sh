#!/usr/bin/env bash
# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# CP-ADMIN slice 1 differential evidence: the production Go gin engine (with
# the api package's own test mocks) and the Rust control-admin router answer
# the same request script; status, content type and body must match except
# where the script declares a divergence owned by the design document. The
# same run compares the Go ConfigManager CRC32 checksum with the Rust
# control-config checksum for default, partial-update, no-change-update and
# namespace-only scenarios.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
GO="${GO:-go}"
CARGO="${CARGO:-cargo}"
script="$root/tests/controlplane/cpadmin/script.json"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT INT TERM

(cd "$root" && CPADMIN_CAPTURE_OUT="$tmp_dir/go.json" CPADMIN_SCRIPT="$script" \
  "$GO" test ./pkg/server/api -run '^TestCPAdminCapture$' -count=1 >"$tmp_dir/go-test.log" 2>&1) \
  || { cat "$tmp_dir/go-test.log" >&2; exit 1; }
# The Go test's working directory is the package directory, which fixes the
# default workdir inside the checksummed configuration.
(cd "$root/rust" && CPADMIN_SCRIPT="$script" CPADMIN_CURRENT_DIR="$root/pkg/server/api" \
  "$CARGO" run --locked --quiet -p control-admin --example cpadmin_replay >"$tmp_dir/rust.json")
# compare.py needs tomllib (Python >= 3.11); honour PYTHON or pick a modern interpreter.
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
"$python" "$root/tests/controlplane/cpadmin/compare.py" "$script" "$tmp_dir/go.json" "$tmp_dir/rust.json"
if [ -n "${CPADMIN_EVIDENCE_DIR:-}" ]; then
  mkdir -p "$CPADMIN_EVIDENCE_DIR"
  cp "$tmp_dir/go.json" "$tmp_dir/rust.json" "$CPADMIN_EVIDENCE_DIR/"
fi
