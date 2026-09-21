#!/usr/bin/env bash
# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# CP-ADMIN slice 4b differential evidence: the production Go API server
# (h2c gin engine + sysutil diagnostics, and its cmux TLS branch) and the Rust
# admin listener answer the same SearchLog/ServerInfo/HTTP-1.1 script over a
# real gRPC wire; packets, status codes and the HTTP/1.1 rejection must match
# except where the script declares a divergence owned by the design document.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
GO="${GO:-go}"
CARGO="${CARGO:-cargo}"
script="$root/tests/controlplane/cpdiag/script.json"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT INT TERM

# The Go API server does not advertise h2 through ALPN on its TLS branch
# (http.Server.Serve over a tls.Listener); grpc-go >= 1.67 refuses such peers
# unless ALPN enforcement is switched off, which is what the older clients the
# Go server was built for do implicitly.
(cd "$root" && GRPC_ENFORCE_ALPN_ENABLED=false CPDIAG_CAPTURE_OUT="$tmp_dir/go.json" CPDIAG_SCRIPT="$script" \
  "$GO" test ./pkg/server/api -run '^TestCPDiagCapture$' -count=1 >"$tmp_dir/go-test.log" 2>&1) \
  || { cat "$tmp_dir/go-test.log" >&2; exit 1; }
(cd "$root/rust" && CPDIAG_SCRIPT="$script" \
  "$CARGO" run --locked --quiet -p control-admin --example cpdiag_replay >"$tmp_dir/rust.json")
python3 "$root/tests/controlplane/cpdiag/compare.py" "$script" "$tmp_dir/go.json" "$tmp_dir/rust.json"
if [ -n "${CPDIAG_EVIDENCE_DIR:-}" ]; then
  mkdir -p "$CPDIAG_EVIDENCE_DIR"
  cp "$tmp_dir/go.json" "$tmp_dir/rust.json" "$CPDIAG_EVIDENCE_DIR/"
fi
