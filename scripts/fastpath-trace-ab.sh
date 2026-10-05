#!/usr/bin/env bash
# Fast-path on/off wire-trace A/B (v5 S2b acceptance).
#
# Runs the `dump_fastpath_wire_trace` integration test twice in separate
# processes — once with the steady-state fast path OFF (TIPROXY_FSM_FASTPATH
# unset) and once ON (=1) — and diffs the ordered command-phase wire trace
# (commands forwarded to the backend + client-visible outcomes). Byte-identical
# traces prove the fast path preserves the observable action sequence; any
# divergence fails the gate.
#
# The `fast_env=` marker line intentionally differs between runs and is stripped
# before the diff.
set -euo pipefail

# Repo root is the script's parent dir; the Rust workspace lives under rust/.
cd "$(dirname "$0")/../rust"

TEST=dump_fastpath_wire_trace
OFF=$(mktemp)
ON=$(mktemp)
trap 'rm -f "$OFF" "$ON"' EXIT

extract() {
  # Keep only the trace body between the markers, dropping the marker lines
  # themselves (the BEGIN line carries the differing fast_env tag).
  sed -n '/WIRE_TRACE_BEGIN/,/WIRE_TRACE_END/p' \
    | grep -E '^(FWD|RSP) '
}

echo "== running $TEST with fast path OFF =="
env -u TIPROXY_FSM_FASTPATH \
  cargo test -p dataplane --test session_engine -- --exact "$TEST" --nocapture \
  | extract > "$OFF"

echo "== running $TEST with fast path ON =="
TIPROXY_FSM_FASTPATH=1 \
  cargo test -p dataplane --test session_engine -- --exact "$TEST" --nocapture \
  | extract > "$ON"

if [ ! -s "$OFF" ] || [ ! -s "$ON" ]; then
  echo "FAIL: empty trace captured (OFF=$(wc -l <"$OFF") ON=$(wc -l <"$ON") lines)" >&2
  exit 1
fi

echo "== diffing traces =="
if diff -u "$OFF" "$ON"; then
  echo "PASS: fast-path on/off wire traces are byte-identical ($(wc -l <"$OFF") lines)"
else
  echo "FAIL: fast-path on/off wire traces diverge" >&2
  exit 1
fi
