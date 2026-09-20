#!/usr/bin/env bash
# Lumberjack retention parity: the Go logger (LocalTime: true) and the Rust
# rotating writer must keep exactly the same backups under a non-UTC zone,
# including the lumberjack quirk that names are rendered in local time but
# parsed as UTC for max-days pruning.
set -euo pipefail
cd "$(dirname "$0")/../../.."
build_dir=$(mktemp -d)
trap 'rm -rf "$build_dir"' EXIT
"${GO:-go}" build -o "$build_dir/go-prune" ./tests/controlplane/cplog/go-prune
"${CARGO:-cargo}" build --locked --quiet --manifest-path rust/Cargo.toml -p control-plane --example log_prune
target_dir=$("${CARGO:-cargo}" metadata --locked --no-deps --format-version 1 --manifest-path rust/Cargo.toml | "${PYTHON:-python3}" -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')
rust_prune="$target_dir/debug/examples/log_prune"

# Backup names as lumberjack would parse them (UTC), placed around the
# max-days=1 boundary: 20h old survives, 28h old is pruned. Under a local
# parse in TZ=Asia/Shanghai the 20h name would read as 28h and be lost.
stamp() { "${PYTHON:-python3}" -c 'import sys,datetime; print((datetime.datetime.now(datetime.timezone.utc)-datetime.timedelta(hours=float(sys.argv[1]))).strftime("%Y-%m-%dT%H-%M-%S.000"))' "$1"; }
keep=$(stamp 20)
drop=$(stamp 28)
run_one() {
  local binary=$1 dir=$2
  mkdir -p "$dir"
  printf 'old\n' > "$dir/tiproxy-$keep.log"
  printf 'old\n' > "$dir/tiproxy-$drop.log"
  printf 'old\n' > "$dir/other-$drop.log"
  "$binary" "$dir/tiproxy.log" 1 0 > "$dir/listing.txt"
  # Normalize the freshly created backup (its timestamp is "now") so both
  # sides are compared on the crafted names and the live file only.
  awk -v keep="tiproxy-$keep.log" -v drop="tiproxy-$drop.log" '
    $0 == keep || $0 == drop { print; next }
    /^tiproxy-[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}-[0-9]{2}-[0-9]{2}\.[0-9]{3}\.log$/ { print "tiproxy-<now>.log"; next }
    { print }
  ' "$dir/listing.txt" | sort -u
}
for zone in UTC Asia/Shanghai America/Los_Angeles; do
  go_out=$(TZ=$zone run_one "$build_dir/go-prune" "$build_dir/go-$zone")
  rust_out=$(TZ=$zone run_one "$rust_prune" "$build_dir/rust-$zone")
  if [ "$go_out" != "$rust_out" ]; then
    echo "retention diverged under TZ=$zone" >&2
    echo "--- go" >&2; echo "$go_out" >&2
    echo "--- rust" >&2; echo "$rust_out" >&2
    exit 1
  fi
  case "$go_out" in
    *"tiproxy-$keep.log"*) ;;
    *) echo "TZ=$zone: the 20h backup must survive max-days=1" >&2; exit 1 ;;
  esac
  case "$go_out" in
    *"tiproxy-$drop.log"*) echo "TZ=$zone: the 28h backup must be pruned" >&2; exit 1 ;;
  esac
  echo "TZ=$zone: Go and Rust keep the same backups"
done
echo "PASS: lumberjack retention parity (local-time names, UTC age parse)"
