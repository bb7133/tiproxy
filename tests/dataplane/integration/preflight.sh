#!/usr/bin/env bash
# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd "$script_dir/../../.." && pwd)
# shellcheck source=versions.env
source "$script_dir/versions.env"

mode=rust
variant=plain
while (($# > 0)); do
	case "$1" in
		--mode)
			mode=${2:?missing value for --mode}
			shift 2
			;;
		--variant)
			variant=${2:?missing value for --variant}
			shift 2
			;;
		*)
			echo "unknown argument: $1" >&2
			exit 2
			;;
	esac
done

case "$mode" in
	go | rust) ;;
	*)
		echo "mode must be go or rust" >&2
		exit 2
		;;
esac
case "$variant" in
	plain | tls | proxy | compress-zlib | compress-zstd | tls-proxy-zstd) ;;
	*)
		echo "unknown variant: $variant" >&2
		exit 2
		;;
esac

missing=()
for command_name in awk curl find go grep make mysql openssl sed tiup; do
	if ! command -v "$command_name" >/dev/null 2>&1; then
		missing+=("$command_name")
	fi
done
if ((${#missing[@]} > 0)); then
	echo "missing required integration tools: ${missing[*]}" >&2
	exit 1
fi

installed_tiup=$(tiup --version | awk 'NR == 1 { print $1 }')
if [[ $installed_tiup != "$TIUP_VERSION" ]]; then
	echo "TiUP version mismatch: need $TIUP_VERSION from versions.env, found $installed_tiup" >&2
	exit 1
fi

if [[ $variant == compress-zstd || $variant == tls-proxy-zstd ]]; then
	if ! mysql --help 2>&1 | grep -q -- '--compression-algorithms'; then
		echo "the selected MySQL client does not support --compression-algorithms=zstd" >&2
		exit 1
	fi
fi

if [[ $mode == go ]]; then
	echo "preflight ok: Go baseline, TiDB $TIDB_VERSION, variant $variant"
	exit 0
fi

rust_binary=${TIPROXY_RS_BIN:-$repo_root/rust/target/debug/tiproxy-rs}
if [[ ! -x $rust_binary ]]; then
	cat >&2 <<EOF
Rust dataplane integration preflight failed: executable not found at $rust_binary.
Build it with 'make rust-build' or set TIPROXY_RS_BIN.
DPL-03 provides the control/generation owner, but the complete Rust SQL proxy
still depends on the DPL-04 session owner and DPL-07 topology projection.
EOF
	exit 78
fi

set +e
capabilities=$($rust_binary --integration-capabilities 2>&1)
capability_status=$?
set -e
if ((capability_status != 0)); then
	cat >&2 <<EOF
Rust dataplane integration preflight failed: '$rust_binary --integration-capabilities' exited $capability_status.
The topology will not substitute a raw TCP relay or the Go dataplane for Rust.

Remaining implementation dependencies for truthful SELECT 1:
  session lifecycle/effects: #38
  namespace/topology path:   #41

DPL-03 deliberately does not advertise end-to-end integration capabilities
until those owners replace its typed parked-session/topology seams.

Executable output:
$capabilities
EOF
	exit 78
fi

for capability in control-bridge-v1 mysql-listener health-endpoint graceful-shutdown; do
	if [[ ",$capabilities," != *",$capability,"* ]]; then
		echo "Rust dataplane integration preflight failed: capability '$capability' is absent from '$capabilities'" >&2
		exit 78
	fi
done
if [[ $variant == tls || $variant == tls-proxy-zstd ]] && [[ ",$capabilities," != *",tls,"* ]]; then
	echo "Rust dataplane integration preflight failed: TLS capability is absent" >&2
	exit 78
fi
if [[ $variant == proxy || $variant == tls-proxy-zstd ]] && [[ ",$capabilities," != *",proxy-v2,"* ]]; then
	echo "Rust dataplane integration preflight failed: PROXY v2 capability is absent" >&2
	exit 78
fi
if [[ $variant == compress-zlib ]] && [[ ",$capabilities," != *",zlib,"* ]]; then
	echo "Rust dataplane integration preflight failed: zlib capability is absent" >&2
	exit 78
fi
if [[ $variant == compress-zstd || $variant == tls-proxy-zstd ]] && [[ ",$capabilities," != *",zstd,"* ]]; then
	echo "Rust dataplane integration preflight failed: zstd capability is absent" >&2
	exit 78
fi

echo "preflight ok: Rust dataplane, TiDB $TIDB_VERSION, variant $variant"
