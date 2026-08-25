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
artifact_root=${DATAPLANE_ARTIFACT_ROOT:-$script_dir/artifacts}
port_offset=${DATAPLANE_PORT_OFFSET:-$((10000 + ($$ % 20) * 100))}

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
		--artifact-root)
			artifact_root=${2:?missing value for --artifact-root}
			shift 2
			;;
		--port-offset)
			port_offset=${2:?missing value for --port-offset}
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

if [[ $variant == all ]]; then
	variants=(plain tls proxy compress-zlib compress-zstd tls-proxy-zstd)
	for index in "${!variants[@]}"; do
		"$0" --mode "$mode" --variant "${variants[$index]}" \
			--artifact-root "$artifact_root" --port-offset "$((port_offset + index * 100))"
	done
	exit 0
fi

case "$variant" in
	plain | tls | proxy | compress-zlib | compress-zstd | tls-proxy-zstd) ;;
	*)
		echo "unknown variant: $variant" >&2
		exit 2
		;;
esac
if [[ ! $port_offset =~ ^[0-9]+$ ]] || ((port_offset < 1000 || port_offset > 20000)); then
	echo "port offset must be an integer from 1000 through 20000" >&2
	exit 2
fi

mkdir -p "$artifact_root"
artifact_root=$(cd "$artifact_root" && pwd)
tag="tiproxy-dp-$mode-$variant-$$"
run_dir="$artifact_root/$tag"
mkdir -p "$run_dir"

finalize() {
	local status=$?
	local cleanup_status=0
	trap - EXIT
	set +e
	"$script_dir/collect-diagnostics.sh" "$run_dir" "$tag"
	"$script_dir/cleanup.sh" "$run_dir" "$tag"
	cleanup_status=$?
	set -e
	if ((status == 0 && cleanup_status != 0)); then
		status=$cleanup_status
	fi
	echo "integration artifacts: $run_dir"
	exit "$status"
}
trap finalize EXIT

set +e
"$script_dir/preflight.sh" --mode "$mode" --variant "$variant" >"$run_dir/preflight.log" 2>&1
preflight_status=$?
set -e
if ((preflight_status != 0)); then
	cat "$run_dir/preflight.log" >&2
	exit "$preflight_status"
fi

if [[ $mode == rust ]]; then
	cat >"$run_dir/rust-launch-blocker.log" <<'EOF'
Rust capabilities were reported, but FND-04 does not yet have a truthful Go
control-bridge launch contract. Refusing to substitute the Go proxy or a raw
TCP relay. Add that wiring only with the real control bridge and Rust runtime
implemented by #10-#15 and #34-#37.
EOF
	cat "$run_dir/rust-launch-blocker.log" >&2
	exit 78
fi

make -C "$repo_root" cmd_tiproxy >"$run_dir/go-build.log" 2>&1
go build -o "$run_dir/faultproxy" "$script_dir/faultproxy"
"$script_dir/render-configs.sh" "$run_dir" "$variant" "$port_offset" >"$run_dir/render.log"
# shellcheck disable=SC1090
source "$run_dir/variant.env"

PORTS="$PD_PORT $((2380 + port_offset)) $((20160 + port_offset)) $((20180 + port_offset)) $TIDB_PORT_0 $TIDB_PORT_1 $((10080 + port_offset)) $((10081 + port_offset)) $TIPROXY_PORT $TIPROXY_API_PORT $FAULT_PORT $FAULT_ADMIN_PORT"
FAULT_PROXY_BIN="$run_dir/faultproxy"
TIUP_PID=
FAULT_PID=
write_state() {
	{
		printf 'TIUP_PID=%q\n' "$TIUP_PID"
		printf 'FAULT_PID=%q\n' "$FAULT_PID"
		printf 'FAULT_PROXY_BIN=%q\n' "$FAULT_PROXY_BIN"
		printf 'PORTS=%q\n' "$PORTS"
	} >"$run_dir/state.env"
}
write_state

for port in $PORTS; do
	if "$FAULT_PROXY_BIN" --probe "127.0.0.1:$port" >/dev/null 2>&1; then
		echo "required port is already in use: $port" >&2
		exit 1
	fi
done

tiup playground "$TIDB_VERSION" --tag "$tag" --without-monitor \
	--host 127.0.0.1 --port-offset "$port_offset" \
	--pd 1 --kv 1 --db 2 --tiflash 0 --db.config "$run_dir/tidb.toml" \
	--tiproxy 1 --tiproxy.binpath "$repo_root/bin/tiproxy" \
	--tiproxy.config "$run_dir/tiproxy.toml" \
	>"$run_dir/tiup-playground.log" 2>&1 &
TIUP_PID=$!
write_state

tiup_data=${TIUP_HOME:-${HOME}/.tiup}/data/$tag
for _ in {1..50}; do
	[[ -d $tiup_data ]] && break
	if ! kill -0 "$TIUP_PID" 2>/dev/null; then
		break
	fi
	sleep 0.1
done
if [[ -d $tiup_data ]]; then
	printf '%s\n' "$run_dir" >"$tiup_data/.tiproxy-integration-owned"
fi

faultproxy_args=(
	--listen "127.0.0.1:$FAULT_PORT"
	--admin "127.0.0.1:$FAULT_ADMIN_PORT"
	--target "127.0.0.1:$TIPROXY_PORT"
)
if [[ $PROXY_ENABLED == true ]]; then
	faultproxy_args+=(--proxy-v2)
fi
"$FAULT_PROXY_BIN" "${faultproxy_args[@]}" >"$run_dir/faultproxy.log" 2>&1 &
FAULT_PID=$!
write_state

"$script_dir/readiness.sh" "$run_dir" 180 | tee "$run_dir/readiness.log"

mysql_tls_args=()
if [[ $TLS_ENABLED == true ]]; then
	mysql_tls_args=(--ssl-mode=VERIFY_IDENTITY --ssl-ca="$CA_CERT" --ssl-cert="$CLIENT_CERT" --ssl-key="$CLIENT_KEY")
else
	mysql_tls_args=(--ssl-mode=DISABLED)
fi
mysql_compression_arg=
case "$COMPRESSION" in
	zlib) mysql_compression_arg=--compression-algorithms=zlib ;;
	zstd) mysql_compression_arg=--compression-algorithms=zstd ;;
esac
mysql_ingress() {
	mysql --batch --skip-column-names --connect-timeout=2 \
		-h 127.0.0.1 -P "$FAULT_PORT" -u root \
		"${mysql_tls_args[@]}" ${mysql_compression_arg:+"$mysql_compression_arg"} -e "$1"
}

select_result=$(mysql_ingress 'SELECT 1')
if [[ $select_result != 1 ]]; then
	echo "unexpected SELECT 1 result: $select_result" >&2
	exit 1
fi

curl --noproxy '*' --fail --silent --show-error -X POST \
	"http://127.0.0.1:$FAULT_ADMIN_PORT/fault/drop-next" -o /dev/null
if mysql_ingress 'SELECT 1' >"$run_dir/drop-next.out" 2>&1; then
	echo "fault injection failed: drop-next SELECT unexpectedly succeeded" >&2
	exit 1
fi
if [[ $(mysql_ingress 'SELECT 1') != 1 ]]; then
	echo "proxy did not recover after the injected connection drop" >&2
	exit 1
fi

echo "PASS: Go baseline $variant executed SELECT 1 and recovered from drop-next"
