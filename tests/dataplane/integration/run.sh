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

rust_binary=
if [[ $mode == rust ]]; then
	# Preflight already verified the binary and its capability contract.
	rust_binary=${TIPROXY_RS_BIN:-$repo_root/rust/target/debug/tiproxy-rs}
fi

make -C "$repo_root" cmd_tiproxy >"$run_dir/go-build.log" 2>&1
go build -o "$run_dir/faultproxy" "$script_dir/faultproxy"
"$script_dir/render-configs.sh" "$run_dir" "$variant" "$port_offset" >"$run_dir/render.log"
# shellcheck disable=SC1090
source "$run_dir/variant.env"

PORTS="$PD_PORT $((2380 + port_offset)) $((20160 + port_offset)) $((20180 + port_offset)) $TIDB_PORT_0 $TIDB_PORT_1 $((10080 + port_offset)) $((10081 + port_offset)) $TIPROXY_PORT $TIPROXY_API_PORT $FAULT_PORT $FAULT_ADMIN_PORT"
RUST_HEALTH_PORT=$((8090 + port_offset))
RUST_SOCKET="${TMPDIR:-/tmp}/$tag.sock"
if [[ $mode == rust ]]; then
	# The Go process cedes the SQL listeners entirely: with the gate
	# enabled it serves only the control plane and API, and the Rust
	# process binds proxy.addr from its wire snapshot. The socket lives
	# under /tmp with the run's unique tag: macOS caps sun_path around
	# 104 bytes, far shorter than the artifact directory path.
	printf '\n[rust-dataplane]\nenabled = true\ncontrol-socket = "%s"\n' \
		"$RUST_SOCKET" >>"$run_dir/tiproxy.toml"
	PORTS="$PORTS $RUST_HEALTH_PORT"
fi
FAULT_PROXY_BIN="$run_dir/faultproxy"
TIUP_PID=
FAULT_PID=
RUST_PID=
write_state() {
	{
		printf 'TIUP_PID=%q\n' "$TIUP_PID"
		printf 'FAULT_PID=%q\n' "$FAULT_PID"
		printf 'RUST_PID=%q\n' "$RUST_PID"
		printf 'RUST_SOCKET=%q\n' "$RUST_SOCKET"
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

if [[ $mode == rust ]]; then
	control_socket="$RUST_SOCKET"
	# The Go control plane creates the socket when it starts; waiting
	# here keeps the launch independent of client reconnect timing.
	for _ in {1..600}; do
		[[ -S $control_socket ]] && break
		if ! kill -0 "$TIUP_PID" 2>/dev/null; then
			echo "TiUP playground exited before the control socket appeared" >&2
			exit 1
		fi
		sleep 0.1
	done
	if [[ ! -S $control_socket ]]; then
		echo "Rust control socket did not appear: $control_socket" >&2
		exit 1
	fi
	"$rust_binary" --control-socket "$control_socket" --control-uid "$(id -u)" \
		--health-port "$RUST_HEALTH_PORT" \
		>"$run_dir/tiproxy-rs.log" 2>&1 &
	RUST_PID=$!
	write_state
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

if [[ $mode == rust ]]; then
	# Gate the shared readiness phase on the Rust process itself: the
	# health endpoint turns 200 once the first generation applies
	# (independent of TiDB warm-up), and a dead tiproxy-rs fails fast
	# here instead of burning the full readiness timeout.
	rust_ready=false
	for _ in {1..180}; do
		if curl --noproxy '*' --fail --silent --max-time 5 \
			"http://127.0.0.1:$RUST_HEALTH_PORT/health" \
			>"$run_dir/tiproxy-rs-health.json" 2>/dev/null; then
			rust_ready=true
			break
		fi
		if ! kill -0 "$RUST_PID" 2>/dev/null; then
			echo "tiproxy-rs exited before readiness; see tiproxy-rs.log" >&2
			exit 1
		fi
		sleep 1
	done
	if [[ $rust_ready != true ]]; then
		echo "Rust dataplane health endpoint was not ready after 180s" >&2
		exit 1
	fi
fi

# The shared readiness phase is monitored: if the Rust process dies
# mid-phase the run fails immediately instead of burning the timeout.
"$script_dir/readiness.sh" "$run_dir" 180 >"$run_dir/readiness.log" 2>&1 &
READINESS_PID=$!
while kill -0 "$READINESS_PID" 2>/dev/null; do
	if [[ -n ${RUST_PID:-} ]] && ! kill -0 "$RUST_PID" 2>/dev/null; then
		kill "$READINESS_PID" 2>/dev/null
		cat "$run_dir/readiness.log"
		echo "tiproxy-rs died during readiness; see tiproxy-rs.log" >&2
		exit 1
	fi
	sleep 1
done
if ! wait "$READINESS_PID"; then
	cat "$run_dir/readiness.log"
	exit 1
fi
cat "$run_dir/readiness.log"

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

# Namespace/topology matrix (DPL-07 #41): three username-resolved
# combinations against the REAL cluster, identical in both modes. Each
# custom namespace pins ONE backend through static instances, so
# `SELECT @@port` proves which backend class served the client; root
# keeps the PD-backed default namespace.
mysql_backend_admin() {
	mysql --batch --skip-column-names --connect-timeout=2 \
		-h 127.0.0.1 -P "$TIDB_PORT_0" -u root --ssl-mode=DISABLED -e "$1"
}
mysql_ingress_as() {
	local user=$1
	local query=$2
	mysql --batch --skip-column-names --connect-timeout=4 \
		-h 127.0.0.1 -P "$FAULT_PORT" -u "$user" \
		"${mysql_tls_args[@]}" ${mysql_compression_arg:+"$mysql_compression_arg"} -e "$query"
}
mysql_backend_admin "CREATE USER IF NOT EXISTS 'alice'@'%'; CREATE USER IF NOT EXISTS 'bob'@'%';"
namespace_api="http://127.0.0.1:$TIPROXY_API_PORT/api/admin/namespace"
curl --noproxy '*' --fail --silent --show-error -X PUT \
	-H 'Content-Type: application/json' \
	-d "{\"namespace\":\"ns-alpha\",\"frontend\":{\"user\":\"alice\"},\"backend\":{\"instances\":[\"127.0.0.1:$TIDB_PORT_0\"]}}" \
	"$namespace_api/ns-alpha" -o /dev/null
curl --noproxy '*' --fail --silent --show-error -X PUT \
	-H 'Content-Type: application/json' \
	-d "{\"namespace\":\"ns-beta\",\"frontend\":{\"user\":\"bob\"},\"backend\":{\"instances\":[\"127.0.0.1:$TIDB_PORT_1\"]}}" \
	"$namespace_api/ns-beta" -o /dev/null
curl --noproxy '*' --fail --silent --show-error -X POST \
	"$namespace_api/commit?namespace=ns-alpha&namespace=ns-beta" -o /dev/null

namespace_matrix() {
	local alice_port bob_port root_port
	alice_port=$(mysql_ingress_as alice 'SELECT @@port' 2>/dev/null) || return 1
	bob_port=$(mysql_ingress_as bob 'SELECT @@port' 2>/dev/null) || return 1
	# root resolves to the PD-backed default namespace, whose router
	# holds BOTH backends: its landing must be one of the two real
	# TiDB ports — the property that distinguishes the default class
	# from the single-backend pinned namespaces.
	root_port=$(mysql_ingress_as root 'SELECT @@port' 2>/dev/null) || return 1
	[[ $alice_port == "$TIDB_PORT_0" && $bob_port == "$TIDB_PORT_1" ]] || return 1
	[[ $root_port == "$TIDB_PORT_0" || $root_port == "$TIDB_PORT_1" ]]
}
namespace_ready=false
for _ in {1..30}; do
	if namespace_matrix; then
		namespace_ready=true
		break
	fi
	sleep 1
done
if [[ $namespace_ready != true ]]; then
	{
		echo "namespace matrix failed:"
		echo "  alice -> $(mysql_ingress_as alice 'SELECT @@port' 2>&1 | tail -1) (want $TIDB_PORT_0)"
		echo "  bob   -> $(mysql_ingress_as bob 'SELECT @@port' 2>&1 | tail -1) (want $TIDB_PORT_1)"
		echo "  root  -> $(mysql_ingress_as root 'SELECT @@port' 2>&1 | tail -1) (want $TIDB_PORT_0 or $TIDB_PORT_1)"
	} >&2
	exit 1
fi
# The third matrix row needs DISCRIMINATING evidence, not mere
# success: the lifecycle logs attribute every connection to the
# namespace the handshake decision resolved. In Rust mode the engine's
# closed-schema logs carry it exactly; in Go mode the per-connection
# logger fields carry it for the pinned namespaces.
if [[ $mode == rust ]]; then
	for expected in '"namespace":"ns-alpha"' '"namespace":"ns-beta"' '"namespace":"default"'; do
		if ! grep -q "\"event\":\"connection_ready\".*$expected" "$run_dir/tiproxy-rs.log"; then
			echo "missing Rust lifecycle namespace attribution: $expected" >&2
			exit 1
		fi
	done
else
	# Under TiUP the Go component logs live in the run's tag data
	# directory (still alive here; cleanup removes it later).
	go_log_root="${TIUP_HOME:-${HOME}/.tiup}/data/$tag"
	for expected in '"ns":"ns-alpha"' '"ns":"ns-beta"'; do
		if ! grep -rq "$expected" "$go_log_root"; then
			echo "missing Go connection namespace attribution: $expected" >&2
			exit 1
		fi
	done
fi
echo "namespace matrix: alice->ns-alpha($TIDB_PORT_0) bob->ns-beta($TIDB_PORT_1) root->default"

if [[ $mode == rust ]]; then
	echo "PASS: Rust dataplane $variant executed SELECT 1, namespace matrix, and recovered from drop-next"
else
	echo "PASS: Go baseline $variant executed SELECT 1, namespace matrix, and recovered from drop-next"
fi
