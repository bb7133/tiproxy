#!/usr/bin/env bash
# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
	echo "usage: $0 RUN_DIRECTORY [TIMEOUT_SECONDS]" >&2
	exit 2
fi

run_dir=$1
timeout_seconds=${2:-120}
if [[ ! $timeout_seconds =~ ^[0-9]+$ ]] || ((timeout_seconds < 1)); then
	echo "timeout must be a positive integer" >&2
	exit 2
fi
# shellcheck disable=SC1090
source "$run_dir/variant.env"
# shellcheck disable=SC1090
source "$run_dir/state.env"

mysql_tls_args=()
if [[ $TLS_ENABLED == true ]]; then
	mysql_tls_args=(
		--ssl-mode=VERIFY_IDENTITY
		--ssl-ca="$CA_CERT"
		--ssl-cert="$CLIENT_CERT"
		--ssl-key="$CLIENT_KEY"
	)
else
	mysql_tls_args=(--ssl-mode=DISABLED)
fi

mysql_ingress_compression_arg=
case "$COMPRESSION" in
	none) ;;
	zlib) mysql_ingress_compression_arg=--compression-algorithms=zlib ;;
	zstd) mysql_ingress_compression_arg=--compression-algorithms=zstd ;;
	*)
		echo "unexpected compression mode: $COMPRESSION" >&2
		exit 2
		;;
esac

mysql_query() {
	local port=$1
	local query=$2
	shift 2
	mysql --batch --skip-column-names --connect-timeout=2 \
		-h 127.0.0.1 -P "$port" -u root \
		"${mysql_tls_args[@]}" "$@" -e "$query"
}

owned_processes_alive() {
	for pid in "$TIUP_PID" "$FAULT_PID"; do
		if ! kill -0 "$pid" 2>/dev/null; then
			echo "topology process exited before readiness: PID $pid" >&2
			return 1
		fi
	done
}

deadline=$((SECONDS + timeout_seconds))
until curl --noproxy '*' --fail --silent --show-error --max-time 2 \
	"http://127.0.0.1:$TIPROXY_API_PORT/api/debug/health" >"$run_dir/tiproxy-health.json" 2>/dev/null; do
	owned_processes_alive
	if ((SECONDS >= deadline)); then
		echo "TiProxy health endpoint was not ready after ${timeout_seconds}s" >&2
		exit 1
	fi
	sleep 1
done

until curl --noproxy '*' --fail --silent --show-error --max-time 2 \
	"http://127.0.0.1:$FAULT_ADMIN_PORT/healthz" >"$run_dir/faultproxy-health.json" 2>/dev/null; do
	owned_processes_alive
	if ((SECONDS >= deadline)); then
		echo "fault proxy was not ready after ${timeout_seconds}s" >&2
		exit 1
	fi
	sleep 1
done

# Checking both backend SQL ports independently proves the requested two-TiDB
# topology exists; the final check below exercises the actual proxy ingress.
for backend_port in "$TIDB_PORT_0" "$TIDB_PORT_1"; do
	until [[ $(mysql_query "$backend_port" 'SELECT 1' 2>/dev/null) == 1 ]]; do
		owned_processes_alive
		if ((SECONDS >= deadline)); then
			echo "TiDB backend $backend_port was not SQL-ready after ${timeout_seconds}s" >&2
			exit 1
		fi
		sleep 1
	done
done

until [[ $(mysql_query "$FAULT_PORT" 'SELECT 1' ${mysql_ingress_compression_arg:+"$mysql_ingress_compression_arg"} 2>/dev/null) == 1 ]]; do
	owned_processes_alive
	if ((SECONDS >= deadline)); then
		echo "proxied SELECT 1 was not ready after ${timeout_seconds}s" >&2
		exit 1
	fi
	sleep 1
done

echo "ready: two TiDB backends and proxied SELECT 1 ($VARIANT)"
