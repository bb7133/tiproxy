#!/usr/bin/env bash
# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

if [[ $# -ne 2 ]]; then
	echo "usage: $0 RUN_DIRECTORY PLAYGROUND_TAG" >&2
	exit 2
fi

run_dir=$(cd "$1" && pwd)
tag=$2
case "$tag" in
	tiproxy-dp-go-* | tiproxy-dp-rust-*) ;;
	*)
		echo "refusing to clean unexpected playground tag: $tag" >&2
		exit 2
		;;
esac

if [[ -f $run_dir/state.env ]]; then
	# shellcheck disable=SC1090
	source "$run_dir/state.env"
fi

stop_owned_process() {
	local pid=$1
	local expected=$2
	local signal=INT
	local command_line
	local process_state
	[[ $pid =~ ^[0-9]+$ ]] || return 0
	command_line=$(ps -p "$pid" -o command= 2>/dev/null || true)
	[[ -n $command_line ]] || return 0
	if [[ $command_line != *"$expected"* ]]; then
		echo "refusing to signal PID $pid: command does not contain '$expected'" >&2
		return 1
	fi
	kill -s "$signal" "$pid" 2>/dev/null || true
	for _ in {1..300}; do
		process_state=$(ps -p "$pid" -o state= 2>/dev/null || true)
		[[ -z $process_state || $process_state == Z* ]] && return 0
		sleep 0.1
	done
	kill -s TERM "$pid" 2>/dev/null || true
	for _ in {1..100}; do
		process_state=$(ps -p "$pid" -o state= 2>/dev/null || true)
		[[ -z $process_state || $process_state == Z* ]] && return 0
		sleep 0.1
	done
	echo "owned process $pid did not exit after INT and TERM" >&2
	return 1
}

cleanup_status=0
# Error-parity conflict phase leftovers (present only when that phase
# started and then failed before its own teardown).
stop_owned_process "${HOLDER_PID:-}" "$run_dir/faultproxy" || cleanup_status=1
stop_owned_process "${CONFLICT_PID:-}" "$run_dir/tiproxy-conflict.toml" || cleanup_status=1
stop_owned_process "${RUST_CONFLICT_PID:-}" "$run_dir/absent.sock" || cleanup_status=1
stop_owned_process "${FAULT_PID:-}" "$run_dir/faultproxy" || cleanup_status=1
# SIGINT drives tiproxy-rs's coordinated shutdown (stop-accept ->
# graceful drain -> force -> join); its command line carries this run's
# unique control-socket path, satisfying the ownership check.
if [[ -n ${RUST_SOCKET:-} ]]; then
	stop_owned_process "${RUST_PID:-}" "$RUST_SOCKET" || cleanup_status=1
	rm -f "$RUST_SOCKET"
fi

# Ask only a playground this run actually started to stop and clean before
# signaling its launcher. Calling `tiup clean` for a preflight-only run creates
# an empty tag directory even though the topology was never provisioned.
if [[ ${TIUP_PID:-} =~ ^[0-9]+$ ]] && command -v tiup >/dev/null 2>&1; then
	tiup clean "$tag" >>"$run_dir/cleanup.log" 2>&1 || true
fi
stop_owned_process "${TIUP_PID:-}" "$tag" || cleanup_status=1

# If the launcher failed before or during TiUP cleanup, delete only a directory
# bearing the marker written by this exact run. The validated tag and marker
# prevent this fallback from touching any unrelated playground.
tiup_root=${TIUP_HOME:-${HOME}/.tiup}
tiup_data="$tiup_root/data/$tag"
ownership_marker="$tiup_data/.tiproxy-integration-owned"
if [[ -d $tiup_data ]]; then
	if [[ -f $ownership_marker && $(<"$ownership_marker") == "$run_dir" ]]; then
		rm -rf "$tiup_data"
	elif [[ ${TIUP_PID:-} =~ ^[0-9]+$ ]]; then
		echo "refusing to remove unmarked TiUP data directory: $tiup_data" >&2
		cleanup_status=1
	fi
fi

# Second backend cluster's playground (dual-cluster runs): same
# stop/clean/marker discipline under its own tag.
if [[ ${TAG_B:-} == tiproxy-dp-go-*-b || ${TAG_B:-} == tiproxy-dp-rust-*-b ]]; then
	if [[ ${TIUP_B_PID:-} =~ ^[0-9]+$ ]] && command -v tiup >/dev/null 2>&1; then
		tiup clean "$TAG_B" >>"$run_dir/cleanup.log" 2>&1 || true
	fi
	stop_owned_process "${TIUP_B_PID:-}" "$TAG_B" || cleanup_status=1
	tiup_data_b="$tiup_root/data/$TAG_B"
	marker_b="$tiup_data_b/.tiproxy-integration-owned"
	if [[ -d $tiup_data_b ]]; then
		if [[ -f $marker_b && $(<"$marker_b") == "$run_dir" ]]; then
			rm -rf "$tiup_data_b"
		elif [[ ${TIUP_B_PID:-} =~ ^[0-9]+$ ]]; then
			echo "refusing to remove unmarked TiUP data directory: $tiup_data_b" >&2
			cleanup_status=1
		fi
	fi
fi

if [[ -x ${FAULT_PROXY_BIN:-$run_dir/faultproxy} && -n ${PORTS:-} ]]; then
	for port in $PORTS; do
		for _ in {1..30}; do
			if ! "${FAULT_PROXY_BIN:-$run_dir/faultproxy}" --probe "127.0.0.1:$port" >/dev/null 2>&1; then
				break
			fi
			sleep 0.1
		done
		if "${FAULT_PROXY_BIN:-$run_dir/faultproxy}" --probe "127.0.0.1:$port" >/dev/null 2>&1; then
			echo "port leaked after cleanup: $port" >&2
			cleanup_status=1
		fi
	done
fi

# Generated private keys are never part of retained CI artifacts.
cert_dir="$run_dir/certs"
if [[ -d $cert_dir ]]; then
	rm -rf "$cert_dir"
fi

exit "$cleanup_status"
