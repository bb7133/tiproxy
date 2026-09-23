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

# Deciseconds allowed after SIGINT, then after SIGTERM, before giving up.
#
# A single helper (faultproxy, a dropper, one tiproxy) exits promptly. A
# `tiup playground` has to stop an entire cluster — PD, TiKV, two TiDB and a
# TiProxy — and on a loaded CI runner that legitimately takes longer than the
# 30s/10s a helper needs. Issue #274: one uniform budget made a passing test
# fail during teardown, twice, on two different integration targets.
readonly STOP_INT_DECISECONDS=300
readonly STOP_TERM_DECISECONDS=100
readonly STOP_INT_DECISECONDS_CLUSTER=1200
readonly STOP_TERM_DECISECONDS_CLUSTER=300

# stop_owned_process PID EXPECTED_MARKER [class]
#
# `class` selects the shutdown budget: "cluster" for a whole playground,
# anything else (default) for a single helper process.
stop_owned_process() {
	local pid=$1
	local expected=$2
	local class=${3:-helper}
	local signal=INT
	local command_line
	local process_state
	local int_budget=$STOP_INT_DECISECONDS
	local term_budget=$STOP_TERM_DECISECONDS
	if [[ $class == cluster ]]; then
		int_budget=$STOP_INT_DECISECONDS_CLUSTER
		term_budget=$STOP_TERM_DECISECONDS_CLUSTER
	fi
	[[ $pid =~ ^[0-9]+$ ]] || return 0
	command_line=$(ps -p "$pid" -o command= 2>/dev/null || true)
	[[ -n $command_line ]] || return 0
	# Marker check first: never signal a PID this run does not own.
	if [[ $command_line != *"$expected"* ]]; then
		echo "refusing to signal PID $pid: command does not contain '$expected'" >&2
		return 1
	fi
	kill -s "$signal" "$pid" 2>/dev/null || true
	for ((i = 0; i < int_budget; i++)); do
		process_state=$(ps -p "$pid" -o state= 2>/dev/null || true)
		[[ -z $process_state || $process_state == Z* ]] && return 0
		sleep 0.1
	done
	kill -s TERM "$pid" 2>/dev/null || true
	for ((i = 0; i < term_budget; i++)); do
		process_state=$(ps -p "$pid" -o state= 2>/dev/null || true)
		[[ -z $process_state || $process_state == Z* ]] && return 0
		sleep 0.1
	done
	# Name what failed. The previous message carried only the PID, so working
	# out which owned process it was meant downloading the CI artifact.
	process_state=$(ps -p "$pid" -o state= 2>/dev/null || true)
	local children
	# GNU ps; absent on macOS, where this block is only read by a developer
	# reproducing locally, so print the line only when there is something.
	children=$(ps --ppid "$pid" -o pid=,state=,command= 2>/dev/null || true)
	{
		echo "owned process $pid did not exit after INT and TERM"
		echo "  class=$class budget=INT ${int_budget}ds then TERM ${term_budget}ds"
		echo "  marker=$expected"
		echo "  state=${process_state:-<gone>}"
		echo "  command=$command_line"
		[[ -n $children ]] && printf '  children:\n%s\n' "$(echo "$children" | sed 's/^/    /')"
	} >&2
	# Bounded either way: report and let the caller set cleanup_status. Whether
	# to add a final SIGKILL backstop is deliberately left to issue #274, since
	# it trades guaranteed teardown against losing a hung process's state.
	return 1
}

cleanup_status=0
# Error-parity conflict phase leftovers (present only when that phase
# started and then failed before its own teardown).
# Keyspace-guard phase leftovers (present only when that phase started
# and then failed before its own teardown).
if [[ -n ${KA_SOCKET:-} ]]; then
	stop_owned_process "${KA_RUST_PID:-}" "${KA_RUST_CONTROL_SOCKET:-$KA_SOCKET}" || cleanup_status=1
	rm -f "$KA_SOCKET"
fi
if [[ -n ${KA_DROP_SOCKET:-} ]]; then
	# stop_owned_process returns 0 for an invalid/already-gone PID, so a
	# success verdict alone does NOT prove the front path belongs to a
	# stopped dropper. Discriminate the inode before unlinking so the
	# fail-closed case (a pre-placed regular file that the dropper's own
	# Lstat rejected, after which its PID vanished) can never delete a
	# bystander: absent -> nothing to do; not a socket -> keep and fail;
	# a socket -> remove only after an owned stop and with no live holder.
	drop_stopped=0
	if stop_owned_process "${KA_DROP_PID:-}" "$run_dir/controldropper"; then
		drop_stopped=1
	else
		cleanup_status=1
	fi
	if [[ -e $KA_DROP_SOCKET ]]; then
		if [[ ! -S $KA_DROP_SOCKET ]]; then
			echo "refusing to remove $KA_DROP_SOCKET: not a socket" >&2
			cleanup_status=1
		elif lsof -- "$KA_DROP_SOCKET" >/dev/null 2>&1; then
			echo "refusing to remove $KA_DROP_SOCKET: still held open" >&2
			cleanup_status=1
		elif ((drop_stopped)); then
			rm -f "$KA_DROP_SOCKET"
		else
			echo "refusing to remove $KA_DROP_SOCKET: owner stop unconfirmed" >&2
			cleanup_status=1
		fi
	fi
fi
stop_owned_process "${KA_PID:-}" "$run_dir/tiproxy-ka.toml" || cleanup_status=1
# MIG-01 live migration session (Rust plain/TLS only). The exact PID and
# FIFO are persisted before the dynamic fail-list swap so a mid-phase failure
# cannot strand the client or its writer endpoint.
if [[ ${MIG_SESSION_PID:-} =~ ^[0-9]+$ ]]; then
	kill "${MIG_SESSION_PID}" 2>/dev/null || true
fi
if [[ -n ${MIG_FIFO:-} ]]; then
	rm -f "$MIG_FIFO"
fi
if [[ ${KA_SESSION_PID:-} =~ ^[0-9]+$ ]]; then
	kill "${KA_SESSION_PID}" 2>/dev/null || true
fi
if [[ -n ${KA_FIFO:-} ]]; then
	rm -f "$KA_FIFO"
fi
# Chaos chain (b)/(a) persistent sessions + FIFOs (present only when that
# chain started and then failed before its own teardown).
if [[ ${KB_SESSION_PID:-} =~ ^[0-9]+$ ]]; then
	kill "${KB_SESSION_PID}" 2>/dev/null || true
fi
if [[ -n ${KB_FIFO:-} ]]; then
	rm -f "$KB_FIFO"
fi
if [[ ${CA_SESSION_PID:-} =~ ^[0-9]+$ ]]; then
	kill "${CA_SESSION_PID}" 2>/dev/null || true
fi
if [[ -n ${CA_FIFO:-} ]]; then
	rm -f "$CA_FIFO"
fi
if [[ ${CC_SESSION_PID:-} =~ ^[0-9]+$ ]]; then
	kill "${CC_SESSION_PID}" 2>/dev/null || true
fi
if [[ -n ${CC_FIFO:-} ]]; then
	rm -f "$CC_FIFO"
fi
for pid_var in CD_SESSION_PID CD2_SESSION_PID; do
	pid=${!pid_var:-}
	[[ $pid =~ ^[0-9]+$ ]] && kill "$pid" 2>/dev/null || true
done
for fifo_var in CD_FIFO CD2_FIFO; do
	fifo=${!fifo_var:-}
	[[ -n $fifo ]] && rm -f "$fifo"
done
stop_owned_process "${HOLDER_PID:-}" "$run_dir/faultproxy" || cleanup_status=1
stop_owned_process "${CONFLICT_PID:-}" "$run_dir/tiproxy-conflict.toml" || cleanup_status=1
stop_owned_process "${RUST_CONFLICT_PID:-}" "$run_dir/absent.sock" || cleanup_status=1
stop_owned_process "${FAULT_PID:-}" "$run_dir/faultproxy" || cleanup_status=1
# SIGINT drives tiproxy-rs's coordinated shutdown (stop-accept ->
# graceful drain -> force -> join); its command line carries this run's
# unique control-socket path, satisfying the ownership check.
if [[ -n ${RUST_SOCKET:-} ]]; then
	stop_owned_process "${RUST_PID:-}" "${RUST_CONTROL_SOCKET:-$RUST_SOCKET}" || cleanup_status=1
	if [[ -n ${T3_DROP_SOCKET:-} ]]; then
		stop_owned_process "${T4_REJECT_PID:-}" "$run_dir/controlrejector" || cleanup_status=1
		t3_drop_stopped=0
		if stop_owned_process "${T3_DROP_PID:-}" "$run_dir/controldropper"; then
			t3_drop_stopped=1
		else
			cleanup_status=1
		fi
		if [[ -e $T3_DROP_SOCKET ]]; then
			if [[ ! -S $T3_DROP_SOCKET ]]; then
				echo "refusing to remove $T3_DROP_SOCKET: not a socket" >&2
				cleanup_status=1
			elif lsof -- "$T3_DROP_SOCKET" >/dev/null 2>&1; then
				echo "refusing to remove $T3_DROP_SOCKET: still held open" >&2
				cleanup_status=1
			elif ((t3_drop_stopped)); then
				rm -f "$T3_DROP_SOCKET"
			else
				echo "refusing to remove $T3_DROP_SOCKET: owner stop unconfirmed" >&2
				cleanup_status=1
			fi
		fi
	fi
	rm -f "$RUST_SOCKET"
fi

# Ask only a playground this run actually started to stop and clean before
# signaling its launcher. Calling `tiup clean` for a preflight-only run creates
# an empty tag directory even though the topology was never provisioned.
if [[ ${TIUP_PID:-} =~ ^[0-9]+$ ]] && command -v tiup >/dev/null 2>&1; then
	tiup clean "$tag" >>"$run_dir/cleanup.log" 2>&1 || true
fi
stop_owned_process "${TIUP_PID:-}" "$tag" cluster || cleanup_status=1

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
# stop/clean/marker discipline. TAG_B must be EXACTLY this run's
# derived secondary tag — a state file naming any other playground is
# refused, never cleaned.
if [[ -n ${TAG_B:-} && ${TAG_B} != "$tag-b" ]]; then
	echo "refusing secondary cleanup: TAG_B '$TAG_B' is not '$tag-b'" >&2
	cleanup_status=1
fi
if [[ ${TAG_B:-} == "$tag-b" ]]; then
	if [[ ${TIUP_B_PID:-} =~ ^[0-9]+$ ]] && command -v tiup >/dev/null 2>&1; then
		tiup clean "$TAG_B" >>"$run_dir/cleanup.log" 2>&1 || true
	fi
	stop_owned_process "${TIUP_B_PID:-}" "$TAG_B" cluster || cleanup_status=1
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
