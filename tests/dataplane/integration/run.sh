#!/usr/bin/env bash
# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd "$script_dir/../../.." && pwd)
# shellcheck source=versions.env
source "$script_dir/versions.env"

resolve_etcdctl() {
	local exact="${TIUP_HOME:-${HOME}/.tiup}/components/ctl/${TIDB_VERSION}/etcdctl"
	if [[ -x $exact ]]; then
		printf '%s\n' "$exact"
		return 0
	fi
	# Formal qualification must use the frozen same-release client installed by
	# warm-tiup-components.sh.  Developer runs may use an explicit host client.
	if [[ ${DATAPLANE_T4_QUALIFICATION:-0} != 1 ]]; then
		command -v etcdctl 2>/dev/null && return 0
	fi
	return 1
}

mode=rust
variant=plain
# Single-process acceptance (task #140): tiup starts no Go tiproxy and the
# standalone Rust binary owns the SQL listeners with no Go control peer.
standalone=${DATAPLANE_STANDALONE:-0}
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

# DATAPLANE_STANDALONE is a single-process acceptance mode: it runs the
# main --standalone MIG-01 and exits before the Go-coupled sub-phases.
# Reject combinations it cannot honestly execute, before the variant=all
# recursion, so an early exit can never mark un-run phases as passed.
if [[ $standalone == 1 ]]; then
	if [[ $mode != rust ]]; then
		echo "DATAPLANE_STANDALONE=1 requires --mode rust (a single Rust process; tiup starts no Go tiproxy); got --mode '$mode'" >&2
		exit 2
	fi
	for _sa_flag in DATAPLANE_T3_FOCUSED DATAPLANE_T4_FOCUSED DATAPLANE_T4_QUALIFICATION DATAPLANE_NATIVE_METER; do
		if [[ ${!_sa_flag:-0} == 1 ]]; then
			echo "DATAPLANE_STANDALONE=1 is incompatible with $_sa_flag=1: the standalone path exits after the main-entry MIG-01 and would not run the focused/qualification phases" >&2
			exit 2
		fi
	done
fi
if [[ $variant == all ]]; then
	# The FULL range is validated up front: six variants at stride 200
	# (each run consumes two 100-port windows), so the base must leave
	# room for 18900 + 5*200 = 19900. Failing late on index 5 after
	# five expensive successful runs is exactly what this prevents.
	if [[ ! $port_offset =~ ^[0-9]+$ ]] || ((port_offset < 1000 || port_offset > 18900)); then
		echo "port offset for --variant all must be an integer from 1000 through 18900" >&2
		exit 2
	fi
	variants=(plain tls proxy compress-zlib compress-zstd tls-proxy-zstd)
	for index in "${!variants[@]}"; do
		"$0" --mode "$mode" --variant "${variants[$index]}" \
			--artifact-root "$artifact_root" --port-offset "$((port_offset + index * 200))"
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
# Each run consumes TWO 100-port windows (the second backend cluster
# lives at +100), so the cap matches the renderer's.
if [[ ! $port_offset =~ ^[0-9]+$ ]] || ((port_offset < 1000 || port_offset > 19900)); then
	echo "port offset must be an integer from 1000 through 19900" >&2
	exit 2
fi

mkdir -p "$artifact_root"
artifact_root=$(cd "$artifact_root" && pwd)
tag="tiproxy-dp-$mode-$variant-$$"
run_dir="$artifact_root/$tag"
mkdir -p "$run_dir"

record_t4_phase() {
	[[ ${DATAPLANE_T4_QUALIFICATION:-0} == 1 ]] || return 0
	printf '%s\t%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$1" >>"$run_dir/t4-phase-receipts.tsv"
}
record_t4_phase harness-start

T4_PROCESS_LINEAGE_JSONL="$run_dir/t4-process-lineage.jsonl"
T4_PROCESS_LINEAGE_JSON="$run_dir/t4-process-lineage.json"
record_t4_process() {
	[[ ${DATAPLANE_T4_QUALIFICATION:-0} == 1 ]] || return 0
	local role=${1:?missing process role}
	local event=${2:?missing process event}
	local pid=${3:-0}
	local predecessor=${4:-0}
	local ppid= start=
	if [[ $pid =~ ^[1-9][0-9]*$ ]]; then
		ppid=$(ps -o ppid= -p "$pid" 2>/dev/null | tr -d ' ' || true)
		start=$(ps -o lstart= -p "$pid" 2>/dev/null | sed 's/^[[:space:]]*//' || true)
	fi
	python3 - "$T4_PROCESS_LINEAGE_JSONL" "$role" "$event" "$pid" "$predecessor" "$ppid" "$start" <<'PYT4PROCESS'
import json
import pathlib
import sys
import time

path = pathlib.Path(sys.argv[1])
row = {
    "recorded_unix_nanos": time.time_ns(),
    "role": sys.argv[2],
    "event": sys.argv[3],
    "pid": int(sys.argv[4]),
    "predecessor_pid": int(sys.argv[5]),
    "parent_pid": int(sys.argv[6]) if sys.argv[6].isdigit() else 0,
    "process_start": sys.argv[7],
}
with path.open("a", encoding="utf-8") as output:
    output.write(json.dumps(row, sort_keys=True) + "\n")
PYT4PROCESS
}

close_t4_process_lineage() {
	[[ ${DATAPLANE_T4_QUALIFICATION:-0} == 1 ]] || return 0
	python3 - "$T4_PROCESS_LINEAGE_JSONL" "$T4_PROCESS_LINEAGE_JSON" \
		"${DATAPLANE_T4_ROW:-}" "$variant" "$(uname -sm)" <<'PYT4PROCESSFINAL'
import json
import pathlib
import sys

source, destination = map(pathlib.Path, sys.argv[1:3])
events = []
if source.is_file():
    events = [json.loads(line) for line in source.read_text().splitlines() if line.strip()]
destination.write_text(json.dumps({
    "schema": 1,
    "row": sys.argv[3],
    "variant": sys.argv[4],
    "platform": sys.argv[5],
    "events": events,
}, sort_keys=True, indent=2) + "\n")
PYT4PROCESSFINAL
}

finalize() {
	local status=$?
	local cleanup_status=0
	local audit_output
	trap - EXIT
	set +e
	record_t4_process harness finalizer 0 0
	close_t4_process_lineage
	if [[ $mode == rust && ${DATAPLANE_T4_QUALIFICATION:-0} == 1 && -n ${T3_DROP_PID:-} ]]; then
		audit_output="$run_dir/t4-route-audit-final.json"
		[[ ! -f $audit_output ]] || audit_output="$run_dir/t4-route-audit-cleanup.json"
		curl --noproxy '*' --fail --silent --max-time 5 \
			"http://127.0.0.1:${T3_DROP_ADMIN_PORT:-0}/state" \
			-o "$audit_output" || true
	fi
	# Preserve the keyspace/redirect tap as well when a T4 row fails before
	# its normal final audit.  In particular, a peer metering fatal can stop
	# the Rust process immediately after the tap observes the fatal frame; the
	# failure artifact must retain that first protocol error instead of only an
	# earlier phase snapshot.
	if [[ $mode == rust && ${DATAPLANE_T4_QUALIFICATION:-0} == 1 &&
		-n ${KA_DROP_PID:-} ]] && kill -0 "$KA_DROP_PID" 2>/dev/null; then
		audit_output="$run_dir/t4-route-audit-ka-final.json"
		[[ ! -f $audit_output ]] || audit_output="$run_dir/t4-route-audit-ka-cleanup.json"
		curl --noproxy '*' --fail --silent --max-time 5 \
			"http://127.0.0.1:${ka_drop_admin_port:-0}/state" \
			-o "$audit_output" || true
	fi
	"$script_dir/collect-diagnostics.sh" "$run_dir" "$tag"
	"$script_dir/cleanup.sh" "$run_dir" "$tag"
	cleanup_status=$?
	# cleanup.log does not exist, and tiup-playground.log still ends at
	# "Cluster is started", when the pass above runs. Re-collect just the
	# teardown evidence now that cleanup has finished, so a stuck playground
	# parent leaves a trace instead of being closable only by a re-run.
	"$script_dir/collect-teardown-diagnostics.sh" "$run_dir" || true
	# The producer WAL lives beside its external socket, outside run_dir.
	# Preserve it after owned cleanup, so a tap ACK can be checked against
	# durable producer state without copying a file still being updated.
	if [[ $cleanup_status == 0 && ${DATAPLANE_T4_QUALIFICATION:-0} == 1 &&
		-n ${ka_rust_control_socket:-} && -f ${ka_rust_control_socket}.metering.wal ]]; then
		cp "${ka_rust_control_socket}.metering.wal" "$run_dir/ka-producer-final.wal" || cleanup_status=1
	fi
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
etcdctl_bin=
if [[ $mode == rust ]]; then
	# Preflight already verified the binary and its capability contract.
	rust_binary=${TIPROXY_RS_BIN:-$repo_root/rust/target/debug/tiproxy-rs}
	if ! etcdctl_bin=$(resolve_etcdctl); then
		echo "Rust integration needs frozen ctl:${TIDB_VERSION} (missing ${TIUP_HOME:-${HOME}/.tiup}/components/ctl/${TIDB_VERSION}/etcdctl)" >&2
		exit 1
	fi
	"$etcdctl_bin" version >"$run_dir/etcdctl-version.txt"
	record_t4_phase etcdctl-resolved
fi

make -C "$repo_root" cmd_tiproxy >"$run_dir/go-build.log" 2>&1
go build -o "$run_dir/faultproxy" "$script_dir/faultproxy"
# Rust+plain uses the control-frame dropper for the focused and chaos gates.
# Formal T4 qualification interposes it for every variant and keeps it alive
# for the complete run so the zero-retired-route-traffic assertion is physical,
# not inferred from source or a short startup sample.
if [[ $mode == rust && ($variant == plain || ${DATAPLANE_T4_QUALIFICATION:-0} == 1) ]]; then
	go build -o "$run_dir/controldropper" "$script_dir/controldropper"
	if [[ $variant == plain && ${DATAPLANE_T4_FOCUSED:-0} == 1 ]]; then
		go build -o "$run_dir/controlrejector" "$script_dir/controlrejector"
	fi
fi
"$script_dir/render-configs.sh" "$run_dir" "$variant" "$port_offset" >"$run_dir/render.log"
if [[ ${DATAPLANE_NATIVE_METER:-0} == 1 ]]; then
    if [[ $mode != rust || $variant != plain ]]; then
        echo "native metering focused probe requires Rust plain" >&2
        exit 2
    fi
    cat >>"$run_dir/tiproxy.toml" <<NATIVEMETERCONFIG

[metering]
type = "localfs"
bucket = "native-process-probe"
shared-pool-id = "native-process-probe"
[metering.localfs]
base-path = "$run_dir/meter-objects"
create-dirs = true
permissions = "0755"
NATIVEMETERCONFIG
fi

# The focused T3 oracle needs all three live backends in one route group: A0
# and A1 share ks-old while B carries ks-new. This lets the final phase fail
# both same-keyspace backends without tripping the all-failed safeguard; the
# sole healthy candidate is then a real cross-keyspace refusal, so timeout-zero
# must issue ForceClose instead of Redirect. Other integration modes retain the
# listener-port topology used by their cluster-isolation matrix.
if [[ $mode == rust && $variant == plain && ${DATAPLANE_T3_FOCUSED:-0} == 1 ]]; then
	if [[ $(grep -Fxc 'routing-rule = "port"' "$run_dir/tiproxy.toml") != 1 ]]; then
		echo "T3 focused config expected exactly one listener-port routing rule" >&2
		exit 1
	fi
	sed 's/^routing-rule = "port"$/routing-rule = ""/' \
		"$run_dir/tiproxy.toml" >"$run_dir/tiproxy-t3.toml"
	mv "$run_dir/tiproxy-t3.toml" "$run_dir/tiproxy.toml"
fi
# shellcheck disable=SC1090
source "$run_dir/variant.env"
# Persistent `/config/proxy` mutations replace the process seed wholesale. Keep
# the variant's PROXY-protocol mode in every complete dynamic seed: otherwise a
# proxy cell starts with v2 enabled, the first fail-list mutation silently
# disables the inbound preamble, and later clients send a valid PROXY header to
# a MySQL packet reader (surfacing 2013 instead of the intended 1105 refusal).
dynamic_proxy_protocol=
if [[ $PROXY_ENABLED == true ]]; then
	dynamic_proxy_protocol=v2
fi

PORTS="$PD_PORT $((2380 + port_offset)) $((20160 + port_offset)) $((20180 + port_offset)) $TIDB_PORT_0 $TIDB_PORT_1 $((10080 + port_offset)) $((10081 + port_offset)) $TIPROXY_PORT $TIPROXY_PORT_B $TIPROXY_API_PORT $FAULT_PORT $FAULT_ADMIN_PORT"
# Second backend cluster's playground window (PORT_OFFSET_B).
PORTS="$PORTS $PD_PORT_B $((2380 + PORT_OFFSET_B)) $((20160 + PORT_OFFSET_B)) $((20180 + PORT_OFFSET_B)) $TIDB_PORT_B $((10080 + PORT_OFFSET_B))"
tag_b="$tag-b"
RUST_HEALTH_PORT=$((8090 + port_offset))
RUST_SOCKET="${TMPDIR:-/tmp}/$tag.sock"
RUST_CONTROL_SOCKET=$RUST_SOCKET
T3_DROP_PID=
T3_DROP_SOCKET="${TMPDIR:-/tmp}/$tag-t3-drop.sock"
if [[ ${DATAPLANE_T4_QUALIFICATION:-0} == 1 ]]; then
	if [[ ! ${DATAPLANE_T4_ROW:-} =~ ^M[1-9]$ ]]; then
		echo "DATAPLANE_T4_ROW must be M1 through M9 for formal qualification" >&2
		exit 2
	fi
	# 8091..8093 are intentionally consumed by the later bind-conflict row.
	T3_DROP_ADMIN_PORT=$((8094 + port_offset))
else
	T3_DROP_ADMIN_PORT=$((8091 + port_offset))
fi
T4_REJECT_PID=
T4_REJECT_STATE="$run_dir/t4-control-rejection.json"
MIG_SESSION_PID=
MIG_FIFO=
if [[ $mode == rust ]]; then
	# The Go process cedes the SQL listeners entirely: with the gate
	# enabled it serves only the control plane and API, and the Rust
	# process binds proxy.addr from its wire snapshot. The socket lives
	# under /tmp with the run's unique tag: macOS caps sun_path around
	# 104 bytes, far shorter than the artifact directory path.
	printf '\n[rust-dataplane]\nenabled = true\ncontrol-socket = "%s"\n' \
		"$RUST_SOCKET" >>"$run_dir/tiproxy.toml"
	if [[ $TLS_ENABLED == true ]]; then
		# The control plane refuses to build a snapshot whose TLS cert paths
		# fall outside an explicit allowlist of roots; admit the generated
		# certs so the tls variants can activate frontend/backend TLS.
		printf 'tls-allowed-roots = ["%s"]\n' "$run_dir/certs" >>"$run_dir/tiproxy.toml"
	fi
	PORTS="$PORTS $RUST_HEALTH_PORT"
	if [[ ${DATAPLANE_T4_QUALIFICATION:-0} == 1 ||
		($variant == plain && (${DATAPLANE_T3_FOCUSED:-0} == 1 || ${DATAPLANE_T4_FOCUSED:-0} == 1 || ${DATAPLANE_NATIVE_METER:-0} == 1)) ]]; then
		PORTS="$PORTS $T3_DROP_ADMIN_PORT"
	fi
fi
FAULT_PROXY_BIN="$run_dir/faultproxy"
TIUP_PID=
TIUP_B_PID=
FAULT_PID=
RUST_PID=
write_state() {
	{
		printf 'TIUP_PID=%q\n' "$TIUP_PID"
		printf 'TIUP_B_PID=%q\n' "$TIUP_B_PID"
		printf 'TAG_B=%q\n' "$tag_b"
		printf 'FAULT_PID=%q\n' "$FAULT_PID"
		printf 'RUST_PID=%q\n' "$RUST_PID"
		printf 'RUST_SOCKET=%q\n' "$RUST_SOCKET"
		printf 'RUST_CONTROL_SOCKET=%q\n' "$RUST_CONTROL_SOCKET"
		printf 'T3_DROP_PID=%q\n' "$T3_DROP_PID"
		printf 'T3_DROP_SOCKET=%q\n' "$T3_DROP_SOCKET"
		printf 'T4_REJECT_PID=%q\n' "$T4_REJECT_PID"
		printf 'T4_REJECT_STATE=%q\n' "$T4_REJECT_STATE"
		printf 'MIG_SESSION_PID=%q\n' "$MIG_SESSION_PID"
		printf 'MIG_FIFO=%q\n' "$MIG_FIFO"
		printf 'FAULT_PROXY_BIN=%q\n' "$FAULT_PROXY_BIN"
		printf 'PORTS=%q\n' "$PORTS"
	} >"$run_dir/state.env"
}
write_state

# One-sided restart helpers (sigkill_owned_process,
# remove_dead_backend_socket) for the chaos-E2E chains.
source "$script_dir/restart-helpers.sh"

for port in $PORTS; do
	if "$FAULT_PROXY_BIN" --probe "127.0.0.1:$port" >/dev/null 2>&1; then
		echo "required port is already in use: $port" >&2
		exit 1
	fi
done

tiup_tiproxy_args=(--tiproxy 1 --tiproxy.binpath "$repo_root/bin/tiproxy" --tiproxy.config "$run_dir/tiproxy.toml")
if [[ $standalone == 1 ]]; then
	tiup_tiproxy_args=(--tiproxy 0)
fi
tiup "playground:v${TIUP_VERSION}" "$TIDB_VERSION" --tag "$tag" --without-monitor \
	--host 127.0.0.1 --port-offset "$port_offset" \
	--pd 1 --kv 1 --db 2 --tiflash 0 --db.config "$run_dir/tidb.toml" \
	"${tiup_tiproxy_args[@]}" \
	>"$run_dir/tiup-playground.log" 2>&1 &
TIUP_PID=$!
record_t4_process tiup-main start "$TIUP_PID" 0
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

# Second backend cluster: its own playground under its own tag and
# port window, no tiproxy of its own (the main proxy's explicit
# backend-clusters reach both PDs).
tiup "playground:v${TIUP_VERSION}" "$TIDB_VERSION" --tag "$tag_b" --without-monitor \
	--host 127.0.0.1 --port-offset "$PORT_OFFSET_B" \
	--pd 1 --kv 1 --db 1 --tiflash 0 --db.config "$run_dir/tidb-b.toml" \
	--tiproxy 0 \
	>"$run_dir/tiup-playground-b.log" 2>&1 &
TIUP_B_PID=$!
record_t4_process tiup-secondary start "$TIUP_B_PID" 0
write_state

tiup_data_b=${TIUP_HOME:-${HOME}/.tiup}/data/$tag_b
for _ in {1..50}; do
	[[ -d $tiup_data_b ]] && break
	if ! kill -0 "$TIUP_B_PID" 2>/dev/null; then
		break
	fi
	sleep 0.1
done
if [[ -d $tiup_data_b ]]; then
	printf '%s\n' "$run_dir" >"$tiup_data_b/.tiproxy-integration-owned"
fi

if [[ $mode == rust ]]; then
	# The Go bridge socket only exists in the two-process path; skip the
	# socket wait and control-tap entirely for the single-process run.
	if [[ $standalone != 1 ]]; then
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
		if [[ ${DATAPLANE_T4_QUALIFICATION:-0} == 1 ||
			($variant == plain && (${DATAPLANE_T3_FOCUSED:-0} == 1 || ${DATAPLANE_T4_FOCUSED:-0} == 1 || ${DATAPLANE_NATIVE_METER:-0} == 1)) ]]; then
		# The focused route-owner probes interpose a byte-transparent bridge
		# process from startup. They later remove only this owned process,
		# creating a real bridge disconnect while Go's API and both TiDB
		# clusters stay alive.
		"$run_dir/controldropper" \
			--front-socket "$T3_DROP_SOCKET" \
			--target-socket "$RUST_SOCKET" \
			--admin "127.0.0.1:$T3_DROP_ADMIN_PORT" \
			>"$run_dir/control-disconnect-dropper.log" 2>&1 &
		T3_DROP_PID=$!
		record_t4_process control-tap start "$T3_DROP_PID" 0
		RUST_CONTROL_SOCKET=$T3_DROP_SOCKET
		write_state
		t3_drop_ready=false
		for _ in {1..100}; do
			if [[ -S $T3_DROP_SOCKET ]] &&
				curl --noproxy '*' --fail --silent --max-time 5 \
					"http://127.0.0.1:$T3_DROP_ADMIN_PORT/state" -o /dev/null; then
				t3_drop_ready=true
				break
			fi
			if ! kill -0 "$T3_DROP_PID" 2>/dev/null; then
				break
			fi
			sleep 0.1
		done
		if [[ $t3_drop_ready != true ]]; then
			echo "focused control dropper did not become ready" >&2
			exit 1
		fi
		control_socket=$RUST_CONTROL_SOCKET
	fi
	fi
	rust_tls_args=()
	if [[ $TLS_ENABLED == true ]]; then
		# The Rust dataplane validates the snapshot's TLS cert paths against
		# its own allowlist of roots, mirroring the control plane's check.
		rust_tls_args=(--tls-root "$run_dir/certs")
	fi
	if [[ $standalone == 1 ]]; then
		# Bridge-free single process: no Go control peer, so no control socket.
		rust_owner_args=(--standalone)
	else
		rust_owner_args=(--control-socket "$control_socket" --control-uid "$(id -u)")
	fi
	"$rust_binary" --config "$run_dir/tiproxy.toml" \
		"${rust_owner_args[@]}" \
		--health-port "$RUST_HEALTH_PORT" \
		${rust_tls_args[@]+"${rust_tls_args[@]}"} \
		>"$run_dir/tiproxy-rs.log" 2>&1 &
	RUST_PID=$!
	record_t4_process rust-main start "$RUST_PID" 0
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
record_t4_process ingress-faultproxy start "$FAULT_PID" 0
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

capture_t4_zero_ledger() {
	local label=$1
	local evidence="$run_dir/t4-ledger-$label.json"
	for _ in {1..100}; do
		if curl --noproxy '*' --fail --silent --max-time 5 \
			"http://127.0.0.1:$RUST_HEALTH_PORT/health" -o "$evidence" &&
			python3 - "$evidence" <<'PYT4LEDGER'
import json
import pathlib
import sys

state = json.loads(pathlib.Path(sys.argv[1]).read_text())
ledger = state.get("route_ledger")
if not isinstance(ledger, dict) or ledger.get("router_incarnations", 0) < 1:
    raise SystemExit(1)
keys = (
    "sessions",
    "reserved",
    "active",
    "incoming",
    "outgoing",
    "unsettled_redirects",
    "unsettled_closes",
)
raise SystemExit(0 if all(ledger.get(key) == 0 for key in keys) else 1)
PYT4LEDGER
		then
			echo "T4 route ledger $label: zero sessions/counts/unsettled terminals"
			return 0
		fi
		sleep 0.1
	done
	echo "T4 route ledger did not settle to zero at $label" >&2
	cat "$evidence" >&2 2>/dev/null || true
	exit 1
}

validate_t4_route_audit() {
	local evidence=${1:?missing route-audit evidence}
	python3 - "$evidence" <<'PYT4AUDIT'
import json
import pathlib
import re
import sys

path = pathlib.Path(sys.argv[1])
state = json.loads(path.read_text())
audit = state.get("route_audit")
if not isinstance(audit, dict):
    raise SystemExit("T4 route tap did not publish route_audit")
legacy = audit.get("legacy_body_counts")
if not isinstance(legacy, dict) or not legacy:
    raise SystemExit("T4 route tap did not publish the retired-body catalog")
nonzero = {name: count for name, count in legacy.items() if count != 0}
for name in (
    "state_backends",
    "state_namespaces",
    "reconcile_request_connections",
    "reconcile_request_event_sequences",
    "reconcile_snapshot_connections",
    "reconcile_snapshot_event_sequences",
):
    if audit.get(name) != 0:
        nonzero[name] = audit.get(name)
if nonzero:
    raise SystemExit(f"T4 retired route traffic observed: {nonzero}")
events = audit.get("metering_events")
if not isinstance(events, list):
    raise SystemExit("T4 control tap did not publish ordered metering audit events")
fatal = [event for event in events if event.get("kind") == "protocol_error" and event.get("fatal")]
if audit.get("fatal_protocol_errors") != len(fatal):
    raise SystemExit(f"T4 metering fatal count disagrees with ordered audit: {audit}")
if fatal:
    raise SystemExit(f"T4 spontaneous fatal protocol error observed: {fatal}")
for expected, actual in enumerate(events, start=1):
    if actual.get("ordinal") != expected:
        raise SystemExit(f"T4 metering audit order is not contiguous: {events}")
metering_frames = [event for event in events if event.get("kind") in ("batch", "ack")]
fingerprints = {event.get("producer_fingerprint") for event in metering_frames}
if metering_frames and (None in fingerprints or "" in fingerprints):
    raise SystemExit(f"T4 metering frame omitted producer fingerprint: {metering_frames}")
if any(re.fullmatch(r"[0-9a-f]{64}", value) is None for value in fingerprints):
    raise SystemExit(f"T4 metering producer fingerprint is not SHA-256 hex: {fingerprints}")
if len(fingerprints) > 1:
    raise SystemExit(f"T4 metering producer identity changed within one WAL lineage: {fingerprints}")
if state.get("connect_count", 0) < 1 or state.get("forwarded", 0) < 1:
    raise SystemExit(f"T4 route tap was not on the live control path: {state}")
producer = next(iter(fingerprints), "none")
print(f"T4 route tap {path.name}: zero retired route state, zero spontaneous fatal protocol errors, producer={producer[:12]}")
PYT4AUDIT
}

capture_t4_final_audit() {
	local url=${1:?missing tap URL} evidence=${2:?missing audit output}
	if [[ ${DATAPLANE_T4_ROW:-} == M9 ]]; then
		# M9 has its own multi-restart oracle; keep that contract unchanged.
		curl --noproxy '*' --fail --silent --show-error --max-time 5 "$url" -o "$evidence"
	else
		python3 "$script_dir/write-t4-row-receipt.py" --capture-url "$url" --output "$evidence"
	fi
	validate_t4_route_audit "$evidence"
}

if [[ $mode == rust && ${DATAPLANE_T4_QUALIFICATION:-0} == 1 ]]; then
	capture_t4_zero_ledger before
fi

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

# MTR-005 lifecycle-log attribution. The faultproxy is the accepted TCP peer;
# in PROXY variants it additionally carries the downstream client's source in
# the v2 header. Run one connection alone in a fresh log window so the row can
# prove both fields without correlating against unrelated lifecycle records.
if [[ $mode == rust ]]; then
	mtr005_offset=$(wc -l <"$run_dir/tiproxy-rs.log" | tr -d ' ')
	if [[ $(mysql_ingress 'SELECT 1') != 1 ]]; then
		echo "MTR-005 attribution query failed" >&2
		exit 1
	fi
	mtr005_fresh=
	for _ in {1..20}; do
		mtr005_fresh=$(tail -n "+$((mtr005_offset + 1))" "$run_dir/tiproxy-rs.log")
		if grep -q '"event":"connection_closed"' <<<"$mtr005_fresh"; then
			break
		fi
		sleep 0.25
	done
	# Allow a closely following record to settle, then reject an ambiguous
	# window instead of selecting whichever close happens to be last.
	sleep 0.25
	mtr005_fresh=$(tail -n "+$((mtr005_offset + 1))" "$run_dir/tiproxy-rs.log")
	mtr005_closed=$(grep -c '"event":"connection_closed"' <<<"$mtr005_fresh" || true)
	if [[ $mtr005_closed != 1 ]]; then
		echo "MTR-005 expected exactly one fresh connection_closed record, got $mtr005_closed" >&2
		exit 1
	fi
	mtr005_line=$(grep '"event":"connection_closed"' <<<"$mtr005_fresh")
	mtr005_peer=$(sed -n 's/.*"client_addr":"\([^"]*\)".*/\1/p' <<<"$mtr005_line")
	mtr005_source=$(sed -n 's/.*"proxy_client_addr":"\([^"]*\)".*/\1/p' <<<"$mtr005_line")
	if [[ -z $mtr005_peer || -z $mtr005_source ]]; then
		echo "MTR-005 lifecycle log omitted a client address: $mtr005_line" >&2
		exit 1
	fi
	if [[ $PROXY_ENABLED == true && $mtr005_peer == "$mtr005_source" ]]; then
		echo "MTR-005 PROXY source regressed to the TCP peer: $mtr005_line" >&2
		exit 1
	fi
	if [[ $PROXY_ENABLED != true && $mtr005_peer != "$mtr005_source" ]]; then
		echo "MTR-005 direct connection did not fall back to the TCP peer: $mtr005_line" >&2
		exit 1
	fi
echo "MTR-005 lifecycle addresses: peer=$mtr005_peer proxy-client=$mtr005_source"
	record_t4_phase mtr005-complete
fi

# M5 qualification evidence must come from the real production route path,
# not a mock selector or replay fixture. Repeated fresh SQL admissions let the
# real metric collector establish CPU history; the Rust health endpoint exposes
# only payload-free counts captured after a successful reservation under the
# current routing/health/metric fences.
run_t4_route_input_probe() {
	local evidence="$run_dir/t4-m5-route-inputs.json"
	local observations health_inputs healthy cpu memory
	for _ in {1..180}; do
		if ! mysql_ingress 'SELECT 1' >/dev/null 2>&1; then
			echo "T4 M5 production route-input query failed" >&2
			exit 1
		fi
		if curl --noproxy '*' --fail --silent --show-error --max-time 5 \
			"http://127.0.0.1:$RUST_HEALTH_PORT/health" -o "$evidence"; then
			observations=$(sed -n 's/.*"observations":\([0-9][0-9]*\).*/\1/p' "$evidence")
			health_inputs=$(sed -n 's/.*"health_input_backends":\([0-9][0-9]*\).*/\1/p' "$evidence")
			healthy=$(sed -n 's/.*"healthy_backends":\([0-9][0-9]*\).*/\1/p' "$evidence")
			cpu=$(sed -n 's/.*"cpu_series":\([0-9][0-9]*\).*/\1/p' "$evidence")
			memory=$(sed -n 's/.*"memory_series":\([0-9][0-9]*\).*/\1/p' "$evidence")
			if [[ $observations =~ ^[1-9][0-9]*$ &&
				$health_inputs =~ ^[1-9][0-9]*$ &&
				$healthy =~ ^[1-9][0-9]*$ &&
				$cpu =~ ^[1-9][0-9]*$ &&
				$memory =~ ^[1-9][0-9]*$ ]]; then
				echo "T4 M5 route inputs: observations=$observations health=$health_inputs healthy=$healthy cpu=$cpu memory=$memory"
				return 0
			fi
		fi
		sleep 1
	done
	echo "T4 M5 never observed nonempty real health, CPU, and memory inputs" >&2
	cat "$evidence" >&2 2>/dev/null || true
	exit 1
}

if [[ $mode == rust && ${DATAPLANE_T4_QUALIFICATION:-0} == 1 && ${DATAPLANE_T4_ROW:-} == M5 ]]; then
	run_t4_route_input_probe
fi

# T2 gate: prove the production local resolver's exact client error after a
# Rust-only restart whose completed CP-CFG relist contains a namespace but no
# `default`. The initial process deliberately seeded default; persisting only
# tenant before restart also proves that startup seeding is not an empty-set
# fallback and does not resurrect default after a nonempty relist.
#
# The public `dataplane-t2-integration` make target and its required CI job set
# the internal focused switch so this gate stays independent from the later T4
# namespace matrix, without requiring developers to remember a hidden env var.
run_t2_namespace_missing_probe() {
	if [[ -z $etcdctl_bin || ! -x $etcdctl_bin ]]; then
		echo "T2 focused NamespaceMissing probe needs etcdctl" >&2
		exit 1
	fi
	ETCDCTL_API=3 "$etcdctl_bin" --endpoints "http://127.0.0.1:$PD_PORT" put \
		/config/ns/tenant '{"namespace":"tenant","frontend":{"user":"alice"}}' \
		>"$run_dir/t2-etcd-put.log"

	kill "$RUST_PID"
	wait "$RUST_PID" || true
	RUST_PID=
	write_state
	"$rust_binary" --config "$run_dir/tiproxy.toml" \
		--control-socket "$RUST_SOCKET" --control-uid "$(id -u)" \
		--health-port "$RUST_HEALTH_PORT" \
		>>"$run_dir/tiproxy-rs.log" 2>&1 &
	RUST_PID=$!
	write_state
	local restarted=false
	for _ in {1..180}; do
		if curl --noproxy '*' --fail --silent --max-time 5 \
			"http://127.0.0.1:$RUST_HEALTH_PORT/health" \
			>"$run_dir/t2-restart-health.json" 2>/dev/null; then
			restarted=true
			break
		fi
		if ! kill -0 "$RUST_PID" 2>/dev/null; then
			echo "T2 focused Rust restart exited before readiness" >&2
			exit 1
		fi
		sleep 1
	done
	if [[ $restarted != true ]]; then
		echo "T2 focused Rust restart did not become ready" >&2
		exit 1
	fi
	set +e
	local namespace_missing
	local namespace_missing_status
	namespace_missing=$(mysql_ingress 'SELECT 1' 2>&1)
	namespace_missing_status=$?
	set -e
	printf '%s\n' "$namespace_missing" >"$run_dir/t2-namespace-missing.out"
	if ((namespace_missing_status == 0)) || \
		! grep -Fq 'ERROR 1105 (HY000): failed to find a namespace' \
			"$run_dir/t2-namespace-missing.out"; then
		echo "T2 focused NamespaceMissing did not return the exact 1105 tuple" >&2
		cat "$run_dir/t2-namespace-missing.out" >&2
		exit 1
	fi
	echo "PASS: T2 local route, retry recovery, lease lifetime, and NamespaceMissing 1105"
	return 0
}

if [[ $mode == rust && $variant == plain && ${DATAPLANE_T2_FOCUSED:-0} == 1 ]]; then
	run_t2_namespace_missing_probe
	exit 0
fi

# T4 capability fence: first prove this exact process completed a compatible
# cap6 session through the transparent dropper, then replace only that dropper
# with a real Go-role peer whose selected capability set omits cap6. Rust must
# reject every reconnect before a session is established, retain local route
# ownership beyond the historical 30-second grace window, and continue
# admitting fresh SQL connections from its last accepted local snapshot.
run_t4_route_owner_capability_probe() {
	curl --noproxy '*' --fail --silent --show-error --max-time 5 \
		"http://127.0.0.1:$T3_DROP_ADMIN_PORT/state" \
		-o "$run_dir/t4-compatible-control-session.json"
	local bridge_state bridge_connects bridge_forwarded
	bridge_state=$(<"$run_dir/t4-compatible-control-session.json")
	bridge_connects=$(sed -n 's/.*"connect_count":\([0-9][0-9]*\).*/\1/p' <<<"$bridge_state")
	bridge_forwarded=$(sed -n 's/.*"forwarded":\([0-9][0-9]*\).*/\1/p' <<<"$bridge_state")
	if [[ $bridge_state != *"\"target\":\"$RUST_SOCKET\""* ||
		! $bridge_connects =~ ^[1-9][0-9]*$ || ! $bridge_forwarded =~ ^[1-9][0-9]*$ ]]; then
		echo "T4 compatible cap6 session did not traverse the owned intermediary: $bridge_state" >&2
		exit 1
	fi

	kill -s INT "$T3_DROP_PID"
	for _ in {1..100}; do
		kill -0 "$T3_DROP_PID" 2>/dev/null || break
		sleep 0.1
	done
	if kill -0 "$T3_DROP_PID" 2>/dev/null; then
		echo "T4 control intermediary did not stop" >&2
		exit 1
	fi
	wait "$T3_DROP_PID" 2>/dev/null || true
	T3_DROP_PID=
	write_state
	for _ in {1..50}; do
		[[ ! -e $T3_DROP_SOCKET ]] && break
		sleep 0.1
	done
	if [[ -e $T3_DROP_SOCKET ]]; then
		echo "T4 control intermediary left its owned front socket behind" >&2
		exit 1
	fi

	"$run_dir/controlrejector" \
		--socket "$T3_DROP_SOCKET" \
		--state "$T4_REJECT_STATE" \
		>"$run_dir/t4-controlrejector.log" 2>&1 &
	T4_REJECT_PID=$!
	write_state
	t4_rejection_recorded() {
		python3 - "$T4_REJECT_STATE" <<'PYT4'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
if not path.is_file():
    raise SystemExit(1)
state = json.loads(path.read_text())
accepted = (
    state.get("attempts", 0) >= 1
    and state.get("missing_capability_rejections", 0) >= 1
    and state.get("unexpected_negotiated_sessions", 0) == 0
    and state.get("peer_advertised_route_owner") is True
)
raise SystemExit(0 if accepted else 1)
PYT4
	}
	local rejected=false
	for _ in {1..120}; do
		if t4_rejection_recorded; then
			rejected=true
			break
		fi
		if ! kill -0 "$T4_REJECT_PID" 2>/dev/null; then
			break
		fi
		sleep 0.25
	done
	if [[ $rejected != true ]]; then
		echo "T4 Rust owner did not reject the incompatible cap5-only reconnect" >&2
		cat "$T4_REJECT_STATE" 2>/dev/null >&2 || true
		tail -20 "$run_dir/t4-controlrejector.log" >&2 || true
		exit 1
	fi

	# Stay disconnected longer than the old 30-second authority grace. A
	# hidden fallback or route-owner demotion would make this fresh admission
	# fail even though the retained Rust process is otherwise healthy.
	sleep 32
	if ! kill -0 "$RUST_PID" 2>/dev/null ||
		! curl --noproxy '*' --fail --silent --max-time 5 \
			"http://127.0.0.1:$RUST_HEALTH_PORT/health" \
			-o "$run_dir/t4-health-after-rejection.json"; then
		echo "T4 Rust owner stopped after the incompatible reconnect" >&2
		exit 1
	fi
	if [[ $(mysql_ingress 'SELECT 1') != 1 ]]; then
		echo "T4 Rust owner did not retain local SQL admission after cap6 rejection" >&2
		exit 1
	fi
	if ! t4_rejection_recorded; then
		echo "T4 incompatible peer unexpectedly negotiated during the grace window" >&2
		cat "$T4_REJECT_STATE" >&2
		exit 1
	fi
	cp "$T4_REJECT_STATE" "$run_dir/t4-control-rejection-final.json"
	echo "PASS: T4 cap6 compatible start, incompatible reconnect rejection, and Rust-local SQL admission beyond 30s"
}

if [[ ${DATAPLANE_NATIVE_METER:-0} == 1 ]]; then
    # Real SQL and recovery above ran through the production process pair.
    # Join Rust explicitly so a failed final export cannot look like success.
    kill -s INT "$RUST_PID"
    for _ in {1..450}; do
        kill -0 "$RUST_PID" 2>/dev/null || break
        sleep 0.1
    done
    if kill -0 "$RUST_PID" 2>/dev/null; then
        echo "native meter process did not join within 45 seconds" >&2
        exit 1
    fi
    if ! wait "$RUST_PID"; then
        echo "native meter process failed its coordinated shutdown" >&2
        exit 1
    fi
    cp "${RUST_CONTROL_SOCKET}.metering.wal" "$run_dir/native-producer-final.wal"
    curl --noproxy '*' --fail --silent --show-error --max-time 5 \
        "http://127.0.0.1:$T3_DROP_ADMIN_PORT/state" -o "$run_dir/native-control-final.json"
    validate_t4_route_audit "$run_dir/native-control-final.json"
    python3 "$repo_root/tests/controlplane/cpmeter/verify-native.py" "$run_dir"
    exit 0
fi

if [[ $mode == rust && $variant == plain && ${DATAPLANE_T4_FOCUSED:-0} == 1 ]]; then
	run_t4_route_owner_capability_probe
	exit 0
fi

# T3 gate: exercise the production dispatcher and the existing atomic session
# migration engine without any Go route command.  The old session is held in a
# transaction until the Rust owner has absorbed the A0 -> A1 fail-list swap;
# the transparent control intermediary is then stopped, creating a real bridge
# disconnect before COMMIT releases the safe boundary.  The same disconnected
# Rust process must migrate with database/user-variable state intact, directly
# force-close through the local FIFO, and admit a fresh session after recovery.
run_t3_local_migration_probe() {
	if [[ -z $etcdctl_bin || ! -x $etcdctl_bin ]]; then
		echo "T3 focused migration needs etcdctl" >&2
		exit 1
	fi
	if ! command -v jq >/dev/null 2>&1; then
		echo "T3 focused migration needs jq" >&2
		exit 1
	fi
	t3_set_route_policy() {
		local failed=$1 timeout=$2 phase=$3 current value
		current=$(ETCDCTL_API=3 "$etcdctl_bin" \
			--endpoints "http://127.0.0.1:$PD_PORT" \
			get /config/proxy --print-value-only)
		# The first mutation owns seeding: the config owner intentionally does
		# not materialize /config/proxy until a writer commits one.  Construct
		# the complete dynamic subset from this topology instead of writing a
		# partial JSON object whose serde defaults would zero max-connections or
		# erase the two clusters.
		if [[ -z $current ]]; then
			current=$(jq -cn \
				--arg pd_a "127.0.0.1:$PD_PORT" \
				--arg pd_b "127.0.0.1:$PD_PORT_B" \
				--arg proxy_protocol "$dynamic_proxy_protocol" \
				'{
					"max-connections": 100,
					"high-memory-usage-reject-threshold": 0.9,
					"conn-buffer-size": 32768,
					"frontend-keepalive": {"enabled":true,"idle":0,"cnt":0,"intvl":0,"timeout":0},
					"backend-healthy-keepalive": {"enabled":true,"idle":60000000000,"cnt":5,"intvl":3000000000,"timeout":15000000000},
					"backend-unhealthy-keepalive": {"enabled":true,"idle":10000000000,"cnt":5,"intvl":1000000000,"timeout":5000000000},
					"proxy-protocol": $proxy_protocol,
					"graceful-wait-before-shutdown": 0,
					"graceful-close-conn-timeout": 5,
					"public-endpoints": [],
					"backend-clusters": [
						{"name":"cluster-a","pd-addrs":$pd_a,"ns-servers":[]},
						{"name":"cluster-b","pd-addrs":$pd_b,"ns-servers":[]}
					],
					"fail-backend-list": [],
					"failover-timeout": 60
				}')
		fi
		value=$(jq -c --argjson failed "$failed" --argjson timeout "$timeout" \
			'.["fail-backend-list"] = $failed | .["failover-timeout"] = $timeout' \
			<<<"$current")
		printf '%s\n' "$value" >"$run_dir/t3-online-$phase.json"
		ETCDCTL_API=3 "$etcdctl_bin" --endpoints "http://127.0.0.1:$PD_PORT" put \
			/config/proxy "$value" >"$run_dir/t3-etcd-$phase.log"
	}
	t3_backend_query() {
		local port=$1 query=$2
		mysql --batch --skip-column-names --connect-timeout=2 \
			-h 127.0.0.1 -P "$port" -u root --ssl-mode=DISABLED -e "$query"
	}
	t3_set_route_policy \
		"[\"127.0.0.1:$TIDB_PORT_1\",\"127.0.0.1:$TIDB_PORT_B\"]" 300 pin
	local pin_ready=false pin_port= pin_streak=0
	for _ in {1..80}; do
		pin_port=$(mysql_ingress 'SELECT @@port' 2>>"$run_dir/t3-pin.err" || true)
		if [[ $pin_port == "$TIDB_PORT_0" ]]; then
			pin_streak=$((pin_streak + 1))
			if ((pin_streak >= 5)); then
				pin_ready=true
				break
			fi
		else
			pin_streak=0
		fi
		sleep 0.25
	done
	if [[ $pin_ready != true ]]; then
		echo "T3 focused A0 pin did not absorb (landed '$pin_port')" >&2
		tail -8 "$run_dir/t3-pin.err" >&2 || true
		exit 1
	fi
	mysql --batch --skip-column-names --connect-timeout=2 \
		-h 127.0.0.1 -P "$TIDB_PORT_0" -u root --ssl-mode=DISABLED \
		-e 'CREATE DATABASE IF NOT EXISTS t3_local_migration;'

	MIG_FIFO="$run_dir/t3-migration-session.fifo"
	mkfifo "$MIG_FIFO"
	local rust_offset
	rust_offset=$(wc -l <"$run_dir/tiproxy-rs.log" | tr -d ' ')
	mysql --batch --skip-column-names --skip-reconnect --unbuffered \
		-h 127.0.0.1 -P "$FAULT_PORT" -u root \
		"${mysql_tls_args[@]}" ${mysql_compression_arg:+"$mysql_compression_arg"} \
		<"$MIG_FIFO" >"$run_dir/t3-migration-session.out" 2>&1 &
	MIG_SESSION_PID=$!
	write_state
	exec 8>"$MIG_FIFO"
	t3_migration_query() {
		local marker=$1 sql=$2 line=
		printf '%s\n' "$sql" >&8
		for _ in {1..60}; do
			line=$(grep -s "^$marker|" "$run_dir/t3-migration-session.out" | tail -1 || true)
			if [[ -n $line ]]; then
				printf '%s\n' "$line"
				return 0
			fi
			if ! kill -0 "$MIG_SESSION_PID" 2>/dev/null; then
				echo "T3 focused migration session exited before $marker" >&2
				tail -8 "$run_dir/t3-migration-session.out" >&2 || true
				return 1
			fi
			sleep 0.25
		done
		echo "T3 focused migration session never answered $marker" >&2
		return 1
	}
	local baseline
	baseline=$(t3_migration_query T3BASE \
		"USE t3_local_migration; SET @t3_marker = 'state-live'; BEGIN; SELECT CONCAT('T3BASE|', CONNECTION_ID(), '|', @@port, '|', COALESCE(DATABASE(), 'NULL'), '|', COALESCE(@t3_marker, 'NULL'));" ) || exit 1
	if [[ $(cut -d'|' -f3 <<<"$baseline") != "$TIDB_PORT_0" ||
		$(cut -d'|' -f4 <<<"$baseline") != t3_local_migration ||
		$(cut -d'|' -f5 <<<"$baseline") != state-live ]]; then
		echo "T3 focused invalid baseline: $baseline" >&2
		exit 1
	fi
	local proxy_connection_id=
	for _ in {1..30}; do
		proxy_connection_id=$(tail -n "+$((rust_offset + 1))" "$run_dir/tiproxy-rs.log" |
			grep '"event":"connection_ready"' | head -1 |
			sed -n 's/.*"connection_id":\([0-9]*\).*/\1/p')
		[[ -n $proxy_connection_id ]] && break
		sleep 0.25
	done
	if [[ -z $proxy_connection_id ]]; then
		echo "T3 focused could not identify the persistent Rust session" >&2
		exit 1
	fi

	t3_set_route_policy \
		"[\"127.0.0.1:$TIDB_PORT_0\",\"127.0.0.1:$TIDB_PORT_B\"]" 300 swap
	local swap_ready=false swap_port= swap_streak=0
	for _ in {1..80}; do
		swap_port=$(mysql_ingress 'SELECT @@port' 2>>"$run_dir/t3-swap.err" || true)
		if [[ $swap_port == "$TIDB_PORT_1" ]]; then
			swap_streak=$((swap_streak + 1))
			if ((swap_streak >= 5)); then
				swap_ready=true
				break
			fi
		else
			swap_streak=0
		fi
		sleep 0.25
	done
	if [[ $swap_ready != true ]]; then
		echo "T3 focused A1 swap did not absorb (landed '$swap_port')" >&2
		tail -8 "$run_dir/t3-swap.err" >&2 || true
		exit 1
	fi

	curl --noproxy '*' --fail --silent --show-error --max-time 5 \
		"http://127.0.0.1:$T3_DROP_ADMIN_PORT/state" \
		-o "$run_dir/t3-bridge-before-disconnect.json"
	local bridge_state bridge_connects bridge_forwarded
	bridge_state=$(<"$run_dir/t3-bridge-before-disconnect.json")
	bridge_connects=$(sed -n 's/.*"connect_count":\([0-9][0-9]*\).*/\1/p' <<<"$bridge_state")
	bridge_forwarded=$(sed -n 's/.*"forwarded":\([0-9][0-9]*\).*/\1/p' <<<"$bridge_state")
	if [[ $bridge_state != *"\"target\":\"$RUST_SOCKET\""* ||
		! $bridge_connects =~ ^[1-9][0-9]*$ || ! $bridge_forwarded =~ ^[1-9][0-9]*$ ]]; then
		echo "T3 bridge intermediary was not transparently active: $bridge_state" >&2
		exit 1
	fi
	kill -s INT "$T3_DROP_PID"
	for _ in {1..100}; do
		kill -0 "$T3_DROP_PID" 2>/dev/null || break
		sleep 0.1
	done
	if kill -0 "$T3_DROP_PID" 2>/dev/null; then
		echo "T3 focused control intermediary did not stop" >&2
		exit 1
	fi
	wait "$T3_DROP_PID" 2>/dev/null || true
	T3_DROP_PID=
	write_state
	if ! kill -0 "$RUST_PID" 2>/dev/null ||
		! curl --noproxy '*' --fail --silent --max-time 5 \
			"http://127.0.0.1:$RUST_HEALTH_PORT/health" -o /dev/null; then
		echo "T3 focused Rust owner stopped when the route bridge disconnected" >&2
		exit 1
	fi

	local migrated= row= row_port= row_db= row_marker=
	# COMMIT opens the safe boundary only after the bridge has disappeared.
	row=$(t3_migration_query T3COMMIT \
		"COMMIT; SELECT CONCAT('T3COMMIT|', CONNECTION_ID(), '|', @@port, '|', COALESCE(DATABASE(), 'NULL'), '|', COALESCE(@t3_marker, 'NULL'));" ) || exit 1
	for attempt in {1..60}; do
		local marker="T3TRY$attempt"
		row=$(t3_migration_query "$marker" \
			"SELECT CONCAT('$marker|', CONNECTION_ID(), '|', @@port, '|', COALESCE(DATABASE(), 'NULL'), '|', COALESCE(@t3_marker, 'NULL'));" ) || exit 1
		row_port=$(cut -d'|' -f3 <<<"$row")
		row_db=$(cut -d'|' -f4 <<<"$row")
		row_marker=$(cut -d'|' -f5 <<<"$row")
		if [[ $row_port == "$TIDB_PORT_1" ]]; then
			migrated=true
			break
		fi
		sleep 0.25
	done
	if [[ $migrated != true || $row_db != t3_local_migration || $row_marker != state-live ]]; then
		echo "T3 focused local redirect failed or lost session state: ${row:-<none>}" >&2
		exit 1
	fi
	# A0/A1 remain directly queryable throughout this phase. B is the sole
	# non-failed member of the all-rule group, but its ks-new identity cannot
	# accept the retained ks-old session. The timeout-zero worker therefore has
	# no legal redirect and must deliver ForceClose through the local FIFO.
	local backend_connection_id backend_port
	backend_connection_id=$(cut -d'|' -f2 <<<"$row")
	for backend_port in "$TIDB_PORT_0" "$TIDB_PORT_1" "$TIDB_PORT_B"; do
		if [[ $(t3_backend_query "$backend_port" 'SELECT 1') != 1 ]]; then
			echo "T3 focused backend $backend_port was not live before ForceClose" >&2
			exit 1
		fi
	done
	# Keep the mysql client blocked on a real backend response so the locally
	# forced socket close is observed immediately; --skip-reconnect prevents a
	# successful new session from hiding the terminal.
	printf '%s\n' "SELECT CONCAT('T3FORCECLOSEPROBE|', SLEEP(30));" >&8
	local force_probe_running=false
	for _ in {1..40}; do
		if [[ $(t3_backend_query "$TIDB_PORT_1" \
			"SELECT COUNT(*) FROM INFORMATION_SCHEMA.PROCESSLIST WHERE ID = $backend_connection_id AND INFO LIKE '%T3FORCECLOSEPROBE%'") == 1 ]]; then
			force_probe_running=true
			break
		fi
		sleep 0.1
	done
	if [[ $force_probe_running != true ]]; then
		echo "T3 focused ForceClose probe never became active on A1 connection $backend_connection_id" >&2
		exit 1
	fi
	t3_set_route_policy \
		"[\"127.0.0.1:$TIDB_PORT_0\",\"127.0.0.1:$TIDB_PORT_1\"]" 0 close
	local force_closed=false
	for _ in {1..160}; do
		if ! kill -0 "$MIG_SESSION_PID" 2>/dev/null; then
			force_closed=true
			break
		fi
		sleep 0.25
	done
	if [[ $force_closed != true ]]; then
		echo "T3 focused local ForceClose did not terminate the session" >&2
		exit 1
	fi
	exec 8>&-
	wait "$MIG_SESSION_PID" 2>/dev/null || true
	rm -f "$MIG_FIFO"
	MIG_SESSION_PID=
	MIG_FIFO=
	write_state
	if grep -Fq 'T3FORCECLOSEPROBE|0' "$run_dir/t3-migration-session.out"; then
		echo "T3 focused probe completed instead of being force-closed" >&2
		exit 1
	fi
	local force_close_record=
	for _ in {1..40}; do
		force_close_record=$(grep "\"event\":\"connection_closed\".*\"connection_id\":$proxy_connection_id.*\"quit_source\":\"proxy shutdown\"" \
			"$run_dir/tiproxy-rs.log" | tail -1 || true)
		[[ -n $force_close_record ]] && break
		sleep 0.1
	done
	if [[ -z $force_close_record ]]; then
		echo "T3 focused ForceClose lacked the exact local connection terminal" >&2
		exit 1
	fi
	for backend_port in "$TIDB_PORT_0" "$TIDB_PORT_1" "$TIDB_PORT_B"; do
		if [[ $(t3_backend_query "$backend_port" 'SELECT 1') != 1 ]]; then
			echo "T3 focused backend $backend_port was not live after ForceClose" >&2
			exit 1
		fi
	done
	if ! kill -0 "$RUST_PID" 2>/dev/null ||
		! curl --noproxy '*' --fail --silent --max-time 5 \
			"http://127.0.0.1:$RUST_HEALTH_PORT/health" -o /dev/null; then
		echo "T3 focused Rust owner stopped while delivering ForceClose" >&2
		exit 1
	fi

	t3_set_route_policy \
		"[\"127.0.0.1:$TIDB_PORT_0\",\"127.0.0.1:$TIDB_PORT_B\"]" 300 recover
	local recovered=false recovered_port= recovered_streak=0
	for _ in {1..160}; do
		recovered_port=$(mysql_ingress 'SELECT @@port' 2>>"$run_dir/t3-recover.err" || true)
		if [[ $recovered_port == "$TIDB_PORT_1" ]]; then
			recovered_streak=$((recovered_streak + 1))
			if ((recovered_streak >= 5)); then
				recovered=true
				break
			fi
		else
			recovered_streak=0
		fi
		sleep 0.25
	done
	if [[ $recovered != true ]]; then
		echo "T3 focused disconnected Rust owner did not admit after recovery" >&2
		tail -8 "$run_dir/t3-recover.err" >&2 || true
		exit 1
	fi
	echo "PASS: T3 local redirect A0->$TIDB_PORT_1, direct ForceClose, and fresh admission survived bridge disconnect (connection $proxy_connection_id)"
}

if [[ $mode == rust && $variant == plain && ${DATAPLANE_T3_FOCUSED:-0} == 1 ]]; then
	run_t3_local_migration_probe
	exit 0
fi

# Namespace/topology matrix (DPL-07 #41): three username-resolved
# combinations against the REAL cluster, identical in both modes.
# `proxy.pd-addrs` always registers an implicit PD-backed backend
# cluster, and once ANY backend cluster exists the Go FallbackFetcher
# serves every namespace the full PD topology — `backend.instances`
# is ignored, so no namespace can pin a backend and `SELECT @@port`
# cannot discriminate the rows. The namespaces therefore list BOTH
# real backends (the set routing actually uses), behavior asserts a
# landing inside that set, and the DISCRIMINATING evidence is
# per-connection namespace attribution: each row runs alone against a
# captured log offset, and the freshly appended records must
# attribute that one connection to exactly the expected namespace.
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
record_t4_phase namespace-bootstrap-start
mysql_backend_admin "CREATE USER IF NOT EXISTS 'alice'@'%'; CREATE USER IF NOT EXISTS 'bob'@'%';"
namespace_api="http://127.0.0.1:$TIPROXY_API_PORT/api/admin/namespace"
ns_alpha_json="{\"namespace\":\"ns-alpha\",\"frontend\":{\"user\":\"alice\"},\"backend\":{\"instances\":[\"127.0.0.1:$TIDB_PORT_0\",\"127.0.0.1:$TIDB_PORT_1\"]}}"
ns_beta_json="{\"namespace\":\"ns-beta\",\"frontend\":{\"user\":\"bob\"},\"backend\":{\"instances\":[\"127.0.0.1:$TIDB_PORT_0\",\"127.0.0.1:$TIDB_PORT_1\"]}}"
if [[ $mode == rust ]]; then
	# Rust owns the production ConfigNamespaceSource, whose persistent input is
	# `/config/ns/*`. The legacy HTTP namespace API is process-local to Go and
	# deliberately cannot become a hidden second Rust routing owner. Exercise the
	# actual external source here; later M1/M2 rows mutate these same keys.
	if [[ -z $etcdctl_bin || ! -x $etcdctl_bin ]]; then
		echo "Rust namespace matrix needs etcdctl" >&2
		exit 1
	fi
	# Once an explicit namespace mutation exists, `/config/ns/*` is the
	# complete authoritative set. Materialize the startup-only implicit default
	# alongside the two named rows so this baseline matrix keeps its intended
	# fallback; M1/M2 later delete it deliberately when testing missing-default.
	ETCDCTL_API=3 "$etcdctl_bin" --endpoints "http://127.0.0.1:$PD_PORT" \
		put /config/ns/default '{"namespace":"default"}' >"$run_dir/ns-default-etcd.log"
	ETCDCTL_API=3 "$etcdctl_bin" --endpoints "http://127.0.0.1:$PD_PORT" \
		put /config/ns/ns-alpha "$ns_alpha_json" >"$run_dir/ns-alpha-etcd.log"
	ETCDCTL_API=3 "$etcdctl_bin" --endpoints "http://127.0.0.1:$PD_PORT" \
		put /config/ns/ns-beta "$ns_beta_json" >"$run_dir/ns-beta-etcd.log"
else
	curl --noproxy '*' --fail --silent --show-error -X PUT \
		-H 'Content-Type: application/json' -d "$ns_alpha_json" \
		"$namespace_api/ns-alpha" -o /dev/null
	curl --noproxy '*' --fail --silent --show-error -X PUT \
		-H 'Content-Type: application/json' -d "$ns_beta_json" \
		"$namespace_api/ns-beta" -o /dev/null
	curl --noproxy '*' --fail --silent --show-error -X POST \
		"$namespace_api/commit?namespace=ns-alpha&namespace=ns-beta" -o /dev/null
fi
record_t4_phase namespace-bootstrap-complete

# Absorption gate: the committed namespaces become routable once the
# proxy rebuilds its user→namespace map and each router observes the
# PD topology. Every user must then land on a REAL backend.
namespace_resolved() {
	local port
	port=$(mysql_ingress_as "$1" 'SELECT @@port' 2>/dev/null) || return 1
	[[ $port == "$TIDB_PORT_0" || $port == "$TIDB_PORT_1" ]]
}
namespace_ready=false
for _ in {1..30}; do
	if namespace_resolved alice && namespace_resolved bob && namespace_resolved root; then
		namespace_ready=true
		break
	fi
	sleep 1
done
if [[ $namespace_ready != true ]]; then
	{
		echo "namespace absorption failed:"
		for user in alice bob root; do
			echo "  $user -> $(mysql_ingress_as "$user" 'SELECT @@port' 2>&1 | tail -1) (want $TIDB_PORT_0 or $TIDB_PORT_1)"
		done
	} >&2
	exit 1
fi
# Per-connection attribution evidence. In Rust mode the engine's
# closed-schema lifecycle log names the decision-resolved namespace;
# in Go mode the per-namespace router logs every route at debug level
# under its namespace field (the tiup component log lives in the tag
# data directory, still alive here; cleanup removes it later).
if [[ $mode == rust ]]; then
	evidence_files() { printf '%s\n' "$run_dir/tiproxy-rs.log"; }
	evidence_pattern() { printf '"event":"connection_ready".*"namespace":"%s"' "$1"; }
else
	go_log_root="${TIUP_HOME:-${HOME}/.tiup}/data/$tag"
	evidence_files() {
		# EXACTLY the main component log: concatenating multiple
		# matching files would misalign the line-count offsets the
		# delta windows depend on whenever any other file grows
		# (old records would "reappear" inside a fresh tail).
		find "$go_log_root" -type f -name 'tiproxy.log' 2>/dev/null | sort
	}
	evidence_pattern() { printf '"logger":"main\\.nsmgr\\.router\\.policy".*"msg":"route".*"namespace":"%s"' "$1"; }
fi
evidence_lines() {
	local files
	files=$(evidence_files)
	if [[ -z $files ]]; then
		echo 0
		return
	fi
	# shellcheck disable=SC2086
	cat $files 2>/dev/null | wc -l | tr -d ' '
}
evidence_tail() {
	local files
	files=$(evidence_files)
	if [[ -z $files ]]; then
		return
	fi
	# shellcheck disable=SC2086
	cat $files 2>/dev/null | tail -n "+$(($1 + 1))"
}
# One row = one connection run ALONE against a captured log offset:
# the fresh records must attribute it to exactly the expected
# namespace and to NO other, which discriminates all three rows even
# though every namespace routes over the same PD-backed backend set.
attribution_row() {
	local user=$1 expected=$2 offset fresh matched=false
	offset=$(evidence_lines)
	if ! namespace_resolved "$user"; then
		echo "$user query failed during the attribution row" >&2
		return 1
	fi
	for _ in {1..20}; do
		fresh=$(evidence_tail "$offset")
		if grep -qE "$(evidence_pattern "$expected")" <<<"$fresh"; then
			matched=true
			break
		fi
		sleep 0.5
	done
	if [[ $matched != true ]]; then
		echo "missing $mode namespace attribution for $user: $expected" >&2
		return 1
	fi
	local other
	for other in ns-alpha ns-beta default; do
		[[ $other == "$expected" ]] && continue
		if grep -qE "$(evidence_pattern "$other")" <<<"$fresh"; then
			echo "$user connection was also attributed to $other" >&2
			return 1
		fi
	done
}
attribution_row alice ns-alpha || exit 1
attribution_row bob ns-beta || exit 1
attribution_row root default || exit 1
echo "namespace matrix: alice->ns-alpha bob->ns-beta root->default (per-connection route attribution)"

# ---- SES-02 live authentication-plugin matrix (#27) ----
# The dataplane relays each backend auth plugin's REAL handshake end to
# end (Rust: session-core AuthRelay, frozen from Go
# pkg/proxy/backend/authenticator.go). Provision users with distinct
# plugins on the real cluster and prove, THROUGH the proxy, that each
# authenticates (or is explicitly rejected) — identically in Go and Rust
# modes. caching_sha2_password is the discriminating case: it is the only
# plugin with a fast path, and its full-auth exchange (RSA public key over
# a non-TLS link, cleartext inside TLS) must be relayed intact. Rows that
# require a TLS frontend run only when the variant provides one.
auth_pw_native="Nat1vePw9"
auth_pw_sha2="Caching2Sha9"
: >"$run_dir/auth-matrix.err"
mysql_backend_admin "
	CREATE USER IF NOT EXISTS 'auth_native'@'%' IDENTIFIED WITH mysql_native_password BY '$auth_pw_native';
	CREATE USER IF NOT EXISTS 'auth_sha2'@'%' IDENTIFIED WITH caching_sha2_password BY '$auth_pw_sha2';
	CREATE USER IF NOT EXISTS 'auth_reqssl'@'%' IDENTIFIED WITH mysql_native_password BY '$auth_pw_native' REQUIRE SSL;
	GRANT ALL PRIVILEGES ON *.* TO 'auth_native'@'%';
	GRANT ALL PRIVILEGES ON *.* TO 'auth_sha2'@'%';
	GRANT ALL PRIVILEGES ON *.* TO 'auth_reqssl'@'%';
"
# auth_probe connects THROUGH the proxy as $1/$2 with the extra client
# args $3.. and echoes the CURRENT_USER() marker; a nonzero exit means
# the handshake was rejected (its diagnostics land in auth-matrix.err).
auth_probe() {
	local user=$1 pass=$2
	shift 2
	mysql --batch --skip-column-names --connect-timeout=6 \
		-h 127.0.0.1 -P "$FAULT_PORT" -u "$user" -p"$pass" "$@" \
		-e "SELECT CONCAT('AUTHOK|', CURRENT_USER());" 2>>"$run_dir/auth-matrix.err"
}
auth_transport=()
[[ ${#mysql_tls_args[@]} -gt 0 ]] && auth_transport+=("${mysql_tls_args[@]}")
[[ -n $mysql_compression_arg ]] && auth_transport+=("$mysql_compression_arg")

# Row 1: mysql_native_password over the variant's own transport.
auth_native_out=$(auth_probe auth_native "$auth_pw_native" "${auth_transport[@]}") || true
if [[ $auth_native_out != AUTHOK\|auth_native@* ]]; then
	echo "auth matrix: mysql_native_password did not authenticate through the proxy (got '$auth_native_out')" >&2
	tail -5 "$run_dir/auth-matrix.err" >&2 || true
	exit 1
fi

# Row 2: caching_sha2_password full-auth relay. The discriminating case
# runs inside TLS, where the client sends the password in the clear and
# the proxy must carry the whole switch + full-auth exchange to the
# backend (the only plugin with a fast path in the relay). The non-TLS
# RSA-public-key variant depends on the backend serving a key and is left
# to the session-core unit matrix; here caching_sha2 success is asserted
# only when the frontend has TLS.
auth_sha2_note="caching_sha2: (skipped; needs a TLS frontend)"
if [[ $TLS_ENABLED == true ]]; then
	auth_sha2_out=$(auth_probe auth_sha2 "$auth_pw_sha2" "${auth_transport[@]}") || true
	if [[ $auth_sha2_out != AUTHOK\|auth_sha2@* ]]; then
		echo "auth matrix: caching_sha2_password full-auth was not relayed over TLS (got '$auth_sha2_out')" >&2
		tail -8 "$run_dir/auth-matrix.err" >&2 || true
		exit 1
	fi
	auth_sha2_note="caching_sha2: full-auth relayed over TLS"
fi

# Row 3: a wrong password is rejected end to end with an explicit
# access-denied error, not a silent hang or a spurious success.
if auth_probe auth_native "Wr0ngPw0" "${auth_transport[@]}" >/dev/null 2>&1; then
	echo "auth matrix: a wrong password unexpectedly authenticated" >&2
	exit 1
fi
if ! grep -qiE "Access denied|error 1045|ERROR 1045" "$run_dir/auth-matrix.err"; then
	echo "auth matrix: wrong-password rejection did not surface an access-denied error" >&2
	tail -5 "$run_dir/auth-matrix.err" >&2 || true
	exit 1
fi

# Row 4: REQUIRE SSL enforcement through the proxy is decided by the
# proxy->backend link, not the client link — verified identical in Go and
# Rust modes. TiDB checks REQUIRE SSL against the connection it actually
# terminates, which is the proxy's backend dial:
#   - Without backend TLS (require_backend_tls=false, the plain/proxy/
#     compress variants) the backend link is plaintext, so a REQUIRE SSL user
#     is refused end to end regardless of the client's own transport.
#   - With backend TLS (require_backend_tls=true, the tls variants) the
#     backend link is always TLS, so the same user authenticates — even from
#     a --ssl-mode=DISABLED client — because the secure requirement is met at
#     the backend hop. This matches Go TiProxy (a non-TLS client reaching a
#     REQUIRE SSL user over a TLS backend link is accepted in both modes), so
#     the non-TLS-refusal assertion only applies when the backend link is
#     itself plaintext.
if [[ $TLS_ENABLED == true ]]; then
	# Prove the backend-link semantic with a PLAINTEXT client
	# (--ssl-mode=DISABLED, no client TLS): the REQUIRE SSL user still
	# authenticates, because the requirement is satisfied at the forced-TLS
	# proxy->backend link, not the client link. Using the TLS client transport
	# here would not distinguish the two.
	auth_reqssl_out=$(auth_probe auth_reqssl "$auth_pw_native" --ssl-mode=DISABLED) || true
	if [[ $auth_reqssl_out != AUTHOK\|auth_reqssl@* ]]; then
		echo "auth matrix: REQUIRE SSL user failed from a plaintext client over the forced TLS backend link (got '$auth_reqssl_out')" >&2
		tail -5 "$run_dir/auth-matrix.err" >&2 || true
		exit 1
	fi
	auth_reqssl_note="require-secure: enforced at backend link (plaintext client accepted over forced TLS backend)"
else
	if auth_probe auth_reqssl "$auth_pw_native" --ssl-mode=DISABLED >/dev/null 2>&1; then
		echo "auth matrix: a REQUIRE SSL user authenticated over a plaintext backend link" >&2
		exit 1
	fi
	auth_reqssl_note="require-secure: plaintext backend link refused"
fi

mysql_backend_admin "DROP USER IF EXISTS 'auth_native'@'%'; DROP USER IF EXISTS 'auth_sha2'@'%'; DROP USER IF EXISTS 'auth_reqssl'@'%';" || true
# tidb_sm3_password / mysql_clear_password / auth_socket / tidb_session_token
# / tidb_auth_token / authentication_ldap_simple / authentication_ldap_sasl
# / unknown "Other" are pass-through in the relay with no fast path; a stock
# mysql client against a bare TiUP playground cannot exercise them without
# extra client plugins or an LDAP/JWKS backend, so their relay behavior is
# covered by the session-core handshake unit matrix rather than this live
# phase: classification (plugin_classification_matches_go_list), fast-path
# gating to caching_sha2_password only (sha2_fast_path_is_plugin_gated), and
# a per-plugin pass-through matrix (pass_through_plugins_have_no_fast_path).
echo "auth matrix: mysql_native_password relayed; $auth_sha2_note; wrong password rejected (1045); $auth_reqssl_note (mode=$mode, tls=$TLS_ENABLED)"

# ---- VAL-01 driver-compatibility smoke (rust plain; opt-in via DATAPLANE_SMOKE=1) ----
# Real MySQL clients (native Go + Python, no containers) run the key workloads
# through the Rust TiProxy against the real TiDB, and compression negotiation is
# asserted from the dataplane's connection-close log — so a "query succeeded
# after a silent capability downgrade" fails, not passes. This runs here, right
# after the auth matrix, while every TiDB backend is still healthy and before the
# deliberately destructive phases (keyspace guard, error parity, drop-next) take
# backends down. It is off by default (fast local runs) and enabled for
# CI/acceptance.
#
# Scoped to the `plain` variant on purpose: the `tls`/`tls-proxy-zstd` variants
# require mutual TLS (a client certificate) and trip driver-specific TLS quirks
# (e.g. Connector/Python's OpenSSL-3 CA keyUsage strictness). The Go/Python smoke
# adapters already accept --ca-file, so driver-level TLS smoke is a documented
# follow-up; the proxy's own TLS path is already covered by run.sh's existing TLS
# phases (mysql CLI with client certs, the REQUIRE SSL auth matrix, and WIRE-04).
if [[ $mode == rust && $variant == plain && ${DATAPLANE_SMOKE:-0} == 1 ]]; then
	if "$repo_root/tests/compatibility/smoke/run-smoke.sh" \
		--host 127.0.0.1 --port "$TIPROXY_PORT" --user root --database test \
		--rust-log "$run_dir/tiproxy-rs.log"; then
		echo "driver smoke: all real-client workloads passed and negotiated their capabilities"
	else
		echo "driver smoke: a real-client workload failed or silently downgraded" >&2
		exit 1
	fi
fi

# ---- Cluster x listener matrix (DPL-07 #41 cluster dimension) ----
# Deterministic construction: routing-rule = "port" groups backends by
# their `tiproxy-port` topology label, so listener A can ONLY select
# cluster-a's backends and listener B only cluster-b's — the same
# client (listener) selects the same backend class in both modes,
# exactly. NON-CLAIM: per-cluster NSServer parity is out of scope (the
# wire snapshot does not project NSServers; the Rust cluster dialer
# resolves direct addresses with the system resolver, same as Go with
# no name servers).
mysql_listener_as() {
	local port=$1
	local query=$2
	mysql --batch --skip-column-names --connect-timeout=4 \
		-h 127.0.0.1 -P "$port" -u root \
		"${mysql_tls_args[@]}" ${mysql_compression_arg:+"$mysql_compression_arg"} -e "$query"
}
mysql_backend_on() {
	mysql --batch --skip-column-names --connect-timeout=2 \
		-h 127.0.0.1 -P "$1" -u root --ssl-mode=DISABLED -e "$2"
}
# Absorption gate for the EXACT healthy set: GetTiDBTopology tolerates
# partial merges, so readiness alone can pass with one cluster absent.
# Both listeners must deterministically reach their own cluster before
# any evidence row runs.
# Cluster-B's OWN liveness is checked directly (playground process
# alive + direct SQL against its TiDB), so a proxy-side fallback can
# never mask a dead second cluster.
cluster_matrix_ready=false
for _ in {1..60}; do
	if ! kill -0 "$TIUP_B_PID" 2>/dev/null; then
		echo "cluster-B playground died during absorption; see tiup-playground-b.log" >&2
		tail -20 "$run_dir/tiup-playground-b.log" >&2 || true
		exit 1
	fi
	direct_b=$(mysql_backend_on "$TIDB_PORT_B" 'SELECT 1' 2>/dev/null || true)
	port_a=$(mysql_listener_as "$TIPROXY_PORT" 'SELECT @@port' 2>/dev/null || true)
	port_b=$(mysql_listener_as "$TIPROXY_PORT_B" 'SELECT @@port' 2>/dev/null || true)
	if [[ $direct_b == 1 && ($port_a == "$TIDB_PORT_0" || $port_a == "$TIDB_PORT_1") && $port_b == "$TIDB_PORT_B" ]]; then
		cluster_matrix_ready=true
		break
	fi
	sleep 1
done
if [[ $cluster_matrix_ready != true ]]; then
	{
		echo "cluster/listener absorption failed:"
		echo "  listener $TIPROXY_PORT -> ${port_a:-<none>} (want $TIDB_PORT_0 or $TIDB_PORT_1)"
		echo "  listener $TIPROXY_PORT_B -> ${port_b:-<none>} (want $TIDB_PORT_B)"
	} >&2
	exit 1
fi
# Per-listener, delta-scoped, bidirectionally cross-checked evidence.
# Go: the fresh route record's `target` address must sit in the
# listener's own cluster port set. Rust: the fresh connection_ready
# record must pair the backend address with the cluster NAME. Both
# classes are covered explicitly (one connection per listener), and a
# fresh record pairing the OTHER cluster's port is a hard failure —
# as is any phantom/empty cluster attribution in rust mode.
# In Go mode its route record must carry the claimed group key, exact member
# count, every expected member, and selected target. In cap6 Rust mode Go is
# deliberately not a route owner and therefore must emit no Rust-session route
# record; the Rust connection_ready record is the per-listener selection oracle,
# while the full-run control tap and residual counters prove Go stayed out.
go_route_files() {
	# EXACTLY the main component log (see evidence_files): a second
	# matching file growing would shift the concatenated line count
	# and leak old records into fresh windows intermittently.
	find "${TIUP_HOME:-${HOME}/.tiup}/data/$tag" -type f -name 'tiproxy.log' 2>/dev/null | sort
}
go_route_lines() {
	local files
	files=$(go_route_files)
	if [[ -z $files ]]; then
		echo 0
		return
	fi
	# shellcheck disable=SC2086
	cat $files 2>/dev/null | wc -l | tr -d ' '
}
go_route_tail() {
	local files
	files=$(go_route_files)
	[[ -n $files ]] || return 0
	# shellcheck disable=SC2086
	cat $files 2>/dev/null | tail -n "+$(($1 + 1))"
}
# Evidence logs are file-buffered: a record written logically before a
# row can flush physically after its window opens. Each row therefore
# waits for BOTH logs to go quiet before capturing its offsets, so
# earlier phases' late flushes can never pollute the window.
quiesce_evidence_logs() {
	local prev_go=-1 prev_ev=-1 now_go now_ev
	for _ in {1..30}; do
		now_go=$(go_route_lines)
		now_ev=$(evidence_lines)
		if [[ $now_go == "$prev_go" && $now_ev == "$prev_ev" ]]; then
			return 0
		fi
		prev_go=$now_go
		prev_ev=$now_ev
		sleep 0.5
	done
	return 0
}
cluster_row() {
	local listener=$1 cluster=$2 want_ports=$3 other_ports=$4
	local offset go_offset fresh go_fresh port record go_record matched=false
	local expected_num
	expected_num=$(wc -w <<<"$want_ports" | tr -d ' ')
	# The QUERY sits inside the retry loop: a group whose second
	# member has not been absorbed yet routes with a partial
	# backend_num, and that record can never satisfy the full-
	# membership pattern — only a NEW query after absorption can.
	local go_pattern rust_pattern attempt
	for attempt in {1..30}; do
		quiesce_evidence_logs
		offset=$(evidence_lines)
		go_offset=$(go_route_lines)
		port=$(mysql_listener_as "$listener" 'SELECT @@port' 2>/dev/null || true)
		if [[ " $want_ports " != *" $port "* ]]; then
			# Topology/health publication and a just-closed connection can race by
			# one scheduler tick. Retry a fresh connection inside this bounded
			# absorption loop; only the terminal attempt is a row failure.
			sleep 0.5
			continue
		fi
		go_pattern="\"msg\":\"route\".*\"values\":\[\"$cluster:$listener\"\].*\"backend_num\":$expected_num.*\"target\":\"127\.0\.0\.1:$port\""
		rust_pattern="\"event\":\"connection_ready\".*\"listener\":\"127\.0\.0\.1:$listener\".*\"backend_addr\":\"127\.0\.0\.1:$port\".*\"cluster\":\"$cluster\""
		for _ in {1..10}; do
			go_fresh=$(go_route_tail "$go_offset")
			go_record=$(grep -E "$go_pattern" <<<"$go_fresh" | head -1 || true)
			if [[ $mode == rust ]]; then
				fresh=$(evidence_tail "$offset")
				record=$(grep -E "$rust_pattern" <<<"$fresh" | head -1 || true)
				if [[ -n $record ]]; then
					matched=true
					break
				fi
			else
				fresh=$go_fresh
				record=$go_record
				if [[ -n $record ]]; then
					matched=true
					break
				fi
			fi
			sleep 0.5
		done
		[[ $matched == true ]] && break
		sleep 1
	done
	if [[ $matched != true ]]; then
		echo "missing $mode cluster attribution for listener $listener (cluster $cluster, port $port)" >&2
		echo "fresh go route candidates:" >&2
		grep -s '"msg":"route"' <<<"${go_fresh:-}" | tail -3 >&2 || true
		return 1
	fi
	# Exact group membership is a Go-route property only. Cap6 Rust owns its
	# selector and intentionally leaves no corresponding Go route record.
	if [[ $mode == go ]]; then
		local member
		for member in $want_ports; do
			if [[ $go_record != *"127.0.0.1:$member"* ]]; then
				echo "group $cluster:$listener route record misses member 127.0.0.1:$member: $go_record" >&2
				return 1
			fi
		done
		printf 'cluster evidence (go route, listener %s): %s\n' "$listener" "$go_record"
	else
		printf 'cluster evidence (rust, listener %s): %s\n' "$listener" "$record"
	fi
	# Bidirectional cross-check over BOTH evidence windows, scoped to
	# the per-connection record kinds (route decisions / lifecycle
	# events): the other cluster's ports may not appear in any of this
	# row's fresh ROUTING records — a route record that even SCORED a
	# foreign backend for this listener's group trips it. Background
	# health/observer records legitimately name every backend at debug
	# level and prove nothing about routing, so they are out of scope.
	local other
	for other in $other_ports; do
		if [[ $mode == go ]] && grep '"msg":"route"' <<<"$go_fresh" | grep -q "127\.0\.0\.1:$other"; then
			{
				echo "listener $listener's window has a route record with the other cluster's port $other"
				echo "foreign route records in the window:"
				grep '"msg":"route"' <<<"$go_fresh" | grep "127\.0\.0\.1:$other" | tail -3
			} >&2
			return 1
		fi
		# connection_ready ONLY: a CLOSED record for an earlier
		# phase's connection is written asynchronously after its
		# client disconnects and can land inside this row's window —
		# it is not a routing decision of this row.
		if [[ $mode == rust ]] &&
			grep '"event":"connection_ready"' <<<"$fresh" | grep -q "127\.0\.0\.1:$other"; then
			echo "listener $listener's window has a ready record with the other cluster's port $other" >&2
			return 1
		fi
	done
	if [[ $mode == rust ]]; then
		if grep -qE "\"event\":\"connection_ready\".*\"cluster\":\"(default)?\"" <<<"$fresh"; then
			echo "phantom/empty cluster attribution in listener $listener's window" >&2
			return 1
		fi
	fi
}
cluster_row "$TIPROXY_PORT" cluster-a "$TIDB_PORT_0 $TIDB_PORT_1" "$TIDB_PORT_B" || exit 1
cluster_row "$TIPROXY_PORT_B" cluster-b "$TIDB_PORT_B" "$TIDB_PORT_0 $TIDB_PORT_1" || exit 1
echo "cluster matrix: listener $TIPROXY_PORT->cluster-a listener $TIPROXY_PORT_B->cluster-b (deterministic port routing)"

# Single-process acceptance: prove the pure-Rust A0->A1 connection migration
# on the main --standalone entry, then stop before the Go-coupled
# keyspace-guard sub-phase (which still reads Go control-plane logs).
if [[ $standalone == 1 ]]; then
	source "$script_dir/standalone-mig01.sh"
	run_standalone_mig01
	echo "PASS: standalone single-process executed SELECT 1, namespace matrix, and MIG-01 live migration (A0->A1, database+user-variable restored) with no Go tiproxy"
	exit 0
fi

# ---- No-keyspace-migration (DPL-07 #41 acceptance) ----
# An isolated MatchAll proxy instance puts cluster-a (ks-old) and
# cluster-b (ks-new) into ONE routing group, pins a persistent session
# onto cluster-a via fail-backend-list, then hot-swaps the list so the
# router genuinely tries to push that session to ks-new. The product
# guard must refuse at the shared issuance boundary while a NEW
# connection proves the change absorbed. Keyspaces are injected via
# topology labels (the classic-topology discrimination channel); real
# /keyspaces/tidb/<ks> propagation is locked by PDFetcher unit tests.
ka_sql_port=$((8097 + port_offset))
ka_api_port=$((8098 + port_offset))
ka_health_port=$((8099 + port_offset))
KA_SOCKET="${TMPDIR:-/tmp}/$tag-ka.sock"
# Control-frame dropper (rust+plain chaos or every T4 qualification variant): Rust dials KA_DROP_SOCKET,
# the dropper forwards to the Go control KA_SOCKET, and its admin port
# arms per-chain drops. Transparent (byte-identical) until armed.
ka_use_dropper=false
if [[ $mode == rust && ($variant == plain || ${DATAPLANE_T4_QUALIFICATION:-0} == 1) ]]; then
	ka_use_dropper=true
fi
KA_DROP_SOCKET="${TMPDIR:-/tmp}/$tag-ka-drop.sock"
ka_drop_admin_port=$((8100 + port_offset))
# CP-ADMIN 5c: the Rust process is the only management API server and binds
# the configured api.addr itself (RUST_API_OWNER), so the admin port is the
# API port. M9 drives its operator drains through it; they never cross the
# bridge.
ka_admin_port=$ka_api_port
# CP-ADMIN 5a: the Rust metric-owner endpoint gets a fixed port so the
# management plane's backend/metrics answer can be compared with it.
ka_metrics_owner_port=$((8102 + port_offset))
ka_phase_ports=("$ka_sql_port" "$ka_api_port" "$ka_health_port")
if [[ $ka_use_dropper == true ]]; then
	ka_phase_ports+=("$ka_drop_admin_port")
fi
if [[ $mode == rust ]]; then
	ka_phase_ports+=("$ka_admin_port" "$ka_metrics_owner_port")
fi
for port in "${ka_phase_ports[@]}"; do
	if "$FAULT_PROXY_BIN" --probe "127.0.0.1:$port" >/dev/null 2>&1; then
		echo "keyspace-guard phase port is already in use: $port" >&2
		exit 1
	fi
done
# Fold the KA-phase ports (incl. dropper admin) into the live PORTS ledger
# BEFORE starting any KA process and persist immediately, so a mid-phase
# failure still leaves them in the post-run leak sweep and the later
# conflict phase appends on top of them instead of overwriting state.env
# with a KA-less list.
PORTS="$PORTS ${ka_phase_ports[*]}"
printf 'PORTS=%q\n' "$PORTS" >>"$run_dir/state.env"
sed '/^\[rust-dataplane\]/,$d' "$run_dir/tiproxy.toml" >"$run_dir/tiproxy-ka.toml"
python3 - "$run_dir/tiproxy-ka.toml" "$ka_sql_port" "$ka_api_port" "$run_dir" "$TIDB_PORT_1" "$TIDB_PORT_B" <<'PYKA'
import re, sys
path, sql_port, api_port, run_dir, tidb_a1, tidb_b = sys.argv[1:7]
text = open(path).read()
text = re.sub(r'(?m)^workdir = .*$', f'workdir = "{run_dir}/ka-workdir"', text)
text = re.sub(r'(?m)^addr = "127\.0\.0\.1:\d+"$',
              lambda m, it=iter([sql_port, api_port]): f'addr = "127.0.0.1:{next(it)}"',
              text, count=2)
text = re.sub(r'(?m)^filename = .*$', f'filename = "{run_dir}/tiproxy-ka.log"', text)
# MatchAll: no port-range listeners, no port routing rule - one group
# holds every backend of both clusters.
text = re.sub(r'(?m)^port-range = .*\n', '', text)
text = re.sub(r'(?m)^routing-rule = .*\n', '', text)
# Initial pin: cluster-b and cluster-a's second backend are failed, so
# the persistent session can only land on A0/ks-old. The failover
# timeout is far beyond the phase duration - the guard, not a force
# close, must be what the old session experiences.
text = re.sub(r'(?m)^graceful-wait-before-shutdown = 0$',
              'graceful-wait-before-shutdown = 0\n'
              f'fail-backend-list = ["127.0.0.1:{tidb_b}", "127.0.0.1:{tidb_a1}"]\n'
              'failover-timeout = 300',
              text)
open(path, 'w').write(text)
PYKA
if [[ $mode == rust ]]; then
	printf '\n[rust-dataplane]\nenabled = true\ncontrol-socket = "%s"\nmetrics-owner-port = %s\n' \
		"$KA_SOCKET" "$ka_metrics_owner_port" >>"$run_dir/tiproxy-ka.toml"
	if [[ $TLS_ENABLED == true ]]; then
		# The keyspace-guard config strips the whole [rust-dataplane] block
		# (and its tls-allowed-roots) when it is regenerated, so re-admit the
		# generated certs here too for the tls variants.
		printf 'tls-allowed-roots = ["%s"]\n' "$run_dir/certs" >>"$run_dir/tiproxy-ka.toml"
	fi
	printf 'KA_SOCKET=%q\n' "$KA_SOCKET" >>"$run_dir/state.env"
fi
# "Go control plane up" for the keyspace-guard instance. In Go mode that is
# its management API. Under RUST_API_OWNER (CP-ADMIN 5c) the Go process
# serves no HTTP at all: its readiness is the control socket it listens on,
# and the management API is checked on the Rust process once that is ready.
ka_wait_go_control_up() {
	local pid=$1
	for _ in {1..100}; do
		if ! kill -0 "$pid" 2>/dev/null; then
			return 1
		fi
		if [[ $mode == rust ]]; then
			[[ -S $KA_SOCKET ]] && return 0
		elif curl --noproxy '*' --fail --silent \
			"http://127.0.0.1:$ka_api_port/api/admin/namespace/" -o /dev/null; then
			return 0
		fi
		sleep 0.2
	done
	return 1
}
"$repo_root/bin/tiproxy" --config "$run_dir/tiproxy-ka.toml" \
	>"$run_dir/tiproxy-ka.out" 2>&1 &
KA_PID=$!
record_t4_process go-ka start "$KA_PID" 0
printf 'KA_PID=%q\n' "$KA_PID" >>"$run_dir/state.env"
if ! ka_wait_go_control_up "$KA_PID"; then
	echo "keyspace-guard instance never came up" >&2
	tail -20 "$run_dir/tiproxy-ka.out" >&2 || true
	exit 1
fi
# The Rust dataplane normally dials the Go control socket directly. In
# the dropper chains it dials the dropper's front socket instead; the
# dropper forwards to the Go control socket and stays byte-transparent
# until an /arm request selects a frame to drop.
ka_rust_control_socket=$KA_SOCKET
if [[ $ka_use_dropper == true ]]; then
	# No pre-removal here: the dropper's own start() Lstat-checks the
	# front path and removes ONLY a pre-existing socket (failing closed
	# on a regular file), so a blind rm would bypass that audited guard.
	# --pause-after-drop: a drop tears the control link and holds
	# reconnects until /release, giving each chain a clean "frame lost,
	# no reconcile yet" observation window and then a deterministic
	# reconnect that fires Rust's automatic ReconcileRequest. It never
	# triggers while unarmed, so the transparent passthrough is unaffected.
	"$run_dir/controldropper" \
		--front-socket "$KA_DROP_SOCKET" \
		--target-socket "$KA_SOCKET" \
		--admin "127.0.0.1:$ka_drop_admin_port" \
		--pause-after-drop \
		>"$run_dir/controldropper.log" 2>&1 &
	KA_DROP_PID=$!
	record_t4_process control-tap-ka start "$KA_DROP_PID" 0
	printf 'KA_DROP_PID=%q\n' "$KA_DROP_PID" >>"$run_dir/state.env"
	printf 'KA_DROP_SOCKET=%q\n' "$KA_DROP_SOCKET" >>"$run_dir/state.env"
	ka_drop_ready=false
	for _ in {1..100}; do
		if ! kill -0 "$KA_DROP_PID" 2>/dev/null; then
			break
		fi
		if [[ -S $KA_DROP_SOCKET ]] &&
			curl --noproxy '*' --fail --silent --max-time 5 \
				"http://127.0.0.1:$ka_drop_admin_port/state" -o /dev/null; then
			ka_drop_ready=true
			break
		fi
		sleep 0.1
	done
	if [[ $ka_drop_ready != true ]]; then
		echo "keyspace-guard phase: control dropper never became ready" >&2
		tail -20 "$run_dir/controldropper.log" >&2 || true
		exit 1
	fi
	ka_rust_control_socket=$KA_DROP_SOCKET
fi
# cleanup.sh reaps the KA Rust process by the control socket it actually
# binds; under the dropper that is KA_DROP_SOCKET, not KA_SOCKET.
printf 'KA_RUST_CONTROL_SOCKET=%q\n' "$ka_rust_control_socket" >>"$run_dir/state.env"
if [[ $mode == rust ]]; then
	ka_rust_tls_args=()
	if [[ $TLS_ENABLED == true ]]; then
		ka_rust_tls_args=(--tls-root "$run_dir/certs")
	fi
	"$rust_binary" --config "$run_dir/tiproxy-ka.toml" \
		--control-socket "$ka_rust_control_socket" --control-uid "$(id -u)" \
		--health-port "$ka_health_port" \
		${ka_rust_tls_args[@]+"${ka_rust_tls_args[@]}"} \
		>"$run_dir/tiproxy-rs-ka.log" 2>&1 &
	KA_RUST_PID=$!
	record_t4_process rust-ka start "$KA_RUST_PID" 0
	printf 'KA_RUST_PID=%q\n' "$KA_RUST_PID" >>"$run_dir/state.env"
	ka_ready=false
	for _ in {1..150}; do
		if ! kill -0 "$KA_RUST_PID" 2>/dev/null; then
			break
		fi
		if curl --noproxy '*' --fail --silent --max-time 5 \
			"http://127.0.0.1:$ka_health_port/" -o /dev/null; then
			ka_ready=true
			break
		fi
		sleep 0.2
	done
	if [[ $ka_ready != true ]]; then
		echo "keyspace-guard rust dataplane never became ready" >&2
		tail -20 "$run_dir/tiproxy-rs-ka.log" >&2 || true
		exit 1
	fi
	# CP-ADMIN 5c: the management API of this pair is the Rust process
	# on api.addr (no --admin-addr); every later management call in this
	# phase goes there.
	if ! curl --noproxy '*' --fail --silent --max-time 5 \
		"http://127.0.0.1:$ka_api_port/api/admin/namespace/" -o /dev/null; then
		echo "keyspace-guard management API (Rust, api.addr) did not answer" >&2
		tail -20 "$run_dir/tiproxy-rs-ka.log" >&2 || true
		exit 1
	fi
	if [[ $ka_use_dropper == true ]]; then
		# Durable transparent-passthrough oracle: with Rust connected and
		# control frames already flowing but nothing armed, the dropper
		# must be a pure forwarder. Snapshot /state into the artifact and
		# assert it, so a silent loss of transparency fails the run.
		curl --noproxy '*' --fail --silent --show-error --max-time 5 \
			"http://127.0.0.1:$ka_drop_admin_port/state" \
			-o "$run_dir/controldropper-state-transparent.json"
		if ! python3 - "$run_dir/controldropper-state-transparent.json" "$KA_SOCKET" <<'PYDROP'
import json, sys
state = json.load(open(sys.argv[1]))
ka_socket = sys.argv[2]
errors = []
if state.get("target") != ka_socket:
    errors.append(f'target={state.get("target")!r} != KA_SOCKET {ka_socket!r}')
if state.get("armed") is not False:
    errors.append(f'armed={state.get("armed")!r} (want false)')
if state.get("drop_count") != 0:
    errors.append(f'drop_count={state.get("drop_count")!r} (want 0)')
if not isinstance(state.get("connect_count"), int) or state["connect_count"] < 1:
    errors.append(f'connect_count={state.get("connect_count")!r} (want >=1)')
if not isinstance(state.get("forwarded"), int) or state["forwarded"] < 1:
    errors.append(f'forwarded={state.get("forwarded")!r} (want >0)')
if errors:
    print("dropper transparent-state oracle failed: " + "; ".join(errors), file=sys.stderr)
    sys.exit(1)
print(f'dropper transparent: target=KA_SOCKET armed=false drop_count=0 '
      f'connect_count={state["connect_count"]} forwarded={state["forwarded"]}')
PYDROP
		then
			echo "keyspace-guard phase: dropper transparent-state oracle failed" >&2
			exit 1
		fi
	fi
fi
ka_log_lines() {
	[[ -f "$run_dir/tiproxy-ka.log" ]] || { echo 0; return; }
	wc -l <"$run_dir/tiproxy-ka.log" | tr -d ' '
}
ka_log_tail() {
	[[ -f "$run_dir/tiproxy-ka.log" ]] || return 0
	tail -n "+$(($1 + 1))" "$run_dir/tiproxy-ka.log"
}
# Redirection-capability gate: EVERY backend of BOTH clusters must
# report its signing cert (per-backend structured evidence), and the
# router's AND-aggregate must have flipped to true and never back -
# otherwise rebalance never runs and the "pressure" would be fake.
# The health check logs backends by their STATUS address.
ka_status_addrs=("127.0.0.1:$((10080 + port_offset))" "127.0.0.1:$((10081 + port_offset))" "127.0.0.1:$((10080 + PORT_OFFSET_B))")
ka_caps_ready=false
for _ in {1..60}; do
	caps=0
	for addr in "${ka_status_addrs[@]}"; do
		if grep -qs "\"backend has updated signing cert\".*\"$addr\".*\"support_redirection\":true" "$run_dir/tiproxy-ka.log"; then
			caps=$((caps + 1))
		fi
	done
	if ((caps == 3)) &&
		grep -qs '"updated supporting redirection".*"support":true' "$run_dir/tiproxy-ka.log"; then
		ka_caps_ready=true
		break
	fi
	sleep 1
done
if [[ $ka_caps_ready != true ]]; then
	echo "keyspace-guard phase: not all backends report redirection capability" >&2
	grep -s "signing cert\|supporting redirection" "$run_dir/tiproxy-ka.log" | tail -6 >&2 || true
	exit 1
fi
if grep -qs '"updated supporting redirection".*"support":false' "$run_dir/tiproxy-ka.log"; then
	echo "keyspace-guard phase: router redirection support flipped off" >&2
	exit 1
fi
for addr in "${ka_status_addrs[@]}"; do
	grep -s "\"backend has updated signing cert\".*\"$addr\".*\"support_redirection\":true" "$run_dir/tiproxy-ka.log" |
		head -1 | sed 's/^/redirection capability: /'
done
mysql_ka_root() {
	mysql --batch --skip-column-names --connect-timeout=4 \
		-h 127.0.0.1 -P "$ka_sql_port" -u root \
		"${mysql_tls_args[@]}" ${mysql_compression_arg:+"$mysql_compression_arg"} -e "$1"
}
ka_set_fail_list() {
	local failed=$1 phase=$2 current value toml_failed
	if [[ $mode == rust ]]; then
		if [[ -z $etcdctl_bin || ! -x $etcdctl_bin ]]; then
			echo "keyspace-guard phase: Rust dynamic config needs etcdctl" >&2
			exit 1
		fi
		if ! command -v jq >/dev/null 2>&1; then
			echo "keyspace-guard phase: Rust dynamic config needs jq" >&2
			exit 1
		fi
		current=$(ETCDCTL_API=3 "$etcdctl_bin" \
			--endpoints "http://127.0.0.1:$PD_PORT" \
			get /config/proxy --print-value-only)
		# The first persistent proxy mutation replaces the process seed.
		# Materialize the complete dynamic subset so that a fail-list-only
		# test never zeros capacity or erases either configured cluster.
		if [[ -z $current ]]; then
			current=$(jq -cn \
				--arg pd_a "127.0.0.1:$PD_PORT" \
				--arg pd_b "127.0.0.1:$PD_PORT_B" \
				--arg proxy_protocol "$dynamic_proxy_protocol" \
				'{
					"max-connections": 100,
					"high-memory-usage-reject-threshold": 0.9,
					"conn-buffer-size": 32768,
					"frontend-keepalive": {"enabled":true,"idle":0,"cnt":0,"intvl":0,"timeout":0},
					"backend-healthy-keepalive": {"enabled":true,"idle":60000000000,"cnt":5,"intvl":3000000000,"timeout":15000000000},
					"backend-unhealthy-keepalive": {"enabled":true,"idle":10000000000,"cnt":5,"intvl":1000000000,"timeout":5000000000},
					"proxy-protocol": $proxy_protocol,
					"graceful-wait-before-shutdown": 0,
					"graceful-close-conn-timeout": 5,
					"public-endpoints": [],
					"backend-clusters": [
						{"name":"cluster-a","pd-addrs":$pd_a,"ns-servers":[]},
						{"name":"cluster-b","pd-addrs":$pd_b,"ns-servers":[]}
					],
					"fail-backend-list": [],
					"failover-timeout": 300
				}')
		fi
		value=$(jq -c --argjson failed "$failed" \
			'.["fail-backend-list"] = $failed | .["failover-timeout"] = 300' \
			<<<"$current")
		printf '%s\n' "$value" >"$run_dir/ka-proxy-$phase.json"
		ETCDCTL_API=3 "$etcdctl_bin" --endpoints "http://127.0.0.1:$PD_PORT" put \
			/config/proxy "$value" >"$run_dir/ka-etcd-$phase.log"
	else
		toml_failed=$(jq -r 'map("\"" + . + "\"") | join(", ")' <<<"$failed")
		cat >"$run_dir/ka-proxy-$phase.toml" <<KATOML
[proxy]
fail-backend-list = [$toml_failed]
KATOML
		curl --noproxy '*' --fail --silent --show-error -X PUT \
			--data-binary "@$run_dir/ka-proxy-$phase.toml" \
			"http://127.0.0.1:$ka_api_port/api/admin/config/" -o /dev/null
	fi
}
# EXACT absorption of the initial pin, evidence-first: the structured
# failover records must show B and A1 entering failover and A0 NOT -
# only then is a probe landing on A0 discriminating rather than a
# lucky sequence over three routeable backends. (The startup
# fail-list reaching a new MatchAll group at all is the product fix
# locked by TestStartupFailoverListAppliesToNewMatchAllGroup.)
ka_failover_ready=false
for _ in {1..30}; do
	if grep -qs "\"backend enters failover\".*\"127\.0\.0\.1:$TIDB_PORT_B\"" "$run_dir/tiproxy-ka.log" &&
		grep -qs "\"backend enters failover\".*\"127\.0\.0\.1:$TIDB_PORT_1\"" "$run_dir/tiproxy-ka.log"; then
		ka_failover_ready=true
		break
	fi
	sleep 1
done
if [[ $ka_failover_ready != true ]]; then
	echo "keyspace-guard phase: initial fail-list never produced failover evidence for B and A1" >&2
	grep -s "backend enters failover" "$run_dir/tiproxy-ka.log" | tail -4 >&2 || true
	exit 1
fi
if grep -qs "\"backend enters failover\".*\"127\.0\.0\.1:$TIDB_PORT_0\"" "$run_dir/tiproxy-ka.log"; then
	echo "keyspace-guard phase: A0 unexpectedly entered failover under the initial pin" >&2
	exit 1
fi
grep -s "backend enters failover" "$run_dir/tiproxy-ka.log" | tail -2 | sed 's/^/initial pin evidence: /'
ka_pin_ready=false
for _ in {1..30}; do
	pin_port=$(mysql_ka_root 'SELECT @@port' 2>/dev/null || true)
	if [[ $pin_port == "$TIDB_PORT_0" ]]; then
		ka_pin_ready=true
		break
	fi
	sleep 1
done
if [[ $ka_pin_ready != true ]]; then
	echo "keyspace-guard phase: initial pin never absorbed (landed '$pin_port', want $TIDB_PORT_0)" >&2
	exit 1
fi

# ---- MIG-01 live same-keyspace migration (all Rust wire variants) ----
# The unit suite proves every candidate-only rollback class. This real-TiDB
# row proves the successful production composition against TiDB's signed
# session token and native SHOW/SET SESSION_STATES implementation: one client
# remains open while the router moves it A0 -> A1 inside ks-old; current DB and
# a user variable survive, and subsequent SQL is served by A1. The same phase
# runs under plain, TLS, PROXY v2, zlib, zstd, and TLS+PROXY+zstd.
if [[ $mode == rust ]]; then
	mysql_backend_admin "CREATE DATABASE IF NOT EXISTS mig01_live;"
	MIG_FIFO="$run_dir/mig01-session.fifo"
	mkfifo "$MIG_FIFO"
	mig_rust_offset=$(wc -l <"$run_dir/tiproxy-rs-ka.log" | tr -d ' ')
	mysql --batch --skip-column-names --force --unbuffered \
		-h 127.0.0.1 -P "$ka_sql_port" -u root \
		"${mysql_tls_args[@]}" ${mysql_compression_arg:+"$mysql_compression_arg"} \
		<"$MIG_FIFO" >"$run_dir/mig01-session.out" 2>&1 &
	MIG_SESSION_PID=$!
	printf 'MIG_SESSION_PID=%q\n' "$MIG_SESSION_PID" >>"$run_dir/state.env"
	printf 'MIG_FIFO=%q\n' "$MIG_FIFO" >>"$run_dir/state.env"
	exec 8>"$MIG_FIFO"
	migration_query() {
		local marker=$1 sql=$2 line=
		printf '%s\n' "$sql" >&8
		for _ in {1..40}; do
			line=$(grep -s "^$marker|" "$run_dir/mig01-session.out" | tail -1 || true)
			if [[ -n $line ]]; then
				printf '%s\n' "$line"
				return 0
			fi
			if ! kill -0 "$MIG_SESSION_PID" 2>/dev/null; then
				echo "MIG-01 live session died; tail:" >&2
				tail -8 "$run_dir/mig01-session.out" >&2 || true
				return 1
			fi
			sleep 0.25
		done
		echo "MIG-01 live session never answered marker $marker" >&2
		return 1
	}
	mig_baseline=$(migration_query MIGBASE \
		"USE mig01_live; SET @mig01_marker = 'state-live'; SELECT CONCAT('MIGBASE|', CONNECTION_ID(), '|', @@port, '|', COALESCE(DATABASE(), 'NULL'), '|', COALESCE(@mig01_marker, 'NULL'));") || exit 1
	mig_base_port=$(cut -d'|' -f3 <<<"$mig_baseline")
	mig_base_db=$(cut -d'|' -f4 <<<"$mig_baseline")
	mig_base_marker=$(cut -d'|' -f5 <<<"$mig_baseline")
	if [[ $mig_base_port != "$TIDB_PORT_0" || $mig_base_db != mig01_live || $mig_base_marker != state-live ]]; then
		echo "MIG-01 invalid baseline: $mig_baseline" >&2
		exit 1
	fi
	mig_proxy_conn_id=
	for _ in {1..20}; do
		mig_proxy_conn_id=$(tail -n "+$((mig_rust_offset + 1))" "$run_dir/tiproxy-rs-ka.log" |
			grep '"event":"connection_ready"' | head -1 |
			sed -n 's/.*"connection_id":\([0-9]*\).*/\1/p')
		[[ -n $mig_proxy_conn_id ]] && break
		sleep 0.5
	done
	if [[ -z $mig_proxy_conn_id ]]; then
		echo "MIG-01 could not capture the persistent session's proxy connection id" >&2
		exit 1
	fi

	# Make A1 the sole routeable same-keyspace target through the Rust
	# owner's persistent CP-CFG source. A fresh connection is the absorption
	# oracle; the old FIFO client is the migration oracle.
	ka_set_fail_list \
		"[\"127.0.0.1:$TIDB_PORT_B\",\"127.0.0.1:$TIDB_PORT_0\"]" \
		mig01-swap
	mig_swap_ready=false
	for _ in {1..40}; do
		mig_new_port=$(mysql_ka_root 'SELECT @@port' 2>/dev/null || true)
		if [[ $mig_new_port == "$TIDB_PORT_1" ]]; then
			mig_swap_ready=true
			break
		fi
		sleep 0.5
	done
	if [[ $mig_swap_ready != true ]]; then
		echo "MIG-01 target swap never absorbed (new connection '$mig_new_port', want $TIDB_PORT_1)" >&2
		exit 1
	fi
	mig_result=
	for attempt in {1..40}; do
		marker="MIGTRY$attempt"
		row=$(migration_query "$marker" \
			"SELECT CONCAT('$marker|', CONNECTION_ID(), '|', @@port, '|', COALESCE(DATABASE(), 'NULL'), '|', COALESCE(@mig01_marker, 'NULL'));") || exit 1
		row_port=$(cut -d'|' -f3 <<<"$row")
		row_db=$(cut -d'|' -f4 <<<"$row")
		row_marker=$(cut -d'|' -f5 <<<"$row")
		if [[ $row_port == "$TIDB_PORT_1" ]]; then
			mig_result=$row
			if [[ $row_db != mig01_live || $row_marker != state-live ]]; then
				echo "MIG-01 reached A1 but lost restored state: $row" >&2
				exit 1
			fi
			break
		fi
		sleep 0.5
	done
	if [[ -z $mig_result ]]; then
		echo "MIG-01 persistent session did not move to A1; last row: ${row:-<none>}" >&2
		exit 1
	fi
	if ! kill -0 "$MIG_SESSION_PID" 2>/dev/null; then
		echo "MIG-01 client process was replaced instead of surviving the atomic swap" >&2
		exit 1
	fi
	echo "MIG-01 live migration: proxy_conn_id=$mig_proxy_conn_id A0=$TIDB_PORT_0 -> A1=$TIDB_PORT_1; database+user-variable restored ($mig_result)"

	# CP-ADMIN 5a/5b real-process row. 5b: the management redirect sweep
	# (Go debug/redirect) must self-migrate the persistent session on the
	# backend it is on (A1): a new backend connection, database and user
	# variable restored, the route ledger settled with the same active count.
	# 5a: the admin backend/metrics answer must be the metric-owner
	# endpoint's bytes, for a named cluster and for the empty name.
	adm_ledger() {
		curl --noproxy '*' --fail --silent --max-time 5 \
			"http://127.0.0.1:$ka_health_port/health" |
			python3 -c 'import json,sys; l=json.load(sys.stdin)["route_ledger"]; print(l["active"], l["incoming"], l["outgoing"], l["unsettled_redirects"])'
	}
	read -r adm_active_before _ _ _ <<<"$(adm_ledger)" || exit 1
	adm_log_offset=$(wc -l <"$run_dir/tiproxy-rs-ka.log")
	adm_conn_before=$(cut -d'|' -f2 <<<"$mig_result")
	adm_code=$(curl --noproxy '*' --silent --show-error -X POST \
		"http://127.0.0.1:$ka_admin_port/api/debug/redirect" \
		-o "$run_dir/cp-admin-redirect.json" -w '%{http_code}')
	if [[ $adm_code != 200 || $(cat "$run_dir/cp-admin-redirect.json") != '""' ]]; then
		echo "CP-ADMIN debug/redirect answered $adm_code: $(cat "$run_dir/cp-admin-redirect.json" 2>/dev/null)" >&2
		exit 1
	fi
	adm_summary=
	for _ in {1..40}; do
		adm_summary=$(tail -n "+$((adm_log_offset + 1))" "$run_dir/tiproxy-rs-ka.log" |
			grep '"event":"redirect_connections"' | head -1 || true)
		[[ -n $adm_summary ]] && break
		sleep 0.25
	done
	if [[ -z $adm_summary ]]; then
		echo "CP-ADMIN redirect sweep logged no summary" >&2
		exit 1
	fi
	adm_accepted=$(sed -n 's/.*"accepted":\([0-9]*\).*/\1/p' <<<"$adm_summary")
	adm_offered=$(sed -n 's/.*"offered":\([0-9]*\).*/\1/p' <<<"$adm_summary")
	if [[ -z $adm_accepted || $adm_accepted -lt 1 ]]; then
		echo "CP-ADMIN redirect sweep accepted nothing: $adm_summary" >&2
		exit 1
	fi
	adm_settled=false
	for _ in {1..100}; do
		read -r adm_active adm_incoming adm_outgoing adm_unsettled <<<"$(adm_ledger)" || exit 1
		if [[ $adm_incoming == 0 && $adm_outgoing == 0 && $adm_unsettled == 0 ]]; then
			adm_settled=true
			break
		fi
		sleep 0.1
	done
	if [[ $adm_settled != true || $adm_active != "$adm_active_before" ]]; then
		echo "CP-ADMIN redirect sweep did not settle (active $adm_active_before -> $adm_active, incoming $adm_incoming, outgoing $adm_outgoing, unsettled $adm_unsettled)" >&2
		exit 1
	fi
	adm_row=$(migration_query MIGADM \
		"SELECT CONCAT('MIGADM|', CONNECTION_ID(), '|', @@port, '|', COALESCE(DATABASE(), 'NULL'), '|', COALESCE(@mig01_marker, 'NULL'));") || exit 1
	adm_conn_after=$(cut -d'|' -f2 <<<"$adm_row")
	if [[ $(cut -d'|' -f3 <<<"$adm_row") != "$TIDB_PORT_1" || $(cut -d'|' -f4 <<<"$adm_row") != mig01_live ||
		$(cut -d'|' -f5 <<<"$adm_row") != state-live || $adm_conn_after == "$adm_conn_before" ]]; then
		echo "CP-ADMIN self-migration lost state or stayed on the old backend connection: before conn $adm_conn_before, after $adm_row" >&2
		exit 1
	fi
	for adm_cluster in cluster-a cluster-b ""; do
		adm_admin_headers="$run_dir/cp-admin-backend-metrics-${adm_cluster:-primary}.headers"
		if ! curl --noproxy '*' --fail --silent --show-error --max-time 5 \
			-D "$adm_admin_headers" -o "$run_dir/cp-admin-backend-metrics-${adm_cluster:-primary}.json" \
			"http://127.0.0.1:$ka_admin_port/api/backend/metrics?cluster=$adm_cluster" ||
			! curl --noproxy '*' --fail --silent --show-error --max-time 5 \
				-o "$run_dir/cp-owner-backend-metrics-${adm_cluster:-primary}.json" \
				"http://127.0.0.1:$ka_metrics_owner_port/api/backend/metrics?cluster=$adm_cluster"; then
			echo "CP-ADMIN backend/metrics request failed for cluster '$adm_cluster'" >&2
			exit 1
		fi
		if ! grep -qi '^content-type: application/json' "$adm_admin_headers" ||
			! cmp -s "$run_dir/cp-admin-backend-metrics-${adm_cluster:-primary}.json" \
				"$run_dir/cp-owner-backend-metrics-${adm_cluster:-primary}.json"; then
			echo "CP-ADMIN backend/metrics for cluster '$adm_cluster' differs from the metric-owner endpoint" >&2
			exit 1
		fi
	done
	echo "CP-ADMIN: debug/redirect sweep offered=$adm_offered accepted=$adm_accepted settled with $adm_active active; persistent session self-migrated on A1 (backend conn $adm_conn_before -> $adm_conn_after, database+user-variable restored); backend/metrics admin == metric-owner bytes (cluster-a $(wc -c <"$run_dir/cp-admin-backend-metrics-cluster-a.json") B, cluster-b $(wc -c <"$run_dir/cp-admin-backend-metrics-cluster-b.json") B, primary $(wc -c <"$run_dir/cp-admin-backend-metrics-primary.json") B)"

	# Close the migrated client, then restore the initial A0 pin before the
	# separate cross-keyspace refusal phase establishes its own old session.
	exec 8>&-
	for _ in {1..40}; do
		kill -0 "$MIG_SESSION_PID" 2>/dev/null || break
		sleep 0.25
	done
	kill "$MIG_SESSION_PID" 2>/dev/null || true
	wait "$MIG_SESSION_PID" 2>/dev/null || true
	rm -f "$MIG_FIFO"
	printf 'MIG_SESSION_PID=\nMIG_FIFO=\n' >>"$run_dir/state.env"
	ka_set_fail_list \
		"[\"127.0.0.1:$TIDB_PORT_B\",\"127.0.0.1:$TIDB_PORT_1\"]" \
		mig01-reset
	mig_reset_ready=false
	for _ in {1..40}; do
		mig_reset_port=$(mysql_ka_root 'SELECT @@port' 2>/dev/null || true)
		if [[ $mig_reset_port == "$TIDB_PORT_0" ]]; then
			mig_reset_ready=true
			break
		fi
		sleep 0.5
	done
	if [[ $mig_reset_ready != true ]]; then
		echo "MIG-01 could not restore the A0 pin (new connection '$mig_reset_port')" >&2
		exit 1
	fi
fi

# The persistent OLD session: a FIFO-driven mysql client that stays
# open across the dynamic swap. FD 9 keeps the FIFO writable.
KA_FIFO="$run_dir/ka-session.fifo"
mkfifo "$KA_FIFO"
# The guard's sample_conn_id is the PROXY-side connection id, not the
# backend CONNECTION_ID(): capture it from the session's own fresh
# "new connection" record (rust mode: the connection_ready record).
ka_session_offset=$(ka_log_lines)
if [[ $mode == rust ]]; then
	ka_rust_session_offset=$(wc -l <"$run_dir/tiproxy-rs-ka.log" | tr -d ' ')
fi
printf 'KA_FIFO=%q\n' "$KA_FIFO" >>"$run_dir/state.env"
# --unbuffered: the client's stdout goes to a file and would otherwise
# sit in a block buffer - the marker poll needs per-query flushes.
mysql --batch --skip-column-names --force --unbuffered \
	-h 127.0.0.1 -P "$ka_sql_port" -u root \
	"${mysql_tls_args[@]}" ${mysql_compression_arg:+"$mysql_compression_arg"} \
	<"$KA_FIFO" >"$run_dir/ka-session.out" 2>&1 &
KA_SESSION_PID=$!
printf 'KA_SESSION_PID=%q\n' "$KA_SESSION_PID" >>"$run_dir/state.env"
exec 9>"$KA_FIFO"
session_query() {
	local marker=$1 sql=$2 line=
	printf '%s\n' "$sql" >&9
	for _ in {1..40}; do
		line=$(grep -s "^$marker|" "$run_dir/ka-session.out" | tail -1 || true)
		if [[ -n $line ]]; then
			printf '%s\n' "$line"
			return 0
		fi
		if ! kill -0 "$KA_SESSION_PID" 2>/dev/null; then
			echo "persistent session died; tail:" >&2
			tail -5 "$run_dir/ka-session.out" >&2 || true
			return 1
		fi
		sleep 0.5
	done
	echo "persistent session never answered marker $marker" >&2
	return 1
}
baseline=$(session_query BASE "SELECT CONCAT('BASE|', CONNECTION_ID(), '|', @@port);") || exit 1
base_conn_id=$(cut -d'|' -f2 <<<"$baseline")
base_port=$(cut -d'|' -f3 <<<"$baseline")
if [[ $base_port != "$TIDB_PORT_0" ]]; then
	echo "old session landed on '$base_port' (want $TIDB_PORT_0)" >&2
	exit 1
fi
proxy_conn_id=
for _ in {1..20}; do
	if [[ $mode == rust ]]; then
		proxy_conn_id=$(tail -n "+$((ka_rust_session_offset + 1))" "$run_dir/tiproxy-rs-ka.log" |
			grep '"event":"connection_ready"' | head -1 |
			sed -n 's/.*"connection_id":\([0-9]*\).*/\1/p')
	else
		proxy_conn_id=$(ka_log_tail "$ka_session_offset" |
			grep '"new connection"' | head -1 |
			sed -n 's/.*"connID":\([0-9]*\).*/\1/p')
	fi
	[[ -n $proxy_conn_id ]] && break
	sleep 0.5
done
if [[ -z $proxy_conn_id ]]; then
	echo "could not capture the old session's proxy-side connection id" >&2
	exit 1
fi
echo "old session baseline: CONNECTION_ID=$base_conn_id proxy_conn_id=$proxy_conn_id backend=127.0.0.1:$base_port (ks-old)"
# THE DYNAMIC SWAP: fail A0+A1 so only ks-new remains routeable. Rust
# CP-CFG owns the mutation in cap6 mode; legacy Go retains its admin API.
ka_guard_offset=$(ka_log_lines)
ka_set_fail_list \
	"[\"127.0.0.1:$TIDB_PORT_0\",\"127.0.0.1:$TIDB_PORT_1\"]" \
	ka-cross-keyspace
# Anti-false-pass: a NEW connection must land on ks-new, proving the
# swap absorbed. Only then does the old session's stability MEAN
# anything.
ka_swap_ready=false
for _ in {1..30}; do
	new_port=$(mysql_ka_root 'SELECT @@port' 2>/dev/null || true)
	if [[ $new_port == "$TIDB_PORT_B" ]]; then
		ka_swap_ready=true
		break
	fi
	sleep 1
done
if [[ $ka_swap_ready != true ]]; then
	echo "keyspace-guard phase: swap never absorbed (new connection landed '$new_port', want $TIDB_PORT_B)" >&2
	exit 1
fi
echo "swap absorbed: new connection -> 127.0.0.1:$new_port (ks-new)"
if [[ $mode == go ]]; then
	# Legacy-owner comparison: Go exposes a structured guard record tied to
	# the exact session and must not issue a redirect for it.
	ka_guard_hit=
	for _ in {1..40}; do
		ka_guard_hit=$(ka_log_tail "$ka_guard_offset" |
			grep -s '"skip cross-keyspace redirect".*"from_keyspace":"ks-old".*"to_keyspace":"ks-new"' |
			head -1 || true)
		if [[ -n $ka_guard_hit ]]; then
			break
		fi
		sleep 0.5
	done
	if [[ -z $ka_guard_hit ]]; then
		echo "keyspace-guard phase: no fresh Go guard hit after the swap" >&2
		ka_log_tail "$ka_guard_offset" | tail -5 >&2 || true
		exit 1
	fi
	if [[ $ka_guard_hit != *"\"sample_conn_id\":$proxy_conn_id"* ||
		$ka_guard_hit != *'"blocked_conn_count":1'* ]]; then
		echo "Go guard hit is not the exact old connection: $ka_guard_hit" >&2
		exit 1
	fi
	if ka_log_tail "$ka_guard_offset" | grep -qs "\"begin redirect connection\".*\"connID\":$proxy_conn_id"; then
		echo "old connection received a redirect despite the guard" >&2
		exit 1
	fi
	echo "guard hit: $ka_guard_hit"
fi
# Old-session oracles on the SAME session: identity and backend both
# unchanged, still serving.
check=$(session_query CHK "SELECT CONCAT('CHK|', CONNECTION_ID(), '|', @@port);") || exit 1
chk_conn_id=$(cut -d'|' -f2 <<<"$check")
chk_port=$(cut -d'|' -f3 <<<"$check")
if [[ $chk_conn_id != "$base_conn_id" || $chk_port != "$base_port" ]]; then
	echo "old session changed identity/backend: $check (baseline $baseline)" >&2
	exit 1
fi
echo "old session intact after swap: CONNECTION_ID=$chk_conn_id backend=127.0.0.1:$chk_port (ks-old)"
if [[ $mode == rust ]]; then
	curl --noproxy '*' --fail --silent --show-error --max-time 5 \
		"http://127.0.0.1:$ka_health_port/health" \
		-o "$run_dir/ka-rust-cross-keyspace-health.json"
	jq -e '.route_ledger.sessions >= 1 and
		.route_ledger.active >= 1 and
		.route_ledger.incoming == 0 and
		.route_ledger.outgoing == 0 and
		.route_ledger.unsettled_redirects == 0 and
		.route_ledger.unsettled_closes == 0' \
		"$run_dir/ka-rust-cross-keyspace-health.json" >/dev/null || {
		echo "Rust cross-keyspace refusal left a pending route token" >&2
		cat "$run_dir/ka-rust-cross-keyspace-health.json" >&2
		exit 1
	}
	echo "Rust cross-keyspace refusal: sole fresh target is ks-new, exact old session remains ks-old, route ledger settled"
fi
# Restore the initial pin well before failover-timeout, close the old
# session cleanly, and tear the instance down.
ka_set_fail_list \
	"[\"127.0.0.1:$TIDB_PORT_B\",\"127.0.0.1:$TIDB_PORT_1\"]" \
	ka-restore
exec 9>&-
for _ in {1..40}; do
	kill -0 "$KA_SESSION_PID" 2>/dev/null || break
	sleep 0.5
done
kill "$KA_SESSION_PID" 2>/dev/null || true
wait "$KA_SESSION_PID" 2>/dev/null || true
if [[ $ka_use_dropper == true && ${DATAPLANE_LEGACY_ROUTE_CHAOS:-0} == 1 ]]; then
	# ---- CTL-06 chaos chain (b): a dropped ConnectionEvent{CLOSED}
	# leaves Go's per-backend accounting holding a ghost; the automatic
	# ReconcileRequest on the next control reconnect clears it to EXACTLY
	# the live count (never negative). Evidence is Go's
	# tiproxy_balance_b_conn gauge plus the dropper's own drop record.
	ka_backend_conn() {
		curl --noproxy '*' --fail --silent --max-time 5 \
			"http://127.0.0.1:$ka_api_port/api/metrics/" 2>/dev/null |
			awk -v b="backend=\"$1\"" \
				'$0 ~ /^tiproxy_balance_b_conn\{/ && index($0, b) { v=$NF } END { print (v==""?0:v) }'
	}
	ka_drop_state() {
		curl --noproxy '*' --fail --silent --max-time 5 \
			"http://127.0.0.1:$ka_drop_admin_port/state" 2>/dev/null
	}
	# The pin is restored to A0 (ks-old): it is the sole routeable
	# backend, so a new session lands there and its gauge is the one under
	# test. Read the baseline BEFORE opening so a pre-existing ghost or an
	# unrelated connection can never masquerade as our +1.
	ka_pinned_addr="127.0.0.1:$TIDB_PORT_0"
	kb_before=$(ka_backend_conn "$ka_pinned_addr")
	# A fresh persistent connection whose CLOSED we will lose.
	KB_FIFO="$run_dir/kb-session.fifo"
	mkfifo "$KB_FIFO"
	printf 'KB_FIFO=%q\n' "$KB_FIFO" >>"$run_dir/state.env"
	kb_rust_offset=$(wc -l <"$run_dir/tiproxy-rs-ka.log" | tr -d ' ')
	mysql --batch --skip-column-names --force --unbuffered \
		-h 127.0.0.1 -P "$ka_sql_port" -u root \
		"${mysql_tls_args[@]}" ${mysql_compression_arg:+"$mysql_compression_arg"} \
		<"$KB_FIFO" >"$run_dir/kb-session.out" 2>&1 &
	KB_SESSION_PID=$!
	printf 'KB_SESSION_PID=%q\n' "$KB_SESSION_PID" >>"$run_dir/state.env"
	exec 8>"$KB_FIFO"
	printf "SELECT CONCAT('KB|', CONNECTION_ID(), '|', @@port);\n" >&8
	kb_line=
	for _ in {1..40}; do
		kb_line=$(grep -s '^KB|' "$run_dir/kb-session.out" | tail -1 || true)
		[[ -n $kb_line ]] && break
		if ! kill -0 "$KB_SESSION_PID" 2>/dev/null; then
			echo "chain-b: session died before establishing" >&2
			tail -5 "$run_dir/kb-session.out" >&2 || true
			exit 1
		fi
		sleep 0.5
	done
	[[ -n $kb_line ]] || { echo "chain-b: session never answered" >&2; exit 1; }
	kb_port=$(cut -d'|' -f3 <<<"$kb_line")
	if [[ $kb_port != "$TIDB_PORT_0" ]]; then
		echo "chain-b: session landed on @@port=$kb_port, expected the pinned $TIDB_PORT_0" >&2
		exit 1
	fi
	# Capture the proxy-side connection id + backend id from Rust's own
	# connection_ready record for this new session.
	kb_conn_id= kb_backend_id= kb_backend_addr=
	for _ in {1..20}; do
		kb_ready=$(tail -n "+$((kb_rust_offset + 1))" "$run_dir/tiproxy-rs-ka.log" |
			grep '"event":"connection_ready"' | tail -1 || true)
		if [[ -n $kb_ready ]]; then
			kb_conn_id=$(sed -n 's/.*"connection_id":\([0-9]*\).*/\1/p' <<<"$kb_ready")
			kb_backend_id=$(sed -n 's/.*"backend_id":"\([^"]*\)".*/\1/p' <<<"$kb_ready")
			kb_backend_addr=$(sed -n 's/.*"backend_addr":"\([^"]*\)".*/\1/p' <<<"$kb_ready")
		fi
		[[ -n $kb_conn_id && -n $kb_backend_id && -n $kb_backend_addr ]] && break
		sleep 0.5
	done
	if [[ -z $kb_conn_id || -z $kb_backend_id || -z $kb_backend_addr ]]; then
		echo "chain-b: could not capture connection_ready identity" >&2
		exit 1
	fi
	if [[ $kb_backend_addr != "$ka_pinned_addr" || $kb_backend_id != *"$ka_pinned_addr" ]]; then
		echo "chain-b: session backend $kb_backend_id/$kb_backend_addr is not the pinned $ka_pinned_addr" >&2
		exit 1
	fi
	echo "chain-b: new session proxy_conn_id=$kb_conn_id backend_id=$kb_backend_id addr=$kb_backend_addr port=$kb_port"
	# The new session must raise the pinned backend's gauge by EXACTLY one
	# (its RouteResult{connected} is forwarded normally and counted).
	kb_open=$kb_before
	for _ in {1..40}; do
		kb_open=$(ka_backend_conn "$ka_pinned_addr")
		((kb_open == kb_before + 1)) && break
		sleep 0.25
	done
	if ((kb_open != kb_before + 1)); then
		echo "chain-b: opening the session did not raise accounting from $kb_before to $((kb_before + 1)) (got $kb_open)" >&2
		exit 1
	fi
	echo "chain-b: pinned backend $ka_pinned_addr before=$kb_before open=$kb_open (exactly +1)"
	# Arm the exact CLOSED drop for THIS connection on THIS backend.
	curl --noproxy '*' --fail --silent --show-error -X POST \
		--data-binary "{\"kind\":\"connection-event-closed\",\"connection_id\":$kb_conn_id,\"backend_id\":\"$kb_backend_id\"}" \
		"http://127.0.0.1:$ka_drop_admin_port/arm" -o /dev/null
	# Close the client: Rust emits ConnectionEvent{CLOSED}, the dropper
	# swallows it and (pause-after-drop) tears + holds the control link.
	exec 8>&-
	for _ in {1..40}; do
		kill -0 "$KB_SESSION_PID" 2>/dev/null || break
		sleep 0.25
	done
	kill "$KB_SESSION_PID" 2>/dev/null || true
	wait "$KB_SESSION_PID" 2>/dev/null || true
	# The session is gone: retract its now-stale PID so the final cleanup
	# never signals a possibly-reused PID without ownership.
	printf 'KB_SESSION_PID=\n' >>"$run_dir/state.env"
	kb_dropped=false
	for _ in {1..40}; do
		if [[ $(ka_drop_state | python3 -c 'import json,sys; print(json.load(sys.stdin).get("drop_count"))' 2>/dev/null) == 1 ]]; then
			kb_dropped=true
			break
		fi
		sleep 0.25
	done
	if [[ $kb_dropped != true ]]; then
		echo "chain-b: the CLOSED frame was never dropped" >&2
		ka_drop_state >&2 || true
		exit 1
	fi
	# Oracle 1 (ghost): Go never saw the CLOSED and no reconcile has run,
	# so the accounting still holds the now-dead connection at before+1.
	kb_ghost=$(ka_backend_conn "$ka_pinned_addr")
	if ((kb_ghost != kb_before + 1)); then
		echo "chain-b: expected ghost accounting to stay $((kb_before + 1)), got $kb_ghost" >&2
		exit 1
	fi
	ka_drop_state >"$run_dir/controldropper-state-chainb-ghost.json"
	if ! python3 - "$run_dir/controldropper-state-chainb-ghost.json" "$kb_conn_id" "$kb_backend_id" <<'PYB'
import json, sys
s = json.load(open(sys.argv[1]))
conn_id, backend_id = int(sys.argv[2]), sys.argv[3]
errs = []
if s.get("drop_count") != 1:
    errs.append(f'drop_count={s.get("drop_count")}')
dropped = s.get("dropped") or []
if len(dropped) != 1:
    errs.append(f'len(dropped)={len(dropped)}')
else:
    d = dropped[0]
    if d.get("kind") != "connection-event-closed":
        errs.append(f'kind={d.get("kind")}')
    if d.get("connection_id") != conn_id:
        errs.append(f'conn_id={d.get("connection_id")}!={conn_id}')
    if d.get("backend_id") != backend_id:
        errs.append(f'backend_id={d.get("backend_id")!r}!={backend_id!r}')
    if d.get("assignment_id"):
        errs.append(f'unexpected assignment_id={d.get("assignment_id")!r}')
if s.get("held") is not True:
    errs.append(f'held={s.get("held")}')
if errs:
    print("chain-b ghost-state oracle failed: " + "; ".join(errs), file=sys.stderr)
    sys.exit(1)
print(f'chain-b ghost: drop_count=1 conn={conn_id} backend={backend_id} held=true')
PYB
	then
		echo "chain-b: dropper ghost-state oracle failed" >&2
		exit 1
	fi
	echo "chain-b ghost: backend $ka_pinned_addr still shows $kb_ghost (CLOSED lost, no reconcile yet)"
	# Release the hold: the next Rust reconnect dials upstream again and,
	# on the fresh Connected session, automatically sends a ReconcileRequest
	# whose inventory omits the dead connection, so Go clears the ghost to
	# EXACTLY the pre-open count.
	curl --noproxy '*' --fail --silent --show-error -X POST \
		"http://127.0.0.1:$ka_drop_admin_port/release" -o /dev/null
	kb_reconciled=false
	kb_now=$kb_ghost
	for _ in {1..60}; do
		kb_now=$(ka_backend_conn "$ka_pinned_addr")
		if ((kb_now < 0)); then
			echo "chain-b: accounting went negative ($kb_now)" >&2
			exit 1
		fi
		if ((kb_now == kb_before)); then
			kb_reconciled=true
			break
		fi
		sleep 0.5
	done
	if [[ $kb_reconciled != true ]]; then
		echo "chain-b: reconcile never cleared the ghost to the pre-open $kb_before (last $kb_now)" >&2
		exit 1
	fi
	ka_drop_state >"$run_dir/controldropper-state-chainb-reconciled.json"
	# Causal proof: the clear followed a real upstream reconnect
	# (release -> dialing-upstream connect), not some other clearing path.
	if ! python3 - "$run_dir/controldropper-state-chainb-ghost.json" "$run_dir/controldropper-state-chainb-reconciled.json" <<'PYR'
import json, sys
ghost = json.load(open(sys.argv[1]))
rec = json.load(open(sys.argv[2]))
errs = []
if rec.get("held") is not False:
    errs.append(f'held={rec.get("held")}')
if rec.get("release_count") != 1:
    errs.append(f'release_count={rec.get("release_count")} (want 1)')
if not (rec.get("connect_count", 0) > ghost.get("connect_count", 0)):
    errs.append(f'connect_count {rec.get("connect_count")} !> ghost {ghost.get("connect_count")}')
if not (rec.get("reconnect_count", 0) > ghost.get("reconnect_count", 0)):
    errs.append(f'reconnect_count {rec.get("reconnect_count")} !> ghost {ghost.get("reconnect_count")}')
events = rec.get("events") or []
drop_seq = max((e["seq"] for e in events if e.get("type") == "drop"), default=None)
if drop_seq is None:
    errs.append('no drop event')
else:
    rel = next((e for e in events if e.get("type") == "release" and e["seq"] > drop_seq), None)
    if rel is None:
        errs.append('no release after the drop')
    else:
        dial = next((e for e in events if e.get("type") == "connect"
                     and "dialing upstream" in (e.get("detail") or "") and e["seq"] > rel["seq"]), None)
        if dial is None:
            errs.append('no dialing-upstream connect after the release')
if errs:
    print("chain-b reconnect-causality oracle failed: " + "; ".join(errs), file=sys.stderr)
    sys.exit(1)
print(f'chain-b reconnect: held=false release_count=1 '
      f'connect {ghost.get("connect_count")}->{rec.get("connect_count")} '
      f'reconnect {ghost.get("reconnect_count")}->{rec.get("reconnect_count")}; '
      f'drop->release->dialing-upstream ordered')
PYR
	then
		echo "chain-b: reconnect-causality oracle failed" >&2
		exit 1
	fi
	echo "chain-b: reconcile cleared the ghost -> backend $ka_pinned_addr now $kb_now (exactly the pre-open $kb_before)"
	rm -f "$KB_FIFO"
	# The FIFO is gone: retract its path so the final cleanup treats it as
	# already handled.
	printf 'KB_FIFO=\n' >>"$run_dir/state.env"
	echo "control-frame-drop-closed: a lost ConnectionEvent{CLOSED} left a ghost; a real reconnect's reconcile cleared it exactly"
fi
if [[ $ka_use_dropper == true && ${DATAPLANE_LEGACY_ROUTE_CHAOS:-0} == 1 ]]; then
	# ---- CTL-06 chaos chain (a): a dropped RouteResult{connected=true}
	# leaves the new connection LIVE but uncounted on Go's side, so its
	# per-backend accounting is short by one. The automatic reconcile on
	# the next control reconnect completes the lost assignment, restoring
	# the count to EXACTLY +1 (never double-counted). The dropper's
	# drop/release counters accumulate across chains, so every assertion
	# here is a DELTA from a baseline captured at chain (a)'s start.
	ca_before=$(ka_backend_conn "$ka_pinned_addr")
	ca_drop_base=$(ka_drop_state | python3 -c 'import json,sys; print(json.load(sys.stdin).get("drop_count",0))')
	ca_release_base=$(ka_drop_state | python3 -c 'import json,sys; print(json.load(sys.stdin).get("release_count",0))')
	# Predict the next proxy connection id: ids are allocated sequentially
	# within a Rust lineage and nothing else opens a client connection in
	# this quiesced window, so the next new session is (max seen)+1. The
	# connection_ready and the drop record are both asserted to equal it,
	# so a mispredict fails closed (the frame is never dropped) rather than
	# passing.
	ca_max=$(grep -s '"event":"connection_ready"' "$run_dir/tiproxy-rs-ka.log" |
		sed -n 's/.*"connection_id":\([0-9]*\).*/\1/p' | sort -n | tail -1)
	[[ -n $ca_max ]] || ca_max=0
	ca_target=$((ca_max + 1))
	# Arm the exact RouteResult{connected} drop for the predicted
	# connection. assignment_id is unobservable before the frame is sent;
	# connection_id alone is exact within the lineage (the reviewed
	# option-1 selector).
	curl --noproxy '*' --fail --silent --show-error -X POST \
		--data-binary "{\"kind\":\"route-result-connected\",\"connection_id\":$ca_target}" \
		"http://127.0.0.1:$ka_drop_admin_port/arm" -o /dev/null
	CA_FIFO="$run_dir/ca-session.fifo"
	mkfifo "$CA_FIFO"
	printf 'CA_FIFO=%q\n' "$CA_FIFO" >>"$run_dir/state.env"
	ca_rust_offset=$(wc -l <"$run_dir/tiproxy-rs-ka.log" | tr -d ' ')
	mysql --batch --skip-column-names --force --unbuffered \
		-h 127.0.0.1 -P "$ka_sql_port" -u root \
		"${mysql_tls_args[@]}" ${mysql_compression_arg:+"$mysql_compression_arg"} \
		<"$CA_FIFO" >"$run_dir/ca-session.out" 2>&1 &
	CA_SESSION_PID=$!
	printf 'CA_SESSION_PID=%q\n' "$CA_SESSION_PID" >>"$run_dir/state.env"
	exec 7>"$CA_FIFO"
	printf "SELECT CONCAT('CA|', CONNECTION_ID(), '|', @@port);\n" >&7
	ca_line=
	for _ in {1..40}; do
		ca_line=$(grep -s '^CA|' "$run_dir/ca-session.out" | tail -1 || true)
		[[ -n $ca_line ]] && break
		if ! kill -0 "$CA_SESSION_PID" 2>/dev/null; then
			echo "chain-a: session died before establishing" >&2
			tail -5 "$run_dir/ca-session.out" >&2 || true
			exit 1
		fi
		sleep 0.5
	done
	[[ -n $ca_line ]] || { echo "chain-a: session never answered" >&2; exit 1; }
	ca_port=$(cut -d'|' -f3 <<<"$ca_line")
	if [[ $ca_port != "$TIDB_PORT_0" ]]; then
		echo "chain-a: session landed on @@port=$ca_port, expected the pinned $TIDB_PORT_0" >&2
		exit 1
	fi
	ca_conn_id= ca_backend_addr=
	for _ in {1..20}; do
		ca_ready=$(tail -n "+$((ca_rust_offset + 1))" "$run_dir/tiproxy-rs-ka.log" |
			grep '"event":"connection_ready"' | tail -1 || true)
		if [[ -n $ca_ready ]]; then
			ca_conn_id=$(sed -n 's/.*"connection_id":\([0-9]*\).*/\1/p' <<<"$ca_ready")
			ca_backend_addr=$(sed -n 's/.*"backend_addr":"\([^"]*\)".*/\1/p' <<<"$ca_ready")
		fi
		[[ -n $ca_conn_id && -n $ca_backend_addr ]] && break
		sleep 0.5
	done
	if [[ -z $ca_conn_id || -z $ca_backend_addr ]]; then
		echo "chain-a: could not capture connection_ready identity" >&2
		exit 1
	fi
	if [[ $ca_conn_id != "$ca_target" ]]; then
		echo "chain-a: connection-id prediction missed (predicted $ca_target, got $ca_conn_id)" >&2
		exit 1
	fi
	if [[ $ca_backend_addr != "$ka_pinned_addr" ]]; then
		echo "chain-a: session backend $ca_backend_addr is not the pinned $ka_pinned_addr" >&2
		exit 1
	fi
	echo "chain-a: new session proxy_conn_id=$ca_conn_id addr=$ca_backend_addr port=$ca_port (predicted $ca_target)"
	# The RouteResult{connected} for this connection must have been dropped
	# (drop_count advances by exactly one from the chain baseline).
	ca_want_drops=$((ca_drop_base + 1))
	ca_dropped=false
	for _ in {1..40}; do
		if [[ $(ka_drop_state | python3 -c 'import json,sys; print(json.load(sys.stdin).get("drop_count",0))' 2>/dev/null) == "$ca_want_drops" ]]; then
			ca_dropped=true
			break
		fi
		sleep 0.25
	done
	if [[ $ca_dropped != true ]]; then
		echo "chain-a: the RouteResult{connected} frame was never dropped" >&2
		ka_drop_state >&2 || true
		exit 1
	fi
	# Oracle 1 (uncounted): the connect was lost, so Go's accounting stays
	# at the pre-open baseline even though the session is up.
	ca_lost=$(ka_backend_conn "$ka_pinned_addr")
	if ((ca_lost != ca_before)); then
		echo "chain-a: expected accounting to stay short at $ca_before, got $ca_lost" >&2
		exit 1
	fi
	# The session still serves a query through the (data-plane) path: it is
	# a LIVE but uncounted connection, not a dead one.
	printf "SELECT CONCAT('CA2|', CONNECTION_ID(), '|', @@port);\n" >&7
	ca_alive=false
	for _ in {1..40}; do
		if grep -qs '^CA2|' "$run_dir/ca-session.out"; then
			ca_alive=true
			break
		fi
		kill -0 "$CA_SESSION_PID" 2>/dev/null || break
		sleep 0.25
	done
	if [[ $ca_alive != true ]]; then
		echo "chain-a: the uncounted session is not serving (expected live-but-uncounted)" >&2
		exit 1
	fi
	ka_drop_state >"$run_dir/controldropper-state-chaina-lost.json"
	if ! python3 - "$run_dir/controldropper-state-chaina-lost.json" "$ca_target" "$ca_want_drops" <<'PYA'
import json, sys
s = json.load(open(sys.argv[1]))
conn_id, want_drops = int(sys.argv[2]), int(sys.argv[3])
errs = []
if s.get("drop_count") != want_drops:
    errs.append(f'drop_count={s.get("drop_count")} (want {want_drops})')
dropped = s.get("dropped") or []
if not dropped:
    errs.append('no dropped records')
else:
    d = dropped[-1]  # this chain's drop is the most recent record
    if d.get("kind") != "route-result-connected":
        errs.append(f'kind={d.get("kind")}')
    if d.get("connection_id") != conn_id:
        errs.append(f'conn_id={d.get("connection_id")}!={conn_id}')
    if not d.get("assignment_id"):
        errs.append('missing assignment_id evidence')
if s.get("held") is not True:
    errs.append(f'held={s.get("held")}')
if errs:
    print("chain-a lost-state oracle failed: " + "; ".join(errs), file=sys.stderr)
    sys.exit(1)
print(f'chain-a lost: drop conn={conn_id} assignment_id={dropped[-1].get("assignment_id")!r} held=true')
PYA
	then
		echo "chain-a: dropper lost-state oracle failed" >&2
		exit 1
	fi
	echo "chain-a lost: backend $ka_pinned_addr still shows $ca_lost (RouteResult lost, session live but uncounted)"
	# Release: the reconnect's automatic reconcile reports the live
	# connection, so Go completes the lost assignment and the gauge rises
	# to EXACTLY ca_before+1.
	curl --noproxy '*' --fail --silent --show-error -X POST \
		"http://127.0.0.1:$ka_drop_admin_port/release" -o /dev/null
	ca_want=$((ca_before + 1))
	ca_repaired=false
	ca_now=$ca_lost
	for _ in {1..60}; do
		ca_now=$(ka_backend_conn "$ka_pinned_addr")
		if ((ca_now > ca_want)); then
			echo "chain-a: accounting over-counted ($ca_now > $ca_want)" >&2
			exit 1
		fi
		if ((ca_now == ca_want)); then
			ca_repaired=true
			break
		fi
		sleep 0.5
	done
	if [[ $ca_repaired != true ]]; then
		echo "chain-a: reconcile never restored accounting to $ca_want (last $ca_now)" >&2
		exit 1
	fi
	ka_drop_state >"$run_dir/controldropper-state-chaina-repaired.json"
	if ! python3 - "$run_dir/controldropper-state-chaina-lost.json" "$run_dir/controldropper-state-chaina-repaired.json" "$ca_release_base" <<'PYAR'
import json, sys
lost = json.load(open(sys.argv[1]))
rep = json.load(open(sys.argv[2]))
release_base = int(sys.argv[3])
errs = []
if rep.get("held") is not False:
    errs.append(f'held={rep.get("held")}')
if rep.get("release_count") != release_base + 1:
    errs.append(f'release_count={rep.get("release_count")} (want {release_base + 1})')
if not (rep.get("connect_count", 0) > lost.get("connect_count", 0)):
    errs.append(f'connect_count {rep.get("connect_count")} !> lost {lost.get("connect_count")}')
if not (rep.get("reconnect_count", 0) > lost.get("reconnect_count", 0)):
    errs.append(f'reconnect_count {rep.get("reconnect_count")} !> lost {lost.get("reconnect_count")}')
events = rep.get("events") or []
drop_seq = max((e["seq"] for e in events if e.get("type") == "drop"), default=None)
if drop_seq is None:
    errs.append('no drop event')
else:
    rel = next((e for e in events if e.get("type") == "release" and e["seq"] > drop_seq), None)
    if rel is None:
        errs.append('no release after this chain drop')
    else:
        dial = next((e for e in events if e.get("type") == "connect"
                     and "dialing upstream" in (e.get("detail") or "") and e["seq"] > rel["seq"]), None)
        if dial is None:
            errs.append('no dialing-upstream connect after the release')
if errs:
    print("chain-a reconnect-causality oracle failed: " + "; ".join(errs), file=sys.stderr)
    sys.exit(1)
print(f'chain-a reconnect: held=false release_count={rep.get("release_count")} '
      f'connect {lost.get("connect_count")}->{rep.get("connect_count")} '
      f'reconnect {lost.get("reconnect_count")}->{rep.get("reconnect_count")}; '
      f'drop->release->dialing-upstream ordered')
PYAR
	then
		echo "chain-a: reconnect-causality oracle failed" >&2
		exit 1
	fi
	echo "chain-a: reconcile restored the lost connect -> backend $ka_pinned_addr now $ca_now (exactly ca_before+1 = $ca_want)"
	# Close the now-counted session cleanly and retract its lifecycle vars.
	exec 7>&-
	for _ in {1..40}; do
		kill -0 "$CA_SESSION_PID" 2>/dev/null || break
		sleep 0.25
	done
	kill "$CA_SESSION_PID" 2>/dev/null || true
	wait "$CA_SESSION_PID" 2>/dev/null || true
	printf 'CA_SESSION_PID=\n' >>"$run_dir/state.env"
	rm -f "$CA_FIFO"
	printf 'CA_FIFO=\n' >>"$run_dir/state.env"
	echo "control-frame-drop-connected: a lost RouteResult{connected} left the session uncounted; a real reconnect's reconcile restored it exactly"
fi
if [[ $ka_use_dropper == true && ${DATAPLANE_LEGACY_ROUTE_CHAOS:-0} == 1 ]]; then
	# ---- CTL-06 chaos chain (c): a one-sided Go control-plane restart.
	# The Go process is SIGKILLed (unclean crash) and restarted on the
	# same control socket + config; the Rust dataplane keeps serving its
	# established session throughout, reconnects to the NEW Go incarnation
	# through the dropper, and rehydrates. Oracles: the old session
	# survives with an unchanged identity+backend, the new incarnation
	# applies a snapshot, its per-backend accounting rehydrates to the
	# exact live count, and a fresh connection works.
	CC_FIFO="$run_dir/cc-session.fifo"
	mkfifo "$CC_FIFO"
	printf 'CC_FIFO=%q\n' "$CC_FIFO" >>"$run_dir/state.env"
	mysql --batch --skip-column-names --force --unbuffered \
		-h 127.0.0.1 -P "$ka_sql_port" -u root \
		"${mysql_tls_args[@]}" ${mysql_compression_arg:+"$mysql_compression_arg"} \
		<"$CC_FIFO" >"$run_dir/cc-session.out" 2>&1 &
	CC_SESSION_PID=$!
	printf 'CC_SESSION_PID=%q\n' "$CC_SESSION_PID" >>"$run_dir/state.env"
	exec 6>"$CC_FIFO"
	cc_query() {
		local marker=$1 sql=$2 line=
		printf '%s\n' "$sql" >&6
		for _ in {1..40}; do
			line=$(grep -s "^$marker|" "$run_dir/cc-session.out" | tail -1 || true)
			if [[ -n $line ]]; then
				printf '%s\n' "$line"
				return 0
			fi
			kill -0 "$CC_SESSION_PID" 2>/dev/null || { echo "chain-c: session died" >&2; return 1; }
			sleep 0.5
		done
		echo "chain-c: session never answered $marker" >&2
		return 1
	}
	cc_baseline=$(cc_query CC1 "SELECT CONCAT('CC1|', CONNECTION_ID(), '|', @@port);") || exit 1
	cc_conn_id=$(cut -d'|' -f2 <<<"$cc_baseline")
	cc_port=$(cut -d'|' -f3 <<<"$cc_baseline")
	if [[ $cc_port != "$TIDB_PORT_0" ]]; then
		echo "chain-c: old session landed on @@port=$cc_port, expected the pinned $TIDB_PORT_0" >&2
		exit 1
	fi
	# Clean baseline: this new session must be the ONLY live connection on
	# the pin (poll until the gauge settles to exactly 1, which also
	# confirms the previous chain fully drained). rehydrate is checked
	# against this exact value.
	cc_before=0
	cc_baseline_ready=false
	for _ in {1..60}; do
		cc_before=$(ka_backend_conn "$ka_pinned_addr")
		((cc_before == 1)) && { cc_baseline_ready=true; break; }
		sleep 0.5
	done
	if [[ $cc_baseline_ready != true ]]; then
		echo "chain-c: pinned backend did not settle to exactly the 1 old session (got $cc_before)" >&2
		exit 1
	fi
	cc_old_pid=$KA_PID
	echo "chain-c: old session CONNECTION_ID=$cc_conn_id backend=127.0.0.1:$cc_port; Go pid=$cc_old_pid; gauge=$cc_before"
	# SIGKILL the Go control plane and clear its dead control socket, then
	# restart it on the same socket + config (ownership-checked helpers).
	record_t4_process go-ka restart-stop "$cc_old_pid" 0
	sigkill_owned_process "$cc_old_pid" "tiproxy-ka.toml" ||
		{ echo "chain-c: could not SIGKILL Go $cc_old_pid" >&2; exit 1; }
	remove_dead_backend_socket "$KA_SOCKET" "$cc_old_pid" ||
		{ echo "chain-c: could not clear the dead Go control socket" >&2; exit 1; }
	"$repo_root/bin/tiproxy" --config "$run_dir/tiproxy-ka.toml" \
		>>"$run_dir/tiproxy-ka.out" 2>&1 &
	KA_PID=$!
	record_t4_process go-ka restart-start "$KA_PID" "$cc_old_pid"
	printf 'KA_PID=%q\n' "$KA_PID" >>"$run_dir/state.env"
	if [[ $KA_PID == "$cc_old_pid" ]]; then
		echo "chain-c: restarted Go reused pid $KA_PID (cannot distinguish incarnations)" >&2
		exit 1
	fi
	echo "chain-c: Go restarted pid $cc_old_pid -> $KA_PID"
	if ! ka_wait_go_control_up "$KA_PID"; then
		echo "chain-c: restarted Go control plane never came up" >&2
		tail -20 "$run_dir/tiproxy-ka.out" >&2 || true
		exit 1
	fi
	# The dataplane must re-sync with the NEW incarnation: it applies a
	# snapshot from the fresh generation sequence.
	cc_synced=false
	cc_applied=0
	for _ in {1..100}; do
		cc_applied=$(curl --noproxy '*' --fail --silent --max-time 5 \
			"http://127.0.0.1:$ka_api_port/api/dataplane/status" 2>/dev/null |
			python3 -c 'import json,sys; print(json.load(sys.stdin).get("applied_generation",0))' 2>/dev/null || echo 0)
		if [[ ${cc_applied:-0} =~ ^[0-9]+$ ]] && ((cc_applied > 0)); then
			cc_synced=true
			break
		fi
		sleep 0.2
	done
	if [[ $cc_synced != true ]]; then
		echo "chain-c: dataplane never re-synced with the restarted Go (applied_generation stayed 0)" >&2
		exit 1
	fi
	echo "chain-c: dataplane re-synced with the new Go incarnation (applied_generation=$cc_applied)"
	# Oracle: the OLD session survived with an unchanged identity+backend.
	cc_check=$(cc_query CC2 "SELECT CONCAT('CC2|', CONNECTION_ID(), '|', @@port);") || exit 1
	cc_conn_id2=$(cut -d'|' -f2 <<<"$cc_check")
	cc_port2=$(cut -d'|' -f3 <<<"$cc_check")
	if [[ $cc_conn_id2 != "$cc_conn_id" || $cc_port2 != "$cc_port" ]]; then
		echo "chain-c: old session changed across the restart: $cc_check (baseline $cc_baseline)" >&2
		exit 1
	fi
	echo "chain-c: old session intact across Go restart: CONNECTION_ID=$cc_conn_id2 backend=127.0.0.1:$cc_port2"
	# Oracle: the new Go rehydrated its per-backend accounting to EXACTLY
	# the live count (the surviving session), never over.
	cc_rehydrated=false
	cc_now=0
	for _ in {1..60}; do
		cc_now=$(ka_backend_conn "$ka_pinned_addr")
		if ((cc_now > cc_before)); then
			echo "chain-c: rehydrated accounting over-counted ($cc_now > $cc_before)" >&2
			exit 1
		fi
		if ((cc_now == cc_before)); then
			cc_rehydrated=true
			break
		fi
		sleep 0.5
	done
	if [[ $cc_rehydrated != true ]]; then
		echo "chain-c: new Go never rehydrated accounting to $cc_before (last $cc_now)" >&2
		exit 1
	fi
	echo "chain-c: new Go rehydrated accounting -> backend $ka_pinned_addr now $cc_now (exact live count)"
	# Oracle: a fresh connection through the restarted control plane works.
	cc_new_port=$(mysql_ka_root 'SELECT @@port' 2>/dev/null || true)
	if [[ $cc_new_port != "$TIDB_PORT_0" ]]; then
		echo "chain-c: a new connection after restart landed on '$cc_new_port', expected $TIDB_PORT_0" >&2
		exit 1
	fi
	echo "chain-c: new connection after restart served by 127.0.0.1:$cc_new_port"
	exec 6>&-
	for _ in {1..40}; do kill -0 "$CC_SESSION_PID" 2>/dev/null || break; sleep 0.25; done
	kill "$CC_SESSION_PID" 2>/dev/null || true
	wait "$CC_SESSION_PID" 2>/dev/null || true
	printf 'CC_SESSION_PID=\n' >>"$run_dir/state.env"
	rm -f "$CC_FIFO"
	printf 'CC_FIFO=\n' >>"$run_dir/state.env"
	echo "go-one-sided-restart: the Go control plane crashed and restarted; the Rust session survived and the new incarnation rehydrated exactly"
fi
if [[ $ka_use_dropper == true && ${DATAPLANE_LEGACY_ROUTE_CHAOS:-0} == 1 ]]; then
	# ---- CTL-06 chaos chain (d): a one-sided Rust dataplane restart. The
	# Rust process is SIGKILLed; its client session dies WITHOUT a CLOSED,
	# so Go keeps it as a ghost. A fresh Rust process reconnects with an
	# EMPTY inventory, and Go's reconcile omission zeroes that ghost; a new
	# session then works and is counted under the new incarnation. Oracles:
	# the dead session's accounting is zeroed to exactly 0, a fresh session
	# is served + counted, and its connection_ready carries a generation
	# (the new session applied a snapshot).
	# Quiesced baseline: the pin must be exactly 0 (the previous chain fully
	# drained) so the session we open is the only thing that can move it,
	# and the ghost we later observe is unambiguously this session's.
	cd_quiesced=false
	cd_base=1
	for _ in {1..60}; do
		cd_base=$(ka_backend_conn "$ka_pinned_addr")
		((cd_base == 0)) && { cd_quiesced=true; break; }
		sleep 0.5
	done
	if [[ $cd_quiesced != true ]]; then
		echo "chain-d: pinned backend never quiesced to 0 before the chain (got $cd_base)" >&2
		exit 1
	fi
	cd_rust_offset=$(wc -l <"$run_dir/tiproxy-rs-ka.log" | tr -d ' ')
	CD_FIFO="$run_dir/cd-session.fifo"
	mkfifo "$CD_FIFO"
	printf 'CD_FIFO=%q\n' "$CD_FIFO" >>"$run_dir/state.env"
	mysql --batch --skip-column-names --force --unbuffered \
		-h 127.0.0.1 -P "$ka_sql_port" -u root \
		"${mysql_tls_args[@]}" ${mysql_compression_arg:+"$mysql_compression_arg"} \
		<"$CD_FIFO" >"$run_dir/cd-session.out" 2>&1 &
	CD_SESSION_PID=$!
	printf 'CD_SESSION_PID=%q\n' "$CD_SESSION_PID" >>"$run_dir/state.env"
	exec 5>"$CD_FIFO"
	printf "SELECT CONCAT('CD|', CONNECTION_ID(), '|', @@port);\n" >&5
	cd_line=
	for _ in {1..40}; do
		cd_line=$(grep -s '^CD|' "$run_dir/cd-session.out" | tail -1 || true)
		[[ -n $cd_line ]] && break
		kill -0 "$CD_SESSION_PID" 2>/dev/null || { echo "chain-d: session died before establishing" >&2; exit 1; }
		sleep 0.5
	done
	[[ -n $cd_line ]] || { echo "chain-d: session never answered" >&2; exit 1; }
	cd_port=$(cut -d'|' -f3 <<<"$cd_line")
	if [[ $cd_port != "$TIDB_PORT_0" ]]; then
		echo "chain-d: session landed on @@port=$cd_port, expected the pinned $TIDB_PORT_0" >&2
		exit 1
	fi
	# Bind the session to A0 via its own fresh connection_ready and require a
	# positive applied generation (a real snapshot, not a zero field).
	cd_gen= cd_backend_addr=
	for _ in {1..20}; do
		cd_ready=$(tail -n "+$((cd_rust_offset + 1))" "$run_dir/tiproxy-rs-ka.log" |
			grep '"event":"connection_ready"' | tail -1 || true)
		if [[ -n $cd_ready ]]; then
			cd_backend_addr=$(sed -n 's/.*"backend_addr":"\([^"]*\)".*/\1/p' <<<"$cd_ready")
			cd_gen=$(sed -n 's/.*"generation":\([0-9]*\).*/\1/p' <<<"$cd_ready")
		fi
		[[ -n $cd_backend_addr && -n $cd_gen ]] && break
		sleep 0.5
	done
	if [[ $cd_backend_addr != "$ka_pinned_addr" ]]; then
		echo "chain-d: session backend $cd_backend_addr is not the pinned $ka_pinned_addr" >&2
		exit 1
	fi
	if [[ ! $cd_gen =~ ^[1-9][0-9]*$ ]]; then
		echo "chain-d: session connection_ready generation '$cd_gen' is not a positive integer" >&2
		exit 1
	fi
	# Confirm the session raised the pin from the quiesced 0 to EXACTLY 1.
	cd_before_ready=false
	cd_before=0
	for _ in {1..60}; do
		cd_before=$(ka_backend_conn "$ka_pinned_addr")
		((cd_before > 1)) && { echo "chain-d: pin over-counted to $cd_before opening the session" >&2; exit 1; }
		((cd_before == 1)) && { cd_before_ready=true; break; }
		sleep 0.5
	done
	if [[ $cd_before_ready != true ]]; then
		echo "chain-d: opening the session did not raise the pin from 0 to exactly 1 (got $cd_before)" >&2
		exit 1
	fi
	cd_old_rust=$KA_RUST_PID
	echo "chain-d: live session backend=127.0.0.1:$cd_port generation=$cd_gen; Rust pid=$cd_old_rust; gauge 0 -> $cd_before"
	# SIGKILL the Rust dataplane; its client session dies without a CLOSED.
	record_t4_process rust-ka restart-stop "$cd_old_rust" 0
	sigkill_owned_process "$cd_old_rust" "$ka_rust_control_socket" ||
		{ echo "chain-d: could not SIGKILL Rust $cd_old_rust" >&2; exit 1; }
	exec 5>&-
	kill "$CD_SESSION_PID" 2>/dev/null || true
	wait "$CD_SESSION_PID" 2>/dev/null || true
	printf 'CD_SESSION_PID=\n' >>"$run_dir/state.env"
	# Ghost window: with the old Rust dead and no CLOSED sent, Go must still
	# hold the session — assert the pin is STILL exactly 1 BEFORE any
	# successor starts, so the later zeroing is attributable solely to the
	# successor Rust control session's empty reconcile (not a delayed CLOSED
	# or the control disconnect).
	cd_ghost=$(ka_backend_conn "$ka_pinned_addr")
	if ((cd_ghost != 1)); then
		echo "chain-d: dead session did not persist as a ghost at 1 before restart (got $cd_ghost)" >&2
		exit 1
	fi
	echo "chain-d: dead session persists as a ghost (gauge=$cd_ghost) before the successor starts"
	# Restart Rust on the same control socket (the dropper front) + health
	# port; it reconnects with an empty inventory.
	"$rust_binary" --config "$run_dir/tiproxy-ka.toml" \
		--control-socket "$ka_rust_control_socket" --control-uid "$(id -u)" \
		--health-port "$ka_health_port" \
		${ka_rust_tls_args[@]+"${ka_rust_tls_args[@]}"} \
		>>"$run_dir/tiproxy-rs-ka.log" 2>&1 &
	KA_RUST_PID=$!
	record_t4_process rust-ka restart-start "$KA_RUST_PID" "$cd_old_rust"
	printf 'KA_RUST_PID=%q\n' "$KA_RUST_PID" >>"$run_dir/state.env"
	if [[ $KA_RUST_PID == "$cd_old_rust" ]]; then
		echo "chain-d: restarted Rust reused pid $KA_RUST_PID" >&2
		exit 1
	fi
	echo "chain-d: Rust restarted pid $cd_old_rust -> $KA_RUST_PID"
	cd_ready=false
	for _ in {1..150}; do
		if ! kill -0 "$KA_RUST_PID" 2>/dev/null; then break; fi
		if curl --noproxy '*' --fail --silent --max-time 5 \
			"http://127.0.0.1:$ka_health_port/" -o /dev/null; then
			cd_ready=true
			break
		fi
		sleep 0.2
	done
	if [[ $cd_ready != true ]]; then
		echo "chain-d: restarted Rust never became ready" >&2
		tail -20 "$run_dir/tiproxy-rs-ka.log" >&2 || true
		exit 1
	fi
	# Oracle: the dead session's ghost is zeroed by the new session's
	# reconcile (empty inventory -> Go omission-closes the ghost).
	cd_zeroed=false
	cd_now=$cd_before
	for _ in {1..60}; do
		cd_now=$(ka_backend_conn "$ka_pinned_addr")
		if ((cd_now == 0)); then
			cd_zeroed=true
			break
		fi
		sleep 0.5
	done
	if [[ $cd_zeroed != true ]]; then
		echo "chain-d: the dead session's ghost was never zeroed (gauge stuck at $cd_now)" >&2
		exit 1
	fi
	echo "chain-d: dead session ghost zeroed -> backend $ka_pinned_addr now $cd_now"
	# Oracle: a fresh session under the new incarnation works, lands on the
	# pin, IS counted (gauge -> 1), and its connection_ready carries a
	# generation (a snapshot was applied under the new session).
	CD2_FIFO="$run_dir/cd2-session.fifo"
	mkfifo "$CD2_FIFO"
	printf 'CD2_FIFO=%q\n' "$CD2_FIFO" >>"$run_dir/state.env"
	cd2_offset=$(wc -l <"$run_dir/tiproxy-rs-ka.log" | tr -d ' ')
	mysql --batch --skip-column-names --force --unbuffered \
		-h 127.0.0.1 -P "$ka_sql_port" -u root \
		"${mysql_tls_args[@]}" ${mysql_compression_arg:+"$mysql_compression_arg"} \
		<"$CD2_FIFO" >"$run_dir/cd2-session.out" 2>&1 &
	CD2_SESSION_PID=$!
	printf 'CD2_SESSION_PID=%q\n' "$CD2_SESSION_PID" >>"$run_dir/state.env"
	exec 4>"$CD2_FIFO"
	printf "SELECT CONCAT('CD2|', CONNECTION_ID(), '|', @@port);\n" >&4
	cd2_line=
	for _ in {1..40}; do
		cd2_line=$(grep -s '^CD2|' "$run_dir/cd2-session.out" | tail -1 || true)
		[[ -n $cd2_line ]] && break
		kill -0 "$CD2_SESSION_PID" 2>/dev/null || { echo "chain-d: new session died before establishing" >&2; exit 1; }
		sleep 0.5
	done
	[[ -n $cd2_line ]] || { echo "chain-d: new session never answered" >&2; exit 1; }
	cd2_port=$(cut -d'|' -f3 <<<"$cd2_line")
	if [[ $cd2_port != "$TIDB_PORT_0" ]]; then
		echo "chain-d: new session landed on @@port=$cd2_port, expected the pinned $TIDB_PORT_0" >&2
		exit 1
	fi
	cd2_counted=false
	cd2_now=0
	for _ in {1..60}; do
		cd2_now=$(ka_backend_conn "$ka_pinned_addr")
		if ((cd2_now == 1)); then
			cd2_counted=true
			break
		fi
		if ((cd2_now > 1)); then
			echo "chain-d: new session over-counted (gauge $cd2_now > 1)" >&2
			exit 1
		fi
		sleep 0.5
	done
	if [[ $cd2_counted != true ]]; then
		echo "chain-d: the new session was not counted to 1 (last $cd2_now)" >&2
		exit 1
	fi
	cd2_gen=
	for _ in {1..20}; do
		cd2_gen=$(tail -n "+$((cd2_offset + 1))" "$run_dir/tiproxy-rs-ka.log" |
			grep '"event":"connection_ready"' | tail -1 |
			sed -n 's/.*"generation":\([0-9]*\).*/\1/p')
		[[ -n $cd2_gen ]] && break
		sleep 0.25
	done
	if [[ ! $cd2_gen =~ ^[1-9][0-9]*$ ]]; then
		echo "chain-d: the new session connection_ready generation '$cd2_gen' is not a positive integer" >&2
		exit 1
	fi
	echo "chain-d: new session counted -> backend $ka_pinned_addr now $cd2_now, connection_ready generation=$cd2_gen"
	exec 4>&-
	for _ in {1..40}; do kill -0 "$CD2_SESSION_PID" 2>/dev/null || break; sleep 0.25; done
	kill "$CD2_SESSION_PID" 2>/dev/null || true
	wait "$CD2_SESSION_PID" 2>/dev/null || true
	printf 'CD2_SESSION_PID=\n' >>"$run_dir/state.env"
	rm -f "$CD_FIFO" "$CD2_FIFO"
	printf 'CD_FIFO=\nCD2_FIFO=\n' >>"$run_dir/state.env"
	echo "rust-one-sided-restart: the Rust dataplane crashed; its dead session's ghost was zeroed by the new session's reconcile and a new counted session works"
fi
if [[ $mode == rust && ${DATAPLANE_T4_QUALIFICATION:-0} == 1 && $ka_use_dropper == true ]]; then
	run_t4_m9_probe() {
		[[ ${DATAPLANE_T4_ROW:-} == M9 ]] || return 0
		local m9_disconnect_started m9_disconnect_seconds
		local m9_pre_status="$run_dir/t4-m9-drain-pre-status.json"
		local m9_post_status="$run_dir/t4-m9-drain-post-status.json"
		local m9_tap_state="$run_dir/t4-m9-route-audit.json"
		local m9_old m9_line m9_conn m9_port m9_proxy

		m9_wait_go() {
			local ready=false
			for _ in {1..150}; do
				# Under RUST_API_OWNER the Go process serves no HTTP; its
				# readiness is the control socket.
				if kill -0 "$KA_PID" 2>/dev/null && [[ -S $KA_SOCKET ]]; then
					ready=true
					break
				fi
				sleep 0.2
			done
			if [[ $ready != true ]]; then
				echo "M9 Go control plane did not become ready" >&2
				tail -20 "$run_dir/tiproxy-ka.out" >&2 || true
				exit 1
			fi
		}
		m9_stop_go() {
			local phase=$1
			m9_old=$KA_PID
			record_t4_process go-ka "$phase-stop" "$m9_old" 0
			sigkill_owned_process "$m9_old" "tiproxy-ka.toml" || exit 1
			wait "$m9_old" 2>/dev/null || true
			remove_dead_backend_socket "$KA_SOCKET" "$m9_old" || exit 1
		}
		m9_start_go() {
			local phase=$1 predecessor=$2
			"$repo_root/bin/tiproxy" --config "$run_dir/tiproxy-ka.toml" \
				>>"$run_dir/tiproxy-ka.out" 2>&1 &
			KA_PID=$!
			record_t4_process go-ka "$phase-start" "$KA_PID" "$predecessor"
			printf 'KA_PID=%q\n' "$KA_PID" >>"$run_dir/state.env"
			m9_wait_go
		}
		m9_stop_tap() {
			local phase=$1 old=$KA_DROP_PID
			record_t4_process control-tap-ka "$phase-stop" "$old" 0
			kill -s INT "$old" 2>/dev/null || true
			for _ in {1..100}; do
				kill -0 "$old" 2>/dev/null || break
				sleep 0.1
			done
			if kill -0 "$old" 2>/dev/null; then
				echo "M9 control tap did not stop" >&2
				exit 1
			fi
			wait "$old" 2>/dev/null || true
			rm -f "$KA_DROP_SOCKET"
		}
		m9_start_tap() {
			local phase=$1 predecessor=$2 ready=false
			"$run_dir/controldropper" \
				--front-socket "$KA_DROP_SOCKET" \
				--target-socket "$KA_SOCKET" \
				--admin "127.0.0.1:$ka_drop_admin_port" \
				--pause-after-drop \
				>>"$run_dir/controldropper.log" 2>&1 &
			KA_DROP_PID=$!
			record_t4_process control-tap-ka "$phase-start" "$KA_DROP_PID" "$predecessor"
			printf 'KA_DROP_PID=%q\n' "$KA_DROP_PID" >>"$run_dir/state.env"
			for _ in {1..100}; do
				if kill -0 "$KA_DROP_PID" 2>/dev/null && [[ -S $KA_DROP_SOCKET ]] &&
					curl --noproxy '*' --fail --silent --max-time 5 \
						"http://127.0.0.1:$ka_drop_admin_port/state" -o /dev/null; then
					ready=true
					break
				fi
				sleep 0.1
			done
			if [[ $ready != true ]]; then
				echo "M9 control tap did not become ready" >&2
				exit 1
			fi
		}
		m9_wait_rust() {
			local evidence=$1 ready=false
			for _ in {1..150}; do
				if kill -0 "$KA_RUST_PID" 2>/dev/null &&
					curl --noproxy '*' --fail --silent --max-time 5 \
						"http://127.0.0.1:$ka_health_port/health" -o "$evidence"; then
					ready=true
					break
				fi
				sleep 0.2
			done
			if [[ $ready != true ]]; then
				echo "M9 Rust dataplane did not become ready" >&2
				tail -20 "$run_dir/tiproxy-rs-ka.log" >&2 || true
				exit 1
			fi
		}
		m9_stop_rust() {
			local phase=$1
			m9_old=$KA_RUST_PID
			record_t4_process rust-ka "$phase-stop" "$m9_old" 0
			sigkill_owned_process "$m9_old" "$ka_rust_control_socket" || exit 1
			wait "$m9_old" 2>/dev/null || true
		}
		m9_start_rust() {
			local phase=$1 predecessor=$2
			"$rust_binary" --config "$run_dir/tiproxy-ka.toml" \
				--control-socket "$ka_rust_control_socket" --control-uid "$(id -u)" \
				--health-port "$ka_health_port" \
				${ka_rust_tls_args[@]+"${ka_rust_tls_args[@]}"} \
				>>"$run_dir/tiproxy-rs-ka.log" 2>&1 &
			KA_RUST_PID=$!
			record_t4_process rust-ka "$phase-start" "$KA_RUST_PID" "$predecessor"
			printf 'KA_RUST_PID=%q\n' "$KA_RUST_PID" >>"$run_dir/state.env"
			m9_wait_rust "$run_dir/t4-m9-health-$phase.json"
		}
		m9_assert_zero_ledger() {
			local label=$1
			local evidence="$run_dir/t4-m9-ledger-$label.json"
			for _ in {1..100}; do
				if curl --noproxy '*' --fail --silent --max-time 5 \
					"http://127.0.0.1:$ka_health_port/health" -o "$evidence" &&
					python3 - "$evidence" <<'PYM9LEDGER'
import json
import pathlib
import sys

ledger = json.loads(pathlib.Path(sys.argv[1]).read_text()).get("route_ledger", {})
keys = ("sessions", "reserved", "active", "incoming", "outgoing",
        "unsettled_redirects", "unsettled_closes")
raise SystemExit(0 if ledger.get("router_incarnations", 0) >= 1 and
                 all(ledger.get(key) == 0 for key in keys) else 1)
PYM9LEDGER
				then
					return 0
				fi
				sleep 0.1
			done
			echo "M9 route ledger did not settle to zero at $label" >&2
			cat "$evidence" >&2 2>/dev/null || true
			exit 1
		}
		m9_wait_tap_watermark() {
			local minimum=$1 evidence=$2
			for _ in {1..100}; do
				if curl --noproxy '*' --fail --silent --max-time 5 \
					"http://127.0.0.1:$ka_drop_admin_port/state" -o "$evidence" &&
					python3 - "$evidence" "$minimum" <<'PYM9WATERMARK'
import json
import pathlib
import sys

audit = json.loads(pathlib.Path(sys.argv[1]).read_text()).get("route_audit", {})
raise SystemExit(0 if audit.get("max_reconcile_request_drain_sequence", 0) >= int(sys.argv[2]) else 1)
PYM9WATERMARK
				then
					return 0
				fi
				sleep 0.1
			done
			echo "M9 reconcile did not restore drain watermark $minimum" >&2
			cat "$evidence" >&2 2>/dev/null || true
			exit 1
		}
		m9_wait_health_watermark() {
			# The Rust readiness probe reports the gate's drain watermark: the
			# sequence a Rust-admin drain consumed, and the value the next
			# reconcile carries to Go.
			local expected=$1 evidence=$2 observed=
			for _ in {1..100}; do
				if curl --noproxy '*' --fail --silent --max-time 5 \
					"http://127.0.0.1:$ka_health_port/health" -o "$evidence"; then
					observed=$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1])).get("drain_watermark", -1))' "$evidence")
					[[ $observed == "$expected" ]] && return 0
				fi
				sleep 0.1
			done
			echo "M9 Rust drain watermark is ${observed:-<none>}, want exactly $expected" >&2
			cat "$evidence" >&2 2>/dev/null || true
			exit 1
		}
		m9_wait_drain() {
			local drain_id=$1 evidence=$2 expected=$3
			for _ in {1..100}; do
				if curl --noproxy '*' --fail --silent --max-time 5 \
					"http://127.0.0.1:$ka_admin_port/api/dataplane/drain/$drain_id" \
					-o "$evidence" &&
					python3 - "$evidence" "$expected" <<'PYM9DRAIN'
import json
import pathlib
import sys

state = json.loads(pathlib.Path(sys.argv[1]).read_text())
expected = int(sys.argv[2])
closed = state.get("gracefully_closed", 0) + state.get("force_closed", 0)
raise SystemExit(0 if state.get("complete") is True and
                 state.get("active_connections") == expected and
                 closed == expected else 1)
PYM9DRAIN
				then
					return 0
				fi
				sleep 0.1
			done
			echo "M9 drain $drain_id did not complete with exactly $expected closes" >&2
			cat "$evidence" >&2 2>/dev/null || true
			exit 1
		}
		m9_wait_fresh_port() {
			local expected=$1 label=$2 observed=
			for _ in {1..80}; do
				observed=$(mysql_ka_root 'SELECT @@port' 2>/dev/null || true)
				if [[ $observed == "$expected" ]]; then
					return 0
				fi
				sleep 0.25
			done
			echo "M9 fresh admission at $label landed on '$observed', want $expected" >&2
			exit 1
		}
		m9_wait_backend_inflight() {
			local backend_port=$1 backend_conn=$2 marker=$3 observed=
			for _ in {1..80}; do
				observed=$(mysql --batch --skip-column-names --connect-timeout=2 \
					-h 127.0.0.1 -P "$backend_port" -u root --ssl-mode=DISABLED \
					-e "SELECT COUNT(*) FROM INFORMATION_SCHEMA.PROCESSLIST WHERE ID = $backend_conn AND INFO LIKE '%$marker%'" \
					2>/dev/null || true)
				if [[ $observed == 1 ]]; then
					return 0
				fi
				kill -0 "$KA_SESSION_PID" 2>/dev/null || break
				sleep 0.1
			done
			echo "M9 backend command $marker never became in-flight on $backend_port/$backend_conn" >&2
			exit 1
		}
		m9_query() {
			local marker=$1 sql=$2 line=
			printf '%s\n' "$sql" >&3
			for _ in {1..80}; do
				line=$(grep -s "^$marker|" "$run_dir/m9-session.out" | tail -1 || true)
				if [[ -n $line ]]; then
					printf '%s\n' "$line"
					return 0
				fi
				if ! kill -0 "$KA_SESSION_PID" 2>/dev/null; then
					echo "M9 session exited before $marker" >&2
					tail -8 "$run_dir/m9-session.out" >&2 || true
					return 1
				fi
				sleep 0.25
			done
			echo "M9 session never answered $marker" >&2
			return 1
		}
		m9_open_session() {
			local label=$1 marker="M9OPEN-$1" rust_offset
			M9_FIFO="$run_dir/m9-session.fifo"
			rm -f "$M9_FIFO"
			mkfifo "$M9_FIFO"
			: >"$run_dir/m9-session.out"
			rust_offset=$(wc -l <"$run_dir/tiproxy-rs-ka.log" | tr -d ' ')
			mysql --batch --skip-column-names --skip-reconnect --force --unbuffered \
				-h 127.0.0.1 -P "$ka_sql_port" -u root \
				"${mysql_tls_args[@]}" ${mysql_compression_arg:+"$mysql_compression_arg"} \
				<"$M9_FIFO" >"$run_dir/m9-session.out" 2>&1 &
			KA_SESSION_PID=$!
			printf 'KA_SESSION_PID=%q\nKA_FIFO=%q\n' "$KA_SESSION_PID" "$M9_FIFO" >>"$run_dir/state.env"
			exec 3>"$M9_FIFO"
			m9_line=$(m9_query "$marker" "SELECT CONCAT('$marker|', CONNECTION_ID(), '|', @@port);") || exit 1
			m9_conn=$(cut -d'|' -f2 <<<"$m9_line")
			m9_port=$(cut -d'|' -f3 <<<"$m9_line")
			m9_proxy=
			for _ in {1..40}; do
				m9_proxy=$(tail -n "+$((rust_offset + 1))" "$run_dir/tiproxy-rs-ka.log" |
					grep '"event":"connection_ready"' | head -1 |
					sed -n 's/.*"connection_id":\([0-9]*\).*/\1/p')
				[[ -n $m9_proxy ]] && break
				sleep 0.1
			done
			if [[ -z $m9_proxy ]]; then
				echo "M9 could not identify the $label session's Rust connection id" >&2
				exit 1
			fi
		}
		m9_close_session() {
			exec 3>&-
			for _ in {1..40}; do
				kill -0 "$KA_SESSION_PID" 2>/dev/null || break
				sleep 0.1
			done
			kill "$KA_SESSION_PID" 2>/dev/null || true
			wait "$KA_SESSION_PID" 2>/dev/null || true
			rm -f "$M9_FIFO"
			printf 'KA_SESSION_PID=\nKA_FIFO=\n' >>"$run_dir/state.env"
		}
		m9_assert_crash_terminal() {
			local marker=$1 backend_port=$2 backend_conn=$3
			exec 3>&-
			for _ in {1..80}; do
				kill -0 "$KA_SESSION_PID" 2>/dev/null || break
				sleep 0.1
			done
			if kill -0 "$KA_SESSION_PID" 2>/dev/null; then
				echo "M9 old SQL client survived $marker crash" >&2
				exit 1
			fi
			wait "$KA_SESSION_PID" 2>/dev/null || true
			if grep -Fq "$marker|0" "$run_dir/m9-session.out"; then
				echo "M9 $marker query completed instead of disconnecting" >&2
				exit 1
			fi
			local gone=false
			for _ in {1..80}; do
				if [[ $(mysql --batch --skip-column-names --connect-timeout=2 \
					-h 127.0.0.1 -P "$backend_port" -u root --ssl-mode=DISABLED \
					-e "SELECT COUNT(*) FROM INFORMATION_SCHEMA.PROCESSLIST WHERE ID = $backend_conn" 2>/dev/null || true) == 0 ]]; then
					gone=true
					break
				fi
				sleep 0.1
			done
			if [[ $gone != true ]]; then
				echo "M9 backend connection $backend_conn survived $marker crash" >&2
				exit 1
			fi
			rm -f "$M9_FIFO"
			printf 'KA_SESSION_PID=\nKA_FIFO=\n' >>"$run_dir/state.env"
		}

		# Seed the Rust gate's drain watermark through the Rust admin port
		# without selecting any live SQL session. The drain is issued inside
		# the Rust process (sequence 1 on the shared gate lineage); a later
		# Go incarnation must learn this exact sequence from ReconcileRequest.
		curl --noproxy '*' --fail --silent --show-error -X POST \
			-H 'Content-Type: application/json' \
			-d '{"drain_id":"m9-pre-restart","listener_names":["m9-no-such-listener"],"graceful_wait_ms":0,"force_timeout_ms":1000}' \
			"http://127.0.0.1:$ka_admin_port/api/dataplane/drain" -o "$run_dir/t4-m9-drain-pre-post.json"
		m9_wait_drain m9-pre-restart "$m9_pre_status" 0
		m9_wait_health_watermark 1 "$run_dir/t4-m9-health-watermark-pre.json"

		# Bridge loss lasts beyond the legacy 30-second grace. During that
		# interval a config-driven A0->A1 redirect and post-grace admission
		# must both remain owned wholly by Rust.
		m9_open_session bridge-disconnect
		if [[ $m9_port != "$TIDB_PORT_0" ]]; then
			echo "M9 bridge baseline landed on $m9_port, want $TIDB_PORT_0" >&2
			exit 1
		fi
		local m9_bridge_conn=$m9_conn m9_bridge_proxy=$m9_proxy
		curl --noproxy '*' --fail --silent --max-time 5 \
			"http://127.0.0.1:$ka_drop_admin_port/state" \
			-o "$run_dir/t4-m9-route-audit-before-disconnect.json"
		validate_t4_route_audit "$run_dir/t4-m9-route-audit-before-disconnect.json"
		local m9_old_tap=$KA_DROP_PID
		m9_stop_tap bridge-disconnect
		m9_disconnect_started=$(date +%s)
		ka_set_fail_list \
			"[\"127.0.0.1:$TIDB_PORT_B\",\"127.0.0.1:$TIDB_PORT_0\"]" \
			t4-m9-local-redirect
		local redirected=false m9_bridge_redirected_conn=
		for attempt in {1..80}; do
			m9_line=$(m9_query "M9BRIDGE$attempt" \
				"SELECT CONCAT('M9BRIDGE$attempt|', CONNECTION_ID(), '|', @@port);") || exit 1
			# A transparent redirect necessarily changes TiDB's backend-side
			# CONNECTION_ID(); the invariant is the one still-running
			# --skip-reconnect client and its stable Rust connection id.
			if [[ $(cut -d'|' -f2 <<<"$m9_line") != "$m9_bridge_conn" &&
				$(cut -d'|' -f3 <<<"$m9_line") == "$TIDB_PORT_1" ]]; then
				redirected=true
				m9_bridge_redirected_conn=$(cut -d'|' -f2 <<<"$m9_line")
				break
			fi
			sleep 0.25
		done
		if [[ $redirected != true ]] ||
			grep -q "\"event\":\"connection_closed\",\"connection_id\":$m9_bridge_proxy," \
				"$run_dir/tiproxy-rs-ka.log"; then
			echo "M9 local redirect did not move the disconnected session A0->A1" >&2
			exit 1
		fi
		while (( $(date +%s) - m9_disconnect_started < 32 )); do
			sleep 1
		done
		m9_disconnect_seconds=$(( $(date +%s) - m9_disconnect_started ))
		m9_line=$(m9_query M9POSTGRACE \
			"SELECT CONCAT('M9POSTGRACE|', CONNECTION_ID(), '|', @@port);") || exit 1
		if [[ $(cut -d'|' -f2 <<<"$m9_line") != "$m9_bridge_redirected_conn" ||
			$(cut -d'|' -f3 <<<"$m9_line") != "$TIDB_PORT_1" ]]; then
			echo "M9 admission or existing SQL failed after ${m9_disconnect_seconds}s bridge loss" >&2
			exit 1
		fi
		m9_wait_fresh_port "$TIDB_PORT_1" post-grace-bridge-loss
		m9_close_session

		# Quiet Go-only restart while the bridge is still absent, then restore
		# the tap. Rust's first reconcile to the new Go process must carry the
		# sequence-1 watermark.
		m9_stop_go go-quiet
		local m9_old_go=$m9_old
		m9_start_go go-quiet "$m9_old_go"
		m9_start_tap bridge-reconnect "$m9_old_tap"
		m9_wait_tap_watermark 1 "$run_dir/t4-m9-reconcile-after-go-quiet.json"
		m9_wait_fresh_port "$TIDB_PORT_1" quiet-go-restart

		# In-flight Go restart: a real backend command and its client identity
		# survive unchanged while only the bridge/control owner restarts.
		m9_open_session go-inflight
		local m9_go_conn=$m9_conn m9_go_port=$m9_port m9_go_proxy=$m9_proxy
		printf '%s\n' "SELECT CONCAT('M9GOINFLIGHT|', SLEEP(3), '|', CONNECTION_ID(), '|', @@port);" >&3
		m9_wait_backend_inflight "$m9_go_port" "$m9_go_conn" M9GOINFLIGHT
		m9_stop_go go-inflight
		m9_old_go=$m9_old
		m9_start_go go-inflight "$m9_old_go"
		m9_line=
		for _ in {1..80}; do
			m9_line=$(grep -s '^M9GOINFLIGHT|' "$run_dir/m9-session.out" | tail -1 || true)
			[[ -n $m9_line ]] && break
			kill -0 "$KA_SESSION_PID" 2>/dev/null || break
			sleep 0.1
		done
		if [[ -z $m9_line || $(cut -d'|' -f3 <<<"$m9_line") != "$m9_go_conn" ||
			$(cut -d'|' -f4 <<<"$m9_line") != "$m9_go_port" ]]; then
			echo "M9 in-flight SQL was interrupted by Go-only restart: ${m9_line:-<none>}" >&2
			exit 1
		fi
		m9_line=$(m9_query M9GOAFTER \
			"SELECT CONCAT('M9GOAFTER|', CONNECTION_ID(), '|', @@port);") || exit 1
		if [[ $(cut -d'|' -f2 <<<"$m9_line") != "$m9_go_conn" ||
			$(cut -d'|' -f3 <<<"$m9_line") != "$m9_go_port" ]] ||
			grep -q "\"event\":\"connection_closed\",\"connection_id\":$m9_go_proxy," \
				"$run_dir/tiproxy-rs-ka.log"; then
			echo "M9 Go restart changed the live SQL identity" >&2
			exit 1
		fi
		m9_wait_tap_watermark 1 "$run_dir/t4-m9-reconcile-after-go-inflight.json"

		# Sequence 2 targets exactly the one retained session, issued through
		# the Rust admin port. Its terminal result must report exactly one
		# close; the Rust health watermark proves the consumed sequence and the
		# tap proves the restored reconcile watermark and that no drain command
		# ever crossed the bridge.
		curl --noproxy '*' --fail --silent --show-error -X POST \
			-H 'Content-Type: application/json' \
			-d '{"drain_id":"m9-post-restart","listener_names":["sql-0"],"graceful_wait_ms":0,"force_timeout_ms":1000}' \
			"http://127.0.0.1:$ka_admin_port/api/dataplane/drain" -o "$run_dir/t4-m9-drain-post-post.json"
		m9_wait_drain m9-post-restart "$m9_post_status" 1
		m9_wait_health_watermark 2 "$run_dir/t4-m9-health-watermark-post.json"
		# CP-FAULT-ADMIN-DRAIN-REPLAY: re-posting the completed label answers
		# the same 202 binding and the retained terminal, consumes no sequence,
		# and closes nothing again (the single close for the targeted session
		# is asserted below on the Rust connection log).
		local m9_replay_code
		m9_replay_code=$(curl --noproxy '*' --silent --show-error -X POST \
			-H 'Content-Type: application/json' \
			-d '{"drain_id":"m9-post-restart","listener_names":["sql-0"],"graceful_wait_ms":0,"force_timeout_ms":1000}' \
			"http://127.0.0.1:$ka_admin_port/api/dataplane/drain" \
			-o "$run_dir/t4-m9-drain-post-replay.json" -w '%{http_code}')
		if [[ $m9_replay_code != 202 ]] ||
			! cmp -s "$run_dir/t4-m9-drain-post-post.json" "$run_dir/t4-m9-drain-post-replay.json"; then
			echo "M9 drain replay answered $m9_replay_code, want 202 with the original binding" >&2
			cat "$run_dir/t4-m9-drain-post-replay.json" >&2 2>/dev/null || true
			exit 1
		fi
		m9_wait_drain m9-post-restart "$run_dir/t4-m9-drain-post-replay-status.json" 1
		if ! cmp -s "$m9_post_status" "$run_dir/t4-m9-drain-post-replay-status.json"; then
			echo "M9 drain replay changed the retained terminal" >&2
			exit 1
		fi
		m9_wait_health_watermark 2 "$run_dir/t4-m9-health-watermark-replay.json"
		local m9_close_count m9_backend_gone=false
		for _ in {1..80}; do
			m9_close_count=$(grep -c "\"event\":\"connection_closed\".*\"connection_id\":$m9_go_proxy," \
				"$run_dir/tiproxy-rs-ka.log" || true)
			if [[ $m9_close_count == 1 &&
				$(mysql --batch --skip-column-names --connect-timeout=2 \
					-h 127.0.0.1 -P "$m9_go_port" -u root --ssl-mode=DISABLED \
					-e "SELECT COUNT(*) FROM INFORMATION_SCHEMA.PROCESSLIST WHERE ID = $m9_go_conn" \
					2>/dev/null || true) == 0 ]]; then
				m9_backend_gone=true
				break
			fi
			sleep 0.1
		done
		if [[ $m9_backend_gone != true ]]; then
			echo "M9 drain did not terminate exact Rust/backend session $m9_go_proxy/$m9_go_conn" >&2
			exit 1
		fi
		# An idle mysql process blocks on the FIFO and cannot observe the peer's
		# EOF until its stdin advances. Close the harness writer only after the
		# Rust terminal and backend PROCESSLIST disappearance are independently
		# proven. The process is only a harness reader at that point; reap it if
		# the mysql CLI keeps waiting while trying to flush QUIT to the dead peer.
		exec 3>&-
		for _ in {1..20}; do
			kill -0 "$KA_SESSION_PID" 2>/dev/null || break
			sleep 0.1
		done
		kill "$KA_SESSION_PID" 2>/dev/null || true
		wait "$KA_SESSION_PID" 2>/dev/null || true
		rm -f "$M9_FIFO"
		printf 'KA_SESSION_PID=\nKA_FIFO=\n' >>"$run_dir/state.env"
		if [[ $m9_close_count != 1 ]]; then
			echo "M9 drain emitted $m9_close_count closes for Rust connection $m9_go_proxy, want 1" >&2
			exit 1
		fi
		m9_wait_tap_watermark 1 "$m9_tap_state"
		if ! python3 - "$m9_tap_state" <<'PYM9SEQUENCE'
import json
import pathlib
import sys

audit = json.loads(pathlib.Path(sys.argv[1]).read_text()).get("route_audit", {})
if audit.get("max_reconcile_request_drain_sequence") != 1:
    raise SystemExit(f"reconcile watermark is not exactly 1: {audit}")
if audit.get("drain_commands", 0) != 0 or audit.get("max_drain_command_sequence", 0) != 0:
    raise SystemExit(f"an operator drain crossed the bridge: {audit}")
PYM9SEQUENCE
		then
			exit 1
		fi
		m9_assert_zero_ledger after-admin-drain

		# Rust-only quiet restart: the new process begins with an empty local
		# ledger, rebuilds its sources, and accepts a fresh SQL session.
		m9_stop_rust rust-quiet
		local m9_old_rust=$m9_old
		m9_start_rust rust-quiet "$m9_old_rust"
		m9_assert_zero_ledger after-rust-quiet
		m9_wait_fresh_port "$TIDB_PORT_1" quiet-rust-restart

		# Rust-only in-flight restart: SIGKILL must disconnect the one old SQL
		# client, leave no backend ghost, and admit a fresh client from a zero
		# ledger in the replacement process.
		m9_open_session rust-inflight
		local m9_rust_conn=$m9_conn m9_rust_port=$m9_port
		# Five seconds is long enough for PROCESSLIST to prove the command is
		# already executing before SIGKILL, while still letting TiDB finish and
		# reap a server-side command that does not cancel immediately when its
		# TCP peer disappears. The client must still observe 2013, never a row.
		printf '%s\n' "SELECT CONCAT('M9RUSTCRASH|', SLEEP(5));" >&3
		m9_wait_backend_inflight "$m9_rust_port" "$m9_rust_conn" M9RUSTCRASH
		m9_stop_rust rust-inflight
		m9_old_rust=$m9_old
		m9_assert_crash_terminal M9RUSTCRASH "$m9_rust_port" "$m9_rust_conn"
		m9_start_rust rust-inflight "$m9_old_rust"
		m9_assert_zero_ledger after-rust-inflight
		m9_wait_fresh_port "$TIDB_PORT_1" in-flight-rust-restart

		# Whole-process quiet restart reuses the exact API/listener/control
		# sockets and workdirs. Successful bind plus zero ledger and SQL proves
		# no stale port, lease, or WAL identity collision survived.
		m9_stop_rust whole-quiet
		m9_old_rust=$m9_old
		m9_stop_go whole-quiet
		m9_old_go=$m9_old
		m9_start_go whole-quiet "$m9_old_go"
		m9_start_rust whole-quiet "$m9_old_rust"
		m9_assert_zero_ledger after-whole-quiet
		m9_wait_fresh_port "$TIDB_PORT_1" quiet-whole-restart

		# Whole-process in-flight restart repeats the crash with one real
		# outstanding backend command, then proves the replacement pair is
		# clean and admits a fresh connection on the same sockets/workdirs.
		m9_open_session whole-inflight
		local m9_whole_conn=$m9_conn m9_whole_port=$m9_port
		printf '%s\n' "SELECT CONCAT('M9WHOLECRASH|', SLEEP(5));" >&3
		m9_wait_backend_inflight "$m9_whole_port" "$m9_whole_conn" M9WHOLECRASH
		m9_stop_rust whole-inflight
		m9_old_rust=$m9_old
		m9_stop_go whole-inflight
		m9_old_go=$m9_old
		m9_assert_crash_terminal M9WHOLECRASH "$m9_whole_port" "$m9_whole_conn"
		m9_start_go whole-inflight "$m9_old_go"
		m9_start_rust whole-inflight "$m9_old_rust"
		m9_assert_zero_ledger after-whole-inflight
		m9_wait_fresh_port "$TIDB_PORT_1" in-flight-whole-restart

		curl --noproxy '*' --fail --silent --show-error --max-time 5 \
			"http://127.0.0.1:$ka_drop_admin_port/state" -o "$m9_tap_state"
		validate_t4_route_audit "$m9_tap_state"
		python3 - "$run_dir/t4-row-M9.json" "$variant" "$m9_disconnect_seconds" \
			"$m9_pre_status" "$m9_post_status" "$m9_tap_state" <<'PYM9RECEIPT'
import json
import pathlib
import platform
import sys

path = pathlib.Path(sys.argv[1])
path.write_text(json.dumps({
    "schema": 1,
    "row": "M9",
    "result": "pass",
    "variant": sys.argv[2],
    "platform": f"{platform.system()} {platform.machine()}",
    "bridge_disconnect_seconds": int(sys.argv[3]),
    "bridge_disconnect_exceeded_legacy_grace": int(sys.argv[3]) > 30,
    "local_redirect_while_disconnected": {"from": "A0", "to": "A1", "pass": True},
    "fresh_admission_after_grace": True,
    "go_restart": {"quiet": "pass", "in_flight": "pass", "existing_sql_survived": True},
    "rust_restart": {"quiet": "pass", "in_flight": "pass", "replacement_ledger_zero": True},
    "whole_restart": {"quiet": "pass", "in_flight": "pass", "same_endpoints_rebound": True},
    "admin_drain": {
        "issuer": "rust-admin",
        "pre_restart_sequence": 1,
        "restored_reconcile_watermark": 1,
        "post_restart_sequence": 2,
        "bridge_drain_commands": 0,
        "targeted_sessions_closed_exactly_once": 1,
        "replay": {"http_status": 202, "same_binding_and_terminal": True, "sequence_consumed": False},
    },
    "evidence": {
        "pre_drain_status": pathlib.Path(sys.argv[4]).name,
        "post_drain_status": pathlib.Path(sys.argv[5]).name,
        "post_drain_replay_status": "t4-m9-drain-post-replay-status.json",
        "health_watermarks": ["t4-m9-health-watermark-pre.json", "t4-m9-health-watermark-post.json", "t4-m9-health-watermark-replay.json"],
        "route_audit": pathlib.Path(sys.argv[6]).name,
    },
}, sort_keys=True, indent=2) + "\n")
PYM9RECEIPT
		echo "PASS: T4 M9 bridge loss ${m9_disconnect_seconds}s, Go/Rust/whole quiet+in-flight restarts, Rust-admin drains 1->2 with zero bridge drain commands and an idempotent replay"
	}
	run_t4_m9_probe
	if [[ -z ${KA_DROP_PID:-} ]] || ! kill -0 "$KA_DROP_PID" 2>/dev/null; then
		echo "T4 keyspace/redirect route tap is not alive at final audit" >&2
		exit 1
	fi
	capture_t4_final_audit "http://127.0.0.1:$ka_drop_admin_port/state" \
		"$run_dir/t4-route-audit-ka-final.json"
fi
if [[ $mode == rust ]]; then
	kill -s INT "$KA_RUST_PID" 2>/dev/null || true
	for _ in {1..100}; do
		kill -0 "$KA_RUST_PID" 2>/dev/null || break
		sleep 0.1
	done
	rm -f "$KA_SOCKET"
fi
if [[ $ka_use_dropper == true ]]; then
	kill -s INT "$KA_DROP_PID" 2>/dev/null || true
	ka_drop_stopped=false
	for _ in {1..100}; do
		if ! kill -0 "$KA_DROP_PID" 2>/dev/null; then
			ka_drop_stopped=true
			break
		fi
		sleep 0.1
	done
	if [[ $ka_drop_stopped != true ]]; then
		kill -s KILL "$KA_DROP_PID" 2>/dev/null || true
		for _ in {1..50}; do
			if ! kill -0 "$KA_DROP_PID" 2>/dev/null; then
				ka_drop_stopped=true
				break
			fi
			sleep 0.1
		done
	fi
	# Unlink the front socket ONLY once its owning dropper is confirmed
	# gone; otherwise leave the inode for cleanup.sh's ownership-checked
	# path rather than orphaning a live socket.
	if [[ $ka_drop_stopped == true ]]; then
		rm -f "$KA_DROP_SOCKET"
	fi
fi
kill -s INT "$KA_PID" 2>/dev/null || true
for _ in {1..100}; do
	kill -0 "$KA_PID" 2>/dev/null || break
	sleep 0.1
done
kill "$KA_PID" 2>/dev/null || true
rm -f "$KA_FIFO"
# KA-phase ports were folded into PORTS and persisted before the phase
# started (see the pre-check above), so no separate PORTS append here.
echo "no-keyspace-migration: old session pinned to ks-old under real migration pressure; guard refused ks-new"

# ---- Error parity (DPL-07 #41): the same semantic ERR in both modes.
# The oracle freezes the ERR packet's SEMANTIC fields (code + SQLSTATE
# + message), never handshake bytes. Free-text equality of operator
# diagnostics between modes is NOT asserted — only bind semantics.

# Unknown namespace is reachable under Rust CP-CFG: the first explicit
# `/config/ns/*` set replaces the one-shot process seed, so omitting
# `/config/ns/default` removes the ordinary fallback and returns the exact
# 1105/HY000 namespace-missing response. The T4 namespace setup materializes
# default before alpha/beta because this full matrix needs all three; the
# directed resolver regression proves both omission and materialization.
# Legacy Go mode retains its process-local bootstrap/upsert-only admin
# behavior and cannot remove default through that API.

# Row 2 (bind conflict): operator parity. Each mode's own listener
# bind must fail fast against an occupied port, name the port in its
# diagnostic, and leave no residue. The holder keeps the fd open for
# the whole phase, proving the conflict is live at bind time.
conflict_port=$((8091 + port_offset))
conflict_admin_port=$((8092 + port_offset))
conflict_api_port=$((8093 + port_offset))
for port in "$conflict_port" "$conflict_admin_port" "$conflict_api_port"; do
	if "$FAULT_PROXY_BIN" --probe "127.0.0.1:$port" >/dev/null 2>&1; then
		echo "conflict-phase port is already in use: $port" >&2
		exit 1
	fi
done
"$FAULT_PROXY_BIN" --listen "127.0.0.1:$conflict_port" \
	--admin "127.0.0.1:$conflict_admin_port" --target 127.0.0.1:1 \
	>"$run_dir/conflict-holder.log" 2>&1 &
HOLDER_PID=$!
printf 'HOLDER_PID=%q\n' "$HOLDER_PID" >>"$run_dir/state.env"

holder_ready=false
for _ in {1..50}; do
	if "$FAULT_PROXY_BIN" --probe "127.0.0.1:$conflict_port" >/dev/null 2>&1; then
		holder_ready=true
		break
	fi
	sleep 0.1
done
if [[ $holder_ready != true ]]; then
	echo "conflict holder never bound" >&2
	exit 1
fi
# The Go instance binds its SQL listener directly (no rust-dataplane
# gate): strip the gate section and repoint every listener/path.
sed '/^\[rust-dataplane\]/,$d' "$run_dir/tiproxy.toml" >"$run_dir/tiproxy-conflict.toml"
python3 - "$run_dir/tiproxy-conflict.toml" "$conflict_port" "$conflict_api_port" "$run_dir" <<'PYCONF'
import re, sys
path, sql_port, api_port, run_dir = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
text = open(path).read()
text = re.sub(r'(?m)^workdir = .*$', f'workdir = "{run_dir}/conflict-workdir"', text)
text = re.sub(r'(?m)^addr = "127\.0\.0\.1:\d+"$',
              lambda m, it=iter([sql_port, api_port]): f'addr = "127.0.0.1:{next(it)}"',
              text, count=2)
text = re.sub(r'(?m)^port-range = .*$', f'port-range = [{sql_port}, {sql_port}]', text)
text = re.sub(r'(?m)^filename = .*$', f'filename = "{run_dir}/tiproxy-conflict.log"', text)
open(path, 'w').write(text)
PYCONF
"$repo_root/bin/tiproxy" --config "$run_dir/tiproxy-conflict.toml" \
	>"$run_dir/tiproxy-conflict.out" 2>&1 &
CONFLICT_PID=$!
printf 'CONFLICT_PID=%q\n' "$CONFLICT_PID" >>"$run_dir/state.env"

conflict_exited=false
for _ in {1..40}; do
	if ! kill -0 "$CONFLICT_PID" 2>/dev/null; then
		conflict_exited=true
		break
	fi
	sleep 0.5
done
if [[ $conflict_exited != true ]]; then
	kill -9 "$CONFLICT_PID" 2>/dev/null || true
	echo "Go bind-conflict instance did not fail within the deadline" >&2
	exit 1
fi
if wait "$CONFLICT_PID"; then
	echo "Go bind-conflict instance exited zero" >&2
	exit 1
fi
if ! grep -Eqs "address already in use|bind" \
	"$run_dir/tiproxy-conflict.out" "$run_dir/tiproxy-conflict.log"; then
	echo "Go bind-conflict diagnostic lacks bind semantics" >&2
	exit 1
fi
if ! grep -qs "$conflict_port" \
	"$run_dir/tiproxy-conflict.out" "$run_dir/tiproxy-conflict.log"; then
	echo "Go bind-conflict diagnostic does not name the port" >&2
	exit 1
fi
if "$FAULT_PROXY_BIN" --probe "127.0.0.1:$conflict_api_port" >/dev/null 2>&1; then
	echo "Go bind-conflict instance left its API listener behind" >&2
	exit 1
fi
if ! "$FAULT_PROXY_BIN" --probe "127.0.0.1:$conflict_port" >/dev/null 2>&1; then
	echo "conflict holder died during the Go bind-conflict check" >&2
	exit 1
fi
if [[ $mode == rust ]]; then
	# The Rust operator-facing listener is the health endpoint, bound
	# at startup before serving precisely so a bad port fails fast.
	"$rust_binary" --config "$run_dir/tiproxy-conflict.toml" \
		--control-socket "$run_dir/absent.sock" \
		--control-uid "$(id -u)" --health-port "$conflict_port" \
		${rust_tls_args[@]+"${rust_tls_args[@]}"} \
		>"$run_dir/tiproxy-rs-conflict.out" 2>&1 &
	RUST_CONFLICT_PID=$!
	printf 'RUST_CONFLICT_PID=%q\n' "$RUST_CONFLICT_PID" >>"$run_dir/state.env"

	rust_conflict_exited=false
	for _ in {1..40}; do
		if ! kill -0 "$RUST_CONFLICT_PID" 2>/dev/null; then
			rust_conflict_exited=true
			break
		fi
		sleep 0.5
	done
	if [[ $rust_conflict_exited != true ]]; then
		kill -9 "$RUST_CONFLICT_PID" 2>/dev/null || true
		echo "Rust bind-conflict instance did not fail within the deadline" >&2
		exit 1
	fi
	if wait "$RUST_CONFLICT_PID"; then
		echo "Rust bind-conflict instance exited zero" >&2
		exit 1
	fi
	if ! grep -Eq "bind health endpoint|[Aa]ddress.*in use" \
		"$run_dir/tiproxy-rs-conflict.out"; then
		echo "Rust bind-conflict diagnostic lacks bind semantics" >&2
		exit 1
	fi
	if ! grep -q "$conflict_port" "$run_dir/tiproxy-rs-conflict.out"; then
		echo "Rust bind-conflict diagnostic does not name the port" >&2
		exit 1
	fi
	if ! "$FAULT_PROXY_BIN" --probe "127.0.0.1:$conflict_port" >/dev/null 2>&1; then
		echo "conflict holder died during the Rust bind-conflict check" >&2
		exit 1
	fi
fi
kill "$HOLDER_PID" 2>/dev/null || true
wait "$HOLDER_PID" 2>/dev/null || true
# The conflict ports join the post-run leak sweep.
printf 'PORTS=%q\n' "$PORTS $conflict_port $conflict_admin_port $conflict_api_port" >>"$run_dir/state.env"
echo "error parity: bind conflict -> fast nonzero exit, port named, no residue"

# Row 3 (no healthy backend): TERMINAL phase — it destroys the SQL
# plane, so nothing SQL-visible may follow. Both TiDB servers are
# killed (expected; the shared readiness gate has already completed
# and cleanup stops TiUP itself, so this never reads as a harness
# failure). The poll then pins the oracle to the eviction-complete
# state: mid-race dial failures surface a different message and keep
# polling; only the frozen vocabulary ends the loop — 1105/HY000
# "No available TiDB instances, please make sure TiDB is available"
# (Go: ErrProxyNoBackend in pkg/proxy/backend/error.go, reached from
# router.ErrNoBackend; Rust: the AcquireError::NoBackend client
# refusal).
# Per-port discipline: EACH TiDB port must have exactly one LISTEN
# owner and the two owners must be distinct processes — an already-dead
# backend or an accidentally shared port is a hard error, never a
# silently "successful" double kill. (Under pipefail a no-match lsof
# would abort the capture silently, so each probe is explicitly
# allowed to fail and reports its owners on error.)
# ALL expected TiDB ports across BOTH clusters: a still-healthy
# cluster-B backend would keep the router serving and the 1105 oracle
# would never converge. Each port must have exactly one LISTEN owner,
# all owners must be distinct processes, and each pid's command line
# must carry ITS OWN playground's unique tag path ("/$tag/" never
# matches "/$tag-b/", so cluster-A's check cannot be satisfied by a
# cluster-B process or vice versa).
tidb_pid_0=$(lsof -ti "tcp:$TIDB_PORT_0" -sTCP:LISTEN 2>/dev/null || true)
tidb_pid_1=$(lsof -ti "tcp:$TIDB_PORT_1" -sTCP:LISTEN 2>/dev/null || true)
tidb_pid_b=$(lsof -ti "tcp:$TIDB_PORT_B" -sTCP:LISTEN 2>/dev/null || true)
for pair in "$TIDB_PORT_0:$tidb_pid_0" "$TIDB_PORT_1:$tidb_pid_1" "$TIDB_PORT_B:$tidb_pid_b"; do
	port=${pair%%:*}
	owner=${pair#*:}
	if [[ ! $owner =~ ^[0-9]+$ ]]; then
		{
			echo "port $port must have exactly one LISTEN owner for the no-backend row; got: '$owner'"
			lsof -i "tcp:$port" || true
		} >&2
		exit 1
	fi
done
if [[ $tidb_pid_0 == "$tidb_pid_1" || $tidb_pid_0 == "$tidb_pid_b" || $tidb_pid_1 == "$tidb_pid_b" ]]; then
	echo "TiDB ports share a LISTEN owner ($tidb_pid_0/$tidb_pid_1/$tidb_pid_b); refusing the no-backend row" >&2
	exit 1
fi
for pair in "$tag:$tidb_pid_0" "$tag:$tidb_pid_1" "$tag_b:$tidb_pid_b"; do
	owner_tag=${pair%%:*}
	pid=${pair#*:}
	pid_cmd=$(ps -p "$pid" -o command= 2>/dev/null || true)
	if [[ $pid_cmd != *"/$owner_tag/"* ]]; then
		echo "refusing to kill PID $pid for the no-backend row: not owned by tag $owner_tag: $pid_cmd" >&2
		exit 1
	fi
done
tidb_pids="$tidb_pid_0
$tidb_pid_1
$tidb_pid_b"
# Source-branch evidence is delta-scoped to the no-backend window:
# only records logged AFTER the kill count (same discipline as the
# matrix rows).
if [[ $mode == go ]]; then
	go_evidence_offset=$(evidence_lines)
fi
echo "no-backend row: killing TiDB listeners: $(tr '\n' ' ' <<<"$tidb_pids")"
# shellcheck disable=SC2086
kill -9 $tidb_pids
no_backend_ok=false
root_err=
for _ in {1..60}; do
	# The client failing IS the expected outcome: the capture must
	# not let pipefail turn it into a silent abort.
	root_err=$(mysql_ingress_as root 'SELECT 1' 2>&1 >/dev/null | tail -1 || true)
	if grep -q "ERROR 1105 (HY000)" <<<"$root_err" &&
		grep -q "No available TiDB instances, please make sure TiDB is available" <<<"$root_err"; then
		no_backend_ok=true
		break
	fi
	sleep 1
done
if [[ $no_backend_ok != true ]]; then
	echo "no-backend parity failed; last client error: $root_err" >&2
	exit 1
fi
if [[ $mode == rust && ${DATAPLANE_T4_QUALIFICATION:-0} == 1 ]]; then
	printf '%s\n' "$root_err" >"$run_dir/t4-no-backend.out"
fi
if [[ $mode == go ]]; then
	# Source-branch evidence: ONE fresh record must carry BOTH the
	# get-backend failure and, in its structured last_err field, the
	# frozen ErrProxyNoBackend text — a generic "get backend failed"
	# alone could be an earlier dial/EOF retry from the eviction race,
	# which proves nothing about the branch that refused the client.
	# The client's 1105 and this log record are written near-
	# simultaneously: the record can land milliseconds after the
	# client observed the refusal, so the read retries briefly.
	go_source_evidence=false
	for _ in {1..20}; do
		if evidence_tail "$go_evidence_offset" |
			grep -Eqs '"get backend failed".*"last_err":"No available TiDB instances, please make sure TiDB is available"'; then
			go_source_evidence=true
			break
		fi
		sleep 0.5
	done
	if [[ $go_source_evidence != true ]]; then
		{
			echo "Go no-backend source-branch evidence missing from the row's window"
			echo "fresh get-backend records were:"
			evidence_tail "$go_evidence_offset" | grep -s "get backend failed" | tail -5
		} >&2
		exit 1
	fi
fi
echo "error parity: no healthy backend -> 1105/HY000 'No available TiDB instances'"

if [[ $mode == rust && ${DATAPLANE_T4_QUALIFICATION:-0} == 1 ]]; then
	capture_t4_zero_ledger after
	if [[ -z $T3_DROP_PID ]] || ! kill -0 "$T3_DROP_PID" 2>/dev/null; then
		echo "T4 full-run route tap is not alive at the final audit" >&2
		exit 1
	fi
	capture_t4_final_audit "http://127.0.0.1:$T3_DROP_ADMIN_PORT/state" \
		"$run_dir/t4-route-audit-final.json"
	if [[ ${DATAPLANE_T4_ROW:-} != M9 ]]; then
		# The evidence writer validates the already-completed cell from its
		# immutable ledgers, route audits, phase receipts, lineage, and the
		# row-specific observations.  It refuses to create a pass receipt if
		# any source is missing or inconsistent. M9 retains its richer restart
		# receipt, which is written by run_t4_m9_probe above.
		close_t4_process_lineage
		python3 "$script_dir/write-t4-row-receipt.py" \
			--run-dir "$run_dir" --row "$DATAPLANE_T4_ROW" --variant "$variant"
	fi
fi

if [[ $mode == rust ]]; then
	echo "PASS: Rust dataplane $variant executed SELECT 1, namespace matrix, MIG-01 live migration, keyspace guard, error parity, and recovered from drop-next"
else
	echo "PASS: Go baseline $variant executed SELECT 1, namespace matrix, keyspace guard, error parity, and recovered from drop-next"
fi
