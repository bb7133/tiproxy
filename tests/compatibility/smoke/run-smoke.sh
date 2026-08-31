#!/usr/bin/env bash
# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# VAL-01 driver-compatibility smoke: run a small set of real MySQL clients
# (native runtimes, no containers) against a live TiProxy SQL listener and
# verify each key operation works AND that requested transport capabilities
# (TLS, compression) were actually negotiated — never silently downgraded.
#
# The client adapters (smoke/go, smoke/python) assert the CLIENT side. This
# orchestrator additionally reads the dataplane's `connection_closed` log line
# for each connection and asserts the negotiated `capabilities` bitmask carries
# the expected flag (CLIENT_SSL / CLIENT_COMPRESS), so a "query succeeded after
# a silent fallback" is a failure, not a pass. Correlation is by order: the
# smoke phase is the only client active, so the single new connection_closed
# line after each invocation belongs to that invocation.
#
# It NEVER prints packet payloads. Reachable host/port are parameters (no
# hardcoded docker `--network host`), so it is portable across Linux/macOS.
set -uo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

host=127.0.0.1
port=""
user=root
password=""
database=test
ca_file=""
server_name=""
rust_log=""            # dataplane log file with connection_closed events
drivers="go python"    # which adapters to run (space-separated)
verify_identity=0      # pass --verify-identity to the TLS workload

while (($# > 0)); do
	case "$1" in
	--host) host=$2; shift 2 ;;
	--port) port=$2; shift 2 ;;
	--user) user=$2; shift 2 ;;
	--password) password=$2; shift 2 ;;
	--database) database=$2; shift 2 ;;
	--ca-file) ca_file=$2; shift 2 ;;
	--server-name) server_name=$2; shift 2 ;;
	--rust-log) rust_log=$2; shift 2 ;;
	--drivers) drivers=$2; shift 2 ;;
	--verify-identity) verify_identity=1; shift ;;
	*) echo "unknown argument: $1" >&2; exit 2 ;;
	esac
done

[[ -n $port ]] || { echo "--port is required" >&2; exit 2; }

# Capability flag bits (mysql-wire constants): CLIENT_COMPRESS = 1<<5,
# CLIENT_SSL = 1<<11.
readonly CLIENT_COMPRESS=$((1 << 5))
readonly CLIENT_SSL=$((1 << 11))

pass_count=0
fail_count=0
skip_count=0

# --- adapter setup ---------------------------------------------------------
go_bin=""
if [[ $drivers == *go* ]]; then
	if command -v go >/dev/null 2>&1; then
		go_bin="$script_dir/.go-smoke.bin"
		if ! (cd "$script_dir/go" && go build -o "$go_bin" ./...) >/dev/null 2>&1; then
			echo "smoke: go adapter failed to build; skipping go driver" >&2
			drivers=${drivers//go/}
		fi
	else
		echo "smoke: go toolchain absent; skipping go driver" >&2
		drivers=${drivers//go/}
	fi
fi

py_bin=""
if [[ $drivers == *python* ]]; then
	venv="$script_dir/.venv"
	if [[ ! -x "$venv/bin/python" ]]; then
		if command -v python3 >/dev/null 2>&1 && python3 -m venv "$venv" >/dev/null 2>&1 &&
			"$venv/bin/pip" install -q -r "$script_dir/python/requirements.txt" >/dev/null 2>&1; then
			py_bin="$venv/bin/python"
		else
			echo "smoke: python env/driver unavailable; skipping python driver" >&2
			drivers=${drivers//python/}
		fi
	else
		py_bin="$venv/bin/python"
	fi
fi

# --- one case: run adapter, assert client success + proxy negotiation ------
# run_case <driver> <workload> <expect_cap_bit|0> <cap_name>
run_case() {
	local driver=$1 workload=$2 expect_bit=$3 cap_name=$4
	local attr="${driver}-${workload}-$$"
	local offset=0
	[[ -n $rust_log && -f $rust_log ]] && offset=$(wc -l <"$rust_log" | tr -d ' ')

	local out rc common=(
		--host "$host" --port "$port" --user "$user" --password "$password"
		--database "$database" --attr "$attr" --workload "$workload"
	)
	[[ -n $ca_file ]] && common+=(--ca-file "$ca_file")
	[[ -n $server_name ]] && common+=(--server-name "$server_name")
	((verify_identity)) && [[ $driver == python ]] && common+=(--verify-identity)

	case $driver in
	go) out=$("$go_bin" "${common[@]}" 2>&1); rc=$? ;;
	python) out=$("$py_bin" "$script_dir/python/smoke.py" "${common[@]}" 2>&1); rc=$? ;;
	*) echo "unknown driver $driver" >&2; return 1 ;;
	esac

	if ((rc != 0)); then
		echo "FAIL $driver $workload: $out"
		((fail_count++))
		return 1
	fi

	# Proxy-side negotiation assertion for transport capabilities.
	if ((expect_bit != 0)) && [[ -n $rust_log ]]; then
		local caps="" line=""
		for _ in {1..40}; do
			line=$(tail -n "+$((offset + 1))" "$rust_log" 2>/dev/null |
				grep '"event":"connection_closed"' | tail -1 || true)
			if [[ -n $line ]]; then
				caps=$(sed -n 's/.*"capabilities":\([0-9]*\).*/\1/p' <<<"$line")
				[[ -n $caps ]] && break
			fi
			sleep 0.25
		done
		if [[ -z $caps ]]; then
			echo "FAIL $driver $workload: no connection_closed log to confirm $cap_name negotiation"
			((fail_count++))
			return 1
		fi
		if (((caps & expect_bit) == 0)); then
			echo "FAIL $driver $workload: $cap_name NOT negotiated (caps=$caps) — silent downgrade"
			((fail_count++))
			return 1
		fi
		echo "PASS $driver $workload ($cap_name negotiated, caps=$caps)"
	else
		echo "PASS $driver $workload"
	fi
	((pass_count++))
	return 0
}

echo "=== VAL-01 driver smoke: drivers=[${drivers## }] host=$host port=$port ==="
for driver in $drivers; do
	run_case "$driver" connect 0 ""
	run_case "$driver" crud 0 ""
	run_case "$driver" prepared 0 ""
	if [[ -n $ca_file ]]; then
		run_case "$driver" tls "$CLIENT_SSL" CLIENT_SSL
	else
		echo "SKIP $driver tls (no --ca-file)"; ((skip_count++))
	fi
	run_case "$driver" compress-zlib "$CLIENT_COMPRESS" CLIENT_COMPRESS
done

echo "=== VAL-01 smoke summary: $pass_count passed, $fail_count failed, $skip_count skipped ==="
((fail_count == 0))
