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
# a silent fallback" is a failure, not a pass.
#
# Correlation is POSITIONAL, not by connection attribute: the smoke phase is the
# only active client and the cases run serially with a single connection each,
# so the window after a case's log offset must contain EXACTLY ONE new
# `connection_closed` line — 0 (never observed) or >1 (ambiguous: a concurrent
# or late-arriving close) both fail. Transport cases REQUIRE a readable
# `--rust-log`; without it the capability cannot be verified and the case fails
# (never a silent pass). The adapters set a unique `--attr` for future
# attribute-correlatable observability, but the current `connection_closed`
# field set does not echo it, so it is not relied upon here.
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
rust_log=""              # dataplane log file with connection_closed events
drivers="go python"      # which adapters to run (space-separated)
verify_identity=0        # pass --verify-identity to the TLS workload
allow_missing_drivers=0  # when set, a requested-but-unavailable driver is a skip, not a failure
self_test=0              # run the negotiation-assertion self-test and exit

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
	--allow-missing-drivers) allow_missing_drivers=1; shift ;;
	--self-test) self_test=1; shift ;;
	*) echo "unknown argument: $1" >&2; exit 2 ;;
	esac
done

# Capability flag bits (mysql-wire constants): CLIENT_COMPRESS = 1<<5,
# CLIENT_SSL = 1<<11.
readonly CLIENT_COMPRESS=$((1 << 5))
readonly CLIENT_SSL=$((1 << 11))

pass_count=0
fail_count=0
skip_count=0

# --- negotiation assertion (fail-closed, positional exactly-one correlation) --
# check_negotiation <rust_log> <offset> <expect_bit> <cap_name> <label>
# Echoes a PASS/FAIL line; returns 0 only when exactly one new connection_closed
# line is present in the window AND its capabilities bitmask carries expect_bit.
# Poll/settle timing is overridable for the self-test.
check_negotiation() {
	local rlog=$1 offset=$2 expect_bit=$3 cap_name=$4 label=$5
	if [[ -z $rlog || ! -r $rlog ]]; then
		echo "FAIL $label: $cap_name needs a readable --rust-log to confirm negotiation (none available)"
		return 1
	fi
	local attempts=${SMOKE_POLL_ATTEMPTS:-40}
	local i newlines count=0
	for ((i = 0; i < attempts; i++)); do
		newlines=$(tail -n "+$((offset + 1))" "$rlog" 2>/dev/null | grep '"event":"connection_closed"' || true)
		count=$(grep -c . <<<"$newlines")
		((count >= 1)) && break
		sleep 0.25
	done
	# Settle: let a straggler close (concurrent / late prior-phase) surface, so
	# 0 or >1 in the window fails as ambiguous rather than silently picking one.
	sleep "${SMOKE_SETTLE_SECS:-0.5}"
	newlines=$(tail -n "+$((offset + 1))" "$rlog" 2>/dev/null | grep '"event":"connection_closed"' || true)
	count=$(grep -c . <<<"$newlines")
	if ((count != 1)); then
		echo "FAIL $label: expected exactly 1 new connection_closed to confirm $cap_name, got $count (ambiguous)"
		return 1
	fi
	local caps
	caps=$(sed -n 's/.*"capabilities":\([0-9]*\).*/\1/p' <<<"$newlines")
	if [[ -z $caps ]]; then
		echo "FAIL $label: connection_closed line has no capabilities field"
		return 1
	fi
	if (((caps & expect_bit) == 0)); then
		echo "FAIL $label: $cap_name NOT negotiated (caps=$caps) — silent downgrade"
		return 1
	fi
	echo "PASS $label ($cap_name negotiated, caps=$caps)"
	return 0
}

# --- self-test: lock the five negotiation-assertion rows without a real TiDB ---
run_self_test() {
	local dir rc=0
	dir=$(mktemp -d)
	local fmt='{"event":"connection_closed","capabilities":%d}\n'
	export SMOKE_POLL_ATTEMPTS=1 SMOKE_SETTLE_SECS=0

	_expect() { # <want_rc> <label> <check_negotiation args...>
		local want=$1 lbl=$2; shift 2
		local got=0
		check_negotiation "$@" >/dev/null 2>&1 || got=1
		if ((got == want)); then
			echo "self-test OK: $lbl"
		else
			echo "self-test FAIL: $lbl (want rc=$want, got rc=$got)"
			rc=1
		fi
	}

	printf 'unrelated log line\n' >"$dir/zero.log"
	printf "$fmt$fmt" 45 45 >"$dir/two.log"
	printf "$fmt" 1 >"$dir/absent.log"   # capabilities=1 → CLIENT_COMPRESS(32) absent
	printf "$fmt" 45 >"$dir/present.log" # capabilities=45=0b101101 → bit5(32) present

	# rows: missing-log / 0-line / 2-line / bit-absent / bit-present
	_expect 1 missing-log "" 0 "$CLIENT_COMPRESS" CLIENT_COMPRESS self
	_expect 1 zero-line "$dir/zero.log" 0 "$CLIENT_COMPRESS" CLIENT_COMPRESS self
	_expect 1 two-line "$dir/two.log" 0 "$CLIENT_COMPRESS" CLIENT_COMPRESS self
	_expect 1 bit-absent "$dir/absent.log" 0 "$CLIENT_COMPRESS" CLIENT_COMPRESS self
	_expect 0 bit-present "$dir/present.log" 0 "$CLIENT_COMPRESS" CLIENT_COMPRESS self

	rm -rf "$dir"
	if ((rc == 0)); then
		echo "=== run-smoke self-test: all 5 negotiation rows OK ==="
	else
		echo "=== run-smoke self-test: FAILURES ===" >&2
	fi
	return $rc
}

if ((self_test)); then
	run_self_test
	exit $?
fi

[[ -n $port ]] || { echo "--port is required" >&2; exit 2; }

# --- adapter setup ---------------------------------------------------------
requested_drivers="$drivers"
go_bin=""
if [[ $drivers == *go* ]]; then
	if command -v go >/dev/null 2>&1; then
		go_bin="$script_dir/.go-smoke.bin"
		if ! (cd "$script_dir/go" && go build -o "$go_bin" ./...) >/dev/null 2>&1; then
			echo "smoke: go adapter failed to build" >&2
			drivers=${drivers//go/}
		fi
	else
		echo "smoke: go toolchain absent" >&2
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
			echo "smoke: python env/driver unavailable" >&2
			drivers=${drivers//python/}
		fi
	else
		py_bin="$venv/bin/python"
	fi
fi

drivers=$(echo $drivers) # normalize whitespace left by removals

# A requested driver that could not be built/provisioned is a FAILURE by default
# (an opt-in acceptance gate must never silently shrink its coverage to 0). Pass
# --allow-missing-drivers to downgrade a genuinely-absent runtime to a skip.
for d in $requested_drivers; do
	case " $drivers " in
	*" $d "*) : ;; # still available
	*)
		if ((allow_missing_drivers)); then
			echo "SKIP $d (requested driver unavailable; --allow-missing-drivers)"
			((skip_count++))
		else
			echo "FAIL $d: requested driver unavailable or failed to build (use --allow-missing-drivers to allow)"
			((fail_count++))
		fi
		;;
	esac
done

# --- one case: run adapter, assert client success + proxy negotiation ------
# run_case <driver> <workload> <expect_cap_bit|0> <cap_name>
run_case() {
	local driver=$1 workload=$2 expect_bit=$3 cap_name=$4
	local attr="${driver}-${workload}-$$"
	local offset=0
	[[ -n $rust_log && -r $rust_log ]] && offset=$(wc -l <"$rust_log" | tr -d ' ')

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

	if ((expect_bit != 0)); then
		if check_negotiation "$rust_log" "$offset" "$expect_bit" "$cap_name" "$driver $workload"; then
			((pass_count++))
			return 0
		fi
		((fail_count++))
		return 1
	fi
	echo "PASS $driver $workload"
	((pass_count++))
	return 0
}

echo "=== VAL-01 driver smoke: drivers=[${drivers}] host=$host port=$port ==="
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
