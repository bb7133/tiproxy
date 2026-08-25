#!/usr/bin/env bash
# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

if [[ $# -ne 2 ]]; then
	echo "usage: $0 RUN_DIRECTORY PLAYGROUND_TAG" >&2
	exit 2
fi

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
run_dir=$1
tag=$2
diagnostics_dir="$run_dir/diagnostics"
mkdir -p "$diagnostics_dir/run" "$diagnostics_dir/tiup"

redact_file() {
	local input=$1
	local output=$2
	mkdir -p "$(dirname "$output")"
	awk -f "$script_dir/redact.awk" "$input" >"$output"
}

safe_text_file() {
	case "$1" in
		*.key | *.pem | *.p12 | *.pfx | *credential* | *secret*) return 1 ;;
		*.log | *.out | *.txt | *.toml | *.env | *.json) return 0 ;;
		*) return 1 ;;
	esac
}

while IFS= read -r -d '' source_file; do
	if safe_text_file "$source_file"; then
		relative=${source_file#"$run_dir"/}
		[[ $relative == diagnostics/* ]] && continue
		redact_file "$source_file" "$diagnostics_dir/run/$relative"
	fi
done < <(find "$run_dir" -type f -print0 2>/dev/null)

tiup_root=${TIUP_HOME:-${HOME}/.tiup}
tiup_data="$tiup_root/data/$tag"
if [[ -d $tiup_data ]]; then
	while IFS= read -r -d '' source_file; do
		if safe_text_file "$source_file"; then
			relative=${source_file#"$tiup_data"/}
			redact_file "$source_file" "$diagnostics_dir/tiup/$relative"
		fi
	done < <(find "$tiup_data" -type f \
		! -path '*/data/*' ! -path '*/proxy_data/*' -print0 2>/dev/null)
fi

{
	echo "tag=$tag"
	echo "collected_at=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
	echo "go=$(go version 2>&1 || true)"
	echo "tiup=$(tiup --version 2>&1 | head -n 1 || true)"
	echo "mysql=$(mysql --version 2>&1 || true)"
	echo
	echo "playground:"
	if [[ -f $run_dir/state.env ]]; then
		# shellcheck disable=SC1090
		source "$run_dir/state.env"
	fi
	if [[ ${TIUP_PID:-} =~ ^[0-9]+$ ]]; then
		tiup playground display -T "$tag" 2>&1 || true
	else
		echo "not started (preflight stopped before provisioning)"
	fi
	echo
	echo "owned_processes:"
	if [[ -f $run_dir/state.env ]]; then
		for pid in "${TIUP_PID:-}" "${FAULT_PID:-}"; do
			[[ $pid =~ ^[0-9]+$ ]] && ps -p "$pid" -o pid=,ppid=,command= 2>&1 || true
		done
	fi
} | awk -f "$script_dir/redact.awk" >"$diagnostics_dir/summary.txt"

echo "redacted diagnostics: $diagnostics_dir"
