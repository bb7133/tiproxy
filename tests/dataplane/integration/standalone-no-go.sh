#!/usr/bin/env bash
# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0

# A reviewable runtime receipt complements TiUP's --tiproxy 0 and both
# Rust --standalone launches. Go tiproxy would use this run's config path
# or leave a component log under the tagged TiUP data directory.
assert_standalone_no_go() {
	local phase=$1 process_lines command pid go_proxy_count=0 nsmgr_count=0
	local go_log_count=0 go_log_root log found
	process_lines=$(ps -Ao pid=,command=) || {
		echo "cannot inspect standalone process table" >&2
		exit 1
	}
	while read -r pid command; do
		if [[ $command == *"$repo_root/bin/tiproxy"* &&
			$command == *"$run_dir/tiproxy.toml"* ]]; then
			((go_proxy_count += 1))
		fi
	done <<<"$process_lines"
	# TiUP stores Go component logs under its tagged data roots, not
	# under run_dir. Scan both playgrounds, as the Go evidence path does.
	for go_log_root in "$tiup_data" "$tiup_data_b"; do
		[[ -d $go_log_root ]] || {
			echo "standalone $phase TiUP data root missing: $go_log_root" >&2
			exit 1
		}
		while IFS= read -r -d '' log; do
			((go_log_count += 1))
			found=$(grep -c 'main\.nsmgr' "$log" || true)
			nsmgr_count=$((nsmgr_count + found))
		done < <(find "$go_log_root" -type f -name 'tiproxy.log' -print0)
	done
	printf 'phase=%s go_proxy_processes=%s go_component_logs=%s main_nsmgr_lines=%s\n' \
		"$phase" "$go_proxy_count" "$go_log_count" "$nsmgr_count" \
		>>"$run_dir/standalone-no-go.txt"
	if ((go_proxy_count != 0 || go_log_count != 0 || nsmgr_count != 0)); then
		echo "standalone $phase launched Go tiproxy: processes=$go_proxy_count component_logs=$go_log_count nsmgr_lines=$nsmgr_count" >&2
		exit 1
	fi
}
