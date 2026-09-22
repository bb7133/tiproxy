#!/usr/bin/env bash
# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0

# Teardown-phase diagnostics.
#
# collect-diagnostics.sh necessarily runs BEFORE cleanup.sh, so the evidence
# that explains a teardown failure does not exist yet when it runs: cleanup.log
# is created by cleanup.sh itself, and tiup-playground.log is snapshotted while
# the cluster is still healthy, ending at "Cluster is started". A stuck
# playground parent therefore left no trace, and the only way such a failure
# could be closed was to re-run it.
#
# This second pass re-collects just the teardown-relevant files after cleanup
# has finished, into the same redacted diagnostics tree CI already uploads.

set -euo pipefail

if [[ $# -ne 1 ]]; then
	echo "usage: $0 RUN_DIRECTORY" >&2
	exit 2
fi

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
run_dir=$(cd "$1" && pwd)
teardown_dir="$run_dir/diagnostics/teardown"
mkdir -p "$teardown_dir"

for name in cleanup.log tiup-playground.log tiup-playground-b.log; do
	source_file="$run_dir/$name"
	[[ -f $source_file ]] || continue
	awk -f "$script_dir/redact.awk" "$source_file" >"$teardown_dir/$name"
done

# Anything still listening or still alive after owned cleanup is the direct
# evidence for a teardown failure, and is gone by the time CI is inspected.
# A command line can carry an authentication value, so this goes through the
# same redaction as every other collected file rather than straight to disk.
{
	echo "# processes matching this run's tag, after cleanup"
	ps -eo pid,ppid,stat,etime,command 2>/dev/null | grep -F -- "$(basename "$run_dir")" | grep -v grep || echo "(none)"
} 2>&1 | awk -f "$script_dir/redact.awk" >"$teardown_dir/survivors.txt"
