#!/usr/bin/env bash
# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=versions.env
source "$script_dir/versions.env"

if ! command -v tiup >/dev/null 2>&1; then
	echo "TiUP is required to preinstall integration components" >&2
	exit 1
fi

# A fresh runner gives both playground processes one shared TIUP_HOME. Install
# every component in separate foreground invocations so signed manifests and
# the component cache are complete before those processes can read them in
# parallel. `tiup install` is idempotent for an already installed version.
components=(playground pd tikv tidb)
versions=("v${TIUP_VERSION}" "$TIDB_VERSION" "$TIDB_VERSION" "$TIDB_VERSION")
for index in "${!components[@]}"; do
	tiup install "${components[$index]}:${versions[$index]}"
done
# Do not rely only on install's exit status: fail closed unless the shared
# profile reports every exact frozen version as installed.
for index in "${!components[@]}"; do
	component=${components[$index]}
	version=${versions[$index]}
	installed=$(tiup list "$component" --installed)
	if ! awk -v version="$version" \
		'$1 == version && $2 == "YES" { found = 1 } END { exit(found ? 0 : 1) }' \
		<<<"$installed"; then
		echo "TiUP component $component:$version is not installed after prewarm" >&2
		printf '%s\n' "$installed" >&2
		exit 1
	fi
done
