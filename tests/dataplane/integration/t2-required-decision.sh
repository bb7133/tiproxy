#!/usr/bin/env bash
# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
event_name=${1:?event name is required}
base=${2-}
head=${3:-HEAD}

if [[ $event_name == workflow_dispatch ]]; then
	echo true
	exit 0
fi

# Missing comparison provenance must fail open into the real probe. Silently
# treating it as unrelated would make the required check unsound.
if [[ -z $base || $base =~ ^0+$ ]] || ! git rev-parse --verify "$base^{commit}" >/dev/null 2>&1; then
	echo true
	exit 0
fi

git diff --name-only "$base" "$head" | "$script_dir/t2-required-paths.sh"
