#!/usr/bin/env bash
# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

while IFS= read -r path; do
	case "$path" in
		.github/workflows/dataplane-t2-local-route.yml | \
			AGENTS.md | Makefile | go.mod | go.sum | \
			lib/config | lib/config/* | lib/go.mod | lib/go.sum | \
			pkg/controlbridge | pkg/controlbridge/* | \
			pkg/server | pkg/server/* | \
			rust-toolchain.toml | rust | rust/* | \
			tests/dataplane/integration | tests/dataplane/integration/*)
			echo true
			exit 0
			;;
	esac
done

echo false
