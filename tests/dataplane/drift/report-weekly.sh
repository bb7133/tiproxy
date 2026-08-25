#!/usr/bin/env bash
# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "${repo_root}"

base_ref="${1:-${PARITY_DRIFT_BASE:-}}"
head_ref="${2:-${PARITY_DRIFT_HEAD:-HEAD}}"
if [[ -z "${base_ref}" ]]; then
  while IFS= read -r candidate; do
    base_ref="${candidate}"
    break
  done < <(sed -n 's/.*`\([0-9a-f]\{40\}\)`.*/\1/p' docs/design/rust-dataplane-parity.md)
fi
if [[ -z "${base_ref}" ]]; then
  echo "unable to read the audited Go commit from docs/design/rust-dataplane-parity.md" >&2
  exit 2
fi

exec go run ./tests/dataplane/drift/cmd/drift \
  -mode report \
  -base "${base_ref}" \
  -head "${head_ref}"
