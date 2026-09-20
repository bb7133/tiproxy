#!/usr/bin/env python3
# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Exact comparison of the Go capture and the Rust replay for CP-ADMIN.

Every step is compared on the fields its script entry lists (default: status,
content_type, body). A step carrying "declared" names a divergence the design
document owns; it must still produce a Rust observation, and the comparison
reports it instead of failing. Any undeclared difference fails."""
import json
import sys


def main() -> int:
    script_path, go_path, rust_path = sys.argv[1:4]
    steps = json.load(open(script_path))
    go = json.load(open(go_path))
    rust = json.load(open(rust_path))
    go_rows = {row["name"]: row for row in go["observations"]}
    rust_rows = {row["name"]: row for row in rust["observations"]}
    failures = []
    declared = []
    compared = 0
    for step in steps:
        name = step["name"]
        fields = step.get("compare", ["status", "content_type", "body"])
        if name not in go_rows or name not in rust_rows:
            failures.append(f"{name}: missing observation (go={name in go_rows}, rust={name in rust_rows})")
            continue
        diffs = [
            f"{field}: go={go_rows[name][field]!r} rust={rust_rows[name][field]!r}"
            for field in fields
            if go_rows[name][field] != rust_rows[name][field]
        ]
        if not diffs:
            compared += 1
            if step.get("declared"):
                failures.append(f"{name}: declared divergence {step['declared']!r} no longer differs; remove the declaration")
            continue
        if step.get("declared"):
            declared.append(f"{name} [{step['declared']}]: " + "; ".join(diffs))
        else:
            failures.append(f"{name}: " + "; ".join(diffs))
    go_sums = go["checksums"]
    rust_sums = rust["checksums"]
    for key in ("default", "partial_update", "no_change_update", "namespace_only_update"):
        if go_sums[key] != rust_sums[key]:
            failures.append(f"checksum {key}: go={go_sums[key]} rust={rust_sums[key]}")
    if go_sums["no_change_update"] != go_sums["partial_update"]:
        failures.append("Go no-change update altered the checksum; the scenario is invalid")
    for line in declared:
        print(f"DECLARED {line}")
    for line in failures:
        print(f"FAIL {line}")
    if failures:
        return 1
    print(
        f"PASS: {compared} identical CP-ADMIN observations, {len(declared)} declared divergences, "
        f"4 config checksums identical (default={go_sums['default']})"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
