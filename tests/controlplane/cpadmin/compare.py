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


ZERO = (None, "", 0, 0.0, False, [], {})


def zeroish(value):
    """Go omitempty view: zero scalars, and containers whose members are all
    zero (an omitted TOML table versus a rendered table of zero values)."""
    if isinstance(value, dict):
        return all(zeroish(member) for member in value.values())
    if isinstance(value, list):
        return len(value) == 0
    return value in ZERO


def semantic_equal(left, right) -> bool:
    """Decoded-value equality with Go omitempty/nil rules: a key present on one
    side only must be zero-valued there, null and [] (nil vs empty slice) are
    the same, and nested values recurse."""
    if isinstance(left, dict) and isinstance(right, dict):
        for key in set(left) | set(right):
            if key in left and key in right:
                if not semantic_equal(left[key], right[key]):
                    return False
            elif not zeroish(left.get(key, right.get(key))):
                return False
        return True
    if isinstance(left, list) and isinstance(right, list):
        return len(left) == len(right) and all(semantic_equal(a, b) for a, b in zip(left, right))
    if zeroish(left) and zeroish(right):
        return True
    return left == right


def decode(kind: str, text: str):
    if kind == "json_semantic":
        return json.loads(text)
    import tomllib
    return tomllib.loads(text)


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
        diffs = []
        for field in fields:
            if field in ("json_semantic", "toml_semantic"):
                try:
                    equal = semantic_equal(decode(field, go_rows[name]["body"]), decode(field, rust_rows[name]["body"]))
                except Exception as error:  # noqa: BLE001 - report as a diff
                    equal = False
                    diffs.append(f"{field}: undecodable body ({error})")
                    continue
                if not equal:
                    diffs.append(f"{field}: go={go_rows[name]['body']!r} rust={rust_rows[name]['body']!r}")
            elif go_rows[name][field] != rust_rows[name][field]:
                diffs.append(f"{field}: go={go_rows[name][field]!r} rust={rust_rows[name][field]!r}")
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
