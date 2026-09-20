#!/usr/bin/env python3
# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Exact comparison of the Go and Rust `tiproxyctl` captures (CP-ADMIN 4d).

Every command is compared on its exit code and stdout, for the plaintext and
the TLS (--insecure) run. A command's "compare" selects "exact" (default),
"json_semantic" or "toml_semantic" for the stdout body, with the same Go
omitempty view as the CP-ADMIN comparator. Declared divergences (script
"declared": {"<side>/<name>": "<owner>"}) must still differ."""
import json
import sys

try:
    import tomllib
except ImportError:  # pragma: no cover - the runner picks a modern interpreter
    tomllib = None

ZERO = (None, "", 0, 0.0, False, [], {})


def zeroish(value):
    if isinstance(value, dict):
        return all(zeroish(member) for member in value.values())
    if isinstance(value, list):
        return len(value) == 0
    return value in ZERO


def semantic_equal(left, right) -> bool:
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


def decode(mode: str, text: str):
    if mode == "json_semantic":
        return json.loads(text)
    return tomllib.loads(text)


def main() -> int:
    script_path, go_path, rust_path = sys.argv[1:4]
    script = json.load(open(script_path))
    go = json.load(open(go_path))
    rust = json.load(open(rust_path))
    declared = script.get("declared", {})
    failures, notes, compared = [], [], 0
    for side in ("plain", "tls"):
        go_rows = {row["name"]: row for row in go[side]}
        rust_rows = {row["name"]: row for row in rust[side]}
        for command in script["commands"]:
            name = command["name"]
            key = f"{side}/{name}"
            if name not in go_rows or name not in rust_rows:
                failures.append(f"{key}: missing (go={name in go_rows}, rust={name in rust_rows})")
                continue
            g, r = go_rows[name], rust_rows[name]
            diffs = []
            if g["exit_code"] != r["exit_code"]:
                diffs.append(f"exit_code go={g['exit_code']} rust={r['exit_code']}")
            mode = command.get("compare", "exact")
            if mode == "exact":
                if g["stdout"] != r["stdout"]:
                    diffs.append(f"stdout go={g['stdout']!r} rust={r['stdout']!r}")
            else:
                try:
                    equal = semantic_equal(decode(mode, g["stdout"]), decode(mode, r["stdout"]))
                except Exception as error:  # noqa: BLE001
                    equal = False
                    diffs.append(f"{mode}: undecodable stdout ({error}) go={g['stdout']!r} rust={r['stdout']!r}")
                if not equal and not diffs:
                    diffs.append(f"{mode}: go={g['stdout']!r} rust={r['stdout']!r}")
            if not diffs:
                compared += 1
                if key in declared:
                    failures.append(f"{key}: declared divergence {declared[key]!r} no longer differs; remove the declaration")
                continue
            if key in declared:
                notes.append(f"{key} [{declared[key]}]: " + "; ".join(diffs))
            else:
                failures.append(f"{key}: " + "; ".join(diffs))
    for line in notes:
        print(f"DECLARED {line}")
    for line in failures:
        print(f"FAIL {line}")
    if failures:
        return 1
    print(f"PASS: {compared} identical tiproxyctl observations across plaintext and TLS, {len(notes)} declared divergences")
    return 0


if __name__ == "__main__":
    sys.exit(main())
