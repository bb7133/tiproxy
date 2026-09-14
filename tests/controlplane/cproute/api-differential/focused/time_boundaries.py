#!/usr/bin/env python3
# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Run and fail-closed validate the fixed time-boundaries focused suite."""

import argparse
import copy
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[5]
HERE = Path(__file__).resolve().parent


def run(cmd, env, cwd):
    print("+", " ".join(cmd), flush=True)
    try:
        return subprocess.run(cmd, cwd=cwd, env=env).returncode
    except OSError as error:
        print(f"cannot execute {cmd[0]}: {error}", file=sys.stderr, flush=True)
        return 127


def load_manifest(path):
    if not path.exists():
        return None, ["no engine manifest"]
    try:
        result = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as error:
        return None, [f"invalid engine manifest: {error}"]
    if not isinstance(result, dict):
        return None, ["engine manifest is not an object"]
    return result, []


def validate_result(engine, result, spec):
    problems = []
    if result.get("engine") != engine:
        problems.append(f"engine {result.get('engine')!r} != {engine!r}")
    if result.get("suite") != spec["suite"]:
        problems.append(f"suite {result.get('suite')!r} != {spec['suite']!r}")
    expected = [(case["name"], position["name"], position["expected_effect"])
                for case in spec["cases"] for position in spec["positions"]]
    rows = result.get("rows")
    if not isinstance(rows, list):
        problems.append("rows is not a list")
        return problems
    actual = [(row.get("case"), row.get("position"), row.get("effect"))
              if isinstance(row, dict) else (None, None, None) for row in rows]
    if actual != expected:
        problems.append("12-row API/effect matrix differs from fixed specification")
    for index, row in enumerate(rows):
        label = f"row {index}"
        if not isinstance(row, dict):
            problems.append(f"{label} is not an object")
            continue
        if row.get("effect") is not row.get("expected_effect"):
            problems.append(f"{label} effect differs from declared expectation")
        if row.get("violations") != []:
            problems.append(f"{label} reports time-boundary violations")
        history = row.get("public_history")
        if not isinstance(history, list) or not history or not all(
                isinstance(event, str) and event for event in history):
            problems.append(f"{label} lacks public API/effect history")
    detected = result.get("negative_control_detected")
    if not isinstance(detected, list) or not detected:
        problems.append("negative control did not detect an inverted boundary")
    return problems


def run_negative_mutations(engine, result, spec):
    mutations = []
    truncated = copy.deepcopy(result)
    truncated["rows"] = truncated.get("rows", [])[:-1]
    mutations.append(("drop-fixed-row", truncated))
    inverted = copy.deepcopy(result)
    if inverted.get("rows"):
        equal = next((row for row in inverted["rows"] if row.get("position") == "equal"), None)
        if equal is not None:
            equal["effect"] = not equal.get("effect")
    mutations.append(("invert-equal-boundary", inverted))
    verdicts = []
    for name, mutation in mutations:
        mutation_problems = validate_result(engine, mutation, spec)
        verdicts.append({"name": name, "detected": bool(mutation_problems),
                         "problems": mutation_problems})
    return verdicts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    spec_path = HERE / "time-boundaries.json"
    spec = json.loads(spec_path.read_text())
    engines = {
        "go": (["go", "test", "-count=1", "-run", "^TestAPITimeBoundaries$", "./pkg/balance/router"], ROOT),
        "rust": (["cargo", "test", "--locked", "-p", "control-router", "--lib", "--",
                  "tests::time_boundaries::api_time_boundaries", "--exact", "--ignored"], ROOT / "rust"),
    }
    expected = [(case["name"], position["name"], position["expected_effect"])
                for case in spec["cases"] for position in spec["positions"]]
    summary = {
        "suite": spec["suite"],
        "spec_sha256": hashlib.sha256(spec_path.read_bytes()).hexdigest(),
        "cases": [row["name"] for row in spec["cases"]],
        "positions": [row["name"] for row in spec["positions"]],
        "engines": {},
    }
    ok = len(expected) == 12
    for engine, (cmd, cwd) in engines.items():
        output = (args.output / f"{engine}.json").resolve()
        output.unlink(missing_ok=True)
        env = dict(os.environ, CPROUTE_TIME_OUTPUT=str(output))
        rc = run(cmd, env, cwd)
        result, problems = load_manifest(output)
        if rc:
            problems.append(f"test exited {rc}")
        negative_mutations = []
        if result is not None:
            problems.extend(validate_result(engine, result, spec))
            negative_mutations = run_negative_mutations(engine, result, spec)
            if not all(row["detected"] for row in negative_mutations):
                problems.append("runner negative mutation escaped validation")
        summary["engines"][engine] = {
            "rc": rc,
            "problems": problems,
            "manifest": output.name,
            "negative_mutations": negative_mutations,
        }
        ok = ok and not problems
    summary["status"] = "passed" if ok else "failed"
    (args.output / "manifest.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary))
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
