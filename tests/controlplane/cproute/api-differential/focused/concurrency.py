#!/usr/bin/env python3
# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Run and fail-closed validate the fixed concurrency focused suite."""

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
    expected = [(case, schedule["id"]) for case in spec["cases"]
                for schedule in spec["schedules"]]
    rows = result.get("rows")
    if not isinstance(rows, list):
        problems.append("rows is not a list")
        return problems
    actual = [(row.get("case"), row.get("schedule"))
              if isinstance(row, dict) else (None, None) for row in rows]
    if actual != expected:
        problems.append("case/schedule matrix differs from fixed specification")
    for index, row in enumerate(rows):
        label = f"row {index}"
        if not isinstance(row, dict):
            problems.append(f"{label} is not an object")
            continue
        history = row.get("history")
        if not isinstance(history, list) or len(history) != 8:
            problems.append(f"{label} does not contain eight public calls")
        else:
            for actor in ("A", "B"):
                steps = sorted(event.get("step") for event in history
                               if isinstance(event, dict) and event.get("actor") == actor)
                if steps != [0, 1, 2, 3]:
                    problems.append(f"{label} actor {actor} steps are not 0..3")
            if any(not isinstance(event, dict)
                   or not isinstance(event.get("call"), str)
                   or not isinstance(event.get("outcome"), str)
                   or event["outcome"].startswith("error:") for event in history):
                problems.append(f"{label} has an invalid public call result")
        if row.get("violations") != []:
            problems.append(f"{label} reports accounting violations")
        if engine == "go":
            if row.get("final_conn_count") != 0:
                problems.append(f"{label} retains live Go connections")
            if row.get("retained_backends") != []:
                problems.append(f"{label} retains Go backends")
        else:
            accounts = row.get("final_accounts")
            if not isinstance(accounts, dict) or set(accounts) != {
                    "default/127.0.0.1:4000", "default/127.0.0.1:4001"}:
                problems.append(f"{label} has incomplete Rust accounting")
            elif any(counts != [0, 0, 0, 0] for counts in accounts.values()):
                problems.append(f"{label} retains Rust accounting")
    detected = result.get("negative_control_detected")
    if not isinstance(detected, list) or not detected:
        problems.append("negative control did not detect invalid history/accounting")
    return problems


def run_negative_mutations(engine, result, spec):
    mutations = []
    truncated = copy.deepcopy(result)
    truncated["rows"] = truncated.get("rows", [])[:-1]
    mutations.append(("drop-fixed-row", truncated))
    leaked = copy.deepcopy(result)
    if leaked.get("rows"):
        if engine == "go":
            leaked["rows"][0]["final_conn_count"] = 1
        else:
            leaked["rows"][0]["final_accounts"]["default/127.0.0.1:4000"] = [1, 0, 0, 0]
    mutations.append(("leak-final-accounting", leaked))
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
    spec_path = HERE / "concurrency.json"
    spec = json.loads(spec_path.read_text())
    schedules = spec["schedules"]
    engines = {
        "go": (["go", "test", "-race", "-count=1", "-run", "^TestAPIConcurrencyFocused$", "./pkg/balance/router"], ROOT),
        "rust": (["cargo", "test", "--locked", "-p", "control-router", "--lib", "--",
                  "tests::concurrency::api_concurrency_focused", "--exact", "--ignored"], ROOT / "rust"),
    }
    summary = {
        "suite": spec["suite"],
        "spec_sha256": hashlib.sha256(spec_path.read_bytes()).hexdigest(),
        "cases": spec["cases"],
        "schedules": [row["id"] for row in schedules],
        "engines": {},
    }
    ok = len(schedules) == 16 and len({row["id"] for row in schedules}) == 16
    ok = ok and all(len(row["release"]) == 8 and row["release"].count("A") == 4
                    and row["release"].count("B") == 4 for row in schedules)
    for engine, (cmd, cwd) in engines.items():
        output = (args.output / f"{engine}.json").resolve()
        output.unlink(missing_ok=True)
        env = dict(os.environ, CPROUTE_CONCURRENCY_OUTPUT=str(output))
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
