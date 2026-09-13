#!/usr/bin/env python3
# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Prepare, record and qualify one failover-family slot on slice-3."""
import argparse
import csv
import json
import subprocess
import sys
from pathlib import Path

import record_slot as common
import validate_failover

HERE = Path(__file__).resolve().parent
PLAN = HERE.parent / "recording-plan.tsv"


def preflight(rows):
    problems = []
    with open(PLAN) as f:
        plan = {r["trace_id"]: r for r in csv.DictReader(f, delimiter="\t") if r["family"] == "failover"}
    if sorted(plan) != sorted(rows):
        problems.append(f"slots {sorted(rows)} differ from the plan's failover rows {sorted(plan)}")
    for slot, row in sorted(rows.items()):
        frozen = plan.get(slot)
        if frozen is None:
            continue
        expected = {"family": frozen["family"], "policy": frozen["balance_policy"],
                    "selection": frozen["routing_policy"],
                    "go_rule": common.PLAN_RULES.get(frozen["routing_rule"], "?" + frozen["routing_rule"])}
        for key, value in expected.items():
            if row[key] != value:
                problems.append(f"{slot}: {key}={row[key]!r}, plan requires {value!r}")
        try:
            seconds = int(row["duration"].removesuffix("s"))
            if not row["duration"].endswith("s") or seconds < int(frozen["min_seconds"]):
                raise ValueError
        except ValueError:
            problems.append(f"{slot}: duration {row['duration']} below plan minimum {frozen['min_seconds']}s")
            seconds = 0
        try:
            if int(row["held_clients"]) <= 0:
                raise ValueError
        except (TypeError, ValueError):
            problems.append(f"{slot}: failover slot requires held clients")
        if row["redirection"] != "on":
            problems.append(f"{slot}: failover family must be recorded with redirection on")
        if sorted(validate_failover.common.parse_labels(row["labels"])) != common.INSTANCES:
            problems.append(f"{slot}: labels must declare exactly {common.INSTANCES}")
        want_listeners = 2 if row["go_rule"] in ("proxy_cidr", "port") else 1
        if len(row["listen"].split(",")) != want_listeners:
            problems.append(f"{slot}: rule {row['go_rule']!r} needs {want_listeners} listener(s)")
        if row["go_rule"] == "client_cidr" and len(row["sources"].split(",")) != 2:
            problems.append(f"{slot}: client_cidr needs two client source addresses")
        try:
            actions = json.loads((HERE / row["script"]).read_text())
            if not isinstance(actions, list) or not actions:
                raise ValueError("not a non-empty action list")
        except (OSError, ValueError) as error:
            problems.append(f"{slot}: script {row['script']}: {error}")
            continue
        if any(not isinstance(action, dict) for action in actions):
            problems.append(f"{slot}: script actions must be objects")
            continue
        if seconds and any(not isinstance(a.get("at_ms"), int) or a["at_ms"] >= seconds * 1000 for a in actions):
            problems.append(f"{slot}: every action must occur before the {row['duration']} capture deadline")
        selects = [a for a in actions if a.get("kind") == "failover_select"]
        if [a.get("effect_control") for a in selects] != ["refuse", "delay"]:
            problems.append(f"{slot}: two failover_select actions must arm refuse then delay")
        if any(not isinstance(a.get("failover_timeout_seconds"), int)
               or isinstance(a.get("failover_timeout_seconds"), bool)
               or a["failover_timeout_seconds"] <= 0 for a in selects):
            problems.append(f"{slot}: every failover_select requires a positive integer timeout")
        kinds = [a.get("kind") for a in actions]
        for kind, count in (("failover_repeat", 1), ("failover_clear", 2), ("close_delayed_redirect", 1)):
            if kinds.count(kind) != count:
                problems.append(f"{slot}: script requires {count} {kind} action(s), got {kinds.count(kind)}")
        if any(kind in kinds for kind in ("refuse_next_effect", "delay_next_redirect_result")):
            problems.append(f"{slot}: standalone effect controls can race; use failover_select.effect_control")
        env_args = [a.get("args", []) for a in actions if a.get("kind") == "env"]
        if not any(args[:1] == ["tidb-stop"] for args in env_args) or not any(args[:1] == ["tidb-start"] for args in env_args):
            problems.append(f"{slot}: script requires tidb-stop and tidb-start health loss/recovery")
    return problems


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("slot")
    ap.add_argument("--attempt", required=True)
    ap.add_argument("--recorder", required=True)
    ap.add_argument("--env", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--clear-labels", action="store_true")
    args = ap.parse_args()
    rows = validate_failover.slot_rows()
    problems = preflight(rows)
    if args.slot not in rows:
        problems.append(f"unknown slot {args.slot}")
    out = Path(args.out)
    attempt_dir = out / f"{args.slot}-{args.attempt}"
    snapshot = out / f"{args.slot}-{args.attempt}.environment-manifest.json"
    for path in (attempt_dir, snapshot):
        if path.exists():
            problems.append(f"{path} already exists")
    if problems:
        sys.exit("preflight failed:\n  " + "\n  ".join(problems))
    row = rows[args.slot]
    labels = validate_failover.common.parse_labels(row["labels"])
    try:
        common.sh(args.env, "tidb-redirection", row["redirection"])
        current = {t["name"]: t.get("labels", {}) for t in json.loads(
            subprocess.run([args.env, "manifest"], check=True, capture_output=True, text=True).stdout)["tidb"]}
        for name in common.INSTANCES:
            if current.get(name, {}) != labels[name]:
                common.sh(args.env, "tidb-relabel", name.removeprefix("tidb-"),
                          ",".join(f"{key}={value}" for key, value in labels[name].items()))
        raw = subprocess.run([args.env, "manifest"], check=True, capture_output=True).stdout
        problems = common.check_manifest(json.loads(raw), row)
        if problems:
            sys.exit("environment does not match the slot:\n  " + "\n  ".join(problems))
        out.mkdir(parents=True, exist_ok=True)
        common.write_exclusive(snapshot, raw)
        command = [args.recorder, "-slot", row["slot"], "-attempt", args.attempt,
                   "-policy", row["policy"], "-selection", row["selection"], "-rule", row["go_rule"],
                   "-listen", row["listen"], "-pd", "127.0.0.1:2379", "-duration", row["duration"],
                   "-clients", row["clients"], "-held-clients", row["held_clients"], "-out", str(out),
                   "-script", str(HERE / row["script"]), "-env", args.env,
                   "-environment-manifest", str(snapshot)]
        if row["sources"]:
            command += ["-sources", row["sources"]]
        rc = subprocess.run(command).returncode
        if not (attempt_dir / "trace.json").exists():
            sys.exit(f"recorder exited {rc} without a trace")
        problems, contexts = validate_failover.validate_dir(args.slot, args.attempt, attempt_dir, snapshot)
        if rc:
            problems.insert(0, f"recorder exited {rc}")
        verdict = {"slot": args.slot, "attempt": args.attempt, "validator": "validate_failover.py",
                   "recorder_exit_code": rc, "passed": not problems, "problems": problems, "contexts": contexts}
        common.write_exclusive(attempt_dir / "failover-validation.json",
                               (json.dumps(verdict, indent=2) + "\n").encode())
        for problem in problems:
            print("FAIL:", problem)
        print("failover validation", "PASS" if not problems else "FAILED", flush=True)
        sys.exit(rc or (1 if problems else 0))
    finally:
        if args.clear_labels:
            for name in common.INSTANCES:
                if labels[name]:
                    common.sh(args.env, "tidb-relabel", name.removeprefix("tidb-"), "")


if __name__ == "__main__":
    main()
