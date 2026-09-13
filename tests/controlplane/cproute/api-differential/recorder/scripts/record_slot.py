#!/usr/bin/env python3
# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Prepare the slice-3 environment for one normal-family slot, record one attempt, qualify it.

1. Preflight: normal-slots.tsv must match the frozen recording plan row for row (policy, selection,
   Go rule spelling, minimum duration, zero held sessions, parseable script); the attempt directory
   and the external manifest snapshot must not exist yet.
2. Set TiDB session-token redirection and per-instance labels through env.sh (only instances whose
   labels differ are restarted).
3. Parse the post-mutation `env.sh manifest` output and assert redirection mode, the exact label map,
   running instances and config identity; write exactly that output as the exclusive snapshot.
4. Run the built recorder, then the event-level validator (validate_normal.py). The verdict is
   written exclusively to <attempt>/normal-validation.json; a failed or missing verdict exits non-zero
   and the attempt must not be counted.
Labels are restored to empty in a finally block when --clear-labels is given.
"""
import argparse, csv, json, os, subprocess, sys
from pathlib import Path

import validate_normal

HERE = Path(__file__).resolve().parent
PLAN = HERE.parent / "recording-plan.tsv"
PLAN_RULES = {"all": "", "client-cidr": "client_cidr", "proxy-cidr": "proxy_cidr", "port": "port"}
INSTANCES = [f"tidb-{i}" for i in range(4)]


def sh(*cmd):
    print("+", " ".join(cmd), flush=True)
    subprocess.run(cmd, check=True)


def preflight(rows):
    problems = []
    with open(PLAN) as f:
        plan = {r["trace_id"]: r for r in csv.DictReader(f, delimiter="\t") if r["family"] == "normal"}
    if sorted(plan) != sorted(rows):
        problems.append(f"slots {sorted(rows)} differ from the plan's normal rows {sorted(plan)}")
    for slot, r in sorted(rows.items()):
        p = plan.get(slot)
        if p is None:
            continue
        expect = {"family": p["family"], "policy": p["balance_policy"], "selection": p["routing_policy"],
                  "go_rule": PLAN_RULES.get(p["routing_rule"], "?" + p["routing_rule"]), "held_clients": "0"}
        for k, v in expect.items():
            if r[k] != v:
                problems.append(f"{slot}: {k}={r[k]!r}, plan requires {v!r}")
        if not r["duration"].endswith("s") or int(r["duration"][:-1]) < int(p["min_seconds"]):
            problems.append(f"{slot}: duration {r['duration']} below plan minimum {p['min_seconds']}s")
        if r["redirection"] not in ("on", "off"):
            problems.append(f"{slot}: redirection must be on or off")
        if sorted(validate_normal.parse_labels(r["labels"])) != INSTANCES:
            problems.append(f"{slot}: labels must declare exactly {INSTANCES}")
        try:
            actions = json.loads((HERE / r["script"]).read_text())
            if not isinstance(actions, list) or not actions:
                problems.append(f"{slot}: script {r['script']} is not a non-empty action list")
        except (OSError, ValueError) as err:
            problems.append(f"{slot}: script {r['script']}: {err}")
        want_listeners = 2 if r["go_rule"] in ("proxy_cidr", "port") else 1
        if len(r["listen"].split(",")) != want_listeners:
            problems.append(f"{slot}: rule {r['go_rule']!r} needs {want_listeners} listener(s)")
        if r["go_rule"] == "client_cidr" and len(r["sources"].split(",")) != 2:
            problems.append(f"{slot}: client_cidr needs two client source addresses")
    return problems


def check_manifest(manifest, row):
    problems = []
    labels = validate_normal.parse_labels(row["labels"])
    tidb = {t["name"]: t for t in manifest.get("tidb", [])}
    if sorted(tidb) != INSTANCES:
        problems.append(f"manifest TiDB instances {sorted(tidb)} differ from {INSTANCES}")
    for name in INSTANCES:
        t = tidb.get(name)
        if t is None:
            continue
        if not t.get("pid"):
            problems.append(f"{name} is not running")
        if not t.get("config_sha256"):
            problems.append(f"{name} has no config identity")
        if t.get("labels") != labels[name]:
            problems.append(f"{name} labels {t.get('labels')} differ from declared {labels[name]}")
        if t.get("session_token_signing") is not (row["redirection"] == "on"):
            problems.append(f"{name} session_token_signing={t.get('session_token_signing')} but redirection={row['redirection']}")
    return problems


def write_exclusive(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("slot")
    ap.add_argument("--attempt", required=True)
    ap.add_argument("--recorder", required=True, help="binary built by record.py build")
    ap.add_argument("--env", required=True, help="slice3 env.sh")
    ap.add_argument("--out", required=True)
    ap.add_argument("--clear-labels", action="store_true")
    args = ap.parse_args()
    rows = validate_normal.slot_rows()
    problems = preflight(rows)
    if args.slot not in rows:
        problems.append(f"unknown slot {args.slot}")
    out = Path(args.out)
    attempt_dir = out / f"{args.slot}-{args.attempt}"
    snapshot = out / f"{args.slot}-{args.attempt}.environment-manifest.json"
    for p in (attempt_dir, snapshot):
        if p.exists():
            problems.append(f"{p} already exists")
    if problems:
        sys.exit("preflight failed:\n  " + "\n  ".join(problems))
    r = rows[args.slot]
    labels = validate_normal.parse_labels(r["labels"])
    try:
        sh(args.env, "tidb-redirection", r["redirection"])
        current = {t["name"]: t.get("labels", {}) for t in json.loads(
            subprocess.run([args.env, "manifest"], check=True, capture_output=True, text=True).stdout)["tidb"]}
        for name in INSTANCES:
            if current.get(name, {}) != labels[name]:
                sh(args.env, "tidb-relabel", name.removeprefix("tidb-"), ",".join(f"{k}={v}" for k, v in labels[name].items()))
        raw = subprocess.run([args.env, "manifest"], check=True, capture_output=True).stdout
        problems = check_manifest(json.loads(raw), r)
        if problems:
            sys.exit("environment does not match the slot:\n  " + "\n  ".join(problems))
        out.mkdir(parents=True, exist_ok=True)
        write_exclusive(snapshot, raw)
        cmd = [args.recorder, "-slot", r["slot"], "-attempt", args.attempt, "-policy", r["policy"],
               "-selection", r["selection"], "-rule", r["go_rule"], "-listen", r["listen"],
               "-pd", "127.0.0.1:2379", "-duration", r["duration"], "-clients", r["clients"],
               "-held-clients", r["held_clients"], "-out", str(out), "-script", str(HERE / r["script"]),
               "-env", args.env, "-environment-manifest", str(snapshot)]
        if r["sources"]:
            cmd += ["-sources", r["sources"]]
        rc = subprocess.run(cmd).returncode
        if not (attempt_dir / "trace.json").exists():
            sys.exit(f"recorder exited {rc} without a trace")
        problems, contexts = validate_normal.validate_dir(args.slot, attempt_dir)
        verdict = {"slot": args.slot, "attempt": args.attempt, "validator": "validate_normal.py",
                   "passed": not problems, "problems": problems, "contexts": contexts}
        write_exclusive(attempt_dir / "normal-validation.json", (json.dumps(verdict, indent=2) + "\n").encode())
        for p in problems:
            print("FAIL:", p)
        print("normal validation", "PASS" if not problems else "FAILED", flush=True)
        sys.exit(rc or (1 if problems else 0))
    finally:
        if args.clear_labels:
            for name in INSTANCES:
                if labels[name]:
                    sh(args.env, "tidb-relabel", name.removeprefix("tidb-"), "")


if __name__ == "__main__":
    main()
