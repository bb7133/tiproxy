#!/usr/bin/env python3
# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Prepare the slice-3 environment for one normal (N0x) or config/source-change (C0x) slot, record
one attempt, qualify it.

1. Preflight: the family table (normal-slots.tsv / config-slots.tsv) must match the frozen recording
   plan row for row (policy, selection, Go rule spelling, minimum duration, zero held sessions,
   parseable script; C scripts must equal gen_config_scripts.py output); the attempt directory and
   the external manifest snapshot must not exist yet.
2. Set TiDB session-token redirection and per-instance labels through env.sh (only instances whose
   labels differ are restarted).
3. Parse the post-mutation `env.sh manifest` output and assert redirection mode, the exact label map
   (config, runtime /info and PD topology labels when reported), running instances and config
   identity; write exactly that output as the exclusive snapshot.
4. Run the built recorder, then the family validator (validate_normal.py / validate_config.py): the
   raw capture gate (manifest status, clean build, slot/attempt, plan minimums, snapshot hash) AND the
   event-level gate. The verdict is written exclusively to <attempt>/<family>-validation.json; a
   failed or missing verdict exits non-zero and the attempt must not be counted.
In a finally block: an added tidb-4 is removed, an instance whose runtime labels differ from its
config labels is restarted (TiDB cannot delete runtime labels), and with --clear-labels configured
labels are cleared.
"""
import argparse, csv, json, os, subprocess, sys
from pathlib import Path

import gen_config_scripts
import validate_config
import validate_normal

HERE = Path(__file__).resolve().parent
PLAN = HERE.parent / "recording-plan.tsv"
PLAN_RULES = {"all": "", "client-cidr": "client_cidr", "proxy-cidr": "proxy_cidr", "port": "port"}
INSTANCES = [f"tidb-{i}" for i in range(4)]
SOURCE_ERRORS = {"cancelled", "deadline_exceeded", "topology_unavailable"}
FAMILIES = {  # slot prefix -> plan family, validator, verdict file, frozen redirection layer
    "N": ("normal", validate_normal, "normal-validation.json", "off"),
    "C": ("config-source", validate_config, "config-validation.json", "on"),
}
NORMAL_CLIENTS = {f"N{i:02d}": ("64" if i in (2, 3) else "8") for i in range(1, 7)}


def sh(*cmd):
    print("+", " ".join(cmd), flush=True)
    subprocess.run(cmd, check=True)


def preflight(rows, family="normal"):
    problems = []
    redirection = next(v[3] for v in FAMILIES.values() if v[0] == family)
    with open(PLAN) as f:
        plan = {r["trace_id"]: r for r in csv.DictReader(f, delimiter="\t") if r["family"] == family}
    if sorted(plan) != sorted(rows):
        problems.append(f"slots {sorted(rows)} differ from the plan's {family} rows {sorted(plan)}")
    for slot, r in sorted(rows.items()):
        p = plan.get(slot)
        if p is None:
            continue
        expect = {"family": p["family"], "policy": p["balance_policy"], "selection": p["routing_policy"],
                  "go_rule": PLAN_RULES.get(p["routing_rule"], "?" + p["routing_rule"]), "held_clients": "0"}
        if family == "normal":
            expect["clients"] = NORMAL_CLIENTS[slot]
        for k, v in expect.items():
            if r[k] != v:
                problems.append(f"{slot}: {k}={r[k]!r}, plan requires {v!r}")
        if not r["duration"].endswith("s") or int(r["duration"][:-1]) < int(p["min_seconds"]):
            problems.append(f"{slot}: duration {r['duration']} below plan minimum {p['min_seconds']}s")
        if r["redirection"] != redirection:
            problems.append(f"{slot}: {family} family is recorded with redirection {redirection} (frozen N(off) -> F/C(on) layering)")
        if family == "config-source":
            problems += config_row_problems(slot, r)
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


def config_row_problems(slot, r):
    problems = []
    labels = validate_normal.parse_labels(r["labels"])
    if r["source_error"] not in SOURCE_ERRORS:
        problems.append(f"{slot}: source_error must be one of {sorted(SOURCE_ERRORS)}")
    change = ("retain_labels", "join_labels", "restore_labels")
    if r["go_rule"] == "":
        if any(r[k] for k in change):
            problems.append(f"{slot}: MatchAll uses a routing-rule config change, not label changes")
    else:
        parsed = {k: dict(p.split("=", 1) for p in r[k].split(",") if p) for k in change}
        if not all(parsed.values()):
            problems.append(f"{slot}: CIDR/Port slots need retain, join and restore labels")
        elif parsed["restore_labels"] != labels["tidb-3"]:
            problems.append(f"{slot}: restore_labels must equal tidb-3's declared labels {labels['tidb-3']}")
        elif parsed["join_labels"] != labels["tidb-2"] or parsed["retain_labels"] == labels["tidb-3"]:
            problems.append(f"{slot}: join must use tidb-2's group labels and retain must change tidb-3's value")
    if r["lifecycle"] != "router-reset-v1":
        problems.append(f"{slot}: unsupported router lifecycle {r['lifecycle']!r}")
    if (HERE / r["script"]).exists() and (HERE / r["script"]).read_text() != gen_config_scripts.render(r):
        problems.append(f"{slot}: {r['script']} differs from gen_config_scripts.py output")
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
        for key in ("labels", "runtime_labels", "topology_labels"):
            if key in t and t[key] != labels[name]:
                problems.append(f"{name} {key} {t[key]} differ from declared {labels[name]}")
        if t.get("session_token_signing") is not (row["redirection"] == "on"):
            problems.append(f"{name} session_token_signing={t.get('session_token_signing')} but redirection={row['redirection']}")
    return problems


def restore_environment(env):
    """Undo in-trace topology/label mutations even when the capture was interrupted."""
    tidb = json.loads(subprocess.run([env, "manifest"], check=True, capture_output=True, text=True).stdout)["tidb"]
    for t in tidb:
        if t["name"] not in INSTANCES:
            sh(env, "tidb-remove", t["name"].removeprefix("tidb-"))
        elif t.get("runtime_labels") is not None and t["runtime_labels"] != t.get("labels"):
            sh(env, "tidb-restart", t["name"].removeprefix("tidb-"))


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
    if args.slot[:1] not in FAMILIES:
        sys.exit(f"unknown slot family {args.slot}")
    family, validator, verdict_name, _ = FAMILIES[args.slot[:1]]
    rows = validator.slot_rows()
    problems = preflight(rows, family)
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
        problems, contexts = validator.validate_dir(args.slot, args.attempt, attempt_dir, snapshot)
        verdict = {"slot": args.slot, "attempt": args.attempt, "validator": Path(validator.__file__).name,
                   "passed": not problems, "problems": problems, "contexts": contexts}
        write_exclusive(attempt_dir / verdict_name, (json.dumps(verdict, indent=2) + "\n").encode())
        for p in problems:
            print("FAIL:", p)
        print(family, "validation", "PASS" if verdict["passed"] else "FAILED", flush=True)
        sys.exit(rc or (0 if verdict["passed"] else 1))
    finally:
        restore_environment(args.env)
        if args.clear_labels:
            for name in INSTANCES:
                if labels[name]:
                    sh(args.env, "tidb-relabel", name.removeprefix("tidb-"), "")


if __name__ == "__main__":
    main()
