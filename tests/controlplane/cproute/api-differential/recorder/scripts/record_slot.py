#!/usr/bin/env python3
# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Prepare the slice-3 environment for one normal-family slot and record one attempt.

Reads normal-slots.tsv: sets TiDB session-token redirection (on/off) and per-instance labels
through env.sh (only instances whose labels differ are restarted), regenerates the environment
manifest, snapshots it next to the output, then runs the built recorder with the slot's policy,
selection, Go routing-rule name, listeners, sources, clients, duration and action script.
Labels are cleared again afterwards only when --clear-labels is given.
"""
import argparse, csv, json, shutil, subprocess, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def sh(*cmd):
    print("+", " ".join(cmd), flush=True)
    subprocess.run(cmd, check=True)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("slot")
    ap.add_argument("--attempt", required=True)
    ap.add_argument("--recorder", required=True, help="binary built by record.py build")
    ap.add_argument("--env", required=True, help="slice3 env.sh")
    ap.add_argument("--root", default=str(Path.home() / ".slice3/cproute"))
    ap.add_argument("--out", required=True)
    ap.add_argument("--clear-labels", action="store_true")
    args = ap.parse_args()
    rows = {r["slot"]: r for r in csv.DictReader(open(HERE / "normal-slots.tsv"), delimiter="\t")}
    r = rows[args.slot]
    sh(args.env, "tidb-redirection", r["redirection"])
    manifest = json.loads(subprocess.run([args.env, "manifest"], check=True, capture_output=True, text=True).stdout)
    current = {t["name"]: t.get("labels", {}) for t in manifest["tidb"]}
    for item in r["labels"].split(";"):
        name, _, labels = item.partition("=")
        wanted = dict(p.split("=", 1) for p in labels.split(",") if p)
        if current.get(name, {}) != wanted:
            sh(args.env, "tidb-relabel", name.removeprefix("tidb-"), labels)
    snapshot = Path(args.out) / f"{args.slot}-{args.attempt}.environment-manifest.json"
    Path(args.out).mkdir(parents=True, exist_ok=True)
    subprocess.run([args.env, "manifest"], check=True, capture_output=True)
    shutil.copyfile(Path(args.root) / "manifest.json", snapshot)
    cmd = [args.recorder, "-slot", r["slot"], "-attempt", args.attempt, "-policy", r["policy"],
           "-selection", r["selection"], "-rule", r["go_rule"], "-listen", r["listen"],
           "-pd", "127.0.0.1:2379", "-duration", r["duration"], "-clients", r["clients"],
           "-held-clients", r["held_clients"], "-out", args.out, "-script", str(HERE / r["script"]),
           "-env", args.env, "-environment-manifest", str(snapshot)]
    if r["sources"]:
        cmd += ["-sources", r["sources"]]
    rc = subprocess.run(cmd).returncode
    if args.clear_labels:
        for item in r["labels"].split(";"):
            name, _, labels = item.partition("=")
            if labels:
                sh(args.env, "tidb-relabel", name.removeprefix("tidb-"), "")
    sys.exit(rc)


if __name__ == "__main__":
    main()
