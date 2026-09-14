#!/usr/bin/env python3
# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Generate the config/source-change action scripts C01..C06 from config-slots.tsv.

Every slot schedules, in order (logical milliseconds):
  valid config update (re-affirms the slot's balance policy/routing policy) and an invalid
  public config (validator rejection); one named source error window and its recovery;
  a group-routing input change; backend addition (tidb-4) and removal.

Group-routing input change (agreed with the reviewer):
  MatchAll slots  submit a valid runtime balance.routing-rule change, which the Go router ignores
                  because the match type is fixed at Init, then restore the original rule.
  CIDR/Port slots retain: replace the routing label of an already grouped backend (tidb-3) with
                  another group's value, which must keep its original group; join: the added
                  tidb-4 starts without labels and joins a group once its label is set; the
                  replaced label of tidb-3 is restored before the end.
After every topology and label change has completed, the lifecycle actions retain a
real MySQL connection on a temporarily unique backend and keep that exclusion config
through the reset boundary. At router_reset execution time the recorder atomically
replaces the exclusions with failover of that unique assignment. Thus ordinary
Resource or Location balancing has neither another destination nor a config-clear
window in which to move the lifecycle session. The action creates one
delayed successful redirect, closes the old router, constructs a fresh router,
republishes the latest health input, rehydrates every surviving connection, looks
up the pending target, then releases the real callback.

Run with --check to verify the committed scripts equal the generated ones.
"""
import argparse, csv, json, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def rows():
    with open(HERE / "config-slots.tsv") as f:
        return [r for r in csv.DictReader(f, delimiter="\t")]


def actions(r):
    a = []

    def add(at, kind, **kw):
        a.append({"at_ms": at, "kind": kind, **kw})

    def env(at, *args, checkpoint):
        add(at, "env", args=list(args))
        add(at + 1, "await_env")
        add(checkpoint, "checkpoint")

    def lifecycle():
        listeners = r["listen"].split(",")
        if r["go_rule"] == "":
            excluded = [f"default/127.0.0.1:400{i}" for i in range(1, 5)]
            listener, source = listeners[0], ""
        else:
            excluded = ["default/127.0.0.1:4003", "default/127.0.0.1:4004"]
            listener = listeners[1] if r["go_rule"] in ("proxy_cidr", "port") else listeners[0]
            source = "127.0.0.1" if r["go_rule"] == "client_cidr" else ""
        add(312000, "lifecycle_open", backends=excluded, listener=listener, source=source,
            timeout_ms=10000)
        add(320000, "router_reset", timeout_ms=15000)
        add(350000, "checkpoint")

    add(10000, "checkpoint")
    add(15000, "config", toml=f'[balance]\npolicy = "{r["policy"]}"\nrouting-policy = "{r["selection"]}"\n')
    add(20000, "config", toml='[balance]\npolicy = "invalid-policy"\n')
    add(25000, "checkpoint")
    add(30000, "source_error", error=r["source_error"])
    add(40000, "source_error", error="")
    add(50000, "checkpoint")
    if r["go_rule"] == "":
        add(55000, "config", toml='[balance]\nrouting-rule = "port"\n')
        add(80000, "checkpoint")
        add(85000, "config", toml='[balance]\nrouting-rule = ""\n')
        add(100000, "checkpoint")
    else:
        env(55000, "tidb-set-labels", "3", r["retain_labels"], checkpoint=100000)
    env(105000, "tidb-add", checkpoint=150000)
    if r["go_rule"] != "":
        env(155000, "tidb-set-labels", "4", r["join_labels"], checkpoint=190000)
    lifecycle()
    env(205000, "tidb-remove", "4", checkpoint=280000)
    if r["go_rule"] != "":
        env(285000, "tidb-set-labels", "3", r["restore_labels"], checkpoint=310000)
    return sorted(a, key=lambda item: item["at_ms"])


def render(r):
    return json.dumps(actions(r), indent=1) + "\n"


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()
    stale = []
    for r in rows():
        path = HERE / r["script"]
        text = render(r)
        if args.check:
            if not path.exists() or path.read_text() != text:
                stale.append(r["script"])
        else:
            path.write_text(text)
    if stale:
        sys.exit(f"generated scripts differ: {stale}")


if __name__ == "__main__":
    main()
