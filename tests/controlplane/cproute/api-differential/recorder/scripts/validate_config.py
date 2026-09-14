#!/usr/bin/env python3
# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Event-level qualification of one config/source-change capture (frozen contract section 3).

Reads trace.json with the aligned go.json and fails unless every required outcome is present in
recorded events (whole health snapshots are the fact source for labels and membership):

- valid config update (config outcome ok) and invalid public-config rejection (invalid_config);
- a named source error: every next between a source_error input and the following health result
  reports exactly that source error, and a successful next follows the window (recovery);
- backend addition and removal: an undeclared backend appears healthy and later leaves health;
  MatchAll selects it while present; CIDR/Port never select it before its routing label appears
  and select it from the joined group's context afterwards (join);
- group-routing input change:
  MatchAll: an accepted runtime balance.routing-rule change after which every next is ok until
            the original rule is restored (the router's match type is fixed at Init);
  CIDR/Port: a grouped backend's routing label changes in health, after which it is still
            selected from its original context and never from the context of its new value (retain);
- one explicit router_reset with settled live sessions, a fresh health publication, successful
  rehydration of every survivor, lookup of the pending redirect target, and its late callback.

The initial health labels must equal the slot's declared map. The raw capture gate is shared with
validate_normal.raw_gate; normal-validation semantics are unchanged.
"""
import argparse, csv, json, sys
from collections import defaultdict
from pathlib import Path

import validate_normal as vn

HERE = Path(__file__).resolve().parent
ROUTING_LABELS = ("cidr", "tiproxy-port")


def slot_rows():
    with open(HERE / "config-slots.tsv") as f:
        return {r["slot"]: r for r in csv.DictReader(f, delimiter="\t")}


def addr(backend_id):
    return backend_id.rpartition("/")[2]


def routing_values(labels):
    return {k: labels[k] for k in ROUTING_LABELS if k in labels}


def validate(row, trace, go):
    rule = row["go_rule"]
    declared = {vn.instance_address(n): l for n, l in vn.parse_labels(row["labels"]).items()}
    events = trace["events"]
    if len(events) != len(go):
        return [f"trace has {len(events)} events but go.json has {len(go)}"], {}
    for i, (e, g) in enumerate(zip(events, go)):
        if g["seq"] != i or g["op"] != e["op"] or g["session"] != e.get("session", ""):
            return [f"trace/go misaligned at {i}"], {}

    problems = []
    s = defaultdict(int)
    context = {}
    health_seen = False
    present = {}                  # address -> labels in the latest whole health snapshot
    healthy = set()
    first_labels = {}             # address -> routing values when first grouped (original group)
    changed = {}                  # address -> routing values after a label change
    added = set()
    added_labeled_at = {}
    removed = set()
    source_window = None          # identity while inside a source-error window
    source_done = False           # source window ended; wait through no-match nexts for recovery
    rule_change = None            # "active" | "restored"
    config_ok = config_invalid = 0
    sessions, pending, active = set(), set(), set()
    reset_survivors = None
    rehydrated = set()
    reset_at = health_after_reset = lookup_at = callback_at = None
    accepted_refs = {}
    settled = set()
    accepted_redirects = 0
    lifecycle_ref = None
    reset_ref = None

    def ctx_routes(ctx, values):
        return vn.routed(rule, ctx, values)

    for i, (e, g) in enumerate(zip(events, go)):
        op, out = e["op"], g["outcome"]
        for effect in g.get("effects", []):
            if effect.get("kind") == "redirect" and effect.get("accepted"):
                accepted_redirects += 1
                accepted_refs[f"redirect/{accepted_redirects}"] = effect
        if op == "health":
            backends = [b for b in e.get("backends") or [] if b.get("cluster", "default") == "default"]
            snapshot = {b["address"]: b.get("labels") or {} for b in backends}
            if not health_seen:
                if set(snapshot) != set(declared):
                    problems.append(f"initial health inventory is {sorted(snapshot)}, slot declares {sorted(declared)}")
                for a in sorted(set(snapshot) & set(declared)):
                    if snapshot[a] != declared[a]:
                        problems.append(f"initial health labels of {a} are {snapshot[a]}, slot declares {declared[a]}")
                health_seen = True
            if reset_at is not None and i > reset_at and health_after_reset is None:
                health_after_reset = i
            if reset_at is None:
                for a, labels in snapshot.items():
                    values = routing_values(labels)
                    if a not in declared and a not in added:
                        added.add(a)
                    if values and a not in first_labels:
                        first_labels[a] = values
                        if a in added:
                            added_labeled_at[a] = i
                    elif a in first_labels and values != first_labels[a]:
                        changed[a] = values
                for a in list(present):
                    if a not in snapshot and a in added:
                        removed.add(a)
            present = snapshot
            healthy = {b["address"] for b in backends if b.get("healthy", True)}
            if source_window is not None:
                source_window, source_done = None, True
        elif op == "source_error":
            identity = e.get("error", "")
            if identity in ("", "unclassified_source_error"):
                problems.append(f"unnamed source error at {i}")
            source_window = identity
            s["source_error_inputs"] += 1
        elif op == "config":
            toml = e.get("toml", "")
            if out == "ok":
                config_ok += 1
                if "routing-rule" in toml:
                    rule_change = "active" if 'routing-rule = ""' not in toml else ("restored" if rule_change else None)
                    s["rule_change_configs"] += 1
            elif out == "invalid_config":
                config_invalid += 1
        elif op == "open":
            context[e["session"]] = vn.context_key(rule, e)
            sessions.add(e["session"])
        elif op == "next":
            ctx = context[e["session"]]
            backend = addr(g["backend"]) if out == "ok" else ""
            if source_window is not None:
                s["source_window_next"] += 1
                if out != f"source_error:{source_window}":
                    s["source_window_other"] += 1
            elif source_done and out == "ok":
                # CIDR/Port captures intentionally keep no-match clients busy.
                # Their first post-window next may correctly report no_backend;
                # that does not disprove recovery for a routed context.
                s["source_recovery_ok"] += 1
                source_done = False
            if rule == "" and rule_change == "active":
                s["rule_change_next"] += 1
                if out != "ok":
                    s["rule_change_not_ok"] += 1
                elif backend not in healthy:
                    s["rule_change_unhealthy"] += 1
            if out != "ok":
                continue
            pending.add(e["session"])
            if backend in added and backend in present:
                if rule == "":
                    s["added_selected"] += 1
                elif backend not in added_labeled_at:
                    s["added_selected_unlabeled"] += 1
                elif ctx_routes(ctx, first_labels[backend]):
                    s["added_joined_selected"] += 1
                else:
                    s["added_selected_outside_group"] += 1
            if backend in changed:
                if ctx_routes(ctx, first_labels[backend]):
                    s["retained_selected"] += 1
                if ctx_routes(ctx, changed[backend]) and not ctx_routes(ctx, first_labels[backend]):
                    s["retained_selected_new_context"] += 1
        elif op == "finish":
            pending.discard(e["session"])
            if e.get("success"):
                active.add(e["session"])
        elif op == "close":
            session = g.get("session", e.get("session", ""))
            sessions.discard(session)
            pending.discard(session)
            active.discard(session)
            settled.update(ref for ref, effect in accepted_refs.items()
                           if effect.get("session") == session)
        elif op == "router_reset":
            if reset_at is not None:
                problems.append(f"second router_reset at {i}")
            if pending or not active or sessions != active or out != "ok":
                problems.append(f"router_reset at {i} lacks settled live assignments for every open session")
            outstanding = sorted(set(accepted_refs) - settled)
            if len(outstanding) != 1:
                problems.append(f"router_reset at {i} requires exactly one pending accepted redirect, got {outstanding}")
            else:
                reset_ref = outstanding[0]
            reset_at = i
            reset_survivors = set(active)
            active.clear()
        elif op == "rehydrate" and out == "ok":
            s["rehydrate_ok"] += 1
            session = g.get("session", e.get("session", ""))
            if reset_at is None or health_after_reset is None or i <= health_after_reset:
                problems.append(f"rehydrate at {i} is not after reset and fresh health")
            if reset_survivors is None or session not in reset_survivors:
                problems.append(f"rehydrate at {i} does not name a reset survivor")
            rehydrated.add(session)
            active.add(session)
            if e.get("effect_ref"):
                lifecycle_ref = e["effect_ref"]
                effect = accepted_refs.get(lifecycle_ref)
                if (lifecycle_ref != reset_ref or effect is None
                        or effect.get("session") != session or lifecycle_ref in settled):
                    problems.append(f"rehydrate at {i} lacks its pending accepted redirect")
        elif op == "lookup":
            s["lookup"] += 1
            lookup_at = i
            if (reset_survivors is None or rehydrated != reset_survivors
                    or e.get("effect_ref") != lifecycle_ref or out != "ok"):
                problems.append(f"lookup at {i} is not after complete effect-relative rehydration")
        elif op == "redirect_result":
            ref = e.get("effect_ref")
            if ref:
                settled.add(ref)
            if ref == lifecycle_ref and e.get("success") is True and out == "ok":
                callback_at = i

    if not config_ok:
        problems.append("no accepted config update")
    if not config_invalid:
        problems.append("no invalid public-config rejection")
    if not s["source_error_inputs"] or not s["source_window_next"]:
        problems.append("no named source error observed by a next")
    if s["source_window_other"]:
        problems.append(f"{s['source_window_other']} next inside a source-error window did not report that source error")
    if not s["source_recovery_ok"]:
        problems.append("no successful next after the source-error window")
    if not added:
        problems.append("no backend addition in health")
    if not removed:
        problems.append("no added backend removed from health")
    if rule == "":
        if not s["added_selected"]:
            problems.append("MatchAll never selected the added backend")
        if not s["rule_change_configs"] or rule_change != "restored":
            problems.append("no accepted routing-rule change followed by restoration")
        if not s["rule_change_next"]:
            problems.append("no next while the routing-rule change was active")
        if s["rule_change_not_ok"] or s["rule_change_unhealthy"]:
            problems.append(f"routing changed while the runtime routing-rule change was active "
                            f"(not ok {s['rule_change_not_ok']}, unhealthy target {s['rule_change_unhealthy']})")
    else:
        if s["added_selected_unlabeled"]:
            problems.append(f"added backend selected {s['added_selected_unlabeled']} times before its routing label")
        if s["added_selected_outside_group"]:
            problems.append(f"added backend selected {s['added_selected_outside_group']} times outside its joined group")
        if not s["added_joined_selected"]:
            problems.append("added backend never selected after joining a group")
        if not changed:
            problems.append("no grouped backend routing label change in health")
        if not s["retained_selected"]:
            problems.append("changed backend not selected from its original group context")
        if s["retained_selected_new_context"]:
            problems.append(f"changed backend selected {s['retained_selected_new_context']} times from its new label's context")
    if reset_at is None or reset_survivors is None:
        problems.append("no router close/recreate lifecycle")
    elif rehydrated != reset_survivors:
        problems.append(f"router reset survivors not rehydrated: {sorted(reset_survivors - rehydrated)}")
    if health_after_reset is None:
        problems.append("no fresh health publication after router reset")
    if lifecycle_ref is None or lookup_at is None:
        problems.append("no effect-relative rehydrate and lookup after router reset")
    if callback_at is None or lookup_at is None or callback_at <= lookup_at:
        problems.append("no successful late redirect callback after router reset lookup")
    summary = dict(sorted(s.items())) | {"added": sorted(added), "removed": sorted(removed),
                                          "changed": {a: v for a, v in sorted(changed.items())}}
    return problems, summary


def validate_dir(slot, attempt, out_dir, snapshot=None):
    row = slot_rows()[slot]
    out_dir = Path(out_dir)
    manifest = json.load(open(out_dir / "manifest.json"))
    snapshot = Path(snapshot) if snapshot else out_dir / "environment-manifest.json"
    problems = vn.raw_gate(row, vn.plan_rows()[slot], attempt, manifest, vn.sha256_file(snapshot))
    if vn.sha256_file(out_dir / "environment-manifest.json") != vn.sha256_file(snapshot):
        problems.append("raw: preserved environment-manifest.json differs from the snapshot")
    event_problems, summary = validate(row, json.load(open(out_dir / "trace.json")), json.load(open(out_dir / "go.json")))
    return problems + event_problems, summary


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("slot")
    ap.add_argument("capture", help="recorder attempt directory <out>/<slot>-<attempt>")
    ap.add_argument("--attempt")
    ap.add_argument("--snapshot")
    ap.add_argument("--events-only", action="store_true", help="skip the raw gate (diagnosing trial captures)")
    args = ap.parse_args()
    if args.events_only:
        d = Path(args.capture)
        problems, summary = validate(slot_rows()[args.slot], json.load(open(d / "trace.json")), json.load(open(d / "go.json")))
    else:
        attempt = args.attempt or Path(args.capture).resolve().name.removeprefix(args.slot + "-")
        problems, summary = validate_dir(args.slot, attempt, args.capture, args.snapshot)
    print(json.dumps(summary, indent=1))
    for p in problems:
        print("FAIL:", p)
    print("PASS" if not problems else f"{len(problems)} problem(s)")
    sys.exit(1 if problems else 0)


if __name__ == "__main__":
    main()
