#!/usr/bin/env python3
# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Failover-family raw/event qualification for the frozen section-3 outcomes."""
import argparse
import csv
import json
import sys
import tomllib
from collections import Counter, defaultdict
from pathlib import Path

import validate_normal as common

HERE = Path(__file__).resolve().parent


def slot_rows():
    with open(HERE / "failover-slots.tsv") as f:
        return {r["slot"]: r for r in csv.DictReader(f, delimiter="\t")}


def failover_config(toml):
    try:
        proxy = tomllib.loads(toml).get("proxy", {})
    except (tomllib.TOMLDecodeError, TypeError):
        return None, None
    targets = proxy.get("fail-backend-list", [])
    if not isinstance(targets, list) or not all(isinstance(v, str) for v in targets):
        return None, None
    timeout = proxy.get("failover-timeout", 0)
    return frozenset(targets), timeout


def backend_address(backend):
    return backend.rpartition("/")[2]


def validate(row, trace, go):
    problems = []
    events = trace.get("events", [])
    if len(events) != len(go):
        return [f"trace has {len(events)} events but go.json has {len(go)}"], {}
    for i, (event, result) in enumerate(zip(events, go)):
        if result.get("seq") != i or result.get("op") != event.get("op") or result.get("session", "") != event.get("session", ""):
            return [f"trace/go misaligned at {i}"], {}

    labels = {common.instance_address(name): value for name, value in common.parse_labels(row["labels"]).items()}
    contexts = {}
    groups = {}
    stats = defaultdict(Counter)

    def group(context):
        if context not in groups:
            groups[context] = {address for address, backend_labels in labels.items()
                               if common.routed(row["go_rule"], context, backend_labels)}
        return groups[context]

    healthy_seen = set()
    health_lost = set()
    health_recovered = set()
    label_mismatch = set()
    redirection_disabled = set()
    config_rows = []
    config_on = config_off = conflict_end = None
    operations = {}
    effect_refs = {}
    accepted_redirects = 0
    results = Counter()
    closes = defaultdict(list)

    for i, (event, result) in enumerate(zip(events, go)):
        op = event["op"]
        if op == "open":
            context = common.context_key(row["go_rule"], event)
            contexts[event["session"]] = context
            group(context)
        elif op == "health":
            backends = event.get("backends") or []
            current_healthy = {b["address"] for b in backends if b.get("healthy", True)}
            for backend in backends:
                address = backend.get("address")
                if backend.get("cluster", "default") != "default" or address not in labels:
                    continue
                if backend.get("labels", {}) != labels[address]:
                    label_mismatch.add((address, json.dumps(backend.get("labels", {}), sort_keys=True)))
                if backend.get("healthy", True) and backend.get("support_redirection") is not True:
                    redirection_disabled.add(address)
            for address in labels:
                if address in healthy_seen and address not in current_healthy:
                    health_lost.add(address)
                if address in health_lost and address in current_healthy:
                    health_recovered.add(address)
            healthy_seen |= current_healthy
            if config_off is not None and conflict_end is None and all(b.get("cluster", "default") == "default" for b in backends):
                conflict_end = i
        elif op == "config":
            targets, timeout = failover_config(event.get("toml", ""))
            if targets is None:
                problems.append(f"config at {i} is not parseable failover input")
            else:
                config_rows.append((i, targets, timeout))
                if targets and (not isinstance(timeout, int) or isinstance(timeout, bool) or timeout <= 0):
                    problems.append(f"config at {i} activates failover with non-positive timeout {timeout!r}")
            if result.get("outcome") != "ok":
                problems.append(f"config at {i} was not accepted: {result.get('outcome')!r}")
            clusters = event.get("toml", "").count("[[proxy.backend-clusters]]")
            if clusters > 1:
                config_on = i if config_on is None else config_on
            elif clusters == 1 and config_on is not None and config_off is None:
                config_off = i
        elif op == "next":
            context = contexts.get(event["session"])
            if context is None:
                problems.append(f"next at {i} has no recorded open context")
                continue
            outcome = result.get("outcome")
            stats[context]["next"] += 1
            stats[context]["next_" + str(outcome)] += 1
            if outcome == "ok":
                address = backend_address(result.get("backend", ""))
                if address not in group(context):
                    stats[context]["outside_group"] += 1
                    stats[context].setdefault("first_outside_group", f"{i}:{address}")
                if conflict_end is not None:
                    stats[context]["ok_after_conflict"] += 1
            elif outcome == "port_conflict":
                if config_on is None:
                    stats[context]["conflict_before_config"] += 1
                elif config_off is None:
                    stats[context]["conflict_inside"] += 1
                elif conflict_end is not None:
                    stats[context]["conflict_after_removal"] += 1
        elif op == "tick":
            for effect in result.get("effects") or []:
                operation = effect.get("operation")
                if not operation:
                    problems.append(f"tick at {i} contains an effect without operation identity")
                elif operation in operations:
                    problems.append(f"duplicate effect operation {operation}")
                else:
                    operations[operation] = (i, effect)
                    if effect.get("kind") == "redirect" and effect.get("accepted") is True:
                        accepted_redirects += 1
                        effect_refs[f"redirect/{accepted_redirects}"] = operation
        elif op == "close":
            closes[event["session"]].append(i)
            effect_ref = event.get("effect_ref")
            if effect_ref:
                operation = effect_refs.get(effect_ref)
                issued = operations.get(operation)
                if (issued is None or issued[1].get("kind") != "redirect"
                        or issued[1].get("accepted") is not True
                        or issued[1].get("session") != event.get("session")):
                    problems.append(f"close at {i} has invalid accepted-effect reference {effect_ref!r}")
        elif op == "redirect_result":
            operation = event.get("operation") or effect_refs.get(event.get("effect_ref"), "")
            results[operation] += 1
            issued = operations.get(operation)
            if issued is None or not issued[1].get("accepted") or issued[1].get("kind") != "redirect":
                problems.append(f"redirect_result at {i} does not settle one accepted redirect {operation!r}")
            elif event.get("session") != issued[1].get("session"):
                problems.append(f"redirect_result at {i} settles {operation!r} for the wrong session")

    singleton = [(i, targets, timeout) for i, targets, timeout in config_rows if len(targets) == 1]
    if len(singleton) != 3:
        problems.append(f"expected select, unchanged repeat and reentry singleton configs, got {len(singleton)}")
    else:
        first, repeat, reentry = singleton
        if repeat[1:] != first[1:]:
            problems.append("unchanged activation did not repeat the same target and timeout")
        if any(first[0] < i < repeat[0] and not targets for i, targets, _ in config_rows):
            problems.append("failover was cleared before the unchanged activation")
        first_clear = next(((i, targets, timeout) for i, targets, timeout in config_rows
                            if repeat[0] < i < reentry[0]), None)
        if first_clear is None or first_clear[1]:
            problems.append("no clear between unchanged activation and reentry")
        reentry_clear = next(((i, targets, timeout) for i, targets, timeout in config_rows
                              if i > reentry[0]), None)
        if reentry_clear is None or reentry_clear[1]:
            problems.append("reentered failover was not cleared")
        for name, current in (("initial activation", first), ("reentry", reentry)):
            i, targets, _ = current
            if i == 0 or events[i - 1].get("op") != "checkpoint":
                problems.append(f"{name} is not immediately bound to a public checkpoint")
                continue
            assigned = {backend_address(v) for v in (go[i - 1].get("assignments") or {}).values()}
            if not targets <= assigned:
                problems.append(f"{name} target {sorted(targets)} was not assigned at the preceding checkpoint {sorted(assigned)}")

        first_target = next(iter(first[1]))
        first_window_end = first_clear[0] if first_clear is not None else len(events)
        refused = [(i, effect) for i, effect in operations.values()
                   if first[0] < i < first_window_end
                   and effect.get("kind") == "redirect" and not effect.get("accepted")
                   and backend_address(effect.get("from", "")) == first_target]
        accepted_after_refusal = False
        for refused_i, effect in refused:
            if any(refused_i < i < first_window_end
                   and later.get("kind") == "redirect" and later.get("accepted")
                   and later.get("session") == effect.get("session")
                   and backend_address(later.get("from", "")) == first_target
                   for i, later in operations.values()):
                accepted_after_refusal = True
                break
        if not refused:
            problems.append("no refused redirect from the checkpoint-selected failover backend")
        elif not accepted_after_refusal:
            problems.append("no later accepted redirect for the refused session")

        reentry_target = next(iter(reentry[1]))
        reentry_window_end = reentry_clear[0] if reentry_clear is not None else len(events)
        late = []
        for operation, (issued_i, effect) in operations.items():
            if not reentry[0] < issued_i < reentry_window_end:
                continue
            if effect.get("kind") != "redirect" or not effect.get("accepted"):
                continue
            if backend_address(effect.get("from", "")) != reentry_target:
                continue
            session = effect.get("session")
            result_i = next((i for i, (event, _) in enumerate(zip(events, go))
                             if event.get("op") == "redirect_result"
                             and (event.get("operation")
                                  or effect_refs.get(event.get("effect_ref"), "")) == operation), None)
            if result_i is not None and any(issued_i < close_i < result_i for close_i in closes[session]):
                late.append(operation)
        if not late:
            problems.append("no accepted redirect completed after its session closed")

    for operation, count in sorted(results.items()):
        if count != 1:
            problems.append(f"redirect operation {operation!r} settled {count} times")
    for operation, (issued_i, effect) in sorted(operations.items()):
        if not effect.get("accepted"):
            continue
        if effect.get("kind") == "redirect" and results[operation] != 1:
            problems.append(f"accepted redirect operation {operation!r} settled {results[operation]} times")
        if effect.get("kind") == "force_close" and not any(close_i > issued_i for close_i in closes[effect.get("session")]):
            problems.append(f"accepted force_close operation {operation!r} has no later close")

    routed_contexts = sorted(context for context in groups if groups[context])
    unrouted_contexts = sorted(context for context in groups if not groups[context])
    routed_addresses = set().union(*(groups[c] for c in routed_contexts)) if routed_contexts else set()
    if not routed_contexts:
        problems.append("no session reached a context with a routed group")
    for address, actual in sorted(label_mismatch):
        problems.append(f"recorded labels of {address} are {actual}, slot declares {json.dumps(labels[address], sort_keys=True)}")
    if redirection_disabled:
        problems.append(f"healthy failover backends lack redirection support: {sorted(redirection_disabled)}")
    if not (health_lost & routed_addresses):
        problems.append("no routed backend changed from healthy to lost/unhealthy")
    if not (health_recovered & routed_addresses):
        problems.append("no routed backend recovered after health loss")
    for context in routed_contexts:
        if not stats[context]["next_ok"]:
            problems.append(f"{context}: routed context never succeeded")
        if stats[context]["outside_group"]:
            problems.append(f"{context}: {stats[context]['outside_group']} successful next outside routed group {sorted(groups[context])}, first {stats[context]['first_outside_group']}")
    for context in unrouted_contexts:
        if not stats[context]["next"] or stats[context]["next"] != stats[context]["next_no_backend"]:
            problems.append(f"{context}: no-match context did not exclusively return no_backend")
    if row["go_rule"] in ("client_cidr", "proxy_cidr") and (not routed_contexts or not unrouted_contexts):
        problems.append(f"CIDR slot needs matching and non-matching contexts, got {sorted(groups)}")

    guards = []
    for i, targets, _ in config_rows:
        covered = [context for context in routed_contexts if len(groups[context]) >= 2 and groups[context] <= targets]
        if not covered:
            continue
        end = next((j for j, _, _ in config_rows if j > i), len(events))
        successful = {contexts.get(event.get("session")) for event, result in zip(events[i + 1:end], go[i + 1:end])
                      if event.get("op") == "next" and result.get("outcome") == "ok"}
        guards.append((i, covered, successful))
    if not any(set(covered) & successful for _, covered, successful in guards):
        problems.append("no all-members failover guard interval preserved successful routing")

    if row["go_rule"] == "port":
        listeners = {"port=" + address.rsplit(":", 1)[1] for address in row["listen"].split(",")}
        if set(groups) != listeners:
            problems.append(f"port contexts {sorted(groups)} differ from listeners {sorted(listeners)}")
        if config_on is None or config_off is None or conflict_end is None:
            problems.append("port slot lacks a complete duplicate-cluster conflict interval")
        for context in sorted(listeners):
            if not stats[context]["conflict_inside"]:
                problems.append(f"{context}: no port_conflict inside the duplicate-cluster interval")
            if stats[context]["conflict_before_config"]:
                problems.append(f"{context}: port_conflict before the duplicate-cluster interval")
            if stats[context]["conflict_after_removal"]:
                problems.append(f"{context}: port_conflict after the duplicate cluster left health")
            if not stats[context]["ok_after_conflict"]:
                problems.append(f"{context}: no recovery success after the duplicate cluster left health")

    if not go or go[-1].get("op") != "checkpoint" or go[-1].get("assignments") or go[-1].get("conn_count") != 0:
        problems.append("final checkpoint does not have an empty logical ledger")
    summary = {context: dict(stats[context]) | {"group": sorted(groups[context])} for context in sorted(groups)}
    summary["failover"] = {"singleton_configs": len(singleton), "operations": len(operations),
                           "settled_operations": len(results), "health_lost": sorted(health_lost),
                           "health_recovered": sorted(health_recovered)}
    return problems, summary


def validate_dir(slot, attempt, out_dir, snapshot=None):
    row = slot_rows()[slot]
    out_dir = Path(out_dir)
    manifest = json.load(open(out_dir / "manifest.json"))
    snapshot = Path(snapshot) if snapshot else out_dir / "environment-manifest.json"
    problems = common.raw_gate(row, common.plan_rows()[slot], attempt, manifest, common.sha256_file(snapshot))
    if common.sha256_file(out_dir / "environment-manifest.json") != common.sha256_file(snapshot):
        problems.append("raw: preserved environment-manifest.json differs from the snapshot")
    script_sha = common.sha256_file(HERE / row["script"])
    if manifest.get("capture", {}).get("script_sha256") != script_sha:
        problems.append("raw: capture script hash differs from the frozen slot script")
    if not (out_dir / "actions.json").exists() or common.sha256_file(out_dir / "actions.json") != script_sha:
        problems.append("raw: preserved actions.json differs from the frozen slot script")
    for name, extension in (("trace", ".json"), ("go", ".json"), ("archive", ".jsonl")):
        path = out_dir / (name + extension)
        if not path.exists() or manifest.get(name + "_sha256") != common.sha256_file(path):
            problems.append(f"raw: {name} bytes do not match manifest {name}_sha256")
    trace = json.load(open(out_dir / "trace.json"))
    go = json.load(open(out_dir / "go.json"))
    event_problems, summary = validate(row, trace, go)
    return problems + event_problems, summary


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("slot")
    ap.add_argument("capture")
    ap.add_argument("--attempt")
    ap.add_argument("--snapshot")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    attempt = args.attempt or Path(args.capture).resolve().name.removeprefix(args.slot + "-")
    problems, summary = validate_dir(args.slot, attempt, args.capture, args.snapshot)
    if args.json:
        print(json.dumps({"slot": args.slot, "passed": not problems, "problems": problems, "contexts": summary}, indent=2))
    else:
        for problem in problems:
            print("FAIL:", problem)
        print("PASS" if not problems else f"{len(problems)} problem(s)")
    sys.exit(1 if problems else 0)


if __name__ == "__main__":
    main()
