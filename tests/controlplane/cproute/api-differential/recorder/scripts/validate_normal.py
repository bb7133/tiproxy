#!/usr/bin/env python3
# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Event-level qualification of one normal-family capture (frozen contract section 3).

A timeline only schedules the environment; it does not make an outcome inevitable. This validator
reads the recorded trace.json and the aligned go.json and fails unless every required normal
outcome is present, correlated with the routing context of each session:

- the recorded health labels equal the slot's declared label map;
- an initial no_backend precedes the first usable health state, and no success precedes it;
- a successful select -> finish(true) -> close lifecycle;
- a finish(false) followed by a successful retry on another backend in the same session;
- a whole routed-group outage during which every routed next is exactly no_backend, then recovery;
- CIDR slots: the matching address succeeds and the non-matching address only gets no_backend;
- port slots: both listener ports succeed before the duplicate-cluster interval, both report
  port_conflict inside it, none before it or after the duplicate cluster has left the health
  snapshot, and both recover after that point.

The raw capture must also qualify on its own (raw_gate): recorded status from a clean identified
build, exact slot/attempt, completed connections and duration at or above the frozen plan minimum,
the planned duration of the slot, and the environment hash bound to the exclusive snapshot. The
verdict passes only when both gates pass.

Routing groups come from normal-slots.tsv (single table), using the Go rule semantics: no rule
routes to every backend, client_cidr/proxy_cidr match the `cidr` label against the client/proxy
IP, and port matches the `tiproxy-port` label against the listener port.
"""
import argparse, csv, hashlib, ipaddress, json, sys
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
PLAN = HERE.parent / "recording-plan.tsv"


def plan_rows():
    with open(PLAN) as f:
        return {r["trace_id"]: r for r in csv.DictReader(f, delimiter="\t")}


def slot_rows():
    with open(HERE / "normal-slots.tsv") as f:
        return {r["slot"]: r for r in csv.DictReader(f, delimiter="\t")}


def parse_labels(spec):
    """'tidb-0=;tidb-2=cidr=127.0.0.1/32' -> {'tidb-0': {}, 'tidb-2': {'cidr': '127.0.0.1/32'}}."""
    out = {}
    for item in spec.split(";"):
        name, _, labels = item.partition("=")
        out[name] = dict(p.split("=", 1) for p in labels.split(",") if p)
    return out


def instance_address(name):
    return f"127.0.0.1:{4000 + int(name.removeprefix('tidb-'))}"


def context_key(rule, ev):
    if rule == "":
        return "all"
    if rule == "client_cidr":
        return "client=" + ev["client"].rsplit(":", 1)[0]
    if rule == "proxy_cidr":
        return "proxy=" + ev["proxy"].rsplit(":", 1)[0]
    if rule == "port":
        return "port=" + ev["port"]
    raise ValueError(f"unsupported rule {rule!r}")


def routed(rule, context, labels):
    if rule == "":
        return True
    kind, _, value = context.partition("=")
    if rule in ("client_cidr", "proxy_cidr"):
        return "cidr" in labels and ipaddress.ip_address(value) in ipaddress.ip_network(labels["cidr"], strict=False)
    return labels.get("tiproxy-port") == value


def validate(row, trace, go):
    problems = []
    rule = row["go_rule"]
    declared = {instance_address(n): l for n, l in parse_labels(row["labels"]).items()}
    events = trace["events"]
    if len(events) != len(go):
        return [f"trace has {len(events)} events but go.json has {len(go)}"], {}
    for i, (e, g) in enumerate(zip(events, go)):
        if g["seq"] != i or g["op"] != e["op"] or g["session"] != e.get("session", ""):
            return [f"trace/go misaligned at {i}"], {}

    context = {}  # session -> routing context
    groups = {}   # context -> routed backend addresses
    healthy = set()
    seen_usable = defaultdict(bool)
    outage = defaultdict(bool)          # context currently in a whole-group outage after being usable
    stats = defaultdict(lambda: defaultdict(int))
    label_mismatch = set()
    config_on = config_off = conflict_end = None
    per_session = defaultdict(list)

    def group(ctx):
        if ctx not in groups:
            groups[ctx] = {a for a, l in declared.items() if routed(rule, ctx, l)}
        return groups[ctx]

    for i, (e, g) in enumerate(zip(events, go)):
        op = e["op"]
        if op == "health":
            healthy = set()
            backends = e.get("backends") or []
            if config_off is not None and conflict_end is None and all(b.get("cluster", "default") == "default" for b in backends):
                conflict_end = i
            for b in backends:
                if b.get("cluster", "default") == "default" and b["address"] in declared and b.get("labels", {}) != declared[b["address"]]:
                    label_mismatch.add((b["address"], json.dumps(b.get("labels", {}), sort_keys=True)))
                if b.get("healthy", True):
                    healthy.add(b["address"])
            for ctx, members in groups.items():
                if members & healthy:
                    seen_usable[ctx] = True
                    outage[ctx] = False
                elif seen_usable[ctx]:
                    if not outage[ctx]:
                        stats[ctx]["outages"] += 1
                    outage[ctx] = True
        elif op == "config":
            if e.get("toml", "").count("[[proxy.backend-clusters]]") > 1:
                config_on = i if config_on is None else config_on
            elif config_on is not None and config_off is None:
                config_off = i
        elif op == "open":
            ctx = context_key(rule, e)
            context[e["session"]] = ctx
            members = group(ctx)
            if members & healthy:
                seen_usable[ctx] = True
        elif op in ("next", "finish", "close"):
            s = e["session"]
            ctx = context[s]
            per_session[s].append((i, op, g["outcome"], g["backend"], e.get("success")))
            if op != "next":
                continue
            out, backend, st = g["outcome"], g["backend"], stats[ctx]
            st["next"] += 1
            st["next_" + out] += 1
            if out == "ok" and backend.rpartition("/")[2] not in group(ctx):
                st["outside_group"] += 1
                st.setdefault("first_outside_group", f"{i}:{backend}")
            if not seen_usable[ctx]:
                st["initial_" + out] += 1
            if outage[ctx]:
                st["outage_next"] += 1
                st["outage_" + out] += 1
            if out == "port_conflict":
                if config_on is None:
                    st["conflict_before_config"] += 1
                elif config_off is None:
                    st["conflict_inside"] += 1
                elif conflict_end is not None:
                    st["conflict_after_removal"] += 1
            if out == "ok":
                if config_on is None:
                    st["ok_before_config"] += 1
                if not outage[ctx] and st["outages"]:
                    st["ok_after_outage"] += 1
                if conflict_end is not None:
                    st["ok_after_conflict"] += 1

    for addr, labels in sorted(label_mismatch):
        problems.append(f"recorded labels of {addr} are {labels}, slot declares {json.dumps(declared[addr], sort_keys=True)}")

    routed_ctx = sorted(c for c in groups if groups[c])
    unrouted_ctx = sorted(c for c in groups if not groups[c])
    if not routed_ctx:
        problems.append("no session reached a context with a routed group")

    if sum(stats[c]["initial_no_backend"] for c in routed_ctx) == 0:
        problems.append("no initial no_backend before the first usable health state")
    for c in groups:
        if stats[c]["initial_ok"]:
            problems.append(f"{c}: {stats[c]['initial_ok']} successful next before the first usable health state")

    lifecycle = retry = False
    for s, seq in per_session.items():
        for k in range(len(seq) - 2):
            if seq[k][1:3] == ("next", "ok") and seq[k + 1][1] == "finish" and seq[k + 1][4] is True and seq[k + 2][1] == "close":
                lifecycle = True
                break
        failed = set()
        for k, (_, op, out, backend, success) in enumerate(seq):
            if op == "next" and out == "ok" and k + 1 < len(seq) and seq[k + 1][1] == "finish":
                if seq[k + 1][4] is False:
                    failed.add(backend.rpartition("/")[2])
                elif failed and backend.rpartition("/")[2] not in failed:
                    retry = True
        if lifecycle and retry:
            break
    if not lifecycle:
        problems.append("no successful select -> finish(true) -> close lifecycle")
    if not retry:
        problems.append("no finish(false) followed by a successful retry on another backend in the same session")

    outage_ctx = [c for c in routed_ctx if stats[c]["outages"] and stats[c]["outage_no_backend"]]
    if not outage_ctx:
        problems.append("no whole routed-group outage observed with a no_backend next inside it")
    for c in routed_ctx:
        if stats[c]["outage_next"] != stats[c]["outage_no_backend"]:
            other = {k[len("outage_"):]: v for k, v in stats[c].items()
                     if k.startswith("outage_") and k not in ("outage_next", "outage_no_backend") and v}
            problems.append(f"{c}: non-no_backend next during a whole routed-group outage {other}")
    for c in outage_ctx:
        if not stats[c]["ok_after_outage"]:
            problems.append(f"{c}: no recovery success after the routed-group outage")

    for c in groups:
        if stats[c]["outside_group"]:
            problems.append(f"{c}: {stats[c]['outside_group']} successful next outside routed group {sorted(groups[c])}, "
                            f"first {stats[c]['first_outside_group']}")
    for c in routed_ctx:
        if not stats[c]["next_ok"]:
            problems.append(f"{c}: routed context never succeeded")
    for c in unrouted_ctx:
        if not stats[c]["next"]:
            problems.append(f"{c}: no-match context has no next")
        if stats[c]["next"] != stats[c]["next_no_backend"]:
            problems.append(f"{c}: no-match context got outcomes other than no_backend")
    if rule in ("client_cidr", "proxy_cidr") and (not routed_ctx or not unrouted_ctx):
        problems.append(f"CIDR slot needs both a matching and a non-matching context, got {sorted(groups)}")

    if rule == "port":
        listeners = {"port=" + a.rsplit(":", 1)[1] for a in row["listen"].split(",")}
        if set(groups) != listeners:
            problems.append(f"port contexts {sorted(groups)} differ from listeners {sorted(listeners)}")
        if config_on is None or config_off is None:
            problems.append("port slot lacks the duplicate-cluster config interval")
        elif conflict_end is None:
            problems.append("duplicate cluster never left the health snapshot after its removal")
        for c in sorted(listeners):
            st = stats[c]
            if not st["ok_before_config"]:
                problems.append(f"{c}: no success before the duplicate-cluster interval")
            if not st["conflict_inside"]:
                problems.append(f"{c}: no port_conflict inside the duplicate-cluster interval")
            if st["conflict_before_config"]:
                problems.append(f"{c}: port_conflict before the duplicate-cluster interval")
            if st["conflict_after_removal"]:
                problems.append(f"{c}: {st['conflict_after_removal']} port_conflict after the duplicate cluster left health")
            if not st["ok_after_conflict"]:
                problems.append(f"{c}: no recovery success after the duplicate cluster left health")
    summary = {c: {k: v for k, v in sorted(stats[c].items())} | {"group": sorted(groups[c])} for c in sorted(groups)}
    return problems, summary


def duration_nanos(text):
    if not text.endswith("s") or not text[:-1].isdigit():
        raise ValueError(f"duration {text!r} must be whole seconds")
    return int(text[:-1]) * 10**9


def raw_gate(row, plan, attempt, manifest, snapshot_sha):
    """Qualification of the raw capture itself, independent of scenario outcomes."""
    problems = []
    cap = manifest.get("capture") or {}
    if manifest.get("status") != "recorded" or manifest.get("incomplete"):
        problems.append(f"raw: status={manifest.get('status')!r} incomplete={manifest.get('incomplete')}")
    if cap.get("source_dirty") != "false" or not cap.get("head") or not cap.get("tree"):
        problems.append(f"raw: build not clean and identified (source_dirty={cap.get('source_dirty')!r}, head={cap.get('head')!r}, tree={cap.get('tree')!r})")
    if manifest.get("slot") != row["slot"] or manifest.get("attempt") != attempt:
        problems.append(f"raw: manifest slot/attempt {manifest.get('slot')}/{manifest.get('attempt')} != {row['slot']}/{attempt}")
    if (cap.get("completed_connections") or 0) < int(plan["min_completed_connections"]):
        problems.append(f"raw: completed_connections {cap.get('completed_connections')} < plan minimum {plan['min_completed_connections']}")
    if (cap.get("duration_nanos") or 0) < int(plan["min_seconds"]) * 10**9:
        problems.append(f"raw: duration_nanos {cap.get('duration_nanos')} < plan minimum {plan['min_seconds']} s")
    if cap.get("planned_duration_nanos") != duration_nanos(row["duration"]):
        problems.append(f"raw: planned_duration_nanos {cap.get('planned_duration_nanos')} != slot duration {row['duration']}")
    if cap.get("clients") != int(row["clients"]) or cap.get("held_clients") != int(row["held_clients"]):
        problems.append(f"raw: clients/held {cap.get('clients')}/{cap.get('held_clients')} != slot {row['clients']}/{row['held_clients']}")
    for key, value in (("environment_manifest_sha256", manifest.get("environment_manifest_sha256")),
                       ("capture.environment_manifest_sha256", cap.get("environment_manifest_sha256"))):
        if value != snapshot_sha:
            problems.append(f"raw: {key} {value} != snapshot sha256 {snapshot_sha}")
    return problems


def sha256_file(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def validate_dir(slot, attempt, out_dir, snapshot=None):
    """Both gates for one attempt directory; snapshot defaults to the recorder's preserved copy."""
    row = slot_rows()[slot]
    out_dir = Path(out_dir)
    manifest = json.load(open(out_dir / "manifest.json"))
    snapshot = Path(snapshot) if snapshot else out_dir / "environment-manifest.json"
    problems = raw_gate(row, plan_rows()[slot], attempt, manifest, sha256_file(snapshot))
    if sha256_file(out_dir / "environment-manifest.json") != sha256_file(snapshot):
        problems.append("raw: preserved environment-manifest.json differs from the snapshot")
    trace = json.load(open(out_dir / "trace.json"))
    go = json.load(open(out_dir / "go.json"))
    event_problems, summary = validate(row, trace, go)
    return problems + event_problems, summary


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("slot")
    ap.add_argument("capture", help="recorder attempt directory <out>/<slot>-<attempt>")
    ap.add_argument("--attempt", help="defaults to the directory name suffix")
    ap.add_argument("--snapshot", help="exclusive environment snapshot passed to the recorder")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    attempt = args.attempt or Path(args.capture).resolve().name.removeprefix(args.slot + "-")
    problems, summary = validate_dir(args.slot, attempt, args.capture, args.snapshot)
    if args.json:
        print(json.dumps({"slot": args.slot, "passed": not problems, "problems": problems, "contexts": summary}, indent=2))
    else:
        for c, s in summary.items():
            print(c, s)
        for p in problems:
            print("FAIL:", p)
        print("PASS" if not problems else f"{len(problems)} problem(s)")
    sys.exit(1 if problems else 0)


if __name__ == "__main__":
    main()
