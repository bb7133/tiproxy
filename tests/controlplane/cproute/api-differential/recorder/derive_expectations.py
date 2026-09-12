#!/usr/bin/env python3
# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Derive trace v1 `expect` blocks from recorded public inputs (contract a9c497c3 §2).

Input : a recorded trace (events without `expect`) and the recorded Go rows for the same
        events (output evidence: per-event outcome/backend/effects).
Output: the trace with `expect` per event, plus a `requires` list when a slot cannot be
        qualified on the current runner (effects-v2, metrics-input, policy-constraint:*).

Rules (README §2): Next/Lookup/Rehydrate are derived separately; error classes map 1:1
from inputs; ordinary exhaustion is exact `no_backend`; unprovable expectations are refused
(the script exits non-zero and names the seq) — never "whatever was recorded".
"""

import argparse
import copy
import json
import sys
from pathlib import Path

SOURCE_ERROR_MAP = {
    "no_backend": "no_backend",
    "wrapped_no_backend": "wrapped_no_backend",
    "port_conflict": "port_conflict",
    "topology_unavailable": "source_error:topology_unavailable",
    "cancelled": "source_error:cancelled",
    "deadline_exceeded": "source_error:deadline_exceeded",
}
PORT_LABEL = "tiproxy-port"
RULES_SUPPORTED = {"", "port"}  # client_cidr / proxy_cidr derivation: policy-constraint until specified


class Refuse(Exception):
    pass


def backend_id(b):
    cluster = b.get("cluster", "default")
    return f"{cluster}/{b['address']}" if cluster else b["address"]


def parse_toml_min(toml):
    """Minimal TOML reader for the keys the derivation needs (fail-backend-list, failover-timeout,
    routing-rule). Anything else is ignored; malformed documents return {}."""
    out, section = {}, ""
    for raw in toml.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip()
            continue
        if "=" not in line:
            continue
        key, value = (x.strip() for x in line.split("=", 1))
        key = f"{section}.{key}" if section else key
        if value.startswith("[") and value.endswith("]"):
            items = [v.strip().strip('"') for v in value[1:-1].split(",") if v.strip()]
            out[key] = items
        else:
            out[key] = value.strip('"')
    return out


class State:
    def __init__(self, config):
        self.rule = config["rule"]  # fixed at Init (router_score.go:90)
        self.policy = config["policy"]  # [balance] policy: runtime-configurable via config events
        self.selection = config["selection"]  # [balance] routing-policy: runtime-configurable
        self.inventory = {}  # id -> backend dict (last consumed health)
        self.observer_error = None
        self.fail_list = set()
        self.failover_timeout = None
        self.sessions = {}  # id -> {"retries": int, "active": bool, "port": str, "client": str, "proxy": str}
        self.assignments = {}  # session -> backend (from recorded rows; evidence only)
        self.retained = set()  # backends healthy in some consumed inventory and not removed since
        self.unique_history = True  # every successful selection so far had a unique legal set
        self.requires = set()
        self.retained_version = ""

    # --- inputs -------------------------------------------------------------------------
    def apply_health(self, backends):
        self.inventory = {backend_id(b): b for b in backends}
        self.observer_error = None
        holding = {b for sid, b in self.assignments.items() if self.sessions.get(sid, {}).get("active")}
        # A backend enters the router's retained set when first seen healthy; it leaves when a later
        # inventory omits it and no connection holds it. A never-healthy backend is unknown.
        self.retained = {i for i in self.retained if i in self.inventory or i in holding}
        self.retained |= {i for i, b in self.inventory.items() if b.get("healthy", True)}
        self.refresh_failover_guard()
        healthy_versions = [b.get("server_version", "") for b in backends if b.get("healthy", True) and b.get("server_version", "")]
        if healthy_versions:
            self.retained_version = healthy_versions[-1]

    def apply_config(self, toml):
        cfg = parse_toml_min(toml)
        if "proxy.fail-backend-list" in cfg:
            self.fail_list = set(cfg["proxy.fail-backend-list"])
        if "proxy.failover-timeout" in cfg:
            self.failover_timeout = cfg["proxy.failover-timeout"]
        if "balance.policy" in cfg:
            self.policy = cfg["balance.policy"]
        if "balance.routing-policy" in cfg:
            self.selection = cfg["balance.routing-policy"]
        self.refresh_failover_guard()

    def refresh_failover_guard(self):
        # group.go updateFailoverLocked: a list that would leave no routeable backend is ignored.
        routeable = [i for i, b in self.inventory.items() if b.get("healthy", True)]
        marked = [i for i in routeable if i.split("/", 1)[-1] in self.fail_list]
        self.failover_ignored = bool(routeable) and len(marked) == len(routeable)

    def failover_active(self, bid):
        if self.failover_ignored or not self.failover_timeout:
            return False
        return bid.split("/", 1)[-1] in self.fail_list

    # --- derived sets ---------------------------------------------------------------------
    def healthy_ids(self):
        return [i for i, b in self.inventory.items() if b.get("healthy", True)]

    def routable_ids(self):
        return [i for i in self.healthy_ids() if not self.failover_active(i)]

    def port_owners(self, port):
        owners = {}
        for i, b in self.inventory.items():
            if b.get("labels", {}).get(PORT_LABEL, "") == port:
                owners.setdefault(b.get("cluster", "default"), []).append(i)
        return owners

    def match_rule(self, session):
        if self.rule == "":
            return self.routable_ids(), None
        if self.rule == "port":
            owners = self.port_owners(session["port"])
            if len(owners) > 1:
                return [], "port_conflict"
            ids = [i for ids in owners.values() for i in ids]
            return [i for i in ids if i in self.routable_ids()], None
        self.requires.add(f"policy-constraint:{self.rule}")
        raise Refuse(f"routing rule {self.rule!r} derivation not specified")

    def retained_ids(self):
        # router.backends: healthy at least once and still listed or holding connections (apply_health).
        return set(self.retained)


def derive(trace, rows, args):
    state = State(trace["config"])
    events = trace["events"]
    if len(rows) != len(events):
        raise Refuse(f"rows {len(rows)} != events {len(events)}")
    out_events = []
    for seq, (event, row) in enumerate(zip(events, rows)):
        op, sid = event["op"], event.get("session", "")
        expect = {"outcome": "ok"}
        if op == "health":
            state.apply_health(event.get("backends", []))
        elif op == "source_error":
            state.observer_error = event["error"]
        elif op == "config":
            # Validator result is public behavior at the validation entry; the derivation cannot
            # re-implement lib/config validation, so the recorded outcome is accepted only if it is
            # one of the two public classes.
            if row["outcome"] not in ("ok", "invalid_config"):
                raise Refuse(f"seq {seq}: config outcome {row['outcome']!r} not a public class")
            expect["outcome"] = row["outcome"]
            if row["outcome"] == "ok":
                state.apply_config(event.get("toml", ""))
        elif op == "open":
            state.sessions[sid] = {"retries": 0, "active": False, "port": event.get("port", ""),
                                   "client": event.get("client", ""), "proxy": event.get("proxy", ""),
                                   "go_excluded": []}
        elif op == "next":
            s = state.sessions[sid]
            if state.observer_error is not None:
                expect["outcome"] = SOURCE_ERROR_MAP[state.observer_error]
            else:
                legal, conflict = state.match_rule(s)
                if conflict:
                    expect["outcome"] = conflict
                elif not legal:
                    expect["outcome"] = "no_backend"  # exact only (exclusion exhaustion never wraps)
                else:
                    if state.policy == "location":
                        # Public rule of the location policy: a local backend is preferred whenever
                        # one is legal; remote backends are legal only when no local one is.
                        local = [i for i in legal if state.inventory[i].get("local", True)]
                        if local:
                            legal = local
                    retrying = s["retries"] > 0
                    if retrying and s["retries"] >= len(legal):
                        # backend_selector.go:26-30: exhausted exclusions reset; a repeat is legal
                        retrying = False
                        s["go_excluded"] = []
                    if len(legal) == 1:
                        expect["backend"] = legal[0]
                    else:
                        expect["legal_backends"] = sorted(legal)
                        state.unique_history = False
                    if retrying:
                        expect["exclude_previous"] = True
                        if s["retries"] >= 2:
                            # The engine must avoid every backend it excluded in this attempt cycle;
                            # run.py's exclude_previous expresses only the last one. Engine-relative
                            # multi-retry exclusion is a runner dependency (README §0), never a relaxed set.
                            state.requires.add("exclusion-history")
            if expect["outcome"] != row["outcome"]:
                raise Refuse(f"seq {seq}: recorded outcome {row['outcome']!r} is not explained by inputs (derived {expect['outcome']!r})")
            if row["outcome"] == "ok":
                chosen = row.get("backend", "")
                if "backend" in expect and chosen != expect["backend"]:
                    raise Refuse(f"seq {seq}: recorded backend {chosen!r} contradicts the unique derivation {expect['backend']!r}")
                if "legal_backends" in expect and chosen not in expect["legal_backends"]:
                    raise Refuse(f"seq {seq}: recorded backend {chosen!r} is outside the derived legal set {expect['legal_backends']}")
                if chosen in s["go_excluded"]:
                    raise Refuse(f"seq {seq}: recorded backend {chosen!r} was already excluded in this attempt cycle {s['go_excluded']}")
                s["go_excluded"].append(chosen)
                state.assignments[sid] = chosen
        elif op == "finish":
            s = state.sessions[sid]
            if event["success"]:
                s["active"], s["retries"], s["go_excluded"] = True, 0, []
            else:
                s["retries"] += 1
        elif op == "close":
            state.sessions.pop(sid, None)
            state.assignments.pop(sid, None)
        elif op in ("lookup", "rehydrate"):
            name = event["backend"]
            retained = state.retained_ids()
            ok = name in retained
            if op == "rehydrate":
                s = state.sessions[sid]
                ok = ok and not s["active"]
            expect["outcome"] = "ok" if ok else "unknown_backend"
            if ok:
                expect["backend"] = name
                if op == "rehydrate":
                    s["active"] = True
                    state.assignments[sid] = name
            if expect["outcome"] != row["outcome"]:
                raise Refuse(f"seq {seq}: {op} outcome {row['outcome']!r} not explained by retained set {sorted(retained)}")
        elif op == "tick":
            effects = row.get("effects", [])
            if state.unique_history:
                if effects:
                    expect["effects"] = effects  # literal form is exact when every prior choice was unique
            else:
                # README §0 D1: once any choice was non-unique, both the presence and the absence of an
                # effect at a tick depend on per-engine history; the slot needs effects-v2 regardless.
                state.requires.add("effects-v2")
        elif op == "redirect_result":
            pass
        elif op == "checkpoint":
            healthy = 0 if state.observer_error is not None else len(state.routable_ids())
            expect["healthy_backend_count"] = healthy
            current = sorted({b.get("server_version", "") for i, b in state.inventory.items() if b.get("healthy", True) and b.get("server_version", "")})
            expect["legal_server_versions"] = current if current else [state.retained_version]
        else:
            raise Refuse(f"seq {seq}: unsupported op {op!r}")
        e = dict(event)
        e["expect"] = expect
        out_events.append(e)
    result = copy.deepcopy(trace)
    result["events"] = out_events
    return result, sorted(state.requires)


def compare_with_reference(derived, reference, requires):
    """Strict regression: every hand-written expectation must be reproduced exactly. A declared
    unique backend must be derived as that unique backend (a legal set containing it is a
    relaxation and fails); a declared legal set must be derived as the same set; error classes,
    exclude_previous, counts and versions must be equal; required effects must be equal unless the
    slot is explicitly marked `requires: effects-v2`, which is reported as WITHHELD (not qualified)."""
    diffs, withheld = [], []
    for seq, (d, r) in enumerate(zip(derived["events"], reference["events"])):
        de, re_ = d["expect"], r["expect"]
        if de["outcome"] != re_["outcome"]:
            diffs.append((seq, "outcome", de["outcome"], re_["outcome"])); continue
        if "backend" in re_ and de.get("backend") != re_["backend"]:
            diffs.append((seq, "backend", de.get("backend", de.get("legal_backends")), re_["backend"]))
        if "legal_backends" in re_ and sorted(de.get("legal_backends", [])) != sorted(re_["legal_backends"]):
            diffs.append((seq, "legal", de.get("legal_backends", de.get("backend")), sorted(re_["legal_backends"])))
        for k in ("exclude_previous", "healthy_backend_count"):
            if k in re_ and de.get(k) != re_[k]:
                diffs.append((seq, k, de.get(k), re_[k]))
            if k == "exclude_previous" and k not in re_ and de.get(k):
                diffs.append((seq, k, de.get(k), None))
        if "legal_server_versions" in re_ and sorted(re_["legal_server_versions"]) != sorted(de.get("legal_server_versions", [])):
            diffs.append((seq, "versions", de.get("legal_server_versions"), re_["legal_server_versions"]))
        if re_.get("effects", []) != de.get("effects", []):
            if "effects-v2" in requires and not de.get("effects"):
                withheld.append(seq)
            else:
                diffs.append((seq, "effects", de.get("effects"), re_.get("effects")))
    return diffs, withheld


def self_check(stripped, rows, reference, requires):
    """Negative regression: corrupt the recorded rows one way at a time; each must be caught."""
    results = {}
    def next_index(pred):
        return next(i for i, e in enumerate(reference["events"]) if e["op"] == "next" and pred(e["expect"]))
    # wrong backend at a uniquely derived next
    bad = copy.deepcopy(rows); i = next_index(lambda x: "backend" in x); bad[i]["backend"] = "default/wrong"
    try:
        derive(copy.deepcopy(stripped), bad, None); results["wrong_backend"] = "NOT CAUGHT"
    except Refuse as e:
        results["wrong_backend"] = f"refused: {e}"
    # wrong error class at a next expected to fail
    bad = copy.deepcopy(rows); i = next_index(lambda x: x["outcome"] != "ok"); bad[i]["outcome"] = "ok"; bad[i]["backend"] = "default/wrong"
    try:
        derive(copy.deepcopy(stripped), bad, None); results["wrong_error_class"] = "NOT CAUGHT"
    except Refuse as e:
        results["wrong_error_class"] = f"refused: {e}"
    # dropped effect: recorded rows lose an effect the reference requires
    try:
        j = next(i for i, e in enumerate(reference["events"]) if e["op"] == "tick" and e["expect"].get("effects"))
        bad = copy.deepcopy(rows); bad[j]["effects"] = []
        derived, req = derive(copy.deepcopy(stripped), bad, None)
        diffs, withheld = compare_with_reference(derived, reference, req)
        caught = any(d[0] == j and d[1] == "effects" for d in diffs) or (j in withheld)
        results["dropped_effect"] = "caught by regression" if any(d[0] == j and d[1] == "effects" for d in diffs) else ("withheld (effects-v2 required)" if j in withheld else "NOT CAUGHT")
    except StopIteration:
        results["dropped_effect"] = "no required effects in this trace"
    results.update(defect_checks())
    print(json.dumps({"self_check": results}, ensure_ascii=False))
    if any(str(v).startswith("NOT CAUGHT") for v in results.values()):
        sys.exit(3)


def defect_checks():
    """Mini traces for reviewer-reported defects (msg 3b98d666)."""
    out = {}
    hb = lambda addr, healthy=True: {"address": addr, "labels": {}, "cluster": "default", "ip": "127.0.0.1", "status_port": 10080, "healthy": healthy, "local": True, "server_version": "8.5.1", "support_redirection": True}
    cfg = {"policy": "connection", "selection": "random", "rule": ""}
    # 1) A fails, B fails, third Next returns the already-excluded A -> refused
    ev = [{"op": "health", "backends": [hb("a:4000"), hb("b:4000"), hb("c:4000")]},
          {"op": "open", "session": "s"}, {"op": "next", "session": "s"}, {"op": "finish", "session": "s", "success": False},
          {"op": "next", "session": "s"}, {"op": "finish", "session": "s", "success": False},
          {"op": "next", "session": "s"}, {"op": "finish", "session": "s", "success": True}, {"op": "close", "session": "s"}, {"op": "checkpoint"}]
    rows = [{"op": e["op"], "outcome": "ok", "backend": ""} for e in ev]
    rows[2]["backend"], rows[4]["backend"], rows[6]["backend"] = "default/a:4000", "default/b:4000", "default/a:4000"
    try:
        derive({"config": cfg, "events": ev}, rows, None); out["excluded_repeat"] = "NOT CAUGHT"
    except Refuse as e:
        out["excluded_repeat"] = f"refused: {e}"
    # 2) never-healthy backend must be unknown to Lookup
    ev = [{"op": "health", "backends": [hb("a:4000"), hb("n:4000", healthy=False)]}, {"op": "lookup", "backend": "default/n:4000"}, {"op": "checkpoint"}]
    rows = [{"op": "health", "outcome": "ok"}, {"op": "lookup", "outcome": "unknown_backend", "backend": ""}, {"op": "checkpoint", "outcome": "ok"}]
    try:
        d, _ = derive({"config": cfg, "events": ev}, rows, None)
        out["never_healthy_lookup"] = "ok: unknown_backend derived" if d["events"][1]["expect"]["outcome"] == "unknown_backend" else "NOT CAUGHT"
    except Refuse as e:
        out["never_healthy_lookup"] = f"NOT CAUGHT (refused: {e})"
    # 3) random history without an effect at the tick must still require effects-v2
    ev = [{"op": "health", "backends": [hb("a:4000"), hb("b:4000")]}, {"op": "open", "session": "s"}, {"op": "next", "session": "s"}, {"op": "finish", "session": "s", "success": True},
          {"op": "tick"}, {"op": "close", "session": "s"}, {"op": "checkpoint"}]
    rows = [{"op": e["op"], "outcome": "ok", "backend": "", "effects": []} for e in ev]; rows[2]["backend"] = "default/a:4000"
    _, req = derive({"config": cfg, "events": ev}, rows, None)
    out["effects_v2_without_effect"] = "ok: requires effects-v2" if "effects-v2" in req else "NOT CAUGHT"
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("trace", type=Path, help="recorded trace (expect blocks ignored if present)")
    ap.add_argument("rows", type=Path, help="recorded Go rows (go.json) for the same events")
    ap.add_argument("--output", type=Path)
    ap.add_argument("--check-against", type=Path, help="hand-written trace with expect blocks (regression)")
    ap.add_argument("--self-check", action="store_true", help="mutate the recorded rows and prove the deriver/regression reject wrong backend, wrong error class and a dropped effect")
    args = ap.parse_args()
    trace = json.loads(args.trace.read_text())
    stripped = copy.deepcopy(trace)
    for e in stripped["events"]:
        e.pop("expect", None)
    rows = json.loads(args.rows.read_text())
    try:
        derived, requires = derive(stripped, rows, args)
    except Refuse as error:
        print(f"REFUSED: {error}", file=sys.stderr)
        sys.exit(2)
    derived["provenance"] = dict(trace.get("provenance", {}), derived_by="derive_expectations.py")
    if requires:
        derived["provenance"]["requires"] = requires
    if args.output:
        args.output.write_text(json.dumps(derived, indent=2) + "\n")
    print(json.dumps({"events": len(derived["events"]), "requires": requires}))
    if args.check_against:
        reference = json.loads(args.check_against.read_text())
        diffs, withheld = compare_with_reference(derived, reference, requires)
        for d in diffs:
            print("DIFF", *d)
        print(json.dumps({"reference_diffs": len(diffs), "withheld_effects": withheld}))
        if args.self_check:
            self_check(stripped, rows, reference, requires)
        sys.exit(1 if diffs else 0)


if __name__ == "__main__":
    main()
