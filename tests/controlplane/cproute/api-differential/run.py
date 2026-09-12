#!/usr/bin/env python3
# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0
"""One external-API replay/comparison entrypoint; smoke evidence is not corpus acceptance."""

import argparse
import ast
import copy
from collections import Counter
import hashlib
import json
import math
import os
from pathlib import Path
import signal
import subprocess
import time
import tomllib

ROOT = Path(__file__).resolve().parents[4]
MAX_BYTES = 32 * 1024 * 1024
OPS = {"health", "source_error", "config", "open", "next", "finish", "close", "checkpoint", "tick", "redirect_result", "lookup", "rehydrate"}
SOURCE_ERRORS = {"no_backend", "wrapped_no_backend", "port_conflict", "topology_unavailable", "cancelled", "deadline_exceeded"}


class Difference(ValueError):
    pass


def require(condition, code, detail):
    if not condition:
        raise Difference(f"{code}: {detail}")


def pairs(items):
    result = {}
    for key, value in items:
        require(key not in result, "INPUT", f"duplicate JSON key {key}")
        result[key] = value
    return result


def load(path):
    data = path.read_bytes()
    require(len(data) <= MAX_BYTES, "INPUT", "size limit")
    try:
        return json.loads(data, object_pairs_hook=pairs)
    except (ValueError, UnicodeError) as error:
        raise Difference(f"INPUT: {error}") from error


def validate(trace):
    require(isinstance(trace, dict) and set(trace) == {"version", "id", "config", "provenance", "events"}, "INPUT", "trace fields")
    require(type(trace["version"]) is int and trace["version"] == 1 and isinstance(trace["id"], str), "INPUT", "version/id")
    config = trace["config"]
    require(isinstance(config,dict) and {"policy", "selection", "rule"} <= set(config) <= {"policy", "selection", "rule", "clock_origin_nanos"}, "INPUT", "config fields")
    origin = config.get("clock_origin_nanos", 1_700_000_000_000_000_000)
    require(type(origin) is int and 0 <= origin <= 2**63 - 1 - 86_400_000_000_000, "INPUT", "clock origin range")
    require(config["policy"] in {"connection", "resource", "location"}, "INPUT", "policy")
    require(config["selection"] in {"random", "prefer-idle"}, "INPUT", "selection")
    require(config["rule"] in {"", "client_cidr", "proxy_cidr", "port"}, "INPUT", "rule")
    require(isinstance(trace["provenance"],dict) and trace["provenance"].get("kind") in {"synthetic", "recorded"}, "INPUT", "provenance kind")
    events = trace["events"]
    require(isinstance(events, list) and 0 < len(events) <= 100_000, "INPUT", "event count")
    allowed = {
        "health":{"backends"},"config":{"toml"},"open":{"client","proxy","port"},
        "next":set(),"finish":{"success"},"close":set(),"checkpoint":set(),
        "tick":{"refuse"},"redirect_result":{"operation","success"},
        "lookup":{"backend"},"rehydrate":{"backend"},
        "source_error":{"error"},
    }
    sessions, pending, active, operations = set(), set(), set(), {}
    at = 0
    for index, event in enumerate(events):
        require(isinstance(event, dict) and event.get("op") in OPS, "INPUT", f"event {index}")
        op, session = event["op"], event.get("session", "")
        require(set(event) <= allowed[op] | {"op","session","at_nanos","expect"} and isinstance(session,str),"INPUT",f"event fields {index}")
        timestamp = event.get("at_nanos",at)
        require(type(timestamp) is int and at <= timestamp <= 86_400_000_000_000,"INPUT","monotonic public clock")
        at = timestamp
        expect = event.get("expect")
        require(isinstance(expect, dict) and set(expect) <= {"outcome", "backend", "legal_backends", "effects", "exclude_previous", "exclude_history", "prefer_local", "prefer_idle_conn", "healthy_backend_count", "legal_server_versions"} and isinstance(expect.get("outcome"), str), "INPUT", f"expectation {index}")
        require("exclude_previous" not in expect or (op == "next" and type(expect["exclude_previous"]) is bool), "INPUT", "retry expectation")
        if "exclude_history" in expect:
            require(op == "next" and expect["outcome"] == "ok" and expect["exclude_history"] is True and "exclude_previous" not in expect,
                    "INPUT", "full exclusion expectation")
        if "prefer_idle_conn" in expect:
            require(expect["prefer_idle_conn"] is True and expect.get("exclude_history") is True and "prefer_local" not in expect,
                    "INPUT", "connection preference after full exclusions")
        if "prefer_local" in expect:
            preferred = expect["prefer_local"]
            candidates = expect.get("legal_backends", [expect.get("backend")])
            require(expect.get("exclude_history") is True and isinstance(candidates, list) and isinstance(preferred, list) and all(isinstance(x, str) and x in candidates for x in preferred)
                    and len(preferred) == len(set(preferred)), "INPUT", "local candidates after exclusions")
        if "healthy_backend_count" in expect:
            require(op == "checkpoint" and type(expect["healthy_backend_count"]) is int and expect["healthy_backend_count"] >= 0,"INPUT","healthy count expectation")
        if "legal_server_versions" in expect:
            versions = expect["legal_server_versions"]
            require(op == "checkpoint" and isinstance(versions,list) and versions and all(isinstance(v,str) for v in versions) and len(versions) == len(set(versions)),"INPUT","version expectation")
        effects = expect.get("effects",[])
        require(isinstance(effects,list),"INPUT","effects")
        for effect in effects:
            require(isinstance(effect,dict) and set(effect) == {"kind","session","operation","from","to","accepted"},"INPUT","effect fields")
            require(effect["kind"] in {"redirect","force_close"} and effect["session"] in active and type(effect["accepted"]) is bool,"INPUT","effect owner/acceptance")
            require(all(isinstance(effect[key],str) for key in ("session","operation","from","to")) and effect["operation"] not in operations,"INPUT","effect identity")
            operations[effect["operation"]] = effect
        if op == "source_error":
            require(isinstance(event.get("error"),str) and event["error"] in SOURCE_ERRORS,"INPUT","observer error identity")
        elif op == "health":
            backends = event.get("backends")
            require(isinstance(backends, list), "INPUT", "health inventory")
            addresses = []
            for backend in backends:
                require(isinstance(backend, dict) and {"address", "labels"} <= set(backend) <= {"address", "labels", "cluster", "keyspace", "ip", "status_port", "healthy", "local", "server_version", "support_redirection"}, "INPUT", "backend fields")
                require(isinstance(backend["address"], str) and isinstance(backend["labels"], dict) and all(isinstance(k,str) and isinstance(v,str) for k,v in backend["labels"].items()), "INPUT", "backend types")
                for key in ("cluster","keyspace","ip","server_version"):
                    require(key not in backend or isinstance(backend[key],str),"INPUT",f"backend {key}")
                for key in ("healthy","local","support_redirection"):
                    require(key not in backend or type(backend[key]) is bool,"INPUT",f"backend {key}")
                require("status_port" not in backend or (type(backend["status_port"]) is int and 0 <= backend["status_port"] < 2**64),"INPUT","backend status port")
                cluster = backend.get("cluster","default")
                addresses.append(cluster+"/"+backend["address"] if cluster else backend["address"])
            require(len(set(addresses)) == len(addresses), "INPUT", "duplicate backend")
        elif op == "config":
            require(isinstance(event.get("toml"), str), "INPUT", "config update")
        elif op == "tick":
            require(isinstance(event.get("refuse",[]),list) and all(id in active for id in event.get("refuse",[])),"INPUT","effect refusal inputs")
        elif op == "redirect_result":
            effect = operations.get(event.get("operation"))
            require(effect is not None and effect["kind"] == "redirect" and effect["accepted"] and type(event.get("success")) is bool,"INPUT","callback authority")
            require(session == effect["session"],"INPUT","callback owner")
        elif op == "open":
            require(session and session not in sessions, "INPUT", "open identity")
            require(all(isinstance(event.get(key,""), str) for key in ("client","proxy","port")), "INPUT", "client addresses")
            sessions.add(session)
        elif op in {"next", "finish", "close","rehydrate"}:
            require(session in sessions, "INPUT", f"unknown session {session}")
            if op in {"next","rehydrate"}:
                require(session not in pending and session not in active, "INPUT", "attempt requires idle session")
                if expect["outcome"] == "ok":
                    exact, legal = expect.get("backend"), expect.get("legal_backends")
                    require((isinstance(exact,str) and bool(exact) and legal is None) or (exact is None and isinstance(legal,list) and legal and all(isinstance(x,str) and x for x in legal) and len(set(legal)) == len(legal)), "INPUT", "declare exact backend or legal set")
                    (pending if op == "next" else active).add(session)
            elif op == "finish":
                require(session in pending and type(event.get("success")) is bool, "INPUT", "Finish without pending attempt")
                pending.remove(session)
                if event["success"]: active.add(session)
            else:
                require(session not in pending, "INPUT", "close requires creation completion")
                sessions.remove(session)
                active.discard(session)
        if op in {"lookup","rehydrate"}:
            require(isinstance(event.get("backend"),str) and event["backend"],"INPUT","named backend")
    require(not sessions and not pending and not active and events[-1]["op"] == "checkpoint", "INPUT", "trace must end at an empty checkpoint")


def causal(effects):
    require(isinstance(effects,list),"EFFECTS","effect array")
    per_session = {}
    for effect in effects:
        require(isinstance(effect,dict) and isinstance(effect.get("session"),str),"EFFECTS","effect identity")
        require(set(effect) == {"kind","session","operation","from","to","accepted"} and type(effect["accepted"]) is bool and all(isinstance(effect[k],str) for k in ("kind","session","operation","from","to")),"EFFECTS","effect fields/types")
        per_session.setdefault(effect["session"],[]).append(effect)
    return per_session


class PublicConnections:
    """One engine's public reservations and connections, never a getter/score tape.

    A successful Next reserves one connection. An accepted redirect transfers that
    reservation immediately, while the public assignment moves only on success.
    This separation matters for new selections during delayed callbacks.
    """
    def __init__(self, config):
        self.pending, self.assigned, self.redirects = {}, {}, {}
        self.policy, self.selection = config["policy"], config["selection"]
        self.ratio, self.rate, self.label_name = 1.2, 0.0, ""

    def prefer_idle(self, candidates):
        require(self.policy == "connection" and self.selection == "prefer-idle" and not self.label_name,
                "INPUT", "connection preference requires connection/prefer-idle without label isolation")
        counts = Counter(self.pending.values()) + Counter(self.assigned.values())
        for effect in self.redirects.values():
            counts[effect["from"]] -= 1
            counts[effect["to"]] += 1
        require(all(n >= 0 for n in counts.values()), "EFFECT_LEDGER", "negative public connection count")
        best = min(counts[b] for b in candidates)
        best_bits = min(best, 65535)
        legal = set()
        for backend in candidates:
            count = counts[backend]
            # Go compares the clamped 16-bit factor first, then calls advice
            # with the original counts. Equal saturated factors are not evicted.
            if min(count, 65535) <= best_bits or float(count) <= float(best + 1) * self.ratio:
                legal.add(backend)
                continue
            rate = self.rate if self.rate > 0 else max(0.0, (float(count + best + 1) / (1 + self.ratio) - float(best + 1)) / 120)
            if rate <= 0.0001:
                legal.add(backend)
        return legal

    def apply(self, event, row):
        op, sid = event["op"], event.get("session", "")
        if op == "config" and row["outcome"] == "ok":
            try:
                balance = tomllib.loads(event["toml"]).get("balance", {})
            except tomllib.TOMLDecodeError as error:
                raise Difference(f"INPUT: accepted config cannot be parsed: {error}") from error
            self.policy = balance.get("policy", self.policy) or "resource"
            self.selection = balance.get("routing-policy", self.selection) or "prefer-idle"
            self.label_name = balance.get("label-name", self.label_name)
            conn = balance.get("conn-count", {})
            ratio = conn.get("count-ratio-threshold", self.ratio)
            rate = conn.get("migrations-per-second", self.rate)
            require(type(ratio) in (int, float) and math.isfinite(ratio) and (ratio == 0 or ratio > 1)
                    and type(rate) in (int, float) and math.isfinite(rate) and rate >= 0,
                    "INPUT", "finite connection policy configuration")
            self.ratio, self.rate = float(ratio or 1.2), float(rate)
        elif op == "next" and row["outcome"] == "ok":
            self.pending[sid] = row["backend"]
        elif op == "finish":
            backend = self.pending.pop(sid)
            if event["success"]:
                self.assigned[sid] = backend
        elif op == "rehydrate" and row["outcome"] == "ok":
            self.assigned[sid] = row["backend"]
        elif op == "redirect_result":
            effect = self.redirects.pop(event["operation"], None)
            if effect is not None and sid in self.assigned and event["success"]:
                self.assigned[sid] = effect["to"]
        elif op == "close":
            self.assigned.pop(sid, None)
            self.redirects = {key: ef for key, ef in self.redirects.items() if ef["session"] != sid}
        for effect in row.get("effects", []):
            if effect["kind"] == "redirect" and effect["accepted"]:
                require(self.assigned.get(effect["session"]) == effect["from"]
                        and not any(ef["session"] == effect["session"] for ef in self.redirects.values()),
                        "EFFECT_LEDGER", "redirect requires one established owner and no pending redirect")
                self.redirects[effect["operation"]] = effect


def observe(trace, rows, engine):
    events = trace["events"]
    require(isinstance(rows,list) and len(rows) == len(events), "MISSING_RESULT", engine)
    pending, ledger, previous, operations, settled = {}, {}, {}, {}, set()
    excluded = {}
    connections = PublicConnections(trace["config"])
    for index, (event,row) in enumerate(zip(events,rows)):
        op, session, expect = event["op"], event.get("session",""), event["expect"]
        fields = {"seq","op","session","outcome","backend","effects"} | ({"assignments","conn_count","healthy_backend_count","server_version"} if op == "checkpoint" else set())
        require(isinstance(row,dict) and set(row) == fields and type(row.get("seq")) is int and row.get("seq") == index and row.get("op") == op and row.get("session") == session, "RESULT_IDENTITY", f"{engine} event {index}")
        require(row.get("outcome") == expect["outcome"], "ERROR_OUTCOME", f"{engine} event {index}: {row.get('outcome')} != {expect['outcome']}")
        require(causal(row["effects"]) == causal(expect.get("effects",[])), "EFFECTS", f"{engine} event {index}")
        for effect in row["effects"]:
            require(effect["from"] == ledger.get(effect["session"]) and effect["operation"] not in operations,"EFFECT_LEDGER",f"{engine} {index}")
            operations[effect["operation"]] = effect
            if not effect["accepted"]: settled.add(effect["operation"])
        if op in {"next","lookup","rehydrate"} and row["outcome"] == "ok":
            backend = row.get("backend")
            if "backend" in expect:
                require(backend == expect["backend"], "BACKEND_RESULT", f"{engine} event {index}")
            else:
                require(backend in expect.get("legal_backends",[]), "ILLEGAL_CHOICE", f"{engine} event {index}")
            if expect.get("exclude_history"):
                candidates = set(expect.get("legal_backends", [expect.get("backend")]))
                history = excluded.setdefault(session, set())
                remaining = candidates - history
                # Next retries internally only after exact exhaustion. Old identities
                # remain excluded across health changes until that reset actually occurs.
                if not remaining:
                    history.clear()
                    remaining = candidates
                require(backend in remaining, "RETRY_RESULT", f"{engine} event {index} repeated a member of its exclusion cycle")
                if expect.get("prefer_idle_conn"):
                    require(backend in connections.prefer_idle(remaining), "POLICY_RESULT", f"{engine} event {index} chose an evicted busy backend")
                if "prefer_local" in expect:
                    preferred = remaining.intersection(expect["prefer_local"])
                    require(backend in (preferred or remaining), "POLICY_RESULT", f"{engine} event {index} bypassed an unexcluded local backend")
            if expect.get("exclude_previous"):
                require(session in previous and backend != previous[session], "RETRY_RESULT", f"{engine} event {index} repeated excluded result")
            if op == "next":
                pending[session] = backend
                previous[session] = backend
                excluded.setdefault(session, set()).add(backend)
            elif op == "rehydrate": ledger[session] = backend
        else:
            require(row.get("backend") == "", "BACKEND_RESULT", f"unexpected {engine} backend at {index}")
        # A returned exact no-backend also clears every engine's own cycle,
        # including an observer sentinel. Wrapped no-backend and other errors do not.
        if op == "next" and row["outcome"] == "no_backend":
            excluded.pop(session, None)
        if op == "finish":
            require(session in pending, "LEDGER", f"{engine} missing attempt")
            backend = pending.pop(session)
            if event["success"]: ledger[session] = backend
        elif op == "redirect_result":
            key = event["operation"]
            require(key in operations,"EFFECT_LEDGER",f"{engine} missing accepted effect")
            if key not in settled and session in ledger and event["success"]: ledger[session] = operations[key]["to"]
            settled.add(key)
        elif op == "close":
            excluded.pop(session, None)
            previous.pop(session, None)
            ledger.pop(session,None)
            settled.update(key for key,effect in operations.items() if effect["session"] == session)
        elif op == "checkpoint":
            require(type(row.get("healthy_backend_count")) is int and row["healthy_backend_count"] >= 0 and isinstance(row.get("server_version"),str),"OBSERVATION","public metadata types")
            if "healthy_backend_count" in expect:
                require(row["healthy_backend_count"] == expect["healthy_backend_count"],"OBSERVATION",f"{engine} healthy count {index}")
            if "legal_server_versions" in expect:
                require(row["server_version"] in expect["legal_server_versions"],"OBSERVATION",f"{engine} server version {index}")
            require(row.get("assignments") == ledger and type(row.get("conn_count")) is int and row["conn_count"] == len(ledger), "LEDGER", f"{engine} checkpoint {index}")
        connections.apply(event, row)
    require(not ledger and not pending and set(operations) <= settled, "LEDGER", f"{engine} final state")


def compare(trace, go, rust):
    validate(trace)
    observe(trace,go,"go")
    observe(trace,rust,"rust")
    for event, left, right in zip(trace["events"],go,rust):
        if event["op"] == "checkpoint":
            require(left["healthy_backend_count"] == right["healthy_backend_count"],"OBSERVATION","healthy backend counts differ")
            if "legal_server_versions" not in event["expect"]:
                require(left["server_version"] == right["server_version"],"OBSERVATION","undeclared server version divergence")
    # Exact errors/effects agree by both satisfying the same public expectation.
    # Legal random backend divergence is retained in raw results; never feed
    # one engine's result into the other's input or compare private scores.
    return {"events":len(trace["events"]),"violations":0,"provenance":trace["provenance"]["kind"]}


def comparator_checks(trace, reference, destination):
    """Eight mutations of this comparator, one external assertion per row.

    An invalid observation must be rejected by the ordinary checker. Disabling
    the targeted check must make that assertion fail (the mutation is killed);
    restoring the original source must reject it again. The raw adapter output
    used as the valid control is retained, not manufactured by the comparator.
    """
    source = Path(__file__).read_text()
    rows = []
    cases = [
        ("wrong_backend","BACKEND_RESULT"),
        ("illegal_random_backend","ILLEGAL_CHOICE"),
        ("erase_error_distinction","ERROR_OUTCOME"),
        ("omit_retry_result_check","RETRY_RESULT"),
        ("drop_effect","EFFECTS"),
        ("duplicate_terminal_result","MISSING_RESULT"),
        ("ignore_final_ledger","LEDGER"),
        ("accept_missing_input","INPUT"),
    ]
    destination.mkdir()
    for name,code in cases:
        bad_trace, bad = copy.deepcopy(trace), copy.deepcopy(reference)
        if name == "wrong_backend":
            index = next(i for i,e in enumerate(trace["events"]) if e["op"] == "lookup" and e["expect"]["outcome"] == "ok")
            bad[index]["backend"] = "default/wrong"
        elif name == "illegal_random_backend":
            index = next(i for i,e in enumerate(trace["events"]) if "legal_backends" in e["expect"])
            bad[index]["backend"] = "default/illegal"
        elif name == "erase_error_distinction":
            index = next(i for i,e in enumerate(trace["events"]) if e["expect"]["outcome"] == "no_backend")
            bad[index]["outcome"] = "wrapped_no_backend"
        elif name == "omit_retry_result_check":
            index = next(i for i,e in enumerate(trace["events"]) if e["expect"].get("exclude_previous"))
            session = trace["events"][index]["session"]
            old = next(r["backend"] for r in reversed(bad[:index]) if r["op"] == "next" and r["session"] == session)
            bad[index]["backend"] = old
            for row in bad[index+1:]:
                if row["op"] == "checkpoint" and session in row["assignments"]: row["assignments"][session] = old
                if row["op"] == "close" and row["session"] == session: break
        elif name == "drop_effect":
            index = next(i for i,r in enumerate(bad) if r["effects"] and not r["effects"][0]["accepted"])
            bad[index]["effects"] = []
        elif name == "duplicate_terminal_result":
            bad.append(copy.deepcopy(bad[-1]))
        elif name == "ignore_final_ledger":
            bad[-1]["conn_count"] = 1
        else:
            # The complete event stream is required; a missing header also
            # fails at the sole import boundary, before any adapter runs.
            bad_trace.pop("id")
        def rejects(checker):
            try: checker(bad_trace,bad,reference)
            except ValueError as error:
                require(str(error).startswith(code+":"),"MUTATION_ASSERTION",f"{name}: unexpected {error}")
                return True
            return False
        require(rejects(compare),"MUTATION_ASSERTION",f"{name}: original accepted invalid observation")
        class Disable(ast.NodeTransformer):
            def visit_Call(self,node):
                self.generic_visit(node)
                if isinstance(node.func,ast.Name) and node.func.id == "require" and len(node.args) >= 2 and isinstance(node.args[1],ast.Constant) and node.args[1].value == code:
                    return ast.copy_location(ast.Constant(value=None),node)
                return node
        tree = ast.fix_missing_locations(Disable().visit(ast.parse(source)))
        mutant_source = ast.unparse(tree)
        mutant = destination / (name+".py")
        mutant.write_text(mutant_source+"\n")
        scope = {"__name__":"comparator_mutant","__file__":str(Path(__file__))}
        exec(compile(tree,str(mutant),"exec"),scope)
        # This is the intended negative assertion: the disabled comparator
        # admits the invalid observation, so its rejection test fails.
        require(not rejects(scope["compare"]),"MUTATION_NOT_EXERCISED",name)
        require(rejects(compare),"RESTORATION",name)
        compare(trace,reference,reference)
        rows.append({"fault":name,"assertion":code,"mutant_assertion":"failed_as_required",
                     "restored":"passed","mutant_sha256":hashlib.sha256(mutant.read_bytes()).hexdigest()})
    result = {"source_sha256":hashlib.sha256(source.encode()).hexdigest(),"faults":rows,"passed":len(rows)}
    (destination/"results.json").write_text(json.dumps(result,indent=2)+"\n")
    return result


def execute(command, env, log, timeout):
    start = time.monotonic()
    with log.open("wb") as output:
        process = subprocess.Popen(command,cwd=ROOT,env=env,stdout=output,stderr=subprocess.STDOUT,start_new_session=True)
        try:
            code = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid,signal.SIGTERM)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid,signal.SIGKILL)
                process.wait()
            raise Difference(f"TIMEOUT: {log}") from None
    require(code == 0,"ENGINE",f"{log}: rc={code}")
    return {"command":command,"seconds":round(time.monotonic()-start,3),"rc":code,"log_sha256":hashlib.sha256(log.read_bytes()).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("trace",type=Path)
    parser.add_argument("--output",type=Path,required=True)
    parser.add_argument("--comparator-check",action="store_true")
    args = parser.parse_args()
    trace = load(args.trace)
    validate(trace)
    destination = args.output.resolve()
    destination.mkdir(parents=True,exist_ok=False)
    # Deliberately omit oracle expectations and provenance from engine inputs.
    inputs = {key:trace[key] for key in ("version","id","config")}
    inputs["events"] = []
    timestamp = 0
    for event in trace["events"]:
        timestamp = event.get("at_nanos",timestamp)
        inputs["events"].append({**{k:v for k,v in event.items() if k != "expect"},"at_nanos":timestamp})
    # Test build only: every router/group/factor time read sees the public event
    # clock. No caller/getter trace is introduced, and random tickets elsewhere
    # remain independent real wall-clock reads in both engines.
    replacements = {}
    for name in ("group.go","router_score.go"):
        original = ROOT / "pkg/balance/router" / name
        replacement = destination / name
        replacement.write_text(original.read_text().replace("time.Now()","apiReplayNow()"))
        replacements[str(original)] = str(replacement)
    for name in ("factor_cpu.go", "factor_memory.go", "factor_health.go"):
        original = ROOT / "pkg/balance/factor" / name
        data = original.read_text()
        require('"time"' in data and "time.Now()" in data, "INPUT", "factor clock overlay anchor")
        data = data.replace('"time"', '"time"\n\treplayclock "github.com/pingcap/tiproxy/tests/controlplane/cproute/api-differential/clock"')
        replacement = destination / name
        replacement.write_text(data.replace("time.Now()", "replayclock.Now()"))
        replacements[str(original)] = str(replacement)
    overlay = destination / "go-overlay.json"
    overlay.write_text(json.dumps({"Replace":replacements},sort_keys=True))
    source = destination / "input.json"
    source.write_text(json.dumps(inputs,sort_keys=True))
    records, failure = {}, None
    result = {"provenance":trace["provenance"]["kind"],"status":"failed"}
    try:
        for engine, command in (
            ("go",["go","test","-overlay",str(overlay),"-race","./pkg/balance/router","-run","^TestRouterAPIDifferential$","-count=1"]),
            ("rust",["cargo","test","--locked","--manifest-path","rust/Cargo.toml","-p","control-router","tests::api_differential::replay","--","--exact"]),
        ):
            env = {**os.environ,"CPROUTE_API_INPUT":str(source),"CPROUTE_API_OUTPUT":str(destination/f"{engine}.json")}
            records[engine] = execute(command,env,destination/f"{engine}.log",900)
        result.update(compare(trace,load(destination/"go.json"),load(destination/"rust.json")))
        if args.comparator_check:
            result["comparator"] = comparator_checks(trace,load(destination/"go.json"),destination/"comparator")
        result["status"] = "passed"
    except (Difference,OSError) as error:
        failure = error
        result["error"] = str(error)
    finally:
        # Publish an incomplete/failed manifest as well as a successful one;
        # existing output directories cannot be reused to hide the first run.
        result.update({"head":subprocess.check_output(["git","rev-parse","HEAD"],cwd=ROOT,text=True).strip(),
                       "tree":subprocess.check_output(["git","rev-parse","HEAD^{tree}"],cwd=ROOT,text=True).strip(),
                       "dirty":bool(subprocess.check_output(["git","status","--porcelain"],cwd=ROOT,text=True).strip()),
                       "trace_sha256":hashlib.sha256(args.trace.read_bytes()).hexdigest(),
                       "input_sha256":hashlib.sha256(source.read_bytes()).hexdigest(),"engines":records,
                       "files":{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in destination.iterdir() if p.is_file()},
                       "acceptance":{"recorded":0,"rounds":0,"special_suites":0,"comparator_mutants":result.get("comparator",{}).get("passed",0)}})
        (destination/"manifest.json").write_text(json.dumps(result,indent=2)+"\n")
        print(json.dumps(result,indent=2))
    if failure:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
