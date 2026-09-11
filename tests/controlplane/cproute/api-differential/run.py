#!/usr/bin/env python3
# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0
"""One external-API replay/comparison entrypoint; smoke evidence is not corpus acceptance."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import time

ROOT = Path(__file__).resolve().parents[4]
MAX_BYTES = 32 * 1024 * 1024
OPS = {"health", "config", "open", "next", "finish", "close", "checkpoint"}


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
    require(set(config) == {"policy", "selection", "rule"}, "INPUT", "config fields")
    require(config["policy"] in {"connection", "resource", "location"}, "INPUT", "policy")
    require(config["selection"] in {"random", "prefer-idle"}, "INPUT", "selection")
    require(config["rule"] in {"", "client_cidr", "proxy_cidr", "port"}, "INPUT", "rule")
    require(trace["provenance"].get("kind") in {"synthetic", "recorded"}, "INPUT", "provenance kind")
    events = trace["events"]
    require(isinstance(events, list) and 0 < len(events) <= 100_000, "INPUT", "event count")
    allowed = {"op", "session", "client", "proxy", "port", "backends", "success", "toml", "expect"}
    sessions, pending, active = set(), set(), set()
    for index, event in enumerate(events):
        require(isinstance(event, dict) and set(event) <= allowed and event.get("op") in OPS, "INPUT", f"event {index}")
        op, session = event["op"], event.get("session", "")
        expect = event.get("expect")
        require(isinstance(expect, dict) and set(expect) <= {"outcome", "backend", "legal_backends", "effects", "exclude_previous"} and isinstance(expect.get("outcome"), str), "INPUT", f"expectation {index}")
        require("exclude_previous" not in expect or (op == "next" and type(expect["exclude_previous"]) is bool), "INPUT", "retry expectation")
        if op == "health":
            backends = event.get("backends")
            require(isinstance(backends, list), "INPUT", "health inventory")
            addresses = []
            for backend in backends:
                require(isinstance(backend, dict) and set(backend) == {"address", "labels"}, "INPUT", "backend fields")
                require(isinstance(backend["address"], str) and isinstance(backend["labels"], dict) and all(isinstance(k,str) and isinstance(v,str) for k,v in backend["labels"].items()), "INPUT", "backend types")
                addresses.append(backend["address"])
            require(len(set(addresses)) == len(addresses), "INPUT", "duplicate backend")
        elif op == "config":
            require(isinstance(event.get("toml"), str), "INPUT", "config update")
        elif op == "open":
            require(isinstance(session, str) and session and session not in sessions, "INPUT", "open identity")
            require(all(isinstance(event.get(key,""), str) for key in ("client","proxy","port")), "INPUT", "client addresses")
            sessions.add(session)
        elif op in {"next", "finish", "close"}:
            require(session in sessions, "INPUT", f"unknown session {session}")
            if op == "next":
                require(session not in pending and session not in active, "INPUT", "next before prior Finish")
                if expect["outcome"] == "ok":
                    exact, legal = expect.get("backend"), expect.get("legal_backends")
                    require((isinstance(exact,str) and bool(exact) and legal is None) or (exact is None and isinstance(legal,list) and legal and all(isinstance(x,str) and x for x in legal) and len(set(legal)) == len(legal)), "INPUT", "declare exact backend or legal set")
                    pending.add(session)
            elif op == "finish":
                require(session in pending and type(event.get("success")) is bool, "INPUT", "Finish without pending attempt")
                pending.remove(session)
                if event["success"]:
                    active.add(session)
            else:
                require(session not in pending, "INPUT", "close requires creation completion")
                sessions.remove(session)
                active.discard(session)
    require(not sessions and not pending and not active and events[-1]["op"] == "checkpoint", "INPUT", "trace must end at an empty checkpoint")


def observe(trace, rows, engine):
    events = trace["events"]
    require(isinstance(rows,list) and len(rows) == len(events), "MISSING_RESULT", engine)
    pending, ledger, previous = {}, {}, {}
    for index, (event,row) in enumerate(zip(events,rows)):
        op, session, expect = event["op"], event.get("session",""), event["expect"]
        fields = {"seq","op","session","outcome","backend","effects"} | ({"assignments","conn_count"} if op == "checkpoint" else set())
        require(isinstance(row,dict) and set(row) == fields and type(row.get("seq")) is int and row.get("seq") == index and row.get("op") == op and row.get("session") == session, "RESULT_IDENTITY", f"{engine} event {index}")
        require(row.get("outcome") == expect["outcome"], "ERROR_OUTCOME", f"{engine} event {index}: {row.get('outcome')} != {expect['outcome']}")
        require(row.get("effects") == expect.get("effects",[]), "EFFECTS", f"{engine} event {index}")
        if op == "next" and row["outcome"] == "ok":
            backend = row.get("backend")
            if "backend" in expect:
                require(backend == expect["backend"], "BACKEND_RESULT", f"{engine} event {index}")
            else:
                require(backend in expect["legal_backends"], "ILLEGAL_CHOICE", f"{engine} event {index}")
            if expect.get("exclude_previous"):
                require(session in previous and backend != previous[session], "RETRY_RESULT", f"{engine} event {index} repeated excluded result")
            pending[session] = backend
            previous[session] = backend
        else:
            require(row.get("backend") == "", "BACKEND_RESULT", f"unexpected {engine} backend at {index}")
        if op == "finish":
            require(session in pending, "LEDGER", f"{engine} missing attempt")
            backend = pending.pop(session)
            if event["success"]:
                ledger[session] = backend
        elif op == "close":
            ledger.pop(session,None)
        elif op == "checkpoint":
            require(row.get("assignments") == ledger and type(row.get("conn_count")) is int and row["conn_count"] == len(ledger), "LEDGER", f"{engine} checkpoint {index}")
    require(not ledger and not pending, "LEDGER", f"{engine} final state")


def compare(trace, go, rust):
    validate(trace)
    observe(trace,go,"go")
    observe(trace,rust,"rust")
    # Exact errors/effects agree by both satisfying the same public expectation.
    # Legal random backend divergence is retained in raw results; never feed
    # one engine's result into the other's input or compare private scores.
    return {"events":len(trace["events"]),"violations":0,"provenance":trace["provenance"]["kind"]}


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
    args = parser.parse_args()
    trace = load(args.trace)
    validate(trace)
    destination = args.output.resolve()
    destination.mkdir(parents=True,exist_ok=False)
    # Deliberately omit oracle expectations and provenance from engine inputs.
    inputs = {key:trace[key] for key in ("version","id","config")}
    inputs["events"] = [{k:v for k,v in event.items() if k != "expect"} for event in trace["events"]]
    source = destination / "input.json"
    source.write_text(json.dumps(inputs,sort_keys=True))
    records, failure = {}, None
    result = {"provenance":trace["provenance"]["kind"],"status":"failed"}
    try:
        for engine, command in (
            ("go",["go","test","-race","./pkg/balance/router","-run","^TestRouterAPIDifferential$","-count=1"]),
            ("rust",["cargo","test","--locked","--manifest-path","rust/Cargo.toml","-p","control-router","tests::api_differential::replay","--","--exact"]),
        ):
            env = {**os.environ,"CPROUTE_API_INPUT":str(source),"CPROUTE_API_OUTPUT":str(destination/f"{engine}.json")}
            records[engine] = execute(command,env,destination/f"{engine}.log",900)
        result.update(compare(trace,load(destination/"go.json"),load(destination/"rust.json")))
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
                       "acceptance":{"recorded":0,"rounds":0,"special_suites":0,"comparator_mutants":0}})
        (destination/"manifest.json").write_text(json.dumps(result,indent=2)+"\n")
        print(json.dumps(result,indent=2))
    if failure:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
