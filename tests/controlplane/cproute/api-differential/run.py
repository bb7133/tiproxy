#!/usr/bin/env python3
# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0
"""One external-API replay/comparison entrypoint; smoke evidence is not corpus acceptance."""

import argparse
import ast
import copy
from collections import Counter
import hashlib
import itertools
import json
import math
import os
import re
from pathlib import Path
import signal
import subprocess
import time
import tomllib

ROOT = Path(__file__).resolve().parents[4]
MAX_BYTES = 32 * 1024 * 1024
OPS = {"health", "source_error", "metrics", "config", "open", "next", "finish", "close", "checkpoint", "tick", "redirect_result", "lookup", "rehydrate"}
SOURCE_ERRORS = {"no_backend", "wrapped_no_backend", "port_conflict", "topology_unavailable", "cancelled", "deadline_exceeded"}
METRIC_KEYS = {"cpu", "memory", "failure_pd", "total_pd", "failure_tikv", "total_tikv"}


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


def validate_metrics(queries):
    require(isinstance(queries, dict) and set(queries) == METRIC_KEYS, "INPUT", "whole metrics query set")
    integer = lambda value: type(value) is int and -(2**63) <= value < 2**63
    for result in queries.values():
        if result is None:
            continue
        require(isinstance(result, dict) and set(result) == {"kind", "updated_nanos", "series"}, "INPUT", "metric result fields")
        require(result["kind"] in {"vector", "matrix"} and (result["updated_nanos"] is None or integer(result["updated_nanos"])), "INPUT", "metric kind/update time")
        require(isinstance(result["series"], list), "INPUT", "metric series")
        for series in result["series"]:
            require(isinstance(series, dict) and set(series) == {"labels", "samples"}, "INPUT", "metric series fields")
            require(isinstance(series["labels"], dict) and all(isinstance(k,str) and isinstance(v,str) for k,v in series["labels"].items()), "INPUT", "metric labels")
            require(isinstance(series["samples"], list) and (result["kind"] == "matrix" or len(series["samples"]) == 1), "INPUT", "metric sample count")
            for sample in series["samples"]:
                require(isinstance(sample, dict) and set(sample) == {"timestamp_ms", "value"} and integer(sample["timestamp_ms"]), "INPUT", "metric sample fields/time")
                value = sample["value"]
                require(isinstance(value,str) and len(value) <= 32, "INPUT", "metric value string")
                if value not in {"NaN", "+Inf", "-Inf"}:
                    require(re.fullmatch(r"-?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?", value) is not None and math.isfinite(float(value)), "INPUT", "metric value encoding")


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
        "next":set(),"finish":{"success"},"close":{"effect_ref"},"checkpoint":set(),
        "tick":{"refuse","refuse_next"},"redirect_result":{"operation","effect_ref","optional_effect","success"},
        "lookup":{"backend"},"rehydrate":{"backend"},
        "source_error":{"error"},
        "metrics":{"queries"},
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
        require(isinstance(expect, dict) and set(expect) <= {"outcome", "backend", "legal_backends", "effects", "force_close_due", "redirect_cadence", "status_scoring", "exclude_previous", "exclude_history", "prefer_local", "prefer_idle_conn", "healthy_backend_count", "legal_server_versions"} and isinstance(expect.get("outcome"), str), "INPUT", f"expectation {index}")
        if "force_close_due" in expect:
            due = expect["force_close_due"]
            require(op == "tick" and expect["outcome"] == "ok" and "effects" not in expect
                    and isinstance(due, list) and all(isinstance(b, str) and b for b in due)
                    and len(due) == len(set(due)), "INPUT", "due failover backends")
        if "status_scoring" in expect:
            scoring = expect["status_scoring"]
            require(isinstance(scoring, list), "INPUT", "status scoring calls")
            for call in scoring:
                require(isinstance(call, dict) and set(call) == {"group", "health"}
                        and isinstance(call["group"], str) and call["group"]
                        and isinstance(call["health"], dict) and call["health"]
                        and all(isinstance(b, str) and b and type(v) is bool
                                for b, v in call["health"].items()), "INPUT", "status scoring call")
        if "redirect_cadence" in expect:
            model = expect["redirect_cadence"]
            require(op == "tick" and expect["outcome"] == "ok" and "effects" not in expect
                    and isinstance(model, dict) and set(model) == {"kind", "groups"}
                    and model["kind"] == "connection" and isinstance(model["groups"], list),
                    "INPUT", "redirect cadence model")
            group_ids, members = set(), set()
            for group in model["groups"]:
                require(isinstance(group, dict) and set(group) == {"group", "members"}
                        and isinstance(group["group"], str) and group["group"] not in group_ids
                        and isinstance(group["members"], list) and group["members"],
                        "INPUT", "redirect cadence group")
                group_ids.add(group["group"])
                for member in group["members"]:
                    require(isinstance(member, dict) and set(member) == {"backend", "healthy", "keyspace"}
                            and isinstance(member["backend"], str) and member["backend"] not in members
                            and type(member["healthy"]) is bool and isinstance(member["keyspace"], str),
                            "INPUT", "redirect cadence member")
                    members.add(member["backend"])
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
        if op == "metrics":
            validate_metrics(event.get("queries"))
        elif op == "source_error":
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
            require(type(event.get("refuse_next", 0)) is int and 0 <= event.get("refuse_next", 0) <= 1,
                    "INPUT", "one-shot effect refusal")
        elif op == "redirect_result":
            operation, effect_ref = event.get("operation"), event.get("effect_ref")
            match = (re.fullmatch(r"redirect/([1-9][0-9]*)", effect_ref)
                     if isinstance(effect_ref, str) else None)
            optional = event.get("optional_effect", False)
            require(type(event.get("success")) is bool and ((isinstance(operation, str) and operation and effect_ref is None)
                    or (operation is None and match is not None))
                    and type(optional) is bool and (not optional or match is not None),
                    "INPUT", "callback authority")
            if operation is not None:
                effect = operations.get(operation)
                require(effect is not None and effect["kind"] == "redirect" and effect["accepted"],"INPUT","callback operation")
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
                if "effect_ref" in event:
                    require(re.fullmatch(r"redirect/[1-9][0-9]*", event["effect_ref"]) is not None,
                            "INPUT", "relative close authority")
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
        self.closing, self.ordinals = set(), Counter()
        self.created, self.last_redirect, self.redirect_failed = {}, {}, {}
        self.group_last_redirect, self.status_snapshots = {}, {}
        self.backend_groups = {}
        self.logical_to_actual, self.effect_refs, self.effect_ref_sessions = {}, {}, {}
        self.unbound_redirects, self.skipped_effect_refs = [], set()
        self.policy, self.selection = config["policy"], config["selection"]
        self.ratio, self.rate, self.status_rate, self.label_name = 1.2, 0.0, 0.0, ""

    def counts(self):
        counts = Counter(self.pending.values()) + Counter(self.assigned.values())
        for effect in self.redirects.values():
            counts[effect["from"]] -= 1
            counts[effect["to"]] += 1
        require(all(n >= 0 for n in counts.values()), "EFFECT_LEDGER", "negative public connection count")
        return counts

    def prefer_idle(self, candidates):
        require(self.policy in {"connection", "resource", "location"}
                and self.selection == "prefer-idle" and not self.label_name,
                "INPUT", "connection-factor preference requires prefer-idle without label isolation")
        counts = self.counts()
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

    def _force_close_effects(self, event, due, refuse_next):
        """Resolve input-defined deadlines against this engine's public owners.

        A refused close remains eligible; an accepted close stays suppressed even
        across failover clear/reentry until the connection is actually closed.
        In-flight redirects retain their public source assignment until success.
        """
        refused = {self.logical_to_actual.get(sid, sid) for sid in event.get("refuse", [])}
        effects = []
        for sid, backend in self.assigned.items():
            if backend not in due or sid in self.closing:
                continue
            scripted = sid in refused
            if not scripted and refuse_next:
                scripted, refuse_next = True, refuse_next - 1
            effects.append({"kind": "force_close", "session": sid,
                            "operation": f"{sid}/{self.ordinals[sid] + 1}",
                            "from": backend, "to": "", "accepted": not scripted})
        return effects, refuse_next

    def force_close_effects(self, event, due):
        return self._force_close_effects(event, due, event.get("refuse_next", 0))[0]

    def prepare(self, event, expect, row, now):
        """Apply input-derived configuration/scoring before this public call."""
        if event["op"] == "config" and row["outcome"] == "ok":
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
            status = balance.get("status", {})
            status_rate = status.get("migrations-per-second", self.status_rate)
            require(type(ratio) in (int, float) and math.isfinite(ratio) and (ratio == 0 or ratio > 1)
                    and type(rate) in (int, float) and math.isfinite(rate) and rate >= 0
                    and type(status_rate) in (int, float) and math.isfinite(status_rate) and status_rate >= 0,
                    "INPUT", "finite connection policy configuration")
            self.ratio, self.rate = float(ratio or 1.2), float(rate)
            self.status_rate = float(status_rate)
        for call in expect.get("status_scoring", []):
            snapshots = self.status_snapshots.setdefault(call["group"], {})
            for backend in call["health"]:
                self.backend_groups[backend] = call["group"]
            counts = self.counts()
            for backend, healthy in call["health"].items():
                if healthy:
                    snapshots.pop(backend, None)
                    continue
                prior = snapshots.get(backend, (0.0, 0))[0]
                rate = prior if prior > 0.0001 else float(counts[backend]) / 5.0
                snapshots[backend] = (rate, now)
            for backend, (_, accessed) in list(snapshots.items()):
                if accessed + 60_000_000_000 < now:
                    del snapshots[backend]

    def resolve_effect(self, event):
        effect_ref = event.get("effect_ref")
        if effect_ref is None:
            return None
        actual = self.logical_to_actual.get(event.get("session", ""), event.get("session", ""))
        if effect_ref in self.effect_refs:
            effect = self.effect_refs[effect_ref]
            require(self.effect_ref_sessions[effect_ref] == event.get("session", ""),
                    "EFFECT_LEDGER", f"relative effect {effect_ref} crossed sessions")
            return effect
        if effect_ref in self.skipped_effect_refs:
            require(self.effect_ref_sessions[effect_ref] == event.get("session", ""),
                    "EFFECT_LEDGER", f"relative callback {effect_ref} crossed sessions")
            require(not any(effect["session"] == actual for effect in self.redirects.values()),
                    "EFFECT_LEDGER",
                    f"relative callback {effect_ref} skipped a same-session redirect")
            return None
        position = next((i for i, effect in enumerate(self.unbound_redirects)
                         if effect["session"] == actual), None)
        if position is None and event["op"] == "close" and self.unbound_redirects:
            # The strict delayed close establishes which engine-local session
            # the recording's logical close handle denotes.
            position = 0
        if position is not None:
            effect = self.unbound_redirects.pop(position)
            self.effect_refs[effect_ref] = effect
            self.effect_ref_sessions[effect_ref] = event.get("session", "")
            return effect
        require(not any(effect["session"] == actual for effect in self.redirects.values()),
                "EFFECT_LEDGER",
                f"relative callback {effect_ref} skipped a same-session redirect")
        require(event.get("optional_effect") is True, "EFFECT_LEDGER",
                f"unknown relative effect {effect_ref}")
        self.skipped_effect_refs.add(effect_ref)
        self.effect_ref_sessions[effect_ref] = event.get("session", "")
        return None

    def resolve_event(self, event):
        """Resolve a logical trace handle to this engine's concrete session.

        A scripted close of the connection carrying a delayed accepted redirect
        swaps logical handles. Later ordinary close events therefore still close
        every remaining concrete connection exactly once.
        """
        logical = event.get("session", "")
        if "effect_ref" not in event:
            return self.logical_to_actual.get(logical, logical)
        effect = self.resolve_effect(event)
        if effect is None:
            return ""
        actual = effect["session"]
        if event["op"] == "close":
            require(logical in self.logical_to_actual and actual in self.logical_to_actual.values(),
                    "EFFECT_LEDGER", "relative close requires two live handles")
            other = next(name for name, value in self.logical_to_actual.items() if value == actual)
            displaced = self.logical_to_actual[logical]
            self.logical_to_actual[logical], self.logical_to_actual[other] = actual, displaced
        return actual

    def resolve_operation(self, event):
        if "effect_ref" in event:
            effect = self.resolve_effect(event)
            return effect["operation"] if effect is not None else ""
        return event.get("operation", "")

    def _group_redirect_options(self, event, group, now, refuse_next):
        members = {item["backend"]: item for item in group["members"]}
        if len(members) <= 1:
            return [([], refuse_next)]
        counts = self.counts()
        physical = Counter(self.assigned.values())
        bits = {backend: (int(not item["healthy"]), min(counts[backend], 65535))
                for backend, item in members.items()}
        minimum = min(bits.values())
        if minimum[0]:
            return [([], refuse_next)]
        refused = {self.logical_to_actual.get(sid, sid) for sid in event.get("refuse", [])}
        options = []
        for target in sorted(backend for backend in members if bits[backend] == minimum):
            sources = []
            for source in members:
                if bits[source] <= minimum or physical[source] == 0 or counts[source] <= 0:
                    continue
                if not members[source]["healthy"]:
                    snapshot = self.status_snapshots.get(group["group"], {}).get(source)
                    require(snapshot is not None, "EFFECT_LEDGER", f"missing status cadence for {source}")
                    rate = self.status_rate if self.status_rate > 0 else snapshot[0]
                else:
                    if float(counts[source]) <= float(counts[target] + 1) * self.ratio:
                        continue
                    rate = self.rate if self.rate > 0 else max(
                        0.0,
                        (float(counts[source] + counts[target] + 1) / (1 + self.ratio)
                         - float(counts[target] + 1)) / 120,
                    )
                if rate > 0.0001:
                    sources.append((source, rate))
            if not sources:
                options.append(([], refuse_next))
                continue
            busiest = max(bits[source] for source, _ in sources)
            for source, rate in sorted(sources):
                if bits[source] != busiest:
                    continue
                if members[source]["keyspace"] != members[target]["keyspace"]:
                    options.append(([], refuse_next))
                    continue
                interval = int(1_000_000_000.0 / rate)
                require(interval > 0, "EFFECT_LEDGER", "unsupported migration interval")
                last = self.group_last_redirect.get(group["group"])
                if interval < 20_000_000:
                    budget = (10_000_000 - 1) // interval + 1
                elif last is None or now - last >= interval:
                    budget = 1
                else:
                    options.append(([], refuse_next))
                    continue
                remaining_refusal = refuse_next
                effects = []
                for sid in sorted(self.assigned, key=lambda item: self.created[item]):
                    if budget == 0:
                        break
                    if (self.assigned[sid] != source or sid in self.closing
                            or any(effect["session"] == sid for effect in self.redirects.values())):
                        continue
                    if (self.redirect_failed.get(sid, False) and sid in self.last_redirect
                            and now < self.last_redirect[sid] + 3_000_000_000):
                        continue
                    scripted = sid in refused
                    if not scripted and remaining_refusal:
                        scripted, remaining_refusal = True, remaining_refusal - 1
                    effects.append({"kind": "redirect", "session": sid,
                                    "operation": f"{sid}/{self.ordinals[sid] + 1}",
                                    "from": source, "to": target, "accepted": not scripted})
                    budget -= int(not scripted)
                options.append((effects, remaining_refusal))
        unique = {}
        for effects, remaining in options:
            key = (json.dumps(causal(effects), sort_keys=True), remaining)
            unique[key] = (effects, remaining)
        return list(unique.values())

    def redirect_effect_alternatives(self, event, model, now):
        groups = model["groups"]
        orders = itertools.permutations(groups) if event.get("refuse_next", 0) and len(groups) > 1 else [groups]
        alternatives = []
        for order in orders:
            partial = [([], event.get("refuse_next", 0))]
            for group in order:
                expanded = []
                for effects, refusal in partial:
                    for more, remaining in self._group_redirect_options(event, group, now, refusal):
                        expanded.append((effects + more, remaining))
                        require(len(expanded) <= 256, "INPUT", "redirect cadence alternatives")
                partial = expanded
            alternatives.extend(partial)
        unique = {}
        for effects, remaining in alternatives:
            key = (json.dumps(causal(effects), sort_keys=True), remaining)
            unique[key] = (effects, remaining)
        return list(unique.values())

    def expected_effect_alternatives(self, event, expect, now):
        if "redirect_cadence" not in expect:
            if "force_close_due" in expect:
                effects, refusal = self._force_close_effects(event, expect["force_close_due"], event.get("refuse_next", 0))
                return [effects] if refusal == 0 else []
            effects = expect.get("effects", [])
            refusal = event.get("refuse_next", 0)
            refused = {self.logical_to_actual.get(sid, sid) for sid in event.get("refuse", [])}
            for effect in effects:
                if effect["session"] not in refused and refusal:
                    if effect["accepted"]:
                        return []
                    refusal -= 1
            return [effects] if refusal == 0 else []
        alternatives = []
        for redirects, refusal in self.redirect_effect_alternatives(event, expect["redirect_cadence"], now):
            closes, refusal = self._force_close_effects(event, expect.get("force_close_due", []), refusal)
            if refusal == 0:
                alternatives.append(redirects + closes)
        return alternatives

    def apply(self, event, row, sid=None, operation=None, index=0, prepared=False):
        op = event["op"]
        if not prepared:
            self.prepare(event, event.get("expect", {}), row, event.get("at_nanos", 0))
        sid = event.get("session", "") if sid is None else sid
        operation = event.get("operation", "") if operation is None else operation
        if op == "open":
            self.logical_to_actual[event["session"]] = sid
        elif op == "next" and row["outcome"] == "ok":
            self.pending[sid] = row["backend"]
        elif op == "finish":
            backend = self.pending.pop(sid)
            if event["success"]:
                self.assigned[sid] = backend
                self.created[sid] = index
        elif op == "rehydrate" and row["outcome"] == "ok":
            self.assigned[sid] = row["backend"]
            self.created[sid] = index
        elif op == "redirect_result":
            effect = self.redirects.pop(operation, None)
            self.unbound_redirects = [item for item in self.unbound_redirects
                                      if item["operation"] != operation]
            if effect is not None:
                self.redirect_failed[sid] = not event["success"]
                if sid in self.assigned and event["success"]:
                    self.assigned[sid] = effect["to"]
                    self.created[sid] = index
        elif op == "close":
            self.assigned.pop(sid, None)
            self.pending.pop(sid, None)
            self.created.pop(sid, None)
            self.last_redirect.pop(sid, None)
            self.redirect_failed.pop(sid, None)
            self.closing.discard(sid)
            self.redirects = {key: ef for key, ef in self.redirects.items() if ef["session"] != sid}
            self.unbound_redirects = [effect for effect in self.unbound_redirects
                                      if effect["session"] != sid]
            self.logical_to_actual.pop(event["session"], None)
        model = event.get("expect", {}).get("redirect_cadence", {})
        group_for = {member["backend"]: group["group"]
                     for group in model.get("groups", []) for member in group["members"]}
        for effect in row.get("effects", []):
            self.ordinals[effect["session"]] += 1
            require(effect["operation"] == f"{effect['session']}/{self.ordinals[effect['session']]}",
                    "EFFECT_LEDGER", "non-monotonic effect operation")
            if effect["kind"] == "force_close" and effect["accepted"]:
                self.closing.add(effect["session"])
            if effect["kind"] == "redirect":
                self.last_redirect[effect["session"]] = event.get("at_nanos", 0)
                self.redirect_failed[effect["session"]] = not effect["accepted"]
            if effect["kind"] == "redirect" and effect["accepted"]:
                require(self.assigned.get(effect["session"]) == effect["from"]
                        and not any(ef["session"] == effect["session"] for ef in self.redirects.values()),
                        "EFFECT_LEDGER", "redirect requires one established owner and no pending redirect")
                self.redirects[effect["operation"]] = effect
                group = group_for.get(effect["from"], self.backend_groups.get(effect["from"]))
                if group is not None:
                    self.group_last_redirect[group] = event.get("at_nanos", 0)
                self.unbound_redirects.append(effect)


def observe(trace, rows, engine):
    events = trace["events"]
    require(isinstance(rows,list) and len(rows) == len(events), "MISSING_RESULT", engine)
    pending, ledger, previous, operations, settled = {}, {}, {}, {}, set()
    settled_by = {}
    excluded = {}
    connections = PublicConnections(trace["config"])
    for index, (event,row) in enumerate(zip(events,rows)):
        op, expect = event["op"], event["expect"]
        now = event.get("at_nanos", 0)
        fields = {"seq","op","session","outcome","backend","effects"} | ({"assignments","conn_count","healthy_backend_count","server_version"} if op == "checkpoint" else set())
        require(isinstance(row,dict) and set(row) == fields and type(row.get("seq")) is int
                and row.get("seq") == index and row.get("op") == op,
                "RESULT_IDENTITY", f"{engine} event {index}")
        connections.prepare(event, expect, row, now)
        session = connections.resolve_event(event)
        operation = connections.resolve_operation(event)
        require(row.get("session") == session, "RESULT_IDENTITY", f"{engine} event {index}")
        expected_outcome = ("no_effect" if event.get("optional_effect") and not operation
                            else expect["outcome"])
        require(row.get("outcome") == expected_outcome, "ERROR_OUTCOME",
                f"{engine} event {index}: {row.get('outcome')} != {expected_outcome}")
        expected_effects = connections.expected_effect_alternatives(event, expect, now)
        require(any(causal(row["effects"]) == causal(alternative) for alternative in expected_effects),
                "EFFECTS", f"{engine} event {index}")
        for effect in row["effects"]:
            require(effect["from"] == ledger.get(effect["session"]) and effect["operation"] not in operations,"EFFECT_LEDGER",f"{engine} {index}")
            operations[effect["operation"]] = effect
            if not effect["accepted"]:
                settled.add(effect["operation"])
                settled_by[effect["operation"]] = "refused"
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
            key = operation
            if key:
                require(key in operations,"EFFECT_LEDGER",f"{engine} missing accepted effect")
                if key not in settled:
                    settled_by[key] = "callback"
                    if session in ledger and event["success"]:
                        ledger[session] = operations[key]["to"]
                settled.add(key)
            else:
                require(event.get("optional_effect") is True, "EFFECT_LEDGER",
                        f"{engine} missing required accepted effect")
        elif op == "close":
            excluded.pop(session, None)
            previous.pop(session, None)
            ledger.pop(session,None)
            closing = {key for key,effect in operations.items()
                       if effect["session"] == session and key not in settled}
            settled.update(closing)
            settled_by.update((key, "close") for key in closing)
        elif op == "checkpoint":
            require(type(row.get("healthy_backend_count")) is int and row["healthy_backend_count"] >= 0 and isinstance(row.get("server_version"),str),"OBSERVATION","public metadata types")
            if "healthy_backend_count" in expect:
                require(row["healthy_backend_count"] == expect["healthy_backend_count"],"OBSERVATION",f"{engine} healthy count {index}")
            if "legal_server_versions" in expect:
                require(row["server_version"] in expect["legal_server_versions"],"OBSERVATION",f"{engine} server version {index}")
            require(row.get("assignments") == ledger and type(row.get("conn_count")) is int and row["conn_count"] == len(ledger), "LEDGER", f"{engine} checkpoint {index}")
        connections.apply(event, row, session, operation, index, prepared=True)
    unsettled = [key for key,effect in operations.items()
                 if effect["accepted"] and key not in settled]
    require(not ledger and not pending and not unsettled
            and not connections.pending and not connections.assigned
            and not connections.redirects and not connections.unbound_redirects
            and not connections.logical_to_actual,
            "LEDGER", f"{engine} final state")
    accepted_redirects = [(key, effect) for key,effect in operations.items()
                          if effect["accepted"] and effect["kind"] == "redirect"]
    accepted_force_closes = [(key, effect) for key,effect in operations.items()
                             if effect["accepted"] and effect["kind"] == "force_close"]
    callback_rows = [row for event,row in zip(events,rows)
                     if event["op"] == "redirect_result"]
    return {
        "accepted_effects": len(accepted_redirects) + len(accepted_force_closes),
        "accepted_redirects": len(accepted_redirects),
        "accepted_force_closes": len(accepted_force_closes),
        "callback_events": len(callback_rows),
        "completed_callbacks": sum(row["outcome"] == "ok" for row in callback_rows),
        "no_effect_callbacks": sum(row["outcome"] == "no_effect" for row in callback_rows),
        "callback_settled_redirects": sum(settled_by.get(key) == "callback"
                                          for key,_ in accepted_redirects),
        "close_settled_redirects": sum(settled_by.get(key) == "close"
                                       for key,_ in accepted_redirects),
        "other_settled_redirects": sum(settled_by.get(key) not in {"callback", "close"}
                                       for key,_ in accepted_redirects),
        "close_settled_force_closes": sum(settled_by.get(key) == "close"
                                          for key,_ in accepted_force_closes),
        "unsettled_accepted_effects": len(unsettled),
        "all_accepted_settled": not unsettled,
        "accepted_operations": [
            {"operation": key, "kind": effect["kind"], "session": effect["session"],
             "settled_by": settled_by.get(key, "unsettled")}
            for key,effect in operations.items() if effect["accepted"]
        ],
    }


def compare(trace, go, rust):
    validate(trace)
    go_effect_ledger = observe(trace,go,"go")
    rust_effect_ledger = observe(trace,rust,"rust")
    for event, left, right in zip(trace["events"],go,rust):
        if event["op"] == "checkpoint":
            require(left["healthy_backend_count"] == right["healthy_backend_count"],"OBSERVATION","healthy backend counts differ")
            if "legal_server_versions" not in event["expect"]:
                require(left["server_version"] == right["server_version"],"OBSERVATION","undeclared server version divergence")
    # Exact errors/effects agree by both satisfying the same public expectation.
    # Legal random backend divergence is retained in raw results; never feed
    # one engine's result into the other's input or compare private scores.
    return {"events":len(trace["events"]),"violations":0,
            "provenance":trace["provenance"]["kind"],
            "effect_ledger":{"go":go_effect_ledger,"rust":rust_effect_ledger}}


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
    for name in ("factor_cpu.go", "factor_memory.go", "factor_health.go", "factor_status.go"):
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
