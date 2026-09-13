# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Bounded Resource expectations use public metric packets, never output rows."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

HERE = Path(__file__).resolve().parent


def load_deriver():
    spec = importlib.util.spec_from_file_location("resource_metric_deriver", HERE / "derive_expectations.py")
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


derive = load_deriver()
A, B = "127.0.0.1:4000", "127.0.0.1:4001"
ORIGIN = 1_800_000_000_000_000_000


def health():
    return [{"address": A, "cluster": "", "ip": "127.0.0.1", "status_port": 10080,
             "labels": {}, "healthy": True, "local": True, "server_version": "",
             "support_redirection": False},
            {"address": B, "cluster": "", "ip": "127.0.0.1", "status_port": 10081,
             "labels": {}, "healthy": True, "local": True, "server_version": "",
             "support_redirection": False}]


def metrics(updated, a, b, sample_ms):
    packet = dict.fromkeys(derive._RUNNER.METRIC_KEYS)
    packet["cpu"] = {"kind": "matrix", "updated_nanos": updated, "series": [
        {"labels": {"instance": "127.0.0.1:10080"},
         "samples": [{"timestamp_ms": sample_ms, "value": str(a)}]},
        {"labels": {"instance": "127.0.0.1:10081"},
         "samples": [{"timestamp_ms": sample_ms, "value": str(b)}]},
    ]}
    return packet


def scenario():
    events = []

    def add(op, at, **fields):
        events.append({"op": op, "at_nanos": at, **fields})

    def attempt(name, at):
        add("open", at, session=name, client="", proxy="", port="")
        add("next", at, session=name)
        add("finish", at, session=name, success=False)
        add("close", at, session=name)

    sample = ORIGIN // 1_000_000
    add("health", 0, backends=health())
    add("metrics", 0, queries=metrics(ORIGIN, 0.1, 0.9, sample))
    attempt("first", 0)
    attempt("same-publication", 10)
    # A different payload with the same QueryResult update time is not a new
    # factor snapshot; it must not silently become a new public oracle.
    add("metrics", 50, queries=metrics(ORIGIN, 0.9, 0.1, sample + 1))
    attempt("same-update-time", 50)
    add("metrics", 100, queries=metrics(ORIGIN + 100, 0.9, 0.1, sample + 1))
    attempt("new-update-time", 100)
    attempt("expiry-equality", 120_000_000_100)
    attempt("expiry-plus-one", 120_000_000_101)
    add("checkpoint", 120_000_000_101)
    trace = {"version": 1, "id": "resource-cpu-public-input", "config": {
        "policy": "resource", "selection": "prefer-idle", "rule": "",
        "clock_origin_nanos": ORIGIN}, "provenance": {
            "kind": "synthetic", "description": "CPU-only Resource selection boundaries"},
        "events": events}
    choices = iter([A, A, A, B, B, A])
    rows = []
    for seq, event in enumerate(events):
        row = {"seq": seq, "op": event["op"], "session": event.get("session", ""),
               "outcome": "ok", "backend": "", "effects": []}
        if event["op"] == "next":
            row["backend"] = next(choices)
        if event["op"] == "checkpoint":
            row.update(assignments={}, conn_count=0, healthy_backend_count=2, server_version="")
        rows.append(row)
    return trace, rows


class ResourceMetricTests(unittest.TestCase):
    def setUp(self):
        self.trace, self.rows = scenario()

    def test_complete_cpu_packets_derive_selection_update_and_expiry(self):
        derived, requires = derive.derive(self.trace, self.rows, None)
        self.assertEqual(requires, [])
        choices = [event["expect"] for event in derived["events"] if event["op"] == "next"]
        self.assertEqual([choice.get("backend") for choice in choices[:5]], [A, A, A, B, B])
        self.assertEqual(choices[5]["legal_backends"], [A, B])
        derive._RUNNER.validate(derived)
        derive._RUNNER.compare(derived, self.rows, self.rows)

    def test_rows_cannot_choose_against_the_public_cpu_packet(self):
        rows = copy.deepcopy(self.rows)
        index = next(i for i, event in enumerate(self.trace["events"]) if event["op"] == "next")
        rows[index]["backend"] = B
        with self.assertRaisesRegex(derive.Refuse, "outside Go's own legal set"):
            derive.derive(self.trace, rows, None)

    def test_changed_public_cpu_values_change_the_derivation(self):
        trace = copy.deepcopy(self.trace)
        first = next(event for event in trace["events"] if event["op"] == "metrics")
        first["queries"] = metrics(ORIGIN, 0.9, 0.1, ORIGIN // 1_000_000)
        with self.assertRaisesRegex(derive.Refuse, "outside Go's own legal set"):
            derive.derive(trace, self.rows, None)

    def test_incomplete_factor_inputs_keep_the_policy_dependency(self):
        def incomplete_memory(packet):
            packet["memory"] = copy.deepcopy(packet["cpu"])
            packet["memory"]["series"].pop()

        for mutate in (lambda packet: packet["cpu"]["series"].pop(), incomplete_memory):
            trace = copy.deepcopy(self.trace)
            trace["events"] = trace["events"][:6]
            rows = copy.deepcopy(self.rows[:6])
            packet = next(event["queries"] for event in trace["events"] if event["op"] == "metrics")
            mutate(packet)
            _, requires = derive.derive(trace, rows, None)
            self.assertIn("policy-constraint:resource/prefer-idle", requires)

    def test_intervening_health_scoring_keeps_unmodeled_history_explicit(self):
        trace = copy.deepcopy(self.trace)
        index = next(i for i, event in enumerate(trace["events"]) if event["op"] == "open")
        trace["events"].insert(index, {"op": "health", "at_nanos": 0, "backends": health()})
        rows = copy.deepcopy(self.rows)
        rows.insert(index, {"seq": index, "op": "health", "session": "", "outcome": "ok", "backend": "", "effects": []})
        for seq, row in enumerate(rows):
            row["seq"] = seq
        _, requires = derive.derive(trace, rows, None)
        self.assertIn("policy-constraint:resource/prefer-idle", requires)

    def test_existing_all_factor_time_fixture_is_independently_derived(self):
        trace = json.loads((HERE.parent / "metrics-time-smoke.json").read_text())
        rows = []
        for event in trace["events"]:
            row = {"op": event["op"], "outcome": event["expect"]["outcome"],
                   "backend": event["expect"].get("backend", ""), "effects": []}
            if event["op"] == "checkpoint":
                row.update(assignments={}, conn_count=0, healthy_backend_count=2, server_version="8.5.1")
            rows.append(row)
        derived, requires = derive.derive(trace, rows, None)
        self.assertEqual(requires, [])
        self.assertEqual(derive.compare_with_reference(derived, trace, requires), ([], []))

    def test_all_factor_fixture_rejects_a_memory_result_from_the_wrong_backend(self):
        trace = json.loads((HERE.parent / "metrics-time-smoke.json").read_text())
        rows = [{"op": event["op"], "outcome": event["expect"]["outcome"],
                 "backend": event["expect"].get("backend", ""), "effects": []}
                for event in trace["events"]]
        event = next(i for i, item in enumerate(trace["events"])
                     if item.get("session") == "memory-epoch" and item["op"] == "next")
        rows[event]["backend"] = B
        with self.assertRaisesRegex(derive.Refuse, "outside Go's own legal set"):
            derive.derive(trace, rows, None)

    def test_memory_and_health_public_values_change_the_derivation(self):
        for session, keys in (("memory-epoch", ("memory",)),
                              ("pd-epoch", ("failure_pd", "total_pd"))):
            trace = json.loads((HERE.parent / "metrics-time-smoke.json").read_text())
            rows = [{"op": event["op"], "outcome": event["expect"]["outcome"],
                     "backend": event["expect"].get("backend", ""), "effects": []}
                    for event in trace["events"]]
            next_index = next(i for i, event in enumerate(trace["events"])
                              if event.get("session") == session and event["op"] == "next")
            packet = trace["events"][next_index - 2]["queries"]
            for key in keys:
                left, right = packet[key]["series"]
                left["samples"], right["samples"] = right["samples"], left["samples"]
            with self.assertRaisesRegex(derive.Refuse, "outside Go's own legal set"):
                derive.derive(trace, rows, None)


if __name__ == "__main__":
    unittest.main()
