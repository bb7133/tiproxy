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


def neutral_health_metrics(updated, risky=None, backends=None):
    packet = dict.fromkeys(derive._RUNNER.METRIC_KEYS)
    backends = backends or health()
    for failure_key, total_key in (("failure_pd", "total_pd"),
                                   ("failure_tikv", "total_tikv")):
        packet[failure_key] = {"kind": "vector", "updated_nanos": updated, "series": []}
        packet[total_key] = {"kind": "vector", "updated_nanos": updated, "series": []}
        for backend in backends:
            labels = {"instance": f"{backend['ip']}:{backend['status_port']}",
                      "tiproxy_cluster": backend.get("cluster") or "default"}
            failure = 1 if backend["address"] == risky else 0
            packet[failure_key]["series"].append(
                {"labels": labels, "samples": [{"timestamp_ms": updated // 1_000_000, "value": str(failure)}]})
            packet[total_key]["series"].append(
                {"labels": labels, "samples": [{"timestamp_ms": updated // 1_000_000, "value": "1"}]})
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

    def test_shared_public_metric_owner_keeps_the_policy_dependency(self):
        trace = copy.deepcopy(self.trace)
        health_event = next(event for event in trace["events"] if event["op"] == "health")
        health_event["backends"][1]["status_port"] = health_event["backends"][0]["status_port"]
        _, requires = derive.derive(trace, self.rows, None)
        self.assertIn("policy-constraint:resource/prefer-idle", requires)

    def test_stable_health_scoring_is_modeled_but_identity_change_is_explicit(self):
        trace = copy.deepcopy(self.trace)
        index = next(i for i, event in enumerate(trace["events"]) if event["op"] == "open")
        trace["events"].insert(index, {"op": "health", "at_nanos": 0, "backends": health()})
        rows = copy.deepcopy(self.rows)
        rows.insert(index, {"seq": index, "op": "health", "session": "", "outcome": "ok", "backend": "", "effects": []})
        for seq, row in enumerate(rows):
            row["seq"] = seq
        _, requires = derive.derive(trace, rows, None)
        self.assertEqual(requires, [])
        trace["events"][index]["backends"][1]["status_port"] = 10082
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

    def test_location_no_data_metrics_reduce_to_each_engines_connection_history(self):
        backends = health()
        events = [
            {"op": "health", "at_nanos": 0, "backends": backends},
            {"op": "metrics", "at_nanos": 0, "queries": neutral_health_metrics(ORIGIN)},
        ]
        choices = (A, A, B)
        for index, backend in enumerate(choices, 1):
            session = f"s{index}"
            events += [
                {"op": "open", "at_nanos": index, "session": session, "client": "", "proxy": "", "port": ""},
                {"op": "next", "at_nanos": index, "session": session},
                {"op": "finish", "at_nanos": index, "session": session, "success": True},
            ]
        events += [{"op": "close", "at_nanos": 10, "session": f"s{index}"} for index in range(1, 4)]
        events.append({"op": "checkpoint", "at_nanos": 10})
        trace = {"version": 1, "id": "location-connection-only", "config": {
            "policy": "location", "selection": "prefer-idle", "rule": "",
            "clock_origin_nanos": ORIGIN}, "provenance": {"kind": "synthetic"}, "events": events}
        rows = []
        choice_iter = iter(choices)
        for seq, event in enumerate(events):
            row = {"seq": seq, "op": event["op"], "session": event.get("session", ""),
                   "outcome": "ok", "backend": "", "effects": []}
            if event["op"] == "next":
                row["backend"] = next(choice_iter)
            if event["op"] == "checkpoint":
                row.update(assignments={}, conn_count=0, healthy_backend_count=2, server_version="")
            rows.append(row)
        derived, requires = derive.derive(trace, rows, None)
        self.assertEqual(requires, [])
        next_events = [event["expect"] for event in derived["events"] if event["op"] == "next"]
        self.assertTrue(all(event.get("exclude_history") and event.get("prefer_idle_conn") for event in next_events))
        derive._RUNNER.validate(derived)
        derive._RUNNER.compare(derived, rows, rows)

        wrong = copy.deepcopy(rows)
        third_next = [i for i, event in enumerate(events) if event["op"] == "next"][2]
        wrong[third_next]["backend"] = A
        with self.assertRaisesRegex(derive.Refuse, "outside Go's own legal set"):
            derive.derive(trace, wrong, None)

    def test_location_risky_health_keeps_policy_constraint(self):
        events = [{"op": "health", "at_nanos": 0, "backends": health()},
                  {"op": "metrics", "at_nanos": 0, "queries": neutral_health_metrics(ORIGIN, risky=B)},
                  {"op": "open", "at_nanos": 1, "session": "s", "client": "", "proxy": "", "port": ""},
                  {"op": "next", "at_nanos": 1, "session": "s"},
                  {"op": "finish", "at_nanos": 1, "session": "s", "success": False},
                  {"op": "close", "at_nanos": 1, "session": "s"}]
        trace = {"config": {"policy": "location", "selection": "prefer-idle", "rule": "",
                            "clock_origin_nanos": ORIGIN}, "events": events}
        _, requires = derive.derive(trace, derive.rows_for(events, e3=A), None)
        self.assertEqual(requires, ["policy-constraint:location/prefer-idle"])

    def test_earlier_cpu_data_prevents_no_data_reduction(self):
        first = neutral_health_metrics(ORIGIN)
        first["cpu"] = metrics(ORIGIN, 0.9, 0.1, ORIGIN // 1_000_000)["cpu"]
        events = [
            {"op": "health", "at_nanos": 0, "backends": health()},
            {"op": "metrics", "at_nanos": 0, "queries": first},
            {"op": "open", "at_nanos": 1, "session": "prime", "client": "", "proxy": "", "port": ""},
            {"op": "next", "at_nanos": 1, "session": "prime"},
            {"op": "finish", "at_nanos": 1, "session": "prime", "success": True},
            {"op": "metrics", "at_nanos": 2, "queries": neutral_health_metrics(ORIGIN + 2)},
            {"op": "open", "at_nanos": 3, "session": "after", "client": "", "proxy": "", "port": ""},
            {"op": "next", "at_nanos": 3, "session": "after"},
        ]
        trace = {"config": {"policy": "location", "selection": "prefer-idle", "rule": "",
                            "clock_origin_nanos": ORIGIN}, "events": events}
        rows = derive.rows_for(events, e3=B, e7=B)
        _, requires = derive.derive(trace, rows, None)
        self.assertEqual(requires, ["policy-constraint:location/prefer-idle"])

    def test_resource_proxy_cidr_reduction_is_group_scoped(self):
        addresses = (A, B, "127.0.0.1:4002", "127.0.0.1:4003")
        backends = []
        for index, address in enumerate(addresses):
            proxy_cidr = "127.0.0.1/32" if index < 2 else "127.0.0.2/32"
            backends.append({
                "address": address, "cluster": "", "ip": "127.0.0.1",
                "status_port": 10080 + index, "labels": {"cidr": proxy_cidr},
                "healthy": True, "local": True, "server_version": "",
                "support_redirection": False,
            })
        events = [
            {"op": "health", "at_nanos": 0, "backends": backends},
            {"op": "metrics", "at_nanos": 0, "queries": neutral_health_metrics(ORIGIN, backends=backends)},
        ]
        choices = (A, A, B, addresses[2], addresses[2], addresses[3])
        for index, backend in enumerate(choices, 1):
            proxy = "127.0.0.1:6000" if index <= 3 else "127.0.0.2:6000"
            session = f"g{1 if index <= 3 else 2}-{index}"
            events += [
                {"op": "open", "at_nanos": index, "session": session,
                 "client": "127.0.0.9:7000", "proxy": proxy, "port": ""},
                {"op": "next", "at_nanos": index, "session": session},
                {"op": "finish", "at_nanos": index, "session": session, "success": True},
            ]
        events += [{"op": "close", "at_nanos": 10, "session": f"g{1 if index <= 3 else 2}-{index}"}
                   for index in range(1, 7)]
        events.append({"op": "checkpoint", "at_nanos": 10})
        trace = {"version": 1, "id": "resource-proxy-cidr-connection-only", "config": {
            "policy": "resource", "selection": "prefer-idle", "rule": "proxy_cidr",
            "clock_origin_nanos": ORIGIN}, "provenance": {"kind": "synthetic"}, "events": events}
        rows, choice_iter = [], iter(choices)
        for seq, event in enumerate(events):
            row = {"seq": seq, "op": event["op"], "session": event.get("session", ""),
                   "outcome": "ok", "backend": "", "effects": []}
            if event["op"] == "next":
                row["backend"] = next(choice_iter)
            if event["op"] == "checkpoint":
                row.update(assignments={}, conn_count=0, healthy_backend_count=4, server_version="")
            rows.append(row)
        derived, requires = derive.derive(trace, rows, None)
        self.assertEqual(requires, [])
        self.assertTrue(all(event["expect"].get("prefer_idle_conn")
                            for event in derived["events"] if event["op"] == "next"))
        derive._RUNNER.validate(derived)
        derive._RUNNER.compare(derived, rows, rows)

        wrong = copy.deepcopy(rows)
        third_next = [i for i, event in enumerate(events) if event["op"] == "next"][2]
        wrong[third_next]["backend"] = A
        with self.assertRaisesRegex(derive.Refuse, "outside Go's own legal set"):
            derive.derive(trace, wrong, None)


if __name__ == "__main__":
    unittest.main()
