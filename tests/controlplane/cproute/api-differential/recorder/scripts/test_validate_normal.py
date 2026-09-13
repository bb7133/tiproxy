# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Normal-slot event validator and record_slot preflight: positive traces and one-fault mutations."""
import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import record_slot  # noqa: E402
import validate_normal as v  # noqa: E402

ROWS = v.slot_rows()
TWO_CLUSTERS = '[proxy]\n[[proxy.backend-clusters]]\nname = "default"\n[[proxy.backend-clusters]]\nname = "conflict"\n'
ONE_CLUSTER = '[proxy]\n[[proxy.backend-clusters]]\nname = "default"\n'


class Trace:
    def __init__(self, row):
        self.labels = {v.instance_address(n): l for n, l in v.parse_labels(row["labels"]).items()}
        self.events, self.go = [], []

    def add(self, event, outcome="ok", backend=""):
        self.go.append({"seq": len(self.events), "op": event["op"], "session": event.get("session", ""),
                        "outcome": outcome, "backend": backend, "effects": []})
        self.events.append(event)

    def health(self, down=()):
        self.add({"op": "health", "backends": [
            {"address": a, "cluster": "default", "healthy": a not in down, "labels": l} for a, l in self.labels.items()]})

    def session(self, s, client="127.0.0.1", port="6000", *steps):
        self.add({"op": "open", "session": s, "client": client + ":1", "proxy": client + ":1", "port": port})
        for outcome, backend, success in steps:
            self.add({"op": "next", "session": s}, outcome, "default/" + backend if backend else "")
            if outcome == "ok":
                self.add({"op": "finish", "session": s, "success": success})
        self.add({"op": "close", "session": s})

    def result(self, row):
        return v.validate(row, {"events": self.events}, self.go)[0]


def cidr_trace():
    t = Trace(ROWS["N02"])
    t.session("a0", "127.0.0.1", "6000", ("no_backend", "", None))
    t.session("b0", "127.0.0.2", "6000", ("no_backend", "", None))
    t.health()
    t.session("a1", "127.0.0.1", "6000", ("ok", "127.0.0.1:4002", False), ("ok", "127.0.0.1:4003", True))
    t.session("b1", "127.0.0.2", "6000", ("no_backend", "", None))
    t.health(down=("127.0.0.1:4002", "127.0.0.1:4003"))
    t.session("a2", "127.0.0.1", "6000", ("no_backend", "", None))
    t.health()
    t.session("a3", "127.0.0.1", "6000", ("ok", "127.0.0.1:4002", True))
    return t


def port_trace():
    t = Trace(ROWS["N04"])
    t.session("p0", "127.0.0.1", "6000", ("no_backend", "", None))
    t.health()
    t.session("p1", "127.0.0.1", "6000", ("ok", "127.0.0.1:4000", False), ("ok", "127.0.0.1:4001", True))
    t.session("q1", "127.0.0.1", "6001", ("ok", "127.0.0.1:4002", True))
    t.health(down=("127.0.0.1:4000", "127.0.0.1:4001"))
    t.session("p2", "127.0.0.1", "6000", ("no_backend", "", None))
    t.session("q2", "127.0.0.1", "6001", ("ok", "127.0.0.1:4003", True))
    t.health()
    t.session("p3", "127.0.0.1", "6000", ("ok", "127.0.0.1:4000", True))
    t.add({"op": "config", "toml": TWO_CLUSTERS})
    t.session("p4", "127.0.0.1", "6000", ("port_conflict", "", None))
    t.session("q4", "127.0.0.1", "6001", ("port_conflict", "", None))
    t.add({"op": "config", "toml": ONE_CLUSTER})
    t.health()
    t.session("p5", "127.0.0.1", "6000", ("ok", "127.0.0.1:4001", True))
    t.session("q5", "127.0.0.1", "6001", ("ok", "127.0.0.1:4003", True))
    return t


def mutate(t, session, op, **fields):
    t = copy.deepcopy(t)
    for e, g in zip(t.events, t.go):
        if e.get("session") == session and e["op"] == op:
            g.update({k: fields[k] for k in ("outcome", "backend") if k in fields})
            e.update({k: fields[k] for k in ("success",) if k in fields})
            return t
    raise AssertionError(f"no {op} for {session}")


def drop(t, session):
    t = copy.deepcopy(t)
    keep = [(e, g) for e, g in zip(t.events, t.go) if e.get("session") != session]
    t.events = [e for e, _ in keep]
    t.go = [dict(g, seq=i) for i, (_, g) in enumerate(keep)]
    return t


class NormalValidatorTests(unittest.TestCase):
    def assertFails(self, t, row, needle):
        problems = t.result(row)
        self.assertTrue(any(needle in p for p in problems), problems)

    def test_positive_traces_pass(self):
        self.assertEqual(cidr_trace().result(ROWS["N02"]), [])
        self.assertEqual(port_trace().result(ROWS["N04"]), [])

    def test_cidr_mutations_are_detected(self):
        row = ROWS["N02"]
        self.assertFails(mutate(cidr_trace(), "b1", "next", outcome="ok", backend="default/127.0.0.1:4000"),
                         row, "no-match context got outcomes other than no_backend")
        self.assertFails(drop(drop(cidr_trace(), "b0"), "b1"), row, "needs both a matching and a non-matching context")
        self.assertFails(mutate(cidr_trace(), "a2", "next", outcome="ok", backend="default/127.0.0.1:4002"),
                         row, "non-no_backend next during a whole routed-group outage")
        self.assertFails(drop(cidr_trace(), "a3"), row, "no recovery success")
        self.assertFails(drop(cidr_trace(), "a0"), row, "no initial no_backend")
        self.assertFails(mutate(cidr_trace(), "a1", "finish", success=True), row, "no finish(false) followed by a successful retry")
        self.assertFails(mutate(cidr_trace(), "a3", "next", backend="default/127.0.0.1:4000"), row, "outside routed group")
        relabeled = cidr_trace()
        relabeled.labels["127.0.0.1:4002"] = {}
        relabeled.health()
        self.assertFails(relabeled, row, "recorded labels of 127.0.0.1:4002")

    def test_port_mutations_are_detected(self):
        row = ROWS["N04"]
        self.assertFails(drop(port_trace(), "q4"), row, "port=6001: no port_conflict inside")
        self.assertFails(drop(port_trace(), "q5"), row, "port=6001: no recovery success after the last port_conflict")
        self.assertFails(drop(drop(port_trace(), "q1"), "q2"), row, "port=6001: no success before the duplicate-cluster interval")
        self.assertFails(mutate(port_trace(), "p2", "next", outcome="port_conflict"), row, "port_conflict before the duplicate-cluster interval")

    def test_misalignment_is_rejected(self):
        t = port_trace()
        t.go[3]["session"] = "other"
        self.assertEqual(t.result(ROWS["N04"]), ["trace/go misaligned at 3"])

    def test_preflight_matches_frozen_plan(self):
        self.assertEqual(record_slot.preflight(ROWS), [])
        bad = copy.deepcopy(ROWS)
        bad["N01"]["duration"] = "30s"
        bad["N03"]["go_rule"] = "proxy-cidr"
        bad["N05"]["held_clients"] = "2"
        del bad["N06"]
        problems = record_slot.preflight(bad)
        for needle in ("N01: duration 30s below plan minimum", "N03: go_rule='proxy-cidr'", "N05: held_clients='2'", "differ from the plan's normal rows"):
            self.assertTrue(any(needle in p for p in problems), (needle, problems))

    def test_manifest_assertions(self):
        row = ROWS["N02"]
        labels = v.parse_labels(row["labels"])
        manifest = {"tidb": [{"name": n, "pid": 1, "config_sha256": "x", "labels": labels[n], "session_token_signing": False} for n in record_slot.INSTANCES]}
        self.assertEqual(record_slot.check_manifest(manifest, row), [])
        manifest["tidb"][2]["labels"] = {}
        manifest["tidb"][0]["session_token_signing"] = True
        manifest["tidb"][1]["pid"] = None
        self.assertEqual(len(record_slot.check_manifest(manifest, row)), 3)


if __name__ == "__main__":
    unittest.main()
