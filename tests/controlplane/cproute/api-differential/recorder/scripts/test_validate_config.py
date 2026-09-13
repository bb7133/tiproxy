# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Config/source-change validator, C preflight and generated scripts: positives and one-fault mutations."""
import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import gen_config_scripts  # noqa: E402
import record_slot  # noqa: E402
import validate_config as vc  # noqa: E402
import validate_normal as vn  # noqa: E402

ROWS = vc.slot_rows()
NEW = "127.0.0.1:4004"


class Trace:
    def __init__(self, row):
        self.row = row
        self.labels = {vn.instance_address(n): dict(l) for n, l in vn.parse_labels(row["labels"]).items()}
        self.events, self.go, self.n = [], [], 0

    def add(self, event, outcome="ok", backend=""):
        self.go.append({"seq": len(self.events), "op": event["op"], "session": event.get("session", ""),
                        "outcome": outcome, "backend": backend, "effects": []})
        self.events.append(event)

    def health(self, down=()):
        self.add({"op": "health", "backends": [{"address": a, "cluster": "default", "healthy": a not in down,
                                                 "labels": l} for a, l in self.labels.items()]})

    def session(self, outcome="ok", backend="", client="127.0.0.1", port="6000"):
        self.n += 1
        s = f"s{self.n}"
        self.add({"op": "open", "session": s, "client": client + ":1", "proxy": client + ":1", "port": port})
        self.add({"op": "next", "session": s}, outcome, "default/" + backend if backend else "")
        if outcome == "ok":
            self.add({"op": "finish", "session": s, "success": True})
        self.add({"op": "close", "session": s})
        return s

    def lifecycle(self):
        self.add({"op": "rehydrate", "session": "r", "backend": "default/127.0.0.1:4000"}, "ok", "default/127.0.0.1:4000")
        self.add({"op": "lookup", "session": "r", "backend": "default/127.0.0.1:4000"}, "ok", "default/127.0.0.1:4000")

    def result(self):
        return vc.validate(self.row, {"events": self.events}, self.go)[0]


def common_prefix(t, ok_backend, client="127.0.0.1", port="6000"):
    t.session("no_backend", client=client, port=port)
    t.health()
    t.session("ok", ok_backend, client, port)
    t.add({"op": "config", "toml": '[balance]\npolicy = "connection"\n'})
    t.add({"op": "config", "toml": '[balance]\npolicy = "invalid-policy"\n'}, "invalid_config")
    t.add({"op": "source_error", "error": "cancelled"})
    t.session("source_error:cancelled", client=client, port=port)
    t.health()
    t.session("ok", ok_backend, client, port)


def matchall_trace():
    t = Trace(ROWS["C01"])
    common_prefix(t, "127.0.0.1:4000")
    t.add({"op": "config", "toml": '[balance]\nrouting-rule = "port"\n'})
    t.session("ok", "127.0.0.1:4001")
    t.add({"op": "config", "toml": '[balance]\nrouting-rule = ""\n'})
    t.labels[NEW] = {}
    t.health()
    t.session("ok", NEW)
    del t.labels[NEW]
    t.health()
    t.session("ok", "127.0.0.1:4002")
    t.lifecycle()
    return t


def port_trace():
    t = Trace(ROWS["C04"])
    common_prefix(t, "127.0.0.1:4002", port="6001")
    t.labels["127.0.0.1:4003"] = {"tiproxy-port": "6000"}  # retain: keeps group 6001
    t.health()
    t.session("ok", "127.0.0.1:4003", port="6001")
    t.session("ok", "127.0.0.1:4000", port="6000")
    t.labels[NEW] = {}
    t.health()
    t.session("ok", "127.0.0.1:4002", port="6001")
    t.labels[NEW] = {"tiproxy-port": "6001"}  # join
    t.health()
    t.session("ok", NEW, port="6001")
    del t.labels[NEW]
    t.health()
    t.labels["127.0.0.1:4003"] = {"tiproxy-port": "6001"}
    t.health()
    t.session("ok", "127.0.0.1:4003", port="6001")
    t.lifecycle()
    return t


def edit(t, session, **fields):
    t = copy.deepcopy(t)
    for e, g in zip(t.events, t.go):
        if e.get("session") == session and e["op"] == "next":
            g.update(fields)
            return t
    raise AssertionError(session)


def without(t, predicate):
    t = copy.deepcopy(t)
    keep = [(e, g) for e, g in zip(t.events, t.go) if not predicate(e, g)]
    t.events = [e for e, _ in keep]
    t.go = [dict(g, seq=i) for i, (_, g) in enumerate(keep)]
    return t


class ConfigValidatorTests(unittest.TestCase):
    def assertFails(self, t, needle):
        problems = t.result()
        self.assertTrue(any(needle in p for p in problems), problems)

    def test_positive_traces_pass(self):
        self.assertEqual(matchall_trace().result(), [])
        self.assertEqual(port_trace().result(), [])

    def test_missing_lifecycle_fails_every_current_capture(self):
        for t in (matchall_trace(), port_trace()):
            self.assertFails(without(t, lambda e, g: e["op"] in ("rehydrate", "lookup")), "pending recorder action")

    def test_common_mutations(self):
        t = matchall_trace()
        self.assertFails(without(t, lambda e, g: g["outcome"] == "invalid_config"), "no invalid public-config rejection")
        self.assertFails(edit(t, "s3", outcome="no_backend"), "did not report that source error")
        self.assertFails(without(t, lambda e, g: e["op"] == "source_error"), "no named source error")
        self.assertFails(without(t, lambda e, g: e.get("session") in ("s4", "s5", "s6", "s7")), "no successful next after the source-error window")
        removal = max(i for i, e in enumerate(t.events) if e["op"] == "health")
        self.assertFails(without(t, lambda e, g: g["seq"] == removal), "no added backend removed")
        relabeled = copy.deepcopy(t)
        next(e for e in relabeled.events if e["op"] == "health")["backends"][0]["labels"] = {"cidr": "127.0.0.9/32"}
        self.assertFails(relabeled, "initial health labels")

    def test_matchall_mutations(self):
        t = matchall_trace()
        self.assertFails(edit(t, "s5", outcome="port_conflict", backend=""), "routing changed while the runtime routing-rule change")
        self.assertFails(without(t, lambda e, g: 'routing-rule = ""' in e.get("toml", "")), "followed by restoration")
        self.assertFails(edit(t, "s6", backend="default/127.0.0.1:4001"), "MatchAll never selected the added backend")

    def test_port_mutations(self):
        t = port_trace()
        self.assertFails(edit(t, "s6", backend="default/127.0.0.1:4003"), "from its new label's context")
        self.assertFails(edit(edit(t, "s5", backend="default/127.0.0.1:4002"), "s9", backend="default/127.0.0.1:4002"),
                         "not selected from its original group context")
        self.assertFails(edit(t, "s7", backend="default/" + NEW), "before its routing label")
        self.assertFails(edit(t, "s8", backend="default/127.0.0.1:4002"), "never selected after joining")
        outside = copy.deepcopy(t)
        outside.events[[i for i, e in enumerate(outside.events) if e.get("session") == "s8"][0]]["port"] = "6000"
        self.assertFails(outside, "outside its joined group")


class ConfigPreflightTests(unittest.TestCase):
    def test_pending_lifecycle_refuses_freeze(self):
        problems = record_slot.preflight(ROWS, "config-source")
        self.assertEqual(len([p for p in problems if "pending placeholder" in p]), 6)
        self.assertEqual(record_slot.preflight(ROWS, "config-source", allow_pending=True), [])

    def test_row_mutations(self):
        bad = copy.deepcopy(ROWS)
        bad["C01"]["redirection"] = "off"
        bad["C02"]["restore_labels"] = "cidr=127.0.0.2/32"
        bad["C03"]["source_error"] = "unclassified_source_error"
        bad["C05"]["retain_labels"] = "cidr=127.0.0.1/32"
        bad["C06"]["join_labels"] = "tiproxy-port=6000"
        problems = record_slot.preflight(bad, "config-source", allow_pending=True)
        for needle in ("C01: config-source family is recorded with redirection on", "C02: restore_labels",
                       "C03: source_error", "C05: MatchAll uses a routing-rule config change", "C06: join must use",
                       "C02: C02.json differs from gen_config_scripts.py output"):
            self.assertTrue(any(needle in p for p in problems), (needle, problems))

    def test_generated_scripts_are_committed(self):
        for r in ROWS.values():
            self.assertEqual((Path(gen_config_scripts.__file__).parent / r["script"]).read_text(), gen_config_scripts.render(r))

    def test_manifest_runtime_and_topology_labels(self):
        row = ROWS["C02"]
        labels = vn.parse_labels(row["labels"])
        manifest = {"tidb": [{"name": n, "pid": 1, "config_sha256": "x", "labels": labels[n], "runtime_labels": labels[n],
                              "topology_labels": labels[n], "session_token_signing": True} for n in record_slot.INSTANCES]}
        self.assertEqual(record_slot.check_manifest(manifest, row), [])
        manifest["tidb"][3]["runtime_labels"] = {"cidr": "127.0.0.2/32"}
        manifest["tidb"][2]["topology_labels"] = {}
        self.assertEqual(len(record_slot.check_manifest(manifest, row)), 2)


if __name__ == "__main__":
    unittest.main()
