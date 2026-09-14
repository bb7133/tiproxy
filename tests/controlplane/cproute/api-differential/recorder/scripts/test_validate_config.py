# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Config/source-change validator, C preflight and generated scripts: positives and one-fault mutations."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import derive_expectations as derive  # noqa: E402
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

    def add(self, event, outcome="ok", backend="", effects=None):
        row = {"seq": len(self.events), "op": event["op"], "session": event.get("session", ""),
               "outcome": outcome, "backend": backend, "effects": effects or []}
        if event["op"] == "checkpoint":
            row.update(assignments={}, conn_count=0, healthy_backend_count=len(self.labels), server_version="")
        self.go.append(row)
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
        source, target, session = "default/127.0.0.1:4000", "default/127.0.0.1:4001", "r"
        self.add({"op": "open", "session": session, "client": "127.0.0.1:1",
                  "proxy": "127.0.0.1:1", "port": "6000"})
        self.add({"op": "next", "session": session}, "ok", source)
        self.add({"op": "finish", "session": session, "success": True})
        self.add({"op": "config", "toml": "[proxy]\nfail-backend-list=['127.0.0.1:4000']\n",
                  "delay_next": 1})
        effect = {"kind": "redirect", "session": session, "operation": f"{session}/1",
                  "from": source, "to": target, "accepted": True}
        self.add({"op": "tick"}, effects=[effect])
        self.add({"op": "config", "toml": "[proxy]\nfail-backend-list=[]\n"})
        self.add({"op": "router_reset"})
        self.health()
        self.add({"op": "rehydrate", "session": session, "effect_ref": "redirect/1"}, "ok", target)
        self.add({"op": "lookup", "effect_ref": "redirect/1"}, "ok", target)
        self.add({"op": "redirect_result", "session": session, "effect_ref": "redirect/1",
                  "optional_effect": True, "success": True})
        self.add({"op": "close", "session": session})
        self.add({"op": "checkpoint"})

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


def post_source_no_match_first(t):
    """Insert a legal no-match request between source recovery health and the first routed success."""
    t = copy.deepcopy(t)
    source = next(i for i, e in enumerate(t.events) if e["op"] == "source_error")
    insert = next(i for i, e in enumerate(t.events) if i > source and e["op"] == "health") + 1
    session = "source-recovery-no-match"
    events = [
        {"op": "open", "session": session, "client": "127.0.0.1:1",
         "proxy": "127.0.0.1:1", "port": "6999"},
        {"op": "next", "session": session},
        {"op": "close", "session": session},
    ]
    rows = [
        {"op": "open", "session": session, "outcome": "ok", "backend": "", "effects": []},
        {"op": "next", "session": session, "outcome": "no_backend", "backend": "", "effects": []},
        {"op": "close", "session": session, "outcome": "ok", "backend": "", "effects": []},
    ]
    t.events[insert:insert] = events
    t.go[insert:insert] = rows
    t.go = [dict(row, seq=i) for i, row in enumerate(t.go)]
    return t


class ConfigValidatorTests(unittest.TestCase):
    def assertFails(self, t, needle):
        problems = t.result()
        self.assertTrue(any(needle in p for p in problems), problems)

    def test_positive_traces_pass(self):
        self.assertEqual(matchall_trace().result(), [])
        self.assertEqual(port_trace().result(), [])

    def test_source_recovery_waits_through_no_match_next(self):
        t = post_source_no_match_first(port_trace())
        self.assertEqual(t.result(), [])

        no_recovery = copy.deepcopy(t)
        source = next(i for i, e in enumerate(no_recovery.events) if e["op"] == "source_error")
        recovery_health = next(i for i, e in enumerate(no_recovery.events)
                               if i > source and e["op"] == "health")
        for event, row in zip(no_recovery.events[recovery_health + 1:],
                              no_recovery.go[recovery_health + 1:]):
            if event["op"] == "next" and row["outcome"] == "ok":
                row.update(outcome="no_backend", backend="")
        self.assertFails(no_recovery, "no successful next after the source-error window")

    def test_router_reset_traces_derive_without_private_dependencies(self):
        for t in (matchall_trace(), port_trace()):
            trace = {"version": 1, "id": "config-router-reset",
                     "config": {"policy": t.row["policy"], "selection": t.row["selection"],
                                "rule": t.row["go_rule"]},
                     "provenance": {"kind": "synthetic"}, "events": t.events}
            derived, requires = derive.derive(trace, t.go, None)
            self.assertEqual(requires, [])
            derive._RUNNER.validate(derived)
            derive._RUNNER.observe(derived, t.go, "go")

    def test_missing_lifecycle_fails(self):
        for t in (matchall_trace(), port_trace()):
            self.assertFails(without(t, lambda e, g: e["op"] in ("router_reset", "rehydrate", "lookup", "redirect_result")),
                             "no router close/recreate lifecycle")

    def test_common_mutations(self):
        t = matchall_trace()
        self.assertFails(without(t, lambda e, g: g["outcome"] == "invalid_config"), "no invalid public-config rejection")
        self.assertFails(edit(t, "s3", outcome="no_backend"), "did not report that source error")
        self.assertFails(without(t, lambda e, g: e["op"] == "source_error"), "no named source error")
        reset = next(i for i, e in enumerate(t.events) if e["op"] == "router_reset")
        removal = max(i for i, e in enumerate(t.events) if e["op"] == "health" and i < reset)
        self.assertFails(without(t, lambda e, g: g["seq"] == removal), "no added backend removed")
        relabeled = copy.deepcopy(t)
        next(e for e in relabeled.events if e["op"] == "health")["backends"][0]["labels"] = {"cidr": "127.0.0.9/32"}
        self.assertFails(relabeled, "initial health labels")
        missing = copy.deepcopy(t)
        next(e for e in missing.events if e["op"] == "health")["backends"].pop()
        self.assertFails(missing, "initial health inventory")

    def test_lifecycle_mutations(self):
        t = matchall_trace()
        self.assertFails(without(t, lambda e, g: e["op"] == "rehydrate"), "survivors not rehydrated")
        self.assertFails(without(t, lambda e, g: e["op"] == "lookup"), "no effect-relative rehydrate and lookup")
        self.assertFails(without(t, lambda e, g: e["op"] == "redirect_result"), "no successful late redirect callback")
        reset = next(i for i, e in enumerate(t.events) if e["op"] == "router_reset")
        self.assertFails(without(t, lambda e, g: g["seq"] > reset and e["op"] == "health"),
                         "no fresh health publication")
        previous = copy.deepcopy(t)
        event = next(e for e in previous.events if e["op"] == "rehydrate")
        event.pop("effect_ref")
        event["backend_ref"] = "previous"
        self.assertFails(previous, "no effect-relative rehydrate and lookup")
        extra = copy.deepcopy(t)
        tick = next(i for i, e in enumerate(extra.events) if e["op"] == "tick")
        extra.go[tick]["effects"].append({"kind": "redirect", "session": "r",
                                           "operation": "r/2", "from": "default/127.0.0.1:4000",
                                           "to": "default/127.0.0.1:4002", "accepted": True})
        self.assertFails(extra, "requires exactly one pending accepted redirect")

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
    def test_exact_router_reset_lifecycle_allows_freeze(self):
        self.assertEqual(record_slot.preflight(ROWS, "config-source"), [])

    def test_row_mutations(self):
        bad = copy.deepcopy(ROWS)
        bad["C01"]["redirection"] = "off"
        bad["C02"]["restore_labels"] = "cidr=127.0.0.2/32"
        bad["C03"]["source_error"] = "unclassified_source_error"
        bad["C05"]["retain_labels"] = "cidr=127.0.0.1/32"
        bad["C06"]["join_labels"] = "tiproxy-port=6000"
        bad["C01"]["lifecycle"] = "placeholder"
        problems = record_slot.preflight(bad, "config-source")
        for needle in ("C01: config-source family is recorded with redirection on", "C02: restore_labels",
                       "C03: source_error", "C05: MatchAll uses a routing-rule config change", "C06: join must use",
                       "C02: C02.json differs from gen_config_scripts.py output", "C01: unsupported router lifecycle"):
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

    def test_record_slot_main_writes_verdict_without_retired_trial_flag(self):
        row = copy.deepcopy(ROWS["C01"])
        labels = vn.parse_labels(row["labels"])
        manifest = {"tidb": [{"name": name, "labels": labels[name]} for name in record_slot.INSTANCES]}
        validator = types.SimpleNamespace(
            __file__="fake_validate_config.py",
            slot_rows=lambda: {"C01": row},
            validate_dir=lambda *_: ([], {"main_path": "covered"}),
        )

        with tempfile.TemporaryDirectory() as tmp:
            def fake_run(cmd, **kwargs):
                if cmd[1:] == ["manifest"]:
                    payload = json.dumps(manifest)
                    return types.SimpleNamespace(
                        returncode=0,
                        stdout=payload if kwargs.get("text") else payload.encode(),
                    )
                attempt = Path(cmd[cmd.index("-out") + 1]) / "C01-a1"
                attempt.mkdir()
                (attempt / "trace.json").write_text("{}\n")
                return types.SimpleNamespace(returncode=0, stdout=b"")

            argv = ["record_slot.py", "C01", "--attempt", "a1", "--recorder", "recorder",
                    "--env", "env", "--out", tmp]
            with mock.patch.object(record_slot, "FAMILIES", {
                    "C": ("config-source", validator, "config-validation.json", "on")}), \
                    mock.patch.object(record_slot, "preflight", return_value=[]), \
                    mock.patch.object(record_slot, "check_manifest", return_value=[]), \
                    mock.patch.object(record_slot, "restore_environment"), \
                    mock.patch.object(record_slot, "sh"), \
                    mock.patch.object(record_slot.subprocess, "run", side_effect=fake_run), \
                    mock.patch.object(sys, "argv", argv):
                with self.assertRaises(SystemExit) as exit_status:
                    record_slot.main()
            self.assertEqual(exit_status.exception.code, 0)
            verdict = json.loads((Path(tmp) / "C01-a1" / "config-validation.json").read_text())
            self.assertEqual(verdict["passed"], True)
            self.assertEqual(verdict["contexts"], {"main_path": "covered"})
            self.assertNotIn("trial", verdict)


if __name__ == "__main__":
    unittest.main()
