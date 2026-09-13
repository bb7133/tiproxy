# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Failover slot validator/preflight positive histories and one-fault counterexamples."""
import copy
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import record_failover  # noqa: E402
import validate_failover as v  # noqa: E402

ROWS = v.slot_rows()


class Trace:
    def __init__(self, row):
        self.row = row
        self.events = []
        self.go = []
        self.labels = {v.common.instance_address(name): labels for name, labels in v.common.parse_labels(row["labels"]).items()}

    def add(self, event, **result):
        result = {"seq": len(self.events), "op": event["op"], "session": event.get("session", ""),
                  "outcome": "ok", "backend": "", "effects": []} | result
        self.events.append(event)
        self.go.append(result)

    def health(self, down=()):
        self.add({"op": "health", "backends": [
            {"address": address, "cluster": "default", "healthy": address not in down,
             "support_redirection": True, "labels": labels}
            for address, labels in self.labels.items()]})

    def open(self, session, client="127.0.0.1", proxy="127.0.0.1", port="6000"):
        self.add({"op": "open", "session": session, "client": client + ":1", "proxy": proxy + ":1", "port": port})

    def next(self, session, outcome="ok", backend=""):
        self.add({"op": "next", "session": session}, outcome=outcome,
                 backend="default/" + backend if backend else "")

    def finish(self, session, success=True):
        self.add({"op": "finish", "session": session, "success": success})

    def close(self, session):
        self.add({"op": "close", "session": session})

    def checkpoint(self, assignments, conn_count=None):
        self.add({"op": "checkpoint"}, assignments=assignments,
                 conn_count=len(assignments) if conn_count is None else conn_count,
                 healthy_backend_count=4, server_version="v")

    def config(self, targets, timeout=60, clusters=0):
        if clusters:
            entries = "".join(f'[[proxy.backend-clusters]]\nname = "{name}"\n' for name in ("default", "conflict")[:clusters])
            toml = "[proxy]\n" + entries
        elif targets:
            values = ", ".join(f'"{target}"' for target in targets)
            toml = f"[proxy]\nfail-backend-list = [{values}]\nfailover-timeout = {timeout}\n"
        else:
            toml = "[proxy]\nfail-backend-list = []\n"
        self.add({"op": "config", "toml": toml})

    def tick(self, *effects):
        self.add({"op": "tick"}, effects=list(effects))

    def redirect_result(self, session, operation, success=True):
        self.add({"op": "redirect_result", "session": session, "operation": operation, "success": success})

    def result(self):
        return v.validate(self.row, {"events": self.events}, self.go)[0]

    def resequence(self):
        for i, result in enumerate(self.go):
            result["seq"] = i


def positive(slot):
    row = ROWS[slot]
    t = Trace(row)
    if row["go_rule"] == "":
        client, proxy, port = "127.0.0.1", "127.0.0.1", "6000"
        first, second = "127.0.0.1:4000", "127.0.0.1:4001"
        guard_targets = sorted(t.labels)
    elif row["go_rule"] == "client_cidr":
        client, proxy, port = "127.0.0.1", "127.0.0.1", "6000"
        first, second = "127.0.0.1:4002", "127.0.0.1:4003"
        guard_targets = [first, second]
    elif row["go_rule"] == "proxy_cidr":
        client, proxy, port = "127.0.0.1", "127.0.0.2", "6000"
        first, second = "127.0.0.1:4002", "127.0.0.1:4003"
        guard_targets = [first, second]
    elif row["go_rule"] == "port":
        client, proxy, port = "127.0.0.1", "127.0.0.1", "6000"
        first, second = "127.0.0.1:4000", "127.0.0.1:4001"
        guard_targets = [first, second]
    else:
        raise AssertionError(f"unsupported test rule {row['go_rule']!r}")
    t.health()
    t.open("held-1", client, proxy, port)
    t.next("held-1", backend=first)
    t.finish("held-1")
    if row["go_rule"] in ("client_cidr", "proxy_cidr"):
        no_match_client = "127.0.0.2" if row["go_rule"] == "client_cidr" else client
        no_match_proxy = "127.0.0.1" if row["go_rule"] == "proxy_cidr" else proxy
        t.open("no-match", no_match_client, no_match_proxy, port)
        t.next("no-match", "no_backend")
        t.close("no-match")
    else:
        t.open("other-port", client, proxy, "6001")
        t.next("other-port", backend="127.0.0.1:4002")
        t.finish("other-port")
        t.close("other-port")

    t.checkpoint({"held-1": "default/" + first})
    t.config([first])
    t.tick({"kind": "redirect", "session": "held-1", "operation": "held-1/1",
            "from": "default/" + first, "to": "default/" + second, "accepted": False})
    t.tick({"kind": "redirect", "session": "held-1", "operation": "held-1/2",
            "from": "default/" + first, "to": "default/" + second, "accepted": True})
    t.redirect_result("held-1", "held-1/2")
    t.config([first])
    t.config([])

    t.open("held-2", client, proxy, port)
    t.next("held-2", backend=second)
    t.finish("held-2")
    t.checkpoint({"held-1": "default/" + second, "held-2": "default/" + second})
    t.config([second])
    t.tick({"kind": "redirect", "session": "held-2", "operation": "held-2/1",
            "from": "default/" + second, "to": "default/" + first, "accepted": True})
    t.close("held-2")
    t.redirect_result("held-2", "held-2/1")
    t.config([])

    t.config(guard_targets)
    t.open("guard", client, proxy, port)
    t.next("guard", backend=first)
    t.finish("guard")
    t.close("guard")
    t.config([])
    t.health(down=(second,))
    t.health()

    if row["go_rule"] == "port":
        t.config([], clusters=2)
        for session, listener in (("conflict-p", "6000"), ("conflict-q", "6001")):
            t.open(session, client, proxy, listener)
            t.next(session, "port_conflict")
            t.close(session)
        t.config([], clusters=1)
        t.health()
        for session, listener, backend in (("recover-p", "6000", first), ("recover-q", "6001", "127.0.0.1:4002")):
            t.open(session, client, proxy, listener)
            t.next(session, backend=backend)
            t.finish(session)
            t.close(session)

    t.close("held-1")
    t.checkpoint({}, 0)
    return t


def drop(t, predicate):
    t = copy.deepcopy(t)
    pairs = [(event, result) for event, result in zip(t.events, t.go) if not predicate(event, result)]
    t.events = [event for event, _ in pairs]
    t.go = [result for _, result in pairs]
    t.resequence()
    return t


def move_after(t, predicate, anchor, anchor_ordinal=1):
    t = copy.deepcopy(t)
    moving = [(event, result) for event, result in zip(t.events, t.go) if predicate(event, result)]
    remaining = [(event, result) for event, result in zip(t.events, t.go) if not predicate(event, result)]
    anchors = [i for i, (event, result) in enumerate(remaining) if anchor(event, result)]
    insert = anchors[anchor_ordinal - 1] + 1
    pairs = remaining[:insert] + moving + remaining[insert:]
    t.events = [event for event, _ in pairs]
    t.go = [result for _, result in pairs]
    t.resequence()
    return t


class FailoverValidatorTests(unittest.TestCase):
    def assertFails(self, trace, needle):
        problems = trace.result()
        self.assertTrue(any(needle in problem for problem in problems), (needle, problems))

    def test_positive_histories_for_all_six_slots_pass(self):
        for slot in sorted(ROWS):
            with self.subTest(slot=slot):
                self.assertEqual(positive(slot).result(), [])

    def test_writer_effect_references_and_delayed_close_are_accepted(self):
        trace = positive("F02")
        references = {}
        ordinal = 0
        for result in trace.go:
            for effect in result.get("effects", []):
                if effect.get("kind") == "redirect" and effect.get("accepted") is True:
                    ordinal += 1
                    references[effect["operation"]] = f"redirect/{ordinal}"
        for event in trace.events:
            operation = event.pop("operation", None)
            if event["op"] == "redirect_result":
                event["effect_ref"] = references[operation]
            elif event["op"] == "close" and event.get("session") == "held-2":
                event["effect_ref"] = references["held-2/1"]
        self.assertEqual(trace.result(), [])
        delayed = next(event for event in trace.events
                       if event["op"] == "close" and event.get("session") == "held-2")
        delayed["effect_ref"] = "redirect/999"
        self.assertFails(trace, "invalid accepted-effect reference")

    def test_activation_checkpoint_timeout_and_sequence_are_required(self):
        trace = positive("F02")
        first_config = next(i for i, event in enumerate(trace.events) if event["op"] == "config" and "4002" in event["toml"])
        trace.go[first_config - 1]["assignments"] = {"held-1": "default/127.0.0.1:4003"}
        self.assertFails(trace, "was not assigned at the preceding checkpoint")

        trace = positive("F02")
        first_config = next(i for i, event in enumerate(trace.events) if event["op"] == "config" and "4002" in event["toml"])
        trace.events[first_config]["toml"] = trace.events[first_config]["toml"].replace("= 60", "= 0")
        self.assertFails(trace, "non-positive timeout")

        trace = positive("F02")
        seen = 0
        # Remove only the repeated singleton config.
        for i, event in enumerate(trace.events):
            if event["op"] == "config" and "4002" in event.get("toml", "") and event["toml"].count("4002") == 1:
                seen += 1
                if seen == 2:
                    del trace.events[i]
                    del trace.go[i]
                    trace.resequence()
                    break
        self.assertFails(trace, "expected select, unchanged repeat and reentry")

    def test_refusal_acceptance_and_late_completion_are_required(self):
        trace = positive("F02")
        for result in trace.go:
            for effect in result.get("effects", []):
                if effect.get("operation") == "held-1/1":
                    effect["accepted"] = True
        self.assertFails(trace, "no refused redirect")

        trace = positive("F02")
        close_i = next(i for i, event in enumerate(trace.events) if event.get("session") == "held-2" and event["op"] == "close")
        result_i = next(i for i, event in enumerate(trace.events) if event.get("operation") == "held-2/1")
        event, result = trace.events.pop(result_i), trace.go.pop(result_i)
        trace.events.insert(close_i, event)
        trace.go.insert(close_i, result)
        trace.resequence()
        self.assertFails(trace, "no accepted redirect completed after")

        trace = positive("F02")
        i = next(i for i, event in enumerate(trace.events) if event.get("operation") == "held-2/1")
        trace.events.insert(i + 1, copy.deepcopy(trace.events[i]))
        trace.go.insert(i + 1, copy.deepcopy(trace.go[i]))
        trace.resequence()
        self.assertFails(trace, "settled 2 times")

        trace = drop(positive("F02"), lambda event, _: event.get("operation") == "held-1/2")
        self.assertFails(trace, "accepted redirect operation 'held-1/2' settled 0 times")

        trace = positive("F02")
        i = next(i for i, event in enumerate(trace.events) if event.get("operation") == "held-1/2")
        trace.events[i]["session"] = "held-2"
        trace.go[i]["session"] = "held-2"
        self.assertFails(trace, "for the wrong session")

        trace = positive("F02")
        for result in trace.go:
            for effect in result.get("effects", []):
                if effect.get("operation") == "held-1/2":
                    effect["from"] = "default/127.0.0.1:4003"
        self.assertFails(trace, "no later accepted redirect for the refused session")

        trace = positive("F02")
        for result in trace.go:
            for effect in result.get("effects", []):
                if effect.get("operation") == "held-2/1":
                    effect["from"] = "default/127.0.0.1:4000"
        self.assertFails(trace, "no accepted redirect completed after its session closed")

        def clear(event, _):
            return event.get("op") == "config" and event.get("toml") == "[proxy]\nfail-backend-list = []\n"

        for slot in ("F02", "F04"):
            with self.subTest(slot=slot, mutation="accepted_after_first_clear"):
                trace = move_after(
                    positive(slot),
                    lambda event, result: event.get("operation") == "held-1/2"
                    or any(effect.get("operation") == "held-1/2" for effect in result.get("effects", [])),
                    clear,
                )
                self.assertFails(trace, "no later accepted redirect for the refused session")

            with self.subTest(slot=slot, mutation="late_issuance_after_reentry_clear"):
                trace = move_after(
                    positive(slot),
                    lambda event, result: event.get("operation") == "held-2/1"
                    or (event.get("op") == "close" and event.get("session") == "held-2")
                    or any(effect.get("operation") == "held-2/1" for effect in result.get("effects", [])),
                    clear,
                    anchor_ordinal=2,
                )
                self.assertFails(trace, "no accepted redirect completed after its session closed")

    def test_health_guard_and_final_ledger_are_required(self):
        trace = positive("F02")
        for event in trace.events:
            if event["op"] == "health":
                for backend in event["backends"]:
                    backend["healthy"] = True
        self.assertFails(trace, "no routed backend changed from healthy")

        trace = positive("F02")
        trace.events[0]["backends"][2]["support_redirection"] = False
        self.assertFails(trace, "lack redirection support")

        trace = positive("F02")
        trace.events[0]["backends"][2]["labels"] = {}
        self.assertFails(trace, "recorded labels of 127.0.0.1:4002")

        trace = positive("F02")
        guard = next(event for event in trace.events if event["op"] == "config" and "4002" in event["toml"] and "4003" in event["toml"])
        guard["toml"] = guard["toml"].replace(', "127.0.0.1:4003"', "")
        self.assertFails(trace, "no all-members failover guard")

        trace = positive("F02")
        trace.go[-1]["assignments"] = {"leak": "default/127.0.0.1:4002"}
        trace.go[-1]["conn_count"] = 1
        self.assertFails(trace, "final checkpoint")

    def test_route_specific_failures_are_detected(self):
        trace = positive("F02")
        i = next(i for i, event in enumerate(trace.events) if event.get("session") == "no-match" and event["op"] == "next")
        trace.go[i]["outcome"] = "ok"
        trace.go[i]["backend"] = "default/127.0.0.1:4002"
        self.assertFails(trace, "no-match context did not exclusively return no_backend")

        trace = drop(positive("F04"), lambda event, _: event.get("session") == "conflict-q")
        self.assertFails(trace, "port=6001: no port_conflict")

    def test_preflight_is_tied_to_frozen_family_and_atomic_controls(self):
        self.assertEqual(record_failover.preflight(ROWS), [])
        rows = copy.deepcopy(ROWS)
        rows["F01"]["redirection"] = "off"
        rows["F02"]["held_clients"] = "0"
        rows["F03"]["go_rule"] = "proxy-cidr"
        rows["F04"]["held_clients"] = "bad"
        del rows["F06"]
        problems = record_failover.preflight(rows)
        for needle in ("must be recorded with redirection on", "requires held clients", "go_rule='proxy-cidr'", "differ from the plan's failover rows"):
            self.assertTrue(any(needle in problem for problem in problems), (needle, problems))


if __name__ == "__main__":
    unittest.main()
