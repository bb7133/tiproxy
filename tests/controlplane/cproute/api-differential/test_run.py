# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Public-history regressions for the common comparator (no engine simulation)."""
import copy
import importlib.util
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location("api_runner", Path(__file__).with_name("run.py"))
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


def trace_for(attempts):
    events = [{"op": "open", "session": "s", "expect": {"outcome": "ok"}}]
    for expectation in attempts:
        events.append({"op": "next", "session": "s", "expect": expectation})
        if expectation["outcome"] == "ok":
            events.append({"op": "finish", "session": "s", "success": False, "expect": {"outcome": "ok"}})
    events += [{"op": "close", "session": "s", "expect": {"outcome": "ok"}},
               {"op": "checkpoint", "expect": {"outcome": "ok"}}]
    return {"version": 1, "id": "retry-contract", "config": {"policy": "connection", "selection": "random", "rule": ""},
            "provenance": {"kind": "synthetic"}, "events": events}


def rows_for(trace, selections):
    choices = iter(selections)
    rows = []
    for index, event in enumerate(trace["events"]):
        row = {"seq": index, "op": event["op"], "session": event.get("session", ""), "outcome": event["expect"]["outcome"],
               "backend": next(choices) if event["op"] == "next" and event["expect"]["outcome"] == "ok" else "", "effects": []}
        if event["op"] == "checkpoint":
            row.update(assignments={}, conn_count=0, healthy_backend_count=0, server_version="")
        rows.append(row)
    return rows


def cycle(*candidates, preferred=None):
    result = {"outcome": "ok", "legal_backends": list(candidates), "exclude_history": True}
    if preferred is not None:
        result["prefer_local"] = preferred
    return result


class RetryHistoryTests(unittest.TestCase):
    def test_two_engines_keep_their_own_complete_cycle(self):
        trace = trace_for([cycle("a", "b", "c")] * 4)
        runner.compare(trace, rows_for(trace, ["a", "b", "c", "a"]), rows_for(trace, ["c", "a", "b", "b"]))
        with self.assertRaisesRegex(runner.Difference, "RETRY_RESULT"):
            runner.compare(trace, rows_for(trace, ["a", "b", "a", "c"]), rows_for(trace, ["c", "a", "b", "b"]))

    def test_reset_is_not_triggered_by_a_removed_exclusion(self):
        trace = trace_for([cycle("a", "b", "c"), cycle("a", "b", "c"), cycle("b", "c")])
        runner.compare(trace, rows_for(trace, ["a", "b", "c"]), rows_for(trace, ["a", "c", "b"]))
        with self.assertRaisesRegex(runner.Difference, "RETRY_RESULT"):
            runner.observe(trace, rows_for(trace, ["a", "b", "b"]), "bad")

    def test_exact_error_resets_but_wrapped_error_keeps_cycle(self):
        wrapped = trace_for([cycle("a", "b"), {"outcome": "wrapped_no_backend"}, cycle("a", "b")])
        runner.observe(wrapped, rows_for(wrapped, ["a", "b"]), "valid")
        with self.assertRaisesRegex(runner.Difference, "RETRY_RESULT"):
            runner.observe(wrapped, rows_for(wrapped, ["a", "a"]), "bad")
        exact = copy.deepcopy(wrapped)
        exact["events"][3]["expect"]["outcome"] = "no_backend"
        runner.observe(exact, rows_for(exact, ["a", "a"]), "valid")

    def test_local_preference_is_applied_after_exclusions(self):
        trace = trace_for([cycle("a", "b", "remote", preferred=["a", "b"])] * 4)
        runner.compare(trace, rows_for(trace, ["a", "b", "remote", "b"]), rows_for(trace, ["b", "a", "remote", "a"]))
        with self.assertRaisesRegex(runner.Difference, "POLICY_RESULT"):
            runner.observe(trace, rows_for(trace, ["a", "remote", "b", "a"]), "bad")

    def test_one_engine_reset_does_not_clear_the_other_engine_history(self):
        trace = trace_for([cycle("a", "b"), cycle("a"), cycle("a", "b", "c")])
        runner.compare(trace, rows_for(trace, ["a", "a", "b"]), rows_for(trace, ["b", "a", "c"]))
        with self.assertRaisesRegex(runner.Difference, "RETRY_RESULT"):
            runner.observe(trace, rows_for(trace, ["b", "a", "b"]), "bad")

    def test_invalid_history_constraints_fail_input_validation(self):
        for extra in ({"exclude_history": False}, {"prefer_local": ["outside"]}, {"exclude_previous": True}, {"prefer_local": ["a", "a"]}):
            trace = trace_for([{**cycle("a", "b"), **extra}])
            with self.assertRaisesRegex(runner.Difference, "INPUT"):
                runner.validate(trace)


if __name__ == "__main__":
    unittest.main()
