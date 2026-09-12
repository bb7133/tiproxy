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


class PublicClockTests(unittest.TestCase):
    def test_clock_origin_rejects_lossy_values_and_overflow(self):
        trace = trace_for([])
        for invalid in [True, 1.7e18, "1700000000000000000", -1, 2**63 - 86_400_000_000_000]:
            trace["config"]["clock_origin_nanos"] = invalid
            with self.assertRaisesRegex(runner.Difference, "clock origin"):
                runner.validate(trace)
        for valid in [0, 1_790_000_000_123_456_789, 2**63 - 1 - 86_400_000_000_000]:
            trace["config"]["clock_origin_nanos"] = valid
            runner.validate(trace)
        del trace["config"]["clock_origin_nanos"]
        runner.validate(trace)  # Older recorded inputs retain their original epoch.


class PublicMetricsTests(unittest.TestCase):
    def packet(self):
        queries = dict.fromkeys(runner.METRIC_KEYS)
        queries["cpu"] = {"kind":"matrix", "updated_nanos":1_790_000_000_123_456_789,
                          "series":[{"labels":{"instance":"b", "tiproxy_cluster":"second"},
                                     "samples":[{"timestamp_ms":123-i, "value":v}
                                                for i,v in enumerate(["-0","NaN","+Inf","-Inf","0.12345678901234566"])]}]}
        return queries

    def test_public_metric_values_keep_order_and_exact_clocks(self):
        queries = self.packet()
        before = copy.deepcopy(queries)
        runner.validate_metrics(queries)
        self.assertEqual(before, queries)
        queries["memory"] = {"kind":"vector", "updated_nanos":None, "series":[]}
        runner.validate_metrics(queries)
        queries["memory"]["updated_nanos"] = 0
        runner.validate_metrics(queries)

    def test_partial_private_or_lossy_values_are_rejected(self):
        changes = [lambda q:q.pop("total_pd"),
                   lambda q:q["cpu"].update(provenance={"source":1}),
                   lambda q:q["cpu"].update(updated_nanos=1.79e18),
                   lambda q:q["cpu"]["series"][0]["samples"][0].update(timestamp_ms=True),
                   lambda q:q["cpu"]["series"][0]["samples"][0].update(value=0.1),
                   lambda q:q["cpu"]["series"][0]["samples"][0].update(value="1e999"),
                   lambda q:q["cpu"].update(kind="vector")]
        for change in changes:
            queries = self.packet()
            change(queries)
            with self.assertRaises(runner.Difference):
                runner.validate_metrics(queries)

    def test_dependency_cannot_be_removed_by_editing_provenance(self):
        trace = trace_for([])
        trace["events"].insert(0, {"op":"metrics", "queries":self.packet(), "expect":{"outcome":"ok"}})
        runner.validate(trace)
        for provenance in ({"kind":"synthetic"}, {"kind":"recorded","requires":[]}):
            trace["provenance"] = provenance
            with self.assertRaisesRegex(runner.Difference, "DEPENDENCY: metrics-input"):
                runner.require_replay_support(trace)


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


class ConnectionPreferenceTests(unittest.TestCase):
    def history(self):
        return runner.PublicConnections({"policy": "connection", "selection": "prefer-idle"})

    def reserve(self, history, sid, backend, finish=None):
        history.apply({"op": "next", "session": sid}, {"outcome": "ok", "backend": backend})
        if finish is not None:
            history.apply({"op": "finish", "session": sid, "success": finish}, {})

    def config(self, history, toml, outcome="ok"):
        history.apply({"op": "config", "toml": toml}, {"outcome": outcome})

    def test_pending_failed_finish_and_close_change_eligibility(self):
        h = self.history()
        self.reserve(h, "a1", "a", True)
        self.assertEqual(h.prefer_idle({"a", "b"}), {"a", "b"})  # small skew is legal
        self.reserve(h, "a2", "a")
        self.assertEqual(h.prefer_idle({"a", "b"}), {"b"})  # pending Next already counts
        self.reserve(h, "b1", "b")
        self.assertEqual(h.prefer_idle({"a", "b"}), {"a", "b"})
        h.apply({"op": "finish", "session": "b1", "success": False}, {})
        self.assertEqual(h.prefer_idle({"a", "b"}), {"b"})
        h.apply({"op": "finish", "session": "a2", "success": True}, {})
        h.apply({"op": "close", "session": "a1"}, {})
        self.assertEqual(h.prefer_idle({"a", "b"}), {"a", "b"})

    def test_config_rate_cutoff_ratio_reset_and_rejected_update(self):
        h = self.history()
        for sid in ("a1", "a2"):
            self.reserve(h, sid, "a", True)
        for rate, expected in ((0.0001, {"a", "b"}), (0.0001001, {"b"})):
            self.config(h, f"[balance.conn-count]\nmigrations-per-second = {rate}\n")
            self.assertEqual(h.prefer_idle({"a", "b"}), expected)
        self.config(h, "[balance.conn-count]\ncount-ratio-threshold = 3.0\n")
        self.assertEqual(h.prefer_idle({"a", "b"}), {"a", "b"})
        self.config(h, "[balance.conn-count]\ncount-ratio-threshold = 0\n")
        self.assertEqual(h.prefer_idle({"a", "b"}), {"b"})
        self.config(h, "invalid TOML", "invalid_config")
        self.assertEqual(h.prefer_idle({"a", "b"}), {"b"})
        for value in ("nan", "inf", "-1"):
            with self.assertRaisesRegex(runner.Difference, "INPUT"):
                self.config(h, f"[balance.conn-count]\nmigrations-per-second = {value}\n")

    def test_saturated_factor_ties_use_clamped_ordering(self):
        h = self.history()
        h.pending = {f"a{i}": "a" for i in range(65535)} | {f"b{i}": "b" for i in range(65537)}
        self.config(h, "[balance.conn-count]\ncount-ratio-threshold = 1.000001\nmigrations-per-second = 1\n")
        self.assertEqual(h.prefer_idle({"a", "b"}), {"a", "b"})
        del h.pending["a0"]
        self.assertEqual(h.prefer_idle({"a", "b"}), {"a"})

    def test_redirect_transfers_reservation_until_callback_or_close(self):
        for result in (False, True, "close"):
            h = self.history()
            for sid in ("s", "keep"):
                self.reserve(h, sid, "a", True)
            ef = {"kind": "redirect", "session": "s", "operation": "s/1", "from": "a", "to": "b", "accepted": True}
            h.apply({"op": "tick"}, {"effects": [dict(ef, accepted=False)]})
            self.assertEqual(h.prefer_idle({"a", "b"}), {"b"})
            h.apply({"op": "tick"}, {"effects": [ef]})
            self.assertEqual(h.prefer_idle({"a", "b"}), {"a", "b"})
            h.apply({"op": "tick"}, {"effects": [dict(ef, kind="force_close", operation="s/2", to="")]})
            if result == "close":
                h.apply({"op": "close", "session": "s"}, {})
            callback = {"op": "redirect_result", "session": "s", "operation": "s/1", "success": result is not False}
            h.apply(callback, {})
            h.apply(callback, {})  # duplicate/late delivery cannot resurrect or double-transfer
            self.assertEqual(h.prefer_idle({"a", "b"}), {"b"} if result is False else {"a", "b"})
            self.assertEqual(h.assigned.get("s"), "a" if result is False else "b" if result is True else None)

    def test_common_comparator_rejects_busy_choice_using_each_engine_history(self):
        # Both engines' first two legal choices differ. A third choice must use
        # their respective idle backend; it cannot be frozen from the Go rows.
        events = []
        for sid in ("s1", "s2", "s3"):
            events += [{"op": "open", "session": sid, "expect": {"outcome": "ok"}},
                       {"op": "next", "session": sid, "expect": {**cycle("a", "b"), "prefer_idle_conn": True}},
                       {"op": "finish", "session": sid, "success": True, "expect": {"outcome": "ok"}}]
        events += [{"op": "close", "session": sid, "expect": {"outcome": "ok"}} for sid in ("s1", "s2", "s3")]
        events += [{"op": "checkpoint", "expect": {"outcome": "ok"}}]
        trace = trace_for([]); trace["config"]["selection"] = "prefer-idle"; trace["events"] = events
        runner.compare(trace, rows_for(trace, ["a", "a", "b"]), rows_for(trace, ["b", "b", "a"]))
        with self.assertRaisesRegex(runner.Difference, "POLICY_RESULT"):
            runner.observe(trace, rows_for(trace, ["b", "b", "b"]), "bad")
        trace["events"][1]["expect"]["prefer_idle_conn"] = False
        with self.assertRaisesRegex(runner.Difference, "INPUT"):
            runner.validate(trace)

    def test_exhaustion_precedes_connection_preference(self):
        trace = trace_for([{**cycle("a", "b"), "prefer_idle_conn": True}] * 3)
        trace["config"]["selection"] = "prefer-idle"
        runner.observe(trace, rows_for(trace, ["a", "b", "a"]), "valid")
        with self.assertRaisesRegex(runner.Difference, "RETRY_RESULT"):
            runner.observe(trace, rows_for(trace, ["a", "a", "b"]), "bad")


if __name__ == "__main__":
    unittest.main()
