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


class RouterResetStructureTests(unittest.TestCase):
    @staticmethod
    def trace(events):
        return {"version": 1, "id": "reset-structure",
                "config": {"policy": "connection", "selection": "random", "rule": ""},
                "provenance": {"kind": "synthetic"}, "events": events}

    def test_reset_rejects_an_idle_open_session(self):
        events = [
            {"op": "open", "session": "live", "expect": {"outcome": "ok"}},
            {"op": "next", "session": "live", "expect": {"outcome": "ok", "backend": "a"}},
            {"op": "finish", "session": "live", "success": True, "expect": {"outcome": "ok"}},
            {"op": "open", "session": "idle", "expect": {"outcome": "ok"}},
            {"op": "next", "session": "idle", "expect": {"outcome": "no_backend"}},
            {"op": "router_reset", "expect": {"outcome": "ok"}},
            {"op": "rehydrate", "session": "live", "backend_ref": "previous",
             "expect": {"outcome": "ok", "backend": "a"}},
            {"op": "close", "session": "live", "expect": {"outcome": "ok"}},
            {"op": "close", "session": "idle", "expect": {"outcome": "ok"}},
            {"op": "checkpoint", "expect": {"outcome": "ok"}},
        ]
        with self.assertRaisesRegex(runner.Difference, "every open session"):
            runner.validate(self.trace(events))

    def test_relative_rehydrate_requires_an_active_reset(self):
        events = [
            {"op": "open", "session": "s", "expect": {"outcome": "ok"}},
            {"op": "rehydrate", "session": "s", "backend_ref": "previous",
             "expect": {"outcome": "ok", "backend": "a"}},
            {"op": "close", "session": "s", "expect": {"outcome": "ok"}},
            {"op": "checkpoint", "expect": {"outcome": "ok"}},
        ]
        with self.assertRaisesRegex(runner.Difference, "surviving pre-reset"):
            runner.validate(self.trace(events))

    def test_relative_failover_requires_active_session_and_singleton_list(self):
        events = [
            {"op": "open", "session": "s", "expect": {"outcome": "ok"}},
            {"op": "next", "session": "s", "expect": {"outcome": "ok", "backend": "a"}},
            {"op": "finish", "session": "s", "success": True, "expect": {"outcome": "ok"}},
            {"op": "config", "fail_backend_ref": "s",
             "toml": "[proxy]\nfail-backend-list=['recorded']\n",
             "expect": {"outcome": "ok"}},
            {"op": "config", "toml": "[proxy]\nfail-backend-list=[]\n",
             "expect": {"outcome": "ok"}},
            {"op": "close", "session": "s", "expect": {"outcome": "ok"}},
            {"op": "checkpoint", "expect": {"outcome": "ok"}},
        ]
        runner.validate(self.trace(events))
        missing = copy.deepcopy(events)
        missing[3]["fail_backend_ref"] = "missing"
        with self.assertRaisesRegex(runner.Difference, "active session"):
            runner.validate(self.trace(missing))
        plural = copy.deepcopy(events)
        plural[3]["toml"] = "[proxy]\nfail-backend-list=['a','b']\n"
        with self.assertRaisesRegex(runner.Difference, "singleton list"):
            runner.validate(self.trace(plural))


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

    def test_zero_and_epoch_times_remain_distinct_inputs(self):
        trace = trace_for([])
        event = {"op":"metrics", "queries":self.packet(), "expect":{"outcome":"ok"}}
        trace["events"].insert(0, event)
        for stamp in (None, 0):
            event["queries"]["cpu"]["updated_nanos"] = stamp
            runner.validate(trace)
            self.assertIs(event["queries"]["cpu"]["updated_nanos"], stamp)


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

    def test_relative_failover_uses_session_assignment_after_balance_move(self):
        h = self.history()
        h.apply({"op": "open", "session": "lifecycle"}, {})
        self.reserve(h, "lifecycle", "b", True)
        arm = {"op": "config", "delay_next": 1,
               "fail_backend_ref": "lifecycle",
               "toml": "[proxy]\nfail-backend-list=['a']\nfailover-timeout=60\n"}
        h.prepare(arm, {}, {"outcome": "ok"}, 0)
        model = {"kind": "connection", "fail_backend_ref": "lifecycle",
                 "groups": [{"group": "group/1", "members": [
                     {"backend": "a", "healthy": True, "keyspace": ""},
                     {"backend": "b", "healthy": True, "keyspace": ""},
                 ]}]}
        effects = h.expected_effect_alternatives(
            {"op": "tick"}, {"redirect_cadence": model}, 0)
        self.assertEqual(len(effects), 1)
        self.assertEqual([(effect["session"], effect["from"], effect["to"])
                          for effect in effects[0]], [("lifecycle", "b", "a")])

        literal = self.history()
        literal.apply({"op": "open", "session": "lifecycle"}, {})
        self.reserve(literal, "lifecycle", "b", True)
        literal.prepare({"op": "config", "delay_next": 1,
                         "toml": arm["toml"]}, {}, {"outcome": "ok"}, 0)
        plain = {"kind": "connection", "groups": model["groups"]}
        self.assertEqual(literal.expected_effect_alternatives(
            {"op": "tick"}, {"redirect_cadence": plain}, 0), [[]])

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
            ef = {"kind": "redirect", "session": "s", "operation": "s/2", "from": "a", "to": "b", "accepted": True}
            h.apply({"op": "tick"}, {"effects": [dict(ef, operation="s/1", accepted=False)]})
            self.assertEqual(h.prefer_idle({"a", "b"}), {"b"})
            h.apply({"op": "tick"}, {"effects": [ef]})
            self.assertEqual(h.prefer_idle({"a", "b"}), {"a", "b"})
            h.apply({"op": "tick"}, {"effects": [dict(ef, kind="force_close", operation="s/3", to="")]})
            if result == "close":
                h.apply({"op": "close", "session": "s"}, {})
            callback = {"op": "redirect_result", "session": "s", "operation": "s/2", "success": result is not False}
            h.apply(callback, {})
            h.apply(callback, {})  # duplicate/late delivery cannot resurrect or double-transfer
            self.assertEqual(h.prefer_idle({"a", "b"}), {"b"} if result is False else {"a", "b"})
            self.assertEqual(h.assigned.get("s"), "a" if result is False else "b" if result is True else None)

    def test_global_refusal_with_zero_attempts_expires_at_failover_clear(self):
        h = self.history()
        event = {"op": "tick", "refuse_next": 1}
        singleton = {"redirect_cadence": {"kind": "connection", "groups": [
            {"group": "group/1", "members": [{"backend": "a", "healthy": True, "keyspace": ""}]},
        ]}}
        h.prepare(event, singleton, {"outcome": "ok"}, 0)
        self.assertEqual(h.expected_effect_alternatives(event, singleton, 0), [[]])
        h.apply(event, {"outcome": "ok", "effects": []}, prepared=True)
        self.assertEqual(h.refuse_next, 1)
        clear = {"op": "config", "toml": "[proxy]\nfail-backend-list=[]\n"}
        h.prepare(clear, {}, {"outcome": "ok"}, 1)
        self.assertEqual(h.refuse_next, 0)

    def test_global_refusal_with_an_eligible_attempt_cannot_expire(self):
        h = self.history()
        h.refuse_next = 1
        h.refusal_attempts = 1
        with self.assertRaisesRegex(runner.Difference, "survived 1 eligible attempts"):
            h.expire_refusal("failover clear")

    def test_config_refusal_arm_requires_nonempty_failover(self):
        h = self.history()
        clear_arm = {"op": "config", "refuse_next": 1,
                     "toml": "[proxy]\nfail-backend-list=[]\n"}
        with self.assertRaisesRegex(runner.Difference, "requires a nonempty failover list"):
            h.prepare(clear_arm, {}, {"outcome": "ok"}, 0)

    def test_session_refused_attempt_does_not_consume_global_refusal(self):
        h = self.history()
        event = {"op": "tick", "refuse_next": 1, "refuse": ["s"]}
        rejected = {"kind": "force_close", "session": "s", "operation": "s/1",
                    "from": "a", "to": "", "accepted": False}
        h.prepare(event, {}, {"outcome": "ok"}, 0)
        h.apply(event, {"outcome": "ok", "effects": [rejected]}, prepared=True)
        self.assertEqual((h.refuse_next, h.refusal_attempts), (1, 0))
        h.expire_refusal("trace end")
        self.assertEqual(h.refuse_next, 0)

    def test_global_refusal_is_consumed_by_first_eligible_attempt(self):
        h = self.history()
        event = {"op": "tick", "refuse_next": 1}
        rejected = {"kind": "force_close", "session": "s", "operation": "s/1",
                    "from": "a", "to": "", "accepted": False}
        h.prepare(event, {}, {"outcome": "ok"}, 0)
        self.assertEqual(h.expected_effect_alternatives(event, {"effects": [rejected]}, 0), [[rejected]])
        h.apply(event, {"outcome": "ok", "effects": [rejected]}, prepared=True)
        self.assertEqual(h.refuse_next, 0)
        second = self.history()
        second.prepare(event, {}, {"outcome": "ok"}, 0)
        self.assertEqual(second.expected_effect_alternatives(
            event, {"effects": [dict(rejected, accepted=True)]}, 0), [])

    def test_config_and_legacy_tick_refusal_cannot_overlap(self):
        h = self.history()
        arm = {"op": "config", "refuse_next": 1,
               "toml": "[proxy]\nfail-backend-list=[\"a\"]\n"}
        h.prepare(arm, {}, {"outcome": "ok"}, 0)
        repeat = {"op": "config", "toml": "[proxy]\nfail-backend-list=[\"a\"]\n"}
        h.prepare(repeat, {}, {"outcome": "ok"}, 1)
        self.assertEqual(h.refuse_next, 1)
        with self.assertRaisesRegex(runner.Difference, "armed while one is pending"):
            h.prepare({"op": "tick", "refuse_next": 1}, {}, {"outcome": "ok"}, 2)

    def test_relative_redirect_ordinal_does_not_embed_a_tick(self):
        for tick in (4, 17):
            with self.subTest(tick=tick):
                h = self.history()
                self.reserve(h, "actual", "a", True)
                redirect = {"kind": "redirect", "session": "actual", "operation": "actual/1",
                            "from": "a", "to": "b", "accepted": True}
                h.apply({"op": "tick", "at_nanos": tick}, {"effects": [redirect]}, index=tick)
                callback = {"op": "redirect_result", "session": "actual",
                            "effect_ref": "redirect/1", "success": True}
                self.assertEqual(h.resolve_event(callback), "actual")
                self.assertEqual(h.resolve_operation(callback), "actual/1")

    def test_relative_effect_binding_is_session_scoped_and_stable(self):
        h = self.history()
        for sid in ("a", "b"):
            self.reserve(h, sid, "source", True)
        for sid in ("a", "b"):
            redirect = {"kind": "redirect", "session": sid, "operation": f"{sid}/1",
                        "from": "source", "to": "target", "accepted": True}
            h.apply({"op": "tick"}, {"effects": [redirect]})

        first = {"op": "redirect_result", "session": "a",
                 "effect_ref": "redirect/1", "success": True}
        self.assertEqual(h.resolve_operation(first), "a/1")
        with self.assertRaisesRegex(runner.Difference, "same-session redirect"):
            h.resolve_operation({"op": "redirect_result", "session": "a",
                                 "effect_ref": "redirect/2", "optional_effect": True,
                                 "success": True})
        # Reusing a bound handle cannot consume the next accepted redirect.
        self.assertEqual(h.resolve_operation(first), "a/1")
        self.assertEqual([effect["operation"] for effect in h.unbound_redirects], ["b/1"])
        with self.assertRaisesRegex(runner.Difference, "crossed sessions"):
            h.resolve_operation({**first, "session": "b"})

    def test_optional_relative_callback_cannot_borrow_another_session(self):
        h = self.history()
        self.reserve(h, "a", "source", True)
        redirect = {"kind": "redirect", "session": "a", "operation": "a/1",
                    "from": "source", "to": "target", "accepted": True}
        h.apply({"op": "tick"}, {"effects": [redirect]})
        callback = {"op": "redirect_result", "session": "b",
                    "effect_ref": "redirect/1", "optional_effect": True,
                    "success": True}
        self.assertEqual(h.resolve_event(callback), "")
        self.assertEqual(h.resolve_operation(callback), "")
        self.assertEqual([effect["operation"] for effect in h.unbound_redirects], ["a/1"])
        self.reserve(h, "b", "source", True)
        other = {"kind": "redirect", "session": "b", "operation": "b/1",
                 "from": "source", "to": "target", "accepted": True}
        h.apply({"op": "tick"}, {"effects": [other]})
        with self.assertRaisesRegex(runner.Difference, "same-session redirect"):
            h.resolve_operation(callback)
        h.apply({"op": "close", "session": "a"}, {})
        h.apply({"op": "close", "session": "b"}, {})
        self.assertEqual(h.unbound_redirects, [])

    def test_strict_relative_close_rejects_multiple_global_candidates(self):
        h = self.history()
        for sid in ("logical", "a", "b"):
            self.reserve(h, sid, "source", True)
        for sid in ("a", "b"):
            redirect = {"kind": "redirect", "session": sid, "operation": f"{sid}/1",
                        "from": "source", "to": "target", "accepted": True}
            h.apply({"op": "tick"}, {"effects": [redirect]})

        close = {"op": "close", "session": "logical", "effect_ref": "redirect/1"}
        with self.assertRaisesRegex(runner.Difference, "ambiguous strict relative effect"):
            h.resolve_event(close)
        self.assertEqual([effect["operation"] for effect in h.unbound_redirects],
                         ["a/1", "b/1"])

    def test_strict_relative_close_swaps_handles_for_one_global_candidate(self):
        h = self.history()
        for sid in ("logical", "actual"):
            h.apply({"op": "open", "session": sid}, {})
            self.reserve(h, sid, "source", True)
        redirect = {"kind": "redirect", "session": "actual", "operation": "actual/1",
                    "from": "source", "to": "target", "accepted": True}
        h.apply({"op": "tick"}, {"effects": [redirect]})

        close = {"op": "close", "session": "logical", "effect_ref": "redirect/1"}
        self.assertEqual(h.resolve_event(close), "actual")
        self.assertEqual(h.logical_to_actual, {"logical": "actual", "actual": "logical"})
        callback = {"op": "redirect_result", "session": "logical",
                    "effect_ref": "redirect/1", "success": True}
        self.assertEqual(h.resolve_operation(callback), "actual/1")

    def test_delayed_arm_binds_each_engines_first_accepted_redirect(self):
        def bound(order):
            h = self.history()
            for sid in ("logical", "a", "b"):
                h.apply({"op": "open", "session": sid}, {})
                self.reserve(h, sid, "source", True)
            arm = {"op": "config", "delay_next": 1,
                   "toml": "[proxy]\nfail-backend-list=['source']\n"}
            h.prepare(arm, {}, {"outcome": "ok"}, 0)
            effects = [{"kind": "redirect", "session": sid,
                        "operation": f"{sid}/1", "from": "source",
                        "to": "target", "accepted": True} for sid in order]
            h.apply({"op": "tick"}, {"effects": effects})
            close = {"op": "close", "session": "logical",
                     "effect_ref": "redirect/1", "optional_effect": True}
            actual = h.resolve_event(close)
            operation = h.resolve_operation(close)
            return actual, operation, h

        left_actual, left_operation, _ = bound(["a", "b"])
        right_actual, right_operation, right = bound(["b", "a"])
        self.assertEqual((left_actual, left_operation), ("a", "a/1"))
        self.assertEqual((right_actual, right_operation), ("b", "b/1"))
        self.assertEqual([effect["operation"] for effect in right.unbound_redirects], ["a/1"])

    def test_delayed_arm_with_zero_accepted_redirects_expires_without_borrowing(self):
        h = self.history()
        for sid in ("logical", "other"):
            h.apply({"op": "open", "session": sid}, {})
            self.reserve(h, sid, "source", True)
        arm = {"op": "config", "delay_next": 1,
               "toml": "[proxy]\nfail-backend-list=['source']\n"}
        h.prepare(arm, {}, {"outcome": "ok"}, 0)
        close = {"op": "close", "session": "logical",
                 "effect_ref": "redirect/1", "optional_effect": True}
        self.assertEqual(h.resolve_event(close), "logical")
        self.assertEqual(h.resolve_operation(close), "")
        h.apply(close, {"outcome": "no_effect", "effects": []}, sid="logical")
        self.assertEqual((h.delay_next, h.delay_attempts), (0, 0))
        later = {"kind": "redirect", "session": "other", "operation": "other/1",
                 "from": "source", "to": "target", "accepted": True}
        h.apply({"op": "tick"}, {"effects": [later]})
        self.assertIsNone(h.delayed_redirect)
        self.assertEqual([effect["operation"] for effect in h.unbound_redirects], ["other/1"])
        clear = {"op": "config", "toml": "[proxy]\nfail-backend-list=[]\n"}
        h.prepare(clear, {}, {"outcome": "ok"}, 1)
        self.assertEqual((h.delay_next, h.delay_attempts), (0, 0))
        self.assertEqual(h.assigned, {"other": "source"})

    def test_expired_delay_ignores_pre_arm_same_session_redirect(self):
        h = self.history()
        for sid in ("logical", "other"):
            h.apply({"op": "open", "session": sid}, {})
            self.reserve(h, sid, "source", True)
        old = {"kind": "redirect", "session": "logical", "operation": "logical/1",
               "from": "source", "to": "target", "accepted": True}
        h.apply({"op": "tick"}, {"effects": [old]})
        arm = {"op": "config", "delay_next": 1,
               "toml": "[proxy]\nfail-backend-list=['source']\n"}
        h.prepare(arm, {}, {"outcome": "ok"}, 0)

        close = {"op": "close", "session": "logical",
                 "effect_ref": "redirect/1", "optional_effect": True}
        self.assertEqual(h.resolve_event(close), "logical")
        self.assertEqual(h.resolve_operation(close), "")
        h.apply(close, {"outcome": "no_effect", "effects": []}, sid="logical")
        callback = {"op": "redirect_result", "session": "logical",
                    "effect_ref": "redirect/1", "optional_effect": True,
                    "success": True}
        self.assertEqual(h.resolve_event(callback), "")
        self.assertEqual(h.resolve_operation(callback), "")
        self.assertEqual((h.delay_next, h.delay_attempts, h.unbound_redirects), (0, 0, []))

    def test_effect_relative_rehydrate_swaps_survivor_handles(self):
        h = self.history()
        for sid in ("recorded", "actual"):
            h.apply({"op": "open", "session": sid}, {}, sid=sid)
            self.reserve(h, sid, "source", True)
        arm = {"op": "config", "delay_next": 1,
               "toml": "[proxy]\nfail-backend-list=['source']\n"}
        h.prepare(arm, {}, {"outcome": "ok"}, 0)
        delayed = {"kind": "redirect", "session": "actual", "operation": "actual/1",
                   "from": "source", "to": "target", "accepted": True}
        h.apply({"op": "tick"}, {"effects": [delayed]})
        h.apply({"op": "router_reset"}, {"outcome": "ok", "effects": []})

        relative = {"op": "rehydrate", "session": "recorded",
                    "effect_ref": "redirect/1"}
        self.assertEqual(h.resolve_event(relative), "actual")
        self.assertEqual(h.logical_to_actual,
                         {"recorded": "actual", "actual": "recorded"})
        self.assertEqual(h.resolve_backend(relative), "target")
        h.apply(relative, {"outcome": "ok", "backend": "target", "effects": []},
                sid="actual")

        previous = {"op": "rehydrate", "session": "actual", "backend_ref": "previous"}
        self.assertEqual(h.resolve_event(previous), "recorded")
        self.assertEqual(h.resolve_backend(previous), "source")
        h.apply(previous, {"outcome": "ok", "backend": "source", "effects": []},
                sid="recorded")
        self.assertEqual(h.assigned, {"actual": "target", "recorded": "source"})
        self.assertEqual(h.reset_previous, {})

    def test_delayed_arm_fails_if_accepted_binding_leaves_public_queue(self):
        h = self.history()
        for sid in ("logical", "actual"):
            h.apply({"op": "open", "session": sid}, {})
            self.reserve(h, sid, "source", True)
        arm = {"op": "config", "delay_next": 1,
               "toml": "[proxy]\nfail-backend-list=['source']\n"}
        h.prepare(arm, {}, {"outcome": "ok"}, 0)
        accepted = {"kind": "redirect", "session": "actual", "operation": "actual/1",
                    "from": "source", "to": "target", "accepted": True}
        h.apply({"op": "tick"}, {"effects": [accepted]})
        h.unbound_redirects.clear()
        close = {"op": "close", "session": "logical",
                 "effect_ref": "redirect/1", "optional_effect": True}
        with self.assertRaisesRegex(runner.Difference, "left the public queue"):
            h.resolve_event(close)

    def test_delayed_operation_settled_by_its_own_early_close_is_not_borrowed(self):
        h = self.history()
        for sid in ("logical", "actual", "other"):
            h.apply({"op": "open", "session": sid}, {})
            self.reserve(h, sid, "source", True)
        arm = {"op": "config", "delay_next": 1,
               "toml": "[proxy]\nfail-backend-list=['source']\n"}
        h.prepare(arm, {}, {"outcome": "ok"}, 0)
        delayed = {"kind": "redirect", "session": "actual", "operation": "actual/1",
                   "from": "source", "to": "target", "accepted": True}
        h.apply({"op": "tick"}, {"effects": [delayed]})
        h.apply({"op": "close", "session": "actual"}, {}, sid="actual")
        ordinary = {"kind": "redirect", "session": "other", "operation": "other/1",
                    "from": "source", "to": "target", "accepted": True}
        h.apply({"op": "tick"}, {"effects": [ordinary]})

        close = {"op": "close", "session": "logical",
                 "effect_ref": "redirect/1", "optional_effect": True}
        self.assertEqual(h.resolve_event(close), "logical")
        self.assertEqual(h.resolve_operation(close), "")
        self.assertEqual([effect["operation"] for effect in h.unbound_redirects], ["other/1"])

    def test_ordinary_callback_cannot_consume_delayed_operation(self):
        h = self.history()
        for sid in ("logical", "actual"):
            h.apply({"op": "open", "session": sid}, {})
            self.reserve(h, sid, "source", True)
        arm = {"op": "config", "delay_next": 1,
               "toml": "[proxy]\nfail-backend-list=['source']\n"}
        h.prepare(arm, {}, {"outcome": "ok"}, 0)
        delayed = {"kind": "redirect", "session": "actual", "operation": "actual/1",
                   "from": "source", "to": "target", "accepted": True}
        h.apply({"op": "tick"}, {"effects": [delayed]})
        callback = {"op": "redirect_result", "session": "actual",
                    "effect_ref": "redirect/99", "optional_effect": True,
                    "success": True}
        self.assertEqual(h.resolve_event(callback), "")
        self.assertEqual(h.resolve_operation(callback), "")
        self.assertEqual([effect["operation"] for effect in h.unbound_redirects], ["actual/1"])
        close = {"op": "close", "session": "logical",
                 "effect_ref": "redirect/1", "optional_effect": True}
        self.assertEqual(h.resolve_event(close), "actual")
        self.assertEqual(h.resolve_operation(close), "actual/1")

    def test_failed_relative_callback_keeps_per_session_cooldown(self):
        h = self.history()
        self.reserve(h, "active", "a", True)
        for sid in ("pending-1", "pending-2", "pending-3"):
            self.reserve(h, sid, "a")
        expect = {"redirect_cadence": {"kind": "connection", "groups": [{
            "group": "group/1",
            "members": [
                {"backend": "a", "healthy": True, "keyspace": ""},
                {"backend": "b", "healthy": True, "keyspace": ""},
            ],
        }]}}
        tick = {"op": "tick", "at_nanos": 0}
        redirect = h.expected_effect_alternatives(tick, expect, 0)[0][0]
        self.assertEqual(redirect["session"], "active")
        h.apply(tick, {"effects": [redirect]})
        h.apply({"op": "redirect_result", "session": "active",
                 "operation": "active/1", "success": False}, {})
        self.assertEqual(h.expected_effect_alternatives(tick, expect, 2_999_999_999), [[]])
        retry = h.expected_effect_alternatives(tick, expect, 3_000_000_000)[0]
        self.assertEqual([(effect["session"], effect["operation"]) for effect in retry],
                         [("active", "active/2")])

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
