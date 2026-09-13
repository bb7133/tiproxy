# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Counterexample rows are hand-written fixture expectations, not engine evidence."""
import copy
import importlib.util
from pathlib import Path
import unittest

HERE = Path(__file__).resolve().parent


def module(name):
    spec = importlib.util.spec_from_file_location(name,HERE / (name + ".py"))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


derive = module("derive_expectations")
fixture = module("cadence_smoke")
A, B = fixture.A, fixture.B


def written_rows(trace):
    """Shape written effects as test observations; never invokes the scheduler."""
    rows, owners, accepted, done = [], {}, {}, set()
    for seq,event in enumerate(trace["events"]):
        sid = event.get("session", "")
        expect = event["expect"]
        row = {"seq":seq,"op":event["op"],"session":sid,"outcome":expect["outcome"],
               "backend":expect.get("backend", ""),"effects":copy.deepcopy(expect.get("effects",[]))}
        for effect in row["effects"]:
            if effect["accepted"]:
                accepted[effect["operation"]] = effect
        if event["op"] == "rehydrate" and expect["outcome"] == "ok":
            owners[sid] = event["backend"]
        if event["op"] == "redirect_result":
            key = event["operation"]
            if key not in done and sid in owners and event["success"]:
                owners[sid] = accepted[key]["to"]
            done.add(key)
        if event["op"] == "close":
            owners.pop(sid,None)
            done.update(key for key,value in accepted.items() if value["session"] == sid)
        if event["op"] == "checkpoint":
            row.update(assignments=dict(owners),conn_count=len(owners),
                       healthy_backend_count=expect["healthy_backend_count"],server_version="")
        rows.append(row)
    return rows


class CadenceTests(unittest.TestCase):
    def setUp(self):
        self.trace = fixture.make_trace()
        self.rows = written_rows(self.trace)

    def index(self, at, op="tick"):
        return next(i for i,e in enumerate(self.trace["events"]) if e["op"] == op and e["at_nanos"] == at)

    def test_written_cadence_scenarios_derive_without_observed_effects_as_expectations(self):
        derived, requires = derive.derive(self.trace,self.rows,None)
        self.assertEqual(requires,[])
        self.assertEqual(derive.compare_with_reference(derived,self.trace,requires),([],[]))
        derive._RUNNER.compare(derived,self.rows,self.rows)

    def test_missing_and_early_effects_are_rejected_at_the_tick(self):
        for at in (0,100_000_000,3_000_000_000,3_540_000_000,40_000_000_001,201_538_461_538):
            rows = copy.deepcopy(self.rows)
            rows[self.index(at)]["effects"] = []
            with self.subTest(at=at), self.assertRaisesRegex(derive.Refuse,"connection cadence"):
                derive.derive(self.trace,rows,None)
        for at in (99_999_999,199_999_999,2_999_999_999,201_538_461_537):
            rows = copy.deepcopy(self.rows)
            rows[self.index(at)]["effects"] = copy.deepcopy(self.rows[self.index(at + 1)]["effects"])
            with self.subTest(at=at), self.assertRaisesRegex(derive.Refuse,"connection cadence"):
                derive.derive(self.trace,rows,None)

    def test_refusal_budget_order_destination_ordinal_and_acceptance(self):
        mutations = [lambda es:es.pop(0),
                     lambda es:es[-1].update(session="slow-5",operation="slow-5/1"),
                     lambda es:es[0].update(accepted=True),
                     lambda es:es[-1].update(operation="slow-2/2"),
                     lambda es:es.append(copy.deepcopy(es[-1])),
                     lambda es:es[-1].update(to=A)]
        for mutate in mutations:
            rows = copy.deepcopy(self.rows)
            mutate(rows[self.index(0)]["effects"])
            with self.assertRaises(derive.Refuse):
                derive.derive(self.trace,rows,None)

    def test_fifo_after_callback_and_fast_batch_budget(self):
        rows = copy.deepcopy(self.rows)
        effect = rows[self.index(3_500_000_000)]["effects"][0]
        effect.update(session="slow-2",operation="slow-2/3")
        with self.assertRaisesRegex(derive.Refuse,"connection cadence"):
            derive.derive(self.trace,rows,None)
        for i,event in enumerate(self.trace["events"]):
            if event["op"] == "tick" and event["at_nanos"] == 50_000_000_000 and len(event["expect"]["effects"]) == 2:
                rows = copy.deepcopy(self.rows);rows[i]["effects"].pop()
                with self.assertRaisesRegex(derive.Refuse,"connection cadence"):
                    derive.derive(self.trace,rows,None)

    def test_unknown_or_wrong_owner_callback_is_refused(self):
        for field,value in (("operation","unknown/1"),("session","slow-1")):
            trace = copy.deepcopy(self.trace)
            trace["events"][self.index(120_000_000,"redirect_result")][field] = value
            with self.assertRaisesRegex(derive.Refuse,"callback lacks"):
                derive.derive(trace,self.rows,None)

    def test_tied_pairs_and_untrusted_histories_stay_unqualified(self):
        state = derive.State(self.trace["config"])
        state.apply_health([{"address":"a","labels":{}},{"address":"b","labels":{}},{"address":"c","labels":{}}])
        for i in range(3):
            s = derive.Session(f"s{i}",{})
            s.assigned = frozenset(["default/a"]);s.created=i
            state.sessions[s.id]=s
        self.assertIsNone(derive.derive_connection_redirects(state,set()))
        state.apply_health([{"address":"a","labels":{}},{"address":"b","labels":{}}])
        self.assertTrue(derive.derive_connection_redirects(state,set()))
        state.unique_history=False
        self.assertIsNone(derive.derive_connection_redirects(state,set()))
        state.unique_history=True;state.requires.add("migration-cadence")
        self.assertIsNone(derive.derive_connection_redirects(state,set()))

    def test_atomic_group_replacement_does_not_choose_map_order_for_the_clock(self):
        state = derive.State(self.trace["config"])
        state.apply_health([{"address":"a"},{"address":"b"}])
        state.group_last_redirect[""] = 1_000_000_000
        state.apply_health([{"address":"c"},{"address":"d"}])
        self.assertEqual(state.ambiguous_group_clocks,{""})
        self.assertIsNone(derive.derive_connection_redirects(state,set()))
        # Separate empty and replacement inputs prove the old group was removed.
        state.apply_health([])
        state.apply_health([{"address":"c"},{"address":"d"}])
        self.assertEqual(state.ambiguous_group_clocks,set())
        self.assertEqual(state.group_last_redirect,{})
        self.assertEqual(derive.derive_connection_redirects(state,set()),[])


if __name__ == "__main__":
    unittest.main()
