# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Counterexamples for public-history close checks; rows here are test data."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("derive", ROOT / "derive_expectations.py")
derive = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(derive)
runner = derive._RUNNER
A, B = "default/a", "default/b"


def effect(backend, ordinal, accepted, sid="s"):
    return {"kind":"force_close", "session":sid, "operation":f"{sid}/{ordinal}",
            "from":backend, "to":"", "accepted":accepted}


def example(backend):
    # The same trace accepts legal A or B. Only A is due at the first deadline.
    events = [
        {"op":"health", "backends":[{"address":"a", "labels":{}, "support_redirection":False},
                                       {"address":"b", "labels":{}, "support_redirection":False}]},
        {"op":"open", "session":"s"}, {"op":"next", "session":"s"},
        {"op":"finish", "session":"s", "success":True},
        {"op":"config", "toml":'[proxy]\nfail-backend-list = ["a"]\nfailover-timeout = 1\n'},
        {"op":"tick", "at_nanos":999_999_999},
        {"op":"tick", "at_nanos":1_000_000_000, "refuse":["s"]},
        {"op":"tick", "at_nanos":1_000_000_001},
        {"op":"tick", "at_nanos":1_000_000_002},
        {"op":"close", "session":"s"}, {"op":"health", "backends":[]}, {"op":"checkpoint"},
    ]
    for e in events:
        e["expect"] = {"outcome":"ok"}
    events[2]["expect"].update(legal_backends=[A,B], exclude_history=True)
    for i, due in ((5,[]),(6,[A]),(7,[A]),(8,[A])):
        events[i]["expect"]["force_close_due"] = due
    events[-1]["expect"].update(healthy_backend_count=0, legal_server_versions=[""])
    trace = {"version":1, "id":"relative-close-test", "config":{"policy":"connection", "selection":"random", "rule":""},
             "provenance":{"kind":"synthetic"}, "events":events}
    rows = [{"seq":i,"op":e["op"],"session":e.get("session",""),"outcome":"ok",
             "backend":backend if i == 2 else "", "effects":[]} for i,e in enumerate(events)]
    if backend == A:
        rows[6]["effects"] = [effect(A,1,False)]
        rows[7]["effects"] = [effect(A,2,True)]
    rows[-1].update(assignments={}, conn_count=0, healthy_backend_count=0, server_version="")
    return trace, rows


class RelativeCloseTests(unittest.TestCase):
    def test_different_legal_owners_produce_different_required_effects(self):
        trace, left = example(A)
        _, right = example(B)
        runner.compare(trace, left, right)
        d1, r1 = derive.derive(trace, left, None)
        d2, r2 = derive.derive(trace, right, None)
        self.assertEqual((r1,r2), ([],[]))
        self.assertEqual(d1,d2)  # No chosen owner is embedded in the expectations.
        self.assertEqual(derive.compare_with_reference(d1,trace,r1), ([],[]))
        runner.compare(d1,left,right)

    def test_missing_early_duplicate_wrong_owner_and_refusal_are_rejected(self):
        trace, rows = example(A)
        changes = [lambda r:r[6].update(effects=[]),
                   lambda r:r[5].update(effects=[effect(A,1,True)]),
                   lambda r:r[8].update(effects=[effect(A,3,True)]),
                   lambda r:r[6]["effects"][0].update(**{"from":B}),
                   lambda r:r[6]["effects"][0].update(accepted=True),
                   lambda r:r[7]["effects"][0].update(operation="s/1"),
                   lambda r:r[7]["effects"].append(effect(A,3,True))]
        for change in changes:
            bad=copy.deepcopy(rows);change(bad)
            with self.assertRaisesRegex(runner.Difference,"EFFECTS"):
                runner.observe(trace,bad,"corrupt")
            with self.assertRaises(derive.Refuse):
                derive.derive(trace,bad,None)

    def test_a_nondue_owner_cannot_borrow_the_other_engines_close(self):
        trace, rows = example(B)
        rows[6]["effects"] = [effect(B,1,False)]
        with self.assertRaisesRegex(runner.Difference,"EFFECTS"):
            runner.observe(trace,rows,"corrupt")
        with self.assertRaises(derive.Refuse):
            derive.derive(trace,rows,None)

    def test_accepted_close_survives_clear_and_reentry(self):
        trace, rows = example(A)
        ledger = runner.PublicConnections(trace["config"])
        for e,r in zip(trace["events"][:8], rows[:8]):
            ledger.apply(e,r)
        self.assertEqual(ledger.force_close_effects({"op":"tick"}, []), [])
        self.assertEqual(ledger.force_close_effects({"op":"tick"}, [A]), [])
        ledger.apply({"op":"close","session":"s"},{"effects":[]})
        self.assertEqual(ledger.force_close_effects({"op":"tick"}, [A]), [])

    def test_inflight_redirect_keeps_physical_owner_until_public_completion(self):
        c = runner.PublicConnections({"policy":"connection","selection":"random"})
        c.apply({"op":"rehydrate","session":"s"},{"outcome":"ok","backend":A})
        redirect={"kind":"redirect","session":"s","operation":"s/1","from":A,"to":B,"accepted":True}
        c.apply({"op":"tick"},{"effects":[redirect]})
        self.assertEqual(c.force_close_effects({"op":"tick"},[A]),[effect(A,2,True)])
        self.assertEqual(c.force_close_effects({"op":"tick"},[B]),[])
        c.apply({"op":"redirect_result","session":"s","operation":"s/1","success":True},{})
        self.assertEqual(c.force_close_effects({"op":"tick"},[B]),[effect(B,2,True)])

    def test_due_constraint_cannot_replace_redirect_cadence(self):
        trace, rows = example(A)
        for b in trace["events"][0]["backends"]: b["support_redirection"] = True
        # All ticks can migrate to B, so the deriver must retain that dependency.
        _, requires = derive.derive(trace,example(B)[1],None)
        self.assertIn("migration-cadence",requires)
        self.assertIn("effects-v2",requires)

    def test_constraint_schema_and_written_deadline_are_checked(self):
        trace, rows = example(A)
        for value in (True,[A,A],[""],[1]):
            bad=copy.deepcopy(trace);bad["events"][6]["expect"]["force_close_due"]=value
            with self.assertRaisesRegex(runner.Difference,"INPUT"):
                runner.validate(bad)
        bad=copy.deepcopy(trace);bad["events"][6]["expect"]["effects"]=[]
        with self.assertRaisesRegex(runner.Difference,"INPUT"):
            runner.validate(bad)
        d, req=derive.derive(trace,rows,None)
        bad=copy.deepcopy(trace);bad["events"][6]["expect"]["force_close_due"]=[B]
        self.assertTrue(derive.compare_with_reference(d,bad,req)[0])
        runner.validate(json.loads((ROOT.parent/"force-close-smoke.json").read_text()))


if __name__ == "__main__":
    unittest.main()
