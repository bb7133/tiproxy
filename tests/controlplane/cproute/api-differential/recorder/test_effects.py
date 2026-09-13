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

    def test_one_shot_refusal_without_an_eligible_effect_expires_at_trace_end(self):
        trace, rows = example(B)
        trace["events"][5]["refuse_next"] = 1
        derived, requires = derive.derive(trace, rows, None)
        self.assertEqual(requires, [])
        runner.observe(derived, rows, "zero-attempt")

    def test_pending_one_shot_cannot_accept_the_first_eligible_attempt(self):
        trace, rows = example(A)
        trace["events"][5]["refuse_next"] = 1
        with self.assertRaisesRegex(runner.Difference, "EFFECTS"):
            runner.observe(trace, rows, "unconsumed-attempt")
        with self.assertRaisesRegex(derive.Refuse, "force_close effects"):
            derive.derive(trace, rows, None)

    def test_accepted_close_survives_clear_and_reentry(self):
        live = runner.PublicConnections({"policy":"connection","selection":"random"})
        live.apply({"op":"rehydrate","session":"s"},
                   {"outcome":"ok","backend":A,"effects":[]})
        accepted = [effect(A,1,True)]
        self.assertEqual(live.force_close_effects({"op":"tick"}, [A]), accepted)
        live.apply({"op":"tick"}, {"effects":accepted})
        live.apply({"op":"close","session":"s"}, {"effects":[]})
        self.assertEqual(live.force_close_effects({"op":"tick"}, [A]), [])

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

    def test_due_constraint_composes_with_engine_relative_redirect_cadence(self):
        trace, rows = example(A)
        for b in trace["events"][0]["backends"]: b["support_redirection"] = True
        derived, requires = derive.derive(trace,example(B)[1],None)
        self.assertEqual(requires, [])
        self.assertTrue(any("redirect_cadence" in e["expect"] for e in derived["events"] if e["op"] == "tick"))

    def test_closed_random_history_does_not_poison_exact_active_effects(self):
        def backend(name, port):
            return {"address":name, "labels":{}, "cluster":"default", "ip":"127.0.0.1",
                    "status_port":port, "healthy":True, "local":True,
                    "server_version":"", "support_redirection":True}

        def neutral_metrics():
            packet=dict.fromkeys(runner.METRIC_KEYS)
            for failure,total in (("failure_pd","total_pd"),("failure_tikv","total_tikv")):
                packet[failure]={"kind":"vector","updated_nanos":0,"series":[]}
                packet[total]={"kind":"vector","updated_nanos":0,"series":[]}
                for name,port in (("a",10080),("b",10081)):
                    labels={"instance":f"127.0.0.1:{port}","tiproxy_cluster":"default"}
                    packet[failure]["series"].append(
                        {"labels":labels,"samples":[{"timestamp_ms":0,"value":"0"}]})
                    packet[total]["series"].append(
                        {"labels":labels,"samples":[{"timestamp_ms":0,"value":"1"}]})
            return packet

        for policy in ("connection","resource","location"):
            with self.subTest(policy=policy):
                both=[backend("a",10080),backend("b",10081)]
                events=[{"op":"health","at_nanos":0,"backends":both}]
                if policy != "connection":
                    events.append({"op":"metrics","at_nanos":0,"queries":neutral_metrics()})
                events += [
                    {"op":"open","at_nanos":1,"session":"closed"},
                    {"op":"next","at_nanos":1,"session":"closed"},
                    {"op":"finish","at_nanos":1,"session":"closed","success":True},
                    {"op":"close","at_nanos":2,"session":"closed"},
                    {"op":"health","at_nanos":3,"backends":[backend("a",10080)]},
                    {"op":"open","at_nanos":4,"session":"held"},
                    {"op":"next","at_nanos":4,"session":"held"},
                    {"op":"finish","at_nanos":4,"session":"held","success":True},
                    {"op":"health","at_nanos":5,"backends":both},
                    {"op":"config","at_nanos":6,"toml":
                     '[proxy]\nfail-backend-list=["a"]\nfailover-timeout=60\n'},
                    {"op":"tick","at_nanos":7,"refuse":["held"]},
                    {"op":"close","at_nanos":8,"session":"held"},
                    {"op":"health","at_nanos":9,"backends":[]},
                    {"op":"checkpoint","at_nanos":9},
                ]
                trace={"version":1,"id":f"{policy}-closed-history-exact-effect",
                       "config":{"policy":policy,"selection":"random","rule":""},
                       "provenance":{"kind":"synthetic"},"events":events}
                rows=[]
                for seq,event in enumerate(events):
                    row={"seq":seq,"op":event["op"],"session":event.get("session",""),
                         "outcome":"ok","backend":"","effects":[]}
                    if event["op"]=="next":
                        row["backend"]=A
                    if event["op"]=="tick":
                        row["effects"]=[{"kind":"redirect","session":"held","operation":"held/1",
                                         "from":A,"to":B,"accepted":False}]
                    if event["op"]=="checkpoint":
                        row.update(assignments={},conn_count=0,healthy_backend_count=0,server_version="")
                    rows.append(row)
                derived,requires=derive.derive(trace,rows,None)
                self.assertEqual(requires,[])
                self.assertEqual(next(e["expect"]["effects"] for e in derived["events"] if e["op"]=="tick"),
                                 rows[next(i for i,e in enumerate(events) if e["op"]=="tick")]["effects"])
                runner.compare(derived,rows,rows)

                missing=copy.deepcopy(rows)
                tick=next(i for i,e in enumerate(events) if e["op"]=="tick")
                missing[tick]["effects"]=[]
                with self.assertRaisesRegex(derive.Refuse,f"input-derived {policy} cadence"):
                    derive.derive(trace,missing,None)

    def test_cross_keyspace_only_targets_do_not_require_migration_cadence(self):
        for keyspaces in (("tenant-A", "tenant-B"), ("", "tenant-A"),
                          ("tenant-A", ""), ("Tenant", "tenant")):
            with self.subTest(keyspaces=keyspaces):
                trace, left = example(A)
                _, right = example(B)
                for backend, keyspace in zip(trace["events"][0]["backends"], keyspaces):
                    backend.update(support_redirection=True, keyspace=keyspace)
                d1, r1 = derive.derive(trace, left, None)
                d2, r2 = derive.derive(trace, right, None)
                self.assertEqual((r1,r2), ([],[]))
                self.assertEqual(d1,d2)
                self.assertEqual(derive.compare_with_reference(d1,trace,r1), ([],[]))
                runner.compare(d1,left,right)

    def test_same_keyspace_and_legacy_empty_use_relative_cadence(self):
        for keyspace in (None, "", "tenant-A"):
            with self.subTest(keyspace=keyspace):
                trace, rows = example(B)
                for backend in trace["events"][0]["backends"]:
                    backend["support_redirection"] = True
                    if keyspace is not None:
                        backend["keyspace"] = keyspace
                derived, requires = derive.derive(trace,rows,None)
                self.assertEqual(requires, [])
                self.assertTrue(any("redirect_cadence" in e["expect"] for e in derived["events"] if e["op"] == "tick"))

    def test_cross_keyspace_redirect_is_refused_even_when_the_script_refuses_it(self):
        for accepted in (True, False):
            trace, rows = example(A)
            for backend, keyspace in zip(trace["events"][0]["backends"], ("red", "blue")):
                backend.update(support_redirection=True, keyspace=keyspace)
            if not accepted:
                trace["events"][5]["refuse"] = ["s"]
            rows[5]["effects"] = [{"kind":"redirect", "session":"s", "operation":"s/1",
                                    "from":A, "to":B, "accepted":accepted}]
            with self.assertRaisesRegex(derive.Refuse, "redirect destination"):
                derive.derive(trace,rows,None)

    def test_keyspaces_follow_whole_health_updates_and_retained_missing_sources(self):
        state = derive.State({"policy":"connection", "selection":"random", "rule":""})
        a = {"address":"a", "labels":{}, "keyspace":"red"}
        b = {"address":"b", "labels":{}, "keyspace":"blue"}
        state.apply_health([a,b])
        session = derive.Session("s", {})
        session.assigned = frozenset([A])
        state.sessions["s"] = session
        self.assertEqual(state.migration_targets(A), set())
        state.apply_health([b])  # retained source keeps its last delivered keyspace
        self.assertIn(A,state.backends)
        self.assertEqual(state.backends[A].keyspace,"red")
        b["keyspace"] = "red"
        state.apply_health([b])
        self.assertEqual(state.migration_targets(A), {B})
        state.apply_health([{"address":"a", "labels":{}},b])
        self.assertEqual(state.backends[A].keyspace, "")  # omitted on refresh resets to legacy
        self.assertEqual(state.migration_targets(A), set())
        self.assertEqual(state.migration_targets("unknown"), set())

    def test_compatible_alternative_keeps_cadence_but_not_across_groups(self):
        for rule in ("", "port"):
            state = derive.State({"policy":"connection", "selection":"random", "rule":rule})
            state.apply_health([
                {"address":"a", "keyspace":"red", "labels":{derive.PORT_LABEL:"4000"}},
                {"address":"b", "keyspace":"blue", "labels":{derive.PORT_LABEL:"4000"}},
                {"address":"c", "keyspace":"red", "labels":{derive.PORT_LABEL:"4001"}},
            ])
            self.assertEqual(state.migration_targets(A), {"default/c"} if rule == "" else set())
            self.assertEqual(state.migration_targets(B), set())
        trace, rows = example(B)
        for backend,keyspace in zip(trace["events"][0]["backends"], ("red","blue")):
            backend.update(support_redirection=True, keyspace=keyspace)
        trace["events"][0]["backends"].append({"address":"c", "labels":{}, "keyspace":"red"})
        derived, requires = derive.derive(trace,rows,None)
        self.assertEqual(requires, [])
        self.assertTrue(any("redirect_cadence" in e["expect"] for e in derived["events"] if e["op"] == "tick"))

    def test_relative_refusal_alias_and_delayed_close_follow_each_engine(self):
        sessions = list("abcde")
        events = [{"op":"health", "backends":[
            {"address":"a", "labels":{}, "support_redirection":True},
            {"address":"b", "labels":{}, "support_redirection":True},
        ]}]
        for sid in sessions:
            events += [{"op":"open", "session":sid}, {"op":"next", "session":sid},
                       {"op":"finish", "session":sid, "success":True}]
        tick = len(events)
        events.append({"op":"tick", "at_nanos":1, "refuse_next":1})
        events.append({"op":"close", "at_nanos":2, "session":"b",
                       "effect_ref":"redirect/1"})
        events.append({"op":"redirect_result", "at_nanos":2, "session":"b",
                       "effect_ref":"redirect/1", "success":True})
        for sid in "acde":
            events.append({"op":"close", "at_nanos":3, "session":sid})
        events += [{"op":"health", "at_nanos":4, "backends":[]},
                   {"op":"checkpoint", "at_nanos":4}]
        trace = {"version":1, "id":"relative-effect-alias",
                 "config":{"policy":"connection", "selection":"random", "rule":""},
                 "provenance":{"kind":"synthetic"}, "events":events}

        def rows(assignments, rejected, accepted, mapped_close):
            result=[]
            for seq,event in enumerate(events):
                sid=event.get("session", "")
                row={"seq":seq,"op":event["op"],"session":sid,"outcome":"ok","backend":"","effects":[]}
                if event["op"]=="next":
                    row["backend"]=assignments[sid]
                result.append(row)
            result[tick]["effects"]=[
                {"kind":"redirect","session":rejected,"operation":f"{rejected}/1",
                 "from":A,"to":B,"accepted":False},
                {"kind":"redirect","session":accepted,"operation":f"{accepted}/1",
                 "from":A,"to":B,"accepted":True},
            ]
            result[tick+1]["session"]=accepted
            result[tick+2]["session"]=accepted
            for logical,actual in mapped_close.items():
                index=next(i for i,e in enumerate(events) if e["op"]=="close" and e.get("session")==logical and i>tick+2)
                result[index]["session"]=actual
            result[-1].update(assignments={},conn_count=0,healthy_backend_count=0,server_version="")
            return result

        left=rows(dict(a=A,b=A,c=A,d=A,e=B),"a","b",{})
        right=rows(dict(a=B,b=A,c=A,d=A,e=A),"b","c",{"c":"b"})
        derived, requires = derive.derive(trace,left,None)
        self.assertEqual(requires, [])
        self.assertIn("redirect_cadence",derived["events"][tick]["expect"])
        runner.compare(derived,left,right)
        bad=copy.deepcopy(right)
        bad[tick]["effects"][1]["to"]=A
        with self.assertRaisesRegex(runner.Difference,"EFFECTS"):
            runner.observe(derived,bad,"corrupt")
        bad=copy.deepcopy(right)
        bad[tick]["effects"]=[]
        with self.assertRaisesRegex(runner.Difference,"EFFECTS"):
            runner.observe(derived,bad,"corrupt")

    def test_optional_callback_handles_engine_relative_cadence_time(self):
        sessions = list("abcde")
        events = [{"op":"health", "backends":[
            {"address":"a", "labels":{}, "support_redirection":True},
            {"address":"b", "labels":{}, "support_redirection":True},
        ]}]
        for sid in sessions:
            events += [{"op":"open", "session":sid}, {"op":"next", "session":sid},
                       {"op":"finish", "session":sid, "success":True}]
        tick=len(events)
        events += [{"op":"tick", "at_nanos":1},
                   {"op":"redirect_result", "at_nanos":2, "session":"a",
                    "operation":"a/1", "success":True},
                   {"op":"tick", "at_nanos":200_000_000_000}]
        events += [{"op":"close", "at_nanos":200_000_000_001, "session":sid}
                   for sid in sessions]
        events += [{"op":"health", "at_nanos":200_000_000_002, "backends":[]},
                   {"op":"checkpoint", "at_nanos":200_000_000_002}]
        trace={"version":1,"id":"optional-relative-callback",
               "config":{"policy":"connection","selection":"random","rule":""},
               "provenance":{"kind":"synthetic"},"events":events}

        def rows(assignments, migrated):
            result=[]
            for seq,event in enumerate(events):
                sid=event.get("session","")
                row={"seq":seq,"op":event["op"],"session":sid,
                     "outcome":"ok","backend":"","effects":[]}
                if event["op"]=="next": row["backend"]=assignments[sid]
                result.append(row)
            if migrated:
                result[tick]["effects"]=[{"kind":"redirect","session":"a","operation":"a/1",
                                           "from":A,"to":B,"accepted":True}]
                result[tick+2]["effects"]=[{"kind":"redirect","session":"b","operation":"b/1",
                                             "from":A,"to":B,"accepted":True}]
            else:
                result[tick+1].update(session="",outcome="no_effect")
            result[-1].update(assignments={},conn_count=0,healthy_backend_count=0,server_version="")
            return result

        left=rows({sid:A for sid in sessions},True)
        right=rows(dict(a=A,b=A,c=A,d=B,e=B),False)
        derived,requires=derive.derive(trace,left,None)
        self.assertEqual(requires,[])
        self.assertTrue(derived["events"][tick+1]["optional_effect"])
        self.assertEqual(derived["events"][tick+1]["effect_ref"],"redirect/1")
        self.assertIn("redirect_cadence",derived["events"][tick+2]["expect"])
        self.assertNotIn("effects",derived["events"][tick+2]["expect"])
        result = runner.compare(derived,left,right)
        self.assertEqual(result["effect_ledger"]["go"], {
            "accepted_effects": 2, "accepted_redirects": 2,
            "accepted_force_closes": 0, "callback_events": 1,
            "completed_callbacks": 1, "no_effect_callbacks": 0,
            "callback_settled_redirects": 1, "close_settled_redirects": 1,
            "other_settled_redirects": 0,
            "close_settled_force_closes": 0, "unsettled_accepted_effects": 0,
            "all_accepted_settled": True,
            "accepted_operations": [
                {"operation":"a/1", "kind":"redirect", "session":"a",
                 "settled_by":"callback"},
                {"operation":"b/1", "kind":"redirect", "session":"b",
                 "settled_by":"close"},
            ],
        })
        self.assertEqual(result["effect_ledger"]["rust"], {
            "accepted_effects": 0, "accepted_redirects": 0,
            "accepted_force_closes": 0, "callback_events": 1,
            "completed_callbacks": 0, "no_effect_callbacks": 1,
            "callback_settled_redirects": 0, "close_settled_redirects": 0,
            "other_settled_redirects": 0,
            "close_settled_force_closes": 0, "unsettled_accepted_effects": 0,
            "all_accepted_settled": True,
            "accepted_operations": [],
        })
        bad=copy.deepcopy(left)
        bad[tick+1].update(session="",outcome="no_effect")
        with self.assertRaisesRegex(runner.Difference,"RESULT_IDENTITY"):
            runner.observe(derived,bad,"same-session-missing")

    def test_keyspace_fixture_preserves_the_existing_session_and_deadline_scenario(self):
        spec = importlib.util.spec_from_file_location("keyspace_smoke", ROOT / "keyspace_smoke.py")
        fixture = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(fixture)
        original = json.loads((ROOT.parent / "force-close-smoke.json").read_text())
        trace = fixture.make_trace()
        self.assertEqual(len(trace["events"]), len(original["events"]) + 1)
        self.assertEqual([e for e in trace["events"] if e["op"] != "health"],
                         [e for e in original["events"] if e["op"] != "health"])
        for event in trace["events"]:
            if event["op"] == "health" and event["backends"]:
                a,b = event["backends"]
                self.assertTrue(a["support_redirection"] and b["support_redirection"])
                self.assertNotEqual(a.get("keyspace",""),b.get("keyspace",""))
        runner.validate(trace)

    def test_force_close_fixture_clears_due_after_the_last_owner_closes(self):
        original = json.loads((ROOT.parent / "force-close-smoke.json").read_text())
        for start, cleanup in ((33, 40), (75, 82)):
            with self.subTest(start=start):
                events = original["events"]
                self.assertEqual(events[start]["expect"]["force_close_due"],
                                 ["default/127.0.0.1:4001"])
                self.assertEqual(events[start + 1]["op"], "checkpoint")
                self.assertTrue(all(event["op"] == "close"
                                    for event in events[start + 2:cleanup]))
                self.assertEqual(len(events[start + 2:cleanup]), 5)
                self.assertEqual(events[cleanup]["op"], "tick")
                self.assertEqual(events[cleanup]["expect"]["force_close_due"], [])

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
