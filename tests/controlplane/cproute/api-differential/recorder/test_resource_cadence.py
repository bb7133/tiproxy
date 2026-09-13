# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Resource migration expectations are derived without engine output as an oracle."""
import copy
import importlib.util
from pathlib import Path
import unittest

HERE = Path(__file__).resolve().parent


def module(name):
    spec = importlib.util.spec_from_file_location(name, HERE / (name + ".py"))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


derive = module("derive_expectations")
fixture = module("resource_cadence_smoke")
A, B = fixture.A, fixture.B


def written_rows(trace):
    rows, owners, accepted, settled = [], {}, {}, set()
    for seq, event in enumerate(trace["events"]):
        expect = event["expect"]
        row = {"seq":seq, "op":event["op"], "session":event.get("session", ""),
               "outcome":expect["outcome"], "backend":expect.get("backend", ""),
               "effects":copy.deepcopy(expect.get("effects", []))}
        for effect in row["effects"]:
            if effect["accepted"]:
                accepted[effect["operation"]] = effect
        if event["op"] == "rehydrate" and expect["outcome"] == "ok":
            owners[event["session"]] = event["backend"]
        elif event["op"] == "redirect_result":
            operation = event["operation"]
            if operation not in settled and event["success"] and event["session"] in owners:
                owners[event["session"]] = accepted[operation]["to"]
            settled.add(operation)
        elif event["op"] == "close":
            owners.pop(event["session"], None)
            settled.update(key for key, value in accepted.items()
                           if value["session"] == event["session"])
        elif event["op"] == "checkpoint":
            row.update(assignments=dict(owners), conn_count=len(owners),
                       healthy_backend_count=expect["healthy_backend_count"],
                       server_version="8.5.1")
        rows.append(row)
    return rows


class ResourceCadenceTests(unittest.TestCase):
    def setUp(self):
        self.trace = fixture.make_trace()
        self.rows = written_rows(self.trace)

    def tick(self, at):
        return next(index for index, event in enumerate(self.trace["events"])
                    if event["op"] == "tick" and event["at_nanos"] == at)

    def test_written_resource_cadence_derives_without_observed_effects(self):
        derived, requires = derive.derive(self.trace, self.rows, None)
        self.assertEqual(requires, [])
        self.assertEqual(derive.compare_with_reference(derived, self.trace, requires), ([], []))
        result = derive._RUNNER.compare(derived, self.rows, self.rows)
        self.assertEqual(result, {"events":34, "violations":0, "provenance":"synthetic"})

    def test_missing_early_and_wrong_resource_effects_are_rejected(self):
        rows = copy.deepcopy(self.rows)
        rows[self.tick(0)]["effects"] = []
        with self.assertRaisesRegex(derive.Refuse, "resource cadence"):
            derive.derive(self.trace, rows, None)
        rows = copy.deepcopy(self.rows)
        rows[self.tick(99_999_999)]["effects"] = [
            copy.deepcopy(rows[self.tick(100_000_000)]["effects"][1])]
        with self.assertRaisesRegex(derive.Refuse, "resource cadence"):
            derive.derive(self.trace, rows, None)
        for mutate in (lambda effects: effects[0].update(to=A),
                       lambda effects: effects[0].update(accepted=True),
                       lambda effects: effects.pop()):
            rows = copy.deepcopy(self.rows)
            mutate(rows[self.tick(100_000_000)]["effects"])
            with self.assertRaises(derive.Refuse):
                derive.derive(self.trace, rows, None)

    def test_public_cpu_values_determine_the_migration_direction(self):
        trace = copy.deepcopy(self.trace)
        packet = next(event["queries"] for event in trace["events"] if event["op"] == "metrics")
        left, right = packet["cpu"]["series"]
        left["samples"], right["samples"] = right["samples"], left["samples"]
        with self.assertRaises(derive.Refuse):
            derive.derive(trace, self.rows, None)

    def test_incomplete_public_metrics_keep_resource_cadence_unqualified(self):
        trace = copy.deepcopy(self.trace)
        packet = next(event["queries"] for event in trace["events"] if event["op"] == "metrics")
        packet["cpu"]["series"].pop()
        derived, requires = derive.derive(trace, self.rows, None)
        self.assertIn("migration-cadence", requires)
        self.assertIn("policy-constraint:resource/prefer-idle", requires)
        diffs, withheld = derive.compare_with_reference(derived, trace, requires)
        self.assertTrue(diffs)
        self.assertTrue(withheld)


if __name__ == "__main__":
    unittest.main()
