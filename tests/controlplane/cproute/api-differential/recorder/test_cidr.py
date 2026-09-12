# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Input-derived CIDR expectations and conservative grouping boundaries."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("derive", ROOT / "derive_expectations.py")
derive = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(derive)


def backend(name, cidrs, healthy=True):
    return {"address": name, "labels": {"cidr": cidrs}, "healthy": healthy}


class CIDRTests(unittest.TestCase):
    def state(self):
        return derive.State({"policy": "connection", "selection": "random", "rule": "client_cidr"})

    def candidates(self, state, address):
        return state.candidates(derive.Session("s", {"client": address}))[0]

    def test_literal_addresses_and_go_default_prefix(self):
        for bad in ("", "127.0.0.1", "localhost:80", "127.0.0.1:8]", "::1:80", "[fe80::1%lo0]:80"):
            self.assertIsNone(derive.address_ip(bad), bad)
        self.assertEqual(str(derive.address_ip("[::ffff:127.0.0.1]:named")), "127.0.0.1")
        self.assertEqual(str(derive.parse_cidrs(["2001:db8::1"])[0]), "2001:db8::/32")
        self.assertEqual(str(derive.parse_cidrs(["::ffff:127.0.0.1/120"])[0]), "127.0.0.0/24")
        for bad in ("127.0.0.1/33", "127.0.0.1/255.255.255.0", "fe80::1%lo0/64", "bad"):
            self.assertIsNone(derive.parse_cidrs([bad]))

    def test_group_refresh_keeps_members_and_last_valid_parse(self):
        state = self.state()
        state.apply_health([backend("a", "127.0.0.0/24"), backend("b", "127.0.0.0/24")])
        state.apply_health([backend("a", "192.0.2.0/24"), backend("b", "127.0.0.0/24")])
        self.assertEqual(self.candidates(state, "192.0.2.8:1"), ["default/a", "default/b"])
        state.apply_health([backend("a", "bad"), backend("b", "127.0.0.0/24")])
        self.assertEqual(self.candidates(state, "192.0.2.8:1"), ["default/a", "default/b"])
        state.apply_health([backend("a", ""), backend("b", "")])
        self.assertEqual(self.candidates(state, "127.0.0.8:1"), [])
        self.assertTrue(all(b.group is not None for b in state.backends.values()))

    def test_unparseable_new_group_has_no_routes(self):
        state = self.state()
        state.apply_health([backend("a", "127.0.0.0/24,bad")])
        self.assertEqual(self.candidates(state, "127.0.0.8:1"), [])
        self.assertIsNone(state.backends["default/a"].group)

    def test_intersecting_new_label_sets_refuse_order_dependence(self):
        for labels in [("127.0.0.0/24", "127.0.0.0/24,192.0.2.0/24"),
                       ("127.0.0.0/24,192.0.2.0/24", "192.0.2.0/24,198.51.100.0/24")]:
            with self.assertRaisesRegex(derive.Refuse, "traversal order"):
                self.state().apply_health([backend("a", labels[0]), backend("b", labels[1])])

    def test_multiple_matching_groups_refuse_borrowed_go_order(self):
        state = self.state()
        state.apply_health([backend("a", "127.0.0.0/24"), backend("b", "127.0.0.0/25")])
        with self.assertRaisesRegex(derive.Refuse, "multiple groups"):
            self.candidates(state, "127.0.0.8:1")
        self.assertEqual(self.candidates(state, "127.0.0.200:1"), ["default/a"])

    def test_bridge_between_retained_groups_is_refused(self):
        state = self.state()
        original = [backend("a", "127.0.0.0/24"), backend("b", "192.0.2.0/24")]
        state.apply_health(original)
        with self.assertRaisesRegex(derive.Refuse, "multiple retained groups"):
            state.apply_health(original + [backend("c", "127.0.0.0/24,192.0.2.0/24")])

    def test_removal_and_admission_order_is_not_assumed(self):
        state = self.state()
        state.apply_health([backend("a", "127.0.0.0/24")])
        with self.assertRaisesRegex(derive.Refuse, "removal/admission"):
            state.apply_health([backend("b", "127.0.0.0/24")])

    def test_engine_relative_retention_cannot_choose_group_members(self):
        state = self.state()
        state.apply_health([backend("a", "127.0.0.0/24"), backend("b", "127.0.0.0/24")])
        session = derive.Session("s", {})
        session.assigned = frozenset(["default/a", "default/b"])
        state.sessions["s"] = session
        with self.assertRaisesRegex(derive.Refuse, "engine-relative retention"):
            state.apply_health([backend("b", "127.0.0.0/24")])

    def test_fixtures_and_wrong_address_result_rejection(self):
        for rule in ("client", "proxy"):
            trace = json.loads((ROOT.parent / f"{rule}-cidr-smoke.json").read_text())
            derive._RUNNER.validate(trace)
            # These rows are only counterexample inputs to the deriver. CI separately
            # obtains real Go/Rust outputs for the same frozen scenario expectations.
            rows = []
            for event in trace["events"]:
                expected = event["expect"]
                rows.append({"outcome": expected["outcome"], "backend": expected.get("backend", expected.get("legal_backends", [""])[0]), "effects": []})
            derived, requires = derive.derive(copy.deepcopy(trace), rows, None)
            self.assertFalse(requires)
            self.assertEqual(derive.compare_with_reference(derived, trace, requires), ([], []))
            bad = copy.deepcopy(rows)
            index = next(i for i, event in enumerate(trace["events"]) if event["op"] == "next" and event["expect"]["outcome"] == "no_backend")
            bad[index].update(outcome="ok", backend="default/127.0.0.1:4020")
            with self.assertRaisesRegex(derive.Refuse, "not explained by inputs"):
                derive.derive(trace, bad, None)


if __name__ == "__main__":
    unittest.main()
