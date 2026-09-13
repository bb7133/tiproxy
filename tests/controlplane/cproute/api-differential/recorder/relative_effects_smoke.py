# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Generate the engine-relative refusal/callback/close adapter smoke."""

import json
from pathlib import Path
import sys

import derive_expectations as derive


A, B = "default/a", "default/b"


def make_case():
    sessions = list("abcde")
    events = [{"op": "health", "backends": [
        {"address": "a", "labels": {}, "support_redirection": True},
    ]}]
    for session in sessions:
        events += [
            {"op": "open", "session": session},
            {"op": "next", "session": session},
            {"op": "finish", "session": session, "success": True},
        ]
    events += [
        {"op": "config", "refuse_next": 1,
         "toml": "[proxy]\nfail-backend-list=[\"a\"]\nfailover-timeout=60\n"},
        # The input control belongs to the whole failover window, not to the
        # recording engine's concrete effect tick. This empty round proves that
        # each adapter retains it until its own first eligible attempt.
        {"op": "tick", "at_nanos": 1},
        {"op": "health", "at_nanos": 2, "backends": [
        {"address": "a", "labels": {}, "support_redirection": True},
        {"address": "b", "labels": {}, "support_redirection": True},
        ]},
    ]
    tick = len(events)
    effect_ref = "redirect/1"
    events += [
        {"op": "tick", "at_nanos": 3},
        {"op": "config", "at_nanos": 4, "toml": "[proxy]\nfail-backend-list=[]\n"},
        {"op": "close", "at_nanos": 5, "session": "b", "effect_ref": effect_ref},
        {"op": "redirect_result", "at_nanos": 5, "session": "b",
         "effect_ref": effect_ref, "success": True},
    ]
    events += [{"op": "close", "at_nanos": 6, "session": session}
               for session in "acde"]
    events += [
        {"op": "health", "at_nanos": 7, "backends": []},
        {"op": "checkpoint", "at_nanos": 7},
    ]
    trace = {
        "version": 1,
        "id": "relative-effect-cadence",
        "config": {"policy": "connection", "selection": "random", "rule": ""},
        "provenance": {"kind": "synthetic"},
        "events": events,
    }
    rows = []
    for seq, event in enumerate(events):
        row = {"seq": seq, "op": event["op"], "session": event.get("session", ""),
               "outcome": "ok", "backend": "", "effects": []}
        if event["op"] == "next":
            row["backend"] = A
        rows.append(row)
    rows[tick]["effects"] = [
        {"kind": "redirect", "session": "a", "operation": "a/1",
         "from": A, "to": B, "accepted": False},
        {"kind": "redirect", "session": "b", "operation": "b/1",
         "from": A, "to": B, "accepted": True},
    ]
    rows[-1].update(assignments={}, conn_count=0, healthy_backend_count=0,
                    server_version="")
    return trace, rows


def main():
    if len(sys.argv) != 2:
        raise SystemExit(f"usage: {Path(sys.argv[0]).name} OUTPUT")
    trace, rows = make_case()
    derived, requires = derive.derive(trace, rows, None)
    if requires:
        raise SystemExit(f"unexpected dependencies: {requires}")
    derive._RUNNER.validate(derived)
    derive._RUNNER.observe(derived, rows, "reference")
    Path(sys.argv[1]).write_text(json.dumps(derived, indent=2) + "\n")


if __name__ == "__main__":
    main()
