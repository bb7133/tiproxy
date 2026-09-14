# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Generate the explicit router reset and engine-relative rehydration smoke."""

import json
from pathlib import Path
import sys

import derive_expectations as derive


A, B = "default/a", "default/b"


def make_case():
    events = [{"op": "health", "backends": [
        {"address": "a", "labels": {}, "support_redirection": True},
    ]}]
    for session in ("a", "b"):
        events.extend([
            {"op": "open", "session": session},
            {"op": "next", "session": session},
            {"op": "finish", "session": session, "success": True},
        ])
    events.extend([
        {"op": "health", "backends": [
            {"address": "a", "labels": {}, "support_redirection": True},
            {"address": "b", "labels": {}, "support_redirection": True},
        ]},
        {"op": "config", "delay_next": 1,
         "toml": "[proxy]\nfail-backend-list=['a']\nfailover-timeout=60\n"},
        {"op": "tick"},
        {"op": "config", "toml": "[proxy]\nfail-backend-list=[]\n"},
        {"op": "router_reset"},
        {"op": "health", "backends": [
            {"address": "a", "labels": {}, "support_redirection": True},
            {"address": "b", "labels": {}, "support_redirection": True},
        ]},
        # The synthetic recording assigned the delayed redirect to logical
        # handle a. Another engine may assign it to b; the adapters swap logical
        # handles so the following previous reference still rehydrates the
        # displaced survivor exactly once.
        {"op": "rehydrate", "session": "a", "effect_ref": "redirect/1"},
        {"op": "rehydrate", "session": "b", "backend_ref": "previous"},
        {"op": "lookup", "effect_ref": "redirect/1"},
        {"op": "redirect_result", "session": "a", "effect_ref": "redirect/1",
         "optional_effect": True, "success": True},
        {"op": "close", "session": "a"},
        {"op": "close", "session": "b"},
        {"op": "checkpoint"},
    ])
    rows = [{"seq": seq, "op": event["op"], "session": event.get("session", ""),
             "outcome": "ok", "backend": "", "effects": []}
            for seq, event in enumerate(events)]
    for seq in (2, 5):
        rows[seq]["backend"] = A
    rows[9]["effects"] = [{"kind": "redirect", "session": "a", "operation": "a/1",
                            "from": A, "to": B, "accepted": True}]
    rows[13]["backend"] = B
    rows[14]["backend"] = A
    rows[15]["backend"] = B
    rows[-1].update(assignments={}, conn_count=0, healthy_backend_count=2,
                    server_version="")
    trace = {
        "version": 1,
        "id": "router-reset-rehydrate",
        "config": {"policy": "connection", "selection": "random", "rule": ""},
        "provenance": {"kind": "synthetic"},
        "events": events,
    }
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
