# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Generate the pre-arm redirect versus expired delay-window adapter smoke."""

import json
from pathlib import Path
import sys

import derive_expectations as derive


A, B = "default/a", "default/b"


def make_case():
    events = [
        {"op": "health", "backends": [
            {"address": "a", "labels": {}, "support_redirection": True},
        ]},
        {"op": "open", "session": "a"},
        {"op": "next", "session": "a"},
        {"op": "finish", "session": "a", "success": True},
        {"op": "health", "backends": [
            {"address": "a", "labels": {}, "support_redirection": True},
            {"address": "b", "labels": {}, "support_redirection": True},
        ]},
        {"op": "config", "toml": "[proxy]\nfail-backend-list=['a']\nfailover-timeout=60\n"},
        {"op": "tick"},
        # The accepted redirect above predates this arm and remains outstanding.
        # With no post-arm tick, the strict opportunity must expire as no_effect
        # and close the logical connection without borrowing the old redirect.
        {"op": "config", "delay_next": 1,
         "toml": "[proxy]\nfail-backend-list=['b']\nfailover-timeout=60\n"},
        {"op": "close", "session": "a", "effect_ref": "redirect/1",
         "optional_effect": True},
        {"op": "redirect_result", "session": "a", "effect_ref": "redirect/1",
         "optional_effect": True, "success": True},
        {"op": "health", "backends": []},
        {"op": "checkpoint"},
    ]
    rows = [{"seq": seq, "op": event["op"], "session": event.get("session", ""),
             "outcome": "ok", "backend": "", "effects": []}
            for seq, event in enumerate(events)]
    rows[2]["backend"] = A
    rows[6]["effects"] = [{"kind": "redirect", "session": "a", "operation": "a/1",
                            "from": A, "to": B, "accepted": True}]
    rows[8]["outcome"] = "no_effect"
    rows[9]["outcome"] = "no_effect"
    rows[9]["session"] = ""
    rows[-1].update(assignments={}, conn_count=0, healthy_backend_count=0,
                    server_version="")
    trace = {
        "version": 1,
        "id": "expired-delay-window",
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
