# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Reuse the close scenario with public keyspaces and enabled redirection."""
import copy
import json
from pathlib import Path
import sys


def make_trace():
    trace = json.loads((Path(__file__).resolve().parent.parent / "force-close-smoke.json").read_text())
    trace["id"] = "cross-keyspace-failover-close"
    trace["provenance"] = {
        "kind": "synthetic",
        "description": "Enabled migration, mismatched public keyspaces, independent close histories; not a qualifying recording",
    }
    health = trace["events"][0]
    for i, backend in enumerate(health["backends"]):
        backend["support_redirection"] = True
        # The absent keyspace on B is Go's legacy empty keyspace.
        if i == 0:
            backend["keyspace"] = "tenant-A"
    # Before the second phase, replace the whole health input with two named
    # keyspaces. The close expectations and all public session inputs stay
    # unchanged; both engines must enforce the current input's pair guard.
    change = copy.deepcopy(health)
    change["at_nanos"] = 10_000_000_000
    change["backends"][0]["keyspace"] = "tenant-B"
    change["backends"][1]["keyspace"] = "tenant-A"
    index = next(i for i,e in enumerate(trace["events"]) if e.get("at_nanos",0) == change["at_nanos"])
    trace["events"].insert(index,change)
    return trace


if __name__ == "__main__":
    Path(sys.argv[1]).write_text(json.dumps(make_trace(), indent=2) + "\n")
