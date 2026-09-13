# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Written Resource migration cadence from public metric and connection inputs."""
import json
from pathlib import Path
import sys

A, B = "127.0.0.1:4000", "127.0.0.1:4001"
ORIGIN = 1_800_000_000_000_000_000


def make_trace():
    events = []

    def add(op, at, expect=None, **values):
        events.append({"op":op, "at_nanos":at, **values,
                       "expect":{"outcome":"ok", **(expect or {})}})

    backends = [
        {"address":A, "cluster":"", "keyspace":"", "ip":"127.0.0.1",
         "status_port":10080, "labels":{}, "healthy":True, "local":True,
         "server_version":"8.5.1", "support_redirection":True},
        {"address":B, "cluster":"", "keyspace":"", "ip":"127.0.0.1",
         "status_port":10081, "labels":{}, "healthy":True, "local":True,
         "server_version":"8.5.1", "support_redirection":True},
    ]
    add("health", 0, backends=backends)
    add("config", 0, toml="[balance]\npolicy='resource'\nrouting-policy='prefer-idle'\n"
        "[balance.cpu]\nmigrations-per-second=10\n")
    for index in range(6):
        session = f"resource-{index}"
        add("open", 0, session=session)
        add("rehydrate", 0, {"backend":A}, session=session, backend=A)
    packet = dict.fromkeys(("cpu", "memory", "failure_pd", "total_pd",
                            "failure_tikv", "total_tikv"))
    packet["cpu"] = {"kind":"matrix", "updated_nanos":ORIGIN, "series":[
        {"labels":{"instance":"127.0.0.1:10080"},
         "samples":[{"timestamp_ms":ORIGIN // 1_000_000, "value":"0.9"}]},
        {"labels":{"instance":"127.0.0.1:10081"},
         "samples":[{"timestamp_ms":ORIGIN // 1_000_000, "value":"0.1"}]},
    ]}
    add("metrics", 0, queries=packet)
    add("tick", 0, {"effects":[{"kind":"redirect", "session":"resource-0",
        "operation":"resource-0/1", "from":A, "to":B, "accepted":True}]})
    add("redirect_result", 1, session="resource-0", operation="resource-0/1", success=True)
    add("tick", 99_999_999, {"effects":[]})
    add("tick", 100_000_000, {"effects":[
        {"kind":"redirect", "session":"resource-1", "operation":"resource-1/1",
         "from":A, "to":B, "accepted":False},
        {"kind":"redirect", "session":"resource-2", "operation":"resource-2/1",
         "from":A, "to":B, "accepted":True},
    ]}, refuse=["resource-1"])
    add("redirect_result", 100_000_001, session="resource-2",
        operation="resource-2/1", success=True)
    # Current CPU estimates have crossed after two reservations, but moving a
    # connection back would violate the higher-priority average-CPU advice.
    add("tick", 200_000_000, {"effects":[]})
    # The supported Balance scoring call is part of the factor history. A later
    # route remains independently derivable instead of losing cache provenance.
    add("open", 200_000_001, session="post-tick")
    add("next", 200_000_001, {"backend":B}, session="post-tick")
    add("finish", 200_000_001, session="post-tick", success=False)
    add("close", 200_000_001, session="post-tick")
    add("checkpoint", 200_000_002, {"healthy_backend_count":2,
        "legal_server_versions":["8.5.1"]})
    for index in range(6):
        add("close", 200_000_003, session=f"resource-{index}")
    add("health", 200_000_004, backends=[])
    add("checkpoint", 200_000_004, {"healthy_backend_count":0,
        "legal_server_versions":["8.5.1"]})
    return {"version":1, "id":"resource-cadence", "config":{
        "policy":"resource", "selection":"prefer-idle", "rule":"",
        "clock_origin_nanos":ORIGIN}, "provenance":{
            "kind":"synthetic",
            "description":"Public Resource metric and migration cadence; not a qualifying recording"},
        "events":events}


if __name__ == "__main__":
    Path(sys.argv[1]).write_text(json.dumps(make_trace(), indent=2) + "\n")
