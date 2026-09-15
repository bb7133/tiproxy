# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Written public migration scenarios; does not import a router or the deriver."""
import json
from pathlib import Path
import sys

A, B = "default/127.0.0.1:4000", "default/127.0.0.1:4001"


def make_trace():
    events = []

    def add(op, at, expect=None, **kwargs):
        events.append({"op":op, "at_nanos":at, **kwargs, "expect":{"outcome":"ok", **(expect or {})}})

    def health(at, enabled=True, empty=False):
        add("health",at,backends=[] if empty else [
            {"address":bid.split("/",1)[1], "labels":{}, "support_redirection":enabled} for bid in (A,B)])

    def rate(at, value, ratio=1.2):
        add("config",at,toml=f"[balance.conn-count]\nmigrations-per-second = {value}\ncount-ratio-threshold = {ratio}\n")

    def restore(at, name, backend=A):
        add("open",at,session=name)
        add("rehydrate",at,{"backend":backend},session=name,backend=backend)

    def tick(at, issued=(), refuse=(), source=A, target=B):
        # Handles and effects are specified independently of any engine output.
        effects = [{"kind":"redirect", "session":sid, "operation":f"{sid}/{ordinal}",
                    "from":source, "to":target, "accepted":sid not in refuse} for sid,ordinal in issued]
        add("tick",at,{"effects":effects},refuse=list(refuse))

    def callback(at, name, ordinal, success=True):
        add("redirect_result",at,session=name,operation=f"{name}/{ordinal}",success=success)

    def close(at, *names):
        for name in names:
            add("close",at,session=name)

    def checkpoint(at, count=2):
        add("checkpoint",at,{"healthy_backend_count":count,"legal_server_versions":[""]})

    # Slow cadence, refusal, delayed failure, equality, FIFO after completion,
    # duplicate old callback during a new operation, and close before completion.
    health(0)
    rate(0,10.0)
    for i in range(6):
        restore(0,f"slow-{i}")
    tick(0,[("slow-0",1),("slow-1",1),("slow-2",1)], ["slow-0","slow-1"])
    health(50_000_000,enabled=False)
    tick(50_000_000)
    health(60_000_000)
    tick(99_999_999)
    tick(100_000_000,[("slow-3",1)])
    callback(120_000_000,"slow-2",1,False)
    tick(199_999_999)
    tick(200_000_000,[("slow-4",1)])
    callback(250_000_000,"slow-3",1)
    callback(250_000_000,"slow-4",1)
    close(300_000_000,"slow-3","slow-4")
    tick(300_000_000,[("slow-5",1)])
    callback(350_000_000,"slow-5",1,False)
    tick(2_999_999_999)
    tick(3_000_000_000,[("slow-0",2)])
    callback(3_010_000_000,"slow-0",2,False)
    tick(3_099_999_999)
    tick(3_100_000_000,[("slow-1",2)])
    callback(3_110_000_000,"slow-1",2)
    tick(3_200_000_000,[("slow-2",2)])
    callback(3_210_000_000,"slow-2",1)  # already failed; must not complete slow-2/2
    checkpoint(3_210_000_000)
    tick(3_300_000_000)
    callback(3_400_000_000,"slow-2",2)
    close(3_500_000_000,"slow-0","slow-5")
    tick(3_500_000_000,[("slow-1",3)],source=B,target=A)
    close(3_510_000_000,"slow-1")
    callback(3_520_000_000,"slow-1",3)
    callback(3_530_000_000,"slow-1",2,False)
    close(3_540_000_000,"slow-2")
    health(3_540_000_000,empty=True)
    health(3_540_000_000)
    restore(3_540_000_000,"recreated-0")
    restore(3_540_000_000,"recreated-1")
    tick(3_540_000_000,[("recreated-0",1)])  # new group does not inherit 3.5s clock
    close(3_540_000_001,"recreated-0","recreated-1")
    health(3_540_000_001,empty=True)
    checkpoint(3_540_000_001,0)

    # Refusals neither consume the one-acceptance budget nor advance cadence.
    health(40_000_000_000)
    restore(40_000_000_000,"refused-0")
    restore(40_000_000_000,"refused-1")
    tick(40_000_000_000,[("refused-0",1),("refused-1",1)], ["refused-0","refused-1"])
    restore(40_000_000_001,"fresh")
    tick(40_000_000_001,[("fresh",1)])
    close(40_000_000_002,"refused-0","refused-1","fresh")
    health(40_000_000_002,empty=True)

    # 20ms is slow; just below 20ms is fast. Exact 10ms permits one request,
    # just below 10ms permits two. The pair and budget stay fixed for the tick.
    health(50_000_000_000)
    for i in range(16):
        restore(50_000_000_000,f"batch-{i}")
    rate(50_000_000_000,50.0)
    tick(50_000_000_000,[("batch-0",1)])
    tick(50_000_000_000)
    rate(50_000_000_000,50.000003)
    tick(50_000_000_000,[("batch-1",1)])
    rate(50_000_000_000,100.0)
    tick(50_000_000_000,[("batch-2",1)])
    rate(50_000_000_000,100.00002)
    tick(50_000_000_000,[("batch-3",1),("batch-4",1)])
    rate(50_000_000_000,200.0)
    tick(50_000_000_000,[("batch-5",1),("batch-6",1)])
    close(50_000_000_001,*(f"batch-{i}" for i in range(16)))
    health(50_000_000_001,empty=True)

    # Default rate after 6/0 -> 5/1 gives a truncated 101538461538ns interval.
    health(100_000_000_000)
    rate(100_000_000_000,0.0)
    for i in range(6):
        restore(100_000_000_000,f"default-{i}")
    tick(100_000_000_000,[("default-0",1)])
    tick(201_538_461_537)
    tick(201_538_461_538,[("default-1",1)])
    close(201_538_461_539,*(f"default-{i}" for i in range(6)))
    health(201_538_461_539,empty=True)

    # Connection ratio equality is neutral, a strictly smaller threshold acts.
    health(250_000_000_000)
    rate(250_000_000_000,10.0,1.5)
    for i in range(3):
        restore(250_000_000_000,f"ratio-{i}")
    restore(250_000_000_000,"ratio-idle",B)
    tick(250_000_000_000)
    rate(250_000_000_000,10.0,1.4999)
    tick(250_000_000_000,[("ratio-0",1)])
    close(250_000_000_001,"ratio-0","ratio-1","ratio-2","ratio-idle")
    health(250_000_000_001,empty=True)
    checkpoint(250_000_000_001,0)
    return {"version":1,"id":"connection-cadence", "config":{"policy":"connection","selection":"random","rule":"","clock_origin_nanos":0},
            "provenance":{"kind":"synthetic","description":"Public connection timing and callback scenarios; not a qualifying recording"},"events":events}


if __name__ == "__main__":
    Path(sys.argv[1]).write_text(json.dumps(make_trace(),indent=2) + "\n")
