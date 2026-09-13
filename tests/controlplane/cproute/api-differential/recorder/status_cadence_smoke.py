# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Written Connection status-migration scenarios using only public events."""
import json
from pathlib import Path
import sys

A, B = "default/127.0.0.1:4000", "default/127.0.0.1:4001"


def make_trace():
    events = []

    def add(op, at, expect=None, **values):
        events.append({"op":op,"at_nanos":at,**values,"expect":{"outcome":"ok",**(expect or {})}})

    def health(at, a=True, b=True, support=True, empty=False):
        add("health",at,backends=[] if empty else [
            {"address":bid.split("/",1)[1],"labels":{},"healthy":healthy,"support_redirection":support}
            for bid,healthy in ((A,a),(B,b))])

    def restore(at, prefix, count, backend=A):
        for i in range(count):
            sid=f"{prefix}-{i}"
            add("open",at,session=sid)
            add("rehydrate",at,{"backend":backend},session=sid,backend=backend)

    def tick(at, sid=None, source=A, target=B):
        effects=[] if sid is None else [{"kind":"redirect","session":sid,"operation":sid+"/1",
                                        "from":source,"to":target,"accepted":True}]
        add("tick",at,{"effects":effects})

    def close(at, *sessions):
        for sid in sessions:
            add("close",at,session=sid)

    def config(at, value):
        add("config",at,toml=value)

    # Status outranks connection count. Its initial rate is retained while the
    # source stays unhealthy, including count decreases and support pauses.
    health(0);restore(0,"retained",6);health(0,a=False)
    tick(0,"retained-0");close(100_000_000,"retained-0")
    tick(833_333_332);tick(833_333_333,"retained-1");close(900_000_000,"retained-1")
    tick(1_666_666_665);tick(1_666_666_666,"retained-2")
    add("redirect_result",1_700_000_000,session="retained-2",operation="retained-2/1",success=False)
    health(2_000_000_000,a=False,support=False);tick(2_500_000_000)
    health(2_500_000_000,a=False);tick(2_500_000_000,"retained-3")
    # Recovery clears status history before the next loss, even with no tick.
    health(3_000_000_000);health(3_100_000_000,a=False)
    tick(3_100_000_000);close(3_200_000_000,"retained-3")
    tick(4_166_666_665);tick(4_166_666_666,"retained-4")
    close(4_200_000_000,"retained-2","retained-4","retained-5");health(4_200_000_000,empty=True)

    # All-unhealthy is unroutable; after target recovery status can move from a
    # source with fewer connections than the healthy destination.
    health(10_000_000_000);restore(10_000_000_000,"unhealthy",2)
    restore(10_000_000_000,"healthy-busy",4,B);health(10_000_000_000,a=False,b=False)
    tick(10_000_000_000);health(11_000_000_000,a=False);tick(11_000_000_000,"unhealthy-0")
    close(11_100_000_000,"unhealthy-0","unhealthy-1",*[f"healthy-busy-{i}" for i in range(4)])
    health(11_100_000_000,empty=True)

    # An intervening healthy-only Route scoring call prunes an unaccessed status
    # entry strictly after 60 seconds. Tick accesses the source before pruning,
    # so just waiting and ticking would not test this expiry boundary.
    for prefix,start,extra in (("equal",20_000_000_000,0),("expired",100_000_000_000,1)):
        health(start);restore(start,prefix,6);health(start,a=False)
        tick(start,prefix+"-0")
        close(start+1,prefix+"-0",prefix+"-1",prefix+"-2",prefix+"-3")
        now=start+60_000_000_000+extra
        query=prefix+"-query"
        add("open",now,session=query)
        add("next",now,{"backend":B},session=query)
        add("finish",now,session=query,success=False)
        close(now,query)
        tick(now,prefix+"-4")
        if extra:
            tick(now+833_333_333)
            tick(now+2_499_999_999)
            tick(now+2_500_000_000,prefix+"-5")
            end=now+2_500_000_001
        else:
            tick(now+833_333_332)
            tick(now+833_333_333,prefix+"-5")
            end=now+833_333_334
        close(end,prefix+"-4",prefix+"-5");health(end,empty=True)

    # Failover guard scoring first clears healthy snapshots, then evaluates the
    # proposed mask. Reapplying the same list therefore refreshes the status rate
    # from current reservations while preserving the failover deadline itself.
    start=200_000_000_000
    health(start);restore(start,"masked",6);restore(start,"destination",2,B)
    mask='[proxy]\nfail-backend-list=["127.0.0.1:4000"]\n'
    config(start,mask);tick(start,"masked-0")
    close(start+1,"masked-0","masked-1","masked-2")
    config(start+100_000_000,mask)
    tick(start+833_333_333);tick(start+1_666_666_666,"masked-3")
    config(start+1_700_000_000,'[proxy]\nfail-backend-list=[]\n')
    config(start+1_800_000_000,'[proxy]\nfail-backend-list=["127.0.0.1:4000","127.0.0.1:4001"]\n')
    tick(start+1_800_000_000)  # all-member mask is ignored
    config(start+1_900_000_000,mask)
    tick(start+4_166_666_665);tick(start+4_166_666_666,"masked-4")
    config(start+4_200_000_000,'[balance.status]\nmigrations-per-second=10.0\n')
    tick(start+4_266_666_665);tick(start+4_266_666_666,"masked-5")
    close(start+4_300_000_000,"masked-3","masked-4","masked-5","destination-0","destination-1")
    health(start+4_300_000_000,empty=True)
    add("checkpoint",start+4_300_000_000,{"healthy_backend_count":0,"legal_server_versions":[""]})
    # A drain deadline still closes the physical source of an accepted redirect
    # whose completion is delayed. The close consumes the next public ordinal.
    start=250_000_000_000
    health(start);restore(start,"deadline",1)
    config(start,'[proxy]\nfail-backend-list=["127.0.0.1:4000"]\nfailover-timeout=1\n')
    tick(start+999_999_999,"deadline-0")
    add("tick",start+1_000_000_000,{"effects":[{"kind":"force_close","session":"deadline-0",
        "operation":"deadline-0/2","from":A,"to":"","accepted":True}]})
    close(start+1_000_000_001,"deadline-0")
    add("redirect_result",start+1_000_000_002,session="deadline-0",operation="deadline-0/1",success=True)
    health(start+1_000_000_003,empty=True)
    add("checkpoint",start+1_000_000_003,{"healthy_backend_count":0,"legal_server_versions":[""]})
    return {"version":1,"id":"connection-status-cadence",
            "config":{"policy":"connection","selection":"random","rule":"","clock_origin_nanos":0},
            "provenance":{"kind":"synthetic","description":"Status migration and expiry inputs; not a qualifying recording"},
            "events":events}


if __name__ == "__main__":
    Path(sys.argv[1]).write_text(json.dumps(make_trace(),indent=2)+"\n")
