#!/usr/bin/env python3
# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Compile actual Group.Balance hook faults in an isolated source tree."""
from pathlib import Path
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[4]
GROUP = 'pkg/balance/router/group.go'
HOOK = 'pkg/balance/router/balance_observation.go'
NATIVE = 'pkg/balance/factor/native_capture.go'
OBS = 'pkg/balance/router/observation.go'
CASES = [
 ('standalone-at-allocation', 'ParentOwnsChildAtRead', 'BALANCE_HOOK_OWNED_AT_ALLOCATION', NATIVE, 'e = caller.BeginEvaluation()', 'e = c.owner.BeginEvaluation()'),
 ('double-native-publication', 'ActualScan/quota', 'BALANCE_HOOK_OWNER_VALID', GROUP, 'g.balanceCaller.CompleteEvaluation(evaluation)', 'g.balanceCaller.CompleteEvaluation(evaluation)\n g.observation.PublishEvaluation(evaluation)'),
 ('cleanup-normal-only', 'UnsealedChildBeforeUnlock', 'BALANCE_HOOK_INVALID_BEFORE_UNLOCK', GROUP, 'defer g.endBalanceObservation(caller)', '_ = caller'),
 ('cleanup-after-unlock', 'UnsealedChildBeforeUnlock', 'BALANCE_HOOK_INVALID_BEFORE_UNLOCK', GROUP, 'defer g.Unlock()\n\tcaller := g.beginBalanceObservation()\n\tdefer g.endBalanceObservation(caller)', 'caller := g.beginBalanceObservation()\n defer func() { g.Unlock(); time.Sleep(time.Millisecond); g.endBalanceObservation(caller) }()'),
 ('unsealed-child-forgotten', 'UnsealedChildBeforeUnlock', 'BALANCE_HOOK_UNSEALED_RELEASE_BEFORE_UNLOCK', 'pkg/balance/observation/caller.go', 'c.evaluations++', '_ = c.evaluations'),
 ('parent-released-at-admission', 'ActualScan/quota', 'BALANCE_HOOK_PARENT_UNTIL_WRITER', HOOK, 'g.observation.PublishCaller(c)', 'g.observation.PublishCaller(c)\n c.Release()'),
 ('context-not-captured', 'ActualScan/cancel', 'BALANCE_HOOK_CONTEXT_READ_ONCE', HOOK, 'c.CaptureBalanceContext(err != nil)', '_ = c'),
 ('nil-after-context', 'ActualScan/nil', 'BALANCE_HOOK_NO_CONTEXT_AFTER_NIL', GROUP, 'ele != nil && g.captureBalanceContext(ctx.Err()) && i < count', 'g.captureBalanceContext(ctx.Err()) && ele != nil && i < count'),
 ('quota-before-context', 'ActualScan/quota', 'BALANCE_HOOK_CONTEXT_BEFORE_QUOTA', GROUP, 'ele != nil && g.captureBalanceContext(ctx.Err()) && i < count', 'ele != nil && i < count && g.captureBalanceContext(ctx.Err())'),
 ('skip-closing-visits', 'ActualScan/quota', 'BALANCE_HOOK_OWNER_VALID', GROUP, 'if caller != nil {\n\t\t\tcaller.CaptureBalanceVisit(conn.observationID)', 'if caller != nil && !conn.forceClosing {\n\t\t\tcaller.CaptureBalanceVisit(conn.observationID)'),
 ('callback-false-is-true', 'ActualScan/refused', 'BALANCE_HOOK_ACTUAL_FALSE_RESULT', GROUP, 'callback := observation.BalanceCallbackRefused', 'callback := observation.BalanceCallbackAccepted'),
 ('backstop-skip-is-false', 'KeyspaceReads/true', 'BALANCE_HOOK_KEYSPACE_VALID', GROUP, 'fromKeyspace, toKeyspace, observation.BalanceCallbackSkipped)', 'fromKeyspace, toKeyspace, observation.BalanceCallbackRefused)'),
 ('direct-read-order-swapped', 'KeyspaceReads/true', 'BALANCE_HOOK_ORIGINAL_DIRECT_FROM', OBS, 'CaptureBalanceRedirect(fromKeyspace, toKeyspace, callback, batch)', 'CaptureBalanceRedirect(toKeyspace, fromKeyspace, callback, batch)'),
 ('capacity-truncates-real-loop', 'CapacityDoesNotTruncateScan', 'BALANCE_HOOK_CAPACITY_CONTINUES_GO', GROUP, 'caller.CaptureBalanceVisit(conn.observationID)', 'if !caller.CaptureBalanceVisit(conn.observationID) { break }'),
]

def main():
    originals = {path: (ROOT/path).read_bytes() for *_, path, old, new in CASES}
    evidence = Path(os.environ.get('CP_ROUTE_BALANCE_HOOK_EVIDENCE') or tempfile.mkdtemp(prefix='balance-hook-evidence-')).resolve()
    evidence.mkdir(parents=True, exist_ok=True)
    (evidence/'source-hashes.json').write_text(json.dumps({path:hashlib.sha256(source).hexdigest() for path,source in originals.items()},indent=2)+'\n')
    rows = []
    with tempfile.TemporaryDirectory(prefix='balance-hooks-') as temporary:
        temp = Path(temporary)
        repo = temp/'repo'
        shutil.copytree(ROOT, repo, ignore=shutil.ignore_patterns('.git','target','bin','artifacts','__pycache__'))
        env = dict(os.environ)
        env.pop('CP_ROUTE_BALANCE_HOOK_FRAMES', None)
        binary = temp/'hooks.test'
        def run(name, args):
            started = time.monotonic()
            p = subprocess.run(args, cwd=repo, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=180)
            (evidence/(name+'.log')).write_text(p.stdout)
            rows.append(dict(name=name,command=args,rc=p.returncode,seconds=round(time.monotonic()-started,3),sha256=hashlib.sha256(p.stdout.encode()).hexdigest()))
            (evidence/'results.json').write_text(json.dumps(rows,indent=2)+'\n')
            return p
        def compile(name):
            p = run(name, ['go','test','-c','-o',str(binary),'./pkg/balance/router'])
            if p.returncode:
                raise RuntimeError('compile failure is not a kill: '+name+'\n'+p.stdout)
            rows[-1]['binary_sha256'] = hashlib.sha256(binary.read_bytes()).hexdigest()
            rows[-1]['binary_mtime_ns'] = binary.stat().st_mtime_ns
            (evidence/'results.json').write_text(json.dumps(rows,indent=2)+'\n')
        compile('baseline-compile')
        p = run('baseline', [str(binary),'-test.run=^TestBalanceHooks','-test.timeout=30s','-test.count=1'])
        if p.returncode:
            raise RuntimeError('baseline failed\n'+p.stdout)
        for name, test, marker, path, old, new in CASES:
            try:
                source = (repo/path).read_text()
                if source.count(old) != 1:
                    raise RuntimeError('stale/ambiguous anchor: '+name)
                (repo/path).write_text(source.replace(old,new,1))
                compile(name+'-compile')
                p = run(name, [str(binary),'-test.run=^TestBalanceHooks'+test+'$','-test.timeout=15s','-test.count=1'])
                if p.returncode == 0 or marker not in p.stdout:
                    raise RuntimeError('survived or failed outside '+marker+'\n'+p.stdout)
                print('BALANCE_HOOK_MUTATION killed: '+name, flush=True)
            finally:
                for path, source in originals.items():
                    (repo/path).write_bytes(source)
        compile('restored-compile')
        p = run('restored', [str(binary),'-test.run=^TestBalanceHooks','-test.timeout=30s','-test.count=1'])
        if p.returncode:
            raise RuntimeError('restored baseline failed\n'+p.stdout)
    if any((ROOT/path).read_bytes()!=source for path,source in originals.items()):
        raise RuntimeError('source worktree changed during mutations')
    print(f'BALANCE_HOOK_MUTATIONS {len(CASES)}/{len(CASES)} compiled faults killed; restored baseline passed; evidence={evidence}', flush=True)

if __name__ == '__main__':
    main()
