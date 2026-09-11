#!/usr/bin/env python3
# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Compile Group-local Route hook faults; retain every attempt as CI evidence."""
from pathlib import Path
import hashlib
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[4]
GROUP = 'pkg/balance/router/group.go'
HOOK = 'pkg/balance/router/route_observation.go'
NATIVE = 'pkg/balance/factor/native_capture.go'
OBS = 'pkg/balance/router/observation.go'
MEMBER = 'pkg/balance/observation/caller_route.go'
CASES = [
 ('standalone-at-allocation', 'router', 'TestRouteHooksParentOwnsChildAtRead', 'ROUTE_HOOK_OWNED_AT_ALLOCATION', NATIVE, 'e = caller.BeginEvaluation()', 'e = c.owner.BeginEvaluation()'),
 ('double-native-publication', 'router', 'TestRouteHooksActualOutcomes/selected', 'ROUTE_HOOK_OWNER_VALID', GROUP, 'g.routeCaller.CompleteEvaluation(evaluation)', 'g.routeCaller.CompleteEvaluation(evaluation)\n g.observation.PublishEvaluation(evaluation)'),
 ('cleanup-normal-only', 'router', 'TestRouteHooksUnsealedChildBeforeUnlock', 'ROUTE_HOOK_INVALID_BEFORE_UNLOCK', GROUP, 'defer g.endRouteObservation(caller)', '_ = caller'),
 ('cleanup-after-unlock', 'router', 'TestRouteHooksUnsealedChildBeforeUnlock', 'ROUTE_HOOK_INVALID_BEFORE_UNLOCK', GROUP, 'defer g.Unlock()\n\tcaller := parent\n\tif caller == nil {\n\t\tcaller = g.beginRouteObservation()\n\t} else {\n\t\tg.routeCaller = caller\n\t}\n\tdefer g.endRouteObservation(caller)', 'caller := parent\n\tif caller == nil {\n\t\tcaller = g.beginRouteObservation()\n\t} else {\n\t\tg.routeCaller = caller\n\t}\n defer func() { g.Unlock(); time.Sleep(time.Millisecond); g.endRouteObservation(caller) }()'),
 ('unsealed-child-forgotten', 'router', 'TestRouteHooksUnsealedChildBeforeUnlock', 'ROUTE_HOOK_UNSEALED_RELEASE_BEFORE_UNLOCK', 'pkg/balance/observation/caller.go', 'c.evaluations++', '_ = c.evaluations'),
 ('parent-released-at-admission', 'router', 'TestRouteHooksActualOutcomes/selected', 'ROUTE_HOOK_PARENT_UNTIL_WRITER', HOOK, 'g.observation.PublishCaller(c)', 'g.observation.PublishCaller(c)\n c.Release()'),
 ('members-omitted', 'router', 'TestRouteHooksActualOutcomes/selected', 'ROUTE_HOOK_FULL_INVENTORY', GROUP, 'caller.CaptureRouteMember(backend.observationID)', '_ = backend.observationID'),
 ('health-inverted', 'router', 'TestRouteHooksActualOutcomes/unhealthy', 'ROUTE_HOOK_ACTUAL_HEALTH', GROUP, 'caller.CaptureRouteHealthy(backend.observationID, healthy)', 'caller.CaptureRouteHealthy(backend.observationID, !healthy)'),
 ('backend-id-read-omitted', 'router', 'TestRouteHooksGetterOrderAndCopies', 'ROUTE_HOOK_ACTUAL_READ_COUNT', GROUP, 'caller.CaptureRouteBackendID(backend.observationID, backendID)', '_ = backendID'),
 ('backend-id-hoisted', 'router', 'TestRouteHooksGetterOrderAndCopies', 'ROUTE_HOOK_EXCLUSION_SHORT_CIRCUIT', GROUP, 'for index, e := range excluded {\n\t\t\tbackendID := backend.ID()', 'backendID := backend.ID()\n for index, e := range excluded {'),
 ('excluded-id-read-twice', 'router', 'TestRouteHooksGetterOrderAndCopies', 'ROUTE_HOOK_ID_READ_ONCE', GROUP, 'excludedID := e.ID()', 'excludedID := e.ID(); _ = e.ID()'),
 ('empty-invents-native', 'router', 'TestRouteHooksActualOutcomes/empty', 'ROUTE_HOOK_EMPTY_NO_NATIVE', GROUP, 'if len(g.backends) == 0 {\n\t\tg.observeNoRoute(selection)', 'if len(g.backends) == 0 {\n g.routePolicy(nil, caller); g.publishPolicyObservationLocked()\n\t\tg.observeNoRoute(selection)'),
 ('filtered-empty-skips-native', 'router', 'TestRouteHooksActualOutcomes/excluded', 'ROUTE_HOOK_FILTERED_HAS_NATIVE', HOOK, 'func (g *Group) routePolicy(backends []policy.BackendCtx, c *observation.Caller) policy.BackendCtx {', 'func (g *Group) routePolicy(backends []policy.BackendCtx, c *observation.Caller) policy.BackendCtx {\n if len(backends) == 0 { return nil }'),
 ('reservation-batch-escapes', 'router', 'TestRouteHooksActualOutcomes/selected', 'ROUTE_HOOK_ONE_PARENT', OBS, 'g.routeCaller.AppendBatch(batch)', 'g.observation.Emit(batch)'),
 ('rejection-batch-escapes', 'router', 'TestRouteHooksActualOutcomes/empty', 'ROUTE_HOOK_ONE_PARENT', OBS, 'g.routeCaller.AppendBatch(observation.Batch{EventCount: 1', 'g.observation.Emit(observation.Batch{EventCount: 1'),
 ('wrong-reservation-operation', 'router', 'TestRouteHooksActualOutcomes/selected', 'ROUTE_HOOK_ORIGINAL_OPERATION', HOOK, 'account, operation = backend.observationID, s.operation', 'account, operation = backend.observationID, s.operation+1'),
 ('capacity-truncates-real-loop', 'router', 'TestRouteHooksCapacityContinuesProduction', 'ROUTE_HOOK_CAPACITY_CONTINUES_GO', GROUP, 'caller.CaptureRouteMember(backend.observationID)', 'if !caller.CaptureRouteMember(backend.observationID) { break }'),
 ('existing-factory-activated', 'router', 'TestRouteHooksExistingFactoryStaysNative', 'ROUTE_HOOK_FACTORY_FENCE', GROUP, 'return newGroupCapture(values, bpCreator, matchType, lg, owner, native, false)', 'return newGroupRouteCaptured(values, bpCreator, matchType, lg, owner, native)'),
 ('member-after-child-allocation', 'observation', 'TestGroupRouteIncrementalMembers/evaluation', 'ROUTE_MEMBER_BEFORE_CHILD_ALLOCATION', MEMBER, 'account == 0 || c.evaluations != 0 || c.batches != 0 || c.children != 0', 'account == 0 || false || c.batches != 0 || c.children != 0'),
 ('duplicate-member-accepted', 'observation', 'TestGroupRouteIncrementalMembers/duplicate', 'ROUTE_MEMBER_UNIQUE', MEMBER, 'if previous == account {', 'if false && previous == account {'),
 ('member-plus-one-accepted', 'observation', 'TestGroupRouteIncrementalMembers/bound', 'ROUTE_MEMBER_BOUND_PLUS_ONE', MEMBER, 'if r.MemberCount == MaxCallerGroups {\n\t\tc.Fail(Capacity)\n\t\treturn false\n\t}', 'if r.MemberCount == MaxCallerGroups { return true }'),
 ('zero-member-accepted', 'observation', 'TestGroupRouteIncrementalMembers/zero', 'ROUTE_MEMBER_NONZERO', MEMBER, 'account == 0 || c.evaluations != 0 || c.batches != 0 || c.children != 0', 'false || c.evaluations != 0 || c.batches != 0 || c.children != 0'),
]


def check_anchors():
    for name, _, _, _, path, old, _ in CASES:
        if (ROOT/path).read_text().count(old) != 1:
            raise RuntimeError('stale/ambiguous anchor: '+name)
    print(f'{len(CASES)} route-hook fault anchors unique at their sites')


def main():
    check_anchors()
    if '--check-anchors' in sys.argv:
        return
    originals = {path: (ROOT/path).read_bytes() for *_, path, old, new in CASES}
    evidence = Path(os.environ.get('CP_ROUTE_ROUTE_HOOK_EVIDENCE') or tempfile.mkdtemp(prefix='route-hook-evidence-')).resolve()
    evidence.mkdir(parents=True, exist_ok=True)
    (evidence/'source-hashes.json').write_text(json.dumps({path: hashlib.sha256(source).hexdigest() for path, source in originals.items()}, indent=2)+'\n')
    rows = []
    with tempfile.TemporaryDirectory(prefix='route-hooks-') as temporary:
        temp = Path(temporary)
        repo = temp/'repo'
        shutil.copytree(ROOT, repo, ignore=shutil.ignore_patterns('.git', 'target', 'bin', 'artifacts', '__pycache__'))
        env = dict(os.environ)
        env.pop('CP_ROUTE_ROUTE_HOOK_FRAMES', None)
        binaries = {package: temp/(package+'.test') for package in ['router', 'observation']}
        def save():
            (evidence/'results.json').write_text(json.dumps(rows, indent=2)+'\n')
        def run(name, args):
            started = time.monotonic()
            child = subprocess.Popen(args, cwd=repo, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)
            timed_out = False
            try:
                output, _ = child.communicate(timeout=180)
            except subprocess.TimeoutExpired:
                timed_out = True
                os.killpg(child.pid, signal.SIGTERM)
                try:
                    output, _ = child.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(child.pid, signal.SIGKILL)
                    output, _ = child.communicate()
            (evidence/(name+'.log')).write_text(output)
            rows.append(dict(name=name, command=args, rc=child.returncode, timeout=timed_out, seconds=round(time.monotonic()-started, 3), sha256=hashlib.sha256(output.encode()).hexdigest()))
            save()
            if timed_out:
                raise RuntimeError('timeout is not a mutation kill: '+name)
            return child.returncode, output
        def compile(name, package):
            binary = binaries[package]
            rc, output = run(name, ['go', 'test', '-c', '-o', str(binary), './pkg/balance/'+package])
            if rc:
                raise RuntimeError('compile failure is not a kill: '+name+'\n'+output)
            rows[-1]['binary_sha256'] = hashlib.sha256(binary.read_bytes()).hexdigest()
            rows[-1]['binary_mtime_ns'] = binary.stat().st_mtime_ns
            save()
        def baseline(prefix):
            for package, test in [('router', '^TestRouteHooks'), ('observation', '^TestGroupRoute')]:
                compile(prefix+'-'+package+'-compile', package)
                rc, output = run(prefix+'-'+package, [str(binaries[package]), '-test.run='+test, '-test.timeout=30s', '-test.count=1'])
                if rc:
                    raise RuntimeError(prefix+' baseline failed\n'+output)
        baseline('baseline')
        for name, package, test, marker, path, old, new in CASES:
            try:
                source = (repo/path).read_text()
                if source.count(old) != 1:
                    raise RuntimeError('stale/ambiguous anchor: '+name)
                (repo/path).write_text(source.replace(old, new, 1))
                compile(name+'-compile', package)
                rc, output = run(name, [str(binaries[package]), '-test.run=^'+test+'$', '-test.timeout=15s', '-test.count=1'])
                if rc == 0 or marker not in output:
                    raise RuntimeError('survived or failed outside '+marker+'\n'+output)
                print('ROUTE_HOOK_MUTATION killed: '+name, flush=True)
            finally:
                for restored_path, source in originals.items():
                    (repo/restored_path).write_bytes(source)
        baseline('restored')
    if any((ROOT/path).read_bytes() != source for path, source in originals.items()):
        raise RuntimeError('source worktree changed during mutations')
    print(f'ROUTE_HOOK_MUTATIONS {len(CASES)}/{len(CASES)} compiled faults killed; restored baseline passed; evidence={evidence}', flush=True)


if __name__ == '__main__':
    main()
