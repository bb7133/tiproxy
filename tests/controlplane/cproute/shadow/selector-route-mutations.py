#!/usr/bin/env python3
# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Compile each derived-result fault and replay the unchanged actual Go stream."""
from pathlib import Path
import hashlib
import json
import os
import signal
import subprocess
import time

ROOT = Path(__file__).resolve().parents[4]
STATE_SOURCE = 'rust/crates/control-router/src/shadow/live/caller/selector_state.rs'
SOURCE = 'rust/crates/control-router/src/shadow/live/caller/route.rs'
CASES = [
    ('wrong-account', 'backend: selected,', 'backend: selected + 1,', 'SELECTOR_ROUTE_RETURN_WITNESS'),
    ('wrong-group', 'group: r.group,', 'group: 0,', 'SELECTOR_ROUTE_TRANSITION'),
    ('wrong-operation', 'operation,', 'operation: operation + 1,', 'SELECTOR_ROUTE_FINISH_BINDING'),
    ('missing-binding', 'binding: (selected != 0).then_some(Binding {', 'binding: false.then_some(Binding {', 'SELECTOR_ROUTE_TRANSITION'),
]


def main():
    evidence = Path(os.environ['CP_ROUTE_SELECTOR_ROUTE_EVIDENCE']).resolve()
    evidence.mkdir(parents=True, exist_ok=True)
    paths = [SOURCE, STATE_SOURCE,
             'pkg/balance/observation/caller_selection.go',
             'pkg/balance/router/selector_observation.go',
             'pkg/controlbridge/shadow/caller_selection_codec.go',
             'rust/crates/control-router/src/shadow/live/caller.rs',
             'rust/crates/control-router/src/shadow/live/caller/selection.rs',
             'rust/crates/legacy-router-shadow/src/caller/selection_wire.rs', 'pkg/balance/router/selector_route_test.go',
             'pkg/balance/router/backend_selector.go', 'pkg/balance/router/router_score.go',
             'rust/crates/legacy-router-shadow/examples/selector_route_check.rs',
             'rust/crates/legacy-router-shadow/examples/support/route_prefix.rs']
    originals = {p: (ROOT / p).read_bytes() for p in paths}
    (evidence / 'source-hashes.json').write_text(json.dumps({p: hashlib.sha256(b).hexdigest() for p, b in originals.items()}, indent=2) + '\n')
    rows = []

    def save():
        (evidence / 'results.json').write_text(json.dumps(rows, indent=2) + '\n')

    def run(name, args, env=None):
        start = time.monotonic()
        proc = subprocess.Popen(args, cwd=ROOT, env=env, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True, start_new_session=True)
        timeout = False
        try:
            output, _ = proc.communicate(timeout=180)
        except subprocess.TimeoutExpired:
            timeout = True
            os.killpg(proc.pid, signal.SIGTERM)
            try:
                output, _ = proc.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, signal.SIGKILL)
                output, _ = proc.communicate()
        (evidence / (name + '.log')).write_text(output)
        rows.append(dict(name=name, command=args, rc=proc.returncode, timeout=timeout,
                         seconds=round(time.monotonic() - start, 3),
                         sha256=hashlib.sha256(output.encode()).hexdigest()))
        save()
        if timeout:
            raise RuntimeError('timeout is not a detected fault: ' + name)
        return proc.returncode, output

    def binary_identity(binary):
        rows[-1]['binary_sha256'] = hashlib.sha256(binary.read_bytes()).hexdigest()
        rows[-1]['binary_mtime_ns'] = binary.stat().st_mtime_ns
        save()

    go_binary = evidence / 'selector-route.test'
    rc, output = run('go-compile', ['go', 'test', '-c', '-o', str(go_binary), './pkg/balance/router'])
    if rc:
        raise RuntimeError('Go compilation failed: ' + output)
    binary_identity(go_binary)
    fixture = evidence / 'selector-route.jsonl'
    env = dict(os.environ, CP_ROUTE_SELECTOR_ROUTE_FRAMES=str(fixture))
    rc, output = run('go-capture', [str(go_binary), '-test.run=^TestSelectorRouteActualFrames$', '-test.count=1', '-test.timeout=30s'], env)
    if rc or 'SELECTOR_ROUTE_ACTUAL_STREAM next=6 attempts=9 successes=4 rejected=2' not in output:
        raise RuntimeError('actual Go capture failed: ' + output)
    bound_fixture = evidence / 'selector-boundary.jsonl'
    env = dict(os.environ, CP_ROUTE_SELECTOR_BOUNDARY_FRAMES=str(bound_fixture))
    rc, output = run('go-boundary-capture', [str(go_binary), '-test.run=^TestSelectorBoundariesActualFrames$', '-test.count=1', '-test.timeout=30s'], env)
    if rc or 'SELECTOR_ROUTE_ACTUAL_STREAM next=6 attempts=9 successes=4 rejected=2' not in output:
        raise RuntimeError('actual selector boundary capture failed: ' + output)
    # Keep executable identity, but do not upload the large reproducible binary.
    go_binary.unlink()
    binary = ROOT / 'rust/target/debug/examples/selector_route_check'

    def attempt(name, marker=None, bound_marker=None):
        rc, output = run(name + '-compile', ['cargo', 'build', '--locked', '--manifest-path', 'rust/Cargo.toml', '-p', 'legacy-router-shadow', '--example', 'selector_route_check'])
        if rc:
            raise RuntimeError('compilation is not a detected fault: ' + name + '\n' + output)
        binary_identity(binary)
        rc, output = run(name + '-compare', [str(binary), str(fixture)])
        if marker is None:
            if rc or 'SELECTOR_ROUTE_INDEPENDENT next=6 attempts=9 successes=4 rejected=2' not in output or output.count('SELECTOR_ROUTE_CORRUPTION ') != 4:
                raise RuntimeError('baseline failed: ' + name + '\n' + output)
        elif rc == 0 or marker not in output:
            raise RuntimeError('survived/wrong failure: ' + name + '\n' + output)
        rc, output = run(name + '-boundary-compare', [str(binary), str(bound_fixture)])
        if bound_marker is None:
            if rc or 'SELECTOR_STATE_RETAINED boundaries=13' not in output or output.count('SELECTOR_ROUTE_CORRUPTION ') != 4:
                raise RuntimeError('retained selector baseline failed: ' + name + '\n' + output)
        elif rc == 0 or bound_marker not in output:
            raise RuntimeError('retained selector survived/wrong failure: ' + name + '\n' + output)

    attempt('baseline')
    for name, old, new, marker in CASES:
        try:
            text = originals[SOURCE].decode()
            offset = text.index('        Ok(DerivedResult {')
            prefix, tail = text[:offset], text[offset:]
            if tail.count(old) != 1:
                raise RuntimeError('stale fault anchor: ' + name)
            (ROOT / SOURCE).write_text(prefix + tail.replace(old, new, 1))
            attempt(name, marker, 'SELECTOR_ROUTE_FINISH_BINDING' if name == 'wrong-operation' else 'SELECTOR_ROUTE_GROUP_COMPARISON')
            print('SELECTOR_ROUTE_MUTATION detected: ' + name, flush=True)
        finally:
            (ROOT / SOURCE).write_bytes(originals[SOURCE])
    for name, old, new, marker in [
        ('selector-ordinal', '.attempt(next, ordinal, excluded, derived)', '.attempt(next, ordinal + 1, excluded, derived)', 'SELECTOR_ROUTE_GROUP_COMPARISON'),
        ('selector-close', 'stored.closed = true;', 'stored.closed = false;', 'SELECTOR_STATE_UNSETTLED'),
    ]:
        try:
            text = originals[STATE_SOURCE].decode()
            if text.count(old) != 1:
                raise RuntimeError('stale selector fault anchor: ' + name)
            (ROOT / STATE_SOURCE).write_text(text.replace(old, new, 1))
            attempt(name, None, marker)
            print('SELECTOR_ROUTE_MUTATION detected: ' + name, flush=True)
        finally:
            (ROOT / STATE_SOURCE).write_bytes(originals[STATE_SOURCE])
    attempt('restored')
    if any((ROOT / p).read_bytes() != data for p, data in originals.items()):
        raise RuntimeError('source not restored')
    print('SELECTOR_ROUTE_MUTATIONS 6/6 compiled faults detected; baseline/restored and 4 witness corruptions passed', flush=True)


if __name__ == '__main__':
    main()
