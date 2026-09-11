#!/usr/bin/env python3
# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Check every native evidence runner's source anchors without compiling."""
from pathlib import Path
import runpy

ROOT = Path(__file__).resolve().parents[4]
RUNNERS = ['native', 'balance-hooks', 'route-hooks', 'selector-core',
           'selector-route', 'metadata', 'router-attempt']


def check_edits(name, edits):
    # Apply successive edits in memory, just as the compiled runner applies
    # them to its private source copy. Never modify the working tree.
    staged = {}
    for path, old, new, start, end in edits:
        source = staged.get(path)
        if source is None:
            source = (ROOT/path).read_text()
        begin = source.index(start) if start else 0
        finish = source.index(end, begin + len(start or '')) if end else len(source)
        section = source[begin:finish]
        if section.count(old) != 1:
            raise RuntimeError('stale/ambiguous anchor: ' + name + ' in ' + path)
        staged[path] = source[:begin] + section.replace(old, new, 1) + source[finish:]


def main():
    for name in RUNNERS:
        module = runpy.run_path(str(Path(__file__).with_name(name + '-mutations.py')))
        if 'check_anchors' in module:
            module['check_anchors']()
            continue
        # Older runners have no standalone checker; their declared mutation
        # tables remain the source of truth for the edits and source paths.
        cases = module['runner'].CASES if name == 'native' else module['CASES']
        checks = 0
        for case in cases:
            if name == 'native':
                edits = case[-1]
            elif name == 'metadata':
                edits = [(*case[1:4], None, None)]
            elif name == 'balance-hooks':
                edits = [(*case[-3:], None, None)]
            else:
                raise RuntimeError('missing anchor adapter: ' + name)
            check_edits(name + '/' + case[0], edits)
            checks += len(edits)
        print(f'{name}: {len(cases)} faults / {checks} edit anchors checked')
    # The sustained timing overlay is also a source edit in native-run.sh.
    check_edits('native timing overlay', [(
        'pkg/balance/router/group.go', 'g.policy.(*factor.FactorBasedBalance)',
        'g.policy.(interface { TakeObservation() *observation.Evaluation })', None, None)])
    print(f'NATIVE_ANCHORS {len(RUNNERS)} mutation runners and timing overlay passed')


if __name__ == '__main__':
    main()
