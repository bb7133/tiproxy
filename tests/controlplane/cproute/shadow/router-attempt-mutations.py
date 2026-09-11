#!/usr/bin/env python3
# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Actual four-router streams with compiled independent-comparison faults."""
from collections import Counter
from pathlib import Path
import hashlib
import json
import os
import re
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[4]
SOURCE = 'rust/crates/control-router/src/shadow/live/caller/router_route.rs'
SCENARIOS = ['all', 'cidr', 'proxy', 'port']
# The unmodified real stream must fail before the diagnostic corruptions run.
# (name, exact old/new source, affected scenarios, first domain status)
CASES = [
    ('invert-match', 'let matches = metadata', 'let matches = !metadata', ['all', 'cidr', 'proxy'], 'Witness'),
    ('reuse-first-address', 'let address = read.address.as_deref();',
     'let address = p.reads[0].address.as_deref();', ['cidr', 'proxy'], 'Witness'),
    ('reverse-inventory', 'metadata.known_groups()?.as_slice() != p.groups',
     'metadata.known_groups()?.as_slice().iter().rev().copied().ne(p.groups.iter().copied())', ['cidr', 'proxy', 'port'], 'Witness'),
    ('erase-listener', 'let listener = p.listener.as_deref().ok_or(InvalidReason::Witness)?;',
     'let listener = "";', ['port'], 'Witness'),
    ('wrapped-as-sentinel', 'return Ok((0, observer_error));',
     'return Ok((0, ErrorClass::NoBackend));', ['all'], 'Witness'),
    ('wrong-selector-attempt', 'p.attempt,\n                        &p.excluded,',
     '3 - p.attempt,\n                        &p.excluded,', SCENARIOS, 'Sequence'),
]


def check_anchors():
    original = (ROOT / SOURCE).read_text()
    for name, old, _, _, _ in CASES:
        if original.count(old) != 1:
            raise RuntimeError('stale anchor: ' + name)
    print(f'{len(CASES)} router-attempt anchors unique; markers statically derived')


def summarize(rows, evidence):
    """Count completed execution records and their source-bound replay logs."""
    phases = ['baseline', *(case[0] for case in CASES), 'restored']
    expected_names = {'go-actual'} | {'compile-' + phase for phase in phases} | {
        phase + '-' + scenario for phase in phases for scenario in SCENARIOS}
    names = [row['name'] for row in rows]
    if len(names) != len(expected_names) or set(names) != expected_names:
        raise RuntimeError('incomplete or duplicate execution records')
    comparisons = [row for row in rows if 'marker_matched' in row]
    if len(comparisons) != len(phases) * len(SCENARIOS):
        raise RuntimeError('missing comparison records')
    statuses = Counter()
    for row in rows:
        if row['timeout'] or ('marker_matched' not in row and row['rc'] != 0):
            raise RuntimeError('unsuccessful execution: ' + row['name'])
        if 'marker_matched' not in row:
            continue
        if not row['marker_matched']:
            raise RuntimeError('unmatched comparison: ' + row['name'])
        if row['rc'] != 0:
            actual = re.search(r'ROUTER_ATTEMPT_REJECTED status=Invalid\((\w+)\)', row['actual_error'])
            if not actual or not row['expected_marker'] or row['expected_marker'] not in row['actual_error']:
                raise RuntimeError('unverified domain failure: ' + row['name'])
            statuses[actual.group(1)] += 1
        elif row['expected_marker']:
            raise RuntimeError('expected failure did not occur: ' + row['name'])
    baseline = [row for row in comparisons if row['name'].startswith('baseline-')]
    strict = corruptions = atomic = 0
    for row in baseline:
        log = (evidence / (row['name'] + '.log')).read_bytes()
        if hashlib.sha256(log).hexdigest() != row['log_sha256']:
            raise RuntimeError('baseline log hash mismatch: ' + row['name'])
        output = log.decode()
        scenario = row['name'].removeprefix('baseline-')
        footer = re.findall(r'^ROUTER_ATTEMPT_INDEPENDENT scenario=' + re.escape(scenario)
                            + r' frames=\d+ strict=(\d+) corruptions=(\d+)$', output, re.MULTILINE)
        strict_lines = re.findall(r'^ROUTER_ATTEMPT_STRICT rejected=(\d+)$', output, re.MULTILINE)
        observed_corruptions = len(re.findall(r'^ROUTER_ATTEMPT_CORRUPTION \S+ rejected$', output, re.MULTILINE))
        observed_atomic = len(re.findall(r'^ROUTER_ATTEMPT_ATOMIC late-next rejected prefix=\d+ retained=\d+$', output, re.MULTILINE))
        if len(footer) != 1 or strict_lines != [footer[0][0]] or observed_corruptions != int(footer[0][1]) or observed_atomic == 0:
            raise RuntimeError('inconsistent replay evidence: ' + row['name'])
        strict += int(strict_lines[0])
        corruptions += observed_corruptions
        atomic += observed_atomic
    return dict(faults=sum(row['name'].startswith('compile-') and row['name'] not in
                          {'compile-baseline', 'compile-restored'} for row in rows),
                records=len(rows), streams=len(baseline), strict=strict,
                corruptions=corruptions, atomic=atomic, comparisons=len(comparisons),
                detected_failures=sum(statuses.values()),
                successful_comparisons=sum(row['rc'] == 0 for row in comparisons),
                failure_status_counts=dict(sorted(statuses.items())))


def main():
    check_anchors()
    if '--check-anchors' in sys.argv:
        return
    evidence = Path(os.environ['CP_ROUTE_ROUTER_ATTEMPT_EVIDENCE']).resolve()
    evidence.mkdir(parents=True, exist_ok=True)
    sources = [SOURCE,
               'rust/crates/control-router/src/shadow/live/caller/metadata.rs',
               'rust/crates/control-router/src/shadow/live/caller/metadata_state.rs',
               'rust/crates/control-router/src/shadow/live/caller.rs',
               'rust/crates/control-router/src/shadow/live/caller/route.rs',
               'rust/crates/control-router/src/shadow/live/caller/selector_state.rs',
               'rust/crates/legacy-router-shadow/src/caller.rs',
               'rust/crates/legacy-router-shadow/src/caller/router_route_wire.rs',
               'rust/crates/legacy-router-shadow/examples/router_attempt_check.rs',
               'pkg/balance/observation/caller_router_route.go',
               'pkg/balance/observation/caller.go',
               'pkg/balance/router/router_attempt_observation.go',
               'pkg/balance/router/router_attempt_observation_test.go',
               'pkg/balance/router/metadata_observation_test.go',
               'pkg/balance/router/router_score.go', 'pkg/balance/router/group.go',
               'pkg/balance/router/route_observation.go', 'pkg/util/netutil/netutil.go',
               'pkg/controlbridge/shadow/caller_router_route_codec.go',
               'tests/controlplane/cproute/shadow/router-attempt-mutations.py']
    original = (ROOT / SOURCE).read_text()
    hashes = {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in sources}
    (evidence / 'source-hashes.json').write_text(json.dumps(hashes, indent=2) + '\n')
    (evidence / 'marker-expectations.json').write_text(json.dumps([
        {'fault': name, 'affected': affected, 'status': status}
        for name, _, _, affected, status in CASES], indent=2) + '\n')
    rows = []

    def save():
        (evidence / 'results.json').write_text(json.dumps(rows, indent=2) + '\n')

    def run(name, args, env=None):
        start = time.monotonic()
        proc = subprocess.Popen(args, cwd=ROOT, env=env, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True, start_new_session=True)
        timeout = False
        try:
            output, _ = proc.communicate(timeout=240)
        except subprocess.TimeoutExpired:
            timeout = True
            os.killpg(proc.pid, signal.SIGTERM)
            try:
                output, _ = proc.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, signal.SIGKILL)
                output, _ = proc.communicate()
        (evidence / f'{name}.log').write_text(output)
        rows.append({'name': name, 'command': args, 'rc': proc.returncode,
                     'timeout': timeout, 'seconds': round(time.monotonic() - start, 3),
                     'log_sha256': hashlib.sha256(output.encode()).hexdigest()})
        save()
        if timeout:
            raise RuntimeError('timeout is not a detected fault: ' + name)
        return proc.returncode, output

    binary = ROOT / 'rust/target/debug/examples/router_attempt_check'
    build = ['cargo', 'build', '--locked', '--manifest-path', 'rust/Cargo.toml',
             '-p', 'legacy-router-shadow', '--example', 'router_attempt_check']

    def compile_source(name):
        # Remove the existing executable so a successful compile must produce
        # this source's binary, even when all executions happen within one tick.
        binary.unlink(missing_ok=True)
        rc, _ = run(name, build)
        if rc != 0 or not binary.exists():
            raise RuntimeError('compile failed: ' + name)
        identity = hashlib.sha256(binary.read_bytes()).hexdigest()
        rows[-1]['binary_sha256'] = identity
        rows[-1]['source_sha256'] = hashlib.sha256((ROOT / SOURCE).read_bytes()).hexdigest()
        save()
        return identity

    def compare(name, scenario, identity, status=None):
        rc, output = run(name, [str(binary), str(evidence / f'{scenario}.frames'), scenario])
        row = rows[-1]
        row['binary_sha256'] = identity
        first_error = next((line for line in output.splitlines() if line.startswith('Error:')), '')
        expected = f'ROUTER_ATTEMPT_REJECTED status=Invalid({status})' if status else ''
        row['expected_marker'] = expected
        row['actual_error'] = first_error
        row['marker_matched'] = expected in first_error if status else rc == 0
        save()
        if status:
            if rc == 0 or not re.search(r'Error:.*' + re.escape(expected), first_error):
                raise RuntimeError('wrong first domain failure: ' + name)
        elif rc != 0 or f'ROUTER_ATTEMPT_INDEPENDENT scenario={scenario}' not in output:
            raise RuntimeError('baseline or unaffected stream failed: ' + name)

    try:
        env = os.environ.copy()
        env['CP_ROUTE_ROUTER_ATTEMPT_FRAMES_DIR'] = str(evidence)
        rc, _ = run('go-actual', ['go', 'test', './pkg/balance/router', '-run',
                                '^TestRouterAttempt(ActualFrames|PanicAndCapacityReleaseParent)$', '-count=1', '-v'], env)
        if rc != 0:
            raise RuntimeError('actual Go capture failed')
        identity = compile_source('compile-baseline')
        for scenario in SCENARIOS:
            compare('baseline-' + scenario, scenario, identity)
        for name, old, new, affected, status in CASES:
            (ROOT / SOURCE).write_text(original.replace(old, new, 1))
            identity = compile_source('compile-' + name)
            for scenario in SCENARIOS:
                compare(name + '-' + scenario, scenario, identity,
                        status if scenario in affected else None)
    finally:
        (ROOT / SOURCE).write_text(original)
        restored = hashlib.sha256((ROOT / SOURCE).read_bytes()).hexdigest()
        (evidence / 'restoration.json').write_text(json.dumps({'source_sha256': restored, 'matches_original': restored == hashes[SOURCE]}, indent=2) + '\n')
    identity = compile_source('compile-restored')
    for scenario in SCENARIOS:
        compare('restored-' + scenario, scenario, identity)
    summary = summarize(rows, evidence)
    (evidence / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    print('ROUTER_ATTEMPT_FAULTS ' + ' '.join(
        f'{key}={summary[key]}' for key in ['faults', 'records', 'streams', 'strict', 'corruptions', 'atomic']))


if __name__ == '__main__':
    main()
