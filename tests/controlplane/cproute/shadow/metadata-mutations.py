#!/usr/bin/env python3
# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Capture real router metadata refreshes, replay them independently, and
compile each derivation fault to prove the unchanged actual streams detect it."""
from pathlib import Path
import hashlib
import json
import os
import signal
import subprocess
import time

ROOT = Path(__file__).resolve().parents[4]
TRACKER = 'rust/crates/control-router/src/shadow/live/caller/metadata.rs'
STATE = 'rust/crates/control-router/src/shadow/live/caller/metadata/state.rs'
LIVE = 'rust/crates/control-router/src/shadow/live/caller/metadata_state.rs'
SNAPSHOT = 'rust/crates/control-router/src/shadow/live/caller/metadata/snapshot.rs'
SCENARIOS = ['all', 'cidr', 'port']
# (name, source, old, new, {scenario that must fail: frozen marker}); every
# other actual stream must still pass unchanged.
CASES = [
    ('drop-live-group-event', LIVE, 'stored.tracker.group_event(event)?;', 'let _ = event;',
     {s: 'METADATA_REPLAY_FAILED scenario=%s generation=1 reason=Lifecycle' % s for s in SCENARIOS}),
    ('drop-live-native-init', LIVE, 'stored.tracker.native_init(evaluation.group)?;', 'let _ = evaluation.group;',
     {s: 'METADATA_REPLAY_FAILED scenario=%s generation=1 reason=Lifecycle' % s for s in SCENARIOS}),
    ('lose-snapshot-generation', SNAPSHOT, 'last_generation: self.last_generation,', 'last_generation: 0,',
     {s: 'METADATA_REPLAY_FAILED scenario=%s generation=2 reason=Sequence' % s for s in ['all', 'cidr']}),
    ('wrong-idle', STATE, 'current_group == 0 || idle(visit.account)', 'current_group == 0 || idle(visit.account) || true',
     {'all': 'METADATA_REPLAY_FAILED scenario=all generation=2 reason=Witness'}),
    ('wrong-intersect', STATE, '.find(|g| g.matcher.intersects(values))', '.find(|g| !g.matcher.intersects(values))',
     {'cidr': 'METADATA_REPLAY_FAILED scenario=cidr generation=1 reason=Witness',
      'port': 'METADATA_REPLAY_FAILED scenario=port generation=1 reason=Witness'}),
    ('drop-failed-construction', TRACKER, 'let construction = open.pending_created.remove(at);\n                        open.failed_constructions.push(construction);',
     'open.pending_created.remove(at);',
     {'cidr': 'METADATA_REPLAY_FAILED scenario=cidr generation=1 reason=Witness'}),
    ('wrong-refresh-parse', TRACKER, 'let parsed = group.matcher.refresh_values(result.clone()).is_ok();', 'let parsed = group.matcher.refresh_values(result.clone()).is_ok() || true;',
     {'cidr': 'METADATA_REPLAY_FAILED scenario=cidr generation=2 reason=Witness'}),
    ('wrong-conflict', STATE, '.filter(|(port, _)| ports.group_for(port).is_err())', '.filter(|(port, _)| ports.group_for(port).is_err() && port.is_empty())',
     {'port': 'METADATA_REPLAY_FAILED scenario=port generation=1 reason=Witness'}),
    ('skip-revisit', TRACKER, 'open.revisit = Some(assign.account);', 'open.revisit = None;',
     {'all': 'METADATA_REPLAY_FAILED scenario=all generation=2 reason=Identity'}),
    ('unbound-created', TRACKER, 'let construction = open.pending_created.remove(at);\n        if open.require_native_init_for(construction) {',
     'let construction = open.pending_created[at];\n        if open.require_native_init_for(construction) {',
     {s: 'METADATA_REPLAY_FAILED scenario=%s generation=1 reason=Lifecycle' % s for s in SCENARIOS}),
]


def main():
    evidence = Path(os.environ['CP_ROUTE_METADATA_EVIDENCE']).resolve()
    evidence.mkdir(parents=True, exist_ok=True)
    paths = [TRACKER, STATE,
             'rust/crates/control-router/src/shadow/live/caller/metadata/snapshot.rs',
             'rust/crates/control-routing/src/group.rs',
             'rust/crates/control-router/src/shadow/live.rs',
             'rust/crates/control-router/src/shadow/live/caller.rs', 'pkg/balance/router/metadata_observation.go',
             'pkg/balance/router/metadata_observation_test.go', 'pkg/balance/router/router_score.go',
             'pkg/balance/router/group.go', 'pkg/balance/observation/caller_metadata.go',
             'pkg/controlbridge/shadow/caller_metadata_codec.go',
             'rust/crates/legacy-router-shadow/src/caller.rs',
             'rust/crates/control-router/src/shadow/live/caller/metadata_state.rs',
             'rust/crates/legacy-router-shadow/examples/metadata_check.rs',
             'rust/crates/legacy-router-shadow/examples/support/route_prefix.rs']
    originals = {p: (ROOT / p).read_bytes() for p in paths}
    (evidence / 'source-hashes.json').write_text(json.dumps({p: hashlib.sha256(b).hexdigest() for p, b in originals.items()}, indent=2) + '\n')
    for name, source, old, _, _ in CASES:
        if originals[source].decode().count(old) != 1:
            raise RuntimeError('stale fault anchor: ' + name)
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

    go_binary = evidence / 'metadata.test'
    rc, output = run('go-compile', ['go', 'test', '-c', '-o', str(go_binary), './pkg/balance/router'])
    if rc:
        raise RuntimeError('Go compilation failed: ' + output)
    binary_identity(go_binary)
    frames = evidence / 'frames'
    env = dict(os.environ, CP_ROUTE_METADATA_FRAMES_DIR=str(frames))
    rc, output = run('go-capture', [str(go_binary), '-test.run=^TestMetadataActualFrames$', '-test.count=1', '-test.timeout=60s'], env)
    if rc or any(not (frames / (s + '.frames')).is_file() for s in SCENARIOS):
        raise RuntimeError('actual Go capture failed: ' + output)
    go_binary.unlink()
    binary = ROOT / 'rust/target/debug/examples/metadata_check'

    def attempt(name, failing=None):
        failing = failing or {}
        rc, output = run(name + '-compile', ['cargo', 'build', '--locked', '--manifest-path', 'rust/Cargo.toml', '-p', 'legacy-router-shadow', '--example', 'metadata_check'])
        if rc:
            raise RuntimeError('compilation is not a detected fault: ' + name + '\n' + output)
        binary_identity(binary)
        for scenario in SCENARIOS:
            rc, output = run(name + '-' + scenario, [str(binary), str(frames / (scenario + '.frames')), scenario])
            marker = failing.get(scenario)
            if marker is None:
                if rc or ('METADATA_INDEPENDENT scenario=' + scenario) not in output:
                    raise RuntimeError('unaffected stream failed: ' + name + '/' + scenario + '\n' + output)
            elif rc == 0 or marker not in output:
                raise RuntimeError('survived/wrong failure: ' + name + '/' + scenario + '\n' + output)

    attempt('baseline')
    for name, source, old, new, failing in CASES:
        try:
            (ROOT / source).write_text(originals[source].decode().replace(old, new, 1))
            attempt(name, failing)
            print('METADATA_MUTATION detected: ' + name + ' (' + ','.join(sorted(failing)) + ')', flush=True)
        finally:
            (ROOT / source).write_bytes(originals[source])
    attempt('restored')
    if any((ROOT / p).read_bytes() != data for p, data in originals.items()):
        raise RuntimeError('source not restored')
    print('METADATA_MUTATIONS %d/%d compiled faults detected on the unchanged actual streams; baseline/restored and 8 witness corruptions passed' % (len(CASES), len(CASES)), flush=True)


if __name__ == '__main__':
    main()
