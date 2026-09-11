#!/usr/bin/env python3
# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Real Init/health streams and twelve compiled startup boundary faults."""
from pathlib import Path
import hashlib
import json
import os
import re
import signal
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[4]
GO = 'pkg/balance/router/router_score.go'
META = 'rust/crates/control-router/src/shadow/live/caller/metadata.rs'
STATE = 'rust/crates/control-router/src/shadow/live/caller/metadata/state.rs'
# name, source, old, new, executable kind, test filter/scenario, intended marker
CASES = [
 ('omit-init', GO, 'r.endStartupObservation(initial, routingRule)', '// omitted Init publication', 'go', '^TestRouterStartupActualFrames$', 'STARTUP_INIT_PUBLISHED'),
 # Consume an actually queued health before publishing Init, deterministically
 # exposing the same ordering violation as publishing after a racing loop.
 ('health-before-init', GO, 'r.endStartupObservation(initial, routingRule)', 'select { case health := <-r.healthCh: r.updateBackendHealth(health); default: }; r.endStartupObservation(initial, routingRule)', 'go', '^TestRouterStartupQueuedHealth$', 'STARTUP_BEFORE_QUEUED_HEALTH'),
 ('reread-init-config', GO, 'r.endStartupObservation(initial, routingRule)', 'r.endStartupObservation(initial, r.cfgGetter.GetConfig().Balance.RoutingRule)', 'go', '^TestRouterStartupRuleAndFailureBoundaries$', 'STARTUP_SINGLE_CONFIG_READ'),
 ('reload-fixed-rule', GO, 'func (router *ScoreBasedRouter) setConfig(cfg *config.Config) {\n\trouter.Lock()', 'func (router *ScoreBasedRouter) setConfig(cfg *config.Config) {\n\trouter.Lock()\n\trouter.matchType = MatchPort', 'go', '^TestRouterStartupActualFrames$', 'STARTUP_FIXED_RULE'),
 ('nil-as-empty-detector', GO, 'parent.CaptureRouterPort(false, "")', 'parent.CaptureRouterPort(true, "")', 'go', '^TestRouterStartupDetectorReads$', 'STARTUP_NIL_IS_NOT_EMPTY'),
 ('early-listener-read', GO, 'parent.CaptureRouterPort(false, "")', 'parent.CaptureRouterPort(false, clientInfo.ListenerPort)', 'go', '^TestRouterStartupDetectorReads$', 'STARTUP_LISTENER_AFTER_DETECTOR'),
 ('gen0-without-init', META, 'if !self.state.initialized {\n                return Err(InvalidReason::MissingBegin);\n            }', 'if !self.state.initialized { return Ok((Rule::All, ErrorClass::None)); }', 'rust', 'startup_missing_duplicate_and_snapshot', 'STARTUP_REQUIRES_INIT'),
 ('gen0-after-begin', META, 'if generation == 0 {\n            if self.open.is_some() || self.last_generation != 0 {', 'if generation == 0 {\n            if self.state.initialized { return Ok((self.state.rule.unwrap(), self.state.observer_error)); }\n            if self.open.is_some() || self.last_generation != 0 {', 'replay', 'port', 'STARTUP_CORRUPTION_ACCEPTED 3'),
 ('duplicate-init', META, 'if self.state.initialized\n            || self.state.rule.is_some()\n            || self.last_generation != 0\n            || self.open.is_some()', 'if false', 'rust', 'startup_missing_duplicate_and_snapshot', 'STARTUP_DUPLICATE_INIT'),
 ('trust-init-witness', META, 'if rule != init.rule {', 'if false {', 'rust', 'startup_rule_sequence_and_atomic_rejection', 'STARTUP_INIT_WITNESS'),
 ('reset-error-detector', META, 'if open.begin.observer_error != ErrorClass::None {\n                // Go returns', 'if open.begin.observer_error != ErrorClass::None {\n                open.working.detector_present = false;\n                // Go returns', 'rust', 'startup_health_fence_and_detector_history', 'STARTUP_ERROR_DETECTOR_HISTORY'),
 ('lose-startup-snapshot', STATE, 'initialized: self.initialized,\n            detector_present: self.detector_present,', 'initialized: false,\n            detector_present: false,', 'rust', 'startup_missing_duplicate_and_snapshot', 'STARTUP_SNAPSHOT_INITIALIZED'),
]
SCENARIOS = ['all', 'cidr', 'proxy', 'port']


def check_anchors():
    for name, path, old, _, _, _, _ in CASES:
        if (ROOT/path).read_text().count(old) != 1:
            raise RuntimeError('stale startup anchor: ' + name)
    print(f'STARTUP_ANCHORS faults={len(CASES)} edits={len(CASES)}')


def main():
    check_anchors()
    if '--check-anchors' in sys.argv:
        return
    evidence = Path(os.environ['CP_ROUTE_STARTUP_EVIDENCE']).resolve()
    evidence.mkdir(parents=True, exist_ok=True)
    source_paths = sorted({case[1] for case in CASES} | {
        'pkg/balance/router/startup_observation.go', 'pkg/balance/router/startup_observation_test.go',
        'pkg/balance/router/router_attempt_observation.go', 'pkg/balance/observation/caller.go',
        'pkg/balance/observation/caller_metadata.go', 'pkg/balance/observation/caller_router_route.go',
        'pkg/controlbridge/shadow/caller_metadata_codec.go', 'pkg/controlbridge/shadow/caller_router_route_codec.go',
        'rust/crates/control-router/src/shadow/live/caller/metadata/snapshot.rs',
        'rust/crates/control-router/src/shadow/live/caller/metadata_state.rs',
        'rust/crates/control-router/src/shadow/live/caller/metadata_state/tests.rs',
        'rust/crates/control-router/src/shadow/live/caller/router_route.rs',
        'rust/crates/legacy-router-shadow/src/caller.rs',
        'rust/crates/legacy-router-shadow/examples/startup_check.rs',
        'tests/controlplane/cproute/shadow/startup-mutations.py'})
    original = {p: (ROOT/p).read_bytes() for p in source_paths}
    sha = lambda data: hashlib.sha256(data).hexdigest()
    hashes = {p: sha(data) for p, data in original.items()}
    (evidence/'source-hashes.json').write_text(json.dumps(hashes, indent=2)+'\n')
    (evidence/'marker-expectations.json').write_text(json.dumps([
        dict(name=c[0], language=c[4], target=c[5], marker=c[6]) for c in CASES], indent=2)+'\n')
    rows = []
    def save():
        (evidence/'results.json').write_text(json.dumps(rows, indent=2)+'\n')
    def run(name, args, *, marker=None, env=None, compile=False):
        start = time.monotonic()
        proc = subprocess.Popen(args, cwd=ROOT, env=env, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True, start_new_session=True)
        timeout = False
        try:
            output, _ = proc.communicate(timeout=600 if compile else 90)
        except subprocess.TimeoutExpired:
            timeout = True
            os.killpg(proc.pid, signal.SIGTERM)
            try:
                output, _ = proc.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, signal.SIGKILL)
                output, _ = proc.communicate()
        (evidence/(name+'.log')).write_text(output)
        matched = not timeout and ((proc.returncode != 0 and marker in output) if marker else proc.returncode == 0)
        rows.append(dict(name=name, command=args, rc=proc.returncode, timeout=timeout,
                         seconds=round(time.monotonic()-start, 3), log_sha256=sha(output.encode()),
                         expected_marker=marker, marker_matched=matched, compilation=compile))
        save()
        if not matched:
            raise RuntimeError('unexpected startup execution: '+name)
        return output
    rust_binary = None
    with tempfile.TemporaryDirectory(prefix='startup-faults-') as temp:
        temp = Path(temp)
        def build(name, kind, overlay=None):
            nonlocal rust_binary
            if kind == 'go':
                binary = temp/'startup.test'
                binary.unlink(missing_ok=True)
                args = ['go', 'test', '-c', '-o', str(binary)]
                if overlay:
                    args += ['-overlay', str(overlay)]
                args += ['./pkg/balance/router']
                run(name+'-compile', args, compile=True)
            elif kind == 'rust':
                if rust_binary:
                    rust_binary.unlink(missing_ok=True)
                output = run(name+'-compile', ['cargo', 'test', '--locked', '--manifest-path', 'rust/Cargo.toml', '-p', 'control-router', '--lib', '--no-run', '--message-format=json'], compile=True)
                executables = []
                for line in output.splitlines():
                    try:
                        msg = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if msg.get('reason') == 'compiler-artifact' and msg.get('executable') and msg.get('profile', {}).get('test'):
                        executables.append(Path(msg['executable']))
                if len(executables) != 1:
                    raise RuntimeError('ambiguous Rust test executable')
                binary = rust_binary = executables[0]
            else:
                binary = ROOT/'rust/target/debug/examples/startup_check'
                binary.unlink(missing_ok=True)
                run(name+'-compile', ['cargo', 'build', '--locked', '--manifest-path', 'rust/Cargo.toml', '-p', 'legacy-router-shadow', '--example', 'startup_check'], compile=True)
            if not binary.is_file():
                raise RuntimeError('missing freshly compiled binary')
            identity = sha(binary.read_bytes())
            rows[-1]['binary_sha256'] = identity
            rows[-1]['source_hashes'] = {p: sha((ROOT/p).read_bytes()) for p in {case[1] for case in CASES}}
            if overlay:
                replacements = json.loads(overlay.read_text())['Replace']
                rows[-1]['overlay_sources'] = {str(Path(p).relative_to(ROOT)): sha(Path(replacement).read_bytes()) for p, replacement in replacements.items()}
            save()
            return binary, identity
        def execute(name, kind, binary, identity, target, frames, marker=None):
            env = os.environ.copy()
            if kind == 'go':
                frames.mkdir(exist_ok=True)
                env['CP_ROUTE_STARTUP_FRAMES_DIR'] = str(frames)
                args = [str(binary), '-test.run='+target, '-test.count=1', '-test.timeout=60s', '-test.v']
            elif kind == 'rust':
                args = [str(binary), target, '--nocapture']
            else:
                args = [str(binary), str(frames/(target+'.frames'))]
            run(name, args, marker=marker, env=env)
            rows[-1]['binary_sha256'] = identity
            if kind == 'replay':
                rows[-1]['frame_sha256'] = sha((frames/(target+'.frames')).read_bytes())
            save()
        def baseline(name):
            frames = evidence/(name+'-frames')
            for kind, target in [('go', '^TestRouterStartup'), ('rust', 'metadata_state::tests::startup_')]:
                binary, identity = build(name+'-'+kind, kind)
                execute(name+'-'+kind, kind, binary, identity, target, frames)
            binary, identity = build(name+'-replay', 'replay')
            for scenario in SCENARIOS:
                execute(name+'-'+scenario, 'replay', binary, identity, scenario, frames)
        try:
            baseline('baseline')
            for name, path, old, new, kind, target, marker in CASES:
                overlay = None
                if kind == 'go':
                    modified = temp/(name+'.go')
                    modified.write_text(original[path].decode().replace(old, new, 1))
                    overlay = temp/(name+'.json')
                    overlay.write_text(json.dumps({'Replace': {str(ROOT/path): str(modified)}}))
                else:
                    (ROOT/path).write_text(original[path].decode().replace(old, new, 1))
                try:
                    binary, identity = build(name, kind, overlay)
                    frames = evidence/(name+'-frames') if kind == 'go' else evidence/'baseline-frames'
                    execute(name, kind, binary, identity, target, frames, marker)
                finally:
                    if kind != 'go':
                        (ROOT/path).write_bytes(original[path])
        finally:
            # Only Rust sources are mutated; Go uses overlay files exclusively.
            for path in {c[1] for c in CASES if c[4] != 'go'}:
                (ROOT/path).write_bytes(original[path])
            restoration = {p: sha((ROOT/p).read_bytes()) == hashes[p] for p in source_paths}
            (evidence/'restoration.json').write_text(json.dumps(restoration, indent=2)+'\n')
            if not all(restoration.values()):
                raise RuntimeError('source restoration mismatch')
        baseline('restored')
    if len(rows) != 42 or len({r['name'] for r in rows}) != 42 or sum(r['rc'] != 0 for r in rows) != 12 or not all(r['marker_matched'] for r in rows):
        raise RuntimeError('unexpected startup record populations')
    strict = corruptions = atomic = 0
    for phase in ['baseline', 'restored']:
        for scenario in SCENARIOS:
            output = (evidence/(phase+'-'+scenario+'.log')).read_text()
            if re.findall(r'^STARTUP_STRICT rejected=(\d+)$', output, re.M) != ['8'] or len(re.findall(r'^STARTUP_CORRUPTION [0-3] rejected$', output, re.M)) != 4 or len(re.findall(r'^STARTUP_ATOMIC rejected prefix=1 retained=\d+$', output, re.M)) != 1 or not re.search(r'^STARTUP_INDEPENDENT frames=\d+ strict=8 corruptions=4 atomic=1$', output, re.M):
                raise RuntimeError('incomplete startup replay assertions')
            strict += int(re.search(r"^STARTUP_STRICT rejected=(\d+)$", output, re.M).group(1))
            corruptions += len(re.findall(r"^STARTUP_CORRUPTION [0-3] rejected$", output, re.M))
            atomic += len(re.findall(r"^STARTUP_ATOMIC rejected prefix=1 retained=\d+$", output, re.M))
    summary = dict(faults=sum(r["expected_marker"] is not None for r in rows), records=len(rows), failures=sum(r["rc"] != 0 for r in rows), streams=sum(r["name"] in {"baseline-"+s for s in SCENARIOS} for r in rows), replays=sum("frame_sha256" in r and r["rc"] == 0 for r in rows), strict=strict, corruptions=corruptions, atomic=atomic)
    if summary != dict(faults=12, records=42, failures=12, streams=4, replays=8, strict=64, corruptions=32, atomic=8):
        raise RuntimeError("startup summary coverage mismatch")
    (evidence/'summary.json').write_text(json.dumps(summary, indent=2)+'\n')
    print('STARTUP_FAULTS '+json.dumps(summary, sort_keys=True))


if __name__ == '__main__':
    main()
