#!/usr/bin/env python3
# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Compile time faults in a source copy, sharing one caller-owned Cargo target."""
from pathlib import Path
import importlib.util
import os
import shutil
import tempfile

spec = importlib.util.spec_from_file_location('live_mutations', Path(__file__).with_name('live-mutations.py'))
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)
ROOT = runner.ROOT
edit, go = runner.edit, runner.go
GO = 'pkg/balance/observation/time.go'
RUST = 'rust/crates/control-routing/src/go_time.rs'

def rust(name, test, marker, edits):
    return name, 'rust', 'control-routing', 'go_time::tests::'+test, marker, edits

CASES = [
 go('relative-monotonic-dropped', 'TestTimeProjectionRawIdentity', 'TIME_ORIGIN_EXACT', [edit(GO, 'value.Monotonic = delta', 'value.Monotonic = 0')]),
 go('location-normalized-by-name', 'TestTimeProjectionRawIdentity', 'TIME_RAW_LOCATION_IDENTITY', [edit(GO, 'entry.location == location', 'entry.location.String() == location.String()')]),
 go('location-equality-refused', 'TestTimeLocationCapacityAndExhaustion', 'TIME_LOCATION_CAP_EQUAL', [edit(GO, 'p.count == MaxTimeLocations', 'p.count == MaxTimeLocations-1')]),
 go('location-plus-one-accepted', 'TestTimeLocationCapacityAndExhaustion', 'TIME_LOCATION_CAP_PLUS_ONE', [edit(GO, 'p.owner.Invalidate(Capacity)\n\t\treturn GoTimeValue{}, false', 'value.Location = 1; return value, true')]),
 go('location-overflow-not-sticky', 'TestTimeLocationCapacityAndExhaustion', 'TIME_LOCATION_STICKY_INVALID', [edit(GO, 'p.owner.Invalidate(Capacity)', '_ = Capacity')]),
 go('startup-self-check-bypassed', 'TestClockOriginSelfCheck', 'TIME_ORIGIN_SELF_CHECK_EXACT', [edit(GO, 'return delta == elapsed', 'return true')]),
 go('startup-version-unchecked', 'TestClockOriginSelfCheck', 'TIME_ORIGIN_VERSION_REJECT', [edit(GO, 'version != SupportedClockToolchain', 'false')]),
 go('sample-domain-lost', 'TestClockOriginSuffixAndDomains', 'TIME_SAMPLE_DOMAIN', [edit(GO, 'Domain: SampleTimeDomain', 'Domain: GoTimeDomain')]),
 go('hot-path-formats-string', 'TestTimeProjectionHotPath', 'TIME_PROJECTION_HOT_PATH', [edit(GO, 'location := t.Location()', '_ = t.String(); location := t.Location()')]),
 go('hot-path-resamples-now', 'TestTimeProjectionHotPath', 'TIME_PROJECTION_HOT_PATH', [edit(GO, 'location := t.Location()', '_ = time.Now(); location := t.Location()')]),
 go('hot-path-formats-time', 'TestTimeProjectionHotPath', 'TIME_PROJECTION_HOT_PATH', [edit(GO, 'location := t.Location()', '_ = t.Format(time.RFC3339); location := t.Location()')]),
 go('baseline-present-lost', 'TestClockOriginSelfCheck', 'TIME_ORIGIN_BASELINE_PRESENT', [edit(GO, 'value.BaselinePresent = true', 'value.BaselinePresent = false')]),
 go('monotonic-with-wall-origin-accepted', 'TestTimeProjectionMissingOriginMonotonic', 'TIME_ORIGIN_DOMAIN_MISMATCH', [edit(GO, '!p.origin.value.HasMonotonic', 'false')]),
 go('startup-nanoseconds-rounded', 'TestClockOriginSuffixAndDomains', 'TIME_ORIGIN_EXACT', [edit(GO, 'magnitude := s*1_000_000_000 + n', 'magnitude := s*1_000_000_000 + n/10')]),
 rust('sample-subtraction-saturates', 'actual_go_oracle', 'TIME_SAMPLE_WRAPPING', [edit(RUST, 'self.0.wrapping_sub(other.0)', 'self.0.saturating_sub(other.0)')]),
 rust('sample-duration-conversion-saturates', 'actual_go_oracle', 'TIME_SAMPLE_WRAPPING', [edit(RUST, '.wrapping_mul(1_000_000)', '.saturating_mul(1_000_000)')]),
 rust('go-monotonic-subtraction-wraps', 'baseline_checked_reconstruction_and_monotonic_add_stripping', 'TIME_MONOTONIC_SUB_SATURATION', [edit(RUST, '.clamp(i128::from(i64::MIN), i128::from(i64::MAX))', '')]),
 rust('origin-reconstruction-wraps', 'baseline_checked_reconstruction_and_monotonic_add_stripping', 'TIME_ORIGIN_REBUILD_PLUS_ONE', [edit(RUST, 'self.monotonic?.checked_add(relative)', 'self.monotonic.map(|base| base.wrapping_add(relative))')]),
 rust('rust-location-identity-dropped', 'actual_go_oracle', 'TIME_GO_RAW_IDENTITY', [edit(RUST, 'location,', 'location: 1,', 'impl GoTime {', '    /// Decode a monotonic-bearing capture.')]),
 rust('absent-baseline-accepted', 'invalid_origin_and_time_values_cannot_be_qualified', 'TIME_ORIGIN_BASELINE_REQUIRED', [edit(RUST, 'monotonic: baseline_present.then_some(baseline)', 'monotonic: Some(baseline)')]),
 rust('monotonic-add-wraps', 'baseline_checked_reconstruction_and_monotonic_add_stripping', 'TIME_MONOTONIC_ADD_STRIP', [edit(RUST, 'self.monotonic.and_then(|value| value.checked_add(duration))', 'self.monotonic.map(|value| value.wrapping_add(duration))')]),
 rust('packed-wall-keeps-monotonic', 'actual_go_oracle', 'TIME_GO_ADD', [edit(RUST, 'if (PACKED_MIN..=PACKED_MAX).contains(&wall)', 'if true')]),
 rust('comparison-always-wall', 'clock_adjustment_and_extreme_wall_add_follow_distinct_rules', 'TIME_MONOTONIC_COMPARE', [edit(RUST, 'return a.cmp(&b);', 'let _ = (a,b);')]),
 rust('go-wall-subtraction-wraps', 'actual_go_oracle', 'TIME_GO_SUB_SATURATION', [edit(RUST, 'if other.add_nanoseconds(duration).same_instant(self)', 'if true')]),
]

def main():
    originals = {path:(ROOT/path).read_bytes() for *_,edits in CASES for path,*_ in edits}
    with tempfile.TemporaryDirectory(prefix='cproute-time-') as temporary:
        directory = Path(temporary)/'repo'
        shutil.copytree(ROOT,directory,ignore=shutil.ignore_patterns('.git','target','bin','artifacts','__pycache__'))
        env = dict(os.environ,CARGO_TARGET_DIR=str(ROOT/'rust/target'))
        env.pop('TIPROXY_CLOCK_ORACLE',None)
        cargo = ['cargo','test','--locked','--offline','--manifest-path','rust/Cargo.toml','-p','control-routing','--lib']
        baseline = ['go','test','./pkg/balance/observation','-run','TestTime|TestClock','-count=1']
        runner.must_pass(baseline,directory,env)
        runner.must_pass(cargo,directory,env)
        for name,mode,package,test,marker,edits in CASES:
            try:
                for path,old,new,start,end in edits:
                    file=directory/path
                    source=file.read_text()
                    begin=source.index(start) if start else 0
                    finish=source.index(end,begin+len(start)) if end else len(source)
                    section=source[begin:finish]
                    if section.count(old)!=1:
                        raise RuntimeError(f'{name}: stale/ambiguous anchor {old!r}')
                    file.write_text(source[:begin]+section.replace(old,new,1)+source[finish:])
                if mode=='go':
                    binary=Path(temporary)/'fault.test'
                    runner.must_pass(['go','test','-c','-o',str(binary),package],directory,env)
                    result=runner.run([str(binary),'-test.run=^'+test+'$','-test.timeout=15s'],directory,env)
                else:
                    runner.must_pass(cargo+['--no-run'],directory,env)
                    result=runner.run(cargo+[test,'--','--exact'],directory,env)
                if result.returncode==0 or marker not in result.stdout:
                    raise RuntimeError(f'{name}: survived or failed outside {marker}\n{result.stdout}')
                print(f'CP-ROUTE time compiling mutation killed: {name}',flush=True)
            finally:
                for path,source in originals.items():
                    (directory/path).write_bytes(source)
        runner.must_pass(baseline,directory,env)
        runner.must_pass(cargo,directory,env)
    if any((ROOT/path).read_bytes()!=source for path,source in originals.items()):
        raise RuntimeError('source worktree changed during mutations')
    print(f'CP-ROUTE time {len(CASES)}/{len(CASES)} compiling mutations killed; restored baseline passed',flush=True)

if __name__=='__main__':
    main()
