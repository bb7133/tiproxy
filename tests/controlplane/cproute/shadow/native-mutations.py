#!/usr/bin/env python3
# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Compiling faults for actual native factor capture and independent comparison."""
from pathlib import Path
import importlib.util
import os
import subprocess
import tempfile

spec = importlib.util.spec_from_file_location('live_mutations', Path(__file__).with_name('live-mutations.py'))
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)
edit, go = runner.edit, runner.go
GROUP = 'pkg/balance/router/group.go'

runner.CASES = [
    go('native-publish-after-group-unlock', 'TestNativeGroupPublicationCannotCrossUnlock', 'NATIVE_GROUP_LOCK_PUBLICATION', [
        edit(GROUP, '"reflect"', '"reflect"\n "runtime"'),
        edit(GROUP, 'g.publishPolicyObservationLocked()', 'g.Unlock()\n runtime.Gosched()\n g.publishPolicyObservationLocked()\n g.Lock()',
             'func (g *Group) routeObserved(', '// crossKeyspaceWarnInterval'),
    ], 'router'),
]

CAP = 'pkg/balance/observation/native_capture.go'
REC = 'pkg/balance/observation/recorder.go'
WIRE = 'rust/crates/legacy-router-shadow/src/native.rs'
LIVE = 'rust/crates/control-router/src/shadow/live/native.rs'
WINDOW = 'rust/crates/control-router/src/factors/window.rs'

def rust(name, package, test, marker, edits):
    return name, 'rust', package, test, marker, edits

def native(name, test, marker, edits):
    return rust(name, 'control-router', 'shadow::live::native::tests::'+test, marker, edits)

def codec(name, test, marker, edits):
    return rust(name, 'legacy-router-shadow', 'native_tests::'+test, marker, edits)

for factor, reference in [('cpu', 'fc.lastMetricTime'), ('memory', 'fm.lastMetricTime'), ('health', 'latestTime')]:
    path = 'pkg/balance/factor/factor_'+factor+'.go'
    runner.CASES.append(go('native-'+factor+'-second-expiry-read', 'TestNativeSingleExpiryInstant', 'NATIVE_SINGLE_EXPIRY_INSTANT', [
        edit(path, 'expiryNow.Sub('+reference+')', 'time.Since('+reference+')')], 'factor'))
runner.CASES += [
    go('native-read-cap-expanded', 'TestNativeReadSampleAndStringBounds', 'NATIVE_READ_PLUS_ONE', [edit('pkg/balance/observation/native_values.go', 'MaxEvaluationReads        = 128', 'MaxEvaluationReads        = 129')]),
    go('native-clock-cap-expanded', 'TestNativeReadSampleAndStringBounds', 'NATIVE_CLOCK_PLUS_ONE', [edit('pkg/balance/observation/native_values.go', 'MaxEvaluationClocks       = 64', 'MaxEvaluationClocks       = 65')]),
    go('native-clock-ordinal-lost', 'TestNativeReadSampleAndStringBounds', 'NATIVE_CLOCK_OCCURRENCES', [edit(CAP, 'read.Ordinal++', 'read.Ordinal = 0')]),
    go('native-samples-total-expanded', 'TestNativeReadSampleAndStringBounds', 'NATIVE_SAMPLES_PLUS_ONE', [edit(CAP, 'MaxEvaluationSamples-int(n.SampleCount)', 'MaxEvaluationSamples+1-int(n.SampleCount)')]),
    go('native-text-bound-expanded', 'TestNativeReadSampleAndStringBounds', 'NATIVE_STRING_PLUS_ONE', [edit(CAP, 'len(value) > MaxEvaluationStringBytes', 'len(value) > MaxEvaluationStringBytes+1')]),
    go('native-total-text-bound-expanded', 'TestNativeReadSampleAndStringBounds', 'NATIVE_STRINGS_PLUS_ONE', [edit(CAP, 'MaxEvaluationStringsBytes-int(n.StringBytes)', 'MaxEvaluationStringsBytes+1-int(n.StringBytes)')]),
    go('native-startup-does-not-fence-legacy', 'TestNativeClockFailureFencesInstallation', 'NATIVE_CLOCK_FAILURE_WHOLE_PROCESS', [edit(REC, 'existing.Invalidate(Malformed)', '_ = existing')]),
    codec('native-arch-label-ignored', 'native_schema_is_strict_and_origin_bound', 'NATIVE_ARCH_LABEL', [edit(WIRE, '"amd64" => domain::GoArch::Amd64', '"amd64" => domain::GoArch::Arm64')]),
    codec('native-unsupported-arch-accepted', 'native_schema_is_strict_and_origin_bound', 'NATIVE_ARCH_UNSUPPORTED', [edit(WIRE, '_ => return Err(Error::Schema)', '_ => domain::GoArch::Arm64', 'go_arch: match', '\n        })')]),
    codec('native-empty-witness-trusted', 'native_query_preserves_labels_samples_and_empty_semantics', 'NATIVE_EMPTY_RECOMPUTED', [edit(WIRE, 'if empty != expected_empty', 'if false && empty != expected_empty')]),
    codec('native-total-samples-expanded', 'native_read_clock_sample_and_string_bounds', 'NATIVE_SAMPLE_TOTAL_PLUS_ONE', [edit(WIRE, 'budget.samples > 4096', 'budget.samples > 4097')]),
    codec('native-wire-clock-cap-expanded', 'native_read_clock_sample_and_string_bounds', 'NATIVE_CLOCK_PLUS_ONE', [edit(WIRE, 'budget.clocks > 64', 'budget.clocks > 65')]),
    native('native-comparison-bypassed', 'bad_native_output_does_not_commit_history_or_prefix', 'NATIVE_ATOMIC_INVALID', [edit(LIVE, 'staged.apply(e).map_err(|_| InvalidReason::Witness)?;', 'let _ = staged.apply(e);')]),
    native('native-old-clone-uncharged', 'native_budget_includes_old_history_clone_and_stage_at_equality', 'NATIVE_HISTORY_PLUS_ONE', [edit(LIVE, '.checked_add(old_charge)', '.checked_add(0)')]),
    native('native-stage-uncharged', 'native_budget_includes_old_history_clone_and_stage_at_equality', 'NATIVE_HISTORY_PLUS_ONE', [edit(LIVE, '.and_then(|v| v.checked_add(STAGE_OVERHEAD))', '.and_then(|v| v.checked_add(0))')]),
    native('native-equality-rejected', 'native_budget_includes_old_history_clone_and_stage_at_equality', 'NATIVE_HISTORY_EQUAL', [edit(LIVE, 'charge <= HISTORY_LIMIT.saturating_sub(self.native_bytes)', 'charge < HISTORY_LIMIT.saturating_sub(self.native_bytes)')]),
    native('native-arch-conflict-accepted', 'conflicting_native_preludes_are_sticky', 'NATIVE_ARCH_PROCESS_CONFLICT', [edit(LIVE, ' || old.coverage.go_arch != coverage.go_arch', '')]),
    native('native-failed-prelude-repairable', 'conflicting_native_preludes_are_sticky', 'NATIVE_PRELUDE_NO_REPAIR', [edit(LIVE, 'self.invalidate(coverage.epoch, reason);', 'let _ = reason;')]),
    native('native-history-mutated-before-comparison', 'bad_native_output_does_not_commit_history_or_prefix', 'NATIVE_ATOMIC_CONTENT', [edit(LIVE, '        let native = self\n            .native\n            .get(&e.epoch)', '        if let Some(stored) = self.native.get_mut(&e.epoch).and_then(|owner| owner.groups.get_mut(&e.group)) { let _ = stored.state.apply(e); }\n        let native = self\n            .native\n            .get(&e.epoch)')]),
]
COMPUTE = 'rust/crates/control-router/src/shadow/native_compute.rs'
for name, old in [
    ('native-score-witness-ignored', 'account.score_count != counts.score'),
    ('native-physical-witness-ignored', 'u64::try_from(account.physical).ok() != Some(counts.physical)'),
    ('native-account-membership-ignored', 'owner.ledger.account_group(account.account) != Some(e.group)'),
]:
    edits = [edit(LIVE, old, 'false')]
    if name == 'native-account-membership-ignored':
        # Also bypass the subsequent lookup; the forged identity must reach the
        # otherwise internally consistent factor computation.
        edits.append(edit(LIVE, '.compact_account(account.account)', '.compact_account(9)'))
    runner.CASES.append(native(name, 'native_counts_and_membership_are_independent_of_consistent_factor_output', 'NATIVE_LEDGER_INDEPENDENT', edits))
runner.CASES.append(native('native-score-getter-presence-ignored', 'native_score_cannot_hide_its_getter_presence_to_bypass_ledger', 'NATIVE_SCORE_PRESENCE_REQUIRED', [edit(COMPUTE, 'self.use_field(8);', 'self.use_field(0);')]))
runner.CASES.append(rust('native-sample-reference-substituted', 'control-routing', 'go_time::tests::actual_go_oracle', 'TIME_SAMPLE_REFERENCE_CONVERSION', [edit('rust/crates/control-routing/src/go_time.rs', 'monotonic: None,', 'monotonic: reference.monotonic,', 'pub fn as_go_time_at(', '/// Project the instant as Go')]))

for name, old, new, marker in [
    ('native-conversion-swapped', 'self == Self::Amd64', 'self == Self::Arm64', 'NATIVE_ARM64_CONVERSION'),
    ('native-conversion-rust-as', 'self == Self::Amd64', 'false', 'NATIVE_AMD64_CONVERSION'),
]:
    runner.CASES.append(rust(name, 'control-router', 'factors::window::numeric_tests::native_numeric_architecture_is_capture_metadata', marker, [edit(WINDOW, old, new)]))

def actual(name, edits):
    return codec(name, 'actual_go_factor_capture_computes_independently', 'NATIVE_ACTUAL_FACTOR', edits)

PHASES = 'rust/crates/control-router/src/factors/phases.rs'
runner.CASES += [
    actual('native-routeable-history-skipped', [edit(COMPUTE, '        let factors = self.prepare(e)?;', '        if e.entry == Entry::Routeable { return Ok(()); }\n        let factors = self.prepare(e)?;')]),
    actual('native-clock-instants-merged', [edit(COMPUTE, 'Ok(*time)', 'Ok(self.reads.iter().find_map(|read| if let Read::Clock { time, .. } = read { Some(*time) } else { None }).unwrap_or(*time))')]),
    actual('native-health-read-order-swapped', [edit(WINDOW, '(QueryId::FailurePd, QueryId::TotalPd, 0.5)', '(QueryId::TotalPd, QueryId::FailurePd, 0.5)')]),
    actual('native-cpu-series-last-only', [edit(WINDOW, 'cpu_usage(samples)', 'cpu_usage(&samples[samples.len()-1..])')]),
    actual('native-memory-series-last-only', [edit(WINDOW, 'memory_usage::<Q::Time>(samples, self.go_arch)', 'memory_usage::<Q::Time>(&samples[samples.len()-1..], self.go_arch)')]),
    actual('native-raw-location-cache-equality-erased', [edit(WINDOW, 'self.cpu_time != Some(query.time())', 'self.cpu_time.is_none_or(|old| old.before(query.time()) || query.time().before(old))')]),
    actual('native-retained-health-query-erased', [edit(WINDOW, 'self.health_queries.insert(id, query.clone());', 'self.health_queries.remove(&id);')]),
    actual('native-wrong-advice-stop', [edit(PHASES, 'answer.advice == BalanceAdvice::Negative', '(from > to && answer.advice == BalanceAdvice::Negative)', 'pub(crate) fn balance', 'pub(crate) fn ticket')]),
    actual('native-random-ticket-law-altered', [edit(PHASES, 'seed % (10 * n + 1) % n', 'seed % n')]),
    codec('native-resource-token-reused', 'actual_go_factor_capture_computes_independently', 'NATIVE_RESOURCE_TOKEN_REUSE', [edit(COMPUTE, 'e.resource <= self.last_resource', 'false')]),
]

for factor, prefix, kind in [('cpu', 'fc', 'CPU'), ('memory', 'fm', 'Memory')]:
    runner.CASES.append(go('native-'+factor+'-query-reread', 'TestNativeEarlyExitAndOriginalBackend', 'NATIVE_HEALTH_CONDITIONAL_ORDER', [
        edit('pkg/balance/factor/factor_'+factor+'.go', prefix+'.capture.query(observation.Query'+kind+', qr)', prefix+'.capture.query(observation.Query'+kind+', '+prefix+'.mr.GetQueryResult('+prefix+'.Name()))')], 'factor'))
runner.CASES += [
    codec('native-producer-identity-dropped', 'native_query_preserves_labels_samples_and_empty_semantics', 'NATIVE_PRODUCER_ID_REQUIRED', [edit(WIRE, ' || self.producer.0 == 0', '')]),
    codec('native-wire-read-cap-expanded', 'native_read_clock_sample_and_string_bounds', 'NATIVE_READ_PLUS_ONE', [edit(WIRE, 'reads: Bounded<WireRead, 128>', 'reads: Bounded<WireRead, 129>')]),
    actual('native-uniform-ticket-law-altered', [edit(PHASES, '        seed % n', '        (seed + 1) % n')]),
    actual('native-random-ticket-offset', [edit(PHASES, 'seed % (10 * n + 1) % n', '(seed % (10 * n + 1) + 1) % n')]),
]
for name, marker, old, new in [
    ('native-packed-output-trusted', 'NATIVE_OUTPUT_COMPUTED', 'if row.score != actual.packed', 'if false && row.score != actual.packed'),
    ('native-unequal-sort-accepted', 'NATIVE_SORT_UNEQUAL', 'previous.is_some_and(|score| score > row.score)', 'previous.is_some_and(|_| false)'),
    ('native-duplicate-sort-accepted', 'NATIVE_SORT_DUPLICATE', 'if seen[i] || previous.is_some_and', 'if false || previous.is_some_and'),
]:
    runner.CASES.append(codec(name, 'actual_go_factor_capture_computes_independently', marker, [edit(COMPUTE, old, new)]))

if __name__ == '__main__':
    with tempfile.TemporaryDirectory(prefix='cproute-native-oracle-') as temporary:
        capture = Path(temporary)/'factors.frames'
        subprocess.run(['go','test','./pkg/balance/factor','-run','^TestNativeFactorFrames$','-count=1'], cwd=runner.ROOT, env=dict(os.environ, CP_ROUTE_NATIVE_FRAMES=str(capture)), check=True)
        os.environ['CP_ROUTE_NATIVE_ORACLE'] = str(capture)
        try:
            runner.main(['go', 'test', './pkg/balance/router', './pkg/balance/factor', './pkg/balance/observation', '-run', 'TestNative|TestEvaluation', '-count=1'])
        finally:
            for source in (runner.ROOT/'rust/crates').rglob('*.rs'):
                source.touch()
