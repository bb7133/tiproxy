#!/usr/bin/env python3
# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Compile each isolated fault, require its named semantic failure, then restore."""
from pathlib import Path
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[4]
DOMAIN = 'rust/crates/control-router/src/shadow/mod.rs'
LEDGER = 'rust/crates/control-router/src/shadow/ledger.rs'
CODEC = 'rust/crates/legacy-router-shadow/src/lib.rs'
WIRE = 'rust/crates/legacy-router-shadow/src/wire.rs'


def edit(path, old, new, start=None, end=None):
    return path, old, new, start, end


def case(name, test, marker, edits, crate='control-router'):
    return name, crate, test, marker, edits


CASES = [
    case('capacity-progress-reset', 'shadow_global_capacity_preserves_each_exact_owners_compared_sequence', 'SHADOW_CAPACITY_PROGRESS', [edit(DOMAIN, '.map_or(0, |owner| owner.sequence)', '.map_or(0, |_| 0)')]),
    case('shadow-api-grouped-production-import', None, 'SHADOW_NO_EFFECT_CAPABILITY', [edit(DOMAIN, '\n#[cfg(test)]\nmod tests;', '\nuse crate::{Router};\nimpl ShadowState {\n    /// Fault: grouped imports must not grant production authority.\n    pub fn accept_production(&self, _router: &Router) {}\n}\n\n#[cfg(test)]\nmod tests;')]),
    case('shadow-api-parent-production-path', None, 'SHADOW_NO_EFFECT_CAPABILITY', [edit(LEDGER, 'use super::', 'impl Mirror {\n    /// Fault: ancestor paths must not grant production authority.\n    pub fn accept_production(&self, _router: &super::super::Router) {} }\n\nuse super::')]),
    case('foreign-invalidation-reports-qualified', 'shadow_foreign_invalidation_cannot_report_another_epoch_qualified', 'SHADOW_INVALIDATION_SCOPE', [edit(DOMAIN, 'if owner.epoch != epoch {', 'if false {', '    pub fn invalidate(', '    /// Read a bounded diagnostic snapshot')]),
    case('unsealed-epoch-qualifies', 'shadow_unsealed_eof_is_not_a_complete_lifecycle_trace', 'SHADOW_UNSEALED_EOF', [edit(DOMAIN, '.all(|owner| owner.status == Status::CleanEnded)', '.all(|_| true)')]),
    case('sequence-gap-accepted', 'shadow_epoch_gap_duplicate_and_begin_replay_are_sticky', 'SHADOW_SEQUENCE_BEGIN', [edit(DOMAIN, 'owner.sequence.checked_add(1) != Some(observation.sequence)', 'false')]),
    case('begin-replay-accepted', 'shadow_epoch_gap_duplicate_and_begin_replay_are_sticky', 'SHADOW_SEQUENCE_BEGIN', [edit(DOMAIN, ' || observation.event == Event::Begin', ''), edit(LEDGER, 'Event::Begin => return Err(InvalidReason::ReplayedBegin),', 'Event::Begin => return Ok(Transition::Ignored),')]),
    case('invalid-keeps-mutating', 'shadow_epoch_gap_duplicate_and_begin_replay_are_sticky', 'SHADOW_INVALID_STICKY', [edit(DOMAIN, 'if matches!(owner.status, Status::Invalid(_)) {', 'if false {')]),
    case('foreign-nonce-ignored', 'shadow_foreign_nonce_and_owner_capacity_fail_without_reusing_registry', 'SHADOW_FOREIGN_NONCE', [edit(DOMAIN, 'owner.epoch != observation.epoch || ', '')]),
    case('late-attach-accepted', 'shadow_epoch_gap_duplicate_and_begin_replay_are_sticky', 'SHADOW_LATE_ATTACH', [edit(DOMAIN, 'observation.sequence != 1 || observation.event != Event::Begin', 'false')]),
    case('resource-token-reused', 'shadow_factor_lifetime_is_separate_and_connection_transition_is_not_coalesced', 'SHADOW_RESOURCE_REENTRY', [edit(LEDGER, 'self.next_factor = next;', 'let _ = next;')]),
    case('local-owner-reused', 'shadow_process_restart_keeps_invalid_old_interval_and_rehydrates_fresh_owner', 'SHADOW_LOCAL_IDENTITY', [edit(DOMAIN, 'self.next_identity = next;', 'let _ = next;')]),
    case('redirect-target-score-not-charged', 'shadow_score_physical_and_both_close_result_orders', 'SHADOW_SCORE_PHYSICAL', [edit(LEDGER, '(target, [0, 0, 1, 0])', '(target, [0, 0, 0, 0])', '    fn redirect(', '    fn redirected(')]),
    case('redirect-success-keeps-old-physical-order', 'shadow_failed_redirect_retains_arrival_and_old_result_cannot_settle_new', 'SHADOW_ARRIVAL_ORDER', [edit(LEDGER, 'success.then_some((source, session))', 'None', '    fn redirected(', '    fn closing('), edit(LEDGER, 'success.then_some((target, session))', 'None', '    fn redirected(', '    fn closing(')]),
    case('old-terminal-settles-new-operation', 'shadow_failed_redirect_retains_arrival_and_old_result_cannot_settle_new', 'SHADOW_OPERATION_IDENTITY', [edit(LEDGER, 'if pending != operation {', 'if pending != operation && false {', '    fn redirected(', '    fn closing(')]),
    case('close-admission-settles-immediately', 'shadow_score_physical_and_both_close_result_orders', 'SHADOW_CLOSE_ADMISSION', [edit(LEDGER, 'state.closing = Some(operation);', 'self.closed(session)?;\n        state.closing = Some(operation);', '    fn closing(', '    fn closed(')]),
    case('pending-close-leaks-incoming', 'shadow_score_physical_and_both_close_result_orders', 'SHADOW_CLOSE_RESULT_ORDER', [edit(LEDGER, '(target, [0, 0, -1, 0])', '(target, [0, 0, 0, 0])', '    fn closed(', '    fn rehydrate(')]),
    case('unknown-terminal-treated-as-duplicate', 'shadow_unknown_terminal_is_missing_history_not_a_duplicate', 'SHADOW_UNKNOWN_IDENTITY', [edit(LEDGER, 'let mut state = self.session(session)?;', 'let Some(mut state) = self.sessions.get(&session).cloned() else { return Ok(Transition::Ignored); };', '    fn closed(', '    fn rehydrate(')]),
    case('lifecycle-claims-full-routing', 'shadow_unknown_terminal_is_missing_history_not_a_duplicate', 'SHADOW_COVERAGE_SCOPE', [edit(LEDGER, 'lifecycle_only: true,', 'lifecycle_only: false,')]),
    case('frame-limit-plus-one-accepted', 'frame_hard_limit_and_truncation_are_checked_before_decode', 'SHADOW_FRAME_LIMIT', [edit(CODEC, 'length > MAX_FRAME_BYTES', 'length > MAX_FRAME_BYTES + 1')], 'legacy-router-shadow'),
    case('record-limit-plus-one-accepted', 'record_budget_limit_plus_one_preserves_fifo_and_charge', 'SHADOW_RECORD_BOUND', [edit(CODEC, 'self.queue.len() >= MAX_QUEUED_RECORDS', 'self.queue.len() > MAX_QUEUED_RECORDS')], 'legacy-router-shadow'),
    case('byte-limit-equality-refused', 'byte_budget_limit_plus_one_is_independent_of_record_budget', 'SHADOW_BYTE_BOUND', [edit(CODEC, 'bytes > MAX_QUEUED_BYTES', 'bytes >= MAX_QUEUED_BYTES')], 'legacy-router-shadow'),
    case('unit-event-unknown-fields-ignored', 'strict_schema_rejects_duplicates_unknown_fields_and_noncanonical_ids', 'SHADOW_STRICT_SCHEMA', [edit(WIRE, '    Begin {},', '    Begin,'), edit(WIRE, 'Event::Begin => Self::Begin {},', 'Event::Begin => Self::Begin,'), edit(WIRE, 'WireEvent::Begin {} => Self::Begin,', 'WireEvent::Begin => Self::Begin,')], 'legacy-router-shadow'),
    case('shadow-api-accepts-production-router', None, 'SHADOW_NO_EFFECT_CAPABILITY', [edit(DOMAIN, '\n#[cfg(test)]\nmod tests;', '\nimpl ShadowState {\n    /// Fault: accepting production authority violates the frozen API.\n    pub fn accept_production(&self, _router: &crate::Router) {}\n}\n\n#[cfg(test)]\nmod tests;')]),
]


def run(args, directory, env):
    return subprocess.run(args, cwd=directory, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)


def baseline(directory, env):
    for crate, test in [('control-router', 'shadow::'), ('legacy-router-shadow', '')]:
        args = ['cargo', 'test', '--locked', '--offline', '--manifest-path', 'rust/Cargo.toml', '-p', crate, '--lib']
        if test:
            args.append(test)
        result = run(args, directory, env)
        if result.returncode:
            raise RuntimeError('restored shadow baseline failed\n' + result.stdout)
    result = run([sys.executable, 'tests/controlplane/cproute/shadow/isolation.py', str(directory)], directory, env)
    if result.returncode:
        raise RuntimeError(result.stdout)


def main():
    original_sources = {path: (ROOT / path).read_bytes() for _, _, _, _, edits in CASES for path, *_ in edits}
    with tempfile.TemporaryDirectory(prefix='cproute-shadow-') as temporary:
        directory = Path(temporary) / 'repo'
        shutil.copytree(ROOT, directory, ignore=shutil.ignore_patterns('.git', 'target', 'bin', 'artifacts', '__pycache__'))
        target = directory / 'rust/target'
        seed = ROOT / 'rust/target'
        # The caller finishes its baseline first. This target is exclusive to
        # this sequential runner and is always removed by TemporaryDirectory.
        if seed.exists():
            if sys.platform == 'darwin':
                subprocess.run(['cp', '-cR', str(seed), str(target)], check=True)
            else:
                shutil.copytree(seed, target, ignore=shutil.ignore_patterns('incremental'))
        env = dict(os.environ, CARGO_TARGET_DIR=str(target))
        files = {path: (directory / path).read_text() for _, _, _, _, edits in CASES for path, *_ in edits}
        baseline(directory, env)
        for name, crate, test, marker, edits in CASES:
            try:
                for path, old, new, start, end in edits:
                    file = directory / path
                    source = file.read_text()
                    begin = source.index(start) if start else 0
                    finish = source.index(end, begin + len(start)) if end else len(source)
                    section = source[begin:finish]
                    if section.count(old) != 1:
                        raise RuntimeError(f'{name}: stale/ambiguous mutation anchor {old!r}')
                    file.write_text(source[:begin] + section.replace(old, new, 1) + source[finish:])
                args = ['cargo', 'test', '--locked', '--offline', '--manifest-path', 'rust/Cargo.toml', '-p', crate, '--lib']
                compiled = run(args + ['--no-run'], directory, env)
                if compiled.returncode:
                    raise RuntimeError(f'{name}: compile failure is not a kill\n{compiled.stdout}')
                if test:
                    prefix = 'shadow::tests::' if crate == 'control-router' else 'tests::'
                    result = run(args + [prefix + test, '--', '--exact'], directory, env)
                else:
                    result = run([sys.executable, 'tests/controlplane/cproute/shadow/isolation.py', str(directory)], directory, env)
                if result.returncode == 0 or marker not in result.stdout:
                    raise RuntimeError(f'{name}: survived or failed outside {marker}\n{result.stdout}')
                print(f'CP-ROUTE shadow compiling mutation killed: {name}', flush=True)
            finally:
                for path, source in files.items():
                    (directory / path).write_text(source)
        baseline(directory, env)
        print(f'CP-ROUTE shadow {len(CASES)}/{len(CASES)} compiling mutations killed; restored baseline passed', flush=True)
    if any((ROOT / path).read_bytes() != source for path, source in original_sources.items()):
        raise RuntimeError('mutation runner changed the source worktree')


if __name__ == '__main__':
    main()
