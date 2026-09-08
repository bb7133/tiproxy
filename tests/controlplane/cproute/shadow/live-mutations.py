#!/usr/bin/env python3
# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Compile real recorder/witness faults in an isolated source copy, then restore.

One caller-owned Cargo cache is reused sequentially. Never copy a live cache or
let a compiler failure count as a semantic kill. The sustained gate is separate.
"""
from pathlib import Path
import os
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[4]
REC = 'pkg/balance/observation/recorder.go'
CAP = 'pkg/balance/router/observation.go'
SCORE = 'pkg/balance/router/router_score.go'
DOMAIN = 'rust/crates/control-router/src/shadow/live.rs'
LEDGER = 'rust/crates/control-router/src/shadow/ledger.rs'
WIRE = 'rust/crates/legacy-router-shadow/src/live.rs'

def edit(path, old, new, start=None, end=None):
    return path, old, new, start, end

def go(name, test, marker, edits, package='observation'):
    return name, 'go', f'./pkg/balance/{package}', test, marker, edits

def rust(name, test, marker, edits):
    return name, 'rust', 'control-router', 'shadow::live::tests::'+test, marker, edits

CASES = [
 go('record-limit-plus-one','TestRecorderBudgetsIncludeWriterOwnedRecord','RECORDER_LIMIT_PLUS_ONE',[edit(REC,'r.records >= int64(r.limits.Records)','r.records > int64(r.limits.Records)')]),
 go('byte-limit-plus-one','TestRecorderBudgetsIncludeWriterOwnedRecord','RECORDER_LIMIT_PLUS_ONE',[edit(REC,'charge > r.limits.Bytes-r.bytes','charge > r.limits.Bytes-r.bytes+BatchCharge')]),
 go('equality-refused','TestRecorderBudgetsIncludeWriterOwnedRecord','RECORDER_LIMIT_EQUALITY',[edit(REC,'r.records >= int64(r.limits.Records)','r.records >= int64(r.limits.Records)-1')]),
 go('writer-charge-released-on-pop','TestRecorderBudgetsIncludeWriterOwnedRecord','RECORDER_WRITER_CHARGE',[edit(REC,'case record := <-r.queue:', 'case record := <-r.queue:\n r.release(BatchCharge)', 'func (r *Recorder) Next(', 'func (r *Recorder) Retained(')]),
 go('batch-sequence-increments-once','TestRecorderBatchSequenceAcrossConcurrentGroups','RECORDER_ATOMIC_SEQUENCE',[edit(REC,'o.sequence += uint64(batch.EventCount)','o.sequence++')]),
 go('contention-drops-capture','TestRecorderLeafSerializationWaitsForPeerProducer','RECORDER_LEAF_SERIALIZATION',[edit(REC,'o.mu.Lock()','if !o.mu.TryLock() { o.Invalidate(Capacity); return false }','func (o *Owner) Emit(', 'func (o *Owner) Invalidate(')]),
 go('full-queue-invalid-notice-lost','TestRecorderBudgetsIncludeWriterOwnedRecord','RECORDER_FULL_QUEUE_INVALID_NOTICE',[edit(REC,'select {\n\tcase o.recorder.changed <- struct{}{}:\n\tdefault:\n\t}', '_ = o.recorder')]),
 go('owner-identity-reused','TestRecorderInvalidBeforeWitnessAndRetainedIdentity','RECORDER_OWNER_REUSE',[edit(REC,'Owner: uint64(len(r.owners)) + 1','Owner: 1')]),
 go('invalid-reason-overwritten','TestRecorderInvalidBeforeWitnessAndRetainedIdentity','RECORDER_INVALID_STICKY',[edit(REC,'o.reason.CompareAndSwap(uint32(Valid), uint32(reason))','func() bool { o.reason.Store(uint32(reason)); return true }()')]),
 go('sequence-overflow-accepted','TestRecorderCountersNeverWrapAndMalformedBatchInvalidates','RECORDER_SEQUENCE_OVERFLOW',[edit(REC,'o.sequence > math.MaxUint64-uint64(batch.EventCount)','false')]),
 go('identity-wrap-reused','TestRecorderCountersNeverWrapAndMalformedBatchInvalidates','RECORDER_IDENTITY_OVERFLOW',[edit(REC,'o.identity == math.MaxUint64','false')]),
 go('batch-bound-expanded','TestRecorderCountersNeverWrapAndMalformedBatchInvalidates','RECORDER_BATCH_BOUND',[edit(REC,'batch.EventCount > MaxEvents','batch.EventCount > MaxEvents+1')]),
 go('witness-bound-expanded','TestRecorderCountersNeverWrapAndMalformedBatchInvalidates','RECORDER_WITNESS_BOUND',[edit(REC,'batch.Witness.AccountCount > MaxWitnesses','batch.Witness.AccountCount > MaxWitnesses+1')]),
 go('queued-credits-survive-close','TestRecorderCloseJoinsAdmissionAndReleasesOnlyOwnedCredits','RECORDER_CLOSE_JOIN',[edit(REC,'\n\tfor {\n\t\tselect {\n\t\tcase <-r.queue:', '\n return\n\tfor {\n\t\tselect {\n\t\tcase <-r.queue:', 'func (r *Recorder) Close()', '// NextOrChanged')]),
 go('discard-silently-accepted','TestObservationAbandonNeverRefunds','UnpairedDiscard must invalidate the entire owner',[edit(CAP,'s.owner.Invalidate(observation.UnpairedDiscard)','_ = s.owner','func (s *selectionObservation) finish()', 'func (s *selectionObservation) noRoute(')],'router'),
 go('invalid-still-copies-witness','TestObservationInvalidFastPathNeverReadsWitness','LIVE_INVALID_BEFORE_COPY',[edit(CAP,'if !g.observation.Enabled() {','if false {','func (g *Group) capture(', 'func (g *Group) observeRedirect(')],'router'),
 go('observer-writes-production-score','TestObservationActualLifecycle','LIVE_NO_ACCOUNTING_EFFECT',[edit(CAP,'witness := observation.AccountWitness{','b.connScore++\n witness := observation.AccountWitness{')],'router'),
 go('default-router-observer-enabled','TestObservationDefaultDisabled','LIVE_DEFAULT_DISABLED',[edit(SCORE,'return NewScoreBasedRouterWithObservation(logger, nil)','r, _ := observation.NewRecorder(observation.DefaultLimits(), 1, 1)\n return NewScoreBasedRouterWithObservation(logger, r.NewOwner())')],'router'),
 ('go-score-witness-drift','cross','./pkg/balance/router','TestObservationActualLifecycle','Invalid(Witness)',[edit(CAP,'Score: int64(b.connScore)','Score: int64(b.connScore)+1')]),
 ('go-head-witness-is-tail','cross','./pkg/balance/router','TestObservationActualLifecycle','Invalid(Witness)',[edit(CAP,'witness.Head = head.Value.observationID','witness.Head = b.connList.Back().Value.observationID')]),
 ('go-arrival-predecessor-dropped','cross','./pkg/balance/router','TestObservationActualLifecycle','Invalid(Witness)',[edit(CAP,'batch.Witness.Predecessor = tail.Prev().Value.observationID','batch.Witness.Predecessor = 0')]),
 rust('rust-ignores-go-score','batch_witness_is_output_and_failure_keeps_previous_compared_sequence','LIVE_WITNESS',[edit(DOMAIN,'owner.ledger.compact_account(witness.id) != Some(*witness)','false')]),
 rust('bad-batch-advances-progress','batch_witness_is_output_and_failure_keeps_previous_compared_sequence','LIVE_BATCH_ATOMIC',[edit(DOMAIN,'owner.sequence = previous;','let _ = previous;')]),
 rust('missing-account-witness-accepted','batch_witness_is_output_and_failure_keeps_previous_compared_sequence','LIVE_WITNESS',[edit(DOMAIN,'required != observed','(!observed.is_empty() && required != observed)')]),
 rust('reconnect-changes-redirect-accounting','reconnect_marker_never_changes_redirect_accounting_or_v1_pending_set','LIVE_RECONNECT_NOT_REDIRECT',[edit(LEDGER,'s.reconnect = Some(operation);','self.change(&[(account, [0, 0, 1, 1])], None, None)?;\n s.redirect = Some((operation,account,account));')]),
 rust('unpaired-selection-only-marked-closed','unpaired_selection_cannot_refund_and_invalid_owner_never_recovers','LIVE_SELECTION_DISCARD',[edit(LEDGER,' || s.reservation.is_some()','', '    pub(super) fn selection_done(', '    // Administrative Go reconnection')]),
 rust('foreign-progress-qualifies-known-owner','omitted_group_history_replayed_nonce_and_batch_overflow_invalidate','LIVE_PROGRESS_IDENTITY',[edit(DOMAIN,'owner.epoch != epoch','false','    pub fn progress(', '    /// Read an explicit diagnostic snapshot')]),
 rust('live-batch-limit-expanded','omitted_group_history_replayed_nonce_and_batch_overflow_invalidate','LIVE_BATCH_BOUND',[edit(DOMAIN,'batch.events.len() > MAX_EVENTS','batch.events.len() > MAX_EVENTS+1')]),
 ('producer-cause-discarded','rust','legacy-router-shadow','consumer::tests::consumer_invalid_summary_and_bad_frames_never_advance_progress','LIVE_PRODUCER_REASON',[edit('rust/crates/legacy-router-shadow/src/consumer.rs','.insert(epoch, (reason, last_admitted));','.get(&epoch); let _ = (reason,last_admitted);')]),
 ('owner-total-added-without-replacement','rust','legacy-router-shadow','consumer::tests::incremental_report_preserves_other_owners_and_replaces_one_contribution','LIVE_INCREMENTAL_TOTALS',[edit('rust/crates/legacy-router-shadow/src/consumer.rs','report.score - previous.0 + totals.0','report.score + totals.0')]),
 ('v2-unknown-envelope-fields-ignored','rust','legacy-router-shadow','live_tests::live_go_golden_and_strict_schema','LIVE_STRICT_SCHEMA',[edit(WIRE,', deny_unknown_fields','', '#[serde(tag = "kind"', 'enum WireFrame')]),
]

def run(args, cwd, env, timeout=180):
    return subprocess.run(args,cwd=cwd,env=env,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=timeout)

def must_pass(args,cwd,env):
    result=run(args,cwd,env)
    if result.returncode:
        raise RuntimeError('baseline/compile failure is not a mutation kill\n'+result.stdout)
    return result

def main(baseline_go=None):
    baseline_go = baseline_go or ['go','test','./pkg/balance/observation','./pkg/balance/router','-run','TestRecorder|TestObservation','-count=1']
    originals={path:(ROOT/path).read_bytes() for *_,edits in CASES for path,*_ in edits}
    with tempfile.TemporaryDirectory(prefix='cproute-live-') as temporary:
        directory=Path(temporary)/'repo'
        shutil.copytree(ROOT,directory,ignore=shutil.ignore_patterns('.git','target','bin','artifacts','__pycache__'))
        env=dict(os.environ,CARGO_TARGET_DIR=str(ROOT/'rust/target'))
        for key in ['CP_ROUTE_LIVE_SOCKET_CHECK','CP_ROUTE_LIVE_FRAMES']:
            env.pop(key,None)
        cargo=['cargo','test','--locked','--offline','--manifest-path','rust/Cargo.toml']
        must_pass(baseline_go,directory,env)
        must_pass(cargo+['-p','control-router','shadow::live::'],directory,env)
        must_pass(cargo+['-p','legacy-router-shadow'],directory,env)
        must_pass(['cargo','build','--locked','--offline','--manifest-path','rust/Cargo.toml','-p','legacy-router-shadow','--example','live_check'],directory,env)
        for name,mode,package,test,marker,edits in CASES:
            try:
                for path,old,new,start,end in edits:
                    file=directory/path;source=file.read_text();begin=source.index(start) if start else 0;finish=source.index(end,begin+len(start)) if end else len(source)
                    section=source[begin:finish]
                    if section.count(old)!=1:
                        raise RuntimeError(f'{name}: stale/ambiguous anchor {old!r}')
                    file.write_text(source[:begin]+section.replace(old,new,1)+source[finish:])
                if mode in ('go','cross'):
                    binary=Path(temporary)/'fault.test'
                    must_pass(['go','test','-c','-o',str(binary),package],directory,env)
                    if mode=='cross':
                        capture=Path(temporary)/'capture.frames'
                        must_pass([str(binary),'-test.run=^'+test+'$','-test.timeout=15s'],directory,dict(env,CP_ROUTE_LIVE_FRAMES=str(capture)))
                        result=run([str(ROOT/'rust/target/debug/examples/live_check'),str(capture)],directory,env)
                    else:
                        result=run([str(binary),'-test.run=^'+test+'$','-test.timeout=15s'],directory,env)
                else:
                    args=cargo+['-p',package,'--lib']
                    must_pass(args+['--no-run'],directory,env)
                    result=run(args+[test,'--','--exact'],directory,env)
                if result.returncode==0 or marker not in result.stdout:
                    raise RuntimeError(f'{name}: survived or failed outside {marker}\n{result.stdout}')
                print(f'CP-ROUTE live compiling mutation killed: {name}',flush=True)
            finally:
                for path,source in originals.items():
                    (directory/path).write_bytes(source)
        must_pass(baseline_go,directory,env)
        must_pass(cargo+['-p','control-router','shadow::live::'],directory,env)
        must_pass(cargo+['-p','legacy-router-shadow'],directory,env)
    if any((ROOT/path).read_bytes()!=source for path,source in originals.items()):
        raise RuntimeError('source worktree changed during mutations')
    print(f'CP-ROUTE live {len(CASES)}/{len(CASES)} compiling mutations killed; restored baseline passed',flush=True)

if __name__=='__main__':
    main()
