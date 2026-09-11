#!/usr/bin/env python3
# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Actual-Go oracle and compiling selector faults, with every attempt retained."""
from pathlib import Path
import hashlib, json, os, shutil, signal, subprocess, tempfile, time, sys

ROOT = Path(__file__).resolve().parents[4]
GO = 'pkg/balance/router/backend_selector.go'
RUST = 'rust/crates/control-router/src/shadow/live/caller/selection.rs'
GO_CASES = [
 ('wrapped-is-retried', 'wrapped-sentinel', [('\t"net"', '\t"net"\n\t"github.com/pingcap/tiproxy/lib/util/errors"'),('err == ErrNoBackend && len(bs.excluded) > 0','errors.Is(err, ErrNoBackend) && len(bs.excluded) > 0')]),
 ('empty-sentinel-is-retried','empty-sentinel',[('err == ErrNoBackend && len(bs.excluded) > 0','err == ErrNoBackend')]),
 ('exclusions-not-reset','exact-retry',[('bs.excluded = bs.excluded[:0]','_ = bs.excluded')]),
 ('second-attempt-omitted','exact-retry',[('backend, err = bs.routeOnce(bs.excluded)','_ = bs.excluded')]),
 ('append-old-current','success-append',[('bs.cur = backend\n\tbs.excluded = append(bs.excluded, backend)','bs.excluded = append(bs.excluded, bs.cur)\n bs.cur = backend')]),
 ('error-backend-lost','ordinary-error',[('\t\treturn backend, err', '\t\treturn nil, err')]),
 # The wrapped error is the first error after a successful Next in oracle order;
 # overwriting cur already diverges there, before the ordinary-error case.
 ('error-overwrites-current','wrapped-sentinel',[('if err != nil {', 'if err != nil {\n bs.cur = backend')]),
 ('finish-loses-current','success-append',[('bs.onCreate(bs.cur, conn, succeed)','bs.onCreate(nil, conn, succeed)')]),
 ('history-deduplicated','duplicate-history',[('bs.excluded = append(bs.excluded, backend)','if len(bs.excluded) == 0 || bs.excluded[len(bs.excluded)-1] != backend { bs.excluded = append(bs.excluded, backend) }')]),
]
RUST_CASES = [
 ('ordinary-error-retried','selection_other_error_keeps_current_and_propagates_backend','SELECTOR_WRAPPED_NOT_RETRIED','derived.error == ErrorClass::NoBackend','derived.error != ErrorClass::None'),
 ('error-erases-current','selection_other_error_keeps_current_and_propagates_backend','SELECTOR_ERROR_RETURN_AND_RETAINED_CURRENT','working.count += 1;','working.count += 1;\n } else { working.current = None;'),
 ('late-exclusions-trusted','selection_late_mismatch_rolls_back_completed_state','SELECTOR_LATE_WITNESS','|| excluded != open.working.excluded()','|| false && excluded != open.working.excluded()'),
 ('plus-one-admitted','selection_limit_accepts_equality_and_never_truncates','SELECTOR_BOUND_PLUS_ONE','if working.count == MAX_EXCLUDED {\n                    return Err(InvalidReason::Capacity);\n                }','if working.count == MAX_EXCLUDED { return Ok((working, false)); }'),
 ('attempt-ordinal-unchecked','selection_missing_duplicate_foreign_and_open_tail_fail','SELECTOR_missing','ordinal != open.attempts + 1','false'),
 ('invalid-owner-repaired','selection_limit_accepts_equality_and_never_truncates','SELECTOR_STICKY','self.failed.map_or(Ok(()), Err)','Ok(())'),
 ('open-next-allowed-at-tail','selection_missing_duplicate_foreign_and_open_tail_fail','SELECTOR_OPEN_TAIL','if self.open.is_some() {\n            Err(InvalidReason::Lifecycle)','if self.open.is_some() {\n            Ok(())'),
]


def check_anchors():
    for name, marker, edits in GO_CASES:
        source = (ROOT / GO).read_text()
        for old, new in edits:
            if source.count(old) != 1:
                raise RuntimeError('stale anchor: ' + name)
            source = source.replace(old, new, 1)
    for name, test, marker, old, new in RUST_CASES:
        if (ROOT / RUST).read_text().count(old) != 1:
            raise RuntimeError('stale anchor: ' + name)
    print('SELECTOR_ANCHORS 16 unique fault anchors; static check only', flush=True)


def main():
    check_anchors()
    evidence=Path(os.environ['CP_ROUTE_SELECTOR_EVIDENCE']).resolve();evidence.mkdir(parents=True,exist_ok=True)
    originals={path:(ROOT/path).read_bytes() for path in [GO,RUST]}
    (evidence/'source-hashes.json').write_text(json.dumps({p:hashlib.sha256(b).hexdigest() for p,b in originals.items()},indent=2)+'\n')
    rows=[]
    def save(): (evidence/'results.json').write_text(json.dumps(rows,indent=2)+'\n')
    def run(name,args,cwd,env=None):
        start=time.monotonic();proc=subprocess.Popen(args,cwd=cwd,env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,start_new_session=True);timeout=False
        try: output,_=proc.communicate(timeout=180)
        except subprocess.TimeoutExpired:
            timeout=True;os.killpg(proc.pid,signal.SIGTERM)
            try: output,_=proc.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid,signal.SIGKILL);output,_=proc.communicate()
        (evidence/(name+'.log')).write_text(output)
        rows.append(dict(name=name,command=args,rc=proc.returncode,timeout=timeout,seconds=round(time.monotonic()-start,3),sha256=hashlib.sha256(output.encode()).hexdigest()));save()
        if timeout: raise RuntimeError('timeout is not a kill: '+name)
        return proc.returncode,output
    def binary_identity(binary):
        rows[-1]['binary_sha256']=hashlib.sha256(binary.read_bytes()).hexdigest();rows[-1]['binary_mtime_ns']=binary.stat().st_mtime_ns;save()
    example=ROOT/'rust/target/debug/examples/selector_check'
    (evidence/'oracle-binary.json').write_text(json.dumps(dict(sha256=hashlib.sha256(example.read_bytes()).hexdigest(),mtime_ns=example.stat().st_mtime_ns),indent=2)+'\n')
    with tempfile.TemporaryDirectory(prefix='selector-core-') as temporary:
        temp=Path(temporary);repo=temp/'repo'
        shutil.copytree(ROOT,repo,ignore=shutil.ignore_patterns('.git','target','bin','artifacts','__pycache__'))
        go_binary=temp/'selector.test'
        def go_attempt(name,marker=None):
            rc,output=run(name+'-compile',['go','test','-c','-o',str(go_binary),'./pkg/balance/router'],repo)
            if rc: raise RuntimeError('compile is not a kill: '+name+'\n'+output)
            binary_identity(go_binary)
            env=dict(os.environ);env['CP_ROUTE_SELECTOR_ORACLE']=str(evidence/(name+'.json'))
            rc,output=run(name+'-capture',[str(go_binary),'-test.run=^TestSelectorTransitionOracle$','-test.timeout=30s','-test.count=1'],repo,env)
            if rc: raise RuntimeError('Go capture failure is not a comparator kill: '+name+'\n'+output)
            rc,output=run(name+'-compare',[str(example),env['CP_ROUTE_SELECTOR_ORACLE']],repo)
            if marker is None:
                if rc or 'SELECTOR_ORACLE cases=12 steps=24 mismatch=0' not in output: raise RuntimeError('baseline failed: '+name+'\n'+output)
            elif rc==0 or 'SELECTOR_ORACLE_MISMATCH case='+marker+' ' not in output:
                raise RuntimeError('survived/wrong marker: '+name+'\n'+output)
        def rust_attempt(name,test,marker=None):
            rc,output=run(name+'-compile',['cargo','test','--locked','--manifest-path','rust/Cargo.toml','-p','control-router','--lib','--no-run','--message-format=json'],ROOT)
            if rc: raise RuntimeError('compile is not a kill: '+name+'\n'+output)
            executables=[Path(row['executable']) for line in output.splitlines() if line.startswith('{') for row in [json.loads(line)] if row.get('reason')=='compiler-artifact' and row.get('executable')]
            if len(executables)!=1: raise RuntimeError('ambiguous test binary')
            binary=executables[0];binary_identity(binary)
            rc,output=run(name,[str(binary),test,'--nocapture'],ROOT)
            if marker is None:
                if rc or '8 passed' not in output: raise RuntimeError('Rust baseline failed: '+name+'\n'+output)
            elif rc==0 or marker not in output:
                raise RuntimeError('survived/wrong marker: '+name+'\n'+output)
        go_attempt('baseline-go')
        rust_attempt('baseline-rust','shadow::live::caller::selection::tests::')
        for name,marker,edits in GO_CASES:
            try:
                source=originals[GO].decode()
                for old,new in edits:
                    if source.count(old)!=1: raise RuntimeError('stale anchor: '+name)
                    source=source.replace(old,new,1)
                (repo/GO).write_text(source);go_attempt(name,marker)
                print('SELECTOR_MUTATION killed: '+name,flush=True)
            finally: (repo/GO).write_bytes(originals[GO])
        for name,test,marker,old,new in RUST_CASES:
            try:
                source=originals[RUST].decode()
                if source.count(old)!=1: raise RuntimeError('stale anchor: '+name)
                (ROOT/RUST).write_text(source.replace(old,new,1))
                rust_attempt(name,'shadow::live::caller::selection::tests::'+test,marker)
                print('SELECTOR_MUTATION killed: '+name,flush=True)
            finally: (ROOT/RUST).write_bytes(originals[RUST])
        go_attempt('restored-go')
        rust_attempt('restored-rust','shadow::live::caller::selection::tests::')
    if any((ROOT/p).read_bytes()!=data for p,data in originals.items()): raise RuntimeError('source changed')
    print(f'SELECTOR_MUTATIONS {len(GO_CASES)+len(RUST_CASES)}/{len(GO_CASES)+len(RUST_CASES)} compiled faults killed; restored Go/Rust baselines passed',flush=True)

if __name__=='__main__':
    if sys.argv[1:] == ['--check-anchors']:
        check_anchors()
    elif sys.argv[1:]:
        raise SystemExit('usage: selector-core-mutations.py [--check-anchors]')
    else:
        main()
