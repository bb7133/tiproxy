#!/usr/bin/env python3
# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Semantic faults for shared leases and actual metrics-read provenance.

Reuse the isolated source-copy compiler/restore discipline of the v2 gate.
These are preparatory guarantees, not v3 factor comparison coverage.
"""
from pathlib import Path
import importlib.util

spec = importlib.util.spec_from_file_location('live_mutations', Path(__file__).with_name('live-mutations.py'))
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)
edit, go = runner.edit, runner.go
REC = runner.REC
LEASE = 'pkg/balance/observation/lease.go'
SOURCE = 'pkg/balance/metricsreader/metrics_reader.go'
PROM = 'pkg/balance/metricsreader/prom_reader.go'
BACKEND = 'pkg/balance/metricsreader/backend_reader.go'
LINEAGE = 'pkg/balance/metricsreader/observation.go'

runner.CASES = [
 go('mixed-record-plus-one', 'TestMixedEvaluationRecordLimit', 'MIXED_RECORD_PLUS_ONE', [edit(REC, 'r.records >= int64(r.limits.Records)', 'r.records > int64(r.limits.Records)')]),
 go('mixed-byte-plus-one', 'TestMixedEvaluationByteLimit', 'MIXED_BYTE_PLUS_ONE', [edit(REC, 'charge > r.limits.Bytes-r.bytes', 'charge > r.limits.Bytes-r.bytes+1')]),
 go('evaluation-undercharged', 'TestMixedEvaluationByteLimit', 'MIXED_WRITER_RETAINED', [edit(LEASE, 'o.recorder.reserve(EvaluationCharge)', 'o.recorder.reserve(BatchCharge)')]),
 go('failed-lease-admission-leaks-record', 'TestMixedEvaluationByteLimit', 'MIXED_FAILED_ATOMIC', [edit(REC, 'if charge > r.limits.Bytes-r.bytes {\n\t\treturn false', 'if charge > r.limits.Bytes-r.bytes {\n\t\tr.records++; return false', 'func (r *Recorder) reserve(', 'func (r *Recorder) release(')]),
 go('mixed-writer-released-on-pop', 'TestMixedEvaluationByteLimit', 'MIXED_WRITER_RETAINED', [edit(REC, 'case record := <-r.queue:', 'case record := <-r.queue:\n r.release(BatchCharge)', 'func (r *Recorder) Next(', 'func (r *Recorder) Retained(')]),
 go('capture-lease-release-missing', 'TestEvaluationLeaseCloseAndInvalidationOwnership', 'MIXED_LEASE_RELEASE', [edit(LEASE, 'l.recorder.release(EvaluationCharge)', '_ = l.recorder')]),
 go('capture-lease-double-release', 'TestEvaluationLeaseCloseAndInvalidationOwnership', 'MIXED_LEASE_RELEASE', [edit(LEASE, 'l.once.Do(func() {', 'func() {'), edit(LEASE, '\t\t})', '\t\t}()')]),
 go('capture-lease-qualifies-sequence', 'TestEvaluationLeaseCloseAndInvalidationOwnership', 'LEASE_NO_SEQUENCE', [edit(LEASE, 'return &EvaluationLease{', 'o.sequence++; o.admitted.Store(o.sequence); return &EvaluationLease{')]),
 go('source-kind-reloaded-after-read', 'TestObservationSourceSelectionIsOneImmutableValue', 'SOURCE_SINGLE_LOAD', [edit(SOURCE, 'result.Provenance.Source = selected.kind', 'result.Provenance.Source = dmr.sourceKind()')], 'metricsreader'),
 go('source-generation-reloaded-after-read', 'TestObservationSourceSelectionIsOneImmutableValue', 'SOURCE_SINGLE_LOAD', [edit(SOURCE, 'result.Provenance.SourceGeneration = selected.generation', 'result.Provenance.SourceGeneration = dmr.source.Load().generation')], 'metricsreader'),
 go('source-ABA-reuses-generation', 'TestObservationSourceSelectionIsOneImmutableValue', 'SOURCE_ABA', [edit(SOURCE, 'generation = old.generation + 1', 'generation = uint64(source)')], 'metricsreader'),
 go('source-overflow-recovers', 'TestObservationIdentityExhaustionCannotRecover', 'SOURCE_GENERATION_OVERFLOW', [edit(SOURCE, 'generation = 0 // sticky', 'generation = 1 // sticky')], 'metricsreader'),
 go('prom-publication-uses-latest-registration', 'TestObservationPublicationRetainsOriginalRegistration', 'PUBLICATION_ORIGINAL_REGISTRATION', [edit(PROM, 'pr.lineage.publication(registrations[key])', 'pr.lineage.publication(pr.lineage.registered[key])')], 'metricsreader'),
 go('prom-unregister-erases-result', 'TestObservationPublicationRetainsOriginalRegistration', 'REMOVAL_RETAINS_RESULT', [edit(PROM, 'delete(pr.queryExprs, key)', 'delete(pr.queryExprs, key); delete(pr.queryResults, key)')], 'metricsreader'),
 go('prom-read-replaces-publication-with-registration', 'TestObservationPublicationRetainsOriginalRegistration', 'REMOVAL_RETAINS_PUBLICATION', [edit(LINEAGE, 'result.Provenance.ReadRegistration = q.registered[key]', 'result.Provenance.Publication = q.registered[key]; result.Provenance.ReadRegistration = q.registered[key]')], 'metricsreader'),
 go('backend-publication-identity-dropped', 'TestObservationBackendPublicationAndMissingRead', 'BACKEND_PUBLICATION_IDENTITY', [edit(BACKEND, 'br.lineage.publication(br.lineage.registered[ruleKey])', 'QueryProvenance{}')], 'metricsreader'),
 go('backend-unregister-erases-result', 'TestObservationBackendPublicationAndMissingRead', 'BACKEND_REMOVAL_RETAINS_TIMESTAMP', [edit(BACKEND, 'delete(br.queryRules, key)', 'delete(br.queryRules, key); delete(br.queryResults, key)')], 'metricsreader'),
 go('query-counter-wraps', 'TestObservationIdentityExhaustionCannotRecover', 'QUERY_IDENTITY_OVERFLOW', [edit(LINEAGE, 'if q.sequence == math.MaxUint64 {', 'if false {')], 'metricsreader'),
 go('cpu-provenance-refreshes-cache', 'TestFactorProvenanceDoesNotRefreshTimestampKeyedCaches', 'PROVENANCE_NOT_CACHE_KEY', [edit('pkg/balance/factor/factor_cpu.go', 'qr.UpdateTime != fc.lastMetricTime', 'qr.UpdateTime != fc.lastMetricTime || qr.Provenance.Publication != 0')], 'factor'),
 go('memory-provenance-refreshes-cache', 'TestFactorProvenanceDoesNotRefreshTimestampKeyedCaches', 'PROVENANCE_NOT_CACHE_KEY', [edit('pkg/balance/factor/factor_memory.go', 'qr.UpdateTime != fm.lastMetricTime', 'qr.UpdateTime != fm.lastMetricTime || qr.Provenance.Publication != 0')], 'factor'),
 go('health-provenance-refreshes-cache', 'TestFactorProvenanceDoesNotRefreshTimestampKeyedCaches', 'HEALTH_RETAINED_QUERY', [edit('pkg/balance/factor/factor_health.go', 'fh.indicators[i].queryFailureResult.UpdateTime != failureQR.UpdateTime', 'fh.indicators[i].queryFailureResult.UpdateTime != failureQR.UpdateTime || failureQR.Provenance.Publication != 0')], 'factor'),
 go('query-exhaustion-only-returns-zero', 'TestObservationExhaustionInvalidatesBoundOwnersBeforeAnyRead', 'READ_OWNER_INVALID_BEFORE_RETURN', [edit(LINEAGE, 'q.owners.invalidate(observation.SequenceExhausted)', '_ = q.owners')], 'metricsreader'),
 go('source-exhaustion-only-returns-zero', 'TestObservationExhaustionInvalidatesBoundOwnersBeforeAnyRead', 'READ_OWNER_INVALID_BEFORE_RETURN', [edit(SOURCE, 'dmr.observationOwners.invalidate(observation.SequenceExhausted)', '_ = dmr.observationOwners')], 'metricsreader'),
 go('missing-erases-exhaustion', 'TestObservationExhaustionInvalidatesBoundOwnersBeforeAnyRead', 'READ_EXHAUSTION_NOT_MISSING', [edit(LINEAGE, 'result.Provenance.Invalid = q.owners.failure', 'result.Provenance.Invalid = observation.Valid')], 'metricsreader'),
 go('late-owner-recovers-exhausted-source', 'TestObservationExhaustionInvalidatesBoundOwnersBeforeAnyRead', 'READ_EXHAUSTION_FRESH_OWNER', [edit(LINEAGE, 'owner.Invalidate(d.failure)', '_ = owner')], 'metricsreader'),
 go('source-owner-limit-plus-one', 'TestObservationOwnerBindingsAreBoundedAndDeduplicated', 'READ_OWNER_BOUND_PLUS_ONE', [edit(LINEAGE, 'len(d.owners) >= observation.MaxOwners', 'len(d.owners) > observation.MaxOwners')], 'metricsreader'),
]

if __name__ == '__main__':
    runner.main(['go','test','./pkg/balance/observation','./pkg/balance/metricsreader','./pkg/balance/factor','-run','TestRecorder|TestMixed|TestEvaluation|TestObservation|TestFactorProvenance','-count=1'])
