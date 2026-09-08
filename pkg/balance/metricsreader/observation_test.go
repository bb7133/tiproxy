// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package metricsreader

import (
	"context"
	"math"
	"sync"
	"testing"
	"time"

	"github.com/pingcap/tiproxy/pkg/balance/observation"
	"github.com/prometheus/common/model"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func diagnosticReader(t *testing.T) *ClusterReader {
	t.Helper()
	return NewDefaultMetricsReader(zap.NewNop(), nil, nil, nil, nil, newHealthCheckConfigForTest(), nil)
}

func TestObservationSourceSelectionIsOneImmutableValue(t *testing.T) {
	r := diagnosticReader(t)
	r.promReader.queryResults["cpu"] = QueryResult{Value: model.Vector{&model.Sample{Value: 11}}}
	r.backendReader.queryResults["cpu"] = QueryResult{Value: model.Vector{&model.Sample{Value: 22}}}
	require.Equal(t, sourceNone, r.sourceKind())
	r.setSource(sourceProm, nil)
	selected := r.source.Load()
	r.setSource(sourceBackend, nil)
	// Force publication between selection and the real reader getter. Production
	// uses this same function; it must never reload source to annotate the value.
	old := r.queryResultFromSelection("cpu", selected)
	require.Equal(t, model.SampleValue(11), old.Value.(model.Vector)[0].Value)
	require.Equal(t, sourceProm, old.Provenance.Source, "SOURCE_SINGLE_LOAD")
	require.EqualValues(t, 1, old.Provenance.SourceGeneration, "SOURCE_SINGLE_LOAD")
	latest := r.GetQueryResult("cpu")
	require.Equal(t, model.SampleValue(22), latest.Value.(model.Vector)[0].Value)
	require.Equal(t, sourceBackend, latest.Provenance.Source)
	require.EqualValues(t, 2, latest.Provenance.SourceGeneration)
	r.setSource(sourceProm, nil)
	aba := r.GetQueryResult("cpu")
	require.EqualValues(t, 3, aba.Provenance.SourceGeneration, "SOURCE_ABA")
	r.setSource(sourceProm, nil)
	require.Equal(t, aba.Provenance, r.GetQueryResult("cpu").Provenance, "SOURCE_NO_FALSE_ROTATION")
	other := diagnosticReader(t)
	require.NotEqual(t, r.identity, other.identity, "SOURCE_READER_INCARNATION")
	require.NotEqual(t, r.promReader.lineage.producer, r.backendReader.lineage.producer)
}

func TestObservationSourceConcurrentReadersAndWriters(t *testing.T) {
	r := diagnosticReader(t)
	r.setSource(sourceProm, nil)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for range 1000 {
			r.setSource(sourceBackend, nil)
			r.setSource(sourceProm, nil)
		}
	}()
	for range 1000 {
		p := r.GetQueryResult("missing").Provenance
		if p.SourceGeneration%2 == 1 {
			require.Equal(t, sourceProm, p.Source, "SOURCE_ATOMIC_PAIR")
		} else {
			require.Equal(t, sourceBackend, p.Source, "SOURCE_ATOMIC_PAIR")
		}
	}
	wg.Wait()
}

func TestObservationPublicationRetainsOriginalRegistration(t *testing.T) {
	handler := newMockHttpHandler(t)
	port := handler.Start()
	t.Cleanup(handler.Close)
	entered, resume := make(chan struct{}), make(chan struct{})
	var once sync.Once
	f := func(string) string {
		once.Do(func() { close(entered); <-resume })
		return `{"status":"success","data":{"resultType":"vector","result":[{"metric":{"instance":"a"},"value":[1000,"1"]}]}}`
	}
	handler.getRespBody.Store(&f)
	pr := NewPromReader(zap.NewNop(), newMockPromFetcher(port), newHealthCheckConfigForTest())
	pr.AddQueryExpr("cpu", QueryExpr{PromQL: "cpu"})
	registration := pr.lineage.registered["cpu"]
	done := make(chan error, 1)
	go func() { done <- pr.ReadMetrics(context.Background()) }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("publication did not enter actual HTTP query")
	}
	pr.RemoveQueryExpr("cpu")
	pr.AddQueryExpr("cpu", QueryExpr{PromQL: "replacement"})
	replacement := pr.lineage.registered["cpu"]
	close(resume)
	require.NoError(t, <-done)
	result := pr.GetQueryResult("cpu")
	require.False(t, result.Empty())
	require.Equal(t, registration, result.Provenance.Registration, "PUBLICATION_ORIGINAL_REGISTRATION")
	require.Equal(t, replacement, result.Provenance.ReadRegistration)
	require.NotZero(t, result.Provenance.Publication, "PUBLICATION_IDENTITY")
	require.NotEqual(t, registration, replacement, "QUERY_REGISTRATION_ABA")
	pr.RemoveQueryExpr("cpu")
	retained := pr.GetQueryResult("cpu")
	require.Equal(t, result.Value, retained.Value, "REMOVAL_RETAINS_RESULT")
	require.Equal(t, result.UpdateTime, retained.UpdateTime, "REMOVAL_RETAINS_TIMESTAMP")
	require.Equal(t, result.Provenance.Publication, retained.Provenance.Publication, "REMOVAL_RETAINS_PUBLICATION")
	require.Equal(t, registration, retained.Provenance.Registration)
	require.Zero(t, retained.Provenance.ReadRegistration)
}

func TestObservationBackendPublicationAndMissingRead(t *testing.T) {
	r := diagnosticReader(t)
	br := r.backendReader
	br.AddQueryRule("cpu", QueryRule{ResultType: model.ValMatrix})
	br.history["cpu"] = map[string]backendHistory{"a": {Step2History: []model.SamplePair{{Timestamp: 1000, Value: 0.5}}}}
	br.history2QueryResult()
	first := br.GetQueryResult("cpu")
	require.NotZero(t, first.Provenance.Producer)
	require.NotZero(t, first.Provenance.Publication, "BACKEND_PUBLICATION_IDENTITY")
	require.Equal(t, first.Provenance.Registration, first.Provenance.ReadRegistration)
	br.history2QueryResult()
	second := br.GetQueryResult("cpu")
	require.Greater(t, second.Provenance.Publication, first.Provenance.Publication, "BACKEND_NEW_PUBLICATION")
	br.RemoveQueryRule("cpu")
	retained := br.GetQueryResult("cpu")
	require.Equal(t, second.UpdateTime, retained.UpdateTime, "BACKEND_REMOVAL_RETAINS_TIMESTAMP")
	require.Equal(t, second.Provenance.Publication, retained.Provenance.Publication)
	require.Zero(t, retained.Provenance.ReadRegistration)
	br.AddQueryRule("cpu", QueryRule{ResultType: model.ValMatrix})
	require.NotEqual(t, second.Provenance.Registration, br.GetQueryResult("cpu").Provenance.ReadRegistration, "BACKEND_REGISTRATION_ABA")
	missing := br.GetQueryResult("missing")
	require.True(t, missing.Empty())
	require.Equal(t, first.Provenance.Producer, missing.Provenance.Producer)
	require.Zero(t, missing.Provenance.Publication)
}

func TestObservationIdentityExhaustionCannotRecover(t *testing.T) {
	q := newQueryLineage()
	q.sequence = math.MaxUint64 - 1
	q.add("cpu")
	require.EqualValues(t, uint64(math.MaxUint64), q.registered["cpu"])
	require.Zero(t, q.publication(q.registered["cpu"]).Publication, "QUERY_IDENTITY_OVERFLOW")
	q.add("cpu")
	require.Zero(t, q.registered["cpu"], "QUERY_IDENTITY_OVERFLOW")
	require.Zero(t, q.next())
	r := diagnosticReader(t)
	r.source.Store(&sourceSelection{kind: sourceProm, generation: math.MaxUint64})
	r.setSource(sourceBackend, nil)
	require.Equal(t, sourceBackend, r.GetQueryResult("missing").Provenance.Source)
	require.Zero(t, r.GetQueryResult("missing").Provenance.SourceGeneration, "SOURCE_GENERATION_OVERFLOW")
	r.setSource(sourceProm, nil)
	require.Zero(t, r.GetQueryResult("missing").Provenance.SourceGeneration, "SOURCE_GENERATION_OVERFLOW")
}

func TestObservationExhaustionInvalidatesBoundOwnersBeforeAnyRead(t *testing.T) {
	for _, boundary := range []string{"registration", "publication", "source"} {
		t.Run(boundary, func(t *testing.T) {
			r := diagnosticReader(t)
			recorder, err := observation.NewRecorder(observation.DefaultLimits(), 10, 20)
			require.NoError(t, err)
			t.Cleanup(recorder.Close)
			first, second := recorder.NewOwner(), recorder.NewOwner()
			r.BindObservationOwner(first)
			r.BindObservationOwner(second)
			r.setSource(sourceBackend, nil)
			br := r.backendReader
			br.AddQueryRule("cpu", QueryRule{ResultType: model.ValMatrix})
			br.history["cpu"] = map[string]backendHistory{"a": {Step2History: []model.SamplePair{{Timestamp: 1000, Value: 0.5}}}}
			switch boundary {
			case "registration":
				br.lineage.sequence = math.MaxUint64
				br.AddQueryRule("memory", QueryRule{})
			case "publication":
				br.lineage.sequence = math.MaxUint64
				br.history2QueryResult()
			case "source":
				r.source.Store(&sourceSelection{kind: sourceProm, generation: math.MaxUint64})
				r.setSource(sourceBackend, nil)
			}
			// No GetQueryResult or Rust consumer has run since exhaustion. The source
			// itself has already invalidated every bound Go owner and preserved its
			// last admitted prefix. A later missing result cannot erase this boundary.
			require.False(t, first.Enabled(), "READ_OWNER_INVALID_BEFORE_RETURN")
			require.False(t, second.Enabled(), "READ_OWNER_INVALID_BEFORE_RETURN")
			for _, summary := range recorder.InvalidOwners() {
				require.Equal(t, observation.SequenceExhausted, summary.Reason)
				require.EqualValues(t, 1, summary.LastAdmitted, "READ_EXHAUSTION_NO_PROGRESS")
			}
			missing := r.GetQueryResult("missing")
			require.True(t, missing.Empty())
			require.Equal(t, observation.SequenceExhausted, missing.Provenance.Invalid, "READ_EXHAUSTION_NOT_MISSING")
			require.Nil(t, first.LeaseEvaluation(), "READ_EXHAUSTION_NO_CAPTURE")
			fresh := recorder.NewOwner()
			r.BindObservationOwner(fresh)
			require.False(t, fresh.Enabled(), "READ_EXHAUSTION_FRESH_OWNER")
			require.Equal(t, observation.SequenceExhausted, recorder.InvalidOwners()[2].Reason)
			if boundary == "publication" {
				// Diagnostics never discard Go's real publication or change its value.
				result := r.GetQueryResult("cpu")
				require.Equal(t, model.SampleValue(0.5), result.Value.(model.Matrix)[0].Values[0].Value)
			}
		})
	}
}

func TestObservationOwnerBindingsAreBoundedAndDeduplicated(t *testing.T) {
	r := diagnosticReader(t)
	recorder, err := observation.NewRecorder(observation.DefaultLimits(), 10, 20)
	require.NoError(t, err)
	t.Cleanup(recorder.Close)
	owners := make([]*observation.Owner, observation.MaxOwners)
	for i := range owners {
		owners[i] = recorder.NewOwner()
		for range 3 {
			r.BindObservationOwner(owners[i])
		}
		require.True(t, owners[i].Enabled(), "READ_OWNER_BOUND_EQUALITY")
	}
	require.Len(t, r.observationOwners.owners, observation.MaxOwners)
	require.Len(t, r.promReader.lineage.owners.owners, observation.MaxOwners)
	require.Len(t, r.backendReader.lineage.owners.owners, observation.MaxOwners)
	other, err := observation.NewRecorder(observation.DefaultLimits(), 11, 21)
	require.NoError(t, err)
	t.Cleanup(other.Close)
	extra := other.NewOwner()
	r.BindObservationOwner(extra)
	require.False(t, extra.Enabled(), "READ_OWNER_BOUND_PLUS_ONE")
	for _, owner := range owners {
		require.False(t, owner.Enabled(), "READ_OWNER_BOUND_ALL_INVALID")
	}
	require.Len(t, r.observationOwners.owners, observation.MaxOwners, "READ_OWNER_BOUND_RETAINED")
	require.Equal(t, observation.Capacity, other.InvalidOwners()[0].Reason)
}
