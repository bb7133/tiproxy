// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"fmt"
	"testing"

	controlpb "github.com/pingcap/tiproxy/pkg/controlbridge/pb"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
)

func TestRustMetricsCounterSequenceDedup(t *testing.T) {
	store := newRustMetricsStore()
	labels := map[string]string{LblBackend: "rust-sequence-test", LblCmdType: "Query"}
	counter := QueryTotalCounter.WithLabelValues(labels[LblBackend], labels[LblCmdType])
	before, err := ReadCounter(counter)
	require.NoError(t, err)
	batch := &controlpb.MetricsBatch{
		Sequence: 1,
		Metrics: []*controlpb.MetricDelta{{
			Name: "tiproxy_session_query_total", Labels: labels, CounterDelta: 3,
		}},
	}
	require.NoError(t, store.apply(7, batch))
	require.NoError(t, store.apply(7, batch))
	restarted := &controlpb.MetricsBatch{
		Sequence: 1,
		Metrics: []*controlpb.MetricDelta{{
			Name: "tiproxy_session_query_total", Labels: labels, CounterDelta: 2,
		}},
	}
	require.NoError(t, store.apply(8, restarted))
	require.NoError(t, store.apply(8, restarted))
	after, err := ReadCounter(counter)
	require.NoError(t, err)
	require.Equal(t, before+5, after)
}

func TestRustMetricsGaugeReconcilesAcrossEpoch(t *testing.T) {
	store := newRustMetricsStore()
	before, err := ReadGauge(ConnGauge)
	require.NoError(t, err)
	makeBatch := func(sequence uint64, value float64) *controlpb.MetricsBatch {
		return &controlpb.MetricsBatch{
			Sequence: sequence,
			Metrics: []*controlpb.MetricDelta{{
				Name: "tiproxy_server_connections", Gauge: value,
			}},
		}
	}
	require.NoError(t, store.apply(11, makeBatch(1, 5)))
	require.NoError(t, store.apply(12, makeBatch(2, 2)))
	after, err := ReadGauge(ConnGauge)
	require.NoError(t, err)
	require.Equal(t, before+2, after)
	// Leave the package-global gauge unchanged for other tests.
	require.NoError(t, store.apply(12, makeBatch(3, 0)))
}

func TestRustMetricsIgnoresStaleControlEpoch(t *testing.T) {
	store := newRustMetricsStore()
	require.NoError(t, store.apply(30, &controlpb.MetricsBatch{Sequence: 10}))
	require.NoError(t, store.apply(29, &controlpb.MetricsBatch{Sequence: 11}))
	require.Equal(t, uint64(30), store.lastEpoch)
	require.Equal(t, uint64(10), store.lastSequence)
}

func TestRustMetricsHistogramMergesExactBuckets(t *testing.T) {
	store := newRustMetricsStore()
	spec := rustMetricSpecs["tiproxy_session_query_duration_seconds"]
	labels := map[string]string{LblBackend: "rust-histogram-test", LblCmdType: "Query"}
	buckets := make([]uint64, len(spec.buckets))
	for i := 4; i < len(buckets); i++ {
		buckets[i] = 2
	}
	require.NoError(t, store.apply(13, &controlpb.MetricsBatch{
		Sequence: 1,
		Metrics: []*controlpb.MetricDelta{{
			Name: spec.name, Labels: labels, CounterDelta: 2,
			Gauge: 0.01, HistogramBucketDeltas: buckets,
		}},
	}))
	QueryDurationHistogram.WithLabelValues(labels[LblBackend], labels[LblCmdType]).Observe(0.02)
	collector := newMergedRustHistogramCollector(spec, store)
	metrics, err := Collect(collector)
	require.NoError(t, err)
	var found bool
	for _, metric := range metrics {
		values, ok := dtoLabelValues(metric, spec.labels)
		if !ok || values[0] != labels[LblBackend] || values[1] != labels[LblCmdType] {
			continue
		}
		found = true
		require.Equal(t, uint64(3), metric.GetHistogram().GetSampleCount())
		require.InDelta(t, 0.03, metric.GetHistogram().GetSampleSum(), 1e-12)
		require.Equal(t, uint64(0), metric.GetHistogram().GetBucket()[3].GetCumulativeCount())
		require.Equal(t, uint64(2), metric.GetHistogram().GetBucket()[4].GetCumulativeCount())
		require.Equal(t, uint64(3), metric.GetHistogram().GetBucket()[6].GetCumulativeCount())
	}
	require.True(t, found)

	originalRegistry := prometheus.NewRegistry()
	require.NoError(t, originalRegistry.Register(spec.local))
	originalFamilies, err := originalRegistry.Gather()
	require.NoError(t, err)
	var originalHelp string
	for _, family := range originalFamilies {
		if family.GetName() == spec.name {
			originalHelp = family.GetHelp()
		}
	}
	require.Equal(t, spec.help, originalHelp, "the bridge descriptor matches the existing metric")

	registry := prometheus.NewRegistry()
	require.NoError(t, registry.Register(collector))
	families, err := registry.Gather()
	require.NoError(t, err)
	var dashboardFamilyFound bool
	for _, family := range families {
		if family.GetName() != spec.name {
			continue
		}
		dashboardFamilyFound = true
		require.Equal(t, spec.help, family.GetHelp())
		require.NotEmpty(t, family.GetMetric())
	}
	require.True(t, dashboardFamilyFound, "the existing dashboard metric name is exported")
}

func TestRustMetricsRejectsUnboundedOrMalformedInput(t *testing.T) {
	store := newRustMetricsStore()
	tests := []*controlpb.MetricDelta{
		{Name: "unknown_metric"},
		{Name: "tiproxy_session_query_total", Labels: map[string]string{LblBackend: "a", LblCmdType: "unknown"}, CounterDelta: 1},
		{Name: "tiproxy_session_query_duration_seconds", Labels: map[string]string{LblBackend: "a", LblCmdType: "Query"}, CounterDelta: 1},
		{Name: "tiproxy_server_connections", Gauge: 1, CounterDelta: 1},
		{Name: "tiproxy_server_connections", Gauge: -1},
		{Name: "tiproxy_server_connections", Gauge: 1.5},
	}
	for i, metric := range tests {
		err := store.apply(20, &controlpb.MetricsBatch{Sequence: uint64(i + 1), Metrics: []*controlpb.MetricDelta{metric}})
		require.Error(t, err, i)
	}
}

func TestRustMetricsSeriesLimitCountsUniqueSeries(t *testing.T) {
	store := newRustMetricsStore()
	for i := 0; i < maxRustMetricSeries-1; i++ {
		store.series[rustSeries{name: "existing", values: fmt.Sprintf("%d", i)}] = struct{}{}
	}
	metric := &controlpb.MetricDelta{
		Name: "tiproxy_session_query_total",
		Labels: map[string]string{
			LblBackend: "rust-duplicate-series-test",
			LblCmdType: "Query",
		},
		CounterDelta: 1,
	}
	repeated := make([]*controlpb.MetricDelta, maxRustMetricsPerBatch)
	for i := range repeated {
		repeated[i] = metric
	}
	require.NoError(t, store.apply(22, &controlpb.MetricsBatch{Sequence: 1, Metrics: repeated}))
	require.Len(t, store.series, maxRustMetricSeries)
}

func TestRustMetricsDeleteBackendRemovesRemoteHistogram(t *testing.T) {
	store := newRustMetricsStore()
	spec := rustMetricSpecs["tiproxy_session_handshake_duration_seconds"]
	labels := map[string]string{LblBackend: "rust-delete-test"}
	buckets := make([]uint64, len(spec.buckets))
	require.NoError(t, store.apply(21, &controlpb.MetricsBatch{
		Sequence: 1,
		Metrics: []*controlpb.MetricDelta{{
			Name: spec.name, Labels: labels, CounterDelta: 1,
			Gauge: 1, HistogramBucketDeltas: buckets,
		}},
	}))
	require.Len(t, store.histogramSnapshot(spec.name), 1)
	store.deletePartial(prometheus.Labels{LblBackend: labels[LblBackend]})
	require.Empty(t, store.histogramSnapshot(spec.name))
}
