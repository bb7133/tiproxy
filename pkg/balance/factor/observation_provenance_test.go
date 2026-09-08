// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package factor

import (
	"maps"
	"testing"
	"time"

	"github.com/pingcap/tiproxy/pkg/balance/metricsreader"
	"github.com/prometheus/common/model"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestFactorProvenanceDoesNotRefreshTimestampKeyedCaches(t *testing.T) {
	now := time.Now().Add(-10 * time.Second)
	sampleTime := model.Time(now.UnixMilli())
	for _, name := range []string{"cpu", "memory"} {
		t.Run(name, func(t *testing.T) {
			qr := metricsreader.QueryResult{UpdateTime: now, Value: model.Matrix{
				createSampleStream([]float64{0.2, 0.3}, 0, sampleTime), createSampleStream([]float64{0.3, 0.4}, 1, sampleTime),
			}, Provenance: metricsreader.QueryProvenance{Producer: 1, Registration: 1, Publication: 2}}
			mr := &mockMetricsReader{qrs: map[string]metricsreader.QueryResult{name: qr}}
			backends := []scoredBackend{createBackend(0, 100, 100), createBackend(1, 100, 100)}
			var factor Factor
			var unchanged func()
			if name == "cpu" {
				cpu := NewFactorCPU(mr, zap.NewNop())
				factor = cpu
				updateScore(factor, backends)
				before := maps.Clone(cpu.snapshot)
				per := cpu.usagePerConn
				unchanged = func() {
					require.Equal(t, before, cpu.snapshot, "PROVENANCE_NOT_CACHE_KEY")
					require.Equal(t, per, cpu.usagePerConn)
				}
			} else {
				memory := NewFactorMemory(mr, zap.NewNop())
				factor = memory
				updateScore(factor, backends)
				before := maps.Clone(memory.snapshot)
				unchanged = func() { require.Equal(t, before, memory.snapshot, "PROVENANCE_NOT_CACHE_KEY") }
			}
			// A newly identified producer/publication is not Go's cache refresh key.
			// Changed sample values/times make a wrong metadata-triggered refresh visible.
			qr.Provenance = metricsreader.QueryProvenance{Producer: 8, Registration: 9, Publication: 10, SourceGeneration: 11}
			qr.Value = model.Matrix{createSampleStream([]float64{0.85, 0.89}, 0, sampleTime+1000), createSampleStream([]float64{0.85, 0.89}, 1, sampleTime+1000)}
			mr.qrs[name] = qr
			updateScore(factor, backends)
			unchanged()
		})
	}
	t.Run("health", func(t *testing.T) {
		mr := &mockMetricsReader{qrs: map[string]metricsreader.QueryResult{}}
		health := NewFactorHealth(mr, zap.NewNop())
		backends := []scoredBackend{createBackend(0, 100, 100), createBackend(1, 100, 100)}
		for _, key := range []string{"failure_pd", "total_pd", "failure_tikv", "total_tikv"} {
			mr.qrs[key] = metricsreader.QueryResult{UpdateTime: now, Value: model.Vector{
				&model.Sample{Metric: createSampleStream(nil, 0, sampleTime).Metric, Value: 1, Timestamp: sampleTime},
				&model.Sample{Metric: createSampleStream(nil, 1, sampleTime).Metric, Value: 1, Timestamp: sampleTime},
			}, Provenance: metricsreader.QueryProvenance{Producer: 1, Publication: 2}}
		}
		updateScore(health, backends)
		before := maps.Clone(health.snapshot)
		retained := health.indicators[0].queryFailureResult
		for key, qr := range mr.qrs {
			qr.Provenance.Publication = 20
			qr.Value = model.Vector{
				&model.Sample{Metric: createSampleStream(nil, 0, sampleTime).Metric, Value: 0, Timestamp: sampleTime + 1000},
				&model.Sample{Metric: createSampleStream(nil, 1, sampleTime).Metric, Value: 0, Timestamp: sampleTime + 1000},
			}
			mr.qrs[key] = qr
		}
		updateScore(health, backends)
		require.Equal(t, before, health.snapshot, "HEALTH_RETAINED_QUERY")
		require.Equal(t, retained, health.indicators[0].queryFailureResult, "HEALTH_RETAINED_PUBLICATION")
	})
}
