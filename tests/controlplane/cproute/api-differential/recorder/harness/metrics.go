// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build apireplay

package harness

import (
	"encoding/json"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/pingcap/tiproxy/pkg/balance/metricsreader"
	replaymetrics "github.com/pingcap/tiproxy/tests/controlplane/cproute/api-differential/metrics"
	"github.com/pingcap/tiproxy/tests/controlplane/cproute/api-differential/recorder/apireplay"
	"github.com/prometheus/common/model"
)

// These are the external query names registered by the three resource factors.
// The recorder samples the entire fixed set, independently of getter calls.
var metricKeys = replaymetrics.Keys

// Wire types are shared with the replay decoder; no private provenance crosses them.
type MetricSample = replaymetrics.Sample
type MetricSeries = replaymetrics.Series
type MetricResult = replaymetrics.Result

func copyMetricResult(q metricsreader.QueryResult) (*MetricResult, metricsreader.QueryResult, error) {
	if q.Value == nil {
		return nil, metricsreader.QueryResult{}, nil
	}
	r := &MetricResult{Series: []MetricSeries{}}
	if !q.UpdateTime.IsZero() {
		n := q.UpdateTime.UnixNano()
		if !q.UpdateTime.Equal(time.Unix(0, n)) {
			return nil, metricsreader.QueryResult{}, fmt.Errorf("metric update time outside nanosecond range")
		}
		r.UpdatedNanos = &n
	}
	// A private deep copy isolates published routing inputs from later source
	// writes. Provenance is deliberately neither copied nor serialized.
	copyResult := metricsreader.QueryResult{UpdateTime: q.UpdateTime}
	copyLabels := func(labels model.Metric) (map[string]string, model.Metric) {
		wire, copied := map[string]string{}, model.Metric{}
		for k, v := range labels {
			wire[string(k)], copied[k] = string(v), v
		}
		return wire, copied
	}
	sample := func(t model.Time, v model.SampleValue) MetricSample {
		return MetricSample{TimestampMillis: int64(t), Value: strconv.FormatFloat(float64(v), 'g', -1, 64)}
	}
	switch value := q.Value.(type) {
	case model.Vector:
		if value == nil {
			return nil, metricsreader.QueryResult{}, nil
		}
		r.Kind = "vector"
		copied := make(model.Vector, 0, len(value))
		for _, v := range value {
			if v == nil {
				return nil, metricsreader.QueryResult{}, fmt.Errorf("nil metric vector sample")
			}
			labels, metric := copyLabels(v.Metric)
			r.Series = append(r.Series, MetricSeries{Labels: labels, Samples: []MetricSample{sample(v.Timestamp, v.Value)}})
			copied = append(copied, &model.Sample{Metric: metric, Timestamp: v.Timestamp, Value: v.Value})
		}
		copyResult.Value = copied
	case model.Matrix:
		if value == nil {
			return nil, metricsreader.QueryResult{}, nil
		}
		r.Kind = "matrix"
		copied := make(model.Matrix, 0, len(value))
		for _, v := range value {
			if v == nil {
				return nil, metricsreader.QueryResult{}, fmt.Errorf("nil metric matrix series")
			}
			labels, metric := copyLabels(v.Metric)
			series := MetricSeries{Labels: labels, Samples: []MetricSample{}}
			for _, pair := range v.Values {
				series.Samples = append(series.Samples, sample(pair.Timestamp, pair.Value))
			}
			r.Series = append(r.Series, series)
			copied = append(copied, &model.SampleStream{Metric: metric, Values: append([]model.SamplePair(nil), v.Values...)})
		}
		copyResult.Value = copied
	default:
		return nil, metricsreader.QueryResult{}, fmt.Errorf("unsupported external metric result shape")
	}
	return r, copyResult, nil
}

// MetricsInputs publishes whole external query sets under the same scheduler
// as health and public router calls. GetQueryResult reads the last publication;
// it does not consult or record the live reader. No getter tape is produced.
type MetricsInputs struct {
	sched    *Scheduler
	source   metricsreader.MetricsQuerier
	mu       sync.RWMutex
	current  map[string]metricsreader.QueryResult
	previous string
	observed bool
}

func NewMetricsInputs(sched *Scheduler, source metricsreader.MetricsQuerier) *MetricsInputs {
	return &MetricsInputs{sched: sched, source: source, current: map[string]metricsreader.QueryResult{}}
}

func (m *MetricsInputs) AddQueryExpr(key string, expr metricsreader.QueryExpr, rule metricsreader.QueryRule) {
	m.source.AddQueryExpr(key, expr, rule)
}
func (m *MetricsInputs) RemoveQueryExpr(key string) { m.source.RemoveQueryExpr(key) }
func (m *MetricsInputs) GetBackendMetrics() []byte  { return m.source.GetBackendMetrics() }
func (m *MetricsInputs) GetQueryResult(key string) metricsreader.QueryResult {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.current[key]
}

// Observed reports actual nonempty input data, not merely an existing reader.
func (m *MetricsInputs) Observed() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.observed
}

// Publish samples all queries at a declared metrics tick, then atomically
// installs and records the copied set. A bad result retains the previous set
// and records an incomplete-capture error; it cannot publish a partial set.
func (m *MetricsInputs) Publish(at int64) {
	m.sched.Run(at, func() {
		wire := make(map[string]*MetricResult, len(metricKeys))
		next := make(map[string]metricsreader.QueryResult, len(metricKeys))
		observed := false
		for _, key := range metricKeys {
			result, copied, err := copyMetricResult(m.source.GetQueryResult(key))
			if err != nil {
				m.sched.Record(apireplay.Event{Op: "recorder_error", Outcome: fmt.Sprintf("metrics %s: %v", key, err)})
				return
			}
			wire[key], next[key] = result, copied
			observed = observed || !copied.Empty()
		}
		data, err := json.Marshal(wire)
		if err != nil {
			m.sched.Record(apireplay.Event{Op: "recorder_error", Outcome: "metric publication encoding failed"})
			return
		}
		m.mu.Lock()
		defer m.mu.Unlock()
		if string(data) == m.previous {
			return // unchanged whole inputs need no repeated event
		}
		m.current, m.previous = next, string(data)
		m.observed = m.observed || observed
		m.sched.Record(apireplay.Event{Op: "metrics", Metrics: data})
	})
}
