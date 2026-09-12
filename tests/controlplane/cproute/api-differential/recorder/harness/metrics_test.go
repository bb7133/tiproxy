// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build apireplay

package harness

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pingcap/tiproxy/lib/config"
	"github.com/pingcap/tiproxy/pkg/balance/factor"
	"github.com/pingcap/tiproxy/pkg/balance/metricsreader"
	"github.com/pingcap/tiproxy/pkg/balance/observer"
	"github.com/pingcap/tiproxy/pkg/balance/policy"
	"github.com/pingcap/tiproxy/pkg/balance/router"
	configmgr "github.com/pingcap/tiproxy/pkg/manager/config"
	replaymetrics "github.com/pingcap/tiproxy/tests/controlplane/cproute/api-differential/metrics"
	"github.com/pingcap/tiproxy/tests/controlplane/cproute/api-differential/recorder/apireplay"
	"github.com/prometheus/common/model"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

type metricsSource struct {
	emptyMetrics
	results map[string]metricsreader.QueryResult
	reads   int
}

func (m *metricsSource) GetQueryResult(key string) metricsreader.QueryResult {
	m.reads++
	return m.results[key]
}

func TestMetricWirePreservesSpecialValuesOrderAndTimes(t *testing.T) {
	now := time.Unix(1_790_000_000, 123456789)
	values := []float64{math.Copysign(0, -1), math.NaN(), math.Inf(1), math.Inf(-1), 0.12345678901234567}
	pairs := make([]model.SamplePair, len(values))
	for i, v := range values {
		pairs[i] = model.SamplePair{Timestamp: model.Time(123 - i), Value: model.SampleValue(v)}
	}
	source := model.Matrix{&model.SampleStream{Metric: model.Metric{"instance": "b", "tiproxy_cluster": "second"}, Values: pairs},
		&model.SampleStream{Metric: model.Metric{"instance": "b", "extra": "first-match-order"}}}
	wire, copied, err := copyMetricResult(metricsreader.QueryResult{Value: source, UpdateTime: now})
	require.NoError(t, err)
	require.Equal(t, now.UnixNano(), *wire.UpdatedNanos)
	require.Equal(t, []MetricSample{{123, "-0"}, {122, "NaN"}, {121, "+Inf"}, {120, "-Inf"}, {119, "0.12345678901234566"}}, wire.Series[0].Samples)
	encoded, err := json.Marshal(wire)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), "Provenance")
	packet := map[string]*replaymetrics.Result{}
	for _, key := range replaymetrics.Keys {
		packet[key] = nil
	}
	packet["cpu"] = wire
	replayed, err := replaymetrics.Decode(packet)
	require.NoError(t, err)
	roundtrip, _, err := copyMetricResult(replayed["cpu"])
	require.NoError(t, err)
	encodedAgain, err := json.Marshal(roundtrip)
	require.NoError(t, err)
	require.JSONEq(t, string(encoded), string(encodedAgain))
	source[0].Metric["instance"] = "changed"
	source[0].Values[0].Value = 1
	require.Equal(t, "b", wire.Series[0].Labels["instance"])
	require.Equal(t, model.LabelValue("b"), copied.Value.(model.Matrix)[0].Metric["instance"])
	require.True(t, math.Signbit(float64(copied.Value.(model.Matrix)[0].Values[0].Value)))
	require.Empty(t, wire.Series[1].Samples)
	for _, stamp := range []time.Time{{}, time.Unix(0, 0)} {
		result, _, err := copyMetricResult(metricsreader.QueryResult{Value: model.Vector{}, UpdateTime: stamp})
		require.NoError(t, err)
		require.Equal(t, stamp.IsZero(), result.UpdatedNanos == nil)
	}
}

func TestMetricPublicationFailureRetainsWholePreviousSet(t *testing.T) {
	sched, err := NewScheduler(filepath.Join(t.TempDir(), "archive.jsonl"))
	require.NoError(t, err)
	defer func() { require.NoError(t, sched.Close()) }()
	source := &metricsSource{results: map[string]metricsreader.QueryResult{}}
	m := NewMetricsInputs(sched, source)
	m.Publish(0)
	require.False(t, m.Observed())
	source.results["cpu"] = metricsreader.QueryResult{Value: model.Matrix{&model.SampleStream{}}}
	source.results["memory"] = metricsreader.QueryResult{Value: &model.Scalar{}}
	m.Publish(1)
	require.True(t, m.GetQueryResult("cpu").Empty(), "do not install the prefix of a rejected whole set")
	require.False(t, m.Observed())
	require.Equal(t, "recorder_error", sched.Log()[1].Event.Op)
	for _, value := range []model.Value{model.Matrix{nil}, model.Vector{nil}, &model.Scalar{}} {
		_, _, err := copyMetricResult(metricsreader.QueryResult{Value: value})
		require.Error(t, err)
	}
}

// The external reader is synthetic; the factor, router, API recorder and
// archive writer are real. This is producer evidence, not a paired replay.
func TestRecordedWholeMetricsDriveRealRouter(t *testing.T) {
	dir := os.Getenv("CPROUTE_RECORDED_METRICS")
	if dir == "" {
		dir = t.TempDir()
	} else {
		require.NoError(t, os.Mkdir(dir, 0o755))
	}
	sched, err := NewScheduler(filepath.Join(dir, "archive.jsonl"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, sched.Close()) })
	cfg := configmgr.NewConfigManager()
	require.NoError(t, cfg.SetTOMLConfig([]byte("[balance]\npolicy='resource'\nrouting-policy='prefer-idle'\n")))
	lg := zap.NewNop()
	source := &metricsSource{results: map[string]metricsreader.QueryResult{}}
	m := NewMetricsInputs(sched, source)
	bo := observer.NewDefaultBackendObserver(lg, config.NewDefaultHealthCheckConfig(), observer.NewStaticFetcher(nil), healthyCheck{}, cfg)
	rt := router.NewScoreBasedRouter(lg)
	driver := router.NewReplayDriver(rt, manualRefreshObserver{bo}, func(lg *zap.Logger) policy.BalancePolicy {
		return factor.NewFactorBasedBalance(lg, m)
	}, cfg)
	t.Cleanup(rt.Close)
	apireplay.Install(sched, "metric")
	t.Cleanup(func() { apireplay.Install(nil, "s") })
	inputs := NewInputs(sched, driver)
	backends := map[string]*observer.BackendHealth{}
	for i, addr := range []string{"127.0.0.1:4000", "127.0.0.1:4001"} {
		backends[addr] = &observer.BackendHealth{BackendInfo: observer.BackendInfo{Addr: addr, IP: "127.0.0.1", StatusPort: uint(10080 + i)}, Healthy: true, Local: true}
	}
	inputs.Deliver(observer.NewHealthResult(backends, nil))
	now := time.Now()
	matrix := model.Matrix{
		&model.SampleStream{Metric: model.Metric{"instance": "127.0.0.1:10080"}, Values: []model.SamplePair{{Timestamp: model.Time(now.UnixMilli()), Value: 0.1}}},
		&model.SampleStream{Metric: model.Metric{"instance": "127.0.0.1:10081"}, Values: []model.SamplePair{{Timestamp: model.Time(now.UnixMilli()), Value: 0.9}}},
	}
	source.results["cpu"] = metricsreader.QueryResult{Value: matrix, UpdateTime: now}
	m.Publish(10)
	require.True(t, m.Observed())
	route := func(want string) {
		sel, session := apireplay.Open(rt, router.ClientInfo{})
		b, err := apireplay.Next(&sel, session)
		require.NoError(t, err)
		require.Equal(t, want, b.ID())
		apireplay.Finish(&sel, session, nil, false)
		apireplay.EndSelection(&sel, session)
	}
	route("127.0.0.1:4000")
	require.Equal(t, 6, source.reads, "factor getter calls cannot read or append live source inputs")
	for i := range matrix {
		matrix[i].Values[0].Value = 1 - matrix[i].Values[0].Value
		matrix[i].Values[0].Timestamp++
	}
	source.results["cpu"] = metricsreader.QueryResult{Value: matrix, UpdateTime: now.Add(time.Nanosecond)}
	route("127.0.0.1:4000") // source changes cannot enter before a public publication
	m.Publish(20)
	route("127.0.0.1:4001")
	require.Equal(t, 12, source.reads)
	before := len(sched.Log())
	m.Publish(21)
	require.Len(t, sched.Log(), before, "unchanged query sets do not add getter-like records")
	source.results = map[string]metricsreader.QueryResult{}
	m.Publish(30)
	require.True(t, m.GetQueryResult("cpu").Empty(), "empty replacement removes the published input")
	checkpoints := map[int]Checkpoint{}
	sched.RunNow(func() {
		seq := sched.Seq()
		checkpoints[seq] = Checkpoint{Seq: seq, Assignments: map[string]string{}, ConnCount: rt.ConnCount(), HealthyBackendCount: rt.HealthyBackendCount(), ServerVersion: rt.ServerVersion()}
		sched.Record(apireplay.Event{Op: "checkpoint"})
	})
	require.NoError(t, sched.Close())
	origin := sched.OriginNanos()
	status, err := Write(dir, "metrics-producer", "a1", TraceConfig{Policy: "resource", Selection: "prefer-idle", ClockOriginNanos: &origin}, sched.Log(), checkpoints, nil, m.Observed(), CaptureSummary{Synthetic: true})
	require.NoError(t, err)
	require.Equal(t, "recorded", status)
	data, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	require.NoError(t, err)
	var manifest map[string]any
	require.NoError(t, json.Unmarshal(data, &manifest))
	require.Equal(t, []any{"metrics-input"}, manifest["requires"])
	require.Equal(t, false, manifest["qualified"])
}
