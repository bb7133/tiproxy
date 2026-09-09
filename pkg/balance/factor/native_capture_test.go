// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package factor

import (
	"context"
	"encoding/json"
	"math"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pingcap/tiproxy/lib/config"
	"github.com/pingcap/tiproxy/pkg/balance/metricsreader"
	"github.com/pingcap/tiproxy/pkg/balance/observation"
	"github.com/pingcap/tiproxy/pkg/balance/observer"
	"github.com/pingcap/tiproxy/pkg/balance/policy"
	"github.com/pingcap/tiproxy/pkg/controlbridge/shadow"
	"github.com/prometheus/common/model"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

type nativeTestReader struct {
	*mockMetricsReader
	owner               *observation.Owner
	reads               []string
	boundBeforeRegister bool
}

func (r *nativeTestReader) BindObservationOwner(o *observation.Owner) { r.owner = o }
func (r *nativeTestReader) AddQueryExpr(key string, expr metricsreader.QueryExpr, rule metricsreader.QueryRule) {
	r.boundBeforeRegister = r.owner != nil
}
func (r *nativeTestReader) GetQueryResult(key string) metricsreader.QueryResult {
	r.reads = append(r.reads, key)
	q := r.mockMetricsReader.GetQueryResult(key)
	q.Provenance = metricsreader.QueryProvenance{Cluster: 1, SourceGeneration: 1, Source: 2, Producer: 2, Registration: 3, Publication: 4, ReadRegistration: 3}
	return q
}

type nativeTestBackend struct {
	*mockBackend
	account     uint64
	getterCalls int
}

func (b *nativeTestBackend) ObservationAccount() uint64 { return b.account }
func (b *nativeTestBackend) ConnScore() int             { b.getterCalls++; return b.mockBackend.ConnScore() }

func nativeFixture(t *testing.T, balance string) (*FactorBasedBalance, *nativeTestReader, *observation.Recorder, *observation.Owner, []policy.BackendCtx) {
	t.Helper()
	r, err := observation.NewRecorder(observation.DefaultLimits(), 1, 2)
	require.NoError(t, err)
	t.Cleanup(r.Close)
	o := r.NewNativeOwner()
	d, err := r.Next(context.Background())
	require.NoError(t, err)
	d.Release()
	mr := &nativeTestReader{mockMetricsReader: newMockMetricsReader()}
	f := NewFactorBasedBalanceObserved(zap.NewNop(), mr, o, o.NextIdentity())
	cfg := config.NewConfig()
	cfg.Balance.Policy, cfg.Balance.RoutingPolicy = balance, config.RoutingPolicyIdlest
	f.Init(cfg)
	nativeDelivery(t, f, o, r).Release()
	backends := make([]policy.BackendCtx, 2)
	for i := range backends {
		b := &nativeTestBackend{mockBackend: newMockBackend(true, 10+i*10), account: o.NextIdentity()}
		b.id, b.addr = string(rune('a'+i)), string(rune('a'+i))+":4000"
		b.BackendInfo = observer.BackendInfo{IP: string(rune('a' + i)), StatusPort: 10080, ClusterName: "default"}
		backends[i] = b
	}
	return f, mr, r, o, backends
}

func nativeDelivery(t *testing.T, f *FactorBasedBalance, o *observation.Owner, r *observation.Recorder) *observation.Delivery {
	t.Helper()
	e := f.TakeObservation()
	require.NotNil(t, e, "NATIVE_COMPLETE_CAPTURE")
	require.True(t, o.PublishEvaluation(e), "NATIVE_COMPLETE_PUBLICATION")
	d, err := r.Next(context.Background())
	require.NoError(t, err)
	if path := os.Getenv("CP_ROUTE_NATIVE_FRAMES"); path != "" {
		file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		require.NoError(t, err)
		if d.Record.Evaluation.Native().ID == 1 {
			metadata, ok := r.NativeMetadata(d.Record.Epoch)
			require.True(t, ok)
			frame, err := shadow.EncodeNativeCoverage(metadata)
			require.NoError(t, err)
			_, err = file.Write(frame)
			require.NoError(t, err)
		}
		frame, err := shadow.EncodeEvaluation(d.Record)
		require.NoError(t, err)
		_, err = file.Write(frame)
		require.NoError(t, err)
		require.NoError(t, file.Close())
	}
	return d
}

func TestNativeEarlyExitAndOriginalBackend(t *testing.T) {
	f, mr, r, o, backends := nativeFixture(t, config.BalancePolicyResource)
	require.True(t, mr.boundBeforeRegister, "NATIVE_FACTORY_BEFORE_REGISTER")
	for _, entry := range []observation.EntryPoint{observation.EntryRoute, observation.EntryRouteable, observation.EntryBalance} {
		before := o.AdmittedSequence()
		switch entry {
		case observation.EntryRoute:
			require.Nil(t, f.BackendToRoute(nil))
		case observation.EntryRouteable:
			require.Empty(t, f.RouteableBackends(nil))
		case observation.EntryBalance:
			f.BackendsToBalance(backends[:1])
		}
		require.Equal(t, before, o.AdmittedSequence(), "NATIVE_NO_SEQUENCE_INSIDE_POLICY")
		d := nativeDelivery(t, f, o, r)
		n := d.Record.Evaluation.Native()
		require.Equal(t, entry, n.Entry)
		require.Zero(t, n.ReadCount, "NATIVE_EARLY_EXIT_NO_READS")
		require.Zero(t, n.SortedCount)
		require.Empty(t, mr.reads)
		d.Release()
	}
	result := f.BackendToRoute(backends)
	require.Same(t, backends[0], result, "NATIVE_ORIGINAL_BACKEND_IDENTITY")
	d := nativeDelivery(t, f, o, r)
	defer d.Release()
	n := d.Record.Evaluation.Native()
	require.Equal(t, []string{"failure_pd", "failure_tikv", "memory", "cpu"}, mr.reads, "NATIVE_HEALTH_CONDITIONAL_ORDER")
	require.EqualValues(t, 7, n.ReadCount, "NATIVE_EMPTY_READ_TAPE")
	require.Equal(t, observation.ClockHealthExpiry, n.Reads[4].Site, "NATIVE_HEALTH_ZERO_EXPIRY")
	require.Equal(t, observation.BackendConnScore, n.Backends[0].Seen&observation.BackendConnScore)
	require.Zero(t, n.Backends[0].Seen&observation.BackendInfo, "NATIVE_NO_INVENTED_METADATA_READ")
	require.EqualValues(t, 1<<16|10, n.Backends[0].Packed)
	require.EqualValues(t, 1<<16|20, n.Backends[1].Packed)
}

func TestNativeQueryCopiesFullSeriesAndRetainsHistory(t *testing.T) {
	f, mr, r, o, backends := nativeFixture(t, config.BalancePolicyResource)
	now := time.Now()
	matrix := model.Matrix{&model.SampleStream{Metric: model.Metric{"instance": "a:10080", "secret": "must-not-copy"}, Values: []model.SamplePair{{Timestamp: 1, Value: 0.1}, {Timestamp: 2, Value: 0.9}}}}
	mr.qrs["cpu"] = metricsreader.QueryResult{Value: matrix, UpdateTime: now}
	mr.qrs["memory"] = metricsreader.QueryResult{Value: matrix, UpdateTime: now}
	f.RouteableBackends(backends)
	d := nativeDelivery(t, f, o, r)
	e := d.Record.Evaluation
	n := e.Native()
	var cpu observation.NativeRead
	for _, read := range n.Reads[:n.ReadCount] {
		if read.Kind == observation.ReadQuery && read.Query == observation.QueryCPU {
			cpu = read
		}
	}
	copied := string(e.Range(cpu.Series))
	require.True(t, json.Valid([]byte(copied)))
	require.Contains(t, copied, `"1","4591870180066957722"`, "NATIVE_FULL_SERIES_FIRST")
	require.Contains(t, copied, `"2","4606281698874543309"`, "NATIVE_FULL_SERIES_LAST")
	require.NotContains(t, copied, "secret", "NATIVE_LABEL_ALLOWLIST")
	matrix[0].Values[0].Value = 0.6
	matrix[0].Metric["instance"] = "changed"
	require.Equal(t, copied, string(e.Range(cpu.Series)), "NATIVE_NO_QUERY_ALIAS")
	d.Release()
	f.RouteableBackends(backends)
	d = nativeDelivery(t, f, o, r)
	defer d.Release()
	n = d.Record.Evaluation.Native()
	for _, read := range n.Reads[:n.ReadCount] {
		require.NotEqual(t, observation.ClockCPUSnapshot, read.Site, "NATIVE_RAW_TIME_RETAINS_CPU_HISTORY")
		require.NotEqual(t, observation.ClockMemorySnapshot, read.Site, "NATIVE_RAW_TIME_RETAINS_MEMORY_HISTORY")
	}
}

func TestNativeConfigResourceLifetimeAndMissingPublication(t *testing.T) {
	f, _, r, o, backends := nativeFixture(t, config.BalancePolicyResource)
	first := f.capture.resource
	cfg := config.NewConfig()
	for _, balance := range []string{config.BalancePolicyLocation, config.BalancePolicyConnection, config.BalancePolicyResource} {
		cfg.Balance.Policy = balance
		f.SetConfig(cfg)
		d := nativeDelivery(t, f, o, r)
		n := d.Record.Evaluation.Native()
		switch balance {
		case config.BalancePolicyLocation:
			require.Equal(t, first, n.Resource, "NATIVE_RESOURCE_LOCATION_RETAINS")
		case config.BalancePolicyConnection:
			require.Zero(t, n.Resource, "NATIVE_RESOURCE_REVOKED")
		case config.BalancePolicyResource:
			require.NotZero(t, n.Resource)
			require.NotEqual(t, first, n.Resource, "NATIVE_RESOURCE_REENTRY_FRESH")
		}
		d.Release()
	}
	sequence := o.AdmittedSequence()
	f.RouteableBackends(backends)
	f.RouteableBackends(backends)
	require.False(t, o.Enabled(), "NATIVE_OMITTED_PUBLICATION_INVALID")
	require.Equal(t, sequence, o.AdmittedSequence(), "NATIVE_GAP_NO_CREDIT")
	require.Nil(t, f.TakeObservation())
}

func TestNativeCaptureLimitsDoNotChangeGoResult(t *testing.T) {
	f, mr, _, o, backends := nativeFixture(t, config.BalancePolicyResource)
	mr.qrs["cpu"] = metricsreader.QueryResult{Value: model.Matrix{&model.SampleStream{Metric: model.Metric{"instance": model.LabelValue(strings.Repeat("x", 513))}, Values: []model.SamplePair{{Value: model.SampleValue(math.NaN())}}}}, UpdateTime: time.Now()}
	require.Same(t, backends[0], f.BackendToRoute(backends), "NATIVE_LIMIT_PRESERVES_GO_RESULT")
	require.False(t, o.Enabled(), "NATIVE_STRING_PLUS_ONE_INVALID")
	require.Nil(t, f.TakeObservation())
}

// This fixture emits actual factor calls through the bounded production codec;
// the Rust checker derives history and outputs without a Go score oracle input.
func TestNativeFactorFrames(t *testing.T) {
	f, mr, r, o, backends := nativeFixture(t, config.BalancePolicyResource)
	for _, balance := range []string{config.BalancePolicyResource, config.BalancePolicyLocation, config.BalancePolicyConnection, config.BalancePolicyResource} {
		for _, routing := range []string{config.RoutingPolicyIdlest, config.RoutingPolicyRandom, config.RoutingPolicyPreferIdle} {
			cfg := config.NewConfig()
			cfg.Balance.Policy = balance
			cfg.Balance.RoutingPolicy = routing
			f.SetConfig(cfg)
			nativeDelivery(t, f, o, r).Release()
			for round := 0; round < 6; round++ {
				now := time.Now()
				tick := model.Time(now.UnixMilli())
				for _, key := range []string{"cpu", "memory"} {
					matrix := model.Matrix{}
					for i, b := range backends {
						matrix = append(matrix, &model.SampleStream{Metric: model.Metric{"instance": model.LabelValue(b.GetBackendInfo().IP + ":10080")}, Values: []model.SamplePair{{Timestamp: tick - 15000, Value: model.SampleValue(0.1 + float64(i)*0.2)}, {Timestamp: tick, Value: model.SampleValue(0.2 + float64(i)*0.6)}}})
					}
					if round == 0 || round == 3 {
						mr.qrs[key] = metricsreader.QueryResult{Value: matrix, UpdateTime: now}
					}
					if round == 2 {
						mr.qrs[key] = metricsreader.QueryResult{}
					}
				}
				for _, def := range errDefinitions {
					for _, key := range []string{def.failureKey, def.totalKey} {
						vector := model.Vector{}
						for i, b := range backends {
							value := model.SampleValue(100)
							if key == def.failureKey {
								value = model.SampleValue(i * 90)
							}
							vector = append(vector, &model.Sample{Metric: model.Metric{"instance": model.LabelValue(b.GetBackendInfo().IP + ":10080")}, Timestamp: tick, Value: value})
						}
						if round == 0 || round == 3 {
							mr.qrs[key] = metricsreader.QueryResult{Value: vector, UpdateTime: now}
						}
						if round == 2 {
							mr.qrs[key] = metricsreader.QueryResult{}
						}
					}
				}
				for i, b := range backends {
					mb := b.(*nativeTestBackend)
					mb.healthy = round != 4 || i == 0
					mb.local = i == 0
					mb.connScore = 10 + i*90
					mb.connCount = mb.connScore
				}
				f.BackendToRoute(backends)
				nativeDelivery(t, f, o, r).Release()
				f.RouteableBackends(backends)
				nativeDelivery(t, f, o, r).Release()
				f.BackendsToBalance(backends)
				nativeDelivery(t, f, o, r).Release()
				f.BackendToRoute(nil)
				nativeDelivery(t, f, o, r).Release()
				f.BackendsToBalance(backends[:1])
				nativeDelivery(t, f, o, r).Release()
			}
		}
	}
	// Exercise applied NaN/Inf configuration and resource values through actual
	// entry points. Query values are already producer outputs, never recast.
	for _, ratio := range []float64{math.NaN(), math.Inf(1), 0, 2} {
		cfg := config.NewConfig()
		cfg.Balance.Policy = config.BalancePolicyConnection
		cfg.Balance.ConnCount.CountRatioThreshold = ratio
		f.SetConfig(cfg)
		nativeDelivery(t, f, o, r).Release()
		for _, b := range backends {
			b.(*nativeTestBackend).healthy = true
		}
		f.BackendsToBalance(backends)
		nativeDelivery(t, f, o, r).Release()
	}
	cfg := config.NewConfig()
	cfg.Balance.Policy = config.BalancePolicyResource
	f.SetConfig(cfg)
	nativeDelivery(t, f, o, r).Release()
	for _, value := range []float64{math.NaN(), math.Inf(1), math.Inf(-1), 0.5} {
		now := time.Now()
		tick := model.Time(now.UnixMilli())
		for _, key := range []string{"cpu", "memory"} {
			matrix := model.Matrix{}
			for _, b := range backends {
				matrix = append(matrix, &model.SampleStream{Metric: model.Metric{"instance": model.LabelValue(b.GetBackendInfo().IP + ":10080")}, Values: []model.SamplePair{{Timestamp: tick - 8_000_000_000_000, Value: 0.4998}, {Timestamp: tick, Value: model.SampleValue(value)}}})
			}
			mr.qrs[key] = metricsreader.QueryResult{Value: matrix, UpdateTime: now}
		}
		f.BackendToRoute(backends)
		nativeDelivery(t, f, o, r).Release()
		f.BackendsToBalance(backends)
		nativeDelivery(t, f, o, r).Release()
	}

	// Raw Location identity and query shape are inputs, including wrong-kind
	// nonempty values and typed nil. No producer/source identity clears caches.
	baseTime := time.Now()
	var nilMatrix model.Matrix
	var nilVector model.Vector
	for _, value := range []model.Value{nil, nilMatrix, nilVector, model.Matrix{}, model.Vector{}, &model.Scalar{Value: 1}, &model.String{Value: "ignored"}} {
		for _, key := range []string{"cpu", "memory", "failure_pd", "total_pd", "failure_tikv", "total_tikv"} {
			mr.qrs[key] = metricsreader.QueryResult{Value: value, UpdateTime: baseTime}
		}
		f.BackendToRoute(backends)
		nativeDelivery(t, f, o, r).Release()
		f.BackendsToBalance(backends)
		nativeDelivery(t, f, o, r).Release()
	}
	for round := 0; round < 3; round++ {
		now := baseTime.In(time.FixedZone("same-name", 0))
		tick := model.Time(baseTime.UnixMilli() + int64(round))
		b := backends[0].(*nativeTestBackend)
		b.addr = "x-tidb-0.x-tidb-peer.ns.svc:4000"
		b.BackendInfo = observer.BackendInfo{IP: "ignored", StatusPort: 10080, ClusterName: "  default  "}
		other := backends[1].(*nativeTestBackend)
		other.addr = "[::1]:4000"
		other.BackendInfo = observer.BackendInfo{IP: "::1", StatusPort: ^uint(0), ClusterName: "beta"}
		for _, key := range []string{"cpu", "memory"} {
			matrix := model.Matrix{}
			for index, instance := range []string{"x-tidb-0", "[::1]:-1"} {
				cluster := "default"
				if index == 1 {
					cluster = "beta"
				}
				for _, label := range []string{"wrong", cluster, cluster} {
					matrix = append(matrix, &model.SampleStream{Metric: model.Metric{metricsreader.LabelNameInstance: model.LabelValue(instance), metricsreader.LabelNameCluster: model.LabelValue(label)}, Values: []model.SamplePair{{Timestamp: tick - 15000, Value: 0.1}, {Timestamp: tick, Value: model.SampleValue(0.2 + float64(round)*0.2)}}})
				}
			}
			mr.qrs[key] = metricsreader.QueryResult{Value: matrix, UpdateTime: now}
		}
		f.BackendToRoute(backends)
		nativeDelivery(t, f, o, r).Release()
		f.BackendsToBalance(backends)
		nativeDelivery(t, f, o, r).Release()
	}

	// Equal discrete CPU scores must still execute the negative CPU advice
	// before considering the lower-priority connection imbalance.
	cfg = config.NewConfig()
	cfg.Balance.Policy = config.BalancePolicyConnection
	f.SetConfig(cfg)
	nativeDelivery(t, f, o, r).Release()
	cfg.Balance.Policy = config.BalancePolicyResource
	f.SetConfig(cfg)
	nativeDelivery(t, f, o, r).Release()
	mr.qrs = make(map[string]metricsreader.QueryResult)
	now := time.Now()
	tick := model.Time(now.UnixMilli())
	cpu := model.Matrix{}
	for i, backend := range backends {
		b := backend.(*nativeTestBackend)
		b.id, b.addr = string(rune('a'+i)), string(rune('a'+i))+":4000"
		b.BackendInfo = observer.BackendInfo{IP: b.id, StatusPort: 10080, ClusterName: "default"}
		b.healthy, b.local = true, true
		b.connCount, b.connScore = 1+i*19, 1+i*19
		cpu = append(cpu, &model.SampleStream{Metric: model.Metric{metricsreader.LabelNameInstance: model.LabelValue(b.id + ":10080")}, Values: []model.SamplePair{{Timestamp: tick, Value: model.SampleValue(0.5 + float64(i)*0.01)}}})
	}
	mr.qrs["cpu"] = metricsreader.QueryResult{Value: cpu, UpdateTime: now}
	from, _, _, _, _ := f.BackendsToBalance(backends)
	require.Nil(t, from, "NATIVE_EQUAL_CPU_NEGATIVE_VETO")
	nativeDelivery(t, f, o, r).Release()

	// Keep two equal choices for both ticket laws. Check the actual output
	// against the captured seed, not just the presence of a clock read.
	for _, routing := range []string{config.RoutingPolicyPreferIdle, config.RoutingPolicyRandom} {
		cfg = config.NewConfig()
		cfg.Balance.Policy = config.BalancePolicyConnection
		cfg.Balance.RoutingPolicy = routing
		f.SetConfig(cfg)
		nativeDelivery(t, f, o, r).Release()
		for _, backend := range backends {
			b := backend.(*nativeTestBackend)
			b.connCount, b.connScore = 10, 10
			b.healthy, b.local = true, true
		}
		chosen := f.BackendToRoute(backends)
		require.NotNil(t, chosen)
		d := nativeDelivery(t, f, o, r)
		native := d.Record.Evaluation.Native()
		require.EqualValues(t, 2, native.SortedCount, "NATIVE_TICKET_TWO_CHOICES")
		require.Equal(t, native.Backends[0].Packed, native.Backends[1].Packed, "NATIVE_TICKET_EQUAL_VECTORS")
		choices := []uint8{native.Sorted[1], native.Sorted[0]} // prefer-idle walks worst to best
		site := observation.ClockPreferIdleTicket
		if routing == config.RoutingPolicyRandom {
			choices = []uint8{native.Sorted[0], native.Sorted[1]}
			site = observation.ClockRandomTicket
		}
		tickets := 0
		for _, read := range native.Reads[:native.ReadCount] {
			if read.Kind != observation.ReadClock || read.Site != site {
				continue
			}
			tickets++
			// GoTimeValue seconds start at year one; recover UnixMicro from
			// that captured instant without taking another clock reading.
			yearOneUnix := time.Date(1, time.January, 1, 0, 0, 0, 0, time.UTC).Unix()
			seed := time.Unix(read.Time.Seconds+yearOneUnix, int64(read.Time.Nanoseconds)).UnixMicro()
			n := int64(len(choices))
			index := seed % n
			if routing == config.RoutingPolicyRandom {
				index = seed % (n*10 + 1) % n
			}
			require.EqualValues(t, 1, native.ReturnedCount, "NATIVE_TICKET_ONE_RESULT")
			require.Equal(t, choices[index], native.Returned[0], "NATIVE_TICKET_VALUE %s", routing)
			require.Same(t, backends[choices[index]], chosen, "NATIVE_TICKET_ORIGINAL_BACKEND %s", routing)
		}
		require.Equal(t, 1, tickets, "NATIVE_TICKET_REACHED %s", routing)
		d.Release()
	}

	f.Close()
	nativeDelivery(t, f, o, r).Release()
	require.True(t, o.Enabled())
}
