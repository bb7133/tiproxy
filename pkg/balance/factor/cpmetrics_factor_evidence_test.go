// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package factor

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/pingcap/tiproxy/lib/config"
	"github.com/pingcap/tiproxy/pkg/balance/metricsreader"
	"github.com/pingcap/tiproxy/pkg/balance/observer"
	"github.com/pingcap/tiproxy/pkg/balance/policy"
	"github.com/prometheus/common/model"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// Only the evidence runner's temporary production-clock overlay reads these.
var cpFactorNow time.Time
var cpFactorTicket int64

type cpFactorBackend struct {
	ID      string `json:"id"`
	Cluster string `json:"cluster"`
	Active  int    `json:"active"`
	Pending int    `json:"pending"`
	Healthy bool   `json:"healthy"`
	Local   bool   `json:"local"`
	Label   bool   `json:"label"`
}
type cpFactorSample struct {
	Time  int64  `json:"time"`
	Value string `json:"value"`
}
type cpFactorSeries struct {
	Instance string           `json:"instance"`
	Cluster  string           `json:"cluster"`
	Samples  []cpFactorSample `json:"samples"`
}
type cpFactorQuery struct {
	Time   int64            `json:"time"`
	Matrix bool             `json:"matrix"`
	Series []cpFactorSeries `json:"series"`
}
type cpFactorAdvice struct {
	Kind  int    `json:"kind"`
	Count string `json:"count"`
}
type cpFactorScore struct {
	ID        string           `json:"id"`
	Score     uint64           `json:"score"`
	Parts     []uint64         `json:"parts"`
	Routeable bool             `json:"routeable"`
	Advice    []cpFactorAdvice `json:"advice"`
}
type cpFactorExpected struct {
	Scores []cpFactorScore `json:"scores"`
	Random map[string]int  `json:"random"`
	Prefer map[string]int  `json:"prefer"`
}
type cpFactorStep struct {
	Now      int64                    `json:"now"`
	Policy   string                   `json:"policy"`
	Label    string                   `json:"label"`
	Rates    [6]float64               `json:"rates"`
	Ratio    float64                  `json:"ratio"`
	Backends []cpFactorBackend        `json:"backends"`
	Queries  map[string]cpFactorQuery `json:"queries"`
	Expected cpFactorExpected         `json:"expected"`
}
type cpFactorCase struct {
	Name  string         `json:"name"`
	Steps []cpFactorStep `json:"steps"`
}

func cpFactorBase() cpFactorStep {
	return cpFactorStep{Now: 1000 * int64(time.Second), Policy: "resource", Backends: []cpFactorBackend{
		{ID: "a", Active: 100, Healthy: true, Local: true, Label: true},
		{ID: "b", Active: 100, Healthy: true, Local: false, Label: true},
	}, Queries: make(map[string]cpFactorQuery)}
}
func cpFactorCopy(s cpFactorStep) cpFactorStep {
	bytes, _ := json.Marshal(s)
	var out cpFactorStep
	_ = json.Unmarshal(bytes, &out)
	return out
}
func cpFactorPut(s *cpFactorStep, key string, index int, values ...string) {
	matrix := key == "cpu" || key == "memory"
	q := s.Queries[key]
	q.Time, q.Matrix = s.Now, matrix
	b := s.Backends[index]
	series := cpFactorSeries{Instance: b.ID + ":10080", Cluster: b.Cluster}
	for i, value := range values {
		series.Samples = append(series.Samples, cpFactorSample{Time: s.Now/int64(time.Millisecond) - int64(len(values)-1-i)*15000, Value: value})
	}
	q.Series = append(q.Series, series)
	s.Queries[key] = q
}
func cpFactorCases() []cpFactorCase {
	var cases []cpFactorCase
	add := func(name string, steps ...cpFactorStep) { cases = append(cases, cpFactorCase{name, steps}) }
	for _, policy := range []string{"resource", "location", "connection"} {
		s := cpFactorBase()
		s.Policy = policy
		cpFactorPut(&s, "cpu", 0, "0.95")
		cpFactorPut(&s, "cpu", 1, "0.1")
		cpFactorPut(&s, "memory", 0, "0.76")
		cpFactorPut(&s, "memory", 1, "0.2")
		add("order-"+policy, s)
	}
	for _, usage := range []string{"0", "0.049999", "0.05", "0.1", "0.6", "0.600001", "0.75", "0.750001", "0.9", "1.2", "NaN", "+Inf", "-Inf", "-0.1"} {
		for _, key := range []string{"cpu", "memory"} {
			s := cpFactorBase()
			cpFactorPut(&s, key, 0, usage)
			cpFactorPut(&s, key, 1, "0.2")
			add(key+"-value-"+usage, s)
		}
	}
	for _, key := range []string{"pd", "tikv"} {
		for _, pair := range [][2]string{{"0", "0"}, {"1", "0"}, {"1", "10"}, {"1.00001", "10"}, {"3", "10"}, {"4.99999", "10"}, {"5", "10"}, {"NaN", "1"}, {"1", "NaN"}, {"+Inf", "+Inf"}} {
			s := cpFactorBase()
			cpFactorPut(&s, "failure_"+key, 0, pair[0])
			cpFactorPut(&s, "total_"+key, 0, pair[1])
			add("health-"+key+"-"+pair[0]+"-"+pair[1], s)
		}
	}
	s := cpFactorBase()
	cpFactorPut(&s, "cpu", 0, "0", "0.55")
	cpFactorPut(&s, "cpu", 1, "0.1")
	add("cpu-ewma", s)
	s = cpFactorBase()
	cpFactorPut(&s, "cpu", 0, "0.1")
	cpFactorPut(&s, "cpu", 1, "0.9")
	s.Backends[0].Pending = 20
	next := cpFactorCopy(s)
	next.Backends[0].Pending = 200
	add("cpu-pending-active-only-snapshot", s, next)
	next = cpFactorCopy(s)
	next.Now += int64(time.Second)
	next.Queries = make(map[string]cpFactorQuery)
	cpFactorPut(&next, "cpu", 0, "0.0001")
	cpFactorPut(&next, "cpu", 1, "0.0001")
	next.Backends[0].Pending = 100
	add("cpu-idle-per-connection-reuse", s, next)
	for _, key := range []string{"cpu", "memory"} {
		s = cpFactorBase()
		cpFactorPut(&s, key, 0, "0.8")
		cpFactorPut(&s, key, 1, "0.2")
		next = cpFactorCopy(s)
		next.Now += int64(time.Second)
		next.Queries = make(map[string]cpFactorQuery)
		cpFactorPut(&next, key, 1, "0.3")
		equal := cpFactorCopy(s)
		q := equal.Queries[key]
		q.Series[0].Samples[0].Value = "0.1"
		equal.Queries[key] = q
		add(key+"-equal-query-time-keeps-cache", s, equal)
		equal = cpFactorCopy(s)
		q = equal.Queries[key]
		q.Time++
		q.Series[0].Samples[0].Value = "0.1"
		equal.Queries[key] = q
		add(key+"-equal-sample-time-keeps-cache", s, equal)
		add(key+"-temporary-missing-keeps-cache", s, next)
		expiry := int64(time.Minute)
		if key == "cpu" {
			expiry *= 2
		}
		boundary := cpFactorCopy(s)
		boundary.Now += expiry
		expired := cpFactorCopy(boundary)
		expired.Now++
		add(key+"-global-expiry-strict", s, boundary, expired)
		fresh := cpFactorCopy(s)
		fresh.Now += expiry
		fresh.Queries = make(map[string]cpFactorQuery)
		cpFactorPut(&fresh, key, 1, "0.3")
		old := s.Queries[key].Series[0]
		q = fresh.Queries[key]
		q.Series = append(q.Series, old)
		fresh.Queries[key] = q
		stale := cpFactorCopy(fresh)
		stale.Now++
		q = stale.Queries[key]
		q.Time++
		stale.Queries[key] = q
		add(key+"-sample-expiry-strict-fresh-sibling", s, fresh, stale)
		empty := cpFactorCopy(s)
		empty.Queries = make(map[string]cpFactorQuery)
		add(key+"-empty-contributes-zero", s, empty)
	}
	for _, history := range [][]string{{"0.5", "0.7"}, {"0.7", "0.7"}, {"0.8", "0.7"}, {"NaN", "0.7"}, {"0.5", "NaN", "0.8"}} {
		s = cpFactorBase()
		cpFactorPut(&s, "memory", 0, history...)
		cpFactorPut(&s, "memory", 1, "0.2")
		add(fmt.Sprint("memory-horizon-", history), s)
	}
	for _, delta := range []int64{9999, 10000} {
		s = cpFactorBase()
		cpFactorPut(&s, "memory", 0, "0.5", "0.7")
		q := s.Queries["memory"]
		q.Series[0].Samples[0].Time = q.Series[0].Samples[1].Time - delta
		s.Queries["memory"] = q
		cpFactorPut(&s, "memory", 1, "0.2")
		add(fmt.Sprint("memory-history-min-", delta), s)
	}
	s = cpFactorBase()
	cpFactorPut(&s, "memory", 0, "0.76")
	cpFactorPut(&s, "memory", 1, "0.2")
	next = cpFactorCopy(s)
	next.Now += int64(time.Second)
	next.Backends[0].Active = 10
	next.Queries = make(map[string]cpFactorQuery)
	cpFactorPut(&next, "memory", 0, "0.76")
	cpFactorPut(&next, "memory", 1, "0.2")
	add("memory-preserve-migration-count", s, next)
	s = cpFactorBase()
	cpFactorPut(&s, "failure_pd", 0, "5")
	cpFactorPut(&s, "total_pd", 0, "10")
	next = cpFactorCopy(s)
	next.Now += int64(time.Second)
	next.Backends[0].Active = 10
	q := next.Queries["failure_pd"]
	q.Time++
	next.Queries["failure_pd"] = q
	add("health-preserve-migration-count", s, next)
	next = cpFactorCopy(s)
	next.Queries = make(map[string]cpFactorQuery)
	cpFactorPut(&next, "failure_tikv", 1, "0")
	cpFactorPut(&next, "total_tikv", 1, "10")
	next.Now += int64(time.Second)
	add("health-missing-indicator-keeps-prior-query", s, next)
	next = cpFactorCopy(s)
	next.Queries = make(map[string]cpFactorQuery)
	cpFactorPut(&next, "failure_pd", 1, "0")
	cpFactorPut(&next, "total_pd", 1, "10")
	q = next.Queries["failure_pd"]
	q.Time++
	next.Queries["failure_pd"] = q
	add("health-backend-missing-default-normal", s, next)
	for _, mode := range []string{"label", "status", "singleton", "none-routeable", "rates", "connection-clamp"} {
		s = cpFactorBase()
		cpFactorPut(&s, "cpu", 0, "0.95")
		cpFactorPut(&s, "cpu", 1, "0.1")
		switch mode {
		case "label":
			s.Label = "business"
			s.Backends[0].Label = false
		case "status":
			s.Backends[0].Healthy = false
		case "singleton":
			s.Backends = s.Backends[:1]
		case "none-routeable":
			s.Backends[0].Healthy = false
			s.Backends[1].Healthy = false
		case "rates":
			s.Rates = [6]float64{2, 3, 4, 5, 6, 7}
			s.Ratio = 1.5
		case "connection-clamp":
			s.Policy = "connection"
			s.Backends[0].Active = 65535
			s.Backends[1].Active = 65536
		}
		add(mode, s)
	}
	s = cpFactorBase()
	cpFactorPut(&s, "cpu", 0, "0.8")
	cpFactorPut(&s, "cpu", 1, "0.2")
	next = cpFactorCopy(s)
	next.Policy = "connection"
	after := cpFactorCopy(s)
	after.Queries = make(map[string]cpFactorQuery)
	cpFactorPut(&after, "cpu", 1, "0.2")
	add("policy-reset-resources", s, next, after)

	// Global max query time remains fresh while cluster-a's individual CPU
	// cache expires. The reader merge itself is observed in the 221-1 suite.
	s = cpFactorBase()
	s.Backends[0].Cluster = "cluster-a"
	s.Backends[1].Cluster = "cluster-b"
	cpFactorPut(&s, "cpu", 0, "0.2")
	cpFactorPut(&s, "cpu", 1, "0.8")
	next = cpFactorCopy(s)
	next.Now += 121 * int64(time.Second)
	next.Queries = make(map[string]cpFactorQuery)
	cpFactorPut(&next, "cpu", 1, "0.3")
	q = next.Queries["cpu"]
	q.Series = append(q.Series, s.Queries["cpu"].Series[0])
	next.Queries["cpu"] = q
	add("two-cluster-global-fresh-stale-cache", s, next)
	for _, previous := range []string{"0.339999999", "0.34", "0.340000001", "0.459999999", "0.46", "0.460000001"} {
		s = cpFactorBase()
		cpFactorPut(&s, "memory", 0, previous, "0.5")
		cpFactorPut(&s, "memory", 1, "0.2")
		add("memory-horizon-threshold-"+previous, s)
	}
	s = cpFactorBase()
	cpFactorPut(&s, "failure_pd", 0, "5")
	cpFactorPut(&s, "total_pd", 0, "10")
	next = cpFactorCopy(s)
	next.Now += int64(time.Minute)
	after = cpFactorCopy(next)
	after.Now++
	add("health-global-expiry-strict", s, next, after)
	next = cpFactorCopy(s)
	next.Queries = make(map[string]cpFactorQuery)
	add("health-empty-score-old-advice", s, next)
	next = cpFactorCopy(s)
	q = next.Queries["failure_pd"]
	q.Series[0].Samples[0].Time -= 600000
	next.Queries["failure_pd"] = q
	add("health-expiry-uses-query-not-sample-time", next)
	s = cpFactorBase()
	s.Backends[0].Healthy = false
	next = cpFactorCopy(s)
	next.Now += int64(time.Second)
	next.Backends[0].Active = 1
	add("status-preserves-migration-count", s, next)
	return cases
}

func TestCPMetricsFactorObservation(t *testing.T) {
	output := os.Getenv("CPMETRICS_FACTOR_OUTPUT")
	if output == "" {
		t.Skip("run factor evidence runner")
	}
	require.Equal(t, "1", os.Getenv("CPMETRICS_FACTOR_CLOCK"))
	cases := cpFactorCases()
	for ci := range cases {
		reader := newMockMetricsReader()
		fbb := NewFactorBasedBalance(zap.NewNop(), reader)
		for si := range cases[ci].Steps {
			s := &cases[ci].Steps[si]
			cpFactorNow = time.Unix(0, s.Now)
			cfg := config.NewConfig()
			cfg.Balance.Policy = s.Policy
			cfg.Balance.LabelName = s.Label
			cfg.Labels = map[string]string{s.Label: "yes"}
			cfg.Balance.Status.MigrationsPerSecond = s.Rates[0]
			cfg.Balance.Health.MigrationsPerSecond = s.Rates[1]
			cfg.Balance.Memory.MigrationsPerSecond = s.Rates[2]
			cfg.Balance.CPU.MigrationsPerSecond = s.Rates[3]
			cfg.Balance.Location.MigrationsPerSecond = s.Rates[4]
			cfg.Balance.ConnCount.MigrationsPerSecond = s.Rates[5]
			cfg.Balance.ConnCount.CountRatioThreshold = s.Ratio
			fbb.SetConfig(cfg)
			var backends []policy.BackendCtx
			for _, b := range s.Backends {
				label := "no"
				if b.Label {
					label = "yes"
				}
				backends = append(backends, &mockBackend{id: b.ID, addr: b.ID + ":4000", connCount: b.Active, connScore: b.Active + b.Pending, healthy: b.Healthy, local: b.Local,
					BackendInfo: observer.BackendInfo{IP: b.ID, StatusPort: 10080, ClusterName: b.Cluster, Labels: map[string]string{s.Label: label}}})
			}
			reader.qrs = make(map[string]metricsreader.QueryResult)
			for key, q := range s.Queries {
				var matrix model.Matrix
				var vector model.Vector
				for _, series := range q.Series {
					labels := model.Metric{"instance": model.LabelValue(series.Instance)}
					cluster := series.Cluster
					if cluster == "" {
						cluster = "default"
					}
					labels["tiproxy_cluster"] = model.LabelValue(cluster)
					var pairs []model.SamplePair
					for _, sample := range series.Samples {
						value, err := strconv.ParseFloat(sample.Value, 64)
						require.NoError(t, err)
						pairs = append(pairs, model.SamplePair{Timestamp: model.Time(sample.Time), Value: model.SampleValue(value)})
					}
					if q.Matrix {
						matrix = append(matrix, &model.SampleStream{Metric: labels, Values: pairs})
					} else if len(pairs) > 0 {
						vector = append(vector, &model.Sample{Metric: labels, Timestamp: pairs[0].Timestamp, Value: pairs[0].Value})
					}
				}
				qr := metricsreader.QueryResult{UpdateTime: time.Unix(0, q.Time)}
				if q.Matrix {
					qr.Value = matrix
				} else {
					qr.Value = vector
				}
				reader.qrs[key] = qr
			}
			scored := fbb.updateScore(backends)
			for _, b := range scored {
				row := cpFactorScore{ID: b.ID(), Score: b.scoreBits, Routeable: fbb.canBeRouted(b.scoreBits)}
				left := fbb.totalBitNum
				for _, factor := range fbb.factors {
					bits := factor.ScoreBitNum()
					row.Parts = append(row.Parts, b.scoreBits<<uint(64-left)>>uint(64-bits))
					left -= bits
					advice, count, _ := factor.BalanceCount(b, scored[0])
					row.Advice = append(row.Advice, cpFactorAdvice{int(advice), strconv.FormatFloat(count, 'g', 17, 64)})
				}
				s.Expected.Scores = append(s.Expected.Scores, row)
			}
			// Both public routeable and selection methods execute the actual factors.
			actual := fbb.RouteableBackends(backends)
			want := 0
			for _, row := range s.Expected.Scores {
				if row.Routeable {
					want++
				}
			}
			require.Len(t, actual, want)
			for _, route := range []string{"random", "prefer-idle"} {
				fbb.routePolicy = route
				weights := map[string]int{}
				for _, b := range backends {
					weights[b.ID()] = 0
				}
				for cpFactorTicket = 0; cpFactorTicket < 63; cpFactorTicket++ {
					chosen := fbb.BackendToRoute(backends)
					if chosen != nil {
						weights[chosen.ID()]++
					}
				}
				if route == "random" {
					s.Expected.Random = weights
				} else {
					s.Expected.Prefer = weights
				}
			}
		}
		fbb.Close()
	}
	bytes, err := json.Marshal(cases)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(output, bytes, 0600))
	t.Logf("actual Go factor scenarios=%d", len(cases))
}
