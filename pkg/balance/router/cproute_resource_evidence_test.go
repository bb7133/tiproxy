// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package router

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pingcap/tiproxy/lib/config"
	"github.com/pingcap/tiproxy/pkg/balance/factor"
	"github.com/pingcap/tiproxy/pkg/balance/metricsreader"
	"github.com/pingcap/tiproxy/pkg/balance/observer"
	"github.com/pingcap/tiproxy/pkg/balance/policy"
	"github.com/prometheus/common/model"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// Only query values are fixtures. Real Group.Route owns health/retry filtering,
// factor invocation and pending increments; real setFactors owns registration.
type cpResourceReader struct {
	queries       map[string]metricsreader.QueryExpr
	now           time.Time
	empty         bool
	adds, removes int
	cpuReads      int
}

func (r *cpResourceReader) AddQueryExpr(key string, expr metricsreader.QueryExpr, _ metricsreader.QueryRule) {
	r.queries[key] = expr
	r.adds++
}
func (r *cpResourceReader) RemoveQueryExpr(key string) {
	delete(r.queries, key)
	r.removes++
}
func (*cpResourceReader) GetBackendMetrics() []byte { return nil }
func (r *cpResourceReader) GetQueryResult(key string) metricsreader.QueryResult {
	if key == "cpu" {
		r.cpuReads++
	}
	expr, exists := r.queries[key]
	if r.empty || !exists {
		return metricsreader.QueryResult{}
	}
	values := [2]float64{10, 10}
	if strings.Contains(expr.PromQL, "irate") {
		values = [2]float64{0.2, 0.8}
	} else if expr.Range > 0 {
		values = [2]float64{0.2, 0.2}
	} else if strings.Contains(expr.PromQL, "failed_cmds") || strings.Contains(expr.PromQL, "backoff_seconds") {
		values = [2]float64{5, 0}
	}
	vector := model.Vector{}
	matrix := model.Matrix{}
	for index, value := range values {
		metric := model.Metric{metricsreader.LabelNameInstance: model.LabelValue(fmt.Sprintf("127.0.0.1:%d", 10080+index))}
		pair := model.SamplePair{Timestamp: model.TimeFromUnixNano(r.now.UnixNano()), Value: model.SampleValue(value)}
		matrix = append(matrix, &model.SampleStream{Metric: metric, Values: []model.SamplePair{pair}})
		vector = append(vector, &model.Sample{Metric: metric, Timestamp: pair.Timestamp, Value: pair.Value})
	}
	var value model.Value = vector
	if expr.Range > 0 {
		value = matrix
	}
	return metricsreader.QueryResult{Value: value, UpdateTime: r.now}
}

func TestCPRouteResourceObservation(t *testing.T) {
	output := os.Getenv("CPROUTE_RESOURCE_OUTPUT")
	if output == "" {
		t.Skip("run make controlplane-cproute-resource-evidence")
	}
	reader := &cpResourceReader{queries: make(map[string]metricsreader.QueryExpr), now: time.Now()}
	group, err := NewGroup(nil, func(lg *zap.Logger) policy.BalancePolicy {
		return factor.NewFactorBasedBalance(lg, reader)
	}, MatchAll, zap.NewNop())
	require.NoError(t, err)
	for index := range 2 {
		addr := fmt.Sprintf("127.0.0.1:%d", 4000+index)
		backend := newBackendWrapper(addr, observer.BackendHealth{BackendInfo: observer.BackendInfo{
			Addr: addr, IP: "127.0.0.1", StatusPort: uint(index + 10080),
		}, Healthy: true, Local: index == 0})
		for range 10 {
			backend.connList.PushBack(&connWrapper{})
		}
		backend.connScore = 12
		group.AddBackend(addr, backend)
	}
	cfg := config.NewConfig()
	cfg.Balance.Policy = config.BalancePolicyConnection
	group.SetConfig(cfg)
	require.Empty(t, reader.queries)
	outcomes := make(map[string]string)
	route := func(name string, excluded []BackendInst) {
		backend, routeErr := group.Route(excluded)
		require.NoError(t, routeErr, name)
		selected := backend.(*backendWrapper)
		require.Equal(t, 13, selected.connScore, name)
		require.Equal(t, 10, selected.ConnCount(), name)
		selected.connScore--
		outcomes[name] = selected.ID()
	}
	cfg.Balance.Policy = config.BalancePolicyResource
	group.SetConfig(cfg)
	require.Len(t, reader.queries, 6)
	route("resource", nil)
	cfg.Balance.LabelName = "zone"
	cfg.Labels = map[string]string{"zone": "z0"}
	health := group.backends["127.0.0.1:4000"].getHealth()
	health.Labels = map[string]string{"zone": "z0"}
	group.backends["127.0.0.1:4000"].setHealth(health)
	group.SetConfig(cfg)
	reads := reader.cpuReads
	route("label", nil)
	require.Greater(t, reader.cpuReads, reads, "Group.Route retains label-mismatched members in the factor pool")
	cfg.Balance.LabelName = ""
	cfg.Balance.Policy = config.BalancePolicyLocation
	group.SetConfig(cfg)
	route("location", nil)
	require.Equal(t, 6, reader.adds, "Resource/Location retain queries")
	require.Zero(t, reader.removes)
	cfg.Balance.Policy = config.BalancePolicyResource
	group.SetConfig(cfg)
	reader.empty = true
	route("missing", nil)
	reader.empty = false
	route("restored", nil)
	route("retry", []BackendInst{group.backends["127.0.0.1:4001"]})
	cfg.Balance.Policy = config.BalancePolicyConnection
	group.SetConfig(cfg)
	require.Empty(t, reader.queries)
	require.Equal(t, 6, reader.removes)
	cfg.Balance.Policy = config.BalancePolicyResource
	group.SetConfig(cfg)
	require.Equal(t, 12, reader.adds)
	route("recreated", nil)
	// Strictly discriminate a bypassed Resource path: actual extra physical
	// connections make Connection prefer A while health still makes Resource B.
	cfg.Balance.Policy = config.BalancePolicyConnection
	group.SetConfig(cfg)
	var extra []*mockRedirectableConn
	for i := range 4 {
		conn := newMockRedirectableConn(t, uint64(100+i))
		_, ok := group.RehydrateConn("127.0.0.1:4001", conn)
		require.True(t, ok)
		extra = append(extra, conn)
	}
	for _, step := range []struct{ name, policy, wanted string }{
		{"connection_strict", config.BalancePolicyConnection, "127.0.0.1:4000"},
		{"resource_strict", config.BalancePolicyResource, "127.0.0.1:4001"},
	} {
		cfg.Balance.Policy = step.policy
		group.SetConfig(cfg)
		backend, err := group.Route(nil)
		require.NoError(t, err)
		require.Equal(t, step.wanted, backend.ID(), step.name)
		backend.(*backendWrapper).connScore--
		outcomes[step.name] = backend.ID()
	}
	for _, conn := range extra {
		require.NoError(t, group.OnConnClosed("127.0.0.1:4001", conn))
	}
	require.Equal(t, 10, group.backends["127.0.0.1:4001"].ConnCount())
	require.Equal(t, 12, group.backends["127.0.0.1:4001"].ConnScore())
	data, err := json.Marshal(outcomes)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(output, data, 0o600))
	t.Logf("CP-ROUTE-COMPOSE actual Go Group.Route: %s; six queries removed/recreated", data)
}
