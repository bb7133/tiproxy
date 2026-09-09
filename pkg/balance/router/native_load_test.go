// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package router

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pingcap/tiproxy/lib/config"
	"github.com/pingcap/tiproxy/pkg/balance/factor"
	"github.com/pingcap/tiproxy/pkg/balance/metricsreader"
	"github.com/pingcap/tiproxy/pkg/balance/observation"
	"github.com/pingcap/tiproxy/pkg/balance/observer"
	"github.com/pingcap/tiproxy/pkg/balance/policy"
	shadowwire "github.com/pingcap/tiproxy/pkg/controlbridge/shadow"
	"github.com/pingcap/tiproxy/pkg/manager/infosync"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
)

// Stdout and stderr share this writer, so os/exec serializes writes. The
// buffer is inspected only after Wait; startup uses its separate one-shot signal.
type nativeLoadOutput struct {
	buffer    *bytes.Buffer
	connected chan struct{}
	signaled  bool
}

func (w *nativeLoadOutput) Write(data []byte) (int, error) {
	n, err := w.buffer.Write(data)
	if !w.signaled && bytes.Contains(w.buffer.Bytes(), []byte("native_consumer_connected\n")) {
		w.signaled = true
		close(w.connected)
	}
	return n, err
}

// Timings are test-only. Each call includes native factor work and capture;
// seal is the separate arena finalization, not an estimate of all copy CPU time.
type nativeLoadTimings struct {
	sync.Mutex
	samples [4][]time.Duration
}

func (m *nativeLoadTimings) record(kind int, started time.Time) {
	elapsed := time.Since(started)
	if m == nil {
		return
	}
	m.Lock()
	m.samples[kind] = append(m.samples[kind], elapsed)
	m.Unlock()
}
func (m *nativeLoadTimings) report(t *testing.T) {
	t.Helper()
	m.Lock()
	defer m.Unlock()
	for kind, name := range []string{"route_call", "routeable_call", "balance_call", "capture_seal"} {
		require.NotEmpty(t, m.samples[kind], "NATIVE_REQUIRED_ENTRYPOINT %s", name)
		t.Logf("%s_count=%d %s_%s", name, len(m.samples[kind]), name, percentiles(m.samples[kind]))
	}
}

type nativeTimedPolicy struct {
	*factor.FactorBasedBalance
	timings *nativeLoadTimings
}

func (p *nativeTimedPolicy) BackendToRoute(backends []policy.BackendCtx) policy.BackendCtx {
	started := time.Now()
	defer p.timings.record(0, started)
	return p.FactorBasedBalance.BackendToRoute(backends)
}
func (p *nativeTimedPolicy) RouteableBackends(backends []policy.BackendCtx) []policy.BackendCtx {
	started := time.Now()
	defer p.timings.record(1, started)
	return p.FactorBasedBalance.RouteableBackends(backends)
}
func (p *nativeTimedPolicy) BackendsToBalance(backends []policy.BackendCtx) (policy.BackendCtx, policy.BackendCtx, float64, string, []zap.Field) {
	started := time.Now()
	defer p.timings.record(2, started)
	return p.FactorBasedBalance.BackendsToBalance(backends)
}
func (p *nativeTimedPolicy) TakeObservation() *observation.Evaluation {
	started := time.Now()
	defer p.timings.record(3, started)
	return p.FactorBasedBalance.TakeObservation()
}

type nativePromFetcher struct{ port int }

func (f *nativePromFetcher) GetPromInfo(context.Context) (*infosync.PrometheusInfo, error) {
	return &infosync.PrometheusInfo{IP: "127.0.0.1", Port: f.port}, nil
}

// The real ClusterReader owns registrations, source selection and publications.
// The HTTP fixture supplies ordinary Prometheus responses, never provenance.
func nativeLoadRouter(t *testing.T, owner *observation.Owner, cfg *config.Config, timings *nativeLoadTimings) (*ScoreBasedRouter, *metricsreader.ClusterReader) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		matrix := strings.HasSuffix(r.URL.Path, "query_range")
		query := r.Form.Get("query")
		results := make([]any, 0, 12)
		stamp := float64(time.Now().UnixMilli()) / 1000
		for owner := range 2 {
			for group := range 2 {
				for backend := range 3 {
					value := 0.2 + float64(backend)*0.2
					if !matrix {
						value = 100
						if strings.Contains(query, "failed") || strings.Contains(query, "backoff") {
							value = float64(backend * 15)
						}
					}
					series := map[string]any{"metric": map[string]string{"instance": fmt.Sprintf("127.0.0.1:%d", 10000+owner*100+group*10+backend), "cluster": "default"}}
					pair := []any{stamp, strconv.FormatFloat(value, 'g', -1, 64)}
					if matrix {
						series["values"] = []any{[]any{stamp - 15, strconv.FormatFloat(value-0.01, 'g', -1, 64)}, pair}
					} else {
						series["value"] = pair
					}
					results = append(results, series)
				}
			}
		}
		kind := "vector"
		if matrix {
			kind = "matrix"
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "success", "data": map[string]any{"resultType": kind, "result": results}})
	}))
	t.Cleanup(server.Close)
	health := config.NewDefaultHealthCheckConfig()
	health.MetricsInterval = 100 * time.Millisecond
	reader := metricsreader.NewDefaultMetricsReader(zaptest.NewLogger(t), &nativePromFetcher{port: server.Listener.Addr().(*net.TCPAddr).Port}, nil, nil, nil, health, newMockConfigGetter(cfg))
	require.NoError(t, reader.Start(context.Background()))
	t.Cleanup(reader.Close)
	r := NewScoreBasedRouterWithNativeObservation(zap.NewNop(), owner, func(lg *zap.Logger, o *observation.Owner, group uint64) policy.BalancePolicy {
		f := factor.NewFactorBasedBalanceObserved(lg, reader, o, group)
		f.Init(cfg)
		if timings != nil && os.Getenv("CP_ROUTE_NATIVE_TIMINGS") == "1" {
			return &nativeTimedPolicy{FactorBasedBalance: f, timings: timings}
		}
		return f
	})
	r.bpCreator = func(lg *zap.Logger) policy.BalancePolicy {
		f := factor.NewFactorBasedBalance(lg, reader)
		f.Init(cfg)
		if timings != nil && os.Getenv("CP_ROUTE_NATIVE_TIMINGS") == "1" {
			return &nativeTimedPolicy{FactorBasedBalance: f, timings: timings}
		}
		return f
	}
	return r, reader
}
func observationLoadHealth(owner int, extra, native bool) observer.HealthResult {
	health := loadHealth(owner, extra)
	if native {
		for _, backend := range health.Backends() {
			_, port, _ := net.SplitHostPort(backend.Addr)
			sqlPort, _ := strconv.Atoi(port)
			backend.IP = "127.0.0.1"
			backend.StatusPort = uint(sqlPort + 6000)
			backend.ClusterName = "default"
		}
	}
	return health
}
func assertNativeLoadQueries(t *testing.T, reader *metricsreader.ClusterReader, cfg *config.Config) {
	t.Helper()
	if cfg.Balance.Policy == config.BalancePolicyConnection {
		return
	}
	for _, key := range []string{"cpu", "memory", "failure_pd", "total_pd", "failure_tikv", "total_tikv"} {
		result := reader.GetQueryResult(key)
		require.False(t, result.Empty(), "NATIVE_REAL_QUERY_PUBLICATION %s", key)
		require.EqualValues(t, 1, result.Provenance.Source) // Actual Prom source.
		require.Positive(t, result.Provenance.SourceGeneration)
		require.Positive(t, result.Provenance.Producer)
		require.Positive(t, result.Provenance.Registration)
		require.Positive(t, result.Provenance.Publication)
	}
}

func TestNativeObservationSustained(t *testing.T) {
	binary := os.Getenv("CP_ROUTE_LIVE_SOCKET_CHECK")
	if binary == "" {
		t.Skip("requires built live_socket_check consumer")
	}
	for _, balance := range []string{config.BalancePolicyResource, config.BalancePolicyLocation, config.BalancePolicyConnection} {
		for _, routing := range []string{config.RoutingPolicyIdlest, config.RoutingPolicyRandom, config.RoutingPolicyPreferIdle} {
			for _, enabled := range []bool{false, true} {
				name := fmt.Sprintf("%s/%s/%t", balance, routing, enabled)
				t.Run(name, func(t *testing.T) {
					cfg := config.NewConfig()
					cfg.Balance.Policy, cfg.Balance.RoutingPolicy = balance, routing
					runObservationLoad(t, binary, enabled, cfg)
				})
			}
		}
	}
}

// A finite actual UDS smoke test precedes, and never substitutes for, 18 full
// sixty-second windows. Both native owners exercise the real metrics reader.
func TestNativeObservationSocketSettlement(t *testing.T) {
	binary := os.Getenv("CP_ROUTE_LIVE_SOCKET_CHECK")
	if binary == "" {
		t.Skip("requires consumer harness")
	}
	dir, err := os.MkdirTemp("/tmp", "native-report-")
	require.NoError(t, err)
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "observe.sock")
	service, err := shadowwire.Start(context.Background(), path, zap.NewNop())
	require.NoError(t, err)
	defer service.Close()
	var owners []*observation.Owner
	for i := range 2 {
		owner := service.Recorder().NewNativeOwner()
		owners = append(owners, owner)
		cfg := config.NewConfig()
		cfg.Balance.Policy = config.BalancePolicyResource
		r, reader := nativeLoadRouter(t, owner, cfg, nil)
		defer r.Close()
		r.updateBackendHealth(observationLoadHealth(i, false, true))
		require.Eventually(t, func() bool { return !reader.GetQueryResult("cpu").Empty() }, 5*time.Second, 10*time.Millisecond, "query=%+v invalid=%+v", reader.GetQueryResult("cpu"), service.Recorder().InvalidOwners())
		assertNativeLoadQueries(t, reader, cfg)
		conn, backend := observedConn(t, r, false)
		require.NoError(t, backend.group.OnConnClosed(backend.ID(), conn))
		backend.group.Balance(context.Background())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, binary, path, "native")
	command.Stdin = bytes.NewBufferString(observationFence(6, owners...))
	output, err := command.CombinedOutput()
	t.Log(string(output))
	require.NoError(t, err)
	require.Contains(t, string(output), "factors=true selection=false scheduler=false")
}
