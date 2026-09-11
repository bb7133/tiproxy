// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package router

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"

	"github.com/pingcap/tiproxy/lib/util/errors"
	"github.com/pingcap/tiproxy/pkg/balance/factor"
	"github.com/pingcap/tiproxy/pkg/balance/metricsreader"
	"github.com/pingcap/tiproxy/pkg/balance/observer"
	"github.com/pingcap/tiproxy/pkg/balance/policy"
	configmgr "github.com/pingcap/tiproxy/pkg/manager/config"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

type apiTraceConfig struct {
	Policy    string `json:"policy"`
	Selection string `json:"selection"`
	Rule      string `json:"rule"`
}

type apiTraceBackend struct {
	Address string            `json:"address"`
	Labels  map[string]string `json:"labels"`
}

type apiTraceEvent struct {
	Op       string            `json:"op"`
	Session  string            `json:"session,omitempty"`
	Client   string            `json:"client,omitempty"`
	Proxy    string            `json:"proxy,omitempty"`
	Port     string            `json:"port,omitempty"`
	Backends []apiTraceBackend `json:"backends,omitempty"`
	Success  bool              `json:"success,omitempty"`
	TOML     string            `json:"toml,omitempty"`
}

type apiEmptyMetrics struct{}

func (apiEmptyMetrics) AddQueryExpr(string, metricsreader.QueryExpr, metricsreader.QueryRule) {}
func (apiEmptyMetrics) RemoveQueryExpr(string)                                                {}
func (apiEmptyMetrics) GetQueryResult(string) metricsreader.QueryResult {
	return metricsreader.QueryResult{}
}
func (apiEmptyMetrics) GetBackendMetrics() []byte { return nil }

type apiAddress string

func (a apiAddress) Network() string { return "tcp" }
func (a apiAddress) String() string  { return string(a) }

func apiClientAddress(value string) net.Addr {
	if value == "" {
		return nil
	}
	return apiAddress(value)
}

func apiError(err error) string {
	switch {
	case err == nil:
		return "ok"
	case err == ErrNoBackend:
		return "no_backend"
	case errors.Is(err, ErrNoBackend):
		return "wrapped_no_backend"
	case errors.Is(err, ErrPortConflict):
		return "port_conflict"
	default:
		return "source_error"
	}
}

// TestRouterAPIDifferential invokes the real router, selector and factor policy.
// Replay owns input delivery/ticks: after Init the background loop is drained,
// then the same health/config handlers used by that loop receive each input
// synchronously. No selected groups, scores or private ledger state are seeded.
// The separately recorded live run keeps the real loop and external sources.
func TestRouterAPIDifferential(t *testing.T) {
	path := os.Getenv("CPROUTE_API_INPUT")
	if path == "" {
		t.Skip("run tests/controlplane/cproute/api-differential/run.py")
	}
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	var trace struct {
		Version int             `json:"version"`
		ID      string          `json:"id"`
		Config  apiTraceConfig  `json:"config"`
		Events  []apiTraceEvent `json:"events"`
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	require.NoError(t, decoder.Decode(&trace))
	require.Equal(t, 1, trace.Version)
	manager := configmgr.NewConfigManager()
	initial := fmt.Sprintf("[balance]\npolicy=%q\nrouting-policy=%q\nrouting-rule=%q\n", trace.Config.Policy, trace.Config.Selection, trace.Config.Rule)
	require.NoError(t, manager.SetTOMLConfig([]byte(initial)))
	r := NewScoreBasedRouter(zap.NewNop())
	ob := newMockBackendObserver()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r.Init(ctx, ob, func(lg *zap.Logger) policy.BalancePolicy {
		return factor.NewFactorBasedBalance(lg, apiEmptyMetrics{})
	}, manager, nil)
	r.wg.Wait()
	t.Cleanup(r.Close)
	type slot struct {
		selector BackendSelector
		conn     *mockRedirectableConn
		current  BackendInst
		active   bool
	}
	sessions := make(map[string]*slot)
	output := make([]map[string]any, 0, len(trace.Events))
	for index, event := range trace.Events {
		row := map[string]any{"seq": index, "op": event.Op, "session": event.Session, "outcome": "ok", "backend": "", "effects": []any{}}
		s := sessions[event.Session]
		switch event.Op {
		case "health":
			backends := make(map[string]*observer.BackendHealth)
			for _, b := range event.Backends {
				backends["default/"+b.Address] = &observer.BackendHealth{BackendInfo: observer.BackendInfo{
					Addr: b.Address, ClusterName: "default", IP: "127.0.0.1", Labels: b.Labels,
				}, Healthy: true, Local: true, SupportRedirection: true}
			}
			r.updateBackendHealth(observer.NewHealthResult(backends, nil))
		case "config":
			if err := manager.SetTOMLConfig([]byte(event.TOML)); err != nil {
				row["outcome"] = "invalid_config"
			} else {
				r.setConfig(manager.GetConfig())
			}
		case "open":
			require.Nil(t, s, "duplicate logical session")
			sessions[event.Session] = &slot{selector: r.GetBackendSelector(ClientInfo{
				ClientAddr: apiClientAddress(event.Client), ProxyAddr: apiClientAddress(event.Proxy), ListenerPort: event.Port,
			}), conn: newMockRedirectableConn(t, uint64(index+1))}
		case "next":
			require.NotNil(t, s)
			backend, routeErr := s.selector.Next()
			row["outcome"] = apiError(routeErr)
			if backend != nil {
				row["backend"] = backend.ID()
			}
			if routeErr == nil {
				s.current = backend
			}
		case "finish":
			require.NotNil(t, s)
			require.NotNil(t, s.current)
			s.conn.from = s.current
			s.selector.Finish(s.conn, event.Success)
			s.active = event.Success
			s.current = nil
		case "close":
			require.NotNil(t, s)
			require.Nil(t, s.current, "pending creation requires its Finish callback")
			if s.active {
				require.NoError(t, s.conn.receiver.OnConnClosed(s.conn.from.ID(), s.conn))
			}
			s.selector.CloseObservation()
			delete(sessions, event.Session)
		case "checkpoint":
			assignments := make(map[string]string)
			for id, live := range sessions {
				if live.active {
					assignments[id] = live.conn.from.ID()
				}
			}
			row["assignments"] = assignments
			row["conn_count"] = r.ConnCount()
		default:
			t.Fatalf("unsupported API input %q", event.Op)
		}
		output = append(output, row)
	}
	require.Empty(t, sessions, "trace must settle and close all logical sessions")
	require.Zero(t, r.ConnCount())
	encoded, err := json.Marshal(output)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(os.Getenv("CPROUTE_API_OUTPUT"), encoded, 0o600))
}
