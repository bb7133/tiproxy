// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package router

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"testing"
	"time"

	"github.com/pingcap/tiproxy/pkg/balance/factor"
	"github.com/pingcap/tiproxy/pkg/balance/observer"
	"github.com/pingcap/tiproxy/pkg/balance/policy"
	configmgr "github.com/pingcap/tiproxy/pkg/manager/config"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// Resource-release focused suite (API differential contract section 4): four
// fixed cases, each repeated for the declared cycle count; afterwards owned
// goroutines and live connections must return to baseline within a bounded
// drain. Only public router boundaries are used: ConnCount, LookupBackend after
// the backends leave health, and the rebalance loop join in Close.

type resourceCases struct {
	Suite       string   `json:"suite"`
	Cycles      int      `json:"cycles"`
	DrainMillis int      `json:"drain_millis"`
	Cases       []string `json:"cases"`
}

type resourceSnapshot struct {
	Goroutines       int      `json:"goroutines"`
	ConnCount        int      `json:"conn_count"`
	RetainedBackends []string `json:"retained_backends"`
}

type resourceCaseResult struct {
	Case       string           `json:"case"`
	Cycles     int              `json:"cycles"`
	Effects    int              `json:"effects"`
	Baseline   resourceSnapshot `json:"baseline"`
	Final      resourceSnapshot `json:"final"`
	DrainNanos int64            `json:"drain_nanos"`
	Violations []string         `json:"violations"`
}

// checkResourceBaseline is a pure checker: it never waits, retries or reads
// router state, so the negative control can exercise it on a fixture.
func checkResourceBaseline(baseline, final resourceSnapshot) []string {
	violations := []string{}
	if final.ConnCount != 0 {
		violations = append(violations, fmt.Sprintf("live connections %d", final.ConnCount))
	}
	if len(final.RetainedBackends) != 0 {
		violations = append(violations, fmt.Sprintf("backends retained after health removal %v", final.RetainedBackends))
	}
	if final.Goroutines > baseline.Goroutines {
		violations = append(violations, fmt.Sprintf("goroutines %d above baseline %d", final.Goroutines, baseline.Goroutines))
	}
	return violations
}

type releaseConn struct {
	*mockRedirectableConn
	refuse  bool
	effects *int
}

func (c *releaseConn) Redirect(to BackendInst) bool {
	*c.effects++
	if c.refuse {
		return false
	}
	return c.mockRedirectableConn.Redirect(to)
}

func (c *releaseConn) ForceClose() bool {
	*c.effects++
	if c.refuse {
		return false
	}
	return c.mockRedirectableConn.ForceClose()
}

type releaseRouter struct {
	router  *ScoreBasedRouter
	manager *configmgr.ConfigManager
	cancel  context.CancelFunc
}

// newReleaseRouter runs the real Init. With live=true the production rebalance
// loop goroutine is running until Close joins it.
func newReleaseRouter(t *testing.T, live bool) *releaseRouter {
	manager := configmgr.NewConfigManager()
	require.NoError(t, manager.SetTOMLConfig([]byte("[balance]\npolicy=\"connection\"\nrouting-policy=\"random\"\n")))
	r := NewScoreBasedRouter(zap.NewNop())
	ctx, cancel := context.WithCancel(context.Background())
	if !live {
		cancel()
	}
	r.Init(ctx, newMockBackendObserver(), func(lg *zap.Logger) policy.BalancePolicy {
		return factor.NewFactorBasedBalance(lg, &apiMetrics{})
	}, manager, nil)
	if !live {
		r.wg.Wait()
	}
	return &releaseRouter{router: r, manager: manager, cancel: cancel}
}

func (rr *releaseRouter) health(addrs ...string) {
	backends := make(map[string]*observer.BackendHealth, len(addrs))
	for _, addr := range addrs {
		backends[addr] = &observer.BackendHealth{BackendInfo: observer.BackendInfo{Addr: addr, IP: "127.0.0.1", StatusPort: 10080},
			Healthy: true, Local: true, SupportRedirection: true}
	}
	rr.router.updateBackendHealth(observer.NewHealthResult(backends, nil))
}

func (rr *releaseRouter) config(t *testing.T, toml string) {
	require.NoError(t, rr.manager.SetTOMLConfig([]byte(toml)))
	rr.router.setConfig(rr.manager.GetConfig())
}

// retained removes every backend from health and reports which IDs the router
// still retains; a leaked reservation or connection keeps its backend alive.
func (rr *releaseRouter) retained(addrs []string) []string {
	rr.health()
	out := []string{}
	for _, addr := range addrs {
		if _, ok := rr.router.LookupBackend(addr); ok {
			out = append(out, addr)
		}
	}
	sort.Strings(out)
	return out
}

func goroutinesWithin(limit int, drain time.Duration) (int, time.Duration) {
	start := time.Now()
	for {
		runtime.GC()
		n := runtime.NumGoroutine()
		if n <= limit || time.Since(start) >= drain {
			return n, time.Since(start)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestAPIResourceRelease(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "tests", "controlplane", "cproute", "api-differential", "focused", "resource-release.json"))
	require.NoError(t, err)
	var cases resourceCases
	require.NoError(t, json.Unmarshal(data, &cases))
	require.Equal(t, "resource-release", cases.Suite)
	require.Positive(t, cases.Cycles)
	drain := time.Duration(cases.DrainMillis) * time.Millisecond
	addrs := []string{"127.0.0.1:4000", "127.0.0.1:4001"}
	results := []resourceCaseResult{}
	var conns uint64

	nextConn := func(effects *int, refuse bool) *releaseConn {
		conns++
		return &releaseConn{mockRedirectableConn: newMockRedirectableConn(t, conns), refuse: refuse, effects: effects}
	}
	// One lifecycle that establishes a connection on the selected backend and closes it through the receiver.
	lifecycle := func(rr *releaseRouter, effects *int) {
		selector := rr.router.GetBackendSelector(ClientInfo{})
		backend, err := selector.Next()
		require.NoError(t, err)
		conn := nextConn(effects, false)
		selector.Finish(conn, true)
		selector.CloseObservation()
		require.NotNil(t, conn.receiver)
		require.NoError(t, conn.receiver.OnConnClosed(backend.ID(), conn))
	}

	run := map[string]func(*testing.T) resourceCaseResult{
		// Every creation fails; the selector walks its exclusions, resets on
		// exact exhaustion and fails again; nothing is ever established.
		"failed_creation": func(t *testing.T) resourceCaseResult {
			rr := newReleaseRouter(t, false)
			defer rr.router.Close()
			result := resourceCaseResult{Case: "failed_creation", Cycles: cases.Cycles}
			cycle := func() {
				rr.health(addrs...)
				selector := rr.router.GetBackendSelector(ClientInfo{})
				for attempt := 0; attempt < len(addrs)+1; attempt++ {
					_, err := selector.Next()
					require.NoError(t, err)
					selector.Finish(nextConn(&result.Effects, false), false)
				}
				selector.CloseObservation()
			}
			cycle()
			result.Baseline = resourceSnapshot{Goroutines: runtime.NumGoroutine(), ConnCount: rr.router.ConnCount()}
			for i := 0; i < cases.Cycles; i++ {
				cycle()
			}
			result.Final.ConnCount = rr.router.ConnCount()
			result.Final.RetainedBackends = rr.retained(addrs)
			result.Final.Goroutines, _ = goroutinesWithin(result.Baseline.Goroutines, drain)
			return result
		},
		// A connection on a drained backend is force-closed at the failover
		// timeout, the client refuses, and the client-side close cleans up.
		"refused_effect_cleanup": func(t *testing.T) resourceCaseResult {
			rr := newReleaseRouter(t, false)
			defer rr.router.Close()
			result := resourceCaseResult{Case: "refused_effect_cleanup", Cycles: cases.Cycles}
			cycle := func() {
				rr.health(addrs[0])
				selector := rr.router.GetBackendSelector(ClientInfo{})
				backend, err := selector.Next()
				require.NoError(t, err)
				conn := nextConn(&result.Effects, true)
				selector.Finish(conn, true)
				selector.CloseObservation()
				rr.health(addrs...)
				before := result.Effects
				rr.config(t, fmt.Sprintf("[proxy]\nfail-backend-list=[%q]\nfailover-timeout=0\n", backend.Addr()))
				rr.router.rebalance(context.Background())
				require.Greater(t, result.Effects, before, "the refused effect must actually be issued")
				require.NoError(t, conn.receiver.OnConnClosed(backend.ID(), conn))
				rr.config(t, "[proxy]\nfail-backend-list=[]\n")
			}
			cycle()
			result.Baseline = resourceSnapshot{Goroutines: runtime.NumGoroutine(), ConnCount: rr.router.ConnCount()}
			for i := 0; i < cases.Cycles; i++ {
				cycle()
			}
			result.Final.ConnCount = rr.router.ConnCount()
			result.Final.RetainedBackends = rr.retained(addrs)
			result.Final.Goroutines, _ = goroutinesWithin(result.Baseline.Goroutines, drain)
			return result
		},
		// The production rebalance loop runs; Close happens with a pending
		// reservation and an accepted, uncompleted redirect. Late settlement
		// after Close must be harmless and leave nothing behind.
		"shutdown_outstanding": func(t *testing.T) resourceCaseResult {
			result := resourceCaseResult{Case: "shutdown_outstanding", Cycles: cases.Cycles}
			var final resourceSnapshot
			cycle := func(measure bool) {
				rr := newReleaseRouter(t, true)
				rr.health(addrs...)
				pending := rr.router.GetBackendSelector(ClientInfo{})
				_, err := pending.Next()
				require.NoError(t, err)
				established := rr.router.GetBackendSelector(ClientInfo{})
				backend, err := established.Next()
				require.NoError(t, err)
				conn := nextConn(&result.Effects, false)
				established.Finish(conn, true)
				established.CloseObservation()
				require.NoError(t, rr.router.RedirectConnections())
				require.NotNil(t, conn.to, "the redirect must be accepted and outstanding")
				rr.router.Close()
				pending.Finish(nextConn(&result.Effects, false), false)
				pending.CloseObservation()
				require.NoError(t, conn.receiver.OnRedirectSucceed(backend.ID(), conn.to.ID(), conn))
				require.NoError(t, conn.receiver.OnConnClosed(conn.to.ID(), conn))
				if measure {
					final.ConnCount = rr.router.ConnCount()
					final.RetainedBackends = rr.retained(addrs)
				}
			}
			cycle(false)
			result.Baseline = resourceSnapshot{Goroutines: runtime.NumGoroutine()}
			for i := 0; i < cases.Cycles; i++ {
				cycle(i == cases.Cycles-1)
			}
			var elapsed time.Duration
			final.Goroutines, elapsed = goroutinesWithin(result.Baseline.Goroutines, drain)
			result.Final, result.DrainNanos = final, elapsed.Nanoseconds()
			return result
		},
		// Each cycle builds a router with its loop, runs one lifecycle and closes it.
		"repeated_create_close": func(t *testing.T) resourceCaseResult {
			result := resourceCaseResult{Case: "repeated_create_close", Cycles: cases.Cycles}
			var final resourceSnapshot
			cycle := func(measure bool) {
				rr := newReleaseRouter(t, true)
				rr.health(addrs...)
				lifecycle(rr, &result.Effects)
				rr.router.Close()
				if measure {
					final.ConnCount = rr.router.ConnCount()
					final.RetainedBackends = rr.retained(addrs)
				}
			}
			cycle(false)
			result.Baseline = resourceSnapshot{Goroutines: runtime.NumGoroutine()}
			for i := 0; i < cases.Cycles; i++ {
				cycle(i == cases.Cycles-1)
			}
			var elapsed time.Duration
			final.Goroutines, elapsed = goroutinesWithin(result.Baseline.Goroutines, drain)
			result.Final, result.DrainNanos = final, elapsed.Nanoseconds()
			return result
		},
	}

	for _, name := range cases.Cases {
		fn, ok := run[name]
		require.True(t, ok, "unknown resource-release case %q", name)
		result := fn(t)
		result.Violations = checkResourceBaseline(result.Baseline, result.Final)
		require.Empty(t, result.Violations, "case %s", name)
		results = append(results, result)
	}

	// Negative control: the same checker must report a real leak. A reservation
	// without Finish keeps its backend retained; no goroutine is left behind.
	leak := newReleaseRouter(t, false)
	selector := leak.router.GetBackendSelector(ClientInfo{})
	leak.health(addrs...)
	_, err = selector.Next()
	require.NoError(t, err)
	leaked := resourceSnapshot{Goroutines: runtime.NumGoroutine(), RetainedBackends: leak.retained(addrs)}
	detected := checkResourceBaseline(resourceSnapshot{Goroutines: leaked.Goroutines}, leaked)
	require.NotEmpty(t, detected, "negative control: a leaked reservation must be reported")
	fixture := checkResourceBaseline(resourceSnapshot{Goroutines: 10}, resourceSnapshot{Goroutines: 11, ConnCount: 1, RetainedBackends: []string{"x"}})
	require.Len(t, fixture, 3)
	selector.Finish(nextConn(new(int), false), false)
	selector.CloseObservation()
	leak.router.Close()

	if path := os.Getenv("CPROUTE_RESOURCE_OUTPUT"); path != "" {
		encoded, err := json.MarshalIndent(map[string]any{"engine": "go", "suite": cases.Suite, "cycles": cases.Cycles,
			"drain_millis": cases.DrainMillis, "cases": results, "negative_control_detected": detected}, "", "  ")
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(path, encoded, 0o600))
	}
}
