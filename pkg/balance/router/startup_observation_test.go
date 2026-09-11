// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package router

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pingcap/tiproxy/lib/config"
	"github.com/pingcap/tiproxy/lib/util/errors"
	"github.com/pingcap/tiproxy/pkg/balance/observation"
	"github.com/pingcap/tiproxy/pkg/balance/observer"
	"github.com/stretchr/testify/require"
)

type startupObserver struct {
	health    chan observer.HealthResult
	refreshes atomic.Int64
}

func (*startupObserver) Start(context.Context)                           {}
func (o *startupObserver) Subscribe(string) <-chan observer.HealthResult { return o.health }
func (*startupObserver) Unsubscribe(string)                              {}
func (o *startupObserver) Refresh()                                      { o.refreshes.Add(1) }
func (*startupObserver) Close()                                          {}

type startupGetter struct {
	cfg       *config.Config
	calls     int
	panicRead bool
}

func (g *startupGetter) GetConfig() *config.Config {
	g.calls++
	if g.panicRead {
		panic("original startup getter panic")
	}
	return g.cfg
}

func startupFixture(t *testing.T, rawRule, path string) (*routerAttemptFixture, *mockConfigGetter, *startupObserver) {
	t.Helper()
	f := &routerAttemptFixture{metadataFixture: newMetadataFixtureWithFactory(t, MatchAll, path, newScoreBasedRouterStartupCaptured)}
	cfg := config.NewConfig()
	cfg.Balance.Policy = config.BalancePolicyConnection
	cfg.Balance.RoutingPolicy = config.RoutingPolicyIdlest
	cfg.Balance.RoutingRule = rawRule
	getter := newMockConfigGetter(cfg)
	ob := &startupObserver{health: make(chan observer.HealthResult)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f.router.Init(ctx, ob, simpleBpCreator, getter, nil)
	cancel()
	f.router.wg.Wait()
	require.True(t, f.router.startupRecorded, "STARTUP_INIT_PUBLISHED")
	f.drain(t)
	return f, getter, ob
}

func TestRouterStartupActualFrames(t *testing.T) {
	dir := os.Getenv("CP_ROUTE_STARTUP_FRAMES_DIR")
	if dir == "" {
		dir = t.TempDir()
	}
	require.NoError(t, os.MkdirAll(dir, 0o755))
	for _, tc := range []struct {
		name, rule string
		kind       MatchType
	}{{"all", "", MatchAll}, {"cidr", "client_cidr", MatchClientCIDR}, {"proxy", "proxy_cidr", MatchProxyCIDR}, {"port", "port", MatchPort}} {
		t.Run(tc.name, func(t *testing.T) {
			f, getter, ob := startupFixture(t, tc.rule, filepath.Join(dir, tc.name+".frames"))
			unused := &routerAttemptAddr{panicRead: true}
			empty := ClientInfo{ClientAddr: unused, ProxyAddr: unused, ListenerPort: "6000"}
			bs := f.router.GetBackendSelector(empty)
			f.next(t, &bs, observation.SelectorExactNoBackend, false)
			f.next(t, &bs, observation.SelectorExactNoBackend, false)
			bs.CloseObservation()
			f.drain(t)
			require.EqualValues(t, 2, ob.refreshes.Load(), "STARTUP_POST_UNLOCK_REFRESH")
			require.Nil(t, f.router.portConflictDetector, "STARTUP_NIL_DETECTOR")
			f.refresh(t, nil, errors.WithStack(ErrNoBackend))
			f.once(t, empty, observation.SelectorOtherError)
			require.Nil(t, f.router.portConflictDetector, "STARTUP_ERROR_PRESERVES_NIL")
			f.refresh(t, map[string]*observer.BackendHealth{}, nil)
			f.once(t, empty, observation.SelectorExactNoBackend)
			if tc.kind == MatchPort {
				require.NotNil(t, f.router.portConflictDetector, "STARTUP_EMPTY_DETECTOR")
			}
			f.refresh(t, nil, fmt.Errorf("ordinary startup observer error"))
			f.once(t, empty, observation.SelectorOtherError)
			if tc.kind == MatchPort {
				require.NotNil(t, f.router.portConflictDetector, "STARTUP_ERROR_PRESERVES_DETECTOR")
			}
			require.Zero(t, unused.calls)
			changed := getter.GetConfig().Clone()
			changed.Balance.RoutingRule = "port"
			if tc.kind == MatchPort {
				changed.Balance.RoutingRule = "client_cidr"
			}
			getter.setConfig(changed)
			f.router.setConfig(changed)
			require.Equal(t, tc.kind, f.router.matchType, "STARTUP_FIXED_RULE")
			health := cidrHealth("a:4000", "10.0.0.0/8", true)
			if tc.kind == MatchPort {
				health = portHealth("a:4000", "cluster", "6000")
			}
			f.refresh(t, map[string]*observer.BackendHealth{"a": health}, nil)
			address := &routerAttemptAddr{values: []string{"10.1.1.1:1"}}
			client := ClientInfo{ClientAddr: unused, ProxyAddr: unused, ListenerPort: "6000"}
			if tc.kind == MatchClientCIDR {
				client.ClientAddr = address
			}
			if tc.kind == MatchProxyCIDR {
				client.ProxyAddr = address
			}
			routed := f.router.GetBackendSelector(client)
			f.next(t, &routed, observation.SelectorNoError, true)
			routed.CloseObservation()
			f.drain(t)
			f.refresh(t, map[string]*observer.BackendHealth{}, nil)
			f.once(t, empty, observation.SelectorExactNoBackend)
			f.finish(t, [5]int{7, 7, 7, 6, 1})
		})
	}
}

func TestRouterStartupRuleAndFailureBoundaries(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		rule MatchType
	}{{"", MatchAll}, {"ClIeNt_CiDr", MatchClientCIDR}, {"CLİENT_CİDR", MatchClientCIDR}, {"PROXY_CIDR", MatchProxyCIDR}, {"PORT", MatchPort}, {" port", MatchAll}, {"port ", MatchAll}, {"unknown", MatchAll}, {strings.Repeat("x", 512), MatchAll}} {
		t.Run(fmt.Sprintf("rule-%q", tc.raw[:min(len(tc.raw), 20)]), func(t *testing.T) {
			f := newMetadataFixtureWithFactory(t, MatchAll, filepath.Join(t.TempDir(), "frames"), newScoreBasedRouterStartupCaptured)
			cfg := config.NewConfig()
			cfg.Balance.RoutingRule = tc.raw
			getter := &startupGetter{cfg: cfg}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			f.router.Init(ctx, &startupObserver{}, simpleBpCreator, getter, nil)
			cancel()
			f.router.wg.Wait()
			require.Equal(t, 1, getter.calls, "STARTUP_SINGLE_CONFIG_READ")
			require.Equal(t, tc.rule, f.router.matchType, "STARTUP_GO_RULE")
			require.True(t, f.o.Enabled())
			found := false
			for n, _ := f.r.Retained(); n > 0; n, _ = f.r.Retained() {
				d, err := f.r.Next(context.Background())
				require.NoError(t, err)
				if d.Record.Caller != nil {
					m := d.Record.Caller.Metadata()
					require.NotNil(t, m)
					require.Equal(t, observation.MetadataInit, m.Kind)
					require.EqualValues(t, 2, d.Record.Sequence, "STARTUP_SEQUENCE_TWO")
					require.Equal(t, tc.raw, string(d.Record.Caller.Bytes()), "STARTUP_ORIGINAL_RULE_READ")
					found = true
				}
				d.Release()
			}
			require.True(t, found, "STARTUP_INIT_FRAME")
		})
	}
	for _, kind := range []string{"panic", "capacity", "utf8", "duplicate", "record-capacity"} {
		t.Run(kind, func(t *testing.T) {
			f := newMetadataFixtureWithFactory(t, MatchAll, filepath.Join(t.TempDir(), "frames"), newScoreBasedRouterStartupCaptured)
			cfg := config.NewConfig()
			getter := &startupGetter{cfg: cfg, panicRead: kind == "panic"}
			if kind == "capacity" {
				cfg.Balance.RoutingRule = strings.Repeat("x", 513)
			}
			if kind == "utf8" {
				cfg.Balance.RoutingRule = string([]byte{0xff})
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if kind == "record-capacity" {
				// Fill the existing finite owner queue without adding another buffer.
				for n, _ := f.r.Retained(); n < int64(observation.DefaultLimits().Records); n, _ = f.r.Retained() {
					f.r.WatermarkOwners()
					if !f.o.Enabled() {
						break
					}
				}
			}
			init := func() { f.router.Init(ctx, &startupObserver{}, simpleBpCreator, getter, nil) }
			if kind == "panic" {
				require.PanicsWithValue(t, "original startup getter panic", init)
			} else {
				init()
				cancel()
				f.router.wg.Wait()
			}
			if kind == "duplicate" {
				init()
				f.router.wg.Wait()
			}
			require.False(t, f.o.Enabled(), "STARTUP_FAILURE_INVALIDATES")
			f.r.Close()
			n, b := f.r.Retained()
			require.Zero(t, n)
			require.Zero(t, b, "STARTUP_PARENT_RELEASED")
		})
	}
}

func TestRouterStartupQueuedHealth(t *testing.T) {
	f := newMetadataFixtureWithFactory(t, MatchAll, filepath.Join(t.TempDir(), "frames"), newScoreBasedRouterStartupCaptured)
	ob := &startupObserver{health: make(chan observer.HealthResult, 1)}
	ob.health <- observer.NewHealthResult(map[string]*observer.BackendHealth{}, nil)
	cfg := config.NewConfig()
	cfg.Balance.RoutingRule = "port"
	configCh := make(chan *config.Config, 1)
	changed := cfg.Clone()
	changed.Balance.RoutingRule = "client_cidr"
	configCh <- changed
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f.router.Init(ctx, ob, simpleBpCreator, newMockConfigGetter(cfg), configCh)
	// Drain the actual ordered stream; the queued health must follow Init.
	deadline, done := context.WithTimeout(context.Background(), 3*time.Second)
	defer done()
	sawInit, sawEnd := false, false
	for !sawEnd {
		d, err := f.r.Next(deadline)
		require.NoError(t, err)
		if d.Record.Caller != nil {
			m := d.Record.Caller.Metadata()
			require.NotNil(t, m)
			if m.Kind == observation.MetadataInit {
				require.False(t, sawInit)
				require.EqualValues(t, 2, d.Record.Sequence, "STARTUP_BEFORE_QUEUED_HEALTH")
				sawInit = true
			} else {
				require.True(t, sawInit, "STARTUP_BEFORE_QUEUED_HEALTH")
			}
			sawEnd = m.Kind == observation.MetadataEnd
		}
		d.Release()
	}
	cancel()
	f.router.wg.Wait()
	require.True(t, f.o.Enabled())
	require.Equal(t, MatchPort, f.router.matchType, "STARTUP_QUEUED_CONFIG_FIXED_RULE")
}

func TestRouterStartupDetectorReads(t *testing.T) {
	f, _, _ := startupFixture(t, "port", filepath.Join(t.TempDir(), "frames"))
	bs := f.router.GetBackendSelector(ClientInfo{ListenerPort: "6000"})
	b, err := bs.Next()
	require.Nil(t, b)
	require.Same(t, ErrNoBackend, err)
	require.True(t, f.o.Enabled(), "STARTUP_LISTENER_AFTER_DETECTOR")
	found := false
	for n, _ := f.r.Retained(); n > 0; n, _ = f.r.Retained() {
		d, err := f.r.Next(context.Background())
		require.NoError(t, err)
		if d.Record.Caller != nil && d.Record.Caller.RouterRoute() != nil {
			route := d.Record.Caller.RouterRoute()
			require.True(t, route.PortVisited)
			require.False(t, route.DetectorPresent, "STARTUP_NIL_IS_NOT_EMPTY")
			require.Zero(t, route.Listener.Length)
			found = true
		}
		d.Release()
	}
	require.True(t, found)
	bs.CloseObservation()
	f.drain(t)
}
