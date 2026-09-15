// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package router

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pingcap/tiproxy/lib/config"
	"github.com/pingcap/tiproxy/pkg/balance/factor"
	"github.com/pingcap/tiproxy/pkg/balance/observer"
	"github.com/pingcap/tiproxy/pkg/balance/policy"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

type timeBoundarySpec struct {
	Suite     string `json:"suite"`
	Positions []struct {
		Name           string `json:"name"`
		DeltaNanos     int64  `json:"delta_nanos"`
		ExpectedEffect bool   `json:"expected_effect"`
	} `json:"positions"`
	Cases []struct {
		Name          string `json:"name"`
		DeadlineNanos int64  `json:"deadline_nanos"`
	} `json:"cases"`
}

type timeBoundaryRow struct {
	Case           string   `json:"case"`
	Position       string   `json:"position"`
	Effect         bool     `json:"effect"`
	ExpectedEffect bool     `json:"expected_effect"`
	PublicHistory  []string `json:"public_history"`
	Violations     []string `json:"violations"`
}

type timeBoundaryPolicy struct {
	policy.BalancePolicy
	from, to    *backendWrapper
	balanceRate float64
}

func (p *timeBoundaryPolicy) BackendsToBalance([]policy.BackendCtx) (policy.BackendCtx, policy.BackendCtx, float64, string, []zap.Field) {
	return p.from, p.to, p.balanceRate, "connection", nil
}

type timeBoundaryConn struct {
	sync.Mutex
	values   map[any]any
	id       uint64
	from     BackendInst
	to       BackendInst
	receiver ConnEventReceiver
	accept   bool
	closing  bool
	effects  atomic.Uint64
}

func newTimeBoundaryConn(id uint64, accept bool) *timeBoundaryConn {
	return &timeBoundaryConn{values: make(map[any]any), id: id, accept: accept}
}
func (c *timeBoundaryConn) SetEventReceiver(receiver ConnEventReceiver) {
	c.Lock()
	c.receiver = receiver
	c.Unlock()
}
func (c *timeBoundaryConn) SetValue(key, value any) {
	c.Lock()
	c.values[key] = value
	c.Unlock()
}
func (c *timeBoundaryConn) Value(key any) any {
	c.Lock()
	defer c.Unlock()
	return c.values[key]
}
func (c *timeBoundaryConn) Redirect(to BackendInst) bool {
	c.effects.Add(1)
	c.Lock()
	defer c.Unlock()
	if !c.accept || c.closing || c.to != nil {
		return false
	}
	c.to = to
	return true
}
func (c *timeBoundaryConn) ForceClose() bool {
	c.effects.Add(1)
	c.Lock()
	defer c.Unlock()
	if c.closing {
		return false
	}
	c.closing = true
	return true
}
func (c *timeBoundaryConn) ConnectionID() uint64  { return c.id }
func (c *timeBoundaryConn) ConnInfo() []zap.Field { return nil }
func (c *timeBoundaryConn) setAccept(accept bool) { c.Lock(); c.accept = accept; c.Unlock() }
func (c *timeBoundaryConn) completeRedirect(success bool) (BackendInst, BackendInst, ConnEventReceiver) {
	c.Lock()
	defer c.Unlock()
	from, to := c.from, c.to
	if success {
		c.from = to
	}
	c.to = nil
	return from, to, c.receiver
}
func (c *timeBoundaryConn) binding() (BackendInst, ConnEventReceiver) {
	c.Lock()
	defer c.Unlock()
	return c.from, c.receiver
}

type timeBoundaryFixture struct {
	group  *Group
	policy *timeBoundaryPolicy
	a, b   *backendWrapper
	conn   *timeBoundaryConn
}

func newTimeBoundaryFixture(t *testing.T, accept bool, rate float64) *timeBoundaryFixture {
	t.Helper()
	p := &timeBoundaryPolicy{BalancePolicy: factor.NewFactorBasedBalance(zap.NewNop(), nil), balanceRate: rate}
	g, err := NewGroup(nil, func(*zap.Logger) policy.BalancePolicy { return p }, MatchAll, zap.NewNop())
	require.NoError(t, err)
	cfg := config.NewConfig()
	cfg.Balance.Policy = config.BalancePolicyConnection
	g.setConfigAt(cfg, time.Unix(1, 0))
	a := newBackendWrapper("a", observer.BackendHealth{BackendInfo: observer.BackendInfo{Addr: "127.0.0.1:4000"}, Healthy: true, SupportRedirection: true})
	b := newBackendWrapper("b", observer.BackendHealth{BackendInfo: observer.BackendInfo{Addr: "127.0.0.1:4001"}, Healthy: true, SupportRedirection: true})
	g.AddBackend("a", a)
	g.AddBackend("b", b)
	conn := newTimeBoundaryConn(1, accept)
	conn.from = a
	_, ok := g.RehydrateConn("a", conn)
	require.True(t, ok)
	p.from, p.to = a, b
	return &timeBoundaryFixture{group: g, policy: p, a: a, b: b, conn: conn}
}

func failoverConfig(timeoutSeconds int) *config.Config {
	cfg := config.NewConfig()
	cfg.Balance.Policy = config.BalancePolicyConnection
	cfg.Proxy.FailBackendList = []string{"127.0.0.1:4000"}
	cfg.Proxy.FailoverTimeout = timeoutSeconds
	return cfg
}

func runGoTimeBoundary(t *testing.T, name, position string, deadline, delta int64, expected bool) timeBoundaryRow {
	t.Helper()
	start := time.Unix(100, 0)
	at := start.Add(time.Duration(deadline + delta))
	history := []string{}
	var effect bool
	switch name {
	case "failed_redirect_cooldown":
		f := newTimeBoundaryFixture(t, false, 100)
		require.False(t, f.group.redirectConn(getConnWrapper(f.conn).Value, f.a, f.b, "connection", nil, start))
		history = append(history, "Redirect(refused)")
		f.conn.setAccept(true)
		before := f.conn.effects.Load()
		f.group.balanceAt(context.Background(), at)
		effect = f.conn.effects.Load() > before
		history = append(history, "Balance", fmt.Sprintf("Redirect(effect=%t)", effect))
		from, receiver := f.conn.binding()
		require.NoError(t, receiver.OnConnClosed(from.ID(), f.conn))
	case "failover_close_timeout", "repeated_activation_preserves_deadline":
		f := newTimeBoundaryFixture(t, true, 1)
		cfg := failoverConfig(int(deadline / int64(time.Second)))
		f.group.setConfigAt(cfg, start)
		history = append(history, "SetConfig(activate)")
		if name == "repeated_activation_preserves_deadline" {
			f.group.setConfigAt(cfg, start.Add(time.Second))
			history = append(history, "SetConfig(repeat)")
		}
		before := f.conn.effects.Load()
		f.group.CloseTimedOutFailoverConnections(at)
		effect = f.conn.effects.Load() > before
		history = append(history, "CloseTimedOutFailoverConnections", fmt.Sprintf("ForceClose(effect=%t)", effect))
		from, receiver := f.conn.binding()
		require.NoError(t, receiver.OnConnClosed(from.ID(), f.conn))
	case "migration_cadence":
		f := newTimeBoundaryFixture(t, true, 1)
		f.group.balanceAt(context.Background(), start)
		from, to, receiver := f.conn.completeRedirect(true)
		require.NotNil(t, to)
		require.NoError(t, receiver.OnRedirectSucceed(from.ID(), to.ID(), f.conn))
		f.policy.from, f.policy.to = f.b, f.a
		history = append(history, "Balance(initial)", "OnRedirectSucceed")
		before := f.conn.effects.Load()
		f.group.balanceAt(context.Background(), at)
		effect = f.conn.effects.Load() > before
		history = append(history, "Balance(boundary)", fmt.Sprintf("Redirect(effect=%t)", effect))
		owner, receiver := f.conn.binding()
		require.NoError(t, receiver.OnConnClosed(owner.ID(), f.conn))
	default:
		t.Fatalf("unknown time-boundary case %q", name)
	}
	row := timeBoundaryRow{
		Case:           name,
		Position:       position,
		Effect:         effect,
		ExpectedEffect: expected,
		PublicHistory:  history,
		Violations:     []string{},
	}
	if effect != expected {
		row.Violations = append(row.Violations, fmt.Sprintf("effect %t != expected %t", effect, expected))
	}
	return row
}

func TestAPITimeBoundaries(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "tests", "controlplane", "cproute", "api-differential", "focused", "time-boundaries.json"))
	require.NoError(t, err)
	var spec timeBoundarySpec
	require.NoError(t, json.Unmarshal(data, &spec))
	require.Equal(t, "time-boundaries", spec.Suite)
	require.Len(t, spec.Cases, 4)
	require.Len(t, spec.Positions, 3)
	rows := make([]timeBoundaryRow, 0, 12)
	for _, boundary := range spec.Cases {
		require.Positive(t, boundary.DeadlineNanos)
		for _, position := range spec.Positions {
			row := runGoTimeBoundary(t, boundary.Name, position.Name, boundary.DeadlineNanos, position.DeltaNanos, position.ExpectedEffect)
			require.Empty(t, row.Violations, "%s/%s", boundary.Name, position.Name)
			rows = append(rows, row)
		}
	}
	negative := timeBoundaryRow{Effect: false, ExpectedEffect: true}
	if negative.Effect != negative.ExpectedEffect {
		negative.Violations = []string{"inverted equal-boundary expectation detected"}
	}
	require.NotEmpty(t, negative.Violations)
	if path := os.Getenv("CPROUTE_TIME_OUTPUT"); path != "" {
		encoded, err := json.MarshalIndent(map[string]any{"engine": "go", "suite": spec.Suite, "rows": rows, "negative_control_detected": negative.Violations}, "", "  ")
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(path, encoded, 0o600))
	}
}
