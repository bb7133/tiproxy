// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package router

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/pingcap/tiproxy/lib/config"
	"github.com/pingcap/tiproxy/pkg/balance/factor"
	"github.com/pingcap/tiproxy/pkg/balance/observer"
	"github.com/pingcap/tiproxy/pkg/balance/policy"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

type cpShadowConn struct {
	*cpMigrationConn
	admitClose bool
}

func (c *cpShadowConn) ForceClose() bool {
	if !c.admitClose {
		return false
	}
	return c.mockRedirectableConn.ForceClose()
}

// This is a real Group lifecycle fixture, not production observation wiring.
// The journal describes accepted operations; expected counters and physical
// order are read independently from Go after each operation.
func TestCPRouteShadowObservation(t *testing.T) {
	output := os.Getenv("CPROUTE_SHADOW_OUTPUT")
	if output == "" {
		t.Skip("run tests/controlplane/cproute/shadow/run.sh")
	}
	var journal bytes.Buffer
	var expected strings.Builder
	list := func(ids []uint64) string {
		if len(ids) == 0 {
			return "-"
		}
		values := make([]string, len(ids))
		for i, id := range ids {
			values[i] = strconv.FormatUint(id, 10)
		}
		return strings.Join(values, ",")
	}
	for scenario := uint64(1); scenario <= 3; scenario++ {
		sequence := uint64(0)
		backends := map[uint64]*backendWrapper{}
		conns := map[uint64]*cpShadowConn{}
		emit := func(event map[string]any) {
			sequence++
			body, err := json.Marshal(map[string]any{
				"version": 1, "process": "18446744073709551615",
				"owner": strconv.FormatUint(scenario, 10), "nonce": "1",
				"sequence": strconv.FormatUint(sequence, 10), "event": event,
			})
			require.NoError(t, err)
			require.LessOrEqual(t, len(body), 1<<20)
			require.NoError(t, binary.Write(&journal, binary.BigEndian, uint32(len(body))))
			_, err = journal.Write(body)
			require.NoError(t, err)
			fmt.Fprintf(&expected, "%d\t%d", scenario, sequence)
			for id := uint64(1); id <= 2; id++ {
				score, count := 0, 0
				physical := []uint64{}
				if b := backends[id]; b != nil {
					score, count = b.ConnScore(), b.ConnCount()
					for e := b.connList.Front(); e != nil; e = e.Next() {
						physical = append(physical, e.Value.ConnectionID())
					}
				}
				fmt.Fprintf(&expected, "\t%d\t%d\t%s", score, count, list(physical))
			}
			pending, closing := []uint64{}, []uint64{}
			for id := uint64(1); id <= 2; id++ {
				if c := conns[id]; c != nil {
					cw := getConnWrapper(c).Value
					if cw.phase == phaseRedirectNotify {
						pending = append(pending, id)
					}
					if cw.forceClosing && cw.phase != phaseClosed {
						closing = append(closing, id)
					}
				}
			}
			fmt.Fprintf(&expected, "\t%s\t%s\n", list(pending), list(closing))
		}
		emit(map[string]any{"kind": "begin"})
		fbb := factor.NewFactorBasedBalance(zap.NewNop(), nil)
		g, err := NewGroup(nil, func(*zap.Logger) policy.BalancePolicy { return fbb }, MatchAll, zap.NewNop())
		require.NoError(t, err)
		cfg := config.NewConfig()
		cfg.Balance.Policy = config.BalancePolicyConnection
		g.SetConfig(cfg)
		emit(map[string]any{"kind": "policy", "value": "connection"})
		for id := uint64(1); id <= 2; id++ {
			b := newBackendWrapper(strconv.FormatUint(id, 10), observer.BackendHealth{BackendInfo: observer.BackendInfo{Addr: fmt.Sprintf("127.0.0.1:%d", 4000+id), Keyspace: "tenant"}, Healthy: true})
			backends[id] = b
			g.AddBackend(b.ID(), b)
			emit(map[string]any{"kind": "account", "id": strconv.FormatUint(id, 10), "group": "1"})
		}
		a, b := backends[1], backends[2]
		c := &cpShadowConn{cpMigrationConn: &cpMigrationConn{mockRedirectableConn: newMockRedirectableConn(t, 1), admit: true}, admitClose: true}
		c.from = a
		_, ok := g.RehydrateConn(a.ID(), c)
		require.True(t, ok)
		conns[1] = c
		emit(map[string]any{"kind": "rehydrate", "session": "1", "account": "1"})
		// Actual selection reserves a second connection; the final create turns
		// that score reservation into physical ownership.
		emit(map[string]any{"kind": "open", "session": "2"})
		selected, err := g.Route([]BackendInst{b})
		require.NoError(t, err)
		require.Equal(t, a.ID(), selected.ID())
		emit(map[string]any{"kind": "reserve", "session": "2", "operation": "1", "account": "1"})
		second := &cpShadowConn{cpMigrationConn: &cpMigrationConn{mockRedirectableConn: newMockRedirectableConn(t, 2), admit: true}}
		second.from = a
		g.onCreateConn(a, second, true)
		conns[2] = second
		emit(map[string]any{"kind": "created", "session": "2", "operation": "1", "success": true})
		// A refused offer cannot move score ownership.
		c.admit = false
		g.Lock()
		accepted := g.redirectConn(getConnWrapper(c).Value, a, b, "connection", nil, time.Now())
		g.Unlock()
		require.False(t, accepted)
		emit(map[string]any{"kind": "rejected", "session": "1"})
		c.admit = true
		g.Lock()
		accepted = g.redirectConn(getConnWrapper(c).Value, a, b, "connection", nil, time.Now())
		g.Unlock()
		require.True(t, accepted)
		emit(map[string]any{"kind": "redirect", "session": "1", "operation": "1", "target": "2"})
		if scenario == 3 {
			c.redirectFail()
			require.NoError(t, g.OnRedirectFail(a.ID(), b.ID(), c))
			emit(map[string]any{"kind": "redirected", "session": "1", "operation": "1", "success": false})
			// Failure retains initial physical arrival order; success appends at target.
			g.Lock()
			accepted = g.redirectConn(getConnWrapper(c).Value, a, b, "connection", nil, time.Now())
			g.Unlock()
			require.True(t, accepted)
			emit(map[string]any{"kind": "redirect", "session": "1", "operation": "2", "target": "2"})
			c.redirectSucceed()
			require.NoError(t, g.OnRedirectSucceed(a.ID(), b.ID(), c))
			emit(map[string]any{"kind": "redirected", "session": "1", "operation": "2", "success": true})
		} else {
			// Exercise the real failover close admission while a redirect is pending.
			cfg.Proxy.FailBackendList = []string{a.Addr()}
			cfg.Proxy.FailoverTimeout = 0
			g.SetConfig(cfg)
			emit(map[string]any{"kind": "policy", "value": "connection"})
			g.CloseTimedOutFailoverConnections(time.Now().Add(time.Second))
			require.True(t, getConnWrapper(c).Value.forceClosing)
			require.False(t, getConnWrapper(second).Value.forceClosing)
			emit(map[string]any{"kind": "closing", "session": "1", "operation": "1"})
			emit(map[string]any{"kind": "rejected", "session": "2"})
			// The second endpoint rejected admission in the first pass. Retry it
			// through the actual close loop, with no observer mutation of Go state.
			second.admitClose = true
			g.CloseTimedOutFailoverConnections(time.Now().Add(2 * time.Second))
			require.True(t, getConnWrapper(second).Value.forceClosing)
			emit(map[string]any{"kind": "closing", "session": "2", "operation": "1"})
			if scenario == 1 {
				require.NoError(t, g.OnConnClosed("ignored", c))
				emit(map[string]any{"kind": "closed", "session": "1"})
				require.NoError(t, g.OnRedirectSucceed(a.ID(), b.ID(), c))
				emit(map[string]any{"kind": "redirected", "session": "1", "operation": "1", "success": true})
			} else {
				c.redirectSucceed()
				require.NoError(t, g.OnRedirectSucceed(a.ID(), b.ID(), c))
				emit(map[string]any{"kind": "redirected", "session": "1", "operation": "1", "success": true})
			}
		}
		for id := uint64(1); id <= 2; id++ {
			require.NoError(t, g.OnConnClosed("ignored", conns[id]))
			emit(map[string]any{"kind": "closed", "session": strconv.FormatUint(id, 10)})
		}
		emit(map[string]any{"kind": "retire"})
		emit(map[string]any{"kind": "end"})
		fbb.Close()
	}
	require.NoError(t, os.WriteFile(output+".bin", journal.Bytes(), 0o600))
	require.NoError(t, os.WriteFile(output+".tsv", []byte(expected.String()), 0o600))
}
