// Copyright 2026 PingCAP, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package router

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/pingcap/tiproxy/lib/config"
	"github.com/pingcap/tiproxy/pkg/balance/factor"
	"github.com/pingcap/tiproxy/pkg/balance/observer"
	"github.com/pingcap/tiproxy/pkg/balance/policy"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

var cpWorkerNow time.Time

type cpWorkerEvent struct {
	Label, Op string
	At        int64
	CloseAt   *int64 `json:"close_at"`
	Enabled   *bool
	ID        uint64
	Fail      []string
}
type cpWorkerScenario struct {
	Name     string
	Rate     float64
	Capacity int
	Timeout  *int64
	Cross    bool
	Events   []cpWorkerEvent
}
type cpWorkerQueue struct {
	capacity int
	entries  []string
}
type cpWorkerConn struct {
	*mockRedirectableConn
	queue        *cpWorkerQueue
	fromID, toID string
}

func (c *cpWorkerConn) Redirect(target BackendInst) bool {
	if len(c.queue.entries) >= c.queue.capacity {
		return false
	}
	if !c.mockRedirectableConn.Redirect(target) {
		return false
	}
	c.fromID = getConnWrapper(c).Value.physicalOwner.ID()
	c.toID = target.ID()
	c.queue.entries = append(c.queue.entries, fmt.Sprintf("r%d", c.connID))
	return true
}
func (c *cpWorkerConn) ForceClose() bool {
	if len(c.queue.entries) >= c.queue.capacity {
		return false
	}
	if !c.mockRedirectableConn.ForceClose() {
		return false
	}
	c.queue.entries = append(c.queue.entries, fmt.Sprintf("c%d", c.connID))
	return true
}
func TestCPRouteWorkerObservation(t *testing.T) {
	path := os.Getenv("CPROUTE_WORKER_FIXTURE")
	if path == "" {
		t.Skip("run worker/run.sh")
	}
	require.Equal(t, "1", os.Getenv("CPROUTE_WORKER_CLOCK"))
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	var scenarios []cpWorkerScenario
	require.NoError(t, json.Unmarshal(data, &scenarios))
	rows := []any{}
	for _, s := range scenarios {
		start := time.Unix(100, 0)
		cpWorkerNow = start
		fbb := factor.NewFactorBasedBalance(zap.NewNop(), nil)
		g, err := NewGroup(nil, func(*zap.Logger) policy.BalancePolicy { return fbb }, MatchAll, zap.NewNop())
		require.NoError(t, err)
		cfg := config.NewConfig()
		cfg.Balance.Policy = config.BalancePolicyConnection
		cfg.Balance.Status.MigrationsPerSecond = s.Rate
		if s.Timeout != nil {
			cfg.Proxy.FailoverTimeout = int(*s.Timeout)
		} else {
			cfg.Proxy.FailoverTimeout = 60
		}
		g.SetConfig(cfg)
		bks := map[string]*backendWrapper{}
		for i, id := range []string{"a", "b"} {
			ks := "tenant"
			if s.Cross && id == "b" {
				ks = "other"
			}
			bks[id] = newBackendWrapper(id, observer.BackendHealth{BackendInfo: observer.BackendInfo{Addr: fmt.Sprintf("127.0.0.1:%d", 4000+i), Keyspace: ks}, Healthy: true})
			g.AddBackend(id, bks[id])
		}
		q := &cpWorkerQueue{capacity: s.Capacity, entries: []string{}}
		conns := map[uint64]*cpWorkerConn{}
		for id := uint64(1); id <= 6; id++ {
			c := &cpWorkerConn{mockRedirectableConn: newMockRedirectableConn(t, id), queue: q}
			c.from = bks["a"]
			conns[id] = c
			_, ok := g.RehydrateConn("a", c)
			require.True(t, ok)
		}
		cfg.Proxy.FailBackendList = []string{bks["a"].Addr()}
		g.SetConfig(cfg)
		records := 0
		var lastRecord time.Time
		for _, e := range s.Events {
			cpWorkerNow = start.Add(time.Duration(e.At))
			c := conns[e.ID]
			switch e.Op {
			case "tick":
				if e.Enabled == nil || *e.Enabled {
					g.Balance(context.Background())
				}
				closeNow := cpWorkerNow
				if e.CloseAt != nil {
					closeNow = start.Add(time.Duration(*e.CloseAt))
				}
				g.CloseTimedOutFailoverConnections(closeNow)
			case "config":
				cfg.Proxy.FailBackendList = nil
				for _, id := range e.Fail {
					cfg.Proxy.FailBackendList = append(cfg.Proxy.FailBackendList, bks[id].Addr())
				}
				g.SetConfig(cfg)
			case "drain":
				q.entries = []string{}
			case "success", "failure":
				cw := getConnWrapper(c).Value
				if e.Op == "success" {
					if cw.phase != phaseClosed {
						c.redirectSucceed()
					}
					require.NoError(t, g.OnRedirectSucceed(c.fromID, c.toID, c))
				} else {
					if cw.phase != phaseClosed {
						c.redirectFail()
					}
					require.NoError(t, g.OnRedirectFail(c.fromID, c.toID, c))
				}
			case "close":
				require.NoError(t, g.OnConnClosed("ignored-owner", c))
			case "backstop":
				g.redirectConn(getConnWrapper(c).Value, bks["a"], bks["b"], "status", nil, cpWorkerNow)
			default:
				t.Fatalf("unknown event %s", e.Op)
			}
			if !g.lastCrossKeyspaceWarn.Equal(lastRecord) {
				records++
				lastRecord = g.lastCrossKeyspaceWarn
			}
			pending, closing := []uint64{}, []uint64{}
			failed := []int64{}
			for id := uint64(1); id <= 6; id++ {
				cw := getConnWrapper(conns[id]).Value
				if cw.phase == phaseRedirectNotify {
					pending = append(pending, id)
				}
				if cw.forceClosing && cw.phase != phaseClosed {
					closing = append(closing, id)
				}
				at := int64(-1)
				if cw.phase == phaseRedirectFail {
					at = cw.lastRedirect.Sub(start).Nanoseconds()
				}
				failed = append(failed, at)
			}
			watermark := int64(-1)
			if !g.lastRedirectTime.IsZero() {
				watermark = g.lastRedirectTime.Sub(start).Nanoseconds()
			}
			queue := append([]string{}, q.entries...)
			rows = append(rows, map[string]any{"label": s.Name + "/" + e.Label, "counts": []int{bks["a"].ConnScore(), bks["a"].ConnCount(), bks["b"].ConnScore(), bks["b"].ConnCount()}, "pending": pending, "closing": closing, "failed": failed, "queue": queue, "watermark": watermark, "refusals": g.crossKeyspaceSkipCount, "records": records})
		}
		fbb.Close()
	}
	out, err := json.MarshalIndent(rows, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(os.Getenv("CPROUTE_WORKER_OUTPUT"), append(out, '\n'), 0600))
	t.Logf("actual Go worker events=%d", len(rows))
}
