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

// Only the clock read in Group.Balance is overlaid. Its real admission,
// cooldown, score transfer, physical completion and close code remain intact.
var cpMigrationNow time.Time

type cpMigrationPolicy struct {
	policy.BalancePolicy
	from, to *backendWrapper
}

func (p *cpMigrationPolicy) BackendsToBalance([]policy.BackendCtx) (policy.BackendCtx, policy.BackendCtx, float64, string, []zap.Field) {
	return p.from, p.to, 100, "connection", nil
}

type cpMigrationConn struct {
	*mockRedirectableConn
	admit             bool
	offered, accepted int
}

func (c *cpMigrationConn) Redirect(target BackendInst) bool {
	c.offered++
	if !c.admit {
		return false
	}
	accepted := c.mockRedirectableConn.Redirect(target)
	if accepted {
		c.accepted++
	}
	return accepted
}

func TestCPRouteMigrationObservation(t *testing.T) {
	input := os.Getenv("CPROUTE_MIGRATION_FIXTURE")
	if input == "" {
		t.Skip("run migration/run.sh")
	}
	require.Equal(t, "1", os.Getenv("CPROUTE_MIGRATION_CLOCK"))
	data, err := os.ReadFile(input)
	require.NoError(t, err)
	var output strings.Builder
	var group *Group
	var p *cpMigrationPolicy
	var conn *cpMigrationConn
	var a, b *backendWrapper
	var from, to string
	start := time.Unix(100, 0)
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		row := strings.Split(line, "\t")
		require.Len(t, row, 4)
		millis, err := strconv.ParseInt(row[2], 10, 64)
		require.NoError(t, err)
		cpMigrationNow = start.Add(time.Duration(millis) * time.Millisecond)
		switch row[1] {
		case "reset":
			p = &cpMigrationPolicy{BalancePolicy: factor.NewFactorBasedBalance(zap.NewNop(), nil)}
			group, err = NewGroup(nil, func(*zap.Logger) policy.BalancePolicy { return p }, MatchAll, zap.NewNop())
			require.NoError(t, err)
			cfg := config.NewConfig()
			cfg.Balance.Policy = config.BalancePolicyConnection
			group.SetConfig(cfg)
			a = newBackendWrapper("a", observer.BackendHealth{BackendInfo: observer.BackendInfo{Addr: "127.0.0.1:4000", Keyspace: "tenant"}, Healthy: true})
			b = newBackendWrapper("b", observer.BackendHealth{BackendInfo: observer.BackendInfo{Addr: "127.0.0.1:4001", Keyspace: "tenant"}, Healthy: true})
			group.AddBackend("a", a)
			group.AddBackend("b", b)
			conn = &cpMigrationConn{mockRedirectableConn: newMockRedirectableConn(t, 1)}
			conn.from = a
			_, ok := group.RehydrateConn("a", conn)
			require.True(t, ok)
		case "balance":
			conn.admit = row[3] == "1"
			p.from = getConnWrapper(conn).Value.physicalOwner
			p.to = b
			if p.from == b {
				p.to = a
			}
			before := conn.accepted
			group.Balance(context.Background())
			if conn.accepted != before {
				from, to = p.from.ID(), p.to.ID()
			}
		case "success":
			conn.redirectSucceed()
			require.NoError(t, group.OnRedirectSucceed(from, to, conn))
		case "failure":
			conn.redirectFail()
			require.NoError(t, group.OnRedirectFail(from, to, conn))
		case "close":
			require.NoError(t, group.OnConnClosed(to, conn))
		case "late_success":
			require.NoError(t, group.OnRedirectSucceed(from, to, conn))
		case "late_failure":
			require.NoError(t, group.OnRedirectFail(from, to, conn))
		case "remove_source":
			delete(group.backends, from)
		default:
			t.Fatalf("unknown action %s", row[1])
		}
		watermark := int64(-1)
		if !group.lastRedirectTime.IsZero() {
			watermark = group.lastRedirectTime.Sub(start).Milliseconds()
		}
		fmt.Fprintf(&output, "%s\t%d\t%d\t%d\t%d\t%d\t%d\t%d\n", row[0], a.ConnScore(), a.ConnCount(), b.ConnScore(), b.ConnCount(), conn.offered, conn.accepted, watermark)
	}
	require.NoError(t, os.WriteFile(os.Getenv("CPROUTE_MIGRATION_OUTPUT"), []byte(output.String()), 0o600))
}
