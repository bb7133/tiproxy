// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package router

import (
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

func TestCPRouteArrivalObservation(t *testing.T) {
	input := os.Getenv("CPROUTE_ARRIVAL_FIXTURE")
	if input == "" {
		t.Skip("run balance/run.sh")
	}
	data, err := os.ReadFile(input)
	require.NoError(t, err)
	fbb := factor.NewFactorBasedBalance(zap.NewNop(), nil)
	defer fbb.Close()
	group, err := NewGroup(nil, func(*zap.Logger) policy.BalancePolicy { return fbb }, MatchAll, zap.NewNop())
	require.NoError(t, err)
	cfg := config.NewConfig()
	cfg.Balance.Policy = config.BalancePolicyConnection
	group.SetConfig(cfg)
	a := newBackendWrapper("a", observer.BackendHealth{BackendInfo: observer.BackendInfo{Addr: "127.0.0.1:4000", Keyspace: "tenant"}, Healthy: true})
	b := newBackendWrapper("b", observer.BackendHealth{BackendInfo: observer.BackendInfo{Addr: "127.0.0.1:4001", Keyspace: "tenant"}, Healthy: true})
	group.AddBackend("a", a)
	group.AddBackend("b", b)
	conns := make(map[uint64]*cpMigrationConn)
	from := make(map[uint64]string)
	to := make(map[uint64]string)
	var output strings.Builder
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		row := strings.Fields(line)
		require.Len(t, row, 5)
		id, err := strconv.ParseUint(row[2], 10, 64)
		require.NoError(t, err)
		ms, err := strconv.ParseInt(row[4], 10, 64)
		require.NoError(t, err)
		now := time.Unix(100, 0).Add(time.Duration(ms) * time.Millisecond)
		owner := a
		if row[3] == "b" {
			owner = b
		}
		conn := conns[id]
		switch row[1] {
		case "reset":
		case "open":
			conns[id] = &cpMigrationConn{mockRedirectableConn: newMockRedirectableConn(t, id)}
		case "connect":
			conn.from = owner
			_, ok := group.RehydrateConn(owner.ID(), conn)
			require.True(t, ok)
		case "admit", "reject":
			cw := getConnWrapper(conn).Value
			conn.admit = row[1] == "admit"
			from[id], to[id] = cw.physicalOwner.ID(), owner.ID()
			require.Equal(t, conn.admit, group.redirectConn(cw, cw.physicalOwner, owner, "connection", nil, now))
		case "success", "late_success":
			if row[1] == "success" {
				conn.redirectSucceed()
			}
			require.NoError(t, group.OnRedirectSucceed(from[id], to[id], conn))
		case "failure":
			conn.redirectFail()
			require.NoError(t, group.OnRedirectFail(from[id], to[id], conn))
		case "close":
			require.NoError(t, group.OnConnClosed(row[3], conn))
		default:
			t.Fatalf("unknown action %s", row[1])
		}
		order := func(backend *backendWrapper) string {
			var ids []string
			for el := backend.connList.Front(); el != nil; el = el.Next() {
				ids = append(ids, strconv.FormatUint(el.Value.ConnectionID(), 10))
			}
			return strings.Join(ids, ",")
		}
		fmt.Fprintf(&output, "%s\t%s\t%s\t%d\t%d\n", row[0], order(a), order(b), a.ConnScore(), b.ConnScore())
	}
	require.NoError(t, os.WriteFile(os.Getenv("CPROUTE_ARRIVAL_OUTPUT"), []byte(output.String()), 0600))
}
