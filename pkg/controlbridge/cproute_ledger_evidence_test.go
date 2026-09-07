// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package controlbridge

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pingcap/tiproxy/lib/config"
	"github.com/pingcap/tiproxy/pkg/balance/observer"
	"github.com/pingcap/tiproxy/pkg/balance/policy"
	"github.com/pingcap/tiproxy/pkg/balance/router"
	controlpb "github.com/pingcap/tiproxy/pkg/controlbridge/pb"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// The observation drives the actual bridge's exact-attempt terminals and the
// actual score router's reservation/connection accounting. Only its transport
// and health source are fixtures; the observed transitions are not reimplemented.
func TestCPRouteLedgerObservation(t *testing.T) {
	input := os.Getenv("CPROUTE_LEDGER_FIXTURE")
	if input == "" {
		t.Skip("run make controlplane-cproute-evidence")
	}
	rows, err := os.Open(input)
	require.NoError(t, err)
	defer func() { require.NoError(t, rows.Close()) }()
	output, err := os.Create(os.Getenv("CPROUTE_LEDGER_OUTPUT"))
	require.NoError(t, err)
	defer func() { require.NoError(t, output.Close()) }()
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	ob := &manualObserver{ch: make(chan observer.HealthResult, 4)}
	rt := router.NewScoreBasedRouter(zap.NewNop())
	rt.Init(ctx, ob, func(*zap.Logger) policy.BalancePolicy {
		bp := policy.NewSimpleBalancePolicy()
		bp.Init(nil)
		return bp
	}, staticConfigGetter{cfg: config.NewConfig()}, make(chan *config.Config))
	t.Cleanup(rt.Close)
	const backendID = "ledger/tidb:4000"
	ob.ch <- observer.NewHealthResult(map[string]*observer.BackendHealth{
		backendID: {BackendInfo: observer.BackendInfo{Addr: "tidb:4000", ClusterName: "ledger"}, Healthy: true, SupportRedirection: true},
	}, nil)
	require.Eventually(t, func() bool { return rt.HealthyBackendCount() == 1 }, time.Second, time.Millisecond)
	instance, ok := rt.LookupBackend(backendID)
	require.True(t, ok)
	score, ok := instance.(interface{ ConnScore() int })
	require.True(t, ok)
	adapter := newTestAdapter(t, &recordingHandler{rt: rt})
	peer := newFakeSender(7)
	var current, previous *controlpb.RouteAssignment
	var connectionID uint64 = 9
	scan := bufio.NewScanner(rows)
	for scan.Scan() {
		if strings.HasPrefix(scan.Text(), "#") || scan.Text() == "" {
			continue
		}
		fields := strings.Split(scan.Text(), "\t")
		require.Len(t, fields, 2)
		t.Logf("ledger row %s", fields[0])
		switch fields[1] {
		case "reserve":
			previous = current
			connectionID++
			sendHandshake(t, adapter, peer, connectionID, "0.0.0.0:6000", "root")
			sendRoute(t, adapter, peer, connectionID, "0.0.0.0:6000", "root")
			current = lastAssignment(t, peer)
		case "repeat":
			sendRoute(t, adapter, peer, connectionID, "0.0.0.0:6000", "root")
			require.Equal(t, current.GetAssignmentId(), lastAssignment(t, peer).GetAssignmentId())
		case "commit":
			sendRouteResult(t, adapter, peer, current, true)
		case "fail":
			sendRouteResult(t, adapter, peer, current, false)
		case "close":
			require.NoError(t, adapter.HandleEnvelope(ctx, peer, connectionEvent(connectionID, controlpb.ConnectionEventKind_CONNECTION_EVENT_KIND_CLOSED)))
		case "old_commit":
			sendRouteResult(t, adapter, peer, previous, true)
		case "old_fail":
			sendRouteResult(t, adapter, peer, previous, false)
		case "fail_retry":
			previous = current
			sendRouteResult(t, adapter, peer, current, false)
			current = lastAssignment(t, peer)
			require.NotEqual(t, previous.GetAssignmentId(), current.GetAssignmentId())
		default:
			t.Fatalf("unknown operation %s", fields[1])
		}
		_, err := fmt.Fprintf(output, "%s\t%d\t%d\n", fields[0], score.ConnScore(), rt.ConnCount())
		require.NoError(t, err)
	}
	require.NoError(t, scan.Err())
}
