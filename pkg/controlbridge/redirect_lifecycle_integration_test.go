// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package controlbridge

import (
	"context"
	"testing"
	"time"

	"github.com/pingcap/tiproxy/lib/config"
	"github.com/pingcap/tiproxy/pkg/balance/observer"
	"github.com/pingcap/tiproxy/pkg/balance/policy"
	"github.com/pingcap/tiproxy/pkg/balance/router"
	controlpb "github.com/pingcap/tiproxy/pkg/controlbridge/pb"
	"github.com/pingcap/tiproxy/pkg/metrics"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"
)

// A failed Rust redirect terminal must close the same old-to-target accounting
// route that the production score router opened. The physical owner and
// connection count stay on the old backend, while a duplicate terminal is a
// no-op instead of decrementing the pending gauge twice.
func TestRedirectFailureBalancesExactRouteAccounting(t *testing.T) {
	const (
		connectionID = uint64(4402)
		backendAID   = "mig-02/tidb-a:4000"
		backendAAddr = "tidb-a:4000"
		backendBID   = "mig-02/tidb-b:4000"
		backendBAddr = "tidb-b:4000"
	)

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	ob := &manualObserver{ch: make(chan observer.HealthResult, 4)}
	cfg := config.NewConfig()
	rt := router.NewScoreBasedRouter(zap.NewNop())
	rt.Init(ctx, ob,
		func(*zap.Logger) policy.BalancePolicy {
			bp := policy.NewSimpleBalancePolicy()
			bp.Init(nil)
			return bp
		},
		staticConfigGetter{cfg: cfg}, make(chan *config.Config))
	t.Cleanup(rt.Close)

	initialHealth := map[string]*observer.BackendHealth{
		backendAID: {
			BackendInfo: observer.BackendInfo{Addr: backendAAddr, ClusterName: "mig-02"},
			Healthy:     true, SupportRedirection: true,
		},
		backendBID: {
			BackendInfo: observer.BackendInfo{Addr: backendBAddr, ClusterName: "mig-02"},
			Healthy:     true, SupportRedirection: true,
		},
	}
	ob.ch <- observer.NewHealthResult(initialHealth, nil)
	require.Eventually(t, func() bool { return rt.HealthyBackendCount() == 2 },
		time.Second, 10*time.Millisecond)

	handler := &recordingHandler{rt: rt}
	adapter := newTestAdapter(t, handler)
	peer := newFakeSender(44)
	establishConnection(t, adapter, peer, connectionID, "0.0.0.0:6000", "root")
	require.Equal(t, 1, rt.ConnCount())

	state := adapter.get(connectionID)
	require.NotNil(t, state)
	state.mu.Lock()
	oldID := state.currentBackend.ID()
	oldAddr := state.currentBackend.Addr()
	conn := state.conn
	state.mu.Unlock()
	targetID, targetAddr := backendAID, backendAAddr
	if oldID == backendAID {
		targetID, targetAddr = backendBID, backendBAddr
	}
	require.NotEqual(t, oldID, targetID)

	pendingGauge := metrics.PendingMigrateGuage.WithLabelValues(oldAddr, targetAddr, "status")
	baseline, err := metrics.ReadGauge(pendingGauge)
	require.NoError(t, err)

	failedHealth := map[string]*observer.BackendHealth{
		backendAID: {
			BackendInfo: observer.BackendInfo{Addr: backendAAddr, ClusterName: "mig-02"},
			Healthy:     backendAID != oldID, SupportRedirection: true,
		},
		backendBID: {
			BackendInfo: observer.BackendInfo{Addr: backendBAddr, ClusterName: "mig-02"},
			Healthy:     backendBID != oldID, SupportRedirection: true,
		},
	}
	ob.ch <- observer.NewHealthResult(failedHealth, nil)

	var redirectEnvelope *controlpb.ControlEnvelope
	require.Eventually(t, func() bool {
		peer.mu.Lock()
		defer peer.mu.Unlock()
		for index := len(peer.messages) - 1; index >= 0; index-- {
			if peer.messages[index].GetRedirectCommand() == nil {
				continue
			}
			cloned, ok := proto.Clone(peer.messages[index]).(*controlpb.ControlEnvelope)
			if ok {
				redirectEnvelope = cloned
				return true
			}
		}
		return false
	}, time.Second, 10*time.Millisecond, "the unhealthy owner is redirected through the production balance loop")
	redirect := redirectEnvelope.GetRedirectCommand()
	require.Equal(t, oldID, state.currentBackend.ID())
	require.Equal(t, targetID, redirect.GetBackendId())
	require.Equal(t, targetAddr, redirect.GetBackendAddress())
	require.Equal(t, uint64(7), redirectEnvelope.GetGeneration())
	require.Equal(t, uint64(1), redirect.GetCommandSequence())
	require.Eventually(t, func() bool {
		value, readErr := metrics.ReadGauge(pendingGauge)
		return readErr == nil && value == baseline+1
	}, time.Second, 10*time.Millisecond, "the exact old-to-target route is pending")

	failed := &controlpb.ControlEnvelope{
		RequestId: 991,
		Body: &controlpb.ControlEnvelope_RedirectResult{RedirectResult: &controlpb.RedirectResult{
			ConnectionId:      connectionID,
			RedirectId:        redirect.GetRedirectId(),
			PreviousBackendId: oldID,
			BackendId:         targetID,
			Succeeded:         false,
			Code:              controlpb.ErrorCode_ERROR_CODE_REDIRECT_FAILED,
		}},
	}
	require.NoError(t, adapter.HandleEnvelope(context.Background(), peer, failed))
	value, err := metrics.ReadGauge(pendingGauge)
	require.NoError(t, err)
	require.Equal(t, baseline, value, "failure retires the exact pending route once")
	require.Equal(t, oldAddr, conn.ServerAddr(), "failure keeps the physical owner")
	require.Equal(t, 1, rt.ConnCount())

	require.NoError(t, adapter.HandleEnvelope(context.Background(), peer, failed))
	value, err = metrics.ReadGauge(pendingGauge)
	require.NoError(t, err)
	require.Equal(t, baseline, value, "duplicate failure cannot decrement accounting twice")
	require.Equal(t, oldAddr, conn.ServerAddr())
	require.Equal(t, 1, rt.ConnCount())

	closed := connectionEvent(connectionID, controlpb.ConnectionEventKind_CONNECTION_EVENT_KIND_CLOSED)
	require.NoError(t, adapter.HandleEnvelope(context.Background(), peer, closed))
	require.NoError(t, adapter.HandleEnvelope(context.Background(), peer, closed))
	require.Equal(t, 1, handler.closeCount())
	require.Equal(t, 0, rt.ConnCount())
}
