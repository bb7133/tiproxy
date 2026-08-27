// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package controlbridge

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/pingcap/tiproxy/lib/config"
	"github.com/pingcap/tiproxy/pkg/balance/observer"
	"github.com/pingcap/tiproxy/pkg/balance/policy"
	"github.com/pingcap/tiproxy/pkg/balance/router"
	controlpb "github.com/pingcap/tiproxy/pkg/controlbridge/pb"
	"github.com/pingcap/tiproxy/pkg/manager/namespace"
	"github.com/pingcap/tiproxy/pkg/proxy/backend"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// manualObserver feeds scripted health results through the production
// subscription path.
type manualObserver struct {
	ch chan observer.HealthResult
}

func (ob *manualObserver) Start(context.Context)                         {}
func (ob *manualObserver) Subscribe(string) <-chan observer.HealthResult { return ob.ch }
func (ob *manualObserver) Unsubscribe(string)                            {}
func (ob *manualObserver) Refresh()                                      {}
func (ob *manualObserver) Close()                                        {}

type staticConfigGetter struct{ cfg *config.Config }

func (getter staticConfigGetter) GetConfig() *config.Config { return getter.cfg }

// parityBackend describes one fabricated backend for a parity router.
type parityBackend struct {
	addr    string
	cluster string
	labels  map[string]string
}

// newParityRouter builds a REAL score-based router through its
// production Init path (observer subscription, routing rule from
// config, balance policy) and feeds it one health observation.
func newParityRouter(t *testing.T, routingRule string, backends []parityBackend) *router.ScoreBasedRouter {
	t.Helper()
	rt := router.NewScoreBasedRouter(zap.NewNop())
	cfg := config.NewConfig()
	cfg.Balance.RoutingRule = routingRule
	ob := &manualObserver{ch: make(chan observer.HealthResult, 4)}
	rt.Init(context.Background(), ob,
		func(*zap.Logger) policy.BalancePolicy {
			bp := policy.NewSimpleBalancePolicy()
			bp.Init(nil)
			return bp
		},
		staticConfigGetter{cfg: cfg}, make(chan *config.Config))
	t.Cleanup(rt.Close)
	health := make(map[string]*observer.BackendHealth, len(backends))
	for _, spec := range backends {
		health[spec.cluster+"/"+spec.addr] = &observer.BackendHealth{
			BackendInfo: observer.BackendInfo{
				Addr:        spec.addr,
				ClusterName: spec.cluster,
				Labels:      spec.labels,
			},
			Healthy:            true,
			SupportRedirection: true,
		}
	}
	ob.ch <- observer.NewHealthResult(health, nil)
	require.Eventually(t, func() bool { return rt.HealthyBackendCount() == len(backends) },
		3*time.Second, 10*time.Millisecond, "the router absorbed the health observation")
	return rt
}

// goModeSelection routes exactly like Go mode does, through the SAME
// handshake handler and the SAME projected connection state the Rust
// seam uses, and returns the chosen backend address.
func goModeSelection(
	t *testing.T,
	handler backend.HandshakeHandler,
	identity *controlpb.ConnectionIdentity,
	metadata *controlpb.HandshakeMetadata,
) string {
	t.Helper()
	conn := newProjectedConn(newTestAdapter(t, handler), identity)
	rt, err := handler.GetRouter(conn, projectHandshake(metadata))
	require.NoError(t, err)
	selector := rt.GetBackendSelector(projectClientInfo(identity))
	selected, err := selector.Next()
	require.NoError(t, err)
	return selected.Addr()
}

// rustModeSelection routes through the control-plane seam (handshake
// event, then route request) and returns the assigned address plus the
// decision's namespace.
func rustModeSelection(
	t *testing.T,
	adapter *RouterAdapter,
	peer *fakeSender,
	connectionID uint64,
	listener, user string,
) (string, string) {
	t.Helper()
	sendHandshake(t, adapter, peer, connectionID, listener, user)
	decision := lastDecision(t, peer)
	require.True(t, decision.GetAccept(), "handshake accepted: %v", decision)
	sendRoute(t, adapter, peer, connectionID, listener, user)
	assignment := lastAssignment(t, peer)
	require.Equal(t, controlpb.ErrorCode_ERROR_CODE_OK, assignment.GetCode(),
		"route assigned: %v", assignment)
	return assignment.GetBackendAddress(), decision.GetNamespace()
}

// Three namespace × cluster combinations resolved by username: the same
// client must select the same backend class in Go mode and Rust mode,
// and the decision must carry the namespace it resolved to.
func TestNamespaceParityAcrossModes(t *testing.T) {
	nsMgr := namespace.NewNamespaceManager()
	nsMgr.SetNamespaceForTest(namespace.NewNamespaceForTest("ns-alpha", "alice",
		newParityRouter(t, "", []parityBackend{{addr: "alpha-tidb:4000", cluster: "alpha"}})))
	nsMgr.SetNamespaceForTest(namespace.NewNamespaceForTest("ns-beta", "bob",
		newParityRouter(t, "", []parityBackend{{addr: "beta-tidb:4000", cluster: "beta"}})))
	nsMgr.SetNamespaceForTest(namespace.NewNamespaceForTest("default", "",
		newParityRouter(t, "", []parityBackend{{addr: "gamma-tidb:4000", cluster: "gamma"}})))
	handler := backend.NewDefaultHandshakeHandler(nsMgr)
	adapter := newTestAdapter(t, handler)
	peer := newFakeSender(1)

	for index, want := range []struct {
		user      string
		namespace string
		address   string
	}{
		{user: "alice", namespace: "ns-alpha", address: "alpha-tidb:4000"},
		{user: "bob", namespace: "ns-beta", address: "beta-tidb:4000"},
		{user: "carol", namespace: "default", address: "gamma-tidb:4000"},
	} {
		connectionID := uint64(100 + index)
		listener := "0.0.0.0:" + strconv.Itoa(6000+index)
		identity := testIdentity(connectionID, listener)
		goAddress := goModeSelection(t, handler, identity, testHandshake(want.user))
		require.Equal(t, want.address, goAddress, "Go mode selects the expected class")

		rustAddress, decisionNamespace := rustModeSelection(t, adapter, peer, connectionID, listener, want.user)
		require.Equal(t, goAddress, rustAddress,
			"the same client selects the same backend in both modes")
		require.Equal(t, want.namespace, decisionNamespace)
	}
}

// The same user on different listener ports lands on different
// cluster-scoped backend classes under port routing — identically in
// both modes — and a port claimed by two clusters is refused, never
// silently routed.
func TestListenerPortRoutingParityAndConflict(t *testing.T) {
	portRouter := newParityRouter(t, config.MatchPortStr, []parityBackend{
		{addr: "alpha-tidb:4000", cluster: "alpha",
			labels: map[string]string{config.TiProxyPortLabelName: "6000"}},
		{addr: "beta-tidb:4000", cluster: "beta",
			labels: map[string]string{config.TiProxyPortLabelName: "7000"}},
		{addr: "alpha-tidb-2:4000", cluster: "alpha",
			labels: map[string]string{config.TiProxyPortLabelName: "8000"}},
		{addr: "beta-tidb-2:4000", cluster: "beta",
			labels: map[string]string{config.TiProxyPortLabelName: "8000"}},
	})
	nsMgr := namespace.NewNamespaceManager()
	nsMgr.SetNamespaceForTest(namespace.NewNamespaceForTest("default", "", portRouter))
	handler := backend.NewDefaultHandshakeHandler(nsMgr)
	adapter := newTestAdapter(t, handler)
	peer := newFakeSender(1)

	for index, want := range []struct {
		listener string
		address  string
	}{
		{listener: "0.0.0.0:6000", address: "alpha-tidb:4000"},
		{listener: "0.0.0.0:7000", address: "beta-tidb:4000"},
	} {
		connectionID := uint64(200 + index)
		identity := testIdentity(connectionID, want.listener)
		goAddress := goModeSelection(t, handler, identity, testHandshake("root"))
		require.Equal(t, want.address, goAddress)
		rustAddress, _ := rustModeSelection(t, adapter, peer, connectionID, want.listener, "root")
		require.Equal(t, goAddress, rustAddress)
	}

	// Port 8000 is claimed by both clusters: refused in both modes with
	// the same conflict semantics.
	conflictIdentity := testIdentity(300, "0.0.0.0:8000")
	conn := newProjectedConn(adapter, conflictIdentity)
	rt, err := handler.GetRouter(conn, projectHandshake(testHandshake("root")))
	require.NoError(t, err)
	conflictSelector := rt.GetBackendSelector(projectClientInfo(conflictIdentity))
	_, goErr := conflictSelector.Next()
	require.ErrorIs(t, goErr, router.ErrPortConflict)

	sendHandshake(t, adapter, peer, 300, "0.0.0.0:8000", "root")
	sendRoute(t, adapter, peer, 300, "0.0.0.0:8000", "root")
	assignment := lastAssignment(t, peer)
	require.Equal(t, controlpb.ErrorCode_ERROR_CODE_INTERNAL, assignment.GetCode(),
		"a conflict is not a no-backend condition")
	require.Contains(t, assignment.GetDetail(), "claimed by multiple backend clusters")
}

// Unknown namespace and no-healthy-backend produce the same refusals in
// Rust mode as Go mode's error classes.
func TestNamespaceErrorParity(t *testing.T) {
	// No default namespace and no user match: the handshake is refused.
	emptyMgr := namespace.NewNamespaceManager()
	emptyMgr.SetNamespaceForTest(namespace.NewNamespaceForTest("ns-alpha", "alice",
		newParityRouter(t, "", []parityBackend{{addr: "alpha-tidb:4000", cluster: "alpha"}})))
	adapter := newTestAdapter(t, backend.NewDefaultHandshakeHandler(emptyMgr))
	peer := newFakeSender(1)
	sendHandshake(t, adapter, peer, 400, "0.0.0.0:6000", "missing")
	decision := lastDecision(t, peer)
	require.False(t, decision.GetAccept())
	require.Equal(t, controlpb.ErrorCode_ERROR_CODE_HANDSHAKE_REJECTED, decision.GetCode())
	require.Contains(t, decision.GetClientMessage(), "failed to find a namespace")

	// A namespace whose router has no healthy backend refuses the route
	// with the no-backend class and Go's exact client-facing error.
	starvedMgr := namespace.NewNamespaceManager()
	starvedMgr.SetNamespaceForTest(namespace.NewNamespaceForTest("default", "",
		newParityRouter(t, "", nil)))
	starvedAdapter := newTestAdapter(t, backend.NewDefaultHandshakeHandler(starvedMgr))
	starvedPeer := newFakeSender(1)
	sendHandshake(t, starvedAdapter, starvedPeer, 401, "0.0.0.0:6000", "root")
	sendRoute(t, starvedAdapter, starvedPeer, 401, "0.0.0.0:6000", "root")
	assignment := lastAssignment(t, starvedPeer)
	require.Equal(t, controlpb.ErrorCode_ERROR_CODE_NO_BACKEND, assignment.GetCode())
	require.Contains(t, assignment.GetDetail(), backend.ErrProxyNoBackend.Error())
}

// A dynamic namespace change re-maps NEW connections only: the session
// established before the change keeps routing against its original
// namespace's backends, so it can never migrate to another keyspace.
func TestDynamicNamespaceChangeKeepsExistingSession(t *testing.T) {
	nsMgr := namespace.NewNamespaceManager()
	nsMgr.SetNamespaceForTest(namespace.NewNamespaceForTest("default", "",
		newParityRouter(t, "", []parityBackend{{addr: "old-tidb:4000", cluster: "old",
			labels: map[string]string{config.KeyspaceLabelName: "ks-old"}}})))
	handler := backend.NewDefaultHandshakeHandler(nsMgr)
	adapter := newTestAdapter(t, handler)
	peer := newFakeSender(1)

	// The existing session pins its router at handshake time.
	sendHandshake(t, adapter, peer, 500, "0.0.0.0:6000", "root")
	require.True(t, lastDecision(t, peer).GetAccept())

	// The operator commits a replacement namespace (same name, new
	// cluster/keyspace).
	nsMgr.SetNamespaceForTest(namespace.NewNamespaceForTest("default", "",
		newParityRouter(t, "", []parityBackend{{addr: "new-tidb:4000", cluster: "new",
			labels: map[string]string{config.KeyspaceLabelName: "ks-new"}}})))

	// The pre-change session still routes inside its original keyspace.
	sendRoute(t, adapter, peer, 500, "0.0.0.0:6000", "root")
	assignment := lastAssignment(t, peer)
	require.Equal(t, controlpb.ErrorCode_ERROR_CODE_OK, assignment.GetCode())
	require.Equal(t, "old-tidb:4000", assignment.GetBackendAddress(),
		"an established session never migrates to the new namespace's keyspace")
	require.Equal(t, "ks-old", assignment.GetKeyspace())

	// A brand-new connection observes the committed change.
	address, _ := rustModeSelection(t, adapter, peer, 501, "0.0.0.0:6000", "root")
	require.Equal(t, "new-tidb:4000", address)
}
