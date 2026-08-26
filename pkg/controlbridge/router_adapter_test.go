// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package controlbridge

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/go-mysql-org/go-mysql/mysql"
	"github.com/pingcap/tiproxy/pkg/balance/router"
	controlpb "github.com/pingcap/tiproxy/pkg/controlbridge/pb"
	"github.com/pingcap/tiproxy/pkg/controlbridge/transport"
	"github.com/pingcap/tiproxy/pkg/manager/namespace"
	"github.com/pingcap/tiproxy/pkg/proxy/backend"
	pnet "github.com/pingcap/tiproxy/pkg/proxy/net"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestRouterAdapterHandshakeHandlerPaths(t *testing.T) {
	t.Run("static", func(t *testing.T) {
		handler := backend.NewStaticHandshakeHandler("tidb-static:4000")
		adapter := newTestAdapter(t, handler)
		peer := newFakeSender(1)
		sendHandshake(t, adapter, peer, 1, "0.0.0.0:6000", "root")
		require.True(t, lastDecision(t, peer).GetAccept())
		require.Equal(t, "default", lastDecision(t, peer).GetNamespace())
		sendRoute(t, adapter, peer, 1, "0.0.0.0:6000", "root")
		require.Equal(t, "tidb-static:4000", lastAssignment(t, peer).GetBackendAddress())
	})

	t.Run("default unknown namespace", func(t *testing.T) {
		handler := backend.NewDefaultHandshakeHandler(namespace.NewNamespaceManager())
		adapter := newTestAdapter(t, handler)
		peer := newFakeSender(1)
		sendHandshake(t, adapter, peer, 2, "0.0.0.0:6000", "missing")
		decision := lastDecision(t, peer)
		require.False(t, decision.GetAccept())
		require.Equal(t, controlpb.ErrorCode_ERROR_CODE_HANDSHAKE_REJECTED, decision.GetCode())
	})

	t.Run("custom projected metadata", func(t *testing.T) {
		handler := &recordingHandler{rt: router.NewStaticRouter([]string{"tidb-custom:4000"})}
		adapter := newTestAdapter(t, handler)
		peer := newFakeSender(1)
		sendHandshake(t, adapter, peer, 3, "127.0.0.1:6001", "alice")
		require.True(t, lastDecision(t, peer).GetAccept())
		require.NotNil(t, handler.response)
		require.Nil(t, handler.response.AuthData)
		require.Equal(t, "alice", handler.response.User)
		require.Equal(t, "db", handler.response.DB)
		require.Equal(t, "caching_sha2_password", handler.response.AuthPlugin)
		require.Equal(t, map[string]string{"program_name": "adapter-test"}, handler.response.Attrs)
	})
}

func TestRouterAdapterRetryAndExactlyOnceLifecycle(t *testing.T) {
	rt := router.NewStaticRouter([]string{"tidb-a:4000", "tidb-b:4000"})
	handler := &recordingHandler{rt: rt, retryHandshakeErrors: 1}
	adapter := newTestAdapter(t, handler)
	peer := newFakeSender(7,
		uint64(controlpb.ControlCapability_CONTROL_CAPABILITY_PER_CONNECTION_CLOSE),
		uint64(controlpb.ControlCapability_CONTROL_CAPABILITY_RECONCILE_CONNECTIONS))

	sendHandshake(t, adapter, peer, 10, "0.0.0.0:6000", "root")
	sendRoute(t, adapter, peer, 10, "0.0.0.0:6000", "root")
	first := lastAssignment(t, peer)
	require.Equal(t, "tidb-a:4000", first.GetBackendAddress())

	// A failed dial releases the first score exactly once and selects the next backend.
	sendRouteResult(t, adapter, peer, first, false)
	second := lastAssignment(t, peer)
	require.Equal(t, "tidb-b:4000", second.GetBackendAddress())
	sendRouteResultWithID(t, adapter, peer, 10, first.GetAssignmentId(), false)
	require.Equal(t, 0, rt.ConnCount())
	sendRouteResult(t, adapter, peer, second, true)
	sendRouteResult(t, adapter, peer, second, true)
	require.Equal(t, 1, rt.ConnCount())

	// A retryable TiDB SQL handshake error abandons the registered backend,
	// then reserves exactly one replacement score.
	require.NoError(t, adapter.HandleEnvelope(context.Background(), peer, &controlpb.ControlEnvelope{
		RequestId: 20,
		Body: &controlpb.ControlEnvelope_HandshakeResult{HandshakeResult: &controlpb.HandshakeResult{
			ConnectionId:   10,
			BackendId:      second.GetBackendId(),
			BackendAddress: second.GetBackendAddress(),
			ErrorSource:    controlpb.ErrorSource_ERROR_SOURCE_BACKEND_SQL,
			Code:           controlpb.ErrorCode_ERROR_CODE_HANDSHAKE_REJECTED,
			MysqlError:     &controlpb.MysqlError{Code: 1045, SqlState: "28000", Message: "access denied"},
		}},
	}))
	third := lastAssignment(t, peer)
	require.NotEqual(t, second.GetAssignmentId(), third.GetAssignmentId())
	require.Equal(t, "tidb-a:4000", third.GetBackendAddress())
	require.Equal(t, 0, rt.ConnCount())
	sendRouteResult(t, adapter, peer, third, true)
	require.Equal(t, 1, rt.ConnCount())

	success := &controlpb.ControlEnvelope{
		RequestId: 21,
		Body: &controlpb.ControlEnvelope_HandshakeResult{HandshakeResult: &controlpb.HandshakeResult{
			ConnectionId:   10,
			BackendId:      third.GetBackendId(),
			BackendAddress: third.GetBackendAddress(),
			Code:           controlpb.ErrorCode_ERROR_CODE_OK,
		}},
	}
	require.NoError(t, adapter.HandleEnvelope(context.Background(), peer, success))
	require.NoError(t, adapter.HandleEnvelope(context.Background(), peer, success))
	require.Equal(t, 1, handler.handshakeCalls)
	require.NoError(t, handler.handshakeErr)

	traffic := connectionEvent(10, controlpb.ConnectionEventKind_CONNECTION_EVENT_KIND_TRAFFIC)
	traffic.GetConnectionEvent().ClientInBytes = 100
	traffic.GetConnectionEvent().ClientOutBytes = 200
	require.NoError(t, adapter.HandleEnvelope(context.Background(), peer, traffic))
	require.NoError(t, adapter.HandleEnvelope(context.Background(), peer, traffic))
	require.Equal(t, 1, handler.trafficCalls)
	require.Equal(t, uint64(100), handler.lastClientIn)
	require.Equal(t, uint64(200), handler.lastClientOut)

	closed := connectionEvent(10, controlpb.ConnectionEventKind_CONNECTION_EVENT_KIND_CLOSED)
	require.NoError(t, adapter.HandleEnvelope(context.Background(), peer, closed))
	require.NoError(t, adapter.HandleEnvelope(context.Background(), peer, closed))
	require.Equal(t, 1, handler.closeCalls)
	require.Equal(t, 0, rt.ConnCount())
	require.Equal(t, 0, adapter.ConnectionCount())
}

func TestRouterAdapterNoBackend(t *testing.T) {
	handler := &recordingHandler{rt: router.NewStaticRouter(nil)}
	adapter := newTestAdapter(t, handler)
	peer := newFakeSender(1)
	sendHandshake(t, adapter, peer, 11, "0.0.0.0:6000", "root")
	sendRoute(t, adapter, peer, 11, "0.0.0.0:6000", "root")
	assignment := lastAssignment(t, peer)
	require.Equal(t, controlpb.ErrorCode_ERROR_CODE_NO_BACKEND, assignment.GetCode())
	require.Empty(t, assignment.GetAssignmentId())
	require.Equal(t, 1, handler.handshakeCalls)
	require.ErrorIs(t, handler.handshakeErr, backend.ErrProxyNoBackend)
}

func TestRouterAdapterRedirectEvictionAndReconcile(t *testing.T) {
	rt := router.NewStaticRouter([]string{"tidb-a:4000"})
	handler := &recordingHandler{rt: rt}
	adapter := newTestAdapter(t, handler)
	peer := newFakeSender(9,
		uint64(controlpb.ControlCapability_CONTROL_CAPABILITY_PER_CONNECTION_CLOSE),
		uint64(controlpb.ControlCapability_CONTROL_CAPABILITY_RECONCILE_CONNECTIONS))
	establishConnection(t, adapter, peer, 30, "0.0.0.0:6000", "root")
	establishConnection(t, adapter, peer, 31, "0.0.0.0:6001", "root")
	require.Equal(t, 2, rt.ConnCount())

	state := adapter.get(30)
	require.NotNil(t, state)
	state.mu.Lock()
	conn := state.conn
	underlying := conn.eventReceiver()
	receiver := &recordingReceiver{next: underlying}
	conn.SetEventReceiver(receiver)
	state.mu.Unlock()
	target := router.NewStaticBackend("tidb-b:4000")
	require.True(t, conn.Redirect(target))
	redirect := lastEnvelope(t, peer).GetRedirectCommand()
	require.NotNil(t, redirect)
	require.Equal(t, uint64(1), lastEnvelope(t, peer).GetRequestId(),
		"application commands share the sender's checked request-id lineage")
	redirectResult := &controlpb.ControlEnvelope{
		RequestId: 40,
		Body: &controlpb.ControlEnvelope_RedirectResult{RedirectResult: &controlpb.RedirectResult{
			ConnectionId:      30,
			RedirectId:        redirect.GetRedirectId(),
			PreviousBackendId: "tidb-a:4000",
			BackendId:         "tidb-b:4000",
			Succeeded:         true,
		}},
	}
	require.NoError(t, adapter.HandleEnvelope(context.Background(), peer, redirectResult))
	require.NoError(t, adapter.HandleEnvelope(context.Background(), peer, redirectResult))
	require.Equal(t, 1, receiver.redirectSuccess)
	require.Equal(t, "tidb-b:4000", conn.ServerAddr())

	require.True(t, conn.ForceClose())
	require.False(t, conn.ForceClose())
	closeCommand := lastEnvelope(t, peer).GetCloseCommand()
	require.NotNil(t, closeCommand)
	require.Equal(t, uint64(2), lastEnvelope(t, peer).GetRequestId())
	require.True(t, closeCommand.GetForce())
	require.Equal(t, []uint64{uint64(controlpb.ControlCapability_CONTROL_CAPABILITY_PER_CONNECTION_CLOSE)},
		lastEnvelope(t, peer).GetRequiredCapabilities())

	// A new Rust epoch reports only connection 30. Connection 31 is removed
	// from handler and router accounting once; unknown Rust connection 999 is
	// deliberately omitted from Go's authoritative snapshot.
	reconnected := newFakeSender(10,
		uint64(controlpb.ControlCapability_CONTROL_CAPABILITY_PER_CONNECTION_CLOSE),
		uint64(controlpb.ControlCapability_CONTROL_CAPABILITY_RECONCILE_CONNECTIONS))
	reconcile := reconcileEnvelope(50, 8, 30, 999)
	require.NoError(t, adapter.HandleEnvelope(context.Background(), reconnected, reconcile))
	snapshot := lastEnvelope(t, reconnected).GetReconcileSnapshot()
	require.NotNil(t, snapshot)
	require.Len(t, snapshot.GetConnections(), 1)
	require.Equal(t, uint64(30), snapshot.GetConnections()[0].GetConnectionId())
	require.Equal(t, 1, handler.closeCalls)
	require.Equal(t, 1, rt.ConnCount())

	require.NoError(t, adapter.HandleEnvelope(context.Background(), reconnected, reconcile))
	require.Equal(t, 1, handler.closeCalls)
	require.Equal(t, 1, rt.ConnCount())

	closed := connectionEvent(30, controlpb.ConnectionEventKind_CONNECTION_EVENT_KIND_CLOSED)
	require.NoError(t, adapter.HandleEnvelope(context.Background(), reconnected, closed))
	require.NoError(t, adapter.HandleEnvelope(context.Background(), reconnected, closed))
	require.Equal(t, 2, handler.closeCalls)
	require.Equal(t, 0, rt.ConnCount())
}

func TestRouterAdapterMultiPortRouting(t *testing.T) {
	rt := &portRouter{routes: map[string]*router.StaticRouter{
		"6000": router.NewStaticRouter([]string{"cluster-a-tidb:4000"}),
		"7000": router.NewStaticRouter([]string{"cluster-b-tidb:4000"}),
	}}
	handler := &recordingHandler{rt: rt}
	adapter := newTestAdapter(t, handler)
	peer := newFakeSender(1)

	for _, test := range []struct {
		id       uint64
		listener string
		backend  string
	}{
		{id: 61, listener: "[::]:6000", backend: "cluster-a-tidb:4000"},
		{id: 62, listener: "127.0.0.1:7000", backend: "cluster-b-tidb:4000"},
	} {
		sendHandshake(t, adapter, peer, test.id, test.listener, "root")
		sendRoute(t, adapter, peer, test.id, test.listener, "root")
		require.Equal(t, test.backend, lastAssignment(t, peer).GetBackendAddress())
	}
	require.Len(t, rt.clients, 2)
	require.Equal(t, "6000", rt.clients[0].ListenerPort)
	require.Equal(t, "10.0.0.1:12345", rt.clients[0].ClientAddr.String())
	require.Equal(t, "192.0.2.10:4000", rt.clients[0].ProxyAddr.String())
	require.Equal(t, "7000", rt.clients[1].ListenerPort)
}

func TestRouterAdapterRequiresNegotiatedCapability(t *testing.T) {
	adapter := newTestAdapter(t, &recordingHandler{rt: router.NewStaticRouter(nil)})
	peer := newFakeSender(1)
	reconcile := reconcileEnvelope(70, 1)
	require.NoError(t, adapter.HandleEnvelope(context.Background(), peer, reconcile))
	protocolErr := lastEnvelope(t, peer).GetError()
	require.NotNil(t, protocolErr)
	require.Equal(t, controlpb.ErrorCode_ERROR_CODE_MISSING_CAPABILITY, protocolErr.GetCode())
}

type fakeSender struct {
	mu           sync.Mutex
	epoch        uint64
	nextID       uint64
	capabilities map[uint64]struct{}
	messages     []*controlpb.ControlEnvelope
}

func newFakeSender(epoch uint64, capabilities ...uint64) *fakeSender {
	peer := &fakeSender{epoch: epoch, capabilities: make(map[uint64]struct{}, len(capabilities))}
	for _, capability := range capabilities {
		peer.capabilities[capability] = struct{}{}
	}
	return peer
}

func (peer *fakeSender) Send(_ context.Context, envelope *controlpb.ControlEnvelope) error {
	peer.mu.Lock()
	defer peer.mu.Unlock()
	cloned, ok := proto.Clone(envelope).(*controlpb.ControlEnvelope)
	if !ok {
		return errors.New("clone fake envelope")
	}
	cloned.ControlEpoch = peer.epoch
	peer.messages = append(peer.messages, cloned)
	return nil
}

func (peer *fakeSender) Epoch() uint64 { return peer.epoch }

func (peer *fakeSender) HasCapability(capability uint64) bool {
	_, ok := peer.capabilities[capability]
	return ok
}

func (peer *fakeSender) AllocateRequestID() (uint64, error) {
	peer.mu.Lock()
	defer peer.mu.Unlock()
	if peer.nextID == ^uint64(0) {
		return 0, transport.ErrRequestIDExhausted
	}
	peer.nextID++
	return peer.nextID, nil
}

type recordingHandler struct {
	mu                   sync.Mutex
	rt                   router.Router
	response             *pnet.HandshakeResp
	retryHandshakeErrors int
	handshakeCalls       int
	handshakeErr         error
	trafficCalls         int
	closeCalls           int
	lastClientIn         uint64
	lastClientOut        uint64
}

func (handler *recordingHandler) HandleHandshakeResp(_ backend.ConnContext, response *pnet.HandshakeResp) error {
	handler.mu.Lock()
	defer handler.mu.Unlock()
	handler.response = response
	return nil
}

func (handler *recordingHandler) HandleHandshakeErr(_ backend.ConnContext, _ *mysql.MyError) bool {
	handler.mu.Lock()
	defer handler.mu.Unlock()
	if handler.retryHandshakeErrors > 0 {
		handler.retryHandshakeErrors--
		return true
	}
	return false
}

func (handler *recordingHandler) GetRouter(_ backend.ConnContext, _ *pnet.HandshakeResp) (router.Router, error) {
	if handler.rt == nil {
		return nil, errors.New("no router")
	}
	return handler.rt, nil
}

func (handler *recordingHandler) OnHandshake(_ backend.ConnContext, _ string, err error, _ backend.ErrorSource) {
	handler.mu.Lock()
	defer handler.mu.Unlock()
	handler.handshakeCalls++
	handler.handshakeErr = err
}

func (handler *recordingHandler) OnConnClose(_ backend.ConnContext, _ backend.ErrorSource) error {
	handler.mu.Lock()
	defer handler.mu.Unlock()
	handler.closeCalls++
	return nil
}

func (handler *recordingHandler) OnTraffic(ctx backend.ConnContext) {
	handler.mu.Lock()
	defer handler.mu.Unlock()
	handler.trafficCalls++
	handler.lastClientIn = ctx.ClientInBytes()
	handler.lastClientOut = ctx.ClientOutBytes()
}

func (handler *recordingHandler) GetCapability() pnet.Capability {
	return backend.SupportedServerCapabilities
}
func (handler *recordingHandler) GetServerVersion() string { return pnet.ServerVersion }

func (handler *recordingHandler) handshakeCount() int {
	handler.mu.Lock()
	defer handler.mu.Unlock()
	return handler.handshakeCalls
}

func (handler *recordingHandler) closeCount() int {
	handler.mu.Lock()
	defer handler.mu.Unlock()
	return handler.closeCalls
}

type recordingReceiver struct {
	next            router.ConnEventReceiver
	redirectSuccess int
	redirectFail    int
	closed          int
}

func (receiver *recordingReceiver) OnRedirectSucceed(from, to string, conn router.RedirectableConn) error {
	receiver.redirectSuccess++
	if receiver.next != nil {
		return receiver.next.OnRedirectSucceed(from, to, conn)
	}
	return nil
}

func (receiver *recordingReceiver) OnRedirectFail(from, to string, conn router.RedirectableConn) error {
	receiver.redirectFail++
	if receiver.next != nil {
		return receiver.next.OnRedirectFail(from, to, conn)
	}
	return nil
}

func (receiver *recordingReceiver) OnConnClosed(id string, conn router.RedirectableConn) error {
	receiver.closed++
	if receiver.next != nil {
		return receiver.next.OnConnClosed(id, conn)
	}
	return nil
}

type portRouter struct {
	routes  map[string]*router.StaticRouter
	clients []router.ClientInfo
}

func (rt *portRouter) GetBackendSelector(client router.ClientInfo) router.BackendSelector {
	rt.clients = append(rt.clients, client)
	selected := rt.routes[client.ListenerPort]
	if selected == nil {
		selected = router.NewStaticRouter(nil)
	}
	return selected.GetBackendSelector(client)
}

func (rt *portRouter) HealthyBackendCount() int { return len(rt.routes) }
func (rt *portRouter) RefreshBackend()          {}
func (rt *portRouter) RedirectConnections() error {
	return nil
}
func (rt *portRouter) ConnCount() int {
	count := 0
	for _, route := range rt.routes {
		count += route.ConnCount()
	}
	return count
}
func (rt *portRouter) ServerVersion() string { return pnet.ServerVersion }
func (rt *portRouter) Close()                {}

func newTestAdapter(t *testing.T, handler backend.HandshakeHandler) *RouterAdapter {
	t.Helper()
	adapter, err := NewRouterAdapter(handler)
	require.NoError(t, err)
	return adapter
}

func sendHandshake(
	t *testing.T,
	adapter *RouterAdapter,
	peer *fakeSender,
	connectionID uint64,
	listener, user string,
) {
	t.Helper()
	require.NoError(t, adapter.HandleEnvelope(context.Background(), peer, &controlpb.ControlEnvelope{
		RequestId:  connectionID*10 + 1,
		Generation: 7,
		Body: &controlpb.ControlEnvelope_HandshakeResponse{HandshakeResponse: &controlpb.HandshakeResponseEvent{
			Connection: testIdentity(connectionID, listener),
			Handshake:  testHandshake(user),
		}},
	}))
}

func sendRoute(
	t *testing.T,
	adapter *RouterAdapter,
	peer *fakeSender,
	connectionID uint64,
	listener, user string,
) {
	t.Helper()
	require.NoError(t, adapter.HandleEnvelope(context.Background(), peer, &controlpb.ControlEnvelope{
		RequestId:  connectionID*10 + 2,
		Generation: 7,
		Body: &controlpb.ControlEnvelope_RouteRequest{RouteRequest: &controlpb.RouteRequest{
			Connection:    testIdentity(connectionID, listener),
			Handshake:     testHandshake(user),
			NamespaceHint: "default",
		}},
	}))
}

func sendRouteResult(
	t *testing.T,
	adapter *RouterAdapter,
	peer *fakeSender,
	assignment *controlpb.RouteAssignment,
	connected bool,
) {
	t.Helper()
	sendRouteResultWithID(t, adapter, peer, assignment.GetConnectionId(), assignment.GetAssignmentId(), connected)
}

func sendRouteResultWithID(
	t *testing.T,
	adapter *RouterAdapter,
	peer *fakeSender,
	connectionID uint64,
	assignmentID string,
	connected bool,
) {
	t.Helper()
	require.NoError(t, adapter.HandleEnvelope(context.Background(), peer, &controlpb.ControlEnvelope{
		RequestId: connectionID*100 + 3,
		Body: &controlpb.ControlEnvelope_RouteResult{RouteResult: &controlpb.RouteResult{
			ConnectionId: connectionID,
			AssignmentId: assignmentID,
			Connected:    connected,
			ErrorSource:  controlpb.ErrorSource_ERROR_SOURCE_BACKEND_NETWORK,
			Code:         controlpb.ErrorCode_ERROR_CODE_BACKEND_DIAL_FAILED,
		}},
	}))
}

func establishConnection(
	t *testing.T,
	adapter *RouterAdapter,
	peer *fakeSender,
	connectionID uint64,
	listener, user string,
) {
	t.Helper()
	sendHandshake(t, adapter, peer, connectionID, listener, user)
	sendRoute(t, adapter, peer, connectionID, listener, user)
	assignment := lastAssignment(t, peer)
	sendRouteResult(t, adapter, peer, assignment, true)
	require.NoError(t, adapter.HandleEnvelope(context.Background(), peer, &controlpb.ControlEnvelope{
		RequestId: connectionID*10 + 4,
		Body: &controlpb.ControlEnvelope_HandshakeResult{HandshakeResult: &controlpb.HandshakeResult{
			ConnectionId:   connectionID,
			BackendId:      assignment.GetBackendId(),
			BackendAddress: assignment.GetBackendAddress(),
			Code:           controlpb.ErrorCode_ERROR_CODE_OK,
		}},
	}))
}

func testIdentity(connectionID uint64, listener string) *controlpb.ConnectionIdentity {
	return &controlpb.ConnectionIdentity{
		ConnectionId:    connectionID,
		ListenerAddress: listener,
		ClientAddress:   "10.0.0.1:12345",
		ProxyAddress:    "192.0.2.10:4000",
	}
}

func testHandshake(user string) *controlpb.HandshakeMetadata {
	return &controlpb.HandshakeMetadata{
		User:                 user,
		Database:             "db",
		AuthPlugin:           "caching_sha2_password",
		Capability:           uint32(pnet.ClientProtocol41),
		Collation:            45,
		ZstdLevel:            3,
		ConnectionAttributes: map[string]string{"program_name": "adapter-test"},
		Tls:                  true,
	}
}

func connectionEvent(connectionID uint64, kind controlpb.ConnectionEventKind) *controlpb.ControlEnvelope {
	return &controlpb.ControlEnvelope{
		RequestId:  connectionID*100 + uint64(kind),
		Generation: 7,
		Body: &controlpb.ControlEnvelope_ConnectionEvent{ConnectionEvent: &controlpb.ConnectionEvent{
			Kind:       kind,
			Connection: testIdentity(connectionID, "0.0.0.0:6000"),
		}},
	}
}

func reconcileEnvelope(requestID, generation uint64, connectionIDs ...uint64) *controlpb.ControlEnvelope {
	connections := make([]*controlpb.ReconcileConnection, 0, len(connectionIDs))
	for _, connectionID := range connectionIDs {
		connections = append(connections, &controlpb.ReconcileConnection{ConnectionId: connectionID})
	}
	return &controlpb.ControlEnvelope{
		RequestId:            requestID,
		Generation:           generation,
		RequiredCapabilities: []uint64{uint64(controlpb.ControlCapability_CONTROL_CAPABILITY_RECONCILE_CONNECTIONS)},
		Body: &controlpb.ControlEnvelope_ReconcileRequest{ReconcileRequest: &controlpb.ReconcileRequest{
			KnownGeneration:             generation,
			LastConnectionEventSequence: 11,
			LastMetricsSequence:         12,
			LastMeteringSequence:        13,
			Connections:                 connections,
		}},
	}
}

func lastEnvelope(t *testing.T, peer *fakeSender) *controlpb.ControlEnvelope {
	t.Helper()
	peer.mu.Lock()
	defer peer.mu.Unlock()
	require.NotEmpty(t, peer.messages)
	return peer.messages[len(peer.messages)-1]
}

func lastDecision(t *testing.T, peer *fakeSender) *controlpb.HandshakeDecision {
	t.Helper()
	decision := lastEnvelope(t, peer).GetHandshakeDecision()
	require.NotNil(t, decision)
	return decision
}

func lastAssignment(t *testing.T, peer *fakeSender) *controlpb.RouteAssignment {
	t.Helper()
	assignment := lastEnvelope(t, peer).GetRouteAssignment()
	require.NotNil(t, assignment)
	return assignment
}

var _ backend.HandshakeHandler = (*recordingHandler)(nil)
var _ router.Router = (*portRouter)(nil)
