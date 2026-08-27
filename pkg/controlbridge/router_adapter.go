// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package controlbridge adapts Rust-owned SQL connections to the existing Go
// handshake and routing lifecycle. MySQL packets and authentication bytes are
// deliberately absent from this package.
package controlbridge

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/go-mysql-org/go-mysql/mysql"
	"github.com/pingcap/tiproxy/pkg/balance/router"
	controlpb "github.com/pingcap/tiproxy/pkg/controlbridge/pb"
	"github.com/pingcap/tiproxy/pkg/controlbridge/transport"
	"github.com/pingcap/tiproxy/pkg/proxy/backend"
	pnet "github.com/pingcap/tiproxy/pkg/proxy/net"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"
)

const maxControlDetailBytes = 4 * 1024
const maxClosedConnectionTombstones = 4 * 1024
const maxConnectionEventKeys = 64

// EnvelopeSender is the negotiated control-session surface used by the
// adapter. Every application command allocates from the same checked lineage
// as heartbeats and snapshots; responses reuse the initiating request ID.
// The small interface also permits a deterministic fake Rust peer.
type EnvelopeSender interface {
	Send(context.Context, *controlpb.ControlEnvelope) error
	Epoch() uint64
	HasCapability(uint64) bool
	AllocateRequestID() (uint64, error)
}

var _ transport.Handler = (*RouterAdapter)(nil)

// RouterAdapter owns Go-side lifecycle state for Rust dataplane connections.
// A connection's callbacks are serialized by connectionState.mu; the global
// mutex is never held while invoking a HandshakeHandler or router callback.
type RouterAdapter struct {
	handler backend.HandshakeHandler

	mu          sync.Mutex
	connections map[uint64]*connectionState
	// closedIDs tombstones closed connection ids **scoped by the
	// control-session epoch they were created under**. Config snapshot
	// generations are NOT a lineage signal (a Rust restart may keep the
	// same generation); the epoch is: a restart forces a reconnect and
	// a new epoch, while a same-process lineage never reuses an id
	// (monotonic in-process counter). Same-epoch reuse is therefore the
	// only illegitimate case.
	closedIDs   map[uint64]uint64
	closedOrder []uint64
	sender      EnvelopeSender
	senderEpoch uint64
	operationID atomic.Uint64

	// metering, when attached, owns deduplicated cumulative metering;
	// its highest applied sequence is the reconcile acknowledgement the
	// Rust producer uses to drop retained batches (CTL-06). Without a
	// consumer the acknowledgement is zero: nothing was applied, so
	// nothing may be dropped.
	metering *MeteringConsumer

	// routerLookup, when attached, resolves a namespace to its router so
	// a restarted lineage can rehydrate accounting for Rust sessions
	// reported through reconciliation (CTL-06). The composition wires it
	// to the namespace manager.
	routerLookup func(namespace string) (router.Router, error)

	// orphans tracks reconcile-reported live sessions this lineage could
	// not rehydrate yet (unknown namespace/backend). They are excluded
	// from redirect/drain by construction (no projectedConn exists) and
	// resolved by bounded retries; past the bound they are closed.
	orphans map[uint64]*orphanState

	// rehydrating claims a connection id for the duration of one
	// rehydration attempt so a concurrent reconcile and ResolveOrphans
	// can never double-attach the same session to router accounting.
	rehydrating map[uint64]struct{}
}

type orphanState struct {
	remote   *controlpb.ReconcileConnection
	attempts int
}

// MaxOrphanResolveAttempts bounds rehydration retries for one orphan
// before the adapter closes the session instead of leaking it forever.
const MaxOrphanResolveAttempts = 3

type connectionState struct {
	mu sync.Mutex

	identity  *controlpb.ConnectionIdentity
	handshake *controlpb.HandshakeMetadata
	conn      *projectedConn
	router    router.Router
	selector  *router.BackendSelector
	namespace string

	// generation is the snapshot generation the connection was admitted
	// under (established by the handshake envelope, restored by
	// reconciliation): per-session commands are stamped with it and the
	// same connection's later envelopes must not drift from it.
	generation uint64
	// epoch is the control-session epoch the connection was admitted
	// (or rehydrated) under: the lineage signal for closed-id
	// tombstones and same-id replacement, deliberately separate from
	// the config generation.
	epoch uint64

	decision       *controlpb.HandshakeDecision
	assignment     *routeAssignment
	currentBackend router.BackendInst
	handshakeDone  bool
	opened         bool
	closed         bool
	eventKeys      map[connectionEventKey]struct{}
	eventOrder     []connectionEventKey
}

type connectionEventKey struct {
	epoch     uint64
	requestID uint64
}

type routeAssignment struct {
	id       string
	backend  router.BackendInst
	finished bool
}

// NewRouterAdapter creates a lifecycle adapter for one HandshakeHandler.
func NewRouterAdapter(handler backend.HandshakeHandler) (*RouterAdapter, error) {
	if handler == nil {
		return nil, errors.New("handshake handler is required")
	}
	return &RouterAdapter{
		handler:     handler,
		connections: make(map[uint64]*connectionState),
		closedIDs:   make(map[uint64]uint64),
		orphans:     make(map[uint64]*orphanState),
		rehydrating: make(map[uint64]struct{}),
	}, nil
}

// HandleControlMessage implements transport.Handler.
func (adapter *RouterAdapter) HandleControlMessage(
	ctx context.Context,
	session *transport.Session,
	envelope *controlpb.ControlEnvelope,
) error {
	return adapter.HandleEnvelope(ctx, session, envelope)
}

// HandleEnvelope processes one Rust control event. It is exported so the
// router lifecycle can be tested without creating a UDS.
func (adapter *RouterAdapter) HandleEnvelope(
	ctx context.Context,
	sender EnvelopeSender,
	envelope *controlpb.ControlEnvelope,
) error {
	if sender == nil || envelope == nil {
		return errors.New("control sender and envelope are required")
	}
	adapter.rememberSender(sender)
	if missing := missingCapability(sender, envelope.GetRequiredCapabilities()); missing != 0 {
		return adapter.sendProtocolError(ctx, sender, envelope.GetRequestId(),
			controlpb.ErrorCode_ERROR_CODE_MISSING_CAPABILITY,
			fmt.Sprintf("required control capability %d was not negotiated", missing))
	}

	switch body := envelope.GetBody().(type) {
	case *controlpb.ControlEnvelope_HandshakeResponse:
		return adapter.handleHandshakeResponse(ctx, sender, envelope.GetRequestId(), envelope.GetGeneration(), body.HandshakeResponse)
	case *controlpb.ControlEnvelope_RouteRequest:
		return adapter.handleRouteRequest(ctx, sender, envelope.GetRequestId(), envelope.GetGeneration(), body.RouteRequest)
	case *controlpb.ControlEnvelope_RouteResult:
		return adapter.handleRouteResult(ctx, sender, envelope.GetRequestId(), body.RouteResult)
	case *controlpb.ControlEnvelope_HandshakeResult:
		return adapter.handleHandshakeResult(ctx, sender, envelope.GetRequestId(), body.HandshakeResult)
	case *controlpb.ControlEnvelope_ConnectionEvent:
		return adapter.handleConnectionEvent(sender.Epoch(), envelope.GetRequestId(), envelope.GetGeneration(), body.ConnectionEvent)
	case *controlpb.ControlEnvelope_RedirectResult:
		return adapter.handleRedirectResult(body.RedirectResult)
	case *controlpb.ControlEnvelope_CloseResult:
		return adapter.handleCloseResult(body.CloseResult)
	case *controlpb.ControlEnvelope_ReconcileRequest:
		return adapter.handleReconcile(ctx, sender, envelope.GetRequestId(), envelope.GetGeneration(), body.ReconcileRequest)
	case *controlpb.ControlEnvelope_Heartbeat, *controlpb.ControlEnvelope_Error:
		return nil
	default:
		// Snapshot, drain, metrics, and metering bodies are owned by adjacent
		// control-plane adapters and may share a composite transport handler.
		return nil
	}
}

func (adapter *RouterAdapter) handleHandshakeResponse(
	ctx context.Context,
	sender EnvelopeSender,
	requestID uint64,
	generation uint64,
	event *controlpb.HandshakeResponseEvent,
) error {
	if event == nil || event.GetConnection() == nil || event.GetHandshake() == nil {
		return adapter.sendProtocolError(ctx, sender, requestID,
			controlpb.ErrorCode_ERROR_CODE_PROTOCOL_VIOLATION, "incomplete handshake response event")
	}
	state, err := adapter.getOrCreate(event.GetConnection(), sender.Epoch())
	if err != nil {
		return adapter.sendProtocolError(ctx, sender, requestID,
			controlpb.ErrorCode_ERROR_CODE_PROTOCOL_VIOLATION, err.Error())
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.decision != nil {
		return sendBody(ctx, sender, requestID, controlpb.Priority_PRIORITY_CONTROL,
			&controlpb.ControlEnvelope_HandshakeDecision{HandshakeDecision: cloneDecision(state.decision)})
	}
	if state.closed {
		return adapter.sendProtocolError(ctx, sender, requestID,
			controlpb.ErrorCode_ERROR_CODE_PROTOCOL_VIOLATION, "handshake event for closed connection")
	}
	if event.GetHandshake().GetCollation() > 255 {
		return adapter.rejectHandshakeLocked(ctx, sender, requestID, state,
			errors.New("handshake collation exceeds one byte"))
	}

	if generation == 0 {
		// State-bearing messages carry a nonzero generation (frozen
		// control-v1 contract).
		return adapter.rejectHandshakeLocked(ctx, sender, requestID, state,
			errors.New("handshake generation must be nonzero"))
	}
	if state.generation == 0 {
		state.generation = generation
		state.conn.generation = generation
	} else if generation != state.generation {
		return adapter.rejectHandshakeLocked(ctx, sender, requestID, state,
			errors.New("handshake generation drifted for an established connection"))
	}
	state.handshake = cloneHandshake(event.GetHandshake())
	response := projectHandshake(state.handshake)
	if err := adapter.handler.HandleHandshakeResp(state.conn, response); err != nil {
		return adapter.rejectHandshakeLocked(ctx, sender, requestID, state, err)
	}
	rt, err := adapter.handler.GetRouter(state.conn, response)
	if err != nil || rt == nil {
		if err == nil {
			err = errors.New("handshake handler returned no router")
		}
		return adapter.rejectHandshakeLocked(ctx, sender, requestID, state, err)
	}
	state.router = rt
	if namespace, ok := state.conn.Value(backend.ConnContextKeyNamespace).(string); ok {
		state.namespace = bounded(namespace)
	}
	state.decision = &controlpb.HandshakeDecision{
		ConnectionId: state.conn.ConnectionID(),
		Accept:       true,
		Code:         controlpb.ErrorCode_ERROR_CODE_OK,
		Namespace:    state.namespace,
	}
	return sendBody(ctx, sender, requestID, controlpb.Priority_PRIORITY_CONTROL,
		&controlpb.ControlEnvelope_HandshakeDecision{HandshakeDecision: cloneDecision(state.decision)})
}

func (adapter *RouterAdapter) rejectHandshakeLocked(
	ctx context.Context,
	sender EnvelopeSender,
	requestID uint64,
	state *connectionState,
	err error,
) error {
	// v1 ADR: client-facing errors carry an enumerated code plus an
	// APPROVED message — arbitrary Go diagnostic text stays in the
	// server-side notification and never crosses to the client. The
	// unknown-namespace refusal is part of the approved vocabulary and
	// matches Go mode's exact client text; everything else stays
	// generic.
	message := "handshake rejected"
	if errors.Is(err, backend.ErrNamespaceNotFound) {
		message = backend.ErrNamespaceNotFound.Error()
	}
	state.decision = &controlpb.HandshakeDecision{
		ConnectionId:  state.conn.ConnectionID(),
		Accept:        false,
		Code:          controlpb.ErrorCode_ERROR_CODE_HANDSHAKE_REJECTED,
		ClientMessage: bounded(message),
	}
	adapter.notifyHandshakeLocked(state, "", err, backend.SrcProxyErr)
	return sendBody(ctx, sender, requestID, controlpb.Priority_PRIORITY_CONTROL,
		&controlpb.ControlEnvelope_HandshakeDecision{HandshakeDecision: cloneDecision(state.decision)})
}

func (adapter *RouterAdapter) handleRouteRequest(
	ctx context.Context,
	sender EnvelopeSender,
	requestID uint64,
	generation uint64,
	request *controlpb.RouteRequest,
) error {
	if request == nil || request.GetConnection() == nil || request.GetHandshake() == nil {
		return adapter.sendProtocolError(ctx, sender, requestID,
			controlpb.ErrorCode_ERROR_CODE_PROTOCOL_VIOLATION, "incomplete route request")
	}
	state := adapter.get(request.GetConnection().GetConnectionId())
	if state == nil {
		return adapter.sendProtocolError(ctx, sender, requestID,
			controlpb.ErrorCode_ERROR_CODE_RECONCILIATION_REQUIRED, "unknown connection")
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if !sameIdentity(state.identity, request.GetConnection()) || !proto.Equal(state.handshake, request.GetHandshake()) {
		return adapter.sendProtocolError(ctx, sender, requestID,
			controlpb.ErrorCode_ERROR_CODE_PROTOCOL_VIOLATION, "route identity differs from handshake event")
	}
	if generation == 0 || (state.generation != 0 && generation != state.generation) {
		return adapter.sendProtocolError(ctx, sender, requestID,
			controlpb.ErrorCode_ERROR_CODE_PROTOCOL_VIOLATION, "route generation missing or drifted for an established connection")
	}
	if state.closed || state.decision == nil || !state.decision.GetAccept() || state.router == nil {
		return adapter.sendProtocolError(ctx, sender, requestID,
			controlpb.ErrorCode_ERROR_CODE_HANDSHAKE_REJECTED, "connection is not eligible for routing")
	}
	if state.assignment != nil {
		return adapter.sendAssignmentLocked(ctx, sender, requestID, state, state.assignment)
	}
	if state.namespace == "" {
		state.namespace = bounded(request.GetNamespaceHint())
	}
	selector := state.router.GetBackendSelector(projectClientInfo(state.identity))
	state.selector = &selector
	return adapter.nextAssignmentLocked(ctx, sender, requestID, state, request.GetExcludedBackendIds())
}

func (adapter *RouterAdapter) nextAssignmentLocked(
	ctx context.Context,
	sender EnvelopeSender,
	requestID uint64,
	state *connectionState,
	excludedIDs []string,
) error {
	if state.selector == nil {
		return adapter.sendProtocolError(ctx, sender, requestID,
			controlpb.ErrorCode_ERROR_CODE_PROTOCOL_VIOLATION, "route selector is not initialized")
	}
	excluded := make(map[string]struct{}, len(excludedIDs))
	for _, id := range excludedIDs {
		excluded[id] = struct{}{}
	}
	seen := make(map[string]struct{}, len(excluded)+1)
	for {
		selected, err := state.selector.Next()
		if err != nil {
			code := controlpb.ErrorCode_ERROR_CODE_INTERNAL
			if errors.Is(err, router.ErrNoBackend) {
				code = controlpb.ErrorCode_ERROR_CODE_NO_BACKEND
				err = backend.ErrProxyNoBackend
			}
			adapter.notifyHandshakeLocked(state, "", err, backend.Error2Source(err))
			return sendBody(ctx, sender, requestID, controlpb.Priority_PRIORITY_CONTROL,
				&controlpb.ControlEnvelope_RouteAssignment{RouteAssignment: &controlpb.RouteAssignment{
					ConnectionId: state.conn.ConnectionID(),
					Code:         code,
					Detail:       bounded(err.Error()),
				}})
		}
		if _, duplicate := seen[selected.ID()]; duplicate {
			state.selector.Finish(state.conn, false)
			adapter.notifyHandshakeLocked(state, "", backend.ErrProxyNoBackend, backend.SrcProxyNoBackend)
			return sendBody(ctx, sender, requestID, controlpb.Priority_PRIORITY_CONTROL,
				&controlpb.ControlEnvelope_RouteAssignment{RouteAssignment: &controlpb.RouteAssignment{
					ConnectionId: state.conn.ConnectionID(),
					Code:         controlpb.ErrorCode_ERROR_CODE_NO_BACKEND,
					Detail:       bounded(backend.ErrProxyNoBackend.Error()),
				}})
		}
		seen[selected.ID()] = struct{}{}
		if _, skip := excluded[selected.ID()]; skip {
			state.selector.Finish(state.conn, false)
			continue
		}
		assignment := &routeAssignment{
			id:      adapter.newOperationID("assignment", sender.Epoch(), state.conn.ConnectionID()),
			backend: selected,
		}
		state.assignment = assignment
		return adapter.sendAssignmentLocked(ctx, sender, requestID, state, assignment)
	}
}

func (adapter *RouterAdapter) sendAssignmentLocked(
	ctx context.Context,
	sender EnvelopeSender,
	requestID uint64,
	state *connectionState,
	assignment *routeAssignment,
) error {
	return sendBody(ctx, sender, requestID, controlpb.Priority_PRIORITY_CONTROL,
		&controlpb.ControlEnvelope_RouteAssignment{RouteAssignment: &controlpb.RouteAssignment{
			ConnectionId:   state.conn.ConnectionID(),
			AssignmentId:   assignment.id,
			BackendId:      assignment.backend.ID(),
			BackendAddress: assignment.backend.Addr(),
			ClusterName:    assignment.backend.ClusterName(),
			Keyspace:       assignment.backend.Keyspace(),
			Healthy:        assignment.backend.Healthy(),
			Local:          assignment.backend.Local(),
			Code:           controlpb.ErrorCode_ERROR_CODE_OK,
		}})
}

func (adapter *RouterAdapter) handleRouteResult(
	ctx context.Context,
	sender EnvelopeSender,
	requestID uint64,
	result *controlpb.RouteResult,
) error {
	if result == nil {
		return adapter.sendProtocolError(ctx, sender, requestID,
			controlpb.ErrorCode_ERROR_CODE_PROTOCOL_VIOLATION, "missing route result")
	}
	state := adapter.get(result.GetConnectionId())
	if state == nil {
		return adapter.sendProtocolError(ctx, sender, requestID,
			controlpb.ErrorCode_ERROR_CODE_RECONCILIATION_REQUIRED, "route result for unknown connection")
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	assignment := state.assignment
	if assignment == nil || assignment.id != result.GetAssignmentId() {
		return nil // stale or duplicate results never repeat selector effects.
	}
	if assignment.finished {
		return nil
	}
	if result.GetConnected() {
		completeAssignmentLocked(state)
		return nil
	}
	assignment.finished = true
	state.selector.Finish(state.conn, false)
	state.assignment = nil
	return adapter.nextAssignmentLocked(ctx, sender, requestID, state, nil)
}

// completeAssignmentLocked applies the success semantics of a connected
// RouteResult exactly once: it tombstones the pending assignment,
// finishes the selector, installs the current backend, and wires the
// event receiver. Callers hold state.mu and have verified the
// assignment is non-nil and unfinished. It is shared by the live
// RouteResult path and the reconcile repair of a LOST successful
// RouteResult, so both seams have identical exactly-once effects.
func completeAssignmentLocked(state *connectionState) {
	assignment := state.assignment
	assignment.finished = true
	state.selector.Finish(state.conn, true)
	state.currentBackend = assignment.backend
	state.conn.setBackend(assignment.backend)
	// ScoreBasedRouter installs its receiver from Finish. Static/custom
	// routers may expose the receiver directly instead.
	if state.conn.eventReceiver() == nil {
		if receiver, ok := state.router.(router.ConnEventReceiver); ok {
			state.conn.SetEventReceiver(receiver)
		}
	}
}

// lostAssignmentVerdict reports what the same-lineage reconcile record
// implied about a pending (unconfirmed) assignment.
type lostAssignmentVerdict int

const (
	// lostAssignmentNone: no pending assignment to repair.
	lostAssignmentNone lostAssignmentVerdict = iota
	// lostAssignmentCompleted: the record named EXACTLY the pending
	// assignment's backend; the assignment completed exactly once.
	lostAssignmentCompleted
	// lostAssignmentDiverged: the record names a DIFFERENT backend (or
	// none) than the pending assignment - the Rust session is really
	// attached to something the local selector never confirmed. The
	// caller must terminate the session; letting it silently serve
	// would repeat the divergence on every reconcile forever.
	lostAssignmentDiverged
)

// completeLostAssignment repairs the lost-successful-RouteResult seam:
// the SAME lineage's authoritative reconcile record names the backend
// the connection is really attached to while the local state still
// holds the pending assignment. An EXACT backend match completes the
// assignment through the same exactly-once path a connected
// RouteResult takes. Anything else is a DIVERGENCE verdict: fail
// closed means terminating that session (never attaching an arbitrary
// remote backend, never silently keeping it alive). A late original
// RouteResult remains idempotent either way — completion and close
// both leave a finished tombstone.
func completeLostAssignment(state *connectionState, remote *controlpb.ReconcileConnection) lostAssignmentVerdict {
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.closed || state.currentBackend != nil || state.selector == nil {
		return lostAssignmentNone
	}
	assignment := state.assignment
	if assignment == nil || assignment.finished || assignment.backend == nil {
		return lostAssignmentNone
	}
	if remote.GetBackendId() != "" && remote.GetBackendId() == assignment.backend.ID() {
		completeAssignmentLocked(state)
		return lostAssignmentCompleted
	}
	return lostAssignmentDiverged
}

// closeDivergedAssignment terminates a session whose reconcile record
// diverged from its pending assignment: the local state retires
// exactly once (the unfinished assignment's selector gets its single
// Finish(false) inside closeStateLocked), and the Rust side receives a
// precise CloseCommand so the client terminates instead of serving on
// an unconfirmed backend.
func (adapter *RouterAdapter) closeDivergedAssignment(
	ctx context.Context,
	sender EnvelopeSender,
	state *connectionState,
	remote *controlpb.ReconcileConnection,
) error {
	state.mu.Lock()
	adapter.closeStateLocked(state, backend.SrcProxyErr)
	state.mu.Unlock()
	if !sender.HasCapability(uint64(controlpb.ControlCapability_CONTROL_CAPABILITY_PER_CONNECTION_CLOSE)) {
		return nil
	}
	requestID, err := sender.AllocateRequestID()
	if err != nil {
		return err
	}
	return sender.Send(ctx, &controlpb.ControlEnvelope{
		RequestId:  requestID,
		Generation: remote.GetGeneration(),
		Priority:   controlpb.Priority_PRIORITY_CRITICAL,
		RequiredCapabilities: []uint64{
			uint64(controlpb.ControlCapability_CONTROL_CAPABILITY_PER_CONNECTION_CLOSE),
		},
		Body: &controlpb.ControlEnvelope_CloseCommand{CloseCommand: &controlpb.CloseCommand{
			ConnectionId: remote.GetConnectionId(),
			CloseId:      adapter.newOperationID("diverged-assignment-close", sender.Epoch(), remote.GetConnectionId()),
			ErrorSource:  controlpb.ErrorSource_ERROR_SOURCE_PROXY,
			Reason:       "reconcile diverged from the pending assignment",
			Force:        true,
		}},
	})
}

func (adapter *RouterAdapter) handleHandshakeResult(
	ctx context.Context,
	sender EnvelopeSender,
	requestID uint64,
	result *controlpb.HandshakeResult,
) error {
	if result == nil {
		return adapter.sendProtocolError(ctx, sender, requestID,
			controlpb.ErrorCode_ERROR_CODE_PROTOCOL_VIOLATION, "missing handshake result")
	}
	state := adapter.get(result.GetConnectionId())
	if state == nil {
		return adapter.sendProtocolError(ctx, sender, requestID,
			controlpb.ErrorCode_ERROR_CODE_RECONCILIATION_REQUIRED, "handshake result for unknown connection")
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.handshakeDone || state.closed {
		return nil
	}
	if mysqlErr := result.GetMysqlError(); mysqlErr != nil {
		projected := &mysql.MyError{
			Code:    uint16(mysqlErr.GetCode()),
			State:   bounded(mysqlErr.GetSqlState()),
			Message: bounded(mysqlErr.GetMessage()),
		}
		if adapter.handler.HandleHandshakeErr(state.conn, projected) {
			adapter.abandonBackendLocked(state)
			state.assignment = nil
			return adapter.nextAssignmentLocked(ctx, sender, requestID, state, nil)
		}
		adapter.notifyHandshakeLocked(state, result.GetBackendAddress(), projected, backend.SrcClientAuthFail)
		return nil
	}
	if result.GetCode() != controlpb.ErrorCode_ERROR_CODE_OK {
		err := errors.New(bounded(result.GetDetail()))
		adapter.notifyHandshakeLocked(state, result.GetBackendAddress(), err, fromControlSource(result.GetErrorSource()))
		return nil
	}
	state.opened = true
	adapter.notifyHandshakeLocked(state, result.GetBackendAddress(), nil, backend.SrcNone)
	return nil
}

func (adapter *RouterAdapter) handleConnectionEvent(
	epoch, requestID, generation uint64,
	event *controlpb.ConnectionEvent,
) error {
	if event == nil || event.GetConnection() == nil {
		return errors.New("incomplete connection event")
	}
	state := adapter.get(event.GetConnection().GetConnectionId())
	if state == nil {
		// A duplicate close after cleanup is idempotent. Other events require
		// the Rust peer to reconcile before they can mutate routing state.
		if event.GetKind() == controlpb.ConnectionEventKind_CONNECTION_EVENT_KIND_CLOSED {
			return nil
		}
		return errors.New("connection event for unknown connection")
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if !sameIdentity(state.identity, event.GetConnection()) {
		return errors.New("connection event identity differs from handshake event")
	}
	if generation == 0 || (state.generation != 0 && generation != state.generation) {
		return errors.New("connection event generation missing or drifted for an established connection")
	}
	if state.seenConnectionEvent(epoch, requestID) {
		return nil
	}
	switch event.GetKind() {
	case controlpb.ConnectionEventKind_CONNECTION_EVENT_KIND_OPENED:
		if !state.closed {
			state.opened = true
		}
	case controlpb.ConnectionEventKind_CONNECTION_EVENT_KIND_TRAFFIC:
		if !state.closed {
			state.conn.setTraffic(event.GetClientInBytes(), event.GetClientOutBytes())
			adapter.handler.OnTraffic(state.conn)
		}
	case controlpb.ConnectionEventKind_CONNECTION_EVENT_KIND_CLOSED:
		adapter.closeStateLocked(state, fromControlSource(event.GetErrorSource()))
	default:
		return errors.New("unspecified connection event kind")
	}
	return nil
}

func (adapter *RouterAdapter) handleRedirectResult(result *controlpb.RedirectResult) error {
	if result == nil {
		return errors.New("missing redirect result")
	}
	state := adapter.get(result.GetConnectionId())
	if state == nil {
		return nil
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if handled, err := adapter.finishRehydratedRedirectLocked(state, result); handled {
		return err
	}
	pending, receiver := state.conn.takeRedirect(result.GetRedirectId())
	if pending == nil || receiver == nil || state.closed {
		return nil
	}
	if result.GetSucceeded() {
		state.currentBackend = pending
		state.conn.setBackend(pending)
		return receiver.OnRedirectSucceed(result.GetPreviousBackendId(), result.GetBackendId(), state.conn)
	}
	return receiver.OnRedirectFail(result.GetPreviousBackendId(), result.GetBackendId(), state.conn)
}

func (adapter *RouterAdapter) handleCloseResult(result *controlpb.CloseResult) error {
	if result == nil {
		return errors.New("missing close result")
	}
	state := adapter.get(result.GetConnectionId())
	if state == nil {
		return nil
	}
	state.conn.finishClose(result.GetCloseId(), result.GetAccepted())
	return nil
}

func (adapter *RouterAdapter) handleReconcile(
	ctx context.Context,
	sender EnvelopeSender,
	requestID uint64,
	generation uint64,
	request *controlpb.ReconcileRequest,
) error {
	if request == nil {
		return adapter.sendProtocolError(ctx, sender, requestID,
			controlpb.ErrorCode_ERROR_CODE_PROTOCOL_VIOLATION, "missing reconcile request")
	}
	rust := make(map[uint64]*controlpb.ReconcileConnection, len(request.GetConnections()))
	for _, connection := range request.GetConnections() {
		if connection == nil || connection.GetConnectionId() == 0 {
			return adapter.sendProtocolError(ctx, sender, requestID,
				controlpb.ErrorCode_ERROR_CODE_PROTOCOL_VIOLATION, "invalid reconcile connection")
		}
		if _, duplicate := rust[connection.GetConnectionId()]; duplicate {
			return adapter.sendProtocolError(ctx, sender, requestID,
				controlpb.ErrorCode_ERROR_CODE_PROTOCOL_VIOLATION, "duplicate reconcile connection")
		}
		rust[connection.GetConnectionId()] = connection
	}

	// The rehydration lifecycle (rebuild, orphans, sequence watermarks)
	// is capability-gated for rolling compatibility: legacy peers keep
	// the original identification-by-omission behavior with no orphan
	// closes.
	rehydration := sender.HasCapability(uint64(controlpb.ControlCapability_CONTROL_CAPABILITY_RECONCILE_SESSION_REHYDRATION))
	if rehydration {
		for id, remote := range rust {
			// With the rehydration capability negotiated, the new
			// required fields are mandatory: zero generation or a
			// missing/inconsistent identity is a protocol violation,
			// never a silent orphan.
			if remote.GetGeneration() == 0 || remote.GetIdentity() == nil ||
				remote.GetIdentity().GetConnectionId() != id {
				return adapter.sendProtocolError(ctx, sender, requestID,
					controlpb.ErrorCode_ERROR_CODE_PROTOCOL_VIOLATION,
					"reconcile connection requires a nonzero generation and a consistent identity")
			}
			// A known id whose generation or identity differs is a new
			// incarnation reusing the id after a Rust restart: retire
			// the stale Go accounting exactly once, then rebuild.
			adapter.mu.Lock()
			existing := adapter.connections[id]
			adapter.mu.Unlock()
			if existing != nil {
				existing.mu.Lock()
				mismatch := !existing.closed &&
					(!sameIdentity(existing.identity, remote.GetIdentity()) ||
						(existing.generation != 0 && remote.GetGeneration() != existing.generation))
				if mismatch {
					adapter.closeStateLocked(existing, backend.SrcProxyQuit)
				}
				existing.mu.Unlock()
				if !mismatch {
					// Same lineage, same identity: repair a lost
					// successful RouteResult before skipping, so the
					// authoritative record's backend is never dropped
					// on the floor (accounting would stay short and
					// the snapshot would echo an empty backend). A
					// DIVERGED record terminates the session instead -
					// no-op survival is not fail-closed.
					if completeLostAssignment(existing, remote) == lostAssignmentDiverged {
						if err := adapter.closeDivergedAssignment(ctx, sender, existing, remote); err != nil {
							return err
						}
					}
					continue
				}
				adapter.forgetClosedState(existing)
			}
			if !adapter.claimRehydration(id) {
				continue
			}
			func() {
				defer func() {
					adapter.mu.Lock()
					delete(adapter.rehydrating, id)
					adapter.mu.Unlock()
				}()
				state := adapter.rehydrateReconciled(remote, sender.Epoch())
				adapter.mu.Lock()
				defer adapter.mu.Unlock()
				if state != nil {
					if _, raced := adapter.connections[id]; !raced {
						adapter.connections[id] = state
					}
					delete(adapter.orphans, id)
				} else if _, tracked := adapter.orphans[id]; !tracked {
					adapter.orphans[id] = &orphanState{remote: proto.Clone(remote).(*controlpb.ReconcileConnection)}
				}
			}()
		}
	}

	adapter.mu.Lock()
	states := make([]*connectionState, 0, len(adapter.connections))
	for _, state := range adapter.connections {
		states = append(states, state)
	}
	adapter.mu.Unlock()
	snapshot := make([]*controlpb.ReconcileConnection, 0, len(states))
	for _, state := range states {
		state.mu.Lock()
		id := state.conn.ConnectionID()
		if !state.closed {
			if _, present := rust[id]; !present {
				adapter.closeStateLocked(state, backend.SrcProxyQuit)
			} else {
				snapshot = append(snapshot, &controlpb.ReconcileConnection{
					ConnectionId:                id,
					BackendId:                   state.conn.backendID(),
					Namespace:                   state.namespace,
					RedirectPending:             state.conn.redirectPending(),
					Generation:                  state.generation,
					PendingRedirectId:           state.conn.pendingRedirectID(),
					Identity:                    proto.Clone(state.identity).(*controlpb.ConnectionIdentity),
					LastRedirectCommandSequence: state.conn.redirectSequence(),
				})
			}
		}
		state.mu.Unlock()
	}
	slices.SortFunc(snapshot, func(a, b *controlpb.ReconcileConnection) int {
		return int64Compare(a.GetConnectionId(), b.GetConnectionId())
	})
	requiredCaps := []uint64{uint64(controlpb.ControlCapability_CONTROL_CAPABILITY_RECONCILE_CONNECTIONS)}
	if rehydration {
		requiredCaps = append(requiredCaps,
			uint64(controlpb.ControlCapability_CONTROL_CAPABILITY_RECONCILE_SESSION_REHYDRATION))
	}
	return sendBodyWithOptions(ctx, sender, requestID, generation, controlpb.Priority_PRIORITY_CRITICAL,
		requiredCaps,
		&controlpb.ControlEnvelope_ReconcileSnapshot{ReconcileSnapshot: &controlpb.ReconcileSnapshot{
			AppliedGeneration:       request.GetKnownGeneration(),
			ConnectionEventSequence: request.GetLastConnectionEventSequence(),
			MetricsSequence:         request.GetLastMetricsSequence(),
			MeteringSequence:        adapter.meteringAcknowledgement(request.GetLastMeteringSequence()),
			Connections:             snapshot,
		}})
}

// AttachMetering installs the deduplicated cumulative metering consumer
// whose applied sequence acknowledges producer retention on reconcile.
func (adapter *RouterAdapter) AttachMetering(consumer *MeteringConsumer) {
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	adapter.metering = consumer
}

// AttachRouterLookup installs the namespace-to-router resolver used to
// rehydrate reconcile-reported sessions after a Go restart. The
// composition wires it to the namespace manager.
func (adapter *RouterAdapter) AttachRouterLookup(lookup func(namespace string) (router.Router, error)) {
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	adapter.routerLookup = lookup
}

func (adapter *RouterAdapter) meteringAcknowledgement(uint64) uint64 {
	adapter.mu.Lock()
	consumer := adapter.metering
	adapter.mu.Unlock()
	if consumer == nil {
		// Nothing was applied, so nothing may be acknowledged: an echo
		// of the producer's claim would let it drop unconsumed batches.
		return 0
	}
	return consumer.LastApplied()
}

// finishRehydratedRedirectLocked retires a reconciliation-restored
// pending redirect exactly once. The target backend inst was unknown at
// rehydration time; the terminal result names it, so the rebind
// resolves it through the router's lookup.
func (adapter *RouterAdapter) finishRehydratedRedirectLocked(
	state *connectionState,
	result *controlpb.RedirectResult,
) (bool, error) {
	conn := state.conn
	conn.mu.Lock()
	pendingID := conn.rehydratedRedirectID
	receiver := conn.receiver
	if pendingID == "" || pendingID != result.GetRedirectId() {
		conn.mu.Unlock()
		return false, nil
	}
	conn.rehydratedRedirectID = ""
	conn.mu.Unlock()
	if state.closed || receiver == nil {
		return true, nil
	}
	if !result.GetSucceeded() {
		return true, receiver.OnRedirectFail(result.GetPreviousBackendId(), result.GetBackendId(), conn)
	}
	if rehydrator, ok := state.router.(router.AssignmentRehydrator); ok {
		if inst, found := rehydrator.LookupBackend(result.GetBackendId()); found {
			state.currentBackend = inst
			conn.setBackend(inst)
		}
	}
	return true, receiver.OnRedirectSucceed(result.GetPreviousBackendId(), result.GetBackendId(), conn)
}

// rehydrateReconciledLocked rebuilds full adapter/router state for one
// reconcile-reported live session unknown to this lineage. Returns the
// new state, or nil when rehydration is not currently possible (the
// caller tracks it as a bounded-retry orphan).
func (adapter *RouterAdapter) rehydrateReconciled(remote *controlpb.ReconcileConnection, epoch uint64) *connectionState {
	identity := remote.GetIdentity()
	if identity == nil || identity.GetConnectionId() != remote.GetConnectionId() {
		return nil
	}
	adapter.mu.Lock()
	lookup := adapter.routerLookup
	adapter.mu.Unlock()
	if lookup == nil {
		return nil
	}
	rt, err := lookup(remote.GetNamespace())
	if err != nil || rt == nil {
		return nil
	}
	rehydrator, ok := rt.(router.AssignmentRehydrator)
	if !ok {
		return nil
	}
	conn := newProjectedConn(adapter, identity)
	conn.generation = remote.GetGeneration()
	conn.redirectSeq = remote.GetLastRedirectCommandSequence()
	inst, ok := rehydrator.RehydrateConn(remote.GetBackendId(), conn)
	if !ok {
		return nil
	}
	conn.mu.Lock()
	conn.server = inst.Addr()
	conn.backend = inst
	conn.rehydratedRedirectID = remote.GetPendingRedirectId()
	if conn.receiver == nil {
		if receiver, ok := rt.(router.ConnEventReceiver); ok {
			conn.receiver = receiver
		}
	}
	conn.mu.Unlock()
	return &connectionState{
		identity:       proto.Clone(identity).(*controlpb.ConnectionIdentity),
		conn:           conn,
		router:         rt,
		namespace:      bounded(remote.GetNamespace()),
		generation:     remote.GetGeneration(),
		epoch:          epoch,
		currentBackend: inst,
		handshakeDone:  true,
		opened:         true,
		eventKeys:      make(map[connectionEventKey]struct{}),
	}
}

func (adapter *RouterAdapter) claimRehydration(id uint64) bool {
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	if _, claimed := adapter.rehydrating[id]; claimed {
		return false
	}
	adapter.rehydrating[id] = struct{}{}
	return true
}

// ResolveOrphans retries rehydration for reconcile-reported sessions
// this lineage could not rebuild, bounded by MaxOrphanResolveAttempts;
// past the bound the session is closed through the ordinary
// per-connection close path instead of leaking forever. The composition
// calls this on its reconcile/maintenance cadence.
func (adapter *RouterAdapter) ResolveOrphans(ctx context.Context) error {
	adapter.mu.Lock()
	pending := make([]*orphanState, 0, len(adapter.orphans))
	for _, orphan := range adapter.orphans {
		pending = append(pending, orphan)
	}
	adapter.mu.Unlock()

	var firstErr error
	for _, orphan := range pending {
		if err := adapter.resolveOneOrphan(ctx, orphan); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// resolveOneOrphan holds the rehydration claim across the **whole**
// resolution lifecycle — rehydrate attempt, attempt bookkeeping,
// sender/capability revalidation, the close send, and the final state
// transition — so a concurrent reconcile can neither double-attach nor
// close a session another path just recovered.
func (adapter *RouterAdapter) resolveOneOrphan(
	ctx context.Context,
	orphan *orphanState,
) error {
	id := orphan.remote.GetConnectionId()
	if !adapter.claimRehydration(id) {
		return nil
	}
	defer func() {
		adapter.mu.Lock()
		delete(adapter.rehydrating, id)
		adapter.mu.Unlock()
	}()

	// The orphan may have been resolved by a reconcile since this
	// resolver snapshotted it.
	adapter.mu.Lock()
	if _, still := adapter.orphans[id]; !still {
		adapter.mu.Unlock()
		return nil
	}
	adapter.mu.Unlock()

	current := adapter.currentSender()
	epoch := uint64(0)
	if current != nil {
		epoch = current.Epoch()
	}
	if state := adapter.rehydrateReconciled(orphan.remote, epoch); state != nil {
		adapter.mu.Lock()
		if _, exists := adapter.connections[id]; !exists {
			adapter.connections[id] = state
		}
		delete(adapter.orphans, id)
		adapter.mu.Unlock()
		return nil
	}

	adapter.mu.Lock()
	orphan.attempts++
	attempts := orphan.attempts
	adapter.mu.Unlock()
	if attempts < MaxOrphanResolveAttempts {
		return nil
	}
	// Bounded: close the session rather than leaking an orphan the
	// control plane can never manage. Responsibility transfers only
	// once the close reached the negotiated sender with both required
	// capabilities: otherwise the orphan is retained and the next
	// cadence retries.
	// Responsibility transfers only once the close reached the
	// **current** negotiated sender — re-read while holding the claim,
	// so a concurrent reconnect cannot let a stale sender's send delete
	// the obligation into the wrong lineage.
	current = adapter.currentSender()
	if current == nil ||
		!current.HasCapability(uint64(controlpb.ControlCapability_CONTROL_CAPABILITY_PER_CONNECTION_CLOSE)) ||
		!current.HasCapability(uint64(controlpb.ControlCapability_CONTROL_CAPABILITY_RECONCILE_SESSION_REHYDRATION)) {
		return nil
	}
	requestID, err := current.AllocateRequestID()
	if err != nil {
		return err
	}
	envelope := &controlpb.ControlEnvelope{
		RequestId:  requestID,
		Generation: orphan.remote.GetGeneration(),
		Priority:   controlpb.Priority_PRIORITY_CRITICAL,
		RequiredCapabilities: []uint64{
			uint64(controlpb.ControlCapability_CONTROL_CAPABILITY_PER_CONNECTION_CLOSE),
			uint64(controlpb.ControlCapability_CONTROL_CAPABILITY_RECONCILE_SESSION_REHYDRATION),
		},
		Body: &controlpb.ControlEnvelope_CloseCommand{CloseCommand: &controlpb.CloseCommand{
			ConnectionId: id,
			CloseId:      adapter.newOperationID("orphan-close", current.Epoch(), id),
			ErrorSource:  controlpb.ErrorSource_ERROR_SOURCE_PROXY,
			Reason:       "unrehydratable after reconciliation",
			Force:        false,
		}},
	}
	if err := current.Send(ctx, envelope); err != nil {
		return err
	}
	// Compare-and-delete in ONE critical section: Send may race a
	// sender rotation — a stale sender's in-flight Send can still
	// return nil while its stream is being torn down, so a nil error
	// alone does not prove the close reached the live lineage. The
	// compare and the delete share the same adapter.mu hold, so they
	// linearize with rememberSender and with reconcile: either the
	// rotation happened first (the sender is no longer current, the
	// orphan is retained for the next cadence) or the delete happens
	// while the carrying sender is still the current lineage. A
	// two-step check would leave a window where a rotation plus a new
	// lineage's reconcile lands between them and the stale resolver
	// deletes an obligation the new lineage still owns.
	adapter.mu.Lock()
	if adapter.sender == current {
		delete(adapter.orphans, id)
	}
	adapter.mu.Unlock()
	return nil
}

// OrphanCount reports currently tracked unrehydrated sessions.
func (adapter *RouterAdapter) OrphanCount() int {
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	return len(adapter.orphans)
}

func (adapter *RouterAdapter) closeStateLocked(state *connectionState, source backend.ErrorSource) {
	if state.closed {
		return
	}
	state.closed = true
	if state.assignment != nil && !state.assignment.finished && state.selector != nil {
		state.assignment.finished = true
		state.selector.Finish(state.conn, false)
	}
	adapter.abandonBackendLocked(state)
	if !state.handshakeDone {
		adapter.notifyHandshakeLocked(state, state.conn.ServerAddr(), errors.New("connection closed during handshake"), source)
	}
	_ = adapter.handler.OnConnClose(state.conn, source)
	state.conn.markClosed()
	adapter.forgetClosedState(state)
}

func (adapter *RouterAdapter) abandonBackendLocked(state *connectionState) {
	receiver := state.conn.takeEventReceiver()
	if receiver != nil && state.currentBackend != nil {
		_ = receiver.OnConnClosed(state.currentBackend.ID(), state.conn)
	}
	state.currentBackend = nil
	state.conn.clearBackend()
}

func (adapter *RouterAdapter) notifyHandshakeLocked(
	state *connectionState,
	address string,
	err error,
	source backend.ErrorSource,
) {
	if state.handshakeDone {
		return
	}
	state.handshakeDone = true
	adapter.handler.OnHandshake(state.conn, bounded(address), err, source)
}

func (adapter *RouterAdapter) getOrCreate(identity *controlpb.ConnectionIdentity, epoch uint64) (*connectionState, error) {
	if identity.GetConnectionId() == 0 {
		return nil, errors.New("connection ID must be nonzero")
	}
	adapter.mu.Lock()
	if closedEpoch, closed := adapter.closedIDs[identity.GetConnectionId()]; closed {
		// Epoch-scoped lineage: only same-epoch reuse is illegitimate.
		// A different epoch means a reconnect happened — and a
		// same-process lineage never reuses ids, so the reuse is a new
		// Rust incarnation (which may well keep the same config
		// generation).
		if epoch == closedEpoch {
			adapter.mu.Unlock()
			return nil, errors.New("closed connection ID was reused")
		}
	}
	existing := adapter.connections[identity.GetConnectionId()]
	adapter.mu.Unlock()
	if existing != nil {
		existing.mu.Lock()
		identical := sameIdentity(existing.identity, identity)
		// A same-id handshake from a NEW control epoch with a different
		// identity is a new lineage arriving before any reconcile:
		// retire the stale state exactly once, then recreate. An
		// identical identity is the same session surviving a control
		// reconnect and is simply reused.
		stale := !existing.closed && epoch != existing.epoch && !identical
		if stale {
			adapter.closeStateLocked(existing, backend.SrcProxyQuit)
		}
		existing.mu.Unlock()
		if !stale {
			if !identical {
				return nil, errors.New("connection ID reused with different identity")
			}
			return existing, nil
		}
		adapter.forgetClosedState(existing)
	}
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	if state := adapter.connections[identity.GetConnectionId()]; state != nil {
		return state, nil
	}
	cloned := cloneIdentity(identity)
	conn := newProjectedConn(adapter, cloned)
	state := &connectionState{
		identity:  cloned,
		conn:      conn,
		epoch:     epoch,
		eventKeys: make(map[connectionEventKey]struct{}),
	}
	adapter.connections[identity.GetConnectionId()] = state
	return state, nil
}

func (state *connectionState) seenConnectionEvent(epoch, requestID uint64) bool {
	if requestID == 0 {
		return false
	}
	key := connectionEventKey{epoch: epoch, requestID: requestID}
	if _, seen := state.eventKeys[key]; seen {
		return true
	}
	state.eventKeys[key] = struct{}{}
	state.eventOrder = append(state.eventOrder, key)
	if len(state.eventOrder) > maxConnectionEventKeys {
		oldest := state.eventOrder[0]
		state.eventOrder = state.eventOrder[1:]
		delete(state.eventKeys, oldest)
	}
	return false
}

func (adapter *RouterAdapter) forgetClosedState(state *connectionState) {
	id := state.conn.ConnectionID()
	adapter.mu.Lock()
	if adapter.connections[id] == state {
		delete(adapter.connections, id)
	}
	if _, exists := adapter.closedIDs[id]; !exists {
		adapter.closedOrder = append(adapter.closedOrder, id)
		if len(adapter.closedOrder) > maxClosedConnectionTombstones {
			oldest := adapter.closedOrder[0]
			adapter.closedOrder = adapter.closedOrder[1:]
			delete(adapter.closedIDs, oldest)
		}
	}
	// Every close advances the tombstone to the incarnation that just
	// closed: a stale epoch here would let the NEXT same-epoch reuse
	// masquerade as a legitimate new lineage.
	adapter.closedIDs[id] = state.epoch
	adapter.mu.Unlock()
}

func (adapter *RouterAdapter) get(connectionID uint64) *connectionState {
	adapter.mu.Lock()
	state := adapter.connections[connectionID]
	adapter.mu.Unlock()
	return state
}

func (adapter *RouterAdapter) rememberSender(sender EnvelopeSender) {
	adapter.mu.Lock()
	if adapter.sender == nil || sender.Epoch() >= adapter.senderEpoch {
		adapter.sender = sender
		adapter.senderEpoch = sender.Epoch()
	}
	adapter.mu.Unlock()
}

func (adapter *RouterAdapter) currentSender() EnvelopeSender {
	adapter.mu.Lock()
	sender := adapter.sender
	adapter.mu.Unlock()
	return sender
}

func (adapter *RouterAdapter) newOperationID(kind string, epoch, connectionID uint64) string {
	return fmt.Sprintf("%s-%d-%d-%d", kind, epoch, connectionID, adapter.operationID.Add(1))
}

func (adapter *RouterAdapter) sendProtocolError(
	ctx context.Context,
	sender EnvelopeSender,
	requestID uint64,
	code controlpb.ErrorCode,
	detail string,
) error {
	return sendBody(ctx, sender, requestID, controlpb.Priority_PRIORITY_CRITICAL,
		&controlpb.ControlEnvelope_Error{Error: &controlpb.ProtocolError{
			Code:               code,
			OffendingRequestId: requestID,
			Detail:             bounded(detail),
		}})
}

// ConnectionCount returns current Go router-accounted Rust connections.
func (adapter *RouterAdapter) ConnectionCount() int {
	adapter.mu.Lock()
	states := make([]*connectionState, 0, len(adapter.connections))
	for _, state := range adapter.connections {
		states = append(states, state)
	}
	adapter.mu.Unlock()
	count := 0
	for _, state := range states {
		state.mu.Lock()
		if !state.closed {
			count++
		}
		state.mu.Unlock()
	}
	return count
}

type projectedConn struct {
	adapter *RouterAdapter
	id      uint64
	client  string
	// generation stamps outgoing per-session commands (redirect/close)
	// so the Rust gate can reject commands minted for a different
	// connection incarnation. Written once under state.mu.
	generation uint64

	mu sync.Mutex

	server     string
	backend    router.BackendInst
	clientIn   uint64
	clientOut  uint64
	values     map[any]any
	logFields  []zap.Field
	receiver   router.ConnEventReceiver
	redirect   router.BackendInst
	redirectID string
	// rehydratedRedirectID is a pending redirect restored from
	// reconciliation whose target backend inst is unknown to this
	// lineage; its terminal result is handled specially and no new
	// redirect may be issued until it retires.
	rehydratedRedirectID string
	// redirectSeq is the per-connection monotonically increasing
	// command sequence (restored from the reconcile watermark on
	// rehydration): the Rust gate proves delayed duplicates of evicted
	// terminals obsolete against it.
	redirectSeq uint64
	closeID     string
	closing     bool
	closed      bool
}

func newProjectedConn(adapter *RouterAdapter, identity *controlpb.ConnectionIdentity) *projectedConn {
	conn := &projectedConn{
		adapter: adapter,
		id:      identity.GetConnectionId(),
		client:  bounded(identity.GetClientAddress()),
		values:  make(map[any]any),
	}
	conn.values[backend.ConnContextKeyConnID] = conn.id
	conn.values[backend.ConnContextKeyConnAddr] = bounded(identity.GetListenerAddress())
	return conn
}

func (conn *projectedConn) ClientAddr() string { return conn.client }

func (conn *projectedConn) ServerAddr() string {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	return conn.server
}

func (conn *projectedConn) ClientInBytes() uint64 {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	return conn.clientIn
}

func (conn *projectedConn) ClientOutBytes() uint64 {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	return conn.clientOut
}

func (conn *projectedConn) UpdateLogger(fields ...zap.Field) {
	conn.mu.Lock()
	conn.logFields = append(conn.logFields, fields...)
	conn.mu.Unlock()
}

func (conn *projectedConn) SetValue(key, value any) {
	conn.mu.Lock()
	conn.values[key] = value
	conn.mu.Unlock()
}

func (conn *projectedConn) Value(key any) any {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	return conn.values[key]
}

func (conn *projectedConn) SetEventReceiver(receiver router.ConnEventReceiver) {
	conn.mu.Lock()
	conn.receiver = receiver
	conn.mu.Unlock()
}

func (conn *projectedConn) Redirect(target router.BackendInst) bool {
	if target == nil {
		return false
	}
	conn.mu.Lock()
	if conn.closed || conn.closing || conn.redirect != nil || conn.rehydratedRedirectID != "" {
		conn.mu.Unlock()
		return false
	}
	sender := conn.adapter.currentSender()
	if sender == nil {
		conn.mu.Unlock()
		return false
	}
	if conn.redirectSeq == ^uint64(0) {
		// The sequence space is exhausted: fail closed rather than
		// wrapping to the forbidden zero.
		conn.mu.Unlock()
		return false
	}
	requestID, err := sender.AllocateRequestID()
	if err != nil {
		conn.mu.Unlock()
		return false
	}
	redirectID := conn.adapter.newOperationID("redirect", sender.Epoch(), conn.id)
	sequence := conn.redirectSeq + 1
	envelope := &controlpb.ControlEnvelope{
		RequestId:  requestID,
		Generation: conn.generation,
		Priority:   controlpb.Priority_PRIORITY_CRITICAL,
		Body: &controlpb.ControlEnvelope_RedirectCommand{RedirectCommand: &controlpb.RedirectCommand{
			ConnectionId:    conn.id,
			RedirectId:      redirectID,
			BackendId:       target.ID(),
			BackendAddress:  target.Addr(),
			ClusterName:     target.ClusterName(),
			CommandSequence: sequence,
		}},
	}
	if err := trySend(sender, envelope); err != nil {
		conn.mu.Unlock()
		return false
	}
	conn.redirect = target
	conn.redirectID = redirectID
	conn.redirectSeq = sequence
	conn.mu.Unlock()
	return true
}

func (conn *projectedConn) ForceClose() bool {
	conn.mu.Lock()
	if conn.closed || conn.closing {
		conn.mu.Unlock()
		return false
	}
	sender := conn.adapter.currentSender()
	capability := uint64(controlpb.ControlCapability_CONTROL_CAPABILITY_PER_CONNECTION_CLOSE)
	if sender == nil || !sender.HasCapability(capability) {
		conn.mu.Unlock()
		return false
	}
	requestID, err := sender.AllocateRequestID()
	if err != nil {
		conn.mu.Unlock()
		return false
	}
	closeID := conn.adapter.newOperationID("close", sender.Epoch(), conn.id)
	envelope := &controlpb.ControlEnvelope{
		RequestId:            requestID,
		Generation:           conn.generation,
		Priority:             controlpb.Priority_PRIORITY_CRITICAL,
		RequiredCapabilities: []uint64{capability},
		Body: &controlpb.ControlEnvelope_CloseCommand{CloseCommand: &controlpb.CloseCommand{
			ConnectionId: conn.id,
			CloseId:      closeID,
			ErrorSource:  controlpb.ErrorSource_ERROR_SOURCE_PROXY,
			Reason:       "router eviction",
			Force:        true,
		}},
	}
	if err := trySend(sender, envelope); err != nil {
		conn.mu.Unlock()
		return false
	}
	conn.closeID = closeID
	conn.closing = true
	conn.mu.Unlock()
	return true
}

func (conn *projectedConn) ConnectionID() uint64 { return conn.id }

func (conn *projectedConn) ConnInfo() []zap.Field {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	fields := slices.Clone(conn.logFields)
	fields = append(fields, zap.String("client_addr", conn.client), zap.String("backend_addr", conn.server))
	return fields
}

func (conn *projectedConn) setBackend(selected router.BackendInst) {
	conn.mu.Lock()
	conn.backend = selected
	conn.server = bounded(selected.Addr())
	conn.mu.Unlock()
}

func (conn *projectedConn) clearBackend() {
	conn.mu.Lock()
	conn.backend = nil
	conn.server = ""
	conn.mu.Unlock()
}

func (conn *projectedConn) backendID() string {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	if conn.backend == nil {
		return ""
	}
	return conn.backend.ID()
}

func (conn *projectedConn) setTraffic(clientIn, clientOut uint64) {
	conn.mu.Lock()
	conn.clientIn = clientIn
	conn.clientOut = clientOut
	conn.mu.Unlock()
}

func (conn *projectedConn) eventReceiver() router.ConnEventReceiver {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	return conn.receiver
}

func (conn *projectedConn) takeEventReceiver() router.ConnEventReceiver {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	receiver := conn.receiver
	conn.receiver = nil
	conn.redirect = nil
	conn.redirectID = ""
	return receiver
}

func (conn *projectedConn) takeRedirect(id string) (router.BackendInst, router.ConnEventReceiver) {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	if id == "" || id != conn.redirectID {
		return nil, nil
	}
	pending := conn.redirect
	conn.redirect = nil
	conn.redirectID = ""
	return pending, conn.receiver
}

func (conn *projectedConn) redirectPending() bool {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	return conn.redirect != nil || conn.rehydratedRedirectID != ""
}

func (conn *projectedConn) redirectSequence() uint64 {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	return conn.redirectSeq
}

func (conn *projectedConn) pendingRedirectID() string {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	if conn.redirect != nil {
		return conn.redirectID
	}
	return conn.rehydratedRedirectID
}

func (conn *projectedConn) finishClose(id string, accepted bool) {
	conn.mu.Lock()
	if id == conn.closeID && !accepted {
		conn.closeID = ""
		conn.closing = false
	}
	conn.mu.Unlock()
}

func (conn *projectedConn) markClosed() {
	conn.mu.Lock()
	conn.closed = true
	conn.closing = true
	conn.redirect = nil
	conn.redirectID = ""
	conn.mu.Unlock()
}

type reportedAddr string

func (address reportedAddr) Network() string { return "tcp" }
func (address reportedAddr) String() string  { return string(address) }

func projectClientInfo(identity *controlpb.ConnectionIdentity) router.ClientInfo {
	return router.ClientInfo{
		ClientAddr:   reportedAddr(bounded(identity.GetClientAddress())),
		ProxyAddr:    reportedAddr(bounded(identity.GetProxyAddress())),
		ListenerPort: listenerPort(identity.GetListenerAddress()),
	}
}

func listenerPort(address string) string {
	_, port, err := net.SplitHostPort(address)
	if err == nil {
		return port
	}
	if value, parseErr := strconv.ParseUint(address, 10, 16); parseErr == nil && value > 0 {
		return address
	}
	return ""
}

func projectHandshake(metadata *controlpb.HandshakeMetadata) *pnet.HandshakeResp {
	return &pnet.HandshakeResp{
		Attrs:      maps.Clone(metadata.GetConnectionAttributes()),
		User:       bounded(metadata.GetUser()),
		DB:         bounded(metadata.GetDatabase()),
		AuthPlugin: bounded(metadata.GetAuthPlugin()),
		AuthData:   nil,
		Capability: pnet.Capability(metadata.GetCapability()),
		ZstdLevel:  int(metadata.GetZstdLevel()),
		Collation:  uint8(metadata.GetCollation()),
	}
}

func fromControlSource(source controlpb.ErrorSource) backend.ErrorSource {
	switch source {
	case controlpb.ErrorSource_ERROR_SOURCE_CLIENT_NETWORK:
		return backend.SrcClientNetwork
	case controlpb.ErrorSource_ERROR_SOURCE_BACKEND_NETWORK:
		return backend.SrcBackendNetwork
	case controlpb.ErrorSource_ERROR_SOURCE_BACKEND_SQL:
		return backend.SrcClientSQLErr
	case controlpb.ErrorSource_ERROR_SOURCE_SHUTDOWN:
		return backend.SrcProxyQuit
	case controlpb.ErrorSource_ERROR_SOURCE_PROXY, controlpb.ErrorSource_ERROR_SOURCE_CONTROL:
		return backend.SrcProxyErr
	default:
		return backend.SrcNone
	}
}

func sendBody(
	ctx context.Context,
	sender EnvelopeSender,
	requestID uint64,
	priority controlpb.Priority,
	body any,
) error {
	return sendBodyWithOptions(ctx, sender, requestID, 0, priority, nil, body)
}

func sendBodyWithOptions(
	ctx context.Context,
	sender EnvelopeSender,
	requestID, generation uint64,
	priority controlpb.Priority,
	required []uint64,
	body any,
) error {
	envelope := &controlpb.ControlEnvelope{
		RequestId:            requestID,
		Generation:           generation,
		Priority:             priority,
		RequiredCapabilities: required,
	}
	switch typed := body.(type) {
	case *controlpb.ControlEnvelope_HandshakeDecision:
		envelope.Body = typed
	case *controlpb.ControlEnvelope_RouteAssignment:
		envelope.Body = typed
	case *controlpb.ControlEnvelope_ReconcileSnapshot:
		envelope.Body = typed
	case *controlpb.ControlEnvelope_Error:
		envelope.Body = typed
	default:
		return fmt.Errorf("unsupported control response %T", body)
	}
	return sender.Send(ctx, envelope)
}

func trySend(sender EnvelopeSender, envelope *controlpb.ControlEnvelope) error {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return sender.Send(ctx, envelope)
}

func missingCapability(sender EnvelopeSender, required []uint64) uint64 {
	for _, capability := range required {
		if !sender.HasCapability(capability) {
			return capability
		}
	}
	return 0
}

func cloneIdentity(identity *controlpb.ConnectionIdentity) *controlpb.ConnectionIdentity {
	cloned, _ := proto.Clone(identity).(*controlpb.ConnectionIdentity)
	return cloned
}

func cloneHandshake(handshake *controlpb.HandshakeMetadata) *controlpb.HandshakeMetadata {
	cloned, _ := proto.Clone(handshake).(*controlpb.HandshakeMetadata)
	return cloned
}

func cloneDecision(decision *controlpb.HandshakeDecision) *controlpb.HandshakeDecision {
	cloned, _ := proto.Clone(decision).(*controlpb.HandshakeDecision)
	return cloned
}

func sameIdentity(left, right *controlpb.ConnectionIdentity) bool {
	return proto.Equal(left, right)
}

func bounded(value string) string {
	value = strings.ToValidUTF8(value, "?")
	if len(value) <= maxControlDetailBytes {
		return value
	}
	return strings.ToValidUTF8(value[:maxControlDetailBytes], "")
}

func int64Compare(left, right uint64) int {
	switch {
	case left < right:
		return -1
	case left > right:
		return 1
	default:
		return 0
	}
}
