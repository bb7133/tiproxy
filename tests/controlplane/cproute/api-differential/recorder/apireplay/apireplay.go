// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build apireplay

// Package apireplay records the router's public API boundary for the API
// differential corpus (contract a9c497c3 §1/§3, recorder README §1/§5).
//
// It is compiled only with the `apireplay` build tag and is reached from the
// proxy through a test-build overlay of pkg/proxy/backend/backend_conn_mgr.go
// that substitutes the public selector calls at their call site:
//
//	r, err := handshakeHandler.GetRouter(...) -> gate := apireplay.BeginRoute(); r, err := ...
//	selector := r.GetBackendSelector(ci)      -> selector, session := apireplay.OpenRoute(gate, r, ci)
//	backend, err = selector.Next()             -> backend, err = apireplay.Next(&selector, session)
//	selector.Finish(mgr, err == nil)           -> apireplay.Finish(&selector, session, mgr, err == nil)
//
// The session handle travels with the caller's selector variable, so
// concurrent connect attempts can never be cross-bound.
//
// Every event is recorded once, at the public method's return, inside the
// harness's serialized critical section (Sink.Record is called while the
// harness scheduler lock is held by the caller of the public method), so no
// other operation can interleave between the real call and its record.
// Nothing here reads router internals; the recorded backend and error are the
// values the caller received.
package apireplay

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"

	"github.com/pingcap/tiproxy/lib/util/errors"
	"github.com/pingcap/tiproxy/pkg/balance/router"
	"go.uber.org/zap"
)

// Effect is one client-side migration effect (redirect / force_close) with its
// acceptance, recorded when the router issues it on the wrapped connection.
type Effect struct {
	Kind      string `json:"kind"`
	Session   string `json:"session"`
	Operation string `json:"operation"`
	From      string `json:"from"`
	To        string `json:"to"`
	Accepted  bool   `json:"accepted"`
	// RefuseNext records which rejected request consumed the external one-shot
	// control. The writer moves it into the tick input; adapter output omits it.
	RefuseNext bool `json:"refuse_next,omitempty"`
	// DelayNext proves which accepted redirect consumed the external delayed
	// callback arm. The writer projects only the arm, never this Go operation.
	DelayNext bool `json:"delay_next,omitempty"`
}

// Event is one trace v1 event as recorded (inputs carry their own fields; the
// `Outcome`/`Backend`/`Effects` fields are the recorded public results and are
// kept apart from the trace input by the writer).
type Event struct {
	Metrics json.RawMessage `json:"queries,omitempty"`
	Op      string          `json:"op"`
	TOML    string          `json:"toml,omitempty"`
	// RefuseNext marks the serialized input boundary that arms the global
	// one-shot client refusal. The consuming Effect carries the same bit only
	// so the writer can prove that the control was consumed exactly once.
	RefuseNext bool `json:"refuse_next,omitempty"`
	// DelayNext marks the same serialized config boundary that arms the first
	// subsequently accepted redirect for delayed callback delivery.
	DelayNext bool            `json:"delay_next,omitempty"`
	Backends  []HealthBackend `json:"backends,omitempty"`
	Session   string          `json:"session,omitempty"`
	Client    string          `json:"client,omitempty"`
	Proxy     string          `json:"proxy,omitempty"`
	Port      string          `json:"port,omitempty"`
	Backend   string          `json:"backend,omitempty"`
	Success   *bool           `json:"success,omitempty"`
	Operation string          `json:"operation,omitempty"`
	// BackendRef identifies a replay-relative backend input. "previous"
	// means this engine's assignment immediately before router_reset;
	// Operation identifies an accepted redirect whose target is the input.
	BackendRef string   `json:"backend_ref,omitempty"`
	Outcome    string   `json:"outcome,omitempty"`
	Effects    []Effect `json:"effects,omitempty"`
}

// HealthBackend is one explicit health inventory entry (every field written).
type HealthBackend struct {
	ID                 string            `json:"-"`
	Address            string            `json:"address"`
	Labels             map[string]string `json:"labels"`
	Cluster            string            `json:"cluster"`
	Keyspace           string            `json:"keyspace"`
	IP                 string            `json:"ip"`
	StatusPort         uint              `json:"status_port"`
	Healthy            bool              `json:"healthy"`
	Local              bool              `json:"local"`
	ServerVersion      string            `json:"server_version"`
	SupportRedirection bool              `json:"support_redirection"`
}

// ErrTopologyUnavailable identifies only the explicitly scripted source fault.
// Unrelated external failures must not be relabelled as this declared outcome.
var ErrTopologyUnavailable = errors.New("declared topology unavailable")

// ErrorIdentity maps an observer error to its trace identity.
func ErrorIdentity(err error) string {
	switch {
	case err == router.ErrNoBackend:
		return "no_backend"
	case errors.Is(err, router.ErrNoBackend):
		return "wrapped_no_backend"
	case errors.Is(err, router.ErrPortConflict):
		return "port_conflict"
	case errors.Is(err, context.Canceled):
		return "cancelled"
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline_exceeded"
	case errors.Is(err, ErrTopologyUnavailable):
		return "topology_unavailable"
	default:
		return "unclassified_source_error"
	}
}

// Sink receives events in real consumption order and owns the harness's
// serialized critical section: Serialize runs fn while no other input delivery
// or public call can interleave, so the real call and its record are one
// atomic step (recorder README §1/§5).
type Sink interface {
	Record(Event)
	Serialize(fn func())
}

// Clock returns the harness logical clock (nanoseconds since trace start).
type Clock func() int64

var (
	sinkMu           sync.Mutex
	sink             Sink
	counter          atomic.Uint64
	overlayInstalled atomic.Bool
	prefix           = "s"
	controls         = newControls()
	resetState       = newRouterResetState()
)

type routerResetState struct {
	mu        sync.Mutex
	resetting bool
	selecting int
	idle      chan struct{}
	resume    chan struct{}
	live      map[*Conn]struct{}
}

func closedSignal() chan struct{} {
	ch := make(chan struct{})
	close(ch)
	return ch
}

func newRouterResetState() *routerResetState {
	return &routerResetState{idle: closedSignal(), live: make(map[*Conn]struct{})}
}

func beginSelection() {
	for {
		resetState.mu.Lock()
		if !resetState.resetting {
			if resetState.selecting == 0 {
				resetState.idle = make(chan struct{})
			}
			resetState.selecting++
			resetState.mu.Unlock()
			return
		}
		resume := resetState.resume
		resetState.mu.Unlock()
		<-resume
	}
}

// RouteGate covers router lookup through selector completion. Starting the
// gate before namespace lookup ensures a reset cannot release a caller that
// captured the old router immediately before OpenRoute.
type RouteGate struct{ active atomic.Bool }

// BeginRoute waits out an active reset and marks one routing attempt in flight.
func BeginRoute() *RouteGate {
	beginSelection()
	gate := &RouteGate{}
	gate.active.Store(true)
	return gate
}

// End abandons or completes a routing attempt. It is safe to call twice.
func (g *RouteGate) End() {
	if g == nil || !g.active.CompareAndSwap(true, false) {
		return
	}
	resetState.mu.Lock()
	resetState.selecting--
	if resetState.selecting == 0 {
		close(resetState.idle)
	}
	resetState.mu.Unlock()
}

// BeginRouterReset prevents new selectors from opening and waits until every
// already-open selector has either finished or abandoned its reservation.
// Finish/EndSelection and terminal callbacks remain runnable while it waits.
func BeginRouterReset(ctx context.Context) error {
	resetState.mu.Lock()
	if resetState.resetting {
		resetState.mu.Unlock()
		return errors.New("router reset already active")
	}
	resetState.resetting = true
	resetState.resume = make(chan struct{})
	idle := resetState.idle
	resetState.mu.Unlock()
	select {
	case <-idle:
		return nil
	case <-ctx.Done():
		EndRouterReset()
		return fmt.Errorf("wait for idle selectors: %w", ctx.Err())
	}
}

// EndRouterReset admits selectors that were held while the router was replaced.
func EndRouterReset() {
	resetState.mu.Lock()
	if resetState.resetting {
		resetState.resetting = false
		close(resetState.resume)
	}
	resetState.mu.Unlock()
}

type delayedRedirect struct {
	from, to string
	success  bool
	settled  chan struct{}
}

type controlState struct {
	mu           sync.Mutex
	refuse       uint64
	delay        uint64
	awaiting     map[*Conn]string
	delayed      map[*Conn]delayedRedirect
	closing      map[*Conn]string
	delayedReady chan struct{}
	errors       []string
}

func newControls() *controlState {
	return &controlState{awaiting: make(map[*Conn]string), delayed: make(map[*Conn]delayedRedirect), closing: make(map[*Conn]string), delayedReady: make(chan struct{}, 1)}
}

// MarkOverlayInstalled is called by a generated source file that record.py
// adds to the overlaid backend package. A recorder binary without the complete
// overlay never calls it and must fail before starting a capture.
func MarkOverlayInstalled() { overlayInstalled.Store(true) }

// OverlayInstalled reports whether the generated build attestation ran.
func OverlayInstalled() bool { return overlayInstalled.Load() }

// Install binds the process-wide sink and session prefix. It is called once by
// the harness before the proxy accepts its first connection.
func Install(s Sink, sessionPrefix string) {
	sinkMu.Lock()
	defer sinkMu.Unlock()
	sink = s
	controls = newControls()
	resetState = newRouterResetState()
	if sessionPrefix != "" {
		prefix = sessionPrefix
	}
}

// RefuseNextEffect makes exactly one subsequently issued Redirect or ForceClose
// return false at the client boundary. It is test-build control input, not a
// router decision or an engine oracle.
func RefuseNextEffect() {
	controls.mu.Lock()
	controls.refuse++
	controls.mu.Unlock()
}

// DelayNextRedirectResult holds exactly one real redirect callback. The
// callback is delivered to the router only after that connection's real close
// callback, allowing the recorder to preserve the required late-completion
// history without fabricating a terminal result.
func DelayNextRedirectResult() {
	controls.mu.Lock()
	controls.delay++
	controls.mu.Unlock()
}

// CloseDelayedRedirect waits until a real redirect callback has been held and
// asks the underlying client connection to close. The real close callback
// releases the held redirect result after the close has reached the router.
func CloseDelayedRedirect(ctx context.Context) error {
	for {
		controls.mu.Lock()
		var conn *Conn
		var result delayedRedirect
		for candidate, delayed := range controls.delayed {
			conn = candidate
			result = delayed
			if conn.redirect != nil {
				controls.closing[conn] = conn.redirect.id
			}
			break
		}
		controls.mu.Unlock()
		if conn != nil {
			if !conn.RedirectableConn.ForceClose() {
				controls.mu.Lock()
				delete(controls.closing, conn)
				controls.mu.Unlock()
				return errors.New("delayed redirect connection refused scripted close")
			}
			select {
			case <-result.settled:
				return nil
			case <-ctx.Done():
				return fmt.Errorf("wait for delayed redirect settlement: %w", ctx.Err())
			}
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("wait for delayed redirect callback: %w", ctx.Err())
		case <-controls.delayedReady:
		}
	}
}

// PendingControls reports unconsumed script controls. Any row here makes the
// capture incomplete: the script tried to exercise an outcome that never
// reached the actual client boundary.
func PendingControls() []string {
	controls.mu.Lock()
	defer controls.mu.Unlock()
	var pending []string
	if controls.refuse != 0 {
		pending = append(pending, fmt.Sprintf("unconsumed refuse_next_effect=%d", controls.refuse))
	}
	if controls.delay != 0 {
		pending = append(pending, fmt.Sprintf("unconsumed delay_next_redirect_result=%d", controls.delay))
	}
	if len(controls.awaiting) != 0 {
		pending = append(pending, fmt.Sprintf("accepted delayed redirects without callback=%d", len(controls.awaiting)))
	}
	if len(controls.delayed) != 0 {
		pending = append(pending, fmt.Sprintf("unsettled delayed redirect callbacks=%d", len(controls.delayed)))
	}
	if len(controls.closing) != 0 {
		pending = append(pending, fmt.Sprintf("unsettled delayed redirect closes=%d", len(controls.closing)))
	}
	pending = append(pending, controls.errors...)
	return pending
}

func consumeRefusal() bool {
	controls.mu.Lock()
	defer controls.mu.Unlock()
	if controls.refuse == 0 {
		return false
	}
	controls.refuse--
	return true
}

func consumeDelay() bool {
	controls.mu.Lock()
	defer controls.mu.Unlock()
	if controls.delay == 0 {
		return false
	}
	controls.delay--
	return true
}

func markDelayedOperation(conn *Conn, operation string) {
	controls.mu.Lock()
	defer controls.mu.Unlock()
	if _, exists := controls.awaiting[conn]; exists {
		controls.errors = append(controls.errors, "multiple delayed operations for one connection")
		return
	}
	controls.awaiting[conn] = operation
}

func holdRedirectResult(conn *Conn, result delayedRedirect) bool {
	controls.mu.Lock()
	defer controls.mu.Unlock()
	if conn.redirect == nil || !conn.redirect.delayed || controls.awaiting[conn] != conn.redirect.id {
		return false
	}
	delete(controls.awaiting, conn)
	if _, exists := controls.delayed[conn]; exists {
		controls.errors = append(controls.errors, "multiple delayed redirect callbacks for one connection")
		return false
	}
	result.settled = make(chan struct{})
	controls.delayed[conn] = result
	select {
	case controls.delayedReady <- struct{}{}:
	default:
	}
	return true
}

func takeDelayedRedirect(conn *Conn) (delayedRedirect, bool) {
	controls.mu.Lock()
	defer controls.mu.Unlock()
	result, ok := controls.delayed[conn]
	if ok {
		delete(controls.delayed, conn)
	}
	return result, ok
}

func takeDelayedClose(conn *Conn) string {
	controls.mu.Lock()
	defer controls.mu.Unlock()
	operation := controls.closing[conn]
	delete(controls.closing, conn)
	return operation
}

func record(ev Event) {
	sinkMu.Lock()
	s := sink
	sinkMu.Unlock()
	if s != nil {
		s.Record(ev)
	}
}

func serialize(fn func()) {
	sinkMu.Lock()
	s := sink
	sinkMu.Unlock()
	if s == nil {
		fn()
		return
	}
	s.Serialize(fn)
}

// Session is the recorded identity of one selector: ids are `<prefix>-<n>`
// with a monotonic n, never reused.
type Session struct {
	id      string
	current router.BackendInst
	ordinal atomic.Uint64
	conn    *Conn
	// A successful Finish transfers the session's terminal event to the real
	// connection callback. An abandoned selector ends at its caller's return.
	established bool
	closed      bool
	gate        *RouteGate
}

// ID returns the recorded session id.
func (s *Session) ID() string { return s.id }

// Open calls the real GetBackendSelector and records the `open` event.
func Open(r router.Router, ci router.ClientInfo) (sel router.BackendSelector, s *Session) {
	return OpenRoute(BeginRoute(), r, ci)
}

// OpenRoute records a selector after BeginRoute has gated the namespace/router
// lookup that supplied r.
func OpenRoute(gate *RouteGate, r router.Router, ci router.ClientInfo) (sel router.BackendSelector, s *Session) {
	if gate == nil || !gate.active.Load() {
		panic("apireplay: OpenRoute requires an active route gate")
	}
	serialize(func() {
		sel = r.GetBackendSelector(ci)
		s = &Session{id: fmt.Sprintf("%s-%d", prefix, counter.Add(1)), gate: gate}
		record(Event{Op: "open", Session: s.id, Client: addr(ci.ClientAddr), Proxy: addr(ci.ProxyAddr), Port: ci.ListenerPort})
	})
	return sel, s
}

// Next calls the real BackendSelector.Next and records exactly one `next`
// event with the public result: the backend ID or the public error class.
func Next(sel *router.BackendSelector, s *Session) (backend router.BackendInst, err error) {
	serialize(func() {
		backend, err = sel.Next()
		ev := Event{Op: "next", Session: s.id, Outcome: outcome(err)}
		if err == nil && backend != nil {
			ev.Backend = backend.ID()
			s.current = backend
		}
		record(ev)
	})
	return backend, err
}

// Finish wraps the caller's RedirectableConn so that the router's later
// effects and the connection's callbacks are recorded, then calls the real
// Finish and records the `finish` event.
func Finish(sel *router.BackendSelector, s *Session, conn router.RedirectableConn, succeed bool) {
	serialize(func() {
		if s.conn == nil {
			s.conn = &Conn{RedirectableConn: conn, session: s}
		}
		sel.Finish(s.conn, succeed)
		if succeed {
			s.established = true
			resetState.mu.Lock()
			resetState.live[s.conn] = struct{}{}
			resetState.mu.Unlock()
		}
		ok := succeed
		record(Event{Op: "finish", Session: s.id, Success: &ok})
	})
}

// EndSelection is called at the real selector scope's deferred cleanup. It
// preserves CloseObservation and never fabricates a Finish or closes a live
// connection. Only attempts that did not establish a connection end here.
func EndSelection(sel *router.BackendSelector, s *Session) {
	serialize(func() {
		sel.CloseObservation()
		s.gate.End()
		if !s.established && !s.closed {
			s.closed = true
			record(Event{Op: "close", Session: s.id})
		}
	})
}

// Conn is the recorded RedirectableConn: the router receives this wrapper from
// Finish, so Redirect/ForceClose are observed at the client-side acceptance
// boundary; the receiver installed by the group is wrapped so the connection's
// terminal callbacks are recorded as `redirect_result` / `close`.
type Conn struct {
	router.RedirectableConn
	session  *Session
	receiver router.ConnEventReceiver
	refuse   atomic.Bool
	redirect *redirectOperation
	wrapper  *receiverWrapper
}

type redirectOperation struct {
	id       string
	from, to router.BackendInst
	settled  bool
	delayed  bool
}

// Refuse makes the next Redirect/ForceClose be refused at the client boundary
// (a scripted, declared refusal — recorder README §4).
func (c *Conn) Refuse(v bool) { c.refuse.Store(v) }

func (c *Conn) effect(kind string, to router.BackendInst, accepted, refuseNext, delayNext bool) string {
	n := c.session.ordinal.Add(1)
	e := Effect{Kind: kind, Session: c.session.id, Operation: fmt.Sprintf("%s/%d", c.session.id, n), Accepted: accepted, RefuseNext: refuseNext, DelayNext: delayNext}
	if c.session.current != nil {
		e.From = c.session.current.ID()
	}
	if to != nil {
		e.To = to.ID()
	}
	record(Event{Op: "effect", Session: c.session.id, Effects: []Effect{e}})
	return e.Operation
}

func (c *Conn) Redirect(to router.BackendInst) bool {
	refused := c.refuse.Load()
	refuseNext := !refused && consumeRefusal()
	accepted := !refused && !refuseNext && c.RedirectableConn.Redirect(to)
	delayNext := accepted && consumeDelay()
	op := c.effect("redirect", to, accepted, refuseNext, delayNext)
	if accepted {
		c.redirect = &redirectOperation{id: op, from: c.session.current, to: to, delayed: delayNext}
		if delayNext {
			markDelayedOperation(c, op)
		}
	}
	return accepted
}

func (c *Conn) ForceClose() bool {
	refused := c.refuse.Load()
	refuseNext := !refused && consumeRefusal()
	accepted := !refused && !refuseNext && c.RedirectableConn.ForceClose()
	c.effect("force_close", nil, accepted, refuseNext, false)
	return accepted
}

func (c *Conn) SetEventReceiver(receiver router.ConnEventReceiver) {
	c.receiver = receiver
	c.wrapper = &receiverWrapper{inner: receiver, conn: c}
	c.RedirectableConn.SetEventReceiver(c.wrapper)
}

type receiverWrapper struct {
	inner router.ConnEventReceiver
	conn  *Conn
}

// The three terminal callbacks arrive on connection goroutines; each real call
// and its record run inside the serialized critical section so they cannot
// interleave with a tick or an input delivery (review msg 4d63e069). The
// router's Redirect/ForceClose on the wrapped connection only post a signal
// (backend_conn_mgr.go), so a tick holding the section never waits on them.
func (w *receiverWrapper) OnRedirectSucceed(from, to string, conn router.RedirectableConn) (err error) {
	serialize(func() {
		if holdRedirectResult(w.conn, delayedRedirect{from: from, to: to, success: true}) {
			return
		}
		err = w.deliverRedirectResult(from, to, true)
	})
	return err
}

func (w *receiverWrapper) OnRedirectFail(from, to string, conn router.RedirectableConn) (err error) {
	serialize(func() {
		if holdRedirectResult(w.conn, delayedRedirect{from: from, to: to}) {
			return
		}
		err = w.deliverRedirectResult(from, to, false)
	})
	return err
}

func (w *receiverWrapper) OnConnClosed(backendID string, conn router.RedirectableConn) (err error) {
	serialize(func() {
		err = w.inner.OnConnClosed(backendID, w.conn)
		w.conn.session.closed = true
		resetState.mu.Lock()
		delete(resetState.live, w.conn)
		resetState.mu.Unlock()
		record(Event{Op: "close", Session: w.conn.session.id, Operation: takeDelayedClose(w.conn)})
		if delayed, ok := takeDelayedRedirect(w.conn); ok {
			lateErr := w.deliverRedirectResult(delayed.from, delayed.to, delayed.success)
			close(delayed.settled)
			if err == nil {
				err = lateErr
			}
		}
	})
	return err
}

// Survivor is one live recorded connection at a router-reset boundary. Backend
// is the physical owner to restore: a held successful redirect has already
// moved the socket to its target even though its callback is still pending.
type Survivor struct {
	Conn      *Conn
	Session   string
	Backend   string
	Operation string
}

// SurvivorsLocked snapshots live connections while the recorder scheduler is
// held after BeginRouterReset. It reads only values observed at public calls.
// The reset is safe only when its one successful delayed callback has already
// arrived and every other accepted redirect has settled on the old router.
func SurvivorsLocked() ([]Survivor, error) {
	controls.mu.Lock()
	if controls.refuse != 0 || controls.delay != 0 || len(controls.awaiting) != 0 || len(controls.closing) != 0 {
		controls.mu.Unlock()
		return nil, errors.New("router reset has pending scripted controls")
	}
	if len(controls.delayed) != 1 {
		count := len(controls.delayed)
		controls.mu.Unlock()
		return nil, fmt.Errorf("router reset requires one held redirect callback, got %d", count)
	}
	delayedByConn := make(map[*Conn]delayedRedirect, len(controls.delayed))
	for conn, delayed := range controls.delayed {
		delayedByConn[conn] = delayed
	}
	controls.mu.Unlock()

	resetState.mu.Lock()
	defer resetState.mu.Unlock()
	if !resetState.resetting {
		return nil, errors.New("router reset snapshot requires an active reset gate")
	}
	out := make([]Survivor, 0, len(resetState.live))
	foundDelayed := false
	for conn := range resetState.live {
		backend, operation := "", ""
		if conn.session.current != nil {
			backend = conn.session.current.ID()
		}
		delayed, isDelayed := delayedByConn[conn]
		if isDelayed {
			op := conn.redirect
			if !delayed.success || delayed.from == "" || delayed.to == "" || op == nil || op.settled || !op.delayed ||
				op.from == nil || op.to == nil || op.from.ID() != delayed.from || op.to.ID() != delayed.to {
				return nil, fmt.Errorf("router reset session %s has an invalid held redirect", conn.session.id)
			}
			backend = delayed.to
			operation = op.id
			foundDelayed = true
		} else if conn.redirect != nil && !conn.redirect.settled {
			return nil, fmt.Errorf("router reset session %s has an unsettled ordinary redirect", conn.session.id)
		}
		if backend == "" {
			return nil, fmt.Errorf("router reset session %s has no current backend", conn.session.id)
		}
		out = append(out, Survivor{Conn: conn, Session: conn.session.id, Backend: backend, Operation: operation})
	}
	if !foundDelayed {
		return nil, errors.New("router reset held redirect does not belong to a live connection")
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Session < out[j].Session })
	return out, nil
}

// RecordRouterResetLocked records completion of the real old-router Close and
// fresh-router construction. The caller owns the scheduler critical section.
func RecordRouterResetLocked() { record(Event{Op: "router_reset", Outcome: "ok"}) }

// RehydrateLocked invokes the new router's public rehydration API and records
// either the prior-assignment reference or an accepted redirect target ref.
func RehydrateLocked(r router.AssignmentRehydrator, survivor Survivor) error {
	backend, ok := r.RehydrateConn(survivor.Backend, survivor.Conn)
	ev := Event{Op: "rehydrate", Session: survivor.Session, Backend: survivor.Backend, Outcome: "unknown_backend", BackendRef: "previous"}
	if survivor.Operation != "" {
		ev.BackendRef = ""
		ev.Operation = survivor.Operation
	}
	if ok {
		ev.Outcome = "ok"
		ev.Backend = backend.ID()
	}
	record(ev)
	if !ok {
		return fmt.Errorf("rehydrate %s on %s: unknown backend", survivor.Session, survivor.Backend)
	}
	return nil
}

// LookupDelayedTargetLocked resolves the held redirect target on the fresh
// router and records it relative to the accepted operation.
func LookupDelayedTargetLocked(r router.AssignmentRehydrator) (*Conn, error) {
	controls.mu.Lock()
	defer controls.mu.Unlock()
	for conn, delayed := range controls.delayed {
		if !delayed.success || conn.redirect == nil {
			return nil, errors.New("router reset requires a successful pending redirect")
		}
		backend, ok := r.LookupBackend(delayed.to)
		ev := Event{Op: "lookup", Backend: delayed.to, Operation: conn.redirect.id, Outcome: "unknown_backend"}
		if ok {
			ev.Outcome = "ok"
			ev.Backend = backend.ID()
		}
		record(ev)
		if !ok {
			return nil, fmt.Errorf("lookup pending redirect target %s: unknown backend", delayed.to)
		}
		return conn, nil
	}
	return nil, errors.New("router reset requires one pending redirect")
}

// ReleaseDelayedRedirectLocked delivers the real callback after rehydration
// and lookup. The caller owns the scheduler critical section.
func ReleaseDelayedRedirectLocked(conn *Conn) error {
	delayed, ok := takeDelayedRedirect(conn)
	if !ok || conn.wrapper == nil {
		return errors.New("pending redirect disappeared during router reset")
	}
	err := conn.wrapper.deliverRedirectResult(delayed.from, delayed.to, delayed.success)
	close(delayed.settled)
	return err
}

// WaitDelayedRedirect waits until the client produced the callback held by a
// declared delay control. It does not consume the callback.
func WaitDelayedRedirect(ctx context.Context) error {
	for {
		controls.mu.Lock()
		ready := len(controls.delayed) == 1
		controls.mu.Unlock()
		if ready {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("wait for pending redirect: %w", ctx.Err())
		case <-controls.delayedReady:
		}
	}
}

func (w *receiverWrapper) deliverRedirectResult(from, to string, success bool) error {
	var err error
	if success {
		err = w.inner.OnRedirectSucceed(from, to, w.conn)
	} else {
		err = w.inner.OnRedirectFail(from, to, w.conn)
	}
	w.recordRedirectResult(from, to, success)
	return err
}

func (w *receiverWrapper) recordRedirectResult(from, to string, success bool) {
	op := w.conn.redirect
	if op == nil || op.from.ID() != from || op.to.ID() != to {
		// Keep unexpected callbacks in the raw archive and mark the capture
		// incomplete. Do not invent authority from the most recent effect.
		record(Event{Op: "recorder_error", Session: w.conn.session.id, Outcome: "redirect_callback_without_matching_operation"})
		return
	}
	if !op.settled && success && !w.conn.session.closed {
		w.conn.session.current = op.to
	}
	op.settled = true
	record(Event{Op: "redirect_result", Session: w.conn.session.id, Success: &success, Operation: op.id, Backend: to})
}

func addr(a interface{ String() string }) string {
	if a == nil {
		return ""
	}
	return a.String()
}

func outcome(err error) string {
	switch {
	case err == nil:
		return "ok"
	case err == router.ErrNoBackend:
		return "no_backend"
	case errors.Is(err, router.ErrNoBackend):
		return "wrapped_no_backend"
	case errors.Is(err, router.ErrPortConflict):
		return "port_conflict"
	case errors.Is(err, context.Canceled):
		return "source_error:cancelled"
	case errors.Is(err, context.DeadlineExceeded):
		return "source_error:deadline_exceeded"
	case errors.Is(err, ErrTopologyUnavailable):
		return "source_error:topology_unavailable"
	default:
		return "unclassified_source_error"
	}
}

// Fields is a convenience for harness logging.
func Fields(ev Event) []zap.Field {
	return []zap.Field{zap.String("op", ev.Op), zap.String("session", ev.Session), zap.String("outcome", ev.Outcome), zap.String("backend", ev.Backend)}
}
