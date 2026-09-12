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
//	selector := r.GetBackendSelector(ci)      -> selector, session := apireplay.Open(r, ci)
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
	"fmt"
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
}

// Event is one trace v1 event as recorded (inputs carry their own fields; the
// `Outcome`/`Backend`/`Effects` fields are the recorded public results and are
// kept apart from the trace input by the writer).
type Event struct {
	Op        string          `json:"op"`
	TOML      string          `json:"toml,omitempty"`
	Backends  []HealthBackend `json:"backends,omitempty"`
	Session   string          `json:"session,omitempty"`
	Client    string          `json:"client,omitempty"`
	Proxy     string          `json:"proxy,omitempty"`
	Port      string          `json:"port,omitempty"`
	Backend   string          `json:"backend,omitempty"`
	Success   *bool           `json:"success,omitempty"`
	Operation string          `json:"operation,omitempty"`
	Outcome   string          `json:"outcome,omitempty"`
	Effects   []Effect        `json:"effects,omitempty"`
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
	default:
		return "topology_unavailable"
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
	sinkMu  sync.Mutex
	sink    Sink
	counter atomic.Uint64
	prefix  = "s"
)

// Install binds the process-wide sink and session prefix. It is called once by
// the harness before the proxy accepts its first connection.
func Install(s Sink, sessionPrefix string) {
	sinkMu.Lock()
	defer sinkMu.Unlock()
	sink = s
	if sessionPrefix != "" {
		prefix = sessionPrefix
	}
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
}

// ID returns the recorded session id.
func (s *Session) ID() string { return s.id }

// Open calls the real GetBackendSelector and records the `open` event.
func Open(r router.Router, ci router.ClientInfo) (sel router.BackendSelector, s *Session) {
	serialize(func() {
		sel = r.GetBackendSelector(ci)
		s = &Session{id: fmt.Sprintf("%s-%d", prefix, counter.Add(1))}
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
		ok := succeed
		record(Event{Op: "finish", Session: s.id, Success: &ok})
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
}

// Refuse makes the next Redirect/ForceClose be refused at the client boundary
// (a scripted, declared refusal — recorder README §4).
func (c *Conn) Refuse(v bool) { c.refuse.Store(v) }

func (c *Conn) effect(kind string, to router.BackendInst, accepted bool) {
	n := c.session.ordinal.Add(1)
	e := Effect{Kind: kind, Session: c.session.id, Operation: fmt.Sprintf("%s/%d", c.session.id, n), Accepted: accepted}
	if c.session.current != nil {
		e.From = c.session.current.ID()
	}
	if to != nil {
		e.To = to.ID()
	}
	record(Event{Op: "effect", Session: c.session.id, Effects: []Effect{e}})
}

func (c *Conn) Redirect(to router.BackendInst) bool {
	accepted := !c.refuse.Load() && c.RedirectableConn.Redirect(to)
	c.effect("redirect", to, accepted)
	return accepted
}

func (c *Conn) ForceClose() bool {
	accepted := !c.refuse.Load() && c.RedirectableConn.ForceClose()
	c.effect("force_close", nil, accepted)
	return accepted
}

func (c *Conn) SetEventReceiver(receiver router.ConnEventReceiver) {
	c.receiver = receiver
	c.RedirectableConn.SetEventReceiver(&receiverWrapper{inner: receiver, conn: c})
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
		err = w.inner.OnRedirectSucceed(from, to, w.conn)
		if b, ok := w.conn.RedirectableConn.Value(backendKey{}).(router.BackendInst); ok {
			w.conn.session.current = b
		}
		ok := true
		record(Event{Op: "redirect_result", Session: w.conn.session.id, Success: &ok, Operation: w.lastOp(), Backend: to})
	})
	return err
}

func (w *receiverWrapper) OnRedirectFail(from, to string, conn router.RedirectableConn) (err error) {
	serialize(func() {
		err = w.inner.OnRedirectFail(from, to, w.conn)
		ok := false
		record(Event{Op: "redirect_result", Session: w.conn.session.id, Success: &ok, Operation: w.lastOp(), Backend: to})
	})
	return err
}

func (w *receiverWrapper) OnConnClosed(backendID string, conn router.RedirectableConn) (err error) {
	serialize(func() {
		err = w.inner.OnConnClosed(backendID, w.conn)
		record(Event{Op: "close", Session: w.conn.session.id})
	})
	return err
}

func (w *receiverWrapper) lastOp() string {
	return fmt.Sprintf("%s/%d", w.conn.session.id, w.conn.session.ordinal.Load())
}

type backendKey struct{}

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
	default:
		return "source_error:topology_unavailable"
	}
}

// Fields is a convenience for harness logging.
func Fields(ev Event) []zap.Field {
	return []zap.Field{zap.String("op", ev.Op), zap.String("session", ev.Session), zap.String("outcome", ev.Outcome), zap.String("backend", ev.Backend)}
}
