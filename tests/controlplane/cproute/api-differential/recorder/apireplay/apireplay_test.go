// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build apireplay

package apireplay

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/pingcap/tiproxy/pkg/balance/router"
)

type reviewSink struct {
	depth, unlocked int
	events          []Event
}

func (s *reviewSink) Serialize(fn func()) { s.depth++; defer func() { s.depth-- }(); fn() }
func (s *reviewSink) Record(e Event) {
	if s.depth == 0 {
		s.unlocked++
	}
	s.events = append(s.events, e)
}

type reviewBackend struct {
	router.BackendInst
	id string
}

func (b reviewBackend) ID() string { return b.id }

type reviewConn struct{ router.RedirectableConn }

func (c reviewConn) Value(any) any                    { return nil }
func (c reviewConn) Redirect(router.BackendInst) bool { return true }
func (c reviewConn) ForceClose() bool                 { return true }

type reviewReceiver struct{ router.ConnEventReceiver }

func (r reviewReceiver) OnRedirectSucceed(string, string, router.RedirectableConn) error { return nil }
func (r reviewReceiver) OnRedirectFail(string, string, router.RedirectableConn) error    { return nil }
func (r reviewReceiver) OnConnClosed(string, router.RedirectableConn) error              { return nil }

func TestReviewCallbackMustSerialize(t *testing.T) {
	out := &reviewSink{}
	Install(out, "review")
	c := &Conn{RedirectableConn: reviewConn{}, session: &Session{id: "s", current: reviewBackend{id: "A"}}}
	w := &receiverWrapper{inner: reviewReceiver{}, conn: c}
	_ = w.OnConnClosed("A", c)
	if out.unlocked != 0 {
		t.Errorf("callback recorded %d event outside Serialize", out.unlocked)
	}
}
func TestReviewRedirectMustBindAcceptedOperationAndDestination(t *testing.T) {
	out := &reviewSink{}
	Install(out, "review")
	c := &Conn{RedirectableConn: reviewConn{}, session: &Session{id: "s", current: reviewBackend{id: "A"}}}
	w := &receiverWrapper{inner: reviewReceiver{}, conn: c}
	out.Serialize(func() { c.Redirect(reviewBackend{id: "B"}); c.ForceClose() })
	_ = w.OnRedirectSucceed("A", "B", c)
	got := out.events[len(out.events)-1]
	if got.Operation != "s/1" {
		t.Errorf("redirect callback bound to %s; expected accepted redirect s/1 (force_close was s/2)", got.Operation)
	}
	if c.session.current.ID() != "B" {
		t.Errorf("successful redirect left current=%s; next effect must originate at B", c.session.current.ID())
	}
}

func TestAbandonedSelectorEndsWithoutInventedFinish(t *testing.T) {
	out := &reviewSink{}
	Install(out, "review")
	s := &Session{id: "abandoned"}
	sel := router.BackendSelector{}
	EndSelection(&sel, s)
	EndSelection(&sel, s)
	if len(out.events) != 1 || out.events[0].Op != "close" {
		t.Fatalf("events=%+v", out.events)
	}
	established := &Session{id: "established", established: true}
	EndSelection(&sel, established)
	if len(out.events) != 1 {
		t.Fatal("successful connection closed at selector scope end")
	}
}
func TestLateRedirectDoesNotResurrectClosedSession(t *testing.T) {
	out := &reviewSink{}
	Install(out, "review")
	c := &Conn{RedirectableConn: reviewConn{}, session: &Session{id: "s", current: reviewBackend{id: "A"}}}
	w := &receiverWrapper{inner: reviewReceiver{}, conn: c}
	out.Serialize(func() { c.Redirect(reviewBackend{id: "B"}); c.ForceClose() })
	if err := w.OnConnClosed("A", c); err != nil {
		t.Fatal(err)
	}
	if err := w.OnRedirectSucceed("A", "B", c); err != nil {
		t.Fatal(err)
	}
	if c.session.current.ID() != "A" || out.events[len(out.events)-1].Operation != "s/1" {
		t.Fatalf("late callback: %+v", out.events)
	}
}

func TestSourceErrorIdentityAndPublicReturn(t *testing.T) {
	for _, tc := range []struct {
		err           error
		input, result string
	}{
		{router.ErrNoBackend, "no_backend", "no_backend"},
		{fmt.Errorf("fetch: %w", router.ErrNoBackend), "wrapped_no_backend", "wrapped_no_backend"},
		{fmt.Errorf("fetch: %w", context.Canceled), "cancelled", "source_error:cancelled"},
		{fmt.Errorf("fetch: %w", context.DeadlineExceeded), "deadline_exceeded", "source_error:deadline_exceeded"},
		{fmt.Errorf("fetch: %w", ErrTopologyUnavailable), "topology_unavailable", "source_error:topology_unavailable"},
		{errors.New("unexpected source failure"), "unclassified_source_error", "unclassified_source_error"},
	} {
		if got := ErrorIdentity(tc.err); got != tc.input {
			t.Errorf("input=%s, want %s", got, tc.input)
		}
		if got := outcome(tc.err); got != tc.result {
			t.Errorf("result=%s, want %s", got, tc.result)
		}
	}
}
