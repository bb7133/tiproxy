// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build apireplay

package apireplay

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

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

type reviewConn struct {
	router.RedirectableConn
	forced      *int
	forcedReady chan<- struct{}
}

func (c reviewConn) Value(any) any                    { return nil }
func (c reviewConn) Redirect(router.BackendInst) bool { return true }
func (c reviewConn) ForceClose() bool {
	if c.forced != nil {
		(*c.forced)++
	}
	if c.forcedReady != nil {
		c.forcedReady <- struct{}{}
	}
	return true
}

type reviewReceiver struct {
	router.ConnEventReceiver
	order *[]string
}

func (r reviewReceiver) append(event string) {
	if r.order != nil {
		*r.order = append(*r.order, event)
	}
}
func (r reviewReceiver) OnRedirectSucceed(string, string, router.RedirectableConn) error {
	r.append("redirect_success")
	return nil
}
func (r reviewReceiver) OnRedirectFail(string, string, router.RedirectableConn) error {
	r.append("redirect_fail")
	return nil
}
func (r reviewReceiver) OnConnClosed(string, router.RedirectableConn) error {
	r.append("close")
	return nil
}

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

func TestScriptedEffectRefusalIsOneShot(t *testing.T) {
	out := &reviewSink{}
	Install(out, "refusal")
	c := &Conn{RedirectableConn: reviewConn{}, session: &Session{id: "s", current: reviewBackend{id: "A"}}}
	RefuseNextEffect()
	var first, second bool
	out.Serialize(func() {
		first = c.Redirect(reviewBackend{id: "B"})
		second = c.Redirect(reviewBackend{id: "B"})
	})
	if first || !second {
		t.Fatalf("one-shot results: first=%v second=%v", first, second)
	}
	if len(out.events) != 2 || out.events[0].Effects[0].Accepted || !out.events[1].Effects[0].Accepted {
		t.Fatalf("recorded effects=%+v", out.events)
	}
	if !out.events[0].Effects[0].RefuseNext || out.events[1].Effects[0].RefuseNext {
		t.Fatalf("global-refusal provenance=%+v", out.events)
	}
	if pending := PendingControls(); len(pending) != 0 {
		t.Fatalf("pending controls=%v", pending)
	}
}

func TestDelayedRedirectResultIsReleasedAfterRealClose(t *testing.T) {
	out := &reviewSink{}
	Install(out, "delayed")
	forced := 0
	forcedReady := make(chan struct{}, 1)
	c := &Conn{RedirectableConn: reviewConn{forced: &forced, forcedReady: forcedReady}, session: &Session{id: "s", current: reviewBackend{id: "A"}}}
	order := []string{}
	w := &receiverWrapper{inner: reviewReceiver{order: &order}, conn: c}
	DelayNextRedirectResult()
	out.Serialize(func() {
		if !c.Redirect(reviewBackend{id: "B"}) {
			t.Fatal("redirect refused")
		}
	})
	if len(out.events) != 1 || !out.events[0].Effects[0].DelayNext {
		t.Fatalf("delayed redirect provenance=%+v", out.events)
	}
	if err := w.OnRedirectSucceed("A", "B", c); err != nil {
		t.Fatal(err)
	}
	if len(order) != 0 || len(out.events) != 1 {
		t.Fatalf("callback was delivered before close: order=%v events=%+v", order, out.events)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	closeResult := make(chan error, 1)
	go func() { closeResult <- CloseDelayedRedirect(ctx) }()
	<-forcedReady
	if forced != 1 {
		t.Fatalf("underlying ForceClose calls=%d", forced)
	}
	if err := w.OnConnClosed("A", c); err != nil {
		t.Fatal(err)
	}
	if err := <-closeResult; err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprint(order); got != "[close redirect_success]" {
		t.Fatalf("callback order=%s", got)
	}
	if len(out.events) != 3 || out.events[1].Op != "close" || out.events[2].Op != "redirect_result" {
		t.Fatalf("recorded events=%+v", out.events)
	}
	if out.events[1].Operation != "s/1" || out.events[2].Operation != "s/1" {
		t.Fatalf("delayed close/result references=%+v", out.events)
	}
	if c.session.current.ID() != "A" {
		t.Fatalf("late callback resurrected closed session on %s", c.session.current.ID())
	}
	if pending := PendingControls(); len(pending) != 0 {
		t.Fatalf("pending controls=%v", pending)
	}
}

func TestDelayedRedirectArmBindsFirstAcceptedRedirect(t *testing.T) {
	out := &reviewSink{}
	Install(out, "delayed-first")
	first := &Conn{RedirectableConn: reviewConn{}, session: &Session{id: "first", current: reviewBackend{id: "A"}}}
	second := &Conn{RedirectableConn: reviewConn{}, session: &Session{id: "second", current: reviewBackend{id: "A"}}}
	third := &Conn{RedirectableConn: reviewConn{}, session: &Session{id: "third", current: reviewBackend{id: "A"}}}
	DelayNextRedirectResult()
	first.Refuse(true)
	out.Serialize(func() {
		if first.Redirect(reviewBackend{id: "B"}) {
			t.Fatal("session-refused redirect was accepted")
		}
	})
	out.Serialize(func() {
		if !second.Redirect(reviewBackend{id: "B"}) || !third.Redirect(reviewBackend{id: "C"}) {
			t.Fatal("accepted redirect was refused")
		}
	})
	if len(out.events) != 3 || out.events[0].Effects[0].DelayNext ||
		!out.events[1].Effects[0].DelayNext || out.events[2].Effects[0].DelayNext {
		t.Fatalf("first accepted delay binding=%+v", out.events)
	}
}

func TestDelayedRedirectControlTimesOutAndRemainsPending(t *testing.T) {
	Install(&reviewSink{}, "timeout")
	DelayNextRedirectResult()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := CloseDelayedRedirect(ctx); err == nil {
		t.Fatal("missing delayed callback did not time out")
	}
	pending := PendingControls()
	if len(pending) != 1 || pending[0] != "unconsumed delay_next_redirect_result=1" {
		t.Fatalf("pending controls=%v", pending)
	}
}

func TestAcceptedDelayedRedirectWithoutCallbackRemainsPending(t *testing.T) {
	out := &reviewSink{}
	Install(out, "missing-callback")
	c := &Conn{RedirectableConn: reviewConn{}, session: &Session{id: "s", current: reviewBackend{id: "A"}}}
	DelayNextRedirectResult()
	out.Serialize(func() {
		if !c.Redirect(reviewBackend{id: "B"}) {
			t.Fatal("redirect refused")
		}
	})
	pending := PendingControls()
	if len(pending) != 1 || pending[0] != "accepted delayed redirects without callback=1" {
		t.Fatalf("pending controls=%v", pending)
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
