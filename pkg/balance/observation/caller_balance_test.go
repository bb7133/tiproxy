// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package observation

import (
	"math"
	"strings"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"
)

func balanceCapture(t *testing.T, rate float64) (*Recorder, *Owner, *Caller) {
	t.Helper()
	r, o := callerOwner(t, DefaultLimits())
	c := o.BeginCaller()
	t.Cleanup(c.Cleanup)
	require.True(t, c.CaptureGroupBalance(70, 2, []uint64{9, 19}))
	e := c.BeginEvaluation()
	require.NotNil(t, e)
	n := e.Native()
	n.Group, n.Entry, n.BalanceCount = 2, EntryBalance, math.Float64bits(rate)
	require.True(t, e.Append([]byte("native")))
	require.True(t, e.Seal())
	require.True(t, c.CompleteEvaluation(e))
	return r, o, c
}
func balanceClock() GoTimeValue { return GoTimeValue{Domain: GoTimeDomain, Location: 1} }
func balanceBatch(session uint64, callback BalanceCallback) Batch {
	kind := Rejected
	if callback == BalanceCallbackAccepted {
		kind = Redirect
	}
	return Batch{EventCount: 1, Events: [MaxEvents]Event{{Kind: kind, Session: session, Account: 9, Target: 19}}}
}

func TestBalanceCaptureValuesOrderAndOwnership(t *testing.T) {
	r, o, c := balanceCapture(t, 50)
	text := []byte("tenant")
	borrowed := unsafe.String(unsafe.SliceData(text), len(text))
	require.True(t, c.CaptureBalanceClock(balanceClock(), borrowed, borrowed))
	require.True(t, c.CaptureBalanceContext(false))
	require.True(t, c.CaptureBalanceVisit(12)) // skipped by original closing/phase read
	require.True(t, c.CaptureBalanceContext(false))
	require.True(t, c.CaptureBalanceVisit(10))
	require.True(t, c.CaptureBalanceRedirect(borrowed, borrowed, BalanceCallbackRefused, balanceBatch(10, BalanceCallbackRefused)))
	text[0] = 'x'
	require.True(t, c.CaptureBalanceContext(false))
	require.True(t, c.CaptureBalanceVisit(11))
	require.True(t, c.CaptureBalanceRedirect("a", "b", BalanceCallbackSkipped, balanceBatch(11, BalanceCallbackSkipped)))
	require.True(t, c.CaptureBalanceContext(false))
	require.True(t, c.CaptureBalanceVisit(13))
	require.True(t, c.CaptureBalanceRedirect("tenant", "tenant", BalanceCallbackAccepted, balanceBatch(13, BalanceCallbackAccepted)))
	require.True(t, c.CaptureBalanceContext(false)) // original quota stop with remaining element
	require.True(t, c.CaptureBalanceResult(1))
	require.True(t, c.Seal())
	b := c.Balance()
	require.Equal(t, "tenant", string(c.Range(b.From)), "BALANCE_CAPTURE_COPIED_KEYSPACE")
	require.Equal(t, "tenant", string(c.Range(b.Visits[1].From)), "BALANCE_CAPTURE_COPIED_KEYSPACE")
	require.EqualValues(t, 5, b.ContextCount, "BALANCE_CAPTURE_FINAL_CONTEXT")
	require.EqualValues(t, 4, b.VisitCount, "BALANCE_CAPTURE_INCLUDES_SKIPS")
	require.False(t, b.Visits[0].Redirect)
	require.Equal(t, BalanceCallbackSkipped, b.Visits[2].Callback)
	require.Equal(t, BalanceCallbackRefused, b.Visits[1].Callback, "BALANCE_CAPTURE_CALLBACK_TRISTATE")
	require.EqualValues(t, 1, b.Visits[1].Child)
	require.EqualValues(t, 3, b.Visits[3].Child, "BALANCE_CAPTURE_CHILD_BINDING")
	require.EqualValues(t, 5, c.Span())
	require.True(t, o.PublishCaller(c))
	d := receive(t, r)
	c.Cleanup()
	r.Close()
	count, bytes := r.Retained()
	require.EqualValues(t, 5, count)
	require.EqualValues(t, CallerCharge+EvaluationCharge+3*BatchCharge, bytes, "BALANCE_CAPTURE_RETAINS_CHILD_LEASES")
	d.Release()
	count, bytes = r.Retained()
	require.Zero(t, count)
	require.Zero(t, bytes)
	require.Nil(t, c.Balance())
	require.LessOrEqual(t, unsafe.Sizeof(callerStorage{})+unsafe.Sizeof(Caller{}), uintptr(CallerCharge), "BALANCE_CAPTURE_LAYOUT_CHARGED")
	t.Logf("balance=%d visit=%d storage+caller=%d", unsafe.Sizeof(GroupBalance{}), unsafe.Sizeof(BalanceVisit{}), unsafe.Sizeof(callerStorage{})+unsafe.Sizeof(Caller{}))
}

func TestBalanceCaptureZeroClockAndFinalFreeze(t *testing.T) {
	for _, rate := range []float64{0, math.Copysign(0, -1)} {
		_, o, c := balanceCapture(t, rate)
		require.False(t, c.CaptureBalanceClock(balanceClock(), "", ""), "BALANCE_CAPTURE_ZERO_NO_CLOCK")
		require.False(t, o.Enabled())
	}
	_, _, c := balanceCapture(t, 0)
	require.True(t, c.CaptureBalanceResult(0))
	require.True(t, c.Seal())
	require.False(t, c.Balance().ClockSet)
	for _, action := range []string{"clock", "context", "visit", "redirect", "evaluation", "complete", "batch", "result"} {
		t.Run(action, func(t *testing.T) {
			_, o, c := balanceCapture(t, 50)
			require.True(t, c.CaptureBalanceClock(balanceClock(), "", ""))
			e := c.storage.children[0].Evaluation
			require.True(t, c.CaptureBalanceResult(0))
			switch action {
			case "clock":
				require.False(t, c.CaptureBalanceClock(balanceClock(), "", ""))
			case "context":
				require.False(t, c.CaptureBalanceContext(false), "BALANCE_CAPTURE_FINAL_FROZEN")
			case "visit":
				require.False(t, c.CaptureBalanceVisit(10))
			case "redirect":
				require.False(t, c.CaptureBalanceRedirect("", "", BalanceCallbackRefused, balanceBatch(10, BalanceCallbackRefused)))
			case "evaluation":
				require.Nil(t, c.BeginEvaluation())
			case "complete":
				require.False(t, c.CompleteEvaluation(e))
			case "batch":
				require.False(t, c.AppendBatch(watermark()))
			case "result":
				require.False(t, c.CaptureBalanceResult(0))
			}
			require.False(t, o.Enabled(), "BALANCE_CAPTURE_FINAL_FROZEN")
		})
	}
}

func TestBalanceCaptureExclusiveVariantAndSingleEvaluation(t *testing.T) {
	for _, other := range []string{"opaque", "pass", "route"} {
		for _, balanceFirst := range []bool{false, true} {
			_, o := callerOwner(t, DefaultLimits())
			c := o.BeginCaller()
			t.Cleanup(c.Cleanup)
			putBalance := func() bool { return c.CaptureGroupBalance(1, 2, nil) }
			putOther := func() bool {
				switch other {
				case "opaque":
					return c.Append([]byte("x"))
				case "pass":
					return c.CapturePassEnd(1, 0, 0)
				default:
					return c.CaptureGroupRoute(1, 2, 10, 0, nil)
				}
			}
			if balanceFirst {
				require.True(t, putBalance())
				require.False(t, putOther(), "BALANCE_CAPTURE_EXCLUSIVE")
			} else {
				require.True(t, putOther())
				require.False(t, putBalance(), "BALANCE_CAPTURE_EXCLUSIVE")
			}
		}
	}
	_, o, c := balanceCapture(t, 1)
	require.Nil(t, c.BeginEvaluation(), "BALANCE_CAPTURE_SINGLE_EVALUATION")
	require.False(t, o.Enabled())
	for _, wrong := range []string{"entry", "group"} {
		_, o := callerOwner(t, DefaultLimits())
		c := o.BeginCaller()
		t.Cleanup(c.Cleanup)
		require.True(t, c.CaptureGroupBalance(1, 2, nil))
		e := c.BeginEvaluation()
		n := e.Native()
		n.Group, n.Entry = 2, EntryBalance
		if wrong == "entry" {
			n.Entry = EntryRoute
		} else {
			n.Group = 3
		}
		require.True(t, e.Append([]byte("native")))
		require.True(t, e.Seal())
		require.False(t, c.CompleteEvaluation(e), "BALANCE_CAPTURE_NATIVE_BINDING")
	}
}

func TestBalanceCaptureCapacityDoesNotTruncate(t *testing.T) {
	for _, which := range []string{"visit", "context"} {
		r, o, c := balanceCapture(t, 50)
		require.True(t, c.CaptureBalanceClock(balanceClock(), "", ""))
		for i := range 64 {
			require.True(t, c.CaptureBalanceContext(false))
			require.True(t, c.CaptureBalanceVisit(uint64(i+1)))
		}
		require.True(t, c.CaptureBalanceContext(false))
		if which == "visit" {
			require.False(t, c.CaptureBalanceVisit(65), "BALANCE_CAPTURE_VISIT_PLUS_ONE")
		} else {
			require.False(t, c.CaptureBalanceContext(false), "BALANCE_CAPTURE_CONTEXT_PLUS_ONE")
		}
		require.Equal(t, Capacity, InvalidReason(o.reason.Load()), "BALANCE_CAPTURE_CAPACITY_REASON")
		require.False(t, c.Seal())
		require.EqualValues(t, 1, o.AdmittedSequence())
		c.Cleanup()
		n, bytes := r.Retained()
		require.Zero(t, n)
		require.EqualValues(t, EvaluationCharge, bytes, "BALANCE_CAPTURE_IDLE_ARENA_STILL_CHARGED")
		r.Close()
		n, bytes = r.Retained()
		require.Zero(t, n)
		require.Zero(t, bytes)
	}
	_, o, c := balanceCapture(t, 50)
	require.True(t, c.CaptureBalanceClock(balanceClock(), "", ""))
	for i := range 31 {
		require.True(t, c.CaptureBalanceContext(false))
		require.True(t, c.CaptureBalanceVisit(uint64(i+1)))
		require.True(t, c.CaptureBalanceRedirect("", "", BalanceCallbackRefused, balanceBatch(uint64(i+1), BalanceCallbackRefused)))
	}
	require.True(t, c.CaptureBalanceContext(false))
	require.True(t, c.CaptureBalanceVisit(32))
	require.True(t, c.CaptureBalanceContext(false))
	require.True(t, c.CaptureBalanceVisit(33))
	require.EqualValues(t, 128, c.storage.balance.ReadCount, "BALANCE_CAPTURE_READ_EQUAL")
	require.False(t, c.CaptureBalanceContext(false), "BALANCE_CAPTURE_READ_PLUS_ONE")
	require.Equal(t, Capacity, InvalidReason(o.reason.Load()))
	_, o, c = balanceCapture(t, 50)
	require.False(t, c.CaptureBalanceClock(balanceClock(), strings.Repeat("x", 513), ""), "BALANCE_CAPTURE_STRING_PLUS_ONE")
	require.Equal(t, Capacity, InvalidReason(o.reason.Load()))
}

func TestBalanceCaptureRejectsMissingAndReorderedValues(t *testing.T) {
	for _, fault := range []string{"unfinalized", "no-clock", "no-context", "cancelled", "duplicate", "extra-context", "unbound-batch", "wrong-session", "callback-null", "callback-false", "redirect-twice"} {
		t.Run(fault, func(t *testing.T) {
			_, o, c := balanceCapture(t, 50)
			if fault == "unfinalized" {
				require.False(t, c.Seal())
			} else if fault == "no-clock" {
				require.False(t, c.CaptureBalanceContext(false))
			} else {
				require.True(t, c.CaptureBalanceClock(balanceClock(), "", ""))
				switch fault {
				case "no-context":
					require.False(t, c.CaptureBalanceVisit(1))
				case "cancelled":
					require.True(t, c.CaptureBalanceContext(true))
					require.False(t, c.CaptureBalanceVisit(1))
				case "extra-context":
					require.True(t, c.CaptureBalanceContext(false))
					require.False(t, c.CaptureBalanceContext(false))
				case "unbound-batch":
					require.False(t, c.AppendBatch(balanceBatch(1, BalanceCallbackRefused)))
				default:
					require.True(t, c.CaptureBalanceContext(false))
					require.True(t, c.CaptureBalanceVisit(1))
					switch fault {
					case "duplicate":
						require.True(t, c.CaptureBalanceContext(false))
						require.False(t, c.CaptureBalanceVisit(1))
					case "wrong-session":
						require.False(t, c.CaptureBalanceRedirect("", "", BalanceCallbackRefused, balanceBatch(2, BalanceCallbackRefused)))
					case "callback-null":
						require.False(t, c.CaptureBalanceRedirect("", "", BalanceCallbackSkipped, balanceBatch(1, BalanceCallbackSkipped)))
					case "callback-false":
						require.False(t, c.CaptureBalanceRedirect("a", "b", BalanceCallbackRefused, balanceBatch(1, BalanceCallbackRefused)), "BALANCE_CAPTURE_CALLBACK_BACKSTOP")
					case "redirect-twice":
						require.True(t, c.CaptureBalanceRedirect("", "", BalanceCallbackRefused, balanceBatch(1, BalanceCallbackRefused)))
						require.False(t, c.CaptureBalanceRedirect("", "", BalanceCallbackRefused, balanceBatch(1, BalanceCallbackRefused)))
					}
				}
			}
			require.False(t, o.Enabled(), "BALANCE_CAPTURE_ORDER_INVALID")
		})
	}
}
