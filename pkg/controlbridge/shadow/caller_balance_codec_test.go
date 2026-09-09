// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package shadow

import (
	"context"
	"encoding/json"
	"math"
	"os"
	"testing"

	"github.com/pingcap/tiproxy/pkg/balance/observation"
	"github.com/stretchr/testify/require"
)

func balanceCodecFixture(t *testing.T) (*observation.Recorder, *observation.Owner, *observation.Delivery) {
	t.Helper()
	r, err := observation.NewRecorder(observation.DefaultLimits(), 41, 43)
	require.NoError(t, err)
	t.Cleanup(r.Close)
	o := r.NewNativeOwner()
	d, err := r.Next(context.Background())
	require.NoError(t, err)
	d.Release()
	// Independently reconstructed prefix in Rust: Group, config, two accounts,
	// five physical sessions and the leading session's closing transition.
	for range 10 {
		require.True(t, o.Emit(observation.Batch{EventCount: 1, Events: [observation.MaxEvents]observation.Event{{Kind: observation.Watermark}}}))
		d, err = r.Next(context.Background())
		require.NoError(t, err)
		d.Release()
	}
	c := o.BeginCaller()
	t.Cleanup(c.Cleanup)
	require.True(t, c.CaptureGroupBalance(70, 2, []uint64{9, 19}))
	e := c.BeginEvaluation()
	n := e.Native()
	n.Group, n.Policy, n.Config, n.ID = 2, 3, 4, 2
	n.Entry = observation.EntryBalance
	n.Configuration.BalancePolicy = e.CopyText("connection")
	n.Configuration.RoutingPolicy = e.CopyText("idlest")
	n.Configuration.CountRatio = math.Float64bits(1.2)
	n.Configuration.Rates[0], n.Configuration.Rates[5] = math.Float64bits(1), math.Float64bits(50)
	n.FactorCount = 2
	n.Factors[0], n.Factors[1] = observation.FactorStatus, observation.FactorConnection
	n.Widths[0], n.Widths[1] = 1, 16
	n.BackendCount = 2
	n.Backends[0] = observation.NativeBackend{Account: 9, Seen: 31, ID: e.CopyText("backend"), Addr: e.CopyText("backend:4000"), Healthy: true, ConnCount: 5, ConnScore: 5, Packed: 5}
	n.Backends[0].Parts[1] = 5
	n.Backends[1] = observation.NativeBackend{Account: 19, Seen: 31, ID: e.CopyText("destination"), Addr: e.CopyText("destination:4000"), Healthy: true, Routeable: true, RouteabilitySeen: true}
	n.SortedCount, n.Sorted[0], n.Sorted[1] = 2, 1, 0
	n.From, n.To, n.BalanceCount, n.Reason = 0, 1, math.Float64bits(50), observation.FactorConnection
	n.AdviceCount = 2
	n.Advice[0] = observation.NativeAdvice{Factor: observation.FactorStatus, From: 0, To: 1, Advice: 2, Count: math.Float64bits(1)}
	n.Advice[1] = observation.NativeAdvice{Factor: observation.FactorConnection, From: 0, To: 1, Advice: 2, Count: math.Float64bits(50)}
	for _, site := range []observation.ClockSite{observation.ClockMetricCadence, observation.ClockStatusSnapshot} {
		require.True(t, e.AddRead(observation.NativeRead{Kind: observation.ReadClock, Site: site, Time: observation.GoTimeValue{Domain: observation.GoTimeDomain, Location: 1}}))
	}
	require.True(t, e.Seal())
	require.True(t, c.CompleteEvaluation(e))
	require.True(t, c.CaptureBalanceClock(observation.GoTimeValue{Domain: observation.GoTimeDomain, Location: 1, Seconds: 63000000010}, "", ""))
	require.True(t, c.CaptureBalanceContext(false))
	require.True(t, c.CaptureBalanceVisit(12))
	for i, session := range []uint64{10, 11, 13} {
		require.True(t, c.CaptureBalanceContext(false))
		require.True(t, c.CaptureBalanceVisit(session))
		before := observation.ConnectionState{Present: true, Physical: 9, ScoreOwner: 9}
		after := before
		from, to, callback := "", "", observation.BalanceCallbackRefused
		batch := observation.Batch{EventCount: 1, Events: [observation.MaxEvents]observation.Event{{Kind: observation.Rejected, Session: session, Account: 9, Target: 19}}, Witness: observation.Witness{Session: session, Before: before, After: after, AccountCount: 2, Accounts: [observation.MaxWitnesses]observation.AccountWitness{{ID: 9, Score: 5, Physical: 5, Head: 12, Tail: 14}, {ID: 19}}}}
		if i == 1 {
			from, to, callback = "a", "b", observation.BalanceCallbackSkipped
		}
		if i == 2 {
			callback = observation.BalanceCallbackAccepted
			batch.Events[0].Kind, batch.Events[0].Operation = observation.Redirect, 1
			batch.Witness.After.ScoreOwner, batch.Witness.After.RedirectPending = 19, true
			batch.Witness.Accounts[0].Score, batch.Witness.Accounts[1].Score = 4, 1
		}
		require.True(t, c.CaptureBalanceRedirect(from, to, callback, batch))
	}
	require.True(t, c.CaptureBalanceContext(false)) // remaining physical14, quota1 reached
	require.True(t, c.CaptureBalanceResult(1))
	require.True(t, c.Seal())
	require.True(t, o.PublishCaller(c))
	d, err = r.Next(context.Background())
	require.NoError(t, err)
	t.Cleanup(d.Release)
	return r, o, d
}

func TestBalanceCodecSharedBodiesAndRetainedCharges(t *testing.T) {
	r, _, d := balanceCodecFixture(t)
	frame, err := EncodeCaller(d.Record)
	require.NoError(t, err)
	fixture := "../../../tests/controlplane/cproute/shadow/v4-group-balance.json"
	if os.Getenv("BALANCE_WRITE_GOLDEN") == "1" {
		require.NoError(t, os.WriteFile(fixture, frame[4:], 0644))
	}
	expected, err := os.ReadFile(fixture)
	require.NoError(t, err)
	require.Equal(t, expected, frame[4:], "BALANCE_SHARED_GO_RUST_FIXTURE")
	var decoded struct {
		Payload struct {
			Balance struct {
				Evaluation json.RawMessage
				Visits     []struct {
					Redirect *struct {
						Callback *bool
						Batch    json.RawMessage
					}
				}
			} `json:"group_balance"`
		}
	}
	require.NoError(t, json.Unmarshal(frame[4:], &decoded))
	b := decoded.Payload.Balance
	children := d.Record.Caller.Children()
	native, err := EncodeEvaluation(observation.Record{Epoch: d.Record.Epoch, Sequence: 12, Native: true, Evaluation: children[0].Evaluation})
	require.NoError(t, err)
	require.Equal(t, []byte(native[4:]), []byte(b.Evaluation), "BALANCE_CODEC_COMPLETE_NATIVE_BODY")
	require.Nil(t, b.Visits[0].Redirect)
	require.NotNil(t, b.Visits[1].Redirect.Callback)
	require.False(t, *b.Visits[1].Redirect.Callback)
	require.Nil(t, b.Visits[2].Redirect.Callback, "BALANCE_CODEC_CALLBACK_TRISTATE")
	require.True(t, *b.Visits[3].Redirect.Callback)
	for i := 1; i < 4; i++ {
		batch, err := EncodeRecord(observation.Record{Epoch: d.Record.Epoch, Sequence: uint64(12 + i), Native: true, Batch: children[i].Batch})
		require.NoError(t, err)
		require.Equal(t, []byte(batch[4:]), []byte(b.Visits[i].Redirect.Batch), "BALANCE_CODEC_COMPLETE_BATCH_BODY")
	}
	require.Same(t, &d.Record.Caller.EncodingBuffer()[0], &frame[0], "BALANCE_CODEC_PARENT_ARENA")
	require.Zero(t, testing.AllocsPerRun(100, func() { _, err = EncodeCaller(d.Record) }), "BALANCE_CODEC_NO_EXTRA_ALLOCATION")
	require.NoError(t, err)
	r.Close()
	count, bytes := r.Retained()
	require.EqualValues(t, 5, count)
	require.EqualValues(t, observation.CallerCharge+observation.EvaluationCharge+3*observation.BatchCharge, bytes, "BALANCE_CODEC_ALL_LEASES_UNTIL_WRITER")
	d.Release()
	count, bytes = r.Retained()
	require.Zero(t, count)
	require.Zero(t, bytes)
}

func TestBalanceCodecRejectsTamperedSealedViews(t *testing.T) {
	for _, fault := range []string{"unused-member", "duplicate-member", "unused-visit", "duplicate-session", "unused-context", "unfinalized", "child-index", "batch-shape", "entry", "group", "callback", "span", "text-offset", "read-count", "string-count", "zero-clock"} {
		t.Run(fault, func(t *testing.T) {
			_, o, d := balanceCodecFixture(t)
			c := d.Record.Caller
			b := c.Balance()
			switch fault {
			case "unused-member":
				b.Members[63] = 99
			case "duplicate-member":
				b.Members[1] = b.Members[0]
			case "unused-visit":
				b.Visits[63].Session = 99
			case "duplicate-session":
				b.Visits[2].Session = b.Visits[1].Session
			case "unused-context":
				b.Contexts[64] = true
			case "unfinalized":
				b.ResultSet = false
			case "child-index":
				b.Visits[2].Child = 1
			case "batch-shape":
				c.Children()[1].Batch.Events[0].Target = 0
			case "entry":
				c.Children()[0].Evaluation.Native().Entry = observation.EntryRoute
			case "group":
				c.Children()[0].Evaluation.Native().Group = 99
			case "callback":
				b.Visits[2].Callback = observation.BalanceCallbackRefused
			case "span":
				c.Children()[1].Batch.EventCount = 2
			case "text-offset":
				b.From.Offset = uint32(len(c.Bytes()) + 1)
			case "read-count":
				b.ReadCount--
			case "string-count":
				b.StringBytes++
			case "zero-clock":
				c.Children()[0].Evaluation.Native().BalanceCount = 0
			}
			_, err := EncodeCaller(d.Record)
			require.Error(t, err, "BALANCE_CODEC_STRICT_SEALED_VIEW")
			require.False(t, o.Enabled())
		})
	}
}

func TestBalanceCodecZeroRateHasExplicitNullClock(t *testing.T) {
	r, err := observation.NewRecorder(observation.DefaultLimits(), 41, 43)
	require.NoError(t, err)
	defer r.Close()
	o := r.NewNativeOwner()
	d, err := r.Next(context.Background())
	require.NoError(t, err)
	d.Release()
	for range 11 {
		require.True(t, o.Emit(observation.Batch{EventCount: 1, Events: [observation.MaxEvents]observation.Event{{Kind: observation.Watermark}}}))
		d, err = r.Next(context.Background())
		require.NoError(t, err)
		d.Release()
	}
	c := o.BeginCaller()
	defer c.Cleanup()
	require.True(t, c.CaptureGroupBalance(70, 2, []uint64{9}))
	e := c.BeginEvaluation()
	n := e.Native()
	n.Group, n.Policy, n.Config, n.ID, n.Entry = 2, 3, 4, 2, observation.EntryBalance
	n.Configuration.BalancePolicy = e.CopyText("connection")
	n.Configuration.RoutingPolicy = e.CopyText("idlest")
	n.Configuration.CountRatio = math.Float64bits(1.2)
	n.Configuration.Rates[0], n.Configuration.Rates[5] = math.Float64bits(1), math.Float64bits(50)
	n.FactorCount = 2
	n.Factors[0], n.Factors[1] = observation.FactorStatus, observation.FactorConnection
	n.Widths[0], n.Widths[1] = 1, 16
	n.BackendCount, n.Backends[0].Account, n.From, n.To = 1, 9, -1, -1
	require.True(t, e.Seal())
	require.True(t, c.CompleteEvaluation(e))
	require.True(t, c.CaptureBalanceResult(0))
	require.True(t, c.Seal())
	require.True(t, o.PublishCaller(c))
	d, err = r.Next(context.Background())
	require.NoError(t, err)
	defer d.Release()
	frame, err := EncodeCaller(d.Record)
	require.NoError(t, err)
	fixture := "../../../tests/controlplane/cproute/shadow/v4-group-balance-zero.json"
	if os.Getenv("BALANCE_WRITE_GOLDEN") == "1" {
		require.NoError(t, os.WriteFile(fixture, frame[4:], 0644))
	}
	expected, err := os.ReadFile(fixture)
	require.NoError(t, err)
	require.Equal(t, expected, frame[4:], "BALANCE_CODEC_ZERO_GOLDEN")
	require.Contains(t, string(frame), `"clock":null,"contexts":[],"visits":[],"accepted":0`, "BALANCE_CODEC_ZERO_NO_READS")
}
