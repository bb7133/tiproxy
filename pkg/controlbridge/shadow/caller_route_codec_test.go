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

func routeCodecFixture(t *testing.T) (*observation.Recorder, *observation.Owner, *observation.Delivery) {
	t.Helper()
	r, err := observation.NewRecorder(observation.DefaultLimits(), 41, 43)
	require.NoError(t, err)
	t.Cleanup(r.Close)
	o := r.NewNativeOwner()
	d, err := r.Next(context.Background())
	require.NoError(t, err)
	d.Release()
	// Advance to the shared fixture's independent ledger/configuration prefix.
	for range 3 {
		require.True(t, o.Emit(observation.Batch{EventCount: 1, Events: [observation.MaxEvents]observation.Event{{Kind: observation.Watermark}}}))
		d, err = r.Next(context.Background())
		require.NoError(t, err)
		d.Release()
	}
	c := o.BeginCaller()
	t.Cleanup(c.Cleanup)
	require.True(t, c.CaptureGroupRoute(1, 2, 10, 0, []uint64{9}))
	require.True(t, c.CaptureRouteHealthy(9, true))
	e := c.BeginEvaluation()
	n := e.Native()
	n.Group, n.Policy, n.Config, n.ID = 2, 3, 4, 2
	n.Entry = observation.EntryRoute
	n.Configuration.BalancePolicy = e.CopyText("connection")
	n.Configuration.RoutingPolicy = e.CopyText("idlest")
	n.Configuration.CountRatio = math.Float64bits(1.2)
	n.FactorCount = 2
	n.Factors[0], n.Factors[1] = observation.FactorStatus, observation.FactorConnection
	n.Widths[0], n.Widths[1] = 1, 16
	n.BackendCount = 1
	n.Backends[0] = observation.NativeBackend{Account: 9, Seen: 31, ID: e.CopyText("backend"), Addr: e.CopyText("backend:4000"), Healthy: true, Routeable: true, RouteabilitySeen: true}
	n.SortedCount, n.ReturnedCount = 1, 1
	for _, site := range []observation.ClockSite{observation.ClockMetricCadence, observation.ClockStatusSnapshot} {
		require.True(t, e.AddRead(observation.NativeRead{Kind: observation.ReadClock, Site: site, Time: observation.GoTimeValue{Domain: observation.GoTimeDomain, Location: 1}}))
	}
	require.True(t, e.Seal())
	require.True(t, c.CompleteEvaluation(e))
	require.True(t, c.AppendBatch(observation.Batch{EventCount: 2, Events: [observation.MaxEvents]observation.Event{{Kind: observation.Open, Session: 10}, {Kind: observation.Reserve, Session: 10, Operation: 1, Account: 9}}, Witness: observation.Witness{AccountCount: 1, Accounts: [observation.MaxWitnesses]observation.AccountWitness{{ID: 9, Score: 1}}, Session: 10}}))
	require.True(t, c.CaptureRouteResult(9, 1))
	require.True(t, c.Seal())
	require.True(t, o.PublishCaller(c))
	d, err = r.Next(context.Background())
	require.NoError(t, err)
	t.Cleanup(d.Release)
	return r, o, d
}
func TestGroupRouteCodecCompleteNestedBodiesAndRetainedLeases(t *testing.T) {
	r, _, d := routeCodecFixture(t)
	frame, err := EncodeCaller(d.Record)
	require.NoError(t, err)
	var decoded struct {
		Payload struct {
			GroupRoute struct {
				Children []map[string]json.RawMessage `json:"children"`
			} `json:"group_route"`
		} `json:"payload"`
	}
	require.NoError(t, json.Unmarshal(frame[4:], &decoded))
	children := decoded.Payload.GroupRoute.Children
	require.Len(t, children, 2)
	e := d.Record.Caller.Children()[0].Evaluation
	nested, err := EncodeEvaluation(observation.Record{Epoch: d.Record.Epoch, Sequence: 5, Native: true, Evaluation: e})
	require.NoError(t, err)
	require.Equal(t, []byte(nested[4:]), []byte(children[0]["evaluation"]), "ROUTE_COMPLETE_UNESCAPED_NATIVE_BODY")
	b := d.Record.Caller.Children()[1].Batch
	batch, err := EncodeRecord(observation.Record{Epoch: d.Record.Epoch, Sequence: 6, Native: true, Batch: b})
	require.NoError(t, err)
	require.Equal(t, []byte(batch[4:]), []byte(children[1]["batch"]), "ROUTE_COMPLETE_V2_BODY")
	require.Same(t, &d.Record.Caller.EncodingBuffer()[0], &frame[0], "ROUTE_PARENT_ARENA")
	require.Zero(t, testing.AllocsPerRun(100, func() { _, err = EncodeCaller(d.Record) }), "ROUTE_ENCODER_NO_EXTRA_ALLOCATION")
	require.NoError(t, err)
	fixture := "../../../tests/controlplane/cproute/shadow/v4-group-route.json"
	expected, err := os.ReadFile(fixture)
	require.NoError(t, err)
	require.Equal(t, expected, frame[4:], "ROUTE_SHARED_GO_RUST_FIXTURE")
	r.Close()
	count, bytes := r.Retained()
	require.EqualValues(t, 3, count)
	require.EqualValues(t, observation.CallerCharge+observation.EvaluationCharge+observation.BatchCharge, bytes, "ROUTE_ALL_LEASES_UNTIL_WRITER")
	d.Release()
	count, bytes = r.Retained()
	require.Zero(t, count)
	require.Zero(t, bytes)
}

func TestGroupRouteCodecRejectsMutatedBorrowedViews(t *testing.T) {
	for _, fault := range []string{"unused-member", "unused-read", "result-position", "text-offset", "batch-shape", "span"} {
		t.Run(fault, func(t *testing.T) {
			_, o, d := routeCodecFixture(t)
			c := d.Record.Caller
			r := c.Route()
			switch fault {
			case "unused-member":
				r.Members[63] = 99
			case "unused-read":
				r.Reads[127] = observation.RouteRead{Kind: observation.RouteHealthy, Account: 9}
			case "result-position":
				r.ResultCompleted = 1
			case "text-offset":
				r.Reads[0] = observation.RouteRead{Kind: observation.RouteBackendID, Account: 9, Text: observation.DataRef{Offset: 9999}}
			case "batch-shape":
				c.Children()[1].Batch.Events[0].Target = 9
			case "span":
				c.Children()[1].Batch.EventCount = 1
			}
			_, err := EncodeCaller(d.Record)
			require.Error(t, err, "ROUTE_BAD_BORROWED_VALUE")
			require.False(t, o.Enabled())
		})
	}
}
