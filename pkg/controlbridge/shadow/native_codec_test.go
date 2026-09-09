// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package shadow

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"testing"
	"time"

	"github.com/pingcap/tiproxy/pkg/balance/observation"
	"github.com/stretchr/testify/require"
)

func nativeCodecFixture(t *testing.T) (*observation.Recorder, *observation.Owner, *observation.Delivery) {
	t.Helper()
	r, err := observation.NewRecorder(observation.DefaultLimits(), 1, 2)
	require.NoError(t, err)
	t.Cleanup(r.Close)
	o := r.NewNativeOwner()
	begin, err := r.Next(context.Background())
	require.NoError(t, err)
	begin.Release()
	e := o.BeginEvaluation()
	n := e.Native()
	n.Group, n.Policy, n.Config, n.ID = 3, 4, 5, 1
	n.Entry = observation.EntryRouteable
	n.Configuration.BalancePolicy = e.CopyText("connection")
	n.Configuration.RoutingPolicy = e.CopyText("idlest")
	n.BackendCount = 1
	n.Backends[0] = observation.NativeBackend{Account: 6, Seen: observation.BackendConnScore, ConnScore: 17, Packed: 17, Routeable: true, RouteabilitySeen: true}
	n.Backends[0].Parts[0] = 17
	n.FactorCount = 1
	n.Factors[0] = observation.FactorConnection
	n.Widths[0] = 16
	n.SortedCount, n.ReturnedCount = 1, 1
	clock, ok := o.TimeProjection().Project(time.Now())
	require.True(t, ok)
	require.True(t, e.AddRead(observation.NativeRead{Kind: observation.ReadClock, Site: observation.ClockMetricCadence, Time: clock}))
	require.True(t, e.Seal())
	require.True(t, o.PublishEvaluation(e))
	d, err := r.Next(context.Background())
	require.NoError(t, err)
	t.Cleanup(d.Release)
	return r, o, d
}

func TestNativeCodecBorrowsChargedWriterArena(t *testing.T) {
	r, _, d := nativeCodecFixture(t)
	frame, err := EncodeEvaluation(d.Record)
	require.NoError(t, err)
	require.Equal(t, len(frame)-4, int(binary.BigEndian.Uint32(frame)))
	var decoded map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(frame[4:], &decoded), "NATIVE_FRAME_JSON")
	require.JSONEq(t, `3`, string(decoded["version"]))
	require.JSONEq(t, `"2"`, string(decoded["sequence"]))
	require.Contains(t, string(decoded["reads"]), `"site":"metric_cadence"`)
	require.Same(t, &d.Record.Evaluation.EncodingBuffer()[0], &frame[0], "NATIVE_WRITER_USES_LEASE")
	_, err = EncodeRecord(d.Record)
	require.Error(t, err, "NATIVE_NOT_V2_BATCH")
	r.Close()
	records, bytes := r.Retained()
	require.EqualValues(t, 1, records)
	require.EqualValues(t, observation.EvaluationCharge, bytes, "NATIVE_ENCODING_KEEPS_CHARGE")
	d.Release()
	records, bytes = r.Retained()
	require.Zero(t, records)
	require.Zero(t, bytes)
}

func TestNativeEncodedBodyEqualityAndPlusOne(t *testing.T) {
	_, _, d := nativeCodecFixture(t)
	w := nativeEncoder{buffer: d.Record.Evaluation.EncodingBuffer(), used: 4, evaluation: d.Record.Evaluation}
	w.raw(make([]byte, observation.MaxEvaluationBodyBytes))
	require.False(t, w.failed, "NATIVE_ENCODED_BODY_EQUAL")
	require.Equal(t, observation.MaxEvaluationBodyBytes+4, w.used)
	w.literal("x")
	require.True(t, w.failed, "NATIVE_ENCODED_BODY_PLUS_ONE")
	require.Equal(t, observation.MaxEvaluationBodyBytes+4, w.used, "NATIVE_ENCODE_NO_PARTIAL_APPEND")
}
