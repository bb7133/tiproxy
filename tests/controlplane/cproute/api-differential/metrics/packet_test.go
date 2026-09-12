// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"math"
	"testing"

	"github.com/prometheus/common/model"
	"github.com/stretchr/testify/require"
)

func TestDecodePreservesOriginalValuesAndRejectsPartialSet(t *testing.T) {
	stamp := int64(0)
	packet := make(map[string]*Result)
	for _, key := range Keys {
		packet[key] = nil
	}
	packet["cpu"] = &Result{Kind: "matrix", UpdatedNanos: &stamp, Series: []Series{
		{Labels: map[string]string{"instance": "a"}, Samples: []Sample{{3, "-0"}, {2, "NaN"}, {1, "+Inf"}, {0, "-Inf"}}},
		{Labels: map[string]string{"instance": "a", "duplicate": "second"}},
	}}
	decoded, err := Decode(packet)
	require.NoError(t, err)
	require.False(t, decoded["cpu"].UpdateTime.IsZero(), "epoch zero is not Go zero time")
	values := decoded["cpu"].Value.(model.Matrix)
	require.True(t, math.Signbit(float64(values[0].Values[0].Value)))
	require.True(t, math.IsNaN(float64(values[0].Values[1].Value)))
	require.True(t, math.IsInf(float64(values[0].Values[2].Value), 1))
	require.True(t, math.IsInf(float64(values[0].Values[3].Value), -1))
	require.Equal(t, model.Time(2), values[0].Values[1].Timestamp)
	require.Equal(t, model.LabelValue("second"), values[1].Metric["duplicate"])
	packet["cpu"].Series[0].Labels["instance"] = "mutated"
	packet["cpu"].Series[0].Samples[0].Value = "1"
	require.Equal(t, model.LabelValue("a"), values[0].Metric["instance"])
	require.True(t, math.Signbit(float64(values[0].Values[0].Value)))
	packet["cpu"].UpdatedNanos = nil
	zero, err := Decode(packet)
	require.NoError(t, err)
	require.True(t, zero["cpu"].UpdateTime.IsZero())
	for _, bad := range []string{"1e999", "Infinity", "nan", "0x1p1", "garbage"} {
		packet["cpu"].Series[0].Samples[0].Value = bad
		next, err := Decode(packet)
		require.Error(t, err)
		require.Nil(t, next)
	}
	packet["cpu"] = nil
	next, err := Decode(packet)
	require.NoError(t, err)
	require.True(t, next["cpu"].Empty(), "null replaces, it cannot retain previous query data")
	delete(packet, "total_pd")
	next, err = Decode(packet)
	require.Error(t, err)
	require.Nil(t, next)
}
