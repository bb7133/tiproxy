// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package observation

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func nativeArena(t *testing.T) (*Owner, *Evaluation) {
	t.Helper()
	r := recorderForTest(t, DefaultLimits())
	o := r.NewOwner()
	receive(t, r).Release()
	e := o.BeginEvaluation()
	t.Cleanup(e.Release)
	return o, e
}

func TestNativeReadSampleAndStringBounds(t *testing.T) {
	t.Run("clocks", func(t *testing.T) {
		o, e := nativeArena(t)
		for i := 0; i < 64; i++ {
			require.True(t, e.AddRead(NativeRead{Kind: ReadClock, Site: ClockCPUExpiry}))
		}
		require.EqualValues(t, 63, e.Native().Reads[63].Ordinal, "NATIVE_CLOCK_OCCURRENCES")
		require.True(t, o.Enabled(), "NATIVE_CLOCK_EQUAL")
		require.False(t, e.AddRead(NativeRead{Kind: ReadClock, Site: ClockCPUExpiry}), "NATIVE_CLOCK_PLUS_ONE")
		require.EqualValues(t, 64, e.Native().ReadCount)
	})
	t.Run("items", func(t *testing.T) {
		o, e := nativeArena(t)
		for i := 0; i < 128; i++ {
			require.True(t, e.AddRead(NativeRead{Kind: ReadQuery, Query: QueryCPU}))
		}
		require.True(t, o.Enabled(), "NATIVE_READ_EQUAL")
		require.False(t, e.AddRead(NativeRead{Kind: ReadQuery, Query: QueryCPU}), "NATIVE_READ_PLUS_ONE")
		require.EqualValues(t, 128, e.Native().ReadCount)
	})
	t.Run("samples", func(t *testing.T) {
		o, e := nativeArena(t)
		require.True(t, e.AddSamples(MaxEvaluationSamples), "NATIVE_SAMPLES_EQUAL")
		require.True(t, o.Enabled())
		require.False(t, e.AddSamples(1), "NATIVE_SAMPLES_PLUS_ONE")
		require.EqualValues(t, 4096, e.Native().SampleCount)
	})
	t.Run("string", func(t *testing.T) {
		o, e := nativeArena(t)
		ref := e.CopyText(strings.Repeat("x", 512))
		require.Len(t, e.Range(ref), 512, "NATIVE_STRING_EQUAL")
		e.CopyText(strings.Repeat("x", 513))
		require.False(t, o.Enabled(), "NATIVE_STRING_PLUS_ONE")
		require.EqualValues(t, 512, e.Native().StringBytes)
	})
	t.Run("total_strings", func(t *testing.T) {
		o, e := nativeArena(t)
		for i := 0; i < 128; i++ {
			e.CopyText(strings.Repeat("x", 512))
		}
		require.True(t, o.Enabled(), "NATIVE_STRINGS_EQUAL")
		e.CopyText("x")
		require.False(t, o.Enabled(), "NATIVE_STRINGS_PLUS_ONE")
		require.EqualValues(t, 64<<10, e.Native().StringBytes)
	})
}

func TestNativeStringEscapingAndArenaReuse(t *testing.T) {
	o, e := nativeArena(t)
	value := "\x00\n\t\r\\\"中文🙂"
	require.True(t, e.JSONText(value))
	var decoded string
	require.NoError(t, json.Unmarshal(e.Range(DataRef{Length: e.Position()}), &decoded))
	require.Equal(t, value, decoded, "NATIVE_ESCAPING_EXACT")
	e.Native().Backends[0].Account = 99
	e.Native().ReadCount = 1
	require.True(t, e.Seal())
	require.True(t, o.PublishEvaluation(e))
	d := receive(t, o.recorder)
	d.Release()
	next := o.BeginEvaluation()
	defer next.Release()
	require.Zero(t, next.Native().ReadCount, "NATIVE_POOL_NO_OLD_READS")
	require.Zero(t, next.Native().Backends[0].Account, "NATIVE_POOL_NO_OLD_ACCOUNT")
	require.EqualValues(t, -1, next.Native().From)
}

func TestNativeClockFailureFencesInstallation(t *testing.T) {
	r := recorderForTest(t, DefaultLimits())
	// Simulate an unsupported startup projection; v2 does not use that domain.
	r.clockInvalid = true
	r.origin = nil
	legacy := r.NewOwner()
	require.True(t, legacy.Enabled(), "NATIVE_CLOCK_FAILURE_V2_UNCHANGED")
	receive(t, r).Release()
	native := r.NewNativeOwner()
	require.False(t, native.Enabled(), "NATIVE_CLOCK_FAILURE_INSTALLATION")
	require.False(t, legacy.Enabled(), "NATIVE_CLOCK_FAILURE_WHOLE_PROCESS")
	require.False(t, r.NewOwner().Enabled(), "NATIVE_CLOCK_FAILURE_STICKY_PROCESS")
}
