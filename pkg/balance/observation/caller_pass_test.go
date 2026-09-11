// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package observation

import (
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"
)

func TestPassCaptureCopiesOrderAndKeepsParentCharge(t *testing.T) {
	r, o := callerOwner(t, DefaultLimits())
	groups := []uint64{9, 3}
	c := o.BeginCaller()
	defer c.Cleanup()
	require.True(t, c.CapturePassBegin(1, false, groups))
	groups[0] = 99
	require.True(t, c.Seal())
	require.Equal(t, []uint64{9, 3}, c.Pass().Groups[:2], "PASS_INPUT_COPIED_IN_ORDER")
	require.Empty(t, c.Bytes())
	require.True(t, o.PublishCaller(c))
	require.EqualValues(t, 2, o.AdmittedSequence())
	d := receive(t, r)
	c.Cleanup()
	r.Close()
	count, bytes := r.Retained()
	require.EqualValues(t, 1, count)
	require.EqualValues(t, CallerCharge, bytes, "PASS_PARENT_WRITER_CHARGE")
	d.Release()
	require.Nil(t, c.Pass())
	count, bytes = r.Retained()
	require.Zero(t, count)
	require.Zero(t, bytes)
	require.LessOrEqual(t, unsafe.Sizeof(callerStorage{})+unsafe.Sizeof(Caller{}), uintptr(CallerCharge), "PASS_LAYOUT_IN_PARENT_CHARGE")
	t.Logf("pass=%d caller=%d storage=%d charge=%d", unsafe.Sizeof(RouterPass{}), unsafe.Sizeof(Caller{}), unsafe.Sizeof(callerStorage{}), CallerCharge)
}

func TestPassCaptureBoundariesAndNoMixedPayload(t *testing.T) {
	for _, failure := range []string{"zero", "duplicate", "groups+1", "zero-id", "counts+1", "opaque-before", "opaque-after", "child-before", "child-after", "batch-before", "batch-after", "duplicate-payload"} {
		t.Run(failure, func(t *testing.T) {
			_, o := callerOwner(t, DefaultLimits())
			c := o.BeginCaller()
			defer c.Cleanup()
			switch failure {
			case "zero":
				require.False(t, c.CapturePassBegin(1, true, []uint64{0}))
			case "duplicate":
				require.False(t, c.CapturePassBegin(1, true, []uint64{1, 1}))
			case "groups+1":
				require.False(t, c.CapturePassBegin(1, true, make([]uint64, 65)))
			case "zero-id":
				require.False(t, c.CapturePassBegin(0, true, nil))
			case "counts+1":
				require.False(t, c.CapturePassEnd(1, 0, 65))
			case "opaque-before":
				require.True(t, c.Append([]byte("x")))
				require.False(t, c.CapturePassEnd(1, 0, 0))
			case "child-before":
				require.NotNil(t, c.BeginEvaluation())
				require.False(t, c.CapturePassEnd(1, 0, 0))
			case "batch-before":
				require.True(t, c.AppendBatch(watermark()))
				require.False(t, c.CapturePassEnd(1, 0, 0))
			default:
				require.True(t, c.CapturePassBegin(1, true, nil))
				switch failure {
				case "opaque-after":
					require.False(t, c.Append([]byte("x")))
				case "child-after":
					require.Nil(t, c.BeginEvaluation())
				case "batch-after":
					require.False(t, c.AppendBatch(watermark()))
				case "duplicate-payload":
					require.False(t, c.CapturePassEnd(1, 0, 0))
				}
			}
			require.False(t, o.Enabled(), "PASS_BAD_INPUT_INVALIDATES")
			require.False(t, c.Seal())
			require.EqualValues(t, 1, o.AdmittedSequence(), "PASS_NO_PARTIAL_SEQUENCE")
		})
	}
	for _, isBegin := range []bool{true, false} {
		_, o := callerOwner(t, DefaultLimits())
		c := o.BeginCaller()
		defer c.Cleanup()
		if isBegin {
			groups := make([]uint64, 64)
			for i := range groups {
				groups[i] = uint64(i + 1)
			}
			require.True(t, c.CapturePassBegin(1, true, groups), "PASS_GROUP_EQUAL")
		} else {
			require.True(t, c.CapturePassEnd(1, 64, 64), "PASS_COUNT_EQUAL")
		}
		require.True(t, c.Seal())
	}
}
