// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package observation

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSelectorBoundarySharesCallerLease(t *testing.T) {
	for _, mixed := range []bool{false, true} {
		t.Run(map[bool]string{false: "delivery", true: "mixed-rejected"}[mixed], func(t *testing.T) {
			r, o := callerOwner(t, DefaultLimits())
			c := o.BeginCaller()
			require.NotNil(t, c)
			value := SelectorBoundary{Kind: SelectorEnd, Session: 10, Next: 1, Current: 9, Backend: 9, Error: SelectorNoError, ExcludedCount: 2}
			value.Excluded[0], value.Excluded[1] = 9, 9
			require.True(t, c.CaptureSelector(&value))
			value.Excluded[0] = 99 // Later source mutation cannot alter the captured slice.
			if mixed {
				require.False(t, c.AppendBatch(Batch{EventCount: 1}), "SELECTOR_NO_ESCAPED_CHILD")
				c.Cleanup()
			} else {
				require.True(t, c.Seal())
				require.Equal(t, uint64(9), c.Selector().Excluded[0])
				require.True(t, o.PublishCaller(c))
				c.Cleanup()
				d := receive(t, r)
				require.Equal(t, uint64(1), d.Record.Caller.Span())
				count, bytes := r.Retained()
				require.EqualValues(t, 1, count)
				require.EqualValues(t, CallerCharge, bytes, "SELECTOR_FULL_PARENT_RETAINED")
				d.Release()
			}
			count, bytes := r.Retained()
			require.Zero(t, count)
			require.Zero(t, bytes, "SELECTOR_RELEASE_EXACTLY_ONCE")
		})
	}
}

func TestFinishParentRetainsCompleteCreated(t *testing.T) {
	r, o := callerOwner(t, DefaultLimits())
	c := o.BeginCaller()
	require.NotNil(t, c)
	require.True(t, c.CaptureGroupFinish(1, 2, 10, 9, 3, false))
	batch := Batch{EventCount: 1, Events: [MaxEvents]Event{{Kind: Created, Session: 10, Operation: 3}}}
	require.True(t, c.AppendBatch(batch))
	batch.Events[0].Operation = 99
	require.True(t, c.CaptureFinishResult())
	require.True(t, c.Seal())
	require.True(t, o.PublishCaller(c))
	c.Cleanup()
	d := receive(t, r)
	require.EqualValues(t, 2, d.Record.Caller.Span())
	require.EqualValues(t, 3, d.Record.Caller.Finish().Operation)
	require.EqualValues(t, 3, d.Record.Caller.Children()[0].Batch.Events[0].Operation)
	records, bytes := r.Retained()
	require.EqualValues(t, 2, records)
	require.EqualValues(t, CallerCharge+BatchCharge, bytes, "FINISH_PARENT_CHILD_RETAINED")
	d.Release()
	records, bytes = r.Retained()
	require.Zero(t, records)
	require.Zero(t, bytes, "FINISH_PARENT_CHILD_RELEASE_ONCE")
}
