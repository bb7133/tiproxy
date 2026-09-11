// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package observation

import (
	"strings"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"
)

func TestGroupRouteCopiedReadsCompletionAndCharge(t *testing.T) {
	r, o := callerOwner(t, DefaultLimits())
	c := o.BeginCaller()
	defer c.Cleanup()
	members := []uint64{9, 3}
	require.True(t, c.CaptureGroupRoute(1, 2, 10, 1, members))
	members[0] = 99
	require.True(t, c.CaptureRouteHealthy(9, true))
	text := []byte("backend")
	require.True(t, c.CaptureRouteBackendID(9, string(text)))
	text[0] = 'x'
	require.True(t, c.CaptureRouteExcludedID(0, "other"))
	require.True(t, c.AppendBatch(watermark()))
	require.True(t, c.CaptureRouteHealthy(3, false))
	require.True(t, c.CaptureRouteResult(0, 0))
	require.True(t, c.Seal())
	v := c.Route()
	require.Equal(t, []uint64{9, 3}, v.Members[:2], "ROUTE_COPIED_MEMBERS")
	require.Equal(t, "backend", string(c.Range(v.Reads[1].Text)), "ROUTE_COPIED_TEXT")
	require.EqualValues(t, 0, v.Reads[0].Completed)
	require.EqualValues(t, 1, v.Reads[3].Completed, "ROUTE_READ_COMPLETION_POSITION")
	require.EqualValues(t, 1, v.ResultCompleted, "ROUTE_RESULT_COMPLETION_POSITION")
	require.True(t, o.PublishCaller(c))
	d := receive(t, r)
	c.Cleanup()
	r.Close()
	n, bytes := r.Retained()
	require.EqualValues(t, 2, n)
	require.EqualValues(t, CallerCharge+BatchCharge, bytes, "ROUTE_CHILD_CHARGE_RETAINED")
	d.Release()
	require.Nil(t, c.Route())
	n, bytes = r.Retained()
	require.Zero(t, n)
	require.Zero(t, bytes)
	require.LessOrEqual(t, unsafe.Sizeof(callerStorage{})+unsafe.Sizeof(Caller{}), uintptr(CallerCharge), "ROUTE_LAYOUT_IN_PARENT_CHARGE")
	t.Logf("route=%d read=%d storage=%d caller=%d", unsafe.Sizeof(GroupRoute{}), unsafe.Sizeof(RouteRead{}), unsafe.Sizeof(callerStorage{}), unsafe.Sizeof(Caller{}))
}
func TestGroupRouteInputBoundsAndFinalImmutability(t *testing.T) {
	for _, fault := range []string{"members+1", "duplicate", "zero", "excluded+1", "read+1", "string+1", "utf8", "pass-before", "pass-after", "opaque", "unfinalized", "read-after", "child-after", "batch-after", "result-after", "partial-result"} {
		t.Run(fault, func(t *testing.T) {
			_, o := callerOwner(t, DefaultLimits())
			c := o.BeginCaller()
			defer c.Cleanup()
			switch fault {
			case "members+1":
				require.False(t, c.CaptureGroupRoute(1, 2, 10, 0, make([]uint64, 65)))
			case "duplicate":
				require.False(t, c.CaptureGroupRoute(1, 2, 10, 0, []uint64{9, 9}))
			case "zero":
				require.False(t, c.CaptureGroupRoute(1, 0, 10, 0, nil))
			case "excluded+1":
				require.False(t, c.CaptureGroupRoute(1, 2, 10, 65, nil))
			case "pass-before":
				require.True(t, c.CapturePassEnd(1, 0, 0))
				require.False(t, c.CaptureGroupRoute(1, 2, 10, 0, nil))
			default:
				require.True(t, c.CaptureGroupRoute(1, 2, 10, 1, []uint64{9}))
				switch fault {
				case "read+1":
					for range MaxCallerReads {
						require.True(t, c.CaptureRouteHealthy(9, true))
					}
					require.False(t, c.CaptureRouteHealthy(9, true))
				case "string+1":
					require.False(t, c.CaptureRouteBackendID(9, strings.Repeat("x", 513)))
				case "utf8":
					require.False(t, c.CaptureRouteBackendID(9, string([]byte{255})))
				case "pass-after":
					require.False(t, c.CapturePassEnd(1, 0, 0))
				case "opaque":
					require.False(t, c.Append([]byte("x")))
				case "unfinalized":
					require.False(t, c.Seal())
				case "partial-result":
					require.False(t, c.CaptureRouteResult(9, 0))
				default:
					require.True(t, c.CaptureRouteResult(9, 1))
					switch fault {
					case "read-after":
						require.False(t, c.CaptureRouteHealthy(9, true))
					case "child-after":
						require.Nil(t, c.BeginEvaluation())
					case "batch-after":
						require.False(t, c.AppendBatch(watermark()))
					case "result-after":
						require.False(t, c.CaptureRouteResult(9, 1))
					}
				}
			}
			require.False(t, o.Enabled(), "ROUTE_BAD_INPUT_INVALIDATES")
			require.EqualValues(t, 1, o.AdmittedSequence())
		})
	}
	_, o := callerOwner(t, DefaultLimits())
	c := o.BeginCaller()
	defer c.Cleanup()
	members := make([]uint64, 64)
	for i := range members {
		members[i] = uint64(i + 1)
	}
	require.True(t, c.CaptureGroupRoute(1, 2, 10, 64, members))
	for range 128 {
		require.True(t, c.CaptureRouteBackendID(9, strings.Repeat("x", 512)), "ROUTE_READ_STRING_EQUAL")
	}
	require.True(t, c.CaptureRouteResult(0, 0))
	require.True(t, c.Seal())
	require.EqualValues(t, 65536, c.Route().StringBytes, "ROUTE_TOTAL_STRING_EQUAL")
}

func TestGroupRouteIncrementalMembers(t *testing.T) {
	for _, mode := range []string{"bound", "duplicate", "zero", "evaluation", "batch", "result"} {
		t.Run(mode, func(t *testing.T) {
			_, o := callerOwner(t, DefaultLimits())
			c := o.BeginCaller()
			defer c.Cleanup()
			require.True(t, c.CaptureGroupRoute(1, 2, 3, 0, nil))
			require.True(t, c.CaptureRouteMember(9))
			require.True(t, c.CaptureRouteHealthy(9, true))
			switch mode {
			case "bound":
				for i := 1; i < MaxCallerGroups; i++ {
					require.True(t, c.CaptureRouteMember(uint64(i+10)), "ROUTE_MEMBER_BOUND_EQUAL")
				}
				require.False(t, c.CaptureRouteMember(100), "ROUTE_MEMBER_BOUND_PLUS_ONE")
			case "duplicate":
				require.False(t, c.CaptureRouteMember(9), "ROUTE_MEMBER_UNIQUE")
			case "zero":
				require.False(t, c.CaptureRouteMember(0), "ROUTE_MEMBER_NONZERO")
			case "evaluation":
				require.NotNil(t, c.BeginEvaluation())
				require.False(t, c.CaptureRouteMember(10), "ROUTE_MEMBER_BEFORE_CHILD_ALLOCATION")
			case "batch":
				require.True(t, c.AppendBatch(watermark()))
				require.False(t, c.CaptureRouteMember(10), "ROUTE_MEMBER_BEFORE_BATCH")
			case "result":
				require.True(t, c.CaptureRouteResult(0, 0))
				require.False(t, c.CaptureRouteMember(10), "ROUTE_MEMBER_BEFORE_RESULT")
			}
			require.False(t, o.Enabled())
		})
	}
}
