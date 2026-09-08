// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package observation

import (
	"go/ast"
	"go/parser"
	"go/token"
	"math"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"

	"github.com/stretchr/testify/require"
)

func TestTimeProjectionHotPath(t *testing.T) {
	_, testFile, _, ok := runtime.Caller(0)
	require.True(t, ok)
	source, err := parser.ParseFile(token.NewFileSet(), filepath.Join(filepath.Dir(testFile), "time.go"), nil, 0)
	require.NoError(t, err)
	functions := map[string]*ast.FuncDecl{}
	for _, declaration := range source.Decls {
		if function, ok := declaration.(*ast.FuncDecl); ok {
			functions[function.Name.Name] = function
		}
	}
	visited := map[string]bool{}
	var inspect func(string)
	inspect = func(name string) {
		function := functions[name]
		if function == nil || visited[name] {
			return
		}
		visited[name] = true
		ast.Inspect(function.Body, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			switch callee := call.Fun.(type) {
			case *ast.Ident:
				inspect(callee.Name)
			case *ast.SelectorExpr:
				switch callee.Sel.Name {
				case "Now", "Since", "Until", "String", "Format", "AppendFormat":
					t.Errorf("TIME_PROJECTION_HOT_PATH: forbidden %s in %s", callee.Sel.Name, name)
				}
				inspect(callee.Sel.Name)
			}
			return true
		})
	}
	inspect("Project")
	require.True(t, visited["Project"])
	require.True(t, visited["hasMonotonic"])
}

func testTimeProjection(t *testing.T, captured time.Time) (*TimeProjection, *Recorder) {
	t.Helper()
	r, err := NewRecorder(DefaultLimits(), 11, 13)
	require.NoError(t, err)
	origin, err := CaptureClockOrigin(captured, captured.Add(time.Nanosecond))
	require.NoError(t, err)
	return NewTimeProjection(r.NewOwner(), origin), r
}

func TestTimeProjectionRawIdentity(t *testing.T) {
	now := time.Now()
	p, _ := testTimeProjection(t, now)
	zone1, zone2 := time.FixedZone("same", 0), time.FixedZone("same", 0)
	values := []time.Time{now, now.Add(time.Second), now.Round(0), now.UTC(),
		now.In(zone1), now.In(zone2), {}, time.Date(9999, 1, 1, 0, 0, 0, 7, time.UTC)}
	for _, a := range values {
		av, ok := p.Project(a)
		require.True(t, ok)
		require.Equal(t, GoTimeDomain, av.Domain)
		for _, b := range values {
			bv, ok := p.Project(b)
			require.True(t, ok)
			require.Equal(t, a == b, av == bv, "TIME_RAW_LOCATION_IDENTITY")
		}
		if av.HasMonotonic {
			absolute, ok := monotonicSuffix(a.String())
			require.True(t, ok)
			require.Equal(t, absolute, p.origin.Value().MonotonicBase+av.Monotonic, "TIME_ORIGIN_EXACT")
		} else {
			require.Zero(t, av.Monotonic)
		}
	}
	a, ok := p.Project(now.In(zone1))
	require.True(t, ok)
	b, ok := p.Project(now.In(zone2))
	require.True(t, ok)
	require.NotEqual(t, a.Location, b.Location, "TIME_RAW_LOCATION_IDENTITY")
	require.Equal(t, a.Seconds, b.Seconds)
	require.Equal(t, a.Nanoseconds, b.Nanoseconds)
	zero, ok := p.Project(time.Time{})
	require.True(t, ok)
	require.Zero(t, zero.Seconds)
	require.Zero(t, zero.Nanoseconds)

	// UnixNano cannot represent this instant; the split representation can.
	far := time.Date(9999, 1, 1, 0, 0, 0, 7, time.UTC)
	v, ok := p.Project(far)
	require.True(t, ok)
	require.True(t, time.Unix(v.Seconds-unixToInternalSeconds, int64(v.Nanoseconds)).Equal(far))
}

func TestTimeLocationCapacityAndExhaustion(t *testing.T) {
	p, r := testTimeProjection(t, time.Now())
	// The dictionary has no backing map or unbounded retained location list.
	require.EqualValues(t, MaxTimeLocations*16, unsafe.Sizeof(p.locations))
	for i := range MaxTimeLocations {
		value, ok := p.Project(time.Unix(int64(i), 0).In(time.FixedZone("same", 0)))
		require.True(t, ok, "TIME_LOCATION_CAP_EQUAL")
		require.NotZero(t, value.Location)
	}
	require.Equal(t, MaxTimeLocations, p.count)
	require.True(t, p.owner.Enabled(), "TIME_LOCATION_CAP_EQUAL")
	_, ok := p.Project(time.Unix(0, 0).In(time.FixedZone("same", 0)))
	require.False(t, ok, "TIME_LOCATION_CAP_PLUS_ONE")
	require.False(t, p.owner.Enabled(), "TIME_LOCATION_STICKY_INVALID")
	require.Len(t, r.InvalidOwners(), 1, "TIME_LOCATION_STICKY_INVALID")
	require.Equal(t, Capacity, r.InvalidOwners()[0].Reason)
	_, ok = p.Project(time.Unix(0, 0).In(p.locations[0].location))
	require.False(t, ok, "TIME_LOCATION_STICKY_INVALID")

	p, r = testTimeProjection(t, time.Now())
	p.owner.identity = math.MaxUint64
	_, ok = p.Project(time.Now())
	require.False(t, ok, "TIME_LOCATION_ID_EXHAUSTION")
	require.Equal(t, SequenceExhausted, r.InvalidOwners()[0].Reason)
}

func TestTimeProjectionConcurrentLocation(t *testing.T) {
	now := time.Now()
	p, _ := testTimeProjection(t, now)
	var wg sync.WaitGroup
	values := make(chan GoTimeValue, 32)
	for range 32 {
		wg.Go(func() {
			v, _ := p.Project(now)
			values <- v
		})
	}
	wg.Wait()
	close(values)
	var first GoTimeValue
	for value := range values {
		require.NotZero(t, value.Location)
		if first.Location == 0 {
			first = value
		}
		require.Equal(t, first, value)
	}
	require.Equal(t, 1, p.count)
}

func TestClockOriginSuffixAndDomains(t *testing.T) {
	for _, row := range []struct {
		input string
		value int64
	}{
		{"t m=+0.000000000", 0},
		{"t m=+1.000000003", 1_000_000_003},
		{"t m=-1.000000003", -1_000_000_003},
		{"t m=+9223372036.854775807", math.MaxInt64},
		{"t m=-9223372036.854775808", math.MinInt64},
	} {
		actual, ok := monotonicSuffix(row.input)
		require.True(t, ok)
		require.Equal(t, row.value, actual, "TIME_ORIGIN_EXACT")
	}
	for _, input := range []string{"t", "t m=0.000000000", "t m=+1.1", "t m=+.000000000",
		"t m=+1.00000000x", "t m=+1.000000000 extra", "t m=+9223372036.854775808",
		"t m=-9223372036.854775809", "t m=+18446744073709551615.000000000"} {
		_, ok := monotonicSuffix(input)
		require.False(t, ok, "TIME_ORIGIN_REJECT_MALFORMED: %s", input)
	}
	origin, err := CaptureClockOrigin(time.Time{}, time.Time{})
	require.NoError(t, err)
	require.False(t, origin.Value().HasMonotonic)
	require.Zero(t, origin.Value().MonotonicBase)

	// Wall-only times need no suffix or zone formatting, even with a large name.
	_, err = CaptureClockOrigin(time.Unix(0, 0).In(time.FixedZone(strings.Repeat("x", 1024), 0)), time.Unix(0, 0))
	require.NoError(t, err)
	for _, value := range []int64{0, math.MinInt64, math.MaxInt64} {
		projected := ProjectSampleTime(value)
		require.Equal(t, SampleTimeDomain, projected.Domain, "TIME_SAMPLE_DOMAIN")
		require.Equal(t, value, projected.Milliseconds)
	}
}

func TestTimeProjectionMissingOriginMonotonic(t *testing.T) {
	now := time.Now()
	p, r := testTimeProjection(t, now.Round(0))
	_, ok := p.Project(now)
	require.False(t, ok, "TIME_ORIGIN_DOMAIN_MISMATCH")
	require.Equal(t, Malformed, r.InvalidOwners()[0].Reason)
	var disabled *TimeProjection
	_, ok = disabled.Project(now)
	require.False(t, ok)
}

func TestClockOriginSelfCheck(t *testing.T) {
	now := time.Now()
	verified, err := CaptureClockOrigin(now, time.Now())
	require.NoError(t, err)
	require.True(t, verified.Value().BaselinePresent, "TIME_ORIGIN_BASELINE_PRESENT")
	require.Equal(t, SupportedClockToolchain, verified.Value().GoVersion)
	_, err = captureClockOrigin(now, now, "go1.26.0")
	require.Error(t, err, "TIME_ORIGIN_VERSION_REJECT")
	_, err = CaptureClockOrigin(now, now.Round(0))
	require.Error(t, err, "TIME_ORIGIN_SELF_CHECK_DOMAIN")
	require.True(t, originConsistent(101, 104, 3))
	require.False(t, originConsistent(101, 104, 2), "TIME_ORIGIN_SELF_CHECK_EXACT")
	require.False(t, originConsistent(math.MinInt64, math.MaxInt64, -1), "TIME_ORIGIN_SELF_CHECK_OVERFLOW")
	require.False(t, originConsistent(0, math.MaxInt64, math.MaxInt64), "TIME_ORIGIN_SELF_CHECK_SATURATION")
}
