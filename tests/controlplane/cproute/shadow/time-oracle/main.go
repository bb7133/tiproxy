// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

// Command time-oracle emits captured operands and results of actual Go time
// operations for the independent Rust arithmetic tests. It uses no unsafe
// manipulation of time.Time and does not modify any production clock.
package main

import (
	"flag"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/pingcap/tiproxy/pkg/balance/observation"
	"github.com/prometheus/common/model"
)

func must[T any](value T, err error) T {
	if err != nil {
		panic(err)
	}
	return value
}

func main() {
	zoneBytes := flag.Int("origin-zone-bytes", 0, "set a bounded-origin fixture zone in this process")
	flag.Parse()
	if *zoneBytes < 0 || *zoneBytes > 1024 {
		panic("invalid fixture zone size")
	}
	if *zoneBytes > 0 {
		time.Local = time.FixedZone(strings.Repeat("x", *zoneBytes), 0)
	}
	now := time.Now()
	origin := must(observation.CaptureClockOrigin(now, time.Now()))
	recorder := must(observation.NewRecorder(observation.DefaultLimits(), 17, 19))
	projection := observation.NewTimeProjection(recorder.NewOwner(), origin)
	v := origin.Value()
	fmt.Printf("origin\t%s\t%t\t%d\n", v.GoVersion, v.BaselinePresent, v.MonotonicBase)
	fields := func(t time.Time) string {
		v, ok := projection.Project(t)
		if !ok {
			panic("time projection failed")
		}
		return fmt.Sprintf("%d,%d,%d,%t,%d", v.Seconds, v.Nanoseconds, v.Location, v.HasMonotonic, v.Monotonic)
	}
	zone1, zone2 := time.FixedZone("same", 0), time.FixedZone("same", 0)
	wallLimit := time.Unix(59_453_308_800+(1<<33)-1-62_135_596_800, 900_000_000)
	packedMono := now.Add(wallLimit.Sub(now))
	for _, row := range []struct {
		name string
		a, b time.Time
		add  time.Duration
	}{
		{"mono", now.Add(3 * time.Second), now, -5 * time.Second},
		{"mono-negative", now, now.Add(3 * time.Second), time.Second},
		{"mixed", now.Add(3 * time.Second), now.Round(0), -time.Nanosecond},
		{"raw-mono", now, now.Round(0), 0},
		{"raw-location", now.In(zone1), now.In(zone2), time.Nanosecond},
		{"wall-carry", time.Unix(0, 999_999_999), time.Unix(0, 0), 2},
		{"wall-borrow", time.Unix(0, 0), time.Unix(0, 1), -2},
		{"wall-positive-saturation", time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC), time.Time{}, time.Duration(math.MaxInt64)},
		{"wall-negative-saturation", time.Time{}, time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC), time.Duration(math.MinInt64)},
		{"packed-wall-strip", packedMono, now, 200 * time.Millisecond},
		{"large-add-strip", now, now, time.Duration(math.MaxInt64)},
		{"zero", time.Time{}, time.Time{}, 0},
	} {
		fmt.Printf("go\t%s\t%s\t%s\t%d\t%s\t%d\t%t\t%t\t%t\t%t\n",
			row.name, fields(row.a), fields(row.b), row.add, fields(row.a.Add(row.add)),
			row.a.Sub(row.b), row.a.Before(row.b), row.a.After(row.b), row.a.Equal(row.b), row.a == row.b)
	}
	for _, row := range []struct {
		name string
		a, b int64
	}{
		{"ordinary", 30000, 10000},
		{"negative", -1, 0},
		{"sample-sub-wrap", math.MaxInt64, -1},
		{"sample-mul-wrap", math.MaxInt64/1_000_000 + 1, 0},
		{"sample-min", math.MinInt64, math.MaxInt64},
	} {
		a, b := model.Time(row.a), model.Time(row.b)
		fmt.Printf("sample\t%s\t%d\t%d\t%d\t%d\t%s\n", row.name, row.a, row.b, a.Sub(b), a.Time().Sub(b.Time()), fields(a.Time()))
	}
}
