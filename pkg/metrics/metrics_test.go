// Copyright 2023 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/pingcap/tiproxy/lib/util/logger"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
)

func TestStartMetricsManager(t *testing.T) {
	log, _ := logger.CreateLoggerForTest(t)
	mm := NewMetricsManager()
	mm.Init(context.Background(), log)
	mm.Close()
}

func TestDelLabelValues(t *testing.T) {
	tests := []struct {
		init     func()
		coll     prometheus.Collector
		allAddrs []string
		delAddr  string
	}{
		{
			// test LblBackend + Gauge
			init: func() {
				BackendConnGauge.WithLabelValues("addr0").Add(1)
				BackendConnGauge.WithLabelValues("addr1").Add(1)
			},
			coll:     BackendConnGauge,
			allAddrs: []string{"addr0", "addr1"},
			delAddr:  "addr0",
		},
		{
			// test LblFrom + LblTo + other labels + Histogram
			init: func() {
				MigrateDurationHistogram.WithLabelValues("addr0", "addr1", "succeed").Observe(1.0)
				MigrateDurationHistogram.WithLabelValues("addr1", "addr2", "fail").Observe(1.0)
				MigrateDurationHistogram.WithLabelValues("addr0", "addr2", "succeed").Observe(1.0)
			},
			coll:     MigrateDurationHistogram,
			allAddrs: []string{"addr0", "addr1", "addr2"},
			delAddr:  "addr1",
		},
		{
			// test LblBackend + other labels + Counter
			init: func() {
				QueryTotalCounter.WithLabelValues("addr0", "query").Add(1)
				QueryTotalCounter.WithLabelValues("addr0", "prepare").Add(1)
				QueryTotalCounter.WithLabelValues("addr1", "query").Add(1)
			},
			coll:     QueryTotalCounter,
			allAddrs: []string{"addr0", "addr1"},
			delAddr:  "addr0",
		},
	}

	getAddrs := func(coll prometheus.Collector) []string {
		results, err := Collect(coll)
		require.NoError(t, err)
		addrs := make([]string, 0, 3)
		for _, m := range results {
			for _, l := range m.Label {
				if strings.HasPrefix(*l.Value, "addr") && !slices.Contains(addrs, *l.Value) {
					addrs = append(addrs, *l.Value)
				}
			}
		}
		slices.Sort(addrs)
		return addrs
	}
	for i, test := range tests {
		test.init()
		require.Equal(t, test.allAddrs, getAddrs(test.coll), "%dth test failed", i)
		DelBackend(test.delAddr)
		newAddrs := make([]string, 0, 3)
		for _, addr := range test.allAddrs {
			if addr != test.delAddr {
				newAddrs = append(newAddrs, addr)
			}
		}
		require.Equal(t, newAddrs, getAddrs(test.coll), "%dth test failed", i)
	}
}

// The Go side of the b_conn deviation recorded as MTR-007.
//
// b_conn is a single global gauge labelled by backend address, but each
// namespace has its own router and each writes with Set. Two namespaces
// holding one connection each to the same backend therefore do not add up:
// the last writer decides and the series reports 1, not the 2 connections
// the process actually holds. Rust sums instead, and
// control-router's migration_snapshot_sums_shared_backend_address asserts
// the 2. This test pins the Go value so the declared difference is held from
// both sides rather than described only in the manifest.
func TestBackendConnGaugeOverwritesAcrossNamespaces(t *testing.T) {
	const addr = "10.0.0.7:4000"
	BackendConnGauge.Reset()
	// Namespace A publishes its one connection to this backend.
	BackendConnGauge.WithLabelValues(addr).Set(1)
	// Namespace B publishes its own one connection to the same backend.
	BackendConnGauge.WithLabelValues(addr).Set(1)

	value, err := ReadGauge(BackendConnGauge.WithLabelValues(addr))
	require.NoError(t, err)
	require.Equal(t, float64(1), value,
		"Go reports the last writer, not the process total; Rust reports 2 by design (MTR-007)")
}
