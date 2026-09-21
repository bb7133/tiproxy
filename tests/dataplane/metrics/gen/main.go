// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

// Command gen renders the Go promhttp text exposition that the Rust native
// exposition must match (tests/dataplane/metrics/parity-expected.txt).
//
// Families that used to cross the control bridge are driven by the recorded
// MetricsBatch deltas. Families Rust serves natively without ever having
// crossed it are driven by explicit fixed observations written straight to
// the Go collectors, because faking them as a batch would assert a wire
// contract that slice 5c retired.
//
// The printed set is tests/dataplane/metrics/native-families.json, not the
// wire catalogue: since slice 5c, Rust owns the exposition and serves
// families the bridge never carried. Registration happens without starting
// the system time monitor, whose real wall clock would otherwise make the
// fixture depend on how long generation took.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	controlpb "github.com/pingcap/tiproxy/pkg/controlbridge/pb"
	"github.com/pingcap/tiproxy/pkg/metrics"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/expfmt"
)

type recordedMetric struct {
	Name                  string            `json:"name"`
	Labels                map[string]string `json:"labels"`
	CounterDelta          int64             `json:"counter_delta"`
	Gauge                 float64           `json:"gauge"`
	HistogramBucketDeltas []uint64          `json:"histogram_bucket_deltas"`
}

type recordedBatch struct {
	Sequence uint64           `json:"sequence"`
	Metrics  []recordedMetric `json:"metrics"`
}

func main() {
	input := flag.String("batches", "tests/dataplane/metrics/parity-batches.json", "recorded Rust metrics batches")
	native := flag.String("native-families", "tests/dataplane/metrics/native-families.json", "families Rust serves natively")
	flag.Parse()
	if err := run(*input, *native); err != nil {
		fmt.Fprintln(os.Stderr, "metrics parity generator:", err)
		os.Exit(1)
	}
}

func run(input, nativeList string) error {
	data, err := os.ReadFile(input)
	if err != nil {
		return err
	}
	var batches []recordedBatch
	if err := json.Unmarshal(data, &batches); err != nil {
		return fmt.Errorf("decode %s: %w", input, err)
	}
	metrics.RegisterProxyMetrics()
	for _, batch := range batches {
		wire := &controlpb.MetricsBatch{Sequence: batch.Sequence}
		for _, metric := range batch.Metrics {
			wire.Metrics = append(wire.Metrics, &controlpb.MetricDelta{
				Name:                  metric.Name,
				Labels:                metric.Labels,
				CounterDelta:          metric.CounterDelta,
				Gauge:                 metric.Gauge,
				HistogramBucketDeltas: metric.HistogramBucketDeltas,
			})
		}
		if err := metrics.ApplyRustMetricsBatch(1, wire); err != nil {
			return fmt.Errorf("apply batch %d: %w", batch.Sequence, err)
		}
	}
	// Families that never crossed the bridge get explicit fixed observations,
	// so the fixture carries a real sample rather than a zero shell. The
	// 100ms/10-tick/5-callback production rule is covered by the Rust unit
	// test against a controllable clock, not by these values.
	for range fixedKeepAlives {
		metrics.KeepAliveCounter.Inc()
	}
	for range fixedTimeJumps {
		metrics.TimeJumpBackCounter.Inc()
	}
	// Session migration: the reason label is frozen when the redirect is
	// issued, so the pending gauge is incremented with that same reason and
	// decremented again when the migration settles. One succeeded and one
	// failed pair settle back to zero; a third stays in flight so the gauge
	// carries a non-zero series too.
	for _, m := range fixedMigrations {
		metrics.PendingMigrateGuage.WithLabelValues(m.from, m.to, m.reason).Inc()
		if !m.settled {
			continue
		}
		metrics.MigrateCounter.WithLabelValues(m.from, m.to, m.reason, m.result).Inc()
		metrics.PendingMigrateGuage.WithLabelValues(m.from, m.to, m.reason).Dec()
		metrics.MigrateDurationHistogram.WithLabelValues(m.from, m.to, m.result).Observe(m.seconds)
	}

	// Backend connection counts. Go sets this per namespace router, so the
	// fixture uses distinct addresses; the overlapping-address difference is
	// pinned by the comparator case, not here.
	for _, b := range fixedBackendConns {
		metrics.BackendConnGauge.WithLabelValues(b.addr).Set(float64(b.conns))
	}

	// Backend health. The three families are written straight to the Go
	// collectors because the observer helpers that drive them in production
	// are unexported. The fixture pins the semantics that distinguish them:
	// b_status has a child only for an address that has been healthy at least
	// once, while ping_duration_seconds has one for every address dialled.
	for _, b := range fixedBackendHealth {
		metrics.PingBackendGauge.WithLabelValues(b.addr).Set(b.pingSeconds)
		if !b.everHealthy {
			continue
		}
		value := 0.0
		if b.healthy {
			value = 1
		}
		metrics.BackendStatusGauge.WithLabelValues(b.addr).Set(value)
	}
	metrics.HealthCheckCycleGauge.Set(fixedHealthCheckCycleSeconds)

	native, err := readNativeFamilies(nativeList)
	if err != nil {
		return err
	}
	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		return err
	}
	gathered := make(map[string]struct{}, len(families))
	for _, family := range families {
		gathered[family.GetName()] = struct{}{}
	}
	for _, name := range native {
		if _, ok := gathered[name]; !ok {
			return fmt.Errorf("%s lists %s, which the Go collectors do not expose: "+
				"the oracle cannot vouch for a family it never gathered", nativeList, name)
		}
	}
	selected := make(map[string]struct{}, len(native))
	for _, name := range native {
		selected[name] = struct{}{}
	}
	encoder := expfmt.NewEncoder(os.Stdout, expfmt.NewFormat(expfmt.TypeTextPlain))
	for _, family := range families {
		if _, ok := selected[family.GetName()]; !ok {
			continue
		}
		if err := encoder.Encode(family); err != nil {
			return err
		}
	}
	return nil
}

// Fixed observations for the natively served families that have no recorded
// batch. Both are non-zero so the fixture cannot pass on empty shells.
const (
	fixedKeepAlives = 3
	fixedTimeJumps  = 2
)

// Backend connection counts, mirrored by the Rust golden test.
var fixedBackendConns = []struct {
	addr  string
	conns int
}{
	{addr: "10.0.0.1:4000", conns: 2},
	{addr: "10.0.0.2:4000", conns: 1},
}

// The migration fixture, mirrored exactly by the Rust golden test.
var fixedMigrations = []struct {
	from    string
	to      string
	reason  string
	result  string
	seconds float64
	settled bool
}{
	{from: "10.0.0.1:4000", to: "10.0.0.2:4000", reason: "conn", result: "succeed", seconds: 0.25, settled: true},
	{from: "10.0.0.1:4000", to: "10.0.0.2:4000", reason: "conn", result: "fail", seconds: 0.5, settled: true},
	{from: "10.0.0.1:4000", to: "10.0.0.3:4000", reason: "status", settled: false},
}

// Backend health, mirrored exactly by the Rust golden test.
//
// `10.0.0.3:4000` has never been healthy, so it is dialled -- and reports a
// ping -- without ever creating a `b_status` child. That asymmetry is the
// point of the case: Go only creates the status child on a transition into
// healthy, so a backend that has only ever failed is absent from b_status
// rather than present at zero.
var fixedBackendHealth = []struct {
	addr        string
	everHealthy bool
	healthy     bool
	pingSeconds float64
}{
	{addr: "10.0.0.1:4000", everHealthy: true, healthy: true, pingSeconds: 0.004},
	{addr: "10.0.0.2:4000", everHealthy: true, healthy: false, pingSeconds: 0.012},
	{addr: "10.0.0.3:4000", everHealthy: false, healthy: false, pingSeconds: 0.25},
}

// One health check cycle's duration.
const fixedHealthCheckCycleSeconds = 1.5

type nativeFamilies struct {
	Families []string `json:"families"`
}

// readNativeFamilies returns the families the Rust process serves natively,
// rejecting duplicates so the list cannot silently disagree with itself.
func readNativeFamilies(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc nativeFamilies
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("decode %s: %w", path, err)
	}
	if len(doc.Families) == 0 {
		return nil, fmt.Errorf("%s lists no families", path)
	}
	seen := make(map[string]struct{}, len(doc.Families))
	for _, name := range doc.Families {
		if _, ok := seen[name]; ok {
			return nil, fmt.Errorf("%s lists %s twice", path, name)
		}
		seen[name] = struct{}{}
	}
	return doc.Families, nil
}
