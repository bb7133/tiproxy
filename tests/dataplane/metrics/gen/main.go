// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

// Command gen renders the Go promhttp text exposition for a recorded sequence
// of Rust MetricsBatch deltas. It is the oracle for the Rust native
// exposition parity gate (tests/dataplane/metrics/parity-expected.txt): the
// same batches the Rust exporter would ship over the bridge are applied to the
// Go metrics store, and the families owned by the Rust catalog are printed in
// the exact bytes Prometheus would scrape from the Go API server.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"

	controlpb "github.com/pingcap/tiproxy/pkg/controlbridge/pb"
	"github.com/pingcap/tiproxy/pkg/metrics"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/expfmt"
	"go.uber.org/zap"
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
	flag.Parse()
	if err := run(*input); err != nil {
		fmt.Fprintln(os.Stderr, "metrics parity generator:", err)
		os.Exit(1)
	}
}

func run(input string) error {
	data, err := os.ReadFile(input)
	if err != nil {
		return err
	}
	var batches []recordedBatch
	if err := json.Unmarshal(data, &batches); err != nil {
		return fmt.Errorf("decode %s: %w", input, err)
	}
	manager := metrics.NewMetricsManager()
	manager.Init(context.Background(), zap.NewNop())
	defer manager.Close()
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
	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		return err
	}
	owned := metrics.RustMetricNames()
	sort.Strings(owned)
	encoder := expfmt.NewEncoder(os.Stdout, expfmt.NewFormat(expfmt.TypeTextPlain))
	for _, family := range families {
		index := sort.SearchStrings(owned, family.GetName())
		if index >= len(owned) || owned[index] != family.GetName() {
			continue
		}
		if err := encoder.Encode(family); err != nil {
			return err
		}
	}
	return nil
}
