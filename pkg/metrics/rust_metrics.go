// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"
	"sync"

	controlpb "github.com/pingcap/tiproxy/pkg/controlbridge/pb"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

const (
	maxRustMetricsPerBatch = 1024
	maxRustMetricSeries    = 4096
	maxRustLabelBytes      = 256
)

type rustMetricKind uint8

const (
	rustCounter rustMetricKind = iota + 1
	rustGauge
	rustHistogram
)

type rustMetricSpec struct {
	name    string
	help    string
	kind    rustMetricKind
	labels  []string
	buckets []float64
	local   prometheus.Collector
}

var rustMetricSpecs = map[string]rustMetricSpec{
	"tiproxy_server_connections": {
		name: "tiproxy_server_connections", kind: rustGauge,
	},
	"tiproxy_server_create_connection_total": {
		name: "tiproxy_server_create_connection_total", kind: rustCounter,
	},
	"tiproxy_server_reject_connection_total": {
		name: "tiproxy_server_reject_connection_total", kind: rustCounter, labels: []string{LblType},
	},
	"tiproxy_server_disconnection_total": {
		name: "tiproxy_server_disconnection_total", kind: rustCounter, labels: []string{LblType},
	},
	"tiproxy_server_event": {
		name: "tiproxy_server_event", kind: rustCounter, labels: []string{LblType},
	},
	"tiproxy_server_err": {
		name: "tiproxy_server_err", kind: rustCounter, labels: []string{LblType},
	},
	"tiproxy_session_query_total": {
		name: "tiproxy_session_query_total", kind: rustCounter, labels: []string{LblBackend, LblCmdType},
	},
	"tiproxy_session_query_duration_seconds": {
		name: "tiproxy_session_query_duration_seconds",
		help: "Bucketed histogram of processing time (s) of handled queries.",
		kind: rustHistogram, labels: []string{LblBackend, LblCmdType},
		buckets: prometheus.ExponentialBuckets(0.0005, 2, 29), local: QueryDurationHistogram,
	},
	"tiproxy_session_handshake_duration_seconds": {
		name: "tiproxy_session_handshake_duration_seconds",
		help: "Bucketed histogram of processing time (s) of handshakes.",
		kind: rustHistogram, labels: []string{LblBackend},
		buckets: prometheus.ExponentialBuckets(0.0005, 2, 29), local: HandshakeDurationHistogram,
	},
	"tiproxy_session_query_time_since_conn_creation_seconds": {
		name:    "tiproxy_session_query_time_since_conn_creation_seconds",
		help:    "Bucketed histogram of query start time (s) since connection creation.",
		kind:    rustHistogram,
		buckets: prometheus.ExponentialBuckets(1, 2, 21), local: QueryTimeSinceConnCreationHistogram,
	},
	"tiproxy_session_conn_lifetime_seconds": {
		name:    "tiproxy_session_conn_lifetime_seconds",
		help:    "Bucketed histogram of connection lifetime (s).",
		kind:    rustHistogram,
		buckets: prometheus.ExponentialBuckets(0.1, 2, 25), local: ConnLifetimeHistogram,
	},
	"tiproxy_backend_get_backend_duration_seconds": {
		name:    "tiproxy_backend_get_backend_duration_seconds",
		help:    "Bucketed histogram of time (s) for getting an available backend.",
		kind:    rustHistogram,
		buckets: prometheus.ExponentialBuckets(0.000001, 2, 26), local: GetBackendHistogram,
	},
	"tiproxy_backend_get_backend": {
		name: "tiproxy_backend_get_backend", kind: rustCounter, labels: []string{LblRes},
	},
	"tiproxy_backend_dial_backend_fail": {
		name: "tiproxy_backend_dial_backend_fail", kind: rustCounter, labels: []string{LblBackend},
	},
	"tiproxy_backend_keepalive_update_total": {
		name: "tiproxy_backend_keepalive_update_total", kind: rustCounter,
		labels: []string{LblBackend, LblHealth, LblResult},
	},
	"tiproxy_traffic_inbound_bytes": {
		name: "tiproxy_traffic_inbound_bytes", kind: rustCounter, labels: []string{LblBackend},
	},
	"tiproxy_traffic_inbound_packets": {
		name: "tiproxy_traffic_inbound_packets", kind: rustCounter, labels: []string{LblBackend},
	},
	"tiproxy_traffic_outbound_bytes": {
		name: "tiproxy_traffic_outbound_bytes", kind: rustCounter, labels: []string{LblBackend},
	},
	"tiproxy_traffic_outbound_packets": {
		name: "tiproxy_traffic_outbound_packets", kind: rustCounter, labels: []string{LblBackend},
	},
	"tiproxy_traffic_cross_location_bytes": {
		name: "tiproxy_traffic_cross_location_bytes", kind: rustCounter,
	},
}

type rustSeries struct {
	name   string
	values string
}

type rustHistogramValue struct {
	labels  []string
	count   uint64
	sum     float64
	buckets []uint64
}

type rustMetricsStore struct {
	mu sync.Mutex

	lastEpoch    uint64
	lastSequence uint64
	series       map[rustSeries]struct{}
	gauges       map[rustSeries]float64
	histograms   map[rustSeries]*rustHistogramValue
}

func newRustMetricsStore() *rustMetricsStore {
	return &rustMetricsStore{
		series:     make(map[rustSeries]struct{}),
		gauges:     make(map[rustSeries]float64),
		histograms: make(map[rustSeries]*rustHistogramValue),
	}
}

var rustMetrics = newRustMetricsStore()

// ApplyRustMetricsBatch validates and merges one Rust bulk observation batch.
// A duplicate sequence in the same control epoch and every stale control
// epoch are ignored. On a newer epoch, a lower sequence is accepted as a
// Rust-process restart while a continuing sequence preserves process counters.
func ApplyRustMetricsBatch(epoch uint64, batch *controlpb.MetricsBatch) error {
	return rustMetrics.apply(epoch, batch)
}

type validatedRustMetric struct {
	spec   rustMetricSpec
	series rustSeries
	labels []string
	wire   *controlpb.MetricDelta
}

func (store *rustMetricsStore) apply(epoch uint64, batch *controlpb.MetricsBatch) error {
	if epoch == 0 {
		return errors.New("Rust metrics require a nonzero control epoch")
	}
	if batch == nil || batch.GetSequence() == 0 {
		return errors.New("Rust metrics require a nonzero batch sequence")
	}
	if len(batch.GetMetrics()) > maxRustMetricsPerBatch {
		return fmt.Errorf("Rust metrics batch has %d entries, limit %d", len(batch.GetMetrics()), maxRustMetricsPerBatch)
	}
	validated := make([]validatedRustMetric, 0, len(batch.GetMetrics()))
	for _, metric := range batch.GetMetrics() {
		value, err := validateRustMetric(metric)
		if err != nil {
			return err
		}
		validated = append(validated, value)
	}

	store.mu.Lock()
	defer store.mu.Unlock()
	if epoch < store.lastEpoch {
		return nil
	}
	if epoch == store.lastEpoch && batch.GetSequence() <= store.lastSequence {
		return nil
	}
	if epoch == store.lastEpoch && store.lastSequence != 0 && batch.GetSequence() > store.lastSequence+1 {
		ServerErrCounter.WithLabelValues("rust_metrics_sequence_gap").Inc()
	}
	newSeries := make(map[rustSeries]struct{})
	for _, metric := range validated {
		if _, exists := store.series[metric.series]; !exists {
			newSeries[metric.series] = struct{}{}
		}
	}
	if len(store.series)+len(newSeries) > maxRustMetricSeries {
		return fmt.Errorf("Rust metrics series limit %d exceeded", maxRustMetricSeries)
	}
	for _, metric := range validated {
		store.series[metric.series] = struct{}{}
		switch metric.spec.kind {
		case rustCounter:
			applyRustCounter(metric.spec.name, metric.labels, float64(metric.wire.GetCounterDelta()))
		case rustGauge:
			old := store.gauges[metric.series]
			store.gauges[metric.series] = metric.wire.GetGauge()
			applyRustGauge(metric.spec.name, metric.wire.GetGauge()-old)
		case rustHistogram:
			histogram := store.histograms[metric.series]
			if histogram == nil {
				histogram = &rustHistogramValue{
					labels:  metric.labels,
					buckets: make([]uint64, len(metric.spec.buckets)),
				}
				store.histograms[metric.series] = histogram
			}
			histogram.count += uint64(metric.wire.GetCounterDelta())
			histogram.sum += metric.wire.GetGauge()
			for i, delta := range metric.wire.GetHistogramBucketDeltas() {
				histogram.buckets[i] += delta
			}
		}
	}
	store.lastEpoch = epoch
	store.lastSequence = batch.GetSequence()
	return nil
}

func validateRustMetric(metric *controlpb.MetricDelta) (validatedRustMetric, error) {
	if metric == nil {
		return validatedRustMetric{}, errors.New("Rust metrics entry is nil")
	}
	spec, ok := rustMetricSpecs[metric.GetName()]
	if !ok {
		return validatedRustMetric{}, fmt.Errorf("unknown Rust metric %q", metric.GetName())
	}
	labels, err := validateRustLabels(spec, metric.GetLabels())
	if err != nil {
		return validatedRustMetric{}, err
	}
	if metric.GetCounterDelta() < 0 || math.IsNaN(metric.GetGauge()) || math.IsInf(metric.GetGauge(), 0) {
		return validatedRustMetric{}, fmt.Errorf("Rust metric %q has an invalid numeric value", spec.name)
	}
	switch spec.kind {
	case rustCounter:
		if metric.GetGauge() != 0 || len(metric.GetHistogramBucketDeltas()) != 0 {
			return validatedRustMetric{}, fmt.Errorf("Rust counter %q carries non-counter fields", spec.name)
		}
	case rustGauge:
		if metric.GetCounterDelta() != 0 || len(metric.GetHistogramBucketDeltas()) != 0 {
			return validatedRustMetric{}, fmt.Errorf("Rust gauge %q carries non-gauge fields", spec.name)
		}
		if metric.GetGauge() < 0 || math.Trunc(metric.GetGauge()) != metric.GetGauge() {
			return validatedRustMetric{}, fmt.Errorf("Rust gauge %q is not a non-negative integer", spec.name)
		}
	case rustHistogram:
		if metric.GetGauge() < 0 || (metric.GetCounterDelta() == 0 && metric.GetGauge() != 0) {
			return validatedRustMetric{}, fmt.Errorf("Rust histogram %q has an invalid sample sum", spec.name)
		}
		if len(metric.GetHistogramBucketDeltas()) != len(spec.buckets) {
			return validatedRustMetric{}, fmt.Errorf("Rust histogram %q has %d buckets, want %d", spec.name, len(metric.GetHistogramBucketDeltas()), len(spec.buckets))
		}
		count := uint64(metric.GetCounterDelta())
		var previous uint64
		for _, bucket := range metric.GetHistogramBucketDeltas() {
			if bucket < previous || bucket > count {
				return validatedRustMetric{}, fmt.Errorf("Rust histogram %q has invalid cumulative buckets", spec.name)
			}
			previous = bucket
		}
	}
	series := rustSeries{name: spec.name, values: strings.Join(labels, "\x00")}
	return validatedRustMetric{spec: spec, series: series, labels: labels, wire: metric}, nil
}

func validateRustLabels(spec rustMetricSpec, labels map[string]string) ([]string, error) {
	if len(labels) != len(spec.labels) {
		return nil, fmt.Errorf("Rust metric %q has %d labels, want %d", spec.name, len(labels), len(spec.labels))
	}
	values := make([]string, len(spec.labels))
	for i, name := range spec.labels {
		value, ok := labels[name]
		if !ok || value == "" || len(value) > maxRustLabelBytes || strings.IndexByte(value, 0) >= 0 {
			return nil, fmt.Errorf("Rust metric %q has invalid %q label", spec.name, name)
		}
		values[i] = value
	}
	if err := validateRustLabelValues(spec.name, values); err != nil {
		return nil, err
	}
	return values, nil
}

func validateRustLabelValues(name string, values []string) error {
	allowed := func(value string, options []string) bool { return slices.Contains(options, value) }
	switch name {
	case "tiproxy_server_reject_connection_total":
		if !allowed(values[0], []string{"memory", "max_connections"}) {
			return fmt.Errorf("Rust reject metric has invalid type %q", values[0])
		}
	case "tiproxy_server_disconnection_total":
		if !allowed(values[0], []string{
			"success", "client network break", "client handshake fail", "auth fail", "SQL error",
			"proxy shutdown", "malformed packet", "get backend fail", "proxy error",
			"backend network break", "backend handshake fail",
		}) {
			return fmt.Errorf("Rust disconnection metric has invalid type %q", values[0])
		}
	case "tiproxy_server_event":
		if values[0] != "rust_control_reconnect" {
			return fmt.Errorf("Rust server event has invalid type %q", values[0])
		}
	case "tiproxy_server_err":
		if !allowed(values[0], []string{
			"rust_memory_probe_failure", "rust_accept_error", "rust_socket_policy_failure",
			"rust_registration_failure", "rust_handler_panic", "rust_metrics_observation_dropped",
			"rust_metrics_batch_dropped", "rust_control_session_scoped_dropped",
			"rust_control_unrouted", "rust_control_stale_dropped", "rust_control_send_failure",
			"rust_metering_failure",
		}) {
			return fmt.Errorf("Rust server error has invalid type %q", values[0])
		}
	case "tiproxy_backend_get_backend":
		if !allowed(values[0], []string{"succeed", "fail"}) {
			return fmt.Errorf("Rust get-backend metric has invalid result %q", values[0])
		}
	case "tiproxy_backend_keepalive_update_total":
		if !allowed(values[1], []string{"healthy", "unhealthy"}) {
			return fmt.Errorf("Rust keepalive metric has invalid health %q", values[1])
		}
		if !allowed(values[2], []string{"succeed", "fail"}) {
			return fmt.Errorf("Rust keepalive metric has invalid result %q", values[2])
		}
	case "tiproxy_session_query_total", "tiproxy_session_query_duration_seconds":
		if !allowed(values[1], rustCommandLabels) {
			return fmt.Errorf("Rust query metric has invalid command %q", values[1])
		}
	}
	return nil
}

var rustCommandLabels = []string{
	"Sleep", "Quit", "InitDB", "Query", "FieldList", "CreateDB", "DropDB", "Refresh",
	"(DEPRECATED)Shutdown", "Statistics", "ProcessInfo", "Connect", "ProcessKill", "Debug",
	"Ping", "Time", "DelayedInsert", "ChangeUser", "BinlogDump", "TableDump", "ConnectOut",
	"RegisterSlave", "StmtPrepare", "StmtExecute", "StmtSendLongData", "StmtClose", "StmtReset",
	"SetOption", "StmtFetch", "Daemon", "BinlogDumpGtid", "ResetConnect",
}

func applyRustCounter(name string, labels []string, delta float64) {
	switch name {
	case "tiproxy_server_create_connection_total":
		CreateConnCounter.Add(delta)
	case "tiproxy_server_reject_connection_total":
		RejectConnCounter.WithLabelValues(labels...).Add(delta)
	case "tiproxy_server_disconnection_total":
		DisConnCounter.WithLabelValues(labels...).Add(delta)
	case "tiproxy_server_event":
		ServerEventCounter.WithLabelValues(labels...).Add(delta)
	case "tiproxy_server_err":
		ServerErrCounter.WithLabelValues(labels...).Add(delta)
	case "tiproxy_session_query_total":
		QueryTotalCounter.WithLabelValues(labels...).Add(delta)
	case "tiproxy_backend_get_backend":
		GetBackendCounter.WithLabelValues(labels...).Add(delta)
	case "tiproxy_backend_dial_backend_fail":
		DialBackendFailCounter.WithLabelValues(labels...).Add(delta)
	case "tiproxy_backend_keepalive_update_total":
		BackendKeepAliveUpdateCounter.WithLabelValues(labels...).Add(delta)
	case "tiproxy_traffic_inbound_bytes":
		InboundBytesCounter.WithLabelValues(labels...).Add(delta)
	case "tiproxy_traffic_inbound_packets":
		InboundPacketsCounter.WithLabelValues(labels...).Add(delta)
	case "tiproxy_traffic_outbound_bytes":
		OutboundBytesCounter.WithLabelValues(labels...).Add(delta)
	case "tiproxy_traffic_outbound_packets":
		OutboundPacketsCounter.WithLabelValues(labels...).Add(delta)
	case "tiproxy_traffic_cross_location_bytes":
		CrossLocationBytesCounter.Add(delta)
	}
}

func applyRustGauge(name string, delta float64) {
	if name == "tiproxy_server_connections" {
		ConnGauge.Add(delta)
	}
}

type mergedRustHistogramCollector struct {
	spec  rustMetricSpec
	desc  *prometheus.Desc
	store *rustMetricsStore
}

func newMergedRustHistogramCollector(spec rustMetricSpec, store *rustMetricsStore) prometheus.Collector {
	return &mergedRustHistogramCollector{
		spec:  spec,
		desc:  prometheus.NewDesc(spec.name, spec.help, spec.labels, nil),
		store: store,
	}
}

func (collector *mergedRustHistogramCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- collector.desc
}

func (collector *mergedRustHistogramCollector) Collect(ch chan<- prometheus.Metric) {
	remote := collector.store.histogramSnapshot(collector.spec.name)
	localCh := make(chan prometheus.Metric)
	go func() {
		collector.spec.local.Collect(localCh)
		close(localCh)
	}()
	for metric := range localCh {
		var dtoMetric dto.Metric
		if err := metric.Write(&dtoMetric); err != nil || dtoMetric.Histogram == nil {
			continue
		}
		labels, ok := dtoLabelValues(&dtoMetric, collector.spec.labels)
		if !ok {
			continue
		}
		key := rustSeries{name: collector.spec.name, values: strings.Join(labels, "\x00")}
		value := remote[key]
		delete(remote, key)
		count := dtoMetric.Histogram.GetSampleCount()
		sum := dtoMetric.Histogram.GetSampleSum()
		buckets := make(map[float64]uint64, len(collector.spec.buckets))
		for _, bucket := range dtoMetric.Histogram.GetBucket() {
			buckets[bucket.GetUpperBound()] = bucket.GetCumulativeCount()
		}
		if value != nil {
			count += value.count
			sum += value.sum
			for i, upper := range collector.spec.buckets {
				buckets[upper] += value.buckets[i]
			}
		}
		if merged, err := prometheus.NewConstHistogram(collector.desc, count, sum, buckets, labels...); err == nil {
			ch <- merged
		}
	}
	for _, value := range remote {
		buckets := make(map[float64]uint64, len(collector.spec.buckets))
		for i, upper := range collector.spec.buckets {
			buckets[upper] = value.buckets[i]
		}
		if metric, err := prometheus.NewConstHistogram(
			collector.desc, value.count, value.sum, buckets, value.labels...,
		); err == nil {
			ch <- metric
		}
	}
}

func dtoLabelValues(metric *dto.Metric, names []string) ([]string, bool) {
	byName := make(map[string]string, len(metric.GetLabel()))
	for _, label := range metric.GetLabel() {
		byName[label.GetName()] = label.GetValue()
	}
	values := make([]string, len(names))
	for i, name := range names {
		value, ok := byName[name]
		if !ok {
			return nil, false
		}
		values[i] = value
	}
	return values, true
}

func (store *rustMetricsStore) histogramSnapshot(name string) map[rustSeries]*rustHistogramValue {
	store.mu.Lock()
	defer store.mu.Unlock()
	snapshot := make(map[rustSeries]*rustHistogramValue)
	for key, value := range store.histograms {
		if key.name != name {
			continue
		}
		snapshot[key] = &rustHistogramValue{
			labels: slices.Clone(value.labels), count: value.count, sum: value.sum,
			buckets: slices.Clone(value.buckets),
		}
	}
	return snapshot
}

func (store *rustMetricsStore) deletePartial(labels prometheus.Labels) {
	store.mu.Lock()
	defer store.mu.Unlock()
	for key := range store.series {
		spec := rustMetricSpecs[key.name]
		values := strings.Split(key.values, "\x00")
		matches := true
		for name, want := range labels {
			index := slices.Index(spec.labels, name)
			if index < 0 || index >= len(values) || values[index] != want {
				matches = false
				break
			}
		}
		if matches {
			delete(store.series, key)
			delete(store.gauges, key)
			delete(store.histograms, key)
		}
	}
}

var rustHistogramCollectors map[prometheus.Collector]prometheus.Collector

func init() {
	rustHistogramCollectors = make(map[prometheus.Collector]prometheus.Collector)
	for _, spec := range rustMetricSpecs {
		if spec.kind == rustHistogram {
			rustHistogramCollectors[spec.local] = newMergedRustHistogramCollector(spec, rustMetrics)
		}
	}
}

func collectorWithRustMetrics(collector prometheus.Collector) prometheus.Collector {
	if merged := rustHistogramCollectors[collector]; merged != nil {
		return merged
	}
	return collector
}
