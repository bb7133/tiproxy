// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

// go-series-probe prints every Prometheus family the Go TiProxy process
// registers, as JSON: name, help, type, labels, and whether Rust metric
// batches feed it (CP-ADMIN slice 5c: the Go API retirement inventory).
package main

import (
	"encoding/json"
	"os"
	"sort"
	"strings"

	"github.com/pingcap/tiproxy/pkg/metrics"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

type family struct {
	Name    string   `json:"name"`
	Help    string   `json:"help"`
	Labels  []string `json:"labels"`
	RustFed bool     `json:"rust_fed"`
}

func main() {
	rustFed := map[string]bool{}
	for _, name := range metrics.RustFedMetricNames() {
		rustFed[name] = true
	}
	seen := map[string]family{}
	for _, collector := range metrics.RegisteredCollectors() {
		descs := make(chan *prometheus.Desc, 64)
		go func() {
			collector.Describe(descs)
			close(descs)
		}()
		for desc := range descs {
			text := desc.String()
			name := between(text, `fqName: "`, `"`)
			help := between(text, `help: "`, `"`)
			labels := between(text, "variableLabels: {", "}")
			var labelNames []string
			for _, label := range strings.Split(labels, ",") {
				if label = strings.TrimSpace(label); label != "" {
					labelNames = append(labelNames, label)
				}
			}
			seen[name] = family{Name: name, Help: help, Labels: labelNames, RustFed: rustFed[name]}
		}
	}
	families := make([]family, 0, len(seen))
	for _, f := range seen {
		families = append(families, f)
	}
	sort.Slice(families, func(i, j int) bool { return families[i].Name < families[j].Name })
	_ = dto.MetricType_COUNTER
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(families); err != nil {
		panic(err)
	}
}

func between(text, start, end string) string {
	i := strings.Index(text, start)
	if i < 0 {
		return ""
	}
	rest := text[i+len(start):]
	j := strings.Index(rest, end)
	if j < 0 {
		return rest
	}
	return rest[:j]
}
