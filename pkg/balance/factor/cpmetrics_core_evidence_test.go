// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package factor

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/pingcap/tiproxy/pkg/balance/metricsreader"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"
	"github.com/stretchr/testify/require"
)

// This observer invokes the production QueryRule closures; it contains no
// replacement CPU/memory/error-counter arithmetic.
func TestCPMetricsRuleObservation(t *testing.T) {
	path := os.Getenv("CPMETRICS_RULE_OUTPUT")
	if path == "" {
		t.Skip("run make controlplane-cpmetrics-evidence")
	}
	output, err := os.Create(path)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, output.Close()) })
	enc := json.NewEncoder(output)
	emit := func(name, op string, input, expected any) {
		require.NoError(t, enc.Encode(map[string]any{"name": name, "op": op, "input": input, "expected": expected}))
	}
	rules := []struct {
		key  string
		expr metricsreader.QueryExpr
		rule metricsreader.QueryRule
	}{
		{"cpu", cpuQueryExpr, cpuQueryRule}, {"memory", memQueryExpr, memoryQueryRule},
	}
	for _, def := range errDefinitions {
		rules = append(rules, struct {
			key  string
			expr metricsreader.QueryExpr
			rule metricsreader.QueryRule
		}{def.failureKey, metricsreader.QueryExpr{PromQL: def.failurePromQL}, def.queryFailureRule})
		rules = append(rules, struct {
			key  string
			expr metricsreader.QueryExpr
			rule metricsreader.QueryRule
		}{def.totalKey, metricsreader.QueryExpr{PromQL: def.totalPromQL}, def.queryTotalRule})
	}
	scalar := func(value model.SampleValue) string { return strconv.FormatFloat(float64(value), 'g', -1, 64) }
	texts := []string{
		"",
		"process_cpu_seconds_total 40\ntidb_server_maxprocs 8\nprocess_resident_memory_bytes 3\ntidb_server_memory_quota_bytes 4\n",
		"process_cpu_seconds_total 4\ntidb_server_maxprocs 0\nprocess_resident_memory_bytes 0\ntidb_server_memory_quota_bytes 0\n",
		"process_cpu_seconds_total NaN\ntidb_server_maxprocs 8\nprocess_resident_memory_bytes +Inf\ntidb_server_memory_quota_bytes 4\n",
		"pd_client_cmd_handle_failed_cmds_duration_seconds_count{type=\"tso\",a=\"one\"} 1.9\npd_client_cmd_handle_failed_cmds_duration_seconds_count{type=\"tso\",a=\"two\"} 2.9\npd_client_cmd_handle_failed_cmds_duration_seconds_count{type=\"other\"} 100\npd_client_cmd_handle_cmds_duration_seconds_count{type=\"tso\"} 12\ntidb_tikvclient_backoff_seconds_count{type=\"tikvRPC\"} 4\ntidb_tikvclient_backoff_seconds_count{type=\"other\"} 100\ntidb_tikvclient_request_seconds_count{type=\"get\"} 10\ntidb_tikvclient_request_seconds_count{type=\"scan\"} 20\n",
		"pd_client_cmd_handle_failed_cmds_duration_seconds_count 9\npd_client_cmd_handle_cmds_duration_seconds_count{other=\"tso\"} 10\ntidb_tikvclient_backoff_seconds_count{type=\"other\"} 50\ntidb_tikvclient_request_seconds_count 99\n",
	}
	histories := [][]model.SamplePair{
		nil,
		{{Timestamp: 1000, Value: 1}},
		{{Timestamp: 1000, Value: 1}, {Timestamp: 2000, Value: 3}},
		{{Timestamp: 1000, Value: 1}, {Timestamp: 1999, Value: 2}, {Timestamp: 2000, Value: 3}},
		{{Timestamp: 1000, Value: 1}, {Timestamp: 1999, Value: 2}},
		{{Timestamp: 1000, Value: 4}, {Timestamp: 2000, Value: 1}},
		{{Timestamp: 1000, Value: 1}, {Timestamp: 2000, Value: 3}, {Timestamp: 1500, Value: 4}},
		{{Timestamp: 1000, Value: model.SampleValue(math.NaN())}, {Timestamp: 2000, Value: 3}},
		{{Timestamp: 1000, Value: 1}, {Timestamp: 2000, Value: model.SampleValue(math.Inf(1))}},
	}
	for _, entry := range rules {
		queries := []string{entry.expr.PromQL}
		if entry.expr.HasLabel {
			queries = []string{fmt.Sprintf(entry.expr.PromQL, "job"), fmt.Sprintf(entry.expr.PromQL, "component")}
		}
		promRange := entry.expr.PromRange(time.UnixMilli(100000))
		var window any
		if !promRange.Start.IsZero() {
			window = []int64{promRange.Start.UnixMilli(), promRange.End.UnixMilli(), promRange.Step.Milliseconds()}
		}
		emit("catalog-"+entry.key, "catalog", entry.key, map[string]any{"queries": queries, "window": window, "range_ms": entry.expr.Range.Milliseconds(), "retention_ms": entry.rule.Retention.Milliseconds(), "kind": entry.rule.ResultType.String(), "names": entry.rule.Names})
		for i, text := range texts {
			var parser expfmt.TextParser
			families, err := parser.TextToMetricFamilies(strings.NewReader(text))
			require.NoError(t, err)
			emit(fmt.Sprintf("metric-%s-%d", entry.key, i), "metric", map[string]any{"key": entry.key, "text": text}, scalar(entry.rule.Metric2Value(families)))
		}
		for i, pairs := range histories {
			if pairs == nil {
				pairs = []model.SamplePair{}
			}
			emit(fmt.Sprintf("range-%s-%d", entry.key, i), "range", map[string]any{"key": entry.key, "pairs": pairs}, scalar(entry.rule.Range2Value(pairs)))
		}
	}
}
