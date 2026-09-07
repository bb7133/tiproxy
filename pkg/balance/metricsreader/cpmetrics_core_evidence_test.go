// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package metricsreader

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/prometheus/common/model"
	"github.com/stretchr/testify/require"
)

func TestCPMetricsHistoryObservation(t *testing.T) {
	path := os.Getenv("CPMETRICS_HISTORY_OUTPUT")
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
	marshal := func(value any) string { data, err := json.Marshal(value); require.NoError(t, err); return string(data) }
	wires := []string{
		"", `null`, `{}`, `{"cpu":{"a":{"Step1History":[[1.001,"1"],[2.9999,"3"]],"Step2History":[[3,"NaN"],[4,"+Inf"]]}}}`,
		`{"outside":{"not-in-topology":{"STEP1HISTORY":[[-1.25,"4"]],"step2history":null}}}`,
		`{"cpu":null,"memory":{"x":null}}`,
		`{"cpu":{"a":{"Step1History":[[1e3,"1"]]}}}`,
		`{"cpu":{"a":{"Step1History":[[1,2]]}}}`,
	}
	for i, wire := range wires {
		var history map[string]map[string]backendHistory
		var err error
		if wire != "" {
			err = json.Unmarshal([]byte(wire), &history)
		}
		if err != nil {
			emit(fmt.Sprintf("owner-decode-%d", i), "owner_decode", wire, map[string]any{"error": true})
			continue
		}
		emit(fmt.Sprintf("owner-decode-%d", i), "owner_decode", wire, map[string]any{"history": cpMetricsHistoryValue(history)})
	}
	local := `{"cpu":{"a":{"Step1History":[[1,"10"],[2,"20"]],"Step2History":[[3,"30"]]}},"memory":{"b":{"Step1History":[[4,"40"]],"Step2History":[]}}}`
	incoming := []string{
		`{"cpu":{"a":{"Step1History":[[2,"99"]],"Step2History":[[2,"22"]]}}}`,
		`{"cpu":{"a":{"Step1History":[[3,"99"]],"Step2History":[[2,"22"]]}}}`,
		`{"cpu":{"a":{"Step1History":[],"Step2History":[[4,"44"]]}}}`,
		`{"outside":{"new-backend":{"Step1History":[[1,"9"]],"Step2History":[[1,"8"]]}}}`,
		`{"cpu":{"new-backend":{"Step1History":[[1,"9"]],"Step2History":[[1,"8"]]}}}`,
	}
	for i, wire := range incoming {
		reader := &BackendReader{}
		require.NoError(t, json.Unmarshal([]byte(local), &reader.history))
		var newHistory map[string]map[string]backendHistory
		require.NoError(t, json.Unmarshal([]byte(wire), &newHistory))
		reader.mergeHistory(newHistory)
		emit(fmt.Sprintf("owner-merge-%d", i), "merge", map[string]any{"local": local, "incoming": wire}, cpMetricsHistoryValue(reader.history))
	}
	for i, pairs := range [][]model.SamplePair{
		{{Timestamp: 0, Value: 1}, {Timestamp: 1, Value: 2}},
		{{Timestamp: 0, Value: 1}},
		{{Timestamp: 1, Value: 1}, {Timestamp: -2, Value: 2}},
		{{Timestamp: 1000000, Value: 1}, {Timestamp: 0, Value: 2}},
	} {
		input := append([]model.SamplePair(nil), pairs...)
		result := purgeHistory(pairs, time.Minute, time.UnixMilli(60000))
		emit(fmt.Sprintf("purge-%d", i), "purge", map[string]any{"pairs": input, "now_ms": 60000, "retention_ms": 60000}, result)
	}
	for i, history := range []string{
		`{}`, `{"cpu":{"a:10080":{"Step1History":[[0,"1"]],"Step2History":[]}}}`,
		`{"memory":{"a:10080":{"Step2History":[[0,"1"]]}}}`,
		`{"outside":{"a:10080":{"Step2History":[[0,"1"]]}}}`,
	} {
		reader := &BackendReader{queryRules: map[string]QueryRule{"cpu": {}, "memory": {}}}
		require.NoError(t, json.Unmarshal([]byte(history), &reader.history))
		addrs := []string{"a:10080", "b:10080"}
		emit(fmt.Sprintf("missing-%d", i), "missing", map[string]any{"history": history, "addresses": addrs}, reader.findMissingBackendAddrs(addrs))
	}
	for _, test := range []struct {
		name, addr, ip string
		port           uint
	}{
		{"plain", "sql:4000", "host", 10080}, {"ipv6", "[::1]:4000", "::1", 10080},
		{"operator", "x-tidb-0.x-tidb-peer.ns.svc:4000", "else", 10080},
		{"ordered-markers", "x-tidb-0.peer.svc.anything", "else", 10080},
		{"wrong-order", "x-tidb-0.svc.peer", "else", 10080},
		{"empty-ip", "raw:4000", "", 0},
	} {
		backend := newMockBackend(test.addr, test.ip, test.port)
		emit("label-"+test.name, "label", map[string]any{"address": test.addr, "ip": test.ip, "port": test.port}, getLabel4Backend(backend))
	}
	for i, cluster := range []string{"", "  ", "default", " cluster-a "} {
		qr := QueryResult{Value: model.Vector{&model.Sample{Metric: model.Metric{"instance": "a", "tiproxy_cluster": "wrong"}, Timestamp: 1001, Value: 2}}, UpdateTime: time.Unix(0, 1000001)}
		qr = attachClusterLabel(qr, cluster)
		emit(fmt.Sprintf("attach-%d", i), "prom_decode", map[string]any{"body": `{"status":"success","data":{"resultType":"vector","result":[{"metric":{"instance":"a","tiproxy_cluster":"wrong"},"value":[1.001,"2"]}]}}`, "cluster": cluster, "updated_nanos": qr.UpdateTime.UnixNano()}, map[string]any{"kind": "vector", "data": qr.Value, "updated_nanos": qr.UpdateTime.UnixNano()})
	}
	for i, body := range []string{
		`{"metric":{"instance":"a"},"values":[[1,"2"],[2,"3"]]}`,
		`{"metric":{"instance":"a","tiproxy_cluster":"other"},"values":[[1,"2"]]}`,
		`{"metric":{"instance":"a","tiproxy_cluster":"default"},"values":[[1,"2"]]}`,
	} {
		var matrix model.Matrix
		require.NoError(t, json.Unmarshal([]byte("["+body+"]"), &matrix))
		qr := QueryResult{Value: matrix}
		backend := newMockBackend("sql:4000", "a", 0)
		// Instance matching is exercised with the actual Go metric-map comparator.
		backend.addr = "x-tidb-a.peer.svc"
		matrix[0].Metric[LabelNameInstance] = "x-tidb-a"
		emit(fmt.Sprintf("lookup-%d", i), "lookup", map[string]any{"body": marshal(matrix), "instance": "x-tidb-a", "cluster": ""}, qr.GetSamplePair4Backend(backend))
	}
	// Exercise the actual owner filter: out-of-topology history is not exported
	// unless the owner included that label in its original backend read list.
	reader := &BackendReader{}
	require.NoError(t, json.Unmarshal([]byte(local), &reader.history))
	for i, selected := range [][]string{nil, {"a"}, {"b"}, {"missing"}} {
		require.NoError(t, reader.marshalHistory(selected))
		var expected map[string]map[string]backendHistory
		require.NoError(t, json.Unmarshal(reader.marshalledHistory, &expected))
		if selected == nil {
			selected = []string{}
		}
		emit(fmt.Sprintf("owner-filter-%d", i), "owner_filter", map[string]any{"history": local, "selected": selected}, cpMetricsHistoryValue(expected))
	}
}

// Normalize nil/empty containers only; metric values/times come unchanged from
// the actual reader. Both forms are accepted by Go's existing owner protocol.
func cpMetricsHistoryValue(history map[string]map[string]backendHistory) map[string]map[string]backendHistory {
	result := make(map[string]map[string]backendHistory, len(history))
	for key, backends := range history {
		values := make(map[string]backendHistory, len(backends))
		for backend, entry := range backends {
			if entry.Step1History == nil {
				entry.Step1History = []model.SamplePair{}
			}
			if entry.Step2History == nil {
				entry.Step2History = []model.SamplePair{}
			}
			values[backend] = entry
		}
		result[key] = values
	}
	return result
}

func TestCPMetricsBackendWireObservation(t *testing.T) {
	path := os.Getenv("CPMETRICS_BACKEND_OUTPUT")
	if path == "" {
		t.Skip("run make controlplane-cpmetrics-evidence")
	}
	file, err := os.Create(path)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, file.Close()) })
	enc := json.NewEncoder(file)
	names := []string{"process_cpu_seconds_total", "tidb_server_maxprocs", "process_resident_memory_bytes", "tidb_server_memory_quota_bytes", "pd_client_cmd_handle_failed_cmds_duration_seconds_count", "pd_client_cmd_handle_cmds_duration_seconds_count", "tidb_tikvclient_backoff_seconds_count", "tidb_tikvclient_request_seconds_count"}
	for i, text := range []string{
		"# TYPE process_cpu_seconds_total counter\nprocess_cpu_seconds_total 3 123\nignore{not=broken\n",
		"pd_client_cmd_handle_cmds_duration_seconds_count{type=\"tso\",zone=\"a\\n\\\"\\\\b\"} 3\n",
		"process_cpu_seconds_total{type=\"a\",type=\"b\"} 3\n",
		"process_cpu_seconds_total{type=\"a\"} 1\nprocess_cpu_seconds_total{type=\"a\"} 2\n",
		"process_cpu_seconds_total_extra 3\nprocess_cpu_seconds_total 5\n",
		"process_cpu_seconds_total 3 trailing\n",
		"process_cpu_seconds_total NaN\ntidb_server_maxprocs +Inf\n",
		"process_cpu_seconds_total{a=\"bad\\q\"} 3\n",
		"process_cpu_seconds_total{3a=\"bad\"} 3\n",
	} {
		families, err := parseMetrics(filterMetrics(text, names))
		var expected any
		if err != nil {
			expected = map[string]any{"error": true}
		} else {
			observed := make(map[string][]map[string]any, len(families))
			for name, family := range families {
				values := make([]map[string]any, 0, len(family.Metric))
				for _, point := range family.Metric {
					labels := make(map[string]string, len(point.Label))
					for _, label := range point.Label {
						labels[label.GetName()] = label.GetValue()
					}
					values = append(values, map[string]any{"labels": labels, "value": strconv.FormatFloat(point.GetUntyped().GetValue(), 'g', -1, 64)})
				}
				observed[name] = values
			}
			expected = observed
		}
		require.NoError(t, enc.Encode(map[string]any{"name": fmt.Sprintf("actual-backend-wire-%d", i), "op": "backend_decode", "input": text, "expected": expected}))
	}
}
