// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package backendcluster

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/pingcap/tiproxy/pkg/balance/metricsreader"
	"github.com/prometheus/common/model"
	"github.com/stretchr/testify/require"
)

func TestCPMetricsMergeObservation(t *testing.T) {
	path := os.Getenv("CPMETRICS_MERGE_OUTPUT")
	if path == "" {
		t.Skip("run make controlplane-cpmetrics-evidence")
	}
	file, err := os.Create(path)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, file.Close()) })
	input := []map[string]any{
		{"body": `{"status":"success","data":{"resultType":"matrix","result":[{"metric":{"instance":"a","tiproxy_cluster":"old"},"values":[[1,"0.2"]]}]}}`, "cluster": "old", "updated_nanos": int64(1)},
		{"body": `{"status":"success","data":{"resultType":"matrix","result":[{"metric":{"instance":"b","tiproxy_cluster":"fresh"},"values":[[300,"0.4"]]}]}}`, "cluster": "fresh", "updated_nanos": int64(300000000001)},
	}
	results := make([]metricsreader.QueryResult, 0, len(input))
	for _, row := range input {
		var response struct {
			Data struct {
				Result model.Matrix `json:"result"`
			} `json:"data"`
		}
		require.NoError(t, json.Unmarshal([]byte(row["body"].(string)), &response))
		results = append(results, metricsreader.QueryResult{Value: response.Data.Result, UpdateTime: time.Unix(0, row["updated_nanos"].(int64))})
	}
	merged := mergeQueryResults(results)
	require.NoError(t, json.NewEncoder(file).Encode(map[string]any{"name": "two-cluster-max-update-keeps-original-sample-times", "op": "merge_results", "input": input, "expected": map[string]any{"kind": "matrix", "data": merged.Value, "updated_nanos": merged.UpdateTime.UnixNano()}}))
}
