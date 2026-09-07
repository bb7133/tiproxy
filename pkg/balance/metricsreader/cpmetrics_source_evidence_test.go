// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package metricsreader

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/pingcap/tiproxy/lib/config"
	"github.com/pingcap/tiproxy/lib/util/logger"
	"github.com/pingcap/tiproxy/pkg/manager/infosync"
	httputil "github.com/pingcap/tiproxy/pkg/util/http"
	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/model"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestCPMetricsSourceObservation(t *testing.T) {
	path := os.Getenv("CPMETRICS_SOURCE_OUTPUT")
	if path == "" {
		t.Skip("run make controlplane-cpmetrics-evidence")
	}
	file, err := os.Create(path)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, file.Close()) })
	prom := newMockHttpHandler(t)
	promPort := prom.Start()
	t.Cleanup(prom.Close)
	backend := newMockHttpHandler(t)
	backendPort := backend.Start()
	t.Cleanup(backend.Close)
	peer := newMockHttpHandler(t)
	peer.statusCode.Store(http.StatusInternalServerError)
	peerPort := peer.Start()
	t.Cleanup(peer.Close)
	setBody := func(handler *mockHttpHandler, body string) {
		f := func(string) string { return body }
		handler.getRespBody.Store(&f)
	}
	setBody(backend, "memory_input 10\n")
	setProm := func(value int, empty bool) {
		body := fmt.Sprintf(`{"status":"success","data":{"resultType":"vector","result":[{"metric":{"instance":"a"},"value":[1,"%d"]}]}}`, value)
		if empty {
			body = `{"status":"success","data":{"resultType":"vector","result":[]}}`
		}
		setBody(prom, body)
	}
	suite := newEtcdTestSuite(t)
	t.Cleanup(suite.close)
	lg, _ := logger.CreateLoggerForTest(t)
	cfg := config.NewConfig()
	health := &config.HealthCheck{MetricsTimeout: 3 * time.Second, DialTimeout: 2 * time.Second, RetryInterval: time.Millisecond}
	reader := NewDefaultMetricsReader(lg, newMockPromFetcher(promPort), newMockBackendFetcher(map[string]*infosync.TiDBTopologyInfo{"sql": {IP: "127.0.0.1", StatusPort: uint(backendPort)}}, nil), httputil.NewHTTPClient(func() *tls.Config { return nil }), suite.client, health, newMockConfigGetter(cfg))
	require.NoError(t, reader.backendReader.Start(context.Background()))
	t.Cleanup(reader.Close)
	reader.AddQueryExpr("memory", QueryExpr{PromQL: "memory_input"}, QueryRule{Names: []string{"memory_input"}, Retention: time.Minute, Metric2Value: func(families map[string]*dto.MetricFamily) model.SampleValue {
		return model.SampleValue(*families["memory_input"].Metric[0].Untyped.Value)
	}, Range2Value: func(pairs []model.SamplePair) model.SampleValue { return pairs[len(pairs)-1].Value }, ResultType: model.ValVector})
	require.Eventually(t, func() bool { return reader.backendReader.isOwner.Load() }, 3*time.Second, 10*time.Millisecond)
	type step struct {
		Kind    string `json:"kind"`
		Value   *int   `json:"value"`
		Success bool   `json:"success"`
	}
	actions := make([]step, 0)
	observations := make([]map[string]any, 0)
	read := func(kind string, value *int, success bool) {
		reader.readMetrics(context.Background())
		source := map[int32]string{sourceNone: "none", sourceProm: "prometheus", sourceBackend: "backend"}[reader.source.Load()]
		var result any
		qr := reader.GetQueryResult("memory")
		if !qr.Empty() {
			result = float64(qr.Value.(model.Vector)[0].Value)
		}
		actions = append(actions, step{kind, value, success})
		observations = append(observations, map[string]any{"source": source, "value": result})
	}
	ten, twenty, thirty, forty := 10, 20, 30, 40
	setProm(ten, false)
	read("prom", &ten, true)
	setProm(0, true)
	read("prom", nil, true)
	// nil fetcher is an actual ErrNoProm path, not a synthetic successful empty read.
	reader.promReader.promFetcher = nil
	read("backend", &ten, true)
	suite.putKV(readerOwnerKeyPrefix+"/remote/owner/test", fmt.Sprintf("127.0.0.1:%d", peerPort))
	setBody(backend, "memory_input 20\n")
	read("backend", &twenty, false)
	reader.promReader.promFetcher = newMockPromFetcher(promPort)
	setProm(thirty, false)
	read("prom", &thirty, true)
	prom.statusCode.Store(http.StatusInternalServerError)
	setBody(backend, "memory_input 40\n")
	read("backend", &forty, false)
	require.NoError(t, json.NewEncoder(file).Encode(map[string]any{"name": "real-go-source-sequence", "op": "source", "input": actions, "expected": observations}))
}

func TestCPMetricsPromWireObservation(t *testing.T) {
	path := os.Getenv("CPMETRICS_PROM_OUTPUT")
	if path == "" {
		t.Skip("run make controlplane-cpmetrics-evidence")
	}
	file, err := os.Create(path)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, file.Close()) })
	enc := json.NewEncoder(file)
	server := newMockHttpHandler(t)
	port := server.Start()
	t.Cleanup(server.Close)
	bodies := []string{
		`{"status":"success","data":{"resultType":"matrix","result":[{"metric":{"instance":"a","job":"tidb"},"values":[[1.001,"0.2"],[2.9999,"NaN"],[3,"+Inf"]]}]}}`,
		`{"status":"success","data":{"resultType":"matrix","result":[{"metric":{"instance":"a"},"values":[]}]}}`,
		`{"status":"success","data":{"resultType":"vector","result":[]}}`,
		`{"status":"success","data":{"resultType":"vector","result":[{"metric":{"instance":"a"},"value":[1,"2"]},{"metric":{"instance":"a"},"value":[1,"3"]}]}}`,
		`{"status":"error","errorType":"bad_data","error":"fixture"}`,
		`{"status":"success","data":{"resultType":"matrix","result":[{"metric":{"instance":"a"},"values":[[1e3,"2"]]}]}}`,
		`{"status":"success","data":{"resultType":"vector","result":[{"metric":{"instance":"a"},"value":[1,2]}]}}`,
	}
	for i, body := range bodies {
		f := func(string) string { return body }
		server.getRespBody.Store(&f)
		policy := config.NewDefaultHealthCheckConfig()
		reader := NewPromReader(zap.NewNop(), newMockPromFetcher(port), policy)
		reader.clusterName = "real-cluster"
		reader.AddQueryExpr("cpu", QueryExpr{PromQL: "fixture"})
		err := reader.ReadMetrics(context.Background())
		var expected any
		var updated int64
		if err != nil {
			expected = map[string]any{"error": true}
		} else {
			result := reader.GetQueryResult("cpu")
			updated = result.UpdateTime.UnixNano()
			expected = map[string]any{"kind": result.Value.Type().String(), "data": result.Value, "updated_nanos": updated}
		}
		require.NoError(t, enc.Encode(map[string]any{"name": fmt.Sprintf("actual-prom-wire-%d", i), "op": "prom_decode", "input": map[string]any{"body": body, "cluster": "real-cluster", "updated_nanos": updated}, "expected": expected}))
	}
}
