// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package metricsreader

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pingcap/tiproxy/lib/config"
	httputil "github.com/pingcap/tiproxy/pkg/util/http"
	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/model"
	"github.com/stretchr/testify/require"
	clientv3 "go.etcd.io/etcd/client/v3"
	"go.uber.org/zap"
)

// The collector gate starts this test as a bounded real Go peer. Its control
// surface invokes the existing BackendReader and election implementation; the
// Rust observer supplies requests and checks etcd/HTTP observations directly.
func TestCPMetricsCollectorPeer(t *testing.T) {
	output := os.Getenv("CPMETRICS_COLLECTOR_PEER_FILE")
	if output == "" {
		t.Skip("run make controlplane-cpmetrics-collector-evidence")
	}
	data, err := os.ReadFile(os.Getenv("CP003_CONNECTION_FILE"))
	require.NoError(t, err)
	var connection struct {
		Endpoint string `json:"etcd_endpoint"`
	}
	require.NoError(t, json.Unmarshal(data, &connection))
	cli, err := clientv3.New(clientv3.Config{Endpoints: []string{connection.Endpoint}, DialTimeout: time.Second})
	require.NoError(t, err)
	defer cli.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	cluster := "collector-fixture"
	hc := config.NewDefaultHealthCheckConfig()
	hc.MaxRetries = 0
	hc.DialTimeout = time.Second
	httpClient := httputil.NewHTTPClient(func() *tls.Config { return nil })
	cfg := config.NewConfig()
	cfg.Proxy.AdvertiseAddr = "127.0.0.1"
	producer := NewClusterBackendReader(zap.NewNop(), cluster, newMockConfigGetter(cfg), httpClient, cli, nil, hc)
	defer producer.Close()
	producer.AddQueryRule("memory", QueryRule{
		Names:     []string{"process_resident_memory_bytes", "tidb_server_memory_quota_bytes"},
		Retention: time.Minute, ResultType: model.ValMatrix,
		Metric2Value: func(families map[string]*dto.MetricFamily) model.SampleValue {
			resident, quota := families["process_resident_memory_bytes"], families["tidb_server_memory_quota_bytes"]
			if resident == nil || quota == nil {
				return 0
			}
			return model.SampleValue(resident.Metric[0].Untyped.GetValue() / quota.Metric[0].Untyped.GetValue())
		},
		Range2Value: func(pairs []model.SamplePair) model.SampleValue { return pairs[len(pairs)-1].Value },
	})
	var historyMu sync.Mutex
	var historyGate chan struct{}
	historyEntered := false
	historyFailure := false
	releaseHistory := func() {
		historyMu.Lock()
		defer historyMu.Unlock()
		if historyGate != nil {
			close(historyGate)
			historyGate = nil
		}
	}
	defer releaseHistory()
	ownerServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != ownerMetricPath {
			http.NotFound(w, r)
			return
		}
		if r.URL.Query().Get("cluster") != cluster {
			return
		}
		historyMu.Lock()
		failed := historyFailure
		historyMu.Unlock()
		if failed {
			http.Error(w, "injected peer dependency failure", http.StatusServiceUnavailable)
			return
		}
		body := producer.GetBackendMetrics()
		historyMu.Lock()
		gate := historyGate
		if gate != nil {
			historyEntered = true
		}
		historyMu.Unlock()
		if gate != nil {
			select {
			case <-gate:
			case <-r.Context().Done():
				return
			}
		}
		_, _ = w.Write(body)
	}))
	defer ownerServer.Close()
	address := strings.TrimPrefix(ownerServer.URL, "http://")
	var mu sync.Mutex
	owners := make(map[string]*BackendReader)
	defer func() {
		for _, owner := range owners {
			owner.Close()
		}
	}()
	done := make(chan struct{})
	var once sync.Once
	control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		query := r.URL.Query()
		emit := func(value any) { _ = json.NewEncoder(w).Encode(value) }
		fail := func(err error) { http.Error(w, err.Error(), http.StatusInternalServerError) }
		switch r.URL.Path {
		case "/fail-history":
			historyMu.Lock()
			historyFailure = query.Get("enabled") == "true"
			historyMu.Unlock()
			emit(true)
		case "/hold-history":
			releaseHistory()
			historyMu.Lock()
			historyGate = make(chan struct{})
			historyEntered = false
			historyMu.Unlock()
			emit(true)
		case "/release-history":
			releaseHistory()
			emit(true)
		case "/history-state":
			historyMu.Lock()
			emit(map[string]bool{"entered": historyEntered})
			historyMu.Unlock()
		case "/campaign":
			zone := query.Get("zone")
			if owners[zone] != nil {
				fail(fmt.Errorf("zone already started"))
				return
			}
			candidate := config.NewConfig()
			candidate.Proxy.AdvertiseAddr = "127.0.0.1"
			candidate.API.Addr = address
			candidate.Labels = map[string]string{config.LocationLabelName: zone}
			reader := NewClusterBackendReader(zap.NewNop(), cluster, newMockConfigGetter(candidate), httpClient, cli, nil, hc)
			if err := reader.Start(ctx); err != nil {
				fail(err)
				return
			}
			owners[zone] = reader
			timer := time.NewTicker(5 * time.Millisecond)
			defer timer.Stop()
			for !reader.isOwner.Load() {
				select {
				case <-ctx.Done():
					fail(ctx.Err())
					return
				case <-r.Context().Done():
					fail(r.Context().Err())
					return
				case <-timer.C:
				}
			}
			emit(map[string]any{"address": address, "zone": zone})
		case "/retire":
			zone := query.Get("zone")
			if reader := owners[zone]; reader != nil {
				reader.Close()
				delete(owners, zone)
			}
			emit(true)
		case "/enumerate":
			zones, addresses, err := producer.queryAllOwners(r.Context())
			if err != nil {
				fail(err)
				return
			}
			slices.Sort(zones)
			slices.Sort(addresses)
			emit(map[string]any{"zones": zones, "addresses": addresses})
		case "/produce":
			labels, err := producer.readFromBackendAddrs(r.Context(), query["backend"])
			if err != nil {
				fail(err)
				return
			}
			if err := producer.marshalHistory(labels); err != nil {
				fail(err)
				return
			}
			_, _ = w.Write(producer.GetBackendMetrics())
		case "/age":
			producer.Lock()
			var selected []string
			for _, histories := range producer.history {
				for label, history := range histories {
					selected = append(selected, label)
					for i := range history.Step1History {
						history.Step1History[i].Timestamp -= model.Time((3 * time.Minute).Milliseconds())
					}
					for i := range history.Step2History {
						history.Step2History[i].Timestamp -= model.Time((3 * time.Minute).Milliseconds())
					}
					histories[label] = history
				}
			}
			producer.Unlock()
			if err := producer.marshalHistory(selected); err != nil {
				fail(err)
				return
			}
			_, _ = w.Write(producer.GetBackendMetrics())
		case "/consume":
			reader := NewClusterBackendReader(zap.NewNop(), cluster, newMockConfigGetter(cfg), httpClient, cli, nil, hc)
			defer reader.Close()
			if err := reader.readFromOwner(r.Context(), query.Get("address")); err != nil {
				fail(err)
				return
			}
			reader.Lock()
			defer reader.Unlock()
			emit(reader.history)
		case "/stop":
			releaseHistory()
			once.Do(func() { close(done) })
			emit(true)
		default:
			http.NotFound(w, r)
		}
	}))
	defer control.Close()
	data, err = json.Marshal(map[string]string{"control_url": control.URL, "owner_address": address})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(output, data, 0o600))
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("collector peer timed out without stop")
	}
}
