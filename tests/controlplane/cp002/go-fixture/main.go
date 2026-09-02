// Copyright 2026 PingCAP, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// The CP-002 Go fixture runs the production etcd/HTTP/DNS clients against real
// loopback services, emits the baseline observation, and remains alive so the
// evidence harness can SIGKILL and replace the dependency process.
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	stdhttp "net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/cenkalti/backoff/v4"
	etcdu "github.com/pingcap/tiproxy/pkg/util/etcd"
	httputil "github.com/pingcap/tiproxy/pkg/util/http"
	"github.com/pingcap/tiproxy/pkg/util/netutil"
	"go.uber.org/zap"
)

type connectionInfo struct {
	EtcdEndpoint string `json:"etcd_endpoint"`
	HTTPURL      string `json:"http_url"`
	HTTPPort     uint16 `json:"http_port"`
}

type observationSet struct {
	SchemaVersion int           `json:"schema_version"`
	Producer      string        `json:"producer"`
	Observations  []observation `json:"observations"`
}

type observation struct {
	ScenarioID string    `json:"scenario_id"`
	Step       uint32    `json:"step"`
	Contracts  []string  `json:"contracts"`
	Subject    subject   `json:"subject"`
	Outcome    string    `json:"outcome"`
	Effects    []string  `json:"effects"`
	State      []field   `json:"state"`
	Counters   []counter `json:"counters"`
}

type subject struct {
	Namespace  string `json:"namespace"`
	Cluster    string `json:"cluster"`
	Generation uint64 `json:"generation"`
}

type field struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type counter struct {
	Key   string `json:"key"`
	Value int64  `json:"value"`
}

func main() {
	addr := flag.String("addr", "127.0.0.1:0", "etcd listen address")
	connectionPath := flag.String("connection-file", "", "path for connection JSON")
	observationPath := flag.String("observation-file", "", "path for baseline JSON")
	dataDir := flag.String("data-dir", "", "embedded etcd data directory")
	generation := flag.Uint64("generation", 1, "dependency process generation")
	flag.Parse()
	if err := run(*addr, *connectionPath, *observationPath, *dataDir, *generation); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(addr, connectionPath, observationPath, dataDir string, generation uint64) error {
	if connectionPath == "" || observationPath == "" || dataDir == "" || generation == 0 {
		return fmt.Errorf("connection-file, observation-file, data-dir, and nonzero generation are required")
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return fmt.Errorf("create etcd data directory: %w", err)
	}
	server, err := etcdu.CreateEtcdServer(addr, filepath.Join(dataDir, "data"), zap.NewNop())
	if err != nil {
		return fmt.Errorf("start embedded etcd fixture: %w", err)
	}
	defer server.Close()
	etcdEndpoint := server.Clients[0].Addr().String()

	httpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("listen HTTP fixture: %w", err)
	}
	mux := stdhttp.NewServeMux()
	mux.HandleFunc("/cp002", func(writer stdhttp.ResponseWriter, _ *stdhttp.Request) {
		writer.Header().Set("Content-Type", "text/plain")
		_, _ = writer.Write([]byte("cp002"))
	})
	httpServer := &stdhttp.Server{Handler: mux, ReadHeaderTimeout: time.Second}
	go func() {
		_ = httpServer.Serve(httpListener)
	}()
	defer httpServer.Close()
	host, portText, err := net.SplitHostPort(httpListener.Addr().String())
	if err != nil {
		return fmt.Errorf("parse HTTP fixture address: %w", err)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		return fmt.Errorf("parse HTTP fixture port: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	etcdClient, err := etcdu.InitEtcdClientWithAddrs(zap.NewNop(), etcdEndpoint, nil)
	if err != nil {
		return fmt.Errorf("start production Go etcd client: %w", err)
	}
	defer etcdClient.Close()
	key := fmt.Sprintf("/tiproxy/cp002/%d/go", generation)
	if _, err := etcdClient.Put(ctx, key, "cp002"); err != nil {
		return fmt.Errorf("Go etcd put: %w", err)
	}
	get, err := etcdClient.Get(ctx, key)
	if err != nil || len(get.Kvs) != 1 || string(get.Kvs[0].Value) != "cp002" {
		return fmt.Errorf("Go etcd get mismatch: %w", err)
	}
	if _, err := etcdClient.Delete(ctx, key); err != nil {
		return fmt.Errorf("Go etcd delete: %w", err)
	}

	httpClient := httputil.NewHTTPClient(func() *tls.Config { return nil })
	body, err := httpClient.Get(
		httpListener.Addr().String(),
		"/cp002",
		backoff.WithMaxRetries(backoff.NewConstantBackOff(time.Millisecond), 0),
		5*time.Second,
	)
	if err != nil || string(body) != "cp002" {
		return fmt.Errorf("Go HTTP body mismatch: %w", err)
	}
	dnsDialer := netutil.NewDNSDialer(nil)
	connection, err := dnsDialer.DialContext(ctx, "tcp", net.JoinHostPort("localhost", portText))
	if err != nil {
		return fmt.Errorf("Go DNS dial: %w", err)
	}
	if err := connection.Close(); err != nil {
		return fmt.Errorf("close Go DNS probe: %w", err)
	}

	info := connectionInfo{
		EtcdEndpoint: etcdEndpoint,
		HTTPURL:      "http://" + net.JoinHostPort(host, portText) + "/cp002",
		HTTPPort:     uint16(port),
	}
	if err := writeJSON(connectionPath, info); err != nil {
		return err
	}
	outcome := "connected"
	if generation > 1 {
		outcome = "reconnected"
	}
	set := observationSet{
		SchemaVersion: 1,
		Producer:      "go",
		Observations: []observation{{
			ScenarioID: "CP-FAULT-EXTERNAL-PROCESS-RESTART",
			Step:       uint32(generation - 1),
			Contracts:  []string{"CP-EXT-001"},
			Subject: subject{
				Namespace:  "process",
				Cluster:    "loopback",
				Generation: generation,
			},
			Outcome: outcome,
			Effects: []string{
				"dns_resolution_succeeded",
				"etcd_kv_round_trip",
				"http_bounded_body",
			},
			State: []field{
				{Key: "cancellation_state", Value: "owner_current"},
				{Key: "dependency", Value: "dns,etcd,http"},
				{Key: "endpoint_address", Value: "loopback"},
			},
			Counters: []counter{
				{Key: "deadline_millis", Value: 5000},
				{Key: "http_body_bytes", Value: int64(len(body))},
				{Key: "retry_count", Value: 0},
			},
		}},
	}
	if err := writeJSON(observationPath, set); err != nil {
		return err
	}
	select {}
}

func writeJSON(path string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("encode %s: %w", path, err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}
