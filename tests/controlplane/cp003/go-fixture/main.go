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

// The CP-ETCD fixture owns a restartable embedded etcd server. Its loopback
// control API gives the evidence harness deterministic outage, lease-revoke,
// revision-bump, and compaction seams without mocking the Rust client.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	etcdu "github.com/pingcap/tiproxy/pkg/util/etcd"
	clientv3 "go.etcd.io/etcd/client/v3"
	"go.etcd.io/etcd/server/v3/embed"
	"go.uber.org/zap"
)

type fixture struct {
	mu       sync.Mutex
	server   *embed.Etcd
	addr     string
	dataPath string
}

type connectionInfo struct {
	EtcdEndpoint string `json:"etcd_endpoint"`
	ControlURL   string `json:"control_url"`
}

func main() {
	connectionPath := flag.String("connection-file", "", "path for connection JSON")
	dataDir := flag.String("data-dir", "", "embedded etcd data directory")
	flag.Parse()
	if err := run(*connectionPath, *dataDir); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(connectionPath, dataDir string) error {
	if connectionPath == "" || dataDir == "" {
		return fmt.Errorf("connection-file and data-dir are required")
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return fmt.Errorf("create fixture data directory: %w", err)
	}
	f := &fixture{dataPath: filepath.Join(dataDir, "data")}
	if err := f.start("127.0.0.1:0"); err != nil {
		return err
	}
	defer f.close()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("listen control API: %w", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/stop", f.stopHandler)
	mux.HandleFunc("/start", f.startHandler)
	mux.HandleFunc("/revoke", f.revokeHandler)
	mux.HandleFunc("/bump-compact", f.bumpCompactHandler)
	mux.HandleFunc("/status", f.statusHandler)
	server := &http.Server{Handler: mux, ReadHeaderTimeout: time.Second}
	go func() {
		_ = server.Serve(listener)
	}()
	defer server.Close()

	info := connectionInfo{
		EtcdEndpoint: f.addr,
		ControlURL:   "http://" + listener.Addr().String(),
	}
	data, err := json.Marshal(info)
	if err != nil {
		return fmt.Errorf("encode fixture connection: %w", err)
	}
	if err := os.WriteFile(connectionPath, append(data, '\n'), 0o600); err != nil {
		return fmt.Errorf("write fixture connection: %w", err)
	}
	select {}
}

func (f *fixture) start(addr string) error {
	server, err := etcdu.CreateEtcdServer(addr, f.dataPath, zap.NewNop())
	if err != nil {
		return fmt.Errorf("start embedded etcd at %s: %w", addr, err)
	}
	f.server = server
	f.addr = server.Clients[0].Addr().String()
	return nil
}

func (f *fixture) close() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.server != nil {
		f.server.Close()
		f.server = nil
	}
}

func (f *fixture) stopHandler(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		http.Error(writer, "POST required", http.StatusMethodNotAllowed)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.server == nil {
		http.Error(writer, "already stopped", http.StatusConflict)
		return
	}
	f.server.Close()
	f.server = nil
	writer.WriteHeader(http.StatusNoContent)
}

func (f *fixture) startHandler(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		http.Error(writer, "POST required", http.StatusMethodNotAllowed)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.server != nil {
		http.Error(writer, "already running", http.StatusConflict)
		return
	}
	if err := f.start(f.addr); err != nil {
		http.Error(writer, err.Error(), http.StatusInternalServerError)
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

func (f *fixture) revokeHandler(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		http.Error(writer, "POST required", http.StatusMethodNotAllowed)
		return
	}
	leaseID, err := strconv.ParseInt(request.URL.Query().Get("lease"), 10, 64)
	if err != nil || leaseID == 0 {
		http.Error(writer, "invalid lease", http.StatusBadRequest)
		return
	}
	if err := f.withClient(func(ctx context.Context, client *clientv3.Client) error {
		_, revokeErr := client.Revoke(ctx, clientv3.LeaseID(leaseID))
		return revokeErr
	}); err != nil {
		http.Error(writer, err.Error(), http.StatusBadGateway)
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

func (f *fixture) bumpCompactHandler(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		http.Error(writer, "POST required", http.StatusMethodNotAllowed)
		return
	}
	var revision int64
	err := f.withClient(func(ctx context.Context, client *clientv3.Client) error {
		for index := 0; index < 8; index++ {
			key := fmt.Sprintf("/tiproxy/cp003/compaction/%d", index)
			response, putErr := client.Put(ctx, key, "bump")
			if putErr != nil {
				return putErr
			}
			revision = response.Header.Revision
		}
		_, compactErr := client.Compact(ctx, revision)
		return compactErr
	})
	if err != nil {
		http.Error(writer, err.Error(), http.StatusBadGateway)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(writer).Encode(map[string]int64{"revision": revision})
}

func (f *fixture) statusHandler(writer http.ResponseWriter, _ *http.Request) {
	f.mu.Lock()
	running := f.server != nil
	f.mu.Unlock()
	writer.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(writer).Encode(map[string]bool{"running": running})
}

func (f *fixture) withClient(operation func(context.Context, *clientv3.Client) error) error {
	f.mu.Lock()
	running := f.server != nil
	addr := f.addr
	f.mu.Unlock()
	if !running {
		return fmt.Errorf("embedded etcd is stopped")
	}
	client, err := etcdu.InitEtcdClientWithAddrs(zap.NewNop(), addr, nil)
	if err != nil {
		return fmt.Errorf("create fixture etcd client: %w", err)
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return operation(ctx, client)
}
