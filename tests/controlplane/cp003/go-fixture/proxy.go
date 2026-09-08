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

package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/pingcap/tiproxy/lib/util/waitgroup"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// Forward actual protobuf frames to embedded etcd. The gate holds a selected
// cleanup RPC before forwarding, without replacing election/lease semantics.
// Neither frames nor credentials are recorded by the fixture.
type rawFrameCodec struct{}

func (rawFrameCodec) Name() string                      { return "proto" }
func (rawFrameCodec) Marshal(value any) ([]byte, error) { return *value.(*[]byte), nil }
func (rawFrameCodec) Unmarshal(data []byte, value any) error {
	*value.(*[]byte) = append((*value.(*[]byte))[:0], data...)
	return nil
}

type cleanupProxy struct {
	server    *grpc.Server
	upstream  *grpc.ClientConn
	workers   waitgroup.WaitGroup
	mu        sync.Mutex
	method    string
	release   chan struct{}
	entered   bool
	completed map[string]int
	started   map[string]int
	forwarded map[string]int
}

func startCleanupProxy(endpoint string, mux *http.ServeMux) (*cleanupProxy, string, error) {
	upstream, err := grpc.NewClient("passthrough:///"+endpoint, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithDefaultCallOptions(grpc.ForceCodec(rawFrameCodec{})))
	if err != nil {
		return nil, "", err
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		_ = upstream.Close()
		return nil, "", err
	}
	p := &cleanupProxy{upstream: upstream, completed: make(map[string]int), started: make(map[string]int), forwarded: make(map[string]int)}
	p.server = grpc.NewServer(grpc.WaitForHandlers(true), grpc.ForceServerCodec(rawFrameCodec{}), grpc.UnknownServiceHandler(p.forward))
	mux.HandleFunc("/hold-cleanup", p.hold)
	mux.HandleFunc("/release-cleanup", p.releaseGate)
	mux.HandleFunc("/cleanup-state", p.state)
	p.workers.Run(func() { _ = p.server.Serve(listener) })
	return p, listener.Addr().String(), nil
}

func (p *cleanupProxy) close() {
	p.server.Stop()
	_ = p.upstream.Close()
	p.workers.Wait()
}

func (p *cleanupProxy) forward(_ any, stream grpc.ServerStream) (result error) {
	method, ok := grpc.MethodFromServerStream(stream)
	if !ok {
		return errors.New("missing RPC method")
	}
	name := method[strings.LastIndex(method, "/")+1:]
	p.mu.Lock()
	p.started[name]++
	var release <-chan struct{}
	if p.method == name && p.release != nil {
		p.entered = true
		release = p.release
	}
	p.mu.Unlock()
	if release != nil {
		select {
		case <-release:
		case <-stream.Context().Done():
			return stream.Context().Err()
		}
	}
	defer func() {
		if result == nil {
			p.mu.Lock()
			p.completed[name]++
			p.mu.Unlock()
		}
	}()
	ctx, cancel := context.WithCancel(stream.Context())
	defer cancel()
	upstream, err := p.upstream.NewStream(ctx, &grpc.StreamDesc{ServerStreams: true, ClientStreams: true}, method)
	if err != nil {
		return err
	}
	p.workers.Run(func() {
		for {
			var frame []byte
			if err := stream.RecvMsg(&frame); err != nil {
				if errors.Is(err, io.EOF) {
					_ = upstream.CloseSend()
				} else {
					cancel()
				}
				return
			}
			p.mu.Lock()
			p.forwarded[name]++
			p.mu.Unlock()
			if err := upstream.SendMsg(&frame); err != nil {
				cancel()
				return
			}
		}
	})
	header, err := upstream.Header()
	if err != nil {
		return err
	}
	if err := stream.SendHeader(header); err != nil {
		return err
	}
	for {
		var frame []byte
		if err := upstream.RecvMsg(&frame); err != nil {
			stream.SetTrailer(upstream.Trailer())
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if err := stream.SendMsg(&frame); err != nil {
			return err
		}
	}
}

func (p *cleanupProxy) hold(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		http.Error(writer, "POST required", http.StatusMethodNotAllowed)
		return
	}
	method := request.URL.Query().Get("rpc")
	if method != "Resign" && method != "LeaseRevoke" {
		http.Error(writer, "invalid cleanup RPC", 400)
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.release != nil {
		close(p.release)
	}
	p.method, p.entered, p.release = method, false, make(chan struct{})
	p.completed = make(map[string]int)
}

func (p *cleanupProxy) releaseGate(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		http.Error(writer, "POST required", http.StatusMethodNotAllowed)
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.release != nil {
		close(p.release)
		p.release = nil
	}
}

func (p *cleanupProxy) state(writer http.ResponseWriter, _ *http.Request) {
	p.mu.Lock()
	defer p.mu.Unlock()
	_ = json.NewEncoder(writer).Encode(map[string]any{"entered": p.entered, "completed": p.completed, "started": p.started, "forwarded": p.forwarded})
}
