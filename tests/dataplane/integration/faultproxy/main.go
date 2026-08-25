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

// faultproxy is a test-only TCP fault injector for the dataplane integration
// topology. It deliberately contains no MySQL protocol implementation.
package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const shutdownTimeout = 5 * time.Second

var proxyV2Signature = [12]byte{0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a}

type faultProxy struct {
	target      string
	proxyV2     bool
	delay       time.Duration
	logger      *log.Logger
	listener    net.Listener
	admin       *http.Server
	adminListen net.Listener
	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup
	dropNext    atomic.Bool
	activeMu    sync.Mutex
	active      map[net.Conn]struct{}
	closeOnce   sync.Once
}

func newFaultProxy(target string, proxyV2 bool, delay time.Duration, logger *log.Logger) *faultProxy {
	ctx, cancel := context.WithCancel(context.Background())
	return &faultProxy{
		target:  target,
		proxyV2: proxyV2,
		delay:   delay,
		logger:  logger,
		ctx:     ctx,
		cancel:  cancel,
		active:  make(map[net.Conn]struct{}),
	}
}

func (p *faultProxy) start(listenAddr, adminAddr string) error {
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("listen for proxied traffic: %w", err)
	}
	p.listener = listener

	adminListener, err := net.Listen("tcp", adminAddr)
	if err != nil {
		_ = listener.Close()
		return fmt.Errorf("listen for admin traffic: %w", err)
	}
	p.adminListen = adminListener

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", p.handleHealth)
	mux.HandleFunc("/state", p.handleState)
	mux.HandleFunc("/fault/drop-next", p.handleDropNext)
	mux.HandleFunc("/fault/reset", p.handleReset)
	p.admin = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 2 * time.Second,
	}

	p.run(func() {
		if serveErr := p.serveTraffic(); serveErr != nil && !errors.Is(serveErr, net.ErrClosed) {
			p.logger.Printf("traffic listener stopped: %v", serveErr)
		}
	})
	p.run(func() {
		if serveErr := p.admin.Serve(adminListener); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			p.logger.Printf("admin listener stopped: %v", serveErr)
		}
	})
	return nil
}

func (p *faultProxy) run(fn func()) {
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		fn()
	}()
}

func (p *faultProxy) serveTraffic() error {
	for {
		conn, err := p.listener.Accept()
		if err != nil {
			return err
		}
		p.run(func() {
			p.handleConnection(conn)
		})
	}
}

func (p *faultProxy) handleConnection(client net.Conn) {
	defer client.Close()
	if p.dropNext.CompareAndSwap(true, false) {
		if tcpConn, ok := client.(*net.TCPConn); ok {
			_ = tcpConn.SetLinger(0)
		}
		return
	}
	if p.delay > 0 {
		timer := time.NewTimer(p.delay)
		select {
		case <-timer.C:
		case <-p.ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return
		}
	}

	dialer := net.Dialer{Timeout: 5 * time.Second}
	upstream, err := dialer.DialContext(p.ctx, "tcp", p.target)
	if err != nil {
		p.logger.Printf("dial target %s: %v", p.target, err)
		return
	}
	defer upstream.Close()
	p.track(client, upstream)
	defer p.untrack(client, upstream)

	if p.proxyV2 {
		header, headerErr := makeProxyV2Header(client.RemoteAddr(), upstream.RemoteAddr())
		if headerErr != nil {
			p.logger.Printf("make PROXY v2 header: %v", headerErr)
			return
		}
		if _, err = upstream.Write(header); err != nil {
			p.logger.Printf("write PROXY v2 header: %v", err)
			return
		}
	}

	done := make(chan struct{}, 2)
	p.run(func() {
		_, _ = io.Copy(upstream, client)
		if tcpConn, ok := upstream.(*net.TCPConn); ok {
			_ = tcpConn.CloseWrite()
		}
		done <- struct{}{}
	})
	p.run(func() {
		_, _ = io.Copy(client, upstream)
		if tcpConn, ok := client.(*net.TCPConn); ok {
			_ = tcpConn.CloseWrite()
		}
		done <- struct{}{}
	})
	<-done
	_ = client.Close()
	_ = upstream.Close()
	<-done
}

func (p *faultProxy) track(conns ...net.Conn) {
	p.activeMu.Lock()
	defer p.activeMu.Unlock()
	for _, conn := range conns {
		p.active[conn] = struct{}{}
	}
}

func (p *faultProxy) untrack(conns ...net.Conn) {
	p.activeMu.Lock()
	defer p.activeMu.Unlock()
	for _, conn := range conns {
		delete(p.active, conn)
	}
}

func (p *faultProxy) resetConnections() int {
	p.activeMu.Lock()
	defer p.activeMu.Unlock()
	count := len(p.active)
	for conn := range p.active {
		_ = conn.Close()
	}
	return count
}

func (p *faultProxy) handleHealth(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		http.Error(writer, "GET required", http.StatusMethodNotAllowed)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(writer, "{\"status\":\"ok\"}\n")
}

func (p *faultProxy) handleState(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		http.Error(writer, "GET required", http.StatusMethodNotAllowed)
		return
	}
	p.activeMu.Lock()
	active := len(p.active) / 2
	p.activeMu.Unlock()
	writer.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(writer).Encode(map[string]any{
		"active_connections": active,
		"drop_next":          p.dropNext.Load(),
		"proxy_v2":           p.proxyV2,
		"target":             p.target,
	})
}

func (p *faultProxy) handleDropNext(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		http.Error(writer, "POST required", http.StatusMethodNotAllowed)
		return
	}
	p.dropNext.Store(true)
	writer.WriteHeader(http.StatusNoContent)
}

func (p *faultProxy) handleReset(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		http.Error(writer, "POST required", http.StatusMethodNotAllowed)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(writer).Encode(map[string]int{"closed_sockets": p.resetConnections()})
}

func (p *faultProxy) close(ctx context.Context) error {
	var closeErr error
	p.closeOnce.Do(func() {
		p.cancel()
		if p.listener != nil {
			closeErr = errors.Join(closeErr, p.listener.Close())
		}
		p.resetConnections()
		if p.admin != nil {
			closeErr = errors.Join(closeErr, p.admin.Shutdown(ctx))
		}
	})
	// Closing both listeners and every tracked socket makes each managed
	// goroutine finite. Waiting here also makes port-release guarantees part of
	// successful shutdown instead of leaving cleanup in an orphan goroutine.
	p.wg.Wait()
	return ignoreClosedErrors(closeErr)
}

func ignoreClosedErrors(err error) error {
	if errors.Is(err, net.ErrClosed) || errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func makeProxyV2Header(src, dst net.Addr) ([]byte, error) {
	srcTCP, ok := src.(*net.TCPAddr)
	if !ok {
		return nil, fmt.Errorf("source address is %T, not TCP", src)
	}
	dstTCP, ok := dst.(*net.TCPAddr)
	if !ok {
		return nil, fmt.Errorf("destination address is %T, not TCP", dst)
	}

	header := append([]byte(nil), proxyV2Signature[:]...)
	header = append(header, 0x21) // version 2, PROXY command
	src4, dst4 := srcTCP.IP.To4(), dstTCP.IP.To4()
	if src4 != nil && dst4 != nil {
		header = append(header, 0x11, 0x00, 0x0c) // INET, STREAM, 12-byte address block
		header = append(header, src4...)
		header = append(header, dst4...)
	} else {
		src16, dst16 := srcTCP.IP.To16(), dstTCP.IP.To16()
		if src16 == nil || dst16 == nil {
			return nil, errors.New("source and destination IP families are incompatible")
		}
		header = append(header, 0x21, 0x00, 0x24) // INET6, STREAM, 36-byte address block
		header = append(header, src16...)
		header = append(header, dst16...)
	}
	ports := make([]byte, 4)
	binary.BigEndian.PutUint16(ports[0:2], uint16(srcTCP.Port))
	binary.BigEndian.PutUint16(ports[2:4], uint16(dstTCP.Port))
	header = append(header, ports...)
	return header, nil
}

func run() error {
	listenAddr := flag.String("listen", "127.0.0.1:6100", "TCP address exposed to test clients")
	adminAddr := flag.String("admin", "127.0.0.1:18474", "HTTP fault-control address")
	targetAddr := flag.String("target", "", "upstream TiProxy address")
	proxyV2 := flag.Bool("proxy-v2", false, "prepend a PROXY protocol v2 header upstream")
	delay := flag.Duration("connect-delay", 0, "delay before opening each upstream connection")
	probeAddr := flag.String("probe", "", "only test whether a TCP address accepts a connection")
	flag.Parse()
	if *probeAddr != "" {
		conn, err := net.DialTimeout("tcp", *probeAddr, 500*time.Millisecond)
		if err != nil {
			return fmt.Errorf("probe %s: %w", *probeAddr, err)
		}
		return conn.Close()
	}
	if *targetAddr == "" {
		return errors.New("--target is required")
	}

	logger := log.New(os.Stderr, "faultproxy: ", log.LstdFlags|log.Lmicroseconds|log.LUTC)
	proxy := newFaultProxy(*targetAddr, *proxyV2, *delay, logger)
	if err := proxy.start(*listenAddr, *adminAddr); err != nil {
		return err
	}
	logger.Printf("ready listen=%s admin=%s target=%s proxy_v2=%t", proxy.listener.Addr(), proxy.adminListen.Addr(), *targetAddr, *proxyV2)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()
	closeCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	return proxy.close(closeCtx)
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
