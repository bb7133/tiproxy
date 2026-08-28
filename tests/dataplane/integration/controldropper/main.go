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

// controldropper is a test-only man-in-the-middle for the Go/Rust control
// Unix-domain socket. It forwards every control frame verbatim EXCEPT the ones
// a chaos test wants to lose: a chosen kind of Rust->Go frame is swallowed
// before it reaches the Go control plane, modeling a control message the Go
// side accepted-as-sent but never observed.
//
// It deliberately implements NO control protocol semantics. It classifies a
// frame by a FIELD-LEVEL bypass scan (protowire tag walk) over the exact wire
// bytes and forwards those exact bytes onward untouched — it never re-marshals
// a protobuf, so a forwarded frame is byte-identical to the one it received.
// Only the Rust->Go direction is inspected; Go->Rust is a raw copy.
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

	"google.golang.org/protobuf/encoding/protowire"
)

const (
	shutdownTimeout = 5 * time.Second
	// defaultMaxFrameBytes mirrors controlpb.DefaultMaxFrameBytes. The
	// dropper does not import the control package so that it stays a pure
	// byte mover; the limit only bounds a single read allocation.
	defaultMaxFrameBytes uint32 = 1024 * 1024
)

// ControlEnvelope top-level field numbers (proto/dataplane/v1/control.proto).
const (
	fieldRouteResult     protowire.Number = 29
	fieldConnectionEvent protowire.Number = 30
)

// Nested discriminant field numbers.
const (
	fieldRouteResultConnected protowire.Number = 3 // RouteResult.connected (bool)
	fieldConnectionEventKind  protowire.Number = 1 // ConnectionEvent.kind (enum)
	connectionEventKindClosed uint64           = 3 // CONNECTION_EVENT_KIND_CLOSED
)

// dropKind is the class of Rust->Go frame the dropper swallows.
type dropKind int

const (
	dropNone dropKind = iota
	dropRouteResultConnected
	dropConnectionEventClosed
)

func parseDropKind(name string) (dropKind, error) {
	switch name {
	case "":
		return dropNone, nil
	case "route-result-connected":
		return dropRouteResultConnected, nil
	case "connection-event-closed":
		return dropConnectionEventClosed, nil
	default:
		return dropNone, fmt.Errorf("unknown --drop-kind %q", name)
	}
}

func (kind dropKind) String() string {
	switch kind {
	case dropRouteResultConnected:
		return "route-result-connected"
	case dropConnectionEventClosed:
		return "connection-event-closed"
	default:
		return "none"
	}
}

// frameMatches reports whether the exact wire bytes of one ControlEnvelope are
// the kind this dropper targets. It walks only the top-level tags and, for a
// candidate body, the one nested discriminant field it needs — never
// unmarshaling into a message value, so the caller's bytes stay authoritative.
func frameMatches(kind dropKind, body []byte) bool {
	switch kind {
	case dropRouteResultConnected:
		nested, ok := lengthDelimitedField(body, fieldRouteResult)
		if !ok {
			return false
		}
		return boolField(nested, fieldRouteResultConnected)
	case dropConnectionEventClosed:
		nested, ok := lengthDelimitedField(body, fieldConnectionEvent)
		if !ok {
			return false
		}
		return varintField(nested, fieldConnectionEventKind) == connectionEventKindClosed
	default:
		return false
	}
}

// lengthDelimitedField returns the value bytes of the first length-delimited
// field with the given number, scanning tags without decoding values.
func lengthDelimitedField(message []byte, want protowire.Number) ([]byte, bool) {
	for len(message) > 0 {
		number, typ, tagLen := protowire.ConsumeTag(message)
		if tagLen < 0 {
			return nil, false
		}
		message = message[tagLen:]
		if number == want && typ == protowire.BytesType {
			value, valueLen := protowire.ConsumeBytes(message)
			if valueLen < 0 {
				return nil, false
			}
			return value, true
		}
		skip := protowire.ConsumeFieldValue(number, typ, message)
		if skip < 0 {
			return nil, false
		}
		message = message[skip:]
	}
	return nil, false
}

// boolField reports whether the first varint field with the given number is a
// nonzero (true) value.
func boolField(message []byte, want protowire.Number) bool {
	return varintField(message, want) != 0
}

// varintField returns the first varint field with the given number, or 0 when
// absent (proto3 scalar default — an omitted field and an explicit zero are
// indistinguishable on the wire, which is exactly the drop semantics we want).
func varintField(message []byte, want protowire.Number) uint64 {
	for len(message) > 0 {
		number, typ, tagLen := protowire.ConsumeTag(message)
		if tagLen < 0 {
			return 0
		}
		message = message[tagLen:]
		if number == want && typ == protowire.VarintType {
			value, valueLen := protowire.ConsumeVarint(message)
			if valueLen < 0 {
				return 0
			}
			return value
		}
		skip := protowire.ConsumeFieldValue(number, typ, message)
		if skip < 0 {
			return 0
		}
		message = message[skip:]
	}
	return 0
}

type dropper struct {
	frontPath string
	target    string
	kind      dropKind
	pause     bool
	logger    *log.Logger

	listener    net.Listener
	admin       *http.Server
	adminListen net.Listener

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	dropRemaining atomic.Int64
	dropped       atomic.Int64
	forwarded     atomic.Int64
	// held is set once a drop happened under --pause-after-drop: new
	// upstream dials are refused until an admin release, modeling a
	// control link that stays down until the test lets it recover.
	held atomic.Bool

	activeMu sync.Mutex
	active   map[net.Conn]struct{}

	closeOnce sync.Once
}

func newDropper(frontPath, target string, kind dropKind, pause bool, dropCount int64, logger *log.Logger) *dropper {
	ctx, cancel := context.WithCancel(context.Background())
	drop := &dropper{
		frontPath: frontPath,
		target:    target,
		kind:      kind,
		pause:     pause,
		logger:    logger,
		ctx:       ctx,
		cancel:    cancel,
		active:    make(map[net.Conn]struct{}),
	}
	drop.dropRemaining.Store(dropCount)
	return drop
}

func (d *dropper) start(adminAddr string) error {
	// A stale socket path from a crashed predecessor would make Listen
	// fail; the caller owns a unique path per run, so removing it here is
	// safe and keeps bring-up deterministic.
	if err := os.Remove(d.frontPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("clear stale front socket: %w", err)
	}
	listener, err := net.Listen("unix", d.frontPath)
	if err != nil {
		return fmt.Errorf("listen on front control socket: %w", err)
	}
	d.listener = listener

	adminListener, err := net.Listen("tcp", adminAddr)
	if err != nil {
		_ = listener.Close()
		return fmt.Errorf("listen for admin traffic: %w", err)
	}
	d.adminListen = adminListener

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", d.handleHealth)
	mux.HandleFunc("/state", d.handleState)
	mux.HandleFunc("/release", d.handleRelease)
	d.admin = &http.Server{Handler: mux, ReadHeaderTimeout: 2 * time.Second}

	d.run(func() {
		if serveErr := d.serve(); serveErr != nil && !errors.Is(serveErr, net.ErrClosed) {
			d.logger.Printf("front listener stopped: %v", serveErr)
		}
	})
	d.run(func() {
		if serveErr := d.admin.Serve(adminListener); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			d.logger.Printf("admin listener stopped: %v", serveErr)
		}
	})
	return nil
}

func (d *dropper) run(fn func()) {
	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		fn()
	}()
}

func (d *dropper) serve() error {
	for {
		client, err := d.listener.Accept()
		if err != nil {
			return err
		}
		d.run(func() {
			d.handleConnection(client)
		})
	}
}

func (d *dropper) handleConnection(client net.Conn) {
	defer client.Close()
	// A held link never dials upstream: the Rust reconnect loop keeps
	// finding a front socket that accepts and immediately closes, exactly
	// like a control plane that is up but wedged.
	if d.held.Load() {
		return
	}
	dialer := net.Dialer{Timeout: 5 * time.Second}
	upstream, err := dialer.DialContext(d.ctx, "unix", d.target)
	if err != nil {
		d.logger.Printf("dial upstream control socket %s: %v", d.target, err)
		return
	}
	defer upstream.Close()
	d.track(client, upstream)
	defer d.untrack(client, upstream)

	done := make(chan struct{}, 2)
	// Rust -> Go: the inspected direction.
	d.run(func() {
		d.pumpInspected(client, upstream)
		if tcpLike, ok := upstream.(interface{ CloseWrite() error }); ok {
			_ = tcpLike.CloseWrite()
		}
		done <- struct{}{}
	})
	// Go -> Rust: a raw copy, never inspected.
	d.run(func() {
		_, _ = io.Copy(client, upstream)
		if tcpLike, ok := client.(interface{ CloseWrite() error }); ok {
			_ = tcpLike.CloseWrite()
		}
		done <- struct{}{}
	})
	<-done
	_ = client.Close()
	_ = upstream.Close()
	<-done
}

// pumpInspected forwards Rust->Go frames verbatim, swallowing frames of the
// configured kind while the drop budget lasts. It preserves bytes exactly: the
// only thing it ever writes upstream is the untouched [prefix|body] it read.
func (d *dropper) pumpInspected(src net.Conn, dst net.Conn) {
	for {
		frame, body, err := readFrame(src)
		if err != nil {
			return
		}
		if d.kind != dropNone && frameMatches(d.kind, body) && d.claimDrop() {
			d.dropped.Add(1)
			d.logger.Printf("dropped %s frame (%d bytes)", d.kind, len(frame))
			if d.pause {
				// Model a link that goes down the instant the frame is
				// lost: tear the pair down and refuse to dial again
				// until an admin release. The dropped frame is gone;
				// the Go side must recover it through reconciliation.
				d.held.Store(true)
				_ = src.Close()
				_ = dst.Close()
				return
			}
			continue
		}
		if _, err := dst.Write(frame); err != nil {
			return
		}
		d.forwarded.Add(1)
	}
}

// claimDrop consumes one unit of the drop budget, returning false once it is
// exhausted so later matching frames flow normally.
func (d *dropper) claimDrop() bool {
	for {
		remaining := d.dropRemaining.Load()
		if remaining <= 0 {
			return false
		}
		if d.dropRemaining.CompareAndSwap(remaining, remaining-1) {
			return true
		}
	}
}

// readFrame reads exactly one length-prefixed control frame and returns both
// the full [prefix|body] slice (for verbatim forwarding) and the body slice
// (for classification). The two share no storage the caller mutates.
func readFrame(reader io.Reader) (frame []byte, body []byte, err error) {
	var prefix [4]byte
	if _, err = io.ReadFull(reader, prefix[:]); err != nil {
		return nil, nil, err
	}
	length := binary.BigEndian.Uint32(prefix[:])
	if length == 0 || length > defaultMaxFrameBytes {
		return nil, nil, fmt.Errorf("invalid control frame length %d", length)
	}
	frame = make([]byte, 4+int(length))
	copy(frame, prefix[:])
	if _, err = io.ReadFull(reader, frame[4:]); err != nil {
		return nil, nil, err
	}
	return frame, frame[4:], nil
}

func (d *dropper) track(conns ...net.Conn) {
	d.activeMu.Lock()
	defer d.activeMu.Unlock()
	for _, conn := range conns {
		d.active[conn] = struct{}{}
	}
}

func (d *dropper) untrack(conns ...net.Conn) {
	d.activeMu.Lock()
	defer d.activeMu.Unlock()
	for _, conn := range conns {
		delete(d.active, conn)
	}
}

func (d *dropper) resetConnections() int {
	d.activeMu.Lock()
	defer d.activeMu.Unlock()
	count := len(d.active)
	for conn := range d.active {
		_ = conn.Close()
	}
	return count
}

func (d *dropper) handleHealth(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		http.Error(writer, "GET required", http.StatusMethodNotAllowed)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(writer, "{\"status\":\"ok\"}\n")
}

func (d *dropper) handleState(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		http.Error(writer, "GET required", http.StatusMethodNotAllowed)
		return
	}
	d.activeMu.Lock()
	active := len(d.active) / 2
	d.activeMu.Unlock()
	writer.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(writer).Encode(map[string]any{
		"drop_kind":          d.kind.String(),
		"dropped":            d.dropped.Load(),
		"drop_remaining":     d.dropRemaining.Load(),
		"forwarded":          d.forwarded.Load(),
		"held":               d.held.Load(),
		"pause_after_drop":   d.pause,
		"active_connections": active,
		"target":             d.target,
	})
}

// handleRelease lifts a post-drop hold so the next Rust reconnect dials
// upstream again — the point where a chaos test lets the control link recover.
func (d *dropper) handleRelease(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		http.Error(writer, "POST required", http.StatusMethodNotAllowed)
		return
	}
	released := d.held.Swap(false)
	writer.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(writer).Encode(map[string]bool{"was_held": released})
}

func (d *dropper) close(ctx context.Context) error {
	var closeErr error
	d.closeOnce.Do(func() {
		d.cancel()
		if d.listener != nil {
			closeErr = errors.Join(closeErr, d.listener.Close())
		}
		d.resetConnections()
		if d.admin != nil {
			closeErr = errors.Join(closeErr, d.admin.Shutdown(ctx))
		}
	})
	d.wg.Wait()
	return ignoreClosedErrors(closeErr)
}

func ignoreClosedErrors(err error) error {
	if errors.Is(err, net.ErrClosed) || errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func run() error {
	frontPath := flag.String("front-socket", "", "Unix socket the Rust dataplane connects to")
	targetPath := flag.String("target-socket", "", "upstream Go control Unix socket")
	adminAddr := flag.String("admin", "127.0.0.1:18575", "HTTP fault-control address")
	dropKindName := flag.String("drop-kind", "", "Rust->Go frame kind to drop: route-result-connected | connection-event-closed")
	dropCount := flag.Int64("drop-count", 1, "maximum number of matching frames to drop")
	pause := flag.Bool("pause-after-drop", false, "tear the link down after a drop and hold reconnects until /release")
	flag.Parse()

	if *frontPath == "" {
		return errors.New("--front-socket is required")
	}
	if *targetPath == "" {
		return errors.New("--target-socket is required")
	}
	kind, err := parseDropKind(*dropKindName)
	if err != nil {
		return err
	}

	logger := log.New(os.Stderr, "controldropper: ", log.LstdFlags|log.Lmicroseconds|log.LUTC)
	drop := newDropper(*frontPath, *targetPath, kind, *pause, *dropCount, logger)
	if err := drop.start(*adminAddr); err != nil {
		return err
	}
	logger.Printf("ready front=%s admin=%s target=%s drop_kind=%s drop_count=%d pause_after_drop=%t",
		drop.listener.Addr(), drop.adminListen.Addr(), *targetPath, kind, *dropCount, *pause)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()
	closeCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	return drop.close(closeCtx)
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
