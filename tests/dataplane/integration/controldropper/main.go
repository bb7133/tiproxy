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
// Unix-domain socket. It forwards every control frame verbatim EXCEPT the one
// a chaos test explicitly arms it to lose: a Rust->Go frame that matches an
// EXACT selector (kind plus connection/assignment/backend identity) is
// swallowed before it reaches the Go control plane, modeling a control message
// the Go side accepted-as-sent but never observed.
//
// It deliberately implements NO control protocol semantics. It classifies and
// selects a frame by a FIELD-LEVEL bypass scan (protowire tag walk) over the
// exact wire bytes and forwards those exact bytes onward untouched — it never
// re-marshals a protobuf, so a forwarded frame is byte-identical to the one it
// received. Only the Rust->Go direction is inspected; Go->Rust is a raw copy.
//
// An exact selector (rather than a bare kind filter) is required so that a
// concurrent, same-kind frame belonging to a different connection/health probe
// is never eaten by mistake. Every drop is recorded with the offending frame's
// exact wire identity, and an ordered event log plus connect/reconnect/release
// counters give a chaos test the evidence it needs to assert what was lost.
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
	fieldEnvelopeControlEpoch protowire.Number = 2
	fieldEnvelopeGeneration   protowire.Number = 3
	fieldEnvelopeRequestID    protowire.Number = 4
	fieldRouteResult          protowire.Number = 29
	fieldConnectionEvent      protowire.Number = 30
)

// Nested field numbers.
const (
	fieldRouteResultConnectionID protowire.Number = 1
	fieldRouteResultAssignmentID protowire.Number = 2
	fieldRouteResultConnected    protowire.Number = 3

	fieldConnectionEventKind       protowire.Number = 1
	fieldConnectionEventConnection protowire.Number = 2
	fieldConnectionEventBackendID  protowire.Number = 3

	fieldConnectionIdentityConnectionID protowire.Number = 1

	connectionEventKindClosed uint64 = 3 // CONNECTION_EVENT_KIND_CLOSED
)

// dropKind is the class of Rust->Go frame the dropper targets.
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
		return dropNone, fmt.Errorf("unknown drop kind %q", name)
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

// frameFields is the exact wire identity extracted from one Rust->Go frame by
// a single field-level scan. The frame's own bytes remain authoritative; this
// is a read-only projection used for classification, selection, and evidence.
type frameFields struct {
	kind         dropKind
	controlEpoch uint64
	generation   uint64
	requestID    uint64
	connectionID uint64
	assignmentID string
	backendID    string
}

// extractFrameFields walks the top-level envelope tags (and the one nested
// message it needs) without decoding into a protobuf value.
func extractFrameFields(body []byte) frameFields {
	fields := frameFields{kind: dropNone}
	message := body
	for len(message) > 0 {
		number, typ, tagLen := protowire.ConsumeTag(message)
		if tagLen < 0 {
			return fields
		}
		message = message[tagLen:]
		var consumed int
		switch {
		case number == fieldEnvelopeControlEpoch && typ == protowire.VarintType:
			fields.controlEpoch, consumed = protowire.ConsumeVarint(message)
		case number == fieldEnvelopeGeneration && typ == protowire.VarintType:
			fields.generation, consumed = protowire.ConsumeVarint(message)
		case number == fieldEnvelopeRequestID && typ == protowire.VarintType:
			fields.requestID, consumed = protowire.ConsumeVarint(message)
		case number == fieldRouteResult && typ == protowire.BytesType:
			var nested []byte
			nested, consumed = protowire.ConsumeBytes(message)
			if consumed >= 0 {
				fillRouteResult(&fields, nested)
			}
		case number == fieldConnectionEvent && typ == protowire.BytesType:
			var nested []byte
			nested, consumed = protowire.ConsumeBytes(message)
			if consumed >= 0 {
				fillConnectionEvent(&fields, nested)
			}
		default:
			consumed = protowire.ConsumeFieldValue(number, typ, message)
		}
		if consumed < 0 {
			return fields
		}
		message = message[consumed:]
	}
	return fields
}

func fillRouteResult(fields *frameFields, message []byte) {
	var connected bool
	for len(message) > 0 {
		number, typ, tagLen := protowire.ConsumeTag(message)
		if tagLen < 0 {
			return
		}
		message = message[tagLen:]
		var consumed int
		switch {
		case number == fieldRouteResultConnectionID && typ == protowire.VarintType:
			fields.connectionID, consumed = protowire.ConsumeVarint(message)
		case number == fieldRouteResultAssignmentID && typ == protowire.BytesType:
			var value []byte
			value, consumed = protowire.ConsumeBytes(message)
			if consumed >= 0 {
				fields.assignmentID = string(value)
			}
		case number == fieldRouteResultConnected && typ == protowire.VarintType:
			var value uint64
			value, consumed = protowire.ConsumeVarint(message)
			connected = value != 0
		default:
			consumed = protowire.ConsumeFieldValue(number, typ, message)
		}
		if consumed < 0 {
			return
		}
		message = message[consumed:]
	}
	if connected {
		fields.kind = dropRouteResultConnected
	}
}

func fillConnectionEvent(fields *frameFields, message []byte) {
	var eventKind uint64
	for len(message) > 0 {
		number, typ, tagLen := protowire.ConsumeTag(message)
		if tagLen < 0 {
			return
		}
		message = message[tagLen:]
		var consumed int
		switch {
		case number == fieldConnectionEventKind && typ == protowire.VarintType:
			eventKind, consumed = protowire.ConsumeVarint(message)
		case number == fieldConnectionEventConnection && typ == protowire.BytesType:
			var nested []byte
			nested, consumed = protowire.ConsumeBytes(message)
			if consumed >= 0 {
				fields.connectionID = connectionIdentityID(nested)
			}
		case number == fieldConnectionEventBackendID && typ == protowire.BytesType:
			var value []byte
			value, consumed = protowire.ConsumeBytes(message)
			if consumed >= 0 {
				fields.backendID = string(value)
			}
		default:
			consumed = protowire.ConsumeFieldValue(number, typ, message)
		}
		if consumed < 0 {
			return
		}
		message = message[consumed:]
	}
	if eventKind == connectionEventKindClosed {
		fields.kind = dropConnectionEventClosed
	}
}

func connectionIdentityID(message []byte) uint64 {
	for len(message) > 0 {
		number, typ, tagLen := protowire.ConsumeTag(message)
		if tagLen < 0 {
			return 0
		}
		message = message[tagLen:]
		if number == fieldConnectionIdentityConnectionID && typ == protowire.VarintType {
			value, consumed := protowire.ConsumeVarint(message)
			if consumed < 0 {
				return 0
			}
			return value
		}
		consumed := protowire.ConsumeFieldValue(number, typ, message)
		if consumed < 0 {
			return 0
		}
		message = message[consumed:]
	}
	return 0
}

// selector is an EXACT match target: the kind must match, and every specified
// identity field must match too. A same-kind frame for a different connection,
// assignment, or backend is therefore never eaten.
type selector struct {
	Kind         string  `json:"kind"`
	ConnectionID *uint64 `json:"connection_id,omitempty"`
	AssignmentID *string `json:"assignment_id,omitempty"`
	BackendID    *string `json:"backend_id,omitempty"`
	Count        *int64  `json:"count,omitempty"`
}

// validate enforces the EXACT-selector contract per kind so a chaos test can
// never arm a partial selector that would eat the wrong same-kind frame. The
// returned count is the validated drop budget.
func (s *selector) validate() (dropKind, int64, error) {
	kind, err := parseDropKind(s.Kind)
	if err != nil {
		return dropNone, 0, err
	}
	switch kind {
	case dropNone:
		return dropNone, 0, errors.New("arm requires a nonempty kind")
	case dropRouteResultConnected:
		// connection_id is the mandatory exact identity: it is the
		// connection's identity within the Rust lineage and alone
		// discriminates a concurrent same-kind frame for a different
		// connection. assignment_id is OPTIONAL further narrowing —
		// it is unobservable before the frame is sent, so a chaos test
		// that quiesces all other clients and arms count=1 targets the
		// one new connection by id. When supplied, it is still matched
		// strictly (matches() checks every set field). A bare kind with
		// no connection_id stays forbidden.
		if s.ConnectionID == nil || *s.ConnectionID == 0 {
			return dropNone, 0, errors.New("route-result-connected requires a nonzero connection_id")
		}
		if s.AssignmentID != nil && *s.AssignmentID == "" {
			return dropNone, 0, errors.New("route-result-connected forbids an empty assignment_id")
		}
		if s.BackendID != nil {
			return dropNone, 0, errors.New("route-result-connected forbids backend_id")
		}
	case dropConnectionEventClosed:
		if s.ConnectionID == nil || *s.ConnectionID == 0 {
			return dropNone, 0, errors.New("connection-event-closed requires a nonzero connection_id")
		}
		if s.BackendID == nil || *s.BackendID == "" {
			return dropNone, 0, errors.New("connection-event-closed requires a nonempty backend_id")
		}
		if s.AssignmentID != nil {
			return dropNone, 0, errors.New("connection-event-closed forbids assignment_id")
		}
	}
	count := int64(1)
	if s.Count != nil {
		if *s.Count <= 0 {
			return dropNone, 0, errors.New("count must be greater than zero")
		}
		count = *s.Count
	}
	return kind, count, nil
}

func (s *selector) matches(kind dropKind, fields frameFields) bool {
	if fields.kind == dropNone || fields.kind != kind {
		return false
	}
	if s.ConnectionID != nil && *s.ConnectionID != fields.connectionID {
		return false
	}
	if s.AssignmentID != nil && *s.AssignmentID != fields.assignmentID {
		return false
	}
	if s.BackendID != nil && *s.BackendID != fields.backendID {
		return false
	}
	return true
}

// dropRecord captures the exact wire identity of one dropped frame.
type dropRecord struct {
	Seq          uint64 `json:"seq"`
	Kind         string `json:"kind"`
	ControlEpoch uint64 `json:"control_epoch"`
	Generation   uint64 `json:"generation"`
	RequestID    uint64 `json:"request_id"`
	ConnectionID uint64 `json:"connection_id"`
	AssignmentID string `json:"assignment_id"`
	BackendID    string `json:"backend_id"`
}

// event is one ordered entry in the observable timeline.
type event struct {
	Seq    uint64 `json:"seq"`
	Type   string `json:"type"` // arm | drop | release | connect | disconnect
	Detail string `json:"detail,omitempty"`
}

type dropper struct {
	frontPath string
	target    string
	pause     bool
	logger    *log.Logger

	listener    net.Listener
	admin       *http.Server
	adminListen net.Listener

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// Mutable observable state, all under mu.
	mu             sync.Mutex
	armedKind      dropKind
	armedSelector  selector
	armRemaining   int64
	dropped        []dropRecord
	events         []event
	seq            uint64
	connectCount   uint64
	reconnectCount uint64
	releaseCount   uint64
	forwarded      uint64
	held           bool

	activeMu sync.Mutex
	active   map[net.Conn]struct{}

	closeOnce sync.Once
}

func newDropper(frontPath, target string, pause bool, logger *log.Logger) *dropper {
	ctx, cancel := context.WithCancel(context.Background())
	return &dropper{
		frontPath: frontPath,
		target:    target,
		pause:     pause,
		logger:    logger,
		ctx:       ctx,
		cancel:    cancel,
		armedKind: dropNone,
		active:    make(map[net.Conn]struct{}),
	}
}

// arm installs an exact one-shot (or count-bounded) drop selector. It replaces
// any prior arming and records an "arm" event.
func (d *dropper) arm(sel selector) error {
	kind, count, err := sel.validate()
	if err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.armedKind = kind
	d.armedSelector = sel
	d.armRemaining = count
	d.appendEventLocked("arm", fmt.Sprintf("kind=%s count=%d", kind, count))
	return nil
}

func (d *dropper) appendEventLocked(kind, detail string) {
	d.seq++
	d.events = append(d.events, event{Seq: d.seq, Type: kind, Detail: detail})
}

// tryClaimDrop atomically decides whether this frame is dropped and, if so,
// records it — all under the same lock so the selector, budget, records, and
// events stay consistent.
func (d *dropper) tryClaimDrop(fields frameFields) (bool, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.armedKind == dropNone || d.armRemaining <= 0 {
		return false, false
	}
	if !d.armedSelector.matches(d.armedKind, fields) {
		return false, false
	}
	d.armRemaining--
	d.seq++
	record := dropRecord{
		Seq:          d.seq,
		Kind:         fields.kind.String(),
		ControlEpoch: fields.controlEpoch,
		Generation:   fields.generation,
		RequestID:    fields.requestID,
		ConnectionID: fields.connectionID,
		AssignmentID: fields.assignmentID,
		BackendID:    fields.backendID,
	}
	d.dropped = append(d.dropped, record)
	d.events = append(d.events, event{Seq: d.seq, Type: "drop", Detail: fmt.Sprintf(
		"kind=%s conn=%d assignment=%s backend=%s epoch=%d gen=%d req=%d",
		record.Kind, record.ConnectionID, record.AssignmentID, record.BackendID,
		record.ControlEpoch, record.Generation, record.RequestID)})
	pause := d.pause
	if pause {
		d.held = true
	}
	return true, pause
}

func (d *dropper) start(adminAddr string) error {
	// A stale path from a crashed predecessor would make Listen fail.
	// Only a path that is ALREADY a socket is removed here — never a
	// regular file or directory — so a mistargeted front path fails
	// loudly instead of being clobbered. (The run helper additionally
	// asserts PID/lsof ownership before reusing a path.)
	if info, err := os.Lstat(d.frontPath); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return fmt.Errorf("front path %s exists and is not a socket", d.frontPath)
		}
		if err := os.Remove(d.frontPath); err != nil {
			return fmt.Errorf("clear stale front socket: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat front socket: %w", err)
	}
	listener, err := net.Listen("unix", d.frontPath)
	if err != nil {
		return fmt.Errorf("listen on front control socket: %w", err)
	}
	// The control socket must not be reachable by other local users:
	// clamp it to owner-only rw regardless of the process umask.
	if err := os.Chmod(d.frontPath, 0o600); err != nil {
		_ = listener.Close()
		return fmt.Errorf("chmod front socket to 0600: %w", err)
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
	mux.HandleFunc("/arm", d.handleArm)
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

	d.mu.Lock()
	d.connectCount++
	if d.connectCount > 1 {
		d.reconnectCount++
	}
	held := d.held
	if held {
		d.appendEventLocked("connect", "held (no upstream dial)")
	} else {
		d.appendEventLocked("connect", "dialing upstream")
	}
	d.mu.Unlock()
	// Every accepted connection records a matching disconnect, including
	// the held and dial-failure early returns, so the event timeline
	// always pairs connect with disconnect.
	defer func() {
		d.mu.Lock()
		d.appendEventLocked("disconnect", "")
		d.mu.Unlock()
	}()

	// A held link never dials upstream: the Rust reconnect loop keeps
	// finding a front socket that accepts and immediately closes, exactly
	// like a control plane that is up but wedged.
	if held {
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

// pumpInspected forwards Rust->Go frames verbatim, swallowing the one armed
// frame. It preserves bytes exactly: the only thing it ever writes upstream is
// the untouched [prefix|body] it read.
func (d *dropper) pumpInspected(src net.Conn, dst net.Conn) {
	for {
		frame, body, err := readFrame(src)
		if err != nil {
			return
		}
		fields := extractFrameFields(body)
		if dropped, pause := d.tryClaimDrop(fields); dropped {
			d.logger.Printf("dropped %s frame conn=%d assignment=%q backend=%q (%d bytes)",
				fields.kind, fields.connectionID, fields.assignmentID, fields.backendID, len(frame))
			if pause {
				// Model a link that goes down the instant the frame is
				// lost: tear the pair down and refuse to dial again
				// until an admin release.
				_ = src.Close()
				_ = dst.Close()
				return
			}
			continue
		}
		if _, err := dst.Write(frame); err != nil {
			return
		}
		atomic.AddUint64(&d.forwarded, 1)
	}
}

// readFrame reads exactly one length-prefixed control frame and returns both
// the full [prefix|body] slice (for verbatim forwarding) and the body slice
// (for classification).
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

	d.mu.Lock()
	state := map[string]any{
		"target":             d.target,
		"pause_after_drop":   d.pause,
		"armed":              d.armedKind != dropNone && d.armRemaining > 0,
		"arm_kind":           d.armedKind.String(),
		"arm_selector":       d.armedSelector,
		"arm_remaining":      d.armRemaining,
		"dropped":            append([]dropRecord(nil), d.dropped...),
		"drop_count":         len(d.dropped),
		"events":             append([]event(nil), d.events...),
		"connect_count":      d.connectCount,
		"reconnect_count":    d.reconnectCount,
		"release_count":      d.releaseCount,
		"forwarded":          atomic.LoadUint64(&d.forwarded),
		"held":               d.held,
		"active_connections": active,
	}
	d.mu.Unlock()

	writer.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(writer).Encode(state)
}

// handleArm installs an exact one-shot drop selector.
func (d *dropper) handleArm(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		http.Error(writer, "POST required", http.StatusMethodNotAllowed)
		return
	}
	var sel selector
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&sel); err != nil {
		http.Error(writer, fmt.Sprintf("bad arm request: %v", err), http.StatusBadRequest)
		return
	}
	if err := d.arm(sel); err != nil {
		http.Error(writer, err.Error(), http.StatusBadRequest)
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

// handleRelease lifts a post-drop hold so the next Rust reconnect dials
// upstream again — the point where a chaos test lets the control link recover.
func (d *dropper) handleRelease(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		http.Error(writer, "POST required", http.StatusMethodNotAllowed)
		return
	}
	d.mu.Lock()
	wasHeld := d.held
	d.held = false
	d.releaseCount++
	d.appendEventLocked("release", fmt.Sprintf("was_held=%t", wasHeld))
	d.mu.Unlock()
	writer.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(writer).Encode(map[string]bool{"was_held": wasHeld})
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
	pause := flag.Bool("pause-after-drop", false, "tear the link down after a drop and hold reconnects until /release")
	// Optional pre-arming at startup (a chaos test usually arms via POST
	// /arm once it knows the exact connection/assignment/backend).
	dropKindName := flag.String("arm-kind", "", "pre-arm a drop of this kind at startup")
	armConnID := flag.Int64("arm-connection-id", -1, "restrict the pre-armed drop to this connection id")
	armAssignment := flag.String("arm-assignment-id", "", "restrict the pre-armed drop to this assignment id")
	armBackend := flag.String("arm-backend-id", "", "restrict the pre-armed drop to this backend id")
	armCount := flag.Int64("arm-count", 1, "how many matching frames the pre-arm drops")
	flag.Parse()

	if *frontPath == "" {
		return errors.New("--front-socket is required")
	}
	if *targetPath == "" {
		return errors.New("--target-socket is required")
	}

	logger := log.New(os.Stderr, "controldropper: ", log.LstdFlags|log.Lmicroseconds|log.LUTC)
	drop := newDropper(*frontPath, *targetPath, *pause, logger)
	if *dropKindName != "" {
		count := *armCount
		sel := selector{Kind: *dropKindName, Count: &count}
		if *armConnID >= 0 {
			id := uint64(*armConnID)
			sel.ConnectionID = &id
		}
		if *armAssignment != "" {
			sel.AssignmentID = armAssignment
		}
		if *armBackend != "" {
			sel.BackendID = armBackend
		}
		// The pre-arm goes through the same exact-selector validation as
		// POST /arm, so a partial startup selector is rejected too.
		if err := drop.arm(sel); err != nil {
			return err
		}
	}
	if err := drop.start(*adminAddr); err != nil {
		return err
	}
	logger.Printf("ready front=%s admin=%s target=%s pause_after_drop=%t",
		drop.listener.Addr(), drop.adminListen.Addr(), *targetPath, *pause)

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
