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
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	controlpb "github.com/pingcap/tiproxy/pkg/controlbridge/pb"
)

func framed(t *testing.T, envelope *controlpb.ControlEnvelope) []byte {
	t.Helper()
	frame, err := controlpb.MarshalFrame(envelope, defaultMaxFrameBytes)
	if err != nil {
		t.Fatalf("marshal frame: %v", err)
	}
	return frame
}

func routeResult(epoch, generation, requestID, connectionID uint64, assignmentID string, connected bool) *controlpb.ControlEnvelope {
	return &controlpb.ControlEnvelope{
		ControlEpoch: epoch,
		Generation:   generation,
		RequestId:    requestID,
		Body: &controlpb.ControlEnvelope_RouteResult{
			RouteResult: &controlpb.RouteResult{
				ConnectionId: connectionID,
				AssignmentId: assignmentID,
				Connected:    connected,
			},
		},
	}
}

func connectionEvent(epoch, generation, requestID, connectionID uint64, backendID string, kind controlpb.ConnectionEventKind) *controlpb.ControlEnvelope {
	return &controlpb.ControlEnvelope{
		ControlEpoch: epoch,
		Generation:   generation,
		RequestId:    requestID,
		Body: &controlpb.ControlEnvelope_ConnectionEvent{
			ConnectionEvent: &controlpb.ConnectionEvent{
				Kind:       kind,
				Connection: &controlpb.ConnectionIdentity{ConnectionId: connectionID},
				BackendId:  backendID,
			},
		},
	}
}

func heartbeat() *controlpb.ControlEnvelope {
	return &controlpb.ControlEnvelope{
		Body: &controlpb.ControlEnvelope_Heartbeat{Heartbeat: &controlpb.Heartbeat{}},
	}
}

func uint64p(v uint64) *uint64 { return &v }
func stringp(v string) *string { return &v }

// TestExtractFrameFieldsMatchesWire proves the field-level scan reads the exact
// identity of a frame without decoding it into a protobuf value.
func TestExtractFrameFieldsMatchesWire(t *testing.T) {
	rr := framed(t, routeResult(4, 9, 77, 42, "assign-x", true))
	got := extractFrameFields(rr[4:])
	if got.kind != dropRouteResultConnected || got.controlEpoch != 4 || got.generation != 9 ||
		got.requestID != 77 || got.connectionID != 42 || got.assignmentID != "assign-x" {
		t.Fatalf("route result fields mismatch: %+v", got)
	}

	ce := framed(t, connectionEvent(5, 3, 88, 43, "tidb-b", controlpb.ConnectionEventKind_CONNECTION_EVENT_KIND_CLOSED))
	got = extractFrameFields(ce[4:])
	if got.kind != dropConnectionEventClosed || got.controlEpoch != 5 || got.generation != 3 ||
		got.requestID != 88 || got.connectionID != 43 || got.backendID != "tidb-b" {
		t.Fatalf("connection event fields mismatch: %+v", got)
	}

	// A connected=false route result and a non-CLOSED event classify as
	// no drop kind.
	open := extractFrameFields(framed(t, routeResult(1, 1, 1, 1, "a", false))[4:])
	if open.kind != dropNone {
		t.Fatalf("refused route result must not classify as a drop kind: %+v", open)
	}
}

// TestArmRejectsPartialAndIncompatibleSelectors proves the exact-selector
// contract is enforced: a bare kind, a partial identity, an incompatible field,
// a non-positive count, and an unknown JSON field are all refused with 400,
// and none of them arms the dropper.
func TestArmRejectsPartialAndIncompatibleSelectors(t *testing.T) {
	fx := startDropperFixture(t, false)
	bad := []string{
		`{"kind":"route-result-connected"}`,                                                         // bare kind
		`{"kind":"route-result-connected","connection_id":7}`,                                       // missing assignment
		`{"kind":"route-result-connected","assignment_id":"a"}`,                                     // missing connection
		`{"kind":"route-result-connected","connection_id":7,"assignment_id":"a","backend_id":"b"}`,  // forbidden backend
		`{"kind":"route-result-connected","connection_id":0,"assignment_id":"a"}`,                   // zero connection
		`{"kind":"connection-event-closed","connection_id":7}`,                                      // missing backend
		`{"kind":"connection-event-closed","connection_id":7,"backend_id":"b","assignment_id":"a"}`, // forbidden assignment
		`{"kind":"route-result-connected","connection_id":7,"assignment_id":"a","count":0}`,         // non-positive count
		`{"kind":"unknown-kind","connection_id":7,"assignment_id":"a"}`,                             // unknown kind
		`{"kind":"route-result-connected","connection_id":7,"assignment_id":"a","bogus":1}`,         // unknown field
	}
	for _, body := range bad {
		resp, err := http.Post(fx.adminAddr+"/arm", "application/json", bytes.NewReader([]byte(body)))
		if err != nil {
			t.Fatalf("POST /arm: %v", err)
		}
		status := resp.StatusCode
		_ = resp.Body.Close()
		if status != http.StatusBadRequest {
			t.Fatalf("selector %q => status %d, want 400", body, status)
		}
	}
	// None of the rejected requests armed the dropper.
	if getState(t, fx.adminAddr)["armed"] != false {
		t.Fatal("no rejected selector may arm the dropper")
	}
	// A complete, exact selector is accepted.
	ok := `{"kind":"route-result-connected","connection_id":7,"assignment_id":"a-7"}`
	resp, err := http.Post(fx.adminAddr+"/arm", "application/json", bytes.NewReader([]byte(ok)))
	if err != nil {
		t.Fatalf("POST /arm: %v", err)
	}
	status := resp.StatusCode
	_ = resp.Body.Close()
	if status != http.StatusNoContent {
		t.Fatalf("exact selector => status %d, want 204", status)
	}
	if getState(t, fx.adminAddr)["armed"] != true {
		t.Fatal("an exact selector must arm the dropper")
	}
}

// TestSelectorMatchesExactIdentity proves an exact selector never matches a
// same-kind frame with a different connection / assignment / backend.
func TestSelectorMatchesExactIdentity(t *testing.T) {
	target := extractFrameFields(framed(t, routeResult(1, 1, 1, 7, "a-7", true))[4:])
	other := extractFrameFields(framed(t, routeResult(1, 1, 1, 8, "a-8", true))[4:])

	sel := selector{Kind: "route-result-connected", ConnectionID: uint64p(7), AssignmentID: stringp("a-7")}
	if !sel.matches(dropRouteResultConnected, target) {
		t.Fatal("selector must match the exact target")
	}
	if sel.matches(dropRouteResultConnected, other) {
		t.Fatal("selector must NOT match a same-kind frame for another connection")
	}
	// Kind mismatch never matches.
	closed := extractFrameFields(framed(t, connectionEvent(1, 1, 1, 7, "b", controlpb.ConnectionEventKind_CONNECTION_EVENT_KIND_CLOSED))[4:])
	if sel.matches(dropConnectionEventClosed, closed) {
		t.Fatal("a route-result selector must not match a connection event")
	}
}

type dropperFixture struct {
	drop      *dropper
	client    net.Conn
	upstream  <-chan []byte
	adminAddr string
}

func startDropperFixture(t *testing.T, pause bool) *dropperFixture {
	t.Helper()
	// Unix socket paths are bounded (~104 bytes on macOS), so a short
	// /tmp directory is used instead of the long t.TempDir() path.
	dir, err := os.MkdirTemp("/tmp", "cd")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	target := filepath.Join(dir, "u.sock")
	front := filepath.Join(dir, "f.sock")

	upstream := listenUpstream(t, target)

	logger := log.New(os.Stderr, "test: ", 0)
	drop := newDropper(front, target, pause, logger)
	if err := drop.start("127.0.0.1:0"); err != nil {
		t.Fatalf("dropper start: %v", err)
	}
	assertFrontSocketSecure(t, front)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		_ = drop.close(ctx)
	})

	client, err := net.Dial("unix", front)
	if err != nil {
		t.Fatalf("dial front: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	return &dropperFixture{
		drop:      drop,
		client:    client,
		upstream:  upstream,
		adminAddr: "http://" + drop.adminListen.Addr().String(),
	}
}

func listenUpstream(t *testing.T, target string) <-chan []byte {
	t.Helper()
	if err := os.Remove(target); err != nil && !os.IsNotExist(err) {
		t.Fatalf("clear target: %v", err)
	}
	listener, err := net.Listen("unix", target)
	if err != nil {
		t.Fatalf("upstream listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	received := make(chan []byte, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			received <- nil
			return
		}
		defer conn.Close()
		all, _ := io.ReadAll(conn)
		received <- all
	}()
	return received
}

// TestForwardedFramesAreByteIdentical proves that with an exact arm, only the
// targeted frame is dropped and every other frame is forwarded byte-for-byte.
func TestForwardedFramesAreByteIdentical(t *testing.T) {
	fx := startDropperFixture(t, false)
	if err := fx.drop.arm(selector{Kind: "route-result-connected", ConnectionID: uint64p(9), AssignmentID: stringp("a-9")}); err != nil {
		t.Fatalf("arm: %v", err)
	}

	keepFirst := framed(t, heartbeat())
	target := framed(t, routeResult(2, 3, 40, 9, "a-9", true))
	keepEvent := framed(t, connectionEvent(2, 3, 41, 9, "tidb", controlpb.ConnectionEventKind_CONNECTION_EVENT_KIND_OPENED))
	keepRefused := framed(t, routeResult(2, 3, 42, 9, "a-9", false))

	for _, frame := range [][]byte{keepFirst, target, keepEvent, keepRefused} {
		if _, err := fx.client.Write(frame); err != nil {
			t.Fatalf("client write: %v", err)
		}
	}
	if err := fx.client.(*net.UnixConn).CloseWrite(); err != nil {
		t.Fatalf("close write: %v", err)
	}

	got := <-fx.upstream
	want := bytes.Join([][]byte{keepFirst, keepEvent, keepRefused}, nil)
	if !bytes.Equal(got, want) {
		t.Fatalf("upstream bytes mismatch:\n got  %x\n want %x", got, want)
	}
	if n := len(fx.drop.dropped); n != 1 {
		t.Fatalf("dropped = %d, want 1", n)
	}
}

// TestNonTargetConcurrentSameKindNotEaten proves the exact selector protects
// concurrent, same-kind frames — for a different connection AND, critically,
// for the SAME connection under a different assignment — from being eaten.
func TestNonTargetConcurrentSameKindNotEaten(t *testing.T) {
	fx := startDropperFixture(t, false)
	// Arm for the exact (connection 7, assignment a-7).
	if err := fx.drop.arm(selector{Kind: "route-result-connected", ConnectionID: uint64p(7), AssignmentID: stringp("a-7")}); err != nil {
		t.Fatalf("arm: %v", err)
	}

	// Same-kind connected route results that must all be forwarded: a
	// different connection, and — the sharp case — the SAME connection 7
	// under a different assignment (a stale/reissued assignment id).
	otherConn := framed(t, routeResult(1, 1, 50, 8, "a-8", true))
	sameConnOtherAssignment := framed(t, routeResult(1, 1, 51, 7, "a-7-stale", true))
	target := framed(t, routeResult(1, 1, 52, 7, "a-7", true))
	after := framed(t, routeResult(1, 1, 53, 9, "a-9", true))
	for _, frame := range [][]byte{otherConn, sameConnOtherAssignment, target, after} {
		if _, err := fx.client.Write(frame); err != nil {
			t.Fatalf("client write: %v", err)
		}
	}
	if err := fx.client.(*net.UnixConn).CloseWrite(); err != nil {
		t.Fatalf("close write: %v", err)
	}

	got := <-fx.upstream
	want := bytes.Join([][]byte{otherConn, sameConnOtherAssignment, after}, nil)
	if !bytes.Equal(got, want) {
		t.Fatalf("only (connection 7, assignment a-7) must be eaten:\n got  %x\n want %x", got, want)
	}
	if n := len(fx.drop.dropped); n != 1 {
		t.Fatalf("dropped = %d, want exactly 1 (connection 7)", n)
	}
}

// TestDropRecordMatchesWire proves the recorded drop carries the offending
// frame's exact wire identity, and the /state schema exposes it.
func TestDropRecordMatchesWire(t *testing.T) {
	fx := startDropperFixture(t, false)
	if err := fx.drop.arm(selector{Kind: "connection-event-closed", ConnectionID: uint64p(43), BackendID: stringp("tidb-b")}); err != nil {
		t.Fatalf("arm: %v", err)
	}
	target := framed(t, connectionEvent(5, 3, 88, 43, "tidb-b", controlpb.ConnectionEventKind_CONNECTION_EVENT_KIND_CLOSED))
	if _, err := fx.client.Write(target); err != nil {
		t.Fatalf("client write: %v", err)
	}
	if err := fx.client.(*net.UnixConn).CloseWrite(); err != nil {
		t.Fatalf("close write: %v", err)
	}
	<-fx.upstream // drains until EOF (nothing forwarded)

	waitFor(t, fx.adminAddr, func(state map[string]any) bool {
		return state["drop_count"] == float64(1)
	})
	state := getState(t, fx.adminAddr)
	records, ok := state["dropped"].([]any)
	if !ok || len(records) != 1 {
		t.Fatalf("expected one drop record, got %v", state["dropped"])
	}
	rec := records[0].(map[string]any)
	checks := map[string]float64{
		"control_epoch": 5, "generation": 3, "request_id": 88, "connection_id": 43,
	}
	for k, want := range checks {
		if rec[k] != want {
			t.Fatalf("drop record %s = %v, want %v", k, rec[k], want)
		}
	}
	if rec["backend_id"] != "tidb-b" || rec["kind"] != "connection-event-closed" {
		t.Fatalf("drop record identity mismatch: %v", rec)
	}
	// The event log records the arm then the drop, in order.
	events, _ := state["events"].([]any)
	if len(events) < 2 {
		t.Fatalf("expected arm+drop events, got %v", events)
	}
}

// TestPauseAfterDropHoldsUntilReleaseAndReconnect proves the hold blocks
// upstream dials until /release, and that a release advances the reconnect
// count as the recovered session dials again.
func TestPauseAfterDropHoldsUntilReleaseAndReconnect(t *testing.T) {
	fx := startDropperFixture(t, true)
	if err := fx.drop.arm(selector{Kind: "route-result-connected", ConnectionID: uint64p(9), AssignmentID: stringp("a-9")}); err != nil {
		t.Fatalf("arm: %v", err)
	}

	if _, err := fx.client.Write(framed(t, routeResult(1, 1, 40, 9, "a-9", true))); err != nil {
		t.Fatalf("client write: %v", err)
	}
	if got := <-fx.upstream; len(got) != 0 {
		t.Fatalf("upstream saw %x while it should have seen nothing", got)
	}
	waitFor(t, fx.adminAddr, func(state map[string]any) bool {
		return state["held"] == true && state["drop_count"] == float64(1)
	})
	beforeReconnects := getState(t, fx.adminAddr)["reconnect_count"].(float64)

	// A reconnect while held is accepted then immediately closed with no
	// upstream dial.
	held, err := net.Dial("unix", fx.drop.frontPath)
	if err != nil {
		t.Fatalf("dial while held: %v", err)
	}
	buf := make([]byte, 1)
	_ = held.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := held.Read(buf); err != io.EOF {
		t.Fatalf("held connection read = %v, want EOF (accept-then-close)", err)
	}
	_ = held.Close()
	waitFor(t, fx.adminAddr, func(state map[string]any) bool {
		return state["reconnect_count"].(float64) >= beforeReconnects+1
	})

	// Release, then a fresh upstream recorder must receive a forwarded
	// frame — the link recovered — and the release advanced the counters.
	upstreamAfter := listenUpstream(t, fx.drop.target)
	post(t, fx.adminAddr+"/release")
	waitFor(t, fx.adminAddr, func(state map[string]any) bool {
		return state["held"] == false && state["release_count"].(float64) >= 1
	})

	recovered, err := net.Dial("unix", fx.drop.frontPath)
	if err != nil {
		t.Fatalf("dial after release: %v", err)
	}
	defer recovered.Close()
	keep := framed(t, heartbeat())
	if _, err := recovered.Write(keep); err != nil {
		t.Fatalf("post-release write: %v", err)
	}
	if err := recovered.(*net.UnixConn).CloseWrite(); err != nil {
		t.Fatalf("post-release close write: %v", err)
	}
	gotAfter := <-upstreamAfter
	if !bytes.Equal(gotAfter, keep) {
		t.Fatalf("post-release upstream got %x, want %x", gotAfter, keep)
	}
	// The reconnect count advanced across the held dial and the recovered
	// dial — release let the link move forward.
	finalReconnects := getState(t, fx.adminAddr)["reconnect_count"].(float64)
	if finalReconnects < beforeReconnects+2 {
		t.Fatalf("reconnect_count = %v, want >= %v", finalReconnects, beforeReconnects+2)
	}
}

// assertFrontSocketSecure verifies the frozen front-socket invariant: it is a
// socket, mode 0600, owned by the current user.
func assertFrontSocketSecure(t *testing.T, front string) {
	t.Helper()
	info, err := os.Lstat(front)
	if err != nil {
		t.Fatalf("lstat front socket: %v", err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("front path is not a socket: mode %v", info.Mode())
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("front socket mode = %o, want 0600", perm)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("no syscall stat for the front socket")
	}
	if int(stat.Uid) != os.Getuid() {
		t.Fatalf("front socket uid = %d, want %d", stat.Uid, os.Getuid())
	}
}

func waitFor(t *testing.T, adminAddr string, predicate func(map[string]any) bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if predicate(getState(t, adminAddr)) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("state never satisfied predicate: last = %v", getState(t, adminAddr))
}

func getState(t *testing.T, adminAddr string) map[string]any {
	t.Helper()
	resp, err := http.Get(adminAddr + "/state")
	if err != nil {
		t.Fatalf("GET /state: %v", err)
	}
	defer resp.Body.Close()
	var state map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&state); err != nil {
		t.Fatalf("decode /state: %v", err)
	}
	return state
}

func post(t *testing.T, url string) {
	t.Helper()
	resp, err := http.Post(url, "application/json", nil)
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	_ = resp.Body.Close()
}
