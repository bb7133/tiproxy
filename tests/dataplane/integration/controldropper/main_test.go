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
	"testing"
	"time"

	controlpb "github.com/pingcap/tiproxy/pkg/controlbridge/pb"
)

// framed encodes one control envelope exactly as the transport writes it.
func framed(t *testing.T, envelope *controlpb.ControlEnvelope) []byte {
	t.Helper()
	frame, err := controlpb.MarshalFrame(envelope, defaultMaxFrameBytes)
	if err != nil {
		t.Fatalf("marshal frame: %v", err)
	}
	return frame
}

func routeResult(connectionID uint64, connected bool) *controlpb.ControlEnvelope {
	return &controlpb.ControlEnvelope{
		RequestId: connectionID,
		Body: &controlpb.ControlEnvelope_RouteResult{
			RouteResult: &controlpb.RouteResult{
				ConnectionId: connectionID,
				AssignmentId: "a-1",
				Connected:    connected,
			},
		},
	}
}

func connectionEvent(kind controlpb.ConnectionEventKind) *controlpb.ControlEnvelope {
	return &controlpb.ControlEnvelope{
		Body: &controlpb.ControlEnvelope_ConnectionEvent{
			ConnectionEvent: &controlpb.ConnectionEvent{
				Kind:      kind,
				BackendId: "tidb-a",
				Namespace: "default",
			},
		},
	}
}

func heartbeat() *controlpb.ControlEnvelope {
	return &controlpb.ControlEnvelope{
		Body: &controlpb.ControlEnvelope_Heartbeat{Heartbeat: &controlpb.Heartbeat{}},
	}
}

// TestFrameMatchesClassifiesByField proves the field-level scan matches
// exactly the targeted kind and nothing adjacent — a connected=false route
// result and a non-CLOSED event are forwarded, not dropped.
func TestFrameMatchesClassifiesByField(t *testing.T) {
	cases := []struct {
		name     string
		kind     dropKind
		envelope *controlpb.ControlEnvelope
		want     bool
	}{
		{"connected route result matches", dropRouteResultConnected, routeResult(9, true), true},
		{"refused route result does not match", dropRouteResultConnected, routeResult(9, false), false},
		{"closed event matches", dropConnectionEventClosed, connectionEvent(controlpb.ConnectionEventKind_CONNECTION_EVENT_KIND_CLOSED), true},
		{"opened event does not match", dropConnectionEventClosed, connectionEvent(controlpb.ConnectionEventKind_CONNECTION_EVENT_KIND_OPENED), false},
		{"heartbeat never matches route kind", dropRouteResultConnected, heartbeat(), false},
		{"connected result is not an event", dropConnectionEventClosed, routeResult(9, true), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body, err := controlpb.MarshalFrame(tc.envelope, defaultMaxFrameBytes)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if got := frameMatches(tc.kind, body[4:]); got != tc.want {
				t.Fatalf("frameMatches = %v, want %v", got, tc.want)
			}
		})
	}
}

// dropperFixture starts a dropper in front of an in-test upstream that records
// every byte it receives, and returns a client connection plus the recorder.
type dropperFixture struct {
	drop      *dropper
	client    net.Conn
	upstream  <-chan []byte
	adminAddr string
}

func startDropperFixture(t *testing.T, kind dropKind, pause bool, dropCount int64) *dropperFixture {
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

	upstreamListener, err := net.Listen("unix", target)
	if err != nil {
		t.Fatalf("upstream listen: %v", err)
	}
	received := make(chan []byte, 1)
	go func() {
		conn, acceptErr := upstreamListener.Accept()
		if acceptErr != nil {
			received <- nil
			return
		}
		defer conn.Close()
		all, _ := io.ReadAll(conn)
		received <- all
	}()

	logger := log.New(os.Stderr, "test: ", 0)
	drop := newDropper(front, target, kind, pause, dropCount, logger)
	if err := drop.start("127.0.0.1:0"); err != nil {
		t.Fatalf("dropper start: %v", err)
	}
	t.Cleanup(func() {
		_ = drop.close(contextWithTimeout(t))
		_ = upstreamListener.Close()
	})

	client, err := net.Dial("unix", front)
	if err != nil {
		t.Fatalf("dial front: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	return &dropperFixture{
		drop:      drop,
		client:    client,
		upstream:  received,
		adminAddr: "http://" + drop.adminListen.Addr().String(),
	}
}

func contextWithTimeout(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	t.Cleanup(cancel)
	return ctx
}

// TestForwardedFramesAreByteIdentical sends a mix of frames and proves the
// upstream received exactly the non-dropped ones, byte-for-byte, in order.
func TestForwardedFramesAreByteIdentical(t *testing.T) {
	fx := startDropperFixture(t, dropRouteResultConnected, false, 1)

	keepFirst := framed(t, heartbeat())
	drop := framed(t, routeResult(9, true))
	keepSecond := framed(t, connectionEvent(controlpb.ConnectionEventKind_CONNECTION_EVENT_KIND_OPENED))
	keepThird := framed(t, routeResult(10, false))

	for _, frame := range [][]byte{keepFirst, drop, keepSecond, keepThird} {
		if _, err := fx.client.Write(frame); err != nil {
			t.Fatalf("client write: %v", err)
		}
	}
	if err := fx.client.(*net.UnixConn).CloseWrite(); err != nil {
		t.Fatalf("close write: %v", err)
	}

	got := <-fx.upstream
	want := bytes.Join([][]byte{keepFirst, keepSecond, keepThird}, nil)
	if !bytes.Equal(got, want) {
		t.Fatalf("upstream bytes mismatch:\n got  %x\n want %x", got, want)
	}
	if dropped := fx.drop.dropped.Load(); dropped != 1 {
		t.Fatalf("dropped = %d, want 1", dropped)
	}
	if forwarded := fx.drop.forwarded.Load(); forwarded != 3 {
		t.Fatalf("forwarded = %d, want 3", forwarded)
	}
}

// TestExactlyOneFrameDropped proves the drop budget is respected: with
// drop-count 1, a second matching frame flows through untouched.
func TestExactlyOneFrameDropped(t *testing.T) {
	fx := startDropperFixture(t, dropConnectionEventClosed, false, 1)

	firstClosed := framed(t, connectionEvent(controlpb.ConnectionEventKind_CONNECTION_EVENT_KIND_CLOSED))
	secondClosed := framed(t, connectionEvent(controlpb.ConnectionEventKind_CONNECTION_EVENT_KIND_CLOSED))
	for _, frame := range [][]byte{firstClosed, secondClosed} {
		if _, err := fx.client.Write(frame); err != nil {
			t.Fatalf("client write: %v", err)
		}
	}
	if err := fx.client.(*net.UnixConn).CloseWrite(); err != nil {
		t.Fatalf("close write: %v", err)
	}

	got := <-fx.upstream
	if !bytes.Equal(got, secondClosed) {
		t.Fatalf("upstream received %x, want the second CLOSED frame %x", got, secondClosed)
	}
	if dropped := fx.drop.dropped.Load(); dropped != 1 {
		t.Fatalf("dropped = %d, want exactly 1", dropped)
	}
}

// TestPauseAfterDropHoldsUntilRelease proves the pause mode tears the pair down
// on a drop, refuses to dial upstream while held, and dials again after
// /release. The upstream sees NOTHING while held (the dropped frame is truly
// lost) and the state endpoint reflects the hold.
func TestPauseAfterDropHoldsUntilRelease(t *testing.T) {
	fx := startDropperFixture(t, dropRouteResultConnected, true, 1)

	// One matching frame: dropped, link torn down, hold engaged.
	if _, err := fx.client.Write(framed(t, routeResult(9, true))); err != nil {
		t.Fatalf("client write: %v", err)
	}
	// The upstream copier ends with no bytes (the drop happened before any
	// forward, then the pair closed).
	got := <-fx.upstream
	if len(got) != 0 {
		t.Fatalf("upstream saw %x while it should have seen nothing", got)
	}

	waitForState(t, fx.adminAddr, func(state map[string]any) bool {
		return state["held"] == true && state["dropped"] == float64(1)
	})

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

	// Release, then a fresh upstream recorder must receive a forwarded
	// frame — the link recovered.
	upstreamAfter := replaceUpstream(t, fx.drop.target)
	post(t, fx.adminAddr+"/release")
	waitForState(t, fx.adminAddr, func(state map[string]any) bool {
		return state["held"] == false
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
}

// replaceUpstream binds a fresh recorder on the same target path after the
// original accepter has consumed its one connection.
func replaceUpstream(t *testing.T, target string) <-chan []byte {
	t.Helper()
	if err := os.Remove(target); err != nil && !os.IsNotExist(err) {
		t.Fatalf("clear target: %v", err)
	}
	listener, err := net.Listen("unix", target)
	if err != nil {
		t.Fatalf("re-listen upstream: %v", err)
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

func waitForState(t *testing.T, adminAddr string, predicate func(map[string]any) bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		state := getState(t, adminAddr)
		if predicate(state) {
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
