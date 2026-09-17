// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

// controlrejector is a test-only Go control peer that deliberately omits
// RUST_ROUTE_OWNER. It records Rust reconnect attempts that fail the required
// capability assertion, letting the T4 live gate prove that a rejected
// reconnect neither demotes routing to Go nor stops local SQL admission.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"slices"
	"sync"
	"syscall"
	"time"

	controlpb "github.com/pingcap/tiproxy/pkg/controlbridge/pb"
)

const routeOwnerCapability = uint64(controlpb.ControlCapability_CONTROL_CAPABILITY_RUST_ROUTE_OWNER)

type evidence struct {
	Attempts                     uint64 `json:"attempts"`
	MissingCapabilityRejections  uint64 `json:"missing_capability_rejections"`
	UnexpectedNegotiatedSessions uint64 `json:"unexpected_negotiated_sessions"`
	PeerAdvertisedRouteOwner     bool   `json:"peer_advertised_route_owner"`
}

type recorder struct {
	mu    sync.Mutex
	path  string
	state evidence
}

func (r *recorder) update(apply func(*evidence)) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	apply(&r.state)
	data, err := json.Marshal(r.state)
	if err != nil {
		return err
	}
	temporary := r.path + ".tmp"
	if err := os.WriteFile(temporary, append(data, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(temporary, r.path)
}

func main() {
	var socketPath string
	var statePath string
	flag.StringVar(&socketPath, "socket", "", "mode-0600 Unix socket to own")
	flag.StringVar(&statePath, "state", "", "JSON evidence file")
	flag.Parse()
	if socketPath == "" || statePath == "" {
		fatalf("--socket and --state are required")
	}

	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		fatalf("listen: %v", err)
	}
	if err := os.Chmod(socketPath, 0o600); err != nil {
		_ = listener.Close()
		fatalf("chmod socket: %v", err)
	}
	socketInfo, err := os.Lstat(socketPath)
	if err != nil {
		_ = listener.Close()
		fatalf("stat socket: %v", err)
	}
	defer func() {
		_ = listener.Close()
		if current, statErr := os.Lstat(socketPath); statErr == nil && os.SameFile(socketInfo, current) {
			_ = os.Remove(socketPath)
		}
	}()

	record := &recorder{path: statePath}
	if err := record.update(func(*evidence) {}); err != nil {
		fatalf("initialize evidence: %v", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	for ctx.Err() == nil {
		if err := listener.SetDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
			fatalf("set accept deadline: %v", err)
		}
		connection, acceptErr := listener.AcceptUnix()
		if acceptErr != nil {
			var netErr net.Error
			if errors.As(acceptErr, &netErr) && netErr.Timeout() {
				continue
			}
			if ctx.Err() != nil || errors.Is(acceptErr, net.ErrClosed) {
				break
			}
			fatalf("accept: %v", acceptErr)
		}
		if err := rejectRouteOwner(connection, record); err != nil {
			fmt.Fprintf(os.Stderr, "controlrejector attempt: %v\n", err)
		}
		_ = connection.Close()
	}
}

func rejectRouteOwner(connection *net.UnixConn, record *recorder) error {
	var attempt uint64
	if err := record.update(func(state *evidence) {
		state.Attempts++
		attempt = state.Attempts
	}); err != nil {
		return fmt.Errorf("record attempt: %w", err)
	}
	if err := connection.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return err
	}
	local := &controlpb.Hello{
		Role:                     controlpb.Role_ROLE_GO_CONTROL,
		SupportedVersions:        []uint32{controlpb.ProtocolV1},
		Capabilities:             []uint64{4, 5},
		MaxFrameBytes:            controlpb.DefaultMaxFrameBytes,
		ProcessId:                "t4-incompatible-go-peer",
		ProcessStartedUnixMillis: uint64(time.Now().UnixMilli()),
	}
	if err := controlpb.WriteFrame(connection, helloEnvelope(local), controlpb.DefaultMaxFrameBytes); err != nil {
		return fmt.Errorf("write Hello: %w", err)
	}
	peerEnvelope, err := controlpb.ReadFrame(connection, controlpb.DefaultMaxFrameBytes)
	if err != nil {
		return fmt.Errorf("read peer Hello: %w", err)
	}
	peer := peerEnvelope.GetHello()
	if peer == nil || peer.GetRole() != controlpb.Role_ROLE_RUST_DATAPLANE {
		return errors.New("peer did not send a Rust Hello")
	}
	advertised := slices.Contains(peer.GetCapabilities(), routeOwnerCapability)
	if err := record.update(func(state *evidence) {
		state.PeerAdvertisedRouteOwner = state.PeerAdvertisedRouteOwner || advertised
	}); err != nil {
		return fmt.Errorf("record peer capabilities: %w", err)
	}
	ack, err := controlpb.NegotiateHello(local, peer, nil, attempt)
	if err != nil {
		return fmt.Errorf("negotiate incomplete peer: %w", err)
	}
	if err := controlpb.WriteFrame(connection, helloAckEnvelope(ack), ack.GetMaxFrameBytes()); err != nil {
		return fmt.Errorf("write incomplete HelloAck: %w", err)
	}
	if _, err := controlpb.ReadFrame(connection, ack.GetMaxFrameBytes()); err != nil {
		if advertised {
			return record.update(func(state *evidence) { state.MissingCapabilityRejections++ })
		}
		return fmt.Errorf("peer closed without advertising route-owner: %w", err)
	}
	if err := record.update(func(state *evidence) { state.UnexpectedNegotiatedSessions++ }); err != nil {
		return err
	}
	return errors.New("Rust unexpectedly accepted the incomplete peer")
}

func helloEnvelope(hello *controlpb.Hello) *controlpb.ControlEnvelope {
	return &controlpb.ControlEnvelope{
		ProtocolVersion: controlpb.ProtocolV1,
		Priority:        controlpb.Priority_PRIORITY_CRITICAL,
		Body:            &controlpb.ControlEnvelope_Hello{Hello: hello},
	}
}

func helloAckEnvelope(ack *controlpb.HelloAck) *controlpb.ControlEnvelope {
	return &controlpb.ControlEnvelope{
		ProtocolVersion: controlpb.ProtocolV1,
		ControlEpoch:    ack.GetControlEpoch(),
		Priority:        controlpb.Priority_PRIORITY_CRITICAL,
		Body:            &controlpb.ControlEnvelope_HelloAck{HelloAck: ack},
	}
}

func fatalf(format string, values ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", values...)
	os.Exit(1)
}
