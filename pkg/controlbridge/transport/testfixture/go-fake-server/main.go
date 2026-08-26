// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

// Command go-fake-server is a cross-language control-transport test peer.
package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	controlpb "github.com/pingcap/tiproxy/pkg/controlbridge/pb"
)

func main() {
	if err := run(); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "go fake control peer: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var socketPath string
	flag.StringVar(&socketPath, "socket", "", "absolute UDS path")
	flag.Parse()
	if socketPath == "" {
		return errors.New("--socket is required")
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	defer func() {
		_ = listener.Close()
		_ = os.Remove(socketPath)
	}()
	if err := os.Chmod(socketPath, 0o600); err != nil {
		return fmt.Errorf("chmod socket: %w", err)
	}
	conn, err := listener.AcceptUnix()
	if err != nil {
		return fmt.Errorf("accept Rust peer: %w", err)
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return fmt.Errorf("set peer deadline: %w", err)
	}

	localHello := &controlpb.Hello{
		Role:              controlpb.Role_ROLE_GO_CONTROL,
		ProcessId:         "go-cross-language-fake",
		SupportedVersions: []uint32{controlpb.ProtocolV1},
		Capabilities:      []uint64{2, 3, 5, 7},
		MaxFrameBytes:     controlpb.DefaultMaxFrameBytes,
	}
	if err := controlpb.WriteFrame(conn, helloEnvelope(localHello), controlpb.DefaultMaxFrameBytes); err != nil {
		return err
	}
	remoteEnvelope, err := controlpb.ReadFrame(conn, controlpb.DefaultMaxFrameBytes)
	if err != nil {
		return err
	}
	remoteHello := remoteEnvelope.GetHello()
	if remoteHello == nil || remoteHello.GetRole() != controlpb.Role_ROLE_RUST_DATAPLANE {
		return errors.New("expected Rust Hello")
	}
	ack, err := controlpb.NegotiateHello(localHello, remoteHello, []uint64{3}, 101)
	if err != nil {
		return err
	}
	if err := controlpb.WriteFrame(conn, helloAckEnvelope(ack), ack.GetMaxFrameBytes()); err != nil {
		return err
	}
	remoteAckEnvelope, err := controlpb.ReadFrame(conn, ack.GetMaxFrameBytes())
	if err != nil {
		return err
	}
	remoteAck := remoteAckEnvelope.GetHelloAck()
	if remoteAck == nil || remoteAck.GetControlEpoch() != 101 ||
		remoteAck.GetRejectionCode() != controlpb.ErrorCode_ERROR_CODE_OK {
		return errors.New("Rust HelloAck rejected Go selection")
	}

	message, err := controlpb.ReadFrame(conn, ack.GetMaxFrameBytes())
	if err != nil {
		return err
	}
	if message.GetControlEpoch() != 101 || message.GetRouteResult() == nil {
		return errors.New("expected epoch-bound Rust RouteResult")
	}
	return controlpb.WriteFrame(conn, &controlpb.ControlEnvelope{
		ProtocolVersion: controlpb.ProtocolV1,
		ControlEpoch:    101,
		Priority:        controlpb.Priority_PRIORITY_CRITICAL,
		Body: &controlpb.ControlEnvelope_Heartbeat{Heartbeat: &controlpb.Heartbeat{
			MonotonicMillis: 4242,
		}},
	}, ack.GetMaxFrameBytes())
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
