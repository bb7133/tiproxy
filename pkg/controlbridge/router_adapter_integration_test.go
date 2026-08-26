// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package controlbridge

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pingcap/tiproxy/pkg/balance/router"
	controlpb "github.com/pingcap/tiproxy/pkg/controlbridge/pb"
	"github.com/pingcap/tiproxy/pkg/controlbridge/transport"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestRouterAdapterWithFakeRustUDSPeer(t *testing.T) {
	handler := &recordingHandler{rt: router.NewStaticRouter([]string{"tidb-uds:4000"})}
	adapter := newTestAdapter(t, handler)
	tempDir, err := os.MkdirTemp("/tmp", "tiproxy-router-adapter-")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, os.RemoveAll(tempDir)) })
	socketPath := filepath.Join(tempDir, "control.sock")
	server, err := transport.Listen(transport.ServerConfig{
		SocketPath: socketPath,
		LocalHello: &controlpb.Hello{
			Role:              controlpb.Role_ROLE_GO_CONTROL,
			ProcessId:         "go-router-adapter-test",
			SupportedVersions: []uint32{controlpb.ProtocolV1},
			Capabilities: []uint64{
				uint64(controlpb.ControlCapability_CONTROL_CAPABILITY_PER_CONNECTION_CLOSE),
				uint64(controlpb.ControlCapability_CONTROL_CAPABILITY_RECONCILE_CONNECTIONS),
			},
			MaxFrameBytes: controlpb.DefaultMaxFrameBytes,
		},
		HandshakeTimeout:  time.Second,
		HeartbeatInterval: time.Second,
		PeerTimeout:       5 * time.Second,
		WriteTimeout:      time.Second,
	}, adapter)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	serveErr := make(chan error, 1)
	go func() { serveErr <- server.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		require.NoError(t, server.Close())
		require.NoError(t, <-serveErr)
	})

	peer, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: socketPath, Net: "unix"})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, peer.Close()) })
	goHelloEnvelope, err := controlpb.ReadFrame(peer, controlpb.DefaultMaxFrameBytes)
	require.NoError(t, err)
	require.Equal(t, controlpb.Role_ROLE_GO_CONTROL, goHelloEnvelope.GetHello().GetRole())
	rustHello := &controlpb.Hello{
		Role:              controlpb.Role_ROLE_RUST_DATAPLANE,
		ProcessId:         "rust-router-adapter-test",
		SupportedVersions: []uint32{controlpb.ProtocolV1},
		Capabilities: []uint64{
			uint64(controlpb.ControlCapability_CONTROL_CAPABILITY_PER_CONNECTION_CLOSE),
			uint64(controlpb.ControlCapability_CONTROL_CAPABILITY_RECONCILE_CONNECTIONS),
		},
		MaxFrameBytes: controlpb.DefaultMaxFrameBytes,
	}
	require.NoError(t, controlpb.WriteFrame(peer, &controlpb.ControlEnvelope{
		ProtocolVersion: controlpb.ProtocolV1,
		Priority:        controlpb.Priority_PRIORITY_CRITICAL,
		Body:            &controlpb.ControlEnvelope_Hello{Hello: rustHello},
	}, controlpb.DefaultMaxFrameBytes))
	ackEnvelope, err := controlpb.ReadFrame(peer, controlpb.DefaultMaxFrameBytes)
	require.NoError(t, err)
	ack := ackEnvelope.GetHelloAck()
	require.Equal(t, controlpb.ErrorCode_ERROR_CODE_OK, ack.GetRejectionCode())
	peerAck, ok := proto.Clone(ack).(*controlpb.HelloAck)
	require.True(t, ok)
	require.NoError(t, controlpb.WriteFrame(peer, &controlpb.ControlEnvelope{
		ProtocolVersion: controlpb.ProtocolV1,
		ControlEpoch:    ack.GetControlEpoch(),
		Priority:        controlpb.Priority_PRIORITY_CRITICAL,
		Body:            &controlpb.ControlEnvelope_HelloAck{HelloAck: peerAck},
	}, ack.GetMaxFrameBytes()))

	writePeerEnvelope(t, peer, ack.GetControlEpoch(), &controlpb.ControlEnvelope{
		RequestId:  1,
		Generation: 7,
		Priority:   controlpb.Priority_PRIORITY_CONTROL,
		Body: &controlpb.ControlEnvelope_HandshakeResponse{HandshakeResponse: &controlpb.HandshakeResponseEvent{
			Connection: testIdentity(100, "0.0.0.0:6000"),
			Handshake:  testHandshake("root"),
		}},
	})
	decision := readPeerResponse(t, peer, func(envelope *controlpb.ControlEnvelope) bool {
		return envelope.GetHandshakeDecision() != nil
	}).GetHandshakeDecision()
	require.True(t, decision.GetAccept())

	writePeerEnvelope(t, peer, ack.GetControlEpoch(), &controlpb.ControlEnvelope{
		RequestId:  2,
		Generation: 7,
		Priority:   controlpb.Priority_PRIORITY_CONTROL,
		Body: &controlpb.ControlEnvelope_RouteRequest{RouteRequest: &controlpb.RouteRequest{
			Connection: testIdentity(100, "0.0.0.0:6000"),
			Handshake:  testHandshake("root"),
		}},
	})
	assignment := readPeerResponse(t, peer, func(envelope *controlpb.ControlEnvelope) bool {
		return envelope.GetRouteAssignment() != nil
	}).GetRouteAssignment()
	require.Equal(t, "tidb-uds:4000", assignment.GetBackendAddress())

	writePeerEnvelope(t, peer, ack.GetControlEpoch(), &controlpb.ControlEnvelope{
		RequestId: 3,
		Priority:  controlpb.Priority_PRIORITY_CRITICAL,
		Body: &controlpb.ControlEnvelope_RouteResult{RouteResult: &controlpb.RouteResult{
			ConnectionId: 100,
			AssignmentId: assignment.GetAssignmentId(),
			Connected:    true,
			Code:         controlpb.ErrorCode_ERROR_CODE_OK,
		}},
	})
	writePeerEnvelope(t, peer, ack.GetControlEpoch(), &controlpb.ControlEnvelope{
		RequestId: 4,
		Priority:  controlpb.Priority_PRIORITY_CONTROL,
		Body: &controlpb.ControlEnvelope_HandshakeResult{HandshakeResult: &controlpb.HandshakeResult{
			ConnectionId:   100,
			BackendId:      assignment.GetBackendId(),
			BackendAddress: assignment.GetBackendAddress(),
			Code:           controlpb.ErrorCode_ERROR_CODE_OK,
		}},
	})
	require.Eventually(t, func() bool { return handler.handshakeCount() == 1 }, time.Second, 10*time.Millisecond)
	require.Equal(t, 1, handler.rt.ConnCount())

	writePeerEnvelope(t, peer, ack.GetControlEpoch(), connectionEvent(100,
		controlpb.ConnectionEventKind_CONNECTION_EVENT_KIND_CLOSED))
	require.Eventually(t, func() bool { return handler.closeCount() == 1 }, time.Second, 10*time.Millisecond)
	require.Equal(t, 0, handler.rt.ConnCount())
}

func writePeerEnvelope(t *testing.T, peer *net.UnixConn, epoch uint64, envelope *controlpb.ControlEnvelope) {
	t.Helper()
	envelope.ProtocolVersion = controlpb.ProtocolV1
	envelope.ControlEpoch = epoch
	require.NoError(t, controlpb.WriteFrame(peer, envelope, controlpb.DefaultMaxFrameBytes))
}

func readPeerResponse(
	t *testing.T,
	peer *net.UnixConn,
	match func(*controlpb.ControlEnvelope) bool,
) *controlpb.ControlEnvelope {
	t.Helper()
	for {
		require.NoError(t, peer.SetReadDeadline(time.Now().Add(time.Second)))
		envelope, err := controlpb.ReadFrame(peer, controlpb.DefaultMaxFrameBytes)
		require.NoError(t, err)
		if match(envelope) {
			return envelope
		}
	}
}
