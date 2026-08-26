// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	controlpb "github.com/pingcap/tiproxy/pkg/controlbridge/pb"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestServerHandshakeLifecycleAndReconnect(t *testing.T) {
	received := make(chan *controlpb.ControlEnvelope, 4)
	server, cancel, serveErr := startTestServer(t, testServerConfig(t), HandlerFunc(func(
		_ context.Context,
		_ *Session,
		envelope *controlpb.ControlEnvelope,
	) error {
		received <- envelope
		return nil
	}))
	t.Cleanup(func() {
		cancel()
		require.NoError(t, server.Close())
		require.NoError(t, <-serveErr)
	})

	info, err := os.Lstat(server.config.SocketPath)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm())

	peer, ack := connectPeer(t, server.config.SocketPath, rustHello(1), true)
	first := waitActive(t, server)
	require.Equal(t, first.Epoch(), ack.GetControlEpoch())
	require.True(t, first.HasCapability(1))
	require.True(t, first.HasCapability(2), "cap 3 requires cap 2 (closure)")
	require.True(t, first.HasCapability(3))

	peerHeartbeat := &controlpb.ControlEnvelope{
		ProtocolVersion: controlpb.ProtocolV1,
		ControlEpoch:    first.Epoch(),
		Priority:        controlpb.Priority_PRIORITY_CRITICAL,
		Body:            &controlpb.ControlEnvelope_Heartbeat{Heartbeat: &controlpb.Heartbeat{LastReceivedRequestId: 55}},
	}
	require.NoError(t, controlpb.WriteFrame(peer, peerHeartbeat, controlpb.DefaultMaxFrameBytes))
	select {
	case envelope := <-received:
		require.Equal(t, uint64(55), envelope.GetHeartbeat().GetLastReceivedRequestId())
	case <-time.After(time.Second):
		require.Fail(t, "handler did not receive peer heartbeat")
	}

	drain := &controlpb.ControlEnvelope{
		Priority: controlpb.Priority_PRIORITY_CRITICAL,
		Body: &controlpb.ControlEnvelope_DrainCommand{DrainCommand: &controlpb.DrainCommand{
			DrainId: "drain-1",
		}},
	}
	require.NoError(t, first.Send(t.Context(), drain))
	serverMessage := readUntil(t, peer, func(envelope *controlpb.ControlEnvelope) bool {
		return envelope.GetDrainCommand() != nil
	})
	require.Equal(t, first.Epoch(), serverMessage.GetControlEpoch())

	require.NoError(t, peer.Close())
	require.Eventually(t, func() bool { return server.Active() == nil }, time.Second, 10*time.Millisecond)
	secondPeer, secondAck := connectPeer(t, server.config.SocketPath, rustHello(1), false)
	second := waitActive(t, server)
	require.Greater(t, second.Epoch(), first.Epoch())
	require.Equal(t, second.Epoch(), secondAck.GetControlEpoch())
	require.NoError(t, secondPeer.Close())
}

func TestServerRejectsDuplicateVersionAndCredential(t *testing.T) {
	server, cancel, serveErr := startTestServer(t, testServerConfig(t), nil)
	firstPeer, _ := connectPeer(t, server.config.SocketPath, rustHello(1), false)
	first := waitActive(t, server)

	duplicate, duplicateAck := attemptPeer(t, server.config.SocketPath, rustHello(1), false)
	require.Equal(t, controlpb.ErrorCode_ERROR_CODE_PROTOCOL_VIOLATION, duplicateAck.GetRejectionCode())
	require.Same(t, first, server.Active())
	require.NoError(t, duplicate.Close())
	require.NoError(t, firstPeer.Close())
	require.Eventually(t, func() bool { return server.Active() == nil }, time.Second, 10*time.Millisecond)
	cancel()
	require.NoError(t, server.Close())
	require.NoError(t, <-serveErr)

	versionServer, versionCancel, versionErr := startTestServer(t, testServerConfig(t), nil)
	invalidVersion, versionAck := attemptPeer(t, versionServer.config.SocketPath, rustHello(2), false)
	require.Equal(t, controlpb.ErrorCode_ERROR_CODE_UNSUPPORTED_VERSION, versionAck.GetRejectionCode())
	require.NoError(t, invalidVersion.Close())
	versionCancel()
	require.NoError(t, versionServer.Close())
	require.NoError(t, <-versionErr)

	credentialConfig := testServerConfig(t)
	wrongUID := uint32(os.Getuid() + 1)
	credentialConfig.AllowedUID = &wrongUID
	credentialServer, credentialCancel, credentialErr := startTestServer(t, credentialConfig, nil)
	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: credentialConfig.SocketPath, Net: "unix"})
	require.NoError(t, err)
	_, err = controlpb.ReadFrame(conn, controlpb.DefaultMaxFrameBytes)
	require.Error(t, err)
	require.NoError(t, conn.Close())
	credentialCancel()
	require.NoError(t, credentialServer.Close())
	require.NoError(t, <-credentialErr)
}

func TestServerSlowAndInvalidPeersExitAndRejoin(t *testing.T) {
	config := testServerConfig(t)
	config.PeerTimeout = 80 * time.Millisecond
	config.WriteTimeout = 80 * time.Millisecond
	config.QueueLimits = QueueLimits{
		Critical: QueueLimit{Messages: 32, Bytes: 2 * 1024 * 1024},
		Control:  QueueLimit{Messages: 32, Bytes: 8 * 1024 * 1024},
		Bulk:     QueueLimit{Messages: 8, Bytes: 2 * 1024 * 1024},
	}
	server, cancel, serveErr := startTestServer(t, config, nil)
	t.Cleanup(func() {
		cancel()
		require.NoError(t, server.Close())
		require.NoError(t, <-serveErr)
	})

	slowWriter, _ := connectPeer(t, config.SocketPath, rustHello(1), false)
	slowWriterSession := waitActive(t, server)
	var prefix [4]byte
	binary.BigEndian.PutUint32(prefix[:], 128)
	_, err := slowWriter.Write(append(prefix[:], 1))
	require.NoError(t, err)
	select {
	case <-slowWriterSession.Done():
	case <-time.After(time.Second):
		require.Fail(t, "partial peer frame did not time out")
	}
	require.NoError(t, slowWriter.Close())
	require.Eventually(t, func() bool { return server.Active() == nil }, time.Second, 10*time.Millisecond)

	oversizedPeer, _ := connectPeer(t, config.SocketPath, rustHello(1), false)
	oversizedSession := waitActive(t, server)
	binary.BigEndian.PutUint32(prefix[:], controlpb.DefaultMaxFrameBytes+1)
	_, err = oversizedPeer.Write(prefix[:])
	require.NoError(t, err)
	select {
	case <-oversizedSession.Done():
	case <-time.After(time.Second):
		require.Fail(t, "oversized peer frame did not close session")
	}
	require.NoError(t, oversizedPeer.Close())
	require.Eventually(t, func() bool { return server.Active() == nil }, time.Second, 10*time.Millisecond)

	slowReader, _ := connectPeer(t, config.SocketPath, rustHello(1), false)
	slowReaderSession := waitActive(t, server)
	large := &controlpb.ControlEnvelope{
		Priority: controlpb.Priority_PRIORITY_CONTROL,
		Body: &controlpb.ControlEnvelope_Error{Error: &controlpb.ProtocolError{
			Detail: strings.Repeat("x", 512*1024),
		}},
	}
	for range 8 {
		ctx, sendCancel := context.WithTimeout(t.Context(), time.Second)
		sendErr := slowReaderSession.Send(ctx, large)
		sendCancel()
		if sendErr != nil && !errors.Is(sendErr, ErrTransportClosed) {
			require.NoError(t, sendErr)
		}
	}
	select {
	case <-slowReaderSession.Done():
	case <-time.After(2 * time.Second):
		require.Fail(t, "slow reader did not hit write deadline")
	}
	require.NoError(t, slowReader.Close())

	reconnected, _ := connectPeer(t, config.SocketPath, rustHello(1), false)
	waitActive(t, server)
	require.NoError(t, reconnected.Close())
}

func startTestServer(
	t *testing.T,
	config ServerConfig,
	handler Handler,
) (*Server, context.CancelFunc, <-chan error) {
	t.Helper()
	server, err := Listen(config, handler)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	serveErr := make(chan error, 1)
	go func() { serveErr <- server.Serve(ctx) }()
	return server, cancel, serveErr
}

func testServerConfig(t *testing.T) ServerConfig {
	t.Helper()
	return ServerConfig{
		SocketPath: filepath.Join(shortTempDir(t), "control.sock"),
		LocalHello: &controlpb.Hello{
			Role:              controlpb.Role_ROLE_GO_CONTROL,
			ProcessId:         "go-test",
			SupportedVersions: []uint32{controlpb.ProtocolV1},
			Capabilities:      []uint64{1, 2, 3},
			MaxFrameBytes:     controlpb.DefaultMaxFrameBytes,
		},
		RequiredCapabilities: []uint64{1},
		HandshakeTimeout:     time.Second,
		HeartbeatInterval:    50 * time.Millisecond,
		PeerTimeout:          500 * time.Millisecond,
		WriteTimeout:         500 * time.Millisecond,
	}
}

func rustHello(version uint32) *controlpb.Hello {
	return &controlpb.Hello{
		Role:              controlpb.Role_ROLE_RUST_DATAPLANE,
		ProcessId:         "rust-test",
		SupportedVersions: []uint32{version},
		Capabilities:      []uint64{1, 2, 3},
		MaxFrameBytes:     controlpb.DefaultMaxFrameBytes,
	}
}

func connectPeer(t *testing.T, path string, hello *controlpb.Hello, partial bool) (*net.UnixConn, *controlpb.HelloAck) {
	t.Helper()
	conn, ack := attemptPeer(t, path, hello, partial)
	require.Equal(t, controlpb.ErrorCode_ERROR_CODE_OK, ack.GetRejectionCode())
	peerAck, ok := proto.Clone(ack).(*controlpb.HelloAck)
	require.True(t, ok)
	require.NoError(t, controlpb.WriteFrame(conn, helloAckEnvelope(peerAck), ack.GetMaxFrameBytes()))
	return conn, ack
}

func attemptPeer(t *testing.T, path string, hello *controlpb.Hello, partial bool) (*net.UnixConn, *controlpb.HelloAck) {
	t.Helper()
	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	require.NoError(t, err)
	serverHello, err := controlpb.ReadFrame(conn, controlpb.DefaultMaxFrameBytes)
	require.NoError(t, err)
	require.NotNil(t, serverHello.GetHello())
	frame, err := controlpb.MarshalFrame(helloEnvelope(hello), controlpb.DefaultMaxFrameBytes)
	require.NoError(t, err)
	if partial {
		for _, octet := range frame {
			_, err = conn.Write([]byte{octet})
			require.NoError(t, err)
		}
	} else {
		_, err = conn.Write(frame)
		require.NoError(t, err)
	}
	ackEnvelope, err := controlpb.ReadFrame(conn, controlpb.DefaultMaxFrameBytes)
	require.NoError(t, err)
	require.NotNil(t, ackEnvelope.GetHelloAck())
	return conn, ackEnvelope.GetHelloAck()
}

func waitActive(t *testing.T, server *Server) *Session {
	t.Helper()
	require.Eventually(t, func() bool { return server.Active() != nil }, time.Second, 5*time.Millisecond)
	return server.Active()
}

func readUntil(
	t *testing.T,
	conn *net.UnixConn,
	predicate func(*controlpb.ControlEnvelope) bool,
) *controlpb.ControlEnvelope {
	t.Helper()
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(time.Second)))
	for {
		envelope, err := controlpb.ReadFrame(conn, controlpb.DefaultMaxFrameBytes)
		require.NoError(t, err)
		if predicate(envelope) {
			return envelope
		}
	}
}

func TestListenRejectsExistingPath(t *testing.T) {
	path := filepath.Join(shortTempDir(t), "control.sock")
	require.NoError(t, os.WriteFile(path, bytes.Repeat([]byte{'x'}, 1), 0o600))
	config := testServerConfig(t)
	config.SocketPath = path
	_, err := Listen(config, nil)
	require.Error(t, err)
}

func TestServerCloseCancelsIncompleteHandshake(t *testing.T) {
	config := testServerConfig(t)
	config.HandshakeTimeout = 10 * time.Second
	server, cancel, serveErr := startTestServer(t, config, nil)
	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: config.SocketPath, Net: "unix"})
	require.NoError(t, err)
	_, err = controlpb.ReadFrame(conn, controlpb.DefaultMaxFrameBytes)
	require.NoError(t, err)

	started := time.Now()
	cancel()
	require.NoError(t, server.Close())
	require.Less(t, time.Since(started), time.Second)
	require.NoError(t, <-serveErr)
	require.NoError(t, conn.Close())
}

func shortTempDir(t *testing.T) string {
	t.Helper()
	directory, err := os.MkdirTemp("/tmp", "tpctl-")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, os.RemoveAll(directory)) })
	return directory
}
