// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package controlbridge

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/pingcap/tiproxy/lib/config"
	controlpb "github.com/pingcap/tiproxy/pkg/controlbridge/pb"
	"github.com/pingcap/tiproxy/pkg/controlbridge/transport"
	"google.golang.org/protobuf/proto"
)

func bridgeTransportConfig(t *testing.T) transport.ServerConfig {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "tiproxy-bridge-*")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return transport.ServerConfig{
		SocketPath: filepath.Join(dir, "control.sock"),
		LocalHello: &controlpb.Hello{
			Role:              controlpb.Role_ROLE_GO_CONTROL,
			ProcessId:         "go-bridge-test",
			SupportedVersions: []uint32{controlpb.ProtocolV1},
			Capabilities:      []uint64{1, 2, 3},
			MaxFrameBytes:     controlpb.DefaultMaxFrameBytes,
		},
		RequiredCapabilities: []uint64{1},
		HandshakeTimeout:     time.Second,
		HeartbeatInterval:    50 * time.Millisecond,
		// Generous: fake peers in these tests do not heartbeat back.
		PeerTimeout:  10 * time.Second,
		WriteTimeout: 500 * time.Millisecond,
	}
}

// The bridge is the one composition entry: it binds the socket, owns
// the composite handler, runs the orphan cadence, and tears all of it
// down on context cancellation.
func TestBridgeOwnsListenerAndCadenceLifecycle(t *testing.T) {
	bridge, err := NewBridge(BridgeConfig{
		Transport:  bridgeTransportConfig(t),
		RouteOwner: true,
	})
	require.NoError(t, err)
	require.NotNil(t, bridge.Consumer())

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- bridge.Run(ctx) }()

	// The cadence runs without incident.
	time.Sleep(50 * time.Millisecond)

	cancel()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("bridge did not stop on context cancellation")
	}
	require.NoError(t, bridge.Close())
}

func TestRouteOwnerBridgeConstructsNoRouterAdapter(t *testing.T) {
	transportConfig := bridgeTransportConfig(t)
	routeCap := uint64(controlpb.ControlCapability_CONTROL_CAPABILITY_RUST_ROUTE_OWNER)
	transportConfig.LocalHello.Capabilities = []uint64{routeCap}
	transportConfig.RequiredCapabilities = []uint64{routeCap}
	bridge, err := NewBridge(BridgeConfig{
		Transport:  transportConfig,
		RouteOwner: true,
	})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, bridge.Close()) })
	status, ok := bridge.RouteOwnerStatus()
	require.True(t, ok)
	require.Zero(t, status.RouterAdapterConstructions)
	require.Zero(t, status.SelectorCalls)
	require.Zero(t, status.SelectorEffects)
	require.Zero(t, status.RouteFinishes)
	require.Zero(t, status.RedirectsIssued)
	require.Zero(t, status.OrphansRehydrated)
	require.Zero(t, status.RouteCloses)
	require.Zero(t, status.ConnectionMappings)
	require.Zero(t, status.LegacyRouteViolations)
	require.Equal(t, emptyRouteStateSHA256, status.RouteStateSHA256)
}

func bridgeFakeRustPeer(t *testing.T, socketPath string) (*net.UnixConn, uint64) {
	t.Helper()
	peer, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: socketPath, Net: "unix"})
	require.NoError(t, err)
	t.Cleanup(func() { _ = peer.Close() })
	goHello, err := controlpb.ReadFrame(peer, controlpb.DefaultMaxFrameBytes)
	require.NoError(t, err)
	require.Equal(t, controlpb.Role_ROLE_GO_CONTROL, goHello.GetHello().GetRole())
	require.NoError(t, controlpb.WriteFrame(peer, &controlpb.ControlEnvelope{
		ProtocolVersion: controlpb.ProtocolV1,
		Priority:        controlpb.Priority_PRIORITY_CRITICAL,
		Body: &controlpb.ControlEnvelope_Hello{Hello: &controlpb.Hello{
			Role:              controlpb.Role_ROLE_RUST_DATAPLANE,
			ProcessId:         "rust-bridge-drain-test",
			SupportedVersions: []uint32{controlpb.ProtocolV1},
			Capabilities:      []uint64{1, 2, 3},
			MaxFrameBytes:     controlpb.DefaultMaxFrameBytes,
		}},
	}, controlpb.DefaultMaxFrameBytes))
	ackEnvelope, err := controlpb.ReadFrame(peer, controlpb.DefaultMaxFrameBytes)
	require.NoError(t, err)
	ack := ackEnvelope.GetHelloAck()
	require.Equal(t, controlpb.ErrorCode_ERROR_CODE_OK, ack.GetRejectionCode())
	echo, ok := proto.Clone(ack).(*controlpb.HelloAck)
	require.True(t, ok)
	require.NoError(t, controlpb.WriteFrame(peer, &controlpb.ControlEnvelope{
		ProtocolVersion: controlpb.ProtocolV1,
		ControlEpoch:    ack.GetControlEpoch(),
		Priority:        controlpb.Priority_PRIORITY_CRITICAL,
		Body:            &controlpb.ControlEnvelope_HelloAck{HelloAck: echo},
	}, ack.GetMaxFrameBytes()))
	return peer, ack.GetControlEpoch()
}

// Every boot precedes its peer: the snapshot cadence must tick with a
// publisher configured and NO active session without dereferencing the
// typed-nil sender (the panic killed the whole process in production).
func TestBridgeCadenceSurvivesTicksWithoutAPeer(t *testing.T) {
	cfg := config.NewConfig()
	builder, err := NewSnapshotBuilder(cfg, nil)
	require.NoError(t, err)
	publisher, err := NewSnapshotPublisher(SnapshotPublisherConfig{
		Builder:              builder,
		Initial:              cfg,
		AdvertisedCapability: 1,
		ServerVersion:        "test-server",
	})
	require.NoError(t, err)
	bridge, err := NewBridge(BridgeConfig{
		Transport:            bridgeTransportConfig(t),
		RouteOwner:           true,
		Publisher:            publisher,
		SnapshotSyncInterval: 5 * time.Millisecond,
	})
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- bridge.Run(ctx) }()

	// Many peerless ticks: a typed-nil dereference would crash here.
	time.Sleep(100 * time.Millisecond)

	cancel()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("bridge did not stop on context cancellation")
	}
	require.NoError(t, bridge.Close())
}

// A topology change reaches the WIRE without any config change: the
// bridge cadence re-projects, stages a fresh generation, and streams
// the new StateSnapshot to the negotiated Rust peer (DPL-07).
func TestBridgeStreamsTopologyChangesToTheWire(t *testing.T) {
	var mu sync.Mutex
	cluster := "alpha"
	cfg := config.NewConfig()
	builder, err := NewSnapshotBuilder(cfg, nil)
	require.NoError(t, err)
	publisher, err := NewSnapshotPublisher(SnapshotPublisherConfig{
		Builder:              builder,
		Initial:              cfg,
		AdvertisedCapability: 1,
		ServerVersion:        "test-server",
		Topology: func() ([]*controlpb.BackendSnapshot, []*controlpb.NamespaceSnapshot) {
			mu.Lock()
			defer mu.Unlock()
			return []*controlpb.BackendSnapshot{{
					BackendId:   cluster + "/tidb:4000",
					Address:     "tidb:4000",
					ClusterName: cluster,
					Healthy:     true,
				}}, []*controlpb.NamespaceSnapshot{{
					Name:           "default",
					BackendCluster: cluster,
				}}
		},
	})
	require.NoError(t, err)

	transportConfig := bridgeTransportConfig(t)
	bridge, err := NewBridge(BridgeConfig{
		Transport:            transportConfig,
		RouteOwner:           true,
		Publisher:            publisher,
		SnapshotSyncInterval: 20 * time.Millisecond,
	})
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- bridge.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		require.NoError(t, <-done)
		require.NoError(t, bridge.Close())
	})

	peer, epoch := bridgeFakeRustPeer(t, transportConfig.SocketPath)

	readSnapshot := func() *controlpb.ControlEnvelope {
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			require.NoError(t, peer.SetReadDeadline(time.Now().Add(time.Second)))
			envelope, err := controlpb.ReadFrame(peer, controlpb.DefaultMaxFrameBytes)
			if err != nil {
				select {
				case runErr := <-done:
					t.Fatalf("bridge run ended: %v (read err %v)", runErr, err)
				default:
					t.Fatalf("read failed while bridge alive: %v", err)
				}
			}
			require.NoError(t, err)
			if envelope.GetStateSnapshot() != nil {
				return envelope
			}
		}
		t.Fatal("no StateSnapshot arrived")
		return nil
	}
	acknowledge := func(envelope *controlpb.ControlEnvelope) {
		require.NoError(t, controlpb.WriteFrame(peer, &controlpb.ControlEnvelope{
			ProtocolVersion: controlpb.ProtocolV1,
			ControlEpoch:    epoch,
			RequestId:       envelope.GetRequestId(),
			Generation:      envelope.GetGeneration(),
			Priority:        controlpb.Priority_PRIORITY_CRITICAL,
			Body: &controlpb.ControlEnvelope_SnapshotResult{SnapshotResult: &controlpb.SnapshotResult{
				AppliedGeneration: envelope.GetGeneration(),
				Code:              controlpb.ErrorCode_ERROR_CODE_OK,
			}},
		}, controlpb.DefaultMaxFrameBytes))
	}

	first := readSnapshot()
	require.Equal(t, "alpha",
		first.GetStateSnapshot().GetNamespaces()[0].GetBackendCluster())
	acknowledge(first)

	// A live topology change — no config change — reaches the wire as
	// a fresh generation.
	mu.Lock()
	cluster = "beta"
	mu.Unlock()
	second := readSnapshot()
	require.Greater(t, second.GetGeneration(), first.GetGeneration())
	require.Equal(t, "beta",
		second.GetStateSnapshot().GetNamespaces()[0].GetBackendCluster())
	require.Equal(t, "beta/tidb:4000",
		second.GetStateSnapshot().GetBackends()[0].GetBackendId())
	acknowledge(second)
}
