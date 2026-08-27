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
	"google.golang.org/protobuf/proto"

	"github.com/pingcap/tiproxy/lib/config"
	"github.com/pingcap/tiproxy/pkg/balance/router"
	controlpb "github.com/pingcap/tiproxy/pkg/controlbridge/pb"
	"github.com/pingcap/tiproxy/pkg/controlbridge/transport"
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
		PeerTimeout:          500 * time.Millisecond,
		WriteTimeout:         500 * time.Millisecond,
	}
}

// The bridge is the one composition entry: it binds the socket, owns
// the composite handler, runs the orphan cadence, and tears all of it
// down on context cancellation.
func TestBridgeOwnsListenerAndCadenceLifecycle(t *testing.T) {
	rt := router.NewStaticRouter([]string{"tidb-a:4000"})
	handler := &recordingHandler{rt: rt}
	bridge, err := NewBridge(BridgeConfig{
		Transport:             bridgeTransportConfig(t),
		Handshake:             handler,
		RouterLookup:          func(string) (router.Router, error) { return rt, nil },
		OrphanResolveInterval: 10 * time.Millisecond,
	})
	require.NoError(t, err)
	require.NotNil(t, bridge.Adapter())
	require.NotNil(t, bridge.Issuer())
	require.NotNil(t, bridge.Consumer())

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- bridge.Run(ctx) }()

	// The cadence runs against an empty orphan set without incident.
	time.Sleep(50 * time.Millisecond)
	require.Equal(t, 0, bridge.Adapter().OrphanCount())

	cancel()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("bridge did not stop on context cancellation")
	}
	require.NoError(t, bridge.Close())
}

// Concurrent orphan resolution, sender rotations, and reconciles under
// -race: the single-critical-section compare-and-delete may only
// remove the obligation while the carrying sender is still current, so
// after every interleaving either the orphan is gone AND the final
// lineage carried (or observed) its close, or the orphan is retained.
func TestOrphanCompareAndDeleteLinearizesWithRotation(t *testing.T) {
	rt := router.NewStaticRouter([]string{"tidb-a:4000"})
	handler := &recordingHandler{rt: rt}
	adapter := newTestAdapter(t, handler)
	capabilities := []uint64{
		uint64(controlpb.ControlCapability_CONTROL_CAPABILITY_RECONCILE_CONNECTIONS),
		uint64(controlpb.ControlCapability_CONTROL_CAPABILITY_RECONCILE_SESSION_REHYDRATION),
		uint64(controlpb.ControlCapability_CONTROL_CAPABILITY_PER_CONNECTION_CLOSE),
	}
	first := newFakeSender(30, capabilities...)
	remote := reconciledConnection(85, "tidb-gone:4000", "")
	require.NoError(t, adapter.HandleEnvelope(context.Background(), first, reconcileRequestEnvelope(99, remote)))
	require.Equal(t, 1, adapter.OrphanCount())

	// Exhaust the bounded retries so every further cadence attempts
	// the close+delete path.
	for attempt := 0; attempt < MaxOrphanResolveAttempts-1; attempt++ {
		require.NoError(t, adapter.ResolveOrphans(context.Background()))
	}

	var wg sync.WaitGroup
	stop := make(chan struct{})
	// Rotation storm: new lineages keep taking over.
	wg.Add(1)
	go func() {
		defer wg.Done()
		epoch := uint64(31)
		for {
			select {
			case <-stop:
				return
			default:
			}
			adapter.rememberSender(newFakeSender(epoch, capabilities...))
			epoch++
		}
	}()
	// Resolver storm.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			_ = adapter.ResolveOrphans(context.Background())
		}
	}()
	// Let both run, then stop the rotation and converge.
	time.Sleep(20 * time.Millisecond)
	close(stop)
	wg.Wait()
	for i := 0; i < 5 && adapter.OrphanCount() > 0; i++ {
		require.NoError(t, adapter.ResolveOrphans(context.Background()))
	}
	require.Equal(t, 0, adapter.OrphanCount(),
		"with rotations stopped the obligation converges to deletion")
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
	// The peer only acknowledges snapshots; keep the server's read
	// deadline out of the way.
	transportConfig.PeerTimeout = 10 * time.Second
	rt := router.NewStaticRouter([]string{"tidb-a:4000"})
	bridge, err := NewBridge(BridgeConfig{
		Transport:             transportConfig,
		Handshake:             &recordingHandler{rt: rt},
		OrphanResolveInterval: time.Hour,
		Publisher:             publisher,
		SnapshotSyncInterval:  20 * time.Millisecond,
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

	peer, err := net.DialUnix("unix", nil,
		&net.UnixAddr{Name: transportConfig.SocketPath, Net: "unix"})
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
			ProcessId:         "rust-topology-test",
			SupportedVersions: []uint32{controlpb.ProtocolV1},
			Capabilities:      []uint64{1, 2, 3},
			MaxFrameBytes:     controlpb.DefaultMaxFrameBytes,
		}},
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
			ControlEpoch:    ack.GetControlEpoch(),
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
