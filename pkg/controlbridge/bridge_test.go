// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package controlbridge

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

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
