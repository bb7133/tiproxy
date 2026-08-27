// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package controlbridge

import (
	"context"
	"time"

	"github.com/pingcap/tiproxy/lib/util/errors"
	"github.com/pingcap/tiproxy/lib/util/waitgroup"
	"github.com/pingcap/tiproxy/pkg/balance/router"
	"github.com/pingcap/tiproxy/pkg/controlbridge/transport"
	"github.com/pingcap/tiproxy/pkg/proxy/backend"
)

// DefaultOrphanResolveInterval paces the rehydration/orphan cadence
// when the configuration leaves it zero.
const DefaultOrphanResolveInterval = 5 * time.Second

// DefaultSnapshotSyncInterval bounds config-to-wire and reconnect-to-resend
// latency without coupling snapshot progress to the slower orphan cadence.
const DefaultSnapshotSyncInterval = 50 * time.Millisecond

// BridgeConfig configures the Go control-plane composition.
type BridgeConfig struct {
	// Transport configures the mode-0600 control UDS owner.
	Transport transport.ServerConfig
	// Handshake is the router adapter's authentication/routing seam.
	Handshake backend.HandshakeHandler
	// RouterLookup resolves a namespace to its router for
	// rehydration; optional at construction, attachable later through
	// the adapter.
	RouterLookup func(namespace string) (router.Router, error)
	// OrphanResolveInterval paces ResolveOrphans; zero uses the
	// default.
	OrphanResolveInterval time.Duration
	// Publisher owns complete StateSnapshot generations. Nil keeps the
	// bridge in the legacy Go-dataplane composition.
	Publisher *SnapshotPublisher
	// SnapshotSyncInterval paces desired-generation and reconnect sync.
	SnapshotSyncInterval time.Duration
}

// Bridge is the single Go composition entry for the control plane
// (CTL-06): it owns the transport listener, the composite handler
// (router adapter + drain issuer + metering consumer), and the
// orphan-resolution and snapshot cadences. DPL-03's proxy bootstrap
// starts it behind the explicit Rust dataplane config gate.
type Bridge struct {
	server           *transport.Server
	adapter          *RouterAdapter
	issuer           *DrainIssuer
	consumer         *MeteringConsumer
	interval         time.Duration
	publisher        *SnapshotPublisher
	snapshotInterval time.Duration
}

// NewBridge builds and binds the whole composition: adapter, issuer
// (fallible incarnation nonce), consumer, composite handler, and the
// listening control socket. On any error nothing is left bound.
func NewBridge(config BridgeConfig) (*Bridge, error) {
	if config.Handshake == nil {
		return nil, errors.New("bridge requires a handshake handler")
	}
	adapter, err := NewRouterAdapter(config.Handshake)
	if err != nil {
		return nil, err
	}
	if config.RouterLookup != nil {
		adapter.AttachRouterLookup(config.RouterLookup)
	}
	issuer, err := NewDrainIssuer()
	if err != nil {
		return nil, err
	}
	consumer := NewMeteringConsumer()
	composite, err := NewCompositeControlHandler(adapter, issuer, consumer)
	if err != nil {
		return nil, err
	}
	if config.Publisher != nil {
		composite.AttachSnapshotPublisher(config.Publisher)
	}
	server, err := transport.Listen(config.Transport, composite)
	if err != nil {
		return nil, err
	}
	interval := config.OrphanResolveInterval
	if interval <= 0 {
		interval = DefaultOrphanResolveInterval
	}
	snapshotInterval := config.SnapshotSyncInterval
	if snapshotInterval <= 0 {
		snapshotInterval = DefaultSnapshotSyncInterval
	}
	return &Bridge{
		server:           server,
		adapter:          adapter,
		issuer:           issuer,
		consumer:         consumer,
		interval:         interval,
		publisher:        config.Publisher,
		snapshotInterval: snapshotInterval,
	}, nil
}

// Adapter exposes the router adapter (bootstrap attaches the namespace
// router lookup here when it comes up after the bridge).
func (bridge *Bridge) Adapter() *RouterAdapter {
	return bridge.adapter
}

// Issuer exposes the drain issuer (operator drain entry).
func (bridge *Bridge) Issuer() *DrainIssuer {
	return bridge.issuer
}

// Consumer exposes the metering consumer (billing export reads its
// totals).
func (bridge *Bridge) Consumer() *MeteringConsumer {
	return bridge.consumer
}

// Publisher exposes the snapshot generation owner, when configured.
func (bridge *Bridge) Publisher() *SnapshotPublisher {
	return bridge.publisher
}

// Run serves the control socket and drives the orphan-resolution
// cadence until ctx cancels or Close is called; it returns the serve
// result after the cadence worker has stopped.
func (bridge *Bridge) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var cadence waitgroup.WaitGroup
	cadence.Run(func() {
		orphanTicker := time.NewTicker(bridge.interval)
		defer orphanTicker.Stop()
		snapshotTicker := time.NewTicker(bridge.snapshotInterval)
		defer snapshotTicker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-orphanTicker.C:
				// Bounded-retry convergence: unresolvable orphans end
				// in a per-connection close; send errors keep the
				// obligation for the next tick.
				_ = bridge.adapter.ResolveOrphans(ctx)
			case <-snapshotTicker.C:
				if bridge.publisher != nil {
					// A topology change (namespace commit, backend
					// health) stages a fresh generation before the
					// sync, so the wire snapshot stays live without a
					// config change.
					_ = bridge.publisher.RefreshTopology()
					_ = bridge.publisher.Sync(ctx, bridge.server.Active())
				}
			}
		}
	})
	err := bridge.server.Serve(ctx)
	cancel()
	cadence.Wait()
	return err
}

// Close unbinds the control socket and stops Serve.
func (bridge *Bridge) Close() error {
	return bridge.server.Close()
}
