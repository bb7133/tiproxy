// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package controlbridge

import (
	"context"
	"time"

	"github.com/pingcap/tiproxy/lib/util/errors"
	"github.com/pingcap/tiproxy/pkg/balance/router"
	"github.com/pingcap/tiproxy/pkg/controlbridge/transport"
	"github.com/pingcap/tiproxy/pkg/proxy/backend"
)

// DefaultOrphanResolveInterval paces the rehydration/orphan cadence
// when the configuration leaves it zero.
const DefaultOrphanResolveInterval = 5 * time.Second

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
}

// Bridge is the single Go composition entry for the control plane
// (CTL-06): it owns the transport listener, the composite handler
// (router adapter + drain issuer + metering consumer), and the
// orphan-resolution cadence. Application bootstrap wiring (the proxy
// server starting a Bridge next to its SQL listeners) lands with the
// DPL-03/05 integrations.
type Bridge struct {
	server   *transport.Server
	adapter  *RouterAdapter
	issuer   *DrainIssuer
	consumer *MeteringConsumer
	interval time.Duration
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
	server, err := transport.Listen(config.Transport, composite)
	if err != nil {
		return nil, err
	}
	interval := config.OrphanResolveInterval
	if interval <= 0 {
		interval = DefaultOrphanResolveInterval
	}
	return &Bridge{
		server:   server,
		adapter:  adapter,
		issuer:   issuer,
		consumer: consumer,
		interval: interval,
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

// Run serves the control socket and drives the orphan-resolution
// cadence until ctx cancels or Close is called; it returns the serve
// result after the cadence worker has stopped.
func (bridge *Bridge) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	cadenceDone := make(chan struct{})
	go func() {
		defer close(cadenceDone)
		ticker := time.NewTicker(bridge.interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				// Bounded-retry convergence: unresolvable orphans end
				// in a per-connection close; send errors keep the
				// obligation for the next tick.
				_ = bridge.adapter.ResolveOrphans(ctx)
			}
		}
	}()
	err := bridge.server.Serve(ctx)
	cancel()
	<-cadenceDone
	return err
}

// Close unbinds the control socket and stops Serve.
func (bridge *Bridge) Close() error {
	return bridge.server.Close()
}
