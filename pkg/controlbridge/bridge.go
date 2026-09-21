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
	// RouteOwner installs the post-cutover residual handler. It is a
	// compatibility assertion: this process never constructs a RouterAdapter
	// and never falls back to Go routing after the first negotiation.
	RouteOwner bool
	// NativeMeterOwner leaves durable metering entirely in Rust. Requires RouteOwner.
	NativeMeterOwner bool
	// NativeAPIOwner leaves the management API entirely in Rust: this process
	// starts no API server and metrics batches are retired wire bodies.
	// Requires RouteOwner.
	NativeAPIOwner bool
	// Handshake is the router adapter's authentication/routing seam.
	// It is required only for the legacy, non-RouteOwner composition.
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
	// MeteringStatePath is the absolute crash-safe consumer state file. Empty
	// retains the legacy in-memory delta consumer for old compositions.
	MeteringStatePath string
	// MeteringSink receives derived response/cross-AZ deltas after durable
	// staging. Nil keeps durable totals available without an external writer.
	MeteringSink MeteringSink
}

// DrainScope selects which sessions a drain covers; empty lists mean
// the whole instance.
type DrainScope struct {
	// ListenerNames restricts the drain to sessions admitted on these
	// listeners.
	ListenerNames []string
	// BackendIDs restricts the drain to sessions currently attached to
	// these backends.
	BackendIDs []string
}

// DrainRequest is one operator drain: a stable caller id, its scope,
// and one absolute time budget (graceful wait, then force).
type DrainRequest struct {
	// DrainID is the operator's stable id; repeating it is idempotent.
	DrainID string
	// Scope selects the covered sessions.
	Scope DrainScope
	// GracefulWait is how long sessions may finish at safe boundaries.
	GracefulWait time.Duration
	// ForceTimeout is the additional window before force close.
	ForceTimeout time.Duration
}

// The drain request/error vocabulary below is the HTTP API contract of
// `/api/dataplane/drain` (pkg/server/api). Since CP-ADMIN slice 3 operator
// drains are issued inside the Rust process; no Go composition implements
// the API's DataplaneDrainer, and these values remain only for the
// handler and its Go oracle in the CP-ADMIN differential harness.

// ErrForeignDrainActive reports that a previous incarnation's drain is
// still running on the dataplane; the operator retries after it
// resolves.
var ErrForeignDrainActive = errors.New("a previous incarnation's drain is still active on the dataplane")

// ErrDrainInProgress rejects a second concurrent drain locally.
var ErrDrainInProgress = errors.New("a different drain is already in progress")

// ErrNoDataplaneSession reports that no negotiated control session
// exists to carry the drain.
var ErrNoDataplaneSession = errors.New("no active Rust dataplane control session")

// MaxDrainDeadlineAhead mirrors the Rust gate's absolute-deadline cap
// (MAX_DRAIN_DEADLINE_AHEAD_MILLIS): each computed deadline must land
// within this window or the command would be rejected on the wire. The
// HTTP layer shares it to validate millisecond inputs BEFORE duration
// conversion, so oversized values can never overflow into small ones.
const MaxDrainDeadlineAhead = 30 * 24 * time.Hour

// ErrInvalidDrainBudget rejects a drain whose budget is negative or
// whose deadlines would exceed the shared 30-day cap.
var ErrInvalidDrainBudget = errors.New("drain budget is negative or exceeds the 30-day deadline cap")

// ErrSnapshotNotReady rejects a drain before the first applied
// configuration generation exists: a generation-0 command from a
// modern peer would be judged stale by the Rust gate.
var ErrSnapshotNotReady = errors.New("no applied configuration generation yet")

// Bridge is the single Go composition entry for the control plane
// (CTL-06): it owns the transport listener, the composite handler
// (router adapter + metering consumer), and the
// orphan-resolution and snapshot cadences. DPL-03's proxy bootstrap
// starts it behind the explicit Rust dataplane config gate.
type Bridge struct {
	server           *transport.Server
	adapter          *RouterAdapter
	handler          *CompositeControlHandler
	routeOwner       bool
	consumer         *MeteringConsumer
	interval         time.Duration
	publisher        *SnapshotPublisher
	snapshotInterval time.Duration
}

// NewBridge builds and binds the whole composition: adapter, consumer,
// composite handler, and the listening control socket. On any error
// nothing is left bound. Operator drains are not part of it: they are
// issued inside the Rust process (CP-ADMIN slice 3).
func NewBridge(config BridgeConfig) (*Bridge, error) {
	if config.NativeMeterOwner && (!config.RouteOwner || config.MeteringStatePath != "" || config.MeteringSink != nil) {
		return nil, errors.New("native metering requires route owner and no Go metering state or sink")
	}
	if config.NativeAPIOwner && !config.RouteOwner {
		return nil, errors.New("native API ownership requires route owner")
	}
	var adapter *RouterAdapter
	var err error
	if !config.RouteOwner {
		if config.Handshake == nil {
			return nil, errors.New("bridge requires a handshake handler")
		}
		adapter, err = NewRouterAdapter(config.Handshake)
		if err != nil {
			return nil, err
		}
		if config.RouterLookup != nil {
			adapter.AttachRouterLookup(config.RouterLookup)
		}
	}
	var consumer *MeteringConsumer
	if !config.NativeMeterOwner {
		consumer = NewMeteringConsumer()
	}
	if config.MeteringStatePath != "" {
		consumer, err = OpenMeteringConsumer(config.MeteringStatePath, config.MeteringSink)
		if err != nil {
			return nil, err
		}
	}
	var composite *CompositeControlHandler
	if config.NativeMeterOwner {
		composite, err = NewNativeMeterOwnerControlHandler()
	} else if config.RouteOwner {
		composite, err = NewRouteOwnerControlHandler(consumer)
	} else {
		composite, err = NewCompositeControlHandler(adapter, consumer)
	}
	if err != nil {
		return nil, err
	}
	composite.nativeAPIOwner = config.NativeAPIOwner
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
		handler:          composite,
		routeOwner:       config.RouteOwner,
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

// RouteOwnerStatus exposes the residual handler's zero-route evidence. The
// boolean is false for legacy compositions, where RouterAdapter intentionally
// remains live.
func (bridge *Bridge) RouteOwnerStatus() (RouteOwnerStatus, bool) {
	if !bridge.routeOwner || bridge.handler == nil {
		return RouteOwnerStatus{}, false
	}
	return bridge.handler.RouteOwnerStatus(), true
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

// Status implements the API readiness surface. A metering durable-state or
// sink failure forces the applied generation to zero, so readiness degrades
// immediately instead of advertising a billable dataplane as healthy.
func (bridge *Bridge) Status() SnapshotStatus {
	if bridge.publisher == nil {
		return SnapshotStatus{}
	}
	status := bridge.publisher.Status()
	if bridge.consumer != nil && !bridge.consumer.Healthy() {
		status.AppliedGeneration = 0
	}
	return status
}

// Run serves the control socket and drives the orphan-resolution
// cadence until ctx cancels or Close is called; it returns the serve
// result after the cadence worker has stopped.
func (bridge *Bridge) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var cadence waitgroup.WaitGroup
	cadence.Run(func() {
		var orphanTicker *time.Ticker
		var orphanTick <-chan time.Time
		if bridge.adapter != nil {
			orphanTicker = time.NewTicker(bridge.interval)
			orphanTick = orphanTicker.C
			defer orphanTicker.Stop()
		}
		snapshotTicker := time.NewTicker(bridge.snapshotInterval)
		defer snapshotTicker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-orphanTick:
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
					// The nil check MUST happen on the concrete
					// *Session: converting a nil pointer into the
					// EnvelopeSender interface would defeat Sync's
					// own guard and dereference nil on first tick
					// of every boot that precedes the peer.
					if sender := bridge.server.Active(); sender != nil {
						_ = bridge.publisher.Sync(ctx, sender)
					}
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
