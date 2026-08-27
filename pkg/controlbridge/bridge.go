// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package controlbridge

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/pingcap/tiproxy/lib/util/errors"
	"github.com/pingcap/tiproxy/lib/util/waitgroup"
	"github.com/pingcap/tiproxy/pkg/balance/router"
	controlpb "github.com/pingcap/tiproxy/pkg/controlbridge/pb"
	"github.com/pingcap/tiproxy/pkg/controlbridge/transport"
	"github.com/pingcap/tiproxy/pkg/proxy/backend"
	"google.golang.org/protobuf/proto"
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

// ErrForeignDrainActive reports that a previous incarnation's drain is
// still running on the dataplane; the operator retries after it
// resolves.
var ErrForeignDrainActive = errors.New("a previous incarnation's drain is still active on the dataplane")

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

// activeDrainState retains the wire-independent request so reconnects
// re-send the same operation idempotently.
type activeDrainState struct {
	request       DrainRequest
	command       *controlpb.DrainCommand
	lastSyncEpoch uint64
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

	drainMu     sync.Mutex
	activeDrain *activeDrainState
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

// StartDrain issues (or idempotently re-issues) one operator drain.
// The wire command carries absolute deadlines computed from one budget
// at first issuance, the issuer's single-flight and sequence binding
// apply, and a send failure keeps the responsibility with the
// operator's next retry (the reservation is released, never the
// binding). A still-active foreign drain (a previous incarnation's)
// is reported for retry; its resolution signal is consumed here.
func (bridge *Bridge) StartDrain(ctx context.Context, request DrainRequest) error {
	if request.DrainID == "" {
		return errors.New("drain id is required")
	}
	// Fail before any reservation: a budget the Rust gate would reject
	// (negative waits, deadlines past the shared cap) or a command it
	// would judge stale (no applied generation yet) must never consume
	// the single-flight slot. Each bound is checked individually first,
	// so the sum cannot overflow.
	if request.GracefulWait < 0 || request.ForceTimeout < 0 ||
		request.GracefulWait > MaxDrainDeadlineAhead ||
		request.ForceTimeout > MaxDrainDeadlineAhead ||
		request.GracefulWait+request.ForceTimeout > MaxDrainDeadlineAhead {
		return ErrInvalidDrainBudget
	}
	if bridge.publisher != nil && bridge.publisher.Status().AppliedGeneration == 0 {
		return ErrSnapshotNotReady
	}
	sender := bridge.server.Active()
	if sender == nil {
		return ErrNoDataplaneSession
	}
	// Consume a resolved foreign drain first: after resolution the
	// operator's own drain may proceed.
	_ = bridge.issuer.ForeignDrainResolved()
	if foreign := bridge.issuer.ForeignActiveDrain(); foreign != nil {
		return fmt.Errorf("%w: %s", ErrForeignDrainActive, foreign.GetDrainId())
	}

	bridge.drainMu.Lock()
	state := bridge.activeDrain
	if state == nil || state.request.DrainID != request.DrainID {
		now := time.Now()
		graceful := now.Add(request.GracefulWait)
		force := graceful.Add(request.ForceTimeout)
		state = &activeDrainState{
			request: request,
			command: &controlpb.DrainCommand{
				DrainId:                    request.DrainID,
				ListenerNames:              request.Scope.ListenerNames,
				BackendIds:                 request.Scope.BackendIDs,
				GracefulDeadlineUnixMillis: uint64(graceful.UnixMilli()),
				ForceDeadlineUnixMillis:    uint64(force.UnixMilli()),
			},
		}
	}
	command, ok := proto.Clone(state.command).(*controlpb.DrainCommand)
	if !ok {
		bridge.drainMu.Unlock()
		return errors.New("clone drain command")
	}
	bridge.drainMu.Unlock()

	requestID, err := sender.AllocateRequestID()
	if err != nil {
		return err
	}
	generation := uint64(0)
	if bridge.publisher != nil {
		generation = bridge.publisher.Status().AppliedGeneration
	}
	if err := bridge.issuer.StartDrain(ctx, sender, requestID, generation, command); err != nil {
		return err
	}
	bridge.drainMu.Lock()
	state.lastSyncEpoch = sender.Epoch()
	bridge.activeDrain = state
	bridge.drainMu.Unlock()
	return nil
}

// DrainStatus reports the latest observed result for the operator's
// drain id plus whether that drain completed. A nil result means the
// id is unknown to this incarnation.
func (bridge *Bridge) DrainStatus(drainID string) (*controlpb.DrainResult, bool) {
	result, completed := bridge.issuer.Progress(drainID)
	return result, completed
}

// syncDrain re-issues the active drain after a control reconnect (a
// restarted Rust lineage lost the gate state; the reconcile watermark
// plus this idempotent replay converge it) and clears the record once
// its terminal result arrived.
func (bridge *Bridge) syncDrain(ctx context.Context) {
	sender := bridge.server.Active()
	if sender == nil {
		return
	}
	bridge.drainMu.Lock()
	state := bridge.activeDrain
	if state == nil {
		bridge.drainMu.Unlock()
		return
	}
	if result, completed := bridge.issuer.Progress(state.request.DrainID); completed &&
		result != nil {
		bridge.activeDrain = nil
		bridge.drainMu.Unlock()
		return
	}
	epoch := sender.Epoch()
	if state.lastSyncEpoch == epoch {
		bridge.drainMu.Unlock()
		return
	}
	command, ok := proto.Clone(state.command).(*controlpb.DrainCommand)
	bridge.drainMu.Unlock()
	if !ok {
		return
	}
	requestID, err := sender.AllocateRequestID()
	if err != nil {
		return
	}
	generation := uint64(0)
	if bridge.publisher != nil {
		generation = bridge.publisher.Status().AppliedGeneration
	}
	if bridge.issuer.StartDrain(ctx, sender, requestID, generation, command) == nil {
		bridge.drainMu.Lock()
		if bridge.activeDrain != nil {
			bridge.activeDrain.lastSyncEpoch = epoch
		}
		bridge.drainMu.Unlock()
	}
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
					// The nil check MUST happen on the concrete
					// *Session: converting a nil pointer into the
					// EnvelopeSender interface would defeat Sync's
					// own guard and dereference nil on first tick
					// of every boot that precedes the peer.
					if sender := bridge.server.Active(); sender != nil {
						_ = bridge.publisher.Sync(ctx, sender)
					}
				}
				bridge.syncDrain(ctx)
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
