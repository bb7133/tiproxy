// Copyright 2026 PingCAP, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package controlbridge

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/pingcap/tiproxy/pkg/balance/router"
	controlpb "github.com/pingcap/tiproxy/pkg/controlbridge/pb"
	"github.com/pingcap/tiproxy/pkg/proxy/backend"
)

func reconciledConnection(id uint64, backendID, pendingRedirect string) *controlpb.ReconcileConnection {
	return &controlpb.ReconcileConnection{
		ConnectionId:      id,
		BackendId:         backendID,
		Namespace:         "ns-a",
		RedirectPending:   pendingRedirect != "",
		Generation:        7,
		PendingRedirectId: pendingRedirect,
		Identity: &controlpb.ConnectionIdentity{
			ConnectionId:    id,
			ListenerAddress: "0.0.0.0:6000",
			ClientAddress:   "10.9.8.7:55555",
			ProxyAddress:    "10.0.0.9:6000",
		},
	}
}

func reconcileRequestEnvelope(requestID uint64, connections ...*controlpb.ReconcileConnection) *controlpb.ControlEnvelope {
	return &controlpb.ControlEnvelope{
		RequestId:  requestID,
		Generation: 7,
		Body: &controlpb.ControlEnvelope_ReconcileRequest{ReconcileRequest: &controlpb.ReconcileRequest{
			KnownGeneration: 7,
			Connections:     connections,
		}},
	}
}

// Go restart rebuilds real router accounting: a fresh adapter
// rehydrates the reported live pair into the router (ConnCount rises),
// the snapshot carries the connection with its generation and identity,
// and a later CLOSED runs the real OnConnClosed exactly once so
// ConnCount returns to its pre-session value with no double finish.
func TestGoRestartRehydratesAccountingAndClosesExactlyOnce(t *testing.T) {
	rt := router.NewStaticRouter([]string{"tidb-a:4000"})
	handler := &recordingHandler{rt: rt}
	adapter := newTestAdapter(t, handler)
	adapter.AttachRouterLookup(func(string) (router.Router, error) { return rt, nil })
	peer := newFakeSender(21,
		uint64(controlpb.ControlCapability_CONTROL_CAPABILITY_RECONCILE_CONNECTIONS),
		uint64(controlpb.ControlCapability_CONTROL_CAPABILITY_RECONCILE_SESSION_REHYDRATION))

	baseline := rt.ConnCount()
	remote := reconciledConnection(80, "tidb-a:4000", "")
	require.NoError(t, adapter.HandleEnvelope(context.Background(), peer, reconcileRequestEnvelope(90, remote)))
	require.Equal(t, baseline+1, rt.ConnCount(), "rehydration joins real router accounting")
	require.Equal(t, 0, adapter.OrphanCount())

	snapshot := lastEnvelope(t, peer).GetReconcileSnapshot()
	require.Len(t, snapshot.GetConnections(), 1)
	rebuilt := snapshot.GetConnections()[0]
	require.EqualValues(t, 80, rebuilt.GetConnectionId())
	require.EqualValues(t, 7, rebuilt.GetGeneration())
	require.NotNil(t, rebuilt.GetIdentity())
	require.Equal(t, "10.9.8.7:55555", rebuilt.GetIdentity().GetClientAddress())

	// Idempotent re-apply: no second rehydration, no drift.
	require.NoError(t, adapter.HandleEnvelope(context.Background(), peer, reconcileRequestEnvelope(91, remote)))
	require.Equal(t, baseline+1, rt.ConnCount())

	// The terminal CLOSED retires the rebuilt session exactly once
	// through the real receiver: ConnCount returns to baseline and a
	// duplicate CLOSED changes nothing.
	closed := &controlpb.ControlEnvelope{
		RequestId:  92,
		Generation: 7,
		Body: &controlpb.ControlEnvelope_ConnectionEvent{ConnectionEvent: &controlpb.ConnectionEvent{
			Kind:       controlpb.ConnectionEventKind_CONNECTION_EVENT_KIND_CLOSED,
			Connection: remote.GetIdentity(),
		}},
	}
	require.NoError(t, adapter.HandleEnvelope(context.Background(), peer, closed))
	require.Equal(t, baseline, rt.ConnCount(), "real OnConnClosed ran exactly once")
	require.Equal(t, 1, handler.closeCalls)
	duplicate := &controlpb.ControlEnvelope{
		RequestId:  93,
		Generation: 7,
		Body: &controlpb.ControlEnvelope_ConnectionEvent{ConnectionEvent: &controlpb.ConnectionEvent{
			Kind:       controlpb.ConnectionEventKind_CONNECTION_EVENT_KIND_CLOSED,
			Connection: remote.GetIdentity(),
		}},
	}
	require.NoError(t, adapter.HandleEnvelope(context.Background(), peer, duplicate))
	require.Equal(t, baseline, rt.ConnCount(), "duplicate CLOSED never double-finishes")
}

// A rehydrated pending redirect converges: no new redirect may be
// issued while it is outstanding, its terminal result retires it
// exactly once through the real receiver, and the duplicate result is
// absorbed.
func TestGoRestartRestoresPendingRedirectExactlyOnce(t *testing.T) {
	rt := router.NewStaticRouter([]string{"tidb-a:4000", "tidb-b:4000"})
	handler := &recordingHandler{rt: rt}
	adapter := newTestAdapter(t, handler)
	adapter.AttachRouterLookup(func(string) (router.Router, error) { return rt, nil })
	peer := newFakeSender(22,
		uint64(controlpb.ControlCapability_CONTROL_CAPABILITY_RECONCILE_CONNECTIONS),
		uint64(controlpb.ControlCapability_CONTROL_CAPABILITY_RECONCILE_SESSION_REHYDRATION))

	remote := reconciledConnection(81, "tidb-a:4000", "r-pending")
	require.NoError(t, adapter.HandleEnvelope(context.Background(), peer, reconcileRequestEnvelope(94, remote)))
	state := adapter.get(81)
	require.NotNil(t, state)
	require.True(t, state.conn.redirectPending())
	require.Equal(t, "r-pending", state.conn.pendingRedirectID())
	// The snapshot reports the restored pending id back to Rust.
	snapshot := lastEnvelope(t, peer).GetReconcileSnapshot()
	require.Equal(t, "r-pending", snapshot.GetConnections()[0].GetPendingRedirectId())

	// No new redirect while the restored one is outstanding.
	require.False(t, state.conn.Redirect(router.NewStaticBackend("tidb-b:4000")),
		"a rehydrated pending redirect blocks new redirects until terminal")

	// The lost terminal result arrives (replayed by Rust after the
	// reconcile): it retires exactly once and rebinds the backend.
	result := &controlpb.ControlEnvelope{
		RequestId: 95,
		Body: &controlpb.ControlEnvelope_RedirectResult{RedirectResult: &controlpb.RedirectResult{
			ConnectionId:      81,
			RedirectId:        "r-pending",
			PreviousBackendId: "tidb-a:4000",
			BackendId:         "tidb-b:4000",
			Succeeded:         true,
		}},
	}
	require.NoError(t, adapter.HandleEnvelope(context.Background(), peer, result))
	require.False(t, state.conn.redirectPending(), "retired")
	require.Equal(t, "tidb-b:4000", state.conn.ServerAddr(), "backend rebound via lookup")
	require.NoError(t, adapter.HandleEnvelope(context.Background(), peer, result))
	require.False(t, state.conn.redirectPending(), "duplicate result absorbed")

	// With the pending redirect retired, a new redirect may be issued.
	require.True(t, state.conn.Redirect(router.NewStaticBackend("tidb-a:4000")))
}

// Persistent rehydration failure converges instead of leaking a forever
// orphan: bounded ResolveOrphans retries end in a generation-stamped
// per-connection CloseCommand; a mid-way recovery rehydrates instead.
func TestOrphanResolutionIsBoundedAndConverges(t *testing.T) {
	rt := router.NewStaticRouter([]string{"tidb-a:4000"})
	handler := &recordingHandler{rt: rt}
	adapter := newTestAdapter(t, handler)
	peer := newFakeSender(23,
		uint64(controlpb.ControlCapability_CONTROL_CAPABILITY_RECONCILE_CONNECTIONS),
		uint64(controlpb.ControlCapability_CONTROL_CAPABILITY_RECONCILE_SESSION_REHYDRATION),
		uint64(controlpb.ControlCapability_CONTROL_CAPABILITY_PER_CONNECTION_CLOSE))

	// No RouterLookup attached: rehydration cannot succeed.
	remote := reconciledConnection(82, "tidb-gone:4000", "")
	require.NoError(t, adapter.HandleEnvelope(context.Background(), peer, reconcileRequestEnvelope(96, remote)))
	require.Empty(t, lastEnvelope(t, peer).GetReconcileSnapshot().GetConnections(),
		"unrehydratable connection identified by omission")
	require.Equal(t, 1, adapter.OrphanCount())

	// Bounded retries; on the final attempt the orphan is closed with a
	// generation-stamped per-connection CloseCommand.
	for attempt := 0; attempt < MaxOrphanResolveAttempts; attempt++ {
		require.NoError(t, adapter.ResolveOrphans(context.Background()))
	}
	require.Equal(t, 0, adapter.OrphanCount(), "orphan converged, never leaked")
	closeCommand := lastEnvelope(t, peer).GetCloseCommand()
	require.NotNil(t, closeCommand, "bounded retries end in a close")
	require.EqualValues(t, 82, closeCommand.GetConnectionId())
	require.False(t, closeCommand.GetForce())
	require.EqualValues(t, 7, lastEnvelope(t, peer).GetGeneration(),
		"the close is stamped with the orphan's incarnation generation")

	// Recovery path: the lookup starts working before the bound — the
	// orphan rehydrates into real accounting instead of closing.
	remote2 := reconciledConnection(83, "tidb-a:4000", "")
	require.NoError(t, adapter.HandleEnvelope(context.Background(), peer, reconcileRequestEnvelope(97, remote2)))
	require.Equal(t, 1, adapter.OrphanCount())
	baseline := rt.ConnCount()
	adapter.AttachRouterLookup(func(string) (router.Router, error) { return rt, nil })
	require.NoError(t, adapter.ResolveOrphans(context.Background()))
	require.Equal(t, 0, adapter.OrphanCount())
	require.Equal(t, baseline+1, rt.ConnCount(), "recovered orphan joins real accounting")
	require.NotNil(t, adapter.get(83))
	_ = backend.SrcNone
}

// A Rust restart reuses connection id 1 under a newer generation: the
// reconcile must retire the stale same-id Go state exactly once and
// rebuild the new incarnation — never leave both sides on different
// generations forever.
func TestReconcileConvergesReusedIdAcrossGenerations(t *testing.T) {
	rt := router.NewStaticRouter([]string{"tidb-a:4000"})
	handler := &recordingHandler{rt: rt}
	adapter := newTestAdapter(t, handler)
	adapter.AttachRouterLookup(func(string) (router.Router, error) { return rt, nil })
	peer := newFakeSender(24,
		uint64(controlpb.ControlCapability_CONTROL_CAPABILITY_RECONCILE_CONNECTIONS),
		uint64(controlpb.ControlCapability_CONTROL_CAPABILITY_RECONCILE_SESSION_REHYDRATION))

	// The old incarnation lives through the normal path (generation 7).
	establishConnection(t, adapter, peer, 1, "0.0.0.0:6000", "root")
	require.Equal(t, 1, rt.ConnCount())
	baselineCloses := handler.closeCalls

	// Rust restarted: id 1 returns under generation 9 with a different
	// client address.
	fresh := reconciledConnection(1, "tidb-a:4000", "")
	fresh.Generation = 9
	fresh.Identity.ClientAddress = "10.9.8.7:60000"
	require.NoError(t, adapter.HandleEnvelope(context.Background(), peer, reconcileRequestEnvelope(98, fresh)))

	// The stale incarnation was retired exactly once and the new one
	// rebuilt: counts stay convergent, the snapshot reports gen 9.
	require.Equal(t, 1, rt.ConnCount(), "old retired, new rehydrated: no drift")
	require.Equal(t, baselineCloses+1, handler.closeCalls, "stale accounting retired exactly once")
	snapshot := lastEnvelope(t, peer).GetReconcileSnapshot()
	require.Len(t, snapshot.GetConnections(), 1)
	require.EqualValues(t, 9, snapshot.GetConnections()[0].GetGeneration())
	require.Equal(t, "10.9.8.7:60000", snapshot.GetConnections()[0].GetIdentity().GetClientAddress())

	// Idempotent re-apply converges with no further retires.
	require.NoError(t, adapter.HandleEnvelope(context.Background(), peer, reconcileRequestEnvelope(99, fresh)))
	require.Equal(t, 1, rt.ConnCount())
	require.Equal(t, baselineCloses+1, handler.closeCalls)
}

// The redirect watermark survives a Go restart: a rehydrated connection
// reporting watermark 37 issues its next redirect with sequence 38 —
// its own new commands are never judged obsolete.
func TestRehydratedWatermarkResumesSequences(t *testing.T) {
	rt := router.NewStaticRouter([]string{"tidb-a:4000", "tidb-b:4000"})
	handler := &recordingHandler{rt: rt}
	adapter := newTestAdapter(t, handler)
	adapter.AttachRouterLookup(func(string) (router.Router, error) { return rt, nil })
	peer := newFakeSender(25,
		uint64(controlpb.ControlCapability_CONTROL_CAPABILITY_RECONCILE_CONNECTIONS),
		uint64(controlpb.ControlCapability_CONTROL_CAPABILITY_RECONCILE_SESSION_REHYDRATION))

	remote := reconciledConnection(84, "tidb-a:4000", "")
	remote.LastRedirectCommandSequence = 37
	require.NoError(t, adapter.HandleEnvelope(context.Background(), peer, reconcileRequestEnvelope(100, remote)))
	snapshot := lastEnvelope(t, peer).GetReconcileSnapshot()
	require.EqualValues(t, 37, snapshot.GetConnections()[0].GetLastRedirectCommandSequence())

	state := adapter.get(84)
	require.NotNil(t, state)
	require.True(t, state.conn.Redirect(router.NewStaticBackend("tidb-b:4000")))
	command := lastEnvelope(t, peer).GetRedirectCommand()
	require.NotNil(t, command)
	require.EqualValues(t, 38, command.GetCommandSequence(), "next = watermark + 1")
	require.EqualValues(t, 7, lastEnvelope(t, peer).GetGeneration(), "stamped with the session generation")

	// The drain issuer's watermark restores the same way.
	issuer := mustDrainIssuer(t)
	issuer.RestoreSequence(9)
	sender := &recordingSender{}
	require.NoError(t, issuer.StartDrain(context.Background(), sender, 1, 12, &controlpb.DrainCommand{DrainId: "d-next"}))
	sent := sender.sent()
	require.EqualValues(t, 10, sent[len(sent)-1].GetDrainCommand().GetCommandSequence())
}

// A legacy peer (no REHYDRATION capability) keeps the original
// behavior: identification by omission with no orphan tracking and no
// orphan closes — a healthy old-peer session is never killed by the new
// lifecycle.
func TestLegacyPeerKeepsOmissionSemantics(t *testing.T) {
	rt := router.NewStaticRouter([]string{"tidb-a:4000"})
	handler := &recordingHandler{rt: rt}
	adapter := newTestAdapter(t, handler)
	adapter.AttachRouterLookup(func(string) (router.Router, error) { return rt, nil })
	peer := newFakeSender(26,
		uint64(controlpb.ControlCapability_CONTROL_CAPABILITY_RECONCILE_CONNECTIONS))

	remote := reconciledConnection(85, "tidb-a:4000", "")
	require.NoError(t, adapter.HandleEnvelope(context.Background(), peer, reconcileRequestEnvelope(101, remote)))
	require.Empty(t, lastEnvelope(t, peer).GetReconcileSnapshot().GetConnections())
	require.Equal(t, 0, adapter.OrphanCount(), "legacy peers are never orphan-tracked")
	require.Equal(t, 0, rt.ConnCount(), "and never blindly adopted")
	require.NoError(t, adapter.ResolveOrphans(context.Background()))
	peer.mu.Lock()
	for _, envelope := range peer.messages {
		require.Nil(t, envelope.GetCloseCommand(), "no orphan close for legacy peers")
	}
	peer.mu.Unlock()
}

// Lineage is the control epoch, not the config generation: a Rust
// restart may keep the same generation, and only the new epoch plus a
// new identity mark the new incarnation. Both arrival orders converge
// with the stale same-id state retired exactly once.
func TestSameGenerationNewEpochLineage(t *testing.T) {
	// Order A: the new incarnation's handshake arrives before any
	// reconcile.
	rt := router.NewStaticRouter([]string{"tidb-a:4000"})
	handler := &recordingHandler{rt: rt}
	adapter := newTestAdapter(t, handler)
	oldPeer := newFakeSender(30)
	establishConnection(t, adapter, oldPeer, 1, "0.0.0.0:6000", "root")
	require.Equal(t, 1, rt.ConnCount())
	baselineCloses := handler.closeCalls

	// Same id, same generation (7), NEW epoch and a different client
	// address: the old state is retired exactly once and the handshake
	// succeeds instead of tripping the closed-id tombstone.
	newPeer := newFakeSender(31)
	require.NoError(t, adapter.HandleEnvelope(context.Background(), newPeer, &controlpb.ControlEnvelope{
		RequestId:  900,
		Generation: 7,
		Body: &controlpb.ControlEnvelope_HandshakeResponse{HandshakeResponse: &controlpb.HandshakeResponseEvent{
			Connection: &controlpb.ConnectionIdentity{
				ConnectionId:    1,
				ListenerAddress: "0.0.0.0:6000",
				ClientAddress:   "10.0.0.2:23456",
				ProxyAddress:    "192.0.2.10:4000",
			},
			Handshake: testHandshake("root"),
		}},
	}))
	require.Equal(t, baselineCloses+1, handler.closeCalls, "stale lineage retired exactly once")
	state := adapter.get(1)
	require.NotNil(t, state)
	require.Equal(t, "10.0.0.2:23456", state.identity.GetClientAddress())

	// Order B: the reconcile arrives before any handshake.
	rt2 := router.NewStaticRouter([]string{"tidb-a:4000"})
	handler2 := &recordingHandler{rt: rt2}
	adapter2 := newTestAdapter(t, handler2)
	adapter2.AttachRouterLookup(func(string) (router.Router, error) { return rt2, nil })
	oldPeer2 := newFakeSender(40)
	establishConnection(t, adapter2, oldPeer2, 1, "0.0.0.0:6000", "root")
	require.Equal(t, 1, rt2.ConnCount())
	closesBefore := handler2.closeCalls

	newPeer2 := newFakeSender(41,
		uint64(controlpb.ControlCapability_CONTROL_CAPABILITY_RECONCILE_CONNECTIONS),
		uint64(controlpb.ControlCapability_CONTROL_CAPABILITY_RECONCILE_SESSION_REHYDRATION))
	fresh := reconciledConnection(1, "tidb-a:4000", "")
	fresh.Generation = 7 // deliberately the SAME generation
	fresh.Identity.ClientAddress = "10.0.0.3:34567"
	require.NoError(t, adapter2.HandleEnvelope(context.Background(), newPeer2, reconcileRequestEnvelope(902, fresh)))
	require.Equal(t, closesBefore+1, handler2.closeCalls, "stale lineage retired exactly once via reconcile")
	require.Equal(t, 1, rt2.ConnCount(), "no drift: retired plus rehydrated")
	snapshot := lastEnvelope(t, newPeer2).GetReconcileSnapshot()
	require.Len(t, snapshot.GetConnections(), 1)
	require.Equal(t, "10.0.0.3:34567", snapshot.GetConnections()[0].GetIdentity().GetClientAddress())
}

// The composite production handler restores the drain watermark from a
// real reconcile request: the next StartDrain issues watermark + 1.
func TestCompositeHandlerRestoresDrainWatermark(t *testing.T) {
	rt := router.NewStaticRouter([]string{"tidb-a:4000"})
	handler := &recordingHandler{rt: rt}
	adapter := newTestAdapter(t, handler)
	issuer := mustDrainIssuer(t)
	consumer := NewMeteringConsumer()
	composite, err := NewCompositeControlHandler(adapter, issuer, consumer)
	require.NoError(t, err)
	peer := newFakeSender(50,
		uint64(controlpb.ControlCapability_CONTROL_CAPABILITY_RECONCILE_CONNECTIONS),
		uint64(controlpb.ControlCapability_CONTROL_CAPABILITY_RECONCILE_SESSION_REHYDRATION))

	// Metering flows through the composite too.
	require.NoError(t, composite.HandleEnvelope(context.Background(), peer, &controlpb.ControlEnvelope{
		RequestId: 1,
		Body: &controlpb.ControlEnvelope_MeteringBatch{MeteringBatch: &controlpb.MeteringBatch{
			Sequence: 1,
			Deltas:   []*controlpb.MeteringDelta{{Keyspace: "ks", BackendId: "tidb-a", ResponseBytes: 5}},
		}},
	}))
	require.EqualValues(t, 1, consumer.LastApplied())

	// The real reconcile request carries the drain watermark.
	require.NoError(t, composite.HandleEnvelope(context.Background(), peer, &controlpb.ControlEnvelope{
		RequestId:  2,
		Generation: 7,
		Body: &controlpb.ControlEnvelope_ReconcileRequest{ReconcileRequest: &controlpb.ReconcileRequest{
			KnownGeneration:          7,
			LastDrainCommandSequence: 9,
		}},
	}))
	snapshot := lastEnvelope(t, peer).GetReconcileSnapshot()
	require.NotNil(t, snapshot)
	require.EqualValues(t, 1, snapshot.GetMeteringSequence(), "composite wires the consumer's ack")

	require.NoError(t, issuer.StartDrain(context.Background(), peer, 3, 12, &controlpb.DrainCommand{DrainId: "d-after"}))
	command := lastEnvelope(t, peer).GetDrainCommand()
	require.NotNil(t, command)
	require.EqualValues(t, 10, command.GetCommandSequence(), "next = restored watermark + 1")
	require.NotEqual(t, "d-after", command.GetDrainId(), "incarnation-qualified wire id")

	// Drain results (carrying the wire id) route through the composite
	// to the issuer.
	require.NoError(t, composite.HandleEnvelope(context.Background(), peer, &controlpb.ControlEnvelope{
		RequestId: 4,
		Body: &controlpb.ControlEnvelope_DrainResult{DrainResult: &controlpb.DrainResult{
			DrainId: command.GetDrainId(), ActiveConnections: 0, Complete: true,
			Code: controlpb.ErrorCode_ERROR_CODE_OK,
		}},
	}))
	_, done := issuer.Progress("d-after")
	require.True(t, done)
}

// A drain id is bound to one issuance for the issuer's lifetime: after
// d1 and d2 both completed, re-issuing d1 re-sends its ORIGINAL
// sequence (never a new one), and the sequence space fails closed at
// exhaustion.
func TestDrainIdBindingAndSequenceExhaustion(t *testing.T) {
	issuer := mustDrainIssuer(t)
	sender := &recordingSender{}
	require.NoError(t, issuer.StartDrain(context.Background(), sender, 1, 12, &controlpb.DrainCommand{DrainId: "d1"}))
	d1Wire := sender.sent()[0].GetDrainCommand().GetDrainId()
	require.NoError(t, issuer.HandleDrainResult(drainResult(d1Wire, 0, 0, 0, true)))
	require.NoError(t, issuer.StartDrain(context.Background(), sender, 2, 12, &controlpb.DrainCommand{DrainId: "d2"}))
	d2Wire := sender.sent()[1].GetDrainCommand().GetDrainId()
	require.NoError(t, issuer.HandleDrainResult(drainResult(d2Wire, 0, 0, 0, true)))

	// Re-issue long-completed d1: the same wire id and sequence 1.
	require.NoError(t, issuer.StartDrain(context.Background(), sender, 3, 12, &controlpb.DrainCommand{DrainId: "d1"}))
	sent := sender.sent()
	last := sent[len(sent)-1].GetDrainCommand()
	require.Equal(t, d1Wire, last.GetDrainId())
	require.EqualValues(t, 1, last.GetCommandSequence(), "the original binding, never a new sequence")

	// Sequence exhaustion fails closed.
	exhausted := mustDrainIssuer(t)
	exhausted.RestoreSequence(^uint64(0))
	err := exhausted.StartDrain(context.Background(), sender, 4, 12, &controlpb.DrainCommand{DrainId: "d-max"})
	require.ErrorIs(t, err, ErrDrainSequenceExhausted)
}

// Concurrent ResolveOrphans and reconcile cannot double-attach or kill
// a freshly recovered session: the rehydration claim spans the whole
// resolution lifecycle.
func TestConcurrentOrphanResolutionAndReconcile(t *testing.T) {
	rt := router.NewStaticRouter([]string{"tidb-a:4000"})
	handler := &recordingHandler{rt: rt}
	adapter := newTestAdapter(t, handler)
	peer := newFakeSender(60,
		uint64(controlpb.ControlCapability_CONTROL_CAPABILITY_RECONCILE_CONNECTIONS),
		uint64(controlpb.ControlCapability_CONTROL_CAPABILITY_RECONCILE_SESSION_REHYDRATION),
		uint64(controlpb.ControlCapability_CONTROL_CAPABILITY_PER_CONNECTION_CLOSE))

	// Seed an orphan (no lookup attached yet).
	remote := reconciledConnection(86, "tidb-a:4000", "")
	require.NoError(t, adapter.HandleEnvelope(context.Background(), peer, reconcileRequestEnvelope(903, remote)))
	require.Equal(t, 1, adapter.OrphanCount())

	// The lookup comes online; a reconcile and the maintenance cadence
	// race to resolve the same orphan.
	adapter.AttachRouterLookup(func(string) (router.Router, error) { return rt, nil })
	done := make(chan struct{}, 2)
	go func() {
		_ = adapter.ResolveOrphans(context.Background())
		done <- struct{}{}
	}()
	go func() {
		_ = adapter.HandleEnvelope(context.Background(), peer, reconcileRequestEnvelope(904, remote))
		done <- struct{}{}
	}()
	<-done
	<-done

	require.Equal(t, 0, adapter.OrphanCount())
	require.Equal(t, 1, rt.ConnCount(), "attached exactly once, never double-counted")
	require.NotNil(t, adapter.get(86))
	// Nothing closed the recovered session.
	peer.mu.Lock()
	for _, envelope := range peer.messages {
		require.Nil(t, envelope.GetCloseCommand(), "no close raced the recovery")
	}
	peer.mu.Unlock()
}

// rotatingSender rotates the adapter's current sender to next while its
// own close Send is still in flight, then returns success — modeling a
// stale lineage whose write completes just as a reconnect lands.
type rotatingSender struct {
	*fakeSender
	adapter *RouterAdapter
	next    EnvelopeSender
	once    sync.Once
}

func (peer *rotatingSender) Send(ctx context.Context, envelope *controlpb.ControlEnvelope) error {
	if err := peer.fakeSender.Send(ctx, envelope); err != nil {
		return err
	}
	if envelope.GetCloseCommand() != nil {
		peer.once.Do(func() { peer.adapter.rememberSender(peer.next) })
	}
	return nil
}

// A stale sender's in-flight Send returning nil after a rotation must
// NOT transfer the orphan-close obligation into the dead lineage: the
// compare-and-delete retains the orphan, and the next cadence carries
// the close on the live sender before deleting.
func TestOrphanCloseRetainedWhenSenderRotatesInFlight(t *testing.T) {
	handler := &recordingHandler{rt: router.NewStaticRouter([]string{"tidb-a:4000"})}
	adapter := newTestAdapter(t, handler)
	capabilities := []uint64{
		uint64(controlpb.ControlCapability_CONTROL_CAPABILITY_RECONCILE_CONNECTIONS),
		uint64(controlpb.ControlCapability_CONTROL_CAPABILITY_RECONCILE_SESSION_REHYDRATION),
		uint64(controlpb.ControlCapability_CONTROL_CAPABILITY_PER_CONNECTION_CLOSE),
	}
	replacement := newFakeSender(24, capabilities...)
	stale := &rotatingSender{
		fakeSender: newFakeSender(23, capabilities...),
		adapter:    adapter,
		next:       replacement,
	}

	// No RouterLookup attached: the orphan cannot rehydrate and must
	// converge to a bounded close.
	remote := reconciledConnection(84, "tidb-gone:4000", "")
	require.NoError(t, adapter.HandleEnvelope(context.Background(), stale, reconcileRequestEnvelope(98, remote)))
	require.Equal(t, 1, adapter.OrphanCount())

	// On the bounded attempt the stale sender's Send succeeds, but the
	// reconnect rotated the current sender mid-flight.
	for attempt := 0; attempt < MaxOrphanResolveAttempts; attempt++ {
		require.NoError(t, adapter.ResolveOrphans(context.Background()))
	}
	require.NotNil(t, lastEnvelope(t, stale.fakeSender).GetCloseCommand(),
		"the stale lineage did carry a close")
	require.Equal(t, 1, adapter.OrphanCount(),
		"nil Send error alone must not delete: the sender is no longer current")

	// The next cadence re-sends on the live lineage and only then
	// transfers responsibility.
	require.NoError(t, adapter.ResolveOrphans(context.Background()))
	require.NotNil(t, lastEnvelope(t, replacement).GetCloseCommand())
	require.Equal(t, 0, adapter.OrphanCount())
}

// A SUCCESSFUL RouteResult lost on the wire, followed by the SAME Rust
// lineage reconnecting (same identity, same generation) with the
// authoritative record naming the assigned backend, must COMPLETE the
// pending assignment exactly once: router/backend accounting reaches
// EXACT 1 and the snapshot echoes the backend. Red-first: the pre-fix
// handleReconcile skipped known same-identity states without aligning
// the remote backend to the pending assignment, so accounting stayed 0
// and the snapshot echoed an empty backend.
func TestReconcileCompletesLostSuccessfulAssignment(t *testing.T) {
	rt := router.NewStaticRouter([]string{"tidb-a:4000"})
	handler := &recordingHandler{rt: rt}
	adapter := newTestAdapter(t, handler)
	adapter.AttachRouterLookup(func(string) (router.Router, error) { return rt, nil })

	oldPeer := newFakeSender(50)
	sendHandshake(t, adapter, oldPeer, 7, "0.0.0.0:6000", "root")
	sendRoute(t, adapter, oldPeer, 7, "0.0.0.0:6000", "root")
	assignment := lastAssignment(t, oldPeer)
	require.Equal(t, "tidb-a:4000", assignment.GetBackendAddress())
	// The successful RouteResult is LOST: accounting never advanced.
	require.Equal(t, 0, rt.ConnCount())

	// The SAME lineage reconnects on a new control session and reports
	// the live connection with the exact identity, generation, and the
	// backend it is really connected to.
	newPeer := newFakeSender(51,
		uint64(controlpb.ControlCapability_CONTROL_CAPABILITY_RECONCILE_CONNECTIONS),
		uint64(controlpb.ControlCapability_CONTROL_CAPABILITY_RECONCILE_SESSION_REHYDRATION))
	remote := &controlpb.ReconcileConnection{
		ConnectionId: 7,
		BackendId:    assignment.GetBackendId(),
		Namespace:    "ns-a",
		Generation:   7,
		Identity:     testIdentity(7, "0.0.0.0:6000"),
	}
	require.NoError(t, adapter.HandleEnvelope(context.Background(), newPeer, reconcileRequestEnvelope(910, remote)))
	require.Equal(t, 1, rt.ConnCount(), "reconcile must repair the lost successful assignment")

	snapshot := lastEnvelope(t, newPeer).GetReconcileSnapshot()
	require.Len(t, snapshot.GetConnections(), 1)
	require.Equal(t, assignment.GetBackendId(), snapshot.GetConnections()[0].GetBackendId(),
		"the snapshot echoes the completed backend, not an empty one")

	// The LATE original RouteResult must be absorbed idempotently.
	sendRouteResult(t, adapter, newPeer, assignment, true)
	require.Equal(t, 1, rt.ConnCount(), "late RouteResult never double-accounts")

	// A remote record naming a DIFFERENT backend than the pending
	// assignment is a DIVERGENCE: the session must terminate (no-op
	// survival is not fail-closed) - the local state retires with the
	// selector's single Finish(false), a precise force CloseCommand
	// goes to the Rust side, no ghost remains, and the late original
	// RouteResult is still a tombstone no-op.
	rt2 := router.NewStaticRouter([]string{"tidb-a:4000"})
	handler2 := &recordingHandler{rt: rt2}
	adapter2 := newTestAdapter(t, handler2)
	adapter2.AttachRouterLookup(func(string) (router.Router, error) { return rt2, nil })
	oldPeer2 := newFakeSender(52)
	sendHandshake(t, adapter2, oldPeer2, 9, "0.0.0.0:6000", "root")
	sendRoute(t, adapter2, oldPeer2, 9, "0.0.0.0:6000", "root")
	divergedAssignment := lastAssignment(t, oldPeer2)
	mismatched := &controlpb.ReconcileConnection{
		ConnectionId: 9,
		BackendId:    "tidb-b:4000",
		Namespace:    "ns-a",
		Generation:   7,
		Identity:     testIdentity(9, "0.0.0.0:6000"),
	}
	newPeer2 := newFakeSender(53,
		uint64(controlpb.ControlCapability_CONTROL_CAPABILITY_RECONCILE_CONNECTIONS),
		uint64(controlpb.ControlCapability_CONTROL_CAPABILITY_RECONCILE_SESSION_REHYDRATION),
		uint64(controlpb.ControlCapability_CONTROL_CAPABILITY_PER_CONNECTION_CLOSE))
	closesBefore := handler2.closeCalls
	require.NoError(t, adapter2.HandleEnvelope(context.Background(), newPeer2, reconcileRequestEnvelope(911, mismatched)))
	require.Equal(t, 0, rt2.ConnCount(), "a diverged backend never joins accounting")
	require.Equal(t, closesBefore+1, handler2.closeCalls, "the diverged session retires exactly once")
	require.Nil(t, adapter2.get(9), "no ghost state remains")
	var divergedClose *controlpb.CloseCommand
	newPeer2.mu.Lock()
	for _, envelope := range newPeer2.messages {
		if cc := envelope.GetCloseCommand(); cc != nil && cc.GetConnectionId() == 9 {
			divergedClose = cc
		}
	}
	newPeer2.mu.Unlock()
	require.NotNil(t, divergedClose, "the Rust side receives a precise CloseCommand")
	require.True(t, divergedClose.GetForce())
	// The late original RouteResult stays a tombstone/unknown no-op.
	sendRouteResultRaw := &controlpb.ControlEnvelope{
		RequestId: 912,
		Body: &controlpb.ControlEnvelope_RouteResult{RouteResult: &controlpb.RouteResult{
			ConnectionId: 9,
			AssignmentId: divergedAssignment.GetAssignmentId(),
			Connected:    true,
		}},
	}
	require.NoError(t, adapter2.HandleEnvelope(context.Background(), newPeer2, sendRouteResultRaw))
	require.Equal(t, 0, rt2.ConnCount(), "late RouteResult after divergence never resurrects accounting")
}
