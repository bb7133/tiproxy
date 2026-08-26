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
	issuer := NewDrainIssuer()
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
