// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package router

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/pingcap/tiproxy/pkg/balance/observation"
	"github.com/pingcap/tiproxy/pkg/balance/observer"
	shadowwire "github.com/pingcap/tiproxy/pkg/controlbridge/shadow"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func observedRouter(t *testing.T, recorder *observation.Recorder) *ScoreBasedRouter {
	t.Helper()
	var owner *observation.Owner
	if recorder != nil {
		owner = recorder.NewOwner()
	}
	r := NewScoreBasedRouterWithObservation(zap.NewNop(), owner)
	r.bpCreator = simpleBpCreator
	r.updateBackendHealth(observer.NewHealthResult(map[string]*observer.BackendHealth{
		"a": {BackendInfo: observer.BackendInfo{Addr: "127.0.0.1:4000"}, Healthy: true, SupportRedirection: true},
		"b": {BackendInfo: observer.BackendInfo{Addr: "127.0.0.1:4001"}, Healthy: true, SupportRedirection: true},
	}, nil))
	t.Cleanup(r.Close)
	return r
}

func observedConn(t *testing.T, r *ScoreBasedRouter, retry bool) (*mockRedirectableConn, *backendWrapper) {
	t.Helper()
	selector := r.GetBackendSelector(ClientInfo{})
	b, err := selector.Next()
	require.NoError(t, err)
	if retry {
		selector.Finish(nil, false)
		b, err = selector.Next()
		require.NoError(t, err)
	}
	// Reusing the production ConnectionID must not reuse diagnostic incarnation.
	conn := newMockRedirectableConn(t, 7)
	conn.from = b
	selector.Finish(conn, true)
	selector.CloseObservation()
	return conn, b.(*backendWrapper)
}

func drainObservation(t *testing.T, r *observation.Recorder) []observation.Record {
	t.Helper()
	var records []observation.Record
	for retained, _ := r.Retained(); retained > 0; retained, _ = r.Retained() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		delivery, err := r.Next(ctx)
		cancel()
		require.NoError(t, err)
		records = append(records, delivery.Record)
		delivery.Release()
	}
	return records
}

// All values exported by this gate originate in real router/group methods.
// The test never emits handcrafted observations to make the ledger agree.
func TestObservationActualLifecycle(t *testing.T) {
	recorder, err := observation.NewRecorder(observation.DefaultLimits(), 41, 43)
	require.NoError(t, err)
	defer recorder.Close()
	r := observedRouter(t, recorder)
	g := r.groups[0]
	conn, from := observedConn(t, r, true)
	var target *backendWrapper
	for _, b := range r.backends {
		if b != from {
			target = b
		}
	}
	restored := newMockRedirectableConn(t, 7)
	restored.from = target
	_, ok := r.RehydrateConn(target.ID(), restored)
	require.True(t, ok)
	require.NotEqual(t, getConnWrapper(conn).Value.observationID, getConnWrapper(restored).Value.observationID)
	g.Lock()
	accepted := g.redirectConn(getConnWrapper(conn).Value, from, target, "observed", nil, time.Now())
	g.Unlock()
	require.True(t, accepted)
	conn.redirectSucceed()
	require.NoError(t, g.OnRedirectSucceed(from.ID(), target.ID(), conn))
	require.NoError(t, g.OnConnClosed(target.ID(), conn))
	// Actual close and duplicate closed callback must not settle twice.
	require.NoError(t, g.OnConnClosed(target.ID(), conn))
	require.NoError(t, g.OnRedirectSucceed(from.ID(), target.ID(), conn))
	require.NoError(t, g.OnConnClosed(target.ID(), restored))

	// Close before redirect result; retained from/to witnesses remain valid.
	pending, source := observedConn(t, r, false)
	for _, b := range r.backends {
		if b != source {
			target = b
		}
	}
	g.Lock()
	accepted = g.redirectConn(getConnWrapper(pending).Value, source, target, "observed", nil, time.Now())
	g.Unlock()
	require.True(t, accepted)
	require.NoError(t, g.OnConnClosed(target.ID(), pending))
	require.NoError(t, g.OnRedirectFail(source.ID(), target.ID(), pending))

	// Refused issuance, then actual force-close acceptance; no premature refund.
	refused, source := observedConn(t, r, false)
	refused.closing = true
	for _, b := range r.backends {
		if b != source {
			target = b
		}
	}
	g.Lock()
	accepted = g.redirectConn(getConnWrapper(refused).Value, source, target, "observed", nil, time.Now())
	g.Unlock()
	require.False(t, accepted)
	source.setFailover(time.Now().Add(-time.Second))
	g.CloseTimedOutFailoverConnections(time.Now()) // refused ForceClose
	refused.closing = false
	g.CloseTimedOutFailoverConnections(time.Now()) // accepted ForceClose
	require.Equal(t, 1, source.connScore, "LIVE_NO_ACCOUNTING_EFFECT")
	require.NoError(t, g.OnConnClosed(source.ID(), refused))
	source.setFailover(time.Time{})

	// Management/test reconnect is a phase marker, not a score transfer.
	reconnect, source := observedConn(t, r, false)
	reconnect.closing = true
	require.NoError(t, g.RedirectConnections())
	require.Equal(t, phaseRedirectNotify, getConnWrapper(reconnect).Value.phase)
	require.Equal(t, 1, source.connScore, "LIVE_NO_ACCOUNTING_EFFECT")
	require.NoError(t, g.OnRedirectFail(source.ID(), source.ID(), reconnect))
	require.NoError(t, g.OnConnClosed(source.ID(), reconnect))

	// A refused cross-keyspace issuance leaves accounting untouched; a later
	// ordinary failed terminal must roll the target score back to the source.
	failedRedirect, source := observedConn(t, r, false)
	for _, b := range r.backends {
		if b != source {
			target = b
		}
	}
	health := target.getHealth()
	health.Keyspace = "different"
	target.setHealth(health)
	g.Lock()
	accepted = g.redirectConn(getConnWrapper(failedRedirect).Value, source, target, "observed", nil, time.Now())
	g.Unlock()
	require.False(t, accepted)
	health.Keyspace = ""
	target.setHealth(health)
	g.Lock()
	accepted = g.redirectConn(getConnWrapper(failedRedirect).Value, source, target, "observed", nil, time.Now())
	g.Unlock()
	require.True(t, accepted)
	failedRedirect.redirectFail()
	require.NoError(t, g.OnRedirectFail(source.ID(), target.ID(), failedRedirect))
	require.NoError(t, g.OnConnClosed(source.ID(), failedRedirect))

	// Accepted administrative self reconnects exercise actual remove+append
	// order in the same account, with no pending_redirects accounting claim.
	admin, source := observedConn(t, r, false)
	adminOther := newMockRedirectableConn(t, 7)
	adminOther.from = source
	_, ok = r.RehydrateConn(source.ID(), adminOther)
	require.True(t, ok)
	require.NoError(t, g.RedirectConnections())
	for _, c := range []*mockRedirectableConn{admin, adminOther} {
		c.redirectSucceed()
		require.NoError(t, g.OnRedirectSucceed(source.ID(), source.ID(), c))
	}
	for _, c := range []*mockRedirectableConn{admin, adminOther} {
		require.NoError(t, g.OnConnClosed(source.ID(), c))
	}

	failed := r.GetBackendSelector(ClientInfo{})
	_, err = failed.Next()
	require.NoError(t, err)
	failed.Finish(nil, false)
	failed.CloseObservation()
	// Real removal/recreation gives a new account and group incarnation.
	old := r.backends["a"].observationID
	r.updateBackendHealth(observer.NewHealthResult(nil, nil))
	emptySelection := r.GetBackendSelector(ClientInfo{})
	_, err = emptySelection.Next()
	require.ErrorIs(t, err, ErrNoBackend)
	emptySelection.CloseObservation()
	r.updateBackendHealth(observer.NewHealthResult(map[string]*observer.BackendHealth{
		"a": {BackendInfo: observer.BackendInfo{Addr: "127.0.0.1:4000"}, Healthy: true, SupportRedirection: true},
	}, nil))
	require.NotEqual(t, old, r.backends["a"].observationID)
	require.Zero(t, r.ConnCount())
	require.Empty(t, recorder.InvalidOwners(), "LIVE_NO_LOSS")
	records := drainObservation(t, recorder)
	var output []byte
	var next uint64 = 1
	kinds := map[observation.Kind]int{}
	successfulArrival := false
	for _, record := range records {
		require.Equal(t, next, record.Sequence)
		next += uint64(record.Batch.EventCount)
		for i := uint8(0); i < record.Batch.EventCount; i++ {
			event := record.Batch.Events[i]
			kinds[event.Kind]++
			if event.Kind == observation.Redirected && event.Success && record.Batch.Witness.Before.RedirectPending && !record.Batch.Witness.After.Closed {
				successfulArrival = true
			}
		}
		frame, err := shadowwire.EncodeRecord(record)
		require.NoError(t, err)
		require.NoError(t, shadowwire.ValidateFrame(frame))
		output = append(output, frame...)
	}
	require.True(t, successfulArrival, "actual receiver callback must publish successful physical arrival")
	for _, kind := range []observation.Kind{observation.Begin, observation.GroupCreated, observation.Account, observation.Open, observation.Reserve, observation.Created, observation.Redirect, observation.Redirected, observation.Closing, observation.Closed, observation.Rehydrate, observation.Rejected, observation.SelectionDone, observation.RouteRejected, observation.Reconnect, observation.RemoveAccount, observation.GroupRemoved} {
		require.Positive(t, kinds[kind], "kind %d", kind)
	}
	if path := os.Getenv("CP_ROUTE_LIVE_FRAMES"); path != "" {
		require.NoError(t, os.WriteFile(path, output, 0600))
	}
	t.Logf("actual capture: %d batches, %d events, %d kinds", len(records), next-1, len(kinds))
}

func TestObservationAbandonNeverRefunds(t *testing.T) {
	recorder, err := observation.NewRecorder(observation.DefaultLimits(), 41, 43)
	require.NoError(t, err)
	defer recorder.Close()
	r := observedRouter(t, recorder)
	selector := r.GetBackendSelector(ClientInfo{})
	b, err := selector.Next()
	require.NoError(t, err)
	selector.CloseObservation()
	require.Equal(t, 1, b.(*backendWrapper).connScore)
	require.Len(t, recorder.InvalidOwners(), 1, "UnpairedDiscard must invalidate the entire owner")
	require.Equal(t, observation.UnpairedDiscard, recorder.InvalidOwners()[0].Reason)
	// A real late Finish still performs Go's rollback, but cannot copy witnesses
	// or restore qualification for the previously invalidated interval.
	retained, _ := recorder.Retained()
	selector.Finish(nil, false)
	require.Zero(t, b.(*backendWrapper).connScore)
	after, _ := recorder.Retained()
	require.Equal(t, retained, after)
	for _, record := range drainObservation(t, recorder) {
		for i := uint8(0); i < record.Batch.EventCount; i++ {
			require.NotEqual(t, observation.Closed, record.Batch.Events[i].Kind)
		}
	}
}

func TestObservationInvalidFastPathNeverReadsWitness(t *testing.T) {
	recorder, err := observation.NewRecorder(observation.DefaultLimits(), 41, 43)
	require.NoError(t, err)
	defer recorder.Close()
	owner := recorder.NewOwner()
	owner.Invalidate(observation.TransportLost)
	group := &Group{observation: owner}
	// A nil connList would panic if the helper copied this diagnostic witness.
	// Invalid must return before dereferencing it; production routing still owns
	// and updates its own real wrappers independently.
	require.NotPanics(t, func() {
		group.capture(observation.Batch{EventCount: 1}, nil, observation.ConnectionState{}, &backendWrapper{observationID: 1})
	}, "LIVE_INVALID_BEFORE_COPY")
	require.Equal(t, observation.TransportLost, recorder.InvalidOwners()[0].Reason)
	r := NewScoreBasedRouterWithObservation(zap.NewNop(), owner)
	r.bpCreator = simpleBpCreator
	r.updateBackendHealth(observer.NewHealthResult(map[string]*observer.BackendHealth{"a": {BackendInfo: observer.BackendInfo{Addr: "127.0.0.1:4000"}, Healthy: true}}, nil))
	conn, b := observedConn(t, r, false)
	require.Equal(t, 1, b.connScore)
	require.NoError(t, b.group.OnConnClosed(b.ID(), conn))
	require.Zero(t, r.ConnCount())
}

func TestObservationDefaultDisabled(t *testing.T) {
	r := NewScoreBasedRouter(zap.NewNop())
	defer r.Close()
	require.Nil(t, r.observation, "LIVE_DEFAULT_DISABLED")
	g, err := NewGroup(nil, simpleBpCreator, MatchAll, zap.NewNop())
	require.NoError(t, err)
	require.Nil(t, g.observation, "LIVE_DEFAULT_DISABLED")
}
