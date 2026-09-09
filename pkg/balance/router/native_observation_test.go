// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package router

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/pingcap/tiproxy/lib/config"
	"github.com/pingcap/tiproxy/pkg/balance/factor"
	"github.com/pingcap/tiproxy/pkg/balance/metricsreader"
	"github.com/pingcap/tiproxy/pkg/balance/observation"
	"github.com/pingcap/tiproxy/pkg/balance/observer"
	"github.com/pingcap/tiproxy/pkg/balance/policy"
	shadowwire "github.com/pingcap/tiproxy/pkg/controlbridge/shadow"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

type nativeGroupReader struct {
	onRead func()
}

func (*nativeGroupReader) BindObservationOwner(*observation.Owner)                               {}
func (*nativeGroupReader) AddQueryExpr(string, metricsreader.QueryExpr, metricsreader.QueryRule) {}
func (*nativeGroupReader) RemoveQueryExpr(string)                                                {}
func (r *nativeGroupReader) GetQueryResult(string) metricsreader.QueryResult {
	if r.onRead != nil {
		r.onRead()
	}
	return metricsreader.QueryResult{Provenance: metricsreader.QueryProvenance{Cluster: 42}}
}
func (*nativeGroupReader) GetBackendMetrics() []byte { return nil }

func TestNativeGroupPublishesBeforeLifecycleReservation(t *testing.T) {
	r, err := observation.NewRecorder(observation.DefaultLimits(), 1, 2)
	require.NoError(t, err)
	defer r.Close()
	o := r.NewNativeOwner()
	next := func() *observation.Delivery {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		d, err := r.Next(ctx)
		require.NoError(t, err)
		return d
	}
	next().Release() // begin
	cfg := config.NewConfig()
	cfg.Balance.Policy = config.BalancePolicyConnection
	cfg.Balance.RoutingPolicy = config.RoutingPolicyIdlest
	create := func(lg *zap.Logger, owner *observation.Owner, group uint64) policy.BalancePolicy {
		f := factor.NewFactorBasedBalanceObserved(lg, &nativeGroupReader{}, owner, group)
		f.Init(cfg)
		return f
	}
	g, err := newGroupCaptured(nil, func(lg *zap.Logger) policy.BalancePolicy { panic("native factory omitted") }, MatchAll, zap.NewNop(), o, create)
	require.NoError(t, err)
	next().Release() // group_created
	init := next()
	require.Equal(t, observation.EntryConfig, init.Record.Evaluation.Native().Entry, "NATIVE_GROUP_FACTORY_INIT")
	init.Release()
	b := newBackendWrapper("a", observer.BackendHealth{BackendInfo: observer.BackendInfo{Addr: "a:4000"}, Healthy: true})
	g.AddBackend("a", b)
	next().Release()
	selection := &selectionObservation{owner: o, session: o.NextIdentity()}
	before := o.AdmittedSequence()
	result, err := g.routeObserved(nil, selection)
	require.NoError(t, err)
	require.Same(t, b, result)
	evaluation := next()
	defer evaluation.Release()
	require.NotNil(t, evaluation.Record.Evaluation, "NATIVE_GROUP_PUBLICATION_PRESENT")
	require.Equal(t, before+1, evaluation.Record.Sequence, "NATIVE_BEFORE_LIFECYCLE_SEQUENCE")
	n := evaluation.Record.Evaluation.Native()
	require.EqualValues(t, 0, n.Backends[0].ConnScore, "NATIVE_PRE_RESERVATION_COUNT")
	reservation := next()
	defer reservation.Release()
	require.Equal(t, evaluation.Record.Sequence+1, reservation.Record.Sequence)
	require.EqualValues(t, 1, reservation.Record.Batch.Witness.Accounts[0].Score, "NATIVE_POST_RESERVATION_COUNT")
	require.Nil(t, g.policy.(*factor.FactorBasedBalance).TakeObservation(), "NATIVE_GROUP_NO_UNPUBLISHED_LOAN")
	require.True(t, o.Enabled())
}

// A config call queued behind the actual resource read must not observe the
// completed route's capture before its publication. A single P and the reader
// barrier place the contender at the Group lock without observer callbacks.
func TestNativeGroupPublicationCannotCrossUnlock(t *testing.T) {
	old := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(old)
	r, err := observation.NewRecorder(observation.DefaultLimits(), 1, 2)
	require.NoError(t, err)
	defer r.Close()
	o := r.NewNativeOwner()
	entered, resume := make(chan struct{}), make(chan struct{})
	var once sync.Once
	reader := &nativeGroupReader{onRead: func() { once.Do(func() { close(entered); <-resume }) }}
	cfg := config.NewConfig()
	cfg.Balance.Policy = config.BalancePolicyResource
	cfg.Balance.RoutingPolicy = config.RoutingPolicyIdlest
	create := func(lg *zap.Logger, owner *observation.Owner, group uint64) policy.BalancePolicy {
		f := factor.NewFactorBasedBalanceObserved(lg, reader, owner, group)
		f.Init(cfg)
		return f
	}
	g, err := newGroupCaptured(nil, func(*zap.Logger) policy.BalancePolicy { panic("native factory omitted") }, MatchAll, zap.NewNop(), o, create)
	require.NoError(t, err)
	for _, id := range []string{"a", "b"} {
		g.AddBackend(id, newBackendWrapper(id, observer.BackendHealth{BackendInfo: observer.BackendInfo{Addr: id + ":4000"}, Healthy: true}))
	}
	wait := func(done <-chan struct{}) {
		t.Helper()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("native Group barrier timeout")
		}
	}
	routeDone := make(chan struct{})
	var routeErr error
	go func() {
		_, routeErr = g.routeObserved(nil, &selectionObservation{owner: o, session: o.NextIdentity()})
		close(routeDone)
	}()
	wait(entered)
	attempted, configDone := make(chan struct{}), make(chan struct{})
	connection := config.NewConfig()
	connection.Balance.Policy = config.BalancePolicyConnection
	go func() { close(attempted); g.SetConfig(connection); close(configDone) }()
	wait(attempted)
	close(resume)
	wait(routeDone)
	wait(configDone)
	require.NoError(t, routeErr)
	require.True(t, o.Enabled(), "NATIVE_GROUP_LOCK_PUBLICATION")
	require.Nil(t, g.policy.(*factor.FactorBasedBalance).TakeObservation(), "NATIVE_GROUP_NO_UNPUBLISHED_LOAN")
}

func TestNativeGroupMixedFrames(t *testing.T) {
	r, err := observation.NewRecorder(observation.DefaultLimits(), 41, 43)
	require.NoError(t, err)
	defer r.Close()
	o := r.NewNativeOwner()
	cfg := config.NewConfig()
	cfg.Balance.Policy = config.BalancePolicyResource
	cfg.Balance.RoutingPolicy = config.RoutingPolicyIdlest
	creator := func(lg *zap.Logger, owner *observation.Owner, group uint64) policy.BalancePolicy {
		f := factor.NewFactorBasedBalanceObserved(lg, &nativeGroupReader{}, owner, group)
		f.Init(cfg)
		return f
	}
	g, err := newGroupCaptured(nil, func(*zap.Logger) policy.BalancePolicy { panic("native factory omitted") }, MatchAll, zap.NewNop(), o, creator)
	require.NoError(t, err)
	for _, id := range []string{"a", "b"} {
		g.AddBackend(id, newBackendWrapper(id, observer.BackendHealth{BackendInfo: observer.BackendInfo{Addr: id + ":4000"}, Healthy: true}))
	}
	path := os.Getenv("CP_ROUTE_NATIVE_MIXED_FRAMES")
	if path == "" {
		path = filepath.Join(t.TempDir(), "native.frames")
	}
	file, err := os.Create(path)
	require.NoError(t, err)
	defer file.Close()
	write := func(frame []byte, err error) {
		t.Helper()
		require.NoError(t, err)
		_, err = file.Write(frame)
		require.NoError(t, err)
	}
	write(shadowwire.EncodeCoverage(41, 43))
	metadata, ok := r.NativeMetadata(o.Epoch())
	require.True(t, ok)
	write(shadowwire.EncodeNativeCoverage(metadata))
	drain := func() {
		t.Helper()
		for count, _ := r.Retained(); count > 0; count, _ = r.Retained() {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			d, err := r.Next(ctx)
			cancel()
			require.NoError(t, err)
			if d.Record.Evaluation != nil {
				write(shadowwire.EncodeEvaluation(d.Record))
			} else {
				write(shadowwire.EncodeRecord(d.Record))
			}
			d.Release()
		}
	}
	drain()
	for _, balance := range []string{config.BalancePolicyResource, config.BalancePolicyLocation, config.BalancePolicyConnection} {
		for _, routing := range []string{config.RoutingPolicyIdlest, config.RoutingPolicyRandom, config.RoutingPolicyPreferIdle} {
			next := config.NewConfig()
			next.Balance.Policy = balance
			next.Balance.RoutingPolicy = routing
			g.SetConfig(next)
			drain()
			for round := 0; round < 3; round++ {
				selection := &selectionObservation{owner: o, session: o.NextIdentity()}
				backend, err := g.routeObserved(nil, selection)
				require.NoError(t, err)
				conn := newMockRedirectableConn(t, uint64(round+1))
				conn.from = backend.(*backendWrapper)
				g.onCreateConnObserved(backend.(BackendInst), conn, true, selection)
				selection.finish()
				drain()
				g.Lock()
				g.routeableObservedBackendsLocked(nil)
				g.Unlock()
				g.Balance(context.Background())
				drain()
				require.NoError(t, g.OnConnClosed(backend.ID(), conn))
				drain()
			}
		}
	}
	require.True(t, o.Enabled(), "NATIVE_MIXED_GO_VALID")
	r.WatermarkOwners()
	drain()
	require.NoError(t, file.Close())
}
