// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package router

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/pingcap/tiproxy/lib/config"
	"github.com/pingcap/tiproxy/pkg/balance/factor"
	"github.com/pingcap/tiproxy/pkg/balance/observation"
	"github.com/pingcap/tiproxy/pkg/balance/observer"
	"github.com/pingcap/tiproxy/pkg/balance/policy"
	shadowwire "github.com/pingcap/tiproxy/pkg/controlbridge/shadow"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func newRouteHookFixture(t *testing.T, count int, enabled bool, resource bool, reader *nativeGroupReader) *balanceHookFixture {
	t.Helper()
	r, err := observation.NewRecorder(observation.DefaultLimits(), 41, 43)
	require.NoError(t, err)
	t.Cleanup(r.Close)
	o := r.NewNativeOwner()
	cfg := config.NewConfig()
	cfg.Balance.Policy = config.BalancePolicyConnection
	cfg.Balance.RoutingPolicy = config.RoutingPolicyIdlest
	if resource {
		cfg.Balance.Policy = config.BalancePolicyResource
	}
	create := func(lg *zap.Logger, owner *observation.Owner, group uint64) policy.BalancePolicy {
		f := factor.NewFactorBasedBalanceObserved(lg, reader, owner, group)
		f.Init(cfg)
		return f
	}
	factory := newGroupCaptured
	if enabled {
		factory = newGroupRouteCaptured
	}
	g, err := factory(nil, func(*zap.Logger) policy.BalancePolicy { panic("native factory omitted") }, MatchAll, zap.NewNop(), o, create)
	require.NoError(t, err)
	f := &balanceHookFixture{r: r, o: o, g: g}
	for i := 0; i < count; i++ {
		id := fmt.Sprintf("backend-%d", i)
		b := newBackendWrapper(id, observer.BackendHealth{BackendInfo: observer.BackendInfo{Addr: id + ":4000", Keyspace: "tenant"}, Healthy: true})
		g.AddBackend(id, b)
		if i == 0 {
			f.a = b
		} else if i == 1 {
			f.b = b
		}
	}
	return f
}

type routeHookExcluded struct {
	BackendInst
	onID func() string
}

func (e routeHookExcluded) ID() string { return e.onID() }

func TestRouteHooksActualOutcomes(t *testing.T) {
	for _, mode := range []string{"empty", "unhealthy", "excluded", "selected"} {
		t.Run(mode, func(t *testing.T) {
			count := 2
			if mode == "empty" {
				count = 0
			}
			f := newRouteHookFixture(t, count, true, false, &nativeGroupReader{})
			f.discardPrefix(t)
			s := &selectionObservation{owner: f.o, session: f.o.NextIdentity()}
			var excluded []BackendInst
			if mode == "excluded" {
				excluded = []BackendInst{f.a, f.b}
			} else if mode == "selected" {
				excluded = []BackendInst{f.a}
			} else if mode == "unhealthy" {
				f.a.mu.BackendHealth.Healthy, f.b.mu.BackendHealth.Healthy = false, false
			}
			before := f.o.AdmittedSequence()
			selected, err := f.g.routeObserved(excluded, s)
			require.True(t, f.o.Enabled(), "ROUTE_HOOK_OWNER_VALID")
			if mode == "selected" {
				require.NoError(t, err)
				require.Same(t, f.b, selected)
				require.Equal(t, 1, f.b.connScore, "ROUTE_HOOK_PRODUCTION_RESERVE")
			} else {
				require.Same(t, ErrNoBackend, err)
				require.Nil(t, selected)
			}
			d := f.take(t)
			c := d.Record.Caller
			require.NotNil(t, c, "ROUTE_HOOK_ONE_PARENT")
			v := c.Route()
			require.NotNil(t, v, "ROUTE_HOOK_PARENT_UNTIL_WRITER")
			require.Equal(t, s.session, v.Session, "ROUTE_HOOK_ORIGINAL_SESSION")
			require.EqualValues(t, count, v.MemberCount, "ROUTE_HOOK_FULL_INVENTORY")
			var visited []uint64
			for _, read := range v.Reads[:v.ReadCount] {
				if read.Kind == observation.RouteHealthy {
					visited = append(visited, read.Account)
					require.Equal(t, mode != "unhealthy", read.Healthy, "ROUTE_HOOK_ACTUAL_HEALTH")
				}
			}
			require.Equal(t, v.Members[:v.MemberCount], append([]uint64{}, visited...), "ROUTE_HOOK_ORIGINAL_MAP_ORDER")
			require.Equal(t, before+1, d.Record.Sequence)
			require.Equal(t, before+c.Span(), f.o.AdmittedSequence(), "ROUTE_HOOK_NO_STANDALONE_CHILD")
			children := c.Children()
			if mode == "empty" {
				require.Len(t, children, 1, "ROUTE_HOOK_EMPTY_NO_NATIVE")
				require.Nil(t, children[0].Evaluation)
			} else {
				require.Len(t, children, 2, "ROUTE_HOOK_FILTERED_HAS_NATIVE")
				require.NotNil(t, children[0].Evaluation, "ROUTE_HOOK_FILTERED_HAS_NATIVE")
				if mode != "selected" {
					require.Zero(t, children[0].Evaluation.Native().BackendCount, "ROUTE_HOOK_FILTERED_NATIVE_INPUT")
				}
			}
			batch := children[len(children)-1].Batch
			if mode == "selected" {
				require.EqualValues(t, 2, batch.EventCount, "ROUTE_HOOK_COMPLETE_OPEN_RESERVE")
				require.Equal(t, observation.Open, batch.Events[0].Kind)
				require.Equal(t, observation.Reserve, batch.Events[1].Kind)
				require.Equal(t, s.operation, v.Operation, "ROUTE_HOOK_ORIGINAL_OPERATION")
				require.Equal(t, f.b.observationID, v.Account)
			} else {
				require.EqualValues(t, 1, batch.EventCount)
				require.Equal(t, observation.RouteRejected, batch.Events[0].Kind, "ROUTE_HOOK_REJECTION_CHILD")
				require.Zero(t, v.Account)
				require.Zero(t, v.Operation)
			}
			require.EqualValues(t, len(children), v.ResultCompleted, "ROUTE_HOOK_RESULT_AFTER_CHILDREN")
			_, err = shadowwire.EncodeCaller(d.Record)
			require.NoError(t, err, "ROUTE_HOOK_STRICT_CODEC")
			f.r.Close()
			records, bytes := f.r.Retained()
			require.EqualValues(t, len(children)+1, records, "ROUTE_HOOK_WRITER_OWNS_CHILDREN")
			require.GreaterOrEqual(t, bytes, int64(observation.CallerCharge+observation.BatchCharge))
			d.Release()
			records, bytes = f.r.Retained()
			require.Zero(t, records)
			require.Zero(t, bytes, "ROUTE_HOOK_FINAL_RELEASE")
			require.Nil(t, f.g.routeCaller)
		})
	}
}

func TestRouteHooksGetterOrderAndCopies(t *testing.T) {
	f := newRouteHookFixture(t, 1, true, false, &nativeGroupReader{})
	f.discardPrefix(t)
	original := f.a.ID()
	reads := 0
	first := routeHookExcluded{onID: func() string {
		reads++
		// The next comparison must read the changed ID, while the first
		// already-captured backend ID remains the original copied value.
		f.a.id = "changed"
		return "miss"
	}}
	second := routeHookExcluded{onID: func() string { reads++; return "changed" }}
	third := routeHookExcluded{onID: func() string { t.Fatal("ROUTE_HOOK_EXCLUSION_SHORT_CIRCUIT"); return "" }}
	s := &selectionObservation{owner: f.o, session: f.o.NextIdentity()}
	_, err := f.g.routeObserved([]BackendInst{first, second, third}, s)
	require.Same(t, ErrNoBackend, err)
	require.Equal(t, 2, reads, "ROUTE_HOOK_ID_READ_ONCE")
	d := f.take(t)
	c := d.Record.Caller
	require.NotNil(t, c)
	v := c.Route()
	require.EqualValues(t, 5, v.ReadCount, "ROUTE_HOOK_ACTUAL_READ_COUNT")
	require.Equal(t, []observation.RouteReadKind{observation.RouteHealthy, observation.RouteBackendID, observation.RouteExcludedID, observation.RouteBackendID, observation.RouteExcludedID}, []observation.RouteReadKind{v.Reads[0].Kind, v.Reads[1].Kind, v.Reads[2].Kind, v.Reads[3].Kind, v.Reads[4].Kind}, "ROUTE_HOOK_GETTER_ORDER")
	require.Equal(t, original, string(c.Range(v.Reads[1].Text)), "ROUTE_HOOK_COPY_BEFORE_EXCLUDED_GETTER")
	require.Equal(t, "changed", string(c.Range(v.Reads[3].Text)), "ROUTE_HOOK_REPEATED_BACKEND_ID")
	for _, read := range v.Reads[:v.ReadCount] {
		require.Zero(t, read.Completed)
	}
}

func TestRouteHooksCapacityContinuesProduction(t *testing.T) {
	f := newRouteHookFixture(t, 65, true, false, &nativeGroupReader{})
	f.discardPrefix(t)
	reads := 0
	excluded := routeHookExcluded{onID: func() string { reads++; return "miss" }}
	s := &selectionObservation{owner: f.o, session: f.o.NextIdentity()}
	selected, err := f.g.routeObserved([]BackendInst{excluded}, s)
	require.NoError(t, err)
	require.NotNil(t, selected)
	require.Equal(t, 65, reads, "ROUTE_HOOK_CAPACITY_CONTINUES_GO")
	require.False(t, f.o.Enabled())
	records, _ := f.r.Retained()
	require.Zero(t, records, "ROUTE_HOOK_CAPACITY_NO_PREFIX")
}

func TestRouteHooksUnsealedChildBeforeUnlock(t *testing.T) {
	previous := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(previous)
	reader := &nativeGroupReader{}
	f := newRouteHookFixture(t, 2, true, true, reader)
	f.discardPrefix(t)
	entered := make(chan struct{})
	type receipt struct {
		enabled bool
		records int64
	}
	done := make(chan receipt, 1)
	go func() {
		<-entered
		f.g.Lock()
		records, _ := f.r.Retained()
		done <- receipt{f.o.Enabled(), records}
		f.g.Unlock()
	}()
	reader.onRead = func() {
		close(entered)
		runtime.Gosched()
		panic("route native reader interrupted")
	}
	s := &selectionObservation{owner: f.o, session: f.o.NextIdentity()}
	require.PanicsWithValue(t, "route native reader interrupted", func() { _, _ = f.g.routeObserved(nil, s) }, "ROUTE_HOOK_ORIGINAL_PANIC")
	select {
	case r := <-done:
		require.False(t, r.enabled, "ROUTE_HOOK_INVALID_BEFORE_UNLOCK")
		require.Zero(t, r.records, "ROUTE_HOOK_UNSEALED_RELEASE_BEFORE_UNLOCK")
	case <-time.After(5 * time.Second):
		t.Fatal("ROUTE_HOOK_CONTENDER_COMPLETES")
	}
	require.Nil(t, f.g.routeCaller)
	require.Nil(t, f.g.policy.(*factor.FactorBasedBalance).TakeObservation(), "ROUTE_HOOK_NO_DANGLING_CAPTURE")
}

func TestRouteHooksParentOwnsChildAtRead(t *testing.T) {
	reader := &nativeGroupReader{}
	f := newRouteHookFixture(t, 2, true, true, reader)
	f.discardPrefix(t)
	called := false
	reader.onRead = func() {
		if !called {
			called = true
			f.g.routeCaller.Cleanup()
			records, _ := f.r.Retained()
			require.Zero(t, records, "ROUTE_HOOK_OWNED_AT_ALLOCATION")
		}
	}
	s := &selectionObservation{owner: f.o, session: f.o.NextIdentity()}
	_, _ = f.g.routeObserved(nil, s)
	require.True(t, called)
	require.False(t, f.o.Enabled())
	require.Nil(t, f.g.policy.(*factor.FactorBasedBalance).TakeObservation())
}

func TestRouteHooksExistingFactoryStaysNative(t *testing.T) {
	f := newRouteHookFixture(t, 2, false, false, &nativeGroupReader{})
	f.discardPrefix(t)
	s := &selectionObservation{owner: f.o, session: f.o.NextIdentity()}
	_, err := f.g.routeObserved(nil, s)
	require.NoError(t, err)
	d := f.take(t)
	require.Nil(t, d.Record.Caller, "ROUTE_HOOK_FACTORY_FENCE")
	require.NotNil(t, d.Record.Evaluation)
}

func TestRouteHooksMissingSelectionInvalidates(t *testing.T) {
	for _, mode := range []string{"nil", "zero", "pending", "bound", "ended"} {
		t.Run(mode, func(t *testing.T) {
			f := newRouteHookFixture(t, 1, true, false, &nativeGroupReader{})
			f.discardPrefix(t)
			s := &selectionObservation{owner: f.o, session: f.o.NextIdentity()}
			switch mode {
			case "nil":
				s = nil
			case "zero":
				s.session = 0
			case "pending":
				s.pending = true
			case "bound":
				s.bound = true
			case "ended":
				s.ended = true
			}
			backend, err := f.g.routeObserved(nil, s)
			require.NoError(t, err)
			require.Same(t, f.a, backend)
			require.Equal(t, 1, f.a.connScore)
			require.False(t, f.o.Enabled(), "ROUTE_HOOK_SELECTION_REQUIRED")
			records, _ := f.r.Retained()
			require.Zero(t, records)
		})
	}
}

func TestRouteHooksActualFrames(t *testing.T) {
	f := newRouteHookFixture(t, 0, true, false, &nativeGroupReader{})
	path := os.Getenv("CP_ROUTE_ROUTE_HOOK_FRAMES")
	if path == "" {
		path = filepath.Join(t.TempDir(), "route.frames")
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
	metadata, ok := f.r.NativeMetadata(f.o.Epoch())
	require.True(t, ok)
	write(shadowwire.EncodeNativeCoverage(metadata))
	callers, selected, zero := 0, 0, 0
	drain := func() {
		t.Helper()
		for records, _ := f.r.Retained(); records > 0; records, _ = f.r.Retained() {
			d := f.take(t)
			switch {
			case d.Record.Caller != nil:
				callers++
				if d.Record.Caller.Route().Account == 0 {
					zero++
				} else {
					selected++
				}
				write(shadowwire.EncodeCaller(d.Record))
			case d.Record.Evaluation != nil:
				write(shadowwire.EncodeEvaluation(d.Record))
			default:
				write(shadowwire.EncodeRecord(d.Record))
			}
			d.Release()
		}
	}
	drain()
	empty := &selectionObservation{owner: f.o, session: f.o.NextIdentity()}
	_, err = f.g.routeObserved(nil, empty)
	require.Same(t, ErrNoBackend, err)
	drain()
	a := newBackendWrapper("a", observer.BackendHealth{BackendInfo: observer.BackendInfo{Addr: "a:4000"}, Healthy: true})
	b := newBackendWrapper("b", observer.BackendHealth{BackendInfo: observer.BackendInfo{Addr: "b:4000"}, Healthy: true})
	f.g.AddBackend("a", a)
	f.g.AddBackend("b", b)
	drain()
	s := &selectionObservation{owner: f.o, session: f.o.NextIdentity()}
	_, err = f.g.routeObserved([]BackendInst{a, b}, s)
	require.Same(t, ErrNoBackend, err)
	drain()
	for i, excluded := range []BackendInst{a, b} {
		backend, routeErr := f.g.routeObserved([]BackendInst{excluded}, s)
		require.NoError(t, routeErr)
		drain()
		conn := newMockRedirectableConn(t, uint64(i+1))
		f.g.onCreateConnObserved(backend.(*backendWrapper), conn, false, s)
		drain()
	}
	s.finish()
	drain()
	f.r.WatermarkOwners()
	drain()
	require.True(t, f.o.Enabled(), "ROUTE_HOOK_STREAM_VALID")
	require.Equal(t, 4, callers)
	require.Equal(t, 2, selected)
	require.Equal(t, 2, zero)
	require.NoError(t, file.Close())
	fmt.Printf("ROUTE_HOOK_ACTUAL_STREAM callers=%d selected=%d zero=%d\n", callers, selected, zero)
}
