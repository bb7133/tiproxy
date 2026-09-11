// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package router

import (
	"context"
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

type balanceHookFixture struct {
	r     *observation.Recorder
	o     *observation.Owner
	g     *Group
	a, b  *backendWrapper
	conns []*mockRedirectableConn
}

func newBalanceHookFixture(t *testing.T, count int, rate float64, enabled bool) *balanceHookFixture {
	t.Helper()
	return newBalanceHookFixturePolicy(t, count, rate, enabled, config.BalancePolicyConnection, &nativeGroupReader{})
}

func newBalanceHookFixturePolicy(t *testing.T, count int, rate float64, enabled bool, balancePolicy string, reader *nativeGroupReader) *balanceHookFixture {
	t.Helper()
	r, err := observation.NewRecorder(observation.DefaultLimits(), 41, 43)
	require.NoError(t, err)
	t.Cleanup(r.Close)
	o := r.NewNativeOwner()
	cfg := config.NewConfig()
	cfg.Balance.Policy = balancePolicy
	cfg.Balance.RoutingPolicy = config.RoutingPolicyIdlest
	cfg.Balance.ConnCount.MigrationsPerSecond = rate
	create := func(lg *zap.Logger, owner *observation.Owner, group uint64) policy.BalancePolicy {
		f := factor.NewFactorBasedBalanceObserved(lg, reader, owner, group)
		f.Init(cfg)
		return f
	}
	factory := newGroupCaptured
	if enabled {
		factory = newGroupBalanceCaptured
	}
	g, err := factory(nil, func(*zap.Logger) policy.BalancePolicy { panic("native factory omitted") }, MatchAll, zap.NewNop(), o, create)
	require.NoError(t, err)
	a := newBackendWrapper("a", observer.BackendHealth{BackendInfo: observer.BackendInfo{Addr: "a:4000", Keyspace: "tenant"}, Healthy: true})
	b := newBackendWrapper("b", observer.BackendHealth{BackendInfo: observer.BackendInfo{Addr: "b:4000", Keyspace: "tenant"}, Healthy: true})
	g.AddBackend("a", a)
	g.AddBackend("b", b)
	f := &balanceHookFixture{r: r, o: o, g: g, a: a, b: b}
	for i := 0; i < count; i++ {
		conn := newMockRedirectableConn(t, uint64(i+1))
		conn.from = a
		_, ok := g.RehydrateConn("a", conn)
		require.True(t, ok)
		f.conns = append(f.conns, conn)
	}
	return f
}

func (f *balanceHookFixture) take(t *testing.T) *observation.Delivery {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	d, err := f.r.Next(ctx)
	require.NoError(t, err)
	t.Cleanup(d.Release)
	return d
}

func (f *balanceHookFixture) discardPrefix(t *testing.T) {
	t.Helper()
	for records, _ := f.r.Retained(); records > 0; records, _ = f.r.Retained() {
		f.take(t).Release()
	}
}

type balanceHookContext struct {
	context.Context
	reads    int
	cancelAt int
	onRead   func(int)
}

func (c *balanceHookContext) Err() error {
	c.reads++
	if c.onRead != nil {
		c.onRead(c.reads)
	}
	if c.cancelAt != 0 && c.reads == c.cancelAt {
		return context.Canceled
	}
	return nil
}

func TestBalanceHooksActualScan(t *testing.T) {
	for _, mode := range []string{"quota", "nil", "cancel", "zero", "refused"} {
		t.Run(mode, func(t *testing.T) {
			count := 4
			if mode == "zero" {
				count = 0
			}
			f := newBalanceHookFixture(t, count, 100, true)
			f.discardPrefix(t)
			ctx := &balanceHookContext{Context: context.Background()}
			if mode == "cancel" {
				ctx.cancelAt = 1
			}
			if mode == "refused" {
				f.conns[0].closing = true
			}
			if mode == "quota" || mode == "nil" {
				for i, conn := range f.conns {
					getConnWrapper(conn).Value.forceClosing = mode == "nil" || i < 2
				}
			}
			before := f.o.AdmittedSequence()
			f.g.Balance(ctx)
			require.True(t, f.o.Enabled(), "BALANCE_HOOK_OWNER_VALID")
			d := f.take(t)
			require.NotNil(t, d.Record.Caller, "BALANCE_HOOK_ONE_PARENT")
			c := d.Record.Caller
			b := c.Balance()
			require.NotNil(t, b, "BALANCE_HOOK_PARENT_UNTIL_WRITER")
			require.Equal(t, before+1, d.Record.Sequence)
			require.Equal(t, before+c.Span(), f.o.AdmittedSequence(), "BALANCE_HOOK_NO_STANDALONE_CHILD")
			require.EqualValues(t, ctx.reads, b.ContextCount, "BALANCE_HOOK_CONTEXT_READ_ONCE")
			switch mode {
			case "refused":
				require.EqualValues(t, 2, b.VisitCount, "BALANCE_HOOK_REFUSAL_CONTINUES")
				require.Equal(t, observation.BalanceCallbackRefused, b.Visits[0].Callback, "BALANCE_HOOK_ACTUAL_FALSE_RESULT")
				require.Equal(t, observation.BalanceCallbackAccepted, b.Visits[1].Callback, "BALANCE_HOOK_ACTUAL_TRUE_RESULT")
				require.EqualValues(t, 1, b.Accepted)
			case "quota":
				require.EqualValues(t, 3, b.VisitCount, "BALANCE_HOOK_SKIPPED_VISITS")
				require.EqualValues(t, 4, b.ContextCount, "BALANCE_HOOK_CONTEXT_BEFORE_QUOTA")
				require.EqualValues(t, 1, b.Accepted)
			case "nil":
				require.EqualValues(t, 4, b.VisitCount, "BALANCE_HOOK_ALL_SKIPPED_VISITS")
				require.EqualValues(t, 4, b.ContextCount, "BALANCE_HOOK_NO_CONTEXT_AFTER_NIL")
				require.Zero(t, b.Accepted)
			case "cancel":
				require.Zero(t, b.VisitCount)
				require.EqualValues(t, 1, b.ContextCount)
				require.True(t, b.Contexts[0])
			case "zero":
				require.Zero(t, b.ContextCount)
				require.False(t, b.ClockSet, "BALANCE_HOOK_ZERO_NO_CLOCK")
			}
			_, err := shadowwire.EncodeCaller(d.Record)
			require.NoError(t, err, "BALANCE_HOOK_STRICT_CODEC")
			f.r.Close()
			records, bytes := f.r.Retained()
			require.EqualValues(t, 2+len(c.Children())-1, records, "BALANCE_HOOK_WRITER_OWNS_CHILDREN")
			require.GreaterOrEqual(t, bytes, int64(observation.CallerCharge+observation.EvaluationCharge))
			d.Release()
			records, bytes = f.r.Retained()
			require.Zero(t, records)
			require.Zero(t, bytes, "BALANCE_HOOK_FINAL_RELEASE")
			require.Nil(t, f.g.balanceCaller)
		})
	}
}

func TestBalanceHooksKeyspaceReads(t *testing.T) {
	for _, direct := range []bool{false, true} {
		t.Run(fmt.Sprint(direct), func(t *testing.T) {
			f := newBalanceHookFixture(t, 4, 100, true)
			f.discardPrefix(t)
			change := func() {
				f.b.mu.Lock()
				f.b.mu.BackendHealth.BackendInfo.Keyspace = "other"
				f.b.mu.Unlock()
			}
			ctx := &balanceHookContext{Context: context.Background()}
			if direct {
				// The actual context read occurs after the whole-pair reads but
				// before redirectConn's independent keyspace backstop.
				ctx.onRead = func(int) { change() }
			} else {
				change()
			}
			f.g.Balance(ctx)
			require.True(t, f.o.Enabled(), "BALANCE_HOOK_KEYSPACE_VALID")
			d := f.take(t)
			c := d.Record.Caller
			require.NotNil(t, c)
			b := c.Balance()
			require.Zero(t, b.Accepted, "BALANCE_HOOK_KEYSPACE_REFUSAL")
			if direct {
				require.EqualValues(t, 4, b.VisitCount, "BALANCE_HOOK_DIRECT_ALL_VISITS")
				require.Equal(t, c.Range(b.From), c.Range(b.To), "BALANCE_HOOK_ORIGINAL_PAIR_READS")
				for _, visit := range b.Visits[:b.VisitCount] {
					require.True(t, visit.Redirect)
					require.Equal(t, observation.BalanceCallbackSkipped, visit.Callback, "BALANCE_HOOK_NO_CALLBACK_AT_BACKSTOP")
					require.Equal(t, "tenant", string(c.Range(visit.From)), "BALANCE_HOOK_ORIGINAL_DIRECT_FROM")
					require.Equal(t, "other", string(c.Range(visit.To)), "BALANCE_HOOK_ORIGINAL_DIRECT_TO")
				}
			} else {
				require.Zero(t, b.ContextCount, "BALANCE_HOOK_PAIR_NO_CONTEXT")
				require.Zero(t, b.VisitCount)
				require.NotEqual(t, c.Range(b.From), c.Range(b.To))
			}
			_, err := shadowwire.EncodeCaller(d.Record)
			require.NoError(t, err)
		})
	}
}

func TestBalanceHooksUnsealedChildBeforeUnlock(t *testing.T) {
	previous := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(previous)
	reader := &nativeGroupReader{}
	f := newBalanceHookFixturePolicy(t, 4, 100, true, config.BalancePolicyResource, reader)
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
		// Let the contender block on the actual Group mutex before unwinding.
		runtime.Gosched()
		panic("balance native reader interrupted")
	}
	require.PanicsWithValue(t, "balance native reader interrupted", func() {
		f.g.Balance(context.Background())
	}, "BALANCE_HOOK_UNSEALED_PANIC")
	select {
	case r := <-done:
		require.False(t, r.enabled, "BALANCE_HOOK_INVALID_BEFORE_UNLOCK")
		require.Zero(t, r.records, "BALANCE_HOOK_UNSEALED_RELEASE_BEFORE_UNLOCK")
	case <-time.After(5 * time.Second):
		t.Fatal("BALANCE_HOOK_CONTENDER_COMPLETES")
	}
	require.Nil(t, f.g.policy.(*factor.FactorBasedBalance).TakeObservation(), "BALANCE_HOOK_NO_DANGLING_CAPTURE")
	f.r.Close()
	records, bytes := f.r.Retained()
	require.Zero(t, records)
	require.Zero(t, bytes)
}

func TestBalanceHooksParentOwnsChildAtRead(t *testing.T) {
	reader := &nativeGroupReader{}
	f := newBalanceHookFixturePolicy(t, 4, 100, true, config.BalancePolicyResource, reader)
	f.discardPrefix(t)
	called := false
	reader.onRead = func() {
		if called {
			return
		}
		called = true
		// Interrupt diagnostic ownership while the child is still inside its
		// first query. The parent alone must already own the unsealed lease.
		f.g.balanceCaller.Cleanup()
		records, _ := f.r.Retained()
		require.Zero(t, records, "BALANCE_HOOK_OWNED_AT_ALLOCATION")
	}
	f.g.Balance(context.Background())
	require.True(t, called)
	require.False(t, f.o.Enabled())
	require.Nil(t, f.g.policy.(*factor.FactorBasedBalance).TakeObservation())
}

func TestBalanceHooksPanicCleansBeforeUnlock(t *testing.T) {
	f := newBalanceHookFixture(t, 4, 2e9, true)
	f.discardPrefix(t)
	before := f.o.AdmittedSequence()
	func() {
		defer func() {
			require.NotNil(t, recover(), "BALANCE_HOOK_ORIGINAL_PANIC")
			require.False(t, f.o.Enabled(), "BALANCE_HOOK_PANIC_INVALID")
			require.Equal(t, before, f.o.AdmittedSequence(), "BALANCE_HOOK_PANIC_NO_PREFIX")
			records, _ := f.r.Retained()
			require.Zero(t, records, "BALANCE_HOOK_PANIC_RELEASE")
			require.Nil(t, f.g.balanceCaller)
			require.True(t, f.g.TryLock(), "BALANCE_HOOK_PANIC_UNLOCK")
			f.g.Unlock()
		}()
		f.g.Balance(context.Background())
	}()
	f.r.Close()
	records, bytes := f.r.Retained()
	require.Zero(t, records)
	require.Zero(t, bytes, "BALANCE_HOOK_PANIC_FINAL_RELEASE")
	require.Nil(t, f.g.policy.(*factor.FactorBasedBalance).TakeObservation())
}

func TestBalanceHooksCapacityDoesNotTruncateScan(t *testing.T) {
	f := newBalanceHookFixture(t, 66, 100, true)
	f.discardPrefix(t)
	for _, conn := range f.conns {
		getConnWrapper(conn).Value.forceClosing = true
	}
	ctx := &balanceHookContext{Context: context.Background()}
	f.g.Balance(ctx)
	require.Equal(t, 66, ctx.reads, "BALANCE_HOOK_CAPACITY_CONTINUES_GO")
	require.False(t, f.o.Enabled(), "BALANCE_HOOK_VISIT_PLUS_ONE")
	records, _ := f.r.Retained()
	require.Zero(t, records, "BALANCE_HOOK_CAPACITY_NO_PREFIX")
}

func TestBalanceHooksExistingFactoryStaysNative(t *testing.T) {
	f := newBalanceHookFixture(t, 4, 100, false)
	f.discardPrefix(t)
	f.g.Balance(context.Background())
	d := f.take(t)
	require.Nil(t, d.Record.Caller, "BALANCE_HOOK_FACTORY_FENCE")
	require.NotNil(t, d.Record.Evaluation)
	d.Release()
	f.discardPrefix(t)
	require.True(t, f.o.Enabled())
}

// Export the full prefix and actual calls, including original native captures
// and complete lifecycle batches. The Rust fixture runner reconstructs history
// from this stream; no synthetic factor/ledger state is supplied by this test.
func TestBalanceHooksActualFrames(t *testing.T) {
	f := newBalanceHookFixture(t, 5, 100, true)
	path := os.Getenv("CP_ROUTE_BALANCE_HOOK_FRAMES")
	if path == "" {
		path = filepath.Join(t.TempDir(), "balance.frames")
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
	callers, positive, zero := 0, 0, 0
	drain := func() {
		t.Helper()
		for records, _ := f.r.Retained(); records > 0; records, _ = f.r.Retained() {
			d := f.take(t)
			switch {
			case d.Record.Caller != nil:
				callers++
				if d.Record.Caller.Balance().ClockSet {
					positive++
				} else {
					zero++
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
	f.conns[0].closing = true // Real callback refusal, distinct from forceClosing.
	for range 3 {
		f.g.Balance(context.Background())
		drain()
	}
	for _, conn := range f.conns {
		require.NoError(t, f.g.OnConnClosed("a", conn))
	}
	drain()
	f.r.WatermarkOwners()
	drain()
	require.True(t, f.o.Enabled(), "BALANCE_HOOK_STREAM_VALID")
	require.Equal(t, 3, callers)
	require.Equal(t, 2, positive)
	require.Equal(t, 1, zero)
	require.NoError(t, file.Close())
	fmt.Printf("BALANCE_HOOK_ACTUAL_STREAM callers=%d positive=%d zero=%d\n", callers, positive, zero)
}
