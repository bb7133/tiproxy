// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package router

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/pingcap/tiproxy/lib/config"
	"github.com/pingcap/tiproxy/pkg/balance/factor"
	"github.com/pingcap/tiproxy/pkg/balance/observation"
	"github.com/pingcap/tiproxy/pkg/balance/observer"
	"github.com/pingcap/tiproxy/pkg/balance/policy"
	shadowwire "github.com/pingcap/tiproxy/pkg/controlbridge/shadow"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// These fixture witnesses surround the real selector and routeOnce closure.
// They do not replace its decision, native policy, reservation or Finish call.
// Router metadata installation is deliberately outside this component oracle.
func TestSelectorRouteActualFrames(t *testing.T) {
	selectorRouteActualFrames(t, false)
}

func TestSelectorBoundariesActualFrames(t *testing.T) {
	selectorRouteActualFrames(t, true)
}

func selectorRouteActualFrames(t *testing.T, captureBoundaries bool) {
	f := newRouteHookFixture(t, 0, true, false, &nativeGroupReader{})
	cfg := config.NewConfig()
	cfg.Balance.Policy = config.BalancePolicyConnection
	cfg.Balance.RoutingPolicy = config.RoutingPolicyIdlest
	g2, err := newGroupRouteCaptured(nil, nil, MatchAll, zap.NewNop(), f.o,
		func(lg *zap.Logger, owner *observation.Owner, group uint64) policy.BalancePolicy {
			p := factor.NewFactorBasedBalanceObserved(lg, &nativeGroupReader{}, owner, group)
			p.Init(cfg)
			return p
		})
	require.NoError(t, err)
	b := newBackendWrapper("b", observer.BackendHealth{BackendInfo: observer.BackendInfo{Addr: "b:4000"}, Healthy: true})
	g2.AddBackend("b", b)
	router := NewScoreBasedRouterWithObservation(zap.NewNop(), f.o)
	if captureBoundaries {
		router = newScoreBasedRouterSelectorCaptured(zap.NewNop(), f.o, nil)
	}
	router.groups = []*Group{f.g}
	path := os.Getenv("CP_ROUTE_SELECTOR_ROUTE_FRAMES")
	if captureBoundaries {
		path = os.Getenv("CP_ROUTE_SELECTOR_BOUNDARY_FRAMES")
	}
	if path == "" {
		path = filepath.Join(t.TempDir(), "selector-route.jsonl")
	}
	file, err := os.Create(path)
	require.NoError(t, err)
	defer file.Close()
	encoder := json.NewEncoder(file)
	write := func(value any) { t.Helper(); require.NoError(t, encoder.Encode(value)) }
	// uint16 produces a JSON byte array instead of Go's base64 []byte encoding.
	array := func(frame []byte, err error) []uint16 {
		t.Helper()
		require.NoError(t, err)
		result := make([]uint16, len(frame))
		for i, v := range frame {
			result[i] = uint16(v)
		}
		return result
	}
	writeFrame := func(frame []byte, err error) {
		write(map[string]any{"kind": "frame", "bytes": array(frame, err)})
	}
	writeFrame(shadowwire.EncodeCoverage(41, 43))
	metadata, ok := f.r.NativeMetadata(f.o.Epoch())
	require.True(t, ok)
	writeFrame(shadowwire.EncodeNativeCoverage(metadata))
	drain := func() {
		t.Helper()
		for records, _ := f.r.Retained(); records > 0; records, _ = f.r.Retained() {
			d := f.take(t)
			if captureBoundaries && d.Record.Caller != nil {
				require.NotNil(t, d.Record.Caller.Selector(), "SELECTOR_BOUNDARY_FAMILY")
				writeFrame(shadowwire.EncodeCaller(d.Record))
			} else if d.Record.Evaluation != nil {
				require.Equal(t, observation.EntryConfig, d.Record.Evaluation.Native().Entry, "SELECTOR_ROUTE_ONLY_CONSTRUCTION_NATIVE")
				writeFrame(shadowwire.EncodeEvaluation(d.Record))
			} else {
				require.Nil(t, d.Record.Caller, "SELECTOR_ROUTE_NO_ESCAPED_ATTEMPT")
				writeFrame(shadowwire.EncodeRecord(d.Record))
			}
			d.Release()
		}
	}
	drain()
	account := func(backend BackendInst) uint64 {
		if backend == nil {
			return 0
		}
		return backend.(*backendWrapper).observationID
	}
	exclusions := func(backends []BackendInst) []uint64 {
		ids := make([]uint64, 0, len(backends))
		for _, backend := range backends {
			ids = append(ids, account(backend))
		}
		return ids
	}
	class := func(err error) string {
		if err == nil {
			return "none"
		}
		if err == ErrNoBackend {
			return "sentinel"
		}
		return "other"
	}
	bs := router.GetBackendSelector(ClientInfo{})
	original := bs.routeOnce
	var next uint64
	ordinal, attempts, successes, rejected := 0, 0, 0, 0
	bs.routeOnce = func(excluded []BackendInst) (BackendInst, error) {
		input := exclusions(excluded)
		if captureBoundaries && ordinal == 0 {
			drain()
		} // Actual Begin precedes this routeOnce.
		backend, routeErr := original(excluded)
		ordinal++
		attempts++
		d := f.take(t)
		require.NotNil(t, d.Record.Caller, "SELECTOR_ROUTE_ACTUAL_CALLER")
		route := d.Record.Caller.Route()
		require.NotNil(t, route)
		require.Equal(t, account(backend), route.Account, "SELECTOR_ROUTE_ACTUAL_RETURN")
		require.EqualValues(t, len(input), route.ExcludedCount, "SELECTOR_ROUTE_ACTUAL_EXCLUSIONS")
		write(map[string]any{"kind": "attempt", "next": next, "ordinal": ordinal, "excluded": input,
			"backend": account(backend), "error": class(routeErr), "bytes": array(shadowwire.EncodeCaller(d.Record))})
		d.Release()
		if captureBoundaries {
			require.Equal(t, next, bs.selectionCapture.next, "SELECTOR_CAPTURE_NEXT")
			require.EqualValues(t, ordinal, bs.selectionCapture.attempt, "SELECTOR_CAPTURE_ATTEMPT")
		}
		if next == 3 && ordinal == 1 {
			// The first actual rejection has released the router lock. A topology
			// update may select a different Group before Next's second call.
			router.Lock()
			router.groups = []*Group{g2}
			router.Unlock()
		}
		return backend, routeErr
	}
	run := func(expected BackendInst, expectedAttempts int) {
		t.Helper()
		next++
		ordinal = 0
		write(map[string]any{"kind": "begin", "next": next, "current": account(bs.cur), "excluded": exclusions(bs.excluded)})
		backend, routeErr := bs.Next()
		if captureBoundaries {
			drain()
		} // Actual End has already captured the final state.
		if expected == nil {
			require.Nil(t, backend, "SELECTOR_ROUTE_GO_OUTCOME")
		} else {
			require.Same(t, expected, backend, "SELECTOR_ROUTE_GO_OUTCOME")
		}
		require.Equal(t, expectedAttempts, ordinal, "SELECTOR_ROUTE_GO_ATTEMPTS")
		write(map[string]any{"kind": "end", "next": next, "backend": account(backend), "error": class(routeErr),
			"current": account(bs.cur), "excluded": exclusions(bs.excluded)})
		if expected == nil {
			require.Same(t, ErrNoBackend, routeErr)
			rejected++
		} else {
			require.NoError(t, routeErr)
			successes++
			write(map[string]any{"kind": "finish", "backend": account(bs.cur)})
			bs.Finish(newMockRedirectableConn(t, next), false)
			drain()
		}
	}
	run(nil, 1) // A genuinely empty Group: no native evaluation.
	a := newBackendWrapper("a", observer.BackendHealth{BackendInfo: observer.BackendInfo{Addr: "a:4000"}, Healthy: true})
	f.g.AddBackend("a", a)
	drain()
	run(a, 1)
	run(b, 2) // Exclude a, reject in A, then actually reserve b in B.
	run(b, 2) // Exclude b, clear once, then reserve b with a new operation.
	b.mu.BackendHealth.Healthy = false
	run(nil, 2) // Both real attempts reject; retain cur=b with empty exclusions.
	router.groups = []*Group{f.g}
	run(a, 1)
	bs.CloseObservation()
	drain()
	f.r.WatermarkOwners()
	drain()
	write(map[string]any{"kind": "tail", "next": next, "attempts": attempts, "successes": successes, "rejected": rejected})
	require.True(t, f.o.Enabled(), "SELECTOR_ROUTE_OWNER_VALID")
	require.Equal(t, 9, attempts)
	require.Equal(t, 4, successes)
	require.Equal(t, 2, rejected)
	require.NoError(t, file.Close())
	fmt.Printf("SELECTOR_ROUTE_ACTUAL_STREAM next=%d attempts=%d successes=%d rejected=%d\n", next, attempts, successes, rejected)
}
