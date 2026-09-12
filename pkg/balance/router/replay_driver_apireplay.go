// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build apireplay

package router

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/pingcap/tiproxy/lib/config"
	"github.com/pingcap/tiproxy/pkg/balance/observer"
	"github.com/pingcap/tiproxy/pkg/balance/policy"
	"go.uber.org/zap"
)

// ReplayDriver schedules the router's external inputs from the API differential
// recorder (contract a9c497c3 §1/§3; recorder README §1/§5). It is compiled only
// with the `apireplay` build tag and is the same technique the reviewed
// api_differential_test.go adapter uses: the background loop is drained after
// the real Init, then every health result, config update and rebalance tick is
// delivered synchronously to the exact production handlers by the harness'
// serialized scheduler. It records nothing itself and reads no private state;
// the harness records each input after the handler returns (consumption time).
type ReplayDriver struct {
	router *ScoreBasedRouter
}

// ReplayNanos is the harness logical clock (nanoseconds since trace start).
// The recording build overlays time.Now() in group.go and router_score.go with
// replayNow (the recording overlay names this symbol; run.py uses its own), so recorded timeouts and
// replayed timeouts share one clock basis.
var ReplayNanos atomic.Int64

func replayNow() time.Time { return time.Unix(1_700_000_000, ReplayNanos.Load()) }

// NewReplayDriver runs the real Init with an already-cancelled context so the
// rebalance loop exits immediately, waits for it, and returns the driver.
// bo may be nil when the harness forwards health results itself.
func NewReplayDriver(router *ScoreBasedRouter, bo observer.BackendObserver, bpCreator func(*zap.Logger) policy.BalancePolicy, cfgGetter config.ConfigGetter) *ReplayDriver {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	router.Init(ctx, bo, bpCreator, cfgGetter, nil)
	router.wg.Wait()
	// The disabled loop would never drain the router's own subscription; the
	// harness forwards every result itself (Inputs.Forward), so drop it here.
	if bo != nil {
		bo.Unsubscribe("score_based_router")
	}
	return &ReplayDriver{router: router}
}

// DeliverHealth applies one observer result through the production handler.
func (d *ReplayDriver) DeliverHealth(result observer.HealthResult) {
	d.router.updateBackendHealth(result)
}

// DeliverConfig applies one validated configuration through the production handler.
func (d *ReplayDriver) DeliverConfig(cfg *config.Config) {
	d.router.setConfig(cfg)
}

// Tick runs one real rebalance iteration (the production loop body).
func (d *ReplayDriver) Tick() {
	d.router.rebalance(context.Background())
}

// Router exposes the wrapped router for public API calls.
func (d *ReplayDriver) Router() *ScoreBasedRouter { return d.router }
