// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package router

import (
	"time"

	"github.com/pingcap/tiproxy/pkg/balance/factor"
	"github.com/pingcap/tiproxy/pkg/balance/observation"
	"github.com/pingcap/tiproxy/pkg/balance/policy"
	"go.uber.org/zap"
)

// The private factory fixes this diagnostic slot before Group publication.
// Existing router factories remain native-factor-only until caller integration
// is complete. Every access below is protected by the original Group lock.
func (g *Group) beginBalanceObservation() *observation.Caller {
	if !g.balanceCapture || !g.observation.Enabled() {
		return nil
	}
	c := g.observation.BeginCaller()
	g.balanceCaller = c
	return c
}

// Registered immediately after acquisition, before input copying or the native
// policy can panic. It never recovers; parent cleanup runs before Group unlock.
func (g *Group) endBalanceObservation(c *observation.Caller) {
	if c == nil {
		return
	}
	g.balanceCaller = nil
	if native, ok := g.policy.(*factor.FactorBasedBalance); ok {
		native.DiscardObservation()
	}
	c.Cleanup()
}

func (g *Group) captureBalanceMembers(c *observation.Caller, backends []policy.BackendCtx) {
	if c == nil {
		return
	}
	if len(backends) > observation.MaxCallerGroups {
		c.Fail(observation.Capacity)
		return
	}
	var members [observation.MaxCallerGroups]uint64
	for i, backend := range backends {
		// Reuse the actual map iteration; do not range the map again or call
		// a backend getter to reconstruct the native input order.
		members[i] = backend.(*backendWrapper).observationID
	}
	c.CaptureGroupBalance(g.observation.NextIdentity(), g.observationID, members[:len(backends)])
}

func (g *Group) balancePolicy(backends []policy.BackendCtx, c *observation.Caller) (policy.BackendCtx, policy.BackendCtx, float64, string, []zap.Field) {
	if c != nil {
		if native, ok := g.policy.(*factor.FactorBasedBalance); ok {
			return native.BackendsToBalanceCaptured(backends, c)
		}
		c.Fail(observation.Malformed)
	}
	return g.policy.BackendsToBalance(backends)
}

func (g *Group) captureBalanceClock(c *observation.Caller, now time.Time, from, to string) {
	if c != nil && g.observation.Enabled() {
		if projected, ok := g.observation.TimeProjection().Project(now); ok {
			c.CaptureBalanceClock(projected, from, to)
		}
	}
}

// err is the original ctx.Err result. Keeping this call between ele != nil and
// i < count preserves Go's reads at list exhaustion and at the quota boundary.
func (g *Group) captureBalanceContext(err error) bool {
	if c := g.balanceCaller; c != nil {
		c.CaptureBalanceContext(err != nil)
	}
	return err == nil
}

// Only explicit normal-return sites publish a result. A panic cannot be
// mistaken for a completed zero-redirect round by the unconditional defer.
func (g *Group) publishBalanceObservation(c *observation.Caller, accepted int) {
	if c == nil {
		return
	}
	if accepted > observation.MaxBalanceVisits {
		c.Fail(observation.Capacity)
		return
	}
	if c.CaptureBalanceResult(uint16(accepted)) && c.Seal() {
		g.observation.PublishCaller(c)
	}
}
