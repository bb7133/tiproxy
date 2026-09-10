// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package router

import (
	"github.com/pingcap/tiproxy/pkg/balance/factor"
	"github.com/pingcap/tiproxy/pkg/balance/observation"
	"github.com/pingcap/tiproxy/pkg/balance/policy"
)

func (g *Group) beginRouteObservation() *observation.Caller {
	if !g.routeCapture || !g.observation.Enabled() {
		return nil
	}
	c := g.observation.BeginCaller()
	g.routeCaller = c
	return c
}

// Registered before header or getter capture; an interrupted native child is
// discarded before releasing its parent's leases and the original Group lock.
func (g *Group) endRouteObservation(c *observation.Caller) {
	if c == nil {
		return
	}
	g.routeCaller = nil
	if native, ok := g.policy.(*factor.FactorBasedBalance); ok {
		native.DiscardObservation()
	}
	c.Cleanup()
}

func (g *Group) captureRouteHeader(c *observation.Caller, s *selectionObservation, excluded int) {
	if c == nil {
		return
	}
	if s == nil || s.owner != g.observation || s.session == 0 || s.pending || s.bound || s.ended {
		c.Fail(observation.UnpairedDiscard)
		return
	}
	if excluded > observation.MaxCallerGroups {
		c.Fail(observation.Capacity)
		return
	}
	c.CaptureGroupRoute(g.observation.NextIdentity(), g.observationID, s.session, uint16(excluded), nil)
}

func (g *Group) routePolicy(backends []policy.BackendCtx, c *observation.Caller) policy.BackendCtx {
	if c != nil {
		if native, ok := g.policy.(*factor.FactorBasedBalance); ok {
			return native.BackendToRouteCaptured(backends, c)
		}
		c.Fail(observation.Malformed)
	}
	return g.policy.BackendToRoute(backends)
}

// These results are published only at the actual three normal return sites.
// The unconditional cleanup defer never publishes a fabricated panic result.
func (g *Group) publishRouteObservation(c *observation.Caller, s *selectionObservation, backend *backendWrapper) {
	if c == nil {
		return
	}
	var account, operation uint64
	if backend != nil {
		if s == nil {
			c.Fail(observation.UnpairedDiscard)
			return
		}
		account, operation = backend.observationID, s.operation
	}
	if c.CaptureRouteResult(account, operation) && c.Seal() {
		g.observation.PublishCaller(c)
	}
}
