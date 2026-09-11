// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package router

import "github.com/pingcap/tiproxy/pkg/balance/observation"

func (g *Group) beginFinishObservation(s *selectionObservation) *observation.Caller {
	if s == nil || !s.capture || !g.observation.Enabled() {
		return nil
	}
	c := g.observation.BeginCaller()
	g.routeCaller = c
	return c
}

// Called only after the cleanup defer has been registered under the Group lock.
// If ensureBackend later recreates an absent account, its extra Account batch
// makes this one-Created envelope fail closed. Recovery needs its own complete
// identity/lifecycle comparison; the original Go recovery still executes.
func (g *Group) captureFinishHeader(c *observation.Caller, s *selectionObservation, backend BackendInst, success bool) {
	if c == nil {
		return
	}
	b, ok := backend.(*backendWrapper)
	if !ok || b == nil || s == nil || s.owner != g.observation || !s.pending || s.ended {
		c.Fail(observation.UnpairedDiscard)
		return
	}
	c.CaptureGroupFinish(g.observation.NextIdentity(), g.observationID, s.session, b.observationID, s.operation, success)
}

func (g *Group) endFinishObservation(c *observation.Caller) {
	if c == nil {
		return
	}
	g.routeCaller = nil
	c.Cleanup()
}
