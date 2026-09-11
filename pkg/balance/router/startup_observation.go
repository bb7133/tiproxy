// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package router

import (
	"github.com/pingcap/tiproxy/pkg/balance/observation"
	"go.uber.org/zap"
)

// This private factory fixes startup capture before Init or any Group exists.
func newScoreBasedRouterStartupCaptured(logger *zap.Logger, owner *observation.Owner, creator NativePolicyCreator) *ScoreBasedRouter {
	r := newScoreBasedRouterAttemptCaptured(logger, owner, creator)
	r.startupCapture = owner != nil && owner.Native()
	return r
}

// Init calls this before Subscribe/GetConfig and immediately defers cleanup.
// No mutex is added to Init: its original publication boundary is unchanged.
func (r *ScoreBasedRouter) beginStartupObservation(c *observation.Caller) {
	if c == nil {
		return
	}
	if r.startupStarted || r.metadataGeneration != 0 || len(r.groups) != 0 || len(r.backends) != 0 || r.portConflictDetector != nil {
		c.Fail(observation.Malformed)
	}
	r.startupStarted = true
}

// The actual switch has completed, but rebalanceLoop cannot yet consume a
// queued health/config result. A publication failure changes only evidence.
func (r *ScoreBasedRouter) endStartupObservation(c *observation.Caller, rawRule string) {
	if c == nil {
		return
	}
	if c.CaptureMetadataInit(rawRule, metadataRule(r.matchType)) && c.Seal() {
		r.startupRecorded = r.observation.PublishCaller(c)
	}
}
