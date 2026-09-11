// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package router

import (
	"github.com/pingcap/tiproxy/pkg/balance/observation"
	"go.uber.org/zap"
)

// Construction fixes all required hooks before any Group or selector exists.
// Production factories do not enter this preparatory path.
func newScoreBasedRouterAttemptCaptured(logger *zap.Logger, owner *observation.Owner, creator NativePolicyCreator) *ScoreBasedRouter {
	router := newScoreBasedRouterMetadataCaptured(logger, owner, creator)
	if owner != nil && owner.Native() {
		router.selectorCapture, router.attemptCapture = true, true
	}
	return router
}

func (router *ScoreBasedRouter) newRouteGroup(values []string) (*Group, error) {
	if router.attemptCapture {
		return newGroupRouteCaptured(values, router.bpCreator, router.matchType, router.logger, router.observation, router.nativeCreator)
	}
	return newGroupCaptured(values, router.bpCreator, router.matchType, router.logger, router.observation, router.nativeCreator)
}

// Called under router.Lock before copying any inventory, address or exclusion.
// The caller registers cleanup before doing any further production work.
func (router *ScoreBasedRouter) beginRouterAttempt(s *selectionObservation, excluded []BackendInst) *observation.Caller {
	if !router.attemptCapture || !router.observation.Enabled() {
		return nil
	}
	c := router.observation.BeginCaller()
	if c == nil {
		return nil
	}
	if s == nil || s.owner != router.observation || !s.capture || s.pending || s.bound || s.ended {
		c.Fail(observation.UnpairedDiscard)
		return c
	}
	if len(router.groups) > observation.MaxCallerGroups || len(excluded) > observation.MaxCallerGroups {
		c.Fail(observation.Capacity)
		return c
	}
	if !c.CaptureRouterRoute(router.observation.NextIdentity(), router.metadataGeneration, s.session, s.next, s.attempt, metadataRule(router.matchType), selectorErrorClass(router.observeError)) {
		return c
	}
	for _, group := range router.groups {
		if group == nil {
			c.Fail(observation.Malformed)
			return c
		}
		if !c.CaptureRouterIdentity(group.observationID, false) {
			return c
		}
	}
	for _, candidate := range excluded {
		backend, ok := candidate.(*backendWrapper)
		if !ok || backend == nil {
			c.Fail(observation.Malformed)
			return c
		}
		if !c.CaptureRouterIdentity(backend.observationID, true) {
			return c
		}
	}
	return c
}

func (router *ScoreBasedRouter) rejectRouterAttempt(c *observation.Caller, s *selectionObservation, err error) {
	if c == nil {
		s.noRoute(0)
		return
	}
	if s == nil {
		c.Fail(observation.Malformed)
		return
	}
	batch := observation.Batch{EventCount: 1, Events: [observation.MaxEvents]observation.Event{{Kind: observation.RouteRejected, Session: s.session}}}
	if c.AppendBatch(batch) && c.CaptureRouterResult(0, selectorErrorClass(err)) && c.Seal() {
		router.observation.PublishCaller(c)
	}
}
