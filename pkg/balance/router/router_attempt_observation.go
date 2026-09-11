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

// Called under router.Lock only after the parent has been leased and its
// cleanup registered, before copying any inventory, address or exclusion.
func (router *ScoreBasedRouter) captureRouterAttempt(c *observation.Caller, s *selectionObservation, excluded []BackendInst) {
	if c == nil {
		return
	}
	if router.metadataGeneration == 0 && !router.startupRecorded {
		c.Fail(observation.Malformed)
		return
	}
	if s == nil || s.owner != router.observation || !s.capture || s.pending || s.bound || s.ended {
		c.Fail(observation.UnpairedDiscard)
		return
	}
	if len(router.groups) > observation.MaxCallerGroups || len(excluded) > observation.MaxCallerGroups {
		c.Fail(observation.Capacity)
		return
	}
	if !c.CaptureRouterRoute(router.observation.NextIdentity(), router.metadataGeneration, s.session, s.next, s.attempt, metadataRule(router.matchType), selectorErrorClass(router.observeError)) {
		return
	}
	for _, group := range router.groups {
		if group == nil {
			c.Fail(observation.Malformed)
			return
		}
		if !c.CaptureRouterIdentity(group.observationID, false) {
			return
		}
	}
	for _, candidate := range excluded {
		backend, ok := candidate.(*backendWrapper)
		if !ok || backend == nil {
			c.Fail(observation.Malformed)
			return
		}
		if !c.CaptureRouterIdentity(backend.observationID, true) {
			return
		}
	}
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
