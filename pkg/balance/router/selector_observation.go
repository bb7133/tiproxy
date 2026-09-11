// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package router

import (
	"github.com/pingcap/tiproxy/pkg/balance/observation"
	"go.uber.org/zap"
)

// selectorBoundary copies only immutable observation identities at the actual
// sequential selector boundary. It never calls a backend getter or changes the
// return, exclusion slice, current backend, or reservation lifecycle.
func (bs *BackendSelector) selectorBoundary(kind observation.SelectorBoundaryKind, backend BackendInst, err error) {
	s := bs.selectionCapture
	if s == nil || !s.owner.Enabled() {
		return
	}
	c := s.owner.BeginCaller()
	defer c.Cleanup()
	if c == nil {
		return
	}
	if len(bs.excluded) > observation.MaxCallerGroups {
		c.Fail(observation.Capacity)
		return
	}
	if kind == observation.SelectorBegin {
		if s.next == ^uint64(0) {
			c.Fail(observation.Capacity)
			return
		}
		s.next++
		s.attempt = 0
	}
	value := observation.SelectorBoundary{Kind: kind, Session: s.session, Next: s.next, ExcludedCount: uint16(len(bs.excluded))}
	identity := func(backend BackendInst) uint64 {
		if backend == nil {
			return 0
		}
		b, ok := backend.(*backendWrapper)
		if !ok || b == nil || b.observationID == 0 {
			c.Fail(observation.Malformed)
			return 0
		}
		return b.observationID
	}
	value.Current = identity(bs.cur)
	for i, excluded := range bs.excluded {
		value.Excluded[i] = identity(excluded)
	}
	if kind == observation.SelectorEnd {
		value.Backend, value.Error = identity(backend), selectorErrorClass(err)
	}
	if c.CaptureSelector(&value) && c.Seal() {
		s.owner.PublishCaller(c)
	}
}

func selectorErrorClass(err error) observation.SelectorErrorClass {
	if err == nil {
		return observation.SelectorNoError
	}
	if err == ErrNoBackend {
		return observation.SelectorExactNoBackend
	}
	return observation.SelectorOtherError
}

// newScoreBasedRouterSelectorCaptured is preparatory private construction. It
// does not expose a live-router attachment or advertise complete C2 coverage.
func newScoreBasedRouterSelectorCaptured(logger *zap.Logger, owner *observation.Owner, creator NativePolicyCreator) *ScoreBasedRouter {
	router := NewScoreBasedRouterWithNativeObservation(logger, owner, creator)
	if owner == nil || !owner.Native() {
		return router
	}
	router.selectorCapture = true
	return router
}
