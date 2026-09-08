// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package router

import "github.com/pingcap/tiproxy/pkg/balance/observation"

// The selector already requires sequential Next/Finish use. This diagnostic
// token follows that same lifetime, including attempts before a conn exists.
// It never supplies an identity or decision to production routing.
type selectionObservation struct {
	owner                         *observation.Owner
	session, operation            uint64
	opened, pending, bound, ended bool
}

func (s *selectionObservation) finish() {
	if s == nil || !s.owner.Enabled() || s.ended {
		return
	}
	s.ended = true
	if s.pending {
		// Actual Go retained the reservation. Do not synthesize Closed or a
		// failed creation: either would refund a count that Go did not refund.
		s.owner.Invalidate(observation.UnpairedDiscard)
		return
	}
	if s.opened && !s.bound {
		s.owner.Emit(observation.Batch{EventCount: 1, Events: [observation.MaxEvents]observation.Event{{Kind: observation.SelectionDone, Session: s.session}}, Witness: observation.Witness{Session: s.session}})
	}
}

func (s *selectionObservation) noRoute(group uint64) {
	if s != nil && s.owner.Enabled() {
		s.owner.Emit(observation.Batch{EventCount: 1, Events: [observation.MaxEvents]observation.Event{{Kind: observation.RouteRejected, Session: s.session, Group: group}}})
	}
}

func (g *Group) observeNoRoute(s *selectionObservation) { s.noRoute(g.observationID) }

func (g *Group) observeAccount(b *backendWrapper) {
	if !g.observation.Enabled() {
		return
	}
	if b.observationID != 0 {
		return
	}
	b.observationID = g.observation.NextIdentity()
	g.capture(observation.Batch{EventCount: 1, Events: [observation.MaxEvents]observation.Event{{Kind: observation.Account, ID: b.observationID, Group: g.observationID}}}, nil, observation.ConnectionState{}, b)
}

func (g *Group) observeReserved(s *selectionObservation, b *backendWrapper) {
	if !g.observation.Enabled() {
		return
	}
	if s == nil || s.owner != g.observation || s.pending || s.bound || s.ended {
		g.observation.Invalidate(observation.UnpairedDiscard)
		return
	}
	s.operation = g.observation.NextIdentity()
	batch := observation.Batch{}
	if !s.opened {
		batch.Events[0] = observation.Event{Kind: observation.Open, Session: s.session}
		batch.EventCount++
		s.opened = true
	}
	batch.Events[batch.EventCount] = observation.Event{Kind: observation.Reserve, Session: s.session, Operation: s.operation, Account: b.observationID}
	batch.EventCount++
	batch.Witness.Session = s.session
	s.pending = true
	g.capture(batch, nil, observation.ConnectionState{}, b)
}

func (g *Group) observeCreated(s *selectionObservation, b *backendWrapper, conn RedirectableConn, success bool) {
	if !g.observation.Enabled() {
		return
	}
	if s == nil || s.owner != g.observation || !s.pending || s.ended {
		g.observation.Invalidate(observation.UnpairedDiscard)
		return
	}
	s.pending, s.bound = false, success
	batch := observation.Batch{EventCount: 1, Events: [observation.MaxEvents]observation.Event{{Kind: observation.Created, Session: s.session, Operation: s.operation, Success: success}}}
	batch.Witness.Session = s.session
	var cw *connWrapper
	if success {
		cw = getConnWrapper(conn).Value
	}
	g.capture(batch, cw, observation.ConnectionState{}, b)
}

// observationState is called only after the Invalid fast-path check and under
// the actual Group lock. It projects fixed fields, with no interface calls.
func observationState(cw *connWrapper) observation.ConnectionState {
	if cw == nil {
		return observation.ConnectionState{}
	}
	state := observation.ConnectionState{Present: true, RedirectPending: cw.phase == phaseRedirectNotify, Closing: cw.forceClosing && cw.phase != phaseClosed, Closed: cw.phase == phaseClosed}
	if cw.physicalOwner != nil {
		state.Physical = cw.physicalOwner.observationID
	}
	if cw.scoreOwner != nil {
		state.ScoreOwner = cw.scoreOwner.observationID
	}
	return state
}

func (g *Group) beforeObservation(cw *connWrapper) observation.ConnectionState {
	if !g.observation.Enabled() {
		return observation.ConnectionState{}
	}
	return observationState(cw)
}

// capture copies at most two account witnesses and one connection, entirely in
// the caller's existing Group critical section. Owner.Emit only serializes the
// completed values; neither it nor the drain can call back into this Group.
func (g *Group) capture(batch observation.Batch, cw *connWrapper, before observation.ConnectionState, accounts ...*backendWrapper) {
	if !g.observation.Enabled() {
		return
	}
	batch.Witness.Before = before
	if cw != nil {
		batch.Witness.Session = cw.observationID
		batch.Witness.After = observationState(cw)
	}
	for _, b := range accounts {
		if b == nil {
			continue
		}
		duplicate := false
		for i := uint8(0); i < batch.Witness.AccountCount; i++ {
			if batch.Witness.Accounts[i].ID == b.observationID {
				duplicate = true
				break
			}
		}
		if duplicate {
			continue
		}
		if batch.Witness.AccountCount == observation.MaxWitnesses || b.observationID == 0 {
			g.observation.Invalidate(observation.Malformed)
			return
		}
		witness := observation.AccountWitness{ID: b.observationID, Score: int64(b.connScore), Physical: uint64(b.connList.Len())}
		if head := b.connList.Front(); head != nil {
			witness.Head = head.Value.observationID
		}
		if tail := b.connList.Back(); tail != nil {
			witness.Tail = tail.Value.observationID
			// The predecessor is only meaningful for an actual physical append.
			appendEvent := false
			for i := uint8(0); i < batch.EventCount; i++ {
				e := batch.Events[i]
				appendEvent = appendEvent || e.Kind == observation.Rehydrate || (e.Kind == observation.Created || e.Kind == observation.Redirected) && e.Success
			}
			if appendEvent && cw != nil && tail.Value == cw && tail.Prev() != nil {
				batch.Witness.Predecessor = tail.Prev().Value.observationID
			}
		}
		batch.Witness.Accounts[batch.Witness.AccountCount] = witness
		batch.Witness.AccountCount++
	}
	g.observation.Emit(batch)
}

func (g *Group) observeRedirect(cw *connWrapper, before observation.ConnectionState, from, to *backendWrapper, accepted bool) {
	if !g.observation.Enabled() {
		return
	}
	kind := observation.Rejected
	operation := g.observation.NextIdentity()
	if accepted {
		kind = observation.Redirect
		cw.observationRedirect = operation
	}
	g.capture(observation.Batch{EventCount: 1, Events: [observation.MaxEvents]observation.Event{{Kind: kind, Session: cw.observationID, Operation: operation, Account: from.observationID, Target: to.observationID}}}, cw, before, from, to)
}

func (g *Group) observeRedirected(cw *connWrapper, before observation.ConnectionState, from, to *backendWrapper, success bool) {
	if !g.observation.Enabled() {
		return
	}
	g.capture(observation.Batch{EventCount: 1, Events: [observation.MaxEvents]observation.Event{{Kind: observation.Redirected, Session: cw.observationID, Operation: cw.observationRedirect, Account: from.observationID, Target: to.observationID, Success: success}}}, cw, before, from, to)
}
