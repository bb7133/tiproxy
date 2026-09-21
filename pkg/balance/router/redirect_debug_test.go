// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package router

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func redirectTarget(conn *mockRedirectableConn) BackendInst {
	conn.Lock()
	defer conn.Unlock()
	return conn.to
}

// The management/test redirect boundary CP-ADMIN slice 5b mirrors: every
// connection is offered a redirect to its own backend (reason "test"), a
// connection whose redirect is already pending (phaseRedirectNotify) is not
// offered again, a refused Redirect only records accepted=false, the
// balancer cooldown never applies, and the router returns nil either way.
func TestRedirectConnectionsDebugBoundary(t *testing.T) {
	r := observedRouter(t, nil)
	g := r.groups[0]
	first, source := observedConn(t, r, false)
	second := newMockRedirectableConn(t, 8)
	second.from = source
	_, ok := r.RehydrateConn(source.ID(), second)
	require.True(t, ok)
	closing := newMockRedirectableConn(t, 9)
	closing.from = source
	_, ok = r.RehydrateConn(source.ID(), closing)
	require.True(t, ok)
	closing.closing = true
	score := source.connScore

	require.NoError(t, r.RedirectConnections())
	for _, conn := range []*mockRedirectableConn{first, second, closing} {
		wrapper := getConnWrapper(conn).Value
		require.Equal(t, phaseRedirectNotify, wrapper.phase, "every connection is marked, accepted or not")
		require.Equal(t, "test", wrapper.redirectReason)
	}
	require.Equal(t, source, redirectTarget(first), "self redirect targets the same backend")
	require.Equal(t, source, redirectTarget(second))
	require.Nil(t, redirectTarget(closing), "a refused Redirect records no target and no error")
	require.Equal(t, score, source.connScore, "a self redirect transfers no score")

	// A second sweep skips the pending connections (the mock would fail on a
	// second Redirect while one is pending) and still returns nil.
	require.NoError(t, r.RedirectConnections())
	require.Equal(t, source, redirectTarget(first))

	// Settling the pending self redirects keeps the account; the refused one
	// fails on the same backend. Afterwards every connection is a candidate
	// again: the debug entry has no cooldown.
	for _, conn := range []*mockRedirectableConn{first, second} {
		conn.redirectSucceed()
		require.NoError(t, g.OnRedirectSucceed(source.ID(), source.ID(), conn))
		require.Equal(t, phaseRedirectEnd, getConnWrapper(conn).Value.phase)
	}
	require.NoError(t, g.OnRedirectFail(source.ID(), source.ID(), closing))
	require.Equal(t, score, source.connScore)
	require.NoError(t, r.RedirectConnections())
	require.Equal(t, source, redirectTarget(first))
	require.Equal(t, source, redirectTarget(second))
	require.Nil(t, redirectTarget(closing))
	for _, conn := range []*mockRedirectableConn{first, second} {
		conn.redirectSucceed()
		require.NoError(t, g.OnRedirectSucceed(source.ID(), source.ID(), conn))
	}
	require.NoError(t, g.OnRedirectFail(source.ID(), source.ID(), closing))
	for _, conn := range []*mockRedirectableConn{first, second, closing} {
		require.NoError(t, g.OnConnClosed(source.ID(), conn))
	}
}
