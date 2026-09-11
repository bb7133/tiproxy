// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package router

import (
	"testing"

	"github.com/stretchr/testify/require"
)

type finishPanicConn struct{ *mockRedirectableConn }

func (c *finishPanicConn) SetEventReceiver(ConnEventReceiver) { panic("actual creation panic") }

func TestFinishPanicReleasesParentWithoutRefund(t *testing.T) {
	f := newRouteHookFixture(t, 1, true, false, &nativeGroupReader{})
	f.discardPrefix(t)
	s := &selectionObservation{owner: f.o, session: f.o.NextIdentity(), capture: true}
	selected, err := f.g.routeObserved(nil, s)
	require.NoError(t, err)
	f.take(t).Release()
	before := f.o.AdmittedSequence()
	require.PanicsWithValue(t, "actual creation panic", func() {
		f.g.onCreateConnObserved(selected.(*backendWrapper), &finishPanicConn{newMockRedirectableConn(t, 1)}, true, s)
	})
	f.g.Lock()
	defer f.g.Unlock()
	require.False(t, f.o.Enabled(), "FINISH_PANIC_INVALID_BEFORE_UNLOCK")
	require.Nil(t, f.g.routeCaller)
	records, bytes := f.r.Retained()
	require.Zero(t, records)
	require.Zero(t, bytes, "FINISH_PANIC_NO_LEAK")
	require.Equal(t, before, f.o.AdmittedSequence(), "FINISH_PANIC_NO_FAKE_CREATED")
	require.Equal(t, 1, f.a.connScore, "FINISH_PANIC_NO_SYNTHETIC_REFUND")
}
