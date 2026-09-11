// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package router

import (
	"testing"

	"github.com/pingcap/tiproxy/pkg/balance/observation"
	"github.com/stretchr/testify/require"
)

type finishPanicConn struct {
	*mockRedirectableConn
	onSet func()
}

func (c *finishPanicConn) SetEventReceiver(ConnEventReceiver) {
	c.onSet()
	panic("actual creation panic")
}

func TestFinishPanicReleasesParentWithoutRefund(t *testing.T) {
	f := newRouteHookFixture(t, 1, true, false, &nativeGroupReader{})
	f.discardPrefix(t)
	s := &selectionObservation{owner: f.o, session: f.o.NextIdentity(), capture: true}
	selected, err := f.g.routeObserved(nil, s)
	require.NoError(t, err)
	f.take(t).Release()
	before := f.o.AdmittedSequence()
	beforeRecords, beforeBytes := f.r.Retained()
	require.Zero(t, beforeRecords)
	require.EqualValues(t, observation.EvaluationCharge, beforeBytes, "FINISH_EXISTING_EVALUATION_CACHE")
	conn := &finishPanicConn{mockRedirectableConn: newMockRedirectableConn(t, 1), onSet: func() {
		records, bytes := f.r.Retained()
		require.Equal(t, beforeRecords+1, records)
		require.EqualValues(t, beforeBytes+observation.CallerCharge, bytes, "FINISH_PARENT_FULLY_CHARGED_AT_CALLBACK")
	}}
	require.PanicsWithValue(t, "actual creation panic", func() {
		f.g.onCreateConnObserved(selected.(*backendWrapper), conn, true, s)
	})
	f.g.Lock()
	defer f.g.Unlock()
	require.False(t, f.o.Enabled(), "FINISH_PANIC_INVALID_BEFORE_UNLOCK")
	require.Nil(t, f.g.routeCaller)
	records, bytes := f.r.Retained()
	require.Zero(t, records)
	require.Equal(t, beforeBytes, bytes, "FINISH_PANIC_PARENT_FULLY_RELEASED")
	require.Equal(t, before, f.o.AdmittedSequence(), "FINISH_PANIC_NO_FAKE_CREATED")
	require.Equal(t, 1, f.a.connScore, "FINISH_PANIC_NO_SYNTHETIC_REFUND")
	f.r.Close()
	records, bytes = f.r.Retained()
	require.Zero(t, records)
	require.Zero(t, bytes, "FINISH_CLOSED_RECORDER_RELEASES_CACHE")
}
