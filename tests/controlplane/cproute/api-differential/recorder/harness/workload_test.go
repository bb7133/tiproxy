// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build apireplay

package harness

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestHeldAddressIntervalsCoverRegistrationRaceAndEndBeforeReuse(t *testing.T) {
	w := &Workload{}
	clientA, serverA := net.Pipe()
	defer serverA.Close()
	dialStarted := time.Now().Add(-2 * time.Second)
	openBeforeRegistration := time.Now().Add(-time.Second)
	heldA := w.trackHeldConnection(clientA, dialStarted)
	require.True(t, w.IsHeldClientAt("pipe", openBeforeRegistration),
		"dial start precedes an open even when interval registration follows it")
	require.NoError(t, heldA.Close())
	require.True(t, w.IsHeldClientAt("pipe", openBeforeRegistration), "closed intervals retain historical identity")
	closedAt := w.heldHistory["pipe"][0].end
	require.False(t, w.IsHeldClientAt("pipe", closedAt), "the held lifetime has a half-open end")
	laterReuse := time.Now().Add(time.Nanosecond)
	require.False(t, w.IsHeldClientAt("pipe", laterReuse), "later reuse is outside the held lifetime")
	_ = heldA.Close()
	require.False(t, w.IsHeldClientAt("pipe", laterReuse), "a repeated close must not extend the interval")
}

func TestWorkloadCoversListenerAndSourceProduct(t *testing.T) {
	w := &Workload{Listeners: []string{"127.0.0.1:6000", "127.0.0.1:6001"}, Sources: []string{"127.0.0.1", "127.0.0.2"}}
	want := [][2]string{
		{"127.0.0.1:6000", "127.0.0.1"},
		{"127.0.0.1:6000", "127.0.0.2"},
		{"127.0.0.1:6001", "127.0.0.1"},
		{"127.0.0.1:6001", "127.0.0.2"},
		{"127.0.0.1:6000", "127.0.0.1"},
	}
	for i, expected := range want {
		listener, source := w.target(i)
		require.Equal(t, expected[0], listener)
		require.Equal(t, expected[1], source)
	}
}

func TestWorkloadListenerFallbackAndRoundRobin(t *testing.T) {
	w := &Workload{Listener: "127.0.0.1:6000"}
	listener, source := w.target(3)
	require.Equal(t, "127.0.0.1:6000", listener)
	require.Empty(t, source)

	w = &Workload{Listeners: []string{"127.0.0.1:6000", "127.0.0.1:6001"}}
	listener, _ = w.target(3)
	require.Equal(t, "127.0.0.1:6001", listener)
}
