// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build apireplay

package harness

import (
	"testing"

	"github.com/stretchr/testify/require"
)

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
