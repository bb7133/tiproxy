// Copyright 2025 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package router

import (
	"testing"

	"github.com/pingcap/tiproxy/lib/config"
	"github.com/pingcap/tiproxy/pkg/balance/observer"
	"github.com/stretchr/testify/require"
)

func TestBackendWrapper(t *testing.T) {
	b := &backendWrapper{}
	b.mu.BackendHealth = observer.BackendHealth{
		Healthy:            true,
		ServerVersion:      "1.0",
		SupportRedirection: false,
		Local:              false,
		BackendInfo: observer.BackendInfo{
			Labels: map[string]string{
				"keyspace": "a",
				"zone":     "b",
			},
		},
	}
	require.Equal(t, "a", b.Keyspace())
	require.Equal(t, "1.0", b.ServerVersion())
	require.True(t, b.Healthy())
	require.False(t, b.SupportRedirection())
	require.False(t, b.Local())
	require.Equal(t, "a", b.GetBackendInfo().Labels["keyspace"])
	require.Equal(t, "b", b.GetBackendInfo().Labels["zone"])
}

// The path-parsed topology keyspace is authoritative: a conflicting
// operator label can never override it; the label remains only a
// fallback channel for classic (keyspace-less) topologies.
func TestBackendKeyspacePrefersPathParsedOverLabel(t *testing.T) {
	backend := newBackendWrapper("b1", observer.BackendHealth{
		BackendInfo: observer.BackendInfo{
			Addr:     "1.1.1.1:4000",
			Keyspace: "ks-path",
			Labels:   map[string]string{config.KeyspaceLabelName: "ks-label"},
		},
	})
	require.Equal(t, "ks-path", backend.Keyspace())

	labelOnly := newBackendWrapper("b2", observer.BackendHealth{
		BackendInfo: observer.BackendInfo{
			Addr:   "2.2.2.2:4000",
			Labels: map[string]string{config.KeyspaceLabelName: "ks-label"},
		},
	})
	require.Equal(t, "ks-label", labelOnly.Keyspace())
}
