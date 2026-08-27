// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package router

import (
	"testing"

	"github.com/pingcap/tiproxy/lib/config"
	"github.com/pingcap/tiproxy/pkg/balance/observer"
	"github.com/stretchr/testify/require"
)

func TestEnumerateTopology(t *testing.T) {
	tester := newRouterTester(t, nil)
	tester.backends["beta:4000"] = &observer.BackendHealth{
		BackendInfo: observer.BackendInfo{
			Addr:        "beta:4000",
			ClusterName: "beta",
		},
		Healthy:            true,
		SupportRedirection: true,
	}
	tester.backends["alpha:4000"] = &observer.BackendHealth{
		BackendInfo: observer.BackendInfo{
			Addr:        "alpha:4000",
			ClusterName: "alpha",
			Labels: map[string]string{
				config.KeyspaceLabelName: "ks-a",
				config.CidrLabelName:     "10.0.0.0/8, 192.168.0.0/16",
				"custom":                 "value",
			},
		},
		Healthy:            true,
		SupportRedirection: true,
		Local:              true,
	}
	tester.notifyHealth()

	topology := tester.router.EnumerateTopology()
	require.Len(t, topology, 2)
	require.Equal(t, "alpha:4000", topology[0].ID, "deterministic id order")
	require.Equal(t, "beta:4000", topology[1].ID)

	alpha := topology[0]
	require.Equal(t, "alpha:4000", alpha.Addr)
	require.Equal(t, "alpha", alpha.ClusterName)
	require.Equal(t, "ks-a", alpha.Keyspace)
	require.True(t, alpha.Healthy)
	require.True(t, alpha.Local)
	require.Equal(t, []string{"10.0.0.0/8", "192.168.0.0/16"}, alpha.CIDRs)
	require.Equal(t, "value", alpha.Labels["custom"])

	beta := topology[1]
	require.Equal(t, "beta", beta.ClusterName)
	require.Empty(t, beta.Keyspace)
	require.Empty(t, beta.CIDRs)
	require.Empty(t, beta.Labels)

	// The projection is a snapshot: mutating it never touches the router.
	alpha.Labels["custom"] = "mutated"
	require.Equal(t, "value", tester.router.EnumerateTopology()[0].Labels["custom"])

	// Health transitions project truthfully.
	tester.backends["beta:4000"].Healthy = false
	tester.notifyHealth()
	topology = tester.router.EnumerateTopology()
	for _, backend := range topology {
		if backend.ID == "beta:4000" {
			require.False(t, backend.Healthy)
		}
	}
}
