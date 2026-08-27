// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"testing"

	"github.com/pingcap/tiproxy/pkg/balance/router"
	mgrns "github.com/pingcap/tiproxy/pkg/manager/namespace"
	"github.com/stretchr/testify/require"
)

// topologyRouter is a static router that can also enumerate backends.
type topologyRouter struct {
	*router.StaticRouter
	backends []router.BackendTopology
}

func (r *topologyRouter) EnumerateTopology() []router.BackendTopology {
	return r.backends
}

type fakeNamespaceLister struct {
	mgrns.NamespaceManager
	namespaces []*mgrns.Namespace
}

func (lister *fakeNamespaceLister) ListNamespaces() []*mgrns.Namespace {
	return lister.namespaces
}

func TestProjectControlTopology(t *testing.T) {
	shared := router.BackendTopology{
		ID:          "alpha/tidb-1:4000",
		Addr:        "tidb-1:4000",
		ClusterName: "alpha",
		Keyspace:    "ks-a",
		Healthy:     true,
		Local:       true,
		CIDRs:       []string{"10.0.0.0/8"},
		Labels:      map[string]string{"zone": "z1"},
	}
	nsAlpha := mgrns.NewNamespaceForTest("ns-alpha", "alice", &topologyRouter{
		StaticRouter: router.NewStaticRouter(nil),
		backends: []router.BackendTopology{
			shared,
			{ID: "alpha/tidb-2:4000", Addr: "tidb-2:4000", ClusterName: "alpha"},
		},
	})
	nsMixed := mgrns.NewNamespaceForTest("ns-mixed", "bob", &topologyRouter{
		StaticRouter: router.NewStaticRouter(nil),
		backends: []router.BackendTopology{
			shared,
			{ID: "beta/tidb-3:4000", Addr: "tidb-3:4000", ClusterName: "beta", Healthy: true},
		},
	})
	// A router that cannot enumerate (the plain static router)
	// contributes namespaces but no backends.
	nsStatic := mgrns.NewNamespaceForTest("ns-static", "", router.NewStaticRouter(nil))

	backends, namespaces := projectControlTopology(&fakeNamespaceLister{
		namespaces: []*mgrns.Namespace{nsAlpha, nsMixed, nsStatic},
	})

	require.Len(t, namespaces, 3)
	require.Equal(t, "ns-alpha", namespaces[0].GetName())
	require.Equal(t, []string{"alice"}, namespaces[0].GetUsers())
	require.Equal(t, "alpha", namespaces[0].GetBackendCluster(),
		"a single-cluster namespace reports its cluster")
	require.Empty(t, namespaces[1].GetBackendCluster(),
		"a mixed-cluster namespace stays honestly empty")
	require.Empty(t, namespaces[2].GetUsers(), "no user projects no users")
	require.Empty(t, namespaces[2].GetBackendCluster())

	require.Len(t, backends, 3, "backends deduplicate across namespaces")
	require.Equal(t, "alpha/tidb-1:4000", backends[0].GetBackendId(), "deterministic order")
	require.Equal(t, "alpha/tidb-2:4000", backends[1].GetBackendId())
	require.Equal(t, "beta/tidb-3:4000", backends[2].GetBackendId())
	first := backends[0]
	require.Equal(t, "tidb-1:4000", first.GetAddress())
	require.Equal(t, "ks-a", first.GetKeyspace())
	require.True(t, first.GetHealthy())
	require.True(t, first.GetLocal())
	require.Equal(t, []string{"10.0.0.0/8"}, first.GetCidrs())
	require.Equal(t, "z1", first.GetLabels()["zone"])
}
