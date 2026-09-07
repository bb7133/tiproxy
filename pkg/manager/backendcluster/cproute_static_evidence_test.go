// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package backendcluster

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/pingcap/tiproxy/lib/config"
	"github.com/pingcap/tiproxy/pkg/balance/observer"
	"github.com/stretchr/testify/require"
)

// The Manager (syncClusters, HasBackendClusters), FallbackFetcher and
// StaticFetcher are production implementations over real embedded etcd
// clusters. Each step applies one cluster configuration and records the mode
// the fallback fetcher selects plus the static identity map when static.
//
// One step is an accepted, explicitly recorded divergence: Go commits per
// cluster (an undesired old cluster is removed even when the new one fails, so
// the applied map can become empty), while Rust rejects the whole generation
// and retains the last-good plan. Both sides assert their own behaviour and
// print the fixture's divergence line so the outputs still compare equal.
func TestCPRouteStaticModeObservation(t *testing.T) {
	input := os.Getenv("CPROUTE_STATIC_FIXTURE")
	if input == "" {
		t.Skip("run make controlplane-cproute-evidence")
	}
	var fixture struct {
		Instances []string
		Steps     []struct {
			Name       string
			Clusters   []string
			Fail       bool
			Divergence string
		}
	}
	data, err := os.ReadFile(input)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(data, &fixture))

	etcds := map[string]*managerTestEtcdCluster{}
	for _, name := range []string{"a", "a2", "b"} {
		cluster := newManagerTestEtcdCluster(t)
		t.Cleanup(func() { cluster.close(t) })
		etcds[name] = cluster
	}
	staticFetcher := observer.NewStaticFetcher(fixture.Instances)
	staticKeys := func() []string {
		backends, err := staticFetcher.GetBackendList(context.Background())
		require.NoError(t, err)
		keys := make([]string, 0, len(backends))
		for key, info := range backends {
			require.Equal(t, key, info.Addr, "static identity is the raw address")
			require.Empty(t, info.ClusterName, "static backends carry no cluster")
			keys = append(keys, key)
		}
		sort.Strings(keys)
		return keys
	}()

	configFor := func(clusters []string, fail bool) *config.Config {
		cfg := newManagerTestConfig()
		for _, name := range clusters {
			// "a2" is cluster "a" pointed at a different etcd: not reusable, so
			// NewCluster runs (and fails when the step says so).
			clusterName := "cluster-" + strings.TrimSuffix(name, "2")
			cfg.Proxy.BackendClusters = append(cfg.Proxy.BackendClusters,
				config.BackendCluster{Name: clusterName, PDAddrs: etcds[name].addr})
		}
		if fail {
			cfg.Proxy.Addr = "invalid"
		}
		return cfg
	}

	initial := configFor(fixture.Steps[0].Clusters, fixture.Steps[0].Fail)
	cfgGetter := newManagerTestConfigGetter(initial)
	cfgCh := make(chan *config.Config, 1)
	mgr := NewManager(zapLoggerForTest(t), nilClusterTLS)
	require.NoError(t, mgr.Start(context.Background(), cfgGetter, cfgCh))
	t.Cleanup(func() {
		close(cfgCh)
		require.NoError(t, mgr.Close())
	})
	dynamic := observer.NewPDFetcher(mgr, zapLoggerForTest(t), config.NewDefaultHealthCheckConfig())
	fallback := observer.NewFallbackFetcher(mgr, dynamic, staticFetcher)

	var output strings.Builder
	for i, step := range fixture.Steps {
		if i > 0 {
			// syncClusters never fails the sync itself; per-cluster failures are
			// logged and the map is committed as described above.
			require.NoError(t, mgr.syncClusters(context.Background(), configFor(step.Clusters, step.Fail)))
		}
		mode := "dynamic"
		if !mgr.HasBackendClusters() {
			mode = "static"
		}
		if step.Divergence != "" {
			require.Equal(t, "static", mode, "Go per-cluster commit leaves an empty map")
			fmt.Fprintf(&output, "%s\tDIVERGENCE\t%s\n", step.Name, step.Divergence)
			continue
		}
		selected, err := fallback.GetBackendList(context.Background())
		require.NoError(t, err)
		if mode == "static" {
			keys := make([]string, 0, len(selected))
			for key := range selected {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			require.Equal(t, staticKeys, keys, "the fallback selected the static list")
			fmt.Fprintf(&output, "%s\tstatic\t%s\n", step.Name, strings.Join(keys, ","))
		} else {
			for key := range selected {
				require.Contains(t, key, "/", "dynamic ids are cluster-qualified")
			}
			fmt.Fprintf(&output, "%s\tdynamic\t-\n", step.Name)
		}
	}
	require.NoError(t, os.WriteFile(os.Getenv("CPROUTE_STATIC_OUTPUT"), []byte(output.String()), 0o600))
}
