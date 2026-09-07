// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package router

import (
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/pingcap/tiproxy/pkg/balance/factor"
	"github.com/pingcap/tiproxy/pkg/balance/observer"
	"github.com/pingcap/tiproxy/pkg/balance/policy"
	configmgr "github.com/pingcap/tiproxy/pkg/manager/config"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// The config manager, factors and Group.Route are production implementations.
// Probe outcomes here are eligibility inputs only; source fencing has separate
// real topology/module tests in control-router.
func TestCPRouteCompositionObservation(t *testing.T) {
	input := os.Getenv("CPROUTE_COMPOSITION_FIXTURE")
	if input == "" {
		t.Skip("run make controlplane-cproute-evidence")
	}
	var fixture struct {
		Scenarios []struct {
			Backends []struct {
				ID, Addr string
				Labels   map[string]string
				Healthy  bool
				Group    uint64
			}
			Steps []struct {
				Name, TOML string
				Excluded   []string
				Group      uint64
			}
		}
		Pods []string
	}
	data, err := os.ReadFile(input)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(data, &fixture))
	var output strings.Builder
	for _, scenario := range fixture.Scenarios {
		manager := configmgr.NewConfigManager()
		require.NoError(t, manager.SetTOMLConfig([]byte("[balance]\npolicy=\"connection\"")))
		groups := make(map[uint64]*Group)
		for _, source := range scenario.Backends {
			group := groups[source.Group]
			if group == nil {
				group, err = NewGroup(nil, func(lg *zap.Logger) policy.BalancePolicy {
					return factor.NewFactorBasedBalance(lg, nil)
				}, MatchAll, zap.NewNop())
				require.NoError(t, err)
				groups[source.Group] = group
			}
			group.AddBackend(source.ID, newBackendWrapper(source.ID, observer.BackendHealth{
				BackendInfo: observer.BackendInfo{Addr: source.Addr, Labels: source.Labels}, Healthy: source.Healthy,
			}))
		}
		for _, row := range scenario.Steps {
			require.NoError(t, manager.SetTOMLConfig([]byte(row.TOML)))
			for _, group := range groups {
				group.SetConfig(manager.GetConfig())
			}
			group := groups[row.Group]
			var eligible []string
			for id := range group.backends {
				var excluded []BackendInst
				for other, backend := range group.backends {
					if other != id || slices.Contains(row.Excluded, id) {
						excluded = append(excluded, backend)
					}
				}
				selected, routeErr := group.Route(excluded)
				if routeErr != nil {
					require.ErrorIs(t, routeErr, ErrNoBackend)
					continue
				}
				require.Equal(t, id, selected.ID())
				// Undo this observation's exact pending score.
				selected.(*backendWrapper).connScore--
				eligible = append(eligible, id)
			}
			slices.Sort(eligible)
			fmt.Fprintf(&output, "%s\t%s\n", row.Name, strings.Join(eligible, ","))
		}
		for _, group := range groups {
			for _, backend := range group.backends {
				require.Zero(t, backend.connScore)
			}
		}
	}
	for i, addr := range fixture.Pods {
		fmt.Fprintf(&output, "pod-%d\t%s\n", i, backendPodNameFromAddr(addr))
	}
	require.NoError(t, os.WriteFile(os.Getenv("CPROUTE_COMPOSITION_OUTPUT"), []byte(output.String()), 0o600))
}

// Every successful Next is settled before the next event. Exact duplicate/late
// transport results are exercised separately against the Rust reservation API.
func TestCPRouteRetryObservation(t *testing.T) {
	input := os.Getenv("CPROUTE_RETRY_FIXTURE")
	if input == "" {
		t.Skip("run make controlplane-cproute-evidence")
	}
	var rows []struct {
		Name     string
		Backends []string
		Conflict bool
	}
	data, err := os.ReadFile(input)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(data, &rows))
	manager := configmgr.NewConfigManager()
	require.NoError(t, manager.SetTOMLConfig([]byte("[balance]\npolicy=\"connection\"")))
	var group *Group
	var detector *portConflictDetector
	selector := BackendSelector{
		routeOnce: func(excluded []BackendInst) (BackendInst, error) {
			selectedGroup, err := detector.groupFor("6000")
			if err != nil {
				return nil, err
			}
			backend, err := selectedGroup.Route(excluded)
			if err != nil {
				return nil, err
			}
			return backend.(*backendWrapper), nil
		},
		onCreate: func(backend BackendInst, conn RedirectableConn, succeed bool) {
			group.onCreateConn(backend, conn, succeed)
		},
	}
	var output strings.Builder
	for _, row := range rows {
		group, err = NewGroup(nil, func(lg *zap.Logger) policy.BalancePolicy {
			return factor.NewFactorBasedBalance(lg, nil)
		}, MatchAll, zap.NewNop())
		require.NoError(t, err)
		for _, addr := range row.Backends {
			group.AddBackend("default/"+addr, newBackendWrapper("default/"+addr,
				observer.BackendHealth{BackendInfo: observer.BackendInfo{Addr: addr}, Healthy: true}))
		}
		group.SetConfig(manager.GetConfig())
		detector = newPortConflictDetector()
		detector.bind("6000", "default", group)
		if row.Conflict {
			detector.bind("6000", "second", &Group{})
		}
		backend, routeErr := selector.Next()
		result := ""
		switch {
		case routeErr == nil:
			result = backend.ID()
			selector.Finish(nil, false)
		case row.Conflict:
			require.ErrorIs(t, routeErr, ErrPortConflict)
			result = "conflict"
		default:
			require.ErrorIs(t, routeErr, ErrNoBackend)
			result = "none"
		}
		excluded := make([]string, len(selector.excluded))
		for i, value := range selector.excluded {
			excluded[i] = value.ID()
		}
		fmt.Fprintf(&output, "%s\t%s\t%s\n", row.Name, result, strings.Join(excluded, ","))
		for _, backend := range group.backends {
			require.Zero(t, backend.connScore)
		}
	}
	require.NoError(t, os.WriteFile(os.Getenv("CPROUTE_RETRY_OUTPUT"), []byte(output.String()), 0o600))
}
