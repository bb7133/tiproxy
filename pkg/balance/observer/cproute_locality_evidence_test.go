// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package observer

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/pingcap/tiproxy/lib/util/logger"
	configmgr "github.com/pingcap/tiproxy/pkg/manager/config"
	"github.com/stretchr/testify/require"
)

// The config manager and checkHealth (setLocal) are production implementations.
// Probe outcomes are eligibility inputs only: every backend reports healthy, so
// the observation isolates Local under each config history and health mode.
func TestCPRouteLocalityObservation(t *testing.T) {
	input := os.Getenv("CPROUTE_LOCALITY_FIXTURE")
	if input == "" {
		t.Skip("run make controlplane-cproute-evidence")
	}
	var fixture struct {
		Backends []struct {
			Addr   string
			Labels map[string]string
		}
		Steps []struct {
			Name, TOML string
			Enabled    bool
		}
	}
	data, err := os.ReadFile(input)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(data, &fixture))

	manager := configmgr.NewConfigManager()
	cfgGetter := newMockConfigGetter(manager.GetConfig())
	hc := newMockHealthCheck()
	backends := make(map[string]*BackendInfo, len(fixture.Backends))
	for _, backend := range fixture.Backends {
		info := &BackendInfo{Addr: backend.Addr, Labels: backend.Labels}
		backends[backend.Addr] = info
		hc.setBackend(backend.Addr, &BackendHealth{BackendInfo: *info, Healthy: true})
	}
	healthCheckConfig := newHealthCheckConfigForTest()
	lg, _ := logger.CreateLoggerForTest(t)
	bo := NewDefaultBackendObserver(lg, healthCheckConfig, nil, hc, cfgGetter)

	var output strings.Builder
	for _, row := range fixture.Steps {
		if row.TOML != "" {
			require.NoError(t, manager.SetTOMLConfig([]byte(row.TOML)))
			cfgGetter.setConfig(manager.GetConfig())
		}
		healthCheckConfig.Enable = row.Enabled
		result := bo.checkHealth(context.Background(), backends)
		require.Len(t, result, len(backends))
		addrs := make([]string, 0, len(result))
		for addr := range result {
			addrs = append(addrs, addr)
		}
		slices.Sort(addrs)
		fields := make([]string, 0, len(addrs))
		for _, addr := range addrs {
			health := result[addr]
			require.True(t, health.Healthy)
			fields = append(fields, fmt.Sprintf("%s=%t", addr, health.Local))
		}
		fmt.Fprintf(&output, "%s\t%s\n", row.Name, strings.Join(fields, ","))
	}
	require.NoError(t, os.WriteFile(os.Getenv("CPROUTE_LOCALITY_OUTPUT"), []byte(output.String()), 0o600))
}
