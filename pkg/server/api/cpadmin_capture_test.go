// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pingcap/tiproxy/lib/config"
	"github.com/pingcap/tiproxy/pkg/controlbridge"
	controlpb "github.com/pingcap/tiproxy/pkg/controlbridge/pb"
	mgrcfg "github.com/pingcap/tiproxy/pkg/manager/config"
	"github.com/stretchr/testify/require"
)

// cpadminStep is one entry of tests/controlplane/cpadmin/script.json, shared
// with the Rust replay so both sides answer the identical request sequence.
type cpadminStep struct {
	Name   string `json:"name"`
	Method string `json:"method"`
	Path   string `json:"path"`
	Body   string `json:"body"`
	Action *struct {
		Ready           *bool `json:"ready"`
		NamespacesReady *bool `json:"namespaces_ready"`
		PreClose        bool  `json:"preclose"`
		Dataplane       *struct {
			DesiredGeneration  uint64 `json:"desired_generation"`
			SentGeneration     uint64 `json:"sent_generation"`
			AppliedGeneration  uint64 `json:"applied_generation"`
			RejectedGeneration uint64 `json:"rejected_generation"`
			LastResultCode     string `json:"last_result_code"`
			Detail             string `json:"detail"`
			LastGoodAgeMillis  int64  `json:"last_good_age_ms"`
		} `json:"dataplane"`
	} `json:"action"`
}

type cpadminObservation struct {
	Name        string `json:"name"`
	Status      int    `json:"status"`
	ContentType string `json:"content_type"`
	Body        string `json:"body"`
}

type cpadminChecksums struct {
	Default       uint32 `json:"default"`
	PartialUpdate uint32 `json:"partial_update"`
	NoChange      uint32 `json:"no_change_update"`
	NamespaceOnly uint32 `json:"namespace_only_update"`
	Workdir       string `json:"workdir"`
}

// TestCPAdminCapture replays the shared script against the production gin
// engine with the same mocks the unit tests use and records status, content
// type and body per step, plus the four config-checksum scenarios. It runs
// only when CPADMIN_CAPTURE_OUT names the output file (see
// tests/controlplane/cpadmin/run.sh).
func TestCPAdminCapture(t *testing.T) {
	out := os.Getenv("CPADMIN_CAPTURE_OUT")
	if out == "" {
		t.Skip("CPADMIN_CAPTURE_OUT is not set")
	}
	script := os.Getenv("CPADMIN_SCRIPT")
	require.NotEmpty(t, script, "CPADMIN_SCRIPT must name the shared script")
	raw, err := os.ReadFile(script)
	require.NoError(t, err)
	var steps []cpadminStep
	require.NoError(t, json.Unmarshal(raw, &steps))

	// The Rust dataplane composition requires enable-traffic-replay = false, so
	// the compared surface is the one an operator sees in that topology.
	srv, _, _ := createServerWithConfig(t, "enable-traffic-replay = false\n")
	addr := srv.listener.Addr().String()
	client := &http.Client{
		// Capture gin's trailing-slash 301 instead of following it.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	observations := make([]cpadminObservation, 0, len(steps))
	for _, step := range steps {
		if step.Action != nil {
			if step.Action.Ready != nil {
				srv.ready.Store(*step.Action.Ready)
			}
			if step.Action.NamespacesReady != nil {
				srv.mgr.NsMgr.(*mockNamespaceManager).success.Store(*step.Action.NamespacesReady)
			}
			if step.Action.PreClose {
				srv.PreClose()
			}
			if dp := step.Action.Dataplane; dp != nil {
				code, ok := controlpb.ErrorCode_value[dp.LastResultCode]
				require.True(t, ok, "unknown error code %q", dp.LastResultCode)
				srv.mgr.DataplaneStatus = staticDataplaneStatus{status: controlbridge.SnapshotStatus{
					DesiredGeneration:  dp.DesiredGeneration,
					SentGeneration:     dp.SentGeneration,
					AppliedGeneration:  dp.AppliedGeneration,
					RejectedGeneration: dp.RejectedGeneration,
					LastResultCode:     controlpb.ErrorCode(code),
					Detail:             dp.Detail,
					LastGoodAge:        time.Duration(dp.LastGoodAgeMillis) * time.Millisecond,
				}}
			}
		}
		var body io.Reader
		if step.Body != "" {
			body = strings.NewReader(step.Body)
		}
		req, err := http.NewRequest(step.Method, fmt.Sprintf("http://%s%s", addr, step.Path), body)
		require.NoError(t, err, step.Name)
		resp, err := client.Do(req)
		require.NoError(t, err, step.Name)
		payload, err := io.ReadAll(resp.Body)
		require.NoError(t, resp.Body.Close())
		require.NoError(t, err, step.Name)
		observations = append(observations, cpadminObservation{
			Name:        step.Name,
			Status:      resp.StatusCode,
			ContentType: resp.Header.Get("Content-Type"),
			Body:        string(payload),
		})
	}

	// Config checksum scenarios on a fresh default manager: default, partial
	// update, the identical update again, and a namespace-only mutation.
	cfgmgr := mgrcfg.NewConfigManager()
	require.NoError(t, cfgmgr.Init(context.Background(), "", ""))
	checksums := cpadminChecksums{Default: cfgmgr.GetConfigChecksum(), Workdir: cfgmgr.GetConfig().Workdir}
	require.NoError(t, cfgmgr.SetTOMLConfig([]byte("[proxy]\nmax-connections = 123\n[log]\nlevel = \"warn\"\n")))
	checksums.PartialUpdate = cfgmgr.GetConfigChecksum()
	require.NoError(t, cfgmgr.SetTOMLConfig([]byte("[proxy]\nmax-connections = 123\n")))
	checksums.NoChange = cfgmgr.GetConfigChecksum()
	require.NoError(t, cfgmgr.SetNamespace(context.Background(), "ns-only", &config.Namespace{Namespace: "ns-only"}))
	checksums.NamespaceOnly = cfgmgr.GetConfigChecksum()

	encoded, err := json.MarshalIndent(map[string]any{"observations": observations, "checksums": checksums}, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(out, append(encoded, '\n'), 0o644))
}
