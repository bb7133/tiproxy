// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build apireplay

package main

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	mgrcfg "github.com/pingcap/tiproxy/pkg/manager/config"
	"github.com/pingcap/tiproxy/tests/controlplane/cproute/api-differential/recorder/apireplay"
	"github.com/pingcap/tiproxy/tests/controlplane/cproute/api-differential/recorder/harness"
	"github.com/stretchr/testify/require"
)

func TestLedgerTracksAbandonedAndClosedSessions(t *testing.T) {
	l := newLedger()
	l.observe(apireplay.Event{Op: "open", Session: "abandoned"})
	if len(l.open) != 1 || len(l.active) != 0 {
		t.Fatal("idle selector missing from finalization ledger")
	}
	l.observe(apireplay.Event{Op: "close", Session: "abandoned"})
	yes := true
	l.observe(apireplay.Event{Op: "open", Session: "s"})
	l.observe(apireplay.Event{Op: "next", Session: "s", Outcome: "ok", Backend: "A"})
	l.observe(apireplay.Event{Op: "finish", Session: "s", Success: &yes})
	l.observe(apireplay.Event{Op: "redirect_result", Session: "s", Success: &yes, Operation: "s/1", Backend: "B"})
	if l.active["s"] != "B" {
		t.Fatal("success did not move assignment")
	}
	l.observe(apireplay.Event{Op: "close", Session: "s"})
	l.observe(apireplay.Event{Op: "redirect_result", Session: "s", Success: &yes, Operation: "s/1", Backend: "B"})
	if len(l.open)+len(l.active)+len(l.pending) != 0 {
		t.Fatal("late callback resurrected session")
	}
}

func TestInvalidActionsFailBeforeCapture(t *testing.T) {
	for _, script := range []string{
		`[{"kind":"source_error","error":"canceled"}]`,
		`[{"kind":"source_error","error":"no_backend"}]`,
		`[{"kind":"source_error","error":"wrapped_no_backend"}]`,
		`[{"kind":"source_error","error":"port_conflict"}]`,
		`[{"kind":"source_error","erorr":"cancelled"}]`,
		`[{"kind":"unknown"}]`,
		`[{"kind":"checkpoint","at_ms":-1}]`,
	} {
		dir := t.TempDir()
		path := filepath.Join(dir, "actions.json")
		require.NoError(t, os.WriteFile(path, []byte(script), 0o600))
		out := filepath.Join(dir, "recordings")
		err := run("test", "a1", "connection", "prefer-idle", "", "127.0.0.1:0", "", time.Second, 1, 0, 0, "", out, path, "", "", time.Millisecond)
		require.Error(t, err)
		require.NoDirExists(t, out)
	}
	for _, identity := range []string{"", "cancelled", "deadline_exceeded", "topology_unavailable"} {
		require.NoError(t, validateActions([]Action{{Kind: "source_error", Error: identity}}))
	}
}

func TestScriptControlValidation(t *testing.T) {
	valid := []Action{
		{Kind: "env", Args: []string{"tidb-stop", "0"}},
		{Kind: "env", Args: []string{"tidb-stop", "1"}},
		{Kind: "await_env"},
		{Kind: "env", Args: []string{"tidb-start", "0"}},
		{Kind: "env", Args: []string{"tidb-start", "1"}},
		{Kind: "await_env"},
		{Kind: "refuse_next_effect"},
		{Kind: "delay_next_redirect_result"},
		{Kind: "close_delayed_redirect", TimeoutMillis: 5000},
	}
	require.NoError(t, validateActions(valid))
	require.True(t, requiresEnvironmentDriver(valid))
	require.Equal(t, 5*time.Second, actionTimeout(valid[len(valid)-1]))
	require.Equal(t, 10*time.Second, actionTimeout(Action{}))

	for name, actions := range map[string][]Action{
		"env missing args":         {{Kind: "env"}, {Kind: "await_env"}},
		"env missing barrier":      {{Kind: "env", Args: []string{"tidb-stop", "0"}}},
		"env overlaps config":      {{Kind: "env", Args: []string{"tidb-stop", "0"}}, {Kind: "config"}},
		"barrier without batch":    {{Kind: "await_env"}},
		"delay not closed":         {{Kind: "delay_next_redirect_result"}},
		"close without delay":      {{Kind: "close_delayed_redirect"}},
		"two pending delays":       {{Kind: "delay_next_redirect_result"}, {Kind: "delay_next_redirect_result"}},
		"timeout on wrong action":  {{Kind: "checkpoint", TimeoutMillis: 1}},
		"negative control timeout": {{Kind: "close_delayed_redirect", TimeoutMillis: -1}},
		"overflowing timeout":      {{Kind: "delay_next_redirect_result"}, {Kind: "close_delayed_redirect", TimeoutMillis: 1<<63 - 1}},
		"args on control":          {{Kind: "refuse_next_effect", Args: []string{"unexpected"}}},
		"toml on checkpoint":       {{Kind: "checkpoint", TOML: "[proxy]"}},
		"error on config":          {{Kind: "config", Error: "cancelled"}},
	} {
		t.Run(name, func(t *testing.T) {
			require.Error(t, validateActions(actions))
		})
	}
}

func TestActionsSortBeforeBarrierValidation(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "actions.json")
	require.NoError(t, os.WriteFile(script, []byte(`[
  {"at_ms":10,"kind":"await_env"},
  {"at_ms":0,"kind":"env","args":["tidb-stop","0"]}
]`), 0o600))
	out := filepath.Join(dir, "recordings")
	err := run("test", "a1", "connection", "prefer-idle", "", "127.0.0.1:0", "", time.Second, 1, 0, 0, "", out, script, "", "", time.Millisecond)
	require.EqualError(t, err, "-env is required by env actions")
	require.NoDirExists(t, out)
}

func TestRecordingConfigPreservesMultipleListeners(t *testing.T) {
	listeners := []string{"127.0.0.1:6000", "127.0.0.1:6001"}
	manager := mgrcfg.NewConfigManager()
	require.NoError(t, manager.SetTOMLConfig([]byte(recordingConfig(listeners, "127.0.0.1:2379", "resource", "random", "port"))))
	got, err := manager.GetConfig().Proxy.GetSQLAddrs()
	require.NoError(t, err)
	require.Equal(t, listeners, got)
}

func TestClientCountMustCoverListenerSourceProduct(t *testing.T) {
	listeners := []string{"127.0.0.1:6000", "127.0.0.2:6001"}
	sources := []string{"127.0.0.1", "127.0.0.2"}
	require.EqualError(t, validateClientCoverage(3, listeners, sources),
		"clients 3 cannot cover all 4 listener/source combinations")
	require.NoError(t, validateClientCoverage(4, listeners, sources))
	require.NoError(t, validateClientCoverage(2, listeners, nil))
}

func TestEnvironmentManifestPreflight(t *testing.T) {
	valid := environmentManifestFixture()
	dir := t.TempDir()
	path := filepath.Join(dir, "environment.json")
	require.NoError(t, os.WriteFile(path, []byte(valid), 0o600))
	data, got, err := loadEnvironmentManifest(path)
	require.NoError(t, err)
	require.Equal(t, []byte(valid), data, "the exact environment bytes are the immutable evidence")
	want := sha256.Sum256([]byte(valid))
	require.Equal(t, fmt.Sprintf("%x", want), got)
	preserved := filepath.Join(dir, "preserved.json")
	require.NoError(t, writeExclusiveFile(preserved, data, 0o600))
	preservedData, err := os.ReadFile(preserved)
	require.NoError(t, err)
	require.Equal(t, data, preservedData)
	require.Error(t, writeExclusiveFile(preserved, []byte("replacement"), 0o600), "a capture must never replace its bound snapshot")

	digest := strings.Repeat("a", sha256.Size*2)
	for name, contents := range map[string]string{
		"trailing value":    valid + `{}`,
		"missing component": strings.Replace(valid, `"prometheus": {"version": "v1", "sha256": `+fmt.Sprintf("%q", digest)+`, "length": 4}`, `"other": {"version": "v1", "sha256": `+fmt.Sprintf("%q", digest)+`, "length": 4}`, 1),
		"bad digest":        strings.Replace(valid, digest, "not-a-sha256", 1),
		"missing endpoint":  strings.Replace(valid, `"client_url": "http://127.0.0.1:2379"`, `"client_url": ""`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			invalidPath := filepath.Join(t.TempDir(), "environment.json")
			require.NoError(t, os.WriteFile(invalidPath, []byte(contents), 0o600))
			_, _, err := loadEnvironmentManifest(invalidPath)
			require.Error(t, err)
		})
	}
}

func environmentManifestFixture() string {
	digest := strings.Repeat("a", sha256.Size*2)
	return fmt.Sprintf(`{
  "generated_at": "2026-09-13T08:00:00Z",
  "host": {"hostname": "recorder", "os": "darwin", "arch": "arm64"},
  "components": {
    "pd": {"version": "v1", "sha256": %q, "length": 1},
    "tikv": {"version": "v1", "sha256": %q, "length": 2},
    "tidb": {"version": "v1", "sha256": %q, "length": 3},
    "prometheus": {"version": "v1", "sha256": %q, "length": 4}
  },
  "binaries": {"pd": "pd-build", "tikv": "tikv-build", "tidb": "tidb-build"},
  "pd": {"client_url": "http://127.0.0.1:2379"},
  "tikv": {"addr": "127.0.0.1:20160", "status": "127.0.0.1:20180"},
  "prometheus": {"base_url": "http://127.0.0.1:9090"},
  "tidb": [{"name": "tidb-0", "sql": "127.0.0.1:4000", "status": "127.0.0.1:10080"}]
}`, digest, digest, digest, digest)
}

func TestEnvironmentManifestIsRequiredBeforeCapture(t *testing.T) {
	out := filepath.Join(t.TempDir(), "recordings")
	err := run("test", "a1", "connection", "prefer-idle", "", "127.0.0.1:0", "", time.Second, 1, 0, 0, "", out, "", "", "", time.Millisecond)
	require.EqualError(t, err, "-environment-manifest is required")
	require.NoDirExists(t, out)
}

func TestRecordedLifecycleGateFailsClosed(t *testing.T) {
	require.ErrorContains(t, validateRecordedLifecycles(harness.LifecycleSummary{}, 1), "completed=0 workload=1 open=0")
	require.NoError(t, validateRecordedLifecycles(harness.LifecycleSummary{Opened: 2, SuccessfulFinishes: 1, Closed: 2, Completed: 1}, 1))
}

func TestRecorderWithoutOverlayFailsBeforeCapture(t *testing.T) {
	dir := t.TempDir()
	environment := filepath.Join(dir, "environment.json")
	require.NoError(t, os.WriteFile(environment, []byte(environmentManifestFixture()), 0o600))
	out := filepath.Join(dir, "recordings")
	err := run("test", "a1", "connection", "prefer-idle", "", "127.0.0.1:0", "", time.Second, 1, 0, 0, "", out, "", "", environment, time.Millisecond)
	require.EqualError(t, err, "recorder build is missing the API replay overlay; use record.py build or run")
	require.NoDirExists(t, out)
}
