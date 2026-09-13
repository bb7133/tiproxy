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

	"github.com/pingcap/tiproxy/tests/controlplane/cproute/api-differential/recorder/apireplay"
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
		err := run("test", "a1", "connection", "prefer-idle", "", "127.0.0.1:0", "", time.Second, 1, 0, "", out, path, "", "", time.Millisecond)
		require.Error(t, err)
		require.NoDirExists(t, out)
	}
	for _, identity := range []string{"", "cancelled", "deadline_exceeded", "topology_unavailable"} {
		require.NoError(t, validateActions([]Action{{Kind: "source_error", Error: identity}}))
	}
}

func TestEnvironmentManifestPreflight(t *testing.T) {
	digest := strings.Repeat("a", sha256.Size*2)
	valid := fmt.Sprintf(`{
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

func TestEnvironmentManifestIsRequiredBeforeCapture(t *testing.T) {
	out := filepath.Join(t.TempDir(), "recordings")
	err := run("test", "a1", "connection", "prefer-idle", "", "127.0.0.1:0", "", time.Second, 1, 0, "", out, "", "", "", time.Millisecond)
	require.EqualError(t, err, "-environment-manifest is required")
	require.NoDirExists(t, out)
}
