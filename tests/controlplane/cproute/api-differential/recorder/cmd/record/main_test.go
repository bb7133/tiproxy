// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build apireplay

package main

import (
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pingcap/tiproxy/tests/controlplane/cproute/api-differential/recorder/apireplay"
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
		err := run("test", "a1", "connection", "prefer-idle", "", "127.0.0.1:0", "", time.Second, 1, 0, "", out, path, "", time.Millisecond)
		require.Error(t, err)
		require.NoDirExists(t, out)
	}
	for _, identity := range []string{"", "cancelled", "deadline_exceeded", "topology_unavailable"} {
		require.NoError(t, validateActions([]Action{{Kind: "source_error", Error: identity}}))
	}
}
