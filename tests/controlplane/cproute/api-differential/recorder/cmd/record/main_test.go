// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build apireplay

package main

import (
	"testing"

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
