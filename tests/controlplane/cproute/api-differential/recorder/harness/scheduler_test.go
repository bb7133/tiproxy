// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build apireplay

package harness

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pingcap/tiproxy/tests/controlplane/cproute/api-differential/recorder/apireplay"
)

func TestArchiveIsExclusiveAndSealed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "archive.jsonl")
	s, err := NewScheduler(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = NewScheduler(path); err == nil {
		t.Fatal("overwrote first attempt")
	}
	s.RunNow(func() { s.Record(apireplay.Event{Op: "checkpoint"}) })
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	s.RunNow(func() { s.Record(apireplay.Event{Op: "health"}) })
	if err = s.Close(); err == nil || !strings.Contains(err.Error(), "after archive sealed") {
		t.Fatalf("late producer not reported: %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) || len(s.Log()) != 1 {
		t.Fatal("sealed snapshot changed")
	}
}
func TestArchiveWriteFailureIsReported(t *testing.T) {
	s, err := NewScheduler(filepath.Join(t.TempDir(), "archive.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if err = s.archive.Close(); err != nil {
		t.Fatal(err)
	}
	s.RunNow(func() { s.Record(apireplay.Event{Op: "checkpoint"}) })
	if err = s.Close(); err == nil || !strings.Contains(err.Error(), "archive seq 0") {
		t.Fatalf("lost write failure: %v", err)
	}
}
