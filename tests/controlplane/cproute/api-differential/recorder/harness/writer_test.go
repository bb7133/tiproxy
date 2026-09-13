// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build apireplay

package harness

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/pingcap/tiproxy/tests/controlplane/cproute/api-differential/recorder/apireplay"
	"github.com/stretchr/testify/require"
)

func TestWriteBindsEnvironmentManifest(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "archive.jsonl"), nil, 0o600))
	environment := []byte(`{"environment":"snapshot"}`)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "environment-manifest.json"), environment, 0o600))
	sum := sha256.Sum256(environment)
	digest := fmt.Sprintf("%x", sum)
	status, err := Write(dir, "N01", "a1", TraceConfig{}, nil, nil, nil, false, CaptureSummary{EnvironmentManifestSHA256: digest})
	require.NoError(t, err)
	require.Equal(t, "recorded", status)
	data, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	require.NoError(t, err)
	var manifest map[string]any
	require.NoError(t, json.Unmarshal(data, &manifest))
	require.Equal(t, "environment-manifest.json", manifest["environment_manifest_file"])
	require.Equal(t, digest, manifest["environment_manifest_sha256"])
	require.Equal(t, digest, manifest["capture"].(map[string]any)["environment_manifest_sha256"])

	changedDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(changedDir, "archive.jsonl"), nil, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(changedDir, "environment-manifest.json"), environment, 0o600))
	_, err = Write(changedDir, "N01", "a2", TraceConfig{}, nil, nil, nil, false, CaptureSummary{EnvironmentManifestSHA256: fmt.Sprintf("%064d", 0)})
	require.ErrorContains(t, err, "environment manifest changed after preflight")
}

func TestSummarizeLifecyclesUsesAPIEvents(t *testing.T) {
	yes, no := true, false
	log := []Recorded{
		{Event: apireplay.Event{Op: "open", Session: "complete"}},
		{Event: apireplay.Event{Op: "next", Session: "complete"}},
		{Event: apireplay.Event{Op: "finish", Session: "complete", Success: &yes}},
		{Event: apireplay.Event{Op: "close", Session: "complete"}},
		{Event: apireplay.Event{Op: "close", Session: "complete"}}, // duplicate is not another completion
		{Event: apireplay.Event{Op: "open", Session: "failed"}},
		{Event: apireplay.Event{Op: "next", Session: "failed"}},
		{Event: apireplay.Event{Op: "finish", Session: "failed", Success: &no}},
		{Event: apireplay.Event{Op: "close", Session: "failed"}},
		{Event: apireplay.Event{Op: "open", Session: "unclosed"}},
		{Event: apireplay.Event{Op: "finish", Session: "unclosed", Success: &yes}},
	}
	require.Equal(t, LifecycleSummary{Opened: 3, Next: 2, SuccessfulFinishes: 2, Closed: 3, Completed: 1}, SummarizeLifecycles(log))
}

func TestQualifyingLifecyclesExcludeHeldSessionsDespiteAddressReuse(t *testing.T) {
	yes := true
	log := []Recorded{
		{Event: apireplay.Event{Op: "open", Session: "work", Client: "127.0.0.1:5000"}},
		{Event: apireplay.Event{Op: "next", Session: "work"}},
		{Event: apireplay.Event{Op: "finish", Session: "work", Success: &yes}},
		{Event: apireplay.Event{Op: "close", Session: "work"}},
		{Event: apireplay.Event{Op: "open", Session: "held", Client: "127.0.0.1:5000"}},
		{Event: apireplay.Event{Op: "next", Session: "held"}},
		{Event: apireplay.Event{Op: "finish", Session: "held", Success: &yes}},
		{Event: apireplay.Event{Op: "close", Session: "held"}},
	}
	require.Equal(t, LifecycleSummary{Opened: 1, Next: 1, SuccessfulFinishes: 1, Closed: 1, Completed: 1},
		SummarizeQualifyingLifecycles(log, map[string]struct{}{"held": {}}))
}

func TestTickRefusalsArePublicInputsAndMixedAcceptanceFailsClosed(t *testing.T) {
	refused, mixed, refuseNext := tickRefusals([]apireplay.Effect{
		{Session: "b", Accepted: false},
		{Session: "a", Accepted: false},
		{Session: "a", Accepted: false},
		{Session: "mixed", Accepted: false},
		{Session: "mixed", Accepted: true},
		{Session: "accepted", Accepted: true},
		{Session: "relative", Accepted: false, RefuseNext: true},
	})
	require.Equal(t, []string{"a", "b"}, refused)
	require.Equal(t, []string{"mixed"}, mixed)
	require.Equal(t, 1, refuseNext)
}

func TestWriteCarriesRefusedEffectIntoTickInput(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "archive.jsonl"), nil, 0o600))
	log := []Recorded{
		{Seq: 0, AtNanos: 10, Event: apireplay.Event{Op: "tick_begin"}},
		{Seq: 1, AtNanos: 10, Event: apireplay.Event{Op: "effect", Effects: []apireplay.Effect{
			{Kind: "force_close", Session: "s", Operation: "s/1", From: "a", Accepted: false},
		}}},
		{Seq: 2, AtNanos: 10, Event: apireplay.Event{Op: "tick_end"}},
	}
	_, err := Write(dir, "F01", "t1", TraceConfig{}, log, nil, nil, false, CaptureSummary{Synthetic: true})
	require.NoError(t, err)
	data, err := os.ReadFile(filepath.Join(dir, "trace.json"))
	require.NoError(t, err)
	var trace struct {
		Events []map[string]any `json:"events"`
	}
	require.NoError(t, json.Unmarshal(data, &trace))
	require.Equal(t, []any{"s"}, trace.Events[0]["refuse"])
}

func TestWriteCarriesRelativeRefusalCallbackAndDelayedClose(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "archive.jsonl"), nil, 0o600))
	yes := true
	log := []Recorded{
		{Seq: 0, AtNanos: 10, Event: apireplay.Event{Op: "tick_begin"}},
		{Seq: 1, AtNanos: 10, Event: apireplay.Event{Op: "effect", Effects: []apireplay.Effect{
			{Kind: "redirect", Session: "first", Operation: "first/1", From: "a", To: "b", Accepted: false, RefuseNext: true},
		}}},
		{Seq: 2, AtNanos: 10, Event: apireplay.Event{Op: "effect", Effects: []apireplay.Effect{
			{Kind: "redirect", Session: "held", Operation: "held/1", From: "a", To: "b", Accepted: true},
		}}},
		{Seq: 3, AtNanos: 10, Event: apireplay.Event{Op: "tick_end"}},
		{Seq: 4, AtNanos: 20, Event: apireplay.Event{Op: "close", Session: "held", Operation: "held/1"}},
		{Seq: 5, AtNanos: 20, Event: apireplay.Event{Op: "redirect_result", Session: "held", Operation: "held/1", Success: &yes}},
	}
	_, err := Write(dir, "F01", "t1", TraceConfig{}, log, nil, nil, false, CaptureSummary{Synthetic: true})
	require.NoError(t, err)
	var trace struct {
		Events []map[string]any `json:"events"`
	}
	data, err := os.ReadFile(filepath.Join(dir, "trace.json"))
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(data, &trace))
	require.Equal(t, float64(1), trace.Events[0]["refuse_next"])
	require.NotContains(t, trace.Events[0], "refuse")
	require.Equal(t, "redirect/1", trace.Events[1]["effect_ref"])
	require.Equal(t, "redirect/1", trace.Events[2]["effect_ref"])

	var rows []map[string]any
	data, err = os.ReadFile(filepath.Join(dir, "go.json"))
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(data, &rows))
	effects := rows[0]["effects"].([]any)
	require.NotContains(t, effects[0].(map[string]any), "refuse_next")
}

func TestWriteArmsGlobalRefusalAtConfigAndConsumesItOnALaterTick(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "archive.jsonl"), nil, 0o600))
	log := []Recorded{
		{Seq: 0, AtNanos: 5, Event: apireplay.Event{Op: "config", TOML: "[proxy]\nfail-backend-list=[\"a\"]\n", Outcome: "ok", RefuseNext: true}},
		{Seq: 1, AtNanos: 10, Event: apireplay.Event{Op: "tick_begin"}},
		{Seq: 2, AtNanos: 10, Event: apireplay.Event{Op: "tick_end"}},
		{Seq: 3, AtNanos: 20, Event: apireplay.Event{Op: "tick_begin"}},
		{Seq: 4, AtNanos: 20, Event: apireplay.Event{Op: "effect", Effects: []apireplay.Effect{
			{Kind: "redirect", Session: "s", Operation: "s/1", From: "a", To: "b", RefuseNext: true},
		}}},
		{Seq: 5, AtNanos: 20, Event: apireplay.Event{Op: "tick_end"}},
		{Seq: 6, AtNanos: 30, Event: apireplay.Event{Op: "config", TOML: "[proxy]\nfail-backend-list=[]\n", Outcome: "ok"}},
	}
	status, err := Write(dir, "F01", "t1", TraceConfig{}, log, nil, nil, false, CaptureSummary{Synthetic: true})
	require.NoError(t, err)
	require.Equal(t, "recorded", status)
	data, err := os.ReadFile(filepath.Join(dir, "trace.json"))
	require.NoError(t, err)
	var trace struct {
		Events []map[string]any `json:"events"`
	}
	require.NoError(t, json.Unmarshal(data, &trace))
	require.Equal(t, float64(1), trace.Events[0]["refuse_next"])
	require.NotContains(t, trace.Events[1], "refuse_next")
	require.NotContains(t, trace.Events[2], "refuse_next")
}

func TestWriteFailsClosedWhenGlobalRefusalReachesFailoverClear(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "archive.jsonl"), nil, 0o600))
	log := []Recorded{
		{Seq: 0, AtNanos: 5, Event: apireplay.Event{Op: "config", TOML: "[proxy]\nfail-backend-list=[\"a\"]\n", Outcome: "ok", RefuseNext: true}},
		{Seq: 1, AtNanos: 10, Event: apireplay.Event{Op: "tick_begin"}},
		{Seq: 2, AtNanos: 10, Event: apireplay.Event{Op: "tick_end"}},
		{Seq: 3, AtNanos: 20, Event: apireplay.Event{Op: "config", TOML: "[proxy]\nfail-backend-list=[]\n", Outcome: "ok"}},
	}
	status, err := Write(dir, "F01", "t1", TraceConfig{}, log, nil, nil, false, CaptureSummary{Synthetic: true})
	require.NoError(t, err)
	require.Equal(t, "incomplete", status)
	data, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	require.NoError(t, err)
	var manifest map[string]any
	require.NoError(t, json.Unmarshal(data, &manifest))
	require.Contains(t, manifest["incomplete"], "seq 3: global refusal was not consumed before failover clear")
}

func TestWriteFailsClosedWhenGlobalRefusalIsArmedTwice(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "archive.jsonl"), nil, 0o600))
	log := []Recorded{
		{Seq: 0, AtNanos: 5, Event: apireplay.Event{Op: "config", TOML: "[proxy]\nfail-backend-list=[\"a\"]\n", Outcome: "ok", RefuseNext: true}},
		{Seq: 1, AtNanos: 10, Event: apireplay.Event{Op: "config", TOML: "[proxy]\nfail-backend-list=[\"a\"]\n", Outcome: "ok", RefuseNext: true}},
	}
	status, err := Write(dir, "F01", "t1", TraceConfig{}, log, nil, nil, false, CaptureSummary{Synthetic: true})
	require.NoError(t, err)
	require.Equal(t, "incomplete", status)
	data, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	require.NoError(t, err)
	var manifest map[string]any
	require.NoError(t, json.Unmarshal(data, &manifest))
	require.Contains(t, manifest["incomplete"], "seq 1: global refusal armed while one is pending")
}

func TestWriteFailsClosedWhenGlobalRefusalIsConsumedTwice(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "archive.jsonl"), nil, 0o600))
	log := []Recorded{
		{Seq: 0, AtNanos: 10, Event: apireplay.Event{Op: "tick_begin"}},
		{Seq: 1, AtNanos: 10, Event: apireplay.Event{Op: "effect", Effects: []apireplay.Effect{
			{Kind: "redirect", Session: "first", Operation: "first/1", From: "a", To: "b", RefuseNext: true},
			{Kind: "redirect", Session: "second", Operation: "second/1", From: "a", To: "b", RefuseNext: true},
		}}},
		{Seq: 2, AtNanos: 10, Event: apireplay.Event{Op: "tick_end"}},
	}
	status, err := Write(dir, "F01", "t1", TraceConfig{}, log, nil, nil, false, CaptureSummary{Synthetic: true})
	require.NoError(t, err)
	require.Equal(t, "incomplete", status)
	data, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	require.NoError(t, err)
	var manifest map[string]any
	require.NoError(t, json.Unmarshal(data, &manifest))
	require.Contains(t, manifest["incomplete"], "tick at 10: global refusal consumed 2 effects")
}

func TestWriteFailsClosedWhenObservedMetricsLackPublication(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "archive.jsonl"), nil, 0o600))
	status, err := Write(dir, "N01", "a1", TraceConfig{}, nil, nil, nil, true, CaptureSummary{Synthetic: true})
	require.NoError(t, err)
	require.Equal(t, "incomplete", status)
	data, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	require.NoError(t, err)
	var manifest map[string]any
	require.NoError(t, json.Unmarshal(data, &manifest))
	require.Equal(t, []any{"nonempty metrics observed without a recorded whole publication"}, manifest["incomplete"])
	require.NotContains(t, manifest, "requires")
	require.Equal(t, "pending-derivation", manifest["qualification"])
}
