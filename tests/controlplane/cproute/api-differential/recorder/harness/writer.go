// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build apireplay

package harness

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/pingcap/tiproxy/tests/controlplane/cproute/api-differential/recorder/apireplay"
)

// TraceConfig is the trace v1 header config block.
type TraceConfig struct {
	ClockOriginNanos *int64 `json:"clock_origin_nanos,omitempty"`
	Policy           string `json:"policy"`
	Selection        string `json:"selection"`
	Rule             string `json:"rule"`
}

// Checkpoint is a public-state snapshot taken by the harness under the
// scheduler lock (router public getters + the harness ledger).
type Checkpoint struct {
	Seq                 int               `json:"seq"`
	Assignments         map[string]string `json:"assignments"`
	ConnCount           int               `json:"conn_count"`
	HealthyBackendCount int               `json:"healthy_backend_count"`
	ServerVersion       string            `json:"server_version"`
}

// CaptureSummary identifies the recording build and workload; qualification
// additionally requires schema validation and replay of the derived inputs.
type CaptureSummary struct {
	Synthetic                 bool   `json:"synthetic,omitempty"`
	Head                      string `json:"head"`
	Tree                      string `json:"tree"`
	SourceDirty               string `json:"source_dirty"`
	DurationNanos             int64  `json:"duration_nanos"`
	PlannedDurationNanos      int64  `json:"planned_duration_nanos"`
	Completed                 int64  `json:"completed_connections"`
	Failed                    int64  `json:"failed_connections"`
	WorkloadCompleted         int64  `json:"workload_completed_queries"`
	WorkloadFailed            int64  `json:"workload_failed_queries"`
	Clients                   int    `json:"clients"`
	HeldClients               int    `json:"held_clients"`
	HeldQueries               int64  `json:"held_queries"`
	HeldFailed                int64  `json:"held_failed_queries"`
	ScriptSHA256              string `json:"script_sha256"`
	EnvironmentManifestSHA256 string `json:"environment_manifest_sha256,omitempty"`
}

// LifecycleSummary counts only recorder API events. Completed is the number of
// distinct opened sessions that established a backend and later closed; this,
// rather than the independent workload counter, is the qualification count.
type LifecycleSummary struct {
	Opened             int64
	Next               int64
	SuccessfulFinishes int64
	Closed             int64
	Completed          int64
}

// SummarizeLifecycles reconstructs every finite public lifecycle from the raw
// archive without consulting router internals.
func SummarizeLifecycles(log []Recorded) LifecycleSummary {
	return summarizeLifecycles(log, nil)
}

// SummarizeQualifyingLifecycles excludes supplemental held-client sessions.
// Their API events remain in the trace for effect coverage, but cannot inflate
// the short-lifecycle threshold. Identity is frozen at each open so a later
// ordinary connection reusing the held connection's address is still counted.
func SummarizeQualifyingLifecycles(log []Recorded, heldSessions map[string]struct{}) LifecycleSummary {
	return summarizeLifecycles(log, heldSessions)
}

func summarizeLifecycles(log []Recorded, heldSessions map[string]struct{}) LifecycleSummary {
	type state struct {
		opened, established, closed bool
	}
	states := make(map[string]*state)
	var summary LifecycleSummary
	for _, record := range log {
		event := record.Event
		s := states[event.Session]
		if s == nil && event.Session != "" {
			s = &state{}
			states[event.Session] = s
		}
		if _, held := heldSessions[event.Session]; held {
			continue
		}
		switch event.Op {
		case "open":
			summary.Opened++
			if s != nil {
				s.opened = true
			}
		case "next":
			summary.Next++
		case "finish":
			if event.Success != nil && *event.Success {
				summary.SuccessfulFinishes++
				if s != nil {
					s.established = true
				}
			}
		case "close":
			summary.Closed++
			if s != nil && s.opened && s.established && !s.closed {
				summary.Completed++
			}
			if s != nil {
				s.closed = true
			}
		}
	}
	return summary
}

func tickRefusals(effects []apireplay.Effect) (refused []string, mixed []string, refuseNext int) {
	type acceptance uint8
	const (
		rejected acceptance = 1 << iota
		accepted
	)
	states := make(map[string]acceptance)
	for _, effect := range effects {
		if effect.RefuseNext {
			refuseNext++
			continue
		}
		if effect.Accepted {
			states[effect.Session] |= accepted
		} else {
			states[effect.Session] |= rejected
		}
	}
	for session, state := range states {
		switch state {
		case rejected:
			refused = append(refused, session)
		case rejected | accepted:
			mixed = append(mixed, session)
		}
	}
	sort.Strings(refused)
	sort.Strings(mixed)
	return
}

func publicEffects(effects []apireplay.Effect) []apireplay.Effect {
	public := make([]apireplay.Effect, len(effects))
	copy(public, effects)
	for i := range public {
		public[i].RefuseNext = false
	}
	return public
}

func clearsFailover(input string) bool {
	var patch struct {
		Proxy struct {
			FailBackendList []string `toml:"fail-backend-list"`
		} `toml:"proxy"`
	}
	metadata, err := toml.Decode(input, &patch)
	return err == nil && metadata.IsDefined("proxy", "fail-backend-list") && len(patch.Proxy.FailBackendList) == 0
}

// Write converts the recorded log into the trace v1 input file (no expect
// blocks), the Go rows file and a manifest with hashes. Ticks are folded:
// `tick_begin` … effects … `tick_end` become one `tick` event whose row carries
// the effects issued during that iteration; `effect` records outside a tick
// (none expected) are refused into the manifest as `incomplete`.
func Write(dir, slot, attempt string, cfg TraceConfig, log []Recorded, checkpoints map[int]Checkpoint, incomplete []string, metricsObserved bool, summary CaptureSummary) (string, error) {
	events := make([]map[string]any, 0, len(log))
	rows := make([]map[string]any, 0, len(log))
	var inTick bool
	var tickEffects []apireplay.Effect
	var tickAt int64
	var metricPublications int
	var pendingGlobalRefusal bool
	operationRefs := make(map[string]string)
	acceptedRedirects := 0
	push := func(ev map[string]any, row map[string]any, at int64) {
		ev["at_nanos"] = at
		row["seq"] = len(rows)
		if _, ok := row["effects"]; !ok {
			row["effects"] = []apireplay.Effect{}
		}
		if _, ok := row["backend"]; !ok {
			row["backend"] = ""
		}
		if _, ok := row["session"]; !ok {
			row["session"] = ""
		}
		events = append(events, ev)
		rows = append(rows, row)
	}
	for _, r := range log {
		e := r.Event
		switch e.Op {
		case "tick_begin":
			if inTick {
				incomplete = append(incomplete, fmt.Sprintf("seq %d: nested tick", r.Seq))
			}
			inTick, tickEffects, tickAt = true, nil, r.AtNanos
		case "tick_end":
			if !inTick {
				incomplete = append(incomplete, fmt.Sprintf("seq %d: tick end without begin", r.Seq))
			}
			ev := map[string]any{"op": "tick"}
			effects := publicEffects(tickEffects)
			if effects == nil {
				effects = []apireplay.Effect{}
			}
			refused, mixed, refuseNext := tickRefusals(tickEffects)
			if len(refused) > 0 {
				ev["refuse"] = refused
			}
			if refuseNext > 0 && pendingGlobalRefusal {
				pendingGlobalRefusal = false
			} else if refuseNext > 0 {
				// Backward-compatible standalone controls cannot be attached to a
				// config boundary, so their consumed effect still carries the arm.
				ev["refuse_next"] = refuseNext
			}
			if refuseNext > 1 {
				incomplete = append(incomplete, fmt.Sprintf("tick at %d: global refusal consumed %d effects", tickAt, refuseNext))
			}
			for _, effect := range effects {
				if effect.Kind == "redirect" && effect.Accepted {
					acceptedRedirects++
					operationRefs[effect.Operation] = fmt.Sprintf("redirect/%d", acceptedRedirects)
				}
			}
			for _, session := range mixed {
				incomplete = append(incomplete, fmt.Sprintf("tick at %d: session %s has both accepted and refused effects", tickAt, session))
			}
			push(ev, map[string]any{"op": "tick", "outcome": "ok", "effects": effects}, tickAt)
			inTick = false
		case "effect":
			if !inTick {
				incomplete = append(incomplete, fmt.Sprintf("seq %d: effect outside a declared tick", r.Seq))
				continue
			}
			tickEffects = append(tickEffects, e.Effects...)
		case "health":
			backends := make([]map[string]any, 0, len(e.Backends))
			sort.Slice(e.Backends, func(i, j int) bool { return e.Backends[i].ID < e.Backends[j].ID })
			for _, b := range e.Backends {
				labels := b.Labels
				if labels == nil {
					labels = map[string]string{}
				}
				backends = append(backends, map[string]any{"address": b.Address, "labels": labels, "cluster": b.Cluster, "keyspace": b.Keyspace, "ip": b.IP,
					"status_port": b.StatusPort, "healthy": b.Healthy, "local": b.Local, "server_version": b.ServerVersion, "support_redirection": b.SupportRedirection})
			}
			push(map[string]any{"op": "health", "backends": backends}, map[string]any{"op": "health", "outcome": "ok"}, r.AtNanos)
		case "metrics":
			push(map[string]any{"op": "metrics", "queries": e.Metrics}, map[string]any{"op": "metrics", "outcome": "ok"}, r.AtNanos)
			metricPublications++
		case "source_error":
			if e.Outcome == "unclassified_source_error" {
				incomplete = append(incomplete, fmt.Sprintf("seq %d: unclassified source error", r.Seq))
			}
			push(map[string]any{"op": "source_error", "error": e.Outcome}, map[string]any{"op": "source_error", "outcome": "ok"}, r.AtNanos)
		case "config":
			ev := map[string]any{"op": "config", "toml": e.TOML}
			if e.RefuseNext {
				if pendingGlobalRefusal {
					incomplete = append(incomplete, fmt.Sprintf("seq %d: global refusal armed while one is pending", r.Seq))
				}
				pendingGlobalRefusal = true
				ev["refuse_next"] = 1
			}
			if e.Outcome == "ok" && clearsFailover(e.TOML) && pendingGlobalRefusal {
				incomplete = append(incomplete, fmt.Sprintf("seq %d: global refusal was not consumed before failover clear", r.Seq))
			}
			push(ev, map[string]any{"op": "config", "outcome": e.Outcome}, r.AtNanos)
		case "open":
			push(map[string]any{"op": "open", "session": e.Session, "client": e.Client, "proxy": e.Proxy, "port": e.Port},
				map[string]any{"op": "open", "session": e.Session, "outcome": "ok"}, r.AtNanos)
		case "next":
			push(map[string]any{"op": "next", "session": e.Session}, map[string]any{"op": "next", "session": e.Session, "outcome": e.Outcome, "backend": e.Backend}, r.AtNanos)
		case "finish":
			push(map[string]any{"op": "finish", "session": e.Session, "success": *e.Success}, map[string]any{"op": "finish", "session": e.Session, "outcome": "ok"}, r.AtNanos)
		case "close":
			ev := map[string]any{"op": "close", "session": e.Session}
			if e.Operation != "" {
				ref, ok := operationRefs[e.Operation]
				if !ok {
					incomplete = append(incomplete, fmt.Sprintf("seq %d: delayed close operation %s has no accepted redirect", r.Seq, e.Operation))
				} else {
					ev["effect_ref"] = ref
				}
			}
			push(ev, map[string]any{"op": "close", "session": e.Session, "outcome": "ok"}, r.AtNanos)
		case "redirect_result":
			ref, ok := operationRefs[e.Operation]
			if !ok {
				incomplete = append(incomplete, fmt.Sprintf("seq %d: redirect result operation %s has no accepted effect", r.Seq, e.Operation))
			}
			push(map[string]any{"op": "redirect_result", "session": e.Session, "effect_ref": ref, "success": *e.Success},
				map[string]any{"op": "redirect_result", "session": e.Session, "outcome": "ok"}, r.AtNanos)
		case "lookup", "rehydrate":
			ev := map[string]any{"op": e.Op, "backend": e.Backend}
			if e.Op == "rehydrate" {
				ev["session"] = e.Session
			}
			row := map[string]any{"op": e.Op, "session": e.Session, "outcome": e.Outcome}
			if e.Outcome == "ok" {
				row["backend"] = e.Backend
			}
			push(ev, row, r.AtNanos)
		case "checkpoint":
			cp := checkpoints[r.Seq]
			push(map[string]any{"op": "checkpoint"}, map[string]any{"op": "checkpoint", "outcome": "ok", "assignments": cp.Assignments,
				"conn_count": cp.ConnCount, "healthy_backend_count": cp.HealthyBackendCount, "server_version": cp.ServerVersion}, r.AtNanos)
		case "recorder_error":
			incomplete = append(incomplete, fmt.Sprintf("seq %d: %s", r.Seq, e.Outcome))
		default:
			incomplete = append(incomplete, fmt.Sprintf("seq %d: unknown record %q", r.Seq, e.Op))
		}
	}
	if inTick {
		incomplete = append(incomplete, "trace ended inside a tick")
	}
	if pendingGlobalRefusal {
		incomplete = append(incomplete, "global refusal input was never consumed")
	}
	// MetricsInputs can observe nonempty source data only while recording the
	// corresponding whole publication under this scheduler. Treat disagreement
	// as capture loss, not as a policy dependency. The independent deriver is
	// the sole authority for `requires` after it consumes the complete history.
	if metricsObserved && metricPublications == 0 {
		incomplete = append(incomplete, "nonempty metrics observed without a recorded whole publication")
	}
	kind := "recorded"
	if summary.Synthetic {
		kind = "synthetic"
	}
	trace := map[string]any{
		"version": 1,
		"id":      slot + "-" + attempt,
		"config":  cfg,
		"provenance": map[string]any{
			"kind": kind, "slot": slot, "attempt": attempt, "recorded_at_utc": time.Now().UTC().Format(time.RFC3339),
			"metrics_observed": metricsObserved,
		},
		"events": events,
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	tracePath := filepath.Join(dir, "trace.json")
	rowsPath := filepath.Join(dir, "go.json")
	if err := writeJSON(tracePath, trace); err != nil {
		return "", err
	}
	if err := writeJSON(rowsPath, rows); err != nil {
		return "", err
	}
	status := "recorded"
	if len(incomplete) > 0 {
		status = "incomplete"
	}
	hashes := make(map[string]string)
	for _, name := range []string{"trace", "go", "archive"} {
		ext := ".json"
		if name == "archive" {
			ext = ".jsonl"
		}
		sum, err := fileSHA(filepath.Join(dir, name+ext))
		if err != nil {
			return "", err
		}
		hashes[name] = sum
	}
	if summary.EnvironmentManifestSHA256 != "" {
		sum, err := fileSHA(filepath.Join(dir, "environment-manifest.json"))
		if err != nil {
			return "", fmt.Errorf("hash environment manifest: %w", err)
		}
		if sum != summary.EnvironmentManifestSHA256 {
			return "", fmt.Errorf("environment manifest changed after preflight: got %s, want %s", sum, summary.EnvironmentManifestSHA256)
		}
	}
	manifest := map[string]any{
		"slot": slot, "attempt": attempt, "status": status, "incomplete": incomplete,
		"capture": summary, "qualified": false, "qualification": "pending-derivation",
		"events": len(events), "trace_sha256": hashes["trace"], "go_sha256": hashes["go"],
		"archive_sha256": hashes["archive"],
	}
	if summary.EnvironmentManifestSHA256 != "" {
		manifest["environment_manifest_file"] = "environment-manifest.json"
		manifest["environment_manifest_sha256"] = summary.EnvironmentManifestSHA256
	}
	if err := writeJSON(filepath.Join(dir, "manifest.json"), manifest); err != nil {
		return "", err
	}
	return status, nil
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(append(b, '\n'))
	return errors.Join(writeErr, f.Sync(), f.Close())
}

func fileSHA(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}
