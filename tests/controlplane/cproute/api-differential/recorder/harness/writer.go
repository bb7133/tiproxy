// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build apireplay

package harness

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/pingcap/tiproxy/tests/controlplane/cproute/api-differential/recorder/apireplay"
)

// TraceConfig is the trace v1 header config block.
type TraceConfig struct {
	Policy    string `json:"policy"`
	Selection string `json:"selection"`
	Rule      string `json:"rule"`
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

// Write converts the recorded log into the trace v1 input file (no expect
// blocks), the Go rows file and a manifest with hashes. Ticks are folded:
// `tick_begin` … effects … `tick_end` become one `tick` event whose row carries
// the effects issued during that iteration; `effect` records outside a tick
// (none expected) are refused into the manifest as `incomplete`.
func Write(dir, slot, attempt string, cfg TraceConfig, log []Recorded, checkpoints map[int]Checkpoint, incomplete []string, metricsObserved bool) (string, error) {
	events := make([]map[string]any, 0, len(log))
	rows := make([]map[string]any, 0, len(log))
	var inTick bool
	var tickEffects []apireplay.Effect
	var tickAt int64
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
			inTick, tickEffects, tickAt = true, nil, r.AtNanos
		case "tick_end":
			ev := map[string]any{"op": "tick"}
			effects := tickEffects
			if effects == nil {
				effects = []apireplay.Effect{}
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
		case "source_error":
			push(map[string]any{"op": "source_error", "error": e.Outcome}, map[string]any{"op": "source_error", "outcome": "ok"}, r.AtNanos)
		case "config":
			push(map[string]any{"op": "config", "toml": e.TOML}, map[string]any{"op": "config", "outcome": e.Outcome}, r.AtNanos)
		case "open":
			push(map[string]any{"op": "open", "session": e.Session, "client": e.Client, "proxy": e.Proxy, "port": e.Port},
				map[string]any{"op": "open", "session": e.Session, "outcome": "ok"}, r.AtNanos)
		case "next":
			push(map[string]any{"op": "next", "session": e.Session}, map[string]any{"op": "next", "session": e.Session, "outcome": e.Outcome, "backend": e.Backend}, r.AtNanos)
		case "finish":
			push(map[string]any{"op": "finish", "session": e.Session, "success": *e.Success}, map[string]any{"op": "finish", "session": e.Session, "outcome": "ok"}, r.AtNanos)
		case "close":
			push(map[string]any{"op": "close", "session": e.Session}, map[string]any{"op": "close", "session": e.Session, "outcome": "ok"}, r.AtNanos)
		case "redirect_result":
			push(map[string]any{"op": "redirect_result", "session": e.Session, "operation": e.Operation, "success": *e.Success},
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
		default:
			incomplete = append(incomplete, fmt.Sprintf("seq %d: unknown record %q", r.Seq, e.Op))
		}
	}
	if inTick {
		incomplete = append(incomplete, "trace ended inside a tick")
	}
	trace := map[string]any{
		"version": 1,
		"id":      slot + "-" + attempt,
		"config":  cfg,
		"provenance": map[string]any{
			"kind": "recorded", "slot": slot, "attempt": attempt, "recorded_at_utc": time.Now().UTC().Format(time.RFC3339),
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
	manifest := map[string]any{
		"slot": slot, "attempt": attempt, "status": status, "incomplete": incomplete,
		"events": len(events), "trace_sha256": fileSHA(tracePath), "go_sha256": fileSHA(rowsPath),
		"archive_sha256": fileSHA(filepath.Join(dir, "archive.jsonl")),
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
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

func fileSHA(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
