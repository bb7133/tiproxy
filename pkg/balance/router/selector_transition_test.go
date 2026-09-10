// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package router

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/pingcap/tiproxy/lib/util/errors"
	"github.com/pingcap/tiproxy/pkg/balance/observer"
	"github.com/stretchr/testify/require"
)

type selectorInput struct {
	Backend uint64 `json:"backend"`
	Error   string `json:"error"`
}
type selectorNext struct {
	Inputs         []selectorInput `json:"inputs"`
	Before         uint64          `json:"before"`
	ExcludedBefore []uint64        `json:"excluded_before"`
	Attempts       [][]uint64      `json:"attempts"`
	Backend        uint64          `json:"backend"`
	Error          string          `json:"error"`
	Current        uint64          `json:"current"`
	Excluded       []uint64        `json:"excluded"`
	Finish         []uint64        `json:"finish"`
}
type selectorCase struct {
	Name  string         `json:"name"`
	Steps []selectorNext `json:"steps"`
}

// This oracle calls the unmodified production Next and Finish with controlled
// routeOnce inputs. It records behavior, rather than implementing expected
// transitions in Go. The Rust component independently calculates that layer.
// It does not establish native routeOnce or router metadata comparison.
func TestSelectorTransitionOracle(t *testing.T) {
	ok := func(id uint64) selectorInput { return selectorInput{Backend: id, Error: "none"} }
	failure := func(kind string, id uint64) selectorInput { return selectorInput{Backend: id, Error: kind} }
	definitions := []struct {
		name  string
		steps [][]selectorInput
	}{
		{"success-append", [][]selectorInput{{ok(1)}, {ok(2)}}},
		{"duplicate-history", [][]selectorInput{{ok(1)}, {ok(1)}}},
		{"empty-sentinel", [][]selectorInput{{failure("sentinel", 0)}}},
		{"exact-retry", [][]selectorInput{{ok(1)}, {failure("sentinel", 0), ok(2)}}},
		{"no-group-retry", [][]selectorInput{{ok(1)}, {failure("no-group", 0), ok(3)}}},
		{"observer-sentinel-retry", [][]selectorInput{{ok(1)}, {failure("observer-sentinel", 0), ok(2)}}},
		{"wrapped-sentinel", [][]selectorInput{{ok(1)}, {failure("wrapped", 0), ok(2)}}},
		{"ordinary-error", [][]selectorInput{{ok(1)}, {failure("ordinary", 9), ok(2)}}},
		{"port-conflict", [][]selectorInput{{ok(1)}, {failure("conflict", 0), ok(2)}}},
		{"retry-second-sentinel", [][]selectorInput{{ok(1)}, {failure("sentinel", 0), failure("sentinel", 0), ok(3)}}},
		{"retry-error-backend", [][]selectorInput{{ok(1)}, {failure("sentinel", 0), failure("ordinary", 9)}}},
		{"retry-then-next", [][]selectorInput{{ok(1)}, {failure("sentinel", 0), failure("ordinary", 9)}, {ok(3)}}},
	}
	backends := make(map[uint64]BackendInst)
	ids := make(map[BackendInst]uint64)
	for _, id := range []uint64{1, 2, 3, 9} {
		b := newBackendWrapper(string(rune('a'+id)), observer.BackendHealth{})
		backends[id], ids[b] = b, id
	}
	capture := func(backends []BackendInst) []uint64 {
		result := make([]uint64, 0, len(backends))
		for _, b := range backends {
			result = append(result, ids[b])
		}
		return result
	}
	errorValue := func(kind string) error {
		switch kind {
		case "none":
			return nil
		case "sentinel", "no-group", "observer-sentinel":
			return ErrNoBackend
		case "wrapped":
			return errors.Wrapf(ErrNoBackend, "wrapped fixture")
		case "conflict":
			return errors.Wrapf(ErrPortConflict, "conflict fixture")
		default:
			return errors.New("ordinary fixture")
		}
	}
	classify := func(err error) string {
		if err == nil {
			return "none"
		}
		if err == ErrNoBackend {
			return "sentinel"
		}
		return "other"
	}
	all := make([]selectorCase, 0, len(definitions))
	for _, definition := range definitions {
		row := selectorCase{Name: definition.name, Steps: make([]selectorNext, 0, len(definition.steps))}
		bs := BackendSelector{}
		for _, inputs := range definition.steps {
			step := selectorNext{Inputs: inputs, Before: ids[bs.cur], ExcludedBefore: capture(bs.excluded), Attempts: make([][]uint64, 0), Finish: make([]uint64, 0)}
			bs.routeOnce = func(excluded []BackendInst) (BackendInst, error) {
				index := len(step.Attempts)
				step.Attempts = append(step.Attempts, capture(excluded))
				if index >= len(inputs) {
					return nil, errors.New("unexpected extra attempt")
				}
				input := inputs[index]
				return backends[input.Backend], errorValue(input.Error)
			}
			bs.onCreate = func(backend BackendInst, _ RedirectableConn, _ bool) { step.Finish = append(step.Finish, ids[backend]) }
			b, err := bs.Next()
			step.Backend, step.Error, step.Current, step.Excluded = ids[b], classify(err), ids[bs.cur], capture(bs.excluded)
			// Even after an error, Finish passes the retained cur, not the error's
			// returned backend. Lifecycle acceptance is deliberately outside this probe.
			bs.Finish(nil, false)
			row.Steps = append(row.Steps, step)
		}
		all = append(all, row)
	}
	path := os.Getenv("CP_ROUTE_SELECTOR_ORACLE")
	if path == "" {
		path = filepath.Join(t.TempDir(), "selector.json")
	}
	data, err := json.Marshal(all)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, data, 0600))
}
