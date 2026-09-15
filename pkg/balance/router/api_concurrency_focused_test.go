// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package router

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// Concurrency focused suite (API differential contract section 4). Each case
// has two four-operation actors. The controller releases them using one of 16
// fixed schedules; adjacent releases may overlap, while repeated releases of
// one actor wait for that actor's prior public call to return.

type concurrencySpec struct {
	Suite     string `json:"suite"`
	Cases     []string
	Schedules []struct {
		ID      string `json:"id"`
		Release string `json:"release"`
	} `json:"schedules"`
}

type concurrencyEvent struct {
	Actor   string `json:"actor"`
	Step    int    `json:"step"`
	Call    string `json:"call"`
	Outcome string `json:"outcome"`
}

type concurrencyRow struct {
	Case             string             `json:"case"`
	Schedule         string             `json:"schedule"`
	History          []concurrencyEvent `json:"history"`
	FinalConnCount   int                `json:"final_conn_count"`
	RetainedBackends []string           `json:"retained_backends"`
	Violations       []string           `json:"violations"`
}

type concurrencyCall func() (string, string)

func runBarrierSchedule(t *testing.T, release string, actorA, actorB []concurrencyCall) []concurrencyEvent {
	t.Helper()
	require.Len(t, actorA, 4)
	require.Len(t, actorB, 4)
	require.Len(t, release, 8)
	ready := [2]chan int{make(chan int, 1), make(chan int, 1)}
	proceed := [2]chan struct{}{make(chan struct{}), make(chan struct{})}
	events := make(chan concurrencyEvent, 8)
	var workers sync.WaitGroup
	start := func(actor int, calls []concurrencyCall) {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for step, call := range calls {
				ready[actor] <- step
				<-proceed[actor]
				name, outcome := call()
				events <- concurrencyEvent{Actor: string(rune('A' + actor)), Step: step, Call: name, Outcome: outcome}
			}
		}()
	}
	start(0, actorA)
	start(1, actorB)
	for _, token := range release {
		actor := int(token - 'A')
		require.Contains(t, []int{0, 1}, actor)
		<-ready[actor]
		proceed[actor] <- struct{}{}
	}
	workers.Wait()
	close(events)
	history := make([]concurrencyEvent, 0, 8)
	for event := range events {
		history = append(history, event)
	}
	return history
}

// concurrencyConn is deliberately free of testing callbacks: failures are
// returned in the public history instead of calling Fatal from a worker.
type concurrencyConn struct {
	sync.Mutex
	values   map[any]any
	id       uint64
	from     BackendInst
	to       BackendInst
	receiver ConnEventReceiver
	closing  bool
	effects  atomic.Uint64
}

func newConcurrencyConn(id uint64) *concurrencyConn {
	return &concurrencyConn{id: id, values: make(map[any]any)}
}

func (c *concurrencyConn) SetEventReceiver(receiver ConnEventReceiver) {
	c.Lock()
	c.receiver = receiver
	c.Unlock()
}
func (c *concurrencyConn) SetValue(key, value any) {
	c.Lock()
	c.values[key] = value
	c.Unlock()
}
func (c *concurrencyConn) Value(key any) any {
	c.Lock()
	defer c.Unlock()
	return c.values[key]
}
func (c *concurrencyConn) Redirect(to BackendInst) bool {
	c.effects.Add(1)
	c.Lock()
	defer c.Unlock()
	if c.closing || c.to != nil {
		return false
	}
	c.to = to
	return true
}
func (c *concurrencyConn) ForceClose() bool {
	c.effects.Add(1)
	c.Lock()
	defer c.Unlock()
	if c.closing {
		return false
	}
	c.closing = true
	return true
}
func (c *concurrencyConn) ConnectionID() uint64  { return c.id }
func (c *concurrencyConn) ConnInfo() []zap.Field { return nil }
func (c *concurrencyConn) binding() (BackendInst, BackendInst, ConnEventReceiver) {
	c.Lock()
	defer c.Unlock()
	return c.from, c.to, c.receiver
}
func (c *concurrencyConn) bindFrom(from BackendInst) {
	c.Lock()
	c.from = from
	c.Unlock()
}

func establishConcurrencyConn(t *testing.T, rr *releaseRouter, id uint64) (*concurrencyConn, BackendInst) {
	t.Helper()
	selector := rr.router.GetBackendSelector(ClientInfo{})
	backend, err := selector.Next()
	require.NoError(t, err)
	conn := newConcurrencyConn(id)
	selector.Finish(conn, true)
	selector.CloseObservation()
	conn.bindFrom(backend)
	return conn, backend
}

func checkConcurrencyRow(row concurrencyRow) []string {
	violations := []string{}
	if len(row.History) != 8 {
		violations = append(violations, fmt.Sprintf("public history has %d events", len(row.History)))
	}
	steps := map[string]map[int]bool{"A": {}, "B": {}}
	for _, event := range row.History {
		if event.Actor != "A" && event.Actor != "B" {
			violations = append(violations, "history contains an unknown actor")
			continue
		}
		if steps[event.Actor][event.Step] {
			violations = append(violations, fmt.Sprintf("duplicate %s/%d", event.Actor, event.Step))
		}
		steps[event.Actor][event.Step] = true
		if strings.HasPrefix(event.Outcome, "error:") {
			violations = append(violations, fmt.Sprintf("%s/%d %s", event.Actor, event.Step, event.Outcome))
		}
	}
	if len(steps["A"]) != 4 || len(steps["B"]) != 4 {
		violations = append(violations, "each actor must complete four public calls")
	}
	if row.FinalConnCount != 0 {
		violations = append(violations, fmt.Sprintf("final live connections %d", row.FinalConnCount))
	}
	if len(row.RetainedBackends) != 0 {
		violations = append(violations, fmt.Sprintf("retained backends %v", row.RetainedBackends))
	}
	return violations
}

func runGoConcurrencyCase(t *testing.T, name, release string, id uint64) concurrencyRow {
	t.Helper()
	addrs := []string{"127.0.0.1:4000", "127.0.0.1:4001"}
	rr := newReleaseRouter(t, name == "shutdown_outstanding_requests")
	rr.health(addrs...)
	row := concurrencyRow{Case: name}
	var actorA, actorB []concurrencyCall
	switch name {
	case "update_racing_next_finish":
		selector := rr.router.GetBackendSelector(ClientInfo{})
		conn := newConcurrencyConn(id)
		var selected BackendInst
		actorA = []concurrencyCall{
			func() (string, string) {
				var err error
				selected, err = selector.Next()
				if err != nil {
					return "Next", "error:" + err.Error()
				}
				return "Next", "selected:" + selected.ID()
			},
			func() (string, string) {
				selector.Finish(conn, true)
				conn.bindFrom(selected)
				return "Finish", "connected"
			},
			func() (string, string) { selector.CloseObservation(); return "CloseObservation", "closed" },
			func() (string, string) {
				_, _, receiver := conn.binding()
				if receiver == nil {
					return "OnConnClosed", "error:missing receiver"
				}
				if err := receiver.OnConnClosed(selected.ID(), conn); err != nil {
					return "OnConnClosed", "error:" + err.Error()
				}
				return "OnConnClosed", "applied"
			},
		}
		actorB = []concurrencyCall{
			func() (string, string) { rr.health(addrs[0]); return "HealthUpdate", "one backend" },
			func() (string, string) { rr.health(addrs...); return "HealthUpdate", "two backends" },
			func() (string, string) { rr.health(addrs[1]); return "HealthUpdate", "other backend" },
			func() (string, string) { rr.health(addrs...); return "HealthUpdate", "restored" },
		}
	case "close_racing_redirect_completion", "duplicate_late_completion", "shutdown_outstanding_requests":
		conn, backend := establishConcurrencyConn(t, rr, id)
		require.NoError(t, rr.router.RedirectConnections())
		from, to, receiver := conn.binding()
		require.NotNil(t, receiver)
		require.NotNil(t, to)
		if name == "close_racing_redirect_completion" {
			actorA = []concurrencyCall{
				func() (string, string) { return "OnConnClosed", errorOutcome(receiver.OnConnClosed(from.ID(), conn)) },
				func() (string, string) {
					return "OnConnClosedDuplicate", errorOutcome(receiver.OnConnClosed(from.ID(), conn))
				},
				func() (string, string) { return "ConnCount", fmt.Sprintf("%d", rr.router.ConnCount()) },
				func() (string, string) {
					_, ok := rr.router.LookupBackend(backend.ID())
					return "LookupBackend", fmt.Sprintf("present:%t", ok)
				},
			}
			actorB = []concurrencyCall{
				func() (string, string) {
					return "OnRedirectSucceed", errorOutcome(receiver.OnRedirectSucceed(from.ID(), to.ID(), conn))
				},
				func() (string, string) {
					return "OnRedirectSucceedDuplicate", errorOutcome(receiver.OnRedirectSucceed(from.ID(), to.ID(), conn))
				},
				func() (string, string) {
					return "OnRedirectFailLate", errorOutcome(receiver.OnRedirectFail(from.ID(), to.ID(), conn))
				},
				func() (string, string) { return "ConnCount", fmt.Sprintf("%d", rr.router.ConnCount()) },
			}
		} else if name == "duplicate_late_completion" {
			actorA = []concurrencyCall{
				func() (string, string) {
					return "OnRedirectSucceed", errorOutcome(receiver.OnRedirectSucceed(from.ID(), to.ID(), conn))
				},
				func() (string, string) {
					return "OnRedirectSucceedDuplicate", errorOutcome(receiver.OnRedirectSucceed(from.ID(), to.ID(), conn))
				},
				func() (string, string) { return "OnConnClosed", errorOutcome(receiver.OnConnClosed(to.ID(), conn)) },
				func() (string, string) {
					return "OnRedirectSucceedLate", errorOutcome(receiver.OnRedirectSucceed(from.ID(), to.ID(), conn))
				},
			}
			actorB = []concurrencyCall{
				func() (string, string) {
					return "OnRedirectFailDuplicate", errorOutcome(receiver.OnRedirectFail(from.ID(), to.ID(), conn))
				},
				func() (string, string) {
					return "OnConnClosedDuplicate", errorOutcome(receiver.OnConnClosed(from.ID(), conn))
				},
				func() (string, string) {
					return "OnRedirectFailLate", errorOutcome(receiver.OnRedirectFail(from.ID(), to.ID(), conn))
				},
				func() (string, string) { return "ConnCount", fmt.Sprintf("%d", rr.router.ConnCount()) },
			}
		} else {
			pending := rr.router.GetBackendSelector(ClientInfo{})
			_, err := pending.Next()
			require.NoError(t, err)
			actorA = []concurrencyCall{
				func() (string, string) { rr.router.Close(); return "Shutdown", "joined" },
				func() (string, string) {
					pending.Finish(newConcurrencyConn(id+1), false)
					return "FinishOutstanding", "rolled_back"
				},
				func() (string, string) { pending.CloseObservation(); return "CloseObservation", "closed" },
				func() (string, string) { return "ConnCount", fmt.Sprintf("%d", rr.router.ConnCount()) },
			}
			actorB = []concurrencyCall{
				func() (string, string) {
					return "OnRedirectSucceed", errorOutcome(receiver.OnRedirectSucceed(from.ID(), to.ID(), conn))
				},
				func() (string, string) { return "OnConnClosed", errorOutcome(receiver.OnConnClosed(to.ID(), conn)) },
				func() (string, string) {
					return "OnRedirectFailLate", errorOutcome(receiver.OnRedirectFail(from.ID(), to.ID(), conn))
				},
				func() (string, string) {
					_, ok := rr.router.LookupBackend(backend.ID())
					return "LookupBackend", fmt.Sprintf("present:%t", ok)
				},
			}
		}
	default:
		t.Fatalf("unknown concurrency case %q", name)
	}
	row.History = runBarrierSchedule(t, release, actorA, actorB)
	rr.router.Close()
	row.FinalConnCount = rr.router.ConnCount()
	row.RetainedBackends = rr.retained(addrs)
	sort.Strings(row.RetainedBackends)
	row.Violations = checkConcurrencyRow(row)
	return row
}

func errorOutcome(err error) string {
	if err != nil {
		return "error:" + err.Error()
	}
	return "returned"
}

func TestAPIConcurrencyFocused(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "tests", "controlplane", "cproute", "api-differential", "focused", "concurrency.json"))
	require.NoError(t, err)
	var spec concurrencySpec
	require.NoError(t, json.Unmarshal(data, &spec))
	require.Equal(t, "concurrency", spec.Suite)
	require.Len(t, spec.Cases, 4)
	require.Len(t, spec.Schedules, 16)
	seen := make(map[string]bool, 16)
	rows := make([]concurrencyRow, 0, 64)
	var id uint64
	for _, schedule := range spec.Schedules {
		require.False(t, seen[schedule.ID], "duplicate schedule")
		seen[schedule.ID] = true
		require.Len(t, schedule.Release, 8)
		require.Equal(t, 4, strings.Count(schedule.Release, "A"))
		require.Equal(t, 4, strings.Count(schedule.Release, "B"))
	}
	for _, name := range spec.Cases {
		for _, schedule := range spec.Schedules {
			id += 2
			row := runGoConcurrencyCase(t, name, schedule.Release, id)
			row.Schedule = schedule.ID
			require.Empty(t, row.Violations, "%s/%s", name, schedule.ID)
			rows = append(rows, row)
		}
	}
	// The exact checker must reject both a truncated public history and leaked
	// accounting; this is not a separate mutation framework.
	negative := concurrencyRow{History: []concurrencyEvent{{Actor: "A", Step: 0}}, FinalConnCount: 1, RetainedBackends: []string{"leaked"}}
	detected := checkConcurrencyRow(negative)
	require.GreaterOrEqual(t, len(detected), 3)
	if path := os.Getenv("CPROUTE_CONCURRENCY_OUTPUT"); path != "" {
		encoded, err := json.MarshalIndent(map[string]any{"engine": "go", "suite": spec.Suite, "rows": rows, "negative_control_detected": detected}, "", "  ")
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(path, encoded, 0o600))
	}
}
