// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package router

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pingcap/tiproxy/lib/config"
	"github.com/pingcap/tiproxy/pkg/balance/observation"
	"github.com/pingcap/tiproxy/pkg/balance/observer"
	shadowwire "github.com/pingcap/tiproxy/pkg/controlbridge/shadow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func loadHealth(owner int, extra bool) observer.HealthResult {
	health := make(map[string]*observer.BackendHealth)
	for group := range 2 {
		count := 2
		if extra {
			count++
		}
		for backend := range count {
			id := fmt.Sprintf("owner%d/group%d/backend%d", owner, group, backend)
			health[id] = &observer.BackendHealth{BackendInfo: observer.BackendInfo{Addr: fmt.Sprintf("127.0.0.1:%d", 4000+owner*100+group*10+backend), Labels: map[string]string{config.CidrLabelName: fmt.Sprintf("10.%d.0.0/24", group+1)}}, Healthy: true, SupportRedirection: true}
		}
	}
	return observer.NewHealthResult(health, nil)
}
func percentiles(values []time.Duration) string {
	slices.Sort(values)
	if len(values) == 0 {
		return "none"
	}
	return fmt.Sprintf("p50=%s p95=%s p99=%s", values[len(values)*50/100], values[len(values)*95/100], values[len(values)*99/100])
}

// The duration/rate/owner/group/client tuple is frozen in recorder-contract.md.
// This is real Go lifecycle capture over the production observation consumer,
// not full SQL/etcd/factor acceptance. Run via the dedicated recorder CI gate.
func TestObservationSustained(t *testing.T) {
	binary := os.Getenv("CP_ROUTE_LIVE_SOCKET_CHECK")
	if binary == "" {
		t.Skip("requires the built live_socket_check consumer harness")
	}
	for _, enabled := range []bool{false, true} {
		name := "disabled"
		if enabled {
			name = "enabled"
		}
		t.Run(name, func(t *testing.T) { runObservationLoad(t, binary, enabled) })
	}
}
func runObservationLoad(t *testing.T, binary string, enabled bool) {
	t.Helper()
	var service *shadowwire.Service
	var recorder *observation.Recorder
	var command *exec.Cmd
	var input interface {
		Write([]byte) (int, error)
		Close() error
	}
	var output bytes.Buffer
	if enabled {
		dir, err := os.MkdirTemp("/tmp", "routing-load-")
		require.NoError(t, err)
		defer os.RemoveAll(dir)
		path := filepath.Join(dir, "observe.sock")
		service, err = shadowwire.Start(context.Background(), path, zap.NewNop())
		require.NoError(t, err)
		defer service.Close()
		recorder = service.Recorder()
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		command = exec.CommandContext(ctx, binary, path)
		command.Stdout = &output
		command.Stderr = &output
		pipe, err := command.StdinPipe()
		require.NoError(t, err)
		input = pipe
		require.NoError(t, command.Start())
		defer func() {
			if command.ProcessState == nil {
				_ = command.Process.Kill()
				_ = command.Wait()
			}
		}()
	}
	var routers [2]*ScoreBasedRouter
	var stable [2][2][2]*backendWrapper
	for owner := range 2 {
		var observed *observation.Owner
		if enabled {
			observed = recorder.NewOwner()
		}
		r := NewScoreBasedRouterWithObservation(zap.NewNop(), observed)
		r.bpCreator = simpleBpCreator
		r.matchType = MatchClientCIDR
		r.updateBackendHealth(loadHealth(owner, false))
		require.Len(t, r.groups, 2)
		routers[owner] = r
		defer r.Close()
		for group := range 2 {
			for backend := range 2 {
				stable[owner][group][backend] = r.backends[fmt.Sprintf("owner%d/group%d/backend%d", owner, group, backend)]
			}
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var publishers sync.WaitGroup
	var publications atomic.Uint64
	publishers.Add(1)
	go func() {
		defer publishers.Done()
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		extra := false
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				extra = !extra
				for owner, r := range routers {
					r.updateBackendHealth(loadHealth(owner, extra))
					publications.Add(1)
				}
			}
		}
	}()
	var sampler sync.WaitGroup
	var highRecords, highBytes int64
	if enabled {
		sampler.Add(1)
		go func() {
			defer sampler.Done()
			ticker := time.NewTicker(time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					r, b := recorder.Retained()
					highRecords = max(highRecords, r)
					highBytes = max(highBytes, b)
				}
			}
		}()
	}
	var workers sync.WaitGroup
	var operations atomic.Uint64
	var elapsed [8][]time.Duration
	var lockHold [8][]time.Duration
	started := time.Now()
	for client := range 8 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			owner, group := client/4, client%2
			r := routers[owner]
			ticker := time.NewTicker(200 * time.Millisecond)
			defer ticker.Stop()
			for range 300 {
				<-ticker.C
				start := time.Now()
				selector := r.GetBackendSelector(ClientInfo{ClientAddr: &net.TCPAddr{IP: net.ParseIP(fmt.Sprintf("10.%d.0.7", group+1)), Port: 10000}})
				backend, err := selector.Next()
				if !assert.NoError(t, err) {
					return
				}
				conn := newMockRedirectableConn(t, 7)
				conn.from = backend
				selector.Finish(conn, true)
				selector.CloseObservation()
				source := backend.(*backendWrapper)
				target := stable[owner][group][0]
				if source == target {
					target = stable[owner][group][1]
				}
				g := source.group
				g.Lock()
				held := time.Now()
				accepted := g.redirectConn(getConnWrapper(conn).Value, source, target, "recorder-load", nil, time.Now())
				duration := time.Since(held)
				g.Unlock()
				if !assert.True(t, accepted) {
					return
				}
				conn.redirectSucceed()
				if !assert.NoError(t, g.OnRedirectSucceed(source.ID(), target.ID(), conn)) {
					return
				}
				if !assert.NoError(t, g.OnConnClosed(target.ID(), conn)) {
					return
				}
				operations.Add(5)
				elapsed[client] = append(elapsed[client], time.Since(start))
				lockHold[client] = append(lockHold[client], duration)
			}
		}()
	}
	workers.Wait()
	duration := time.Since(started)
	cancel()
	publishers.Wait()
	sampler.Wait()
	require.GreaterOrEqual(t, duration, 60*time.Second)
	require.EqualValues(t, 12000, operations.Load(), "200 accepted lifecycle operations/s for 60s")
	require.GreaterOrEqual(t, publications.Load(), uint64(1000), "concurrent backend publication must run throughout")
	for owner, r := range routers {
		r.updateBackendHealth(loadHealth(owner, false))
		require.Zero(t, r.ConnCount())
	}
	var cycleSamples, holdSamples []time.Duration
	for i := range 8 {
		cycleSamples = append(cycleSamples, elapsed[i]...)
		holdSamples = append(holdSamples, lockHold[i]...)
	}
	var memory runtime.MemStats
	runtime.ReadMemStats(&memory)
	t.Logf("enabled=%t duration=%s owners=2 groups_per_owner=2 clients=8 accepted_ops=%d publications=%d cycle_%s group_lock_hold_%s heap_inuse=%d sampled_queue_high_records=%d sampled_queue_high_bytes=%d", enabled, duration, operations.Load(), publications.Load(), percentiles(cycleSamples), percentiles(holdSamples), memory.HeapInuse, highRecords, highBytes)
	if enabled {
		require.Empty(t, recorder.InvalidOwners(), "positive gate cannot discard any owner")
		require.LessOrEqual(t, highRecords, int64(observation.MaxRecords))
		require.LessOrEqual(t, highBytes, int64(observation.MaxQueuedBytes))
		_, err := fmt.Fprint(input, observationFence(operations.Load(), routers[0].observation, routers[1].observation))
		require.NoError(t, err)
		require.NoError(t, input.Close())
		err = command.Wait()
		t.Log(output.String())
		require.NoError(t, err, "independent Rust comparison")
		require.Contains(t, output.String(), "owners=2 operations=12000")
		require.Contains(t, output.String(), "score=0 physical=0 invalid=0 mismatch=0 connections=1 transport_errors=0")
	}
}

// A finite actual-call seam isolates report/drain problems from the frozen
// sustained gate. It does not substitute for that gate's duration or rate.
func TestObservationSocketSettlementReport(t *testing.T) {
	binary := os.Getenv("CP_ROUTE_LIVE_SOCKET_CHECK")
	if binary == "" {
		t.Skip("requires consumer harness")
	}
	dir, err := os.MkdirTemp("/tmp", "routing-report-")
	require.NoError(t, err)
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "observe.sock")
	service, err := shadowwire.Start(context.Background(), path, zap.NewNop())
	require.NoError(t, err)
	defer service.Close()
	var owners []*observation.Owner
	for range 2 {
		r := observedRouter(t, service.Recorder())
		owners = append(owners, r.observation)
		conn, b := observedConn(t, r, false)
		g := b.group
		var target *backendWrapper
		for _, candidate := range r.backends {
			if candidate != b {
				target = candidate
			}
		}
		g.Lock()
		accepted := g.redirectConn(getConnWrapper(conn).Value, b, target, "report", nil, time.Now())
		g.Unlock()
		require.True(t, accepted)
		conn.redirectSucceed()
		require.NoError(t, g.OnRedirectSucceed(b.ID(), target.ID(), conn))
		require.NoError(t, g.OnConnClosed(target.ID(), conn))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, binary, path)
	command.Stdin = bytes.NewBufferString(observationFence(10, owners...))
	output, err := command.CombinedOutput()
	t.Log(string(output))
	require.NoError(t, err)
	require.Contains(t, string(output), "owners=2 operations=10")
}

// This measures the capture helper in isolation on actual Go wrapper state.
// Its repeated diagnostic input is not lifecycle evidence and is never sent to
// Rust. The separate sustained test supplies real lifecycle qualification.
func TestObservationCaptureLatency(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		var recorder *observation.Recorder
		if enabled {
			var err error
			recorder, err = observation.NewRecorder(observation.DefaultLimits(), 71, 73)
			require.NoError(t, err)
			defer recorder.Close()
		}
		r := observedRouter(t, recorder)
		conn, source := observedConn(t, r, false)
		cw := getConnWrapper(conn).Value
		if enabled {
			drainObservation(t, recorder)
		}
		elapsed := make([]time.Duration, 10000)
		holds := make([]time.Duration, len(elapsed))
		for i := range elapsed {
			g := source.group
			g.Lock()
			held := time.Now()
			before := g.beforeObservation(cw)
			batch := observation.Batch{EventCount: 1, Events: [observation.MaxEvents]observation.Event{{Kind: observation.Rejected, Session: cw.observationID, Account: source.observationID, Target: source.observationID}}}
			start := time.Now()
			g.capture(batch, cw, before, source)
			elapsed[i] = time.Since(start)
			holds[i] = time.Since(held)
			g.Unlock()
			if enabled {
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				delivery, err := recorder.Next(ctx)
				cancel()
				require.NoError(t, err)
				delivery.Release()
			}
		}
		if enabled {
			require.Empty(t, recorder.InvalidOwners())
		}
		require.Equal(t, 1, source.connScore)
		require.NoError(t, source.group.OnConnClosed(source.ID(), conn))
		t.Logf("capture_component_only enabled=%t samples=%d helper(%s) group_lock_hold(%s)", enabled, len(elapsed), percentiles(elapsed), percentiles(holds))
	}
}

// This test-control input is separate from the one-way observation socket.
// Reaching business totals alone does not prove the final metadata tail was read.
func observationFence(operations uint64, owners ...*observation.Owner) string {
	fields := []string{fmt.Sprint(operations)}
	for _, owner := range owners {
		epoch := owner.Epoch()
		fields = append(fields, fmt.Sprintf("%d:%d:%d:%d", epoch.Process, epoch.Owner, epoch.Nonce, owner.AdmittedSequence()))
	}
	return strings.Join(fields, " ") + "\n"
}
