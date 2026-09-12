// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build apireplay

package harness

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pingcap/tiproxy/lib/config"
	"github.com/pingcap/tiproxy/pkg/balance/factor"
	"github.com/pingcap/tiproxy/pkg/balance/metricsreader"
	"github.com/pingcap/tiproxy/pkg/balance/observer"
	"github.com/pingcap/tiproxy/pkg/balance/policy"
	"github.com/pingcap/tiproxy/pkg/balance/router"
	configmgr "github.com/pingcap/tiproxy/pkg/manager/config"
	"github.com/pingcap/tiproxy/pkg/util/waitgroup"
	"github.com/pingcap/tiproxy/tests/controlplane/cproute/api-differential/recorder/apireplay"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestUnknownSourceErrorIsNotDeclaredFault(t *testing.T) {
	require.Equal(t, "unclassified_source_error", apireplay.ErrorIdentity(errors.New("unexpected source failure")))
}

type emptyMetrics struct{}

func (emptyMetrics) AddQueryExpr(string, metricsreader.QueryExpr, metricsreader.QueryRule) {}
func (emptyMetrics) RemoveQueryExpr(string)                                                {}
func (emptyMetrics) GetQueryResult(string) metricsreader.QueryResult {
	return metricsreader.QueryResult{}
}
func (emptyMetrics) GetBackendMetrics() []byte { return nil }

type healthyCheck struct{}

func (healthyCheck) Check(_ context.Context, info *observer.BackendInfo, _ *observer.BackendHealth) *observer.BackendHealth {
	return &observer.BackendHealth{BackendInfo: *info, Healthy: true, ServerVersion: "8.5.1", SupportRedirection: true}
}

type manualRefreshObserver struct{ observer.BackendObserver }

func (manualRefreshObserver) Refresh() {}

type subscribedObserver struct {
	observer.BackendObserver
	ready chan struct{}
}

func (b subscribedObserver) Subscribe(name string) <-chan observer.HealthResult {
	ch := b.BackendObserver.Subscribe(name)
	close(b.ready)
	return ch
}

// This is a synthetic source-driver integration test, not an N/K corpus slot.
// Keep the actual observer, input forwarder, router, recording wrappers and
// writer in the path. Only the external inventory and health check are fakes.
func TestRecordedObserverSourceErrors(t *testing.T) {
	dir := os.Getenv("CPROUTE_RECORDED_SOURCE_ERRORS")
	if dir == "" {
		dir = t.TempDir()
	} else {
		require.NoError(t, os.Mkdir(dir, 0o755))
	}
	sched, err := NewScheduler(filepath.Join(dir, "archive.jsonl"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, sched.Close()) })
	cfg := configmgr.NewConfigManager()
	require.NoError(t, cfg.SetTOMLConfig([]byte("[balance]\npolicy='connection'\nrouting-policy='prefer-idle'\n")))
	lg := zap.NewNop()
	fetcher := &FaultFetcher{BackendFetcher: observer.NewStaticFetcher([]string{"127.0.0.1:4000"})}
	hc := config.NewDefaultHealthCheckConfig()
	hc.Interval = time.Hour // subsequent publications are driven by Refresh
	bo := observer.NewDefaultBackendObserver(lg, hc, fetcher, healthyCheck{}, cfg)
	rt := router.NewScoreBasedRouter(lg)
	// The forwarder owns the observer subscription. Do not let selector retries
	// add undeclared source refreshes to this finite integration scenario.
	driver := router.NewReplayDriver(rt, manualRefreshObserver{bo}, func(lg *zap.Logger) policy.BalancePolicy {
		return factor.NewFactorBasedBalance(lg, emptyMetrics{})
	}, cfg)
	t.Cleanup(rt.Close)
	inputs := NewInputs(sched, driver)
	apireplay.Install(sched, "source")
	t.Cleanup(func() { apireplay.Install(nil, "s") })
	deliveries := make(chan apireplay.Event, 16)
	sched.Observe(func(e apireplay.Event) {
		if e.Op == "health" || e.Op == "source_error" {
			deliveries <- e
		}
	})
	route := func(want string) {
		sel, session := apireplay.Open(rt, router.ClientInfo{})
		backend, err := apireplay.Next(&sel, session)
		if want == "ok" {
			require.NoError(t, err)
			require.Equal(t, "127.0.0.1:4000", backend.ID())
			apireplay.Finish(&sel, session, nil, false)
		} else {
			require.Error(t, err)
			require.Equal(t, want, apireplay.ErrorIdentity(err))
		}
		apireplay.EndSelection(&sel, session)
	}
	route("no_backend")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	var wg waitgroup.WaitGroup
	t.Cleanup(func() { cancel(); wg.Wait(); bo.Close() })
	wrapped := subscribedObserver{BackendObserver: bo, ready: make(chan struct{})}
	wg.Run(func() { inputs.Forward(ctx, wrapped, "source-test") }, lg)
	select {
	case <-wrapped.ready:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	bo.Start(ctx)
	await := func(op, identity string) {
		select {
		case e := <-deliveries:
			require.Equal(t, op, e.Op)
			require.Equal(t, identity, e.Outcome)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	await("health", "")
	route("ok")
	for _, identity := range []string{"cancelled", "deadline_exceeded", "topology_unavailable"} {
		fault, err := FaultError(identity)
		require.NoError(t, err)
		fetcher.Set(fault)
		bo.Refresh()
		await("source_error", identity)
		route(identity)
		fetcher.Set(nil)
		bo.Refresh()
		await("health", "")
		route("ok")
	}
	cancel()
	wg.Wait()
	checkpoints := map[int]Checkpoint{}
	sched.RunNow(func() {
		seq := sched.Seq()
		checkpoints[seq] = Checkpoint{Seq: seq, Assignments: map[string]string{}, ConnCount: rt.ConnCount(), HealthyBackendCount: rt.HealthyBackendCount(), ServerVersion: rt.ServerVersion()}
		sched.Record(apireplay.Event{Op: "checkpoint"})
	})
	require.NoError(t, sched.Close())
	origin := sched.OriginNanos()
	status, err := Write(dir, "observer-source-smoke", "a1", TraceConfig{Policy: "connection", Selection: "prefer-idle", ClockOriginNanos: &origin}, sched.Log(), checkpoints, nil, false, CaptureSummary{Synthetic: true})
	require.NoError(t, err)
	require.Equal(t, "recorded", status)
	var trace struct{ Events []struct{ Op, Error string } }
	data, err := os.ReadFile(filepath.Join(dir, "trace.json"))
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(data, &trace))
	var names []string
	for _, e := range trace.Events {
		if e.Op == "source_error" {
			names = append(names, e.Error)
		}
	}
	require.Equal(t, []string{"cancelled", "deadline_exceeded", "topology_unavailable"}, names)
}

func TestUnclassifiedSourceErrorPreservesIncompleteArchive(t *testing.T) {
	dir := t.TempDir()
	sched, err := NewScheduler(filepath.Join(dir, "archive.jsonl"))
	require.NoError(t, err)
	sched.RunNow(func() {
		sched.Record(apireplay.Event{Op: "source_error", Outcome: apireplay.ErrorIdentity(errors.New("unexpected source failure"))})
	})
	require.NoError(t, sched.Close())
	status, err := Write(dir, "unknown-source", "a1", TraceConfig{}, sched.Log(), nil, nil, false, CaptureSummary{Synthetic: true})
	require.NoError(t, err)
	require.Equal(t, "incomplete", status)
	for _, name := range []string{"archive.jsonl", "trace.json"} {
		data, err := os.ReadFile(filepath.Join(dir, name))
		require.NoError(t, err)
		require.Contains(t, string(data), "unclassified_source_error")
		require.NotContains(t, string(data), "topology_unavailable")
		require.NotContains(t, string(data), "unexpected source failure")
	}
}
