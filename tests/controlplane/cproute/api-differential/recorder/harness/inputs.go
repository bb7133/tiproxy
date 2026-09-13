// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build apireplay

package harness

import (
	"context"
	"fmt"
	"sync"

	"github.com/pingcap/tiproxy/lib/config"
	"github.com/pingcap/tiproxy/pkg/balance/observer"
	"github.com/pingcap/tiproxy/pkg/balance/router"
	"github.com/pingcap/tiproxy/tests/controlplane/cproute/api-differential/recorder/apireplay"
)

// Inputs forwards the real observer's results, config updates and timer ticks
// to the production handlers through the ReplayDriver, recording each input
// after the handler returns (consumption time), all under the Scheduler.
type Inputs struct {
	sched  *Scheduler
	driver *router.ReplayDriver
	mu     sync.Mutex
	raw    []observer.HealthResult
}

func NewInputs(sched *Scheduler, driver *router.ReplayDriver) *Inputs {
	return &Inputs{sched: sched, driver: driver}
}

// Forward subscribes to the real observer and delivers every result in
// arrival order at the current logical time. It returns when ctx ends.
func (in *Inputs) Forward(ctx context.Context, bo observer.BackendObserver, name string) {
	// The observer closes every subscription in Close; the forwarder only stops.
	ch := bo.Subscribe(name)
	for {
		select {
		case <-ctx.Done():
			return
		case result, ok := <-ch:
			if !ok {
				return
			}
			in.Deliver(result)
		}
	}
}

// Deliver applies one observer result through the production handler and
// records it as `health` (explicit inventory) or `source_error` (identity).
func (in *Inputs) Deliver(result observer.HealthResult) {
	in.sched.RunNow(func() {
		in.mu.Lock()
		in.raw = append(in.raw, result)
		in.mu.Unlock()
		in.driver.DeliverHealth(result)
		if err := result.Error(); err != nil {
			in.sched.Record(apireplay.Event{Op: "source_error", Outcome: apireplay.ErrorIdentity(err)})
			return
		}
		ev := apireplay.Event{Op: "health"}
		for id, bh := range result.Backends() {
			ev.Backends = append(ev.Backends, apireplay.HealthBackend{
				Address: bh.Addr, Labels: bh.Labels, Cluster: bh.ClusterName, Keyspace: bh.Keyspace,
				IP: bh.IP, StatusPort: bh.StatusPort, Healthy: bh.Healthy, Local: bh.Local,
				ServerVersion: bh.ServerVersion, SupportRedirection: bh.SupportRedirection, ID: id,
			})
		}
		in.sched.Record(ev)
	})
}

// DeliverConfig applies a validated config through the production handler and
// records the `config` input with the validator's public outcome.
func (in *Inputs) DeliverConfig(toml string, cfg *config.Config, validationErr error) {
	in.sched.RunNow(func() {
		ev := apireplay.Event{Op: "config", TOML: toml, Outcome: "ok"}
		if validationErr != nil {
			ev.Outcome = "invalid_config"
		} else {
			in.driver.DeliverConfig(cfg)
		}
		in.sched.Record(ev)
	})
}

// Tick runs one real rebalance iteration at the declared logical instant and
// records the `tick` (effects produced during it are recorded by the conn
// wrapper inside the same critical section and folded in by the writer).
func (in *Inputs) Tick(at int64) {
	in.sched.Run(at, func() {
		in.sched.Record(apireplay.Event{Op: "tick_begin"})
		in.driver.Tick()
		in.sched.Record(apireplay.Event{Op: "tick_end"})
	})
}

// Raw returns the archived raw observer results.
func (in *Inputs) Raw() []observer.HealthResult {
	in.mu.Lock()
	defer in.mu.Unlock()
	out := make([]observer.HealthResult, len(in.raw))
	copy(out, in.raw)
	return out
}

// FaultError maps a declared source-error identity to the injected error; ""
// clears the window. Only the three fetcher-boundary identities are injectable
// (README §4); no-backend and port-conflict come from the router itself.
// The second result reports an invalid script name, before any fault is set.
func FaultError(identity string) (error, error) {
	switch identity {
	case "":
		return nil, nil
	case "cancelled":
		return context.Canceled, nil
	case "deadline_exceeded":
		return context.DeadlineExceeded, nil
	case "topology_unavailable":
		return apireplay.ErrTopologyUnavailable, nil
	default:
		return nil, fmt.Errorf("unsupported source_error identity %q", identity)
	}
}

// FaultFetcher wraps the real BackendFetcher and, for a scripted window,
// returns the declared error so the real observer publishes an observer
// error (recorder README §4). Outside the window it is transparent.
type FaultFetcher struct {
	observer.BackendFetcher
	mu  sync.Mutex
	err error
}

func (f *FaultFetcher) Set(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.err = err
}

func (f *FaultFetcher) GetBackendList(ctx context.Context) (map[string]*observer.BackendInfo, error) {
	f.mu.Lock()
	err := f.err
	f.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return f.BackendFetcher.GetBackendList(ctx)
}
