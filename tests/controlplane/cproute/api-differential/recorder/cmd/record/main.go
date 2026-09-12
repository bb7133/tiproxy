// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build apireplay

// record runs the real TiProxy Go proxy against the live slice-3 environment
// with the API-boundary recorder installed (recorder README §4/§5) and writes
// one trace v1 recording (trace.json + go.json + archive.jsonl + manifest.json).
//
// Build with the overlay produced by record.py (call-site substitution in
// backend_conn_mgr.go and the router clock), e.g.
//
//	go build -tags apireplay -overlay /tmp/rec/overlay.json -o /tmp/rec/record ./tests/controlplane/cproute/api-differential/recorder/cmd/record
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/pingcap/tiproxy/lib/config"
	"github.com/pingcap/tiproxy/pkg/balance/factor"
	"github.com/pingcap/tiproxy/pkg/balance/observer"
	"github.com/pingcap/tiproxy/pkg/balance/policy"
	"github.com/pingcap/tiproxy/pkg/balance/router"
	"github.com/pingcap/tiproxy/pkg/manager/backendcluster"
	"github.com/pingcap/tiproxy/pkg/manager/cert"
	mgrcfg "github.com/pingcap/tiproxy/pkg/manager/config"
	"github.com/pingcap/tiproxy/pkg/manager/id"
	"github.com/pingcap/tiproxy/pkg/manager/memory"
	"github.com/pingcap/tiproxy/pkg/proxy"
	"github.com/pingcap/tiproxy/pkg/proxy/backend"
	"github.com/pingcap/tiproxy/tests/controlplane/cproute/api-differential/recorder/apireplay"
	"github.com/pingcap/tiproxy/tests/controlplane/cproute/api-differential/recorder/harness"
	"go.uber.org/zap"
)

// Action is one scripted, declared operation at a wall offset from trace start.
type Action struct {
	AtMillis int64    `json:"at_ms"`
	Kind     string   `json:"kind"` // env | config | source_error | checkpoint | refuse
	Args     []string `json:"args,omitempty"`
	TOML     string   `json:"toml,omitempty"`
	Error    string   `json:"error,omitempty"` // source_error identity; "" clears the fault window
}

func main() {
	var (
		slot      = flag.String("slot", "smoke", "trace slot id (recording-plan.tsv)")
		attempt   = flag.String("attempt", "a1", "attempt id; a new capture never overwrites a previous one")
		policyF   = flag.String("policy", "connection", "[balance] policy")
		selection = flag.String("selection", "prefer-idle", "[balance] routing-policy")
		rule      = flag.String("rule", "", "[balance] routing-rule (fixed at Init)")
		listen    = flag.String("listen", "127.0.0.1:6000", "proxy listener(s), comma separated")
		pd        = flag.String("pd", "127.0.0.1:2379", "PD address")
		duration  = flag.Duration("duration", 60*time.Second, "recording duration")
		clients   = flag.Int("clients", 8, "concurrent mysql clients")
		pause     = flag.Duration("pause", 200*time.Millisecond, "pause between lifecycles per client")
		sources   = flag.String("sources", "", "comma separated loopback source IPs for clients")
		out       = flag.String("out", "", "output directory (required)")
		script    = flag.String("script", "", "JSON file with scripted actions")
		envSh     = flag.String("env", "", "path to slice3 env.sh for env actions")
		tick      = flag.Duration("tick", 10*time.Millisecond, "declared rebalance tick interval")
	)
	flag.Parse()
	if *out == "" {
		fmt.Fprintln(os.Stderr, "-out is required")
		os.Exit(2)
	}
	if err := run(*slot, *attempt, *policyF, *selection, *rule, *listen, *pd, *duration, *clients, *pause, *sources, *out, *script, *envSh, *tick); err != nil {
		fmt.Fprintln(os.Stderr, "record:", err)
		os.Exit(1)
	}
}

func run(slot, attempt, policyName, selection, rule, listen, pd string, duration time.Duration, clients int, pause time.Duration, sources, out, script, envSh string, tickEvery time.Duration) error {
	dir := filepath.Join(out, slot+"-"+attempt)
	if _, err := os.Stat(dir); err == nil {
		return fmt.Errorf("%s exists; a new attempt needs a new id (README §1)", dir)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	lg, _ := zap.NewDevelopment(zap.IncreaseLevel(zap.WarnLevel))
	listeners := strings.Split(listen, ",")
	toml := fmt.Sprintf("[proxy]\naddr = %q\npd-addrs = %q\n[balance]\npolicy = %q\nrouting-policy = %q\nrouting-rule = %q\n[log]\nlevel = \"warn\"\n",
		listeners[0], pd, policyName, selection, rule)
	cfgFile := filepath.Join(dir, "proxy.toml")
	if err := os.WriteFile(cfgFile, []byte(toml), 0o644); err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	cfgMgr := mgrcfg.NewConfigManager()
	if err := cfgMgr.Init(ctx, cfgFile, ""); err != nil {
		return err
	}
	cfg := cfgMgr.GetConfig()
	certMgr := cert.NewCertManager()
	if err := certMgr.Init(cfg, lg.Named("cert"), cfgMgr.WatchConfig()); err != nil {
		return err
	}
	clusterMgr := backendcluster.NewManager(lg.Named("backendcluster"), certMgr.ClusterTLS)
	if err := clusterMgr.Start(ctx, cfgMgr, cfgMgr.WatchConfig()); err != nil {
		return err
	}
	defer clusterMgr.Close()

	sched, err := harness.NewScheduler(filepath.Join(dir, "archive.jsonl"))
	if err != nil {
		return err
	}
	defer sched.Close()

	// Real observer over the real PD-backed fetcher, with the declared fault wrapper (README §4).
	hcCfg := config.NewDefaultHealthCheckConfig()
	fetcher := &harness.FaultFetcher{BackendFetcher: observer.NewFallbackFetcher(clusterMgr, observer.NewPDFetcher(clusterMgr, lg.Named("be_fetcher"), hcCfg), observer.NewStaticFetcher(nil))}
	hc := observer.NewDefaultHealthCheckWithNetwork(clusterMgr.NetworkRouter(), hcCfg, lg.Named("hc"))
	bo := observer.NewDefaultBackendObserver(lg.Named("observer"), hcCfg, fetcher, hc, cfgMgr)

	// Real router, background loop disabled, driven by the scheduler.
	rt := router.NewScoreBasedRouter(lg.Named("router"))
	bpCreator := func(lg *zap.Logger) policy.BalancePolicy {
		p := factor.NewFactorBasedBalance(lg, clusterMgr.MetricsQuerier())
		p.Init(cfgMgr.GetConfig())
		return p
	}
	driver := router.NewReplayDriver(rt, bo, bpCreator, cfgMgr)
	inputs := harness.NewInputs(sched, driver)
	apireplay.Install(sched, slot)
	ledger := newLedger()
	sched.Observe(ledger.observe)

	// Real proxy exactly as pkg/server/server.go composes it, with the recording namespace manager.
	nsMgr := harness.NewRecordingNamespaceManager(rt)
	hsHandler := backend.NewDefaultHandshakeHandler(nsMgr)
	memMgr := memory.NewMemManager(lg.Named("mem"), cfgMgr)
	memMgr.Start(ctx)
	sqlSrv, err := proxy.NewSQLServer(lg.Named("proxy"), cfg, certMgr, id.NewIDManager(), nil, nil, hsHandler, memMgr)
	if err != nil {
		return err
	}
	sqlSrv.SetBackendDialer(clusterMgr.NetworkRouter())
	sqlSrv.Run(ctx, cfgMgr.WatchConfig())
	defer func() {
		sqlSrv.PreClose() // closes the listeners so the accept loops exit (server.go preClose order)
		_ = sqlSrv.Close()
	}()

	// Inputs start flowing only now: the first HealthResult is consumed after the proxy is up.
	bo.Start(ctx)
	defer bo.Close()
	go inputs.Forward(ctx, bo, "recorder")

	var actions []Action
	if script != "" {
		b, err := os.ReadFile(script)
		if err != nil {
			return err
		}
		if err := json.Unmarshal(b, &actions); err != nil {
			return err
		}
		sort.SliceStable(actions, func(i, j int) bool { return actions[i].AtMillis < actions[j].AtMillis })
	}

	// Declared timer schedule: every tickEvery from trace start, plus boundary
	// instants registered when a failover timeout is consumed (Inputs reports them).
	runCtx, stop := context.WithTimeout(ctx, duration)
	defer stop()
	var incomplete []string
	checkpoints := map[int]harness.Checkpoint{}
	go func() {
		var k int64
		for runCtx.Err() == nil {
			k++
			declared := k * tickEvery.Nanoseconds()
			wait := time.Duration(declared) - sched.Elapsed()
			if wait > 0 {
				select {
				case <-time.After(wait):
				case <-runCtx.Done():
					return
				}
			}
			inputs.Tick(declared)
		}
	}()
	go func() {
		for _, a := range actions {
			wait := time.Duration(a.AtMillis)*time.Millisecond - sched.Elapsed()
			if wait > 0 {
				select {
				case <-time.After(wait):
				case <-runCtx.Done():
					return
				}
			}
			switch a.Kind {
			case "env":
				cmd := exec.CommandContext(ctx, envSh, a.Args...)
				cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
				if err := cmd.Run(); err != nil {
					incomplete = append(incomplete, fmt.Sprintf("env %v: %v", a.Args, err))
				}
			case "config":
				err := cfgMgr.SetTOMLConfig([]byte(a.TOML))
				inputs.DeliverConfig(a.TOML, cfgMgr.GetConfig(), err)
			case "source_error":
				fetcher.Set(harness.FaultError(a.Error))
			case "checkpoint":
				sched.RunNow(func() {
					seq := sched.Seq()
					checkpoints[seq] = harness.Checkpoint{Seq: seq, Assignments: ledger.assignments(), ConnCount: rt.ConnCount(),
						HealthyBackendCount: rt.HealthyBackendCount(), ServerVersion: rt.ServerVersion()}
					sched.Record(apireplay.Event{Op: "checkpoint"})
				})
			default:
				incomplete = append(incomplete, fmt.Sprintf("unknown action %q", a.Kind))
			}
		}
	}()

	wl := &harness.Workload{Listener: listeners[0], Clients: clients, Pause: pause, User: "root"}
	if sources != "" {
		wl.Sources = strings.Split(sources, ",")
	}
	wl.Run(runCtx)
	// Let the last lifecycles settle (close callbacks arrive asynchronously), then checkpoint.
	for i := 0; i < 100; i++ {
		var open bool
		sched.RunNow(func() { open = len(ledger.active)+len(ledger.pending) > 0 })
		if !open {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	sched.RunNow(func() {
		seq := sched.Seq()
		checkpoints[seq] = harness.Checkpoint{Seq: seq, Assignments: ledger.assignments(), ConnCount: rt.ConnCount(),
			HealthyBackendCount: rt.HealthyBackendCount(), ServerVersion: rt.ServerVersion()}
		sched.Record(apireplay.Event{Op: "checkpoint"})
	})
	stop()
	status, err := harness.Write(dir, slot, attempt, harness.TraceConfig{Policy: policyName, Selection: selection, Rule: rule}, sched.Log(), checkpoints, incomplete,
		clusterMgr.MetricsQuerier() != nil)
	if err != nil {
		return err
	}
	fmt.Printf("%s: status=%s completed=%d failed=%d events=%d dir=%s\n", slot, status, wl.Completed(), wl.Failed(), len(sched.Log()), dir)
	return nil
}

// ledger mirrors run.py's public assignment ledger from the recorded events so
// checkpoints carry `assignments` the way the adapter reports them.
type ledger struct {
	pending map[string]string
	active  map[string]string
}

func newLedger() *ledger { return &ledger{pending: map[string]string{}, active: map[string]string{}} }

func (l *ledger) observe(ev apireplay.Event) {
	switch ev.Op {
	case "next":
		if ev.Outcome == "ok" {
			l.pending[ev.Session] = ev.Backend
		}
	case "finish":
		b := l.pending[ev.Session]
		delete(l.pending, ev.Session)
		if ev.Success != nil && *ev.Success {
			l.active[ev.Session] = b
		}
	case "redirect_result":
		if ev.Success != nil && *ev.Success {
			l.active[ev.Session] = ev.Backend
		}
	case "close":
		delete(l.active, ev.Session)
		delete(l.pending, ev.Session)
	}
}

func (l *ledger) assignments() map[string]string {
	out := make(map[string]string, len(l.active))
	for k, v := range l.active {
		out[k] = v
	}
	return out
}
