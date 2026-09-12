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
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
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
	"github.com/pingcap/tiproxy/pkg/util/waitgroup"
	"github.com/pingcap/tiproxy/tests/controlplane/cproute/api-differential/recorder/apireplay"
	"github.com/pingcap/tiproxy/tests/controlplane/cproute/api-differential/recorder/harness"
	"go.uber.org/zap"
)

// Set by record.py from the exact source tree used for this build.
var sourceHead, sourceTree, sourceDirty string

// Action is one scripted, declared operation at a wall offset from trace start.
type Action struct {
	AtMillis int64    `json:"at_ms"`
	Kind     string   `json:"kind"` // env | config | source_error | checkpoint
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

func run(slot, attempt, policyName, selection, rule, listen, pd string, duration time.Duration, clients int, pause time.Duration, sources, out, script, envSh string, tickEvery time.Duration) (runErr error) {
	if duration <= 0 || tickEvery <= 0 || clients <= 0 || pause < 0 {
		return fmt.Errorf("duration, tick and clients must be positive; pause must be nonnegative")
	}
	// Validate the complete script before opening an attempt or starting live services.
	var actions []Action
	var scriptData []byte
	scriptSHA := ""
	if script != "" {
		var err error
		scriptData, err = os.ReadFile(script)
		if err != nil {
			return err
		}
		decoder := json.NewDecoder(bytes.NewReader(scriptData))
		decoder.DisallowUnknownFields()
		if err = decoder.Decode(&actions); err != nil {
			return err
		}
		if err = decoder.Decode(new(any)); err != io.EOF {
			return fmt.Errorf("action script must contain exactly one JSON array")
		}
		if err = validateActions(actions); err != nil {
			return err
		}
		scriptSHA = fmt.Sprintf("%x", sha256.Sum256(scriptData))
		sort.SliceStable(actions, func(i, j int) bool { return actions[i].AtMillis < actions[j].AtMillis })
	}
	dir := filepath.Join(out, slot+"-"+attempt)
	if err := os.MkdirAll(out, 0o755); err != nil {
		return err
	}
	if err := os.Mkdir(dir, 0o755); err != nil {
		return err
	}
	lg, err := zap.NewDevelopment(zap.IncreaseLevel(zap.WarnLevel))
	if err != nil {
		return err
	}
	listeners := strings.Split(listen, ",")
	toml := fmt.Sprintf("[proxy]\naddr = %q\npd-addrs = %q\n[balance]\npolicy = %q\nrouting-policy = %q\nrouting-rule = %q\n[log]\nlevel = \"warn\"\n",
		listeners[0], pd, policyName, selection, rule)
	cfgFile := filepath.Join(dir, "proxy.toml")
	if err := os.WriteFile(cfgFile, []byte(toml), 0o600); err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	cfgMgr := mgrcfg.NewConfigManager()
	if err := cfgMgr.Init(ctx, cfgFile, ""); err != nil {
		return err
	}
	defer func() { runErr = errors.Join(runErr, cfgMgr.Close()) }()
	cfg := cfgMgr.GetConfig()
	certMgr := cert.NewCertManager()
	if err := certMgr.Init(cfg, lg.Named("cert"), cfgMgr.WatchConfig()); err != nil {
		return err
	}
	defer certMgr.Close()
	clusterMgr := backendcluster.NewManager(lg.Named("backendcluster"), certMgr.ClusterTLS)
	if err := clusterMgr.Start(ctx, cfgMgr, cfgMgr.WatchConfig()); err != nil {
		return err
	}
	defer clusterMgr.Close()

	sched, err := harness.NewScheduler(filepath.Join(dir, "archive.jsonl"))
	if err != nil {
		return err
	}
	defer func() { runErr = errors.Join(runErr, sched.Close()) }()

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
	defer rt.Close()
	inputs := harness.NewInputs(sched, driver)
	apireplay.Install(sched, slot)
	ledger := newLedger()
	sched.Observe(ledger.observe)

	// Real proxy exactly as pkg/server/server.go composes it, with the recording namespace manager.
	nsMgr := harness.NewRecordingNamespaceManager(rt)
	hsHandler := backend.NewDefaultHandshakeHandler(nsMgr)
	memMgr := memory.NewMemManager(lg.Named("mem"), cfgMgr)
	memMgr.Start(ctx)
	defer memMgr.Close()
	sqlSrv, err := proxy.NewSQLServer(lg.Named("proxy"), cfg, certMgr, id.NewIDManager(), nil, nil, hsHandler, memMgr)
	if err != nil {
		return err
	}
	sqlSrv.SetBackendDialer(clusterMgr.NetworkRouter())
	sqlSrv.Run(ctx, cfgMgr.WatchConfig())
	sqlClosed := false
	defer func() {
		if sqlClosed {
			return
		}
		sqlSrv.PreClose() // closes the listeners so the accept loops exit (server.go preClose order)
		runErr = errors.Join(runErr, sqlSrv.Close())
	}()

	// Inputs start flowing only now: the first HealthResult is consumed after the proxy is up.
	bo.Start(ctx)
	defer bo.Close()
	inputCtx, stopInputs := context.WithCancel(ctx)
	var inputWG waitgroup.WaitGroup
	inputWG.Run(func() { inputs.Forward(inputCtx, bo, "recorder") }, lg)
	defer func() { stopInputs(); inputWG.Wait() }()

	if script != "" {
		if err := os.WriteFile(filepath.Join(dir, "actions.json"), scriptData, 0o600); err != nil {
			return err
		}
	}

	// Declared timer schedule: every tickEvery from trace start, plus boundary
	// instants supplied by the recording script. Automatic boundary expansion
	// is not implemented by this recorder yet.
	runCtx, stop := context.WithTimeout(ctx, duration)
	defer stop()
	var incomplete []string
	var incompleteMu sync.Mutex
	markIncomplete := func(reason string) {
		incompleteMu.Lock()
		defer incompleteMu.Unlock()
		incomplete = append(incomplete, reason)
	}
	var producerWG, envWG waitgroup.WaitGroup
	checkpoints := map[int]harness.Checkpoint{}
	producerWG.Run(func() {
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
	}, lg)
	producerWG.Run(func() {
		for _, a := range actions {
			if runCtx.Err() != nil {
				return
			}
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
				// env.sh primitives block until their own readiness condition (e.g. topology
				// key gone); track them separately so later actions keep their instants
				// and finalization joins every command before sealing the archive.
				envWG.Run(func() {
					// #nosec G204 -- The operator supplies the isolated environment driver and its argument vector; no shell or network payload is evaluated.
					cmd := exec.CommandContext(runCtx, envSh, a.Args...)
					cmd.WaitDelay = 2 * time.Second
					cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
					fmt.Fprintf(os.Stderr, "[record] env %v at wall %s\n", a.Args, sched.Elapsed())
					if err := cmd.Run(); err != nil {
						markIncomplete(fmt.Sprintf("env %v: %v", a.Args, err))
					}
					fmt.Fprintf(os.Stderr, "[record] env %v done at wall %s\n", a.Args, sched.Elapsed())
				}, lg)
			case "config":
				err := cfgMgr.SetTOMLConfig([]byte(a.TOML))
				inputs.DeliverConfig(a.TOML, cfgMgr.GetConfig(), err)
			case "source_error":
				fault, err := harness.FaultError(a.Error)
				if err != nil {
					markIncomplete(err.Error())
					return
				}
				fetcher.Set(fault)
			case "checkpoint":
				sched.RunNow(func() {
					seq := sched.Seq()
					checkpoints[seq] = harness.Checkpoint{Seq: seq, Assignments: ledger.assignments(), ConnCount: rt.ConnCount(),
						HealthyBackendCount: rt.HealthyBackendCount(), ServerVersion: rt.ServerVersion()}
					sched.Record(apireplay.Event{Op: "checkpoint"})
				})
			default:
				markIncomplete(fmt.Sprintf("unknown action %q", a.Kind))
			}
		}
	}, lg)

	wl := &harness.Workload{Listener: listeners[0], Clients: clients, Pause: pause, User: "root"}
	if sources != "" {
		wl.Sources = strings.Split(sources, ",")
	}
	wl.Run(runCtx)
	// No producer may race the final checkpoint or the archive hash. The real
	// SQL server's Close joins connection goroutines and their terminal callbacks.
	stop()
	producerWG.Wait() // finishes adding environment jobs before envWG.Wait
	envWG.Wait()
	stopInputs()
	inputWG.Wait()
	sqlSrv.PreClose()
	closeErr := sqlSrv.Close()
	sqlClosed = true
	if closeErr != nil {
		markIncomplete(fmt.Sprintf("close SQL server: %v", closeErr))
	}
	if ctx.Err() != nil {
		markIncomplete("recording interrupted before normal duration elapsed")
	}

	sched.RunNow(func() {
		seq := sched.Seq()
		checkpoints[seq] = harness.Checkpoint{Seq: seq, Assignments: ledger.assignments(), ConnCount: rt.ConnCount(),
			HealthyBackendCount: rt.HealthyBackendCount(), ServerVersion: rt.ServerVersion()}
		sched.Record(apireplay.Event{Op: "checkpoint"})
	})
	if len(ledger.open) != 0 || len(ledger.pending) != 0 || len(ledger.active) != 0 {
		markIncomplete(fmt.Sprintf("unsettled sessions: open=%d pending=%d active=%d", len(ledger.open), len(ledger.pending), len(ledger.active)))
	}
	if err := sched.Close(); err != nil {
		markIncomplete(fmt.Sprintf("seal archive: %v", err))
	}
	for _, reason := range ledger.violations {
		markIncomplete(reason)
	}
	if sourceHead == "" || sourceTree == "" || sourceDirty != "false" {
		markIncomplete("capture requires a clean, identified source tree built by record.py")
	}
	meta := harness.CaptureSummary{Head: sourceHead, Tree: sourceTree, SourceDirty: sourceDirty,
		DurationNanos: sched.Elapsed().Nanoseconds(), PlannedDurationNanos: duration.Nanoseconds(),
		Completed: wl.Completed(), Failed: wl.Failed(), Clients: clients, ScriptSHA256: scriptSHA}
	status, err := harness.Write(dir, slot, attempt, harness.TraceConfig{Policy: policyName, Selection: selection, Rule: rule}, sched.Log(), checkpoints, incomplete,
		clusterMgr.MetricsQuerier() != nil, meta)
	if err != nil {
		return err
	}
	fmt.Printf("%s: status=%s completed=%d failed=%d events=%d dir=%s\n", slot, status, wl.Completed(), wl.Failed(), len(sched.Log()), dir)
	return nil
}

func validateActions(actions []Action) error {
	for i, a := range actions {
		if a.AtMillis < 0 {
			return fmt.Errorf("action %d: negative at_ms", i)
		}
		switch a.Kind {
		case "env", "config", "checkpoint":
		case "source_error":
			if _, err := harness.FaultError(a.Error); err != nil {
				return fmt.Errorf("action %d: %w", i, err)
			}
		default:
			return fmt.Errorf("action %d: unsupported kind %q", i, a.Kind)
		}
	}
	return nil
}

// ledger mirrors run.py's public assignment ledger from the recorded events so
// checkpoints carry `assignments` the way the adapter reports them.
type ledger struct {
	open       map[string]bool
	settled    map[string]bool
	violations []string
	pending    map[string]string
	active     map[string]string
}

func newLedger() *ledger {
	return &ledger{open: map[string]bool{}, settled: map[string]bool{}, pending: map[string]string{}, active: map[string]string{}}
}

func (l *ledger) observe(ev apireplay.Event) {
	switch ev.Op {
	case "open":
		l.open[ev.Session] = true
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
		if ev.Success != nil && *ev.Success && l.open[ev.Session] && l.active[ev.Session] != "" && !l.settled[ev.Operation] {
			l.active[ev.Session] = ev.Backend
		}
		l.settled[ev.Operation] = true
	case "close":
		if l.pending[ev.Session] != "" {
			l.violations = append(l.violations, "close with pending reservation: "+ev.Session)
		}
		if !l.open[ev.Session] {
			l.violations = append(l.violations, "close without open selector: "+ev.Session)
		}
		delete(l.open, ev.Session)
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
