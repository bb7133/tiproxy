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
	"encoding/hex"
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
	AtMillis               int64    `json:"at_ms"`
	Kind                   string   `json:"kind"` // env | await_env | config | source_error | checkpoint | scripted client controls
	Args                   []string `json:"args,omitempty"`
	TOML                   string   `json:"toml,omitempty"`
	Error                  string   `json:"error,omitempty"` // source_error identity; "" clears the fault window
	TimeoutMillis          int64    `json:"timeout_ms,omitempty"`
	FailoverTimeoutSeconds int64    `json:"failover_timeout_seconds,omitempty"`
	EffectControl          string   `json:"effect_control,omitempty"` // refuse | delay; armed atomically with failover_select
}

type environmentComponent struct {
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
	Length  int64  `json:"length"`
}

type environmentManifest struct {
	GeneratedAt string `json:"generated_at"`
	Host        struct {
		Hostname string `json:"hostname"`
		OS       string `json:"os"`
		Arch     string `json:"arch"`
	} `json:"host"`
	Components map[string]environmentComponent `json:"components"`
	Binaries   map[string]string               `json:"binaries"`
	PD         struct {
		ClientURL string `json:"client_url"`
	} `json:"pd"`
	TiKV struct {
		Addr   string `json:"addr"`
		Status string `json:"status"`
	} `json:"tikv"`
	Prometheus struct {
		BaseURL string `json:"base_url"`
	} `json:"prometheus"`
	TiDB []struct {
		Name   string `json:"name"`
		SQL    string `json:"sql"`
		Status string `json:"status"`
	} `json:"tidb"`
}

func main() {
	var (
		slot         = flag.String("slot", "smoke", "trace slot id (recording-plan.tsv)")
		attempt      = flag.String("attempt", "a1", "attempt id; a new capture never overwrites a previous one")
		policyF      = flag.String("policy", "connection", "[balance] policy")
		selection    = flag.String("selection", "prefer-idle", "[balance] routing-policy")
		rule         = flag.String("rule", "", "[balance] routing-rule (fixed at Init)")
		listen       = flag.String("listen", "127.0.0.1:6000", "proxy listener(s), comma separated")
		pd           = flag.String("pd", "127.0.0.1:2379", "PD address")
		duration     = flag.Duration("duration", 60*time.Second, "recording duration")
		clients      = flag.Int("clients", 8, "concurrent mysql clients")
		heldClients  = flag.Int("held-clients", 0, "supplemental long-lived mysql clients for migration controls")
		pause        = flag.Duration("pause", 200*time.Millisecond, "pause between lifecycles per client")
		sources      = flag.String("sources", "", "comma separated loopback source IPs for clients")
		out          = flag.String("out", "", "output directory (required)")
		script       = flag.String("script", "", "JSON file with scripted actions")
		envSh        = flag.String("env", "", "path to slice3 env.sh for env actions")
		envManifest  = flag.String("environment-manifest", "", "immutable JSON snapshot from the live environment (required)")
		tick         = flag.Duration("tick", 10*time.Millisecond, "declared rebalance tick interval")
		checkOverlay = flag.Bool("check-overlay", false, "verify that record.py's build overlay is installed, then exit")
	)
	flag.Parse()
	if *checkOverlay {
		if !apireplay.OverlayInstalled() {
			fmt.Fprintln(os.Stderr, "API replay overlay is not installed")
			os.Exit(1)
		}
		fmt.Println("API replay overlay: installed")
		return
	}
	if *out == "" {
		fmt.Fprintln(os.Stderr, "-out is required")
		os.Exit(2)
	}
	if err := run(*slot, *attempt, *policyF, *selection, *rule, *listen, *pd, *duration, *clients, *heldClients, *pause, *sources, *out, *script, *envSh, *envManifest, *tick); err != nil {
		fmt.Fprintln(os.Stderr, "record:", err)
		os.Exit(1)
	}
}

func run(slot, attempt, policyName, selection, rule, listen, pd string, duration time.Duration, clients, heldClients int, pause time.Duration, sources, out, script, envSh, envManifestPath string, tickEvery time.Duration) (runErr error) {
	if duration <= 0 || tickEvery <= 0 || clients <= 0 || heldClients < 0 || pause < 0 {
		return fmt.Errorf("duration, tick and clients must be positive; held-clients and pause must be nonnegative")
	}
	listeners := config.SplitAddrList(listen)
	if len(listeners) == 0 {
		return errors.New("-listen requires at least one address")
	}
	sourceList := config.SplitAddrList(sources)
	if err := validateClientCoverage(clients, listeners, sourceList); err != nil {
		return err
	}
	wl := &harness.Workload{Listeners: listeners, Sources: sourceList, Clients: clients,
		HeldClients: heldClients, Pause: pause, User: "root"}
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
		sort.SliceStable(actions, func(i, j int) bool { return actions[i].AtMillis < actions[j].AtMillis })
		if err = validateActions(actions); err != nil {
			return err
		}
		if requiresEnvironmentDriver(actions) && envSh == "" {
			return errors.New("-env is required by env actions")
		}
		scriptSHA = fmt.Sprintf("%x", sha256.Sum256(scriptData))
	}
	envManifestData, envManifestSHA, err := loadEnvironmentManifest(envManifestPath)
	if err != nil {
		return err
	}
	if !apireplay.OverlayInstalled() {
		return errors.New("recorder build is missing the API replay overlay; use record.py build or run")
	}
	dir := filepath.Join(out, slot+"-"+attempt)
	if err := os.MkdirAll(out, 0o755); err != nil {
		return err
	}
	if err := os.Mkdir(dir, 0o755); err != nil {
		return err
	}
	if err := writeExclusiveFile(filepath.Join(dir, "environment-manifest.json"), envManifestData, 0o600); err != nil {
		return fmt.Errorf("preserve environment manifest: %w", err)
	}
	lg, err := zap.NewDevelopment(zap.IncreaseLevel(zap.WarnLevel))
	if err != nil {
		return err
	}
	toml := recordingConfig(listeners, pd, policyName, selection, rule)
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
	metricInputs := harness.NewMetricsInputs(sched, clusterMgr.MetricsQuerier())
	bpCreator := func(lg *zap.Logger) policy.BalancePolicy {
		p := factor.NewFactorBasedBalance(lg, metricInputs)
		p.Init(cfgMgr.GetConfig())
		return p
	}
	driver := router.NewReplayDriver(rt, bo, bpCreator, cfgMgr)
	defer rt.Close()
	inputs := harness.NewInputs(sched, driver)
	apireplay.Install(sched, slot)
	ledger := newLedger(wl.IsHeldClientAt)
	sched.ObserveRecorded(func(record harness.Recorded) { ledger.observeAt(record.Event, record.Wall) })

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
	selectedFailoverBackend := ""
	selectedFailoverTimeout := int64(0)
	producerWG.Run(func() {
		for k := int64(0); runCtx.Err() == nil; k++ {
			declared := k * hcCfg.MetricsInterval.Nanoseconds()
			if wait := time.Duration(declared) - sched.Elapsed(); wait > 0 {
				select {
				case <-time.After(wait):
				case <-runCtx.Done():
					return
				}
			}
			metricInputs.Publish(declared)
		}
	}, lg)
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
			case "await_env":
				envWG.Wait()
			case "config":
				err := cfgMgr.SetTOMLConfig([]byte(a.TOML))
				inputs.DeliverConfig(a.TOML, cfgMgr.GetConfig(), err)
			case "failover_select":
				sched.RunNow(func() {
					seq := sched.Seq()
					assignments := ledger.assignments()
					checkpoints[seq] = harness.Checkpoint{Seq: seq, Assignments: assignments, ConnCount: rt.ConnCount(),
						HealthyBackendCount: rt.HealthyBackendCount(), ServerVersion: rt.ServerVersion()}
					sched.Record(apireplay.Event{Op: "checkpoint"})
					selectedFailoverBackend = ledger.chooseHeldBackend()
					selectedFailoverTimeout = a.FailoverTimeoutSeconds
					if selectedFailoverBackend == "" {
						markIncomplete("failover_select found no established held-client assignment")
						sched.Record(apireplay.Event{Op: "recorder_error", Outcome: "failover_select_without_held_assignment"})
						return
					}
					toml := failoverConfig(selectedFailoverBackend, selectedFailoverTimeout)
					err := cfgMgr.SetTOMLConfig([]byte(toml))
					armEffectControl(a.EffectControl)
					inputs.DeliverConfigLocked(toml, cfgMgr.GetConfig(), err, a.EffectControl == "refuse")
				})
			case "failover_repeat":
				toml := failoverConfig(selectedFailoverBackend, selectedFailoverTimeout)
				err := cfgMgr.SetTOMLConfig([]byte(toml))
				inputs.DeliverConfig(toml, cfgMgr.GetConfig(), err)
			case "failover_clear":
				toml := failoverConfig("", 0)
				err := cfgMgr.SetTOMLConfig([]byte(toml))
				inputs.DeliverConfig(toml, cfgMgr.GetConfig(), err)
			case "source_error":
				fault, err := harness.FaultError(a.Error)
				if err != nil {
					markIncomplete(err.Error())
					return
				}
				fetcher.Set(fault)
			case "refuse_next_effect":
				sched.RunNow(apireplay.RefuseNextEffect)
			case "delay_next_redirect_result":
				sched.RunNow(apireplay.DelayNextRedirectResult)
			case "close_delayed_redirect":
				controlCtx, cancelControl := context.WithTimeout(runCtx, actionTimeout(a))
				err := apireplay.CloseDelayedRedirect(controlCtx)
				cancelControl()
				if err != nil {
					markIncomplete(fmt.Sprintf("close delayed redirect: %v", err))
					return
				}
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
	for _, reason := range apireplay.PendingControls() {
		markIncomplete(reason)
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
	records := sched.Log()
	lifecycles := harness.SummarizeQualifyingLifecycles(records, ledger.heldSessions())
	if err := validateRecordedLifecycles(lifecycles, wl.Completed()); err != nil {
		markIncomplete(err.Error())
	}
	if sourceHead == "" || sourceTree == "" || sourceDirty != "false" {
		markIncomplete("capture requires a clean, identified source tree built by record.py")
	}
	meta := harness.CaptureSummary{Head: sourceHead, Tree: sourceTree, SourceDirty: sourceDirty,
		DurationNanos: sched.Elapsed().Nanoseconds(), PlannedDurationNanos: duration.Nanoseconds(),
		Completed: lifecycles.Completed, Failed: lifecycles.Opened - lifecycles.Completed,
		WorkloadCompleted: wl.Completed(), WorkloadFailed: wl.Failed(), Clients: clients,
		HeldClients: heldClients, HeldQueries: wl.HeldQueries(), HeldFailed: wl.HeldFailed(), ScriptSHA256: scriptSHA,
		EnvironmentManifestSHA256: envManifestSHA}
	origin := sched.OriginNanos()
	status, err := harness.Write(dir, slot, attempt, harness.TraceConfig{Policy: policyName, Selection: selection, Rule: rule, ClockOriginNanos: &origin}, records, checkpoints, incomplete,
		metricInputs.Observed(), meta)
	if err != nil {
		return err
	}
	fmt.Printf("%s: status=%s completed=%d workload_completed=%d workload_failed=%d events=%d dir=%s\n",
		slot, status, lifecycles.Completed, wl.Completed(), wl.Failed(), len(records), dir)
	return nil
}

func validateClientCoverage(clients int, listeners, sources []string) error {
	combinations := len(listeners)
	if len(sources) > 0 {
		combinations *= len(sources)
	}
	if clients < combinations {
		return fmt.Errorf("clients %d cannot cover all %d listener/source combinations", clients, combinations)
	}
	return nil
}

func validateActions(actions []Action) error {
	const maxDurationMillis = int64((time.Duration(1<<63 - 1)) / time.Millisecond)
	pendingEnvironment := false
	pendingDelayedRedirect := false
	selectedFailover := false
	activeFailover := false
	for i, a := range actions {
		if a.AtMillis < 0 || a.AtMillis > maxDurationMillis {
			return fmt.Errorf("action %d: at_ms is outside time.Duration range", i)
		}
		if a.TimeoutMillis < 0 || a.TimeoutMillis > maxDurationMillis {
			return fmt.Errorf("action %d: timeout_ms is outside time.Duration range", i)
		}
		if len(a.Args) != 0 && a.Kind != "env" {
			return fmt.Errorf("action %d: args is only valid for env", i)
		}
		if a.TOML != "" && a.Kind != "config" {
			return fmt.Errorf("action %d: toml is only valid for config", i)
		}
		if a.Error != "" && a.Kind != "source_error" {
			return fmt.Errorf("action %d: error is only valid for source_error", i)
		}
		if a.FailoverTimeoutSeconds != 0 && a.Kind != "failover_select" {
			return fmt.Errorf("action %d: failover_timeout_seconds is only valid for failover_select", i)
		}
		if a.EffectControl != "" && a.Kind != "failover_select" {
			return fmt.Errorf("action %d: effect_control is only valid for failover_select", i)
		}
		if pendingEnvironment && a.Kind != "env" && a.Kind != "await_env" {
			return fmt.Errorf("action %d: env batch requires await_env before %q", i, a.Kind)
		}
		switch a.Kind {
		case "env":
			if len(a.Args) == 0 {
				return fmt.Errorf("action %d: env requires a nonempty args vector", i)
			}
			pendingEnvironment = true
		case "await_env":
			if !pendingEnvironment {
				return fmt.Errorf("action %d: await_env has no pending env batch", i)
			}
			pendingEnvironment = false
		case "config", "checkpoint", "refuse_next_effect":
		case "source_error":
			if _, err := harness.FaultError(a.Error); err != nil {
				return fmt.Errorf("action %d: %w", i, err)
			}
		case "delay_next_redirect_result":
			if pendingDelayedRedirect {
				return fmt.Errorf("action %d: a delayed redirect control is already pending", i)
			}
			pendingDelayedRedirect = true
		case "failover_select":
			if a.FailoverTimeoutSeconds <= 0 {
				return fmt.Errorf("action %d: failover_select requires a positive failover_timeout_seconds", i)
			}
			if activeFailover {
				return fmt.Errorf("action %d: failover_select requires a preceding failover_clear", i)
			}
			if a.EffectControl != "" && a.EffectControl != "refuse" && a.EffectControl != "delay" {
				return fmt.Errorf("action %d: unsupported effect_control %q", i, a.EffectControl)
			}
			if a.EffectControl == "delay" {
				if pendingDelayedRedirect {
					return fmt.Errorf("action %d: a delayed redirect control is already pending", i)
				}
				pendingDelayedRedirect = true
			}
			selectedFailover = true
			activeFailover = true
		case "failover_repeat":
			if !selectedFailover || !activeFailover {
				return fmt.Errorf("action %d: failover_repeat requires an active failover_select", i)
			}
		case "failover_clear":
			if !activeFailover {
				return fmt.Errorf("action %d: failover_clear requires an active failover_select", i)
			}
			activeFailover = false
		case "close_delayed_redirect":
			if !pendingDelayedRedirect {
				return fmt.Errorf("action %d: close_delayed_redirect has no preceding delay control", i)
			}
			pendingDelayedRedirect = false
		default:
			return fmt.Errorf("action %d: unsupported kind %q", i, a.Kind)
		}
		if a.TimeoutMillis != 0 && a.Kind != "close_delayed_redirect" {
			return fmt.Errorf("action %d: timeout_ms is only valid for close_delayed_redirect", i)
		}
	}
	if pendingEnvironment {
		return errors.New("action script ends with an env batch that has no await_env")
	}
	if pendingDelayedRedirect {
		return errors.New("action script ends with an unclosed delayed redirect control")
	}
	if activeFailover {
		return errors.New("action script ends with an active selected failover")
	}
	return nil
}

func requiresEnvironmentDriver(actions []Action) bool {
	for _, action := range actions {
		if action.Kind == "env" {
			return true
		}
	}
	return false
}

func actionTimeout(action Action) time.Duration {
	if action.TimeoutMillis == 0 {
		return 10 * time.Second
	}
	return time.Duration(action.TimeoutMillis) * time.Millisecond
}

func armEffectControl(control string) {
	switch control {
	case "refuse":
		apireplay.RefuseNextEffect()
	case "delay":
		apireplay.DelayNextRedirectResult()
	}
}

func failoverConfig(backend string, timeoutSeconds int64) string {
	if backend == "" {
		return "[proxy]\nfail-backend-list = []\n"
	}
	return fmt.Sprintf("[proxy]\nfail-backend-list = [%q]\nfailover-timeout = %d\n", backendAddress(backend), timeoutSeconds)
}

func backendAddress(backend string) string {
	if i := strings.LastIndexByte(backend, '/'); i >= 0 {
		return backend[i+1:]
	}
	return backend
}

func recordingConfig(listeners []string, pd, policyName, selection, rule string) string {
	return fmt.Sprintf("[proxy]\naddr = %q\npd-addrs = %q\n[balance]\npolicy = %q\nrouting-policy = %q\nrouting-rule = %q\n[log]\nlevel = \"warn\"\n",
		strings.Join(listeners, ","), pd, policyName, selection, rule)
}

func validateRecordedLifecycles(lifecycles harness.LifecycleSummary, workloadCompleted int64) error {
	if lifecycles.Completed < workloadCompleted {
		return fmt.Errorf("recorded API lifecycles below successful workload queries: completed=%d workload=%d open=%d finish_success=%d close=%d",
			lifecycles.Completed, workloadCompleted, lifecycles.Opened, lifecycles.SuccessfulFinishes, lifecycles.Closed)
	}
	return nil
}

func loadEnvironmentManifest(path string) ([]byte, string, error) {
	if path == "" {
		return nil, "", errors.New("-environment-manifest is required")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, "", fmt.Errorf("read environment manifest: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	var manifest environmentManifest
	if err := decoder.Decode(&manifest); err != nil {
		return nil, "", fmt.Errorf("decode environment manifest: %w", err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, "", errors.New("environment manifest must contain exactly one JSON object")
	}
	if _, err := time.Parse(time.RFC3339, manifest.GeneratedAt); err != nil {
		return nil, "", fmt.Errorf("environment manifest generated_at must be RFC3339: %w", err)
	}
	if manifest.Host.Hostname == "" || manifest.Host.OS == "" || manifest.Host.Arch == "" {
		return nil, "", errors.New("environment manifest requires host hostname, os and arch")
	}
	for _, name := range []string{"pd", "tikv", "tidb", "prometheus"} {
		component, ok := manifest.Components[name]
		if !ok || component.Version == "" || component.Length <= 0 {
			return nil, "", fmt.Errorf("environment manifest requires version and positive length for component %q", name)
		}
		decoded, err := hex.DecodeString(component.SHA256)
		if err != nil || len(decoded) != sha256.Size {
			return nil, "", fmt.Errorf("environment manifest component %q requires a SHA-256 digest", name)
		}
	}
	for _, name := range []string{"pd", "tikv", "tidb"} {
		if manifest.Binaries[name] == "" {
			return nil, "", fmt.Errorf("environment manifest requires binary identity for %q", name)
		}
	}
	if manifest.PD.ClientURL == "" || manifest.TiKV.Addr == "" || manifest.TiKV.Status == "" || manifest.Prometheus.BaseURL == "" {
		return nil, "", errors.New("environment manifest requires PD, TiKV and Prometheus endpoints")
	}
	if len(manifest.TiDB) == 0 {
		return nil, "", errors.New("environment manifest requires at least one TiDB instance")
	}
	for i, instance := range manifest.TiDB {
		if instance.Name == "" || instance.SQL == "" || instance.Status == "" {
			return nil, "", fmt.Errorf("environment manifest TiDB instance %d requires name, sql and status", i)
		}
	}
	sum := sha256.Sum256(data)
	return data, hex.EncodeToString(sum[:]), nil
}

func writeExclusiveFile(path string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}
	n, writeErr := f.Write(data)
	if writeErr == nil && n != len(data) {
		writeErr = io.ErrShortWrite
	}
	return errors.Join(writeErr, f.Sync(), f.Close())
}

// ledger mirrors run.py's public assignment ledger from the recorded events so
// checkpoints carry `assignments` the way the adapter reports them.
type ledger struct {
	open       map[string]bool
	client     map[string]string
	openedAt   map[string]time.Time
	held       map[string]bool
	settled    map[string]bool
	violations []string
	pending    map[string]string
	active     map[string]string
	isHeld     func(string, time.Time) bool
}

func newLedger(isHeld func(string, time.Time) bool) *ledger {
	return &ledger{open: map[string]bool{}, client: map[string]string{}, openedAt: map[string]time.Time{}, held: map[string]bool{},
		settled: map[string]bool{}, pending: map[string]string{}, active: map[string]string{}, isHeld: isHeld}
}

func (l *ledger) observe(ev apireplay.Event) {
	l.observeAt(ev, time.Now())
}

func (l *ledger) observeAt(ev apireplay.Event, wall time.Time) {
	// A TCP accept can be observed just before the held dial callback returns
	// and records its address interval. Recheck every still-open, unclassified
	// session at later serialized events; the immutable open time distinguishes
	// a held lifetime from earlier or later reuse of the same ephemeral port.
	l.refreshHeldSessions()
	switch ev.Op {
	case "open":
		l.open[ev.Session] = true
		l.client[ev.Session] = ev.Client
		l.openedAt[ev.Session] = wall
		l.refreshHeldSessions()
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
		delete(l.client, ev.Session)
		delete(l.openedAt, ev.Session)
		delete(l.active, ev.Session)
		delete(l.pending, ev.Session)
	}
}

func (l *ledger) refreshHeldSessions() {
	if l.isHeld == nil {
		return
	}
	for session, client := range l.client {
		if !l.held[session] && l.isHeld(client, l.openedAt[session]) {
			l.held[session] = true
		}
	}
}

func (l *ledger) chooseHeldBackend() string {
	l.refreshHeldSessions()
	choices := make([]string, 0)
	seen := make(map[string]struct{})
	for session, backend := range l.active {
		if !l.held[session] || backend == "" {
			continue
		}
		if _, exists := seen[backend]; !exists {
			seen[backend] = struct{}{}
			choices = append(choices, backend)
		}
	}
	sort.Strings(choices)
	if len(choices) == 0 {
		return ""
	}
	return choices[0]
}

func (l *ledger) heldSessions() map[string]struct{} {
	l.refreshHeldSessions()
	result := make(map[string]struct{})
	for session, held := range l.held {
		if held {
			result[session] = struct{}{}
		}
	}
	return result
}

func (l *ledger) assignments() map[string]string {
	out := make(map[string]string, len(l.active))
	for k, v := range l.active {
		out[k] = v
	}
	return out
}
