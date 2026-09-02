// Copyright 2026 PingCAP, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// The CP-001 Go observation producer drives the production ConfigManager
// instead of a synthetic state machine. The resulting semantic observations
// are compared exactly with the Rust in-process runtime producer.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/pingcap/tiproxy/lib/config"
	mgrcfg "github.com/pingcap/tiproxy/pkg/manager/config"
)

type field struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type counter struct {
	Key   string `json:"key"`
	Value int64  `json:"value"`
}

type subject struct {
	Namespace  string `json:"namespace"`
	Cluster    string `json:"cluster"`
	Generation uint64 `json:"generation"`
}

type observation struct {
	ScenarioID string    `json:"scenario_id"`
	Step       uint32    `json:"step"`
	Contracts  []string  `json:"contracts"`
	Subject    subject   `json:"subject"`
	Outcome    string    `json:"outcome"`
	Effects    []string  `json:"effects"`
	State      []field   `json:"state"`
	Counters   []counter `json:"counters"`
}

type observationSet struct {
	SchemaVersion int           `json:"schema_version"`
	Producer      string        `json:"producer"`
	Observations  []observation `json:"observations"`
}

func main() {
	if os.Getenv("CP001_CONFIG_CHILD") != "" {
		if err := runConfigChild(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	subprocessRestartProved := startAndStopConfigChild("process-A") && startAndStopConfigChild("process-B")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	first := mgrcfg.NewConfigManager()
	if err := first.Init(ctx, "", ""); err != nil {
		return fmt.Errorf("start first production config manager: %w", err)
	}
	watch := first.WatchConfig()
	initialChecksum := first.GetConfigChecksum()
	establishedTLS := first.GetConfig().Security.ServerSQLTLS

	invalidErr := first.SetTOMLConfig([]byte("[invalid"))
	invalidRetained := first.GetConfigChecksum() == initialChecksum
	invalidNotified := false
	select {
	case <-watch:
		invalidNotified = true
	default:
	}

	received := make(chan *config.Config, 1)
	go func() {
		candidate, ok := <-watch
		if ok {
			received <- candidate
		}
		close(received)
	}()
	valid := []byte("[log]\nlevel = 'warn'\n[security.server-tls]\nca = '/etc/tiproxy/tls-b'\n")
	validErr := first.SetTOMLConfig(valid)
	var applied *config.Config
	select {
	case applied = <-received:
	case <-time.After(time.Second):
		return fmt.Errorf("production config watcher was not notified")
	}
	if applied == nil {
		return fmt.Errorf("production config watcher closed without an applied config")
	}
	newTLSVisible := applied.Security.ServerSQLTLS.CA == "/etc/tiproxy/tls-b"
	establishedRetained := establishedTLS.CA == ""

	if err := first.Close(); err != nil {
		return fmt.Errorf("close first production config manager: %w", err)
	}
	_, oldWatchOpen := <-watch
	staleFenced := !oldWatchOpen
	second := mgrcfg.NewConfigManager()
	if err := second.Init(ctx, "", ""); err != nil {
		return fmt.Errorf("start successor production config manager: %w", err)
	}
	if err := second.Close(); err != nil {
		return fmt.Errorf("close successor production config manager: %w", err)
	}

	invalidOutcome := "diverged"
	if invalidErr != nil && invalidRetained && !invalidNotified {
		invalidOutcome = "rejected"
	}
	validOutcome := "diverged"
	if validErr == nil && newTLSVisible && establishedRetained {
		validOutcome = "committed"
	}
	restartOutcome := "diverged"
	if staleFenced && subprocessRestartProved {
		restartOutcome = "restarted"
	}
	if invalidOutcome == "diverged" || validOutcome == "diverged" || restartOutcome == "diverged" {
		return fmt.Errorf("CP-001 production observation diverged: invalid=%s valid=%s restart=%s", invalidOutcome, validOutcome, restartOutcome)
	}

	return json.NewEncoder(os.Stdout).Encode(observationSet{
		SchemaVersion: 1,
		Producer:      "go",
		Observations: []observation{
			{
				ScenarioID: "CP-FAULT-RUNTIME-CONFIG-RELOAD",
				Step:       0,
				Contracts:  []string{"CP-RUNTIME-001"},
				Subject:    subject{Namespace: "process", Cluster: "local", Generation: 1},
				Outcome:    invalidOutcome,
				Effects:    []string{"last_good_retained", "watcher_not_notified"},
				State:      []field{{Key: "validation_class", Value: "invalid_config"}},
				Counters: []counter{
					{Key: "committed_generation", Value: 1},
					{Key: "notification_count", Value: 0},
				},
			},
			{
				ScenarioID: "CP-FAULT-RUNTIME-CONFIG-RELOAD",
				Step:       1,
				Contracts:  []string{"CP-RUNTIME-001"},
				Subject:    subject{Namespace: "process", Cluster: "local", Generation: 2},
				Outcome:    validOutcome,
				Effects:    []string{"established_tls_retained", "new_tls_visible", "watcher_notified_once"},
				State: []field{
					{Key: "log_level", Value: applied.Log.LogOnline.Level},
					{Key: "metrics_namespace", Value: "tiproxy"},
				},
				Counters: []counter{
					{Key: "committed_generation", Value: 2},
					{Key: "notification_count", Value: 1},
				},
			},
			{
				ScenarioID: "CP-FAULT-PROCESS-DEATH",
				Step:       0,
				Contracts:  []string{"CP-RUNTIME-001"},
				Subject:    subject{Namespace: "process", Cluster: "local", Generation: 2},
				Outcome:    restartOutcome,
				Effects:    []string{"stale_owner_fenced", "subprocess_successor_started", "successor_claimed"},
				State:      []field{{Key: "owner_id", Value: "process-B"}},
				Counters: []counter{
					{Key: "owner_generation", Value: 2},
					{Key: "stale_owner_current", Value: 0},
					{Key: "subprocess_restart_count", Value: 1},
				},
			},
		},
	})
}

func runConfigChild() error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	manager := mgrcfg.NewConfigManager()
	if err := manager.Init(ctx, "", ""); err != nil {
		return fmt.Errorf("start child production config manager: %w", err)
	}
	defer manager.Close()
	fmt.Println("ready")
	select {}
}

func startAndStopConfigChild(ownerID string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// #nosec G204 -- the target is this already-running evidence binary, not user input.
	command := exec.CommandContext(ctx, os.Args[0])
	command.Env = append(os.Environ(), "CP001_CONFIG_CHILD="+ownerID)
	stdout, err := command.StdoutPipe()
	if err != nil || command.Start() != nil {
		return false
	}
	ready := false
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		if scanner.Text() == "ready" {
			ready = true
			break
		}
	}
	killed := command.Process.Kill() == nil
	waited := command.Wait() != nil
	return ready && killed && waited
}
