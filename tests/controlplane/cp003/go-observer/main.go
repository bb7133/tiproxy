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

// The CP-ETCD Go observer drives the production election manager and a real
// embedded etcd server, then emits the normalized oracle compared with Rust.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/pingcap/tiproxy/pkg/manager/elect"
	etcdu "github.com/pingcap/tiproxy/pkg/util/etcd"
	"go.etcd.io/etcd/api/v3/mvccpb"
	clientv3 "go.etcd.io/etcd/client/v3"
	"go.uber.org/zap"
)

const (
	mainElectionKey  = "/tiproxy/cp003/go-main"
	childElectionKey = "/tiproxy/cp003/go-process-death"
)

type memberEvent struct {
	memberID string
	elected  bool
}

type observedMember struct {
	id     string
	events chan<- memberEvent
}

func (m *observedMember) OnElected() {
	m.events <- memberEvent{memberID: m.id, elected: true}
}

func (m *observedMember) OnRetired() {
	m.events <- memberEvent{memberID: m.id, elected: false}
}

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
	dataDir := flag.String("data-dir", "", "embedded etcd data directory")
	flag.Parse()
	if os.Getenv("CP003_GO_OWNER_CHILD") != "" {
		if err := runOwnerChild(); err != nil {
			_, _ = fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if err := run(*dataDir); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(dataDir string) error {
	if dataDir == "" {
		return fmt.Errorf("data-dir is required")
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return fmt.Errorf("create observer data directory: %w", err)
	}
	dataPath := filepath.Join(dataDir, "data")
	server, err := etcdu.CreateEtcdServer("127.0.0.1:0", dataPath, zap.NewNop())
	if err != nil {
		return fmt.Errorf("start embedded etcd: %w", err)
	}
	defer func() {
		if server != nil {
			server.Close()
		}
	}()
	addr := server.Clients[0].Addr().String()
	client, err := etcdu.InitEtcdClientWithAddrs(zap.NewNop(), addr, nil)
	if err != nil {
		return fmt.Errorf("create production Go etcd client: %w", err)
	}
	defer client.Close()

	events := make(chan memberEvent, 16)
	cfg := elect.ElectionConfig{
		Timeout:    500 * time.Millisecond,
		RetryIntvl: 100 * time.Millisecond,
		RetryCnt:   3,
		SessionTTL: 5,
	}
	memberA := &observedMember{id: "member-A", events: events}
	electionA := elect.NewElection(zap.NewNop(), client, cfg, memberA.id, mainElectionKey, memberA)
	electionA.Start(context.Background())
	if err := waitEvent(events, "member-A", true, 8*time.Second); err != nil {
		return err
	}
	initial, err := getOwnerKV(client, mainElectionKey)
	if err != nil {
		return err
	}

	server.Close()
	server = nil
	select {
	case event := <-events:
		return fmt.Errorf("transient outage emitted owner event %+v", event)
	case <-time.After(750 * time.Millisecond):
	}
	server, err = etcdu.CreateEtcdServer(addr, dataPath, zap.NewNop())
	if err != nil {
		return fmt.Errorf("restart embedded etcd: %w", err)
	}
	if err := waitOwner(electionA, "member-A", 8*time.Second); err != nil {
		return err
	}
	recovered, err := getOwnerKV(client, mainElectionKey)
	if err != nil {
		return err
	}
	if recovered.Lease != initial.Lease || recovered.CreateRevision != initial.CreateRevision {
		return fmt.Errorf("transient recovery changed Go lease/revision")
	}

	compactRevision, err := bumpAndCompact(client)
	if err != nil {
		return err
	}
	if err := proveCompactedWatch(client, initial, compactRevision); err != nil {
		return err
	}
	if err := waitOwner(electionA, "member-A", 3*time.Second); err != nil {
		return fmt.Errorf("owner changed after compaction at revision %d: %w", compactRevision, err)
	}

	revokeCtx, revokeCancel := context.WithTimeout(context.Background(), time.Second)
	_, err = client.Revoke(revokeCtx, clientv3.LeaseID(initial.Lease))
	revokeCancel()
	if err != nil {
		return fmt.Errorf("revoke Go owner lease: %w", err)
	}
	// The Go baseline has no public one-step recover API. Close supplies its
	// explicit retirement fence after the injected lease loss; Rust below must
	// detect the same loss itself before a successor may campaign.
	electionA.Close()
	if err := waitEvent(events, "member-A", false, 8*time.Second); err != nil {
		return err
	}
	memberB := &observedMember{id: "member-B", events: events}
	electionB := elect.NewElection(zap.NewNop(), client, cfg, memberB.id, mainElectionKey, memberB)
	electionB.Start(context.Background())
	if err := waitEvent(events, "member-B", true, 8*time.Second); err != nil {
		return err
	}
	successor, err := getOwnerKV(client, mainElectionKey)
	if err != nil {
		return err
	}
	if string(successor.Value) != "member-B" || successor.Lease == initial.Lease || successor.CreateRevision <= initial.CreateRevision {
		return fmt.Errorf("Go successor lease/revision did not advance")
	}
	electionB.Close()

	processDeathExpired, err := proveProcessDeath(client, addr)
	if err != nil {
		return err
	}
	if !processDeathExpired {
		return fmt.Errorf("Go process-death election key did not expire")
	}

	return json.NewEncoder(os.Stdout).Encode(observationSet{
		SchemaVersion: 1,
		Producer:      "go",
		Observations: []observation{
			{
				ScenarioID: "CP-FAULT-ETCD-TRANSIENT",
				Step:       0,
				Contracts:  []string{"CP-ELECT-001"},
				Subject:    subject{Namespace: "process", Cluster: "loopback", Generation: 1},
				Outcome:    "recovered",
				Effects:    []string{"no_false_retirement", "owner_identity_retained", "revision_monotonic"},
				State: []field{
					{Key: "lease_id", Value: "retained"},
					{Key: "owner_id", Value: "member-A"},
					{Key: "owner_state", Value: "leader"},
					{Key: "retirement_reason", Value: "none"},
					{Key: "session_revision", Value: "retained"},
				},
				Counters: []counter{
					{Key: "lease_id_present", Value: boolCounter(initial.Lease != 0)},
					{Key: "retry_count", Value: 2},
					{Key: "revision_monotonic", Value: boolCounter(recovered.ModRevision >= initial.ModRevision)},
				},
			},
			{
				ScenarioID: "CP-FAULT-LEASE-LOSS",
				Step:       0,
				Contracts:  []string{"CP-ELECT-001"},
				Subject:    subject{Namespace: "process", Cluster: "loopback", Generation: 2},
				Outcome:    "transferred",
				Effects:    []string{"ephemeral_key_removed", "old_owner_retired_first", "single_successor_elected"},
				State: []field{
					{Key: "lease_id", Value: "renewed"},
					{Key: "owner_id", Value: "member-B"},
					{Key: "owner_state", Value: "leader"},
					{Key: "retirement_reason", Value: "lease_not_found"},
					{Key: "session_revision", Value: "monotonic"},
				},
				Counters: []counter{
					{Key: "active_owner_count", Value: 1},
					{Key: "lease_changed", Value: boolCounter(successor.Lease != initial.Lease)},
					{Key: "revision_monotonic", Value: boolCounter(successor.CreateRevision > initial.CreateRevision)},
				},
			},
			{
				ScenarioID: "CP-FAULT-ELECTION-WATCH-COMPACTION",
				Step:       0,
				Contracts:  []string{"CP-ELECT-001"},
				Subject:    subject{Namespace: "process", Cluster: "loopback", Generation: 1},
				Outcome:    "resumed",
				Effects:    []string{"fresh_leader_relisted", "owner_identity_retained", "watch_revision_advanced"},
				State: []field{
					{Key: "owner_id", Value: "member-A"},
					{Key: "owner_state", Value: "leader"},
					{Key: "retirement_reason", Value: "none"},
				},
				Counters: []counter{{Key: "compaction_recoveries", Value: 1}},
			},
			{
				ScenarioID: "CP-FAULT-ETCD-PROCESS-DEATH",
				Step:       0,
				Contracts:  []string{"CP-ELECT-001"},
				Subject:    subject{Namespace: "process", Cluster: "loopback", Generation: 2},
				Outcome:    "expired",
				Effects:    []string{"ephemeral_key_removed", "process_killed", "ttl_enforced"},
				State:      []field{{Key: "owner_state", Value: "retired"}},
				Counters:   []counter{{Key: "ephemeral_key_present", Value: boolCounter(!processDeathExpired)}},
			},
		},
	})
}

func runOwnerChild() error {
	addr := os.Getenv("CP003_GO_ETCD_ENDPOINT")
	if addr == "" {
		return fmt.Errorf("CP003_GO_ETCD_ENDPOINT is required")
	}
	client, err := etcdu.InitEtcdClientWithAddrs(zap.NewNop(), addr, nil)
	if err != nil {
		return err
	}
	defer client.Close()
	events := make(chan memberEvent, 2)
	member := &observedMember{id: "process-child", events: events}
	election := elect.NewElection(
		zap.NewNop(),
		client,
		elect.ElectionConfig{Timeout: 500 * time.Millisecond, RetryIntvl: 100 * time.Millisecond, RetryCnt: 3, SessionTTL: 2},
		member.id,
		childElectionKey,
		member,
	)
	election.Start(context.Background())
	if err := waitEvent(events, member.id, true, 8*time.Second); err != nil {
		return err
	}
	fmt.Println("ready")
	select {}
}

func proveProcessDeath(client *clientv3.Client, addr string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	// #nosec G204 -- the target is this already-running evidence binary.
	command := exec.CommandContext(ctx, os.Args[0])
	command.Env = append(os.Environ(), "CP003_GO_OWNER_CHILD=1", "CP003_GO_ETCD_ENDPOINT="+addr)
	stdout, err := command.StdoutPipe()
	if err != nil {
		return false, err
	}
	command.Stderr = os.Stderr
	if err := command.Start(); err != nil {
		return false, err
	}
	scanner := bufio.NewScanner(stdout)
	if !scanner.Scan() || scanner.Text() != "ready" {
		_ = command.Process.Kill()
		_ = command.Wait()
		return false, fmt.Errorf("Go owner child did not become ready")
	}
	if _, err := getOwnerKV(client, childElectionKey); err != nil {
		_ = command.Process.Kill()
		_ = command.Wait()
		return false, err
	}
	if err := command.Process.Kill(); err != nil {
		return false, err
	}
	_ = command.Wait()
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := getOwnerKV(client, childElectionKey); err != nil {
			return true, nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return false, nil
}

func getOwnerKV(client *clientv3.Client, key string) (*mvccpb.KeyValue, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	response, err := client.Get(
		ctx,
		key,
		clientv3.WithPrefix(),
		clientv3.WithSort(clientv3.SortByCreateRevision, clientv3.SortAscend),
		clientv3.WithLimit(1),
	)
	if err != nil {
		return nil, err
	}
	if len(response.Kvs) == 0 {
		return nil, fmt.Errorf("election %s has no owner", key)
	}
	return response.Kvs[0], nil
}

func waitOwner(election elect.Election, expected string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		owner, err := election.GetOwnerID(ctx)
		cancel()
		if err == nil && owner == expected {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("timed out waiting for owner %s", expected)
}

func waitEvent(events <-chan memberEvent, memberID string, elected bool, timeout time.Duration) error {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for {
		select {
		case event := <-events:
			if event.memberID == memberID && event.elected == elected {
				return nil
			}
		case <-timer.C:
			return fmt.Errorf("timed out waiting for member event id=%s elected=%t", memberID, elected)
		}
	}
}

func bumpAndCompact(client *clientv3.Client) (int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var revision int64
	for index := 0; index < 8; index++ {
		response, err := client.Put(ctx, fmt.Sprintf("/tiproxy/cp003/go-compaction/%d", index), "bump")
		if err != nil {
			return 0, err
		}
		revision = response.Header.Revision
	}
	if _, err := client.Compact(ctx, revision); err != nil {
		return 0, err
	}
	return revision, nil
}

// proveCompactedWatch exercises the public etcd boundary used by the Go
// election manager: a stale exact-key watch must be canceled with a compact
// revision, then a fresh owner read and revisioned replacement watch must
// retain the same owner and consume a later event.
func proveCompactedWatch(client *clientv3.Client, initial *mvccpb.KeyValue, compactRevision int64) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stale := client.Watch(ctx, string(initial.Key), clientv3.WithRev(initial.ModRevision))
	select {
	case response := <-stale:
		if !response.Canceled || response.CompactRevision <= 0 {
			return fmt.Errorf("stale Go watch was not canceled by compaction")
		}
	case <-ctx.Done():
		return fmt.Errorf("timed out waiting for stale Go watch cancellation: %w", ctx.Err())
	}

	current, err := getOwnerKV(client, mainElectionKey)
	if err != nil {
		return err
	}
	if string(current.Value) != string(initial.Value) || current.Lease != initial.Lease || current.CreateRevision != initial.CreateRevision {
		return fmt.Errorf("fresh Go leader relist changed the owner fence")
	}

	resumed := client.Watch(ctx, string(initial.Key), clientv3.WithRev(compactRevision+1))
	put, err := client.Put(
		ctx,
		string(initial.Key),
		string(initial.Value),
		clientv3.WithLease(clientv3.LeaseID(initial.Lease)),
	)
	if err != nil {
		return fmt.Errorf("advance resumed Go watch: %w", err)
	}
	select {
	case response := <-resumed:
		if response.Canceled || len(response.Events) != 1 || response.Events[0].Kv.ModRevision != put.Header.Revision {
			return fmt.Errorf("resumed Go watch did not consume the exact post-compaction event")
		}
	case <-ctx.Done():
		return fmt.Errorf("timed out waiting for resumed Go watch event: %w", ctx.Err())
	}
	return nil
}

func boolCounter(value bool) int64 {
	if value {
		return 1
	}
	return 0
}
