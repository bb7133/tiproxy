// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

// Command go-observer drives the production Go consumer and durable meter.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/pingcap/tiproxy/lib/config"
	"github.com/pingcap/tiproxy/pkg/controlbridge"
	pb "github.com/pingcap/tiproxy/pkg/controlbridge/pb"
	"github.com/pingcap/tiproxy/pkg/manager/meter"
	"go.uber.org/zap"
)

type source struct {
	Key      struct{ ConnectionID, ProcessGeneration, BackendGeneration uint64 }
	Baseline struct {
		BackendID, ClusterName, Keyspace                                 string
		Local, PublicEndpoint                                            bool
		InboundBytes, OutboundBytes, InboundWrapEpoch, OutboundWrapEpoch uint64
	}
	Final bool `json:"final_sample"`
}
type event struct {
	Reopen bool `json:"reopen"`
	Batch  struct {
		Producer  string   `json:"producer_id"`
		Sequence  uint64   `json:"sequence"`
		Snapshots []source `json:"snapshots"`
	} `json:"batch"`
}

func run() error {
	if len(os.Args) != 3 {
		return fmt.Errorf("usage: go-observer STATE_DIR EVENTS_JSON")
	}
	dir, err := filepath.Abs(os.Args[1])
	if err != nil {
		return err
	}
	data, err := os.ReadFile(os.Args[2])
	if err != nil {
		return err
	}
	var events []event
	if err := json.Unmarshal(data, &events); err != nil {
		return err
	}
	cfg := config.NewConfig()
	cfg.Workdir = dir
	cfg.Metering.WithLocalFS(filepath.Join(dir, "objects"))
	cfg.Metering.Bucket = "parity-test"
	consumerPath := filepath.Join(dir, "consumer.json")
	outboxPath := filepath.Join(dir, "run", "metering-outbox.json")
	open := func() (*controlbridge.MeteringConsumer, error) {
		sink, err := meter.NewMeter(cfg, zap.NewNop())
		if err != nil {
			return nil, err
		}
		// Do not Start/Close: Close flushes; this observer only exercises durable ingestion.
		return controlbridge.OpenMeteringConsumer(consumerPath, sink)
	}
	consumer, err := open()
	if err != nil {
		return err
	}
	observations := make([]map[string]any, 0, len(events))
	for _, e := range events {
		var applied any
		var applyErr error
		if e.Reopen {
			consumer, err = open()
			if err != nil {
				return err
			}
		} else {
			batch := &pb.MeteringBatch{ProducerId: e.Batch.Producer, Sequence: e.Batch.Sequence}
			for _, s := range e.Batch.Snapshots {
				b, k := s.Baseline, s.Key
				batch.Snapshots = append(batch.Snapshots, &pb.MeteringSourceSnapshot{
					ConnectionId: k.ConnectionID, ProcessGeneration: k.ProcessGeneration, BackendGeneration: k.BackendGeneration,
					BackendId: b.BackendID, ClusterName: b.ClusterName, Keyspace: b.Keyspace, Local: b.Local, PublicEndpoint: b.PublicEndpoint,
					BackendInboundBytes: b.InboundBytes, BackendOutboundBytes: b.OutboundBytes,
					InboundWrapEpoch: b.InboundWrapEpoch, OutboundWrapEpoch: b.OutboundWrapEpoch, Final: s.Final,
				})
			}
			applied, applyErr = consumer.ApplyAbsolute(batch)
		}
		state := map[string]any{"applied": applied, "error": applyErr != nil, "healthy": consumer.Healthy()}
		for name, path := range map[string]string{"consumer": consumerPath, "outbox": outboxPath} {
			value, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			state[name] = json.RawMessage(value)
		}
		observations = append(observations, state)
	}
	return json.NewEncoder(os.Stdout).Encode(observations)
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
