// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
	"path/filepath"

	controlpb "github.com/pingcap/tiproxy/pkg/controlbridge/pb"
)

func main() {
	if err := run(); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	root, err := os.Getwd()
	if err != nil {
		return err
	}
	envelope := &controlpb.ControlEnvelope{
		ProtocolVersion:      controlpb.ProtocolV1,
		ControlEpoch:         41,
		Generation:           7,
		RequestId:            99,
		Priority:             controlpb.Priority_PRIORITY_CRITICAL,
		SentUnixMillis:       1_800_000_000_000,
		RequiredCapabilities: []uint64{1, 7, 63},
		Body: &controlpb.ControlEnvelope_Hello{Hello: &controlpb.Hello{
			Role:                     controlpb.Role_ROLE_GO_CONTROL,
			ProcessId:                "go-control-golden",
			ProcessStartedUnixMillis: 1_799_999_999_000,
			SupportedVersions:        []uint32{1, 2},
			Capabilities:             []uint64{1, 3, 7, 63},
			MaxFrameBytes:            controlpb.DefaultMaxFrameBytes,
			BuildVersion:             "v1.0.0-golden",
			BuildCommit:              "0123456789abcdef",
		}},
	}
	if err := writeFrame(root, "go-hello.frame", envelope); err != nil {
		return err
	}
	return writeFrame(root, "go-close.frame", &controlpb.ControlEnvelope{
		ProtocolVersion: controlpb.ProtocolV1,
		ControlEpoch:    42,
		RequestId:       100,
		Priority:        controlpb.Priority_PRIORITY_CRITICAL,
		RequiredCapabilities: []uint64{
			uint64(controlpb.ControlCapability_CONTROL_CAPABILITY_PER_CONNECTION_CLOSE),
		},
		Body: &controlpb.ControlEnvelope_CloseCommand{CloseCommand: &controlpb.CloseCommand{
			ConnectionId: 77,
			CloseId:      "evict-77",
			ErrorSource:  controlpb.ErrorSource_ERROR_SOURCE_SHUTDOWN,
			Reason:       "router eviction",
			Force:        true,
		}},
	})
}

func writeFrame(root, name string, envelope *controlpb.ControlEnvelope) error {
	frame, err := controlpb.MarshalFrame(envelope, controlpb.DefaultMaxFrameBytes)
	if err != nil {
		return err
	}
	path := filepath.Join(root, "proto", "dataplane", "v1", "testdata", name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(path, frame, 0o600); err != nil {
		return err
	}
	fmt.Printf("wrote %s (%d bytes)\n", path, len(frame))
	return nil
}
