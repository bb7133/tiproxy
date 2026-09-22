// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package controlbridge

import (
	"context"
	"fmt"
	"strings"

	controlpb "github.com/pingcap/tiproxy/pkg/controlbridge/pb"
)

// Bounded detail length for protocol diagnostics.
const maxControlDetailBytes = 4 * 1024

// EnvelopeSender is the negotiated control-session surface. Every application
// command allocates from the same checked lineage as heartbeats and
// snapshots; responses reuse the initiating request ID. The small interface
// also permits a deterministic fake Rust peer.
//
// It outlived the legacy RouterAdapter deleted at #223 Phase 2: the residual
// route-owner handler, the snapshot publisher and the metering path all send
// through it.
type EnvelopeSender interface {
	Send(context.Context, *controlpb.ControlEnvelope) error
	Epoch() uint64
	HasCapability(uint64) bool
	AllocateRequestID() (uint64, error)
}

func sendBody(
	ctx context.Context,
	sender EnvelopeSender,
	requestID uint64,
	priority controlpb.Priority,
	body any,
) error {
	return sendBodyWithOptions(ctx, sender, requestID, 0, priority, nil, body)
}

// sendBodyWithOptions serves only the bodies a route-owner process still
// produces. `HandshakeDecision` and `RouteAssignment` were removed with the
// adapter that produced them: under CONTROL_CAPABILITY_RUST_ROUTE_OWNER no
// component may emit either, so an attempt is a programming error here rather
// than a silently well-formed envelope. The v1 schema keeps both as
// tombstones -- this is the producer going away, not the wire contract.
func sendBodyWithOptions(
	ctx context.Context,
	sender EnvelopeSender,
	requestID, generation uint64,
	priority controlpb.Priority,
	required []uint64,
	body any,
) error {
	envelope := &controlpb.ControlEnvelope{
		RequestId:            requestID,
		Generation:           generation,
		Priority:             priority,
		RequiredCapabilities: required,
	}
	switch typed := body.(type) {
	case *controlpb.ControlEnvelope_ReconcileSnapshot:
		envelope.Body = typed
	case *controlpb.ControlEnvelope_Error:
		envelope.Body = typed
	default:
		return fmt.Errorf("unsupported control response %T", body)
	}
	return sender.Send(ctx, envelope)
}

// bounded clamps operator-visible diagnostic text to a fixed budget and
// replaces invalid UTF-8, so a remote detail string cannot inflate a log
// line or carry raw bytes.
func bounded(value string) string {
	value = strings.ToValidUTF8(value, "?")
	if len(value) <= maxControlDetailBytes {
		return value
	}
	return strings.ToValidUTF8(value[:maxControlDetailBytes], "")
}
