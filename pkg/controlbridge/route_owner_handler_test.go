// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package controlbridge

import (
	"context"
	"testing"

	controlpb "github.com/pingcap/tiproxy/pkg/controlbridge/pb"
	"github.com/stretchr/testify/require"
)

func TestRouteOwnerResidualReconcileIsEmptyAndPreservesWatermarks(t *testing.T) {
	consumer := NewMeteringConsumer()
	require.True(t, consumer.Apply(&controlpb.MeteringBatch{Sequence: 1}))
	handler, err := NewRouteOwnerControlHandler(consumer)
	require.NoError(t, err)
	peer := &recordingSender{}

	envelope := &controlpb.ControlEnvelope{
		RequestId:  9,
		Generation: 17,
		Body: &controlpb.ControlEnvelope_ReconcileRequest{ReconcileRequest: &controlpb.ReconcileRequest{
			KnownGeneration:          17,
			LastMetricsSequence:      21,
			LastMeteringSequence:     1,
			LastDrainCommandSequence: 4,
		}},
	}
	require.NoError(t, handler.HandleEnvelope(t.Context(), peer, envelope))
	sent := peer.sent()
	require.Len(t, sent, 1)
	snapshot := sent[0].GetReconcileSnapshot()
	require.NotNil(t, snapshot)
	require.EqualValues(t, 17, snapshot.GetAppliedGeneration())
	require.Zero(t, snapshot.GetConnectionEventSequence())
	require.EqualValues(t, 21, snapshot.GetMetricsSequence())
	require.EqualValues(t, 1, snapshot.GetMeteringSequence())
	require.Empty(t, snapshot.GetConnections())
	require.Equal(t,
		[]uint64{uint64(controlpb.ControlCapability_CONTROL_CAPABILITY_RUST_ROUTE_OWNER)},
		sent[0].GetRequiredCapabilities())
}

func TestRouteOwnerRejectsEveryRetiredRouteFamilyWithoutState(t *testing.T) {
	handler, err := NewRouteOwnerControlHandler(NewMeteringConsumer())
	require.NoError(t, err)
	peer := &recordingSender{}
	bodies := []any{
		&controlpb.ControlEnvelope_HandshakeResponse{HandshakeResponse: &controlpb.HandshakeResponseEvent{}},
		&controlpb.ControlEnvelope_HandshakeDecision{HandshakeDecision: &controlpb.HandshakeDecision{}},
		&controlpb.ControlEnvelope_HandshakeResult{HandshakeResult: &controlpb.HandshakeResult{}},
		&controlpb.ControlEnvelope_RouteRequest{RouteRequest: &controlpb.RouteRequest{}},
		&controlpb.ControlEnvelope_RouteAssignment{RouteAssignment: &controlpb.RouteAssignment{}},
		&controlpb.ControlEnvelope_RouteResult{RouteResult: &controlpb.RouteResult{}},
		&controlpb.ControlEnvelope_ConnectionEvent{ConnectionEvent: &controlpb.ConnectionEvent{}},
		&controlpb.ControlEnvelope_RedirectCommand{RedirectCommand: &controlpb.RedirectCommand{}},
		&controlpb.ControlEnvelope_RedirectResult{RedirectResult: &controlpb.RedirectResult{}},
		&controlpb.ControlEnvelope_CloseCommand{CloseCommand: &controlpb.CloseCommand{}},
		&controlpb.ControlEnvelope_CloseResult{CloseResult: &controlpb.CloseResult{}},
		&controlpb.ControlEnvelope_ReconcileSnapshot{ReconcileSnapshot: &controlpb.ReconcileSnapshot{}},
	}
	initial := handler.RouteOwnerStatus()
	for index, body := range bodies {
		envelope := &controlpb.ControlEnvelope{RequestId: uint64(index + 1)}
		switch typed := body.(type) {
		case *controlpb.ControlEnvelope_HandshakeResponse:
			envelope.Body = typed
		case *controlpb.ControlEnvelope_HandshakeDecision:
			envelope.Body = typed
		case *controlpb.ControlEnvelope_HandshakeResult:
			envelope.Body = typed
		case *controlpb.ControlEnvelope_RouteRequest:
			envelope.Body = typed
		case *controlpb.ControlEnvelope_RouteAssignment:
			envelope.Body = typed
		case *controlpb.ControlEnvelope_RouteResult:
			envelope.Body = typed
		case *controlpb.ControlEnvelope_ConnectionEvent:
			envelope.Body = typed
		case *controlpb.ControlEnvelope_RedirectCommand:
			envelope.Body = typed
		case *controlpb.ControlEnvelope_RedirectResult:
			envelope.Body = typed
		case *controlpb.ControlEnvelope_CloseCommand:
			envelope.Body = typed
		case *controlpb.ControlEnvelope_CloseResult:
			envelope.Body = typed
		case *controlpb.ControlEnvelope_ReconcileSnapshot:
			envelope.Body = typed
		default:
			t.Fatalf("unhandled body %T", body)
		}
		before := handler.RouteOwnerStatus()
		require.NoError(t, handler.HandleEnvelope(context.Background(), peer, envelope))
		after := handler.RouteOwnerStatus()
		require.Equal(t, before.RouteStateSHA256, after.RouteStateSHA256)
		require.EqualValues(t, before.LegacyRouteViolations+1, after.LegacyRouteViolations)
		answer := peer.sent()[index]
		require.Equal(t, controlpb.ErrorCode_ERROR_CODE_PROTOCOL_VIOLATION, answer.GetError().GetCode())
		require.False(t, answer.GetError().GetFatal())
	}
	final := handler.RouteOwnerStatus()
	require.EqualValues(t, len(bodies), final.LegacyRouteViolations-initial.LegacyRouteViolations)
	require.Equal(t, initial.RouteStateSHA256, final.RouteStateSHA256)
}

func TestRouteOwnerRejectsNonemptyResidualReconcile(t *testing.T) {
	handler, err := NewRouteOwnerControlHandler(NewMeteringConsumer())
	require.NoError(t, err)
	peer := &recordingSender{}
	for _, request := range []*controlpb.ReconcileRequest{
		{LastConnectionEventSequence: 1},
		{Connections: []*controlpb.ReconcileConnection{{ConnectionId: 1}}},
	} {
		before := handler.RouteOwnerStatus()
		require.NoError(t, handler.HandleEnvelope(t.Context(), peer, &controlpb.ControlEnvelope{
			RequestId: 1,
			Body:      &controlpb.ControlEnvelope_ReconcileRequest{ReconcileRequest: request},
		}))
		after := handler.RouteOwnerStatus()
		require.EqualValues(t, before.LegacyRouteViolations+1, after.LegacyRouteViolations)
		require.Equal(t, before.RouteStateSHA256, after.RouteStateSHA256)
	}
}

// CP-ADMIN slice 3b: operator drains are issued inside the Rust process, so
// both drain bodies are retired tombstones for the route owner. Each is
// answered with a nonfatal PROTOCOL_VIOLATION on the one legacy-violation
// counter and leaves the route state hash (and everything else) untouched;
// the reconcile watermark they used to feed is diagnostic only.
func TestRouteOwnerRejectsRetiredDrainBodiesWithoutState(t *testing.T) {
	handler, err := NewRouteOwnerControlHandler(NewMeteringConsumer())
	require.NoError(t, err)
	peer := &recordingSender{}
	initial := handler.RouteOwnerStatus()
	bodies := []any{
		&controlpb.ControlEnvelope_DrainCommand{DrainCommand: &controlpb.DrainCommand{DrainId: "op@retired", CommandSequence: 1}},
		&controlpb.ControlEnvelope_DrainResult{DrainResult: &controlpb.DrainResult{DrainId: "op@retired", Complete: true}},
	}
	for index, body := range bodies {
		envelope := &controlpb.ControlEnvelope{RequestId: uint64(index + 1)}
		switch typed := body.(type) {
		case *controlpb.ControlEnvelope_DrainCommand:
			envelope.Body = typed
		case *controlpb.ControlEnvelope_DrainResult:
			envelope.Body = typed
		}
		require.NoError(t, handler.HandleEnvelope(t.Context(), peer, envelope))
		answer := peer.sent()[index]
		require.EqualValues(t, index+1, answer.GetError().GetOffendingRequestId())
		require.Equal(t, controlpb.ErrorCode_ERROR_CODE_PROTOCOL_VIOLATION, answer.GetError().GetCode())
		require.False(t, answer.GetError().GetFatal())
	}
	final := handler.RouteOwnerStatus()
	require.EqualValues(t, len(bodies), final.LegacyRouteViolations-initial.LegacyRouteViolations)
	require.Equal(t, initial.RouteStateSHA256, final.RouteStateSHA256)

	// The reconcile watermark is still answered, never restored into an issuer.
	require.NoError(t, handler.HandleEnvelope(t.Context(), peer, &controlpb.ControlEnvelope{
		RequestId: 9,
		Body: &controlpb.ControlEnvelope_ReconcileRequest{ReconcileRequest: &controlpb.ReconcileRequest{
			KnownGeneration: 3, LastDrainCommandSequence: 4,
		}},
	}))
	require.NotNil(t, peer.sent()[len(bodies)].GetReconcileSnapshot())
	require.EqualValues(t, final.LegacyRouteViolations, handler.RouteOwnerStatus().LegacyRouteViolations)
}

func TestNativeMeterOwnerHasNoConsumerAndRejectsRetiredMetering(t *testing.T) {
	handler, err := NewNativeMeterOwnerControlHandler()
	require.NoError(t, err)
	require.Nil(t, handler.consumer)
	peer := &recordingSender{}
	for _, envelope := range []*controlpb.ControlEnvelope{
		{RequestId: 1, Body: &controlpb.ControlEnvelope_MeteringBatch{MeteringBatch: &controlpb.MeteringBatch{ProducerId: "producer", Sequence: 1}}},
		{RequestId: 2, Body: &controlpb.ControlEnvelope_MeteringAck{MeteringAck: &controlpb.MeteringAck{ProducerId: "producer", Sequence: 1}}},
	} {
		require.NoError(t, handler.HandleEnvelope(t.Context(), peer, envelope))
	}
	require.EqualValues(t, 2, handler.legacyMeterViolations.Load())
	for _, sent := range peer.sent() {
		require.NotNil(t, sent.GetError())
		require.Nil(t, sent.GetMeteringAck())
		require.Nil(t, sent.GetMeteringBatch())
	}
	require.NoError(t, handler.HandleEnvelope(t.Context(), peer, &controlpb.ControlEnvelope{RequestId: 3, Body: &controlpb.ControlEnvelope_ReconcileRequest{ReconcileRequest: &controlpb.ReconcileRequest{LastMeteringSequence: 99}}}))
	require.Zero(t, peer.sent()[2].GetReconcileSnapshot().GetMeteringSequence())
}

func TestNativeAPIOwnerRejectsRetiredMetricsBatch(t *testing.T) {
	handler, err := NewNativeMeterOwnerControlHandler()
	require.NoError(t, err)
	handler.nativeAPIOwner = true
	peer := &recordingSender{}
	require.NoError(t, handler.HandleEnvelope(t.Context(), peer, &controlpb.ControlEnvelope{
		RequestId: 7,
		Body:      &controlpb.ControlEnvelope_MetricsBatch{MetricsBatch: &controlpb.MetricsBatch{Sequence: 1}},
	}))
	require.EqualValues(t, 1, handler.legacyMetricsViolations.Load())
	require.Len(t, peer.sent(), 1)
	rejection := peer.sent()[0].GetError()
	require.NotNil(t, rejection)
	require.Equal(t, controlpb.ErrorCode_ERROR_CODE_PROTOCOL_VIOLATION, rejection.GetCode())
	require.EqualValues(t, 7, rejection.GetOffendingRequestId())
	require.Equal(t, "retired metrics message under RUST_API_OWNER", rejection.GetDetail())

	// Without API ownership the batch keeps its legacy handling.
	legacy, err := NewNativeMeterOwnerControlHandler()
	require.NoError(t, err)
	require.NoError(t, legacy.HandleEnvelope(t.Context(), peer, &controlpb.ControlEnvelope{
		RequestId: 8,
		Body:      &controlpb.ControlEnvelope_MetricsBatch{MetricsBatch: &controlpb.MetricsBatch{Sequence: 1}},
	}))
	require.Zero(t, legacy.legacyMetricsViolations.Load())
	require.Len(t, peer.sent(), 1)
}

func TestNativeAPIOwnerRequiresRouteOwner(t *testing.T) {
	_, err := NewBridge(BridgeConfig{NativeAPIOwner: true})
	require.ErrorContains(t, err, "native API ownership requires route owner")
}

func TestNativeMeterOwnerRejectsGoStateOrLegacyComposition(t *testing.T) {
	for _, config := range []BridgeConfig{
		{NativeMeterOwner: true},
		{NativeMeterOwner: true, RouteOwner: true, MeteringStatePath: "must-not-open"},
	} {
		_, err := NewBridge(config)
		require.ErrorContains(t, err, "native metering requires route owner and no Go metering state or sink")
	}
}
