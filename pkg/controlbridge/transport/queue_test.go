// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"context"
	"errors"
	"testing"
	"time"

	controlpb "github.com/pingcap/tiproxy/pkg/controlbridge/pb"
	"github.com/stretchr/testify/require"
)

func TestQueuePressureAndPriority(t *testing.T) {
	limits := QueueLimits{
		Critical: QueueLimit{Messages: 32, Bytes: 64 * 1024},
		Control:  QueueLimit{Messages: 2, Bytes: 64 * 1024},
		Bulk:     QueueLimit{Messages: 1, Bytes: 64 * 1024},
	}
	queues := newOutboundQueues(limits)
	t.Cleanup(queues.close)

	bulkMetric := envelopeWithPriority(controlpb.Priority_PRIORITY_BULK, &controlpb.ControlEnvelope_MetricsBatch{
		MetricsBatch: &controlpb.MetricsBatch{Sequence: 1},
	})
	require.NoError(t, queues.enqueue(t.Context(), bulkMetric))
	require.ErrorIs(t, queues.enqueue(t.Context(), bulkMetric), ErrMetricsDropped)

	metering := envelopeWithPriority(controlpb.Priority_PRIORITY_BULK, &controlpb.ControlEnvelope_MeteringBatch{
		MeteringBatch: &controlpb.MeteringBatch{Sequence: 2},
	})
	pushDone := make(chan error, 1)
	go func() {
		pushDone <- queues.enqueue(t.Context(), metering)
	}()
	select {
	case err := <-pushDone:
		require.Failf(t, "metering enqueue returned before space", "error: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	first, err := queues.next(t.Context())
	require.NoError(t, err)
	require.NotNil(t, first.GetMetricsBatch())
	require.NoError(t, <-pushDone)

	for id := uint64(1); id <= 17; id++ {
		require.NoError(t, queues.enqueue(t.Context(), envelopeWithPriority(
			controlpb.Priority_PRIORITY_CRITICAL,
			&controlpb.ControlEnvelope_Heartbeat{Heartbeat: &controlpb.Heartbeat{LastReceivedRequestId: id}},
		)))
	}
	require.NoError(t, queues.enqueue(t.Context(), envelopeWithPriority(
		controlpb.Priority_PRIORITY_CONTROL,
		&controlpb.ControlEnvelope_DrainCommand{DrainCommand: &controlpb.DrainCommand{DrainId: "drain"}},
	)))
	for range 16 {
		next, err := queues.next(t.Context())
		require.NoError(t, err)
		require.NotNil(t, next.GetHeartbeat())
	}
	next, err := queues.next(t.Context())
	require.NoError(t, err)
	require.NotNil(t, next.GetDrainCommand())
}

func TestQueueCancellationAndByteLimit(t *testing.T) {
	limits := QueueLimits{
		Critical: QueueLimit{Messages: 1, Bytes: 16},
		Control:  QueueLimit{Messages: 1, Bytes: 16},
		Bulk:     QueueLimit{Messages: 1, Bytes: 16},
	}
	queues := newOutboundQueues(limits)
	tooLarge := envelopeWithPriority(controlpb.Priority_PRIORITY_CONTROL, &controlpb.ControlEnvelope_Error{
		Error: &controlpb.ProtocolError{Detail: "this envelope is deliberately larger than sixteen bytes"},
	})
	require.ErrorIs(t, queues.enqueue(t.Context(), tooLarge), ErrQueueFull)

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := queues.next(ctx)
	require.ErrorIs(t, err, context.Canceled)
	queues.close()
	require.ErrorIs(t, queues.enqueue(t.Context(), envelopeWithPriority(
		controlpb.Priority_PRIORITY_CRITICAL,
		&controlpb.ControlEnvelope_Heartbeat{Heartbeat: &controlpb.Heartbeat{}},
	)), ErrTransportClosed)
	_, err = queues.next(t.Context())
	require.True(t, errors.Is(err, ErrTransportClosed))
}

func envelopeWithPriority(priority controlpb.Priority, body any) *controlpb.ControlEnvelope {
	envelope := &controlpb.ControlEnvelope{Priority: priority}
	switch message := body.(type) {
	case *controlpb.ControlEnvelope_MetricsBatch:
		envelope.Body = message
	case *controlpb.ControlEnvelope_MeteringBatch:
		envelope.Body = message
	case *controlpb.ControlEnvelope_Heartbeat:
		envelope.Body = message
	case *controlpb.ControlEnvelope_DrainCommand:
		envelope.Body = message
	case *controlpb.ControlEnvelope_Error:
		envelope.Body = message
	default:
		panic("unsupported test envelope body")
	}
	return envelope
}
