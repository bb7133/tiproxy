// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package controlbridge

import (
	"context"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	controlpb "github.com/pingcap/tiproxy/pkg/controlbridge/pb"
)

type durableSinkStub struct {
	producer string
	last     uint64
	deltas   []MeteringDelta
	fail     bool
}

type legacySinkStub struct{}

func (*legacySinkStub) IncTraffic(string, int64, int64, bool) {}

func (sink *durableSinkStub) IncTraffic(string, int64, int64, bool) {}

func (sink *durableSinkStub) ApplyMeteringBatch(
	producer string,
	sequence uint64,
	deltas []MeteringDelta,
) error {
	if sink.fail {
		return errMeteringSinkTest
	}
	if sink.producer == producer && sequence <= sink.last {
		return nil
	}
	if sink.producer != "" && sink.producer != producer {
		return errMeteringSinkTest
	}
	sink.producer = producer
	sink.last = sequence
	sink.deltas = append(sink.deltas, deltas...)
	return nil
}

func (sink *durableSinkStub) Healthy() bool { return !sink.fail }

func (sink *durableSinkStub) MeteringCheckpoint() (string, uint64) {
	return sink.producer, sink.last
}

type meteringSinkTestError struct{}

func (meteringSinkTestError) Error() string { return "metering sink test failure" }

var errMeteringSinkTest = meteringSinkTestError{}

const testMeteringProducerID = "0123456789abcdef0123456789abcdef"

func absoluteBatch(sequence uint64, snapshots ...*controlpb.MeteringSourceSnapshot) *controlpb.MeteringBatch {
	return &controlpb.MeteringBatch{
		Sequence:   sequence,
		ProducerId: testMeteringProducerID,
		Snapshots:  snapshots,
	}
}

func absoluteSnapshot(connectionID, processGeneration, backendGeneration, inbound, outbound uint64) *controlpb.MeteringSourceSnapshot {
	return &controlpb.MeteringSourceSnapshot{
		ConnectionId:         connectionID,
		ProcessGeneration:    processGeneration,
		BackendGeneration:    backendGeneration,
		BackendId:            "backend-a",
		ClusterName:          "cluster-a",
		Keyspace:             "keyspace-a",
		Local:                false,
		PublicEndpoint:       true,
		BackendInboundBytes:  inbound,
		BackendOutboundBytes: outbound,
	}
}

func TestAbsoluteMeteringDeltasRedirectFinalAndRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "consumer.json")
	sink := &durableSinkStub{}
	consumer, err := OpenMeteringConsumer(path, sink)
	require.NoError(t, err)

	first := absoluteSnapshot(11, 7, 1, 100, 40)
	applied, err := consumer.ApplyAbsolute(absoluteBatch(1, first))
	require.NoError(t, err)
	require.True(t, applied)
	response, cross := consumer.Totals("keyspace-a", "backend-a", true)
	require.EqualValues(t, 100, response)
	require.EqualValues(t, 140, cross)

	second := absoluteSnapshot(11, 7, 1, 150, 60)
	applied, err = consumer.ApplyAbsolute(absoluteBatch(2, second))
	require.NoError(t, err)
	require.True(t, applied)
	response, cross = consumer.Totals("keyspace-a", "backend-a", true)
	require.EqualValues(t, 150, response)
	require.EqualValues(t, 210, cross)

	oldFinal := absoluteSnapshot(11, 7, 1, 170, 80)
	oldFinal.Final = true
	newBackend := absoluteSnapshot(11, 7, 2, 5, 7)
	newBackend.BackendId = "backend-b"
	newBackend.Local = true
	newBackend.PublicEndpoint = false
	applied, err = consumer.ApplyAbsolute(absoluteBatch(3, oldFinal, newBackend))
	require.NoError(t, err)
	require.True(t, applied)
	response, cross = consumer.Totals("keyspace-a", "backend-a", true)
	require.EqualValues(t, 170, response)
	require.EqualValues(t, 250, cross)
	response, cross = consumer.Totals("keyspace-a", "backend-b", false)
	require.EqualValues(t, 5, response)
	require.Zero(t, cross, "local traffic never contributes cross-location bytes")

	newFinal := absoluteSnapshot(11, 7, 2, 25, 17)
	newFinal.BackendId = "backend-b"
	newFinal.Local = true
	newFinal.PublicEndpoint = false
	newFinal.Final = true
	applied, err = consumer.ApplyAbsolute(absoluteBatch(4, newFinal))
	require.NoError(t, err)
	require.True(t, applied)
	response, cross = consumer.Totals("keyspace-a", "backend-b", false)
	require.EqualValues(t, 25, response)
	require.Zero(t, cross)

	// Restart reloads producer, sequence, active baselines, and cumulative
	// totals. Duplicate delivery is re-ACKable and cannot double count. Final
	// source baselines are garbage-collected, so durable state stays bounded by
	// active sources rather than lifetime connections.
	restarted, err := OpenMeteringConsumer(path, sink)
	require.NoError(t, err)
	applied, err = restarted.ApplyAbsolute(absoluteBatch(4, newFinal))
	require.NoError(t, err)
	require.False(t, applied)
	response, _ = restarted.Totals("keyspace-a", "backend-b", false)
	require.EqualValues(t, 25, response)
	require.Empty(t, restarted.sources)
}

func TestAbsoluteMeteringHealthIncludesDurableSink(t *testing.T) {
	sink := &durableSinkStub{}
	consumer, err := OpenMeteringConsumer(filepath.Join(t.TempDir(), "consumer.json"), sink)
	require.NoError(t, err)
	require.True(t, consumer.Healthy())

	sink.fail = true
	require.False(t, consumer.Healthy(), "asynchronous meter failure degrades readiness")
}

func TestAbsoluteMeteringRejectsDurableSinkCheckpointLoss(t *testing.T) {
	path := filepath.Join(t.TempDir(), "consumer.json")
	sink := &durableSinkStub{}
	consumer, err := OpenMeteringConsumer(path, sink)
	require.NoError(t, err)
	_, err = consumer.ApplyAbsolute(absoluteBatch(1, absoluteSnapshot(1, 1, 1, 12, 3)))
	require.NoError(t, err)

	_, err = OpenMeteringConsumer(path, &durableSinkStub{})
	require.ErrorContains(t, err, "checkpoint does not match")
}

func TestAbsoluteMeteringRejectsNonDurableSink(t *testing.T) {
	_, err := OpenMeteringConsumer(filepath.Join(t.TempDir(), "consumer.json"), &legacySinkStub{})
	require.ErrorContains(t, err, "requires a durable sink")
}

func TestAbsoluteMeteringRejectsUnknownPersistedTotal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "consumer.json")
	content, err := json.Marshal(meteringConsumerDiskState{
		Version:           meteringConsumerStateVersion,
		ProducerID:        testMeteringProducerID,
		LastApplied:       1,
		ProcessGeneration: 1,
		Totals: []persistedMeteringTotal{{
			BackendID: "backend-a",
		}},
	})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, content, 0o600))
	_, err = OpenMeteringConsumer(path, &durableSinkStub{
		producer: testMeteringProducerID,
		last:     1,
	})
	require.ErrorContains(t, err, "unknown total attribution")
}

func TestAbsoluteMeteringNewProcessGenerationPrunesCrashedSources(t *testing.T) {
	consumer, err := OpenMeteringConsumer(filepath.Join(t.TempDir(), "consumer.json"), nil)
	require.NoError(t, err)
	old := absoluteSnapshot(1, 7, 1, 10, 2)
	_, err = consumer.ApplyAbsolute(absoluteBatch(1, old))
	require.NoError(t, err)
	require.Len(t, consumer.sources, 1)

	current := absoluteSnapshot(1, 9, 1, 3, 1)
	_, err = consumer.ApplyAbsolute(absoluteBatch(2, current))
	require.NoError(t, err)
	require.EqualValues(t, 9, consumer.processGeneration)
	require.Len(t, consumer.sources, 1)
	for key := range consumer.sources {
		require.EqualValues(t, 9, key.ProcessGeneration)
	}
	response, cross := consumer.Totals("keyspace-a", "backend-a", true)
	require.EqualValues(t, 13, response)
	require.EqualValues(t, 16, cross)

	regressed := absoluteSnapshot(2, 8, 1, 1, 1)
	_, err = consumer.ApplyAbsolute(absoluteBatch(3, regressed))
	require.ErrorContains(t, err, "process generation regressed")
}

func TestAbsoluteMeteringRejectsUnknownGapMutationAndHandlesWrap(t *testing.T) {
	consumer, err := OpenMeteringConsumer(filepath.Join(t.TempDir(), "consumer.json"), nil)
	require.NoError(t, err)

	unknown := absoluteSnapshot(1, 1, 1, 1, 1)
	unknown.BackendId = ""
	_, err = consumer.ApplyAbsolute(absoluteBatch(1, unknown))
	require.ErrorContains(t, err, "unknown attribution")
	unknown = absoluteSnapshot(1, 1, 1, 1, 1)
	unknown.Keyspace = ""
	_, err = consumer.ApplyAbsolute(absoluteBatch(1, unknown))
	require.ErrorContains(t, err, "unknown attribution")

	first := absoluteSnapshot(1, 1, 1, math.MaxUint64-5, 0)
	first.Local = true
	_, err = consumer.ApplyAbsolute(absoluteBatch(1, first))
	require.NoError(t, err)

	gap := absoluteSnapshot(1, 1, 1, math.MaxUint64-4, 0)
	_, err = consumer.ApplyAbsolute(absoluteBatch(3, gap))
	require.ErrorContains(t, err, "sequence gap")

	mutated := absoluteSnapshot(1, 1, 1, math.MaxUint64-4, 0)
	mutated.Keyspace = "wrong"
	_, err = consumer.ApplyAbsolute(absoluteBatch(2, mutated))
	require.ErrorContains(t, err, "attribution mutated")

	wrapped := absoluteSnapshot(1, 1, 1, 3, 0)
	wrapped.Local = true
	wrapped.InboundWrapEpoch = 1
	_, err = consumer.ApplyAbsolute(absoluteBatch(2, wrapped))
	require.NoError(t, err)
	response, _ := consumer.Totals("keyspace-a", "backend-a", true)
	require.Equal(t, uint64(math.MaxUint64), response, "diagnostic lifetime total saturates")
}

func TestAbsoluteMeteringPendingSurvivesSinkFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "consumer.json")
	failing := &durableSinkStub{}
	consumer, err := OpenMeteringConsumer(path, failing)
	require.NoError(t, err)
	failing.fail = true
	_, err = consumer.ApplyAbsolute(absoluteBatch(1, absoluteSnapshot(1, 1, 1, 12, 3)))
	require.ErrorContains(t, err, "persist metering sink batch")
	require.False(t, consumer.Healthy())

	recoveredSink := &durableSinkStub{}
	restarted, err := OpenMeteringConsumer(path, recoveredSink)
	require.NoError(t, err)
	applied, err := restarted.ApplyAbsolute(absoluteBatch(1, absoluteSnapshot(1, 1, 1, 12, 3)))
	require.NoError(t, err)
	require.False(t, applied, "durable duplicate only drains pending work")
	require.EqualValues(t, 1, recoveredSink.last)
	require.Len(t, recoveredSink.deltas, 1)
}

func TestCompositeExplicitMeteringAck(t *testing.T) {
	consumer, err := OpenMeteringConsumer(filepath.Join(t.TempDir(), "consumer.json"), nil)
	require.NoError(t, err)
	adapter := newTestAdapter(t, &recordingHandler{})
	composite, err := NewCompositeControlHandler(adapter, mustDrainIssuer(t), consumer)
	require.NoError(t, err)
	sender := &recordingSender{}
	batch := absoluteBatch(1, absoluteSnapshot(1, 1, 1, 8, 2))
	require.NoError(t, composite.HandleEnvelope(context.Background(), sender, &controlpb.ControlEnvelope{
		Body: &controlpb.ControlEnvelope_MeteringBatch{MeteringBatch: batch},
	}))
	require.Len(t, sender.sent(), 1)
	ack := sender.sent()[0]
	require.Equal(t, controlpb.Priority_PRIORITY_CRITICAL, ack.GetPriority())
	require.Equal(t, testMeteringProducerID, ack.GetMeteringAck().GetProducerId())
	require.EqualValues(t, 1, ack.GetMeteringAck().GetSequence())
}

func TestCompositeMeteringFailureSendsFatalInsteadOfDisconnectOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "consumer.json")
	sink := &durableSinkStub{}
	consumer, err := OpenMeteringConsumer(path, sink)
	require.NoError(t, err)
	sink.fail = true
	adapter := newTestAdapter(t, &recordingHandler{})
	composite, err := NewCompositeControlHandler(adapter, mustDrainIssuer(t), consumer)
	require.NoError(t, err)
	sender := &recordingSender{}

	err = composite.HandleEnvelope(context.Background(), sender, &controlpb.ControlEnvelope{
		RequestId: 77,
		Body: &controlpb.ControlEnvelope_MeteringBatch{
			MeteringBatch: absoluteBatch(1, absoluteSnapshot(1, 1, 1, 8, 2)),
		},
	})
	require.NoError(t, err, "fatal signal stays on the live session until Rust receives it")
	require.Len(t, sender.sent(), 1)
	fatal := sender.sent()[0]
	require.Equal(t, controlpb.Priority_PRIORITY_CRITICAL, fatal.GetPriority())
	require.EqualValues(t, 77, fatal.GetRequestId())
	require.Equal(t, []uint64{
		uint64(controlpb.ControlCapability_CONTROL_CAPABILITY_METERING_ABSOLUTE_SNAPSHOTS),
	}, fatal.GetRequiredCapabilities())
	require.Equal(t, controlpb.ErrorCode_ERROR_CODE_INTERNAL, fatal.GetError().GetCode())
	require.EqualValues(t, 77, fatal.GetError().GetOffendingRequestId())
	require.True(t, fatal.GetError().GetFatal())
	require.False(t, consumer.Healthy())
}

func TestCompositeMeteringAckAllocatorFailureAlsoSendsFatal(t *testing.T) {
	consumer, err := OpenMeteringConsumer(filepath.Join(t.TempDir(), "consumer.json"), nil)
	require.NoError(t, err)
	adapter := newTestAdapter(t, &recordingHandler{})
	composite, err := NewCompositeControlHandler(adapter, mustDrainIssuer(t), consumer)
	require.NoError(t, err)
	sender := &recordingSender{nextID: ^uint64(0)}

	err = composite.HandleEnvelope(context.Background(), sender, &controlpb.ControlEnvelope{
		RequestId: 88,
		Body: &controlpb.ControlEnvelope_MeteringBatch{
			MeteringBatch: absoluteBatch(1, absoluteSnapshot(1, 1, 1, 8, 2)),
		},
	})
	require.NoError(t, err)
	require.Len(t, sender.sent(), 1)
	require.True(t, sender.sent()[0].GetError().GetFatal())
	require.EqualValues(t, 88, sender.sent()[0].GetError().GetOffendingRequestId())
}
