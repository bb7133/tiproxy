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

package controlbridge

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	controlpb "github.com/pingcap/tiproxy/pkg/controlbridge/pb"
	"github.com/pingcap/tiproxy/pkg/controlbridge/transport"
	proxymetrics "github.com/pingcap/tiproxy/pkg/metrics"
)

// mustDrainIssuer builds an issuer or fails the test: crypto/rand is
// healthy in the test environment, so an error is a real defect.
type recordingSender struct {
	mu        sync.Mutex
	nextID    uint64
	envelopes []*controlpb.ControlEnvelope
}

func (sender *recordingSender) Send(_ context.Context, envelope *controlpb.ControlEnvelope) error {
	sender.mu.Lock()
	defer sender.mu.Unlock()
	sender.envelopes = append(sender.envelopes, envelope)
	return nil
}

func (sender *recordingSender) Epoch() uint64             { return 1 }
func (sender *recordingSender) HasCapability(uint64) bool { return true }

func (sender *recordingSender) AllocateRequestID() (uint64, error) {
	sender.mu.Lock()
	defer sender.mu.Unlock()
	if sender.nextID == ^uint64(0) {
		return 0, transport.ErrRequestIDExhausted
	}
	sender.nextID++
	return sender.nextID, nil
}

func (sender *recordingSender) sent() []*controlpb.ControlEnvelope {
	sender.mu.Lock()
	defer sender.mu.Unlock()
	return append([]*controlpb.ControlEnvelope(nil), sender.envelopes...)
}

// The consumer applies a batch only when its sequence advances:
// duplicates and reordered replays of already-applied batches change
// nothing (no double counting), and totals accumulate cumulatively per
// dimension. LastApplied feeds the reconcile acknowledgement.
func TestMeteringConsumerDeduplicatesBySequence(t *testing.T) {
	consumer := NewMeteringConsumer()
	batch := func(sequence uint64, bytes uint64) *controlpb.MeteringBatch {
		return &controlpb.MeteringBatch{
			Sequence: sequence,
			Deltas: []*controlpb.MeteringDelta{{
				Keyspace:           "ks-a",
				BackendId:          "tidb-a",
				ResponseBytes:      bytes,
				CrossLocationBytes: bytes / 2,
			}},
		}
	}

	require.True(t, consumer.Apply(batch(1, 100)))
	require.True(t, consumer.Apply(batch(2, 50)))
	response, cross := consumer.Totals("ks-a", "tidb-a", false)
	require.EqualValues(t, 150, response)
	require.EqualValues(t, 75, cross)

	// A replay of an applied batch (at-least-once delivery after a
	// reconnect) never double-counts.
	require.False(t, consumer.Apply(batch(1, 100)))
	require.False(t, consumer.Apply(batch(2, 50)))
	response, _ = consumer.Totals("ks-a", "tidb-a", false)
	require.EqualValues(t, 150, response)

	// Out-of-order old sequences are ignored: the producer replays in
	// order, so a lower sequence after a higher one is already-applied
	// content.
	require.False(t, consumer.Apply(batch(1, 999)))
	require.EqualValues(t, 2, consumer.LastApplied())

	// A gap is refused too — applying 4 before 3 would lose 3 forever.
	// The producer's in-order replay then converges.
	require.False(t, consumer.Apply(batch(4, 7)), "gap refused")
	require.EqualValues(t, 2, consumer.LastApplied())
	require.True(t, consumer.Apply(batch(3, 1)))
	require.True(t, consumer.Apply(batch(4, 7)))
	require.EqualValues(t, 4, consumer.LastApplied())
	response, _ = consumer.Totals("ks-a", "tidb-a", false)
	require.EqualValues(t, 158, response)
}

func TestCompositeHandlerAppliesMetricsWithoutControlFailure(t *testing.T) {
	composite, err := NewRouteOwnerControlHandler(NewMeteringConsumer())
	require.NoError(t, err)
	peer := newFakeSender(61)

	query := proxymetrics.QueryTotalCounter.WithLabelValues("rust-composite-test", "Query")
	queryBefore, err := proxymetrics.ReadCounter(query)
	require.NoError(t, err)
	require.NoError(t, composite.HandleEnvelope(context.Background(), peer, &controlpb.ControlEnvelope{
		RequestId: 1,
		Body: &controlpb.ControlEnvelope_MetricsBatch{MetricsBatch: &controlpb.MetricsBatch{
			Sequence: 1,
			Metrics: []*controlpb.MetricDelta{{
				Name: "tiproxy_session_query_total",
				Labels: map[string]string{
					proxymetrics.LblBackend: "rust-composite-test",
					proxymetrics.LblCmdType: "Query",
				},
				CounterDelta: 2,
			}},
		}},
	}))
	queryAfter, err := proxymetrics.ReadCounter(query)
	require.NoError(t, err)
	require.Equal(t, queryBefore+2, queryAfter)

	invalid := proxymetrics.ServerErrCounter.WithLabelValues("rust_metrics_invalid")
	invalidBefore, err := proxymetrics.ReadCounter(invalid)
	require.NoError(t, err)
	// Unknown metrics are observable but intentionally do not close or fail
	// the control stream: SQL/control work must continue when metrics degrade.
	require.NoError(t, composite.HandleEnvelope(context.Background(), peer, &controlpb.ControlEnvelope{
		RequestId: 2,
		Body: &controlpb.ControlEnvelope_MetricsBatch{MetricsBatch: &controlpb.MetricsBatch{
			Sequence: 2,
			Metrics:  []*controlpb.MetricDelta{{Name: "not_in_the_closed_catalog"}},
		}},
	}))
	invalidAfter, err := proxymetrics.ReadCounter(invalid)
	require.NoError(t, err)
	require.Equal(t, invalidBefore+1, invalidAfter)
}

// The reconcile acknowledgement reports the consumer's actually-applied
// metering sequence, never the producer's claim. This is the only test
// that distinguishes the two: `route_owner_handler_test.go` sends a claim
// equal to the applied value, so it would pass either way.
//
// #223 Phase 2 note: this used to run the Go-restart rehydration direction
// through the legacy RouterAdapter, asserting that unknown Rust sessions
// were identified by omission. A route owner has no route sessions to
// rehydrate and rejects a reconcile carrying connections outright
// (`handleResidualReconcile`), so only the metering half survives, in its
// residual form.
func TestResidualReconcileAcksAppliedMeteringNotTheProducerClaim(t *testing.T) {
	consumer := NewMeteringConsumer()
	for sequence := uint64(1); sequence <= 4; sequence++ {
		require.True(t, consumer.Apply(&controlpb.MeteringBatch{
			Sequence: sequence,
			Deltas: []*controlpb.MeteringDelta{{
				Keyspace: "ks-a", BackendId: "tidb-a", ResponseBytes: 10,
			}},
		}))
	}
	composite, err := NewRouteOwnerControlHandler(consumer)
	require.NoError(t, err)
	peer := newFakeSender(11)

	// The producer claims 9; this consumer only ever applied 4.
	reconcile := &controlpb.ControlEnvelope{
		RequestId:  60,
		Generation: 12,
		Body: &controlpb.ControlEnvelope_ReconcileRequest{ReconcileRequest: &controlpb.ReconcileRequest{
			KnownGeneration:      12,
			LastMeteringSequence: 9,
		}},
	}
	require.NoError(t, composite.HandleEnvelope(context.Background(), peer, reconcile))
	snapshot := lastEnvelope(t, peer).GetReconcileSnapshot()
	require.NotNil(t, snapshot)
	require.EqualValues(t, 4, snapshot.GetMeteringSequence(),
		"the acknowledgement is the consumer's applied sequence, not the producer's claim")
	require.Empty(t, snapshot.GetConnections())

	// Idempotent re-apply: the same request yields the same answer.
	require.NoError(t, composite.HandleEnvelope(context.Background(), peer, reconcile))
	require.EqualValues(t, 4, lastEnvelope(t, peer).GetReconcileSnapshot().GetMeteringSequence())
}
