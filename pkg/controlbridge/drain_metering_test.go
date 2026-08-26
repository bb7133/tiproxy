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

	"github.com/pingcap/tiproxy/pkg/balance/router"
	controlpb "github.com/pingcap/tiproxy/pkg/controlbridge/pb"
)

type recordingSender struct {
	mu        sync.Mutex
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

func (sender *recordingSender) sent() []*controlpb.ControlEnvelope {
	sender.mu.Lock()
	defer sender.mu.Unlock()
	return append([]*controlpb.ControlEnvelope(nil), sender.envelopes...)
}

func drainResult(id string, graceful, forced uint64, complete bool) *controlpb.DrainResult {
	return &controlpb.DrainResult{
		DrainId:           id,
		ActiveConnections: graceful + forced,
		GracefullyClosed:  graceful,
		ForceClosed:       forced,
		Complete:          complete,
		Code:              controlpb.ErrorCode_ERROR_CODE_OK,
	}
}

// The issuer is single-flight: re-issuing the active id re-sends the
// identical command (the Rust gate answers progress), a different id is
// rejected locally, and duplicate/out-of-order results apply
// idempotently with the terminal result completing exactly once.
func TestDrainIssuerSingleFlightAndIdempotentResults(t *testing.T) {
	issuer := NewDrainIssuer()
	sender := &recordingSender{}
	command := &controlpb.DrainCommand{
		DrainId:       "d-1",
		ListenerNames: []string{"sql-a"},
	}

	require.NoError(t, issuer.StartDrain(context.Background(), sender, 1, 12, command))
	// Re-issuing the active id is a harmless duplicate command.
	require.NoError(t, issuer.StartDrain(context.Background(), sender, 2, 12, command))
	require.Len(t, sender.sent(), 2)
	// A different id while active never reaches the wire.
	err := issuer.StartDrain(context.Background(), sender, 3, 12, &controlpb.DrainCommand{DrainId: "d-2"})
	require.ErrorIs(t, err, ErrDrainInProgress)
	require.Len(t, sender.sent(), 2)

	// Progress applies idempotently; an out-of-order older result is
	// just replaced by the next observation (absolute counters).
	require.NoError(t, issuer.HandleDrainResult(drainResult("d-1", 1, 0, false)))
	progress, done := issuer.Progress("d-1")
	require.False(t, done)
	require.EqualValues(t, 1, progress.GetGracefullyClosed())

	// A stray result for an unknown id is dropped without effect.
	require.NoError(t, issuer.HandleDrainResult(drainResult("d-9", 5, 5, true)))
	_, known := issuer.Progress("d-9")
	require.False(t, known)

	// The terminal result completes the drain exactly once; duplicates
	// of the terminal replay refresh the completed record harmlessly.
	require.NoError(t, issuer.HandleDrainResult(drainResult("d-1", 1, 1, true)))
	final, done := issuer.Progress("d-1")
	require.True(t, done)
	require.True(t, final.GetComplete())
	require.NoError(t, issuer.HandleDrainResult(drainResult("d-1", 1, 1, true)))
	final, done = issuer.Progress("d-1")
	require.True(t, done)
	require.EqualValues(t, 1, final.GetForceClosed())

	// While idle, re-issuing the completed d-1 id re-sends for a
	// replayed final result instead of restarting a drain.
	require.NoError(t, issuer.StartDrain(context.Background(), sender, 4, 12, command))
	_, done = issuer.Progress("d-1")
	require.True(t, done, "completed drain stays completed")
	// With d-1 terminal, a new drain may start — and then the completed
	// d-1 id conflicts like any different id (single-flight, matching
	// the Rust gate).
	require.NoError(t, issuer.StartDrain(context.Background(), sender, 5, 12, &controlpb.DrainCommand{DrainId: "d-2"}))
	require.ErrorIs(t, issuer.StartDrain(context.Background(), sender, 6, 12, command), ErrDrainInProgress)
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

// Go↔Rust drain roundtrip at the wire-type level: the command the
// issuer sends is exactly what the Rust gate consumes, and the results
// the Rust gate produces (progress, conflict, replay) drive the issuer
// through its lifecycle. The byte-level codec equivalence is pinned by
// the CTL-02/03 golden corpus; this test fixes the semantic contract.
func TestDrainCommandRoundTripContract(t *testing.T) {
	issuer := NewDrainIssuer()
	sender := &recordingSender{}
	command := &controlpb.DrainCommand{
		DrainId:                    "d-rt",
		BackendIds:                 []string{"tidb-a"},
		GracefulDeadlineUnixMillis: 1_000,
		ForceDeadlineUnixMillis:    2_000,
	}
	require.NoError(t, issuer.StartDrain(context.Background(), sender, 7, 12, command))
	envelopes := sender.sent()
	require.Len(t, envelopes, 1)
	sent := envelopes[0].GetDrainCommand()
	require.NotNil(t, sent)
	require.Equal(t, "d-rt", sent.GetDrainId())
	require.Equal(t, []string{"tidb-a"}, sent.GetBackendIds())
	require.Equal(t, controlpb.Priority_PRIORITY_CRITICAL, envelopes[0].GetPriority())

	// The Rust gate's progress answer for a duplicate command applies
	// idempotently on this side too.
	require.NoError(t, issuer.HandleDrainResult(drainResult("d-rt", 0, 0, false)))
	require.NoError(t, issuer.HandleDrainResult(drainResult("d-rt", 2, 1, true)))
	final, done := issuer.Progress("d-rt")
	require.True(t, done)
	require.EqualValues(t, 3, final.GetActiveConnections())
}

// Go-restart direction of the reconcile contract: a fresh adapter (no
// memory of any Rust session) answers a ReconcileRequest by identifying
// the Rust connections as unknown to this lineage — an empty snapshot —
// without inventing accounting for them or crashing; the Rust side
// preserves those sessions (proven in the Rust model tests). With a
// metering consumer attached, the snapshot acknowledges the consumer's
// actually-applied sequence, not the producer's claim.
func TestGoRestartIdentifiesUnknownConnectionsAndAcksMetering(t *testing.T) {
	rt := router.NewStaticRouter([]string{"tidb-a:4000"})
	handler := &recordingHandler{rt: rt}
	adapter := newTestAdapter(t, handler)
	consumer := NewMeteringConsumer()
	for sequence := uint64(1); sequence <= 4; sequence++ {
		require.True(t, consumer.Apply(&controlpb.MeteringBatch{
			Sequence: sequence,
			Deltas: []*controlpb.MeteringDelta{{
				Keyspace: "ks-a", BackendId: "tidb-a", ResponseBytes: 10,
			}},
		}))
	}
	adapter.AttachMetering(consumer)

	peer := newFakeSender(11,
		uint64(controlpb.ControlCapability_CONTROL_CAPABILITY_RECONCILE_CONNECTIONS))
	// Rust survived a Go restart and reports two live sessions plus a
	// producer metering sequence beyond what this consumer ever saw.
	reconcile := &controlpb.ControlEnvelope{
		RequestId:  60,
		Generation: 12,
		Body: &controlpb.ControlEnvelope_ReconcileRequest{ReconcileRequest: &controlpb.ReconcileRequest{
			KnownGeneration:      12,
			LastMeteringSequence: 9,
			Connections: []*controlpb.ReconcileConnection{
				{ConnectionId: 70, BackendId: "tidb-a:4000", Namespace: "ns-a", RedirectPending: true},
				{ConnectionId: 71, BackendId: "tidb-a:4000", Namespace: "ns-a"},
			},
		}},
	}
	require.NoError(t, adapter.HandleEnvelope(context.Background(), peer, reconcile))
	snapshot := lastEnvelope(t, peer).GetReconcileSnapshot()
	require.NotNil(t, snapshot)
	require.Empty(t, snapshot.GetConnections(),
		"unknown-to-lineage connections are identified by omission, never adopted blindly")
	require.EqualValues(t, 4, snapshot.GetMeteringSequence(),
		"the acknowledgement is the consumer's applied sequence, not the producer's claim")
	require.Equal(t, 0, handler.closeCalls, "no phantom accounting, no negative counts")
	require.Equal(t, 0, rt.ConnCount())

	// Idempotent re-apply: the same request yields the same answer with
	// no accounting drift.
	require.NoError(t, adapter.HandleEnvelope(context.Background(), peer, reconcile))
	require.Equal(t, 0, handler.closeCalls)
	require.Equal(t, 0, rt.ConnCount())
}
