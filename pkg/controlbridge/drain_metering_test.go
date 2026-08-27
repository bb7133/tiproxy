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
	"time"

	"github.com/stretchr/testify/require"

	"github.com/pingcap/tiproxy/pkg/balance/router"
	controlpb "github.com/pingcap/tiproxy/pkg/controlbridge/pb"
	"github.com/pingcap/tiproxy/pkg/controlbridge/transport"
)

// mustDrainIssuer builds an issuer or fails the test: crypto/rand is
// healthy in the test environment, so an error is a real defect.
func mustDrainIssuer(t *testing.T) *DrainIssuer {
	t.Helper()
	issuer, err := NewDrainIssuer()
	if err != nil {
		t.Fatalf("NewDrainIssuer: %v", err)
	}
	return issuer
}

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

// epochedSender overrides the fixed epoch so tests can model transport
// reconnects (request ids restart every epoch).
type epochedSender struct {
	recordingSender
	epoch uint64
}

func (sender *epochedSender) Epoch() uint64 { return sender.epoch }

func drainResult(id string, active, graceful, forced uint64, complete bool) *controlpb.DrainResult {
	return &controlpb.DrainResult{
		DrainId:           id,
		ActiveConnections: active,
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
	issuer := mustDrainIssuer(t)
	sender := &recordingSender{}
	command := &controlpb.DrainCommand{
		DrainId:       "d-1",
		ListenerNames: []string{"sql-a"},
	}

	require.NoError(t, issuer.StartDrain(context.Background(), sender, 1, 12, command))
	wireID := sender.sent()[0].GetDrainCommand().GetDrainId()
	require.NotEqual(t, "d-1", wireID, "wire id is incarnation-qualified")
	// Re-issuing the active id is a harmless duplicate command reusing
	// the same wire identity.
	require.NoError(t, issuer.StartDrain(context.Background(), sender, 2, 12, command))
	require.Len(t, sender.sent(), 2)
	require.Equal(t, wireID, sender.sent()[1].GetDrainCommand().GetDrainId())
	// A different id while active never reaches the wire.
	err := issuer.StartDrain(context.Background(), sender, 3, 12, &controlpb.DrainCommand{DrainId: "d-2"})
	require.ErrorIs(t, err, ErrDrainInProgress)
	require.Len(t, sender.sent(), 2)

	// Progress applies idempotently; an out-of-order older result is
	// just replaced by the next observation (absolute counters).
	require.NoError(t, issuer.HandleDrainResult(drainResult(wireID, 2, 1, 0, false)))
	progress, done := issuer.Progress("d-1")
	require.False(t, done)
	require.EqualValues(t, 1, progress.GetGracefullyClosed())

	// A stray result for an unknown id is dropped without effect.
	require.NoError(t, issuer.HandleDrainResult(drainResult("d-9", 10, 5, 5, true)))
	_, known := issuer.Progress("d-9")
	require.False(t, known)

	// The terminal result completes the drain exactly once; duplicates
	// of the terminal replay refresh the completed record harmlessly.
	require.NoError(t, issuer.HandleDrainResult(drainResult(wireID, 2, 1, 1, true)))
	final, done := issuer.Progress("d-1")
	require.True(t, done)
	require.True(t, final.GetComplete())
	require.NoError(t, issuer.HandleDrainResult(drainResult(wireID, 2, 1, 1, true)))
	final, done = issuer.Progress("d-1")
	require.True(t, done)
	require.EqualValues(t, 1, final.GetForceClosed())

	// While idle, re-issuing the completed d-1 id re-sends for a
	// replayed final result instead of restarting a drain.
	require.NoError(t, issuer.StartDrain(context.Background(), sender, 4, 12, command))
	_, done = issuer.Progress("d-1")
	require.True(t, done, "completed drain stays completed")
	// With d-1 terminal, a new drain may start; a completed id's replay
	// re-send stays harmless even while another is active (it can never
	// start anything — the Rust gate replays or proves it obsolete).
	require.NoError(t, issuer.StartDrain(context.Background(), sender, 5, 12, &controlpb.DrainCommand{DrainId: "d-2"}))
	require.NoError(t, issuer.StartDrain(context.Background(), sender, 6, 12, command))
	all := sender.sent()
	replayed := all[len(all)-1].GetDrainCommand()
	require.Equal(t, wireID, replayed.GetDrainId())
	require.EqualValues(t, 1, replayed.GetCommandSequence(), "replay reuses the original binding")
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
	issuer := mustDrainIssuer(t)
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
	rtWire := sent.GetDrainId()
	require.NotEqual(t, "d-rt", rtWire, "wire id is incarnation-qualified")
	require.Equal(t, []string{"tidb-a"}, sent.GetBackendIds())
	require.Equal(t, controlpb.Priority_PRIORITY_CRITICAL, envelopes[0].GetPriority())

	// The Rust gate's progress answer for a duplicate command applies
	// idempotently on this side too, correlated by the wire id.
	require.NoError(t, issuer.HandleDrainResult(drainResult(rtWire, 3, 0, 0, false)))
	require.NoError(t, issuer.HandleDrainResult(drainResult(rtWire, 3, 2, 1, true)))
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
		uint64(controlpb.ControlCapability_CONTROL_CAPABILITY_RECONCILE_CONNECTIONS),
		uint64(controlpb.ControlCapability_CONTROL_CAPABILITY_RECONCILE_SESSION_REHYDRATION))
	// Rust survived a Go restart and reports two live sessions plus a
	// producer metering sequence beyond what this consumer ever saw.
	reconcile := &controlpb.ControlEnvelope{
		RequestId:  60,
		Generation: 12,
		Body: &controlpb.ControlEnvelope_ReconcileRequest{ReconcileRequest: &controlpb.ReconcileRequest{
			KnownGeneration:      12,
			LastMeteringSequence: 9,
			Connections: []*controlpb.ReconcileConnection{
				reconciledConnection(70, "tidb-a:4000", "r-70"),
				reconciledConnection(71, "tidb-a:4000", ""),
			},
		}},
	}
	require.NoError(t, adapter.HandleEnvelope(context.Background(), peer, reconcile))
	snapshot := lastEnvelope(t, peer).GetReconcileSnapshot()
	require.NotNil(t, snapshot)
	require.Empty(t, snapshot.GetConnections(),
		"unrehydratable connections (no router lookup attached) are identified by omission")
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

// Incarnation lineage: two fresh issuers (as after a Go restart, where
// transport epochs can repeat) mint distinct wire ids for the same
// operator label — old wire ids are never reissued — while ONE
// incarnation keeps the same wire id and sequence for its label across
// reconnects/epochs (an epoch change never turns one operation into a
// new one). A previous incarnation's still-active drain is observable
// through the DRAIN_IN_PROGRESS answer instead of being silently lost.
func TestIncarnationLineageForDrainWireIds(t *testing.T) {
	first := mustDrainIssuer(t)
	second := mustDrainIssuer(t)
	senderA := &recordingSender{}
	senderB := &recordingSender{}

	require.NoError(t, first.StartDrain(context.Background(), senderA, 1, 12, &controlpb.DrainCommand{DrainId: "ops-drain"}))
	require.NoError(t, second.StartDrain(context.Background(), senderB, 1, 12, &controlpb.DrainCommand{DrainId: "ops-drain"}))
	wireA := senderA.sent()[0].GetDrainCommand().GetDrainId()
	wireB := senderB.sent()[0].GetDrainCommand().GetDrainId()
	require.NotEqual(t, wireA, wireB,
		"fresh incarnations mint distinct wire ids even at equal epochs")

	// Same incarnation across a reconnect (epoch changes): the label
	// keeps its original wire id and sequence.
	reconnected := &recordingSender{}
	require.NoError(t, first.StartDrain(context.Background(), reconnected, 2, 12, &controlpb.DrainCommand{DrainId: "ops-drain"}))
	resent := reconnected.sent()[0].GetDrainCommand()
	require.Equal(t, wireA, resent.GetDrainId(),
		"one incarnation, one operation: epochs never re-mint the id")
	require.EqualValues(t, 1, resent.GetCommandSequence())

	// The old incarnation's drain still runs on the Rust side: the new
	// incarnation's command is answered DRAIN_IN_PROGRESS naming the old
	// wire id — recorded observably for a later retry.
	require.NoError(t, second.HandleDrainResult(&controlpb.DrainResult{
		DrainId:           wireA,
		ActiveConnections: 3,
		Code:              controlpb.ErrorCode_ERROR_CODE_DRAIN_IN_PROGRESS,
	}))
	foreign := second.ForeignActiveDrain()
	require.NotNil(t, foreign, "the previous incarnation's operation is visible")
	require.Equal(t, wireA, foreign.GetDrainId())
}

// A foreign drain (a previous incarnation's wire id) clears on its
// terminal result and arms the consume-once retry signal — the Rust
// side answers the completion transition proactively, so the observing
// incarnation never has to re-ask.
func TestForeignDrainClearsOnTerminalAndSignalsRetry(t *testing.T) {
	issuer := mustDrainIssuer(t)
	foreign := &controlpb.DrainResult{
		DrainId:           "old@deadbeef",
		ActiveConnections: 3,
		Code:              controlpb.ErrorCode_ERROR_CODE_DRAIN_IN_PROGRESS,
	}
	require.NoError(t, issuer.HandleDrainResult(foreign))
	require.NotNil(t, issuer.ForeignActiveDrain())
	require.Nil(t, issuer.ForeignDrainResolved(), "no terminal observed yet")

	// A terminal for a DIFFERENT unknown wire id clears nothing.
	require.NoError(t, issuer.HandleDrainResult(&controlpb.DrainResult{
		DrainId:  "other@cafe",
		Complete: true,
	}))
	require.NotNil(t, issuer.ForeignActiveDrain())
	require.Nil(t, issuer.ForeignDrainResolved())

	// The foreign drain's own terminal clears the record and arms the
	// retry signal exactly once.
	require.NoError(t, issuer.HandleDrainResult(&controlpb.DrainResult{
		DrainId:           "old@deadbeef",
		ActiveConnections: 3,
		GracefullyClosed:  2,
		ForceClosed:       1,
		Complete:          true,
	}))
	require.Nil(t, issuer.ForeignActiveDrain(), "terminal clears the foreign record")
	resolved := issuer.ForeignDrainResolved()
	require.NotNil(t, resolved, "the retry signal is armed")
	require.Equal(t, "old@deadbeef", resolved.GetDrainId())
	require.Nil(t, issuer.ForeignDrainResolved(), "the retry signal consumes once")
}

func TestProtocolFailureReleasesDrainSlot(t *testing.T) {
	issuer, err := NewDrainIssuer()
	require.NoError(t, err)
	sender := &recordingSender{}
	requestID, err := sender.AllocateRequestID()
	require.NoError(t, err)
	require.NoError(t, issuer.StartDrain(context.Background(), sender, requestID, 7,
		&controlpb.DrainCommand{DrainId: "d-bad"}))

	// The rejected issuance holds the single-flight slot until resolved.
	blockedID, err := sender.AllocateRequestID()
	require.NoError(t, err)
	require.ErrorIs(t, issuer.StartDrain(context.Background(), sender, blockedID, 7,
		&controlpb.DrainCommand{DrainId: "d-next"}), ErrDrainInProgress)

	// An uncorrelated error stays with the generic transport handling.
	require.False(t, issuer.HandleProtocolFailure(1, 99_999, &controlpb.ProtocolError{
		Code: controlpb.ErrorCode_ERROR_CODE_STALE_GENERATION,
	}))

	// The correlated ProtocolError (via offending_request_id) completes
	// the issuance as an observable failure and releases the slot.
	require.True(t, issuer.HandleProtocolFailure(1, 0, &controlpb.ProtocolError{
		Code:               controlpb.ErrorCode_ERROR_CODE_STALE_GENERATION,
		OffendingRequestId: requestID,
		Detail:             "drain minted before applied snapshot",
	}))
	result, completed := issuer.Progress("d-bad")
	require.True(t, completed)
	require.Equal(t, controlpb.ErrorCode_ERROR_CODE_STALE_GENERATION, result.GetCode())

	// The next drain id proceeds on a fresh issuance.
	nextID, err := sender.AllocateRequestID()
	require.NoError(t, err)
	require.NoError(t, issuer.StartDrain(context.Background(), sender, nextID, 7,
		&controlpb.DrainCommand{DrainId: "d-next"}))
}

func TestLateEpochErrorNeverResolvesNewEpochIssuance(t *testing.T) {
	issuer, err := NewDrainIssuer()
	require.NoError(t, err)

	// Epoch 1: drain d-one on request 1 runs to its ordinary terminal.
	epochOne := &epochedSender{epoch: 1}
	firstID, err := epochOne.AllocateRequestID()
	require.NoError(t, err)
	require.NoError(t, issuer.StartDrain(context.Background(), epochOne, firstID, 7,
		&controlpb.DrainCommand{DrainId: "d-one"}))
	sent := epochOne.sent()
	require.Len(t, sent, 1)
	wireID := sent[0].GetDrainCommand().GetDrainId()
	require.NoError(t, issuer.HandleDrainResult(drainResult(wireID, 1, 1, 0, true)))

	// Epoch 2 (reconnect): request ids restart, so drain d-two also
	// sends on request 1.
	epochTwo := &epochedSender{epoch: 2}
	secondID, err := epochTwo.AllocateRequestID()
	require.NoError(t, err)
	require.Equal(t, firstID, secondID, "the collision under test")
	require.NoError(t, issuer.StartDrain(context.Background(), epochTwo, secondID, 8,
		&controlpb.DrainCommand{DrainId: "d-two"}))

	// A late epoch-1 error for request 1 must not touch d-two.
	require.False(t, issuer.HandleProtocolFailure(1, firstID, &controlpb.ProtocolError{
		Code: controlpb.ErrorCode_ERROR_CODE_STALE_GENERATION,
	}))
	_, completed := issuer.Progress("d-two")
	require.False(t, completed, "the new epoch's issuance stays live")

	// The epoch-2 correlated error resolves d-two observably.
	require.True(t, issuer.HandleProtocolFailure(2, secondID, &controlpb.ProtocolError{
		Code: controlpb.ErrorCode_ERROR_CODE_STALE_GENERATION,
	}))
	result, completed := issuer.Progress("d-two")
	require.True(t, completed)
	require.Equal(t, controlpb.ErrorCode_ERROR_CODE_STALE_GENERATION, result.GetCode())
}

func TestStartDrainRejectsInvalidBudgetsBeforeReservation(t *testing.T) {
	bridge := &Bridge{}
	for name, request := range map[string]DrainRequest{
		"negative graceful": {DrainID: "d", GracefulWait: -time.Second},
		"negative force":    {DrainID: "d", ForceTimeout: -time.Second},
		"graceful over cap": {DrainID: "d", GracefulWait: MaxDrainDeadlineAhead + time.Second},
		"force over cap":    {DrainID: "d", ForceTimeout: MaxDrainDeadlineAhead + time.Second},
		"sum over cap": {
			DrainID:      "d",
			GracefulWait: MaxDrainDeadlineAhead - time.Second,
			ForceTimeout: 2 * time.Second,
		},
	} {
		require.ErrorIs(t, bridge.StartDrain(context.Background(), request),
			ErrInvalidDrainBudget, name)
	}
}

func TestStartDrainRejectsBeforeFirstAppliedGeneration(t *testing.T) {
	bridge := &Bridge{publisher: &SnapshotPublisher{}}
	require.ErrorIs(t,
		bridge.StartDrain(context.Background(), DrainRequest{DrainID: "d-early"}),
		ErrSnapshotNotReady)
}

// earlyErrorSender answers every drain send with a synchronous
// correlated ProtocolError BEFORE Send returns — the fastest possible
// error must still find its armed issuance.
type earlyErrorSender struct {
	recordingSender
	issuer *DrainIssuer
	hit    bool
}

func (sender *earlyErrorSender) Send(
	ctx context.Context,
	envelope *controlpb.ControlEnvelope,
) error {
	sender.hit = sender.issuer.HandleProtocolFailure(sender.Epoch(), envelope.GetRequestId(),
		&controlpb.ProtocolError{Code: controlpb.ErrorCode_ERROR_CODE_STALE_GENERATION})
	return sender.recordingSender.Send(ctx, envelope)
}

func TestSynchronousEarlyErrorStillCorrelates(t *testing.T) {
	issuer, err := NewDrainIssuer()
	require.NoError(t, err)
	sender := &earlyErrorSender{issuer: issuer}
	requestID, err := sender.AllocateRequestID()
	require.NoError(t, err)
	require.NoError(t, issuer.StartDrain(context.Background(), sender, requestID, 7,
		&controlpb.DrainCommand{DrainId: "d-early"}))
	require.True(t, sender.hit, "the error arrived before Send returned and still correlated")
	result, completed := issuer.Progress("d-early")
	require.True(t, completed, "the issuance resolved as an observable failure")
	require.Equal(t, controlpb.ErrorCode_ERROR_CODE_STALE_GENERATION, result.GetCode())

	// The slot is free for the next drain id.
	nextID, err := sender.AllocateRequestID()
	require.NoError(t, err)
	require.NoError(t, issuer.StartDrain(context.Background(), &sender.recordingSender, nextID, 7,
		&controlpb.DrainCommand{DrainId: "d-after"}))
}

func TestCompletedDrainReplayLeavesNoCorrelationState(t *testing.T) {
	issuer, err := NewDrainIssuer()
	require.NoError(t, err)
	sender := &recordingSender{}
	firstID, err := sender.AllocateRequestID()
	require.NoError(t, err)
	require.NoError(t, issuer.StartDrain(context.Background(), sender, firstID, 7,
		&controlpb.DrainCommand{DrainId: "d-done"}))
	sent := sender.sent()
	require.Len(t, sent, 1)
	wireID := sent[0].GetDrainCommand().GetDrainId()
	require.NoError(t, issuer.HandleDrainResult(drainResult(wireID, 1, 1, 0, true)))

	// Re-issuing the completed id (the Rust gate replays the terminal)
	// must never accumulate correlation state, however often it runs.
	for i := 0; i < 3; i++ {
		replayID, err := sender.AllocateRequestID()
		require.NoError(t, err)
		require.NoError(t, issuer.StartDrain(context.Background(), sender, replayID, 7,
			&controlpb.DrainCommand{DrainId: "d-done"}))
	}
	issuer.mu.Lock()
	indexSize := len(issuer.requestIndex)
	outstanding := len(issuer.operations[wireID].outstanding)
	issuer.mu.Unlock()
	require.Zero(t, indexSize, "a completed drain's replays arm nothing")
	require.Zero(t, outstanding)

	// The slot is free for the next drain id.
	nextID, err := sender.AllocateRequestID()
	require.NoError(t, err)
	require.NoError(t, issuer.StartDrain(context.Background(), sender, nextID, 7,
		&controlpb.DrainCommand{DrainId: "d-next"}))
}

// terminalDuringSendSender delivers the operation's terminal result
// while Send is still in flight — the arm→re-lock window — so the
// terminal's cleanup runs before the new key exists in its view.
type terminalDuringSendSender struct {
	recordingSender
	issuer *DrainIssuer
}

func (sender *terminalDuringSendSender) Send(
	ctx context.Context,
	envelope *controlpb.ControlEnvelope,
) error {
	_ = sender.issuer.HandleDrainResult(&controlpb.DrainResult{
		DrainId:           envelope.GetDrainCommand().GetDrainId(),
		ActiveConnections: 1,
		GracefullyClosed:  1,
		Complete:          true,
		Code:              controlpb.ErrorCode_ERROR_CODE_OK,
	})
	return sender.recordingSender.Send(ctx, envelope)
}

func TestTerminalDuringSendLeavesNoCorrelationState(t *testing.T) {
	issuer, err := NewDrainIssuer()
	require.NoError(t, err)
	sender := &terminalDuringSendSender{issuer: issuer}
	requestID, err := sender.AllocateRequestID()
	require.NoError(t, err)
	require.NoError(t, issuer.StartDrain(context.Background(), sender, requestID, 7,
		&controlpb.DrainCommand{DrainId: "d-race"}))

	issuer.mu.Lock()
	indexSize := len(issuer.requestIndex)
	var outstanding int
	for _, operation := range issuer.operations {
		outstanding += len(operation.outstanding)
	}
	completed := issuer.activeID == ""
	issuer.mu.Unlock()
	require.Zero(t, indexSize,
		"a terminal landing mid-send leaves no armed key behind")
	require.Zero(t, outstanding)
	require.True(t, completed, "the slot released with the terminal")
}
