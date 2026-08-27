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
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"

	"google.golang.org/protobuf/proto"

	"github.com/pingcap/tiproxy/lib/util/errors"
	controlpb "github.com/pingcap/tiproxy/pkg/controlbridge/pb"
	"github.com/pingcap/tiproxy/pkg/controlbridge/transport"
)

// DrainIssuer owns the Go side of scoped drain (CTL-06): it issues
// DrainCommand envelopes keyed by drain_id and consumes DrainResult
// progress idempotently. One drain is in flight at a time, matching the
// Rust gate's single-flight rule; re-sending the active id is harmless
// (the Rust side answers current progress), and a different id while
// one is active is rejected locally before any envelope is sent.
type DrainIssuer struct {
	mu sync.Mutex
	// incarnation is a random 128-bit boot nonce minted at construction:
	// the issuer-incarnation identity that makes wire ids unique across
	// Go process restarts. Control epochs are NOT a restart identity
	// (the transport's epoch counter is per-process and can repeat), so
	// the nonce, not the epoch, qualifies the wire id.
	incarnation string
	// operations owns every drain this issuer ever put on the wire,
	// keyed by the incarnation-qualified wire id. An id is bound to
	// exactly one issuance (sequence) for the issuer's lifetime; a
	// restarted lineage's re-request of the same operator label mints a
	// NEW wire identity and sequence — by protocol definition that is a
	// new operation, not a resumption (resuming would require
	// persistence of the caller→wire mapping, which is deliberately not
	// claimed). Drains are operator-initiated and low cardinality; the
	// unbounded maps are a deliberate, documented trade for the
	// provable binding.
	operations map[string]*drainOperation
	// callerIndex maps the operator-supplied label to its wire id
	// within this incarnation: the same label across reconnects (new
	// epochs) of ONE incarnation keeps its original wire id/sequence.
	callerIndex map[string]string
	// requestIndex maps a sent envelope's request id to its wire id
	// while the issuance awaits its result, so a correlated
	// ProtocolError can resolve that issuance as an observable failure.
	requestIndex map[uint64]string
	activeID     string
	// sequence is the issuer-wide monotonically increasing command
	// sequence; restored from the reconcile watermark after a restart
	// so new drains are never judged obsolete by the Rust gate.
	sequence uint64
	// foreignActive records the most recent DRAIN_IN_PROGRESS answer
	// naming a wire id this incarnation never issued: a previous
	// incarnation's drain is still running on the Rust side. The
	// composition observes it and retries once that operation
	// completes.
	foreignActive *controlpb.DrainResult
	// foreignResolved holds the terminal result that ended the
	// observed foreign drain — the consumable retry signal for the
	// composition's own pending drain.
	foreignResolved *controlpb.DrainResult
}

type drainOperation struct {
	wireID        string
	sequence      uint64
	latest        *controlpb.DrainResult
	completed     bool
	everSent      bool
	lastRequestID uint64
}

// ErrDrainInProgress rejects a second concurrent drain locally.
var ErrDrainInProgress = errors.New("a different drain is already in progress")

// NewDrainIssuer creates an idle issuer with a fresh incarnation
// nonce. It fails when crypto/rand does: lineage identity is the
// safety anchor for drain wire ids, and a weaker (guessable or
// collision-prone) nonce could silently alias two incarnations, so the
// constructor refuses to start rather than degrade.
func NewDrainIssuer() (*DrainIssuer, error) {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("drain issuer incarnation nonce: %w", err)
	}
	return &DrainIssuer{
		incarnation:  hex.EncodeToString(nonce),
		operations:   make(map[string]*drainOperation),
		callerIndex:  make(map[string]string),
		requestIndex: make(map[uint64]string),
	}, nil
}

// ForeignActiveDrain reports a previous incarnation's drain the Rust
// side answered DRAIN_IN_PROGRESS for (nil when none observed): the
// composition retries its own drain after that operation completes.
// The record clears when a terminal result for that wire id arrives —
// [DrainIssuer.ForeignDrainResolved] is the retry signal.
func (issuer *DrainIssuer) ForeignActiveDrain() *controlpb.DrainResult {
	issuer.mu.Lock()
	defer issuer.mu.Unlock()
	return issuer.foreignActive
}

// ForeignDrainResolved consumes the retry signal: it returns the
// terminal result that ended the previously observed foreign drain
// (nil when none has completed since the last call) and clears it, so
// the composition retries its own drain exactly once per resolution.
func (issuer *DrainIssuer) ForeignDrainResolved() *controlpb.DrainResult {
	issuer.mu.Lock()
	defer issuer.mu.Unlock()
	resolved := issuer.foreignResolved
	issuer.foreignResolved = nil
	return resolved
}

// ErrDrainSequenceExhausted fails closed when the monotonic sequence
// space is exhausted: wrapping to zero would violate the nonzero
// contract and break the obsolescence proof.
var ErrDrainSequenceExhausted = errors.New("drain command sequence space is exhausted")

// RestoreSequence adopts the reconcile-reported drain watermark: the
// next issued drain uses watermark + 1.
func (issuer *DrainIssuer) RestoreSequence(watermark uint64) {
	issuer.mu.Lock()
	defer issuer.mu.Unlock()
	if watermark > issuer.sequence {
		issuer.sequence = watermark
	}
}

// CompositeControlHandler is the production transport handler for the
// Go control plane: it owns the drain issuer and metering consumer
// alongside the router adapter, restores the drain sequence watermark
// from every reconcile request before delegating, applies metering
// batches, and routes drain results to the issuer. Everything else goes
// to the RouterAdapter.
type CompositeControlHandler struct {
	adapter   *RouterAdapter
	issuer    *DrainIssuer
	consumer  *MeteringConsumer
	publisher *SnapshotPublisher
}

// AttachSnapshotPublisher routes correlated Rust apply/reject answers to the
// Go generation owner. It is optional for legacy Go-dataplane compositions.
func (handler *CompositeControlHandler) AttachSnapshotPublisher(publisher *SnapshotPublisher) {
	handler.publisher = publisher
}

// NewCompositeControlHandler wires the three owners together; the
// consumer's applied sequence becomes the adapter's reconcile
// acknowledgement.
func NewCompositeControlHandler(
	adapter *RouterAdapter,
	issuer *DrainIssuer,
	consumer *MeteringConsumer,
) (*CompositeControlHandler, error) {
	if adapter == nil || issuer == nil || consumer == nil {
		return nil, errors.New("composite control handler requires adapter, issuer, and consumer")
	}
	adapter.AttachMetering(consumer)
	return &CompositeControlHandler{adapter: adapter, issuer: issuer, consumer: consumer}, nil
}

// HandleControlMessage implements transport.Handler.
func (handler *CompositeControlHandler) HandleControlMessage(
	ctx context.Context,
	session *transport.Session,
	envelope *controlpb.ControlEnvelope,
) error {
	return handler.HandleEnvelope(ctx, session, envelope)
}

// HandleEnvelope dispatches one control message across the three
// production owners.
func (handler *CompositeControlHandler) HandleEnvelope(
	ctx context.Context,
	sender EnvelopeSender,
	envelope *controlpb.ControlEnvelope,
) error {
	if envelope == nil {
		return errors.New("control envelope is required")
	}
	switch body := envelope.GetBody().(type) {
	case *controlpb.ControlEnvelope_SnapshotResult:
		if handler.publisher == nil {
			return errors.New("snapshot result received without a publisher")
		}
		return handler.publisher.HandleResult(sender, envelope)
	case *controlpb.ControlEnvelope_MeteringBatch:
		// Dedup by contiguous sequence; the acknowledgement flows back
		// through the reconcile snapshot. Refused batches are the
		// producer's replay concern, not an error.
		_ = handler.consumer.Apply(body.MeteringBatch)
		return nil
	case *controlpb.ControlEnvelope_DrainResult:
		return handler.issuer.HandleDrainResult(body.DrainResult)
	case *controlpb.ControlEnvelope_Error:
		// A ProtocolError correlated to a drain issuance is that
		// drain's observable failure; anything else keeps the
		// transport's generic (ignore) handling via the adapter.
		_ = handler.issuer.HandleProtocolFailure(envelope.GetRequestId(), body.Error)
		return handler.adapter.HandleEnvelope(ctx, sender, envelope)
	case *controlpb.ControlEnvelope_ReconcileRequest:
		// Restore the issuer-wide drain watermark before the adapter
		// answers, so drains issued after the reconcile resume from
		// watermark + 1.
		handler.issuer.RestoreSequence(body.ReconcileRequest.GetLastDrainCommandSequence())
		return handler.adapter.HandleEnvelope(ctx, sender, envelope)
	default:
		return handler.adapter.HandleEnvelope(ctx, sender, envelope)
	}
}

// ResolveOrphans delegates the maintenance cadence to the adapter.
func (handler *CompositeControlHandler) ResolveOrphans(ctx context.Context) error {
	return handler.adapter.ResolveOrphans(ctx)
}

// StartDrain sends the DrainCommand for drainID over the negotiated
// control session. Re-issuing the active drain ID re-sends the same
// command (the Rust gate answers progress, never a second drain).
// Re-issuing a completed drain ID also re-sends (the Rust gate replays
// the final result). A different ID while one drain is active returns
// ErrDrainInProgress without sending anything.
// The generation stamps the command's provenance: the Rust gate rejects
// drains minted before its applied config snapshot. Per-connection
// generations are deliberately not involved (one drain spans
// mixed-generation sessions). The operator id in the command is
// rewritten to the epoch-qualified wire id before sending.
func (issuer *DrainIssuer) StartDrain(
	ctx context.Context,
	sender EnvelopeSender,
	requestID uint64,
	generation uint64,
	command *controlpb.DrainCommand,
) error {
	if command == nil || command.GetDrainId() == "" {
		return errors.New("drain command requires a drain id")
	}
	callerID := command.GetDrainId()

	issuer.mu.Lock()
	wireID, known := issuer.callerIndex[callerID]
	var operation *drainOperation
	if known {
		operation = issuer.operations[wireID]
	}
	if operation == nil {
		// A new issuance for this operator id under the current control
		// epoch: the wire id embeds the epoch, so a restarted lineage
		// mints a fresh identity instead of colliding with a bound one.
		if issuer.activeID != "" {
			issuer.mu.Unlock()
			return ErrDrainInProgress
		}
		if issuer.sequence == ^uint64(0) {
			issuer.mu.Unlock()
			return ErrDrainSequenceExhausted
		}
		issuer.sequence++
		wireID = fmt.Sprintf("%s@%s", callerID, issuer.incarnation)
		operation = &drainOperation{wireID: wireID, sequence: issuer.sequence}
		issuer.operations[wireID] = operation
		issuer.callerIndex[callerID] = wireID
		issuer.activeID = wireID
	} else {
		if !operation.completed {
			if issuer.activeID != "" && issuer.activeID != wireID {
				issuer.mu.Unlock()
				return ErrDrainInProgress
			}
			// A retry of a not-yet-terminal drain (including one whose
			// first send failed) restores it as the active operation so
			// its eventual terminal result is owned, never a stray.
			issuer.activeID = wireID
		}
	}
	sequence := operation.sequence
	issuer.mu.Unlock()

	wire, ok := proto.Clone(command).(*controlpb.DrainCommand)
	if !ok {
		return errors.New("clone drain command")
	}
	wire.DrainId = wireID
	wire.CommandSequence = sequence
	err := sender.Send(ctx, &controlpb.ControlEnvelope{
		RequestId:  requestID,
		Generation: generation,
		Priority:   controlpb.Priority_PRIORITY_CRITICAL,
		Body:       &controlpb.ControlEnvelope_DrainCommand{DrainCommand: wire},
	})
	issuer.mu.Lock()
	if err == nil {
		operation.everSent = true
		operation.lastRequestID = requestID
		issuer.requestIndex[requestID] = wireID
	} else if !operation.everSent && !operation.completed && issuer.activeID == wireID {
		// Never reached the wire: release the single-flight slot so a
		// different drain is not blocked forever; the binding itself is
		// retained (the id stays bound to its one sequence for any
		// retry).
		issuer.activeID = ""
	}
	issuer.mu.Unlock()
	return err
}

// HandleDrainResult applies one progress or terminal result. Duplicate
// and out-of-order deliveries are harmless: results carry absolute
// counters, so the last observation simply replaces the previous one,
// and a terminal result moves the operation to completed exactly once.
func (issuer *DrainIssuer) HandleDrainResult(result *controlpb.DrainResult) error {
	if result == nil || result.GetDrainId() == "" {
		return errors.New("drain result requires a drain id")
	}
	issuer.mu.Lock()
	defer issuer.mu.Unlock()
	operation := issuer.operations[result.GetDrainId()]
	if operation == nil {
		// A wire id this incarnation never bound. A DRAIN_IN_PROGRESS
		// answer here names a previous incarnation's still-active
		// drain: record it observably so the composition can wait and
		// retry instead of never learning about the old operation. Its
		// terminal (the Rust side answers the completion transition
		// proactively) clears the record and arms the retry signal.
		if result.GetComplete() {
			if issuer.foreignActive != nil &&
				issuer.foreignActive.GetDrainId() == result.GetDrainId() {
				issuer.foreignActive = nil
				issuer.foreignResolved = result
			}
			return nil
		}
		if result.GetCode() == controlpb.ErrorCode_ERROR_CODE_DRAIN_IN_PROGRESS {
			issuer.foreignActive = result
		}
		return nil
	}
	if operation.completed {
		// Terminal is absolute: a replayed terminal refreshes nothing
		// and a reordered non-terminal never regresses it.
		return nil
	}
	// Counters are absolute and per-field monotonic: any single field
	// moving backwards (or the matched population drifting) marks a
	// reordered duplicate, which is ignored. Field-wise comparison also
	// avoids the sum overflow a combined check would risk.
	if latest := operation.latest; latest != nil {
		if result.GetGracefullyClosed() < latest.GetGracefullyClosed() ||
			result.GetForceClosed() < latest.GetForceClosed() ||
			result.GetActiveConnections() != latest.GetActiveConnections() ||
			(latest.GetComplete() && !result.GetComplete()) {
			return nil
		}
	}
	// Closed totals can never exceed the stable matched population.
	if result.GetGracefullyClosed() > result.GetActiveConnections() ||
		result.GetForceClosed() > result.GetActiveConnections()-result.GetGracefullyClosed() {
		return nil
	}
	operation.latest = result
	if result.GetComplete() {
		operation.completed = true
		delete(issuer.requestIndex, operation.lastRequestID)
		if issuer.activeID == operation.wireID {
			issuer.activeID = ""
		}
	}
	return nil
}

// HandleProtocolFailure resolves a correlated ProtocolError against the
// issuance whose request it rejects: the operation completes as an
// observable failure and the single-flight slot is released, so one
// rejected drain (malformed deadlines, a too-early generation) can
// never wedge every later drain. Uncorrelated errors report false and
// stay with the transport's generic handling.
func (issuer *DrainIssuer) HandleProtocolFailure(
	requestID uint64,
	failure *controlpb.ProtocolError,
) bool {
	if failure == nil {
		return false
	}
	if offending := failure.GetOffendingRequestId(); offending != 0 {
		requestID = offending
	}
	if requestID == 0 {
		return false
	}
	issuer.mu.Lock()
	defer issuer.mu.Unlock()
	wireID, correlated := issuer.requestIndex[requestID]
	if !correlated {
		return false
	}
	delete(issuer.requestIndex, requestID)
	operation := issuer.operations[wireID]
	if operation == nil || operation.completed {
		return operation != nil
	}
	operation.completed = true
	operation.latest = &controlpb.DrainResult{
		DrainId:  wireID,
		Complete: true,
		Code:     failure.GetCode(),
		Detail:   failure.GetDetail(),
	}
	if issuer.activeID == wireID {
		issuer.activeID = ""
	}
	return true
}

// Progress returns the latest observed result for the operator's drain
// id and whether that drain finished. Unknown ids return (nil, false).
func (issuer *DrainIssuer) Progress(callerID string) (*controlpb.DrainResult, bool) {
	issuer.mu.Lock()
	defer issuer.mu.Unlock()
	wireID, known := issuer.callerIndex[callerID]
	if !known {
		return nil, false
	}
	operation := issuer.operations[wireID]
	if operation == nil {
		return nil, false
	}
	return operation.latest, operation.completed
}

// MeteringConsumer owns the Go side of deduplicated cumulative metering
// (CTL-06): a batch applies only when its sequence is strictly greater
// than the last applied one, so the Rust producer's at-least-once
// replay (verbatim batches under their original sequences) can never
// double-count. LastApplied feeds the reconcile snapshot so the
// producer can drop acknowledged retention.
type MeteringConsumer struct {
	mu          sync.Mutex
	lastApplied uint64
	totals      map[meteringKey]*meteringTotals
}

type meteringKey struct {
	keyspace       string
	backendID      string
	publicEndpoint bool
}

type meteringTotals struct {
	responseBytes      uint64
	crossLocationBytes uint64
}

// NewMeteringConsumer creates an empty consumer.
func NewMeteringConsumer() *MeteringConsumer {
	return &MeteringConsumer{totals: make(map[meteringKey]*meteringTotals)}
}

// Apply accumulates one batch if and only if its sequence advances past
// the last applied one; duplicates and reordered replays return false
// without changing any counter.
func (consumer *MeteringConsumer) Apply(batch *controlpb.MeteringBatch) bool {
	if batch == nil {
		return false
	}
	consumer.mu.Lock()
	defer consumer.mu.Unlock()
	// The sequence space is exhausted: +1 would wrap and accept
	// sequence 0. Fail closed on everything.
	if consumer.lastApplied == ^uint64(0) {
		return false
	}
	// Only the contiguous next sequence applies: a gap means an earlier
	// batch is still in flight (the producer replays in order), and
	// applying past it would lose that batch forever.
	if batch.GetSequence() != consumer.lastApplied+1 {
		return false
	}
	// Transactional: validate every checked addition first; only a
	// fully valid batch advances the sequence or touches a counter, so
	// an overflow can neither wrap totals nor acknowledge the batch.
	type pendingAdd struct {
		key      meteringKey
		response uint64
		cross    uint64
	}
	adds := make([]pendingAdd, 0, len(batch.GetDeltas()))
	staged := make(map[meteringKey]meteringTotals, len(batch.GetDeltas()))
	for _, delta := range batch.GetDeltas() {
		key := meteringKey{
			keyspace:       delta.GetKeyspace(),
			backendID:      delta.GetBackendId(),
			publicEndpoint: delta.GetPublicEndpoint(),
		}
		current, ok := staged[key]
		if !ok {
			if existing, present := consumer.totals[key]; present {
				current = *existing
			}
		}
		response := current.responseBytes + delta.GetResponseBytes()
		cross := current.crossLocationBytes + delta.GetCrossLocationBytes()
		if response < current.responseBytes || cross < current.crossLocationBytes {
			return false
		}
		staged[key] = meteringTotals{responseBytes: response, crossLocationBytes: cross}
		adds = append(adds, pendingAdd{key: key, response: response, cross: cross})
	}
	for _, add := range adds {
		totals, ok := consumer.totals[add.key]
		if !ok {
			totals = &meteringTotals{}
			consumer.totals[add.key] = totals
		}
		totals.responseBytes = add.response
		totals.crossLocationBytes = add.cross
	}
	consumer.lastApplied = batch.GetSequence()
	return true
}

// LastApplied returns the highest applied sequence for the reconcile
// snapshot's metering acknowledgement.
func (consumer *MeteringConsumer) LastApplied() uint64 {
	consumer.mu.Lock()
	defer consumer.mu.Unlock()
	return consumer.lastApplied
}

// Totals returns the accumulated counters for one metering dimension.
func (consumer *MeteringConsumer) Totals(keyspace, backendID string, publicEndpoint bool) (responseBytes, crossLocationBytes uint64) {
	consumer.mu.Lock()
	defer consumer.mu.Unlock()
	totals, ok := consumer.totals[meteringKey{keyspace: keyspace, backendID: backendID, publicEndpoint: publicEndpoint}]
	if !ok {
		return 0, 0
	}
	return totals.responseBytes, totals.crossLocationBytes
}
