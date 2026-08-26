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
	mu            sync.Mutex
	active        *drainOperation
	lastCompleted *drainOperation
	// sequence is the issuer-wide monotonically increasing command
	// sequence; restored from the reconcile watermark after a restart
	// so new drains are never judged obsolete by the Rust gate.
	sequence uint64
	// issued binds every drain id ever issued by this issuer to its
	// sequence for the issuer's lifetime: an id is bound to exactly one
	// issuance, so any re-send reuses the original sequence (the Rust
	// gate then replays its tombstone or proves it obsolete — it can
	// never re-execute). Drains are operator-initiated and low
	// cardinality, so the unbounded map is a deliberate, documented
	// trade for the provable binding.
	issued map[string]uint64
}

type drainOperation struct {
	drainID  string
	sequence uint64
	latest   *controlpb.DrainResult
}

// ErrDrainInProgress rejects a second concurrent drain locally.
var ErrDrainInProgress = errors.New("a different drain is already in progress")

// NewDrainIssuer creates an idle issuer.
func NewDrainIssuer() *DrainIssuer {
	return &DrainIssuer{issued: make(map[string]uint64)}
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
	adapter  *RouterAdapter
	issuer   *DrainIssuer
	consumer *MeteringConsumer
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
	case *controlpb.ControlEnvelope_MeteringBatch:
		// Dedup by contiguous sequence; the acknowledgement flows back
		// through the reconcile snapshot. Refused batches are the
		// producer's replay concern, not an error.
		_ = handler.consumer.Apply(body.MeteringBatch)
		return nil
	case *controlpb.ControlEnvelope_DrainResult:
		return handler.issuer.HandleDrainResult(body.DrainResult)
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
// mixed-generation sessions).
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
	issuer.mu.Lock()
	if issuer.active != nil && issuer.active.drainID != command.GetDrainId() {
		issuer.mu.Unlock()
		return ErrDrainInProgress
	}
	created := false
	if bound, ever := issuer.issued[command.GetDrainId()]; ever {
		// An id is bound to exactly one issuance for the issuer's
		// lifetime: every re-send (active, completed, or long-evicted)
		// reuses the original sequence.
		command.CommandSequence = bound
	} else {
		if issuer.sequence == ^uint64(0) {
			issuer.mu.Unlock()
			return ErrDrainSequenceExhausted
		}
		issuer.sequence++
		command.CommandSequence = issuer.sequence
		issuer.issued[command.GetDrainId()] = issuer.sequence
		issuer.active = &drainOperation{drainID: command.GetDrainId(), sequence: issuer.sequence}
		created = true
	}
	issuer.mu.Unlock()

	err := sender.Send(ctx, &controlpb.ControlEnvelope{
		RequestId:  requestID,
		Generation: generation,
		Priority:   controlpb.Priority_PRIORITY_CRITICAL,
		Body:       &controlpb.ControlEnvelope_DrainCommand{DrainCommand: command},
	})
	if err != nil && created {
		// The command never reached the wire: roll the registration
		// back so a later different drain is not rejected forever.
		issuer.mu.Lock()
		if issuer.active != nil && issuer.active.drainID == command.GetDrainId() && issuer.active.latest == nil {
			issuer.active = nil
		}
		issuer.mu.Unlock()
	}
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
	if issuer.active == nil || issuer.active.drainID != result.GetDrainId() {
		// A completed drain's record is terminal: late strays (including
		// reordered non-terminal progress) never regress it.
		return nil
	}
	// Counters are absolute and per-field monotonic: any single field
	// moving backwards (or the matched population drifting) marks a
	// reordered duplicate, which is ignored. Field-wise comparison also
	// avoids the sum overflow a combined check would risk.
	if latest := issuer.active.latest; latest != nil {
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
	issuer.active.latest = result
	if result.GetComplete() {
		issuer.lastCompleted = issuer.active
		issuer.active = nil
	}
	return nil
}

// Progress returns the latest observed result for drainID and whether
// the drain is finished. Unknown IDs return (nil, false).
func (issuer *DrainIssuer) Progress(drainID string) (*controlpb.DrainResult, bool) {
	issuer.mu.Lock()
	defer issuer.mu.Unlock()
	if issuer.active != nil && issuer.active.drainID == drainID {
		return issuer.active.latest, false
	}
	if issuer.lastCompleted != nil && issuer.lastCompleted.drainID == drainID {
		return issuer.lastCompleted.latest, true
	}
	return nil, false
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
