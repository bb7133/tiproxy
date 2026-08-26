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
}

type drainOperation struct {
	drainID string
	latest  *controlpb.DrainResult
}

// ErrDrainInProgress rejects a second concurrent drain locally.
var ErrDrainInProgress = errors.New("a different drain is already in progress")

// NewDrainIssuer creates an idle issuer.
func NewDrainIssuer() *DrainIssuer {
	return &DrainIssuer{}
}

// StartDrain sends the DrainCommand for drainID over the negotiated
// control session. Re-issuing the active drain ID re-sends the same
// command (the Rust gate answers progress, never a second drain).
// Re-issuing a completed drain ID also re-sends (the Rust gate replays
// the final result). A different ID while one drain is active returns
// ErrDrainInProgress without sending anything.
func (issuer *DrainIssuer) StartDrain(
	ctx context.Context,
	sender EnvelopeSender,
	requestID uint64,
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
	if issuer.active == nil {
		if issuer.lastCompleted == nil || issuer.lastCompleted.drainID != command.GetDrainId() {
			issuer.active = &drainOperation{drainID: command.GetDrainId()}
		}
	}
	issuer.mu.Unlock()

	return sender.Send(ctx, &controlpb.ControlEnvelope{
		RequestId: requestID,
		Priority:  controlpb.Priority_PRIORITY_CRITICAL,
		Body:      &controlpb.ControlEnvelope_DrainCommand{DrainCommand: command},
	})
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
		// A late replay for an already-completed drain refreshes the
		// completed record; anything else is a stale stray and drops.
		if issuer.lastCompleted != nil && issuer.lastCompleted.drainID == result.GetDrainId() {
			issuer.lastCompleted.latest = result
		}
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
	if batch.GetSequence() <= consumer.lastApplied {
		return false
	}
	consumer.lastApplied = batch.GetSequence()
	for _, delta := range batch.GetDeltas() {
		key := meteringKey{
			keyspace:       delta.GetKeyspace(),
			backendID:      delta.GetBackendId(),
			publicEndpoint: delta.GetPublicEndpoint(),
		}
		totals, ok := consumer.totals[key]
		if !ok {
			totals = &meteringTotals{}
			consumer.totals[key] = totals
		}
		totals.responseBytes += delta.GetResponseBytes()
		totals.crossLocationBytes += delta.GetCrossLocationBytes()
	}
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
