// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package observation

import "math"

const (
	MaxEvaluationCopyBytes = 512 << 10
	MaxEvaluationBodyBytes = 512 << 10
	// Conservative fixed charge for the capture/lease handles and a future
	// native projection and frame header. It is part of copied storage, not extra uncharged memory.
	evaluationHeaderCharge = 64 << 10
	MaxEvaluationDataBytes = MaxEvaluationCopyBytes - evaluationHeaderCharge
	maxEvaluationArenas    = MaxQueuedBytes / EvaluationCharge
)

// evaluationStorage contains fixed values and bytes only: pooled storage cannot retain a query,
// backend, policy, owner or an earlier capture handle. Even idle arenas remain
// charged against the same recorder byte budget until reused or evicted.
type evaluationStorage struct {
	native NativeEvaluation
	input  [MaxEvaluationDataBytes]byte
	output [MaxEvaluationBodyBytes + 4]byte
}

// Evaluation is one private, leased capture under the caller's Group/policy
// lock. It becomes immutable at Seal, and PublishEvaluation transfers lifetime
// to the recorder delivery. No data may be used after Release. A fresh handle
// is created for each loan, so releasing an old loan cannot release a reused
// arena's new lease.
type Evaluation struct {
	owner     *Owner
	lease     *EvaluationLease
	length    int
	sealed    bool
	published bool
}

// BeginEvaluation reserves before allocating or copying. Unlike an unattached
// EvaluationLease, this lease includes reusable, budgeted input/output storage.
// It does not allocate a sequence or hold the owner leaf across capture.
func (o *Owner) BeginEvaluation() *Evaluation {
	if !o.Enabled() {
		return nil
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if !o.Enabled() {
		return nil
	}
	storage := o.recorder.acquireEvaluationStorage()
	if storage == nil {
		o.Invalidate(Capacity)
		return nil
	}
	storage.native = NativeEvaluation{From: -1, To: -1}
	return &Evaluation{owner: o, lease: &EvaluationLease{recorder: o.recorder, storage: storage}}
}

func (e *Evaluation) active() bool {
	return e != nil && !e.lease.released.Load() && e.owner.Enabled()
}

// Append copies supplied values only. A failed append is atomic and invalidates
// the owner; a prefix can never be qualified as a completed evaluation.
func (e *Evaluation) Append(value []byte) bool {
	if !e.active() {
		return false
	}
	if e.sealed {
		e.owner.Invalidate(Malformed)
		return false
	}
	if len(value) > MaxEvaluationDataBytes-e.length {
		e.owner.Invalidate(Capacity)
		return false
	}
	copy(e.lease.storage.input[e.length:], value)
	e.length += len(value)
	return true
}

// Seal is called after all actual inputs and outputs have been captured. The
// producer still holds its Group lock, but the native policy call has returned.
func (e *Evaluation) Seal() bool {
	if !e.active() || e.sealed || e.length == 0 {
		return false
	}
	e.sealed = true
	return true
}

// Bytes is an immutable borrowed view valid until the delivery is released.
// The codec must write only to EncodingBuffer, never to this capture view.
func (e *Evaluation) Bytes() []byte {
	if e == nil || !e.sealed || e.lease.released.Load() {
		return nil
	}
	return e.lease.storage.input[:e.length:e.length]
}

// EncodingBuffer is owned exclusively by the final writer after publication.
// The codec must independently reject an encoded body beyond this bound.
func (e *Evaluation) EncodingBuffer() []byte {
	if e == nil || !e.published || e.lease.released.Load() {
		return nil
	}
	return e.lease.storage.output[:]
}

func (e *Evaluation) Release() {
	if e != nil {
		if !e.published && !e.lease.released.Load() {
			e.owner.Invalidate(UnpairedDiscard)
		}
		e.lease.Release()
	}
}

// PublishEvaluation is called after the policy returns and BEFORE Group unlock.
// Completion and sequence assignment are atomic under the short owner leaf.
// Failure leaves no partial sequence and returns the private lease immediately.
func (o *Owner) PublishEvaluation(e *Evaluation) bool {
	if e == nil {
		return false
	}
	if o == nil || e.owner != o || !e.sealed || e.published || e.lease.released.Load() {
		if o != nil {
			o.Invalidate(Malformed)
		}
		e.owner.Invalidate(Malformed)
		// A published loan belongs to its writer; never reclaim that storage.
		if !e.published {
			e.Release()
		}
		return false
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if !o.Enabled() {
		e.Release()
		return false
	}
	if o.sequence == math.MaxUint64 {
		o.Invalidate(SequenceExhausted)
		e.Release()
		return false
	}
	// Set the writer-visible state before the channel establishes publication.
	e.published = true
	record := Record{Epoch: o.epoch, Sequence: o.sequence + 1, Evaluation: e, Native: o.native}
	select {
	case o.recorder.queue <- record:
		o.sequence++
		o.admitted.Store(o.sequence)
		return true
	default:
		o.Invalidate(Capacity)
		e.Release()
		return false
	}
}

func (r *Recorder) acquireEvaluationStorage() *evaluationStorage {
	r.budgetMu.Lock()
	if r.budgetStopped || r.records >= int64(r.limits.Records) {
		r.budgetMu.Unlock()
		return nil
	}
	if r.freeArenaCount > 0 {
		r.freeArenaCount--
		storage := r.freeArenas[r.freeArenaCount]
		r.freeArenas[r.freeArenaCount] = nil
		r.records++ // The idle arena's bytes were never returned.
		r.budgetMu.Unlock()
		return storage
	}
	if EvaluationCharge > r.limits.Bytes-r.bytes {
		r.budgetMu.Unlock()
		return nil
	}
	r.records++
	r.bytes += EvaluationCharge
	r.budgetMu.Unlock()
	return &evaluationStorage{}
}

func (r *Recorder) releaseEvaluationStorage(storage *evaluationStorage) {
	r.budgetMu.Lock()
	defer r.budgetMu.Unlock()
	r.records--
	if r.budgetStopped {
		r.bytes -= EvaluationCharge
		return
	}
	r.freeArenas[r.freeArenaCount] = storage
	r.freeArenaCount++
}

// Idle arenas yield their charged bytes to either dialect's new reservations.
// This is storage reuse only, never eviction of compared history or live input.
func (r *Recorder) evictEvaluationStorageLocked(charge int64) {
	for charge > r.limits.Bytes-r.bytes && r.freeArenaCount > 0 {
		r.freeArenaCount--
		r.freeArenas[r.freeArenaCount] = nil
		r.bytes -= EvaluationCharge
	}
}

func (r *Recorder) closeEvaluationStorage() {
	r.budgetMu.Lock()
	defer r.budgetMu.Unlock()
	r.budgetStopped = true
	for r.freeArenaCount > 0 {
		r.freeArenaCount--
		r.freeArenas[r.freeArenaCount] = nil
		r.bytes -= EvaluationCharge
	}
}
