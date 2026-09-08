// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package observation

import (
	"context"
	"errors"
	"math"
	"sync"
	"sync/atomic"
)

type Limits struct {
	Owners  int
	Records int
	Bytes   int64
}

func DefaultLimits() Limits {
	return Limits{Owners: MaxOwners, Records: MaxRecords, Bytes: MaxQueuedBytes}
}

// Recorder owns one bounded channel, its in-flight charge and retained owners.
// An enabled recorder is installed before namespace creation; it has no attach
// operation that can reconstruct an existing production owner's history.
type Recorder struct {
	registry sync.Mutex
	owners   []*Owner
	closed   bool
	process  uint64
	nonce    uint64
	limits   Limits
	queue    chan Record
	changed  chan struct{}
	budgetMu sync.Mutex // leaf: never held while calling an owner or production code
	records  int64
	bytes    int64
}

// Owner serializes the sequence and queue admission of all groups in one owner.
// Its Mutex is a leaf. No caller may acquire a production lock while holding it.
// The drain never takes this Mutex; normal producer contention is serialized.
type Owner struct {
	recorder *Recorder
	epoch    Epoch
	mu       sync.Mutex
	sequence uint64
	reason   atomic.Uint32
	admitted atomic.Uint64
	identity uint64
}

func NewRecorder(limits Limits, process, nonce uint64) (*Recorder, error) {
	if process == 0 || nonce == 0 || limits.Owners < 1 || limits.Owners > MaxOwners ||
		limits.Records < 1 || limits.Records > MaxRecords || limits.Bytes < BatchCharge || limits.Bytes > MaxQueuedBytes {
		return nil, errors.New("invalid routing observation identity or limits")
	}
	capacity := min(limits.Records, int(limits.Bytes/BatchCharge))
	return &Recorder{
		process: process, nonce: nonce, limits: limits,
		queue: make(chan Record, capacity), changed: make(chan struct{}, 1),
	}, nil
}

// NewOwner is a factory-only operation, before any router/policy initialization.
// Registry entries are never evicted, including after invalidation or retirement.
func (r *Recorder) NewOwner() *Owner {
	r.registry.Lock()
	defer r.registry.Unlock()
	if r.closed {
		return nil
	}
	if len(r.owners) >= r.limits.Owners {
		r.closed = true
		for _, owner := range r.owners {
			owner.Invalidate(Capacity)
		}
		return nil
	}
	owner := &Owner{recorder: r, epoch: Epoch{Process: r.process, Owner: uint64(len(r.owners)) + 1, Nonce: r.nonce}}
	r.owners = append(r.owners, owner)
	owner.Emit(Batch{EventCount: 1, Events: [MaxEvents]Event{{Kind: Begin}}})
	return owner
}

// Enabled is the mandatory caller-side fast path BEFORE building any witness.
// A nil owner is the default-disabled path and allocates/copies nothing.
func (o *Owner) Enabled() bool {
	return o != nil && o.reason.Load() == uint32(Valid)
}

func (o *Owner) Epoch() Epoch {
	return o.epoch
}

// AdmittedSequence reads producer metadata only. It does not imply delivery or
// successful Rust comparison; consumers must independently reach this boundary.
func (o *Owner) AdmittedSequence() uint64 {
	if o == nil {
		return 0
	}
	return o.admitted.Load()
}

// NextIdentity allocates diagnostic group/account/session/operation identities.
// Exhaustion invalidates this owner; a wrapped value is never reused.
func (o *Owner) NextIdentity() uint64 {
	if !o.Enabled() {
		return 0
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if !o.Enabled() {
		return 0
	}
	if o.identity == math.MaxUint64 {
		o.Invalidate(SequenceExhausted)
		return 0
	}
	o.identity++
	return o.identity
}

// Emit only consumes fixed-size values. Production capture helpers must first
// call Enabled, while holding their existing locks, before constructing Batch.
func (o *Owner) Emit(batch Batch) bool {
	if !o.Enabled() {
		return false
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if !o.Enabled() {
		return false
	}
	if batch.EventCount == 0 || batch.EventCount > MaxEvents || batch.Witness.AccountCount > MaxWitnesses {
		o.Invalidate(Malformed)
		return false
	}
	if o.sequence > math.MaxUint64-uint64(batch.EventCount) {
		o.Invalidate(SequenceExhausted)
		return false
	}
	r := o.recorder
	// Reserve both limits once, before publishing. The short budget lock does
	// not span production work, queue operations or encoding. A writer keeps
	// the reservation after dequeue, just like an in-flight evaluation.
	if !r.reserve(BatchCharge) {
		o.Invalidate(Capacity)
		return false
	}
	record := Record{Epoch: o.epoch, Sequence: o.sequence + 1, Batch: batch}
	select {
	case r.queue <- record:
		o.sequence += uint64(batch.EventCount)
		o.admitted.Store(o.sequence)
		return true
	default:
		r.release(BatchCharge)
		o.Invalidate(Capacity)
		return false
	}
}

func (o *Owner) Invalidate(reason InvalidReason) {
	if o == nil || reason == Valid || !o.reason.CompareAndSwap(uint32(Valid), uint32(reason)) {
		return
	}
	// A separate bounded wake-up never depends on room in the data queue.
	select {
	case o.recorder.changed <- struct{}{}:
	default:
	}
}

func (r *Recorder) Changed() <-chan struct{} { return r.changed }

// InvalidOwners snapshots bounded diagnostic metadata, never production state.
func (r *Recorder) InvalidOwners() []InvalidSummary {
	r.registry.Lock()
	defer r.registry.Unlock()
	result := make([]InvalidSummary, 0, len(r.owners))
	for _, owner := range r.owners {
		if reason := InvalidReason(owner.reason.Load()); reason != Valid {
			result = append(result, InvalidSummary{Epoch: owner.epoch, Reason: reason, LastAdmitted: owner.admitted.Load()})
		}
	}
	return result
}

func (r *Recorder) InvalidateAll(reason InvalidReason) {
	r.registry.Lock()
	defer r.registry.Unlock()
	for _, owner := range r.owners {
		owner.Invalidate(reason)
	}
}

// Delivery retains its credit until the writer finishes or discards it.
type Delivery struct {
	Record Record
	once   sync.Once
	owner  *Recorder
}

func (d *Delivery) Release() {
	d.once.Do(func() { d.owner.release(BatchCharge) })
}

func (r *Recorder) reserve(charge int64) bool {
	r.budgetMu.Lock()
	defer r.budgetMu.Unlock()
	if charge <= 0 || r.records >= int64(r.limits.Records) || charge > r.limits.Bytes-r.bytes {
		return false
	}
	r.records++
	r.bytes += charge
	return true
}

func (r *Recorder) release(charge int64) {
	r.budgetMu.Lock()
	r.records--
	r.bytes -= charge
	r.budgetMu.Unlock()
}

func (r *Recorder) Next(ctx context.Context) (*Delivery, error) {
	select {
	case record := <-r.queue:
		return &Delivery{Record: record, owner: r}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (r *Recorder) Retained() (records, bytes int64) {
	r.budgetMu.Lock()
	defer r.budgetMu.Unlock()
	return r.records, r.bytes
}

// Close is called after stopping and joining the transport consumer. It fences
// owner factories, invalidates producers, joins their bounded critical sections
// and releases queued credits. It acquires no production lock and fabricates no
// End record. An already leased writer record must be released by its owner.
func (r *Recorder) Close() {
	r.registry.Lock()
	defer r.registry.Unlock()
	r.closed = true
	for _, owner := range r.owners {
		owner.Invalidate(Shutdown)
	}
	for _, owner := range r.owners {
		owner.mu.Lock()
		// Publish the final admitted boundary after joining the last producer.
		owner.admitted.Store(owner.sequence)
		owner.mu.Unlock()
	}
	for {
		select {
		case <-r.queue:
			r.release(BatchCharge)
		default:
			return
		}
	}
}

// NextOrChanged wakes the drain for an out-of-band invalid notice even when no
// data record can be admitted. A nil delivery means re-read InvalidOwners.
func (r *Recorder) NextOrChanged(ctx context.Context) (*Delivery, error) {
	select {
	case record := <-r.queue:
		return &Delivery{Record: record, owner: r}, nil
	case <-r.changed:
		return nil, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// WatermarkOwners is a separate observation producer, never the socket drain.
// It serializes liveness records without reading any production object.
func (r *Recorder) WatermarkOwners() {
	r.registry.Lock()
	defer r.registry.Unlock()
	for _, owner := range r.owners {
		owner.Emit(Batch{EventCount: 1, Events: [MaxEvents]Event{{Kind: Watermark}}})
	}
}

// IsInvalid consults only retained recorder metadata, for dropping pre-loss
// queued data during a reconnect. It acquires no producer or production lock.
func (r *Recorder) IsInvalid(epoch Epoch) bool {
	r.registry.Lock()
	defer r.registry.Unlock()
	if epoch.Process != r.process || epoch.Nonce != r.nonce || epoch.Owner == 0 || epoch.Owner > uint64(len(r.owners)) {
		return true
	}
	return !r.owners[epoch.Owner-1].Enabled()
}
