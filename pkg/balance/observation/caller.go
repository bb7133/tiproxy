// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package observation

import (
	"math"
	"sync"
	"sync/atomic"
)

const (
	MaxCallerCopyBytes   = 512 << 10
	MaxCallerFrameBytes  = 1 << 20 // Includes the four-byte transport prefix.
	CallerCharge         = MaxCallerCopyBytes + MaxCallerFrameBytes
	MaxCallerEvaluations = 4
	MaxCallerBatches     = 64
	callerHeaderCharge   = 64 << 10
	MaxCallerDataBytes   = MaxCallerCopyBytes - callerHeaderCharge
)

// CallerChild preserves completion/mutation order within one production lock.
// Exactly one of Evaluation and Batch is present. Child sequences are assigned
// only when the entire caller is admitted; children never enter the queue alone.
type CallerChild struct {
	Evaluation *Evaluation
	Batch      Batch
}

type callerStorage struct {
	balance     GroupBalance
	route       GroupRoute
	pass        RouterPass
	selector    SelectorBoundary
	finish      GroupFinish
	metadata    RouterMetadata
	input       [MaxCallerDataBytes]byte
	output      [MaxCallerFrameBytes]byte
	evaluations [MaxCallerEvaluations]*Evaluation // Includes unfinished captures.
	children    [MaxCallerEvaluations + MaxCallerBatches]CallerChild
}

// Caller is preparation for the caller codec and comparator. No installed
// router factory uses it or advertises selection/scheduler coverage yet. Like
// Evaluation, its input bytes grant no comparison credit by themselves.
//
// The producer holds its existing Group (or router-only attempt) lock. It must
// register defer caller.Cleanup() immediately after BeginCaller, before any
// further panicable work and before that lock's deferred unlock. Cleanup does
// not recover a panic or call production code. Publication transfers all loans
// to the writer together.
type Caller struct {
	owner       *Owner
	storage     *callerStorage
	once        sync.Once
	released    atomic.Bool
	length      int
	evaluations int
	batches     int
	children    int
	span        uint64
	sealed      bool
	published   bool
}

// BeginCaller reserves the entire parent before allocation/copy. The owner
// leaf is not held across a policy invocation or connection operation.
func (o *Owner) BeginCaller() *Caller {
	if !o.Enabled() {
		return nil
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if !o.Enabled() {
		return nil
	}
	if !o.native {
		o.Invalidate(Malformed)
		return nil
	}
	if !o.recorder.reserve(CallerCharge) {
		o.Invalidate(Capacity)
		return nil
	}
	return &Caller{owner: o, storage: &callerStorage{}, span: 1}
}

func (c *Caller) active() bool {
	return c != nil && !c.released.Load() && c.owner.Enabled()
}

func (c *Caller) writable() bool {
	if !c.active() {
		return false
	}
	if c.sealed || c.published {
		c.owner.Invalidate(Malformed)
		return false
	}
	return true
}

// Append copies already-read caller inputs. It neither reads production state
// nor accepts a truncated input after overflow. The typed codec validates the
// eventual schema; this primitive only owns bounded storage and publication.
func (c *Caller) Append(value []byte) bool {
	if !c.writable() {
		return false
	}
	if c.storage.finish.ID != 0 || c.storage.selector.Kind != 0 || c.storage.pass.Kind != 0 || c.storage.route.ID != 0 || c.storage.balance.ID != 0 || c.storage.metadata.Kind != 0 {
		c.owner.Invalidate(Malformed)
		return false
	}
	return c.appendBytes(value)
}

func (c *Caller) appendBytes(value []byte) bool {
	if len(value) > MaxCallerDataBytes-c.length {
		c.owner.Invalidate(Capacity)
		return false
	}
	copy(c.storage.input[c.length:], value)
	c.length += len(value)
	return true
}

// BeginEvaluation attaches ownership immediately, before the policy can copy
// or evaluate anything. An interrupted, unsealed child is still owned here.
func (c *Caller) BeginEvaluation() *Evaluation {
	if !c.writable() {
		return nil
	}
	if c.storage.finish.ID != 0 || c.storage.selector.Kind != 0 || c.storage.pass.Kind != 0 || c.storage.route.ResultSet || c.storage.balance.ResultSet || c.storage.balance.ID != 0 && c.evaluations != 0 {
		c.owner.Invalidate(Malformed)
		return nil
	}
	if c.evaluations == MaxCallerEvaluations {
		c.owner.Invalidate(Capacity)
		return nil
	}
	e := c.owner.BeginEvaluation()
	if e == nil {
		return nil
	}
	e.parent = c
	c.storage.evaluations[c.evaluations] = e
	c.evaluations++
	return e
}

// CompleteEvaluation records the actual policy completion site. It does not
// publish a child or release its unused standalone encoding storage.
func (c *Caller) CompleteEvaluation(e *Evaluation) bool {
	if !c.writable() {
		return false
	}
	if c.storage.finish.ID != 0 || c.storage.balance.ResultSet || c.storage.route.ResultSet || e == nil || e.parent != c || !e.sealed || e.published || e.lease.released.Load() {
		c.owner.Invalidate(Malformed)
		return false
	}
	if c.storage.balance.ID != 0 {
		n := e.Native()
		if c.children != 0 || n == nil || n.Entry != EntryBalance || n.Group != c.storage.balance.Group {
			c.Fail(Malformed)
			return false
		}
	}
	for _, earlier := range c.storage.children[:c.children] {
		if earlier.Evaluation == e {
			c.owner.Invalidate(Malformed)
			return false
		}
	}
	c.storage.children[c.children] = CallerChild{Evaluation: e}
	c.children++
	c.span++
	return true
}

// AppendBatch keeps each complete compound transition, with its full fixed
// charge, even though its values fit inside the parent's metadata allowance.
func (c *Caller) AppendBatch(batch Batch) bool {
	if !c.writable() {
		return false
	}
	if c.storage.balance.ID != 0 {
		c.Fail(Malformed)
		return false
	}
	return c.appendBatch(batch)
}

func (c *Caller) appendBatch(batch Batch) bool {
	if !c.writable() {
		return false
	}
	if c.storage.finish.ResultSet || c.storage.selector.Kind != 0 || c.storage.pass.Kind != 0 || c.storage.route.ResultSet || c.storage.balance.ResultSet || batch.EventCount == 0 || batch.EventCount > MaxEvents || batch.Witness.AccountCount > MaxWitnesses {
		c.owner.Invalidate(Malformed)
		return false
	}
	if c.batches == MaxCallerBatches || !c.owner.recorder.reserve(BatchCharge) {
		c.owner.Invalidate(Capacity)
		return false
	}
	c.storage.children[c.children] = CallerChild{Batch: batch}
	c.children++
	c.batches++
	c.span += uint64(batch.EventCount)
	return true
}

func (c *Caller) Seal() bool {
	if !c.writable() {
		return false
	}
	if c.length == 0 && c.storage.finish.ID == 0 && c.storage.selector.Kind == 0 && c.storage.pass.Kind == 0 && c.storage.route.ID == 0 && c.storage.balance.ID == 0 && c.storage.metadata.Kind == 0 || c.storage.route.ID != 0 && !c.storage.route.ResultSet || c.storage.balance.ID != 0 && !c.storage.balance.ResultSet || c.storage.finish.ID != 0 && !c.storage.finish.ResultSet || c.storage.metadata.Kind == MetadataRefresh && !c.storage.metadata.ResultSet || c.children != c.evaluations+c.batches {
		c.owner.Invalidate(Malformed)
		return false
	}
	c.sealed = true
	return true
}

// Cleanup is the producer's unconditional defer. A successful handoff must
// survive the producer's normal return, including a writer concurrently
// releasing the delivery. The published field is immutable after handoff.
func (c *Caller) Cleanup() {
	if c != nil && !c.published {
		c.Release()
	}
}

// Release belongs to the final delivery, or to Cleanup before transfer.
func (c *Caller) Release() {
	if c == nil {
		return
	}
	c.once.Do(func() {
		if c.owner == nil || c.storage == nil {
			c.released.Store(true)
			return
		}
		if !c.published {
			c.owner.Invalidate(UnpairedDiscard)
		}
		c.released.Store(true)
		for _, e := range c.storage.evaluations[:c.evaluations] {
			e.lease.Release()
		}
		for range c.batches {
			c.owner.recorder.release(BatchCharge)
		}
		c.storage = nil
		c.owner.recorder.release(CallerCharge)
	})
}

func (c *Caller) Bytes() []byte {
	if c == nil || !c.sealed || c.released.Load() {
		return nil
	}
	return c.storage.input[:c.length:c.length]
}

func (c *Caller) Children() []CallerChild {
	if c == nil || !c.sealed || c.released.Load() {
		return nil
	}
	return c.storage.children[:c.children:c.children]
}

func (c *Caller) EncodingBuffer() []byte {
	if c == nil || !c.published || c.released.Load() {
		return nil
	}
	return c.storage.output[:]
}

// Span includes each native child, every lifecycle event, and the final caller
// check. It is meaningful only for a sealed parent, never an open capture.
func (c *Caller) Span() uint64 {
	if c == nil || !c.sealed || c.released.Load() {
		return 0
	}
	return c.span
}

// PublishCaller atomically assigns one contiguous span and one queue slot to
// all completed children and the caller check, before the production unlock.
// All individual ownership charges persist after dequeue until writer release.
func (o *Owner) PublishCaller(c *Caller) bool {
	if c == nil {
		return false
	}
	if o == nil || c.owner != o || !c.sealed || c.published || c.released.Load() {
		o.Invalidate(Malformed)
		c.owner.Invalidate(Malformed)
		c.Cleanup()
		return false
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if !o.Enabled() {
		c.Cleanup()
		return false
	}
	if c.span > math.MaxUint64-o.sequence {
		o.Invalidate(SequenceExhausted)
		c.Cleanup()
		return false
	}
	c.published = true
	for _, e := range c.storage.evaluations[:c.evaluations] {
		e.published = true
	}
	record := Record{Epoch: o.epoch, Sequence: o.sequence + 1, Caller: c, Native: true}
	select {
	case o.recorder.queue <- record:
		o.sequence += c.span
		o.admitted.Store(o.sequence)
		return true
	default:
		o.Invalidate(Capacity)
		c.Release()
		return false
	}
}
