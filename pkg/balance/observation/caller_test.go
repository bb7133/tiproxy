// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package observation

import (
	"math"
	"sync"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"
)

func callerOwner(t *testing.T, limits Limits) (*Recorder, *Owner) {
	t.Helper()
	r := recorderForTest(t, limits)
	o := r.NewNativeOwner()
	receive(t, r).Release()
	return r, o
}

func callerChild(t *testing.T, c *Caller) *Evaluation {
	t.Helper()
	e := c.BeginEvaluation()
	require.NotNil(t, e)
	require.True(t, e.Append([]byte("child")))
	require.True(t, e.Seal())
	require.True(t, c.CompleteEvaluation(e))
	return e
}

func TestCallerStorageAndInputBounds(t *testing.T) {
	require.LessOrEqual(t, unsafe.Sizeof(callerStorage{})+unsafe.Sizeof(Caller{}), uintptr(CallerCharge), "CALLER_STORAGE_CHARGE")
	require.Equal(t, 1<<20, MaxCallerFrameBytes, "CALLER_PREFIX_INCLUDED")
	_, o := callerOwner(t, DefaultLimits())
	c := o.BeginCaller()
	defer c.Cleanup()
	require.True(t, c.Append(make([]byte, MaxCallerDataBytes)), "CALLER_COPY_EQUAL")
	require.False(t, c.Append([]byte{1}), "CALLER_COPY_PLUS_ONE")
	require.Equal(t, MaxCallerDataBytes, c.length, "CALLER_COPY_ATOMIC")
	require.False(t, c.Seal())
	require.False(t, o.PublishCaller(c))
	require.EqualValues(t, 1, o.AdmittedSequence(), "CALLER_FAILED_NO_SEQUENCE")
}

func TestCallerCombinedOwnershipAndShutdown(t *testing.T) {
	r, o := callerOwner(t, DefaultLimits())
	c := o.BeginCaller()
	defer c.Cleanup()
	require.True(t, c.Append([]byte("caller")))
	for range MaxCallerEvaluations {
		callerChild(t, c)
	}
	for range MaxCallerBatches {
		require.True(t, c.AppendBatch(Batch{EventCount: MaxEvents}))
	}
	count, bytes := r.Retained()
	require.EqualValues(t, 69, count, "CALLER_ALL_69_SLOTS")
	require.EqualValues(t, 6<<20, bytes, "CALLER_ALL_6_MIB")
	require.EqualValues(t, 1, o.AdmittedSequence(), "CALLER_CHILDREN_PRIVATE")
	require.True(t, c.Seal())
	require.True(t, o.PublishCaller(c))
	c.Cleanup()
	d := receive(t, r)
	require.Same(t, c, d.Record.Caller)
	require.EqualValues(t, 2, d.Record.Sequence)
	require.EqualValues(t, 261, c.Span(), "CALLER_PRODUCER_CLEANUP_KEEPS_TRANSFER")
	require.EqualValues(t, 262, o.AdmittedSequence())
	require.Len(t, c.Children(), 68)
	require.Len(t, c.EncodingBuffer(), 1<<20)
	require.Equal(t, []byte("caller"), c.Bytes())

	// Retain a full parent in the writer while another evaluation becomes idle
	// and a v2 batch remains queued. These are simultaneous, not added maxima.
	e := o.BeginEvaluation()
	require.NotNil(t, e)
	require.True(t, e.Append([]byte{1}))
	require.True(t, e.Seal())
	require.True(t, o.PublishEvaluation(e))
	receive(t, r).Release()
	require.True(t, o.Emit(watermark()))
	count, bytes = r.Retained()
	require.EqualValues(t, 70, count, "CALLER_WRITER_QUEUE_SLOTS")
	require.EqualValues(t, 7<<20+BatchCharge, bytes, "CALLER_WRITER_QUEUE_IDLE_BYTES")
	r.Close()
	count, bytes = r.Retained()
	require.EqualValues(t, 69, count, "CALLER_SHUTDOWN_RETAINS_WRITER")
	require.EqualValues(t, 6<<20, bytes)
	d.Release()
	d.Release()
	c.Release()
	c.Cleanup()
	count, bytes = r.Retained()
	require.Zero(t, count, "CALLER_RELEASE_EXACTLY_ONCE")
	require.Zero(t, bytes)
	require.Nil(t, c.Bytes())
	require.Nil(t, c.Children())
	require.Nil(t, c.EncodingBuffer())
}

func TestCallerRejectsPartialAndEscapedChildren(t *testing.T) {
	for _, failure := range []string{"empty", "unsealed", "unfinished-child", "duplicate-child", "foreign-child", "child-publish", "child-release", "foreign-owner", "sealed-append", "sequence-overflow", "evaluation-plus-one", "batch-plus-one", "bad-batch"} {
		t.Run(failure, func(t *testing.T) {
			r, o := callerOwner(t, DefaultLimits())
			c := o.BeginCaller()
			defer c.Cleanup()
			if failure != "empty" {
				require.True(t, c.Append([]byte{1}))
			}
			switch failure {
			case "empty":
				require.False(t, c.Seal())
			case "unsealed":
				require.False(t, o.PublishCaller(c))
			case "unfinished-child":
				require.NotNil(t, c.BeginEvaluation())
				require.False(t, c.Seal(), "CALLER_UNSEALED_CHILD_REJECTED")
			case "duplicate-child":
				e := callerChild(t, c)
				require.False(t, c.CompleteEvaluation(e))
			case "foreign-child":
				e := o.BeginEvaluation()
				defer e.Release()
				require.False(t, c.CompleteEvaluation(e))
			case "child-publish":
				e := callerChild(t, c)
				require.False(t, o.PublishEvaluation(e), "CALLER_CHILD_CANNOT_PUBLISH_ALONE")
			case "child-release":
				e := callerChild(t, c)
				e.Release()
				count, _ := r.Retained()
				require.EqualValues(t, 2, count, "CALLER_CHILD_CANNOT_RELEASE_PARENT_LOAN")
			case "foreign-owner":
				require.True(t, c.Seal())
				other := r.NewNativeOwner()
				receive(t, r).Release()
				require.False(t, other.PublishCaller(c))
				require.False(t, other.Enabled())
			case "sealed-append":
				require.True(t, c.Seal())
				require.False(t, c.Append([]byte{2}))
			case "sequence-overflow":
				require.True(t, c.AppendBatch(watermark()))
				require.True(t, c.Seal())
				o.sequence = math.MaxUint64 - 1
				require.False(t, o.PublishCaller(c), "CALLER_SPAN_NO_WRAP")
			case "evaluation-plus-one":
				for range MaxCallerEvaluations {
					callerChild(t, c)
				}
				require.Nil(t, c.BeginEvaluation(), "CALLER_EVALUATION_PLUS_ONE")
			case "batch-plus-one":
				for range MaxCallerBatches {
					require.True(t, c.AppendBatch(watermark()))
				}
				require.False(t, c.AppendBatch(watermark()), "CALLER_BATCH_PLUS_ONE")
			case "bad-batch":
				require.False(t, c.AppendBatch(Batch{EventCount: MaxEvents + 1}))
			}
			require.False(t, o.Enabled())
			require.EqualValues(t, 1, o.AdmittedSequence(), "CALLER_NO_PARTIAL_SPAN")
			c.Cleanup()
			c.Cleanup()
			r.Close()
			count, bytes := r.Retained()
			// A foreign standalone lease is still owned by its local defer.
			if failure != "foreign-child" {
				require.Zero(t, count)
				require.Zero(t, bytes)
			}
		})
	}
}

func TestCallerPanicCleanupBeforeUnlock(t *testing.T) {
	for _, boundary := range []string{"copy", "unsealed-child", "sealed-child", "batch", "before-publish"} {
		t.Run(boundary, func(t *testing.T) {
			r, o := callerOwner(t, DefaultLimits())
			var lock sync.Mutex
			panicValue := &struct{ boundary string }{boundary}
			func() {
				defer func() { require.Same(t, panicValue, recover(), "CALLER_ORIGINAL_PANIC") }()
				lock.Lock()
				defer func() {
					require.False(t, o.Enabled(), "CALLER_INVALID_BEFORE_UNLOCK")
					count, _ := r.Retained()
					require.Zero(t, count, "CALLER_ALL_CHILDREN_RELEASED_BEFORE_UNLOCK")
					lock.Unlock()
				}()
				c := o.BeginCaller()
				defer c.Cleanup()
				if boundary != "copy" {
					e := c.BeginEvaluation()
					require.NotNil(t, e)
					if boundary != "unsealed-child" {
						require.True(t, e.Append([]byte{1}))
						require.True(t, e.Seal())
						require.True(t, c.CompleteEvaluation(e))
					}
				}
				if boundary == "batch" || boundary == "before-publish" {
					require.True(t, c.AppendBatch(watermark()))
				}
				if boundary == "before-publish" {
					require.True(t, c.Append([]byte{1}))
					require.True(t, c.Seal())
				}
				panic(panicValue)
			}()
			r.Close()
			count, bytes := r.Retained()
			require.Zero(t, count)
			require.Zero(t, bytes)
		})
	}
}

func TestCallerConcurrentSpansWithLifecycleInterleaving(t *testing.T) {
	r, o := callerOwner(t, DefaultLimits())
	var producers sync.WaitGroup
	for i := range 8 {
		producers.Go(func() {
			c := o.BeginCaller()
			defer c.Cleanup()
			require.True(t, c.Append([]byte{byte(i)}))
			callerChild(t, c)
			require.True(t, o.Emit(watermark())) // Another unlocked Group callback.
			require.True(t, c.AppendBatch(Batch{EventCount: 4}))
			require.True(t, c.Seal())
			require.True(t, o.PublishCaller(c))
		})
	}
	producers.Wait()
	next := uint64(2)
	seen := map[byte]bool{}
	for range 16 {
		d := receive(t, r)
		require.Equal(t, next, d.Record.Sequence, "CALLER_CONTIGUOUS_SPAN")
		if c := d.Record.Caller; c != nil {
			require.False(t, seen[c.Bytes()[0]])
			seen[c.Bytes()[0]] = true
			require.EqualValues(t, 6, c.Span())
			require.NotNil(t, c.Children()[0].Evaluation, "CALLER_ORIGINAL_CHILD_ORDER")
			require.EqualValues(t, 4, c.Children()[1].Batch.EventCount)
			next += c.Span()
		} else {
			next += uint64(d.Record.Batch.EventCount)
		}
		d.Release()
	}
	require.Len(t, seen, 8)
	require.Equal(t, next-1, o.AdmittedSequence())
	require.True(t, o.Enabled())
}

func TestCallerCapacityAndAdmissionFailure(t *testing.T) {
	for _, boundary := range []string{"parent-bytes", "child-bytes", "batch-bytes", "slots", "queue", "shutdown"} {
		t.Run(boundary, func(t *testing.T) {
			limits := DefaultLimits()
			switch boundary {
			case "parent-bytes":
				limits.Bytes = CallerCharge - 1
			case "child-bytes":
				limits.Bytes = CallerCharge + EvaluationCharge - 1
			case "batch-bytes":
				limits.Bytes = CallerCharge + BatchCharge - 1
			case "slots":
				limits.Records = 2
			}
			r, o := callerOwner(t, limits)
			c := o.BeginCaller()
			if boundary == "parent-bytes" {
				require.Nil(t, c, "CALLER_PARENT_RESERVE_BEFORE_ALLOCATE")
			} else {
				require.NotNil(t, c)
				defer c.Cleanup()
				require.True(t, c.Append([]byte{1}))
				switch boundary {
				case "child-bytes":
					require.Nil(t, c.BeginEvaluation())
				case "batch-bytes":
					require.False(t, c.AppendBatch(watermark()))
				case "slots":
					callerChild(t, c)
					require.False(t, c.AppendBatch(watermark()))
				case "queue":
					// Force the defensive nonblocking queue branch independently
					// of byte/slot admission, without inventing a charged record.
					r.queue = make(chan Record)
					require.True(t, c.Seal())
					require.False(t, o.PublishCaller(c), "CALLER_QUEUE_FAILURE_RELEASES")
				case "shutdown":
					callerChild(t, c)
					require.True(t, c.Seal())
					r.Close()
					require.False(t, o.PublishCaller(c))
				}
			}
			require.False(t, o.Enabled())
			require.EqualValues(t, 1, o.AdmittedSequence())
			c.Cleanup()
			r.Close()
			count, bytes := r.Retained()
			require.Zero(t, count)
			require.Zero(t, bytes)
		})
	}
}

func TestCallerTransferredLoanCannotBePublishedTwice(t *testing.T) {
	r, o := callerOwner(t, DefaultLimits())
	c := o.BeginCaller()
	defer c.Cleanup()
	callerChild(t, c)
	require.True(t, c.Append([]byte{1}))
	require.True(t, c.Seal())
	// The last representable span is legal; one more must not wrap.
	o.sequence = math.MaxUint64 - c.Span()
	require.True(t, o.PublishCaller(c), "CALLER_SEQUENCE_EQUAL")
	require.Equal(t, uint64(math.MaxUint64), o.AdmittedSequence())
	d := receive(t, r)
	require.False(t, o.PublishCaller(c), "CALLER_DUPLICATE_PUBLISH")
	c.Cleanup()
	count, bytes := r.Retained()
	require.EqualValues(t, 2, count, "CALLER_DUPLICATE_RETAINS_WRITER")
	require.EqualValues(t, CallerCharge+EvaluationCharge, bytes)
	r.Close()
	d.Release()
	count, bytes = r.Retained()
	require.Zero(t, count)
	require.Zero(t, bytes)
}

func TestCallerDefaultAndLifecycleOnlyOwnersRemainOff(t *testing.T) {
	var disabled *Owner
	require.Nil(t, disabled.BeginCaller())
	r := recorderForTest(t, DefaultLimits())
	o := r.NewOwner()
	receive(t, r).Release()
	require.Nil(t, o.BeginCaller())
	require.False(t, o.Enabled())
	count, bytes := r.Retained()
	require.Zero(t, count)
	require.Zero(t, bytes)
	_, native := callerOwner(t, DefaultLimits())
	require.False(t, native.PublishCaller(&Caller{}), "CALLER_ZERO_HANDLE_REJECTED")
	require.False(t, native.Enabled())
}
