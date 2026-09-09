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

func TestEvaluationStorageLayoutAndCopyBoundary(t *testing.T) {
	metadata := unsafe.Sizeof(Evaluation{}) + unsafe.Sizeof(EvaluationLease{}) + unsafe.Sizeof(NativeEvaluation{})
	require.LessOrEqual(t, metadata, uintptr(evaluationHeaderCharge), "EVALUATION_METADATA_CHARGE")
	require.LessOrEqual(t, unsafe.Sizeof(evaluationStorage{})+metadata-unsafe.Sizeof(NativeEvaluation{}), uintptr(EvaluationCharge), "EVALUATION_STORAGE_CHARGE")
	require.Equal(t, MaxEvaluationCopyBytes, MaxEvaluationDataBytes+evaluationHeaderCharge)
	r := recorderForTest(t, DefaultLimits())
	o := r.NewOwner()
	receive(t, r).Release()
	e := o.BeginEvaluation()
	require.NotNil(t, e)
	defer e.Release()
	require.True(t, e.Append(make([]byte, MaxEvaluationDataBytes)), "EVALUATION_COPY_EQUAL")
	require.False(t, e.Append([]byte{1}), "EVALUATION_COPY_PLUS_ONE")
	require.Equal(t, MaxEvaluationDataBytes, e.length, "EVALUATION_COPY_ATOMIC")
	require.False(t, o.Enabled())
	require.False(t, e.Seal())
	require.False(t, o.PublishEvaluation(e), "EVALUATION_NO_PARTIAL_PUBLICATION")
	require.EqualValues(t, 1, o.AdmittedSequence())
}

func TestEvaluationPublishAndWriterOwnership(t *testing.T) {
	limits := DefaultLimits()
	limits.Bytes = EvaluationCharge + BatchCharge
	r := recorderForTest(t, limits)
	o := r.NewOwner()
	receive(t, r).Release()
	e := o.BeginEvaluation()
	require.NotNil(t, e)
	require.EqualValues(t, 1, o.AdmittedSequence(), "EVALUATION_RESERVE_NO_SEQUENCE")
	require.True(t, e.Append([]byte{1, 2, 3}))
	require.True(t, e.Seal())
	require.True(t, o.PublishEvaluation(e))
	require.True(t, o.Emit(watermark()))
	d := receive(t, r)
	require.Same(t, e, d.Record.Evaluation)
	require.EqualValues(t, 2, d.Record.Sequence, "EVALUATION_ATOMIC_SEQUENCE")
	require.Equal(t, []byte{1, 2, 3}, e.Bytes())
	require.Len(t, e.EncodingBuffer(), MaxEvaluationBodyBytes+4)
	count, used := r.Retained()
	require.EqualValues(t, 2, count)
	require.EqualValues(t, EvaluationCharge+BatchCharge, used, "EVALUATION_WRITER_RETAINS_BYTES")
	require.Nil(t, o.BeginEvaluation(), "EVALUATION_WRITER_NO_REUSE")
	r.Close()
	count, used = r.Retained()
	require.EqualValues(t, 1, count)
	require.EqualValues(t, EvaluationCharge, used, "EVALUATION_CLOSE_RETAINS_WRITER")
	d.Release()
	d.Release()
	count, used = r.Retained()
	require.Zero(t, count)
	require.Zero(t, used)
	require.Nil(t, e.Bytes())
	require.Nil(t, e.EncodingBuffer())
}

func TestEvaluationIdleStorageChargedReusedAndEvicted(t *testing.T) {
	limits := DefaultLimits()
	limits.Bytes = EvaluationCharge
	r := recorderForTest(t, limits)
	o := r.NewOwner()
	receive(t, r).Release()
	first := o.BeginEvaluation()
	storage := first.lease.storage
	require.True(t, first.Append([]byte{1}))
	require.True(t, first.Seal())
	require.True(t, o.PublishEvaluation(first))
	d := receive(t, r)
	d.Release()
	count, used := r.Retained()
	require.Zero(t, count)
	require.EqualValues(t, EvaluationCharge, used, "EVALUATION_IDLE_BYTES_CHARGED")
	reused := o.BeginEvaluation()
	require.Same(t, storage, reused.lease.storage, "EVALUATION_REUSES_ARENA")
	first.Release() // An older handle cannot release the current borrow.
	count, used = r.Retained()
	require.EqualValues(t, 1, count, "EVALUATION_REUSE_OLD_RELEASE")
	require.EqualValues(t, EvaluationCharge, used)
	require.True(t, reused.Append([]byte{2}))
	require.True(t, reused.Seal())
	require.True(t, o.PublishEvaluation(reused))
	receive(t, r).Release()
	require.True(t, o.Emit(watermark()), "EVALUATION_IDLE_YIELDS_TO_V2")
	count, used = r.Retained()
	require.EqualValues(t, 1, count)
	require.EqualValues(t, BatchCharge, used, "EVALUATION_IDLE_EVICTION_CHARGE")
	require.Zero(t, r.freeArenaCount)
	r.Close()
	count, used = r.Retained()
	require.Zero(t, count)
	require.Zero(t, used)
}

func TestEvaluationInvalidAndIncompleteCannotPublish(t *testing.T) {
	for _, failure := range []string{"unsealed", "overflow", "foreign", "discard", "append-after-seal"} {
		t.Run(failure, func(t *testing.T) {
			r := recorderForTest(t, DefaultLimits())
			o := r.NewOwner()
			receive(t, r).Release()
			e := o.BeginEvaluation()
			require.NotNil(t, e)
			require.True(t, e.Append([]byte{1}))
			before := o.AdmittedSequence()
			switch failure {
			case "unsealed":
				require.False(t, o.PublishEvaluation(e), "EVALUATION_UNSEALED_REJECT")
			case "overflow":
				require.True(t, e.Seal())
				o.sequence = math.MaxUint64
				require.False(t, o.PublishEvaluation(e), "EVALUATION_SEQUENCE_NO_WRAP")
			case "foreign":
				require.True(t, e.Seal())
				other := r.NewOwner()
				receive(t, r).Release()
				require.False(t, other.PublishEvaluation(e), "EVALUATION_FOREIGN_OWNER")
				require.False(t, other.Enabled())
			case "discard":
				e.Release()
			case "append-after-seal":
				require.True(t, e.Seal())
				require.False(t, e.Append([]byte{2}), "EVALUATION_SEALED_IMMUTABLE")
				require.False(t, o.PublishEvaluation(e))
			}
			require.False(t, o.Enabled(), "EVALUATION_FAILURE_STICKY")
			require.Equal(t, before, o.AdmittedSequence(), "EVALUATION_FAILURE_NO_SEQUENCE")
			e.Release()
			r.Close()
			count, used := r.Retained()
			require.Zero(t, count)
			require.Zero(t, used)
		})
	}
}

func TestEvaluationConcurrentGroupsCompleteBeforePublication(t *testing.T) {
	r := recorderForTest(t, DefaultLimits())
	o := r.NewOwner()
	receive(t, r).Release()
	var jobs sync.WaitGroup
	for i := range 16 {
		jobs.Go(func() {
			e := o.BeginEvaluation()
			if e == nil || !e.Append([]byte{byte(i)}) || !e.Seal() || !o.PublishEvaluation(e) {
				t.Errorf("EVALUATION_CONCURRENT_PUBLICATION: group %d", i)
			}
		})
	}
	jobs.Wait()
	seen := map[byte]bool{}
	for sequence := uint64(2); sequence <= 17; sequence++ {
		d := receive(t, r)
		require.Equal(t, sequence, d.Record.Sequence)
		require.NotNil(t, d.Record.Evaluation)
		input := d.Record.Evaluation.Bytes()
		require.Len(t, input, 1)
		require.False(t, seen[input[0]])
		seen[input[0]] = true
		d.Release()
	}
	require.Len(t, seen, 16)
	require.True(t, o.Enabled())
}
