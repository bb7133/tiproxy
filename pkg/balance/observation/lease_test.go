// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package observation

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMixedEvaluationRecordLimit(t *testing.T) {
	r := recorderForTest(t, DefaultLimits())
	o := r.NewOwner()
	capture := o.LeaseEvaluation()
	require.NotNil(t, capture)
	defer capture.Release()
	for range MaxRecords - 2 {
		require.True(t, o.Emit(watermark()), "MIXED_RECORD_EQUALITY")
	}
	writer := receive(t, r)
	defer writer.Release()
	records, bytes := r.Retained()
	require.EqualValues(t, MaxRecords, records, "MIXED_RECORD_EQUALITY")
	require.EqualValues(t, EvaluationCharge+(MaxRecords-1)*BatchCharge, bytes)
	require.Nil(t, o.LeaseEvaluation(), "MIXED_RECORD_PLUS_ONE")
	require.Equal(t, Capacity, r.InvalidOwners()[0].Reason)
	require.EqualValues(t, MaxRecords-1, o.AdmittedSequence(), "LEASE_NO_SEQUENCE")
}

func TestMixedEvaluationByteLimit(t *testing.T) {
	for _, short := range []int64{0, 1} {
		t.Run(map[int64]string{0: "equality", 1: "plus_one_byte"}[short], func(t *testing.T) {
			limits := DefaultLimits()
			limits.Bytes -= short
			r := recorderForTest(t, limits)
			o := r.NewOwner()
			leases := make([]*EvaluationLease, 0, 63)
			defer func() {
				for _, lease := range leases {
					lease.Release()
				}
			}()
			for range 63 {
				lease := o.LeaseEvaluation()
				require.NotNil(t, lease)
				leases = append(leases, lease)
			}
			// Begin plus these records fills the remaining 1MiB exactly.
			for range 126 {
				require.True(t, o.Emit(watermark()))
			}
			writer := receive(t, r)
			defer writer.Release()
			accepted := o.Emit(watermark())
			if short == 0 {
				require.True(t, accepted, "MIXED_BYTE_EQUALITY")
				records, bytes := r.Retained()
				require.EqualValues(t, 191, records, "MIXED_WRITER_RETAINED")
				require.EqualValues(t, MaxQueuedBytes, bytes, "MIXED_WRITER_RETAINED")
				require.False(t, o.Emit(watermark()), "MIXED_BYTE_NEXT_RECORD")
			} else {
				require.False(t, accepted, "MIXED_BYTE_PLUS_ONE")
				records, bytes := r.Retained()
				require.EqualValues(t, 190, records, "MIXED_FAILED_ATOMIC")
				require.EqualValues(t, MaxQueuedBytes-BatchCharge, bytes, "MIXED_FAILED_ATOMIC")
			}
		})
	}
}

func TestEvaluationLeaseCloseAndInvalidationOwnership(t *testing.T) {
	r := recorderForTest(t, DefaultLimits())
	o := r.NewOwner()
	writer := receive(t, r)
	lease := o.LeaseEvaluation()
	require.NotNil(t, lease)
	require.EqualValues(t, 1, o.AdmittedSequence(), "LEASE_NO_SEQUENCE")
	o.Invalidate(OwnerDisappeared)
	require.Nil(t, o.LeaseEvaluation())
	r.Close()
	records, bytes := r.Retained()
	require.EqualValues(t, 2, records, "MIXED_CLOSE_RETAINS_BORROWERS")
	require.EqualValues(t, BatchCharge+EvaluationCharge, bytes)
	writer.Release()
	lease.Release()
	lease.Release()
	records, bytes = r.Retained()
	require.Zero(t, records, "MIXED_LEASE_RELEASE")
	require.Zero(t, bytes, "MIXED_LEASE_RELEASE")
}

func TestEvaluationLeaseAtomicAdmissionAcrossOwners(t *testing.T) {
	limits := DefaultLimits()
	limits.Bytes = 8 * EvaluationCharge
	r := recorderForTest(t, limits)
	owners := make([]*Owner, 16)
	for i := range owners {
		owners[i] = r.NewOwner()
		receive(t, r).Release()
	}
	var wg sync.WaitGroup
	start := make(chan struct{})
	leases := make(chan *EvaluationLease, len(owners))
	for _, o := range owners {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if l := o.LeaseEvaluation(); l != nil {
				leases <- l
			}
		}()
	}
	close(start)
	wg.Wait()
	close(leases)
	require.Len(t, leases, 8, "MIXED_ATOMIC_ADMISSION")
	records, bytes := r.Retained()
	require.EqualValues(t, 8, records)
	require.EqualValues(t, limits.Bytes, bytes, "MIXED_ATOMIC_ADMISSION")
	for l := range leases {
		l.Release()
	}
	records, bytes = r.Retained()
	require.Zero(t, records, "MIXED_LEASE_RELEASE")
	require.Zero(t, bytes, "MIXED_LEASE_RELEASE")
}
