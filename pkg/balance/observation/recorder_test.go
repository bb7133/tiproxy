// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package observation

import (
	"context"
	"math"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func watermark() Batch {
	return Batch{EventCount: 1, Events: [MaxEvents]Event{{Kind: Watermark}}}
}

func recorderForTest(t *testing.T, limits Limits) *Recorder {
	r, err := NewRecorder(limits, 10, 20)
	require.NoError(t, err)
	t.Cleanup(r.Close)
	return r
}

func receive(t *testing.T, r *Recorder) *Delivery {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	delivery, err := r.Next(ctx)
	require.NoError(t, err)
	return delivery
}

func TestRecorderBatchSequenceAcrossConcurrentGroups(t *testing.T) {
	r := recorderForTest(t, DefaultLimits())
	owners := []*Owner{r.NewOwner(), r.NewOwner()}
	var writers sync.WaitGroup
	for i := range 8 {
		writers.Add(1)
		go func() {
			defer writers.Done()
			owner := owners[i%2]
			for range 128 {
				require.True(t, owner.Emit(Batch{EventCount: 2, Events: [MaxEvents]Event{{Kind: Watermark}, {Kind: Watermark}}}), "RECORDER_CONCURRENT_CAPTURE")
			}
		}()
	}
	writers.Wait()
	sequences := make(map[uint64]uint64)
	for range 8*128 + 2 {
		delivery := receive(t, r)
		record := delivery.Record
		require.Equal(t, sequences[record.Epoch.Owner]+1, record.Sequence, "RECORDER_ATOMIC_SEQUENCE")
		sequences[record.Epoch.Owner] += uint64(record.Batch.EventCount)
		delivery.Release()
	}
	require.Equal(t, map[uint64]uint64{1: 1025, 2: 1025}, sequences)
	require.Empty(t, r.InvalidOwners(), "RECORDER_CONCURRENT_CAPTURE")
	records, bytes := r.Retained()
	require.Zero(t, records)
	require.Zero(t, bytes)
}

func TestRecorderBudgetsIncludeWriterOwnedRecord(t *testing.T) {
	for _, limits := range []Limits{
		{Owners: 2, Records: 2, Bytes: 3 * BatchCharge},
		{Owners: 2, Records: 3, Bytes: 2 * BatchCharge},
	} {
		r := recorderForTest(t, limits)
		owner := r.NewOwner()
		require.True(t, owner.Emit(watermark()), "RECORDER_LIMIT_EQUALITY")
		lease := receive(t, r)
		records, bytes := r.Retained()
		require.EqualValues(t, 2, records, "RECORDER_WRITER_CHARGE")
		require.EqualValues(t, 2*BatchCharge, bytes, "RECORDER_WRITER_CHARGE")
		require.False(t, owner.Emit(watermark()), "RECORDER_LIMIT_PLUS_ONE")
		require.False(t, owner.Enabled())
		require.Equal(t, []InvalidSummary{{Epoch: owner.Epoch(), Reason: Capacity, LastAdmitted: 2}}, r.InvalidOwners())
		select {
		case <-r.Changed():
		default:
			t.Fatal("RECORDER_FULL_QUEUE_INVALID_NOTICE")
		}
		lease.Release()
		lease.Release() // cannot return the writer credit twice
		r.Close()
		records, bytes = r.Retained()
		require.Zero(t, records)
		require.Zero(t, bytes)
	}
}

func TestRecorderInvalidBeforeWitnessAndRetainedIdentity(t *testing.T) {
	r := recorderForTest(t, Limits{Owners: 2, Records: 8, Bytes: 8 * BatchCharge})
	old := r.NewOwner()
	first := old.NextIdentity()
	second := old.NextIdentity()
	require.NotEqual(t, first, second)
	old.Invalidate(OwnerDisappeared)
	copies := 0
	capture := func(owner *Owner) {
		if !owner.Enabled() {
			return
		}
		copies++
		owner.Emit(watermark())
	}
	capture(old)
	capture(nil)
	require.Zero(t, copies, "RECORDER_INVALID_BEFORE_COPY")
	require.Zero(t, old.NextIdentity())
	require.False(t, old.Emit(Batch{EventCount: 1, Events: [MaxEvents]Event{{Kind: End}}}))
	fresh := r.NewOwner()
	require.NotEqual(t, old.Epoch(), fresh.Epoch(), "RECORDER_OWNER_REUSE")
	capture(fresh)
	require.Equal(t, 1, copies)
	require.Nil(t, r.NewOwner(), "RECORDER_OWNER_BOUND")
	require.Equal(t, OwnerDisappeared, r.InvalidOwners()[0].Reason, "RECORDER_INVALID_STICKY")
	require.Equal(t, Capacity, r.InvalidOwners()[1].Reason)
}

func TestRecorderCountersNeverWrapAndMalformedBatchInvalidates(t *testing.T) {
	r := recorderForTest(t, DefaultLimits())
	owner := r.NewOwner()
	owner.sequence = math.MaxUint64 - 1
	require.False(t, owner.Emit(Batch{EventCount: 2}), "RECORDER_SEQUENCE_OVERFLOW")
	require.Equal(t, SequenceExhausted, r.InvalidOwners()[0].Reason)
	owner = r.NewOwner()
	owner.identity = math.MaxUint64
	require.Zero(t, owner.NextIdentity(), "RECORDER_IDENTITY_OVERFLOW")
	require.Zero(t, owner.NextIdentity(), "RECORDER_IDENTITY_OVERFLOW")
	owner = r.NewOwner()
	require.False(t, owner.Emit(Batch{EventCount: MaxEvents + 1}), "RECORDER_BATCH_BOUND")
	owner = r.NewOwner()
	require.False(t, owner.Emit(Batch{EventCount: 1, Witness: Witness{AccountCount: MaxWitnesses + 1}}), "RECORDER_WITNESS_BOUND")
}

func TestRecorderCloseJoinsAdmissionAndReleasesOnlyOwnedCredits(t *testing.T) {
	r := recorderForTest(t, DefaultLimits())
	owner := r.NewOwner()
	lease := receive(t, r)
	require.True(t, owner.Emit(watermark()))
	var writers sync.WaitGroup
	for range 8 {
		writers.Add(1)
		go func() {
			defer writers.Done()
			for range 64 {
				owner.Emit(watermark())
			}
		}()
	}
	r.Close()
	writers.Wait()
	records, bytes := r.Retained()
	require.EqualValues(t, 1, records, "RECORDER_CLOSE_JOIN")
	require.EqualValues(t, BatchCharge, bytes)
	lease.Release()
	records, bytes = r.Retained()
	require.Zero(t, records)
	require.Zero(t, bytes)
	require.Nil(t, r.NewOwner())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := r.Next(ctx)
	require.ErrorIs(t, err, context.Canceled)
}

func TestRecorderLeafSerializationWaitsForPeerProducer(t *testing.T) {
	r := recorderForTest(t, DefaultLimits())
	owner := r.NewOwner()
	owner.mu.Lock()
	done := make(chan bool, 1)
	go func() { done <- owner.Emit(watermark()) }()
	select {
	case <-done:
		owner.mu.Unlock()
		t.Fatal("RECORDER_LEAF_SERIALIZATION: contention cannot discard capture")
	case <-time.After(10 * time.Millisecond):
		owner.mu.Unlock()
	}
	select {
	case accepted := <-done:
		require.True(t, accepted, "RECORDER_LEAF_SERIALIZATION")
	case <-time.After(time.Second):
		t.Fatal("RECORDER_LEAF_SERIALIZATION: admission did not resume")
	}
}
