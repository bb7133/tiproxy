// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package shadow

import (
	"context"
	"encoding/binary"
	"os"
	"testing"

	"github.com/pingcap/tiproxy/pkg/balance/observation"
	"github.com/stretchr/testify/require"
)

func TestCallerCannotMasqueradeAsAnExistingDialect(t *testing.T) {
	record := observation.Record{
		Native: true, Epoch: observation.Epoch{Process: 1, Owner: 1, Nonce: 1}, Sequence: 1,
		Batch: observation.Batch{EventCount: 1, Events: [observation.MaxEvents]observation.Event{{Kind: observation.Begin}}},
	}
	_, err := EncodeRecord(record)
	require.NoError(t, err)
	record.Caller = &observation.Caller{}
	_, err = EncodeRecord(record)
	require.Error(t, err, "CALLER_NOT_V2_BATCH")
	_, err = EncodeEvaluation(record)
	require.Error(t, err, "CALLER_NOT_V3_EVALUATION")
}

func TestCallerPassCodecDirectArenaAndStrictVariants(t *testing.T) {
	for _, begin := range []bool{true, false} {
		r, err := observation.NewRecorder(observation.DefaultLimits(), 1, 2)
		require.NoError(t, err)
		defer r.Close()
		o := r.NewNativeOwner()
		d, err := r.Next(context.Background())
		require.NoError(t, err)
		d.Release()
		c := o.BeginCaller()
		defer c.Cleanup()
		fixture := "v4-pass-end.json"
		if begin {
			require.True(t, c.CapturePassBegin(1, false, []uint64{9, 3}))
			fixture = "v4-pass-begin.json"
		} else {
			require.True(t, c.CapturePassEnd(1, 0, 2))
		}
		require.True(t, c.Seal())
		require.True(t, o.PublishCaller(c))
		d, err = r.Next(context.Background())
		require.NoError(t, err)
		frame, err := EncodeCaller(d.Record)
		require.NoError(t, err)
		expected, err := os.ReadFile("../../../tests/controlplane/cproute/shadow/" + fixture)
		require.NoError(t, err)
		require.Equal(t, expected, frame[4:], "PASS_GO_RUST_WIRE_FIXTURE")
		require.EqualValues(t, len(frame)-4, binary.BigEndian.Uint32(frame))
		require.Same(t, &c.EncodingBuffer()[0], &frame[0], "PASS_ENCODER_BORROWS_PARENT")
		require.Zero(t, testing.AllocsPerRun(100, func() { _, err = EncodeCaller(d.Record) }), "PASS_NO_EXTRA_ENCODING_ALLOCATION")
		require.NoError(t, err)
		require.Error(t, ValidateFrame(frame), "PASS_NOT_V2")
		// A borrowed view must not be mutated by a producer. Defensively refuse an
		// inconsistent variant, even if a caller breaks that API rule.
		c.Pass().Groups[63] = 99
		_, err = EncodeCaller(d.Record)
		require.Error(t, err, "PASS_UNUSED_FIELDS_REJECTED")
		require.False(t, o.Enabled())
		d.Release()
	}
}

func TestCallerEncoderPrefixInclusiveLimit(t *testing.T) {
	w := nativeEncoder{buffer: make([]byte, observation.MaxCallerFrameBytes), used: 4}
	w.raw(make([]byte, observation.MaxCallerFrameBytes-4))
	require.False(t, w.failed, "PASS_FRAME_EQUAL")
	require.Equal(t, observation.MaxCallerFrameBytes, w.used)
	w.literal("x")
	require.True(t, w.failed, "PASS_FRAME_PLUS_ONE")
	require.Equal(t, observation.MaxCallerFrameBytes, w.used)
}
