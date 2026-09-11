// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package shadow

import (
	"context"
	"encoding/binary"
	"os"
	"strings"
	"testing"

	"github.com/pingcap/tiproxy/pkg/balance/observation"
	"github.com/stretchr/testify/require"
)

func metadataCaller(t *testing.T, capture func(c *observation.Caller) bool) (*observation.Recorder, observation.Record, *observation.Caller) {
	t.Helper()
	r, err := observation.NewRecorder(observation.DefaultLimits(), 1, 2)
	require.NoError(t, err)
	o := r.NewNativeOwner()
	d, err := r.Next(context.Background())
	require.NoError(t, err)
	d.Release()
	c := o.BeginCaller()
	require.NotNil(t, c)
	require.True(t, capture(c), "METADATA_CAPTURE")
	require.True(t, c.Seal(), "METADATA_SEAL")
	require.True(t, o.PublishCaller(c), "METADATA_PUBLISH")
	d, err = r.Next(context.Background())
	require.NoError(t, err)
	return r, d.Record, c
}

type metadataInputValue struct {
	account                                    uint64
	held, healthy, supportRedirection, present bool
}

var metadataInputs = []metadataInputValue{
	{7, true, true, true, true},
	{8, true, false, true, false},
	{0, false, false, true, true}, // unhealthy and never held: unidentified
	{9, true, true, false, true},
}

func captureInputs(c *observation.Caller, inputs []metadataInputValue) bool {
	for _, input := range inputs {
		if !c.CaptureMetadataInput(input.account, input.held, input.healthy, input.supportRedirection, input.present) {
			return false
		}
	}
	return true
}

func TestCallerMetadataCodecFixturesAndStrictVariants(t *testing.T) {
	cases := []struct {
		fixture string
		capture func(c *observation.Caller) bool
	}{
		{"v4-metadata-begin.json", func(c *observation.Caller) bool {
			return c.CaptureMetadataBegin(3, observation.SelectorNoError, observation.MetadataRuleClientCIDR) && captureInputs(c, metadataInputs)
		}},
		{"v4-metadata-begin-error.json", func(c *observation.Caller) bool {
			return c.CaptureMetadataBegin(4, observation.SelectorExactNoBackend, observation.MetadataRulePort)
		}},
		{"v4-metadata-assign.json", func(c *observation.Caller) bool {
			return c.CaptureMetadataAssign(3, 1, 9, 12, false, true, true, []string{"10.0.0.0/8", "192.168.1.0/24"})
		}},
		{"v4-metadata-assign-removed.json", func(c *observation.Caller) bool {
			return c.CaptureMetadataAssign(3, 2, 8, 0, true, false, false, nil)
		}},
		{"v4-metadata-refresh.json", func(c *observation.Caller) bool {
			return c.CaptureMetadataRefresh(3, 12, true) &&
				c.CaptureMetadataRefreshMember(9, []string{"10.0.0.0/8", "192.168.1.0/24"}) &&
				c.CaptureMetadataRefreshMember(7, []string{"10.0.0.0/8", "bad-cidr"}) &&
				c.CaptureMetadataRefreshResult([]string{"192.168.1.0/24", "10.0.0.0/8", "bad-cidr"}, false)
		}},
		{"v4-metadata-refresh-port.json", func(c *observation.Caller) bool {
			return c.CaptureMetadataRefresh(3, 12, false) && c.CaptureMetadataRefreshResult(nil, true)
		}},
		{"v4-metadata-end.json", func(c *observation.Caller) bool {
			return c.CaptureMetadataEnd(3, true, 2, 1, 0, 1, 0)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.fixture, func(t *testing.T) {
			r, record, c := metadataCaller(t, tc.capture)
			defer r.Close()
			defer c.Cleanup()
			frame, err := EncodeCaller(record)
			require.NoError(t, err)
			path := "../../../tests/controlplane/cproute/shadow/" + tc.fixture
			if os.Getenv("CP_ROUTE_WRITE_FIXTURES") != "" {
				require.NoError(t, os.WriteFile(path, frame[4:], 0o644))
			}
			expected, err := os.ReadFile(path)
			require.NoError(t, err)
			require.Equal(t, string(expected), string(frame[4:]), "METADATA_GO_RUST_WIRE_FIXTURE")
			require.EqualValues(t, len(frame)-4, binary.BigEndian.Uint32(frame))
			require.Same(t, &c.EncodingBuffer()[0], &frame[0], "METADATA_ENCODER_BORROWS_PARENT")
			require.Zero(t, testing.AllocsPerRun(100, func() { _, err = EncodeCaller(record) }), "METADATA_NO_EXTRA_ENCODING_ALLOCATION")
			require.NoError(t, err)
			require.True(t, strings.Contains(string(frame[4:]), `"span":"1"`), "METADATA_SPAN_ONE")
		})
	}
}

// fresh returns an enabled native owner with a started caller on its own recorder.
func fresh(t *testing.T) (*observation.Owner, *observation.Caller) {
	t.Helper()
	r, err := observation.NewRecorder(observation.DefaultLimits(), 1, 2)
	require.NoError(t, err)
	t.Cleanup(r.Close)
	o := r.NewNativeOwner()
	d, err := r.Next(context.Background())
	require.NoError(t, err)
	d.Release()
	c := o.BeginCaller()
	require.NotNil(t, c, "METADATA_FRESH_CALLER")
	t.Cleanup(c.Cleanup)
	return o, c
}

func TestCallerMetadataCaptureIsExclusiveAndBounded(t *testing.T) {
	// Zero generation is malformed and invalidates the owner.
	o, c := fresh(t)
	require.False(t, c.CaptureMetadataBegin(0, observation.SelectorNoError, observation.MetadataRuleAll), "METADATA_ZERO_GENERATION")
	require.False(t, o.Enabled(), "METADATA_MALFORMED_INVALIDATES_OWNER")

	// No route, balance, pass or child may join a metadata frame.
	o, c = fresh(t)
	require.True(t, c.CaptureMetadataBegin(1, observation.SelectorNoError, observation.MetadataRuleAll))
	require.False(t, c.CaptureGroupRoute(1, 2, 3, 0, nil), "METADATA_EXCLUDES_ROUTE")
	require.False(t, o.Enabled())

	o, c = fresh(t)
	require.True(t, c.CapturePassBegin(1, true, []uint64{1}))
	require.False(t, c.CaptureMetadataEnd(1, true, 1, 0, 0, 0, 0), "PASS_EXCLUDES_METADATA")
	require.False(t, o.Enabled())

	// An observer error carries no inputs; an input needs an open Begin.
	o, c = fresh(t)
	require.True(t, c.CaptureMetadataBegin(1, observation.SelectorOtherError, observation.MetadataRuleAll))
	require.False(t, c.CaptureMetadataInput(1, true, true, true, true), "METADATA_ERROR_WITH_INPUTS")
	require.False(t, o.Enabled())
	o, c = fresh(t)
	require.False(t, c.CaptureMetadataInput(1, true, true, true, true), "METADATA_INPUT_WITHOUT_BEGIN")
	require.False(t, o.Enabled())

	// Held and identified are the same statement; an unheld backend is
	// unhealthy and present (Go creates a wrapper for every healthy one).
	o, c = fresh(t)
	require.True(t, c.CaptureMetadataBegin(1, observation.SelectorNoError, observation.MetadataRuleAll))
	require.False(t, c.CaptureMetadataInput(0, true, true, true, true), "METADATA_HELD_WITHOUT_ACCOUNT")
	require.False(t, o.Enabled())
	o, c = fresh(t)
	require.True(t, c.CaptureMetadataBegin(1, observation.SelectorNoError, observation.MetadataRuleAll))
	require.False(t, c.CaptureMetadataInput(0, false, true, true, true), "METADATA_UNHELD_HEALTHY")
	require.False(t, o.Enabled())
	o, c = fresh(t)
	require.True(t, c.CaptureMetadataBegin(1, observation.SelectorNoError, observation.MetadataRuleAll))
	require.True(t, c.CaptureMetadataInput(5, true, true, true, true))
	require.False(t, c.CaptureMetadataInput(5, true, false, true, true), "METADATA_DUPLICATE_ACCOUNT")
	require.False(t, o.Enabled())

	// Plus-one bounds: the 65th backend is a capacity failure, not a cut;
	// exactly 64 is accepted and seals.
	o, c = fresh(t)
	require.True(t, c.CaptureMetadataBegin(1, observation.SelectorNoError, observation.MetadataRuleAll))
	for i := range observation.MaxMetadataBackends {
		require.True(t, c.CaptureMetadataInput(uint64(i+1), true, true, true, true))
	}
	require.False(t, c.CaptureMetadataInput(observation.MaxMetadataBackends+1, true, true, true, true), "METADATA_BACKENDS_PLUS_ONE")
	require.False(t, o.Enabled())
	o, c = fresh(t)
	require.True(t, c.CaptureMetadataBegin(1, observation.SelectorNoError, observation.MetadataRuleAll))
	for i := range observation.MaxMetadataBackends {
		require.True(t, c.CaptureMetadataInput(uint64(i+1), true, true, true, true))
	}
	require.True(t, c.Seal(), "METADATA_BOUNDS_EQUALITY")
	require.True(t, o.Enabled())

	// Values: 257 in one frame, a 513-byte value and invalid UTF-8 fail;
	// exactly 256 values of 256 bytes (64 KiB aggregate) seal.
	o, c = fresh(t)
	many := make([]string, observation.MaxMetadataValues+1)
	for j := range many {
		many[j] = "10.0.0.0/8"
	}
	require.False(t, c.CaptureMetadataAssign(1, 0, 5, 3, false, false, true, many), "METADATA_VALUES_PLUS_ONE")
	require.False(t, o.Enabled())
	o, c = fresh(t)
	require.True(t, c.CaptureMetadataRefresh(1, 3, true))
	require.False(t, c.CaptureMetadataRefreshMember(5, []string{strings.Repeat("a", observation.MaxEvaluationStringBytes+1)}), "METADATA_VALUE_BYTES_PLUS_ONE")
	require.False(t, o.Enabled())
	o, c = fresh(t)
	require.False(t, c.CaptureMetadataAssign(1, 0, 5, 3, false, false, true, []string{"\xff"}), "METADATA_VALUE_UTF8")
	require.False(t, o.Enabled())
	o, c = fresh(t)
	full := make([]string, observation.MaxMetadataValues)
	for j := range full {
		full[j] = strings.Repeat("b", observation.MaxEvaluationStringsBytes/observation.MaxMetadataValues)
	}
	require.True(t, c.CaptureMetadataAssign(1, 0, 5, 3, false, false, true, full), "METADATA_VALUES_EQUALITY")
	require.True(t, c.Seal())
	require.True(t, o.Enabled())

	// Assign, Refresh and End invariants.
	o, c = fresh(t)
	require.False(t, c.CaptureMetadataAssign(1, 0, 5, 3, true, false, false, nil), "METADATA_REMOVED_WITH_GROUP")
	require.False(t, o.Enabled())
	o, c = fresh(t)
	require.False(t, c.CaptureMetadataAssign(1, 0, 5, 0, false, true, false, nil), "METADATA_CREATED_WITHOUT_GROUP")
	require.False(t, o.Enabled())
	o, c = fresh(t)
	require.False(t, c.CaptureMetadataAssign(1, 0, 5, 0, true, false, true, []string{"10.0.0.0/8"}), "METADATA_REMOVED_READS_VALUES")
	require.False(t, o.Enabled())
	o, c = fresh(t)
	require.False(t, c.CaptureMetadataAssign(1, 0, 5, 3, false, false, false, []string{"10.0.0.0/8"}), "METADATA_UNREAD_VALUES")
	require.False(t, o.Enabled())
	o, c = fresh(t)
	require.True(t, c.CaptureMetadataRefresh(1, 3, false))
	require.False(t, c.CaptureMetadataRefreshResult(nil, false), "METADATA_UNREAD_REFRESH_FAILS")
	require.False(t, o.Enabled())
	o, c = fresh(t)
	require.False(t, c.CaptureMetadataRefresh(1, 0, true), "METADATA_REFRESH_WITHOUT_GROUP")
	require.False(t, o.Enabled())
	o, c = fresh(t)
	require.True(t, c.CaptureMetadataRefresh(1, 3, false))
	require.False(t, c.CaptureMetadataRefreshMember(5, nil), "METADATA_UNREAD_REFRESH_MEMBER")
	require.False(t, o.Enabled())
	o, c = fresh(t)
	require.True(t, c.CaptureMetadataRefresh(1, 3, true))
	require.True(t, c.CaptureMetadataRefreshMember(5, []string{"10.0.0.0/8"}))
	require.False(t, c.CaptureMetadataRefreshMember(5, nil), "METADATA_DUPLICATE_MEMBER")
	require.False(t, o.Enabled())
	o, c = fresh(t)
	require.True(t, c.CaptureMetadataRefresh(1, 3, true))
	require.False(t, c.Seal(), "METADATA_REFRESH_WITHOUT_RESULT")
	require.False(t, o.Enabled())
	o, c = fresh(t)
	require.True(t, c.CaptureMetadataRefresh(1, 3, true))
	for i := range observation.MaxMetadataBackends {
		require.True(t, c.CaptureMetadataRefreshMember(uint64(i+1), nil))
	}
	require.False(t, c.CaptureMetadataRefreshMember(observation.MaxMetadataBackends+1, nil), "METADATA_MEMBERS_PLUS_ONE")
	require.False(t, o.Enabled())
	o, c = fresh(t)
	require.True(t, c.CaptureMetadataRefresh(1, 3, true))
	require.True(t, c.CaptureMetadataRefreshResult([]string{"10.0.0.0/8"}, true))
	require.False(t, c.CaptureMetadataRefreshMember(5, nil), "METADATA_MEMBER_AFTER_RESULT")
	require.False(t, o.Enabled())
	o, c = fresh(t)
	require.False(t, c.CaptureMetadataEnd(1, true, observation.MaxCallerGroups+1, 0, 0, 0, 0), "METADATA_GROUPS_PLUS_ONE")
	require.False(t, o.Enabled())
	o, c = fresh(t)
	require.True(t, c.CaptureMetadataEnd(1, true, 1, 0, 0, 0, 0))
	require.False(t, c.CaptureMetadataBegin(1, observation.SelectorNoError, observation.MetadataRuleAll), "METADATA_ONE_KIND_PER_FRAME")
	require.False(t, o.Enabled())
}
