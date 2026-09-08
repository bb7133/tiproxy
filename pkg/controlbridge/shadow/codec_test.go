// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package shadow

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"math"
	"os"
	"testing"

	"github.com/pingcap/tiproxy/pkg/balance/observation"
	"github.com/stretchr/testify/require"
)

func framed(body []byte) []byte {
	frame := make([]byte, 4)
	binary.BigEndian.PutUint32(frame, uint32(len(body)))
	return append(frame, body...)
}
func TestLiveCodecGoldenAndStrictBounds(t *testing.T) {
	record := observation.Record{Epoch: observation.Epoch{Process: 41, Owner: 1, Nonce: 43}, Sequence: 1, Batch: observation.Batch{EventCount: 1, Events: [observation.MaxEvents]observation.Event{{Kind: observation.Begin}}}}
	frame, err := EncodeRecord(record)
	require.NoError(t, err)
	require.NoError(t, ValidateFrame(frame))
	golden, err := os.ReadFile("../../../tests/controlplane/cproute/shadow/v2-begin.json")
	require.NoError(t, err)
	require.Equal(t, bytes.TrimSpace(golden), frame[4:])
	tests := map[string][]byte{
		"version":             bytes.Replace(frame[4:], []byte(`"version":2`), []byte(`"version":1`), 1),
		"duplicate":           bytes.Replace(frame[4:], []byte(`"owner":"1"`), []byte(`"owner":"1","owner":"1"`), 1),
		"missing":             bytes.Replace(frame[4:], []byte(`"factors":false,`), nil, 1),
		"unknown_extra":       bytes.Replace(frame[4:], []byte(`"factors":false,`), []byte(`"extra":0,"factors":false,`), 1),
		"unknown_event_field": bytes.Replace(frame[4:], []byte(`"kind":"begin"`), []byte(`"kind":"begin","extra":0`), 1),
		"unknown":             bytes.Replace(frame[4:], []byte(`"factors":false,`), []byte(`"unknown":false,`), 1),
		"noncanonical":        bytes.Replace(frame[4:], []byte(`"sequence":"1"`), []byte(`"sequence":"01"`), 1),
		"numeric_id":          bytes.Replace(frame[4:], []byte(`"owner":"1"`), []byte(`"owner":1`), 1),
		"unknown_event":       bytes.Replace(frame[4:], []byte(`"kind":"begin"`), []byte(`"kind":"policy"`), 1),
		"coverage_overclaim":  bytes.Replace(frame[4:], []byte(`"selection":false`), []byte(`"selection":true`), 1),
		"null_accounts":       bytes.Replace(frame[4:], []byte(`"accounts":[]`), []byte(`"accounts":null`), 1),
		"wrong_unused":        bytes.Replace(frame[4:], []byte(`"target":"0"`), []byte(`"target":"1"`), 1),
		"duplicate_nested":    bytes.Replace(frame[4:], []byte(`"present":false`), []byte(`"present":false,"present":false`), 1),
	}
	for name, body := range tests {
		t.Run(name, func(t *testing.T) { require.Error(t, ValidateFrame(framed(body))) })
	}
	require.Error(t, ValidateFrame(frame[:len(frame)-1]))
	require.Error(t, ValidateFrame(append(frame, 0)))
	prefix := make([]byte, 4)
	binary.BigEndian.PutUint32(prefix, observation.MaxFrameBytes+1)
	require.Error(t, ValidateFrame(prefix))
	padded := append(append([]byte{}, golden...), bytes.Repeat([]byte(" "), observation.MaxFrameBytes-len(golden))...)
	require.NoError(t, ValidateFrame(framed(padded)), "LIVE_FRAME_EQUALITY")
	require.Error(t, ValidateFrame(framed(append(padded, ' '))), "LIVE_FRAME_LIMIT_PLUS_ONE")
	record.Epoch.Process = math.MaxUint64
	frame, err = EncodeRecord(record)
	require.NoError(t, err)
	require.NoError(t, ValidateFrame(frame))
	record.Batch.EventCount = observation.MaxEvents + 1
	_, err = EncodeRecord(record)
	require.Error(t, err)
	record.Batch.EventCount = 1
	record.Batch.Witness.AccountCount = observation.MaxWitnesses + 1
	_, err = EncodeRecord(record)
	require.Error(t, err)
	for _, kind := range []string{"events", "accounts"} {
		var value map[string]any
		require.NoError(t, json.Unmarshal(golden, &value))
		if kind == "events" {
			event := value["events"].([]any)[0]
			value["events"] = []any{event, event, event, event, event}
		} else {
			value["witness"].(map[string]any)["accounts"] = []any{map[string]any{}, map[string]any{}, map[string]any{}}
		}
		body, err := json.Marshal(value)
		require.NoError(t, err)
		require.Error(t, ValidateFrame(framed(body)))
	}
}
