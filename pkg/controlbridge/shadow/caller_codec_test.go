// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package shadow

import (
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
