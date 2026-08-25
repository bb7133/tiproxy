// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package corpus

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGenerateIsDeterministic(t *testing.T) {
	first := t.TempDir()
	second := t.TempDir()
	require.NoError(t, Write(first))
	require.NoError(t, Write(second))
	require.NoError(t, compareTrees(first, second))
	require.NoError(t, Validate(first))
}

func TestComparatorDetectsMutatedImplementation(t *testing.T) {
	manifest := Build()
	observed := ExpectedObservations(manifest, "rust-mutant")
	require.NotEmpty(t, observed.Cases)
	observed.Cases[0].TerminalState = "mutated-state"
	err := Compare(manifest, observed)
	require.Error(t, err)
	require.Contains(t, err.Error(), observed.Cases[0].ID)
	require.Contains(t, err.Error(), "mutated-state")
}

func TestComparatorRejectsMissingAndUnknownCases(t *testing.T) {
	manifest := Build()
	observed := ExpectedObservations(manifest, "rust-incomplete")
	missingID := observed.Cases[len(observed.Cases)-1].ID
	observed.Cases = observed.Cases[:len(observed.Cases)-1]
	observed.Cases = append(observed.Cases, Observation{ID: "not-in-corpus", Outcome: "accept", TerminalState: "ready", Effects: []string{"none"}})
	err := Compare(manifest, observed)
	require.Error(t, err)
	require.Contains(t, err.Error(), missingID)
	require.Contains(t, err.Error(), "not-in-corpus")
}
