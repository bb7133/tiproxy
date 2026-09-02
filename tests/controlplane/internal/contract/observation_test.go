// Copyright 2026 PingCAP, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package contract

import (
	"path/filepath"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEquivalentObservationsCompareEqual(t *testing.T) {
	root, err := FindRepoRoot(".")
	require.NoError(t, err)
	baseline, err := LoadObservations(filepath.Join(root, "tests/controlplane/differential/testdata/go-baseline.v1.json"))
	require.NoError(t, err)
	equivalent, err := LoadObservations(filepath.Join(root, "tests/controlplane/differential/testdata/rust-equivalent.v1.json"))
	require.NoError(t, err)

	require.Equal(t, Report{Equal: true}, Compare(baseline, equivalent))
}

func TestMutationReportsFirstExactDivergence(t *testing.T) {
	root, err := FindRepoRoot(".")
	require.NoError(t, err)
	baseline, err := LoadObservations(filepath.Join(root, "tests/controlplane/differential/testdata/go-baseline.v1.json"))
	require.NoError(t, err)
	mutated, err := LoadObservations(filepath.Join(root, "tests/controlplane/differential/testdata/rust-mutated.v1.json"))
	require.NoError(t, err)

	require.Equal(t, Report{
		Equal:      false,
		ScenarioID: "CP-FAULT-METER-DUPLICATE",
		Step:       1,
		Field:      "counters.last_applied_sequence",
		Expected:   int64(1),
		Observed:   int64(2),
	}, Compare(baseline, mutated))
}

func TestObservationRejectsSecretBearingKeys(t *testing.T) {
	observations := ObservationSet{
		SchemaVersion: 1,
		Producer:      "go",
		Observations: []Observation{{
			ScenarioID: "CP-FAULT-CONTROL-UNAVAILABLE",
			Contracts:  []string{"CP-API-001"},
			Outcome:    "ok",
			State:      []Field{{Key: "auth_payload", Value: "redacted"}},
		}},
	}
	err := NormalizeAndValidate(&observations)
	require.ErrorContains(t, err, "forbidden key")
}

func TestSemanticAddressAndOwnerIDAreComparedExactly(t *testing.T) {
	expected := ObservationSet{
		SchemaVersion: 1,
		Producer:      "go",
		Observations: []Observation{{
			ScenarioID: "CP-FAULT-BRIDGE-RECONNECT",
			Contracts:  []string{"CP-BRIDGE-001"},
			Outcome:    "ok",
			State: []Field{
				{Key: "owner_id", Value: "owner-a"},
				{Key: "semantic_address", Value: "127.0.0.1:6000"},
			},
		}},
	}
	observed := expected
	observed.Producer = "rust"
	observed.Observations = slices.Clone(expected.Observations)
	observed.Observations[0].State = slices.Clone(expected.Observations[0].State)
	observed.Observations[0].State[0].Value = "owner-b"
	require.NoError(t, NormalizeAndValidate(&expected))
	require.NoError(t, NormalizeAndValidate(&observed))

	require.Equal(t, Report{
		Equal:      false,
		ScenarioID: "CP-FAULT-BRIDGE-RECONNECT",
		Field:      "state.owner_id",
		Expected:   "owner-a",
		Observed:   "owner-b",
	}, Compare(expected, observed))
}
