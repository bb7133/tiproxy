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

package differential

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCompareEquivalentAndShard(t *testing.T) {
	manifest := testManifest("case-a", "case-b", "case-c")
	observed := Observation{
		SchemaVersion:  schemaVersion,
		Implementation: "rust-dataplane",
		ShardIndex:     1,
		ShardCount:     2,
		Cases:          []ObservedCase{testObservation("case-b")},
	}
	report, err := Compare(manifest, observed, 1, 2)
	require.NoError(t, err)
	require.Equal(t, "equivalent", report.Status)
	require.Nil(t, report.Divergence)
	require.Equal(t, 1, report.CaseCount)
}

func TestCompareReportsFirstPacketField(t *testing.T) {
	manifest := testManifest("case-a", "case-b")
	first := testObservation("case-a")
	first.Records[0].SequenceStart = 9
	second := testObservation("case-b")
	second.TerminalState = "also-wrong"
	observed := Observation{
		SchemaVersion:  schemaVersion,
		Implementation: "rust-dataplane",
		ShardCount:     1,
		Cases:          []ObservedCase{first, second},
	}
	report, err := Compare(manifest, observed, 0, 1)
	require.NoError(t, err)
	require.Equal(t, "diverged", report.Status)
	require.Equal(t, "case-a", report.Divergence.CaseID)
	require.Equal(t, 0, report.Divergence.PacketIndex)
	require.Equal(t, "sequence_start", report.Divergence.Field)
	require.JSONEq(t, "0", string(report.Divergence.Expected))
	require.JSONEq(t, "9", string(report.Divergence.Observed))
}

func TestCompareKillsFinalStateMutationWithEffects(t *testing.T) {
	manifest := testManifest("case-a")
	mutated := testObservation("case-a")
	mutated.Records[0].State = "known_mutation"
	mutated.Records[0].Effects = []string{"known_mutation(final_state)"}
	mutated.TerminalState = "known_mutation"
	observed := Observation{
		SchemaVersion:  schemaVersion,
		Implementation: "rust-dataplane",
		ShardCount:     1,
		Cases:          []ObservedCase{mutated},
	}
	report, err := Compare(manifest, observed, 0, 1)
	require.NoError(t, err)
	require.Equal(t, "state", report.Divergence.Field)
	require.Equal(t, 0, report.Divergence.PacketIndex)
	require.Equal(t, []string{"oracle effect"}, report.Divergence.ExpectedEffects)
	require.Equal(t, []string{"known_mutation(final_state)"}, report.Divergence.ObservedEffects)
}

func testManifest(ids ...string) Manifest {
	manifest := Manifest{SchemaVersion: schemaVersion, GeneratedBy: "test"}
	for _, id := range ids {
		manifest.Cases = append(manifest.Cases, OracleCase{
			ID:        id,
			ParityIDs: []string{"CMD-001"},
			Records: []OracleRecord{{
				Direction:           "client_to_proxy",
				SequenceStart:       0,
				LogicalPayloadBytes: 1,
				PhysicalPackets:     1,
			}},
			Expected: OracleExpected{
				Outcome:       "forward",
				TerminalState: "ready",
				Effects:       []string{"oracle effect"},
			},
		})
	}
	return manifest
}

func testObservation(id string) ObservedCase {
	return ObservedCase{
		ID:            id,
		Outcome:       "forward",
		TerminalState: "ready",
		Records: []ObservedRecord{{
			RecordIndex:         0,
			Direction:           "client_to_proxy",
			SequenceStart:       0,
			LogicalPayloadBytes: 1,
			PhysicalPackets:     1,
			State:               "ready",
		}},
	}
}
