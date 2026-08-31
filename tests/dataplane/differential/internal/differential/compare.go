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
	"encoding/json"
	"fmt"
	"reflect"
)

func Compare(manifest Manifest, observed Observation, shardIndex, shardCount int) (Report, error) {
	report := Report{
		SchemaVersion:  schemaVersion,
		Status:         "equivalent",
		Implementation: observed.Implementation,
		ShardIndex:     shardIndex,
		ShardCount:     shardCount,
	}
	if shardCount <= 0 || shardIndex < 0 || shardIndex >= shardCount {
		return report, fmt.Errorf("invalid shard %d/%d", shardIndex, shardCount)
	}
	if manifest.SchemaVersion != schemaVersion {
		return report, fmt.Errorf("unsupported corpus schema %d", manifest.SchemaVersion)
	}
	if observed.SchemaVersion != schemaVersion {
		return report, fmt.Errorf("unsupported observation schema %d", observed.SchemaVersion)
	}
	if observed.Implementation != "rust-dataplane" {
		return report, fmt.Errorf("unexpected implementation %q", observed.Implementation)
	}
	if observed.ShardIndex != shardIndex || observed.ShardCount != shardCount {
		return report, fmt.Errorf(
			"observation shard %d/%d does not match requested shard %d/%d",
			observed.ShardIndex,
			observed.ShardCount,
			shardIndex,
			shardCount,
		)
	}

	expected := shardCases(manifest.Cases, shardIndex, shardCount)
	report.CaseCount = len(expected)
	limit := min(len(expected), len(observed.Cases))
	for index := 0; index < limit; index++ {
		if divergence := compareCase(expected[index], observed.Cases[index]); divergence != nil {
			report.Status = "diverged"
			report.Divergence = divergence
			return report, nil
		}
	}
	if len(expected) != len(observed.Cases) {
		caseID := "<end>"
		if limit < len(expected) {
			caseID = expected[limit].ID
		} else if limit < len(observed.Cases) {
			caseID = observed.Cases[limit].ID
		}
		report.Status = "diverged"
		report.Divergence = newDivergence(caseID, -1, "case_count", len(expected), len(observed.Cases), nil, nil)
	}
	return report, nil
}

func shardCases(cases []OracleCase, shardIndex, shardCount int) []OracleCase {
	selected := make([]OracleCase, 0, (len(cases)+shardCount-1)/shardCount)
	for index, oracleCase := range cases {
		if index%shardCount == shardIndex {
			selected = append(selected, oracleCase)
		}
	}
	return selected
}

func compareCase(expected OracleCase, observed ObservedCase) *Divergence {
	if expected.ID != observed.ID {
		return newDivergence(expected.ID, -1, "case_id", expected.ID, observed.ID, nil, nil)
	}
	limit := min(len(expected.Records), len(observed.Records))
	for index := 0; index < limit; index++ {
		want := expected.Records[index]
		got := observed.Records[index]
		for _, field := range []struct {
			name     string
			expected any
			observed any
		}{
			{"record_index", index, got.RecordIndex},
			{"direction", want.Direction, got.Direction},
			{"sequence_start", want.SequenceStart, got.SequenceStart},
			{"logical_payload_bytes", want.LogicalPayloadBytes, got.LogicalPayloadBytes},
			{"physical_packets", want.PhysicalPackets, got.PhysicalPackets},
		} {
			if !reflect.DeepEqual(field.expected, field.observed) {
				return newDivergence(expected.ID, index, field.name, field.expected, field.observed, expected.Expected.Effects, got.Effects)
			}
		}
	}
	if len(expected.Records) != len(observed.Records) {
		return newDivergence(expected.ID, limit, "record_count", len(expected.Records), len(observed.Records), expected.Expected.Effects, nil)
	}
	packetIndex := len(expected.Records) - 1
	var effects []string
	if packetIndex >= 0 {
		effects = observed.Records[packetIndex].Effects
		if expected.Expected.TerminalState != observed.Records[packetIndex].State {
			return newDivergence(
				expected.ID,
				packetIndex,
				"state",
				expected.Expected.TerminalState,
				observed.Records[packetIndex].State,
				expected.Expected.Effects,
				effects,
			)
		}
	}
	for _, field := range []struct {
		name     string
		expected any
		observed any
	}{
		{"outcome", expected.Expected.Outcome, observed.Outcome},
		{"terminal_state", expected.Expected.TerminalState, observed.TerminalState},
		{"server_status", normalizeStrings(expected.Expected.ServerStatus), normalizeStrings(observed.ServerStatus)},
		{"error_code", expected.Expected.ErrorCode, observed.ErrorCode},
	} {
		if !reflect.DeepEqual(field.expected, field.observed) {
			return newDivergence(expected.ID, packetIndex, field.name, field.expected, field.observed, expected.Expected.Effects, effects)
		}
	}
	return nil
}

func normalizeStrings(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}

func newDivergence(
	caseID string,
	packetIndex int,
	field string,
	expected any,
	observed any,
	expectedEffects []string,
	observedEffects []string,
) *Divergence {
	return &Divergence{
		CaseID:          caseID,
		PacketIndex:     packetIndex,
		Field:           field,
		Expected:        mustJSON(expected),
		Observed:        mustJSON(observed),
		ExpectedEffects: expectedEffects,
		ObservedEffects: observedEffects,
	}
}

func mustJSON(value any) json.RawMessage {
	encoded, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return encoded
}
