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

import "encoding/json"

const schemaVersion = 1

type Manifest struct {
	SchemaVersion int          `json:"schema_version"`
	GeneratedBy   string       `json:"generated_by"`
	Cases         []OracleCase `json:"cases"`
}

type OracleCase struct {
	ID        string         `json:"id"`
	ParityIDs []string       `json:"parity_ids"`
	Records   []OracleRecord `json:"records"`
	Expected  OracleExpected `json:"expected"`
}

type OracleRecord struct {
	Direction           string `json:"direction"`
	SequenceStart       uint8  `json:"sequence_start"`
	LogicalPayloadBytes uint64 `json:"logical_payload_bytes"`
	PhysicalPackets     uint64 `json:"physical_packets"`
}

type OracleExpected struct {
	Outcome       string   `json:"outcome"`
	TerminalState string   `json:"terminal_state"`
	ServerStatus  []string `json:"server_status"`
	ErrorCode     uint16   `json:"error_code"`
	Effects       []string `json:"effects"`
}

type Observation struct {
	SchemaVersion  int            `json:"schema_version"`
	Implementation string         `json:"implementation"`
	ShardIndex     int            `json:"shard_index"`
	ShardCount     int            `json:"shard_count"`
	Cases          []ObservedCase `json:"cases"`
}

type ObservedCase struct {
	ID            string           `json:"id"`
	Outcome       string           `json:"outcome"`
	TerminalState string           `json:"terminal_state"`
	ServerStatus  []string         `json:"server_status"`
	ErrorCode     uint16           `json:"error_code"`
	Records       []ObservedRecord `json:"records"`
}

type ObservedRecord struct {
	RecordIndex         int      `json:"record_index"`
	Direction           string   `json:"direction"`
	SequenceStart       uint8    `json:"sequence_start"`
	LogicalPayloadBytes uint64   `json:"logical_payload_bytes"`
	PhysicalPackets     uint64   `json:"physical_packets"`
	State               string   `json:"state"`
	Effects             []string `json:"effects"`
}

type Report struct {
	SchemaVersion  int         `json:"schema_version"`
	Status         string      `json:"status"`
	Implementation string      `json:"implementation"`
	ShardIndex     int         `json:"shard_index"`
	ShardCount     int         `json:"shard_count"`
	CaseCount      int         `json:"case_count"`
	Divergence     *Divergence `json:"divergence,omitempty"`
}

type Divergence struct {
	CaseID          string          `json:"case_id"`
	PacketIndex     int             `json:"packet_index"`
	Field           string          `json:"field"`
	Expected        json.RawMessage `json:"expected"`
	Observed        json.RawMessage `json:"observed"`
	ExpectedEffects []string        `json:"expected_effects,omitempty"`
	ObservedEffects []string        `json:"observed_effects,omitempty"`
}

type CoverageExclusions struct {
	SchemaVersion int         `json:"schema_version"`
	Exclusions    []Exclusion `json:"exclusions"`
}

type Exclusion struct {
	ParityID string `json:"parity_id"`
	Reason   string `json:"reason"`
}

type CoverageReport struct {
	SchemaVersion      int              `json:"schema_version"`
	Status             string           `json:"status"`
	ParityItems        int              `json:"parity_items"`
	CorpusCovered      int              `json:"corpus_covered"`
	ExplicitlyExcluded int              `json:"explicitly_excluded"`
	Divergence         *CoverageFailure `json:"divergence,omitempty"`
}

type CoverageFailure struct {
	ParityID string `json:"parity_id"`
	Field    string `json:"field"`
	Reason   string `json:"reason"`
}

type MutationReport struct {
	SchemaVersion int         `json:"schema_version"`
	Status        string      `json:"status"`
	Mutation      string      `json:"mutation"`
	Divergence    *Divergence `json:"divergence"`
}
