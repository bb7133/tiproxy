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
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"slices"
	"sort"
	"strings"
)

type Field struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type Counter struct {
	Key   string `json:"key"`
	Value int64  `json:"value"`
}

type Subject struct {
	Namespace  string `json:"namespace,omitempty"`
	Cluster    string `json:"cluster,omitempty"`
	Generation uint64 `json:"generation,omitempty"`
}

type Observation struct {
	ScenarioID  string    `json:"scenario_id"`
	Step        uint32    `json:"step"`
	Contracts   []string  `json:"contracts"`
	Subject     Subject   `json:"subject"`
	Outcome     string    `json:"outcome"`
	ErrorClass  string    `json:"error_class,omitempty"`
	ErrorSource string    `json:"error_source,omitempty"`
	Effects     []string  `json:"effects"`
	State       []Field   `json:"state"`
	Counters    []Counter `json:"counters"`
}

type ObservationSet struct {
	SchemaVersion int           `json:"schema_version"`
	Producer      string        `json:"producer"`
	Observations  []Observation `json:"observations"`
}

type Report struct {
	Equal      bool   `json:"equal"`
	ScenarioID string `json:"scenario_id,omitempty"`
	Step       uint32 `json:"step,omitempty"`
	Field      string `json:"field,omitempty"`
	Expected   any    `json:"expected,omitempty"`
	Observed   any    `json:"observed,omitempty"`
}

func LoadObservations(path string) (ObservationSet, error) {
	var observations ObservationSet
	data, err := os.ReadFile(path)
	if err != nil {
		return observations, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&observations); err != nil {
		return observations, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return observations, fmt.Errorf("trailing JSON value")
		}
		return observations, fmt.Errorf("trailing data: %w", err)
	}
	if err := NormalizeAndValidate(&observations); err != nil {
		return observations, err
	}
	return observations, nil
}

func NormalizeAndValidate(observations *ObservationSet) error {
	if observations == nil || observations.SchemaVersion != 1 {
		return fmt.Errorf("observation schema_version must be 1")
	}
	if observations.Producer != "go" && observations.Producer != "rust" {
		return fmt.Errorf("producer must be go or rust")
	}
	seen := make(map[string]struct{}, len(observations.Observations))
	for index := range observations.Observations {
		observation := &observations.Observations[index]
		if !faultIDPattern.MatchString(observation.ScenarioID) || observation.Outcome == "" || len(observation.Contracts) == 0 {
			return fmt.Errorf("observation %d is missing scenario, contract, or outcome", index)
		}
		identity := fmt.Sprintf("%s/%010d", observation.ScenarioID, observation.Step)
		if _, duplicate := seen[identity]; duplicate {
			return fmt.Errorf("duplicate observation %s", identity)
		}
		seen[identity] = struct{}{}
		for _, contractID := range observation.Contracts {
			if !contractIDPattern.MatchString(contractID) {
				return fmt.Errorf("observation %s has invalid contract %q", identity, contractID)
			}
		}
		if err := validateBoundedStrings(identity, observation); err != nil {
			return err
		}
		sort.Strings(observation.Contracts)
		sort.Strings(observation.Effects)
		if len(observation.Contracts) != len(slices.Compact(slices.Clone(observation.Contracts))) ||
			len(observation.Effects) != len(slices.Compact(slices.Clone(observation.Effects))) {
			return fmt.Errorf("observation %s contains duplicate contracts or effects", identity)
		}
		sort.Slice(observation.State, func(i, j int) bool { return observation.State[i].Key < observation.State[j].Key })
		sort.Slice(observation.Counters, func(i, j int) bool { return observation.Counters[i].Key < observation.Counters[j].Key })
		if err := uniqueFieldKeys(identity, observation.State, observation.Counters); err != nil {
			return err
		}
	}
	sort.Slice(observations.Observations, func(i, j int) bool {
		left, right := observations.Observations[i], observations.Observations[j]
		if left.ScenarioID != right.ScenarioID {
			return left.ScenarioID < right.ScenarioID
		}
		return left.Step < right.Step
	})
	return nil
}

func Compare(expected, observed ObservationSet) Report {
	if len(expected.Observations) != len(observed.Observations) {
		return Report{Equal: false, Field: "observations.length", Expected: len(expected.Observations), Observed: len(observed.Observations)}
	}
	for index := range expected.Observations {
		left, right := expected.Observations[index], observed.Observations[index]
		report := compareObservation(left, right)
		if !report.Equal {
			return report
		}
	}
	return Report{Equal: true}
}

func compareObservation(expected, observed Observation) Report {
	base := Report{ScenarioID: expected.ScenarioID, Step: expected.Step}
	for _, comparison := range []struct {
		field    string
		expected any
		observed any
		equal    bool
	}{
		{"scenario_id", expected.ScenarioID, observed.ScenarioID, expected.ScenarioID == observed.ScenarioID},
		{"step", expected.Step, observed.Step, expected.Step == observed.Step},
		{"contracts", expected.Contracts, observed.Contracts, slices.Equal(expected.Contracts, observed.Contracts)},
		{"subject.namespace", expected.Subject.Namespace, observed.Subject.Namespace, expected.Subject.Namespace == observed.Subject.Namespace},
		{"subject.cluster", expected.Subject.Cluster, observed.Subject.Cluster, expected.Subject.Cluster == observed.Subject.Cluster},
		{"subject.generation", expected.Subject.Generation, observed.Subject.Generation, expected.Subject.Generation == observed.Subject.Generation},
		{"outcome", expected.Outcome, observed.Outcome, expected.Outcome == observed.Outcome},
		{"error_class", expected.ErrorClass, observed.ErrorClass, expected.ErrorClass == observed.ErrorClass},
		{"error_source", expected.ErrorSource, observed.ErrorSource, expected.ErrorSource == observed.ErrorSource},
		{"effects", expected.Effects, observed.Effects, slices.Equal(expected.Effects, observed.Effects)},
	} {
		if !comparison.equal {
			base.Field, base.Expected, base.Observed = comparison.field, comparison.expected, comparison.observed
			return base
		}
	}
	if report := compareFields(base, expected.State, observed.State); !report.Equal {
		return report
	}
	if report := compareCounters(base, expected.Counters, observed.Counters); !report.Equal {
		return report
	}
	return Report{Equal: true}
}

func compareFields(base Report, expected, observed []Field) Report {
	if len(expected) != len(observed) {
		base.Field, base.Expected, base.Observed = "state.length", len(expected), len(observed)
		return base
	}
	for index := range expected {
		if expected[index].Key != observed[index].Key {
			base.Field, base.Expected, base.Observed = "state.key", expected[index].Key, observed[index].Key
			return base
		}
		if expected[index].Value != observed[index].Value {
			base.Field = "state." + expected[index].Key
			base.Expected, base.Observed = expected[index].Value, observed[index].Value
			return base
		}
	}
	return Report{Equal: true}
}

func compareCounters(base Report, expected, observed []Counter) Report {
	if len(expected) != len(observed) {
		base.Field, base.Expected, base.Observed = "counters.length", len(expected), len(observed)
		return base
	}
	for index := range expected {
		if expected[index].Key != observed[index].Key {
			base.Field, base.Expected, base.Observed = "counters.key", expected[index].Key, observed[index].Key
			return base
		}
		if expected[index].Value != observed[index].Value {
			base.Field = "counters." + expected[index].Key
			base.Expected, base.Observed = expected[index].Value, observed[index].Value
			return base
		}
	}
	return Report{Equal: true}
}

func validateBoundedStrings(identity string, observation *Observation) error {
	values := []string{
		observation.ScenarioID, observation.Subject.Namespace, observation.Subject.Cluster,
		observation.Outcome, observation.ErrorClass, observation.ErrorSource,
	}
	values = append(values, observation.Contracts...)
	values = append(values, observation.Effects...)
	for _, field := range observation.State {
		values = append(values, field.Key, field.Value)
	}
	for _, counter := range observation.Counters {
		values = append(values, counter.Key)
	}
	for _, value := range values {
		if len(value) > 256 {
			return fmt.Errorf("observation %s contains an overlong string", identity)
		}
	}
	for _, key := range append(fieldKeys(observation.State), counterKeys(observation.Counters)...) {
		lower := strings.ToLower(key)
		for _, forbidden := range []string{"password", "auth", "token", "payload", "sql"} {
			if strings.Contains(lower, forbidden) {
				return fmt.Errorf("observation %s contains forbidden key %q", identity, key)
			}
		}
	}
	return nil
}

func uniqueFieldKeys(identity string, fields []Field, counters []Counter) error {
	seen := make(map[string]struct{}, len(fields)+len(counters))
	for _, key := range append(fieldKeys(fields), counterKeys(counters)...) {
		if key == "" {
			return fmt.Errorf("observation %s contains an empty key", identity)
		}
		if _, duplicate := seen[key]; duplicate {
			return fmt.Errorf("observation %s contains duplicate key %q", identity, key)
		}
		seen[key] = struct{}{}
	}
	return nil
}

func fieldKeys(fields []Field) []string {
	keys := make([]string, 0, len(fields))
	for _, field := range fields {
		keys = append(keys, field.Key)
	}
	return keys
}

func counterKeys(counters []Counter) []string {
	keys := make([]string, 0, len(counters))
	for _, counter := range counters {
		keys = append(keys, counter.Key)
	}
	return keys
}
