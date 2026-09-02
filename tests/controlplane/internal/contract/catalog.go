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
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
)

const (
	contractsPath = "tests/controlplane/contracts.v1.json"
	faultsPath    = "tests/controlplane/fault-scenarios.v1.json"
	controlProto  = "proto/dataplane/v1/control.proto"
)

var (
	contractIDPattern = regexp.MustCompile(`^CP-[A-Z]+-[0-9]{3}$`)
	faultIDPattern    = regexp.MustCompile(`^CP-FAULT-[A-Z0-9-]+$`)
	issuePattern      = regexp.MustCompile(`^#[0-9]+$`)
	oneofStartPattern = regexp.MustCompile(`^\s*oneof\s+body\s*\{\s*$`)
	oneofFieldPattern = regexp.MustCompile(`^\s*[A-Za-z0-9_]+\s+([a-z][a-z0-9_]*)\s*=\s*[0-9]+;\s*$`)
)

type Anchor struct {
	Path     string `json:"path"`
	Contains string `json:"contains"`
}

type Contract struct {
	ID             string   `json:"id"`
	Family         string   `json:"family"`
	Summary        string   `json:"summary"`
	GoOwner        string   `json:"go_owner"`
	RustTarget     string   `json:"rust_target"`
	GoBaseline     string   `json:"go_baseline"`
	RustStatus     string   `json:"rust_status"`
	Anchors        []Anchor `json:"anchors"`
	ObservedFields []string `json:"observed_fields"`
	FaultScenarios []string `json:"fault_scenarios"`
	BridgeMessages []string `json:"bridge_messages"`
	Handoff        string   `json:"handoff"`
}

type BridgeMessage struct {
	Name        string `json:"name"`
	Direction   string `json:"direction"`
	TargetIssue string `json:"target_issue"`
}

type Catalog struct {
	SchemaVersion  int             `json:"schema_version"`
	Families       []string        `json:"families"`
	Contracts      []Contract      `json:"contracts"`
	BridgeMessages []BridgeMessage `json:"bridge_messages"`
}

type FaultScenario struct {
	ID             string   `json:"id"`
	Summary        string   `json:"summary"`
	TargetIssue    string   `json:"target_issue"`
	Contracts      []string `json:"contracts"`
	Steps          []string `json:"steps"`
	Expectations   []string `json:"expectations"`
	ObservedFields []string `json:"observed_fields"`
}

type FaultCatalog struct {
	SchemaVersion int             `json:"schema_version"`
	Scenarios     []FaultScenario `json:"scenarios"`
}

func FindRepoRoot(start string) (string, error) {
	current, err := filepath.Abs(start)
	if err != nil {
		return "", err
	}
	for {
		if metadata, statErr := os.Stat(filepath.Join(current, "go.mod")); statErr == nil && !metadata.IsDir() {
			return current, nil
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", fmt.Errorf("find repository root from %q: go.mod not found", start)
		}
		current = parent
	}
}

func LoadCatalog(root string) (Catalog, error) {
	var catalog Catalog
	if err := decodeStrict(filepath.Join(root, contractsPath), &catalog); err != nil {
		return Catalog{}, err
	}
	return catalog, nil
}

func LoadFaultCatalog(root string) (FaultCatalog, error) {
	var catalog FaultCatalog
	if err := decodeStrict(filepath.Join(root, faultsPath), &catalog); err != nil {
		return FaultCatalog{}, err
	}
	return catalog, nil
}

func ValidateRepository(root string) error {
	catalog, err := LoadCatalog(root)
	if err != nil {
		return err
	}
	faults, err := LoadFaultCatalog(root)
	if err != nil {
		return err
	}
	if err := ValidateCatalog(root, catalog, faults); err != nil {
		return err
	}
	for _, schemaPath := range []string{
		"tests/controlplane/schema/contracts.v1.schema.json",
		"tests/controlplane/schema/fault-scenarios.v1.schema.json",
		"tests/controlplane/schema/observations.v1.schema.json",
	} {
		data, readErr := os.ReadFile(filepath.Join(root, schemaPath))
		if readErr != nil {
			return fmt.Errorf("read schema %s: %w", schemaPath, readErr)
		}
		if !json.Valid(data) {
			return fmt.Errorf("schema %s is not valid JSON", schemaPath)
		}
	}
	return nil
}

func ValidateCatalog(root string, catalog Catalog, faults FaultCatalog) error {
	if catalog.SchemaVersion != 1 {
		return fmt.Errorf("contracts schema_version must be 1, got %d", catalog.SchemaVersion)
	}
	if faults.SchemaVersion != 1 {
		return fmt.Errorf("fault schema_version must be 1, got %d", faults.SchemaVersion)
	}
	if len(catalog.Families) == 0 || !sort.StringsAreSorted(catalog.Families) {
		return fmt.Errorf("families must be nonempty and sorted")
	}
	if len(catalog.Families) != len(slices.Compact(slices.Clone(catalog.Families))) {
		return fmt.Errorf("families must be unique")
	}
	if len(catalog.Contracts) == 0 || len(catalog.BridgeMessages) == 0 || len(faults.Scenarios) == 0 {
		return fmt.Errorf("contracts, bridge messages, and fault scenarios must be nonempty")
	}

	familySet := make(map[string]struct{}, len(catalog.Families))
	familyCoverage := make(map[string]int, len(catalog.Families))
	for _, family := range catalog.Families {
		if strings.TrimSpace(family) == "" {
			return fmt.Errorf("family names must be nonempty")
		}
		familySet[family] = struct{}{}
	}

	contractSet := make(map[string]struct{}, len(catalog.Contracts))
	bridgeReferences := make(map[string]int, len(catalog.BridgeMessages))
	for _, contract := range catalog.Contracts {
		if !contractIDPattern.MatchString(contract.ID) {
			return fmt.Errorf("contract id %q is invalid", contract.ID)
		}
		if _, duplicate := contractSet[contract.ID]; duplicate {
			return fmt.Errorf("duplicate contract id %q", contract.ID)
		}
		contractSet[contract.ID] = struct{}{}
		if _, ok := familySet[contract.Family]; !ok {
			return fmt.Errorf("contract %s has unknown family %q", contract.ID, contract.Family)
		}
		familyCoverage[contract.Family]++
		if strings.TrimSpace(contract.Summary) == "" || strings.TrimSpace(contract.GoOwner) == "" ||
			strings.TrimSpace(contract.Handoff) == "" {
			return fmt.Errorf("contract %s has an empty summary, owner, or handoff", contract.ID)
		}
		if !issuePattern.MatchString(contract.RustTarget) {
			return fmt.Errorf("contract %s has invalid rust_target %q", contract.ID, contract.RustTarget)
		}
		if contract.GoBaseline != "anchored" ||
			!slices.Contains([]string{"pending", "shadow", "parity", "owned"}, contract.RustStatus) {
			return fmt.Errorf("contract %s has invalid baseline/status %q/%q", contract.ID, contract.GoBaseline, contract.RustStatus)
		}
		if len(contract.Anchors) < 2 || len(contract.ObservedFields) == 0 || len(contract.FaultScenarios) == 0 {
			return fmt.Errorf("contract %s needs at least two anchors plus observed and fault bindings", contract.ID)
		}
		for _, anchor := range contract.Anchors {
			if err := validateAnchor(root, contract.ID, anchor); err != nil {
				return err
			}
		}
		for _, message := range contract.BridgeMessages {
			bridgeReferences[message]++
		}
	}
	for _, family := range catalog.Families {
		if familyCoverage[family] == 0 {
			return fmt.Errorf("family %q has no contract", family)
		}
	}

	protoMessages, err := readControlOneof(filepath.Join(root, controlProto))
	if err != nil {
		return err
	}
	catalogMessages := make([]string, 0, len(catalog.BridgeMessages))
	seenMessages := make(map[string]struct{}, len(catalog.BridgeMessages))
	for _, message := range catalog.BridgeMessages {
		if _, duplicate := seenMessages[message.Name]; duplicate {
			return fmt.Errorf("duplicate bridge message %q", message.Name)
		}
		seenMessages[message.Name] = struct{}{}
		catalogMessages = append(catalogMessages, message.Name)
		if message.Direction != "go_to_rust" && message.Direction != "rust_to_go" && message.Direction != "bidirectional" {
			return fmt.Errorf("bridge message %s has invalid direction %q", message.Name, message.Direction)
		}
		if !issuePattern.MatchString(message.TargetIssue) {
			return fmt.Errorf("bridge message %s has invalid target_issue %q", message.Name, message.TargetIssue)
		}
		if bridgeReferences[message.Name] == 0 {
			return fmt.Errorf("bridge message %s is not referenced by a contract", message.Name)
		}
	}
	sort.Strings(catalogMessages)
	if !slices.Equal(protoMessages, catalogMessages) {
		return fmt.Errorf("bridge inventory drift: proto=%v catalog=%v", protoMessages, catalogMessages)
	}
	for message := range bridgeReferences {
		if _, ok := seenMessages[message]; !ok {
			return fmt.Errorf("contract references unknown bridge message %q", message)
		}
	}

	faultSet := make(map[string]struct{}, len(faults.Scenarios))
	for _, scenario := range faults.Scenarios {
		if !faultIDPattern.MatchString(scenario.ID) || strings.TrimSpace(scenario.Summary) == "" {
			return fmt.Errorf("fault scenario %q is invalid", scenario.ID)
		}
		if _, duplicate := faultSet[scenario.ID]; duplicate {
			return fmt.Errorf("duplicate fault scenario %q", scenario.ID)
		}
		faultSet[scenario.ID] = struct{}{}
		if !issuePattern.MatchString(scenario.TargetIssue) || len(scenario.Contracts) == 0 ||
			len(scenario.Steps) == 0 || len(scenario.Expectations) == 0 || len(scenario.ObservedFields) == 0 {
			return fmt.Errorf("fault scenario %s is incomplete", scenario.ID)
		}
		for _, contractID := range scenario.Contracts {
			if _, ok := contractSet[contractID]; !ok {
				return fmt.Errorf("fault scenario %s references unknown contract %s", scenario.ID, contractID)
			}
			if !slices.Contains(findContract(catalog.Contracts, contractID).FaultScenarios, scenario.ID) {
				return fmt.Errorf("fault scenario %s and contract %s are not bound in both directions", scenario.ID, contractID)
			}
		}
	}
	for _, contract := range catalog.Contracts {
		for _, scenarioID := range contract.FaultScenarios {
			if _, ok := faultSet[scenarioID]; !ok {
				return fmt.Errorf("contract %s references unknown fault scenario %s", contract.ID, scenarioID)
			}
			if !slices.Contains(findFault(faults.Scenarios, scenarioID).Contracts, contract.ID) {
				return fmt.Errorf("contract %s and fault scenario %s are not bound in both directions", contract.ID, scenarioID)
			}
		}
	}
	for _, target := range []string{"#142", "#143", "#144", "#145", "#146", "#147", "#148", "#149", "#150"} {
		covered := false
		for _, contract := range catalog.Contracts {
			covered = covered || contract.RustTarget == target
		}
		if !covered {
			return fmt.Errorf("M1 target %s has no contract handoff", target)
		}
	}
	return nil
}

func findFault(scenarios []FaultScenario, id string) FaultScenario {
	for _, scenario := range scenarios {
		if scenario.ID == id {
			return scenario
		}
	}
	return FaultScenario{}
}

func findContract(contracts []Contract, id string) Contract {
	for _, contract := range contracts {
		if contract.ID == id {
			return contract
		}
	}
	return Contract{}
}

func ValidateObservationBindings(observations ObservationSet, catalog Catalog, faults FaultCatalog) error {
	contractSet := make(map[string]struct{}, len(catalog.Contracts))
	for _, contract := range catalog.Contracts {
		contractSet[contract.ID] = struct{}{}
	}
	faultSet := make(map[string]FaultScenario, len(faults.Scenarios))
	for _, scenario := range faults.Scenarios {
		faultSet[scenario.ID] = scenario
	}
	for _, observation := range observations.Observations {
		scenario, ok := faultSet[observation.ScenarioID]
		if !ok {
			return fmt.Errorf("observation references unknown scenario %s", observation.ScenarioID)
		}
		for _, contractID := range observation.Contracts {
			if _, ok := contractSet[contractID]; !ok {
				return fmt.Errorf("observation %s references unknown contract %s", observation.ScenarioID, contractID)
			}
			if !slices.Contains(scenario.Contracts, contractID) {
				return fmt.Errorf("observation %s is not bound to contract %s", observation.ScenarioID, contractID)
			}
		}
	}
	return nil
}

func decodeStrict(path string, target any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("decode %s: %w", path, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("decode %s: trailing JSON value", path)
		}
		return fmt.Errorf("decode %s: trailing data: %w", path, err)
	}
	return nil
}

func validateAnchor(root, contractID string, anchor Anchor) error {
	if anchor.Path == "" || anchor.Contains == "" || filepath.IsAbs(anchor.Path) ||
		strings.HasPrefix(filepath.Clean(anchor.Path), "..") {
		return fmt.Errorf("contract %s has unsafe or empty anchor %+v", contractID, anchor)
	}
	data, err := os.ReadFile(filepath.Join(root, anchor.Path))
	if err != nil {
		return fmt.Errorf("contract %s read anchor %s: %w", contractID, anchor.Path, err)
	}
	if !bytes.Contains(data, []byte(anchor.Contains)) {
		return fmt.Errorf("contract %s anchor %s no longer contains %q", contractID, anchor.Path, anchor.Contains)
	}
	return nil
}

func readControlOneof(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open control proto: %w", err)
	}
	defer file.Close()

	inBody := false
	var messages []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if !inBody {
			inBody = oneofStartPattern.MatchString(line)
			continue
		}
		if strings.TrimSpace(line) == "}" {
			break
		}
		if strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), "//") {
			continue
		}
		match := oneofFieldPattern.FindStringSubmatch(line)
		if len(match) != 2 {
			return nil, fmt.Errorf("unrecognized ControlEnvelope body field %q", line)
		}
		messages = append(messages, match[1])
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read control proto: %w", err)
	}
	if !inBody || len(messages) == 0 {
		return nil, fmt.Errorf("ControlEnvelope oneof body not found")
	}
	sort.Strings(messages)
	return messages, nil
}
