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
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
)

var parityRow = regexp.MustCompile(`^\|\s*([A-Z]+-[0-9]{3})\s*\|`)

func CheckCoverage(manifest Manifest, parityPath, exclusionsPath string) (CoverageReport, error) {
	report := CoverageReport{SchemaVersion: schemaVersion, Status: "complete"}
	parityIDs, err := loadParityIDs(parityPath)
	if err != nil {
		return report, err
	}
	exclusions, err := loadExclusions(exclusionsPath)
	if err != nil {
		return report, err
	}
	if exclusions.SchemaVersion != schemaVersion {
		return report, fmt.Errorf("unsupported exclusion schema %d", exclusions.SchemaVersion)
	}

	covered := make(map[string]struct{})
	for _, corpusCase := range manifest.Cases {
		for _, parityID := range corpusCase.ParityIDs {
			covered[parityID] = struct{}{}
		}
	}
	excluded := make(map[string]string, len(exclusions.Exclusions))
	for _, exclusion := range exclusions.Exclusions {
		if exclusion.ParityID == "" || strings.TrimSpace(exclusion.Reason) == "" {
			return report, fmt.Errorf("every exclusion requires a parity_id and reason")
		}
		if _, exists := excluded[exclusion.ParityID]; exists {
			return report, fmt.Errorf("duplicate exclusion %s", exclusion.ParityID)
		}
		excluded[exclusion.ParityID] = exclusion.Reason
	}

	report.ParityItems = len(parityIDs)
	report.CorpusCovered = len(covered)
	report.ExplicitlyExcluded = len(excluded)
	for _, parityID := range sortedKeys(covered) {
		if _, exists := parityIDs[parityID]; !exists {
			return coverageFailure(report, parityID, "corpus", "corpus references an ID absent from the parity manifest"), nil
		}
		if _, exists := excluded[parityID]; exists {
			return coverageFailure(report, parityID, "exclusion", "covered ID still has a stale exclusion"), nil
		}
	}
	for _, parityID := range sortedKeys(excluded) {
		if _, exists := parityIDs[parityID]; !exists {
			return coverageFailure(report, parityID, "exclusion", "exclusion references an ID absent from the parity manifest"), nil
		}
	}
	for _, parityID := range sortedKeys(parityIDs) {
		_, isCovered := covered[parityID]
		_, isExcluded := excluded[parityID]
		if !isCovered && !isExcluded {
			return coverageFailure(report, parityID, "coverage", "parity item has neither a corpus case nor an explicit exclusion"), nil
		}
	}
	return report, nil
}

func coverageFailure(report CoverageReport, parityID, field, reason string) CoverageReport {
	report.Status = "incomplete"
	report.Divergence = &CoverageFailure{ParityID: parityID, Field: field, Reason: reason}
	return report
}

func loadParityIDs(path string) (map[string]struct{}, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	ids := make(map[string]struct{})
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		match := parityRow.FindStringSubmatch(scanner.Text())
		if len(match) == 2 {
			ids[match[1]] = struct{}{}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("no parity rows found in %s", path)
	}
	return ids, nil
}

func loadExclusions(path string) (CoverageExclusions, error) {
	var exclusions CoverageExclusions
	data, err := os.ReadFile(path)
	if err != nil {
		return exclusions, err
	}
	if err := json.Unmarshal(data, &exclusions); err != nil {
		return exclusions, err
	}
	return exclusions, nil
}

func sortedKeys[V any](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
