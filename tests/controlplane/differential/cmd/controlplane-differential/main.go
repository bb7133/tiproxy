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

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/pingcap/tiproxy/tests/controlplane/internal/contract"
)

func main() {
	mode := flag.String("mode", "validate", "validate, compare, or self-test")
	baselinePath := flag.String("baseline", "", "Go baseline observation JSON")
	candidatePath := flag.String("candidate", "", "Rust candidate observation JSON")
	flag.Parse()

	root, err := contract.FindRepoRoot(".")
	if err != nil {
		fatal(err)
	}
	switch *mode {
	case "validate":
		if err := contract.ValidateRepository(root); err != nil {
			fatal(err)
		}
		writeJSON(map[string]any{"valid": true, "schema_version": 1})
	case "compare":
		if *baselinePath == "" || *candidatePath == "" {
			fatal(fmt.Errorf("compare mode requires -baseline and -candidate"))
		}
		report, err := compareFiles(root, *baselinePath, *candidatePath)
		if err != nil {
			fatal(err)
		}
		writeJSON(report)
		if !report.Equal {
			os.Exit(1)
		}
	case "self-test":
		testdata := filepath.Join(root, "tests/controlplane/differential/testdata")
		equalReport, err := compareFiles(root,
			filepath.Join(testdata, "go-baseline.v1.json"),
			filepath.Join(testdata, "rust-equivalent.v1.json"))
		if err != nil {
			fatal(err)
		}
		if !equalReport.Equal {
			fatal(fmt.Errorf("equivalent fixture diverged: %+v", equalReport))
		}
		mutationReport, err := compareFiles(root,
			filepath.Join(testdata, "go-baseline.v1.json"),
			filepath.Join(testdata, "rust-mutated.v1.json"))
		if err != nil {
			fatal(err)
		}
		if mutationReport.Equal || mutationReport.ScenarioID != "CP-FAULT-METER-DUPLICATE" ||
			mutationReport.Step != 1 || mutationReport.Field != "counters.last_applied_sequence" {
			fatal(fmt.Errorf("known mutation was not rejected at the expected boundary: %+v", mutationReport))
		}
		writeJSON(map[string]any{
			"equivalent_passed": true,
			"mutation_killed":   true,
			"first_divergence":  mutationReport,
		})
	default:
		fatal(fmt.Errorf("unknown mode %q", *mode))
	}
}

func compareFiles(root, baselinePath, candidatePath string) (contract.Report, error) {
	if err := contract.ValidateRepository(root); err != nil {
		return contract.Report{}, fmt.Errorf("validate repository: %w", err)
	}
	catalog, err := contract.LoadCatalog(root)
	if err != nil {
		return contract.Report{}, err
	}
	faults, err := contract.LoadFaultCatalog(root)
	if err != nil {
		return contract.Report{}, err
	}
	if !filepath.IsAbs(baselinePath) {
		baselinePath = filepath.Join(root, baselinePath)
	}
	if !filepath.IsAbs(candidatePath) {
		candidatePath = filepath.Join(root, candidatePath)
	}
	baseline, err := contract.LoadObservations(baselinePath)
	if err != nil {
		return contract.Report{}, fmt.Errorf("load baseline: %w", err)
	}
	candidate, err := contract.LoadObservations(candidatePath)
	if err != nil {
		return contract.Report{}, fmt.Errorf("load candidate: %w", err)
	}
	if err := contract.ValidateObservationBindings(baseline, catalog, faults); err != nil {
		return contract.Report{}, fmt.Errorf("validate baseline bindings: %w", err)
	}
	if err := contract.ValidateObservationBindings(candidate, catalog, faults); err != nil {
		return contract.Report{}, fmt.Errorf("validate candidate bindings: %w", err)
	}
	return contract.Compare(baseline, candidate), nil
}

func writeJSON(value any) {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		fatal(err)
	}
}

func fatal(err error) {
	_, _ = fmt.Fprintln(os.Stderr, err)
	os.Exit(2)
}
