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
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/pingcap/tiproxy/tests/dataplane/differential/internal/differential"
)

func main() {
	if err := run(context.Background()); err != nil {
		writeJSON(os.Stderr, map[string]any{
			"schema_version": 1,
			"status":         "error",
			"error":          err.Error(),
		})
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	mode := flag.String("mode", "compare", "compare, coverage, or mutation-self-check")
	root := flag.String("root", ".", "repository root")
	corpus := flag.String("corpus", "tests/dataplane/corpus/v1", "immutable Go oracle corpus")
	observed := flag.String("observed", "", "read a Rust observation JSON instead of invoking cargo")
	shardIndex := flag.Int("shard-index", 0, "zero-based shard index")
	shardCount := flag.Int("shard-count", 1, "positive shard count")
	flag.Parse()

	options := differential.RunOptions{
		Root:         *root,
		Corpus:       *corpus,
		ObservedPath: *observed,
		ShardIndex:   *shardIndex,
		ShardCount:   *shardCount,
	}
	switch *mode {
	case "compare":
		report, err := differential.RunComparison(ctx, options)
		if err != nil {
			return err
		}
		writeJSON(os.Stdout, report)
		if report.Status != "equivalent" {
			return fmt.Errorf("first Go/Rust divergence: %s packet %d field %s", report.Divergence.CaseID, report.Divergence.PacketIndex, report.Divergence.Field)
		}
		return nil
	case "mutation-self-check":
		if options.ObservedPath != "" {
			return fmt.Errorf("mutation self-check cannot use a precomputed observation")
		}
		options.KnownMutation = "final-state"
		report, err := differential.RunComparison(ctx, options)
		if err != nil {
			return err
		}
		if report.Status != "diverged" || report.Divergence == nil || report.Divergence.PacketIndex < 0 || report.Divergence.Field != "state" {
			return fmt.Errorf("known Rust mutation survived: %#v", report)
		}
		writeJSON(os.Stdout, differential.MutationReport{
			SchemaVersion: 1,
			Status:        "mutation_killed",
			Mutation:      options.KnownMutation,
			Divergence:    report.Divergence,
		})
		return nil
	case "coverage":
		manifestPath := *corpus
		if !filepath.IsAbs(manifestPath) {
			manifestPath = filepath.Join(*root, manifestPath)
		}
		manifest, err := differential.LoadManifest(filepath.Join(manifestPath, "manifest.json"))
		if err != nil {
			return err
		}
		report, err := differential.CheckCoverage(
			manifest,
			filepath.Join(*root, "docs", "design", "rust-dataplane-parity.md"),
			filepath.Join(*root, "tests", "dataplane", "differential", "parity-exclusions.json"),
		)
		if err != nil {
			return err
		}
		writeJSON(os.Stdout, report)
		if report.Status != "complete" {
			return fmt.Errorf("parity coverage incomplete at %s", report.Divergence.ParityID)
		}
		return nil
	default:
		return fmt.Errorf("unknown mode %q", *mode)
	}
}

func writeJSON(file *os.File, value any) {
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		panic(err)
	}
}
