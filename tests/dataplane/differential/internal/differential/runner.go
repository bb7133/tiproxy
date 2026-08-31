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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

type RunOptions struct {
	Root          string
	Corpus        string
	ShardIndex    int
	ShardCount    int
	ObservedPath  string
	KnownMutation string
}

func LoadManifest(path string) (Manifest, error) {
	var manifest Manifest
	data, err := os.ReadFile(path)
	if err != nil {
		return manifest, err
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		return manifest, err
	}
	return manifest, nil
}

func ObserveRust(ctx context.Context, options RunOptions) (Observation, error) {
	var observed Observation
	if options.ObservedPath != "" {
		data, err := os.ReadFile(options.ObservedPath)
		if err != nil {
			return observed, err
		}
		if err := json.Unmarshal(data, &observed); err != nil {
			return observed, err
		}
		return observed, nil
	}

	corpus := options.Corpus
	if !filepath.IsAbs(corpus) {
		corpus = filepath.Join(options.Root, corpus)
	}
	arguments := []string{
		"run",
		"--quiet",
		"--locked",
		"--manifest-path", filepath.Join(options.Root, "rust", "Cargo.toml"),
		"-p", "tiproxy-differential-runner",
		"--",
		"--corpus", corpus,
		"--shard-index", strconv.Itoa(options.ShardIndex),
		"--shard-count", strconv.Itoa(options.ShardCount),
	}
	if options.KnownMutation != "" {
		arguments = append(arguments, "--known-mutation", options.KnownMutation)
	}
	command := exec.CommandContext(ctx, "cargo", arguments...)
	command.Dir = options.Root
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		return observed, fmt.Errorf("Rust consumer failed: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	if err := json.Unmarshal(stdout.Bytes(), &observed); err != nil {
		return observed, fmt.Errorf("decode Rust observation: %w", err)
	}
	return observed, nil
}

func RunComparison(ctx context.Context, options RunOptions) (Report, error) {
	manifestPath := options.Corpus
	if !filepath.IsAbs(manifestPath) {
		manifestPath = filepath.Join(options.Root, manifestPath)
	}
	manifest, err := LoadManifest(filepath.Join(manifestPath, "manifest.json"))
	if err != nil {
		return Report{}, err
	}
	observed, err := ObserveRust(ctx, options)
	if err != nil {
		return Report{}, err
	}
	return Compare(manifest, observed, options.ShardIndex, options.ShardCount)
}
