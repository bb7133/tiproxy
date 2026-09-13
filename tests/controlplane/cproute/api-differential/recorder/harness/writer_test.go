// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build apireplay

package harness

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestWriteBindsEnvironmentManifest(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "archive.jsonl"), nil, 0o600))
	environment := []byte(`{"environment":"snapshot"}`)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "environment-manifest.json"), environment, 0o600))
	sum := sha256.Sum256(environment)
	digest := fmt.Sprintf("%x", sum)
	status, err := Write(dir, "N01", "a1", TraceConfig{}, nil, nil, nil, false, CaptureSummary{EnvironmentManifestSHA256: digest})
	require.NoError(t, err)
	require.Equal(t, "recorded", status)
	data, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	require.NoError(t, err)
	var manifest map[string]any
	require.NoError(t, json.Unmarshal(data, &manifest))
	require.Equal(t, "environment-manifest.json", manifest["environment_manifest_file"])
	require.Equal(t, digest, manifest["environment_manifest_sha256"])
	require.Equal(t, digest, manifest["capture"].(map[string]any)["environment_manifest_sha256"])

	changedDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(changedDir, "archive.jsonl"), nil, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(changedDir, "environment-manifest.json"), environment, 0o600))
	_, err = Write(changedDir, "N01", "a2", TraceConfig{}, nil, nil, nil, false, CaptureSummary{EnvironmentManifestSHA256: fmt.Sprintf("%064d", 0)})
	require.ErrorContains(t, err, "environment manifest changed after preflight")
}
