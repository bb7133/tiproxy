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
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCoverageRequiresCorpusOrExplicitExclusion(t *testing.T) {
	directory := t.TempDir()
	parity := filepath.Join(directory, "parity.md")
	exclusions := filepath.Join(directory, "exclusions.json")
	require.NoError(t, os.WriteFile(parity, []byte("| ID | Semantics |\n| --- | --- |\n| CMD-001 | covered |\n| MIG-001 | live only |\n"), 0o600))
	require.NoError(t, os.WriteFile(exclusions, []byte(`{"schema_version":1,"exclusions":[{"parity_id":"MIG-001","reason":"Requires a live redirect target and cannot be represented by the immutable byte corpus."}]}`), 0o600))

	manifest := testManifest("case-a")
	report, err := CheckCoverage(manifest, parity, exclusions)
	require.NoError(t, err)
	require.Equal(t, "complete", report.Status)
	require.Equal(t, 2, report.ParityItems)
	require.Equal(t, 1, report.CorpusCovered)
	require.Equal(t, 1, report.ExplicitlyExcluded)

	require.NoError(t, os.WriteFile(exclusions, []byte(`{"schema_version":1,"exclusions":[]}`), 0o600))
	report, err = CheckCoverage(manifest, parity, exclusions)
	require.NoError(t, err)
	require.Equal(t, "incomplete", report.Status)
	require.Equal(t, "MIG-001", report.Divergence.ParityID)
}

func TestCoverageRejectsBothDirectionsOfDrift(t *testing.T) {
	directory := t.TempDir()
	parity := filepath.Join(directory, "parity.md")
	exclusions := filepath.Join(directory, "exclusions.json")
	require.NoError(t, os.WriteFile(parity, []byte("| CMD-001 | covered |\n"), 0o600))
	require.NoError(t, os.WriteFile(exclusions, []byte(`{"schema_version":1,"exclusions":[{"parity_id":"CMD-001","reason":"stale because the corpus now covers this item"}]}`), 0o600))

	report, err := CheckCoverage(testManifest("case-a"), parity, exclusions)
	require.NoError(t, err)
	require.Equal(t, "incomplete", report.Status)
	require.Equal(t, "exclusion", report.Divergence.Field)

	manifest := testManifest("case-a")
	manifest.Cases[0].ParityIDs = []string{"CMD-999"}
	require.NoError(t, os.WriteFile(exclusions, []byte(`{"schema_version":1,"exclusions":[{"parity_id":"CMD-001","reason":"the only manifest item is intentionally excluded from this corpus"}]}`), 0o600))
	report, err = CheckCoverage(manifest, parity, exclusions)
	require.NoError(t, err)
	require.Equal(t, "CMD-999", report.Divergence.ParityID)
	require.Equal(t, "corpus", report.Divergence.Field)
}
