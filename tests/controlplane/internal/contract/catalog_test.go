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
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRepositoryCatalog(t *testing.T) {
	root, err := FindRepoRoot(".")
	require.NoError(t, err)
	require.NoError(t, ValidateRepository(root))
}

func TestBridgeInventoryDriftFailsClosed(t *testing.T) {
	root, err := FindRepoRoot(".")
	require.NoError(t, err)
	catalog, err := LoadCatalog(root)
	require.NoError(t, err)
	faults, err := LoadFaultCatalog(root)
	require.NoError(t, err)

	catalog.BridgeMessages = catalog.BridgeMessages[1:]
	err = ValidateCatalog(root, catalog, faults)
	require.ErrorContains(t, err, "bridge inventory drift")
}

func TestAnchorDriftFailsClosed(t *testing.T) {
	root, err := FindRepoRoot(".")
	require.NoError(t, err)
	catalog, err := LoadCatalog(root)
	require.NoError(t, err)
	faults, err := LoadFaultCatalog(root)
	require.NoError(t, err)

	catalog.Contracts[0].Anchors[0].Contains = "definitely-not-a-real-symbol"
	err = ValidateCatalog(root, catalog, faults)
	require.ErrorContains(t, err, "no longer contains")
}

func TestFindRepoRootFailsOutsideRepository(t *testing.T) {
	directory := t.TempDir()
	_, err := FindRepoRoot(directory)
	require.ErrorContains(t, err, "go.mod not found")
	_, err = os.Stat(directory)
	require.NoError(t, err)
}
