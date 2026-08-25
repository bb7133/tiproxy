// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package drift

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestSemanticDriftCategories(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		path       string
		content    string
		wantArea   string
		wantCorpus bool
	}{
		{
			name:       "new command",
			path:       "pkg/proxy/net/command.go",
			content:    "package net\n\nconst (\n\tCommandQuery = 3\n\tCommandNew = 33\n)\n",
			wantArea:   "command",
			wantCorpus: true,
		},
		{
			name:     "new config",
			path:     "lib/config/proxy.go",
			content:  "package config\n\ntype Proxy struct {\n\tPort int\n\tNewBehavior bool\n}\n",
			wantArea: "config",
		},
		{
			name:     "new metric",
			path:     "pkg/metrics/session.go",
			content:  "package metrics\n\nvar (\n\tSessions = 1\n\tNewDataplaneMetric = 2\n)\n",
			wantArea: "metric",
		},
		{
			name:       "new error source",
			path:       "pkg/proxy/backend/error.go",
			content:    "package backend\n\nconst (\n\tErrClient = 1\n\tErrNewSource = 2\n)\n",
			wantArea:   "error_source",
			wantCorpus: true,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			repo := newTestRepo(t)
			base := repo.head(t)
			repo.write(t, test.path, test.content)
			head := repo.commit(t, test.name)

			result := checkRange(t, repo.dir, base, head)
			if !result.HasDrift() {
				t.Fatalf("expected %s drift", test.wantArea)
			}
			problem := findProblem(t, result, test.path, test.wantArea)
			if !contains(problem.Missing, "parity manifest row") {
				t.Errorf("missing precise manifest failure: %+v", problem)
			}
			if got := contains(problem.Missing, "protocol corpus case and material"); got != test.wantCorpus {
				t.Errorf("corpus requirement = %v, want %v: %+v", got, test.wantCorpus, problem)
			}
			output := result.CheckOutput()
			if !strings.Contains(output, test.path+" ["+test.wantArea+"]") || !strings.Contains(output, "semantic hashes") {
				t.Errorf("failure is not precise:\n%s", output)
			}
		})
	}
}

func TestCommentsFormattingAndTestsDoNotBlock(t *testing.T) {
	t.Parallel()

	repo := newTestRepo(t)
	base := repo.head(t)
	repo.write(t, "pkg/proxy/net/command.go", `// A comment that does not affect the AST.
package net

const CommandQuery = 3 // another comment
`)
	repo.write(t, "pkg/proxy/net/command_test.go", `package net

func ExampleCommandQuery() {
	_ = CommandQuery
}
`)
	head := repo.commit(t, "comments and test")

	result := checkRange(t, repo.dir, base, head)
	if result.HasDrift() {
		t.Fatalf("comment/test-only changes must not block:\n%s", result.CheckOutput())
	}
	if len(result.Changes) != 0 || len(result.Ignored) != 2 {
		t.Fatalf("unexpected classification: changes=%+v ignored=%+v", result.Changes, result.Ignored)
	}
}

func TestCommandArtifactsSatisfyGate(t *testing.T) {
	t.Parallel()

	repo := newTestRepo(t)
	base := repo.head(t)
	repo.write(t, "pkg/proxy/net/command.go", "package net\n\nconst (\n\tCommandQuery = 3\n\tCommandNew = 33\n)\n")
	repo.write(t, "docs/design/rust-dataplane-parity.md", "| ID | Behavior |\n| --- | --- |\n| CMD-000 | Query and the new command behavior |\n")
	repo.write(t, "tests/dataplane/corpus/v1/manifest.json", `{
  "cases": [
    {
      "id": "query",
      "description": "query plus new command branch",
      "parity_ids": ["CMD-000"]
    }
  ]
}
`)
	repo.write(t, "tests/dataplane/corpus/internal/corpus/corpus.go", "package corpus\n\nconst includesNewCommand = true\n")
	head := repo.commit(t, "command with artifacts")

	result := checkRange(t, repo.dir, base, head)
	if result.HasDrift() {
		t.Fatalf("matching manifest and corpus changes should pass:\n%s", result.CheckOutput())
	}
	if len(result.Changes) != 1 || result.Changes[0].Disposition != "covered" {
		t.Fatalf("unexpected changes: %+v", result.Changes)
	}
}

func TestExactNoImpactDeclaration(t *testing.T) {
	t.Parallel()

	repo := newTestRepo(t)
	base := repo.head(t)
	repo.write(t, "lib/config/proxy.go", "package config\n\ntype Proxy struct {\n\tPort int\n\tInternalCacheHint bool\n}\n")
	changedHead := repo.commit(t, "internal refactor")
	initial := checkRange(t, repo.dir, base, changedHead)
	if !initial.HasDrift() || len(initial.Changes) != 1 {
		t.Fatalf("expected initial drift, got %+v", initial)
	}
	change := initial.Changes[0]
	declaration := noImpactDeclaration{
		SchemaVersion: 1,
		ID:            "NO-IMPACT-INTERNAL-CACHE-HINT",
		Reason:        "This refactor changes only an unused internal cache hint and cannot alter configuration parsing or reload behavior.",
		Owner:         "@bb7133",
		ReviewURL:     "https://github.com/bb7133/tiproxy/pull/99#pullrequestreview-123456",
		Changes: []noImpactDeclaredChange{{
			Path:     change.Path,
			BaseHash: change.BaseHash,
			HeadHash: change.HeadHash,
		}},
	}
	encoded, err := json.MarshalIndent(declaration, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	repo.write(t, ".github/parity-no-impact/internal-cache-hint.json", string(encoded)+"\n")
	declaredHead := repo.commit(t, "add reviewed declaration")

	result := checkRange(t, repo.dir, base, declaredHead)
	if result.HasDrift() {
		t.Fatalf("exact declaration should pass:\n%s", result.CheckOutput())
	}
	if len(result.Changes) != 1 || result.Changes[0].Disposition != "no_impact" || result.Changes[0].WaivedBy != declaration.ID {
		t.Fatalf("unexpected declaration match: %+v", result.Changes)
	}

	repo.write(t, "lib/config/proxy.go", "package config\n\ntype Proxy struct {\n\tPort int\n\tInternalCacheHint int\n}\n")
	staleHead := repo.commit(t, "change after declaration")
	stale := checkRange(t, repo.dir, base, staleHead)
	if !stale.HasDrift() {
		t.Fatal("later semantic edits must invalidate the exact-hash declaration")
	}
}

func TestBuildDirectiveIsSemantic(t *testing.T) {
	t.Parallel()

	baseSource := []byte("//go:build linux\n\npackage proxy\n\nconst enabled = true\n")
	headSource := []byte("//go:build darwin\n\npackage proxy\n\nconst enabled = true\n")
	baseHash, err := semanticHash("pkg/proxy/build.go", baseSource, true)
	if err != nil {
		t.Fatal(err)
	}
	headHash, err := semanticHash("pkg/proxy/build.go", headSource, true)
	if err != nil {
		t.Fatal(err)
	}
	if baseHash == headHash {
		t.Fatal("build directive must affect semantic hash")
	}
}

func TestParseManifestRowsAllowsDigitBearingPrefixes(t *testing.T) {
	t.Parallel()

	rows := parseManifestRows([]byte("| PP2-001 | PROXY protocol v2 |\n| TLS-001 | frontend TLS |\n"))
	if _, ok := rows["PP2-001"]; !ok {
		t.Fatalf("digit-bearing parity prefix was not parsed: %+v", rows)
	}
	if _, ok := rows["TLS-001"]; !ok {
		t.Fatalf("alphabetic parity prefix was not parsed: %+v", rows)
	}
}

func findProblem(t *testing.T, result *Result, path, area string) Problem {
	t.Helper()
	for _, problem := range result.Problems {
		if problem.Path == path && problem.Area == area {
			return problem
		}
	}
	t.Fatalf("no problem for %s [%s]: %+v", path, area, result.Problems)
	return Problem{}
}

func checkRange(t *testing.T, repoDir, base, head string) *Result {
	t.Helper()
	policyPath, err := filepath.Abs(filepath.Join("..", "..", "watch-policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	result, err := Check(context.Background(), Options{
		RepoDir:    repoDir,
		BaseRef:    base,
		HeadRef:    head,
		PolicyPath: policyPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

type testRepo struct {
	dir string
}

func newTestRepo(t *testing.T) testRepo {
	t.Helper()
	repo := testRepo{dir: t.TempDir()}
	repo.git(t, "init", "-q")
	repo.git(t, "config", "user.name", "Parity Drift Test")
	repo.git(t, "config", "user.email", "parity-drift@example.invalid")
	repo.write(t, ".github/CODEOWNERS", "/.github/parity-no-impact/ @bb7133\n")
	repo.write(t, "docs/design/rust-dataplane-parity.md", "| ID | Behavior |\n| --- | --- |\n| CMD-000 | Query |\n| CFG-001 | Config |\n| MTR-001 | Metrics |\n| HS-008 | Errors |\n")
	repo.write(t, "tests/dataplane/corpus/v1/manifest.json", `{"cases":[{"id":"query","description":"query","parity_ids":["CMD-000","HS-008"]}]}`+"\n")
	repo.write(t, "pkg/proxy/net/command.go", "package net\n\nconst CommandQuery = 3\n")
	repo.write(t, "lib/config/proxy.go", "package config\n\ntype Proxy struct { Port int }\n")
	repo.write(t, "pkg/metrics/session.go", "package metrics\n\nvar Sessions = 1\n")
	repo.write(t, "pkg/proxy/backend/error.go", "package backend\n\nconst ErrClient = 1\n")
	repo.commit(t, "initial")
	return repo
}

func (r testRepo) write(t *testing.T, path, content string) {
	t.Helper()
	fullPath := filepath.Join(r.dir, filepath.FromSlash(path))
	if err := os.MkdirAll(filepath.Dir(fullPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fullPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func (r testRepo) commit(t *testing.T, message string) string {
	t.Helper()
	r.git(t, "add", ".")
	r.git(t, "commit", "-q", "-m", message)
	return r.head(t)
}

func (r testRepo) head(t *testing.T) string {
	t.Helper()
	return strings.TrimSpace(r.git(t, "rev-parse", "HEAD"))
}

func (r testRepo) git(t *testing.T, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = r.dir
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v: %s", strings.Join(args, " "), err, output)
	}
	return string(output)
}
