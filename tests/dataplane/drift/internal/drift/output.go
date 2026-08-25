// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package drift

import (
	"encoding/json"
	"fmt"
	"strings"
)

// CheckOutput formats the concise blocking CI result.
func (r *Result) CheckOutput() string {
	if !r.HasDrift() {
		return fmt.Sprintf(
			"dataplane parity drift check passed for %s..%s: %d monitored semantic change(s), %d ignored comment/test-only change(s)",
			shortCommit(r.BaseCommit), shortCommit(r.HeadCommit), len(r.Changes), len(r.Ignored),
		)
	}
	var output strings.Builder
	fmt.Fprintf(&output, "dataplane parity drift detected for %s..%s:\n", shortCommit(r.BaseCommit), shortCommit(r.HeadCommit))
	for _, problem := range r.Problems {
		fmt.Fprintf(
			&output,
			"- %s [%s]: missing %s; update a %s parity row",
			problem.Path,
			problem.Area,
			strings.Join(problem.Missing, " and "),
			strings.Join(problem.ManifestPrefixes, "/"),
		)
		if contains(problem.Missing, "protocol corpus case and material") {
			output.WriteString(" and a corpus case linked to that row")
		}
		fmt.Fprintf(&output, ".\n  semantic hashes: base=%s head=%s\n", problem.BaseHash, problem.HeadHash)
	}
	output.WriteString("Update the listed parity artifacts, or add an exact-hash owner-reviewed declaration under .github/parity-no-impact/.\n")
	return strings.TrimSuffix(output.String(), "\n")
}

// MarkdownReport formats the weekly human-readable report.
func (r *Result) MarkdownReport() string {
	var output strings.Builder
	output.WriteString("# TiProxy dataplane parity drift report\n\n")
	fmt.Fprintf(&output, "Range: `%s..%s`\n\n", r.BaseCommit, r.HeadCommit)
	fmt.Fprintf(&output, "- Monitored semantic changes: %d\n", len(r.Changes))
	fmt.Fprintf(&output, "- Ignored comment/test-only changes: %d\n", len(r.Ignored))
	fmt.Fprintf(&output, "- Changed parity rows: %d\n", len(r.ChangedRows))
	fmt.Fprintf(&output, "- Changed corpus cases: %d\n", len(r.ChangedCorpus))
	fmt.Fprintf(&output, "- Outstanding drift findings: %d\n\n", len(r.Problems))

	if len(r.Changes) > 0 {
		output.WriteString("| Path | Area | Disposition | Declaration |\n")
		output.WriteString("| --- | --- | --- | --- |\n")
		for _, change := range r.Changes {
			fmt.Fprintf(
				&output,
				"| `%s` | %s | %s | %s |\n",
				change.Path,
				strings.Join(change.Areas, ", "),
				change.Disposition,
				markdownValue(change.WaivedBy),
			)
		}
		output.WriteByte('\n')
	}
	if len(r.Problems) == 0 {
		output.WriteString("Result: **PASS** — no unaccounted dataplane parity drift.\n")
		return output.String()
	}
	output.WriteString("## Outstanding findings\n\n")
	for _, problem := range r.Problems {
		fmt.Fprintf(
			&output,
			"- `%s` (`%s`): missing %s. Accepted manifest prefixes: `%s`. Base `%s`, head `%s`.\n",
			problem.Path,
			problem.Area,
			strings.Join(problem.Missing, " and "),
			strings.Join(problem.ManifestPrefixes, "`, `"),
			problem.BaseHash,
			problem.HeadHash,
		)
	}
	output.WriteString("\nResult: **FAIL** — update the parity artifacts or add an exact-hash owner-reviewed no-impact declaration.\n")
	return output.String()
}

// HashInventory emits deterministic JSON suitable for a no-impact declaration.
func (r *Result) HashInventory() (string, error) {
	inventory := struct {
		BaseCommit string         `json:"base_commit"`
		HeadCommit string         `json:"head_commit"`
		Changes    []ChangeResult `json:"changes"`
	}{
		BaseCommit: r.BaseCommit,
		HeadCommit: r.HeadCommit,
		Changes:    r.Changes,
	}
	data, err := json.MarshalIndent(inventory, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func contains(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}

func shortCommit(commit string) string {
	if len(commit) <= 12 {
		return commit
	}
	return commit[:12]
}

func markdownValue(value string) string {
	if value == "" {
		return "—"
	}
	return "`" + value + "`"
}
