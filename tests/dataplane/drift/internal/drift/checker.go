// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package drift

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"go/format"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const absentSemantic = "tiproxy-parity-drift:absent:v1"

var (
	manifestRowPattern = regexp.MustCompile(`^\|\s*([A-Z0-9]+-[0-9]{3})\s*\|`)
	sha256Pattern      = regexp.MustCompile(`^[0-9a-f]{64}$`)
	declarationID      = regexp.MustCompile(`^NO-IMPACT-[A-Z0-9-]+$`)
	ownerPattern       = regexp.MustCompile(`^@[A-Za-z0-9-]+$`)
	reviewURLPattern   = regexp.MustCompile(`^https://github\.com/.+/pull/[0-9]+#pullrequestreview-[0-9]+$`)
)

// Options defines one immutable Git range to inspect.
type Options struct {
	RepoDir    string
	BaseRef    string
	HeadRef    string
	PolicyPath string
}

// Result is the deterministic result of one parity-drift check.
type Result struct {
	BaseCommit        string         `json:"base_commit"`
	HeadCommit        string         `json:"head_commit"`
	ChangedRows       []string       `json:"changed_manifest_rows"`
	ChangedCorpus     []string       `json:"changed_corpus_cases"`
	Changes           []ChangeResult `json:"changes"`
	Ignored           []string       `json:"ignored"`
	Problems          []Problem      `json:"problems"`
	NoImpactDocuments []string       `json:"no_impact_documents"`
}

// ChangeResult records one semantically changed monitored production file.
type ChangeResult struct {
	Path        string   `json:"path"`
	BaseHash    string   `json:"base_semantic_sha256"`
	HeadHash    string   `json:"head_semantic_sha256"`
	Areas       []string `json:"areas"`
	Disposition string   `json:"disposition"`
	WaivedBy    string   `json:"waived_by,omitempty"`
}

// Problem explains which parity artifact is missing for one behavior area.
type Problem struct {
	Path             string   `json:"path"`
	Area             string   `json:"area"`
	AreaDescription  string   `json:"area_description"`
	Missing          []string `json:"missing"`
	ManifestPrefixes []string `json:"accepted_manifest_prefixes"`
	BaseHash         string   `json:"base_semantic_sha256"`
	HeadHash         string   `json:"head_semantic_sha256"`
}

// HasDrift reports whether the range contains unaccounted semantic changes.
func (r *Result) HasDrift() bool {
	return len(r.Problems) > 0
}

type watchPolicy struct {
	SchemaVersion          int         `json:"schema_version"`
	ParityManifest         string      `json:"parity_manifest"`
	CorpusManifest         string      `json:"corpus_manifest"`
	CorpusMaterialPrefixes []string    `json:"corpus_material_prefixes"`
	NoImpactDirectory      string      `json:"no_impact_directory"`
	Areas                  []watchArea `json:"areas"`
}

type watchArea struct {
	ID               string   `json:"id"`
	Description      string   `json:"description"`
	PathExact        []string `json:"path_exact"`
	PathPrefix       []string `json:"path_prefix"`
	ManifestPrefixes []string `json:"manifest_prefixes"`
	CorpusRequired   bool     `json:"corpus_required"`
}

type fileChange struct {
	Status  string
	OldPath string
	NewPath string
}

type semanticChange struct {
	Path     string
	BaseHash string
	HeadHash string
	Areas    []watchArea
}

type noImpactDeclaration struct {
	SchemaVersion int                      `json:"schema_version"`
	ID            string                   `json:"id"`
	Reason        string                   `json:"reason"`
	Owner         string                   `json:"owner"`
	ReviewURL     string                   `json:"review_url"`
	Changes       []noImpactDeclaredChange `json:"changes"`
}

type noImpactDeclaredChange struct {
	Path     string `json:"path"`
	BaseHash string `json:"base_semantic_sha256"`
	HeadHash string `json:"head_semantic_sha256"`
}

type corpusManifest struct {
	Cases []map[string]any `json:"cases"`
}

// Check inspects a Git range using the repository-local watch policy.
func Check(ctx context.Context, options Options) (*Result, error) {
	if options.RepoDir == "" {
		options.RepoDir = "."
	}
	if options.BaseRef == "" || options.HeadRef == "" {
		return nil, errors.New("both base and head refs are required")
	}
	policyPath := options.PolicyPath
	if policyPath == "" {
		policyPath = filepath.Join(options.RepoDir, "tests/dataplane/drift/watch-policy.json")
	}
	policy, err := loadPolicy(policyPath)
	if err != nil {
		return nil, err
	}
	repo := gitRepo{dir: options.RepoDir}
	baseCommit, err := repo.revParse(ctx, options.BaseRef)
	if err != nil {
		return nil, fmt.Errorf("resolve base ref %q: %w", options.BaseRef, err)
	}
	headCommit, err := repo.revParse(ctx, options.HeadRef)
	if err != nil {
		return nil, fmt.Errorf("resolve head ref %q: %w", options.HeadRef, err)
	}
	changes, err := repo.diff(ctx, baseCommit, headCommit)
	if err != nil {
		return nil, err
	}

	changedRows, err := changedManifestRows(ctx, repo, baseCommit, headCommit, policy.ParityManifest)
	if err != nil {
		return nil, err
	}
	changedCorpus, corpusParityIDs, err := changedCorpusCases(ctx, repo, baseCommit, headCommit, policy.CorpusManifest)
	if err != nil {
		return nil, err
	}
	corpusMaterialChanged, err := hasCorpusMaterialChange(ctx, repo, baseCommit, headCommit, changes, policy.CorpusMaterialPrefixes)
	if err != nil {
		return nil, err
	}
	declarations, declarationPaths, err := loadDeclarations(ctx, repo, headCommit, policy.NoImpactDirectory)
	if err != nil {
		return nil, err
	}

	result := &Result{
		BaseCommit:        baseCommit,
		HeadCommit:        headCommit,
		ChangedRows:       sortedSet(changedRows),
		ChangedCorpus:     changedCorpus,
		NoImpactDocuments: declarationPaths,
	}
	for _, change := range changes {
		semantic, ignored, err := classifySemanticChange(ctx, repo, baseCommit, headCommit, change, policy.Areas)
		if err != nil {
			return nil, err
		}
		if ignored != "" {
			result.Ignored = append(result.Ignored, ignored)
			continue
		}
		if semantic == nil {
			continue
		}
		changeResult := ChangeResult{
			Path:        semantic.Path,
			BaseHash:    semantic.BaseHash,
			HeadHash:    semantic.HeadHash,
			Areas:       areaIDs(semantic.Areas),
			Disposition: "covered",
		}
		if declaration := matchingDeclaration(declarations, *semantic); declaration != "" {
			changeResult.Disposition = "no_impact"
			changeResult.WaivedBy = declaration
			result.Changes = append(result.Changes, changeResult)
			continue
		}

		for _, area := range semantic.Areas {
			missing := missingArtifacts(area, changedRows, corpusParityIDs, corpusMaterialChanged)
			if len(missing) == 0 {
				continue
			}
			changeResult.Disposition = "drift"
			result.Problems = append(result.Problems, Problem{
				Path:             semantic.Path,
				Area:             area.ID,
				AreaDescription:  area.Description,
				Missing:          missing,
				ManifestPrefixes: append([]string(nil), area.ManifestPrefixes...),
				BaseHash:         semantic.BaseHash,
				HeadHash:         semantic.HeadHash,
			})
		}
		result.Changes = append(result.Changes, changeResult)
	}
	sort.Strings(result.Ignored)
	sort.Slice(result.Changes, func(i, j int) bool { return result.Changes[i].Path < result.Changes[j].Path })
	sort.Slice(result.Problems, func(i, j int) bool {
		if result.Problems[i].Path == result.Problems[j].Path {
			return result.Problems[i].Area < result.Problems[j].Area
		}
		return result.Problems[i].Path < result.Problems[j].Path
	})
	return result, nil
}

func loadPolicy(path string) (watchPolicy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return watchPolicy{}, fmt.Errorf("read drift policy %s: %w", path, err)
	}
	var policy watchPolicy
	if err := json.Unmarshal(data, &policy); err != nil {
		return watchPolicy{}, fmt.Errorf("decode drift policy %s: %w", path, err)
	}
	if policy.SchemaVersion != 1 || policy.ParityManifest == "" || policy.CorpusManifest == "" || len(policy.Areas) == 0 {
		return watchPolicy{}, fmt.Errorf("invalid drift policy %s", path)
	}
	seen := make(map[string]struct{}, len(policy.Areas))
	for _, area := range policy.Areas {
		if area.ID == "" || area.Description == "" || len(area.ManifestPrefixes) == 0 {
			return watchPolicy{}, fmt.Errorf("invalid drift policy area %q", area.ID)
		}
		if _, exists := seen[area.ID]; exists {
			return watchPolicy{}, fmt.Errorf("duplicate drift policy area %q", area.ID)
		}
		seen[area.ID] = struct{}{}
	}
	return policy, nil
}

type gitRepo struct {
	dir string
}

func (r gitRepo) command(ctx context.Context, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = r.dir
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return output, nil
}

func (r gitRepo) revParse(ctx context.Context, ref string) (string, error) {
	output, err := r.command(ctx, "rev-parse", "--verify", ref+"^{commit}")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}

func (r gitRepo) diff(ctx context.Context, base, head string) ([]fileChange, error) {
	output, err := r.command(ctx, "diff", "--name-status", "--find-renames", "-z", base, head, "--")
	if err != nil {
		return nil, fmt.Errorf("list changed files: %w", err)
	}
	fields := bytes.Split(output, []byte{0})
	changes := make([]fileChange, 0, len(fields)/2)
	for i := 0; i < len(fields) && len(fields[i]) > 0; {
		status := string(fields[i])
		i++
		if i >= len(fields) {
			return nil, errors.New("malformed NUL-delimited git diff output")
		}
		oldPath := string(fields[i])
		newPath := oldPath
		i++
		if strings.HasPrefix(status, "R") || strings.HasPrefix(status, "C") {
			if i >= len(fields) {
				return nil, errors.New("malformed rename in git diff output")
			}
			newPath = string(fields[i])
			i++
		}
		if strings.HasPrefix(status, "A") {
			oldPath = ""
		}
		if strings.HasPrefix(status, "D") {
			newPath = ""
		}
		changes = append(changes, fileChange{Status: status, OldPath: oldPath, NewPath: newPath})
	}
	return changes, nil
}

func (r gitRepo) content(ctx context.Context, ref, path string) ([]byte, bool, error) {
	if path == "" {
		return nil, false, nil
	}
	// git receives ref:path as one argv value; no shell interprets it.
	cmd := exec.CommandContext(ctx, "git", "cat-file", "-e", ref+":"+path) //nolint:gosec
	cmd.Dir = r.dir
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("check %s:%s: %w", ref, path, err)
	}
	output, err := r.command(ctx, "show", ref+":"+path)
	if err != nil {
		return nil, false, err
	}
	return output, true, nil
}

func (r gitRepo) listFiles(ctx context.Context, ref, directory string) ([]string, error) {
	output, err := r.command(ctx, "ls-tree", "-r", "--name-only", ref, "--", directory)
	if err != nil {
		return nil, err
	}
	var files []string
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		if line != "" {
			files = append(files, line)
		}
	}
	sort.Strings(files)
	return files, nil
}

func classifySemanticChange(
	ctx context.Context,
	repo gitRepo,
	base, head string,
	change fileChange,
	areas []watchArea,
) (*semanticChange, string, error) {
	matched := matchingAreas(change.OldPath, change.NewPath, areas)
	if len(matched) == 0 {
		return nil, "", nil
	}
	oldContent, oldExists, err := repo.content(ctx, base, change.OldPath)
	if err != nil {
		return nil, "", err
	}
	newContent, newExists, err := repo.content(ctx, head, change.NewPath)
	if err != nil {
		return nil, "", err
	}
	path := change.NewPath
	if path == "" {
		path = change.OldPath
	}
	if allExistingPathsAreTests(change, oldExists, newExists) {
		return nil, path + " (test-only)", nil
	}
	baseHash, err := semanticHash(change.OldPath, oldContent, oldExists)
	if err != nil {
		return nil, "", fmt.Errorf("normalize %s at %s: %w", change.OldPath, base, err)
	}
	headHash, err := semanticHash(change.NewPath, newContent, newExists)
	if err != nil {
		return nil, "", fmt.Errorf("normalize %s at %s: %w", change.NewPath, head, err)
	}
	if baseHash == headHash {
		return nil, path + " (comment-or-format-only)", nil
	}
	return &semanticChange{Path: path, BaseHash: baseHash, HeadHash: headHash, Areas: matched}, "", nil
}

func matchingAreas(oldPath, newPath string, areas []watchArea) []watchArea {
	var specific []watchArea
	var fallback *watchArea
	for i := range areas {
		area := areas[i]
		if !areaMatches(area, oldPath) && !areaMatches(area, newPath) {
			continue
		}
		if area.ID == "dataplane" {
			copyOfArea := area
			fallback = &copyOfArea
		} else {
			specific = append(specific, area)
		}
	}
	if len(specific) == 0 && fallback != nil {
		specific = append(specific, *fallback)
	}
	sort.Slice(specific, func(i, j int) bool { return specific[i].ID < specific[j].ID })
	return specific
}

func areaMatches(area watchArea, path string) bool {
	if path == "" {
		return false
	}
	for _, exact := range area.PathExact {
		if path == exact {
			return true
		}
	}
	for _, prefix := range area.PathPrefix {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

func allExistingPathsAreTests(change fileChange, oldExists, newExists bool) bool {
	if oldExists && !strings.HasSuffix(change.OldPath, "_test.go") {
		return false
	}
	if newExists && !strings.HasSuffix(change.NewPath, "_test.go") {
		return false
	}
	return oldExists || newExists
}

func semanticHash(path string, content []byte, exists bool) (string, error) {
	if !exists {
		sum := sha256.Sum256([]byte(absentSemantic))
		return hex.EncodeToString(sum[:]), nil
	}
	normalized := content
	if strings.HasSuffix(path, ".go") {
		var err error
		normalized, err = normalizeGo(content)
		if err != nil {
			return "", err
		}
	}
	// The repository path is part of Go build selection (package directory and
	// filename suffixes such as _linux.go), so a rename is semantic even when
	// the formatted AST is byte-identical.
	hashInput := make([]byte, 0, len(path)+1+len(normalized))
	hashInput = append(hashInput, path...)
	hashInput = append(hashInput, '\n')
	hashInput = append(hashInput, normalized...)
	sum := sha256.Sum256(hashInput)
	return hex.EncodeToString(sum[:]), nil
}

func normalizeGo(content []byte) ([]byte, error) {
	file, err := parser.ParseFile(token.NewFileSet(), "semantic.go", content, parser.SkipObjectResolution)
	if err != nil {
		return nil, err
	}
	var formatted bytes.Buffer
	if err := format.Node(&formatted, token.NewFileSet(), file); err != nil {
		return nil, err
	}
	var directives []string
	scanner := bufio.NewScanner(bytes.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "//go:") || strings.HasPrefix(line, "// +build") || strings.HasPrefix(line, "//line ") {
			directives = append(directives, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	sort.Strings(directives)
	formatted.WriteByte('\n')
	formatted.WriteString(strings.Join(directives, "\n"))
	return formatted.Bytes(), nil
}

func changedManifestRows(ctx context.Context, repo gitRepo, base, head, path string) (map[string]struct{}, error) {
	baseContent, _, err := repo.content(ctx, base, path)
	if err != nil {
		return nil, err
	}
	headContent, _, err := repo.content(ctx, head, path)
	if err != nil {
		return nil, err
	}
	baseRows := parseManifestRows(baseContent)
	headRows := parseManifestRows(headContent)
	changed := make(map[string]struct{})
	for id, baseRow := range baseRows {
		if headRow, exists := headRows[id]; !exists || headRow != baseRow {
			changed[id] = struct{}{}
		}
	}
	for id, headRow := range headRows {
		if baseRow, exists := baseRows[id]; !exists || headRow != baseRow {
			changed[id] = struct{}{}
		}
	}
	return changed, nil
}

func parseManifestRows(content []byte) map[string]string {
	rows := make(map[string]string)
	scanner := bufio.NewScanner(bytes.NewReader(content))
	for scanner.Scan() {
		line := scanner.Text()
		match := manifestRowPattern.FindStringSubmatch(line)
		if len(match) == 2 {
			rows[match[1]] = strings.Join(strings.Fields(line), " ")
		}
	}
	return rows
}

func changedCorpusCases(
	ctx context.Context,
	repo gitRepo,
	base, head, path string,
) ([]string, map[string]struct{}, error) {
	baseContent, _, err := repo.content(ctx, base, path)
	if err != nil {
		return nil, nil, err
	}
	headContent, _, err := repo.content(ctx, head, path)
	if err != nil {
		return nil, nil, err
	}
	baseCases, err := parseCorpusCases(baseContent)
	if err != nil {
		return nil, nil, fmt.Errorf("parse %s at %s: %w", path, base, err)
	}
	headCases, err := parseCorpusCases(headContent)
	if err != nil {
		return nil, nil, fmt.Errorf("parse %s at %s: %w", path, head, err)
	}
	changed := make(map[string]struct{})
	parityIDs := make(map[string]struct{})
	for id, baseCase := range baseCases {
		headCase, exists := headCases[id]
		if !exists || !bytes.Equal(baseCase.canonical, headCase.canonical) {
			changed[id] = struct{}{}
			for _, parityID := range baseCase.parityIDs {
				parityIDs[parityID] = struct{}{}
			}
			for _, parityID := range headCase.parityIDs {
				parityIDs[parityID] = struct{}{}
			}
		}
	}
	for id, headCase := range headCases {
		if _, exists := baseCases[id]; !exists {
			changed[id] = struct{}{}
			for _, parityID := range headCase.parityIDs {
				parityIDs[parityID] = struct{}{}
			}
		}
	}
	return sortedSet(changed), parityIDs, nil
}

type parsedCorpusCase struct {
	canonical []byte
	parityIDs []string
}

func parseCorpusCases(content []byte) (map[string]parsedCorpusCase, error) {
	if len(content) == 0 {
		return map[string]parsedCorpusCase{}, nil
	}
	var manifest corpusManifest
	if err := json.Unmarshal(content, &manifest); err != nil {
		return nil, err
	}
	cases := make(map[string]parsedCorpusCase, len(manifest.Cases))
	for _, item := range manifest.Cases {
		id, ok := item["id"].(string)
		if !ok || id == "" {
			return nil, errors.New("corpus case has no string id")
		}
		if _, exists := cases[id]; exists {
			return nil, fmt.Errorf("duplicate corpus case %s", id)
		}
		canonical, err := json.Marshal(item)
		if err != nil {
			return nil, err
		}
		var parityIDs []string
		if rawParity, ok := item["parity_ids"].([]any); ok {
			for _, rawID := range rawParity {
				if id, ok := rawID.(string); ok {
					parityIDs = append(parityIDs, id)
				}
			}
		}
		cases[id] = parsedCorpusCase{canonical: canonical, parityIDs: parityIDs}
	}
	return cases, nil
}

func hasCorpusMaterialChange(
	ctx context.Context,
	repo gitRepo,
	base, head string,
	changes []fileChange,
	prefixes []string,
) (bool, error) {
	for _, change := range changes {
		path := change.NewPath
		if path == "" {
			path = change.OldPath
		}
		if !hasAnyPrefix(change.OldPath, prefixes) && !hasAnyPrefix(change.NewPath, prefixes) {
			continue
		}
		oldContent, oldExists, err := repo.content(ctx, base, change.OldPath)
		if err != nil {
			return false, err
		}
		newContent, newExists, err := repo.content(ctx, head, change.NewPath)
		if err != nil {
			return false, err
		}
		if allExistingPathsAreTests(change, oldExists, newExists) {
			continue
		}
		oldHash, err := semanticHash(change.OldPath, oldContent, oldExists)
		if err != nil {
			return false, fmt.Errorf("normalize corpus material %s: %w", path, err)
		}
		newHash, err := semanticHash(change.NewPath, newContent, newExists)
		if err != nil {
			return false, fmt.Errorf("normalize corpus material %s: %w", path, err)
		}
		if oldHash != newHash {
			return true, nil
		}
	}
	return false, nil
}

func loadDeclarations(
	ctx context.Context,
	repo gitRepo,
	head, directory string,
) ([]noImpactDeclaration, []string, error) {
	files, err := repo.listFiles(ctx, head, directory)
	if err != nil {
		return nil, nil, err
	}
	var declarationFiles []string
	for _, path := range files {
		if filepath.Ext(path) == ".json" && filepath.Base(path) != "schema.json" {
			declarationFiles = append(declarationFiles, path)
		}
	}
	if len(declarationFiles) == 0 {
		return nil, nil, nil
	}
	owners, err := noImpactOwners(ctx, repo, head, directory)
	if err != nil {
		return nil, nil, err
	}
	var declarations []noImpactDeclaration
	var declarationPaths []string
	seen := make(map[string]struct{})
	for _, path := range declarationFiles {
		content, _, err := repo.content(ctx, head, path)
		if err != nil {
			return nil, nil, err
		}
		var declaration noImpactDeclaration
		if err := json.Unmarshal(content, &declaration); err != nil {
			return nil, nil, fmt.Errorf("decode no-impact declaration %s: %w", path, err)
		}
		if err := validateDeclaration(declaration, owners); err != nil {
			return nil, nil, fmt.Errorf("invalid no-impact declaration %s: %w", path, err)
		}
		if _, exists := seen[declaration.ID]; exists {
			return nil, nil, fmt.Errorf("duplicate no-impact declaration id %s", declaration.ID)
		}
		seen[declaration.ID] = struct{}{}
		declarations = append(declarations, declaration)
		declarationPaths = append(declarationPaths, path)
	}
	return declarations, declarationPaths, nil
}

func noImpactOwners(ctx context.Context, repo gitRepo, head, directory string) (map[string]struct{}, error) {
	content, exists, err := repo.content(ctx, head, ".github/CODEOWNERS")
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.New(".github/CODEOWNERS is required for no-impact declarations")
	}
	wanted := "/" + strings.TrimPrefix(strings.TrimSuffix(directory, "/"), "/") + "/"
	owners := make(map[string]struct{})
	scanner := bufio.NewScanner(bytes.NewReader(content))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 || fields[0] != wanted {
			continue
		}
		for _, owner := range fields[1:] {
			owners[owner] = struct{}{}
		}
	}
	if len(owners) == 0 {
		return nil, fmt.Errorf("CODEOWNERS has no owner for %s", wanted)
	}
	return owners, nil
}

func validateDeclaration(declaration noImpactDeclaration, owners map[string]struct{}) error {
	if declaration.SchemaVersion != 1 || !declarationID.MatchString(declaration.ID) {
		return errors.New("schema_version must be 1 and id must match NO-IMPACT-[A-Z0-9-]+")
	}
	if len(strings.TrimSpace(declaration.Reason)) < 40 {
		return errors.New("reason must contain at least 40 characters")
	}
	if !ownerPattern.MatchString(declaration.Owner) {
		return fmt.Errorf("invalid owner %q", declaration.Owner)
	}
	if _, exists := owners[declaration.Owner]; !exists {
		return fmt.Errorf("owner %s is not a CODEOWNER for parity-no-impact", declaration.Owner)
	}
	if !reviewURLPattern.MatchString(declaration.ReviewURL) {
		return fmt.Errorf("invalid review_url %q", declaration.ReviewURL)
	}
	if len(declaration.Changes) == 0 {
		return errors.New("changes must not be empty")
	}
	seen := make(map[string]struct{}, len(declaration.Changes))
	for _, change := range declaration.Changes {
		if change.Path == "" || filepath.IsAbs(change.Path) || strings.HasPrefix(filepath.Clean(change.Path), "..") {
			return fmt.Errorf("unsafe change path %q", change.Path)
		}
		if !sha256Pattern.MatchString(change.BaseHash) || !sha256Pattern.MatchString(change.HeadHash) {
			return fmt.Errorf("change %s has invalid semantic hashes", change.Path)
		}
		if _, exists := seen[change.Path]; exists {
			return fmt.Errorf("duplicate change path %s", change.Path)
		}
		seen[change.Path] = struct{}{}
	}
	return nil
}

func matchingDeclaration(declarations []noImpactDeclaration, change semanticChange) string {
	for _, declaration := range declarations {
		for _, declared := range declaration.Changes {
			if declared.Path == change.Path && declared.BaseHash == change.BaseHash && declared.HeadHash == change.HeadHash {
				return declaration.ID
			}
		}
	}
	return ""
}

func missingArtifacts(
	area watchArea,
	changedRows map[string]struct{},
	corpusParityIDs map[string]struct{},
	corpusMaterialChanged bool,
) []string {
	var missing []string
	if !hasIDWithPrefix(changedRows, area.ManifestPrefixes) {
		missing = append(missing, "parity manifest row")
	}
	if area.CorpusRequired && (!corpusMaterialChanged || !hasIDWithPrefix(corpusParityIDs, area.ManifestPrefixes)) {
		missing = append(missing, "protocol corpus case and material")
	}
	return missing
}

func hasIDWithPrefix(ids map[string]struct{}, prefixes []string) bool {
	for id := range ids {
		prefix := id
		if dash := strings.IndexByte(id, '-'); dash >= 0 {
			prefix = id[:dash]
		}
		for _, allowed := range prefixes {
			if prefix == allowed {
				return true
			}
		}
	}
	return false
}

func hasAnyPrefix(path string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

func areaIDs(areas []watchArea) []string {
	ids := make([]string, 0, len(areas))
	for _, area := range areas {
		ids = append(ids, area.ID)
	}
	return ids
}

func sortedSet(values map[string]struct{}) []string {
	items := make([]string, 0, len(values))
	for value := range values {
		items = append(items, value)
	}
	sort.Strings(items)
	return items
}
