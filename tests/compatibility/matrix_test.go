// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package compatibility

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

type matrixManifest struct {
	SchemaVersion string `json:"schema_version"`
	MatrixVersion string `json:"matrix_version"`
	Environment   struct {
		Architectures []string `json:"architectures"`
		TiDBImage     string   `json:"tidb_image"`
		Variants      []string `json:"dataplane_variants"`
		Variables     []string `json:"required_environment_variables"`
	} `json:"execution_environment"`
	Drivers      []driver     `json:"drivers"`
	Capabilities []capability `json:"capabilities"`
	Cases        []matrixCase `json:"cases"`
	Approval     approval     `json:"approval"`
}

type driver struct {
	ID                string            `json:"id"`
	Version           string            `json:"version"`
	RuntimeImage      string            `json:"runtime_image"`
	Source            string            `json:"source"`
	CapabilitySupport map[string]string `json:"capability_support"`
}

type capability struct {
	ID            string   `json:"id"`
	ParityCaseIDs []string `json:"parity_case_ids"`
}

type matrixCase struct {
	ID             string   `json:"id"`
	DriverID       string   `json:"driver_id"`
	WorkloadID     string   `json:"workload_id"`
	CapabilityIDs  []string `json:"capability_ids"`
	ParityCaseIDs  []string `json:"parity_case_ids"`
	Classification string   `json:"classification"`
	Expected       struct {
		Outcome string `json:"outcome"`
		Detail  string `json:"detail"`
	} `json:"expected"`
	GoBaseline struct {
		Status   string `json:"status"`
		Evidence string `json:"evidence"`
	} `json:"go_baseline"`
}

type approval struct {
	Status        string           `json:"status"`
	RequiredRoles []string         `json:"required_roles"`
	Records       []approvalRecord `json:"records"`
}

type approvalRecord struct {
	Role     string `json:"role"`
	Approver string `json:"approver"`
	Date     string `json:"date"`
}

type workloadManifest struct {
	SchemaVersion   string     `json:"schema_version"`
	WorkloadVersion string     `json:"workload_version"`
	Workloads       []workload `json:"workloads"`
}

type workload struct {
	ID         string   `json:"id"`
	Summary    string   `json:"summary"`
	Operation  string   `json:"operation"`
	Assertions []string `json:"assertions"`
	Steps      []string `json:"steps"`
	Fixture    string   `json:"fixture"`
}

var (
	matrixCaseIDPattern = regexp.MustCompile(`^DRV-(GO|JDBC|PY|NODE|RUST|CLI|WIRE)-[0-9]{3}$`)
	workloadIDPattern   = regexp.MustCompile(`^WL-[A-Z0-9-]+$`)
	parityCaseIDPattern = regexp.MustCompile(`^(HS|TLS|CMP|CMD|RSP|PS|PKT)-[0-9]{3}$`)
)

func TestDriverMatrixContract(t *testing.T) {
	t.Parallel()

	matrix := readJSON[matrixManifest](t, "driver-matrix.v1.json")
	workloads := readJSON[workloadManifest](t, "workloads.v1.json")

	checkVersions(t, matrix, workloads)
	workloadIDs := checkWorkloads(t, workloads)
	driverIDs, capabilityIDs, allowedParityIDs := checkDriversAndCapabilities(t, matrix)
	checkCases(t, matrix, driverIDs, capabilityIDs, allowedParityIDs, workloadIDs)
	checkApproval(t, matrix.Approval)
}

func readJSON[T any](t *testing.T, name string) T {
	t.Helper()

	data, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	var value T
	if err := json.Unmarshal(data, &value); err != nil {
		t.Fatalf("decode %s: %v", name, err)
	}
	return value
}

func checkVersions(t *testing.T, matrix matrixManifest, workloads workloadManifest) {
	t.Helper()

	if matrix.SchemaVersion != "tiproxy-driver-matrix/v1" {
		t.Errorf("unexpected matrix schema %q", matrix.SchemaVersion)
	}
	if workloads.SchemaVersion != "tiproxy-compat-workloads/v1" {
		t.Errorf("unexpected workload schema %q", workloads.SchemaVersion)
	}
	if matrix.MatrixVersion == "" || matrix.MatrixVersion != workloads.WorkloadVersion {
		t.Errorf("matrix version %q must equal workload version %q", matrix.MatrixVersion, workloads.WorkloadVersion)
	}
	wantItems(t, "architectures", matrix.Environment.Architectures, "linux/amd64", "linux/arm64")
	wantItems(t, "dataplane variants", matrix.Environment.Variants, "go", "rust")
	if !strings.Contains(matrix.Environment.TiDBImage, "@sha256:") {
		t.Errorf("TiDB image must be pinned by digest: %q", matrix.Environment.TiDBImage)
	}
	if len(matrix.Environment.Variables) == 0 {
		t.Error("required environment variables are empty")
	}
}

func checkWorkloads(t *testing.T, manifest workloadManifest) map[string]workload {
	t.Helper()

	workloads := make(map[string]workload, len(manifest.Workloads))
	for _, workload := range manifest.Workloads {
		if !workloadIDPattern.MatchString(workload.ID) {
			t.Errorf("invalid workload ID %q", workload.ID)
		}
		if _, exists := workloads[workload.ID]; exists {
			t.Errorf("duplicate workload ID %q", workload.ID)
		}
		if workload.Summary == "" || workload.Operation == "" || len(workload.Assertions) == 0 {
			t.Errorf("workload %s must have summary, operation, and assertions", workload.ID)
		}
		workloads[workload.ID] = workload
	}
	for _, workload := range manifest.Workloads {
		for _, step := range workload.Steps {
			if _, exists := workloads[step]; !exists {
				t.Errorf("workload %s references missing step %s", workload.ID, step)
			}
		}
		if workload.Fixture != "" {
			fixturePath := filepath.Clean(workload.Fixture)
			if fixturePath == "." || filepath.IsAbs(fixturePath) || strings.HasPrefix(fixturePath, "..") {
				t.Errorf("workload %s has unsafe fixture path %q", workload.ID, workload.Fixture)
				continue
			}
			if _, err := os.Stat(fixturePath); err != nil {
				t.Errorf("workload %s fixture %s: %v", workload.ID, fixturePath, err)
			}
		}
	}
	return workloads
}

func checkDriversAndCapabilities(t *testing.T, matrix matrixManifest) (map[string]driver, map[string]capability, map[string]struct{}) {
	t.Helper()

	drivers := make(map[string]driver, len(matrix.Drivers))
	for _, driver := range matrix.Drivers {
		if _, exists := drivers[driver.ID]; exists {
			t.Errorf("duplicate driver ID %q", driver.ID)
		}
		if driver.Version == "" || driver.RuntimeImage == "" || driver.Source == "" {
			t.Errorf("driver %s must pin version, runtime image, and source", driver.ID)
		}
		if driver.ID != "wire-probe" && !strings.Contains(driver.RuntimeImage, "@sha256:") {
			t.Errorf("driver %s runtime image must be pinned by digest: %q", driver.ID, driver.RuntimeImage)
		}
		drivers[driver.ID] = driver
	}
	wantItems(t, "drivers", sortedKeys(drivers),
		"go-database-sql", "jdbc", "mysql-cli", "nodejs", "python", "rust", "wire-probe")

	capabilities := make(map[string]capability, len(matrix.Capabilities))
	allowedParityIDs := make(map[string]struct{})
	for _, capability := range matrix.Capabilities {
		if _, exists := capabilities[capability.ID]; exists {
			t.Errorf("duplicate capability ID %q", capability.ID)
		}
		if len(capability.ParityCaseIDs) == 0 {
			t.Errorf("capability %s has no parity links", capability.ID)
		}
		for _, parityID := range capability.ParityCaseIDs {
			if !parityCaseIDPattern.MatchString(parityID) {
				t.Errorf("capability %s has invalid parity ID %q", capability.ID, parityID)
			}
			allowedParityIDs[parityID] = struct{}{}
		}
		capabilities[capability.ID] = capability
	}
	wantItems(t, "capabilities", sortedKeys(capabilities),
		"auth", "compression_zlib", "compression_zstd", "connection_attributes", "cursor_fetch",
		"deprecated_eof", "large_packets", "local_infile", "multi_statements_results",
		"prepared_statements", "tls_verification")

	allowedSupport := map[string]struct{}{
		"required": {}, "supported_not_configurable": {}, "unsupported_explicit": {}, "probe_only": {},
	}
	for _, driver := range matrix.Drivers {
		for capabilityID := range capabilities {
			support, exists := driver.CapabilitySupport[capabilityID]
			if !exists {
				t.Errorf("driver %s omits capability %s", driver.ID, capabilityID)
				continue
			}
			if _, ok := allowedSupport[support]; !ok {
				t.Errorf("driver %s capability %s has invalid support %q", driver.ID, capabilityID, support)
			}
		}
		for capabilityID := range driver.CapabilitySupport {
			if _, exists := capabilities[capabilityID]; !exists {
				t.Errorf("driver %s references unknown capability %s", driver.ID, capabilityID)
			}
		}
	}
	return drivers, capabilities, allowedParityIDs
}

func checkCases(
	t *testing.T,
	matrix matrixManifest,
	drivers map[string]driver,
	capabilities map[string]capability,
	allowedParityIDs map[string]struct{},
	workloads map[string]workload,
) {
	t.Helper()

	caseIDs := make(map[string]struct{}, len(matrix.Cases))
	driverOutcomes := make(map[string]map[string]bool)
	capabilityOutcomes := make(map[string]map[string]bool)
	for _, testCase := range matrix.Cases {
		if !matrixCaseIDPattern.MatchString(testCase.ID) {
			t.Errorf("invalid matrix case ID %q", testCase.ID)
		}
		if _, exists := caseIDs[testCase.ID]; exists {
			t.Errorf("duplicate matrix case ID %q", testCase.ID)
		}
		caseIDs[testCase.ID] = struct{}{}
		if _, exists := drivers[testCase.DriverID]; !exists {
			t.Errorf("case %s references unknown driver %s", testCase.ID, testCase.DriverID)
		}
		if _, exists := workloads[testCase.WorkloadID]; !exists {
			t.Errorf("case %s references unknown workload %s", testCase.ID, testCase.WorkloadID)
		}
		if testCase.Classification != "blocking" && testCase.Classification != "non_blocking" {
			t.Errorf("case %s has invalid classification %q", testCase.ID, testCase.Classification)
		}
		if testCase.Expected.Detail == "" {
			t.Errorf("case %s has no expected detail", testCase.ID)
		}
		switch testCase.Expected.Outcome {
		case "success", "rejection", "error":
		default:
			t.Errorf("case %s has invalid expected outcome %q", testCase.ID, testCase.Expected.Outcome)
		}
		if testCase.GoBaseline.Status == "" || testCase.GoBaseline.Evidence == "" {
			t.Errorf("case %s must record Go baseline status and evidence", testCase.ID)
		}
		if len(testCase.CapabilityIDs) == 0 || len(testCase.ParityCaseIDs) == 0 {
			t.Errorf("case %s must reference capabilities and parity cases", testCase.ID)
		}
		caseParityIDs := make(map[string]struct{})
		for _, capabilityID := range testCase.CapabilityIDs {
			capability, exists := capabilities[capabilityID]
			if !exists {
				t.Errorf("case %s references unknown capability %s", testCase.ID, capabilityID)
				continue
			}
			for _, parityID := range capability.ParityCaseIDs {
				caseParityIDs[parityID] = struct{}{}
			}
			markOutcome(capabilityOutcomes, capabilityID, testCase.Expected.Outcome)
		}
		for _, parityID := range testCase.ParityCaseIDs {
			if !parityCaseIDPattern.MatchString(parityID) {
				t.Errorf("case %s has invalid parity ID %q", testCase.ID, parityID)
			}
			if _, exists := allowedParityIDs[parityID]; !exists {
				t.Errorf("case %s parity ID %s is not declared in the capability catalog", testCase.ID, parityID)
			}
			if _, exists := caseParityIDs[parityID]; !exists {
				t.Errorf("case %s parity ID %s is not declared by one of its capabilities", testCase.ID, parityID)
			}
		}
		markOutcome(driverOutcomes, testCase.DriverID, testCase.Expected.Outcome)
	}

	for capabilityID := range capabilities {
		outcomes := capabilityOutcomes[capabilityID]
		if !outcomes["success"] || (!outcomes["rejection"] && !outcomes["error"]) {
			t.Errorf("capability %s needs at least one success and one rejection/error case", capabilityID)
		}
	}
	for driverID := range drivers {
		if driverID == "wire-probe" {
			continue
		}
		outcomes := driverOutcomes[driverID]
		if !outcomes["success"] || (!outcomes["rejection"] && !outcomes["error"]) {
			t.Errorf("driver %s needs at least one success and one rejection/error case", driverID)
		}
	}
}

func checkApproval(t *testing.T, approval approval) {
	t.Helper()

	wantItems(t, "approval roles", append([]string(nil), approval.RequiredRoles...), "mysql_protocol_owner", "product_owner")
	if approval.Status != "pending" && approval.Status != "approved" {
		t.Errorf("invalid approval status %q", approval.Status)
	}
	if approval.Status != "approved" {
		return
	}
	approvedRoles := make(map[string]struct{}, len(approval.Records))
	for _, record := range approval.Records {
		if record.Approver == "" || record.Date == "" {
			t.Errorf("approval record for %s must name approver and date", record.Role)
		}
		approvedRoles[record.Role] = struct{}{}
	}
	for _, role := range approval.RequiredRoles {
		if _, exists := approvedRoles[role]; !exists {
			t.Errorf("approval status is approved but role %s has no record", role)
		}
	}
}

func markOutcome(outcomes map[string]map[string]bool, key, outcome string) {
	if outcomes[key] == nil {
		outcomes[key] = make(map[string]bool)
	}
	outcomes[key][outcome] = true
}

func sortedKeys[V any](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func wantItems(t *testing.T, name string, got []string, want ...string) {
	t.Helper()

	sort.Strings(got)
	sort.Strings(want)
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("unexpected %s: got %v, want %v", name, got, want)
	}
}
