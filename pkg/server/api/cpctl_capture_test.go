// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// CP-ADMIN slice 4d oracle: the real `tiproxyctl` binary runs the shared
// command script against the production API server (plaintext, and the cmux
// TLS branch with auto certificates, driven with --insecure); the Rust replay
// runs the same binary against the Rust admin listener.
type cpctlCommand struct {
	Name string   `json:"name"`
	Args []string `json:"args"`
}

type cpctlScript struct {
	Files    map[string]string `json:"files"`
	Commands []cpctlCommand    `json:"commands"`
}

type cpctlObservation struct {
	Name     string `json:"name"`
	Stdout   string `json:"stdout"`
	ExitCode int    `json:"exit_code"`
}

type cpctlCapture struct {
	Plain []cpctlObservation `json:"plain"`
	TLS   []cpctlObservation `json:"tls"`
}

func cpctlWriteFiles(t *testing.T, dir string, files map[string]string) {
	for name, content := range files {
		path := filepath.Join(dir, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
		require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	}
}

// cpctlArgs resolves `@name` fixture references to paths inside dir.
func cpctlArgs(dir string, args []string) []string {
	resolved := make([]string, 0, len(args))
	for _, arg := range args {
		if strings.HasPrefix(arg, "@") {
			arg = filepath.Join(dir, strings.TrimPrefix(arg, "@"))
		}
		resolved = append(resolved, arg)
	}
	return resolved
}

func cpctlRun(t *testing.T, binary, dir, host string, port int, insecure bool, script *cpctlScript) []cpctlObservation {
	observations := make([]cpctlObservation, 0, len(script.Commands))
	for _, command := range script.Commands {
		args := []string{"--host", host, "--port", strconv.Itoa(port)}
		if insecure {
			args = append(args, "--insecure")
		}
		args = append(args, cpctlArgs(dir, command.Args)...)
		cmd := exec.Command(binary, args...)
		// Never route through an inherited proxy; keep the environment minimal
		// so the binary's own logger has no file to write.
		cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + dir, "NO_PROXY=*", "no_proxy=*"}
		out, err := cmd.Output()
		exitCode := 0
		if err != nil {
			exitErr, ok := err.(*exec.ExitError)
			require.True(t, ok, "%s: %v", command.Name, err)
			exitCode = exitErr.ExitCode()
		}
		observations = append(observations, cpctlObservation{
			Name:     command.Name,
			Stdout:   strings.TrimRight(string(out), "\n"),
			ExitCode: exitCode,
		})
	}
	return observations
}

func TestCPCtlCapture(t *testing.T) {
	out := os.Getenv("CPCTL_CAPTURE_OUT")
	if out == "" {
		t.Skip("CPCTL_CAPTURE_OUT is not set")
	}
	binary := os.Getenv("CPCTL_TIPROXYCTL")
	require.NotEmpty(t, binary, "CPCTL_TIPROXYCTL must name the tiproxyctl binary")
	raw, err := os.ReadFile(os.Getenv("CPCTL_SCRIPT"))
	require.NoError(t, err)
	var script cpctlScript
	require.NoError(t, json.Unmarshal(raw, &script))
	capture := cpctlCapture{}
	for _, tlsMode := range []bool{false, true} {
		dir := t.TempDir()
		cpctlWriteFiles(t, dir, script.Files)
		config := "enable-traffic-replay = false\n"
		if tlsMode {
			config += "security.server-http-tls.auto-certs = true\n"
		}
		srv, _, _ := createServerWithConfig(t, config)
		addr := srv.listener.Addr().(interface{ String() string }).String()
		_, portText, err := splitHostPort(addr)
		require.NoError(t, err)
		port, err := strconv.Atoi(portText)
		require.NoError(t, err)
		observations := cpctlRun(t, binary, dir, "127.0.0.1", port, tlsMode, &script)
		if tlsMode {
			capture.TLS = observations
		} else {
			capture.Plain = observations
		}
	}
	encoded, err := json.MarshalIndent(capture, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(out, append(encoded, '\n'), 0o600))
}

func splitHostPort(addr string) (string, string, error) {
	index := strings.LastIndex(addr, ":")
	if index < 0 {
		return "", "", os.ErrInvalid
	}
	return addr[:index], addr[index+1:], nil
}
