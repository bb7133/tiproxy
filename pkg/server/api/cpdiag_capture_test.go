// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pingcap/kvproto/pkg/diagnosticspb"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

// CP-ADMIN slice 4b oracle: the production API server (h2c gin engine plus the
// sysutil diagnostics service, and the cmux TLS branch) answers the shared
// script over a real gRPC/HTTP wire; the Rust replay produces the same
// document from its admin listener.
type cpdiagFile struct {
	Name     string   `json:"name"`
	Gz       bool     `json:"gz"`
	Lines    []string `json:"lines"`
	Generate *struct {
		Count       int    `json:"count"`
		StampPrefix string `json:"stamp_prefix"`
		Level       string `json:"level"`
	} `json:"generate"`
}

type cpdiagSearch struct {
	Name               string   `json:"name"`
	StartTime          int64    `json:"start_time"`
	EndTime            int64    `json:"end_time"`
	Levels             []string `json:"levels"`
	Patterns           []string `json:"patterns"`
	CancelAfterPackets int      `json:"cancel_after_packets"`
}

type cpdiagScript struct {
	Files          []cpdiagFile   `json:"files"`
	Searches       []cpdiagSearch `json:"searches"`
	HTTP1ProbePath string         `json:"http1_probe_path"`
}

type cpdiagMessage struct {
	Time    int64  `json:"time"`
	Level   int32  `json:"level"`
	Message string `json:"message"`
}

type cpdiagSearchResult struct {
	Name    string            `json:"name"`
	Packets [][]cpdiagMessage `json:"packets"`
	Code    string            `json:"code"`
}

type cpdiagSide struct {
	Searches        []cpdiagSearchResult `json:"searches"`
	ServerInfoCode  string               `json:"server_info_code"`
	ServerInfoItems int                  `json:"server_info_items"`
	HTTP1GrpcStatus int                  `json:"http1_grpc_status"`
}

type cpdiagCapture struct {
	Plain cpdiagSide `json:"plain"`
	TLS   cpdiagSide `json:"tls"`
}

// cpdiagLines expands one file entry; generated files follow the shared
// rule "line i is stamped <prefix><i/1000:02>.<i%1000:03> -04:00".
func cpdiagLines(file cpdiagFile) []string {
	if file.Generate == nil {
		return file.Lines
	}
	lines := make([]string, 0, file.Generate.Count)
	for i := 0; i < file.Generate.Count; i++ {
		lines = append(lines, fmt.Sprintf("[%s%02d.%03d -04:00] [%s] [bulk.go:1] [\"line %d\"]",
			file.Generate.StampPrefix, i/1000, i%1000, file.Generate.Level, i))
	}
	return lines
}

func cpdiagWriteFixture(t *testing.T, dir string, files []cpdiagFile) {
	for _, file := range files {
		content := strings.Join(cpdiagLines(file), "\n") + "\n"
		path := filepath.Join(dir, file.Name)
		if file.Gz {
			f, err := os.Create(path)
			require.NoError(t, err)
			w := gzip.NewWriter(f)
			_, err = w.Write([]byte(content))
			require.NoError(t, err)
			require.NoError(t, w.Close())
			require.NoError(t, f.Close())
			continue
		}
		require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	}
}

func cpdiagRun(t *testing.T, cc *grpc.ClientConn, httpClient *http.Client, scheme, addr string, script *cpdiagScript) cpdiagSide {
	client := diagnosticspb.NewDiagnosticsClient(cc)
	side := cpdiagSide{}
	for _, search := range script.Searches {
		request := &diagnosticspb.SearchLogRequest{StartTime: search.StartTime, EndTime: search.EndTime}
		for _, level := range search.Levels {
			value, ok := diagnosticspb.LogLevel_value[level]
			require.True(t, ok, "unknown level %q", level)
			request.Levels = append(request.Levels, diagnosticspb.LogLevel(value))
		}
		request.Patterns = append(request.Patterns, search.Patterns...)
		ctx, cancel := context.WithCancel(context.Background())
		result := cpdiagSearchResult{Name: search.Name, Packets: [][]cpdiagMessage{}}
		stream, err := client.SearchLog(ctx, request)
		require.NoError(t, err)
		for {
			response, err := stream.Recv()
			if err != nil {
				if errors.Is(err, io.EOF) {
					result.Code = "OK"
				} else {
					result.Code = status.Code(err).String()
				}
				break
			}
			packet := make([]cpdiagMessage, 0, len(response.Messages))
			for _, message := range response.Messages {
				packet = append(packet, cpdiagMessage{Time: message.Time, Level: int32(message.Level), Message: message.Message})
			}
			result.Packets = append(result.Packets, packet)
			if search.CancelAfterPackets > 0 && len(result.Packets) >= search.CancelAfterPackets {
				cancel()
				// The client observes its own cancellation; the server's scan
				// stops when the stream context ends.
				result.Code = "Canceled"
				break
			}
		}
		cancel()
		side.Searches = append(side.Searches, result)
	}
	info, err := client.ServerInfo(context.Background(), &diagnosticspb.ServerInfoRequest{Tp: diagnosticspb.ServerInfoType_LoadInfo})
	side.ServerInfoCode = status.Code(err).String()
	if err == nil {
		side.ServerInfoItems = len(info.Items)
	}
	req, err := http.NewRequest(http.MethodPost, scheme+"://"+addr+script.HTTP1ProbePath, strings.NewReader(""))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/grpc")
	resp, err := httpClient.Do(req)
	require.NoError(t, err)
	side.HTTP1GrpcStatus = resp.StatusCode
	require.NoError(t, resp.Body.Close())
	return side
}

func TestCPDiagCapture(t *testing.T) {
	out := os.Getenv("CPDIAG_CAPTURE_OUT")
	if out == "" {
		t.Skip("CPDIAG_CAPTURE_OUT is not set")
	}
	raw, err := os.ReadFile(os.Getenv("CPDIAG_SCRIPT"))
	require.NoError(t, err)
	var script cpdiagScript
	require.NoError(t, json.Unmarshal(raw, &script))
	dir := t.TempDir()
	cpdiagWriteFixture(t, dir, script.Files)
	// Dotted keys: a table header would swallow the later security key.
	logConfig := fmt.Sprintf("log.log-file.filename = %q\n", filepath.Join(dir, "tiproxy.log"))

	capture := cpdiagCapture{}
	{
		srv, _, _ := createServerWithConfig(t, logConfig)
		addr := srv.listener.Addr().String()
		cc, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
		require.NoError(t, err)
		httpClient := &http.Client{Transport: &http.Transport{Proxy: nil, ForceAttemptHTTP2: false}}
		capture.Plain = cpdiagRun(t, cc, httpClient, "http", addr, &script)
		require.NoError(t, cc.Close())
	}
	{
		srv, _, _ := createServerWithConfig(t, logConfig+"security.server-http-tls.auto-certs = true\n")
		addr := srv.listener.Addr().String()
		tlsConfig := &tls.Config{InsecureSkipVerify: true} //nolint:gosec // self-signed test server
		cc, err := grpc.NewClient(addr, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
		require.NoError(t, err)
		httpClient := &http.Client{Transport: &http.Transport{Proxy: nil, ForceAttemptHTTP2: false, TLSClientConfig: tlsConfig}}
		capture.TLS = cpdiagRun(t, cc, httpClient, "https", addr, &script)
		require.NoError(t, cc.Close())
	}
	encoded, err := json.MarshalIndent(capture, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(out, append(encoded, '\n'), 0o600))
}
