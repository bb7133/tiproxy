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

// Capture the production metering provider with LoadDefaultConfig and real HTTP/TLS.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/internal/sdk"
	"github.com/pingcap/metering_sdk/storage/provider"
)

type request struct {
	Headers map[string]string `json:"headers"`
	Body    []byte            `json:"body"`
	Length  int64             `json:"length"`
	Signed  []string          `json:"signed"`
}
type row struct {
	Name        string            `json:"name"`
	Secure      bool              `json:"secure"`
	Method      string            `json:"method"`
	Env         map[string]string `json:"env"`
	Profile     string            `json:"profile"`
	Credentials string            `json:"credentials"`
	Payload     []byte            `json:"payload"`
	Retry       bool              `json:"retry"`
	LoadError   bool              `json:"load_error"`
	Error       bool              `json:"error"`
	Requests    []request         `json:"requests"`
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
func main() {
	// This process has no access to ambient AWS identities or config files.
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if strings.HasPrefix(key, "AWS_") {
			must(os.Unsetenv(key))
		}
	}
	sdk.SleepWithContext = func(context.Context, time.Duration) error { return nil }
	dir, err := os.MkdirTemp("", "s3-checksum-probe-")
	must(err)
	defer os.RemoveAll(dir)
	var rows []row
	for _, secure := range []bool{false, true} {
		rows = append(rows, row{Name: "head", Secure: secure, Method: "HEAD"})
		for _, body := range []struct {
			name  string
			value []byte
		}{
			{"empty", []byte{}}, {"ascii", []byte("payload")},
			{"binary", []byte{0, 255, 128, 13, 10}}, {"large", bytes.Repeat([]byte("a"), 65537)},
		} {
			rows = append(rows, row{Name: body.name, Secure: secure, Method: "PUT", Payload: body.value})
		}
		rows = append(rows, row{Name: "retry", Secure: secure, Method: "PUT", Payload: []byte("payload"), Retry: true})
		rows = append(rows, row{Name: "required", Secure: secure, Method: "PUT", Payload: []byte("payload"), Env: map[string]string{"AWS_REQUEST_CHECKSUM_CALCULATION": "when_required"}})
	}
	for _, config := range []row{
		{Name: "env-supported", Env: map[string]string{"AWS_REQUEST_CHECKSUM_CALCULATION": "WHEN_SUPPORTED"}},
		{Name: "env-required-case", Env: map[string]string{"AWS_REQUEST_CHECKSUM_CALCULATION": "When_Required"}},
		{Name: "env-empty", Env: map[string]string{"AWS_REQUEST_CHECKSUM_CALCULATION": ""}},
		{Name: "env-invalid", Env: map[string]string{"AWS_REQUEST_CHECKSUM_CALCULATION": "bogus"}},
		{Name: "env-spaces", Env: map[string]string{"AWS_REQUEST_CHECKSUM_CALCULATION": " when_required "}},
		{Name: "profile-required", Profile: "request_checksum_calculation=when_required"},
		{Name: "profile-case", Profile: "request_checksum_calculation=WHEN_REQUIRED"},
		{Name: "profile-empty", Profile: "request_checksum_calculation="},
		{Name: "profile-invalid", Profile: "request_checksum_calculation=bogus"},
		{Name: "env-precedence", Profile: "request_checksum_calculation=when_required", Env: map[string]string{"AWS_REQUEST_CHECKSUM_CALCULATION": "when_supported"}},
		{Name: "invalid-profile-not-masked", Profile: "request_checksum_calculation=bogus", Env: map[string]string{"AWS_REQUEST_CHECKSUM_CALCULATION": "when_required"}},
		{Name: "credentials-precedence", Profile: "request_checksum_calculation=when_supported", Credentials: "request_checksum_calculation=when_required"},
	} {
		config.Secure = true
		config.Method = "PUT"
		config.Payload = []byte("payload")
		rows = append(rows, config)
	}
	for index := range rows {
		r := &rows[index]
		for _, key := range []string{"AWS_REQUEST_CHECKSUM_CALCULATION"} {
			must(os.Unsetenv(key))
		}
		for key, value := range r.Env {
			must(os.Setenv(key, value))
		}
		must(os.Setenv("AWS_CONFIG_FILE", filepath.Join(dir, "config")))
		must(os.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(dir, "credentials")))
		must(os.Setenv("AWS_EC2_METADATA_DISABLED", "true"))
		must(os.Setenv("AWS_NEW_RETRIES_2026", "false"))
		must(os.WriteFile(filepath.Join(dir, "config"), []byte("[default]\n"+r.Profile+"\n"), 0600))
		must(os.WriteFile(filepath.Join(dir, "credentials"), []byte("[default]\n"+r.Credentials+"\n"), 0600))
		server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			data, readErr := io.ReadAll(req.Body)
			must(readErr)
			recorded := request{Headers: map[string]string{}, Body: data, Length: req.ContentLength}
			for _, key := range []string{"content-encoding", "x-amz-checksum-crc32", "x-amz-content-sha256", "x-amz-decoded-content-length", "x-amz-trailer", "x-amz-sdk-checksum-algorithm"} {
				if v := req.Header.Get(key); v != "" {
					recorded.Headers[key] = v
				}
			}
			_, suffix, ok := strings.Cut(req.Header.Get("Authorization"), "SignedHeaders=")
			if !ok {
				panic("unsigned request")
			}
			signed, _, _ := strings.Cut(suffix, ",")
			for _, name := range strings.Split(signed, ";") {
				if _, ok := recorded.Headers[name]; ok {
					recorded.Signed = append(recorded.Signed, name)
				}
			}
			r.Requests = append(r.Requests, recorded)
			if r.Retry && len(r.Requests) == 1 {
				w.WriteHeader(503)
				return
			}
			w.WriteHeader(200)
		}))
		if r.Secure {
			server.StartTLS()
			must(os.WriteFile(filepath.Join(dir, "ca.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600))
			must(os.Setenv("AWS_CA_BUNDLE", filepath.Join(dir, "ca.pem")))
		} else {
			server.Start()
			must(os.Unsetenv("AWS_CA_BUNDLE"))
		}
		p, loadErr := provider.NewS3Provider(&provider.ProviderConfig{Type: provider.ProviderTypeS3, Region: "us-east-1", Bucket: "bucket", Endpoint: server.URL, AWS: &provider.AWSConfig{AccessKey: "key", SecretAccessKey: "secret", S3ForcePathStyle: true}})
		r.LoadError = loadErr != nil
		if loadErr == nil {
			if r.Method == "PUT" {
				r.Error = p.Upload(context.Background(), "meter.json.gz", bytes.NewReader(r.Payload)) != nil
			} else {
				_, err = p.Exists(context.Background(), "meter.json.gz")
				r.Error = err != nil
			}
		}
		server.Close()
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	must(enc.Encode(rows))
}
