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

// Actual production provider and UploadStream against real loopback HTTP.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf16"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/pingcap/metering_sdk/storage/provider"
)

type reply struct {
	Status    int      `json:"status"`
	Challenge []string `json:"challenge"`
}
type operation struct {
	WaitMS  int     `json:"wait_ms,omitempty"`
	Method  string  `json:"method"`
	Replies []reply `json:"replies"`
	Error   bool    `json:"error"`
	Exists  bool    `json:"exists"`
}
type observed struct {
	Kind   string `json:"kind"`
	Value  string `json:"value"`
	Method string `json:"method"`
	Size   int    `json:"size"`
	SHA256 string `json:"sha256"`
}
type row struct {
	TTL         int         `json:"ttl,omitempty"`
	FailCommand int         `json:"fail_command,omitempty"`
	Source      string      `json:"source"`
	Name        string      `json:"name"`
	Ops         []operation `json:"ops"`
	Seen        []observed  `json:"seen"`
}

func main() {
	if len(os.Args) > 2 && os.Args[1] == "--stub" {
		stub(os.Args[2], os.Args[3:])
		return
	}
	stubDir, err := os.MkdirTemp("", "azure-bearer-cli-")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(stubDir)
	executable, err := os.Executable()
	if err != nil {
		panic(err)
	}
	for _, tool := range []string{"az", "azd", "pwsh"} {
		script := "#!/bin/sh\nexec '" + strings.ReplaceAll(executable, "'", "'\"'\"'") + "' --stub " + tool + " \"$@\"\n"
		if err := os.WriteFile(filepath.Join(stubDir, tool), []byte(script), 0700); err != nil {
			panic(err)
		}
	}
	_ = os.Setenv("PATH", stubDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	stubLog := filepath.Join(stubDir, "calls.jsonl")
	_ = os.Setenv("AZURE_BEARER_STUB_LOG", stubLog)

	for _, name := range []string{"AZURE_CLIENT_ID", "AZURE_TENANT_ID", "AZURE_CLIENT_SECRET", "AZURE_CLIENT_CERTIFICATE_PATH", "AZURE_USERNAME", "AZURE_PASSWORD", "AZURE_FEDERATED_TOKEN_FILE", "MSI_ENDPOINT", "MSI_SECRET", "IMDS_ENDPOINT", "IDENTITY_SERVER_THUMBPRINT"} {
		_ = os.Unsetenv(name)
	}
	_ = os.Setenv("AZURE_TOKEN_CREDENTIALS", "ManagedIdentityCredential")
	challenge := func(scope string) string {
		return `Bearer authorization_uri="https://login.microsoftonline.com/fake-tenant", resource_id="` + scope + `"`
	}
	claims := `Bearer error="insufficient_claims", claims="` + base64.StdEncoding.EncodeToString([]byte(`{"access_token":{"synthetic":"yes"}}`)) + `"`
	var rows []row
	for _, method := range []string{"HEAD", "PUT"} {
		add := func(name string, replies ...reply) {
			rows = append(rows, row{Name: method + "-" + name, Ops: []operation{{Method: method, Replies: replies}}})
		}
		for _, c := range []struct{ name, header string }{
			{"scope", challenge("https://other.invalid")}, {"same-scope", challenge("https://storage.azure.com")},
			{"already-default", challenge("https://other.invalid/.default")}, {"scope-only", `resource_id="https://other.invalid"`},
			{"basic-resource", `Basic resource_id="https://other.invalid"`}, {"lowercase", `bearer resource_id="https://other.invalid"`},
			{"empty-resource", `Bearer resource_id=""`}, {"no-resource", `Bearer authorization_uri="https://login.microsoftonline.com/fake"`},
			{"empty-header", ""}, {"malformed", "invalid"}, {"no-space", `Bearer authorization_uri="https://login.microsoftonline.com/fake",resource_id="https://other.invalid"`},
			{"duplicate-resource", `Bearer resource_id="https://first.invalid" resource_id="https://other.invalid"`},
			{"cae", claims}, {"cae-invalid", `Bearer error="insufficient_claims", claims="invalid!"`},
			{"cae-empty", `Bearer error="insufficient_claims", claims=""`},
			{"cae-trailing-bits", `Bearer error="insufficient_claims", claims="Zh=="`},
			{"non-cae-claims", `Bearer error="other", claims="e30=" resource_id="https://other.invalid"`},
		} {
			add(c.name, reply{401, []string{c.header}}, reply{})
		}
		add("no-header", reply{Status: 401}, reply{})
		add("second-scope", reply{401, []string{challenge("https://other.invalid")}}, reply{401, []string{challenge("https://third.invalid")}}, reply{})
		add("scope-then-cae", reply{401, []string{challenge("https://other.invalid")}}, reply{401, []string{claims}}, reply{})
		add("cae-then-scope", reply{401, []string{claims}}, reply{401, []string{challenge("https://other.invalid")}}, reply{})
		add("cae-twice", reply{401, []string{claims}}, reply{401, []string{claims}}, reply{})
		add("challenge-repeat-after-retry", reply{401, []string{challenge("https://other.invalid")}}, reply{Status: 503}, reply{401, []string{challenge("https://third.invalid")}}, reply{})
		add("retry-before-scope", reply{Status: 503}, reply{401, []string{challenge("https://other.invalid")}}, reply{})
		add("retry-after-scope", reply{401, []string{challenge("https://other.invalid")}}, reply{Status: 503}, reply{})
		add("cae-second-value", reply{401, []string{challenge("https://other.invalid"), claims}}, reply{})
		add("basic-then-cae", reply{401, []string{`Basic realm="fake", ` + claims}}, reply{})
		rows = append(rows, row{Name: method + "-scope-persists", Ops: []operation{{Method: method, Replies: []reply{{401, []string{challenge("https://other.invalid")}}, {}}}, {Method: method, Replies: []reply{{}}}}})
		rows = append(rows, row{Name: method + "-scope-reverts", Ops: []operation{{Method: method, Replies: []reply{{401, []string{challenge("https://other.invalid")}}, {}}}, {Method: method, Replies: []reply{{401, []string{challenge("https://storage.azure.com")}}, {}}}}})
		rows = append(rows, row{Name: method + "-cae-persists", Ops: []operation{{Method: method, Replies: []reply{{401, []string{claims}}, {}}}, {Method: method, Replies: []reply{{}}}}})
	}
	base, _ := json.Marshal(rows)
	rows = nil
	for _, source := range []string{"ManagedIdentityCredential", "AzureCLICredential", "AzureDeveloperCLICredential", "AzurePowerShellCredential"} {
		var copyRows []row
		if err := json.Unmarshal(base, &copyRows); err != nil {
			panic(err)
		}
		for i := range copyRows {
			copyRows[i].Source = source
		}
		rows = append(rows, copyRows...)
	}
	rows = append(rows, row{Source: "AzureCLICredential", Name: "HEAD-refresh-failure-fallback-and-401", TTL: 120, FailCommand: 2, Ops: []operation{
		{Method: "HEAD", Replies: []reply{{}}},
		{Method: "HEAD", WaitMS: 31000, Replies: []reply{{}}},
		{Method: "HEAD", Replies: []reply{{}}},
		{Method: "HEAD", Replies: []reply{{401, []string{challenge("https://storage.azure.com")}}, {}}},
	}})
	for n := range rows {
		r := &rows[n]
		_ = os.Setenv("AZURE_TOKEN_CREDENTIALS", r.Source)
		_ = os.Setenv("AZURE_BEARER_STUB_TTL", fmt.Sprint(r.TTL))
		_ = os.Setenv("AZURE_BEARER_STUB_FAIL", fmt.Sprint(r.FailCommand))
		if err := os.WriteFile(stubLog, nil, 0600); err != nil {
			panic(err)
		}
		stubOffset := 0
		flushStub := func() {
			data, err := os.ReadFile(stubLog)
			if err != nil {
				panic(err)
			}
			for _, line := range bytes.Split(data[stubOffset:], []byte("\n")) {
				if len(line) > 0 {
					var event observed
					if err := json.Unmarshal(line, &event); err != nil {
						panic(err)
					}
					r.Seen = append(r.Seen, event)
				}
			}
			stubOffset = len(data)
		}
		var mu sync.Mutex
		tokenNum, opIndex, responseIndex := 0, 0, 0
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			mu.Lock()
			defer mu.Unlock()
			b, e := io.ReadAll(req.Body)
			if e != nil {
				panic(e)
			}
			if req.URL.Path == "/metadata" {
				tokenNum++
				resource := req.URL.Query().Get("resource")
				r.Seen = append(r.Seen, observed{Kind: "metadata", Value: resource, Method: req.Method})
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{"access_token": fmt.Sprintf("fake-%d", tokenNum), "expires_on": fmt.Sprint(time.Now().Add(time.Hour).Unix()), "token_type": "Bearer", "resource": resource})
				return
			}
			flushStub()
			sum := sha256.Sum256(b)
			r.Seen = append(r.Seen, observed{Kind: "object", Value: req.Header.Get("Authorization"), Method: req.Method, Size: len(b), SHA256: hex.EncodeToString(sum[:])})
			op := r.Ops[opIndex]
			i := responseIndex
			if i >= len(op.Replies) {
				i = len(op.Replies) - 1
			}
			resp := op.Replies[i]
			responseIndex++
			for _, c := range resp.Challenge {
				w.Header().Add("WWW-Authenticate", c)
			}
			status := resp.Status
			if status == 0 {
				status = 200
				if req.Method == "PUT" {
					status = 201
				}
			}
			w.WriteHeader(status)
		}))
		pool := x509.NewCertPool()
		pool.AddCert(srv.Certificate())
		if n == 0 {
			_ = os.Setenv("GODEBUG", "x509usefallbackroots=1")
			x509.SetFallbackRoots(pool)
		}
		_ = os.Setenv("IDENTITY_ENDPOINT", srv.URL+"/metadata")
		_ = os.Setenv("IDENTITY_HEADER", "fake-header")
		_ = os.Setenv("AZURE_CLIENT_ID", fmt.Sprintf("fake-client-%d", n))
		p, e := provider.NewAzureProvider(&provider.ProviderConfig{Type: provider.ProviderTypeAzure, Bucket: "bucket", Endpoint: srv.URL, Prefix: "prefix"})
		if e != nil {
			panic(e)
		}
		for j := range r.Ops {
			mu.Lock()
			opIndex = j
			responseIndex = 0
			mu.Unlock()
			ctx := policy.WithRetryOptions(context.Background(), policy.RetryOptions{RetryDelay: 1})
			op := &r.Ops[j]
			if op.WaitMS > 0 {
				time.Sleep(time.Duration(op.WaitMS) * time.Millisecond)
			}
			if op.Method == "HEAD" {
				op.Exists, e = p.Exists(ctx, "key.json.gz")
			} else {
				e = p.Upload(ctx, "key.json.gz", bytes.NewBufferString("payload"))
			}
			op.Error = e != nil
			mu.Lock()
			flushStub()
			mu.Unlock()
		}
		srv.Close()
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if e := enc.Encode(rows); e != nil {
		panic(e)
	}
}

// Fake executable used by the unmodified SDK command runner. It records only
// synthetic scope/claims and returns a token; no Azure CLI is contacted.
func stub(tool string, args []string) {
	scope, claims := "", ""
	for i, a := range args {
		if i+1 < len(args) {
			switch strings.ToLower(a) {
			case "--scope":
				scope = args[i+1]
			case "--resource":
				scope = args[i+1] + "/.default"
			case "--claims":
				claims = args[i+1]
			case "-encodedcommand":
				b, e := base64.StdEncoding.DecodeString(args[i+1])
				if e != nil {
					panic(e)
				}
				units := make([]uint16, len(b)/2)
				for j := range units {
					units[j] = binary.LittleEndian.Uint16(b[2*j:])
				}
				script := string(utf16.Decode(units))
				m := regexp.MustCompile(`ResourceUrl\s*=\s*'([^']*)'`).FindStringSubmatch(script)
				if len(m) != 2 {
					panic("missing PowerShell resource")
				}
				scope = m[1] + "/.default"
			}
		}
	}
	if scope == "" {
		panic("missing synthetic scope")
	}
	log := os.Getenv("AZURE_BEARER_STUB_LOG")
	data, e := os.ReadFile(log)
	if e != nil {
		panic(e)
	}
	count := bytes.Count(data, []byte("\n")) + 1
	event := observed{Kind: tool, Value: scope + "|" + claims}
	f, e := os.OpenFile(log, os.O_APPEND|os.O_WRONLY, 0600)
	if e != nil {
		panic(e)
	}
	if e = json.NewEncoder(f).Encode(event); e != nil {
		panic(e)
	}
	_ = f.Close()
	if os.Getenv("AZURE_BEARER_STUB_FAIL") == fmt.Sprint(count) {
		fmt.Fprintln(os.Stderr, "synthetic refresh failure")
		os.Exit(1)
	}
	expiry := int64(4070908800)
	var ttl int
	_, _ = fmt.Sscan(os.Getenv("AZURE_BEARER_STUB_TTL"), &ttl)
	if ttl > 0 {
		expiry = time.Now().Add(time.Duration(ttl) * time.Second).Unix()
	}
	token := fmt.Sprintf("fake-%d", count)
	var response any
	switch tool {
	case "az":
		response = map[string]any{"accessToken": token, "expires_on": expiry, "tokenType": "Bearer"}
	case "azd":
		response = map[string]any{"token": token, "expiresOn": "2099-01-01T00:00:00Z"}
	case "pwsh":
		response = map[string]any{"Token": token, "ExpiresOn": expiry}
	}
	if e := json.NewEncoder(os.Stdout).Encode(response); e != nil {
		panic(e)
	}
}
