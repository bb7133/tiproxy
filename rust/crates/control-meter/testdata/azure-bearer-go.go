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
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/pingcap/metering_sdk/storage/provider"
)

type reply struct {
	Status    int      `json:"status"`
	Challenge []string `json:"challenge"`
}
type operation struct {
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
	Name string      `json:"name"`
	Ops  []operation `json:"ops"`
	Seen []observed  `json:"seen"`
}

func main() {
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
	for n := range rows {
		r := &rows[n]
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
			if op.Method == "HEAD" {
				op.Exists, e = p.Exists(ctx, "key.json.gz")
			} else {
				e = p.Upload(ctx, "key.json.gz", bytes.NewBufferString("payload"))
			}
			op.Error = e != nil
		}
		srv.Close()
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if e := enc.Encode(rows); e != nil {
		panic(e)
	}
}
