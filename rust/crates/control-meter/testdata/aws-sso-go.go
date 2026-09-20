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

// Capture pinned Go SSO config, token refresh, cache replacement and role requests.
package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/ssocreds"
)

type observed struct {
	Method      string `json:"method"`
	URL         string `json:"url"`
	Body        string `json:"body"`
	Token       string `json:"token"`
	ContentType string `json:"content_type"`
}
type fixture struct {
	Name       string          `json:"name"`
	Config     string          `json:"config"`
	Cache      string          `json:"cache"`
	Key        string          `json:"key"`
	Denied     string          `json:"denied"`
	LoadError  bool            `json:"load_error"`
	Error      bool            `json:"error"`
	Credential string          `json:"credential"`
	Filename   string          `json:"filename"`
	Updated    json.RawMessage `json:"updated"`
	Requests   []observed      `json:"requests"`
}
type client func(*http.Request) (*http.Response, error)

func (f client) Do(r *http.Request) (*http.Response, error) { return f(r) }
func main() {
	legacy := "[default]\nsso_region=us-east-1\nsso_start_url=https://example.awsapps.com/start\nsso_account_id=123456789012\nsso_role_name=Dev + Ops\n"
	modern := "[default]\nsso_session=fixture-session\nsso_account_id=123456789012\nsso_role_name=Dev + Ops\n[sso-session fixture-session]\nsso_region=us-east-1\nsso_start_url=https://example.awsapps.com/start\n"
	live := `{"accessToken":"old-token","expiresAt":"2099-01-01T00:00:00Z","unknown":{"keep":true}}`
	expired := `{"accessToken":"old-token","expiresAt":"2000-01-01T00:00:00Z","clientId":"fake-client","clientSecret":"fake-secret","refreshToken":"fake-refresh","registrationExpiresAt":"2000-01-01T00:00:00Z","unknown":{"keep":true}}`
	cases := []fixture{
		{Name: "legacy-live", Config: legacy, Cache: live, Key: "https://example.awsapps.com/start"},
		{Name: "legacy-expired-no-refresh", Config: legacy, Cache: expired, Key: "https://example.awsapps.com/start"},
		{Name: "session-live", Config: modern, Cache: live, Key: "fixture-session"},
		{Name: "session-refresh", Config: modern, Cache: expired, Key: "fixture-session"},
		{Name: "session-zero-time-rejected", Config: modern, Cache: strings.ReplaceAll(expired, "2000-01-01T00:00:00Z", "0001-01-01T00:00:00Z"), Key: "fixture-session"},
		{Name: "session-bad-refresh-response", Config: modern, Cache: expired, Key: "fixture-session", Denied: "bad-token-response"},
		{Name: "session-cache-write-fails", Config: modern, Cache: expired, Key: "fixture-session", Denied: "cache-write"},
		{Name: "session-refresh-denied", Config: modern, Cache: expired, Key: "fixture-session", Denied: "token"},
		{Name: "role-denied", Config: modern, Cache: live, Key: "fixture-session", Denied: "role"},
		{Name: "session-expired-missing-client", Config: modern, Cache: `{"accessToken":"old-token","expiresAt":"2000-01-01T00:00:00Z"}`, Key: "fixture-session"},
		{Name: "missing-access-token", Config: modern, Cache: `{"expiresAt":"2099-01-01T00:00:00Z"}`, Key: "fixture-session"},
		{Name: "bad-expiration", Config: modern, Cache: `{"accessToken":"old-token","expiresAt":"yesterday"}`, Key: "fixture-session"},
		{Name: "legacy-incomplete", Config: strings.ReplaceAll(legacy, "sso_role_name=Dev + Ops\n", ""), Cache: live, Key: "https://example.awsapps.com/start"},
		{Name: "session-missing-section", Config: "[default]\nsso_session=missing\n", Cache: live, Key: "missing"},
		{Name: "session-incomplete", Config: strings.ReplaceAll(modern, "sso_region=us-east-1\n", ""), Cache: live, Key: "fixture-session"},
		{Name: "session-conflicting-region", Config: strings.ReplaceAll(modern, "[default]", "[default]\nsso_region=eu-west-1"), Cache: live, Key: "fixture-session"},
		{Name: "session-conflicting-url", Config: strings.ReplaceAll(modern, "[default]", "[default]\nsso_start_url=https://other.invalid"), Cache: live, Key: "fixture-session"},
		{Name: "session-china", Config: strings.ReplaceAll(modern, "us-east-1", "cn-north-1"), Cache: live, Key: "fixture-session"},
		{Name: "session-empty-account-role", Config: strings.ReplaceAll(strings.ReplaceAll(modern, "sso_role_name=Dev + Ops\n", ""), "sso_account_id=123456789012\n", ""), Cache: live, Key: "fixture-session"},
	}
	for i := range cases {
		row := &cases[i]
		for _, entry := range os.Environ() {
			key := strings.SplitN(entry, "=", 2)[0]
			if strings.HasPrefix(key, "AWS_") {
				_ = os.Unsetenv(key)
			}
		}
		dir, err := os.MkdirTemp("", "sso-go-fixture-")
		if err != nil {
			panic(err)
		}
		path := filepath.Join(dir, "cache.json")
		if err = os.WriteFile(path, []byte(row.Cache), 0600); err != nil {
			panic(err)
		}
		if err = os.WriteFile(filepath.Join(dir, "config"), []byte(row.Config), 0600); err != nil {
			panic(err)
		}
		_ = os.Setenv("AWS_CONFIG_FILE", filepath.Join(dir, "config"))
		_ = os.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(dir, "absent"))
		canonical, err := ssocreds.StandardCachedTokenFilepath(row.Key)
		if err != nil {
			panic(err)
		}
		row.Filename = filepath.Base(canonical)
		transport := client(func(req *http.Request) (*http.Response, error) {
			var raw []byte
			if req.Body != nil {
				raw, _ = io.ReadAll(req.Body)
			}
			row.Requests = append(row.Requests, observed{req.Method, req.URL.String(), string(raw), req.Header.Get("x-amz-sso_bearer_token"), req.Header.Get("Content-Type")})
			body := `{"roleCredentials":{"accessKeyId":"sso-key","secretAccessKey":"sso-secret","sessionToken":"sso-token","expiration":4070908800000}}`
			kind := "role"
			if req.URL.Path == "/token" {
				kind = "token"
				body = `{"accessToken":"new-token","refreshToken":"new-refresh","expiresIn":3600,"tokenType":"Bearer"}`
			}
			if row.Denied == "bad-token-response" && kind == "token" {
				body = `{"accessToken":"new-token","expiresIn":"invalid"}`
			}
			if row.Denied == "cache-write" && kind == "token" {
				if err := os.Rename(path, path+".old"); err != nil {
					panic(err)
				}
				if err := os.Mkdir(path, 0700); err != nil {
					panic(err)
				}
			}
			status := 200
			if row.Denied == kind {
				status = 400
				body = `{"error":"invalid_grant","message":"fixture denied"}`
			}
			return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(body)), Request: req}, nil
		})
		cfg, err := config.LoadDefaultConfig(context.Background(), config.WithRegion("us-east-1"), config.WithHTTPClient(transport), config.WithRetryer(func() aws.Retryer { return aws.NopRetryer{} }), config.WithSSOTokenProviderOptions(func(o *ssocreds.SSOTokenProviderOptions) { o.CachedTokenFilepath = path }), config.WithSSOProviderOptions(func(o *ssocreds.Options) { o.CachedTokenFilepath = path }))
		row.LoadError = err != nil
		if err == nil {
			var c aws.Credentials
			c, err = cfg.Credentials.Retrieve(context.Background())
			if err == nil {
				row.Credential = c.AccessKeyID
			}
		}
		row.Error = err != nil
		readPath := path
		if row.Denied == "cache-write" {
			readPath = path + ".old"
		}
		contents, err := os.ReadFile(readPath)
		if err != nil {
			panic(err)
		}
		var updated map[string]any
		if err = json.Unmarshal(contents, &updated); err != nil {
			panic(err)
		}
		if updated["accessToken"] == "new-token" {
			exp, err := time.Parse(time.RFC3339, updated["expiresAt"].(string))
			if err != nil || time.Until(exp) < 3590*time.Second || time.Until(exp) > 3600*time.Second {
				panic("bad refresh expiration")
			}
			updated["expiresAt"] = "REFRESH_PLUS_3600"
		}
		row.Updated, err = json.Marshal(updated)
		if err != nil {
			panic(err)
		}
		_ = os.RemoveAll(dir)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(cases); err != nil {
		panic(err)
	}
}
