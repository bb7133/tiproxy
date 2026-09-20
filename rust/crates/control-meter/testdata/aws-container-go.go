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
	"github.com/aws/aws-sdk-go-v2/credentials/endpointcreds"
)

type observed struct {
	Method string `json:"method"`
	URL    string `json:"url"`
	Token  string `json:"token"`
	Accept string `json:"accept"`
}
type fixture struct {
	Name       string            `json:"name"`
	Env        map[string]string `json:"env"`
	TokenFile  *string           `json:"token_file"`
	Response   string            `json:"response"`
	Status     int               `json:"status"`
	LoadError  bool              `json:"load_error"`
	Error      bool              `json:"error"`
	Key        string            `json:"key"`
	Token      string            `json:"token"`
	Expiration string            `json:"expiration"`
	Requests   []observed        `json:"requests"`
}
type client func(*http.Request) (*http.Response, error)

func (f client) Do(r *http.Request) (*http.Response, error) { return f(r) }
func ptr(s string) *string                                  { return &s }
func main() {
	valid := `{"AccessKeyId":"container-key","SecretAccessKey":"container-secret","Token":"container-token","Expiration":"2099-01-01T00:00:00Z"}`
	relative := "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"
	full := "AWS_CONTAINER_CREDENTIALS_FULL_URI"
	authorizationEnv := "AWS_CONTAINER_AUTHORIZATION_TOKEN"
	file := "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE"
	cases := []fixture{
		{Name: "relative", Env: map[string]string{relative: "/fixture"}},
		{Name: "relative-beats-full", Env: map[string]string{relative: "/fixture", full: "http://192.0.2.1/ignored"}},
		{Name: "full-loopback", Env: map[string]string{full: "http://127.0.0.1:8080/path?arg=1"}},
		{Name: "full-ecs", Env: map[string]string{full: "http://169.254.170.2/path"}},
		{Name: "full-eks-v4", Env: map[string]string{full: "http://169.254.170.23/path"}},
		{Name: "full-eks-v6", Env: map[string]string{full: "http://[fd00:ec2::23]/path"}},
		{Name: "full-ipv6-loopback", Env: map[string]string{full: "http://[::1]/path"}},
		{Name: "http-public-rejected", Env: map[string]string{full: "http://192.0.2.1/path"}},
		{Name: "https-public", Env: map[string]string{full: "https://example.invalid/credentials"}},
		{Name: "full-missing-host", Env: map[string]string{full: "/relative"}},
		{Name: "environment-token", Env: map[string]string{relative: "/fixture", authorizationEnv: "env-token"}},
		{Name: "file-overrides-env", Env: map[string]string{relative: "/fixture", authorizationEnv: "env-token", file: "TOKEN_FILE"}, TokenFile: ptr("file-token")},
		{Name: "file-keeps-spaces", Env: map[string]string{relative: "/fixture", file: "TOKEN_FILE"}, TokenFile: ptr(" file-token ")},
		{Name: "file-empty-overrides-env", Env: map[string]string{relative: "/fixture", authorizationEnv: "env-token", file: "TOKEN_FILE"}, TokenFile: ptr("")},
		{Name: "file-newline-rejected", Env: map[string]string{relative: "/fixture", file: "TOKEN_FILE"}, TokenFile: ptr("file-token\n")},
		{Name: "file-missing-rejected", Env: map[string]string{relative: "/fixture", file: "TOKEN_FILE"}},
		{Name: "env-newline-rejected", Env: map[string]string{relative: "/fixture", authorizationEnv: "env-token\n"}},
		{Name: "static-no-expiry", Env: map[string]string{relative: "/fixture"}, Response: `{"AccessKeyId":"static-key","SecretAccessKey":"static-secret"}`},
		{Name: "null-expiry", Env: map[string]string{relative: "/fixture"}, Response: `{"AccessKeyId":"static-key","SecretAccessKey":"static-secret","Expiration":null}`},
		{Name: "wrong-token-type", Env: map[string]string{relative: "/fixture"}, Response: `{"AccessKeyId":"key","SecretAccessKey":"secret","Token":123}`},
		{Name: "invalid-expiry", Env: map[string]string{relative: "/fixture"}, Response: strings.ReplaceAll(valid, "2099-01-01T00:00:00Z", "invalid")},
		{Name: "case-null-duplicate", Env: map[string]string{relative: "/fixture"}, Response: `{"accesskeyid":"first","ACCESSKEYID":"last","AccessKeyId":null,"secretaccesskey":"secret","TOKEN":"token","Expiration":null}`},
		{Name: "trailing-json-ignored", Env: map[string]string{relative: "/fixture"}, Response: valid + ` {}`},
		{Name: "created-status", Env: map[string]string{relative: "/fixture"}, Status: 201},
		{Name: "denied", Env: map[string]string{relative: "/fixture"}, Status: 403, Response: `{"code":"AccessDenied","message":"private failure"}`},
		{Name: "already-expired-returned", Env: map[string]string{relative: "/fixture"}, Response: strings.ReplaceAll(valid, "2099-01-01T00:00:00Z", "2000-01-01T00:00:00Z")},
	}
	for i := range cases {
		row := &cases[i]
		if row.Response == "" {
			row.Response = valid
		}
		if row.Status == 0 {
			row.Status = 200
		}
		for _, entry := range os.Environ() {
			k := strings.SplitN(entry, "=", 2)[0]
			if strings.HasPrefix(k, "AWS_") {
				_ = os.Unsetenv(k)
			}
		}
		dir, err := os.MkdirTemp("", "container-go-fixture-")
		if err != nil {
			panic(err)
		}
		configPath := filepath.Join(dir, "config")
		if err = os.WriteFile(configPath, []byte("[default]\n"), 0600); err != nil {
			panic(err)
		}
		_ = os.Setenv("AWS_CONFIG_FILE", configPath)
		_ = os.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(dir, "absent"))
		for k, v := range row.Env {
			if v == "TOKEN_FILE" {
				v = filepath.Join(dir, "token")
			}
			_ = os.Setenv(k, v)
		}
		if row.TokenFile != nil {
			if err = os.WriteFile(filepath.Join(dir, "token"), []byte(*row.TokenFile), 0600); err != nil {
				panic(err)
			}
		}
		transport := client(func(req *http.Request) (*http.Response, error) {
			// net/http interprets an empty method as GET on the wire.
			method := req.Method
			if method == "" {
				method = http.MethodGet
			}
			row.Requests = append(row.Requests, observed{method, req.URL.String(), req.Header.Get("Authorization"), req.Header.Get("Accept")})
			return &http.Response{StatusCode: row.Status, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(row.Response)), Request: req}, nil
		})
		cfg, err := config.LoadDefaultConfig(context.Background(), config.WithRegion("us-east-1"), config.WithRetryer(func() aws.Retryer { return aws.NopRetryer{} }), config.WithEndpointCredentialOptions(func(o *endpointcreds.Options) { o.HTTPClient = transport }))
		row.LoadError = err != nil
		if err == nil {
			var c aws.Credentials
			c, err = cfg.Credentials.Retrieve(context.Background())
			if err == nil {
				row.Key = c.AccessKeyID
				row.Token = c.SessionToken
				if c.CanExpire {
					row.Expiration = c.Expires.UTC().Format(time.RFC3339)
				}
				_, err = cfg.Credentials.Retrieve(context.Background())
			}
		}
		row.Error = err != nil
		_ = os.RemoveAll(dir)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(cases); err != nil {
		panic(err)
	}
}
