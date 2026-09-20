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

// Capture the pinned IMDS client and EC2 role cache using only a fake HTTP client.
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
)

type observed struct {
	Method string `json:"method"`
	URL    string `json:"url"`
	Token  string `json:"token"`
	TTL    string `json:"ttl"`
}
type fixture struct {
	Name             string            `json:"name"`
	Config           string            `json:"config"`
	Env              map[string]string `json:"env"`
	Roles            string            `json:"roles"`
	Response         string            `json:"response"`
	TokenStatus      int               `json:"token_status"`
	TTL              string            `json:"ttl"`
	Denied           string            `json:"denied"`
	LoadError        bool              `json:"load_error"`
	Error            bool              `json:"error"`
	SecondError      bool              `json:"second_error"`
	Key              string            `json:"key"`
	Expiration       string            `json:"expiration"`
	SecondExpiration string            `json:"second_expiration"`
	Requests         []observed        `json:"requests"`
}
type client func(*http.Request) (*http.Response, error)

func (f client) Do(r *http.Request) (*http.Response, error) { return f(r) }
func expiration(t time.Time) string {
	delta := time.Until(t)
	if delta > 3590*time.Second && delta <= 3600*time.Second {
		return "NOW_PLUS_3600"
	}
	if delta >= 299*time.Second && delta < 900*time.Second {
		return "EXTENDED_5_TO_15_MINUTES"
	}
	return t.UTC().Format(time.RFC3339Nano)
}
func main() {
	valid := `{"Code":"Success","AccessKeyId":"imds-key","SecretAccessKey":"imds-secret","Token":"imds-token","Expiration":"2099-01-01T00:00:00Z"}`
	expired := strings.ReplaceAll(valid, "2099-01-01T00:00:00Z", "2000-01-01T00:00:00Z")
	cases := []fixture{
		{Name: "default"},
		{Name: "ipv6-env", Env: map[string]string{"AWS_EC2_METADATA_SERVICE_ENDPOINT_MODE": "IPv6"}},
		{Name: "ipv6-env-spaces", Env: map[string]string{"AWS_EC2_METADATA_SERVICE_ENDPOINT_MODE": " IPv6 "}},
		{Name: "mode-env-whitespace-default", Env: map[string]string{"AWS_EC2_METADATA_SERVICE_ENDPOINT_MODE": "  "}},
		{Name: "blank-env-mode-uses-profile", Env: map[string]string{"AWS_EC2_METADATA_SERVICE_ENDPOINT_MODE": "  "}, Config: "[default]\nec2_metadata_service_endpoint_mode=IPv6\n"},
		{Name: "ipv6-profile", Config: "[default]\nec2_metadata_service_endpoint_mode=IPv6\n"},
		{Name: "profile-endpoint", Config: "[default]\nec2_metadata_service_endpoint=http://127.0.0.1:8070/prefix\n"},
		{Name: "env-overrides-profile", Config: "[default]\nec2_metadata_service_endpoint=http://127.0.0.1:8070/ignored\n", Env: map[string]string{"AWS_EC2_METADATA_SERVICE_ENDPOINT": "http://127.0.0.1:8071/prefix"}},
		{Name: "disabled-case-insensitive", Env: map[string]string{"AWS_EC2_METADATA_DISABLED": "TRUE"}},
		{Name: "invalid-disabled-ignored", Env: map[string]string{"AWS_EC2_METADATA_DISABLED": "invalid"}},
		{Name: "invalid-mode-env", Env: map[string]string{"AWS_EC2_METADATA_SERVICE_ENDPOINT_MODE": "invalid"}},
		{Name: "invalid-v1-env", Env: map[string]string{"AWS_EC2_METADATA_V1_DISABLED": "invalid"}},
		{Name: "first-role-line", Roles: "first-role\r\nsecond-role\n"},
		{Name: "role-spaces", Roles: " role name \n"},
		{Name: "role-path-clean", Roles: "nested/../role\n"},
		{Name: "empty-role-list", Roles: "EMPTY"},
		{Name: "token-400-terminal", TokenStatus: 400},
		{Name: "token-403-fallback", TokenStatus: 403},
		{Name: "token-404-fallback", TokenStatus: 404},
		{Name: "token-405-fallback", TokenStatus: 405},
		{Name: "token-500-per-request-fallback", TokenStatus: 500},
		{Name: "token-missing-ttl", TTL: "MISSING"},
		{Name: "token-zero-ttl", TTL: "0"},
		{Name: "v1-disabled-env", TokenStatus: 403, Env: map[string]string{"AWS_EC2_METADATA_V1_DISABLED": "true"}},
		{Name: "v1-disabled-profile", TokenStatus: 403, Config: "[default]\nec2_metadata_v1_disabled=true\n"},
		{Name: "role-list-denied", Denied: "list"},
		{Name: "role-denied", Denied: "role"},
		{Name: "code-case-insensitive", Response: strings.ReplaceAll(valid, "Success", "sUcCeSs")},
		{Name: "code-denied", Response: strings.ReplaceAll(valid, "Success", "AccessDenied")},
		{Name: "expired-returned", Response: expired},
		{Name: "expired-refresh-failure-extends", Response: expired, Denied: "after-first"},
	}
	for i := range cases {
		r := &cases[i]
		if r.Response == "" {
			r.Response = valid
		}
		if r.Roles == "" {
			r.Roles = "fixture-role\n"
		}
		if r.Roles == "EMPTY" {
			r.Roles = ""
		}
		if r.TokenStatus == 0 {
			r.TokenStatus = 200
		}
		if r.TTL == "" {
			r.TTL = "300"
		}
		for _, entry := range os.Environ() {
			k := strings.SplitN(entry, "=", 2)[0]
			if strings.HasPrefix(k, "AWS_") {
				_ = os.Unsetenv(k)
			}
		}
		dir, err := os.MkdirTemp("", "imds-go-fixture-")
		if err != nil {
			panic(err)
		}
		cfgpath := filepath.Join(dir, "config")
		if err = os.WriteFile(cfgpath, []byte(r.Config), 0600); err != nil {
			panic(err)
		}
		_ = os.Setenv("AWS_CONFIG_FILE", cfgpath)
		_ = os.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(dir, "absent"))
		for k, v := range r.Env {
			_ = os.Setenv(k, v)
		}
		lists := 0
		transport := client(func(req *http.Request) (*http.Response, error) {
			r.Requests = append(r.Requests, observed{req.Method, req.URL.String(), req.Header.Get("x-aws-ec2-metadata-token"), req.Header.Get("x-aws-ec2-metadata-token-ttl-seconds")})
			body := r.Response
			status := 200
			h := http.Header{}
			if strings.HasSuffix(req.URL.Path, "/api/token") {
				body = "metadata-token"
				status = r.TokenStatus
				if r.TTL != "MISSING" {
					h.Set("x-aws-ec2-metadata-token-ttl-seconds", r.TTL)
				}
			} else if strings.HasSuffix(req.URL.Path, "/iam/security-credentials/") {
				lists++
				body = r.Roles
				if r.Denied == "list" || (r.Denied == "after-first" && lists > 1) {
					status = 403
					body = "denied"
				}
			} else if r.Denied == "role" {
				status = 403
				body = "denied"
			}
			return &http.Response{StatusCode: status, Header: h, Body: io.NopCloser(strings.NewReader(body)), Request: req}, nil
		})
		cfg, err := config.LoadDefaultConfig(context.Background(), config.WithRegion("us-east-1"), config.WithHTTPClient(transport))
		r.LoadError = err != nil
		if err == nil {
			var c aws.Credentials
			c, err = cfg.Credentials.Retrieve(context.Background())
			if err == nil {
				r.Key = c.AccessKeyID
				r.Expiration = expiration(c.Expires)
				c, err = cfg.Credentials.Retrieve(context.Background())
				r.SecondError = err != nil
				if err == nil {
					r.SecondExpiration = expiration(c.Expires)
				}
			}
		}
		r.Error = err != nil
		_ = os.RemoveAll(dir)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(cases); err != nil {
		panic(err)
	}
}
