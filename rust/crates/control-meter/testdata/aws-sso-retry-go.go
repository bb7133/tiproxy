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

// Capture production SSO/OIDC retries; the HTTP client supplies responses only.
package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sso"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc"
)

type row struct {
	Name    string `json:"name"`
	Service string `json:"service"`
	New     bool   `json:"new"`
	Status  int    `json:"status"`
	Body    string `json:"body"`
	Header  string `json:"header"`
	After   string `json:"after"`
	Exhaust bool   `json:"exhaust"`
	Calls   int    `json:"calls"`
	Error   bool   `json:"error"`
}
type client func(*http.Request) (*http.Response, error)

func (f client) Do(r *http.Request) (*http.Response, error) { return f(r) }
func run(r *row) {
	c := client(func(req *http.Request) (*http.Response, error) {
		r.Calls++
		code, body := r.Status, r.Body
		if r.Calls > 1 && !r.Exhaust {
			code = 200
			body = `{"accessToken":"token","expiresIn":3600,"roleCredentials":{"accessKeyId":"key","secretAccessKey":"secret","sessionToken":"token","expiration":4070908800000}}`
		}
		return &http.Response{StatusCode: code, Header: http.Header{"X-Amzn-Errortype": []string{r.Header}, "X-Amz-Retry-After": []string{r.After}}, Body: io.NopCloser(strings.NewReader(body)), Request: req}, nil
	})
	start := time.Now()
	var e error
	if r.Service == "sso" {
		_, e = sso.New(sso.Options{Region: "us-east-1", HTTPClient: c}).GetRoleCredentials(context.Background(), &sso.GetRoleCredentialsInput{AccessToken: aws.String("token"), AccountId: aws.String("123456789012"), RoleName: aws.String("role")})
	} else {
		_, e = ssooidc.New(ssooidc.Options{Region: "us-east-1", HTTPClient: c}).CreateToken(context.Background(), &ssooidc.CreateTokenInput{ClientId: aws.String("client"), ClientSecret: aws.String("secret"), GrantType: aws.String("refresh_token"), RefreshToken: aws.String("refresh")})
	}
	r.Error = e != nil
	if r.New && r.After == "2000" && r.Calls == 2 && (time.Since(start) < 2*time.Second || time.Since(start) > 3*time.Second) {
		panic("retry-after elapsed mismatch")
	}
}
func main() {
	base := []row{
		{Name: "503-recovers", Status: 503, Body: `{}`},
		{Name: "503-exhausted", Status: 503, Body: `{}`, Exhaust: true},
		{Name: "429", Status: 429, Body: `{}`},
		{Name: "malformed-503", Status: 503, Body: `{`},
		{Name: "malformed-400-header-throttle", Status: 400, Body: `{`, Header: "Throttling"},
		{Name: "empty-503", Status: 503},
		{Name: "null-throttle-header", Status: 400, Body: `null`, Header: "Throttling"},
		{Name: "401", Status: 401, Body: `{}`},
		{Name: "typed-throttle", Status: 400, Body: `{"code":"TooManyRequestsException"}`},
		{Name: "typed-lower-throttle", Status: 400, Body: `{"code":"toomanyrequestsexception"}`},
		{Name: "type-throttle", Status: 400, Body: `{"__type":"ns#Throttling:details"}`},
		{Name: "generic-lower-throttle", Status: 400, Body: `{"code":"throttling"}`},
		{Name: "header-overrides-code", Status: 400, Body: `{"code":"Throttling"}`, Header: "AccessDeniedException"},
		{Name: "bad-message-type", Status: 400, Body: `{"code":"Throttling","message":3}`},
		{Name: "code-precedes-type", Status: 400, Body: `{"code":"AccessDeniedException","__type":"Throttling"}`},
		{Name: "casefold-duplicate-null", Status: 400, Body: `{"Code":"Throttling","code":null}`},
		{Name: "trailing-json", Status: 400, Body: `{"code":"Throttling"}{}`},
		{Name: "slow-down-exception", Status: 400, Body: `{"code":"SlowDownException"}`},
		{Name: "retry-after", Status: 503, Body: `{}`, After: "2000"},
		{Name: "bad-json-retry-after", Status: 503, Body: `{`, After: "2000"},
	}
	var rows []row
	for _, mode := range []bool{false, true} {
		if mode {
			_ = os.Setenv("AWS_NEW_RETRIES_2026", "true")
		} else {
			_ = os.Unsetenv("AWS_NEW_RETRIES_2026")
		}
		start := len(rows)
		for _, service := range []string{"sso", "oidc"} {
			for _, r := range base {
				r.New = mode
				r.Service = service
				rows = append(rows, r)
			}
		}
		var wg sync.WaitGroup
		for i := start; i < len(rows); i++ {
			wg.Add(1)
			go func(i int) { defer wg.Done(); run(&rows[i]) }(i)
		}
		wg.Wait()
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if e := enc.Encode(rows); e != nil {
		panic(e)
	}
}
