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

// Capture STS credential-provider retries using the pinned production SDK.
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

	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

type row struct {
	Name    string `json:"name"`
	Web     bool   `json:"web"`
	New     bool   `json:"new"`
	Status  int    `json:"status"`
	Body    string `json:"body"`
	After   string `json:"after"`
	Exhaust bool   `json:"exhaust"`
	Calls   int    `json:"calls"`
	Error   bool   `json:"error"`
}
type client func(*http.Request) (*http.Response, error)

func (f client) Do(r *http.Request) (*http.Response, error) { return f(r) }

type token struct{}

func (token) GetIdentityToken() ([]byte, error) { return []byte("web-token\n"), nil }
func run(r *row) {
	c := client(func(req *http.Request) (*http.Response, error) {
		r.Calls++
		code, body := r.Status, r.Body
		if r.Calls > 1 && !r.Exhaust {
			code = 200
			name := "AssumeRole"
			if r.Web {
				name = "AssumeRoleWithWebIdentity"
			}
			body = "<" + name + "Response><" + name + "Result><Credentials><AccessKeyId>ASIA1234567890123456</AccessKeyId><SecretAccessKey>secret</SecretAccessKey><SessionToken>token</SessionToken><Expiration>2099-01-01T00:00:00Z</Expiration></Credentials></" + name + "Result></" + name + "Response>"
		}
		return &http.Response{StatusCode: code, Header: http.Header{"X-Amz-Retry-After": []string{r.After}}, Body: io.NopCloser(strings.NewReader(body)), Request: req}, nil
	})
	sc := sts.New(sts.Options{Region: "us-east-1", Credentials: credentials.NewStaticCredentialsProvider("key", "secret", ""), HTTPClient: c})
	start := time.Now()
	var e error
	if r.Web {
		_, e = stscreds.NewWebIdentityRoleProvider(sc, "arn:aws:iam::123456789012:role/test", token{}, func(o *stscreds.WebIdentityRoleOptions) { o.RoleSessionName = "session" }).Retrieve(context.Background())
	} else {
		_, e = stscreds.NewAssumeRoleProvider(sc, "arn:aws:iam::123456789012:role/test", func(o *stscreds.AssumeRoleOptions) { o.RoleSessionName = "session" }).Retrieve(context.Background())
	}
	r.Error = e != nil
	if r.New && r.After == "2000" && r.Calls == 2 && (time.Since(start) < 2*time.Second || time.Since(start) > 3*time.Second) {
		panic("retry-after elapsed mismatch")
	}
}
func main() {
	xml := func(code string) string {
		return "<ErrorResponse><Error><Code>" + code + "</Code><Message>failure</Message></Error></ErrorResponse>"
	}
	base := []row{
		{Name: "503-recovers", Status: 503, Body: xml("Unknown")},
		{Name: "503-exhausted", Status: 503, Body: xml("Unknown"), Exhaust: true},
		{Name: "429", Status: 429, Body: xml("Unknown")},
		{Name: "malformed-503", Status: 503, Body: "<ErrorResponse>"},
		{Name: "empty-503", Status: 503},
		{Name: "401", Status: 401, Body: xml("AccessDenied")},
		{Name: "throttle", Status: 400, Body: xml("Throttling")},
		{Name: "lower-throttle", Status: 400, Body: xml("throttling")},
		{Name: "request-timeout", Status: 400, Body: xml("RequestTimeout")},
		{Name: "invalid-token", Status: 400, Body: xml("InvalidIdentityToken")},
		{Name: "lower-invalid-token", Status: 400, Body: xml("invalididentitytoken")},
		{Name: "unwrapped-throttle", Status: 400, Body: "<Error><Code>Throttling</Code></Error>"},
		{Name: "retry-after", Status: 503, Body: xml("Unknown"), After: "2000"},
		{Name: "malformed-retry-after", Status: 503, Body: "<ErrorResponse>", After: "2000"},
	}
	var rows []row
	for _, mode := range []bool{false, true} {
		if mode {
			_ = os.Setenv("AWS_NEW_RETRIES_2026", "true")
		} else {
			_ = os.Unsetenv("AWS_NEW_RETRIES_2026")
		}
		start := len(rows)
		for _, web := range []bool{false, true} {
			for _, r := range base {
				r.New = mode
				r.Web = web
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
