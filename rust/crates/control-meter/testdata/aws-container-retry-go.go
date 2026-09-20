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

// Capture the pinned endpointcreds retry policy with fake HTTP only.
// Request cases use its real default retryer. The quota probe changes only the
// backoff to zero so it can exhaust/replenish a real SDK token bucket quickly.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/credentials/endpointcreds"
)

type client func(*http.Request) (*http.Response, error)

func (f client) Do(r *http.Request) (*http.Response, error) { return f(r) }

type row struct {
	Name        string `json:"name"`
	New         bool   `json:"new"`
	Status      int    `json:"status"`
	Body        string `json:"body"`
	ContentType string `json:"content_type"`
	Transport   string `json:"transport"`
	Recover     bool   `json:"recover"`
	Attempts    int    `json:"attempts"`
	Error       bool   `json:"error"`
}

func reply(r *http.Request, status int, ct, body string) (*http.Response, error) {
	return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": []string{ct}}, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
}
func run(r *row) {
	p := endpointcreds.New("http://127.0.0.1/credentials", func(o *endpointcreds.Options) {
		o.HTTPClient = client(func(req *http.Request) (*http.Response, error) {
			r.Attempts++
			if r.Recover && r.Attempts > 1 {
				return reply(req, 200, "application/json", `{"AccessKeyId":"key","SecretAccessKey":"secret"}`)
			}
			switch r.Transport {
			case "timeout":
				return nil, &net.DNSError{IsTimeout: true}
			case "connection-reset":
				return nil, &net.OpError{Op: "read", Err: errors.New("connection reset by peer")}
			case "nxdomain":
				return nil, &net.DNSError{IsNotFound: true}
			case "plain":
				return nil, errors.New("non-network failure")
			}
			return reply(req, r.Status, r.ContentType, r.Body)
		})
	})
	_, err := p.Retrieve(context.Background())
	r.Error = err != nil
}

type quota struct {
	New      bool  `json:"new"`
	Attempts []int `json:"attempts"`
}

func exhaustion(newMode bool) quota {
	q := quota{New: newMode}
	count := 0
	success := false
	p := endpointcreds.New("http://127.0.0.1/credentials", func(o *endpointcreds.Options) {
		o.Retryer = retry.NewStandard(func(v *retry.StandardOptions) {
			v.Backoff = retry.BackoffDelayerFunc(func(int, error) (time.Duration, error) { return 0, nil })
		})
		o.HTTPClient = client(func(req *http.Request) (*http.Response, error) {
			count++
			if success {
				return reply(req, 200, "application/json", `{"AccessKeyId":"key","SecretAccessKey":"secret"}`)
			}
			return reply(req, 503, "text/plain", "busy")
		})
	})
	// 52 failures, then 14 successful first attempts replenish the bucket, then
	// one more failure. The same provider and retryer survive all retrieves.
	for i := 0; i < 67; i++ {
		success = i >= 52 && i < 66
		before := count
		_, _ = p.Retrieve(context.Background())
		q.Attempts = append(q.Attempts, count-before)
	}
	return q
}
func main() {
	templates := []row{
		{Name: "plain-429", Status: 429}, {Name: "plain-500", Status: 500}, {Name: "plain-502", Status: 502}, {Name: "plain-503", Status: 503}, {Name: "plain-504", Status: 504},
		{Name: "plain-501-terminal", Status: 501}, {Name: "plain-400-terminal", Status: 400}, {Name: "plain-401-terminal", Status: 401}, {Name: "plain-403-terminal", Status: 403},
		{Name: "json-throttle", Status: 400, ContentType: "application/json", Body: `{"code":"Throttling"}`},
		{Name: "json-timeout", Status: 400, ContentType: "application/json", Body: `{"code":"RequestTimeout"}`},
		{Name: "json-code-case-sensitive", Status: 400, ContentType: "application/json", Body: `{"code":"throttling"}`},
		{Name: "json-field-folded", Status: 400, ContentType: "application/json", Body: `{"CODE":"SlowDown"}`},
		{Name: "json-duplicate-code", Status: 400, ContentType: "application/json", Body: `{"code":"Denied","CODE":"Throttling"}`},
		{Name: "json-null-preserves", Status: 400, ContentType: "application/json", Body: `{"code":"Throttling","Code":null}`},
		{Name: "json-trailing-value", Status: 400, ContentType: "application/json", Body: `{"code":"Throttling"} {}`},
		{Name: "json-content-type-exact", Status: 400, ContentType: "application/json; charset=utf-8", Body: `{"code":"Throttling"}`},
		{Name: "malformed-json-503", Status: 503, ContentType: "application/json", Body: `oops`},
		{Name: "wrong-code-type-503", Status: 503, ContentType: "application/json", Body: `{"code":4}`},
		{Name: "wrong-message-type-503", Status: 503, ContentType: "application/json", Body: `{"code":"Throttling","message":4}`},
		{Name: "malformed-success-terminal", Status: 200, ContentType: "application/json", Body: `oops`},
		{Name: "recover-503", Status: 503, Recover: true}, {Name: "recover-429", Status: 429, Recover: true},
		{Name: "timeout", Transport: "timeout"}, {Name: "connection-reset", Transport: "connection-reset"}, {Name: "nxdomain-terminal", Transport: "nxdomain"}, {Name: "plain-send-error", Transport: "plain"},
	}
	rows := []row{}
	quotas := []quota{}
	for _, newMode := range []bool{false, true} {
		if newMode {
			_ = os.Setenv("AWS_NEW_RETRIES_2026", "true")
		} else {
			_ = os.Unsetenv("AWS_NEW_RETRIES_2026")
		}
		start := len(rows)
		for _, v := range templates {
			v.New = newMode
			rows = append(rows, v)
		}
		var wg sync.WaitGroup
		for i := start; i < len(rows); i++ {
			wg.Add(1)
			go func(i int) { defer wg.Done(); run(&rows[i]) }(i)
		}
		wg.Wait()
		quotas = append(quotas, exhaustion(newMode))
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(struct {
		Rows   []row   `json:"rows"`
		Quotas []quota `json:"quotas"`
	}{rows, quotas}); err != nil {
		panic(err)
	}
}
