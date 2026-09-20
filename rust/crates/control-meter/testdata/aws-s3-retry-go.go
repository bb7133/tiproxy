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

// Capture the actual metering SDK S3 Exists/Upload retries, not a copied policy.
package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/internal/sdk"
	"github.com/pingcap/metering_sdk/storage/provider"
)

type response struct {
	Status    int    `json:"status"`
	Body      string `json:"body"`
	Date      string `json:"date"`
	Offset    int    `json:"offset"`
	Transport bool   `json:"transport"`
}
type operation struct {
	Responses []response `json:"responses"`
	Calls     int        `json:"calls"`
	Error     bool       `json:"error"`
	Exists    bool       `json:"exists"`
	Signed    []int64    `json:"signed"`
}
type row struct {
	Name       string      `json:"name"`
	Method     string      `json:"method"`
	New        bool        `json:"new"`
	Operations []operation `json:"operations"`
}
type transport func(*http.Request) (*http.Response, error)

func (f transport) Do(r *http.Request) (*http.Response, error) { return f(r) }
func main() {
	base := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	sdk.NowTime = func() time.Time { return base }
	sdk.SleepWithContext = func(context.Context, time.Duration) error { return nil }
	op := func(r ...response) operation { return operation{Responses: r} }
	xml := func(code string) string { return "<Error><Code>" + code + "</Code></Error>" }
	ok := response{Status: 200}
	cases := []row{
		{Name: "success", Operations: []operation{op(ok)}},
		{Name: "404-empty", Operations: []operation{op(response{Status: 404})}},
		{Name: "404-malformed", Operations: []operation{op(response{Status: 404, Body: "<bad"})}},
		{Name: "403-empty", Operations: []operation{op(response{Status: 403})}},
		{Name: "429-empty", Operations: []operation{op(response{Status: 429})}},
		{Name: "503-then-success", Operations: []operation{op(response{Status: 503, Body: "<bad"}, ok)}},
		{Name: "500-exhaustion", Operations: []operation{op(response{Status: 500})}},
		{Name: "transport-then-success", Operations: []operation{op(response{Transport: true}, ok)}},
		{Name: "SlowDown", Operations: []operation{op(response{Status: 400, Body: xml("SlowDown")}, ok)}},
		{Name: "lowercase-slowdown", Operations: []operation{op(response{Status: 400, Body: xml("slowdown")}, ok)}},
		{Name: "RequestTimeout", Operations: []operation{op(response{Status: 400, Body: xml("RequestTimeout")}, ok)}},
		{Name: "NoSuchKey-status403", Operations: []operation{op(response{Status: 403, Body: xml("NoSuchKey")})}},
		{Name: "notfound-model-casefold", Operations: []operation{op(response{Status: 400, Body: xml("notfound")})}},
		{Name: "NotFound-in-message", Operations: []operation{op(response{Status: 403, Body: "<Error><Code>Denied</Code><Message>NotFound</Message></Error>"})}},
		{Name: "wrapped-not-an-s3-code", Operations: []operation{op(response{Status: 400, Body: "<Response>" + xml("SlowDown") + "</Response>"})}},
		{Name: "clock-definite", Operations: []operation{op(response{Status: 400, Body: xml("RequestExpired"), Date: "http", Offset: 600}, ok), op(ok)}},
		{Name: "clock-persists-across-operations", Operations: []operation{op(response{Status: 200, Date: "http", Offset: 600}), op(response{Status: 400, Body: xml("AuthFailure")}, ok), op(ok)}},
		{Name: "absent-final-date-preserves-client-skew", Operations: []operation{op(response{Status: 200, Date: "http", Offset: 600}), op(ok), op(ok)}},
		{Name: "valid-final-date-heals-skew", Operations: []operation{op(response{Status: 200, Date: "http", Offset: 600}), op(response{Status: 200, Date: "http"}), op(ok)}},
		{Name: "transport-resets-attempt-not-client", Operations: []operation{op(response{Status: 200, Date: "http", Offset: 600}), op(response{Transport: true}, response{Status: 400, Body: xml("AuthFailure")}), op(ok)}},
	}
	var rows []row
	for _, mode := range []bool{false, true} {
		_ = os.Setenv("AWS_NEW_RETRIES_2026", map[bool]string{false: "false", true: "true"}[mode])
		for _, method := range []string{"HEAD", "PUT"} {
			for _, original := range cases {
				raw, _ := json.Marshal(original)
				var r row
				_ = json.Unmarshal(raw, &r)
				r.New = mode
				r.Method = method
				var current *operation
				client := transport(func(req *http.Request) (*http.Response, error) {
					index := current.Calls
					if index >= len(current.Responses) {
						index = len(current.Responses) - 1
					}
					step := current.Responses[index]
					current.Calls++
					d, e := time.Parse("20060102T150405Z", req.Header.Get("X-Amz-Date"))
					if e != nil {
						panic(e)
					}
					current.Signed = append(current.Signed, int64(d.Sub(base)/time.Second))
					if req.Method != method {
						panic("unexpected method")
					}
					if req.Body != nil {
						_, _ = io.Copy(io.Discard, req.Body)
					}
					if step.Transport {
						return nil, io.ErrUnexpectedEOF
					}
					hdr := http.Header{}
					if step.Date == "http" {
						hdr.Set("Date", base.Add(time.Duration(step.Offset)*time.Second).Format(http.TimeFormat))
					} else if step.Date != "" {
						hdr.Set("Date", step.Date)
					}
					return &http.Response{StatusCode: step.Status, Header: hdr, Body: io.NopCloser(strings.NewReader(step.Body)), Request: req}, nil
				})
				cfg := aws.Config{Region: "us-east-1", HTTPClient: client, Credentials: credentials.NewStaticCredentialsProvider("key", "secret", ""), Retryer: func() aws.Retryer {
					return retry.NewStandard(func(o *retry.StandardOptions) {
						o.Backoff = retry.BackoffDelayerFunc(func(int, error) (time.Duration, error) { return 0, nil })
					})
				}}
				p, e := provider.NewS3Provider(&provider.ProviderConfig{Type: provider.ProviderTypeS3, Bucket: "bucket", AWS: &provider.AWSConfig{CustomConfig: cfg, S3ForcePathStyle: true}})
				if e != nil {
					panic(e)
				}
				for i := range r.Operations {
					current = &r.Operations[i]
					var err error
					if method == "HEAD" {
						current.Exists, err = p.Exists(context.Background(), "meter.json.gz")
					} else {
						err = p.Upload(context.Background(), "meter.json.gz", strings.NewReader("payload"))
					}
					current.Error = err != nil
				}
				rows = append(rows, r)
			}
		}
	}
	type signature struct {
		Method        string `json:"method"`
		URL           string `json:"url"`
		Time          string `json:"time"`
		Authorization string `json:"authorization"`
	}
	var signatures []signature
	for _, value := range []signature{{Method: "HEAD", URL: "https://s3.us-east-1.amazonaws.com/bucket/object", Time: "20260615T120000Z"}, {Method: "PUT", URL: "https://custom.example/prefix%20space/%25text/object", Time: "20260614T235959Z"}} {
		req, e := http.NewRequest(value.Method, value.URL, nil)
		if e != nil {
			panic(e)
		}
		req.Header.Set("X-Amz-Content-Sha256", "UNSIGNED-PAYLOAD")
		at, e := time.Parse("20060102T150405Z", value.Time)
		if e != nil {
			panic(e)
		}
		e = v4.NewSigner().SignHTTP(context.Background(), aws.Credentials{AccessKeyID: "key", SecretAccessKey: "secret", SessionToken: "token"}, req, "UNSIGNED-PAYLOAD", "s3", "us-east-1", at, func(o *v4.SignerOptions) { o.DisableURIPathEscaping = true })
		if e != nil {
			panic(e)
		}
		value.Authorization = req.Header.Get("Authorization")
		signatures = append(signatures, value)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if e := enc.Encode(struct {
		Requests   []row       `json:"requests"`
		Signatures []signature `json:"signatures"`
	}{rows, signatures}); e != nil {
		panic(e)
	}
}
