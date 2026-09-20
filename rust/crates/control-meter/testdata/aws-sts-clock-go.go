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

// Capture actual STS v1.38 clock skew, HTTP date parsing and fixed-time SigV4.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
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
	"github.com/aws/aws-sdk-go-v2/service/sts"
	smithytime "github.com/aws/smithy-go/time"
)

type response struct {
	Code   string `json:"code"`
	Date   string `json:"date"`
	Offset int    `json:"offset"`
	Status int    `json:"status"`
}
type operation struct {
	Responses []response `json:"responses"`
	Signed    []int64    `json:"signed"`
	Calls     int        `json:"calls"`
	Error     bool       `json:"error"`
}
type row struct {
	Name       string      `json:"name"`
	Web        bool        `json:"web"`
	New        bool        `json:"new"`
	Operations []operation `json:"operations"`
}
type transport func(*http.Request) (*http.Response, error)

func (f transport) Do(r *http.Request) (*http.Response, error) { return f(r) }
func main() {
	base := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	sdk.NowTime = func() time.Time { return base }
	sdk.SleepWithContext = func(context.Context, time.Duration) error { return nil }
	ok := response{Date: "http"}
	at := func(code string, offset int) response { return response{Code: code, Date: "http", Offset: offset} }
	op := func(r ...response) operation { return operation{Responses: r} }
	var cases []row
	for _, code := range []string{"RequestExpired", "RequestInTheFuture", "RequestTimeTooSkewed"} {
		cases = append(cases, row{Name: code, Operations: []operation{op(at(code, 600), ok), op(ok)}})
	}
	for _, code := range []string{"InvalidSignatureException", "SignatureDoesNotMatch", "AuthFailure"} {
		cases = append(cases, row{Name: code, Operations: []operation{op(at(code, 600), ok), op(at(code, 0), ok), op(ok)}})
	}
	for _, delta := range []int{-600, 239, 240, 241} {
		cases = append(cases, row{Name: "possible-after-offset", Operations: []operation{op(response{Status: 503, Date: "http", Offset: delta}, at("AuthFailure", 0), ok), op(ok)}})
	}
	cases = append(cases,
		row{Name: "retry-without-date-resets-attempt-skew", Operations: []operation{op(response{Status: 503, Date: "http", Offset: 600}, response{Code: "RequestExpired"}, at("AuthFailure", 0)), op(ok)}},
		row{Name: "absent-final-date-does-not-persist-client-skew", Operations: []operation{op(at("", 600)), op(response{Code: "Denied"}), op(ok)}},
		row{Name: "malformed-date-ignored", Operations: []operation{op(response{Code: "RequestExpired", Date: "bad"}, ok), op(ok)}},
		row{Name: "negative-skew-signing", Operations: []operation{op(at("RequestExpired", -600), ok), op(ok)}},
		row{Name: "lowercase-not-clock-error", Operations: []operation{op(at("requestexpired", 600), ok), op(ok)}},
		row{Name: "http503-sets-next-attempt-skew", Operations: []operation{op(response{Status: 503, Date: "http", Offset: 600}, at("AuthFailure", 0), ok), op(ok)}},
	)
	var rows []row
	for _, newMode := range []bool{false, true} {
		_ = os.Setenv("AWS_NEW_RETRIES_2026", map[bool]string{true: "true", false: "false"}[newMode])
		for _, web := range []bool{false, true} {
			for _, original := range cases {
				raw, _ := json.Marshal(original)
				var r row
				_ = json.Unmarshal(raw, &r)
				r.Web = web
				r.New = newMode
				var current *operation
				client := transport(func(req *http.Request) (*http.Response, error) {
					index := current.Calls
					if index >= len(current.Responses) {
						index = len(current.Responses) - 1
					}
					step := current.Responses[index]
					current.Calls++
					if d := req.Header.Get("X-Amz-Date"); d != "" {
						tm, e := time.Parse("20060102T150405Z", d)
						if e != nil {
							panic(e)
						}
						current.Signed = append(current.Signed, int64(tm.Sub(base)/time.Second))
					}
					action := "AssumeRole"
					if web {
						action = "AssumeRoleWithWebIdentity"
					}
					code := step.Status
					if code == 0 {
						code = 200
					}
					body := "<" + action + "Response><" + action + "Result><Credentials><AccessKeyId>ASIA1234567890123456</AccessKeyId><SecretAccessKey>secret</SecretAccessKey><SessionToken>token</SessionToken><Expiration>2099-01-01T00:00:00Z</Expiration></Credentials></" + action + "Result></" + action + "Response>"
					if step.Code != "" {
						code = 400
						body = "<ErrorResponse><Error><Code>" + step.Code + "</Code></Error></ErrorResponse>"
					}
					hdr := http.Header{}
					if step.Date == "http" {
						hdr.Set("Date", base.Add(time.Duration(step.Offset)*time.Second).Format(http.TimeFormat))
					} else if step.Date != "" {
						hdr.Set("Date", step.Date)
					}
					return &http.Response{StatusCode: code, Header: hdr, Body: io.NopCloser(strings.NewReader(body)), Request: req}, nil
				})
				c := sts.New(sts.Options{Region: "us-east-1", HTTPClient: client, Credentials: credentials.NewStaticCredentialsProvider("key", "secret", ""), Retryer: retry.NewStandard(func(o *retry.StandardOptions) {
					o.Backoff = retry.BackoffDelayerFunc(func(int, error) (time.Duration, error) { return 0, nil })
				})})
				for i := range r.Operations {
					current = &r.Operations[i]
					var err error
					if web {
						_, err = c.AssumeRoleWithWebIdentity(context.Background(), &sts.AssumeRoleWithWebIdentityInput{RoleArn: aws.String("arn:aws:iam::123456789012:role/test"), RoleSessionName: aws.String("session"), WebIdentityToken: aws.String("token")})
					} else {
						_, err = c.AssumeRole(context.Background(), &sts.AssumeRoleInput{RoleArn: aws.String("arn:aws:iam::123456789012:role/test"), RoleSessionName: aws.String("session")})
					}
					current.Error = err != nil
				}
				rows = append(rows, r)
			}
		}
	}

	type parsed struct {
		Input   string `json:"input"`
		Seconds int64  `json:"seconds"`
		Nanos   int    `json:"nanos"`
		Error   bool   `json:"error"`
	}
	var dates []parsed
	for _, value := range []string{
		"Mon, 15 Jun 2026 12:00:00 GMT", "Mon, 5 Jun 2026 12:00:00 GMT", "Mon,  5 Jun 26 12:00:00 GMT", "Monday, 15-Jun-26 12:00:00 GMT", "Mon Jun 15 12:00:00 2026", "Tue, 15 Jun 2026 12:00:00 GMT", "Mon, 15 Jun 2026 12:00:00.123456789 GMT", "Mon, 15 Jun 2026 12:00:00,123 GMT", "Mon, 15 Jun 2026 12:00:00.12345678912 GMT", "Monday, 15-Jun-69 12:00:00 GMT", "Monday, 15-Jun-26 12:00:00 EST", "Mon, 15 Jun 2026 12:00:00 UTC", "Mon, 15 Jun 2026 12:00:00 +0000", " Mon, 15 Jun 2026 12:00:00 GMT", "Mon, 15 Jun 2026 12:00:00 GMT ", "Mon,  15  Jun  2026 12:00:00 GMT", "Mon, 31 Jun 2026 12:00:00 GMT", "Bad, 15 Jun 2026 12:00:00 GMT", "Mon, 15 jun 2026 12:00:00 GMT", "Mon, 15 Jun 2026 1:00:00 GMT", "Mon, 015 Jun 2026 12:00:00 GMT", "", "bad",
	} {
		t, e := smithytime.ParseHTTPDate(value)
		d := parsed{Input: value, Error: e != nil}
		if e == nil {
			d.Seconds = t.Unix()
			d.Nanos = t.Nanosecond()
		}
		dates = append(dates, d)
	}
	type signature struct {
		URL           string `json:"url"`
		Body          string `json:"body"`
		Token         string `json:"token"`
		Time          string `json:"time"`
		Authorization string `json:"authorization"`
	}
	var signatures []signature
	for _, r := range []signature{{URL: "https://sts.us-east-1.amazonaws.com/", Body: "Action=AssumeRole&Version=2011-06-15", Time: "20260615T120000Z"}, {URL: "https://custom.example/a/b?x=2&x=1", Body: "Action=AssumeRole&RoleArn=arn%3Aexample", Token: "token", Time: "20260614T235959Z"}} {
		req, e := http.NewRequest("POST", r.URL, strings.NewReader(r.Body))
		if e != nil {
			panic(e)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		payload := fmt.Sprintf("%x", sha256.Sum256([]byte(r.Body)))
		req.Header.Set("X-Amz-Content-Sha256", payload)
		t, e := time.Parse("20060102T150405Z", r.Time)
		if e != nil {
			panic(e)
		}
		e = v4.NewSigner().SignHTTP(context.Background(), aws.Credentials{AccessKeyID: "key", SecretAccessKey: "secret", SessionToken: r.Token}, req, payload, "sts", "us-east-1", t)
		if e != nil {
			panic(e)
		}
		r.Authorization = req.Header.Get("Authorization")
		signatures = append(signatures, r)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if e := enc.Encode(struct {
		Requests   []row       `json:"requests"`
		Dates      []parsed    `json:"dates"`
		Signatures []signature `json:"signatures"`
	}{rows, dates, signatures}); e != nil {
		panic(e)
	}
}
