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

// Actual metering COS provider, including its default CRC check and retry marker.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/pingcap/metering_sdk/storage/provider"
	"hash/crc64"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
)

type reply struct {
	Status    int    `json:"status"`
	Body      string `json:"body"`
	CRC       string `json:"crc"`
	Transport bool   `json:"transport"`
}
type attempt struct {
	Retry  bool   `json:"retry"`
	Body   string `json:"body"`
	Signed bool   `json:"signed"`
}
type row struct {
	Name      string    `json:"name"`
	Method    string    `json:"method"`
	Payload   string    `json:"payload"`
	Responses []reply   `json:"responses"`
	Attempts  []attempt `json:"attempts"`
	Exists    bool      `json:"exists"`
	Error     bool      `json:"error"`
}
type transport func(*http.Request) (*http.Response, error)

func (f transport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func main() {
	cases := []row{
		{Name: "empty-put-ignoresCRC", Responses: []reply{{Status: 200, CRC: "1"}}},
		{Name: "unicode-payload", Payload: "汉字\x00payload", Responses: []reply{{Status: 200, CRC: "correct"}}},
		{Name: "success", Responses: []reply{{Status: 200, CRC: "correct"}}},
		{Name: "empty404", Responses: []reply{{Status: 404}}},
		{Name: "malformed404", Responses: []reply{{Status: 404, Body: "<bad"}}},
		{Name: "NoSuchKey403", Responses: []reply{{Status: 403, Body: "<Error><Code>NoSuchKey</Code></Error>"}}},
		{Name: "401terminal", Responses: []reply{{Status: 401}}},
		{Name: "408terminal", Responses: []reply{{Status: 408}}},
		{Name: "429terminal", Responses: []reply{{Status: 429}}},
		{Name: "503retry", Responses: []reply{{Status: 503}, {Status: 200, CRC: "correct"}}},
		{Name: "501retry", Responses: []reply{{Status: 501}, {Status: 200, CRC: "correct"}}},
		{Name: "599exhaustion", Responses: []reply{{Status: 599}}},
		{Name: "transport-retry", Responses: []reply{{Transport: true}, {Status: 200, CRC: "correct"}}},
		{Name: "BadRequest400terminal", Responses: []reply{{Status: 400, Body: "<Error><Code>BadRequest</Code></Error>"}}},
		{Name: "missingCRC", Responses: []reply{{Status: 200}}},
		{Name: "wrongCRC", Responses: []reply{{Status: 200, CRC: "1"}}},
		{Name: "malformedCRC", Responses: []reply{{Status: 200, CRC: "invalid"}}},
		{Name: "crc-error-not-retried", Responses: []reply{{Status: 200, CRC: "1"}, {Status: 200, CRC: "correct"}}},
	}
	var rows []row
	for _, method := range []string{"HEAD", "PUT"} {
		for _, original := range cases {
			r := original
			r.Method = method
			if method == "PUT" && r.Name != "empty-put-ignoresCRC" && r.Payload == "" {
				r.Payload = "payload"
			}
			if method == "HEAD" {
				r.Payload = ""
			}
			r.Responses = append([]reply(nil), r.Responses...)
			for i := range r.Responses {
				if r.Responses[i].CRC == "correct" {
					r.Responses[i].CRC = strconv.FormatUint(crc64.Checksum([]byte(r.Payload), crc64.MakeTable(crc64.ECMA)), 10)
				}
			}
			http.DefaultTransport = transport(func(req *http.Request) (*http.Response, error) {
				i := len(r.Attempts)
				if i >= len(r.Responses) {
					i = len(r.Responses) - 1
				}
				v := r.Responses[i]
				var body []byte
				if req.Body != nil {
					body, _ = io.ReadAll(req.Body)
				}
				r.Attempts = append(r.Attempts, attempt{Retry: req.Header.Get("X-Cos-Sdk-Retry") == "true", Body: string(body), Signed: strings.HasPrefix(req.Header.Get("Authorization"), "q-sign-algorithm=sha1")})
				if v.Transport {
					return nil, errors.New("synthetic transport failure")
				}
				h := http.Header{}
				if v.CRC != "" {
					h.Set("x-cos-hash-crc64ecma", v.CRC)
				}
				return &http.Response{StatusCode: v.Status, Header: h, Body: io.NopCloser(strings.NewReader(v.Body)), Request: req}, nil
			})
			p, e := provider.NewCOSProvider(&provider.ProviderConfig{Type: provider.ProviderTypeCOS, Bucket: "bucket-123456", Region: "ap-guangzhou", COS: &provider.COSConfig{AccessKey: "key", SecretAccessKey: "secret"}})
			if e != nil {
				panic(e)
			}
			if method == "HEAD" {
				r.Exists, e = p.Exists(context.Background(), "object")
			} else {
				e = p.Upload(context.Background(), "object", bytes.NewReader([]byte(r.Payload)))
			}
			r.Error = e != nil
			rows = append(rows, r)
		}
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if e := enc.Encode(rows); e != nil {
		panic(e)
	}
}
