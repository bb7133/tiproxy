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

// Actual OSS provider defaults; scripted transport only replaces I/O and retry delay.
package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"hash/crc64"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/aliyun/alibabacloud-oss-go-sdk-v2/oss"
	"github.com/aliyun/alibabacloud-oss-go-sdk-v2/oss/credentials"
	"github.com/aliyun/alibabacloud-oss-go-sdk-v2/oss/retry"
	"github.com/aliyun/alibabacloud-oss-go-sdk-v2/oss/signer"
	"github.com/pingcap/metering_sdk/storage/provider"
)

type reply struct {
	Status      int    `json:"status"`
	Body        string `json:"body"`
	CRC         string `json:"crc"`
	Transport   string `json:"transport"`
	Date        string `json:"date"`
	HeaderError string `json:"header_error"`
}
type attempt struct {
	Body        string `json:"body"`
	ContentType string `json:"content_type"`
	Path        string `json:"path"`
	Signed      bool   `json:"signed"`
	Offset      int64  `json:"offset"`
}
type operation struct {
	Responses []reply   `json:"responses"`
	Attempts  []attempt `json:"attempts"`
	Exists    bool      `json:"exists"`
	Error     bool      `json:"error"`
}
type row struct {
	Name       string      `json:"name"`
	Method     string      `json:"method"`
	Key        string      `json:"key"`
	Payload    string      `json:"payload"`
	RealHTTP   bool        `json:"real_http"`
	Operations []operation `json:"operations"`
}
type transport func(*http.Request) (*http.Response, error)

func (f transport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func errXML(code string) string                                       { return "<Error><Code>" + code + "</Code></Error>" }
func main() {
	cases := []row{}
	add := func(name string, responses ...reply) {
		cases = append(cases, row{Name: name, Operations: []operation{{Responses: responses}}})
	}
	add("success", reply{Status: 200, CRC: "correct"})
	add("empty", reply{Status: 200, CRC: "1"})
	add("missing-crc", reply{Status: 200})
	add("malformed-crc", reply{Status: 200, CRC: "invalid"})
	add("leading-zero-crc", reply{Status: 200, CRC: "leading"})
	add("crc-retry", reply{Status: 200, CRC: "1"}, reply{Status: 200, CRC: "correct"})
	add("empty404", reply{Status: 404})
	add("malformed404", reply{Status: 404, Body: "<bad"})
	add("wrong-xml-root", reply{Status: 403, Body: "<Other><Code>NoSuchKey</Code></Other>"})
	add("partial-xml-code", reply{Status: 400, Body: "<Error><Code>BadRequest</Code><bad"}, reply{Status: 200, CRC: "correct"})
	add("partial-xml-field", reply{Status: 403, Body: "<Error><Code>NoSuchKey"})
	add("encoded-code", reply{Status: 403, Body: "<Error><Code>NoSuch&#75;ey</Code></Error>"})
	add("key-leading-separators", reply{Status: 200, CRC: "correct"})
	cases[len(cases)-1].Key = "//nested//.json.gz"
	add("key-escaped", reply{Status: 200, CRC: "correct"})
	cases[len(cases)-1].Key = "space here/汉字+%.json.gz"

	add("NoSuchKey403", reply{Status: 403, Body: errXML("NoSuchKey")})
	add("NoSuchKey503", reply{Status: 503, Body: errXML("NoSuchKey")})
	add("header-NoSuchKey", reply{Status: 403, HeaderError: base64.StdEncoding.EncodeToString([]byte(errXML("NoSuchKey")))})
	add("body-before-header", reply{Status: 403, Body: errXML("Denied"), HeaderError: base64.StdEncoding.EncodeToString([]byte(errXML("NoSuchKey")))})
	add("bad-header-error", reply{Status: 403, HeaderError: "!invalid!"})
	for _, code := range []int{400, 401, 403, 408, 429, 500, 501, 503, 599} {
		add("status"+strconv.Itoa(code), reply{Status: code}, reply{Status: 200, CRC: "correct"})
	}
	add("exhausted503", reply{Status: 503})
	for _, code := range []string{"BadRequest", "badrequest", "RequestTimeTooSkewed", "RequestExpired", "SlowDown", "NoSuchBucket"} {
		add(code, reply{Status: 400, Body: errXML(code)}, reply{Status: 200, CRC: "correct"})
	}
	for _, kind := range []string{"connection reset", "connection refused", "EOF", "unexpected EOF", "synthetic terminal error", "tls: unknown certificate"} {
		add(kind, reply{Transport: kind}, reply{Status: 200, CRC: "correct"})
	}
	for _, d := range []string{"600", "-600", "bad", ""} {
		add("clock-"+d, reply{Status: 403, Body: errXML("RequestTimeTooSkewed"), Date: d}, reply{Status: 200, CRC: "correct"})
		cases[len(cases)-1].Operations = append(cases[len(cases)-1].Operations, operation{Responses: []reply{{Status: 200, CRC: "correct"}}})
	}
	add("clock-repeated", reply{Status: 403, Body: errXML("RequestTimeTooSkewed"), Date: "600"}, reply{Status: 403, Body: errXML("RequestTimeTooSkewed"), Date: "600"}, reply{Status: 200, CRC: "correct"})
	add("clock-failure-not-saved", reply{Status: 403, Body: errXML("RequestTimeTooSkewed"), Date: "600"})
	cases[len(cases)-1].Operations = append(cases[len(cases)-1].Operations, operation{Responses: []reply{{Status: 200, CRC: "correct"}}})
	add("other-code-no-clock", reply{Status: 503, Body: errXML("BadRequest"), Date: "600"}, reply{Status: 200, CRC: "correct"})
	add("default-real-http", reply{Status: 503}, reply{Status: 200, CRC: "correct"})
	cases[len(cases)-1].RealHTTP = true
	add("default-real-crc", reply{Status: 200, CRC: "1"}, reply{Status: 200, CRC: "correct"})
	cases[len(cases)-1].RealHTTP = true
	var rows []row
	for _, method := range []string{"HEAD", "PUT"} {
		for _, c := range cases {
			r := c
			r.Method = method
			if r.Key == "" {
				r.Key = "meter.json.gz"
			}
			if method == "PUT" && r.Name != "empty" {
				r.Payload = "汉字\x00payload"
			}
			// Copy nested slices before materializing response CRCs.
			r.Operations = append([]operation(nil), c.Operations...)
			for i := range r.Operations {
				r.Operations[i].Responses = append([]reply(nil), r.Operations[i].Responses...)
				for j := range r.Operations[i].Responses {
					v := &r.Operations[i].Responses[j]
					crc := strconv.FormatUint(crc64.Checksum([]byte(r.Payload), crc64.MakeTable(crc64.ECMA)), 10)
					if v.CRC == "correct" {
						v.CRC = crc
					}
					if v.CRC == "leading" {
						v.CRC = "0" + crc
					}
				}
			}
			op := 0
			roundtrip := func(req *http.Request) (*http.Response, error) {
				cur := &r.Operations[op]
				n := len(cur.Attempts)
				if n >= len(cur.Responses) {
					n = len(cur.Responses) - 1
				}
				v := cur.Responses[n]
				b, _ := io.ReadAll(req.Body)
				when, e := time.Parse("20060102T150405Z", req.Header.Get("X-Oss-Date"))
				if e != nil {
					panic(e)
				}
				cur.Attempts = append(cur.Attempts, attempt{Body: string(b), ContentType: req.Header.Get("Content-Type"), Path: req.URL.EscapedPath(), Signed: strings.HasPrefix(req.Header.Get("Authorization"), "OSS4-HMAC-SHA256 "), Offset: int64(math.Round(float64(when.Unix()-time.Now().Unix())/10)) * 10})
				if v.Transport != "" {
					switch v.Transport {
					case "EOF":
						return nil, io.EOF
					case "unexpected EOF":
						return nil, io.ErrUnexpectedEOF
					default:
						return nil, errors.New(v.Transport)
					}
				}
				h := http.Header{}
				if v.CRC != "" {
					h.Set("x-oss-hash-crc64ecma", v.CRC)
				}
				if v.HeaderError != "" {
					h.Set("x-oss-err", v.HeaderError)
				}
				if v.Date != "" {
					if n, e := strconv.Atoi(v.Date); e == nil {
						h.Set("Date", time.Now().Add(time.Duration(n)*time.Second).UTC().Format(http.TimeFormat))
					} else {
						h.Set("Date", v.Date)
					}
				}
				return &http.Response{StatusCode: v.Status, Header: h, Body: io.NopCloser(strings.NewReader(v.Body)), Request: req}, nil
			}
			pc := &provider.ProviderConfig{Type: provider.ProviderTypeOSS, Bucket: "bucket", Region: "cn-hangzhou", OSS: &provider.OSSConfig{AccessKey: "key", SecretAccessKey: "secret", SessionToken: "token"}}
			var server *httptest.Server
			if r.RealHTTP {
				server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
					resp, e := roundtrip(req)
					if e != nil {
						panic(e)
					}
					for k, v := range resp.Header {
						w.Header()[k] = v
					}
					w.Header()["Date"] = nil
					w.WriteHeader(resp.StatusCode)
					b, _ := io.ReadAll(resp.Body)
					_, _ = w.Write(b)
				}))
				pc.Endpoint = server.URL + "/ignored-base"
			} else {
				pc.OSS.CustomConfig = oss.LoadDefaultConfig().WithRegion(pc.Region).WithCredentialsProvider(credentials.NewStaticCredentialsProvider("key", "secret", "token")).WithHttpClient(&http.Client{Transport: transport(roundtrip)}).WithRetryer(retry.NewStandard(func(o *retry.RetryOptions) { o.Backoff = retry.NewFixedDelayBackoff(0) }))
			}
			p, e := provider.NewOSSProvider(pc)
			if e != nil {
				panic(e)
			}
			for op = 0; op < len(r.Operations); op++ {
				if method == "HEAD" {
					r.Operations[op].Exists, e = p.Exists(context.Background(), r.Key)
				} else {
					e = p.Upload(context.Background(), r.Key, bytes.NewReader([]byte(r.Payload)))
				}
				r.Operations[op].Error = e != nil
			}
			if server != nil {
				server.Close()
			}
			rows = append(rows, r)
		}
	}
	type signature struct {
		Method        string `json:"method"`
		Key           string `json:"key"`
		Time          string `json:"time"`
		ContentType   string `json:"content_type"`
		Authorization string `json:"authorization"`
	}
	var signatures []signature
	for _, key := range []string{"meter.json.gz", "space here/汉字+%.json.gz", "//nested//.json.gz"} {
		for _, method := range []string{"HEAD", "PUT"} {
			now := time.Date(2026, 9, 21, 0, 0, 1, 0, time.UTC)
			req, _ := http.NewRequest(method, "https://bucket.oss-cn-hangzhou.aliyuncs.com/", nil)
			ct := ""
			if method == "PUT" {
				ct = oss.TypeByExtension(key)
				req.Header.Set("Content-Type", ct)
			}
			creds := credentials.Credentials{AccessKeyID: "key", AccessKeySecret: "secret", SecurityToken: "token"}
			sc := &signer.SigningContext{Request: req, Bucket: oss.Ptr("bucket"), Key: &key, Product: oss.Ptr("oss"), Region: oss.Ptr("cn-hangzhou"), Credentials: &creds, Time: now}
			if e := (&signer.SignerV4{}).Sign(context.Background(), sc); e != nil {
				panic(e)
			}
			signatures = append(signatures, signature{method, key, now.Format(time.RFC3339), ct, req.Header.Get("Authorization")})
		}
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if e := enc.Encode(struct {
		Rows       []row       `json:"rows"`
		Signatures []signature `json:"signatures"`
	}{rows, signatures}); e != nil {
		panic(e)
	}
}
