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

// Actual production provider and UploadStream against real loopback HTTP.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/pingcap/metering_sdk/storage/provider"
)

type reply struct {
	Status  int               `json:"status"`
	Code    string            `json:"code"`
	Body    string            `json:"body"`
	Headers map[string]string `json:"headers,omitempty"`
	Drop    bool              `json:"drop"`
}
type attempt struct {
	CommitBody  string   `json:"commit_body"`
	Method      string   `json:"method"`
	Path        string   `json:"path"`
	Comp        string   `json:"comp"`
	Length      int      `json:"length"`
	SHA256      string   `json:"sha256"`
	Blocks      []uint32 `json:"blocks"`
	ContentType string   `json:"content_type"`
	BlobType    string   `json:"blob_type"`
	Signed      bool     `json:"signed"`
	RequestID   int      `json:"request_id"`
	SAS         bool     `json:"sas"`
}
type row struct {
	Name        string    `json:"name"`
	Method      string    `json:"method"`
	Size        int       `json:"size"`
	SAS         bool      `json:"sas"`
	FailureComp string    `json:"failure_comp"`
	Responses   []reply   `json:"responses"`
	Attempts    []attempt `json:"attempts"`
	Error       bool      `json:"error"`
	Exists      bool      `json:"exists"`
}

func main() {
	cases := []row{}
	for _, method := range []string{"HEAD", "PUT"} {
		size := 7
		if method == "HEAD" {
			size = 0
		}
		add := func(name string, r ...reply) {
			cases = append(cases, row{Name: name, Method: method, Size: size, Responses: r})
		}
		for _, code := range []int{200, 201, 202, 204, 400, 401, 403, 404, 408, 409, 429, 500, 501, 502, 503, 504, 599} {
			add("status"+strconv.Itoa(code), reply{Status: code}, reply{})
		}
		add("exhausted503", reply{Status: 503})
		for _, code := range []string{"BlobNotFound", "ResourceNotFound", "ContainerNotFound", "blobnotfound", "Denied"} {
			add("code"+code, reply{Status: 403, Code: code})
		}
		add("header-before-xml", reply{Status: 403, Code: "Denied", Body: "<Error><Code>BlobNotFound</Code></Error>"})
		add("xml-code", reply{Status: 403, Body: "<Error><Code>BlobNotFound</Code></Error>"})
		add("json-code", reply{Status: 403, Body: `{"error":{"code":"BlobNotFound"}}`})
		add("transport-retry", reply{Drop: true}, reply{})
		add("retry-ms", reply{Status: 503, Headers: map[string]string{"retry-after-ms": "1", "x-ms-retry-after-ms": "60001", "retry-after": "61"}}, reply{})
		add("retry-cap", reply{Status: 503, Headers: map[string]string{"retry-after-ms": "60001"}}, reply{})
		add("retry-fallback-cap", reply{Status: 503, Headers: map[string]string{"retry-after-ms": "0", "x-ms-retry-after-ms": "60001"}}, reply{})
		add("retry-seconds-cap", reply{Status: 503, Headers: map[string]string{"retry-after": "61"}}, reply{})
		add("retry-invalid", reply{Status: 503, Headers: map[string]string{"retry-after": "nonsense"}}, reply{})
		add("opaque-utf8-metadata", reply{Headers: map[string]string{"x-ms-meta-label": "café", "etag": "étiquette"}})
		add("retry-cap-absent", reply{Status: 503, Code: "BlobNotFound", Headers: map[string]string{"retry-after": "61"}})
		for _, h := range []string{"Date", "Last-Modified", "Content-MD5", "x-ms-content-crc64", "x-ms-request-server-encrypted", "x-ms-server-encrypted", "x-ms-blob-committed-block-count"} {
			add("invalid-"+h, reply{Headers: map[string]string{h: "invalid"}})
		}

		dates := []string{
			"Mon, 02 Jan 2006 15:04:05 GMT", "Tue, 02 Jan 2006 15:04:05 GMT",
			"mon, 02 jan 2006 15:04:05 GMT", "Mon,  02  Jan  2006  15:04:05  GMT",
			"Mon, 2 Jan 2006 15:04:05 GMT", "Mon, 02 Jan 06 15:04:05 GMT",
			"Mon, 02 Jan 2006 5:04:05 GMT", "Mon, 02 Jan 2006 15:4:05 GMT",
			"Mon, 02 Jan 2006 15:04:5 GMT", "Mon, 02 Jan 2006 15:04:05.123456789123 GMT",
			"Mon, 02 Jan 2006 15:04:05,1 GMT", "Mon, 02 Jan 2006 15:04:05. GMT",
			"Mon, 29 Feb 2000 15:04:05 GMT", "Mon, 29 Feb 1900 15:04:05 GMT",
			"Mon, 29 Feb 0000 15:04:05 GMT", "Mon, 31 Apr 2006 15:04:05 GMT",
			"Mon, 00 Jan 2006 15:04:05 GMT", "Mon, 02 Jan 2006 24:04:05 GMT",
			"Mon, 02 Jan 2006 15:60:05 GMT", "Mon, 02 Jan 2006 15:04:60 GMT",
			"Monday, 02 Jan 2006 15:04:05 GMT", "Mon, 02 January 2006 15:04:05 GMT",
			"Sun Nov  6 08:49:37 1994", "Sunday, 06-Nov-94 08:49:37 GMT",
			"Mon,02 Jan 2006 15:04:05 GMT", "Mon, 02Jan 2006 15:04:05 GMT",
		}
		for _, zone := range []string{"UTC", "PST", "CST", "FOO", "WITA", "ChST", "MeST", "CEST", "ABCET", "ABCD", "ABCDE", "ABCDEF", "UT", "Z", "gmt", "GMT+1", "GMT-23", "GMT+24", "GMT+0", "GMT+00001", "+01", "-00", "+1", "-24", "+0000", "+000000000000000000000001", "+999999999999999999999999999", "GMT+01:00"} {
			dates = append(dates, "Mon, 02 Jan 2006 15:04:05 "+zone)
		}
		for i, date := range dates {
			add(fmt.Sprintf("metadata-date-%d", i), reply{Headers: map[string]string{"Last-Modified": date}})
		}

		for _, header := range []string{"Content-MD5", "x-ms-content-crc64"} {
			for i, value := range []string{"Zg==", "Zh==", "Zm8=", "Zm9=", "Zg", "Zg=", "Z===", ""} {
				add(fmt.Sprintf("metadata-base64-%s-%d", header, i), reply{Headers: map[string]string{header: value}})
			}
		}
		add("sas-retry", reply{Status: 503}, reply{})
		cases[len(cases)-1].SAS = true
	}
	for _, size := range []int{0, 1, 1048575, 1048576, 1048577, 2097152, 2097153} {
		cases = append(cases, row{Name: fmt.Sprintf("size%d", size), Method: "PUT", Size: size, Responses: []reply{{}}})
	}
	for _, comp := range []string{"block", "blocklist"} {
		for _, exhaust := range []bool{false, true} {
			r := row{Name: fmt.Sprintf("%s-exhaust%v", comp, exhaust), Method: "PUT", Size: 1048577, FailureComp: comp, Responses: []reply{{Status: 503}}}
			if !exhaust {
				r.Responses = append(r.Responses, reply{})
			}
			cases = append(cases, r)
		}
	}
	for i := range cases {
		r := &cases[i]
		requests := map[string]int{}
		attemptIndex := 0
		var blockPrefix []byte
		blockNumber := func(id string) uint32 {
			b, e := base64.StdEncoding.DecodeString(id)
			if e != nil || len(b) != 64 {
				panic("invalid block ID")
			}
			if blockPrefix == nil {
				blockPrefix = append([]byte(nil), b[:16]...)
			}
			if !bytes.Equal(blockPrefix, b[:16]) || !bytes.Equal(b[20:], make([]byte, 44)) {
				panic("unstable block ID prefix")
			}
			return binary.BigEndian.Uint32(b[16:20])
		}
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			b, e := io.ReadAll(req.Body)
			if e != nil {
				panic(e)
			}
			comp := req.URL.Query().Get("comp")
			digest := sha256.Sum256(b)
			h := hex.EncodeToString(digest[:])
			var blocks []uint32
			if comp == "block" {
				blocks = append(blocks, blockNumber(req.URL.Query().Get("blockid")))
			}
			commitBody := ""
			if comp == "blocklist" {
				var list struct {
					Latest []string `xml:"Latest"`
				}
				if e := xml.Unmarshal(b, &list); e != nil {
					panic(e)
				}
				commitBody = string(b)
				for _, id := range list.Latest {
					blocks = append(blocks, blockNumber(id))
					raw, _ := base64.StdEncoding.DecodeString(id)
					copy(raw[:16], make([]byte, 16))
					commitBody = strings.ReplaceAll(commitBody, id, base64.StdEncoding.EncodeToString(raw))
				}
				h = "blocklist"
			}
			rid := req.Header.Get("x-ms-client-request-id")
			id, ok := requests[rid]
			if rid == "" {
				id = -1
			} else if !ok {
				id = len(requests)
				requests[rid] = id
			}
			r.Attempts = append(r.Attempts, attempt{commitBody, req.Method, req.URL.EscapedPath(), comp, len(b), h, blocks, req.Header.Get("Content-Type"), req.Header.Get("X-Ms-Blob-Type"), strings.HasPrefix(req.Header.Get("Authorization"), "SharedKey account:"), id, req.URL.Query().Get("sig") == "fake"})
			resp := reply{}
			if r.FailureComp == "" || r.FailureComp == comp {
				j := attemptIndex
				if j >= len(r.Responses) {
					j = len(r.Responses) - 1
				}
				resp = r.Responses[j]
				attemptIndex++
			}
			if resp.Drop {
				conn, _, e := w.(http.Hijacker).Hijack()
				if e != nil {
					panic(e)
				}
				_ = conn.Close()
				return
			}
			status := resp.Status
			if status == 0 {
				status = 200
				if req.Method == "PUT" {
					status = 201
				}
			}
			if resp.Code != "" {
				w.Header().Set("x-ms-error-code", resp.Code)
			}
			for k, v := range resp.Headers {
				w.Header().Set(k, v)
			}
			w.WriteHeader(status)
			_, _ = w.Write([]byte(resp.Body))
		}))
		cfg := &provider.ProviderConfig{Type: provider.ProviderTypeAzure, Bucket: "bucket", Prefix: "prefix space/%text", Endpoint: srv.URL + "/base", Azure: &provider.AzureConfig{AccountName: "account", AccountKey: base64.StdEncoding.EncodeToString([]byte("fake-account-key"))}}
		if r.SAS {
			cfg.Azure.AccountKey = ""
			cfg.Azure.SASToken = "?sig=fake&sp=rw&sv=2025-11-05"
		}
		p, e := provider.NewAzureProvider(cfg)
		if e != nil {
			panic(e)
		}
		// Only backoff is shortened to 1ns, via the documented per-call override.
		// azcore1.20 treats a zero calculated delay as overflow, so do not use -1.
		ctx := policy.WithRetryOptions(context.Background(), policy.RetryOptions{RetryDelay: 1})
		if r.Method == "HEAD" {
			r.Exists, e = p.Exists(ctx, "key.json.gz")
		} else {
			e = p.Upload(ctx, "key.json.gz", bytes.NewReader(bytes.Repeat([]byte("p"), r.Size)))
		}
		r.Error = e != nil
		srv.Close()
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if e := enc.Encode(cases); e != nil {
		panic(e)
	}
}
