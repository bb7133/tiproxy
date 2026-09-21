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

// Run from the repository root; only a capturing HTTP client is used.
package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type row struct {
	Endpoint string `json:"endpoint"`
	Bucket   string `json:"bucket"`
	Force    bool   `json:"force"`
	URL      string `json:"url"`
}
type capture struct{ row *row }

func (c capture) Do(r *http.Request) (*http.Response, error) {
	c.row.URL = r.URL.String()
	return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
}
func main() {
	rows := []row{
		{"", "bucket", false, ""},
		{"https://store.invalid", "bucket", false, ""},
		{"http://store.invalid:9000/base", "bucket", true, ""},
		{"http://127.0.0.1:9000/base", "bucket", false, ""},
		{"https://store.invalid", "bucket.dotted", false, ""},
		{"http://store.invalid", "bucket.dotted", false, ""},
		{"https://store.invalid", "Bucket_Upper", false, ""},
		{"https://store.invalid", "192.168.1.1", false, ""},
		{"https://store.invalid", "ab", false, ""},
	}
	for i := range rows {
		cfg := aws.Config{Region: "us-east-1", Credentials: aws.NewCredentialsCache(credentials.NewStaticCredentialsProvider("fake-id", "fake-secret", "fake-token")), HTTPClient: capture{&rows[i]}}
		client := s3.NewFromConfig(cfg, func(o *s3.Options) {
			o.UsePathStyle = rows[i].Force
			if rows[i].Endpoint != "" {
				o.BaseEndpoint = aws.String(rows[i].Endpoint)
			}
		})
		_, err := client.HeadObject(context.Background(), &s3.HeadObjectInput{Bucket: aws.String(rows[i].Bucket), Key: aws.String("prefix space/%text/key")})
		if err != nil {
			panic(err)
		}
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(rows); err != nil {
		panic(err)
	}
}
