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

// Run from the repository root. Fake requests use an in-memory AWS transport
// and a local OSS HTTP server; no cloud endpoints are contacted.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"time"

	openapi "github.com/alibabacloud-go/darabonba-openapi/v2/client"
	alists "github.com/alibabacloud-go/sts-20150401/v2/client"
	util "github.com/alibabacloud-go/tea-utils/v2/service"
	"github.com/alibabacloud-go/tea/tea"
	alicred "github.com/aliyun/credentials-go/credentials"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

type roundTrip func(*http.Request) (*http.Response, error)

func (r roundTrip) Do(req *http.Request) (*http.Response, error) { return r(req) }

type capture struct {
	Name          string `json:"name"`
	Method        string `json:"method"`
	URL           string `json:"url"`
	Body          string `json:"body"`
	ContentType   string `json:"content_type"`
	SecurityToken string `json:"security_token,omitempty"`
}

func record(name string, req *http.Request) capture {
	body, _ := io.ReadAll(req.Body)
	return capture{name, req.Method, req.URL.String(), string(body), req.Header.Get("Content-Type"), req.Header.Get("X-Amz-Security-Token")}
}
func main() {
	for _, key := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"} {
		_ = os.Unsetenv(key)
	}
	var rows []capture
	for _, item := range []struct{ name, region, endpoint string }{
		{"aws-regional", "us-east-1", ""},
		{"aws-china", "cn-north-1", ""},
		{"aws-custom", "us-east-1", "http://sts.fixture.invalid:9000/prefix"},
	} {
		var firstSession string
		calls := 0
		cfg := aws.Config{Region: item.region, Credentials: credentials.NewStaticCredentialsProvider("base-id", "base-secret", "base-token"), HTTPClient: roundTrip(func(req *http.Request) (*http.Response, error) {
			row := record(item.name, req)
			values, err := url.ParseQuery(row.Body)
			if err != nil {
				panic(err)
			}
			session := values.Get("RoleSessionName")
			if !strings.HasPrefix(session, "aws-go-sdk-") || values.Get("DurationSeconds") != "900" {
				panic("AWS role defaults changed")
			}
			if calls == 0 {
				firstSession = session
			} else if session != firstSession {
				panic("AWS session changed on refresh")
			}
			// Only the auto-generated session is normalized. The other fields are
			// captured from the actual SDK request, including its regional/custom URL.
			row.Body = strings.ReplaceAll(row.Body, session, "aws-go-sdk-1789891200000000000")
			if calls == 0 {
				rows = append(rows, row)
			}
			calls++
			return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`<AssumeRoleResponse><AssumeRoleResult><Credentials><AccessKeyId>ASIAEXAMPLE0000000000</AccessKeyId><SecretAccessKey>role-secret</SecretAccessKey><SessionToken>role-token</SessionToken><Expiration>2099-01-01T00:00:00Z</Expiration></Credentials></AssumeRoleResult></AssumeRoleResponse>`)), Request: req}, nil
		})}
		if item.endpoint != "" {
			cfg.BaseEndpoint = aws.String(item.endpoint)
		}
		arn := "arn:aws:iam::123456789012:role/metering"
		if strings.HasPrefix(item.region, "cn-") {
			arn = "arn:aws-cn:iam::123456789012:role/metering"
		}
		p := stscreds.NewAssumeRoleProvider(sts.NewFromConfig(cfg), arn)
		for range 2 {
			if _, err := p.Retrieve(context.Background()); err != nil {
				panic(err)
			}
		}
	}
	for _, kind := range []string{"access_key", "sts"} {
		base, err := alicred.NewCredential(&alicred.Config{Type: tea.String(kind), AccessKeyId: tea.String("base-id"), AccessKeySecret: tea.String("base-secret"), SecurityToken: tea.String("base-token")})
		if err != nil {
			panic(err)
		}
		endpoint := ""
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			row := record("oss-"+kind, r)
			row.URL = "https://" + endpoint + r.URL.RequestURI()
			rows = append(rows, row)
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"Credentials":{"AccessKeyId":"role-id","AccessKeySecret":"role-secret","SecurityToken":"role-token","Expiration":"2099-01-01T00:00:00Z"}}`)
		}))
		client, err := alists.NewClient(&openapi.Config{Credential: base, RegionId: tea.String("cn-hangzhou")})
		if err != nil {
			panic(err)
		}
		endpoint = tea.StringValue(client.Endpoint)
		client.Endpoint = tea.String(strings.TrimPrefix(srv.URL, "http://"))
		client.Protocol = tea.String("HTTP")
		_, err = client.AssumeRoleWithOptions(&alists.AssumeRoleRequest{RoleArn: tea.String("acs:ram::123456789012:role/metering"), RoleSessionName: tea.String(fmt.Sprintf("oss-sdk-session-%d", time.Now().Unix())), DurationSeconds: tea.Int64(3600)}, &util.RuntimeOptions{})
		srv.Close()
		if err != nil {
			panic(err)
		}
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(rows); err != nil {
		panic(err)
	}
}
