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

// Capture the actual metering SDK provider with isolated files and HTTP.
package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/pingcap/metering_sdk/storage/provider"
)

type cosDefaultCase struct {
	Name          string            `json:"name"`
	Env           map[string]string `json:"env"`
	Token         bool              `json:"token_file"`
	Denied        bool              `json:"denied"`
	ID            string            `json:"credential"`
	SecurityToken string            `json:"security_token"`
	Error         bool              `json:"error"`
	STS           []map[string]any  `json:"sts"`
}
type cosTransport func(*http.Request) (*http.Response, error)

func (f cosTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func main() {
	cases := []cosDefaultCase{
		{Name: "environment-ignores-token", Env: map[string]string{"TENCENTCLOUD_SECRET_ID": "env-id", "TENCENTCLOUD_SECRET_KEY": "env-secret", "TENCENTCLOUD_TOKEN": "ignored-token"}},
		{Name: "partial-env-allows-profile", Env: map[string]string{"TENCENTCLOUD_SECRET_ID": "partial-id"}},
		{Name: "empty-env-stops-chain", Env: map[string]string{"TENCENTCLOUD_SECRET_ID": "", "TENCENTCLOUD_SECRET_KEY": "secret"}},
		{Name: "unreadable-tke-skipped"},
		{Name: "tke-before-profile", Token: true},
		{Name: "tke-sts-denied-stops-chain", Token: true, Denied: true},
	}
	for i := range cases {
		row := &cases[i]
		for _, kv := range os.Environ() {
			k := strings.SplitN(kv, "=", 2)[0]
			if strings.HasPrefix(k, "TENCENTCLOUD_") || strings.HasPrefix(k, "TKE_") {
				_ = os.Unsetenv(k)
			}
		}
		dir, err := os.MkdirTemp("", "cos-default-fixture-")
		if err != nil {
			panic(err)
		}
		if err = os.WriteFile(filepath.Join(dir, "credentials"), []byte("[default]\nsecret_id=profile-id\nsecret_key=profile-secret\n"), 0600); err != nil {
			panic(err)
		}
		_ = os.Setenv("TENCENTCLOUD_CREDENTIALS_FILE", filepath.Join(dir, "credentials"))
		for key, value := range row.Env {
			_ = os.Setenv(key, value)
		}
		if strings.Contains(row.Name, "tke") {
			for key, value := range map[string]string{"TKE_REGION": "ap-singapore", "TKE_PROVIDER_ID": "provider-id", "TKE_WEB_IDENTITY_TOKEN_FILE": filepath.Join(dir, "token"), "TKE_ROLE_ARN": "qcs::cam::uin/123:roleName/test"} {
				_ = os.Setenv(key, value)
			}
			if row.Token {
				if err = os.WriteFile(filepath.Join(dir, "token"), []byte("fake-token\n"), 0600); err != nil {
					panic(err)
				}
			}
		}
		http.DefaultTransport = cosTransport(func(req *http.Request) (*http.Response, error) {
			response := ""
			if req.URL.Host == "sts.tencentcloudapi.com" {
				raw, _ := io.ReadAll(req.Body)
				var body map[string]any
				if err := json.Unmarshal(raw, &body); err != nil {
					panic(err)
				}
				session := body["RoleSessionName"].(string)
				micros, err := strconv.ParseInt(strings.TrimPrefix(session, "tencentcloud-go-sdk-"), 10, 64)
				if err != nil || !strings.HasPrefix(session, "tencentcloud-go-sdk-") || time.Since(time.UnixMicro(micros)).Abs() > time.Minute {
					panic("unexpected Go TKE session time")
				}
				body["RoleSessionName"] = "fixture-session"
				row.STS = append(row.STS, map[string]any{"method": req.Method, "url": req.URL.String(), "region": req.Header.Get("X-TC-Region"), "authorization": req.Header.Get("Authorization"), "body": body})
				response = `{"Response":{"Credentials":{"TmpSecretId":"tke-id","TmpSecretKey":"tke-secret","Token":"tke-token"},"ExpiredTime":4070908800}}`
				if row.Denied {
					response = `{"Response":{"Error":{"Code":"AuthFailure","Message":"fixture denied"}}}`
				}
			} else {
				values, _ := url.ParseQuery(req.Header.Get("Authorization"))
				row.ID = values.Get("q-ak")
				row.SecurityToken = req.Header.Get("X-Cos-Security-Token")
			}
			return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(response)), Request: req}, nil
		})
		store, err := provider.NewCOSProvider(&provider.ProviderConfig{Type: provider.ProviderTypeCOS, Bucket: "fixture-1250000000", Region: "ap-guangzhou"})
		if err == nil {
			err = store.Upload(context.Background(), "key", strings.NewReader("data"))
		}
		row.Error = err != nil
		_ = os.RemoveAll(dir)
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(cases); err != nil {
		panic(err)
	}
}
