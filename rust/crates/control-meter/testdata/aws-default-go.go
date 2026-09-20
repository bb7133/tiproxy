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

// Capture the actual pinned Go credential resolver with isolated fake files and HTTP.
package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
)

type defaultRequest struct {
	Method     string `json:"method"`
	URL        string `json:"url"`
	Body       string `json:"body"`
	SigningKey string `json:"signing_key"`
	Token      string `json:"token"`
}
type defaultCase struct {
	Name       string            `json:"name"`
	Env        map[string]string `json:"env"`
	Files      map[string]string `json:"files"`
	Denied     bool              `json:"denied"`
	Credential string            `json:"credential"`
	Secret     string            `json:"secret"`
	Error      bool              `json:"error"`
	Requests   []defaultRequest  `json:"requests"`
}
type defaultTransport func(*http.Request) (*http.Response, error)

func (f defaultTransport) Do(r *http.Request) (*http.Response, error) { return f(r) }

func main() {
	profile := "[default]\naws_access_key_id=profile-id\naws_secret_access_key=profile-secret\n"
	env := map[string]string{"AWS_ACCESS_KEY_ID": "env-id", "AWS_SECRET_ACCESS_KEY": "env-secret"}
	cases := []defaultCase{
		{Name: "environment-before-profile", Env: env, Files: map[string]string{"config": profile}},
		{Name: "legacy-environment-aliases", Env: map[string]string{"AWS_ACCESS_KEY": "legacy-id", "AWS_SECRET_KEY": "legacy-secret"}, Files: map[string]string{"config": profile}},
		{Name: "partial-env-allows-profile", Env: map[string]string{"AWS_ACCESS_KEY_ID": "partial-id"}, Files: map[string]string{"config": profile}},
		{Name: "web-identity-before-profile", Env: map[string]string{"AWS_WEB_IDENTITY_TOKEN_FILE": "/fixture/token", "AWS_ROLE_ARN": "arn:aws:iam::123456789012:role/web", "AWS_ROLE_SESSION_NAME": "web-session"}, Files: map[string]string{"config": profile, "token": "fake-web-token\n"}},
		{Name: "missing-web-token-never-falls-back", Env: map[string]string{"AWS_WEB_IDENTITY_TOKEN_FILE": "/fixture/missing", "AWS_ROLE_ARN": "arn:aws:iam::123456789012:role/web"}, Files: map[string]string{"config": profile}},
		{Name: "denied-web-never-falls-back", Env: map[string]string{"AWS_WEB_IDENTITY_TOKEN_FILE": "/fixture/token", "AWS_ROLE_ARN": "arn:aws:iam::123456789012:role/web", "AWS_ROLE_SESSION_NAME": "web-session"}, Files: map[string]string{"config": profile, "token": "fake-web-token"}, Denied: true},
		{Name: "credentials-file-over-config", Files: map[string]string{"config": profile, "credentials": "[default]\naws_access_key_id=file-id\naws_secret_access_key=file-secret\n"}},
		{Name: "named-source-profile-role", Env: map[string]string{"AWS_PROFILE": "target"}, Files: map[string]string{"config": "[profile target]\nrole_arn=arn:aws:iam::123456789012:role/profile\nsource_profile=base\nrole_session_name=profile-session\nduration_seconds=1200\nexternal_id=fixture-external\n[profile base]\naws_access_key_id=source-id\naws_secret_access_key=source-secret\naws_session_token=source-token\n"}},
		{Name: "profile-cycle-rejected", Env: map[string]string{"AWS_PROFILE": "a"}, Files: map[string]string{"config": "[profile a]\nrole_arn=arn:aws:iam::123456789012:role/a\nsource_profile=b\n[profile b]\nrole_arn=arn:aws:iam::123456789012:role/b\nsource_profile=a\n"}},
		{Name: "failed-process-never-falls-back", Env: map[string]string{"AWS_CONTAINER_CREDENTIALS_FULL_URI": "http://127.0.0.1/credentials"}, Files: map[string]string{"config": "[default]\ncredential_process=false\n"}},
		{Name: "env-still-validates-profile-conflict", Env: env, Files: map[string]string{"config": "[default]\nrole_arn=arn:aws:iam::123456789012:role/profile\nsource_profile=base\ncredential_process=false\n[profile base]\naws_access_key_id=base-id\naws_secret_access_key=base-secret\n"}},
		{Name: "env-still-requires-named-profile", Env: map[string]string{"AWS_PROFILE": "missing", "AWS_ACCESS_KEY_ID": "env-id", "AWS_SECRET_ACCESS_KEY": "env-secret"}, Files: map[string]string{"config": profile}},
		{Name: "credential-source-requires-role", Files: map[string]string{"config": "[default]\ncredential_source=Environment\n"}},
		{Name: "partial-file-keys-cannot-merge", Files: map[string]string{"config": "[default]\naws_access_key_id=config-id\n", "credentials": "[default]\naws_secret_access_key=file-secret\n"}},
		{Name: "complete-file-overrides-partial-config", Files: map[string]string{"config": "[default]\naws_access_key_id=config-id\n", "credentials": "[default]\naws_access_key_id=file-id\naws_secret_access_key=file-secret\n"}},
		{Name: "prefixed-credentials-section-ignored", Files: map[string]string{"config": profile, "credentials": "[profile default]\naws_access_key_id=wrong-id\naws_secret_access_key=wrong-secret\n"}},
		{Name: "role-self-source-static", Files: map[string]string{"config": profile + "role_arn=arn:aws:iam::123456789012:role/self\nsource_profile=default\nrole_session_name=self-session\n"}},
		{Name: "mfa-without-role-ignored", Files: map[string]string{"config": profile + "mfa_serial=fixture-mfa\n"}},
		{Name: "unrecognized-ini-lines-ignored", Env: env, Files: map[string]string{"config": "[default\ninvalid"}},
		{Name: "profile-process-collision-rejected", Files: map[string]string{"config": "[default]\nrole_arn=arn:aws:iam::123456789012:role/profile\ncredential_source=Environment\ncredential_process=false\n"}},
		{Name: "profile-web-ignores-duration", Files: map[string]string{"config": "[default]\nrole_arn=arn:aws:iam::123456789012:role/web\nweb_identity_token_file=/fixture/token\nrole_session_name=web-session\nduration_seconds=1200\n", "token": "profile-token\n"}},
		{Name: "profile-role-short-duration-default", Files: map[string]string{"config": profile + "role_arn=arn:aws:iam::123456789012:role/short\nrole_session_name=short-session\nduration_seconds=959\n"}},
		{Name: "literal-ini-quotes-colon-comments", Files: map[string]string{"config": "[ default ] ; profile comment\nAWS_ACCESS_KEY_ID : 'literal-id' # comment\n  AWS_SECRET_ACCESS_KEY = \"literal-secret\\path\" ; comment\n"}},
		{Name: "prefixed-default-wins", Files: map[string]string{"config": "[profile default]\naws_access_key_id=prefixed-id\naws_secret_access_key=prefixed-secret\n[default]\naws_access_key_id=plain-id\naws_secret_access_key=plain-secret\n"}},
	}
	for i := range cases {
		row := &cases[i]
		for _, key := range os.Environ() {
			key = strings.SplitN(key, "=", 2)[0]
			if strings.HasPrefix(key, "AWS_") {
				_ = os.Unsetenv(key)
			}
		}
		dir, err := os.MkdirTemp("", "aws-default-fixture-")
		if err != nil {
			panic(err)
		}
		for name, body := range row.Files {
			if err = os.WriteFile(filepath.Join(dir, name), []byte(strings.ReplaceAll(body, "/fixture/", dir+string(os.PathSeparator))), 0600); err != nil {
				panic(err)
			}
		}
		_ = os.Setenv("AWS_CONFIG_FILE", filepath.Join(dir, "config"))
		_ = os.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(dir, "credentials"))
		for key, value := range row.Env {
			if strings.HasPrefix(value, "/fixture/") {
				value = filepath.Join(dir, strings.TrimPrefix(value, "/fixture/"))
			}
			_ = os.Setenv(key, value)
		}
		transport := defaultTransport(func(req *http.Request) (*http.Response, error) {
			body, _ := io.ReadAll(req.Body)
			signingKey := ""
			if _, tail, ok := strings.Cut(req.Header.Get("Authorization"), "Credential="); ok {
				signingKey = strings.SplitN(tail, "/", 2)[0]
			}
			row.Requests = append(row.Requests, defaultRequest{req.Method, req.URL.String(), string(body), signingKey, req.Header.Get("X-Amz-Security-Token")})
			status := 200
			values, _ := url.ParseQuery(string(body))
			action := values.Get("Action")
			id := "ASIASOURCEROLE0000000"
			if action == "AssumeRoleWithWebIdentity" {
				id = "ASIAWEBIDENTITY000000"
			}
			response := "<" + action + "Response><" + action + "Result><Credentials><AccessKeyId>" + id + "</AccessKeyId><SecretAccessKey>fake-secret</SecretAccessKey><SessionToken>fake-token</SessionToken><Expiration>2099-01-01T00:00:00Z</Expiration></Credentials></" + action + "Result></" + action + "Response>"
			if row.Denied {
				status = 403
				response = "<ErrorResponse><Error><Code>AccessDenied</Code><Message>fixture denied</Message></Error></ErrorResponse>"
			}
			return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(response)), Request: req}, nil
		})
		cfg, err := config.LoadDefaultConfig(context.Background(), config.WithRegion("us-east-1"), config.WithHTTPClient(transport), config.WithRetryer(func() aws.Retryer { return aws.NopRetryer{} }))
		if err == nil {
			var credential aws.Credentials
			credential, err = cfg.Credentials.Retrieve(context.Background())
			if err == nil {
				row.Credential = credential.AccessKeyID
				row.Secret = credential.SecretAccessKey
			}
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
